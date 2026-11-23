package task

import (
	"errors"
	"sync"
	"testing"
	"time"

	taskpkg "gsb/batch46-safety-c-04"
)

const (
	srvA  = "ntp-a.example.net"
	srvB  = "ntp-b.example.net"
	keyID = uint32(7)
)

func base() time.Time {
	return time.Unix(1700000000, 0)
}

func testConfig() taskpkg.Config {
	return taskpkg.Config{
		MaxOffset:    500 * time.Millisecond,
		MinRounds:    1,
		MaxSkew:      100 * time.Millisecond,
		MaxSlewPPM:   100,
		ServerMaxAge: time.Hour,
	}
}

func mustGuard(t *testing.T, cfg taskpkg.Config) *taskpkg.NtpAuthGuard {
	t.Helper()
	g := taskpkg.NewNtpAuthGuard(cfg)
	if err := g.AddKey(srvA, keyID); err != nil {
		t.Fatalf("AddKey(%s): %v", srvA, err)
	}
	if err := g.AddKey(srvB, keyID); err != nil {
		t.Fatalf("AddKey(%s): %v", srvB, err)
	}
	return g
}

func mustQuery(t *testing.T, g *taskpkg.NtpAuthGuard, server string, now time.Time) taskpkg.Query {
	t.Helper()
	q, err := g.Query(server, now)
	if err != nil {
		t.Fatalf("Query(%s): %v", server, err)
	}
	return q
}

func response(q taskpkg.Query, receive, transmit, destination time.Time) taskpkg.Response {
	return taskpkg.Response{
		Server:      q.Server,
		KeyID:       keyID,
		AuthOK:      true,
		Version:     4,
		Leap:        0,
		Stratum:     2,
		Originate:   q.T1,
		Receive:     receive,
		Transmit:    transmit,
		Destination: destination,
		Nonce:       q.Nonce,
	}
}

// symmetric returns a response whose implied offset is exactly d.
func symmetric(q taskpkg.Query, d time.Duration) taskpkg.Response {
	t4 := q.T1.Add(d)
	return response(q, t4, t4, t4)
}

// A response without a valid authenticator must not be used.
func TestSubmitRejectsAuthFailure(t *testing.T) {
	now := base()
	g := mustGuard(t, testConfig())
	q := mustQuery(t, g, srvA, now)
	resp := symmetric(q, 0)
	resp.AuthOK = false
	if _, err := g.Submit(resp, now); !errors.Is(err, taskpkg.ErrAuth) {
		t.Fatalf("unauthenticated response = %v, want ErrAuth", err)
	}
}

// Unknown and revoked key ids must be rejected.
func TestSubmitRejectsUnknownOrRevokedKey(t *testing.T) {
	now := base()
	g := mustGuard(t, testConfig())
	q := mustQuery(t, g, srvA, now)
	unknown := symmetric(q, 0)
	unknown.KeyID = 99
	if _, err := g.Submit(unknown, now); !errors.Is(err, taskpkg.ErrKey) {
		t.Fatalf("unknown key id = %v, want ErrKey", err)
	}
	if err := g.RevokeKey(srvA, keyID); err != nil {
		t.Fatalf("RevokeKey: %v", err)
	}
	q2 := mustQuery(t, g, srvB, now)
	revoked := symmetric(q2, 0)
	revoked.Server = srvA
	revoked.Originate = q2.T1
	revoked.Nonce = q2.Nonce
	revoked.KeyID = keyID
	if _, err := g.Submit(revoked, now); !errors.Is(err, taskpkg.ErrKey) {
		t.Fatalf("revoked key id = %v, want ErrKey", err)
	}
}

// Only version 4 responses are understood.
func TestSubmitRejectsBadVersion(t *testing.T) {
	now := base()
	g := mustGuard(t, testConfig())
	q := mustQuery(t, g, srvA, now)
	resp := symmetric(q, 0)
	resp.Version = 3
	if _, err := g.Submit(resp, now); !errors.Is(err, taskpkg.ErrPacket) {
		t.Fatalf("version 3 = %v, want ErrPacket", err)
	}
}

// Stratum 0 (kiss-o'-death) and stratum 16 (unsynchronised) are unusable.
func TestSubmitRejectsBadStratum(t *testing.T) {
	now := base()
	g := mustGuard(t, testConfig())
	q := mustQuery(t, g, srvA, now)
	zero := symmetric(q, 0)
	zero.Stratum = 0
	if _, err := g.Submit(zero, now); !errors.Is(err, taskpkg.ErrPacket) {
		t.Fatalf("stratum 0 = %v, want ErrPacket", err)
	}
	q2 := mustQuery(t, g, srvA, now.Add(time.Second))
	unsync := symmetric(q2, 0)
	unsync.Stratum = 16
	if _, err := g.Submit(unsync, now.Add(time.Second)); !errors.Is(err, taskpkg.ErrPacket) {
		t.Fatalf("stratum 16 = %v, want ErrPacket", err)
	}
}

// A leap indicator of 3 means the server itself is unsynchronised.
func TestSubmitRejectsUnsyncedLeap(t *testing.T) {
	now := base()
	g := mustGuard(t, testConfig())
	q := mustQuery(t, g, srvA, now)
	resp := symmetric(q, 0)
	resp.Leap = 3
	if _, err := g.Submit(resp, now); !errors.Is(err, taskpkg.ErrPacket) {
		t.Fatalf("leap 3 = %v, want ErrPacket", err)
	}
}

// The response must echo the originate timestamp of the outstanding query.
func TestSubmitRejectsStaleOriginate(t *testing.T) {
	now := base()
	g := mustGuard(t, testConfig())
	q := mustQuery(t, g, srvA, now)
	resp := symmetric(q, 0)
	resp.Originate = q.T1.Add(-time.Second)
	if _, err := g.Submit(resp, now); !errors.Is(err, taskpkg.ErrStale) {
		t.Fatalf("wrong originate timestamp = %v, want ErrStale", err)
	}
}

// A nonce may be used once; resubmitting the same response is a replay.
func TestSubmitRejectsReplayedNonce(t *testing.T) {
	now := base()
	g := mustGuard(t, testConfig())
	q := mustQuery(t, g, srvA, now)
	resp := symmetric(q, 0)
	if _, err := g.Submit(resp, now); err != nil {
		t.Fatalf("first Submit: %v", err)
	}
	if _, err := g.Submit(resp, now.Add(time.Second)); !errors.Is(err, taskpkg.ErrReplay) {
		t.Fatalf("replayed response = %v, want ErrReplay", err)
	}
}

// A server that implies an offset beyond MaxOffset is a falseticker.
func TestSubmitRejectsOffsetBeyondLimit(t *testing.T) {
	now := base()
	g := mustGuard(t, testConfig())
	q := mustQuery(t, g, srvA, now)
	resp := symmetric(q, 2*time.Second)
	if _, err := g.Submit(resp, now.Add(time.Second)); !errors.Is(err, taskpkg.ErrOffset) {
		t.Fatalf("offset of 1s with a 500ms limit = %v, want ErrOffset", err)
	}
}

// The offset and delay must follow the NTP formulas exactly.
func TestSubmitComputesOffsetAndDelay(t *testing.T) {
	now := base()
	g := mustGuard(t, testConfig())
	q := mustQuery(t, g, srvA, now)
	resp := response(q, now.Add(10*time.Millisecond), now.Add(12*time.Millisecond), now.Add(30*time.Millisecond))
	sample, err := g.Submit(resp, now.Add(31*time.Millisecond))
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if sample.Offset != -4*time.Millisecond {
		t.Fatalf("offset = %v, want -4ms", sample.Offset)
	}
	if sample.Delay != 28*time.Millisecond {
		t.Fatalf("delay = %v, want 28ms", sample.Delay)
	}
	if sample.Stratum != 2 || sample.Server != srvA {
		t.Fatalf("sample = %+v, want stratum 2 from %s", sample, srvA)
	}
	got, ok := g.Offset(srvA)
	if !ok || got != -4*time.Millisecond {
		t.Fatalf("Offset(%s) = %v, %v; want -4ms", srvA, got, ok)
	}
}

// A server becomes selectable only after MinRounds accepted samples.
func TestSelectedServerRequiresMinRounds(t *testing.T) {
	now := base()
	cfg := testConfig()
	cfg.MinRounds = 2
	g := mustGuard(t, cfg)
	q := mustQuery(t, g, srvA, now)
	if _, err := g.Submit(symmetric(q, 0), now); err != nil {
		t.Fatalf("first Submit: %v", err)
	}
	if _, err := g.SelectedServer(now); !errors.Is(err, taskpkg.ErrNoSource) {
		t.Fatalf("selection after one of two rounds = %v, want ErrNoSource", err)
	}
	later := now.Add(time.Second)
	q2 := mustQuery(t, g, srvA, later)
	if _, err := g.Submit(symmetric(q2, 0), later); err != nil {
		t.Fatalf("second Submit: %v", err)
	}
	sel, err := g.SelectedServer(later)
	if err != nil {
		t.Fatalf("SelectedServer: %v", err)
	}
	if sel != srvA {
		t.Fatalf("SelectedServer = %q, want %q", sel, srvA)
	}
}

// Two selectable servers that disagree beyond MaxSkew must not be trusted.
func TestSelectedServerDetectsDivergence(t *testing.T) {
	now := base()
	g := mustGuard(t, testConfig())
	qa := mustQuery(t, g, srvA, now)
	if _, err := g.Submit(symmetric(qa, 0), now); err != nil {
		t.Fatalf("Submit %s: %v", srvA, err)
	}
	qb := mustQuery(t, g, srvB, now)
	if _, err := g.Submit(symmetric(qb, 400*time.Millisecond), now); err != nil {
		t.Fatalf("Submit %s: %v", srvB, err)
	}
	if _, err := g.SelectedServer(now); !errors.Is(err, taskpkg.ErrDivergence) {
		t.Fatalf("disagreeing sources = %v, want ErrDivergence", err)
	}
}

// Corrections may only be applied at the slew rate, and the rest stays
// pending for the next call.
func TestApplyRespectsSlewBudget(t *testing.T) {
	now := base()
	g := mustGuard(t, testConfig())
	q := mustQuery(t, g, srvA, now)
	if _, err := g.Submit(symmetric(q, 2*time.Millisecond), now.Add(2*time.Millisecond)); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	first, err := g.Apply(now.Add(2*time.Millisecond + time.Second))
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if first.Applied != 100*time.Microsecond || first.Remaining != 900*time.Microsecond {
		t.Fatalf("first Apply = %+v, want 100us applied and 900us left", first)
	}
	second, err := g.Apply(now.Add(2*time.Millisecond + 10*time.Second))
	if err != nil {
		t.Fatalf("second Apply: %v", err)
	}
	if second.Applied != 900*time.Microsecond || second.Remaining != 0 {
		t.Fatalf("second Apply = %+v, want 900us applied and nothing left", second)
	}
}

// Samples older than ServerMaxAge stop a server from being selected.
func TestSweepRemovesStaleServer(t *testing.T) {
	now := base()
	cfg := testConfig()
	cfg.ServerMaxAge = time.Minute
	g := mustGuard(t, cfg)
	q := mustQuery(t, g, srvA, now)
	if _, err := g.Submit(symmetric(q, 0), now); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	later := now.Add(2 * time.Minute)
	if _, err := g.SelectedServer(later); !errors.Is(err, taskpkg.ErrNoSource) {
		t.Fatalf("selection with an aged sample = %v, want ErrNoSource", err)
	}
	if n := g.Sweep(later); n != 1 {
		t.Fatalf("Sweep removed %d servers, want 1", n)
	}
	if got := g.Stats().Servers; got != 0 {
		t.Fatalf("Stats().Servers after sweep = %d, want 0", got)
	}
}

// A restarted guard must keep keys, round counts and last samples.
func TestSnapshotRestoresRoundsAndKeys(t *testing.T) {
	now := base()
	cfg := testConfig()
	cfg.MinRounds = 2
	g := mustGuard(t, cfg)
	q := mustQuery(t, g, srvA, now)
	if _, err := g.Submit(symmetric(q, 8*time.Millisecond), now); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	snap, err := g.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	restored, err := taskpkg.NewNtpAuthGuardFromSnapshot(cfg, snap)
	if err != nil {
		t.Fatalf("NewNtpAuthGuardFromSnapshot: %v", err)
	}
	if got := restored.Stats().Rounds; got != 1 {
		t.Fatalf("rounds after restart = %d, want 1", got)
	}
	if off, ok := restored.Offset(srvA); !ok || off != 4*time.Millisecond {
		t.Fatalf("restored offset = %v, %v; want 4ms", off, ok)
	}
	if _, err := restored.SelectedServer(now); !errors.Is(err, taskpkg.ErrNoSource) {
		t.Fatalf("selection after restart with one of two rounds = %v, want ErrNoSource", err)
	}
	later := now.Add(time.Second)
	q2 := mustQuery(t, restored, srvA, later)
	if _, err := restored.Submit(symmetric(q2, 8*time.Millisecond), later); err != nil {
		t.Fatalf("Submit after restart: %v", err)
	}
	sel, err := restored.SelectedServer(later)
	if err != nil || sel != srvA {
		t.Fatalf("SelectedServer after restart = %q, %v", sel, err)
	}
}

// Two concurrent submissions of the same response must not both count.
func TestConcurrentDuplicateSubmitSingleWinner(t *testing.T) {
	now := base()
	g := mustGuard(t, testConfig())
	q := mustQuery(t, g, srvA, now)
	resp := symmetric(q, 0)
	errs := make([]error, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, errs[0] = g.Submit(resp, now)
	}()
	go func() {
		defer wg.Done()
		_, errs[1] = g.Submit(resp, now)
	}()
	wg.Wait()
	successes := 0
	for _, err := range errs {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent duplicate submissions: %d accepted, want exactly 1", successes)
	}
	if got := g.Stats().Rounds; got != 1 {
		t.Fatalf("rounds after the race = %d, want 1", got)
	}
}
