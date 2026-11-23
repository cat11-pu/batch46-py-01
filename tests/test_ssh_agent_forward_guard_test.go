package task

import (
	"errors"
	"sync"
	"testing"
	"time"

	taskpkg "gsb/batch46-safety-b-06"
)

func baseConfig() taskpkg.Config {
	return taskpkg.Config{
		MaxSignsPerSession: 10,
		MaxSignsPerKey:     10,
		MaxSessions:        8,
		SessionTTL:         time.Hour,
	}
}

func testKey(fingerprint, tenant string) taskpkg.Key {
	return taskpkg.Key{
		Fingerprint: fingerprint,
		TenantID:    tenant,
		Purpose:     "deploy",
		Comment:     "ci-runner@bastion",
	}
}

func testSession(id, tenant string, now time.Time) taskpkg.Session {
	return taskpkg.Session{ID: id, TenantID: tenant, Host: "web-01.internal", ExpiresAt: now.Add(time.Hour)}
}

func newGuard(t *testing.T, cfg taskpkg.Config) *taskpkg.AgentForwardGuard {
	t.Helper()
	g := taskpkg.NewAgentForwardGuard(cfg)
	if g == nil {
		t.Fatal("NewAgentForwardGuard returned nil")
	}
	return g
}

func mustRegister(t *testing.T, g *taskpkg.AgentForwardGuard, k taskpkg.Key, flags uint32) {
	t.Helper()
	if err := g.RegisterKey(k, flags); err != nil {
		t.Fatalf("RegisterKey(%s): %v", k.Fingerprint, err)
	}
}

func mustOpen(t *testing.T, g *taskpkg.AgentForwardGuard, s taskpkg.Session, now time.Time) {
	t.Helper()
	if err := g.OpenSession(s, now); err != nil {
		t.Fatalf("OpenSession(%s): %v", s.ID, err)
	}
}

func mustSign(t *testing.T, g *taskpkg.AgentForwardGuard, req taskpkg.SignRequest, now time.Time) taskpkg.SignResult {
	t.Helper()
	res, err := g.Sign(req, now)
	if err != nil {
		t.Fatalf("Sign(session=%s, key=%s): %v", req.SessionID, req.Fingerprint, err)
	}
	return res
}

// A signature request for an ID that was never opened must be refused, and it
// must be distinguishable from an expired session.
func TestUnknownSessionRejected(t *testing.T) {
	now := time.Unix(1726400000, 0)
	g := newGuard(t, baseConfig())
	mustRegister(t, g, testKey("SHA256:unknown-case", "tenant-a"), 2)
	if _, err := g.Sign(taskpkg.SignRequest{SessionID: "sess-never", Fingerprint: "SHA256:unknown-case", Flags: 2, Data: []byte("x")}, now); !errors.Is(err, taskpkg.ErrSessionUnknown) {
		t.Fatalf("Sign with an unopened session: got %v, want ErrSessionUnknown", err)
	}
}

// Reaching ExpiresAt must stop signing even when the session is still present,
// and the failed attempt must not consume budget.
func TestExpiredSessionRejected(t *testing.T) {
	now := time.Unix(1726400000, 0)
	g := newGuard(t, baseConfig())
	mustRegister(t, g, testKey("SHA256:expiry-case", "tenant-a"), 2)
	mustOpen(t, g, testSession("sess-expiry", "tenant-a", now), now)
	if _, err := g.Sign(taskpkg.SignRequest{SessionID: "sess-expiry", Fingerprint: "SHA256:expiry-case", Flags: 2, Data: []byte("y")}, now.Add(time.Hour)); !errors.Is(err, taskpkg.ErrSessionExpired) {
		t.Fatalf("Sign at ExpiresAt: got %v, want ErrSessionExpired", err)
	}
	signs, err := g.SessionSigns("tenant-a", "sess-expiry")
	if err != nil {
		t.Fatalf("SessionSigns after expired attempt: %v", err)
	}
	if signs != 0 {
		t.Fatalf("expired attempt consumed budget: SessionSigns=%d, want 0", signs)
	}
}

// Opening the same session ID twice must be refused while the first is live.
func TestDuplicateSessionRejected(t *testing.T) {
	now := time.Unix(1726400000, 0)
	g := newGuard(t, baseConfig())
	mustOpen(t, g, testSession("sess-dup", "tenant-a", now), now)
	if err := g.OpenSession(testSession("sess-dup", "tenant-a", now), now); !errors.Is(err, taskpkg.ErrSessionDuplicate) {
		t.Fatalf("second OpenSession with the same ID: got %v, want ErrSessionDuplicate", err)
	}
}

// The live session cap must hold, and sessions that expired must stop
// occupying slots without any explicit cleanup call.
func TestSessionCapEnforced(t *testing.T) {
	now := time.Unix(1726400000, 0)
	cfg := baseConfig()
	cfg.MaxSessions = 2
	cfg.SessionTTL = 5 * time.Minute
	g := newGuard(t, cfg)
	short := func(id string) taskpkg.Session {
		return taskpkg.Session{ID: id, TenantID: "tenant-a", Host: "web-01.internal", ExpiresAt: now.Add(5 * time.Minute)}
	}
	mustOpen(t, g, short("sess-cap-1"), now)
	mustOpen(t, g, short("sess-cap-2"), now)
	if err := g.OpenSession(short("sess-cap-3"), now); !errors.Is(err, taskpkg.ErrSessionCap) {
		t.Fatalf("third live session: got %v, want ErrSessionCap", err)
	}
	if live := g.ActiveSessions(now); live != 2 {
		t.Fatalf("ActiveSessions=%d, want 2", live)
	}
	later := now.Add(6 * time.Minute)
	if live := g.ActiveSessions(later); live != 0 {
		t.Fatalf("ActiveSessions after TTL=%d, want 0", live)
	}
	mustOpen(t, g, taskpkg.Session{ID: "sess-cap-3", TenantID: "tenant-a", Host: "web-01.internal", ExpiresAt: later.Add(time.Minute)}, later)
}

// Sign returns the request payload unchanged and a per-session serial that
// starts at 1 and grows monotonically.
func TestSignSerialAndDataEcho(t *testing.T) {
	now := time.Unix(1726400000, 0)
	g := newGuard(t, baseConfig())
	mustRegister(t, g, testKey("SHA256:serial-case", "tenant-a"), 6)
	mustOpen(t, g, testSession("sess-serial", "tenant-a", now), now)
	first := mustSign(t, g, taskpkg.SignRequest{SessionID: "sess-serial", Fingerprint: "SHA256:serial-case", Flags: 2, Data: []byte("git-upload-pack")}, now)
	if first.Fingerprint != "SHA256:serial-case" {
		t.Fatalf("SignResult.Fingerprint=%q, want SHA256:serial-case", first.Fingerprint)
	}
	if first.Serial != 1 {
		t.Fatalf("first Serial=%d, want 1", first.Serial)
	}
	if string(first.Data) != "git-upload-pack" {
		t.Fatalf("first Data=%q, want git-upload-pack", first.Data)
	}
	second := mustSign(t, g, taskpkg.SignRequest{SessionID: "sess-serial", Fingerprint: "SHA256:serial-case", Flags: 4, Data: []byte("git-receive-pack")}, now)
	if second.Serial != 2 {
		t.Fatalf("second Serial=%d, want 2", second.Serial)
	}
	if string(second.Data) != "git-receive-pack" {
		t.Fatalf("second Data=%q, want git-receive-pack", second.Data)
	}
}

// The per-session budget must stop signing even for a different key, and the
// refusal must not be counted.
func TestSessionSignBudgetEnforced(t *testing.T) {
	now := time.Unix(1726400000, 0)
	cfg := baseConfig()
	cfg.MaxSignsPerSession = 2
	g := newGuard(t, cfg)
	mustRegister(t, g, testKey("SHA256:budget-a", "tenant-a"), 2)
	mustRegister(t, g, testKey("SHA256:budget-b", "tenant-a"), 2)
	mustOpen(t, g, testSession("sess-budget", "tenant-a", now), now)
	mustSign(t, g, taskpkg.SignRequest{SessionID: "sess-budget", Fingerprint: "SHA256:budget-a", Flags: 2, Data: []byte("one")}, now)
	mustSign(t, g, taskpkg.SignRequest{SessionID: "sess-budget", Fingerprint: "SHA256:budget-b", Flags: 2, Data: []byte("two")}, now)
	if _, err := g.Sign(taskpkg.SignRequest{SessionID: "sess-budget", Fingerprint: "SHA256:budget-a", Flags: 2, Data: []byte("three")}, now); !errors.Is(err, taskpkg.ErrSignBudget) {
		t.Fatalf("third sign in a two-sign session: got %v, want ErrSignBudget", err)
	}
	signs, err := g.SessionSigns("tenant-a", "sess-budget")
	if err != nil {
		t.Fatalf("SessionSigns: %v", err)
	}
	if signs != 2 {
		t.Fatalf("SessionSigns=%d, want 2", signs)
	}
}

// A key budget is shared by all sessions of its tenant.
func TestPerKeySignBudgetEnforced(t *testing.T) {
	now := time.Unix(1726400000, 0)
	cfg := baseConfig()
	cfg.MaxSignsPerKey = 1
	g := newGuard(t, cfg)
	mustRegister(t, g, testKey("SHA256:keycap-a", "tenant-a"), 2)
	mustRegister(t, g, testKey("SHA256:keycap-b", "tenant-a"), 2)
	mustOpen(t, g, testSession("sess-key-1", "tenant-a", now), now)
	mustOpen(t, g, testSession("sess-key-2", "tenant-a", now), now)
	mustSign(t, g, taskpkg.SignRequest{SessionID: "sess-key-1", Fingerprint: "SHA256:keycap-a", Flags: 2, Data: []byte("a")}, now)
	if _, err := g.Sign(taskpkg.SignRequest{SessionID: "sess-key-2", Fingerprint: "SHA256:keycap-a", Flags: 2, Data: []byte("b")}, now); !errors.Is(err, taskpkg.ErrSignBudget) {
		t.Fatalf("second sign of a one-sign key in another session: got %v, want ErrSignBudget", err)
	}
	mustSign(t, g, taskpkg.SignRequest{SessionID: "sess-key-2", Fingerprint: "SHA256:keycap-b", Flags: 2, Data: []byte("c")}, now)
	used, err := g.KeySigns("tenant-a", "SHA256:keycap-a")
	if err != nil {
		t.Fatalf("KeySigns: %v", err)
	}
	if used != 1 {
		t.Fatalf("KeySigns(keycap-a)=%d, want 1", used)
	}
}

// Concurrent submissions of the same session must never exceed the session
// budget: with a budget of three, exactly three of ten racing request win.
func TestConcurrentSignsNeverExceedSessionBudget(t *testing.T) {
	now := time.Unix(1726400000, 0)
	cfg := baseConfig()
	cfg.MaxSignsPerSession = 3
	cfg.MaxSignsPerKey = 100
	g := newGuard(t, cfg)
	mustRegister(t, g, testKey("SHA256:race-case", "tenant-a"), 2)
	mustOpen(t, g, testSession("sess-race", "tenant-a", now), now)
	var wg sync.WaitGroup
	var mu sync.Mutex
	successes := 0
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			if _, err := g.Sign(taskpkg.SignRequest{SessionID: "sess-race", Fingerprint: "SHA256:race-case", Flags: 2, Data: []byte{byte(n)}}, now); err == nil {
				mu.Lock()
				successes++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	if successes != 3 {
		t.Fatalf("concurrent successes=%d, want exactly 3", successes)
	}
	signs, err := g.SessionSigns("tenant-a", "sess-race")
	if err != nil {
		t.Fatalf("SessionSigns: %v", err)
	}
	if signs != 3 {
		t.Fatalf("SessionSigns=%d, want 3", signs)
	}
}

// Flags must be a non-zero subset of the mask the key was registered with.
func TestFlagsMustBeNonZeroSubset(t *testing.T) {
	now := time.Unix(1726400000, 0)
	g := newGuard(t, baseConfig())
	mustRegister(t, g, testKey("SHA256:flags-case", "tenant-a"), 2)
	mustOpen(t, g, testSession("sess-flags", "tenant-a", now), now)
	if _, err := g.Sign(taskpkg.SignRequest{SessionID: "sess-flags", Fingerprint: "SHA256:flags-case", Flags: 4, Data: []byte("a")}, now); !errors.Is(err, taskpkg.ErrFlagNotAllowed) {
		t.Fatalf("flag outside the mask: got %v, want ErrFlagNotAllowed", err)
	}
	if _, err := g.Sign(taskpkg.SignRequest{SessionID: "sess-flags", Fingerprint: "SHA256:flags-case", Flags: 0, Data: []byte("b")}, now); !errors.Is(err, taskpkg.ErrFlagNotAllowed) {
		t.Fatalf("zero flags: got %v, want ErrFlagNotAllowed", err)
	}
	if _, err := g.Sign(taskpkg.SignRequest{SessionID: "sess-flags", Fingerprint: "SHA256:flags-case", Flags: 2, Data: []byte("c")}, now); err != nil {
		t.Fatalf("allowed flag: %v", err)
	}
}

// A revoked key stays revoked when it is registered again, stays out of the
// listing, and is reported as revoked rather than unknown.
func TestRevokedKeyStaysRevokedAfterReregister(t *testing.T) {
	now := time.Unix(1726400000, 0)
	g := newGuard(t, baseConfig())
	key := testKey("SHA256:revoke-case", "tenant-a")
	mustRegister(t, g, key, 2)
	mustOpen(t, g, testSession("sess-revoke", "tenant-a", now), now)
	if err := g.RevokeKey("tenant-a", "SHA256:revoke-case"); err != nil {
		t.Fatalf("RevokeKey: %v", err)
	}
	if _, err := g.Sign(taskpkg.SignRequest{SessionID: "sess-revoke", Fingerprint: "SHA256:revoke-case", Flags: 2, Data: []byte("a")}, now); !errors.Is(err, taskpkg.ErrKeyRevoked) {
		t.Fatalf("sign with a revoked key: got %v, want ErrKeyRevoked", err)
	}
	mustRegister(t, g, key, 2|4)
	if _, err := g.Sign(taskpkg.SignRequest{SessionID: "sess-revoke", Fingerprint: "SHA256:revoke-case", Flags: 4, Data: []byte("b")}, now); !errors.Is(err, taskpkg.ErrKeyRevoked) {
		t.Fatalf("sign after re-registering a revoked key: got %v, want ErrKeyRevoked", err)
	}
	keys, err := g.ListKeys("tenant-a", "sess-revoke")
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("ListKeys returned %v, want no keys", keys)
	}
}

// ListKeys is sorted and only exposes keys of the session's own tenant.
func TestKeyListingTenantScopedAndSorted(t *testing.T) {
	now := time.Unix(1726400000, 0)
	g := newGuard(t, baseConfig())
	mustRegister(t, g, testKey("SHA256:ccc", "tenant-a"), 2)
	mustRegister(t, g, testKey("SHA256:aaa", "tenant-a"), 2)
	mustRegister(t, g, testKey("SHA256:bbb", "tenant-a"), 2)
	mustRegister(t, g, testKey("SHA256:zzz", "tenant-b"), 2)
	mustOpen(t, g, testSession("sess-list-a", "tenant-a", now), now)
	mustOpen(t, g, testSession("sess-list-b", "tenant-b", now), now)
	keysA, err := g.ListKeys("tenant-a", "sess-list-a")
	if err != nil {
		t.Fatalf("ListKeys tenant-a: %v", err)
	}
	wantA := []string{"SHA256:aaa", "SHA256:bbb", "SHA256:ccc"}
	if len(keysA) != len(wantA) {
		t.Fatalf("ListKeys tenant-a=%v, want %v", keysA, wantA)
	}
	for i := range wantA {
		if keysA[i] != wantA[i] {
			t.Fatalf("ListKeys tenant-a=%v, want %v", keysA, wantA)
		}
	}
	keysB, err := g.ListKeys("tenant-b", "sess-list-b")
	if err != nil {
		t.Fatalf("ListKeys tenant-b: %v", err)
	}
	if len(keysB) != 1 || keysB[0] != "SHA256:zzz" {
		t.Fatalf("ListKeys tenant-b=%v, want [SHA256:zzz]", keysB)
	}
}

// A key registered for another tenant must not be usable from this tenant's
// session, and must be reported as unknown, not as revoked.
func TestCrossTenantKeyNotUsable(t *testing.T) {
	now := time.Unix(1726400000, 0)
	g := newGuard(t, baseConfig())
	mustRegister(t, g, testKey("SHA256:tenant-b-key", "tenant-b"), 2)
	mustOpen(t, g, testSession("sess-cross", "tenant-a", now), now)
	if _, err := g.Sign(taskpkg.SignRequest{SessionID: "sess-cross", Fingerprint: "SHA256:tenant-b-key", Flags: 2, Data: []byte("x")}, now); !errors.Is(err, taskpkg.ErrKeyUnknown) {
		t.Fatalf("sign with another tenant's key: got %v, want ErrKeyUnknown", err)
	}
}

// Closing a session must make later signs and counters fail as unknown.
func TestClosedSessionRejectsSign(t *testing.T) {
	now := time.Unix(1726400000, 0)
	g := newGuard(t, baseConfig())
	mustRegister(t, g, testKey("SHA256:close-case", "tenant-a"), 2)
	mustOpen(t, g, testSession("sess-close", "tenant-a", now), now)
	if err := g.CloseSession("tenant-a", "sess-close"); err != nil {
		t.Fatalf("CloseSession: %v", err)
	}
	if _, err := g.Sign(taskpkg.SignRequest{SessionID: "sess-close", Fingerprint: "SHA256:close-case", Flags: 2, Data: []byte("x")}, now); !errors.Is(err, taskpkg.ErrSessionUnknown) {
		t.Fatalf("sign after close: got %v, want ErrSessionUnknown", err)
	}
	if _, err := g.SessionSigns("tenant-a", "sess-close"); !errors.Is(err, taskpkg.ErrSessionUnknown) {
		t.Fatalf("SessionSigns after close: got %v, want ErrSessionUnknown", err)
	}
}

// A restart must not hand out a fresh budget: session and key counters carry
// over, so the key cap that stopped the proxy before restart still stops it.
func TestBudgetsSurviveRestart(t *testing.T) {
	now := time.Unix(1726400000, 0)
	cfg := baseConfig()
	cfg.MaxSignsPerSession = 4
	cfg.MaxSignsPerKey = 3
	g := newGuard(t, cfg)
	mustRegister(t, g, testKey("SHA256:persist-budget", "tenant-a"), 2)
	mustOpen(t, g, testSession("sess-persist", "tenant-a", now), now)
	mustSign(t, g, taskpkg.SignRequest{SessionID: "sess-persist", Fingerprint: "SHA256:persist-budget", Flags: 2, Data: []byte("one")}, now)
	mustSign(t, g, taskpkg.SignRequest{SessionID: "sess-persist", Fingerprint: "SHA256:persist-budget", Flags: 2, Data: []byte("two")}, now)
	snap, err := g.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	restored, err := taskpkg.NewAgentForwardGuardFromSnapshot(cfg, snap)
	if err != nil {
		t.Fatalf("NewAgentForwardGuardFromSnapshot: %v", err)
	}
	if live := restored.ActiveSessions(now); live != 1 {
		t.Fatalf("ActiveSessions after restore=%d, want 1", live)
	}
	third := mustSign(t, restored, taskpkg.SignRequest{SessionID: "sess-persist", Fingerprint: "SHA256:persist-budget", Flags: 2, Data: []byte("three")}, now)
	if third.Serial != 3 {
		t.Fatalf("serial after restore=%d, want 3", third.Serial)
	}
	if _, err := restored.Sign(taskpkg.SignRequest{SessionID: "sess-persist", Fingerprint: "SHA256:persist-budget", Flags: 2, Data: []byte("four")}, now); !errors.Is(err, taskpkg.ErrSignBudget) {
		t.Fatalf("sign past the key cap after restore: got %v, want ErrSignBudget", err)
	}
}

// Revocations must survive a restart, including the listing.
func TestRevocationSurvivesRestart(t *testing.T) {
	now := time.Unix(1726400000, 0)
	cfg := baseConfig()
	g := newGuard(t, cfg)
	mustRegister(t, g, testKey("SHA256:persist-revoke", "tenant-a"), 2)
	mustOpen(t, g, testSession("sess-revoke-persist", "tenant-a", now), now)
	if err := g.RevokeKey("tenant-a", "SHA256:persist-revoke"); err != nil {
		t.Fatalf("RevokeKey: %v", err)
	}
	snap, err := g.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	restored, err := taskpkg.NewAgentForwardGuardFromSnapshot(cfg, snap)
	if err != nil {
		t.Fatalf("NewAgentForwardGuardFromSnapshot: %v", err)
	}
	if _, err := restored.Sign(taskpkg.SignRequest{SessionID: "sess-revoke-persist", Fingerprint: "SHA256:persist-revoke", Flags: 2, Data: []byte("x")}, now); !errors.Is(err, taskpkg.ErrKeyRevoked) {
		t.Fatalf("sign with a key revoked before restart: got %v, want ErrKeyRevoked", err)
	}
	keys, err := restored.ListKeys("tenant-a", "sess-revoke-persist")
	if err != nil {
		t.Fatalf("ListKeys after restore: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("ListKeys after restore=%v, want no keys", keys)
	}
}
