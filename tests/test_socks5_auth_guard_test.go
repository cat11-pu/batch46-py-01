package task

import (
	"errors"
	"sync"
	"testing"
	"time"

	taskpkg "gsb/batch46-safety-c-05"
)

const (
	tenantA  = "tenant-a"
	userA    = "alice"
	userB    = "bob"
	proofA   = "proof-alice"
	proofB   = "proof-bob"
	publicIP = "203.0.113.10"
)

func testConfig() taskpkg.Config {
	return taskpkg.Config{
		MaxSessions:        4,
		MaxSessionsPerUser: 2,
		IdleTimeout:        time.Minute,
		MaxBytesPerSession: 1 << 20,
		AllowedPorts:       []int{443, 80},
		MaxAuthFailures:    3,
		LockoutDuration:    time.Minute,
	}
}

func mustGuard(t *testing.T, cfg taskpkg.Config) *taskpkg.Socks5Guard {
	t.Helper()
	g := taskpkg.NewSocks5Guard(cfg)
	if err := g.AddUser(userA, proofA, tenantA); err != nil {
		t.Fatalf("AddUser(%s): %v", userA, err)
	}
	if err := g.AddUser(userB, proofB, tenantA); err != nil {
		t.Fatalf("AddUser(%s): %v", userB, err)
	}
	return g
}

func mustOpen(t *testing.T, g *taskpkg.Socks5Guard, now time.Time) taskpkg.Session {
	t.Helper()
	s, err := g.Open(now)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return s
}

func mustGreet(t *testing.T, g *taskpkg.Socks5Guard, id string, now time.Time) {
	t.Helper()
	if err := g.Greet(id, taskpkg.Greeting{Version: 5, Methods: []byte{0x02}}, now); err != nil {
		t.Fatalf("Greet(%s): %v", id, err)
	}
}

func mustAuth(t *testing.T, g *taskpkg.Socks5Guard, id, user, proof string, now time.Time) {
	t.Helper()
	if err := g.Authenticate(id, user, proof, now); err != nil {
		t.Fatalf("Authenticate(%s): %v", id, err)
	}
}

func mustSessionAs(t *testing.T, g *taskpkg.Socks5Guard, user, proof string, now time.Time) taskpkg.Session {
	t.Helper()
	s := mustOpen(t, g, now)
	mustGreet(t, g, s.ID, now)
	mustAuth(t, g, s.ID, user, proof, now)
	return s
}

func mustSession(t *testing.T, g *taskpkg.Socks5Guard, now time.Time) taskpkg.Session {
	t.Helper()
	return mustSessionAs(t, g, userA, proofA, now)
}

// The method negotiation must reject a non-5 version without closing the
// session for a correct retry.
func TestGreetRejectsWrongVersion(t *testing.T) {
	now := time.Unix(1700000000, 0)
	g := mustGuard(t, testConfig())
	s := mustOpen(t, g, now)
	if err := g.Greet(s.ID, taskpkg.Greeting{Version: 4, Methods: []byte{0x02}}, now); !errors.Is(err, taskpkg.ErrVersion) {
		t.Fatalf("version 4 greeting = %v, want ErrVersion", err)
	}
	mustGreet(t, g, s.ID, now)
}

// The no-authentication method must never be selected.
func TestGreetRejectsNoAcceptableMethod(t *testing.T) {
	now := time.Unix(1700000000, 0)
	g := mustGuard(t, testConfig())
	s := mustOpen(t, g, now)
	bad := taskpkg.Greeting{Version: 5, Methods: []byte{0x00, 0x01}}
	if err := g.Greet(s.ID, bad, now); !errors.Is(err, taskpkg.ErrMethod) {
		t.Fatalf("greeting without username/password = %v, want ErrMethod", err)
	}
	mustGreet(t, g, s.ID, now)
}

// The global session cap must hold, and closing a session must free a slot.
func TestSessionCapEnforced(t *testing.T) {
	now := time.Unix(1700000000, 0)
	cfg := testConfig()
	cfg.MaxSessions = 1
	g := mustGuard(t, cfg)
	first := mustOpen(t, g, now)
	if _, err := g.Open(now); !errors.Is(err, taskpkg.ErrCapacity) {
		t.Fatalf("second session with MaxSessions 1 = %v, want ErrCapacity", err)
	}
	if err := g.Close(first.ID, now); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := g.Open(now); err != nil {
		t.Fatalf("Open after Close: %v", err)
	}
}

// A wrong proof and an unknown user must be reported identically.
func TestAuthFailureIndistinguishable(t *testing.T) {
	now := time.Unix(1700000000, 0)
	g := mustGuard(t, testConfig())
	s1 := mustOpen(t, g, now)
	mustGreet(t, g, s1.ID, now)
	wrongProof := g.Authenticate(s1.ID, userA, "not-the-proof", now)
	if !errors.Is(wrongProof, taskpkg.ErrAuth) {
		t.Fatalf("wrong proof = %v, want ErrAuth", wrongProof)
	}
	s2 := mustOpen(t, g, now)
	mustGreet(t, g, s2.ID, now)
	unknownUser := g.Authenticate(s2.ID, "mallory", "whatever", now)
	if !errors.Is(unknownUser, taskpkg.ErrAuth) {
		t.Fatalf("unknown user = %v, want ErrAuth", unknownUser)
	}
	if wrongProof.Error() != unknownUser.Error() {
		t.Fatalf("auth errors leak user existence: %q vs %q", wrongProof, unknownUser)
	}
}

// Repeated failures lock the account even for the correct proof, and the lock
// expires after LockoutDuration.
func TestLockoutAfterMaxFailures(t *testing.T) {
	now := time.Unix(1700000000, 0)
	g := mustGuard(t, testConfig())
	s := mustOpen(t, g, now)
	mustGreet(t, g, s.ID, now)
	for i := 0; i < 3; i++ {
		if err := g.Authenticate(s.ID, userA, "wrong", now); !errors.Is(err, taskpkg.ErrAuth) {
			t.Fatalf("failure %d = %v, want ErrAuth", i+1, err)
		}
	}
	if err := g.Authenticate(s.ID, userA, proofA, now); !errors.Is(err, taskpkg.ErrLocked) {
		t.Fatalf("correct proof while locked = %v, want ErrLocked", err)
	}
	later := now.Add(61 * time.Second)
	if err := g.Authenticate(s.ID, userA, proofA, later); err != nil {
		t.Fatalf("correct proof after the lockout: %v", err)
	}
}

// Handshake steps must happen in order.
func TestOutOfOrderCallsRejected(t *testing.T) {
	now := time.Unix(1700000000, 0)
	g := mustGuard(t, testConfig())
	s := mustOpen(t, g, now)
	if err := g.Authenticate(s.ID, userA, proofA, now); !errors.Is(err, taskpkg.ErrState) {
		t.Fatalf("Authenticate before Greet = %v, want ErrState", err)
	}
	if _, err := g.Connect(s.ID, publicIP, 443, now); !errors.Is(err, taskpkg.ErrState) {
		t.Fatalf("Connect before Authenticate = %v, want ErrState", err)
	}
	mustGreet(t, g, s.ID, now)
	if err := g.Greet(s.ID, taskpkg.Greeting{Version: 5, Methods: []byte{0x02}}, now); !errors.Is(err, taskpkg.ErrState) {
		t.Fatalf("second Greet = %v, want ErrState", err)
	}
}

// One user may not exceed its concurrent session quota, another user still
// can.
func TestPerUserSessionQuota(t *testing.T) {
	now := time.Unix(1700000000, 0)
	cfg := testConfig()
	cfg.MaxSessionsPerUser = 1
	g := mustGuard(t, cfg)
	mustSession(t, g, now)
	second := mustOpen(t, g, now)
	mustGreet(t, g, second.ID, now)
	if err := g.Authenticate(second.ID, userA, proofA, now); !errors.Is(err, taskpkg.ErrQuota) {
		t.Fatalf("second session for one user = %v, want ErrQuota", err)
	}
	third := mustOpen(t, g, now)
	mustGreet(t, g, third.ID, now)
	mustAuth(t, g, third.ID, userB, proofB, now)
}

// Destinations outside the allowlist must not be dialed.
func TestConnectRejectsPortNotAllowed(t *testing.T) {
	now := time.Unix(1700000000, 0)
	g := mustGuard(t, testConfig())
	s := mustSession(t, g, now)
	if _, err := g.Connect(s.ID, publicIP, 25, now); !errors.Is(err, taskpkg.ErrPort) {
		t.Fatalf("port 25 = %v, want ErrPort", err)
	}
	target, err := g.Connect(s.ID, publicIP, 443, now)
	if err != nil {
		t.Fatalf("Connect on an allowed port: %v", err)
	}
	if target.IP != publicIP || target.Port != 443 {
		t.Fatalf("target = %+v, want %s:443", target, publicIP)
	}
}

// Loopback and link-local destinations must be refused.
func TestConnectRejectsPrivateAddress(t *testing.T) {
	now := time.Unix(1700000000, 0)
	g := mustGuard(t, testConfig())
	s := mustSession(t, g, now)
	if _, err := g.Connect(s.ID, "127.0.0.1", 443, now); !errors.Is(err, taskpkg.ErrAddress) {
		t.Fatalf("loopback destination = %v, want ErrAddress", err)
	}
	if _, err := g.Connect(s.ID, "169.254.169.254", 443, now); !errors.Is(err, taskpkg.ErrAddress) {
		t.Fatalf("link-local destination = %v, want ErrAddress", err)
	}
}

// A hostname that starts resolving to an internal address must be refused
// even though an earlier session used it safely.
func TestConnectBlocksDNSRebinding(t *testing.T) {
	now := time.Unix(1700000000, 0)
	g := mustGuard(t, testConfig())
	calls := 0
	if err := g.SetResolver(func(host string) ([]string, error) {
		calls++
		if host != "rebind.example" {
			return nil, errors.New("unexpected host")
		}
		if calls == 1 {
			return []string{publicIP}, nil
		}
		return []string{"10.0.0.7"}, nil
	}); err != nil {
		t.Fatalf("SetResolver: %v", err)
	}
	first := mustSession(t, g, now)
	target, err := g.Connect(first.ID, "rebind.example", 443, now)
	if err != nil {
		t.Fatalf("first Connect: %v", err)
	}
	if target.IP != publicIP {
		t.Fatalf("first target IP = %q, want %q", target.IP, publicIP)
	}
	second := mustSession(t, g, now)
	if _, err := g.Connect(second.ID, "rebind.example", 443, now.Add(time.Second)); !errors.Is(err, taskpkg.ErrAddress) {
		t.Fatalf("rebinding hostname = %v, want ErrAddress", err)
	}
}

// Idle sessions are closed by Sweep and can no longer forward bytes.
func TestSweepClosesIdleSession(t *testing.T) {
	now := time.Unix(1700000000, 0)
	g := mustGuard(t, testConfig())
	s := mustSession(t, g, now)
	if _, err := g.Connect(s.ID, publicIP, 443, now); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	later := now.Add(61 * time.Second)
	if n := g.Sweep(later); n != 1 {
		t.Fatalf("Sweep closed %d sessions, want 1", n)
	}
	if err := g.Transfer(s.ID, 1, 1, later); !errors.Is(err, taskpkg.ErrState) {
		t.Fatalf("Transfer on a swept session = %v, want ErrState", err)
	}
	if got := g.Stats().Active; got != 0 {
		t.Fatalf("Stats().Active after sweep = %d, want 0", got)
	}
}

// The per-session byte budget must close the session instead of overflowing.
func TestTransferBudgetEnforced(t *testing.T) {
	now := time.Unix(1700000000, 0)
	cfg := testConfig()
	cfg.MaxBytesPerSession = 100
	g := mustGuard(t, cfg)
	s := mustSession(t, g, now)
	if _, err := g.Connect(s.ID, publicIP, 443, now); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if err := g.Transfer(s.ID, 60, 0, now); err != nil {
		t.Fatalf("first Transfer: %v", err)
	}
	if err := g.Transfer(s.ID, 0, 60, now); !errors.Is(err, taskpkg.ErrBudget) {
		t.Fatalf("Transfer beyond the budget = %v, want ErrBudget", err)
	}
	if err := g.Transfer(s.ID, 1, 0, now); !errors.Is(err, taskpkg.ErrState) {
		t.Fatalf("Transfer after the budget closed the session = %v, want ErrState", err)
	}
}

// Upload and download bytes must be accounted exactly, per session and in
// the totals.
func TestTransferAccounting(t *testing.T) {
	now := time.Unix(1700000000, 0)
	g := mustGuard(t, testConfig())
	s := mustSession(t, g, now)
	if _, err := g.Connect(s.ID, publicIP, 443, now); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if err := g.Transfer(s.ID, 30, 20, now); err != nil {
		t.Fatalf("first Transfer: %v", err)
	}
	if err := g.Transfer(s.ID, 40, 10, now); err != nil {
		t.Fatalf("second Transfer: %v", err)
	}
	stats := g.Stats()
	if stats.BytesUp != 70 || stats.BytesDown != 30 {
		t.Fatalf("Stats bytes = %d/%d, want 70/30", stats.BytesUp, stats.BytesDown)
	}
	if stats.Active != 1 {
		t.Fatalf("Stats().Active = %d, want 1", stats.Active)
	}
}

// A restarted guard must keep lockout state and counters.
func TestSnapshotPreservesLockoutAndCounters(t *testing.T) {
	now := time.Unix(1700000000, 0)
	cfg := testConfig()
	g := mustGuard(t, cfg)
	bad := mustOpen(t, g, now)
	mustGreet(t, g, bad.ID, now)
	for i := 0; i < 2; i++ {
		if err := g.Authenticate(bad.ID, userA, "wrong", now); !errors.Is(err, taskpkg.ErrAuth) {
			t.Fatalf("failure %d = %v, want ErrAuth", i+1, err)
		}
	}
	ok := mustSessionAs(t, g, userB, proofB, now)
	if _, err := g.Connect(ok.ID, publicIP, 443, now); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if err := g.Transfer(ok.ID, 30, 20, now); err != nil {
		t.Fatalf("Transfer: %v", err)
	}
	snap, err := g.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	restored, err := taskpkg.NewSocks5GuardFromSnapshot(cfg, snap)
	if err != nil {
		t.Fatalf("NewSocks5GuardFromSnapshot: %v", err)
	}
	stats := restored.Stats()
	if stats.AuthFails != 2 || stats.BytesUp != 30 || stats.BytesDown != 20 {
		t.Fatalf("restored stats = %+v, want 2 failures and 30/20 bytes", stats)
	}
	next := mustOpen(t, restored, now)
	mustGreet(t, restored, next.ID, now)
	if err := restored.Authenticate(next.ID, userA, "wrong", now); !errors.Is(err, taskpkg.ErrAuth) {
		t.Fatalf("third failure after restart = %v, want ErrAuth", err)
	}
	if err := restored.Authenticate(next.ID, userA, proofA, now); !errors.Is(err, taskpkg.ErrLocked) {
		t.Fatalf("locked user after restart = %v, want ErrLocked", err)
	}
}

// Two CONNECT calls racing on one session must not both win.
func TestConcurrentConnectSingleWinner(t *testing.T) {
	now := time.Unix(1700000000, 0)
	g := mustGuard(t, testConfig())
	s := mustSession(t, g, now)
	errs := make([]error, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, errs[0] = g.Connect(s.ID, publicIP, 443, now)
	}()
	go func() {
		defer wg.Done()
		_, errs[1] = g.Connect(s.ID, publicIP, 443, now)
	}()
	wg.Wait()
	successes := 0
	for _, err := range errs {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent CONNECTs: %d succeeded, want exactly 1", successes)
	}
	if got := g.Stats().Active; got != 1 {
		t.Fatalf("Stats().Active = %d, want 1", got)
	}
}
