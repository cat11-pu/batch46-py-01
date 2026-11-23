package task

import (
	"errors"
	"sync"
	"testing"
	"time"

	taskpkg "gsb/batch46-safety-b-09"
)

const testPIN = "4821"

func hsmConfig() taskpkg.Config {
	return taskpkg.Config{
		MaxLoginAttempts:     3,
		HandleTTL:            time.Minute,
		MaxHandlesPerSession: 4,
		OpsPerRotation:       4,
	}
}

func rsaKey(tenantID string) taskpkg.KeyInfo {
	return taskpkg.KeyInfo{TenantID: tenantID, Label: "deploy-rsa", Type: "rsa2048", Ops: []string{"sign", "verify"}}
}

func aesKey(tenantID string) taskpkg.KeyInfo {
	return taskpkg.KeyInfo{TenantID: tenantID, Label: "wrap-aes", Type: "aes256", Ops: []string{"encrypt", "decrypt"}}
}

func newGuard(t *testing.T, cfg taskpkg.Config) *taskpkg.HsmSessionGuard {
	t.Helper()
	g := taskpkg.NewHsmSessionGuard(cfg)
	if g == nil {
		t.Fatal("NewHsmSessionGuard returned nil")
	}
	return g
}

func prepareTenant(t *testing.T, g *taskpkg.HsmSessionGuard, tenantID, sessionID string, now time.Time) {
	t.Helper()
	if err := g.SetPIN(tenantID, testPIN); err != nil {
		t.Fatalf("SetPIN: %v", err)
	}
	if err := g.ProvisionKey(rsaKey(tenantID)); err != nil {
		t.Fatalf("ProvisionKey(rsa): %v", err)
	}
	if err := g.ProvisionKey(aesKey(tenantID)); err != nil {
		t.Fatalf("ProvisionKey(aes): %v", err)
	}
	if err := g.OpenSession(tenantID, sessionID, now); err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
}

func mustLogin(t *testing.T, g *taskpkg.HsmSessionGuard, tenantID, sessionID string, now time.Time) {
	t.Helper()
	if err := g.Login(tenantID, sessionID, testPIN, now); err != nil {
		t.Fatalf("Login: %v", err)
	}
}

func mustOpenKey(t *testing.T, g *taskpkg.HsmSessionGuard, tenantID, sessionID, label string, now time.Time) taskpkg.Handle {
	t.Helper()
	h, err := g.OpenKey(tenantID, sessionID, label, now)
	if err != nil {
		t.Fatalf("OpenKey(%s): %v", label, err)
	}
	if h.ID == "" {
		t.Fatalf("OpenKey(%s) returned an empty handle ID", label)
	}
	return h
}

func mustPerform(t *testing.T, g *taskpkg.HsmSessionGuard, tenantID, sessionID, handleID, op string, now time.Time) taskpkg.OpResult {
	t.Helper()
	res, err := g.Perform(tenantID, sessionID, handleID, op, now)
	if err != nil {
		t.Fatalf("Perform(%s): %v", op, err)
	}
	return res
}

// Operations must be refused until the session logs in.
func TestPerformWithoutLoginRejected(t *testing.T) {
	now := time.Unix(1726700000, 0)
	g := newGuard(t, hsmConfig())
	prepareTenant(t, g, "tenant-a", "sess-1", now)
	if _, err := g.Perform("tenant-a", "sess-1", "h-unknown", "sign", now); !errors.Is(err, taskpkg.ErrNotLoggedIn) {
		t.Fatalf("Perform before login: got %v, want ErrNotLoggedIn", err)
	}
}

// Consecutive bad PINs lock the session, and the lock also blocks the correct
// PIN.
func TestWrongPINCountsAndLocks(t *testing.T) {
	now := time.Unix(1726700000, 0)
	g := newGuard(t, hsmConfig())
	prepareTenant(t, g, "tenant-a", "sess-lock", now)
	for i := 0; i < 3; i++ {
		if err := g.Login("tenant-a", "sess-lock", "0000", now); !errors.Is(err, taskpkg.ErrPINInvalid) {
			t.Fatalf("bad PIN attempt %d: got %v, want ErrPINInvalid", i+1, err)
		}
	}
	if err := g.Login("tenant-a", "sess-lock", testPIN, now); !errors.Is(err, taskpkg.ErrPINLocked) {
		t.Fatalf("correct PIN on a locked session: got %v, want ErrPINLocked", err)
	}
}

// A successful login resets the bad PIN counter.
func TestLoginResetsAttempts(t *testing.T) {
	now := time.Unix(1726700000, 0)
	g := newGuard(t, hsmConfig())
	prepareTenant(t, g, "tenant-a", "sess-reset", now)
	for round := 0; round < 2; round++ {
		if err := g.Login("tenant-a", "sess-reset", "1111", now); !errors.Is(err, taskpkg.ErrPINInvalid) {
			t.Fatalf("round %d bad PIN 1: got %v, want ErrPINInvalid", round, err)
		}
		if err := g.Login("tenant-a", "sess-reset", "2222", now); !errors.Is(err, taskpkg.ErrPINInvalid) {
			t.Fatalf("round %d bad PIN 2: got %v, want ErrPINInvalid", round, err)
		}
		mustLogin(t, g, "tenant-a", "sess-reset", now)
	}
}

// Opening a key returns a session-bound handle, and performing an operation on
// it counts once in the session.
func TestOpenKeyAndPerform(t *testing.T) {
	now := time.Unix(1726700000, 0)
	g := newGuard(t, hsmConfig())
	prepareTenant(t, g, "tenant-a", "sess-ok", now)
	mustLogin(t, g, "tenant-a", "sess-ok", now)
	h := mustOpenKey(t, g, "tenant-a", "sess-ok", "deploy-rsa", now)
	if h.KeyLabel != "deploy-rsa" || h.TenantID != "tenant-a" {
		t.Fatalf("Handle=%+v, want label deploy-rsa of tenant-a", h)
	}
	res := mustPerform(t, g, "tenant-a", "sess-ok", h.ID, "sign", now)
	if res.Ops != 1 {
		t.Fatalf("OpResult.Ops=%d, want 1", res.Ops)
	}
	if res.Rotated {
		t.Fatal("first operation rotated the handle")
	}
	if res.Handle != h.ID {
		t.Fatalf("OpResult.Handle=%q, want the original handle %q", res.Handle, h.ID)
	}
	ops, err := g.SessionOps("tenant-a", "sess-ok")
	if err != nil {
		t.Fatalf("SessionOps: %v", err)
	}
	if ops != 1 {
		t.Fatalf("SessionOps=%d, want 1", ops)
	}
}

// A key only performs the operations it was provisioned for, and a refused
// operation must not be counted.
func TestOpNotAllowedForKey(t *testing.T) {
	now := time.Unix(1726700000, 0)
	g := newGuard(t, hsmConfig())
	prepareTenant(t, g, "tenant-a", "sess-op", now)
	mustLogin(t, g, "tenant-a", "sess-op", now)
	h := mustOpenKey(t, g, "tenant-a", "sess-op", "wrap-aes", now)
	if _, err := g.Perform("tenant-a", "sess-op", h.ID, "sign", now); !errors.Is(err, taskpkg.ErrOpNotAllowed) {
		t.Fatalf("sign with an aes key: got %v, want ErrOpNotAllowed", err)
	}
	ops, err := g.SessionOps("tenant-a", "sess-op")
	if err != nil {
		t.Fatalf("SessionOps: %v", err)
	}
	if ops != 0 {
		t.Fatalf("SessionOps=%d after a refused operation, want 0", ops)
	}
}

// A handle must not be usable from another session.
func TestHandleSessionIsolation(t *testing.T) {
	now := time.Unix(1726700000, 0)
	g := newGuard(t, hsmConfig())
	prepareTenant(t, g, "tenant-a", "sess-a", now)
	if err := g.OpenSession("tenant-a", "sess-b", now); err != nil {
		t.Fatalf("OpenSession(sess-b): %v", err)
	}
	mustLogin(t, g, "tenant-a", "sess-a", now)
	mustLogin(t, g, "tenant-a", "sess-b", now)
	h := mustOpenKey(t, g, "tenant-a", "sess-a", "deploy-rsa", now)
	if _, err := g.Perform("tenant-a", "sess-b", h.ID, "sign", now); !errors.Is(err, taskpkg.ErrCrossSession) {
		t.Fatalf("handle used from another session: got %v, want ErrCrossSession", err)
	}
}

// A handle past its TTL is stale, not silently accepted.
func TestHandleExpiry(t *testing.T) {
	now := time.Unix(1726700000, 0)
	g := newGuard(t, hsmConfig())
	prepareTenant(t, g, "tenant-a", "sess-ttl", now)
	mustLogin(t, g, "tenant-a", "sess-ttl", now)
	h := mustOpenKey(t, g, "tenant-a", "sess-ttl", "deploy-rsa", now)
	if _, err := g.Perform("tenant-a", "sess-ttl", h.ID, "sign", now.Add(2*time.Minute)); !errors.Is(err, taskpkg.ErrHandleStale) {
		t.Fatalf("expired handle: got %v, want ErrHandleStale", err)
	}
}

// After OpsPerRotation operations the handle is rotated, the old one is dead
// immediately and the returned one keeps working.
func TestRotationAfterOps(t *testing.T) {
	now := time.Unix(1726700000, 0)
	cfg := hsmConfig()
	cfg.OpsPerRotation = 3
	g := newGuard(t, cfg)
	prepareTenant(t, g, "tenant-a", "sess-rot", now)
	mustLogin(t, g, "tenant-a", "sess-rot", now)
	h := mustOpenKey(t, g, "tenant-a", "sess-rot", "deploy-rsa", now)
	first := mustPerform(t, g, "tenant-a", "sess-rot", h.ID, "sign", now)
	if first.Rotated || first.Ops != 1 {
		t.Fatalf("first op: %+v, want Ops=1 and no rotation", first)
	}
	second := mustPerform(t, g, "tenant-a", "sess-rot", h.ID, "verify", now)
	if second.Rotated || second.Ops != 2 {
		t.Fatalf("second op: %+v, want Ops=2 and no rotation", second)
	}
	third := mustPerform(t, g, "tenant-a", "sess-rot", h.ID, "sign", now)
	if !third.Rotated {
		t.Fatalf("third op: %+v, want rotation", third)
	}
	if third.Ops != 3 {
		t.Fatalf("third op Ops=%d, want 3", third.Ops)
	}
	if third.Handle == h.ID {
		t.Fatalf("rotated handle kept the old ID %q", h.ID)
	}
	if _, err := g.Perform("tenant-a", "sess-rot", h.ID, "sign", now); !errors.Is(err, taskpkg.ErrHandleStale) {
		t.Fatalf("old handle after rotation: got %v, want ErrHandleStale", err)
	}
	fourth := mustPerform(t, g, "tenant-a", "sess-rot", third.Handle, "sign", now)
	if fourth.Ops != 4 || fourth.Rotated {
		t.Fatalf("new handle op: %+v, want Ops=4 and no rotation", fourth)
	}
}

// Two racing operations on a handle that rotates after one use: exactly one
// may succeed.
func TestConcurrentOpsAtRotationBoundary(t *testing.T) {
	now := time.Unix(1726700000, 0)
	cfg := hsmConfig()
	cfg.OpsPerRotation = 1
	g := newGuard(t, cfg)
	prepareTenant(t, g, "tenant-a", "sess-race", now)
	mustLogin(t, g, "tenant-a", "sess-race", now)
	h := mustOpenKey(t, g, "tenant-a", "sess-race", "deploy-rsa", now)
	var wg sync.WaitGroup
	var mu sync.Mutex
	successes := 0
	wg.Add(2)
	for i := 0; i < 2; i++ {
		go func() {
			defer wg.Done()
			if _, err := g.Perform("tenant-a", "sess-race", h.ID, "sign", now); err == nil {
				mu.Lock()
				successes++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if successes != 1 {
		t.Fatalf("concurrent operations on a rotating handle: %d successes, want exactly 1", successes)
	}
	ops, err := g.SessionOps("tenant-a", "sess-race")
	if err != nil {
		t.Fatalf("SessionOps: %v", err)
	}
	if ops != 1 {
		t.Fatalf("SessionOps=%d, want 1", ops)
	}
}

// The per-session handle budget applies and a closed handle frees a slot.
func TestHandleLimit(t *testing.T) {
	now := time.Unix(1726700000, 0)
	cfg := hsmConfig()
	cfg.MaxHandlesPerSession = 2
	g := newGuard(t, cfg)
	prepareTenant(t, g, "tenant-a", "sess-cap", now)
	mustLogin(t, g, "tenant-a", "sess-cap", now)
	first := mustOpenKey(t, g, "tenant-a", "sess-cap", "deploy-rsa", now)
	mustOpenKey(t, g, "tenant-a", "sess-cap", "wrap-aes", now)
	if _, err := g.OpenKey("tenant-a", "sess-cap", "deploy-rsa", now); !errors.Is(err, taskpkg.ErrHandleLimit) {
		t.Fatalf("third handle in a two-handle session: got %v, want ErrHandleLimit", err)
	}
	if err := g.CloseHandle("tenant-a", "sess-cap", first.ID); err != nil {
		t.Fatalf("CloseHandle: %v", err)
	}
	mustOpenKey(t, g, "tenant-a", "sess-cap", "deploy-rsa", now)
}

// A closed session rejects operations, key opening and counter queries.
func TestClosedSessionRejects(t *testing.T) {
	now := time.Unix(1726700000, 0)
	g := newGuard(t, hsmConfig())
	prepareTenant(t, g, "tenant-a", "sess-close", now)
	mustLogin(t, g, "tenant-a", "sess-close", now)
	h := mustOpenKey(t, g, "tenant-a", "sess-close", "deploy-rsa", now)
	if err := g.CloseSession("tenant-a", "sess-close"); err != nil {
		t.Fatalf("CloseSession: %v", err)
	}
	if _, err := g.Perform("tenant-a", "sess-close", h.ID, "sign", now); !errors.Is(err, taskpkg.ErrSessionClosed) {
		t.Fatalf("Perform after close: got %v, want ErrSessionClosed", err)
	}
	if _, err := g.OpenKey("tenant-a", "sess-close", "deploy-rsa", now); !errors.Is(err, taskpkg.ErrSessionClosed) {
		t.Fatalf("OpenKey after close: got %v, want ErrSessionClosed", err)
	}
	if _, err := g.SessionOps("tenant-a", "sess-close"); !errors.Is(err, taskpkg.ErrSessionClosed) {
		t.Fatalf("SessionOps after close: got %v, want ErrSessionClosed", err)
	}
}

// Keys are tenant scoped; another tenant's label must look unknown.
func TestCrossTenantKeyNotVisible(t *testing.T) {
	now := time.Unix(1726700000, 0)
	g := newGuard(t, hsmConfig())
	prepareTenant(t, g, "tenant-a", "sess-a", now)
	if err := g.SetPIN("tenant-b", testPIN); err != nil {
		t.Fatalf("SetPIN tenant-b: %v", err)
	}
	if err := g.OpenSession("tenant-b", "sess-b", now); err != nil {
		t.Fatalf("OpenSession tenant-b: %v", err)
	}
	mustLogin(t, g, "tenant-b", "sess-b", now)
	if _, err := g.OpenKey("tenant-b", "sess-b", "deploy-rsa", now); !errors.Is(err, taskpkg.ErrKeyUnknown) {
		t.Fatalf("OpenKey for another tenant's label: got %v, want ErrKeyUnknown", err)
	}
}

// A refused operation must not count towards the rotation threshold.
func TestFailedOpDoesNotConsumeRotation(t *testing.T) {
	now := time.Unix(1726700000, 0)
	cfg := hsmConfig()
	cfg.OpsPerRotation = 2
	g := newGuard(t, cfg)
	prepareTenant(t, g, "tenant-a", "sess-mix", now)
	mustLogin(t, g, "tenant-a", "sess-mix", now)
	rsa := mustOpenKey(t, g, "tenant-a", "sess-mix", "deploy-rsa", now)
	aes := mustOpenKey(t, g, "tenant-a", "sess-mix", "wrap-aes", now)
	if _, err := g.Perform("tenant-a", "sess-mix", aes.ID, "sign", now); !errors.Is(err, taskpkg.ErrOpNotAllowed) {
		t.Fatalf("sign with aes key: got %v, want ErrOpNotAllowed", err)
	}
	first := mustPerform(t, g, "tenant-a", "sess-mix", rsa.ID, "sign", now)
	if first.Rotated || first.Ops != 1 {
		t.Fatalf("first valid op: %+v, want Ops=1 and no rotation", first)
	}
	second := mustPerform(t, g, "tenant-a", "sess-mix", rsa.ID, "verify", now)
	if !second.Rotated {
		t.Fatalf("second valid op: %+v, want rotation at OpsPerRotation=2", second)
	}
}

// A snapshot restores counters and keys but never login state or handles.
func TestSnapshotDropsLoginButKeepsCounters(t *testing.T) {
	now := time.Unix(1726700000, 0)
	cfg := hsmConfig()
	g := newGuard(t, cfg)
	prepareTenant(t, g, "tenant-a", "sess-persist", now)
	mustLogin(t, g, "tenant-a", "sess-persist", now)
	h := mustOpenKey(t, g, "tenant-a", "sess-persist", "deploy-rsa", now)
	mustPerform(t, g, "tenant-a", "sess-persist", h.ID, "sign", now)
	snap, err := g.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	restored, err := taskpkg.NewHsmSessionGuardFromSnapshot(cfg, snap)
	if err != nil {
		t.Fatalf("NewHsmSessionGuardFromSnapshot: %v", err)
	}
	if _, err := restored.Perform("tenant-a", "sess-persist", h.ID, "sign", now); !errors.Is(err, taskpkg.ErrNotLoggedIn) {
		t.Fatalf("Perform on a restored session: got %v, want ErrNotLoggedIn", err)
	}
	mustLogin(t, restored, "tenant-a", "sess-persist", now)
	ops, err := restored.SessionOps("tenant-a", "sess-persist")
	if err != nil {
		t.Fatalf("SessionOps after restore: %v", err)
	}
	if ops != 1 {
		t.Fatalf("SessionOps after restore=%d, want 1", ops)
	}
	h2 := mustOpenKey(t, restored, "tenant-a", "sess-persist", "deploy-rsa", now)
	res := mustPerform(t, restored, "tenant-a", "sess-persist", h2.ID, "sign", now)
	if res.Ops != 2 {
		t.Fatalf("OpResult.Ops after restore=%d, want 2", res.Ops)
	}
}

// Handle identifiers must never repeat, including after a restart.
func TestSnapshotDoesNotReuseHandles(t *testing.T) {
	now := time.Unix(1726700000, 0)
	cfg := hsmConfig()
	cfg.OpsPerRotation = 1
	g := newGuard(t, cfg)
	prepareTenant(t, g, "tenant-a", "sess-epoch", now)
	mustLogin(t, g, "tenant-a", "sess-epoch", now)
	first := mustOpenKey(t, g, "tenant-a", "sess-epoch", "deploy-rsa", now)
	rotated := mustPerform(t, g, "tenant-a", "sess-epoch", first.ID, "sign", now)
	if !rotated.Rotated || rotated.Handle == first.ID {
		t.Fatalf("first rotation: %+v, want a new handle", rotated)
	}
	snap, err := g.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	restored, err := taskpkg.NewHsmSessionGuardFromSnapshot(cfg, snap)
	if err != nil {
		t.Fatalf("NewHsmSessionGuardFromSnapshot: %v", err)
	}
	mustLogin(t, restored, "tenant-a", "sess-epoch", now)
	if _, err := restored.Perform("tenant-a", "sess-epoch", rotated.Handle, "sign", now); !errors.Is(err, taskpkg.ErrHandleInvalid) {
		t.Fatalf("pre-restart handle: got %v, want ErrHandleInvalid", err)
	}
	open := mustOpenKey(t, restored, "tenant-a", "sess-epoch", "deploy-rsa", now)
	if open.ID == first.ID || open.ID == rotated.Handle {
		t.Fatalf("handle ID %q was reused after restart", open.ID)
	}
	next := mustPerform(t, restored, "tenant-a", "sess-epoch", open.ID, "sign", now)
	if !next.Rotated || next.Handle == open.ID {
		t.Fatalf("post-restart rotation: %+v, want a fresh handle", next)
	}
	again := mustPerform(t, restored, "tenant-a", "sess-epoch", next.Handle, "sign", now)
	if again.Ops != 3 {
		t.Fatalf("OpResult.Ops=%d, want 3", again.Ops)
	}
	if again.Handle == next.Handle || again.Handle == open.ID || again.Handle == rotated.Handle {
		t.Fatalf("rotated handle %q collided with an earlier handle", again.Handle)
	}
}
