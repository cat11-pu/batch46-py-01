package task

import (
	"errors"
	"sync"
	"testing"
	"time"

	taskpkg "gsb/batch46-safety-b-07"
)

func quoteConfig() taskpkg.Config {
	return taskpkg.Config{
		MaxQuoteAge:     2 * time.Minute,
		NonceTTL:        time.Minute,
		MaxPCRsPerQuote: 4,
	}
}

func pcrSet() map[int]string {
	return map[int]string{0: "aa11", 7: "bb22"}
}

func newGuard(t *testing.T, cfg taskpkg.Config) *taskpkg.TpmQuoteGuard {
	t.Helper()
	g := taskpkg.NewTpmQuoteGuard(cfg)
	if g == nil {
		t.Fatal("NewTpmQuoteGuard returned nil")
	}
	return g
}

// setupNode registers the AK and the golden PCR set for node-01 of tenant-a.
func setupNode(t *testing.T, g *taskpkg.TpmQuoteGuard) {
	t.Helper()
	if err := g.RegisterAK(taskpkg.AK{Name: "ak-node-01", TenantID: "tenant-a", PublicHash: "sha256:9f2c"}); err != nil {
		t.Fatalf("RegisterAK: %v", err)
	}
	if err := g.SetPolicy(taskpkg.PCRPolicy{TenantID: "tenant-a", NodeID: "node-01", Expected: pcrSet()}); err != nil {
		t.Fatalf("SetPolicy: %v", err)
	}
}

func newQuote(t *testing.T, g *taskpkg.TpmQuoteGuard, now time.Time, tenantID, nodeID string, clock uint64) taskpkg.Quote {
	t.Helper()
	nonce, err := g.IssueNonce(tenantID, nodeID, now)
	if err != nil {
		t.Fatalf("IssueNonce(%s/%s): %v", tenantID, nodeID, err)
	}
	return taskpkg.Quote{
		TenantID:       tenantID,
		NodeID:         nodeID,
		AKName:         "ak-node-01",
		Nonce:          nonce,
		Firmware:       "fw-2.14.0",
		Clock:          clock,
		AttestedAt:     now,
		SignatureValid: true,
		PCRs:           pcrSet(),
	}
}

func mustVerify(t *testing.T, g *taskpkg.TpmQuoteGuard, q taskpkg.Quote, now time.Time) taskpkg.Verdict {
	t.Helper()
	v, err := g.Verify(q, now)
	if err != nil {
		t.Fatalf("Verify(node=%s): %v", q.NodeID, err)
	}
	return v
}

// A quote that satisfies every rule is recorded and counted.
func TestValidQuoteAccepted(t *testing.T) {
	now := time.Unix(1726500000, 0)
	g := newGuard(t, quoteConfig())
	setupNode(t, g)
	v := mustVerify(t, g, newQuote(t, g, now, "tenant-a", "node-01", 1000), now)
	if v.NodeID != "node-01" {
		t.Fatalf("Verdict.NodeID=%q, want node-01", v.NodeID)
	}
	if v.Firmware != "fw-2.14.0" {
		t.Fatalf("Verdict.Firmware=%q, want fw-2.14.0", v.Firmware)
	}
	if v.Clock != 1000 {
		t.Fatalf("Verdict.Clock=%d, want 1000", v.Clock)
	}
	if v.PCRsChecked != 2 {
		t.Fatalf("Verdict.PCRsChecked=%d, want 2", v.PCRsChecked)
	}
	if !v.At.Equal(now) {
		t.Fatalf("Verdict.At=%v, want %v", v.At, now)
	}
	stored, err := g.LastVerdict("tenant-a", "node-01")
	if err != nil {
		t.Fatalf("LastVerdict: %v", err)
	}
	if stored.Clock != 1000 || stored.NodeID != "node-01" {
		t.Fatalf("LastVerdict=%+v, want the verdict just returned", stored)
	}
	if n := g.Evaluations(); n != 1 {
		t.Fatalf("Evaluations=%d, want 1", n)
	}
}

// A nonce the service never issued must be refused.
func TestUnknownNonceRejected(t *testing.T) {
	now := time.Unix(1726500000, 0)
	g := newGuard(t, quoteConfig())
	setupNode(t, g)
	q := newQuote(t, g, now, "tenant-a", "node-01", 1000)
	q.Nonce = "nonce-from-nowhere"
	if _, err := g.Verify(q, now); !errors.Is(err, taskpkg.ErrNonceUnknown) {
		t.Fatalf("Verify with an unissued nonce: got %v, want ErrNonceUnknown", err)
	}
}

// A nonce is bound to the node it was issued for, and a node without a policy
// cannot be verified at all.
func TestNonceBoundToNodeAndPolicyRequired(t *testing.T) {
	now := time.Unix(1726500000, 0)
	g := newGuard(t, quoteConfig())
	setupNode(t, g)
	q := newQuote(t, g, now, "tenant-a", "node-01", 1000)
	foreign, err := g.IssueNonce("tenant-a", "node-02", now)
	if err != nil {
		t.Fatalf("IssueNonce(node-02): %v", err)
	}
	q.Nonce = foreign
	if _, err := g.Verify(q, now); !errors.Is(err, taskpkg.ErrNonceUnknown) {
		t.Fatalf("nonce issued to another node: got %v, want ErrNonceUnknown", err)
	}
	if _, err := g.Verify(newQuote(t, g, now, "tenant-a", "node-03", 1000), now); !errors.Is(err, taskpkg.ErrPolicyMissing) {
		t.Fatalf("node without policy: got %v, want ErrPolicyMissing", err)
	}
}

// The same nonce must not be accepted twice.
func TestReplayedNonceRejected(t *testing.T) {
	now := time.Unix(1726500000, 0)
	g := newGuard(t, quoteConfig())
	setupNode(t, g)
	q := newQuote(t, g, now, "tenant-a", "node-01", 1000)
	mustVerify(t, g, q, now)
	if _, err := g.Verify(q, now); !errors.Is(err, taskpkg.ErrNonceReplay) {
		t.Fatalf("replayed nonce: got %v, want ErrNonceReplay", err)
	}
}

// A nonce past its TTL is unknown, not a replay.
func TestExpiredNonceRejected(t *testing.T) {
	now := time.Unix(1726500000, 0)
	g := newGuard(t, quoteConfig())
	setupNode(t, g)
	q := newQuote(t, g, now, "tenant-a", "node-01", 1000)
	if _, err := g.Verify(q, now.Add(2*time.Minute)); !errors.Is(err, taskpkg.ErrNonceUnknown) {
		t.Fatalf("nonce past NonceTTL: got %v, want ErrNonceUnknown", err)
	}
}

// One altered PCR digest must fail the whole quote and leave no verdict.
func TestPCRMismatchRejected(t *testing.T) {
	now := time.Unix(1726500000, 0)
	g := newGuard(t, quoteConfig())
	setupNode(t, g)
	q := newQuote(t, g, now, "tenant-a", "node-01", 1000)
	q.PCRs[7] = "cc33"
	if _, err := g.Verify(q, now); !errors.Is(err, taskpkg.ErrPCRMismatch) {
		t.Fatalf("altered PCR 7: got %v, want ErrPCRMismatch", err)
	}
	if _, err := g.LastVerdict("tenant-a", "node-01"); !errors.Is(err, taskpkg.ErrNoVerdict) {
		t.Fatalf("LastVerdict after a failed quote: got %v, want ErrNoVerdict", err)
	}
	if n := g.Evaluations(); n != 0 {
		t.Fatalf("Evaluations after a failed quote=%d, want 0", n)
	}
}

// A policy PCR missing from the quote must fail even if the other digests
// match.
func TestMissingPCRRejected(t *testing.T) {
	now := time.Unix(1726500000, 0)
	g := newGuard(t, quoteConfig())
	setupNode(t, g)
	q := newQuote(t, g, now, "tenant-a", "node-01", 1000)
	delete(q.PCRs, 7)
	if _, err := g.Verify(q, now); !errors.Is(err, taskpkg.ErrPCRMismatch) {
		t.Fatalf("quote missing a policy PCR: got %v, want ErrPCRMismatch", err)
	}
}

// One quote may not carry more PCR entries than the configured budget.
func TestTooManyPCRsRejected(t *testing.T) {
	now := time.Unix(1726500000, 0)
	cfg := quoteConfig()
	cfg.MaxPCRsPerQuote = 2
	g := newGuard(t, cfg)
	setupNode(t, g)
	q := newQuote(t, g, now, "tenant-a", "node-01", 1000)
	q.PCRs[4] = "dd44"
	if _, err := g.Verify(q, now); !errors.Is(err, taskpkg.ErrQuoteInvalid) {
		t.Fatalf("quote above MaxPCRsPerQuote: got %v, want ErrQuoteInvalid", err)
	}
}

// AK registration is single-shot per name and revocation is permanent.
func TestAKRegistrationAndRevocation(t *testing.T) {
	now := time.Unix(1726500000, 0)
	g := newGuard(t, quoteConfig())
	setupNode(t, g)
	if err := g.RegisterAK(taskpkg.AK{Name: "ak-node-01", TenantID: "tenant-a", PublicHash: "sha256:other"}); !errors.Is(err, taskpkg.ErrAKDuplicate) {
		t.Fatalf("duplicate RegisterAK: got %v, want ErrAKDuplicate", err)
	}
	if err := g.RegisterAK(taskpkg.AK{Name: "", TenantID: "tenant-a"}); !errors.Is(err, taskpkg.ErrQuoteInvalid) {
		t.Fatalf("RegisterAK with an empty name: got %v, want ErrQuoteInvalid", err)
	}
	if err := g.RevokeAK("tenant-a", "ak-node-01"); err != nil {
		t.Fatalf("RevokeAK: %v", err)
	}
	if _, err := g.Verify(newQuote(t, g, now, "tenant-a", "node-01", 1000), now); !errors.Is(err, taskpkg.ErrAKRevoked) {
		t.Fatalf("quote signed by a revoked AK: got %v, want ErrAKRevoked", err)
	}
}

// An AK of another tenant must be reported as a tenant mismatch rather than as
// an unknown key.
func TestCrossTenantAKRejected(t *testing.T) {
	now := time.Unix(1726500000, 0)
	g := newGuard(t, quoteConfig())
	setupNode(t, g)
	if err := g.RegisterAK(taskpkg.AK{Name: "ak-node-04", TenantID: "tenant-b", PublicHash: "sha256:77ab"}); err != nil {
		t.Fatalf("RegisterAK tenant-b: %v", err)
	}
	q := taskpkg.Quote{
		TenantID:       "tenant-a",
		NodeID:         "node-04",
		AKName:         "ak-node-04",
		Nonce:          "irrelevant",
		Firmware:       "fw-2.14.0",
		Clock:          1000,
		AttestedAt:     now,
		SignatureValid: true,
		PCRs:           pcrSet(),
	}
	if _, err := g.Verify(q, now); !errors.Is(err, taskpkg.ErrTenantMismatch) {
		t.Fatalf("quote naming another tenant's AK: got %v, want ErrTenantMismatch", err)
	}
}

// Attestations older or newer than the freshness window are stale.
func TestStaleQuoteRejected(t *testing.T) {
	now := time.Unix(1726500000, 0)
	g := newGuard(t, quoteConfig())
	setupNode(t, g)
	old := newQuote(t, g, now, "tenant-a", "node-01", 1000)
	old.AttestedAt = now.Add(-10 * time.Minute)
	if _, err := g.Verify(old, now); !errors.Is(err, taskpkg.ErrQuoteStale) {
		t.Fatalf("10 minute old quote: got %v, want ErrQuoteStale", err)
	}
	future := newQuote(t, g, now, "tenant-a", "node-01", 1000)
	future.AttestedAt = now.Add(5 * time.Minute)
	if _, err := g.Verify(future, now); !errors.Is(err, taskpkg.ErrQuoteStale) {
		t.Fatalf("quote from the future: got %v, want ErrQuoteStale", err)
	}
}

// The TPM clock of a node must move strictly forward between accepted quotes.
func TestClockRollbackRejected(t *testing.T) {
	now := time.Unix(1726500000, 0)
	g := newGuard(t, quoteConfig())
	setupNode(t, g)
	mustVerify(t, g, newQuote(t, g, now, "tenant-a", "node-01", 1000), now)
	if _, err := g.Verify(newQuote(t, g, now, "tenant-a", "node-01", 999), now); !errors.Is(err, taskpkg.ErrClockRollback) {
		t.Fatalf("quote with a lower clock: got %v, want ErrClockRollback", err)
	}
	stored, err := g.LastVerdict("tenant-a", "node-01")
	if err != nil {
		t.Fatalf("LastVerdict: %v", err)
	}
	if stored.Clock != 1000 {
		t.Fatalf("LastVerdict.Clock=%d after a rollback attempt, want 1000", stored.Clock)
	}
}

// Two concurrent submissions of one nonce must yield exactly one verdict.
func TestConcurrentNonceSingleUse(t *testing.T) {
	now := time.Unix(1726500000, 0)
	g := newGuard(t, quoteConfig())
	setupNode(t, g)
	q := newQuote(t, g, now, "tenant-a", "node-01", 1000)
	var wg sync.WaitGroup
	var mu sync.Mutex
	successes := 0
	wg.Add(2)
	for i := 0; i < 2; i++ {
		go func() {
			defer wg.Done()
			if _, err := g.Verify(q, now); err == nil {
				mu.Lock()
				successes++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if successes != 1 {
		t.Fatalf("concurrent verifies of one nonce: %d successes, want exactly 1", successes)
	}
}

// Used nonces, clock baselines and the evaluation counter survive a restart.
func TestSnapshotKeepsNonceAndClock(t *testing.T) {
	now := time.Unix(1726500000, 0)
	cfg := quoteConfig()
	g := newGuard(t, cfg)
	setupNode(t, g)
	q := newQuote(t, g, now, "tenant-a", "node-01", 1000)
	mustVerify(t, g, q, now)
	snap, err := g.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	restored, err := taskpkg.NewTpmQuoteGuardFromSnapshot(cfg, snap)
	if err != nil {
		t.Fatalf("NewTpmQuoteGuardFromSnapshot: %v", err)
	}
	if n := restored.Evaluations(); n != 1 {
		t.Fatalf("Evaluations after restore=%d, want 1", n)
	}
	if _, err := restored.Verify(q, now); !errors.Is(err, taskpkg.ErrNonceReplay) {
		t.Fatalf("replayed nonce after restore: got %v, want ErrNonceReplay", err)
	}
	if _, err := restored.Verify(newQuote(t, restored, now, "tenant-a", "node-01", 999), now); !errors.Is(err, taskpkg.ErrClockRollback) {
		t.Fatalf("rolled back clock after restore: got %v, want ErrClockRollback", err)
	}
}

// A rejected quote must not consume its nonce nor move the clock baseline.
func TestFailedQuoteDoesNotPoisonState(t *testing.T) {
	now := time.Unix(1726500000, 0)
	g := newGuard(t, quoteConfig())
	setupNode(t, g)
	q := newQuote(t, g, now, "tenant-a", "node-01", 1000)
	q.PCRs[0] = "ffff"
	if _, err := g.Verify(q, now); !errors.Is(err, taskpkg.ErrPCRMismatch) {
		t.Fatalf("bad PCR quote: got %v, want ErrPCRMismatch", err)
	}
	if _, err := g.LastVerdict("tenant-a", "node-01"); !errors.Is(err, taskpkg.ErrNoVerdict) {
		t.Fatalf("LastVerdict after a rejected quote: got %v, want ErrNoVerdict", err)
	}
	q.PCRs[0] = "aa11"
	mustVerify(t, g, q, now)
	if _, err := g.Verify(newQuote(t, g, now, "tenant-a", "node-01", 900), now); !errors.Is(err, taskpkg.ErrClockRollback) {
		t.Fatalf("clock below the accepted baseline: got %v, want ErrClockRollback", err)
	}
	if n := g.Evaluations(); n != 1 {
		t.Fatalf("Evaluations=%d, want 1", n)
	}
}
