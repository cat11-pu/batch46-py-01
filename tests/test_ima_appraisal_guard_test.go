package task

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	taskpkg "gsb/batch46-safety-b-08"
)

func imaConfig() taskpkg.Config {
	return taskpkg.Config{
		ViolationBudget:     5,
		MaxEntries:          8,
		MaxStoredViolations: 4,
	}
}

func signedEntry(seq uint64, path, hash, template, signer string) taskpkg.Entry {
	return taskpkg.Entry{
		Seq:        seq,
		Path:       path,
		Hash:       hash,
		Template:   template,
		Signer:     signer,
		MeasuredAt: time.Unix(1726600000, 0),
	}
}

func entry(seq uint64, path, hash string) taskpkg.Entry {
	return signedEntry(seq, path, hash, "ima-sig", "key-7f31")
}

func aggregate(entries []taskpkg.Entry) string {
	var b strings.Builder
	for _, e := range entries {
		fmt.Fprintf(&b, "%d:%s:%s\n", e.Seq, e.Path, e.Hash)
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

func newGuard(t *testing.T, cfg taskpkg.Config) *taskpkg.ImaGuard {
	t.Helper()
	g := taskpkg.NewImaGuard(cfg)
	if g == nil {
		t.Fatal("NewImaGuard returned nil")
	}
	return g
}

func addRules(t *testing.T, g *taskpkg.ImaGuard) {
	t.Helper()
	if err := g.AddRule(taskpkg.Rule{TenantID: "tenant-a", Path: "/usr/bin/sshd", Label: "admin", AllowedHashes: []string{"aabb"}}); err != nil {
		t.Fatalf("AddRule(sshd): %v", err)
	}
	if err := g.AddRule(taskpkg.Rule{TenantID: "tenant-a", Path: "/usr/bin/agentsvc", Label: "agent", AllowedHashes: []string{"ccdd"}}); err != nil {
		t.Fatalf("AddRule(agentsvc): %v", err)
	}
}

func mustAppraise(t *testing.T, g *taskpkg.ImaGuard, tenantID, nodeID string, entries []taskpkg.Entry, now time.Time) taskpkg.Assessment {
	t.Helper()
	ass, err := g.Appraise(tenantID, nodeID, entries, aggregate(entries), now)
	if err != nil {
		t.Fatalf("Appraise(%s/%s): %v", tenantID, nodeID, err)
	}
	return ass
}

func singleViolation(t *testing.T, ass taskpkg.Assessment, want string) {
	t.Helper()
	if len(ass.Violations) != 1 {
		t.Fatalf("Violations=%v, want exactly [%s]", ass.Violations, want)
	}
	if ass.Violations[0] != want {
		t.Fatalf("Violations[0]=%q, want %q", ass.Violations[0], want)
	}
}

// A list whose entries match the rules is clean and recorded as the verdict.
func TestCleanListAppraises(t *testing.T) {
	now := time.Unix(1726600000, 0)
	g := newGuard(t, imaConfig())
	addRules(t, g)
	entries := []taskpkg.Entry{
		entry(10, "/usr/bin/sshd", "aabb"),
		entry(11, "/usr/bin/agentsvc", "ccdd"),
	}
	ass := mustAppraise(t, g, "tenant-a", "node-01", entries, now)
	if ass.NodeID != "node-01" {
		t.Fatalf("Assessment.NodeID=%q, want node-01", ass.NodeID)
	}
	if ass.Evaluated != 2 {
		t.Fatalf("Assessment.Evaluated=%d, want 2", ass.Evaluated)
	}
	if len(ass.Violations) != 0 {
		t.Fatalf("Assessment.Violations=%v, want none", ass.Violations)
	}
	if ass.Quarantined {
		t.Fatal("clean node was quarantined")
	}
	stored, err := g.Verdict("tenant-a", "node-01")
	if err != nil {
		t.Fatalf("Verdict: %v", err)
	}
	if stored.Evaluated != 2 || len(stored.Violations) != 0 {
		t.Fatalf("stored verdict=%+v, want the clean assessment", stored)
	}
	if g.ViolationCount("tenant-a", "node-01") != 0 {
		t.Fatalf("ViolationCount=%d, want 0", g.ViolationCount("tenant-a", "node-01"))
	}
}

// A measured binary whose digest is not in the rule's allow list is a policy
// violation, not a fatal list error.
func TestHashNotAllowedViolation(t *testing.T) {
	now := time.Unix(1726600000, 0)
	g := newGuard(t, imaConfig())
	addRules(t, g)
	entries := []taskpkg.Entry{entry(20, "/usr/bin/sshd", "ffee")}
	ass := mustAppraise(t, g, "tenant-a", "node-02", entries, now)
	singleViolation(t, ass, "hash:/usr/bin/sshd")
	if g.ViolationCount("tenant-a", "node-02") != 1 {
		t.Fatalf("ViolationCount=%d, want 1", g.ViolationCount("tenant-a", "node-02"))
	}
}

// A measured path without any rule is reported with the no-policy prefix.
func TestMissingPolicyViolation(t *testing.T) {
	now := time.Unix(1726600000, 0)
	g := newGuard(t, imaConfig())
	addRules(t, g)
	entries := []taskpkg.Entry{entry(30, "/opt/app/bin", "1234")}
	ass := mustAppraise(t, g, "tenant-a", "node-03", entries, now)
	singleViolation(t, ass, "no-policy:/opt/app/bin")
}

// Under RequireSigned, an ima-ng measurement counts as unsigned.
func TestUnsignedMeasurementViolation(t *testing.T) {
	now := time.Unix(1726600000, 0)
	cfg := imaConfig()
	cfg.RequireSigned = true
	g := newGuard(t, cfg)
	addRules(t, g)
	entries := []taskpkg.Entry{signedEntry(40, "/usr/bin/agentsvc", "ccdd", "ima-ng", "")}
	ass := mustAppraise(t, g, "tenant-a", "node-04", entries, now)
	singleViolation(t, ass, "unsigned:/usr/bin/agentsvc")
}

// Measuring the same path twice in one list is an anomaly even when both
// digests are allowed.
func TestDuplicatePathViolation(t *testing.T) {
	now := time.Unix(1726600000, 0)
	g := newGuard(t, imaConfig())
	addRules(t, g)
	entries := []taskpkg.Entry{
		entry(50, "/usr/bin/sshd", "aabb"),
		entry(51, "/usr/bin/sshd", "aabb"),
	}
	ass := mustAppraise(t, g, "tenant-a", "node-05", entries, now)
	singleViolation(t, ass, "duplicate:/usr/bin/sshd")
}

// An aggregate that does not match the list means the transport was tampered
// with, and no verdict may be recorded.
func TestAggregateTamperRejected(t *testing.T) {
	now := time.Unix(1726600000, 0)
	g := newGuard(t, imaConfig())
	addRules(t, g)
	entries := []taskpkg.Entry{entry(60, "/usr/bin/sshd", "aabb")}
	if _, err := g.Appraise("tenant-a", "node-06", entries, "0000000000000000", now); !errors.Is(err, taskpkg.ErrListTampered) {
		t.Fatalf("Appraise with a wrong aggregate: got %v, want ErrListTampered", err)
	}
	if _, err := g.Verdict("tenant-a", "node-06"); !errors.Is(err, taskpkg.ErrNoVerdict) {
		t.Fatalf("Verdict after a tampered list: got %v, want ErrNoVerdict", err)
	}
}

// Sequence numbers must strictly increase.
func TestSequenceMustIncrease(t *testing.T) {
	now := time.Unix(1726600000, 0)
	g := newGuard(t, imaConfig())
	addRules(t, g)
	entries := []taskpkg.Entry{
		entry(70, "/usr/bin/sshd", "aabb"),
		entry(69, "/usr/bin/agentsvc", "ccdd"),
	}
	if _, err := g.Appraise("tenant-a", "node-07", entries, aggregate(entries), now); !errors.Is(err, taskpkg.ErrSeqOrder) {
		t.Fatalf("Appraise with a decreasing sequence: got %v, want ErrSeqOrder", err)
	}
}

// Structural limits are enforced before any policy evaluation.
func TestEntryStructuralLimits(t *testing.T) {
	now := time.Unix(1726600000, 0)
	cfg := imaConfig()
	cfg.MaxEntries = 2
	g := newGuard(t, cfg)
	addRules(t, g)
	tooMany := []taskpkg.Entry{
		entry(80, "/usr/bin/sshd", "aabb"),
		entry(81, "/usr/bin/agentsvc", "ccdd"),
		entry(82, "/usr/bin/sshd", "aabb"),
	}
	if _, err := g.Appraise("tenant-a", "node-08", tooMany, aggregate(tooMany), now); !errors.Is(err, taskpkg.ErrEntryInvalid) {
		t.Fatalf("list above MaxEntries: got %v, want ErrEntryInvalid", err)
	}
	emptyPath := []taskpkg.Entry{entry(83, "", "aabb")}
	if _, err := g.Appraise("tenant-a", "node-08", emptyPath, aggregate(emptyPath), now); !errors.Is(err, taskpkg.ErrEntryInvalid) {
		t.Fatalf("entry without a path: got %v, want ErrEntryInvalid", err)
	}
	if err := g.AddRule(taskpkg.Rule{TenantID: "tenant-a", Path: "/usr/bin/cron"}); !errors.Is(err, taskpkg.ErrRuleInvalid) {
		t.Fatalf("AddRule without hashes: got %v, want ErrRuleInvalid", err)
	}
}

// A critical rule that never shows up in the list fails the whole appraisal.
func TestMissingCriticalMeasurement(t *testing.T) {
	now := time.Unix(1726600000, 0)
	g := newGuard(t, imaConfig())
	addRules(t, g)
	if err := g.AddRule(taskpkg.Rule{TenantID: "tenant-a", Path: "/etc/ssh/sshd_config", Label: "config", AllowedHashes: []string{"9988"}, Critical: true}); err != nil {
		t.Fatalf("AddRule(critical): %v", err)
	}
	entries := []taskpkg.Entry{entry(90, "/usr/bin/sshd", "aabb")}
	if _, err := g.Appraise("tenant-a", "node-09", entries, aggregate(entries), now); !errors.Is(err, taskpkg.ErrMissingCritical) {
		t.Fatalf("list missing a critical file: got %v, want ErrMissingCritical", err)
	}
}

// Cumulative violations above ViolationBudget quarantine the node.
func TestViolationBudgetQuarantines(t *testing.T) {
	now := time.Unix(1726600000, 0)
	cfg := imaConfig()
	cfg.ViolationBudget = 2
	g := newGuard(t, cfg)
	entries := []taskpkg.Entry{
		entry(100, "/opt/a", "1111"),
		entry(101, "/opt/b", "2222"),
		entry(102, "/opt/c", "3333"),
	}
	ass := mustAppraise(t, g, "tenant-a", "node-10", entries, now)
	if len(ass.Violations) != 3 {
		t.Fatalf("Violations=%v, want three", ass.Violations)
	}
	if !ass.Quarantined {
		t.Fatal("node with 3 violations and a budget of 2 was not quarantined")
	}
	if !g.IsQuarantined("tenant-a", "node-10") {
		t.Fatal("IsQuarantined=false, want true")
	}
}

// A quarantined node rejects further appraisals until an explicit reset.
func TestQuarantineBlocksAndResetClears(t *testing.T) {
	now := time.Unix(1726600000, 0)
	cfg := imaConfig()
	cfg.ViolationBudget = 0
	g := newGuard(t, cfg)
	addRules(t, g)
	bad := []taskpkg.Entry{entry(110, "/opt/unruled", "4444")}
	mustAppraise(t, g, "tenant-a", "node-11", bad, now)
	clean := []taskpkg.Entry{entry(111, "/usr/bin/sshd", "aabb")}
	if _, err := g.Appraise("tenant-a", "node-11", clean, aggregate(clean), now); !errors.Is(err, taskpkg.ErrQuarantined) {
		t.Fatalf("appraisal of a quarantined node: got %v, want ErrQuarantined", err)
	}
	if err := g.Reset("tenant-a", "node-11"); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if g.IsQuarantined("tenant-a", "node-11") {
		t.Fatal("node still quarantined after Reset")
	}
	if n := g.ViolationCount("tenant-a", "node-11"); n != 0 {
		t.Fatalf("ViolationCount after Reset=%d, want 0", n)
	}
	ass := mustAppraise(t, g, "tenant-a", "node-11", clean, now)
	if ass.Quarantined || len(ass.Violations) != 0 {
		t.Fatalf("clean appraisal after Reset=%+v, want no violations", ass)
	}
}

// Stored violation strings are capped even while the counter keeps growing.
func TestStoredViolationsCapped(t *testing.T) {
	now := time.Unix(1726600000, 0)
	cfg := imaConfig()
	cfg.ViolationBudget = 100
	cfg.MaxStoredViolations = 4
	g := newGuard(t, cfg)
	entries := []taskpkg.Entry{
		entry(120, "/opt/v1", "0101"),
		entry(121, "/opt/v2", "0202"),
		entry(122, "/opt/v3", "0303"),
		entry(123, "/opt/v4", "0404"),
		entry(124, "/opt/v5", "0505"),
		entry(125, "/opt/v6", "0606"),
	}
	mustAppraise(t, g, "tenant-a", "node-12", entries, now)
	if n := g.ViolationCount("tenant-a", "node-12"); n != 6 {
		t.Fatalf("ViolationCount=%d, want 6", n)
	}
	stored := g.Violations("tenant-a", "node-12")
	if len(stored) != 4 {
		t.Fatalf("stored violations=%d, want 4", len(stored))
	}
	if stored[0] != "no-policy:/opt/v1" {
		t.Fatalf("stored[0]=%q, want no-policy:/opt/v1", stored[0])
	}
}

// Rules and node state are isolated per tenant, even for identical node IDs.
func TestTenantIsolation(t *testing.T) {
	now := time.Unix(1726600000, 0)
	g := newGuard(t, imaConfig())
	addRules(t, g)
	entries := []taskpkg.Entry{entry(130, "/usr/bin/sshd", "aabb")}
	ass := mustAppraise(t, g, "tenant-b", "node-shared", entries, now)
	singleViolation(t, ass, "no-policy:/usr/bin/sshd")
	if _, err := g.Verdict("tenant-a", "node-shared"); !errors.Is(err, taskpkg.ErrNoVerdict) {
		t.Fatalf("Verdict of tenant-a: got %v, want ErrNoVerdict", err)
	}
	if _, err := g.Verdict("tenant-b", "node-shared"); err != nil {
		t.Fatalf("Verdict of tenant-b: %v", err)
	}
	if n := g.ViolationCount("tenant-a", "node-shared"); n != 0 {
		t.Fatalf("tenant-a violation count=%d, want 0", n)
	}
	if n := g.ViolationCount("tenant-b", "node-shared"); n != 1 {
		t.Fatalf("tenant-b violation count=%d, want 1", n)
	}
}

// Concurrent appraisals of one node must account for every violation.
func TestConcurrentAppraisalAccounting(t *testing.T) {
	now := time.Unix(1726600000, 0)
	cfg := imaConfig()
	cfg.ViolationBudget = 200
	cfg.MaxStoredViolations = 4
	cfg.MaxEntries = 4
	g := newGuard(t, cfg)
	var wg sync.WaitGroup
	errs := make(chan error, 50)
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			entries := []taskpkg.Entry{entry(uint64(n+1), fmt.Sprintf("/srv/wl-%02d", n), "abcd")}
			_, err := g.Appraise("tenant-a", "node-race", entries, aggregate(entries), now)
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent Appraise: %v", err)
		}
	}
	if n := g.ViolationCount("tenant-a", "node-race"); n != 50 {
		t.Fatalf("ViolationCount=%d, want 50", n)
	}
	if stored := g.Violations("tenant-a", "node-race"); len(stored) != 4 {
		t.Fatalf("stored violations=%d, want the cap of 4", len(stored))
	}
}

// Quarantine, violation counts and rules must survive a restart.
func TestStateSurvivesRestart(t *testing.T) {
	now := time.Unix(1726600000, 0)
	cfg := imaConfig()
	cfg.ViolationBudget = 1
	g := newGuard(t, cfg)
	entries := []taskpkg.Entry{
		entry(140, "/opt/x", "aaaa"),
		entry(141, "/opt/y", "bbbb"),
	}
	mustAppraise(t, g, "tenant-a", "node-13", entries, now)
	if !g.IsQuarantined("tenant-a", "node-13") {
		t.Fatal("node not quarantined before snapshot")
	}
	snap, err := g.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	restored, err := taskpkg.NewImaGuardFromSnapshot(cfg, snap)
	if err != nil {
		t.Fatalf("NewImaGuardFromSnapshot: %v", err)
	}
	if !restored.IsQuarantined("tenant-a", "node-13") {
		t.Fatal("quarantine was lost across restart")
	}
	if n := restored.ViolationCount("tenant-a", "node-13"); n != 2 {
		t.Fatalf("ViolationCount after restore=%d, want 2", n)
	}
	clean := []taskpkg.Entry{entry(142, "/opt/x", "aaaa")}
	if _, err := restored.Appraise("tenant-a", "node-13", clean, aggregate(clean), now); !errors.Is(err, taskpkg.ErrQuarantined) {
		t.Fatalf("appraisal after restore: got %v, want ErrQuarantined", err)
	}
}
