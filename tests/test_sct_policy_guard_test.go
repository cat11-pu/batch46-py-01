package task

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	taskpkg "gsb/batch46-safety-b-05"
)

func sctConfig() taskpkg.Config {
	return taskpkg.Config{
		MinDistinctLogs: 2,
		MinOperators:    2,
		MaxLogs:         12,
		MaxSCTAge:       24 * time.Hour,
		ClockSkew:       time.Minute,
	}
}

func sctCert(now time.Time) taskpkg.Cert {
	return taskpkg.Cert{
		Serial:    "0x1a2b3c",
		Issuer:    "CN=Example Public CA",
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.Add(24 * time.Hour),
	}
}

func sctLog(id, operator string) taskpkg.Log {
	return taskpkg.Log{ID: id, Operator: operator, State: taskpkg.LogUsable}
}

func sctFor(logID string, now time.Time) taskpkg.SCT {
	return taskpkg.SCT{
		LogID:          logID,
		Timestamp:      now.Add(-time.Minute),
		SignatureValid: true,
		Source:         "embedded",
	}
}

func mustAddLog(t *testing.T, g *taskpkg.SctGuard, l taskpkg.Log) {
	t.Helper()
	if err := g.AddLog(l); err != nil {
		t.Fatalf("AddLog(%s): %v", l.ID, err)
	}
}

// A log id may only be registered once.
func TestAddLogRejectsDuplicate(t *testing.T) {
	g := taskpkg.NewSctGuard(sctConfig())
	l := sctLog("log-a", "op-1")
	if err := g.AddLog(l); err != nil {
		t.Fatalf("first AddLog: %v", err)
	}
	if err := g.AddLog(l); !errors.Is(err, taskpkg.ErrLogExists) {
		t.Fatalf("duplicate AddLog err = %v, want ErrLogExists", err)
	}
}

// The registry must stop at the configured log budget.
func TestAddLogEnforcesMaxLogs(t *testing.T) {
	cfg := sctConfig()
	cfg.MaxLogs = 1
	g := taskpkg.NewSctGuard(cfg)
	mustAddLog(t, g, sctLog("log-a", "op-1"))
	if err := g.AddLog(sctLog("log-b", "op-2")); !errors.Is(err, taskpkg.ErrTooManyLogs) {
		t.Fatalf("second AddLog err = %v, want ErrTooManyLogs", err)
	}
}

// An SCT naming a log that is not in the policy registry invalidates the
// evaluation.
func TestEvaluateRejectsUnknownLog(t *testing.T) {
	g := taskpkg.NewSctGuard(sctConfig())
	now := time.Unix(1700000000, 0)
	mustAddLog(t, g, sctLog("log-a", "op-1"))

	if _, err := g.Evaluate(sctCert(now), []taskpkg.SCT{sctFor("log-ghost", now)}, now); !errors.Is(err, taskpkg.ErrUnknownLog) {
		t.Fatalf("Evaluate ghost log err = %v, want ErrUnknownLog", err)
	}
}

// SCTs from a disqualified log must not be counted.
func TestEvaluateIgnoresDisqualifiedLog(t *testing.T) {
	g := taskpkg.NewSctGuard(sctConfig())
	now := time.Unix(1700000000, 0)
	mustAddLog(t, g, sctLog("log-a", "op-1"))
	mustAddLog(t, g, sctLog("log-b", "op-2"))
	if err := g.SetLogState("log-b", taskpkg.LogDisqualified); err != nil {
		t.Fatalf("SetLogState: %v", err)
	}
	scts := []taskpkg.SCT{sctFor("log-a", now), sctFor("log-b", now)}

	verdict, err := g.Evaluate(sctCert(now), scts, now)
	if !errors.Is(err, taskpkg.ErrTooFewSCTs) {
		t.Fatalf("Evaluate with a disqualified log err = %v, want ErrTooFewSCTs", err)
	}
	if verdict.Count != 1 {
		t.Fatalf("counted %d SCTs, want 1", verdict.Count)
	}
	if len(verdict.Logs) != 1 || verdict.Logs[0] != "log-a" {
		t.Fatalf("counted logs = %v, want [log-a]", verdict.Logs)
	}
}

// Two SCTs from the same log count as one distinct log.
func TestDuplicateLogCountsOnce(t *testing.T) {
	g := taskpkg.NewSctGuard(sctConfig())
	now := time.Unix(1700000000, 0)
	mustAddLog(t, g, sctLog("log-a", "op-1"))
	first := sctFor("log-a", now)
	second := sctFor("log-a", now)
	second.Timestamp = now.Add(-2 * time.Minute)

	verdict, err := g.Evaluate(sctCert(now), []taskpkg.SCT{first, second}, now)
	if !errors.Is(err, taskpkg.ErrTooFewSCTs) {
		t.Fatalf("Evaluate duplicate log err = %v, want ErrTooFewSCTs", err)
	}
	if verdict.Count != 1 {
		t.Fatalf("counted %d distinct logs, want 1", verdict.Count)
	}
}

// The same log reached through two delivery channels still counts once.
func TestSameLogAcrossSourcesCountsOnce(t *testing.T) {
	g := taskpkg.NewSctGuard(sctConfig())
	now := time.Unix(1700000000, 0)
	mustAddLog(t, g, sctLog("log-a", "op-1"))
	embedded := sctFor("log-a", now)
	ocsp := sctFor("log-a", now)
	ocsp.Source = "ocsp"

	verdict, err := g.Evaluate(sctCert(now), []taskpkg.SCT{embedded, ocsp}, now)
	if !errors.Is(err, taskpkg.ErrTooFewSCTs) {
		t.Fatalf("Evaluate multi-source duplicate err = %v, want ErrTooFewSCTs", err)
	}
	if verdict.Count != 1 {
		t.Fatalf("counted %d distinct logs, want 1", verdict.Count)
	}
}

// An SCT with an invalid signature invalidates the evaluation.
func TestEvaluateRejectsBadSCTSignature(t *testing.T) {
	g := taskpkg.NewSctGuard(sctConfig())
	now := time.Unix(1700000000, 0)
	mustAddLog(t, g, sctLog("log-a", "op-1"))
	mustAddLog(t, g, sctLog("log-b", "op-2"))
	bad := sctFor("log-b", now)
	bad.SignatureValid = false
	scts := []taskpkg.SCT{sctFor("log-a", now), bad}

	if _, err := g.Evaluate(sctCert(now), scts, now); !errors.Is(err, taskpkg.ErrBadSCTSignature) {
		t.Fatalf("Evaluate bad signature err = %v, want ErrBadSCTSignature", err)
	}
}

// An SCT logged before the certificate existed cannot be valid.
func TestEvaluateRejectsSCTBeforeCertNotBefore(t *testing.T) {
	g := taskpkg.NewSctGuard(sctConfig())
	now := time.Unix(1700000000, 0)
	mustAddLog(t, g, sctLog("log-a", "op-1"))
	mustAddLog(t, g, sctLog("log-b", "op-2"))
	cert := sctCert(now)
	early := sctFor("log-b", now)
	early.Timestamp = cert.NotBefore.Add(-2 * time.Minute)
	scts := []taskpkg.SCT{sctFor("log-a", now), early}

	if _, err := g.Evaluate(cert, scts, now); !errors.Is(err, taskpkg.ErrSCTTimestamp) {
		t.Fatalf("Evaluate pre-issuance SCT err = %v, want ErrSCTTimestamp", err)
	}
}

// An SCT older than MaxSCTAge must be rejected even if it is inside the
// certificate validity window.
func TestEvaluateRejectsStaleSCT(t *testing.T) {
	g := taskpkg.NewSctGuard(sctConfig())
	now := time.Unix(1700000000, 0)
	mustAddLog(t, g, sctLog("log-a", "op-1"))
	mustAddLog(t, g, sctLog("log-b", "op-2"))
	cert := sctCert(now)
	cert.NotBefore = now.Add(-72 * time.Hour)
	stale := sctFor("log-b", now)
	stale.Timestamp = now.Add(-48 * time.Hour)
	scts := []taskpkg.SCT{sctFor("log-a", now), stale}

	if _, err := g.Evaluate(cert, scts, now); !errors.Is(err, taskpkg.ErrSCTTimestamp) {
		t.Fatalf("Evaluate stale SCT err = %v, want ErrSCTTimestamp", err)
	}
}

// An SCT timestamped in the future beyond the clock skew must be rejected.
func TestEvaluateRejectsFutureSCT(t *testing.T) {
	g := taskpkg.NewSctGuard(sctConfig())
	now := time.Unix(1700000000, 0)
	mustAddLog(t, g, sctLog("log-a", "op-1"))
	mustAddLog(t, g, sctLog("log-b", "op-2"))
	future := sctFor("log-b", now)
	future.Timestamp = now.Add(10 * time.Minute)
	scts := []taskpkg.SCT{sctFor("log-a", now), future}

	if _, err := g.Evaluate(sctCert(now), scts, now); !errors.Is(err, taskpkg.ErrSCTTimestamp) {
		t.Fatalf("Evaluate future SCT err = %v, want ErrSCTTimestamp", err)
	}
}

// Two logs run by the same operator do not satisfy the diversity requirement.
func TestEvaluateRequiresOperatorDiversity(t *testing.T) {
	g := taskpkg.NewSctGuard(sctConfig())
	now := time.Unix(1700000000, 0)
	mustAddLog(t, g, sctLog("log-a", "op-1"))
	mustAddLog(t, g, sctLog("log-b", "op-1"))
	scts := []taskpkg.SCT{sctFor("log-a", now), sctFor("log-b", now)}

	verdict, err := g.Evaluate(sctCert(now), scts, now)
	if !errors.Is(err, taskpkg.ErrOperatorDiversity) {
		t.Fatalf("Evaluate single-operator SCTs err = %v, want ErrOperatorDiversity", err)
	}
	if verdict.Count != 2 {
		t.Fatalf("counted %d logs, want 2 before the diversity failure", verdict.Count)
	}
}

// A compliant set of SCTs is accepted and reported in sorted order.
func TestEvaluateAcceptsCompliantSCTs(t *testing.T) {
	g := taskpkg.NewSctGuard(sctConfig())
	now := time.Unix(1700000000, 0)
	mustAddLog(t, g, sctLog("log-c", "op-2"))
	mustAddLog(t, g, sctLog("log-a", "op-1"))
	mustAddLog(t, g, sctLog("log-b", "op-1"))
	scts := []taskpkg.SCT{sctFor("log-c", now), sctFor("log-a", now), sctFor("log-b", now)}

	verdict, err := g.Evaluate(sctCert(now), scts, now)
	if err != nil {
		t.Fatalf("Evaluate compliant SCTs: %v", err)
	}
	if !verdict.Accepted || verdict.Count != 3 {
		t.Fatalf("verdict = %+v, want accepted with 3 logs", verdict)
	}
	wantLogs := []string{"log-a", "log-b", "log-c"}
	if len(verdict.Logs) != len(wantLogs) {
		t.Fatalf("verdict logs = %v, want %v", verdict.Logs, wantLogs)
	}
	for i, want := range wantLogs {
		if verdict.Logs[i] != want {
			t.Fatalf("verdict logs = %v, want %v", verdict.Logs, wantLogs)
		}
	}
	wantOps := []string{"op-1", "op-2"}
	if len(verdict.Operators) != len(wantOps) {
		t.Fatalf("verdict operators = %v, want %v", verdict.Operators, wantOps)
	}
	for i, want := range wantOps {
		if verdict.Operators[i] != want {
			t.Fatalf("verdict operators = %v, want %v", verdict.Operators, wantOps)
		}
	}
}

// An expired certificate cannot be covered by SCTs.
func TestEvaluateRejectsExpiredCertificate(t *testing.T) {
	g := taskpkg.NewSctGuard(sctConfig())
	now := time.Unix(1700000000, 0)
	mustAddLog(t, g, sctLog("log-a", "op-1"))
	mustAddLog(t, g, sctLog("log-b", "op-2"))
	cert := sctCert(now)
	cert.NotAfter = now.Add(-time.Hour)
	scts := []taskpkg.SCT{sctFor("log-a", now), sctFor("log-b", now)}

	if _, err := g.Evaluate(cert, scts, now); !errors.Is(err, taskpkg.ErrCertExpired) {
		t.Fatalf("Evaluate expired certificate err = %v, want ErrCertExpired", err)
	}
}

// Concurrent registrations must not overshoot the log budget.
func TestConcurrentAddLogsRespectsMaxLogs(t *testing.T) {
	const maxLogs = 10
	cfg := sctConfig()
	cfg.MaxLogs = maxLogs
	g := taskpkg.NewSctGuard(cfg)

	const workers = 50
	errs := make([]error, workers)
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func(idx int) {
			defer wg.Done()
			l := sctLog(fmt.Sprintf("log-%02d", idx), fmt.Sprintf("op-%02d", idx))
			errs[idx] = g.AddLog(l)
		}(i)
	}
	wg.Wait()

	successes := 0
	for _, err := range errs {
		if err == nil {
			successes++
		}
	}
	if successes != maxLogs {
		t.Fatalf("%d concurrent registrations succeeded, want exactly %d", successes, maxLogs)
	}
	if n := g.LogCount(); n != maxLogs {
		t.Fatalf("log count = %d, want %d", n, maxLogs)
	}
}

// A restart must keep disqualified logs disqualified.
func TestSnapshotRestoresLogStates(t *testing.T) {
	g := taskpkg.NewSctGuard(sctConfig())
	now := time.Unix(1700000000, 0)
	mustAddLog(t, g, sctLog("log-a", "op-1"))
	mustAddLog(t, g, sctLog("log-b", "op-2"))
	if err := g.SetLogState("log-b", taskpkg.LogDisqualified); err != nil {
		t.Fatalf("SetLogState: %v", err)
	}
	snap, err := g.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	restored, err := taskpkg.NewSctGuardFromSnapshot(sctConfig(), snap)
	if err != nil {
		t.Fatalf("NewSctGuardFromSnapshot: %v", err)
	}
	if n := restored.LogCount(); n != 2 {
		t.Fatalf("restored log count = %d, want 2", n)
	}
	scts := []taskpkg.SCT{sctFor("log-a", now), sctFor("log-b", now)}
	verdict, err := restored.Evaluate(sctCert(now), scts, now)
	if !errors.Is(err, taskpkg.ErrTooFewSCTs) {
		t.Fatalf("restored Evaluate err = %v, want ErrTooFewSCTs", err)
	}
	if verdict.Count != 1 {
		t.Fatalf("restored evaluation counted %d logs, want 1", verdict.Count)
	}
}
