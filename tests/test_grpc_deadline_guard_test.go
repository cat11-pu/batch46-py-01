package task

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	taskpkg "gsb/batch46-safety-d-09"
)

func deadlineConfig() taskpkg.Config {
	return taskpkg.Config{
		MaxDeadline:    10 * time.Second,
		MinBudget:      50 * time.Millisecond,
		DefaultTimeout: 250 * time.Millisecond,
		HopReserve:     100 * time.Millisecond,
		MaxHops:        5,
	}
}

// A root call gets exactly the budget it asked for.
func TestStartCallUsesRequestedBudget(t *testing.T) {
	g := taskpkg.NewDeadlineGuard(deadlineConfig())
	now := time.Unix(1700000000, 0)
	d, err := g.StartCall("root", "", 500*time.Millisecond, now)
	if err != nil {
		t.Fatalf("StartCall: %v", err)
	}
	if d.CallID != "root" || d.Remaining != 500*time.Millisecond || d.Hop != 1 {
		t.Fatalf("Deadline = %+v, want root/500ms/hop1", d)
	}
	if !d.At.Equal(now.Add(500 * time.Millisecond)) {
		t.Fatalf("At = %v, want %v", d.At, now.Add(500*time.Millisecond))
	}
	at, err := g.Deadline("root")
	if err != nil || !at.Equal(now.Add(500*time.Millisecond)) {
		t.Fatalf("Deadline(root) = %v, %v; want %v", at, err, now.Add(500*time.Millisecond))
	}
	if g.ActiveCount() != 1 {
		t.Fatalf("ActiveCount = %d, want 1", g.ActiveCount())
	}
	if stats := g.Stats(); stats.Started != 1 {
		t.Fatalf("Started = %d, want 1", stats.Started)
	}
}

// A child may never claim more than the parent has left after the hop
// reserve.
func TestChildCannotExceedParentBudget(t *testing.T) {
	g := taskpkg.NewDeadlineGuard(deadlineConfig())
	now := time.Unix(1700000000, 0)
	if _, err := g.StartCall("root", "", 500*time.Millisecond, now); err != nil {
		t.Fatalf("StartCall root: %v", err)
	}
	child, err := g.StartCall("child", "root", time.Second, now)
	if err != nil {
		t.Fatalf("StartCall child: %v", err)
	}
	if child.Remaining != 400*time.Millisecond {
		t.Fatalf("child Remaining = %v, want 400ms", child.Remaining)
	}
	if !child.At.Equal(now.Add(400 * time.Millisecond)) {
		t.Fatalf("child At = %v, want %v", child.At, now.Add(400*time.Millisecond))
	}
	if child.Hop != 2 {
		t.Fatalf("child Hop = %d, want 2", child.Hop)
	}
}

// A child asking for less than the parent allows keeps its own smaller
// budget.
func TestChildShorterThanParentKept(t *testing.T) {
	g := taskpkg.NewDeadlineGuard(deadlineConfig())
	now := time.Unix(1700000000, 0)
	if _, err := g.StartCall("root", "", time.Second, now); err != nil {
		t.Fatalf("StartCall root: %v", err)
	}
	child, err := g.StartCall("child", "root", 200*time.Millisecond, now)
	if err != nil {
		t.Fatalf("StartCall child: %v", err)
	}
	if child.Remaining != 200*time.Millisecond {
		t.Fatalf("child Remaining = %v, want 200ms", child.Remaining)
	}
}

// A budget under MinBudget must be refused instead of starting a call that
// cannot do useful work.
func TestChildBelowMinimumBudgetRejected(t *testing.T) {
	now := time.Unix(1700000000, 0)
	g := taskpkg.NewDeadlineGuard(deadlineConfig())
	if _, err := g.StartCall("root", "", 500*time.Millisecond, now); err != nil {
		t.Fatalf("StartCall root: %v", err)
	}
	if _, err := g.StartCall("child", "root", 10*time.Millisecond, now); !errors.Is(err, taskpkg.ErrBudgetBelowMinimum) {
		t.Fatalf("StartCall below MinBudget = %v, want ErrBudgetBelowMinimum", err)
	}
	if g.ActiveCount() != 1 || g.IsActive("child") {
		t.Fatalf("rejected child was tracked: active=%d child=%v", g.ActiveCount(), g.IsActive("child"))
	}
	near := taskpkg.NewDeadlineGuard(deadlineConfig())
	if _, err := near.StartCall("root", "", 120*time.Millisecond, now); err != nil {
		t.Fatalf("StartCall near root: %v", err)
	}
	if _, err := near.StartCall("child", "root", 100*time.Millisecond, now); !errors.Is(err, taskpkg.ErrBudgetBelowMinimum) {
		t.Fatalf("child squeezed under the hop reserve = %v, want ErrBudgetBelowMinimum", err)
	}
}

// An expired parent cannot spawn a child, even exactly at its deadline.
func TestExpiredParentRejectsChild(t *testing.T) {
	g := taskpkg.NewDeadlineGuard(deadlineConfig())
	now := time.Unix(1700000000, 0)
	if _, err := g.StartCall("root", "", 200*time.Millisecond, now); err != nil {
		t.Fatalf("StartCall root: %v", err)
	}
	if _, err := g.StartCall("child", "root", 100*time.Millisecond, now.Add(250*time.Millisecond)); !errors.Is(err, taskpkg.ErrDeadlineExceeded) {
		t.Fatalf("child after the parent expired = %v, want ErrDeadlineExceeded", err)
	}
	if _, err := g.StartCall("edge", "root", 100*time.Millisecond, now.Add(200*time.Millisecond)); !errors.Is(err, taskpkg.ErrDeadlineExceeded) {
		t.Fatalf("child exactly at the parent deadline = %v, want ErrDeadlineExceeded", err)
	}
	if g.ActiveCount() != 1 {
		t.Fatalf("ActiveCount = %d, want only the root", g.ActiveCount())
	}
}

// A parent that was never started cannot be used for derivation.
func TestStartCallRejectsUnknownParent(t *testing.T) {
	g := taskpkg.NewDeadlineGuard(deadlineConfig())
	now := time.Unix(1700000000, 0)
	if _, err := g.StartCall("child", "missing", 100*time.Millisecond, now); !errors.Is(err, taskpkg.ErrUnknownCall) {
		t.Fatalf("StartCall with an unknown parent = %v, want ErrUnknownCall", err)
	}
	if g.ActiveCount() != 0 {
		t.Fatalf("ActiveCount = %d after a rejected parent, want 0", g.ActiveCount())
	}
	if stats := g.Stats(); stats.Started != 0 {
		t.Fatalf("Started = %d after a rejected parent, want 0", stats.Started)
	}
}

// Call ids are unique while tracked.
func TestStartCallRejectsDuplicateID(t *testing.T) {
	g := taskpkg.NewDeadlineGuard(deadlineConfig())
	now := time.Unix(1700000000, 0)
	if _, err := g.StartCall("root", "", 100*time.Millisecond, now); err != nil {
		t.Fatalf("StartCall: %v", err)
	}
	if _, err := g.StartCall("root", "", 200*time.Millisecond, now); !errors.Is(err, taskpkg.ErrDuplicateCall) {
		t.Fatalf("duplicate StartCall = %v, want ErrDuplicateCall", err)
	}
	if g.ActiveCount() != 1 {
		t.Fatalf("ActiveCount = %d after a duplicate, want 1", g.ActiveCount())
	}
}

// A zero request falls back to the configured default timeout.
func TestRequestedZeroUsesDefaultTimeout(t *testing.T) {
	g := taskpkg.NewDeadlineGuard(deadlineConfig())
	now := time.Unix(1700000000, 0)
	d, err := g.StartCall("root", "", 0, now)
	if err != nil {
		t.Fatalf("StartCall: %v", err)
	}
	if d.Remaining != 250*time.Millisecond {
		t.Fatalf("Remaining = %v, want the 250ms default", d.Remaining)
	}
}

// A request above MaxDeadline is cut down to the cap.
func TestMaxDeadlineCapsRequest(t *testing.T) {
	g := taskpkg.NewDeadlineGuard(deadlineConfig())
	now := time.Unix(1700000000, 0)
	d, err := g.StartCall("root", "", time.Hour, now)
	if err != nil {
		t.Fatalf("StartCall: %v", err)
	}
	if d.Remaining != 10*time.Second {
		t.Fatalf("Remaining = %v, want the 10s MaxDeadline", d.Remaining)
	}
}

// Remaining clamps at zero once the deadline passed and reports why.
func TestRemainingReportsExceeded(t *testing.T) {
	g := taskpkg.NewDeadlineGuard(deadlineConfig())
	now := time.Unix(1700000000, 0)
	if _, err := g.StartCall("root", "", 100*time.Millisecond, now); err != nil {
		t.Fatalf("StartCall: %v", err)
	}
	left, err := g.Remaining("root", now.Add(40*time.Millisecond))
	if err != nil || left != 60*time.Millisecond {
		t.Fatalf("Remaining at +40ms = %v, %v; want 60ms", left, err)
	}
	left, err = g.Remaining("root", now.Add(150*time.Millisecond))
	if left != 0 || !errors.Is(err, taskpkg.ErrDeadlineExceeded) {
		t.Fatalf("Remaining at +150ms = %v, %v; want 0, ErrDeadlineExceeded", left, err)
	}
	if _, err := g.Remaining("missing", now); !errors.Is(err, taskpkg.ErrUnknownCall) {
		t.Fatalf("Remaining of an unknown call = %v, want ErrUnknownCall", err)
	}
}

// Finishing a call closes its whole subtree and reports the descendants.
func TestFinishCascadesChildren(t *testing.T) {
	g := taskpkg.NewDeadlineGuard(deadlineConfig())
	now := time.Unix(1700000000, 0)
	if _, err := g.StartCall("root", "", time.Second, now); err != nil {
		t.Fatalf("StartCall root: %v", err)
	}
	if _, err := g.StartCall("child-1", "root", 400*time.Millisecond, now); err != nil {
		t.Fatalf("StartCall child-1: %v", err)
	}
	if _, err := g.StartCall("child-2", "root", 300*time.Millisecond, now); err != nil {
		t.Fatalf("StartCall child-2: %v", err)
	}
	if _, err := g.StartCall("grand", "child-1", 200*time.Millisecond, now); err != nil {
		t.Fatalf("StartCall grand: %v", err)
	}
	closed, err := g.Finish("root")
	if err != nil {
		t.Fatalf("Finish root: %v", err)
	}
	if closed != 3 {
		t.Fatalf("Finish(root) closed %d descendants, want 3", closed)
	}
	if g.ActiveCount() != 0 {
		t.Fatalf("ActiveCount = %d after finishing the tree, want 0", g.ActiveCount())
	}
	if g.IsActive("child-1") || g.IsActive("grand") {
		t.Fatal("descendants survived the cascade")
	}
	if _, err := g.Finish("child-2"); !errors.Is(err, taskpkg.ErrUnknownCall) {
		t.Fatalf("Finish of an already closed call = %v, want ErrUnknownCall", err)
	}
	if stats := g.Stats(); stats.Finished != 4 {
		t.Fatalf("Finished = %d, want 4 calls closed", stats.Finished)
	}
}

// The hop limit stops runaway call chains.
func TestHopLimitRejectsDeepChain(t *testing.T) {
	cfg := deadlineConfig()
	cfg.MaxHops = 2
	g := taskpkg.NewDeadlineGuard(cfg)
	now := time.Unix(1700000000, 0)
	root, err := g.StartCall("root", "", time.Second, now)
	if err != nil || root.Hop != 1 {
		t.Fatalf("StartCall root = %+v, %v; want hop 1", root, err)
	}
	child, err := g.StartCall("child", "root", 400*time.Millisecond, now)
	if err != nil || child.Hop != 2 {
		t.Fatalf("StartCall child = %+v, %v; want hop 2", child, err)
	}
	if _, err := g.StartCall("grand", "child", 100*time.Millisecond, now); !errors.Is(err, taskpkg.ErrMaxHops) {
		t.Fatalf("third hop = %v, want ErrMaxHops", err)
	}
	if g.ActiveCount() != 2 {
		t.Fatalf("ActiveCount = %d after the hop rejection, want 2", g.ActiveCount())
	}
}

// A retry may only spend its even share of the remaining budget.
func TestRetrySliceSplitsRemaining(t *testing.T) {
	g := taskpkg.NewDeadlineGuard(deadlineConfig())
	now := time.Unix(1700000000, 0)
	if _, err := g.StartCall("root", "", 900*time.Millisecond, now); err != nil {
		t.Fatalf("StartCall: %v", err)
	}
	for attempt := 1; attempt <= 3; attempt++ {
		slice, err := g.RetrySlice("root", attempt, 3, now)
		if err != nil {
			t.Fatalf("RetrySlice attempt %d: %v", attempt, err)
		}
		if slice != 300*time.Millisecond {
			t.Fatalf("RetrySlice attempt %d = %v, want 300ms", attempt, slice)
		}
	}
	if _, err := g.RetrySlice("root", 0, 3, now); !errors.Is(err, taskpkg.ErrInvalidAttempt) {
		t.Fatalf("attempt 0 = %v, want ErrInvalidAttempt", err)
	}
	if _, err := g.RetrySlice("root", 4, 3, now); !errors.Is(err, taskpkg.ErrInvalidAttempt) {
		t.Fatalf("attempt 4 of 3 = %v, want ErrInvalidAttempt", err)
	}
	tight := deadlineConfig()
	tight.MinBudget = 400 * time.Millisecond
	gt := taskpkg.NewDeadlineGuard(tight)
	if _, err := gt.StartCall("root", "", 900*time.Millisecond, now); err != nil {
		t.Fatalf("StartCall tight: %v", err)
	}
	if _, err := gt.RetrySlice("root", 1, 3, now); !errors.Is(err, taskpkg.ErrBudgetBelowMinimum) {
		t.Fatalf("slice under MinBudget = %v, want ErrBudgetBelowMinimum", err)
	}
}

// Absolute deadlines and parent links survive a restart.
func TestSnapshotRestoresDeadlines(t *testing.T) {
	g := taskpkg.NewDeadlineGuard(deadlineConfig())
	now := time.Unix(1700000000, 0)
	if _, err := g.StartCall("root", "", time.Second, now); err != nil {
		t.Fatalf("StartCall root: %v", err)
	}
	if _, err := g.StartCall("child", "root", 400*time.Millisecond, now); err != nil {
		t.Fatalf("StartCall child: %v", err)
	}
	snap, err := g.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	restored, err := taskpkg.NewDeadlineGuardFromSnapshot(deadlineConfig(), snap)
	if err != nil {
		t.Fatalf("NewDeadlineGuardFromSnapshot: %v", err)
	}
	if restored.ActiveCount() != 2 {
		t.Fatalf("ActiveCount after restore = %d, want 2", restored.ActiveCount())
	}
	left, err := restored.Remaining("child", now.Add(100*time.Millisecond))
	if err != nil || left != 300*time.Millisecond {
		t.Fatalf("Remaining(child) after restore = %v, %v; want 300ms", left, err)
	}
	at, err := restored.Deadline("child")
	if err != nil || !at.Equal(now.Add(400*time.Millisecond)) {
		t.Fatalf("Deadline(child) after restore = %v, %v; want %v", at, err, now.Add(400*time.Millisecond))
	}
	closed, err := restored.Finish("root")
	if err != nil || closed != 1 {
		t.Fatalf("Finish(root) after restore = %d, %v; want 1 descendant", closed, err)
	}
	if restored.ActiveCount() != 0 {
		t.Fatalf("ActiveCount = %d after finishing the restored tree, want 0", restored.ActiveCount())
	}
}

// Concurrent children of one parent must all derive the same cap without
// corrupting the tree.
func TestConcurrentStartCallRespectsParentBudget(t *testing.T) {
	cfg := taskpkg.Config{
		MaxDeadline:    10 * time.Second,
		MinBudget:      10 * time.Millisecond,
		DefaultTimeout: 100 * time.Millisecond,
		HopReserve:     50 * time.Millisecond,
		MaxHops:        5,
	}
	g := taskpkg.NewDeadlineGuard(cfg)
	now := time.Unix(1700000000, 0)
	if _, err := g.StartCall("root", "", 500*time.Millisecond, now); err != nil {
		t.Fatalf("StartCall root: %v", err)
	}
	const workers = 20
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			d, err := g.StartCall(fmt.Sprintf("child-%d", i), "root", 450*time.Millisecond, now)
			if err != nil {
				errs <- err
				return
			}
			if d.Remaining != 450*time.Millisecond {
				errs <- fmt.Errorf("child %d remaining %v, want 450ms", i, d.Remaining)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent child: %v", err)
	}
	if got := g.ActiveCount(); got != workers+1 {
		t.Fatalf("ActiveCount = %d, want %d", got, workers+1)
	}
}
