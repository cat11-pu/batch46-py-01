package task

import (
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	taskpkg "gsb/batch46-safety-d-01"
)

func mplsPolicy() taskpkg.Policy {
	return taskpkg.Policy{
		MaxDepth:      4,
		MinTTL:        2,
		AllowedLabels: []uint32{100, 200, 300, 400},
		ReplayWindow:  time.Minute,
		MaxFlows:      8,
	}
}

func label(v uint32, tc uint8, s bool, ttl uint8) taskpkg.Label {
	return taskpkg.Label{Value: v, TC: tc, S: s, TTL: ttl}
}

func validStack() []taskpkg.Label {
	return []taskpkg.Label{
		label(100, 0, false, 64),
		label(200, 1, false, 64),
		label(300, 0, true, 64),
	}
}

func mustGuard(t *testing.T, p taskpkg.Policy) *taskpkg.MplsGuard {
	t.Helper()
	g := taskpkg.NewMplsGuard(p)
	if g == nil {
		t.Fatalf("NewMplsGuard returned nil")
	}
	return g
}

func mustAddNexthop(t *testing.T, g *taskpkg.MplsGuard, name string, stack []uint32) {
	t.Helper()
	if err := g.AddNexthop(name, stack); err != nil {
		t.Fatalf("AddNexthop(%q): %v", name, err)
	}
}

// An empty stack carries no label and must never reach the forwarding plane.
func TestEmptyStackRejected(t *testing.T) {
	g := mustGuard(t, mplsPolicy())
	if err := g.ValidateStack(nil); !errors.Is(err, taskpkg.ErrLabelInvalid) {
		t.Fatalf("nil stack: want ErrLabelInvalid, got %v", err)
	}
	if err := g.ValidateStack([]taskpkg.Label{}); !errors.Is(err, taskpkg.ErrLabelInvalid) {
		t.Fatalf("empty stack: want ErrLabelInvalid, got %v", err)
	}
}

// Label values are 20 bit wide and the traffic class is 3 bit wide.
func TestLabelValueAndTrafficClassRanges(t *testing.T) {
	g := mustGuard(t, mplsPolicy())
	tooBig := []taskpkg.Label{
		label(100, 0, false, 64),
		label(1<<20, 0, true, 64),
	}
	if err := g.ValidateStack(tooBig); !errors.Is(err, taskpkg.ErrLabelInvalid) {
		t.Fatalf("21-bit label value: want ErrLabelInvalid, got %v", err)
	}
	badTC := []taskpkg.Label{
		label(100, 0, false, 64),
		label(300, 8, true, 64),
	}
	if err := g.ValidateStack(badTC); !errors.Is(err, taskpkg.ErrLabelInvalid) {
		t.Fatalf("4-bit traffic class: want ErrLabelInvalid, got %v", err)
	}
}

// A stack deeper than MaxDepth is rejected and counted as a depth rejection.
func TestDepthAboveLimitRejected(t *testing.T) {
	g := mustGuard(t, mplsPolicy())
	deep := []taskpkg.Label{
		label(100, 0, false, 64),
		label(200, 0, false, 64),
		label(300, 0, false, 64),
		label(400, 0, false, 64),
		label(100, 0, true, 64),
	}
	if err := g.ValidateStack(deep); !errors.Is(err, taskpkg.ErrStackDepth) {
		t.Fatalf("depth 5 over limit 4: want ErrStackDepth, got %v", err)
	}
	if got := g.Counters().DepthRejected; got != 1 {
		t.Fatalf("DepthRejected = %d, want 1", got)
	}
}

// A stack exactly at the depth limit is legal.
func TestDepthAtLimitAccepted(t *testing.T) {
	g := mustGuard(t, mplsPolicy())
	atLimit := []taskpkg.Label{
		label(100, 0, false, 64),
		label(200, 0, false, 64),
		label(300, 0, false, 64),
		label(400, 0, true, 64),
	}
	original := append([]taskpkg.Label(nil), atLimit...)
	if err := g.ValidateStack(atLimit); err != nil {
		t.Fatalf("depth 4 at limit: %v", err)
	}
	if !reflect.DeepEqual(atLimit, original) {
		t.Fatalf("ValidateStack mutated its input: %+v", atLimit)
	}
	if got := g.Counters().DepthRejected; got != 0 {
		t.Fatalf("DepthRejected = %d, want 0", got)
	}
}

// The bottom-of-stack bit must be set on the last label and nowhere else.
func TestBottomOfStackBitEnforced(t *testing.T) {
	g := mustGuard(t, mplsPolicy())
	missingBottom := []taskpkg.Label{
		label(100, 0, false, 64),
		label(300, 0, false, 64),
	}
	if err := g.ValidateStack(missingBottom); !errors.Is(err, taskpkg.ErrLabelInvalid) {
		t.Fatalf("missing S bit on bottom label: want ErrLabelInvalid, got %v", err)
	}
	earlyBottom := []taskpkg.Label{
		label(100, 0, true, 64),
		label(300, 0, true, 64),
	}
	if err := g.ValidateStack(earlyBottom); !errors.Is(err, taskpkg.ErrLabelInvalid) {
		t.Fatalf("S bit on non-bottom label: want ErrLabelInvalid, got %v", err)
	}
}

// Reserved labels 0, 2 and 3 are only legal as the bottom label; the other
// reserved values are never legal in transit.
func TestReservedLabelsOnlyAtBottom(t *testing.T) {
	g := mustGuard(t, mplsPolicy())
	if err := g.ValidateStack([]taskpkg.Label{label(7, 0, true, 64)}); !errors.Is(err, taskpkg.ErrReserved) {
		t.Fatalf("reserved label 7: want ErrReserved, got %v", err)
	}
	notBottom := []taskpkg.Label{
		label(0, 0, false, 64),
		label(300, 0, true, 64),
	}
	if err := g.ValidateStack(notBottom); !errors.Is(err, taskpkg.ErrReserved) {
		t.Fatalf("explicit-null label above bottom: want ErrReserved, got %v", err)
	}
	if err := g.ValidateStack([]taskpkg.Label{label(0, 0, true, 64)}); err != nil {
		t.Fatalf("IPv4 explicit null as bottom label: %v", err)
	}
	if err := g.ValidateStack([]taskpkg.Label{label(3, 0, true, 64)}); err != nil {
		t.Fatalf("implicit null as bottom label: %v", err)
	}
}

// TTL zero and TTL below the policy minimum are both rejected.
func TestTTLZeroAndMinTTL(t *testing.T) {
	g := mustGuard(t, mplsPolicy())
	zero := []taskpkg.Label{
		label(100, 0, false, 0),
		label(300, 0, true, 64),
	}
	if err := g.ValidateStack(zero); !errors.Is(err, taskpkg.ErrTTL) {
		t.Fatalf("TTL 0: want ErrTTL, got %v", err)
	}
	belowMin := []taskpkg.Label{
		label(100, 0, false, 64),
		label(300, 0, true, 1),
	}
	if err := g.ValidateStack(belowMin); !errors.Is(err, taskpkg.ErrTTL) {
		t.Fatalf("TTL 1 below MinTTL 2: want ErrTTL, got %v", err)
	}
}

// The policy allow list rejects foreign label values, and an empty list means
// every normal label is allowed.
func TestLabelNotAllowedByPolicy(t *testing.T) {
	g := mustGuard(t, mplsPolicy())
	foreign := []taskpkg.Label{
		label(999, 0, false, 64),
		label(300, 0, true, 64),
	}
	if err := g.ValidateStack(foreign); !errors.Is(err, taskpkg.ErrLabelNotAllowed) {
		t.Fatalf("label outside allow list: want ErrLabelNotAllowed, got %v", err)
	}
	open := mplsPolicy()
	open.AllowedLabels = nil
	g2 := mustGuard(t, open)
	if err := g2.ValidateStack(foreign); err != nil {
		t.Fatalf("label allowed with empty allow list: %v", err)
	}
}

// The stack must match the nexthop expectation exactly, additions are
// idempotent, conflicting re-adds are refused and unknown names are reported.
func TestNexthopExactMatchAndUnknown(t *testing.T) {
	g := mustGuard(t, mplsPolicy())
	mustAddNexthop(t, g, "pe1", []uint32{100, 200, 300})
	if err := g.AddNexthop("pe1", []uint32{100, 200, 300}); err != nil {
		t.Fatalf("idempotent add: %v", err)
	}
	if err := g.AddNexthop("pe1", []uint32{100, 200}); !errors.Is(err, taskpkg.ErrLabelInvalid) {
		t.Fatalf("conflicting add: want ErrLabelInvalid, got %v", err)
	}
	got, err := g.NexthopStack("pe1")
	if err != nil {
		t.Fatalf("NexthopStack: %v", err)
	}
	if !reflect.DeepEqual(got, []uint32{100, 200, 300}) {
		t.Fatalf("NexthopStack = %v, want [100 200 300]", got)
	}
	if err := g.ValidateNexthop("pe1", validStack()); err != nil {
		t.Fatalf("matching nexthop stack: %v", err)
	}
	swapped := []taskpkg.Label{
		label(200, 0, false, 64),
		label(100, 0, false, 64),
		label(300, 0, true, 64),
	}
	if err := g.ValidateNexthop("pe1", swapped); !errors.Is(err, taskpkg.ErrLabelInvalid) {
		t.Fatalf("swapped labels: want ErrLabelInvalid, got %v", err)
	}
	if err := g.ValidateNexthop("pe9", validStack()); !errors.Is(err, taskpkg.ErrNotFound) {
		t.Fatalf("unknown nexthop: want ErrNotFound, got %v", err)
	}
}

// Popping decrements the TTL of the new top label, refuses to empty the stack
// and does not mutate the caller's slice.
func TestPopTTLAndBounds(t *testing.T) {
	g := mustGuard(t, mplsPolicy())
	stack := validStack()
	original := append([]taskpkg.Label(nil), stack...)
	out, err := g.Pop(stack, 2)
	if err != nil {
		t.Fatalf("Pop(2): %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("Pop(2) returned %d labels, want 1", len(out))
	}
	if out[0].Value != 300 || out[0].TTL != 63 {
		t.Fatalf("new top = %+v, want value 300 ttl 63", out[0])
	}
	if !reflect.DeepEqual(stack, original) {
		t.Fatalf("Pop mutated its input: %+v", stack)
	}
	if _, err := g.Pop(stack, 3); !errors.Is(err, taskpkg.ErrStackDepth) {
		t.Fatalf("Pop(3) of depth 3: want ErrStackDepth, got %v", err)
	}
	if _, err := g.Pop(stack, 0); !errors.Is(err, taskpkg.ErrStackDepth) {
		t.Fatalf("Pop(0): want ErrStackDepth, got %v", err)
	}
}

// Push enforces the depth limit, the reserved range and the rule that pushed
// labels are never marked as bottom of stack.
func TestPushDepthAndBottomRules(t *testing.T) {
	g := mustGuard(t, mplsPolicy())
	base := []taskpkg.Label{
		label(100, 0, false, 64),
		label(200, 0, true, 64),
	}
	original := append([]taskpkg.Label(nil), base...)
	tooMany := []taskpkg.Label{
		label(400, 0, false, 64),
		label(400, 0, false, 64),
		label(400, 0, false, 64),
	}
	if _, err := g.Push(base, tooMany); !errors.Is(err, taskpkg.ErrStackDepth) {
		t.Fatalf("push to depth 5: want ErrStackDepth, got %v", err)
	}
	if _, err := g.Push(base, []taskpkg.Label{label(400, 0, true, 64)}); !errors.Is(err, taskpkg.ErrLabelInvalid) {
		t.Fatalf("pushed label with S bit: want ErrLabelInvalid, got %v", err)
	}
	if _, err := g.Push(base, []taskpkg.Label{label(0, 0, false, 64)}); !errors.Is(err, taskpkg.ErrReserved) {
		t.Fatalf("pushed reserved label: want ErrReserved, got %v", err)
	}
	out, err := g.Push(base, []taskpkg.Label{label(400, 0, false, 64)})
	if err != nil {
		t.Fatalf("valid push: %v", err)
	}
	if len(out) != 3 || out[0].Value != 400 || out[2].Value != 200 {
		t.Fatalf("push result = %+v", out)
	}
	if !out[2].S || out[0].S || out[1].S {
		t.Fatalf("bottom-of-stack bits wrong after push: %+v", out)
	}
	if !reflect.DeepEqual(base, original) {
		t.Fatalf("Push mutated its input: %+v", base)
	}
}

// A stack observed twice inside the replay window is a replay; the entry
// expires after the window.
func TestObserveReplayWindow(t *testing.T) {
	g := mustGuard(t, mplsPolicy())
	now := time.Unix(1700000000, 0)
	stack := validStack()
	if err := g.Observe("ac-1", stack, now); err != nil {
		t.Fatalf("first observe: %v", err)
	}
	if err := g.Observe("ac-1", stack, now.Add(30*time.Second)); !errors.Is(err, taskpkg.ErrReplay) {
		t.Fatalf("replayed stack: want ErrReplay, got %v", err)
	}
	if got := g.Counters().ReplayRejected; got != 1 {
		t.Fatalf("ReplayRejected = %d, want 1", got)
	}
	if err := g.Observe("ac-1", stack, now.Add(61*time.Second)); err != nil {
		t.Fatalf("observe after replay window: %v", err)
	}
}

// Live observation entries are bounded by MaxFlows; expired entries are
// reclaimed before the limit is applied.
func TestObserveFlowLimit(t *testing.T) {
	p := mplsPolicy()
	p.MaxFlows = 2
	g := mustGuard(t, p)
	now := time.Unix(1700000000, 0)
	a := []taskpkg.Label{label(100, 0, false, 64), label(300, 0, true, 64)}
	b := []taskpkg.Label{label(200, 0, false, 64), label(300, 0, true, 64)}
	c := []taskpkg.Label{label(400, 0, true, 64)}
	if err := g.Observe("ac-1", a, now); err != nil {
		t.Fatalf("observe a: %v", err)
	}
	if err := g.Observe("ac-1", b, now); err != nil {
		t.Fatalf("observe b: %v", err)
	}
	if err := g.Observe("ac-1", c, now); !errors.Is(err, taskpkg.ErrFlowLimit) {
		t.Fatalf("overflow flow table: want ErrFlowLimit, got %v", err)
	}
	if got := g.Counters().FlowRejected; got != 1 {
		t.Fatalf("FlowRejected = %d, want 1", got)
	}
	if err := g.Observe("ac-1", c, now.Add(61*time.Second)); err != nil {
		t.Fatalf("observe after expiry: %v", err)
	}
}

// Two concurrent observations of the same stack must admit exactly one.
func TestObserveConcurrentSingleWinner(t *testing.T) {
	g := mustGuard(t, mplsPolicy())
	now := time.Unix(1700000000, 0)
	stack := validStack()
	var wg sync.WaitGroup
	errs := make([]error, 2)
	wg.Add(2)
	for i := 0; i < 2; i++ {
		go func(idx int) {
			defer wg.Done()
			errs[idx] = g.Observe("ac-7", stack, now)
		}(i)
	}
	wg.Wait()
	success := 0
	replays := 0
	for _, err := range errs {
		switch {
		case err == nil:
			success++
		case errors.Is(err, taskpkg.ErrReplay):
			replays++
		}
	}
	if success != 1 || replays != 1 {
		t.Fatalf("want one success and one replay, got success=%d replay=%d errs=%v", success, replays, errs)
	}
}

// A restart must keep both replay state and counters; corrupt snapshots are
// refused.
func TestSnapshotRestoresState(t *testing.T) {
	p := mplsPolicy()
	g := mustGuard(t, p)
	now := time.Unix(1700000000, 0)
	stack := validStack()
	if err := g.Observe("ac-1", stack, now); err != nil {
		t.Fatalf("observe: %v", err)
	}
	snap, err := g.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if _, err := taskpkg.NewMplsGuardFromSnapshot(p, []byte("{not-json")); !errors.Is(err, taskpkg.ErrSnapshot) {
		t.Fatalf("corrupt snapshot: want ErrSnapshot, got %v", err)
	}
	restored, err := taskpkg.NewMplsGuardFromSnapshot(p, snap)
	if err != nil {
		t.Fatalf("NewMplsGuardFromSnapshot: %v", err)
	}
	if err := restored.Observe("ac-1", stack, now.Add(10*time.Second)); !errors.Is(err, taskpkg.ErrReplay) {
		t.Fatalf("replay after restart: want ErrReplay, got %v", err)
	}
	if got := restored.Counters().Accepted; got != 1 {
		t.Fatalf("Accepted after restore = %d, want 1", got)
	}
}
