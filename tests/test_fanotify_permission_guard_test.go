package task

import (
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	taskpkg "gsb/batch46-safety-e-03"
)

func fanCfg() taskpkg.Config {
	return taskpkg.Config{
		ResponseTimeout: 5 * time.Second,
		MaxMarks:        4,
		MaxPending:      2,
	}
}

func markOK(t *testing.T, g *taskpkg.FanotifyGuard, path string, mask taskpkg.Mask) int {
	t.Helper()
	id, err := g.Mark(path, mask)
	if err != nil {
		t.Fatalf("Mark %q: %v", path, err)
	}
	return id
}

func beginOK(t *testing.T, g *taskpkg.FanotifyGuard, path string, op taskpkg.Op, now time.Time) taskpkg.Event {
	t.Helper()
	ev, err := g.Begin(path, op, now)
	if err != nil {
		t.Fatalf("Begin %q %s: %v", path, op, err)
	}
	return ev
}

// Marks only make sense for absolute, already cleaned paths.
func TestMarkRejectsInvalidPath(t *testing.T) {
	g := taskpkg.NewFanotifyGuard(fanCfg())
	for _, p := range []string{"", "etc/nginx.conf", "/etc/./nginx.conf", "/etc/nginx.conf/"} {
		if _, err := g.Mark(p, taskpkg.MaskOpenPerm); !errors.Is(err, taskpkg.ErrInvalidPath) {
			t.Fatalf("Mark(%q): want ErrInvalidPath, got %v", p, err)
		}
	}
}

// A mask without FAN_*_PERM would never produce a permission event.
func TestMarkRejectsMaskWithoutPermissionBits(t *testing.T) {
	g := taskpkg.NewFanotifyGuard(fanCfg())
	if _, err := g.Mark("/etc/nginx.conf", 0); !errors.Is(err, taskpkg.ErrInvalidMask) {
		t.Fatalf("empty mask: want ErrInvalidMask, got %v", err)
	}
}

// Two marks for the same path would answer one event twice.
func TestMarkDuplicatePathRejected(t *testing.T) {
	g := taskpkg.NewFanotifyGuard(fanCfg())
	markOK(t, g, "/etc/nginx.conf", taskpkg.MaskOpenPerm)
	if _, err := g.Mark("/etc/nginx.conf", taskpkg.MaskAccessPerm); !errors.Is(err, taskpkg.ErrAlreadyMarked) {
		t.Fatalf("second mark for the same path: want ErrAlreadyMarked, got %v", err)
	}
}

// The mark table is bounded by MaxMarks.
func TestMarkCapEnforced(t *testing.T) {
	g := taskpkg.NewFanotifyGuard(fanCfg())
	markOK(t, g, "/etc/passwd", taskpkg.MaskOpenPerm)
	markOK(t, g, "/etc/shadow", taskpkg.MaskOpenPerm)
	markOK(t, g, "/etc/nginx.conf", taskpkg.MaskOpenPerm)
	markOK(t, g, "/srv/data/app.db", taskpkg.MaskAccessPerm)
	if _, err := g.Mark("/srv/data/app.log", taskpkg.MaskAccessPerm); !errors.Is(err, taskpkg.ErrCapReached) {
		t.Fatalf("fifth mark: want ErrCapReached, got %v", err)
	}
}

// Removing a mark that was never created must be reported.
func TestUnmarkUnknownIDRejected(t *testing.T) {
	g := taskpkg.NewFanotifyGuard(fanCfg())
	if err := g.Unmark(42); !errors.Is(err, taskpkg.ErrUnknownMark) {
		t.Fatalf("Unmark 42: want ErrUnknownMark, got %v", err)
	}
}

// A mark with a blocked event cannot be removed until the event is answered.
func TestUnmarkBusyWhileEventPending(t *testing.T) {
	g := taskpkg.NewFanotifyGuard(fanCfg())
	now := time.Unix(1700000000, 0)
	id := markOK(t, g, "/etc/nginx.conf", taskpkg.MaskOpenPerm)
	ev := beginOK(t, g, "/etc/nginx.conf", taskpkg.OpOpen, now)
	if err := g.Unmark(id); !errors.Is(err, taskpkg.ErrBusy) {
		t.Fatalf("unmark with a blocked event: want ErrBusy, got %v", err)
	}
	if err := g.Respond(ev.ID, taskpkg.DecisionAllow, now); err != nil {
		t.Fatalf("Respond allow: %v", err)
	}
	if err := g.Unmark(id); err != nil {
		t.Fatalf("unmark after the event was answered: %v", err)
	}
}

// An event is only raised where a mark covers its operation.
func TestBeginRequiresCoveringMark(t *testing.T) {
	g := taskpkg.NewFanotifyGuard(fanCfg())
	now := time.Unix(1700000000, 0)
	if _, err := g.Begin("/proc/self/maps", taskpkg.OpOpen, now); !errors.Is(err, taskpkg.ErrNoMark) {
		t.Fatalf("unmarked path: want ErrNoMark, got %v", err)
	}
	markOK(t, g, "/etc/nginx.conf", taskpkg.MaskOpenPerm)
	if _, err := g.Begin("/etc/nginx.conf", taskpkg.OpAccess, now); !errors.Is(err, taskpkg.ErrNoMark) {
		t.Fatalf("access event without the access bit: want ErrNoMark, got %v", err)
	}
	if _, err := g.Begin("/etc/nginx.conf", taskpkg.OpOpen, now); err != nil {
		t.Fatalf("open event on a marked path: %v", err)
	}
}

// Blocked processes are a bounded resource; the queue must push back.
func TestBeginQueueCapEnforced(t *testing.T) {
	cfg := fanCfg()
	cfg.MaxPending = 1
	g := taskpkg.NewFanotifyGuard(cfg)
	now := time.Unix(1700000000, 0)
	markOK(t, g, "/etc/nginx.conf", taskpkg.MaskOpenPerm)
	beginOK(t, g, "/etc/nginx.conf", taskpkg.OpOpen, now)
	if _, err := g.Begin("/etc/nginx.conf", taskpkg.OpOpen, now.Add(time.Second)); !errors.Is(err, taskpkg.ErrQueueFull) {
		t.Fatalf("second blocked event: want ErrQueueFull, got %v", err)
	}
}

// Answering an event id the guard never issued must not create state.
func TestRespondUnknownEventRejected(t *testing.T) {
	g := taskpkg.NewFanotifyGuard(fanCfg())
	now := time.Unix(1700000000, 0)
	markOK(t, g, "/etc/nginx.conf", taskpkg.MaskOpenPerm)
	if err := g.Respond(taskpkg.EventID(999), taskpkg.DecisionAllow, now); !errors.Is(err, taskpkg.ErrUnknownEvent) {
		t.Fatalf("Respond 999: want ErrUnknownEvent, got %v", err)
	}
	if got := g.PendingCount(); got != 0 {
		t.Fatalf("unknown id changed the queue: pending=%d", got)
	}
}

// A verdict is only accepted once, and only for a real Decision.
func TestRespondAllowClearsPending(t *testing.T) {
	g := taskpkg.NewFanotifyGuard(fanCfg())
	now := time.Unix(1700000000, 0)
	markOK(t, g, "/etc/nginx.conf", taskpkg.MaskOpenPerm)
	ev := beginOK(t, g, "/etc/nginx.conf", taskpkg.OpOpen, now)
	if err := g.Respond(ev.ID, taskpkg.Decision("maybe"), now); !errors.Is(err, taskpkg.ErrInvalidDecision) {
		t.Fatalf("bogus decision: want ErrInvalidDecision, got %v", err)
	}
	if got := g.PendingCount(); got != 1 {
		t.Fatalf("rejected decision consumed the event: pending=%d, want 1", got)
	}
	if err := g.Respond(ev.ID, taskpkg.DecisionAllow, now); err != nil {
		t.Fatalf("Respond allow: %v", err)
	}
	st := g.Stats()
	if st.Allowed != 1 || st.Pending != 0 || st.Denied != 0 {
		t.Fatalf("stats = %+v, want allowed=1 pending=0 denied=0", st)
	}
	if err := g.Respond(ev.ID, taskpkg.DecisionDeny, now); !errors.Is(err, taskpkg.ErrAlreadyAnswered) {
		t.Fatalf("second verdict: want ErrAlreadyAnswered, got %v", err)
	}
}

// The kernel does not accept two verdicts for the same blocked process.
func TestRespondTwiceRejected(t *testing.T) {
	g := taskpkg.NewFanotifyGuard(fanCfg())
	now := time.Unix(1700000000, 0)
	markOK(t, g, "/srv/data/app.db", taskpkg.MaskAccessPerm)
	ev := beginOK(t, g, "/srv/data/app.db", taskpkg.OpAccess, now)
	if err := g.Respond(ev.ID, taskpkg.DecisionDeny, now); err != nil {
		t.Fatalf("Respond deny: %v", err)
	}
	if err := g.Respond(ev.ID, taskpkg.DecisionAllow, now); !errors.Is(err, taskpkg.ErrAlreadyAnswered) {
		t.Fatalf("verdict after deny: want ErrAlreadyAnswered, got %v", err)
	}
	if got := g.Stats(); got.Denied != 1 || got.Allowed != 0 {
		t.Fatalf("stats = %+v, want denied=1 allowed=0", got)
	}
}

// A responder that stalls must not leave processes blocked forever.
func TestSweepExpiresPendingEvents(t *testing.T) {
	g := taskpkg.NewFanotifyGuard(fanCfg())
	now := time.Unix(1700000000, 0)
	markOK(t, g, "/etc/nginx.conf", taskpkg.MaskOpenPerm)
	ev := beginOK(t, g, "/etc/nginx.conf", taskpkg.OpOpen, now)
	if got := g.Sweep(now.Add(4 * time.Second)); got != 0 {
		t.Fatalf("sweep before the deadline expired %d events", got)
	}
	if got := g.Sweep(now.Add(5 * time.Second)); got != 1 {
		t.Fatalf("sweep at the deadline expired %d events, want 1", got)
	}
	st := g.Stats()
	if st.Denied != 1 || st.Expired != 1 || st.Pending != 0 {
		t.Fatalf("stats = %+v, want denied=1 expired=1 pending=0", st)
	}
	if err := g.Respond(ev.ID, taskpkg.DecisionAllow, now.Add(6*time.Second)); !errors.Is(err, taskpkg.ErrExpired) {
		t.Fatalf("verdict after expiry: want ErrExpired, got %v", err)
	}
	if got := g.Sweep(now.Add(7 * time.Second)); got != 0 {
		t.Fatalf("second sweep expired %d events, want 0", got)
	}
}

// Two threads answering the same blocked process: one verdict, one rejection.
func TestConcurrentRespondSingleWinner(t *testing.T) {
	g := taskpkg.NewFanotifyGuard(fanCfg())
	now := time.Unix(1700000000, 0)
	markOK(t, g, "/srv/data/app.db", taskpkg.MaskAccessPerm)
	ev := beginOK(t, g, "/srv/data/app.db", taskpkg.OpAccess, now)
	errs := make([]error, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		errs[0] = g.Respond(ev.ID, taskpkg.DecisionAllow, now)
	}()
	go func() {
		defer wg.Done()
		errs[1] = g.Respond(ev.ID, taskpkg.DecisionDeny, now)
	}()
	wg.Wait()
	wins := 0
	for _, err := range errs {
		if err == nil {
			wins++
		} else if !errors.Is(err, taskpkg.ErrAlreadyAnswered) {
			t.Fatalf("loser returned %v, want ErrAlreadyAnswered", err)
		}
	}
	if wins != 1 {
		t.Fatalf("concurrent verdicts: %d winners, want exactly 1", wins)
	}
	if st := g.Stats(); st.Allowed+st.Denied != 1 {
		t.Fatalf("stats after the race = %+v, want exactly one verdict", st)
	}
}

// A restart keeps marks and counters but unblocks every waiting process.
func TestSnapshotRestoresMarksAndDropsPending(t *testing.T) {
	g := taskpkg.NewFanotifyGuard(fanCfg())
	now := time.Unix(1700000000, 0)
	markOK(t, g, "/etc/passwd", taskpkg.MaskOpenPerm)
	markOK(t, g, "/etc/shadow", taskpkg.MaskAccessPerm)
	ev := beginOK(t, g, "/etc/passwd", taskpkg.OpOpen, now)
	snap, err := g.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	restored, err := taskpkg.NewFanotifyGuardFromSnapshot(fanCfg(), snap)
	if err != nil {
		t.Fatalf("NewFanotifyGuardFromSnapshot: %v", err)
	}
	want := []taskpkg.Mark{
		{ID: 1, Path: "/etc/passwd", Mask: taskpkg.MaskOpenPerm},
		{ID: 2, Path: "/etc/shadow", Mask: taskpkg.MaskAccessPerm},
	}
	if got := restored.Marks(); !reflect.DeepEqual(got, want) {
		t.Fatalf("restored marks = %+v, want %+v", got, want)
	}
	if got := restored.PendingCount(); got != 0 {
		t.Fatalf("restored pending = %d, want 0", got)
	}
	if err := restored.Respond(ev.ID, taskpkg.DecisionAllow, now); !errors.Is(err, taskpkg.ErrUnknownEvent) {
		t.Fatalf("verdict for a pre-restart event: want ErrUnknownEvent, got %v", err)
	}
	next := beginOK(t, restored, "/etc/passwd", taskpkg.OpOpen, now)
	if next.ID <= ev.ID {
		t.Fatalf("event id after restart = %d, want > %d", next.ID, ev.ID)
	}
}

// Marks are always reported in path order.
func TestMarksSortedByPath(t *testing.T) {
	g := taskpkg.NewFanotifyGuard(fanCfg())
	markOK(t, g, "/srv/zeta/app.db", taskpkg.MaskAccessPerm)
	markOK(t, g, "/etc/nginx.conf", taskpkg.MaskOpenPerm)
	markOK(t, g, "/etc/passwd", taskpkg.MaskOpenPerm)
	marks := g.Marks()
	paths := make([]string, 0, len(marks))
	for _, m := range marks {
		paths = append(paths, m.Path)
	}
	want := []string{"/etc/nginx.conf", "/etc/passwd", "/srv/zeta/app.db"}
	if !reflect.DeepEqual(paths, want) {
		t.Fatalf("mark order = %v, want %v", paths, want)
	}
}
