package task

import (
	"errors"
	"sync"
	"testing"
	"time"

	taskpkg "gsb/batch46-safety-d-07"
)

func dotConfig() taskpkg.Config {
	return taskpkg.Config{
		BlockSize:         128,
		MinSize:           64,
		MaxSize:           4096,
		MaxConns:          4,
		MaxOutstanding:    2,
		MaxQueriesPerConn: 100,
		IdleTimeout:       30 * time.Second,
	}
}

func padConfig() taskpkg.Config {
	cfg := dotConfig()
	cfg.MinSize = 0
	return cfg
}

// The padded length is the smallest block multiple not below the wire size.
func TestPadLengthRoundsUpToBlock(t *testing.T) {
	g := taskpkg.NewDotPaddingGuard(padConfig())
	got, err := g.PadLength(45)
	if err != nil {
		t.Fatalf("PadLength(45): %v", err)
	}
	if got != 128 {
		t.Fatalf("PadLength(45) = %d, want 128", got)
	}
	got, err = g.PadLength(129)
	if err != nil {
		t.Fatalf("PadLength(129): %v", err)
	}
	if got != 256 {
		t.Fatalf("PadLength(129) = %d, want 256", got)
	}
}

// Small messages are raised to MinSize before rounding.
func TestPadLengthHonorsMinimumSize(t *testing.T) {
	cfg := dotConfig()
	cfg.MinSize = 200
	g := taskpkg.NewDotPaddingGuard(cfg)
	got, err := g.PadLength(45)
	if err != nil {
		t.Fatalf("PadLength(45): %v", err)
	}
	if got != 256 {
		t.Fatalf("PadLength(45) with MinSize 200 = %d, want 256", got)
	}
	got, err = g.PadLength(129)
	if err != nil {
		t.Fatalf("PadLength(129): %v", err)
	}
	if got != 256 {
		t.Fatalf("PadLength(129) with MinSize 200 = %d, want 256", got)
	}
}

// A message that already ends on a block boundary must not grow by a full
// block.
func TestPadLengthKeepsExactMultiple(t *testing.T) {
	g := taskpkg.NewDotPaddingGuard(padConfig())
	got, err := g.PadLength(128)
	if err != nil {
		t.Fatalf("PadLength(128): %v", err)
	}
	if got != 128 {
		t.Fatalf("PadLength(128) = %d, want 128", got)
	}
	got, err = g.PadLength(256)
	if err != nil {
		t.Fatalf("PadLength(256): %v", err)
	}
	if got != 256 {
		t.Fatalf("PadLength(256) = %d, want 256", got)
	}
}

// Messages above MaxSize are refused, including the case where rounding
// pushes a legal wire size over the limit.
func TestPadLengthRejectsOversize(t *testing.T) {
	cfg := padConfig()
	cfg.MaxSize = 512
	g := taskpkg.NewDotPaddingGuard(cfg)
	if _, err := g.PadLength(600); !errors.Is(err, taskpkg.ErrTooLarge) {
		t.Fatalf("PadLength(600) = %v, want ErrTooLarge", err)
	}
	if got, err := g.PadLength(500); err != nil || got != 512 {
		t.Fatalf("PadLength(500) = %d, %v; want 512 inside MaxSize", got, err)
	}
	tight := padConfig()
	tight.MinSize = 500
	tight.MaxSize = 500
	gt := taskpkg.NewDotPaddingGuard(tight)
	if _, err := gt.PadLength(100); !errors.Is(err, taskpkg.ErrTooLarge) {
		t.Fatalf("PadLength rounded past MaxSize = %v, want ErrTooLarge", err)
	}
}

// A broken block size or a negative wire size is a configuration error.
func TestPadLengthRejectsInvalidConfig(t *testing.T) {
	broken := padConfig()
	broken.BlockSize = 0
	g := taskpkg.NewDotPaddingGuard(broken)
	if _, err := g.PadLength(45); !errors.Is(err, taskpkg.ErrInvalidConfig) {
		t.Fatalf("PadLength with BlockSize 0 = %v, want ErrInvalidConfig", err)
	}
	ok := taskpkg.NewDotPaddingGuard(padConfig())
	if _, err := ok.PadLength(-1); !errors.Is(err, taskpkg.ErrInvalidConfig) {
		t.Fatalf("PadLength(-1) = %v, want ErrInvalidConfig", err)
	}
}

// PaddingBytes is exactly the gap between wire size and padded length.
func TestPaddingBytesMatchesPaddedLength(t *testing.T) {
	g := taskpkg.NewDotPaddingGuard(padConfig())
	pad, err := g.PaddingBytes(100)
	if err != nil {
		t.Fatalf("PaddingBytes(100): %v", err)
	}
	if pad != 28 {
		t.Fatalf("PaddingBytes(100) = %d, want 28", pad)
	}
	total, err := g.PadLength(100)
	if err != nil {
		t.Fatalf("PadLength(100): %v", err)
	}
	if total-pad != 100 {
		t.Fatalf("padded length %d minus padding %d = %d, want 100", total, pad, total-pad)
	}
	zero, err := g.PaddingBytes(128)
	if err != nil {
		t.Fatalf("PaddingBytes(128): %v", err)
	}
	if zero != 0 {
		t.Fatalf("PaddingBytes(128) = %d, want 0", zero)
	}
}

// A first acquire opens a connection and books one in-flight query.
func TestAcquireCreatesConnection(t *testing.T) {
	g := taskpkg.NewDotPaddingGuard(dotConfig())
	now := time.Unix(1700000000, 0)
	id, err := g.Acquire(now)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if id == "" {
		t.Fatal("Acquire returned an empty connection id")
	}
	if n := g.ConnCount(); n != 1 {
		t.Fatalf("ConnCount = %d after first acquire, want 1", n)
	}
	if out, err := g.Outstanding(id); err != nil || out != 1 {
		t.Fatalf("Outstanding(%q) = %d, %v; want 1, nil", id, out, err)
	}
	if stats := g.Stats(); stats.Outstanding != 1 || stats.Acquired != 1 {
		t.Fatalf("Stats = %+v after one acquire, want Outstanding 1 and Acquired 1", stats)
	}
}

// The least loaded connection is reused until it reaches MaxOutstanding.
func TestAcquireReusesLeastLoadedConnection(t *testing.T) {
	g := taskpkg.NewDotPaddingGuard(dotConfig())
	now := time.Unix(1700000000, 0)
	first, err := g.Acquire(now)
	if err != nil {
		t.Fatalf("Acquire 1: %v", err)
	}
	second, err := g.Acquire(now)
	if err != nil {
		t.Fatalf("Acquire 2: %v", err)
	}
	if second != first {
		t.Fatalf("second acquire used %q instead of reusing %q", second, first)
	}
	if n := g.ConnCount(); n != 1 {
		t.Fatalf("ConnCount = %d after two acquires with room, want 1", n)
	}
	if out, err := g.Outstanding(first); err != nil || out != 2 {
		t.Fatalf("Outstanding(%q) = %d, %v; want 2, nil", first, out, err)
	}
	third, err := g.Acquire(now)
	if err != nil {
		t.Fatalf("Acquire 3: %v", err)
	}
	if third == first {
		t.Fatalf("third acquire reused a full connection %q", third)
	}
	if n := g.ConnCount(); n != 2 {
		t.Fatalf("ConnCount = %d after opening a second connection, want 2", n)
	}
}

// A connection at its in-flight limit must not receive more queries.
func TestAcquireSpreadsAtOutstandingLimit(t *testing.T) {
	cfg := dotConfig()
	cfg.MaxOutstanding = 1
	cfg.MaxConns = 3
	g := taskpkg.NewDotPaddingGuard(cfg)
	now := time.Unix(1700000000, 0)
	a, err := g.Acquire(now)
	if err != nil {
		t.Fatalf("Acquire 1: %v", err)
	}
	b, err := g.Acquire(now)
	if err != nil {
		t.Fatalf("Acquire 2: %v", err)
	}
	if a == b {
		t.Fatalf("both acquires used the same saturated connection %q", a)
	}
	if n := g.ConnCount(); n != 2 {
		t.Fatalf("ConnCount = %d, want 2 distinct connections", n)
	}
}

// When every connection is saturated and the pool cannot grow, Acquire fails
// without leaking a slot.
func TestAcquireFailsAtCapacity(t *testing.T) {
	cfg := dotConfig()
	cfg.MaxConns = 1
	cfg.MaxOutstanding = 1
	g := taskpkg.NewDotPaddingGuard(cfg)
	now := time.Unix(1700000000, 0)
	if _, err := g.Acquire(now); err != nil {
		t.Fatalf("first Acquire: %v", err)
	}
	id, err := g.Acquire(now)
	if !errors.Is(err, taskpkg.ErrPoolFull) {
		t.Fatalf("second Acquire = %q, %v; want ErrPoolFull", id, err)
	}
	if id != "" {
		t.Fatalf("failed Acquire returned id %q, want empty", id)
	}
	if stats := g.Stats(); stats.Acquired != 1 || stats.Outstanding != 1 || stats.Conns != 1 {
		t.Fatalf("Stats = %+v after a rejected acquire, want Acquired 1, Outstanding 1, Conns 1", stats)
	}
}

// Release gives the slot back exactly once and double release is rejected.
func TestReleaseAccountingAndDoubleRelease(t *testing.T) {
	g := taskpkg.NewDotPaddingGuard(dotConfig())
	now := time.Unix(1700000000, 0)
	id, err := g.Acquire(now)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if err := g.Release(id, now); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if out, err := g.Outstanding(id); err != nil || out != 0 {
		t.Fatalf("Outstanding(%q) after release = %d, %v; want 0, nil", id, out, err)
	}
	if stats := g.Stats(); stats.Outstanding != 0 || stats.Released != 1 {
		t.Fatalf("Stats = %+v after release, want Outstanding 0 and Released 1", stats)
	}
	if err := g.Release(id, now); !errors.Is(err, taskpkg.ErrUnknownConn) {
		t.Fatalf("double release = %v, want ErrUnknownConn", err)
	}
	if stats := g.Stats(); stats.Outstanding != 0 || stats.Released != 1 {
		t.Fatalf("Stats = %+v after a double release, want no change", stats)
	}
}

// Idle cleanup closes only connections without leases.
func TestCloseIdleClosesOnlyIdleConnections(t *testing.T) {
	cfg := dotConfig()
	cfg.MaxOutstanding = 1
	cfg.MaxConns = 2
	cfg.IdleTimeout = 30 * time.Second
	g := taskpkg.NewDotPaddingGuard(cfg)
	now := time.Unix(1700000000, 0)
	idle, err := g.Acquire(now)
	if err != nil {
		t.Fatalf("Acquire idle: %v", err)
	}
	busy, err := g.Acquire(now)
	if err != nil {
		t.Fatalf("Acquire busy: %v", err)
	}
	if idle == busy {
		t.Fatalf("expected two connections, both acquires used %q", idle)
	}
	if err := g.Release(idle, now); err != nil {
		t.Fatalf("Release idle: %v", err)
	}
	if closed := g.CloseIdle(now.Add(31 * time.Second)); closed != 1 {
		t.Fatalf("CloseIdle closed %d connections, want 1", closed)
	}
	if n := g.ConnCount(); n != 1 {
		t.Fatalf("ConnCount = %d after idle cleanup, want 1 busy connection", n)
	}
	if _, err := g.Outstanding(idle); !errors.Is(err, taskpkg.ErrUnknownConn) {
		t.Fatalf("Outstanding of the closed connection = %v, want ErrUnknownConn", err)
	}
	if out, err := g.Outstanding(busy); err != nil || out != 1 {
		t.Fatalf("Outstanding of the busy connection = %d, %v; want 1, nil", out, err)
	}
	if closed := g.CloseIdle(now.Add(60 * time.Second)); closed != 0 {
		t.Fatalf("CloseIdle closed %d busy connections, want 0", closed)
	}
}

// A connection that spent its query budget is retired after the last lease
// is released.
func TestConnectionRetiredAfterQueryBudget(t *testing.T) {
	cfg := dotConfig()
	cfg.MaxConns = 2
	cfg.MaxOutstanding = 1
	cfg.MaxQueriesPerConn = 2
	g := taskpkg.NewDotPaddingGuard(cfg)
	now := time.Unix(1700000000, 0)
	first, err := g.Acquire(now)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if err := g.MarkSent(first); err != nil {
		t.Fatalf("MarkSent 1: %v", err)
	}
	if err := g.MarkSent(first); err != nil {
		t.Fatalf("MarkSent 2: %v", err)
	}
	if err := g.MarkSent(first); !errors.Is(err, taskpkg.ErrQueryBudget) {
		t.Fatalf("MarkSent past the budget = %v, want ErrQueryBudget", err)
	}
	if err := g.Release(first, now); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if n := g.ConnCount(); n != 0 {
		t.Fatalf("ConnCount = %d after retiring a spent connection, want 0", n)
	}
	second, err := g.Acquire(now)
	if err != nil {
		t.Fatalf("Acquire after retirement: %v", err)
	}
	if second == first {
		t.Fatalf("retired connection %q was handed out again", second)
	}
}

// Connection ids and in-flight accounting survive a snapshot and restore.
func TestSnapshotRestoresPoolState(t *testing.T) {
	cfg := dotConfig()
	cfg.MaxOutstanding = 1
	cfg.MaxConns = 2
	g := taskpkg.NewDotPaddingGuard(cfg)
	now := time.Unix(1700000000, 0)
	a, err := g.Acquire(now)
	if err != nil {
		t.Fatalf("Acquire a: %v", err)
	}
	b, err := g.Acquire(now)
	if err != nil {
		t.Fatalf("Acquire b: %v", err)
	}
	if err := g.MarkSent(a); err != nil {
		t.Fatalf("MarkSent: %v", err)
	}
	snap, err := g.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	restored, err := taskpkg.NewDotPaddingGuardFromSnapshot(cfg, snap)
	if err != nil {
		t.Fatalf("NewDotPaddingGuardFromSnapshot: %v", err)
	}
	if n := restored.ConnCount(); n != 2 {
		t.Fatalf("ConnCount after restore = %d, want 2", n)
	}
	if out, err := restored.Outstanding(a); err != nil || out != 1 {
		t.Fatalf("Outstanding(%q) after restore = %d, %v; want 1, nil", a, out, err)
	}
	if out, err := restored.Outstanding(b); err != nil || out != 1 {
		t.Fatalf("Outstanding(%q) after restore = %d, %v; want 1, nil", b, out, err)
	}
	if err := restored.Release(a, now.Add(time.Second)); err != nil {
		t.Fatalf("Release after restore: %v", err)
	}
	if out, err := restored.Outstanding(a); err != nil || out != 0 {
		t.Fatalf("Outstanding(%q) after restored release = %d, %v; want 0, nil", a, out, err)
	}
}

// Concurrent acquire/release cycles must balance out and respect the pool
// limits.
func TestConcurrentAcquireReleaseBalances(t *testing.T) {
	cfg := dotConfig()
	cfg.MaxConns = 8
	cfg.MaxOutstanding = 8
	cfg.MaxQueriesPerConn = 1000
	g := taskpkg.NewDotPaddingGuard(cfg)
	now := time.Unix(1700000000, 0)
	const workers = 40
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id, err := g.Acquire(now)
			if err != nil {
				errs <- err
				return
			}
			if err := g.MarkSent(id); err != nil {
				errs <- err
				return
			}
			if err := g.Release(id, now); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent acquire/release: %v", err)
	}
	stats := g.Stats()
	if stats.Acquired != workers || stats.Released != workers {
		t.Fatalf("Stats = %+v, want Acquired and Released both %d", stats, workers)
	}
	if stats.Outstanding != 0 {
		t.Fatalf("Outstanding = %d after all leases were released, want 0", stats.Outstanding)
	}
	if stats.Conns > cfg.MaxConns {
		t.Fatalf("Conns = %d exceeds MaxConns %d", stats.Conns, cfg.MaxConns)
	}
}
