package task

import (
	"errors"
	"reflect"
	"sync"
	"testing"

	taskpkg "gsb/batch46-safety-e-05"
)

func overlayCfg() taskpkg.Config {
	return taskpkg.Config{MaxLayers: 6, MaxEntriesPerLayer: 8}
}

func fileEntry(path string, size int64) taskpkg.Entry {
	return taskpkg.Entry{Path: path, Kind: taskpkg.KindFile, Size: size}
}

func dirEntry(path string) taskpkg.Entry {
	return taskpkg.Entry{Path: path, Kind: taskpkg.KindDir}
}

func addLayerOK(t *testing.T, g *taskpkg.OverlayGuard, l taskpkg.Layer) {
	t.Helper()
	if err := g.AddLayer(l); err != nil {
		t.Fatalf("AddLayer %d: %v", l.ID, err)
	}
}

// Layer ids start at 1 and may only move forward.
func TestLayerOrderRequiresIncreasingIDs(t *testing.T) {
	g := taskpkg.NewOverlayGuard(overlayCfg())
	if err := g.AddLayer(taskpkg.Layer{ID: 0}); !errors.Is(err, taskpkg.ErrLayerOrder) {
		t.Fatalf("layer id 0: want ErrLayerOrder, got %v", err)
	}
	addLayerOK(t, g, taskpkg.Layer{ID: 2, Entries: []taskpkg.Entry{fileEntry("/etc/nginx.conf", 10)}})
	if err := g.AddLayer(taskpkg.Layer{ID: 1, Entries: []taskpkg.Entry{fileEntry("/etc/nginx.conf", 10)}}); !errors.Is(err, taskpkg.ErrLayerOrder) {
		t.Fatalf("layer id going backwards: want ErrLayerOrder, got %v", err)
	}
}

// Replaying the same layer twice must not merge it twice.
func TestDuplicateLayerIDRejected(t *testing.T) {
	g := taskpkg.NewOverlayGuard(overlayCfg())
	addLayerOK(t, g, taskpkg.Layer{ID: 1, Entries: []taskpkg.Entry{fileEntry("/etc/passwd", 40)}})
	err := g.AddLayer(taskpkg.Layer{ID: 1, Entries: []taskpkg.Entry{fileEntry("/etc/passwd", 40)}})
	if !errors.Is(err, taskpkg.ErrDuplicateLayer) {
		t.Fatalf("duplicate layer: want ErrDuplicateLayer, got %v", err)
	}
	if got := g.Stats().Layers; got != 1 {
		t.Fatalf("layers after duplicate = %d, want 1", got)
	}
}

// One layer cannot carry two inodes for the same path.
func TestDuplicateEntryRejected(t *testing.T) {
	g := taskpkg.NewOverlayGuard(overlayCfg())
	err := g.AddLayer(taskpkg.Layer{ID: 1, Entries: []taskpkg.Entry{
		fileEntry("/etc/nginx.conf", 10),
		fileEntry("/etc/nginx.conf", 20),
	}})
	if !errors.Is(err, taskpkg.ErrDuplicateEntry) {
		t.Fatalf("duplicate entry: want ErrDuplicateEntry, got %v", err)
	}
}

// A layer cannot both ship a file and delete it.
func TestWhiteoutConflictRejected(t *testing.T) {
	g := taskpkg.NewOverlayGuard(overlayCfg())
	err := g.AddLayer(taskpkg.Layer{
		ID:        1,
		Entries:   []taskpkg.Entry{fileEntry("/etc/nginx.conf", 10)},
		Whiteouts: []string{"/etc/nginx.conf"},
	})
	if !errors.Is(err, taskpkg.ErrWhiteoutConflict) {
		t.Fatalf("whiteout over a same-layer entry: want ErrWhiteoutConflict, got %v", err)
	}
}

// Opaque only makes sense on a directory the layer itself provides.
func TestOpaqueWithoutDirRejected(t *testing.T) {
	g := taskpkg.NewOverlayGuard(overlayCfg())
	err := g.AddLayer(taskpkg.Layer{ID: 1, Opaque: []string{"/var/cache"}})
	if !errors.Is(err, taskpkg.ErrOpaqueWithoutDir) {
		t.Fatalf("opaque without an entry: want ErrOpaqueWithoutDir, got %v", err)
	}
	err = g.AddLayer(taskpkg.Layer{
		ID:      1,
		Entries: []taskpkg.Entry{fileEntry("/var/cache", 9)},
		Opaque:  []string{"/var/cache"},
	})
	if !errors.Is(err, taskpkg.ErrOpaqueWithoutDir) {
		t.Fatalf("opaque on a file entry: want ErrOpaqueWithoutDir, got %v", err)
	}
}

// One layer must stay inside the entry budget.
func TestEntryBudgetEnforced(t *testing.T) {
	cfg := overlayCfg()
	cfg.MaxEntriesPerLayer = 2
	g := taskpkg.NewOverlayGuard(cfg)
	err := g.AddLayer(taskpkg.Layer{ID: 1, Entries: []taskpkg.Entry{
		dirEntry("/etc"),
		fileEntry("/etc/passwd", 40),
		fileEntry("/etc/shadow", 30),
	}})
	if !errors.Is(err, taskpkg.ErrTooManyEntries) {
		t.Fatalf("three entries with a budget of two: want ErrTooManyEntries, got %v", err)
	}
	if got := g.Stats().Layers; got != 0 {
		t.Fatalf("rejected layer was stored: layers=%d", got)
	}
}

// A path present in two layers resolves to the upper one.
func TestResolveHighestLayerWins(t *testing.T) {
	g := taskpkg.NewOverlayGuard(overlayCfg())
	addLayerOK(t, g, taskpkg.Layer{ID: 1, Entries: []taskpkg.Entry{
		dirEntry("/etc"),
		fileEntry("/etc/nginx.conf", 10),
	}})
	addLayerOK(t, g, taskpkg.Layer{ID: 2, Entries: []taskpkg.Entry{
		fileEntry("/etc/nginx.conf", 20),
	}})
	got, err := g.Resolve("/etc/nginx.conf")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.Layer != 2 || got.Entry.Size != 20 {
		t.Fatalf("resolved %+v, want layer 2 size 20", got)
	}
}

// A whiteout in an upper layer deletes the lower file from the merged view.
func TestWhiteoutHidesLowerEntry(t *testing.T) {
	g := taskpkg.NewOverlayGuard(overlayCfg())
	addLayerOK(t, g, taskpkg.Layer{ID: 1, Entries: []taskpkg.Entry{
		dirEntry("/etc"),
		fileEntry("/etc/nginx.conf", 10),
	}})
	addLayerOK(t, g, taskpkg.Layer{ID: 2, Whiteouts: []string{"/etc/nginx.conf"}})
	if _, err := g.Resolve("/etc/nginx.conf"); !errors.Is(err, taskpkg.ErrNotFound) {
		t.Fatalf("whiteouted path: want ErrNotFound, got %v", err)
	}
	if g.Exists("/etc/nginx.conf") {
		t.Fatalf("Exists reported a whiteouted path")
	}
	if !g.Exists("/etc") {
		t.Fatalf("whiteout of a file hid its parent directory")
	}
}

// A later layer may reintroduce a path that an intermediate whiteout removed.
func TestHigherLayerResurrects(t *testing.T) {
	g := taskpkg.NewOverlayGuard(overlayCfg())
	addLayerOK(t, g, taskpkg.Layer{ID: 1, Entries: []taskpkg.Entry{
		dirEntry("/etc"),
		fileEntry("/etc/nginx.conf", 10),
	}})
	addLayerOK(t, g, taskpkg.Layer{ID: 2, Whiteouts: []string{"/etc/nginx.conf"}})
	addLayerOK(t, g, taskpkg.Layer{ID: 3, Entries: []taskpkg.Entry{
		fileEntry("/etc/nginx.conf", 30),
	}})
	got, err := g.Resolve("/etc/nginx.conf")
	if err != nil {
		t.Fatalf("Resolve after resurrection: %v", err)
	}
	if got.Layer != 3 || got.Entry.Size != 30 {
		t.Fatalf("resolved %+v, want layer 3 size 30", got)
	}
}

// An opaque directory keeps its own content and discards the lower content.
func TestOpaqueDirHidesLowerChildren(t *testing.T) {
	g := taskpkg.NewOverlayGuard(overlayCfg())
	addLayerOK(t, g, taskpkg.Layer{ID: 1, Entries: []taskpkg.Entry{
		dirEntry("/var/cache"),
		fileEntry("/var/cache/a", 1),
		fileEntry("/var/cache/b", 2),
	}})
	addLayerOK(t, g, taskpkg.Layer{
		ID:      2,
		Entries: []taskpkg.Entry{dirEntry("/var/cache"), fileEntry("/var/cache/c", 3)},
		Opaque:  []string{"/var/cache"},
	})
	got, err := g.List("/var/cache")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	want := []taskpkg.Entry{fileEntry("/var/cache/c", 3)}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("children = %+v, want %+v", got, want)
	}
	if _, err := g.Resolve("/var/cache/a"); !errors.Is(err, taskpkg.ErrNotFound) {
		t.Fatalf("lower child under opaque dir: want ErrNotFound, got %v", err)
	}
	if r, err := g.Resolve("/var/cache"); err != nil || r.Layer != 2 || r.Entry.Kind != taskpkg.KindDir {
		t.Fatalf("opaque dir itself: resolved %+v err %v, want layer 2 dir", r, err)
	}
}

// List returns the direct children only, in path order.
func TestListSortedDirectChildren(t *testing.T) {
	g := taskpkg.NewOverlayGuard(overlayCfg())
	addLayerOK(t, g, taskpkg.Layer{ID: 1, Entries: []taskpkg.Entry{
		dirEntry("/srv"),
		fileEntry("/srv/b.txt", 22),
		fileEntry("/srv/a.txt", 11),
		dirEntry("/srv/sub"),
		fileEntry("/srv/sub/deep.txt", 33),
	}})
	got, err := g.List("/srv")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	want := []taskpkg.Entry{
		fileEntry("/srv/a.txt", 11),
		fileEntry("/srv/b.txt", 22),
		dirEntry("/srv/sub"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("children = %+v, want %+v", got, want)
	}
	if _, err := g.List("/srv/a.txt"); !errors.Is(err, taskpkg.ErrNotDir) {
		t.Fatalf("List on a file: want ErrNotDir, got %v", err)
	}
}

// A layer upgrade plans deletions first, then creates parents before children.
func TestPlanDeletesBeforeCreates(t *testing.T) {
	g := taskpkg.NewOverlayGuard(overlayCfg())
	addLayerOK(t, g, taskpkg.Layer{ID: 1, Entries: []taskpkg.Entry{
		dirEntry("/etc"),
		fileEntry("/etc/nginx.conf", 100),
		fileEntry("/etc/old.conf", 5),
		dirEntry("/usr"),
	}})
	addLayerOK(t, g, taskpkg.Layer{
		ID:        2,
		Entries:   []taskpkg.Entry{dirEntry("/usr/bin"), fileEntry("/usr/bin/app", 7)},
		Whiteouts: []string{"/etc/old.conf"},
	})
	ops, err := g.Plan(1, 2)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	want := []taskpkg.Op{
		{Kind: taskpkg.OpDelete, Path: "/etc/old.conf"},
		{Kind: taskpkg.OpCreate, Path: "/usr/bin"},
		{Kind: taskpkg.OpCreate, Path: "/usr/bin/app"},
	}
	if !reflect.DeepEqual(ops, want) {
		t.Fatalf("plan = %+v, want %+v", ops, want)
	}
	if _, err := g.Plan(2, 2); !errors.Is(err, taskpkg.ErrInvalidRange) {
		t.Fatalf("empty range: want ErrInvalidRange, got %v", err)
	}
}

// Whiteouts that target nothing in a lower layer are cleanup candidates.
func TestOrphansSorted(t *testing.T) {
	g := taskpkg.NewOverlayGuard(overlayCfg())
	addLayerOK(t, g, taskpkg.Layer{ID: 1, Entries: []taskpkg.Entry{
		dirEntry("/etc"),
		fileEntry("/etc/nginx.conf", 10),
		dirEntry("/usr"),
	}})
	addLayerOK(t, g, taskpkg.Layer{ID: 2, Whiteouts: []string{
		"/etc/nginx.conf",
		"/opt/missing",
		"/etc/gone.conf",
	}})
	got := g.Orphans()
	want := []string{"/etc/gone.conf", "/opt/missing"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("orphans = %v, want %v", got, want)
	}
	if got := g.Stats().Whiteouts; got != 3 {
		t.Fatalf("whiteout count = %d, want 3", got)
	}
}

// A restart rebuilds the exact merged view and keeps the id registry.
func TestSnapshotRestoresMergedView(t *testing.T) {
	g := taskpkg.NewOverlayGuard(overlayCfg())
	addLayerOK(t, g, taskpkg.Layer{ID: 1, Entries: []taskpkg.Entry{
		dirEntry("/etc"),
		fileEntry("/etc/nginx.conf", 10),
		fileEntry("/etc/old.conf", 5),
	}})
	addLayerOK(t, g, taskpkg.Layer{
		ID:        2,
		Entries:   []taskpkg.Entry{fileEntry("/etc/nginx.conf", 20)},
		Whiteouts: []string{"/etc/old.conf"},
	})
	snap, err := g.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	restored, err := taskpkg.NewOverlayGuardFromSnapshot(overlayCfg(), snap)
	if err != nil {
		t.Fatalf("NewOverlayGuardFromSnapshot: %v", err)
	}
	got, err := restored.Resolve("/etc/nginx.conf")
	if err != nil {
		t.Fatalf("restored Resolve: %v", err)
	}
	if got.Layer != 2 || got.Entry.Size != 20 {
		t.Fatalf("restored resolve = %+v, want layer 2 size 20", got)
	}
	if _, err := restored.Resolve("/etc/old.conf"); !errors.Is(err, taskpkg.ErrNotFound) {
		t.Fatalf("restored whiteout lost: %v", err)
	}
	if got := restored.Stats().Layers; got != 2 {
		t.Fatalf("restored layers = %d, want 2", got)
	}
	err = restored.AddLayer(taskpkg.Layer{ID: 2, Entries: []taskpkg.Entry{fileEntry("/etc/nginx.conf", 20)}})
	if !errors.Is(err, taskpkg.ErrDuplicateLayer) {
		t.Fatalf("restored registry accepted a used id: want ErrDuplicateLayer, got %v", err)
	}
	addLayerOK(t, restored, taskpkg.Layer{ID: 3, Entries: []taskpkg.Entry{fileEntry("/srv/app", 64)}})
	if r, err := restored.Resolve("/srv/app"); err != nil || r.Layer != 3 {
		t.Fatalf("new layer after restore: resolved %+v err %v, want layer 3", r, err)
	}
}

// Two unpackers racing on the same layer id: exactly one layer is stored.
func TestConcurrentAddLayerSingleWinner(t *testing.T) {
	g := taskpkg.NewOverlayGuard(overlayCfg())
	layer := taskpkg.Layer{ID: 1, Entries: []taskpkg.Entry{
		dirEntry("/etc"),
		fileEntry("/etc/nginx.conf", 10),
	}}
	errs := make([]error, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	for i := range errs {
		go func(i int) {
			defer wg.Done()
			errs[i] = g.AddLayer(layer)
		}(i)
	}
	wg.Wait()
	wins := 0
	for _, err := range errs {
		if err == nil {
			wins++
		} else if !errors.Is(err, taskpkg.ErrDuplicateLayer) {
			t.Fatalf("loser returned %v, want ErrDuplicateLayer", err)
		}
	}
	if wins != 1 {
		t.Fatalf("concurrent layer adds: %d winners, want exactly 1", wins)
	}
	if got := g.Stats().Layers; got != 1 {
		t.Fatalf("layers stored = %d, want 1", got)
	}
}
