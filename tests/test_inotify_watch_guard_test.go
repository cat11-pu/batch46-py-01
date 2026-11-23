package task

import (
	"errors"
	"fmt"
	"sync"
	"testing"

	taskpkg "gsb/batch46-safety-e-04"
)

func inoConfig() taskpkg.Config {
	return taskpkg.Config{MaxWatches: 6, MaxPerRoot: 3}
}

func addOK(t *testing.T, g *taskpkg.InotifyGuard, path string, mask taskpkg.Mask) int {
	t.Helper()
	wd, err := g.Add(path, mask)
	if err != nil {
		t.Fatalf("Add %q: %v", path, err)
	}
	return wd
}

// Paths handed to the kernel must already be absolute and clean.
func TestAddRejectsUncleanPath(t *testing.T) {
	g := taskpkg.NewInotifyGuard(inoConfig())
	for _, p := range []string{"", "data/app", "/data/app/", "/data/./app", "/data/../etc"} {
		if _, err := g.Add(p, taskpkg.MaskCreate); !errors.Is(err, taskpkg.ErrInvalidPath) {
			t.Fatalf("Add(%q): want ErrInvalidPath, got %v", p, err)
		}
	}
}

// A watch without events is a leak of kernel resources.
func TestAddRejectsEmptyMask(t *testing.T) {
	g := taskpkg.NewInotifyGuard(inoConfig())
	if _, err := g.Add("/data/app", 0); !errors.Is(err, taskpkg.ErrInvalidMask) {
		t.Fatalf("empty mask: want ErrInvalidMask, got %v", err)
	}
}

// A kernel watch carries one mask; a second mask needs another subscriber path.
func TestAddMaskConflictRejected(t *testing.T) {
	g := taskpkg.NewInotifyGuard(inoConfig())
	addOK(t, g, "/data/app", taskpkg.MaskCreate)
	if _, err := g.Add("/data/app", taskpkg.MaskCreate|taskpkg.MaskDelete); !errors.Is(err, taskpkg.ErrMaskConflict) {
		t.Fatalf("conflicting mask: want ErrMaskConflict, got %v", err)
	}
}

// Re-adding the same watch must share one descriptor, not consume the quota.
func TestAddSamePathSharesWatch(t *testing.T) {
	g := taskpkg.NewInotifyGuard(inoConfig())
	first := addOK(t, g, "/srv/app/conf", taskpkg.MaskModify)
	second := addOK(t, g, "/srv/app/conf", taskpkg.MaskModify)
	if first != second {
		t.Fatalf("shared watch got wd %d then %d", first, second)
	}
	w, err := g.Watch(first)
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}
	if w.Refs != 2 {
		t.Fatalf("refs = %d, want 2", w.Refs)
	}
	if g.Len() != 1 || g.TotalRefs() != 2 {
		t.Fatalf("len=%d refs=%d, want 1/2", g.Len(), g.TotalRefs())
	}
}

// The total descriptor quota is a hard limit.
func TestAddEnforcesTotalQuota(t *testing.T) {
	cfg := inoConfig()
	cfg.MaxPerRoot = 10
	g := taskpkg.NewInotifyGuard(cfg)
	addOK(t, g, "/a/one", taskpkg.MaskCreate)
	addOK(t, g, "/b/two", taskpkg.MaskCreate)
	addOK(t, g, "/c/three", taskpkg.MaskCreate)
	addOK(t, g, "/d/four", taskpkg.MaskCreate)
	addOK(t, g, "/e/five", taskpkg.MaskCreate)
	addOK(t, g, "/f/six", taskpkg.MaskCreate)
	if _, err := g.Add("/g/seven", taskpkg.MaskCreate); !errors.Is(err, taskpkg.ErrQuotaExceeded) {
		t.Fatalf("seventh watch: want ErrQuotaExceeded, got %v", err)
	}
}

// One hot directory tree must not starve the other roots.
func TestAddEnforcesRootQuota(t *testing.T) {
	g := taskpkg.NewInotifyGuard(inoConfig())
	addOK(t, g, "/data/app/cache", taskpkg.MaskCreate)
	addOK(t, g, "/data/app/logs", taskpkg.MaskCreate)
	addOK(t, g, "/data/app/run", taskpkg.MaskCreate)
	if _, err := g.Add("/data/other", taskpkg.MaskCreate); !errors.Is(err, taskpkg.ErrRootQuota) {
		t.Fatalf("fourth watch below /data: want ErrRootQuota, got %v", err)
	}
	if _, err := g.Add("/srv/www", taskpkg.MaskCreate); err != nil {
		t.Fatalf("watch under another root was refused: %v", err)
	}
}

// Lookup normalises the caller's spelling of an already watched path.
func TestLookupNormalizesPath(t *testing.T) {
	g := taskpkg.NewInotifyGuard(inoConfig())
	wd := addOK(t, g, "/data/app/sub", taskpkg.MaskCreate)
	for _, p := range []string{"/data//app/./sub", "/data/app/sub"} {
		got, err := g.Lookup(p)
		if err != nil {
			t.Fatalf("Lookup(%q): %v", p, err)
		}
		if got != wd {
			t.Fatalf("Lookup(%q) = %d, want %d", p, got, wd)
		}
	}
	if _, err := g.Lookup("/data/app/other"); !errors.Is(err, taskpkg.ErrUnknownWatch) {
		t.Fatalf("unwatched path: want ErrUnknownWatch, got %v", err)
	}
}

// The last reference releases the descriptor.
func TestRemoveDecrementsRefs(t *testing.T) {
	g := taskpkg.NewInotifyGuard(inoConfig())
	wd := addOK(t, g, "/data/app", taskpkg.MaskCreate)
	addOK(t, g, "/data/app", taskpkg.MaskCreate)
	if err := g.Remove(wd); err != nil {
		t.Fatalf("first Remove: %v", err)
	}
	w, err := g.Watch(wd)
	if err != nil {
		t.Fatalf("Watch after one Remove: %v", err)
	}
	if w.Refs != 1 {
		t.Fatalf("refs = %d, want 1", w.Refs)
	}
	if err := g.Remove(wd); err != nil {
		t.Fatalf("second Remove: %v", err)
	}
	if g.Len() != 0 {
		t.Fatalf("watch survived its last reference: len=%d", g.Len())
	}
	if err := g.Remove(wd); !errors.Is(err, taskpkg.ErrUnknownWatch) {
		t.Fatalf("third Remove: want ErrUnknownWatch, got %v", err)
	}
}

// Removing an unknown descriptor must be reported, never ignored.
func TestRemoveUnknownWatchRejected(t *testing.T) {
	g := taskpkg.NewInotifyGuard(inoConfig())
	if err := g.Remove(99); !errors.Is(err, taskpkg.ErrUnknownWatch) {
		t.Fatalf("Remove 99: want ErrUnknownWatch, got %v", err)
	}
}

// IN_IGNORED means the kernel already dropped the watch and all its users.
func TestHandleIgnoredDropsWatchRegardlessOfRefs(t *testing.T) {
	g := taskpkg.NewInotifyGuard(inoConfig())
	wd := addOK(t, g, "/data/app", taskpkg.MaskCreate)
	addOK(t, g, "/data/app", taskpkg.MaskCreate)
	if err := g.HandleIgnored(wd); err != nil {
		t.Fatalf("HandleIgnored: %v", err)
	}
	if g.Len() != 0 || g.TotalRefs() != 0 {
		t.Fatalf("after IN_IGNORED len=%d refs=%d, want 0/0", g.Len(), g.TotalRefs())
	}
	if err := g.HandleIgnored(wd); !errors.Is(err, taskpkg.ErrUnknownWatch) {
		t.Fatalf("second IN_IGNORED: want ErrUnknownWatch, got %v", err)
	}
}

// Evicting a deleted directory must not touch a sibling with a longer name.
func TestEvictRootRespectsPathBoundary(t *testing.T) {
	cfg := inoConfig()
	cfg.MaxPerRoot = 10
	g := taskpkg.NewInotifyGuard(cfg)
	addOK(t, g, "/data/app/cache", taskpkg.MaskCreate)
	addOK(t, g, "/data/app", taskpkg.MaskDelete)
	addOK(t, g, "/data/application", taskpkg.MaskCreate)
	removed, err := g.EvictRoot("/data/app")
	if err != nil {
		t.Fatalf("EvictRoot: %v", err)
	}
	if removed != 2 {
		t.Fatalf("evicted %d watches, want 2", removed)
	}
	if _, err := g.Lookup("/data/application"); err != nil {
		t.Fatalf("sibling /data/application was evicted: %v", err)
	}
	if g.Len() != 1 {
		t.Fatalf("remaining watches = %d, want 1", g.Len())
	}
}

// Evicting frees quota for the next mount.
func TestEvictRootFreesQuota(t *testing.T) {
	cfg := inoConfig()
	cfg.MaxWatches = 2
	cfg.MaxPerRoot = 2
	g := taskpkg.NewInotifyGuard(cfg)
	addOK(t, g, "/mnt/vol1/a", taskpkg.MaskCreate)
	addOK(t, g, "/mnt/vol1/b", taskpkg.MaskCreate)
	if _, err := g.Add("/mnt/vol1/c", taskpkg.MaskCreate); !errors.Is(err, taskpkg.ErrQuotaExceeded) {
		t.Fatalf("quota was not reached: %v", err)
	}
	removed, err := g.EvictRoot("/mnt/vol1")
	if err != nil {
		t.Fatalf("EvictRoot: %v", err)
	}
	if removed != 2 {
		t.Fatalf("evicted %d, want 2", removed)
	}
	addOK(t, g, "/mnt/vol2/a", taskpkg.MaskCreate)
	addOK(t, g, "/mnt/vol2/b", taskpkg.MaskCreate)
}

// A burst of concurrent adds must never exceed the kernel quota.
func TestConcurrentAddRespectsQuota(t *testing.T) {
	cfg := taskpkg.Config{MaxWatches: 10, MaxPerRoot: 10}
	g := taskpkg.NewInotifyGuard(cfg)
	const workers = 40
	errs := make([]error, workers)
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func(i int) {
			defer wg.Done()
			_, errs[i] = g.Add(fmt.Sprintf("/srv/burst/item%d", i), taskpkg.MaskCreate)
		}(i)
	}
	wg.Wait()
	wins, refused := 0, 0
	for _, err := range errs {
		switch {
		case err == nil:
			wins++
		case errors.Is(err, taskpkg.ErrQuotaExceeded):
			refused++
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if wins != 10 || refused != workers-10 {
		t.Fatalf("wins=%d refused=%d, want 10/%d", wins, refused, workers-10)
	}
	if g.Len() != 10 {
		t.Fatalf("watch count = %d, want 10", g.Len())
	}
}

// A restart keeps descriptors, masks and reference counts.
func TestSnapshotRestoresWatchesAndRefs(t *testing.T) {
	g := taskpkg.NewInotifyGuard(inoConfig())
	wd := addOK(t, g, "/srv/app/conf/nginx.conf", taskpkg.MaskModify)
	addOK(t, g, "/srv/app/conf/nginx.conf", taskpkg.MaskModify)
	addOK(t, g, "/srv/app/logs", taskpkg.MaskDelete)
	snap, err := g.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	restored, err := taskpkg.NewInotifyGuardFromSnapshot(inoConfig(), snap)
	if err != nil {
		t.Fatalf("NewInotifyGuardFromSnapshot: %v", err)
	}
	if restored.Len() != 2 || restored.TotalRefs() != 3 {
		t.Fatalf("restored len=%d refs=%d, want 2/3", restored.Len(), restored.TotalRefs())
	}
	w, err := restored.Watch(wd)
	if err != nil {
		t.Fatalf("restored Watch: %v", err)
	}
	if w.Path != "/srv/app/conf/nginx.conf" || w.Mask != taskpkg.MaskModify || w.Refs != 2 {
		t.Fatalf("restored watch = %+v", w)
	}
	if _, err := restored.Lookup("/srv/app/logs"); err != nil {
		t.Fatalf("restored Lookup: %v", err)
	}
}

// A restarted watcher must not hand out a descriptor the kernel still owns.
func TestWatchDescriptorsNotReusedAfterRestore(t *testing.T) {
	g := taskpkg.NewInotifyGuard(inoConfig())
	first := addOK(t, g, "/srv/app/a", taskpkg.MaskCreate)
	second := addOK(t, g, "/srv/app/b", taskpkg.MaskCreate)
	high := first
	if second > high {
		high = second
	}
	if err := g.Remove(first); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	snap, err := g.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	restored, err := taskpkg.NewInotifyGuardFromSnapshot(inoConfig(), snap)
	if err != nil {
		t.Fatalf("NewInotifyGuardFromSnapshot: %v", err)
	}
	fresh := addOK(t, restored, "/srv/app/c", taskpkg.MaskCreate)
	if fresh <= high {
		t.Fatalf("new wd %d reuses a descriptor at or below %d", fresh, high)
	}
}
