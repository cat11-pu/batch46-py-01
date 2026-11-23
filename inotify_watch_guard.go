package task

import (
	"encoding/json"
	"errors"
	pathpkg "path"
	"strings"
	"sync"
)

// Sentinel errors returned by InotifyGuard.
var (
	ErrInvalidPath   = errors.New("inotify: invalid path")
	ErrInvalidMask   = errors.New("inotify: empty watch mask")
	ErrMaskConflict  = errors.New("inotify: path watched with a different mask")
	ErrQuotaExceeded = errors.New("inotify: watch quota exceeded")
	ErrRootQuota     = errors.New("inotify: per-root watch quota exceeded")
	ErrUnknownWatch  = errors.New("inotify: unknown watch descriptor")
	ErrBadSnapshot   = errors.New("inotify: malformed snapshot")
)

// Mask selects the events delivered for a watch.
type Mask uint32

const (
	MaskCreate Mask = 1 << iota
	MaskDelete
	MaskModify
)

// Config holds the kernel-side quotas the guard must never exceed.
type Config struct {
	// MaxWatches is the total number of distinct watch descriptors.
	MaxWatches int
	// MaxPerRoot caps distinct watches below one first-level directory.
	MaxPerRoot int
}

// Watch is one inotify watch descriptor and its reference count.
type Watch struct {
	WD   int
	Path string
	Mask Mask
	// Refs counts how many subscribers share this descriptor.
	Refs int
}

// Stats is a point-in-time accounting of the guard.
type Stats struct {
	Watches int
	Refs    int
	Roots   int
}

// InotifyGuard owns the watch descriptors of one watcher process.
type InotifyGuard struct {
	mu         sync.Mutex
	cfg        Config
	byWD       map[int]*Watch
	byPath     map[string]int
	rootCounts map[string]int
	nextWD     int
}

// NewInotifyGuard returns an empty guard configured by cfg.
func NewInotifyGuard(cfg Config) *InotifyGuard {
	return &InotifyGuard{
		cfg:        cfg,
		byWD:       make(map[int]*Watch),
		byPath:     make(map[string]int),
		rootCounts: make(map[string]int),
		nextWD:     1,
	}
}

// snapshotData is the serialised form of the guard: every live watch plus the
// descriptor allocator high-water mark.
type snapshotData struct {
	NextWD  int     `json:"next_wd"`
	Watches []Watch `json:"watches"`
}

// NewInotifyGuardFromSnapshot restores watches, reference counts and the
// descriptor allocator from a snapshot produced by Snapshot.
func NewInotifyGuardFromSnapshot(cfg Config, data []byte) (*InotifyGuard, error) {
	var snap snapshotData
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, ErrBadSnapshot
	}
	g := NewInotifyGuard(cfg)
	maxWD := 0
	for _, w := range snap.Watches {
		if w.WD < 1 || w.Refs < 1 || w.Mask == 0 || !isCleanAbsPath(w.Path) {
			return nil, ErrBadSnapshot
		}
		if _, dup := g.byWD[w.WD]; dup {
			return nil, ErrBadSnapshot
		}
		if _, dup := g.byPath[w.Path]; dup {
			return nil, ErrBadSnapshot
		}
		watch := w
		g.byWD[watch.WD] = &watch
		g.byPath[watch.Path] = watch.WD
		g.rootCounts[rootOf(watch.Path)]++
		if watch.WD > maxWD {
			maxWD = watch.WD
		}
	}
	if snap.NextWD <= maxWD {
		return nil, ErrBadSnapshot
	}
	g.nextWD = snap.NextWD
	return g, nil
}

// Add subscribes to path with mask and returns its watch descriptor. A second
// Add of the same path and mask shares the descriptor and bumps its refcount.
func (g *InotifyGuard) Add(path string, mask Mask) (int, error) {
	if !isCleanAbsPath(path) {
		return 0, ErrInvalidPath
	}
	if mask == 0 {
		return 0, ErrInvalidMask
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if wd, ok := g.byPath[path]; ok {
		w := g.byWD[wd]
		if w.Mask != mask {
			return 0, ErrMaskConflict
		}
		w.Refs++
		return wd, nil
	}
	if len(g.byWD) >= g.cfg.MaxWatches {
		return 0, ErrQuotaExceeded
	}
	root := rootOf(path)
	if g.rootCounts[root] >= g.cfg.MaxPerRoot {
		return 0, ErrRootQuota
	}
	wd := g.nextWD
	g.nextWD++
	g.byWD[wd] = &Watch{WD: wd, Path: path, Mask: mask, Refs: 1}
	g.byPath[path] = wd
	g.rootCounts[root]++
	return wd, nil
}

// Remove drops one reference; the descriptor disappears with its last one.
func (g *InotifyGuard) Remove(wd int) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	w, ok := g.byWD[wd]
	if !ok {
		return ErrUnknownWatch
	}
	w.Refs--
	if w.Refs == 0 {
		g.dropLocked(w)
	}
	return nil
}

// HandleIgnored reacts to IN_IGNORED: the kernel dropped the watch, so it is
// removed together with every reference.
func (g *InotifyGuard) HandleIgnored(wd int) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	w, ok := g.byWD[wd]
	if !ok {
		return ErrUnknownWatch
	}
	g.dropLocked(w)
	return nil
}

// Lookup returns the descriptor watching path.
func (g *InotifyGuard) Lookup(path string) (int, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	wd, ok := g.byPath[pathpkg.Clean(path)]
	if !ok {
		return 0, ErrUnknownWatch
	}
	return wd, nil
}

// Watch returns a copy of the watch registered under wd.
func (g *InotifyGuard) Watch(wd int) (Watch, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	w, ok := g.byWD[wd]
	if !ok {
		return Watch{}, ErrUnknownWatch
	}
	return *w, nil
}

// Len returns the number of distinct watch descriptors.
func (g *InotifyGuard) Len() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.byWD)
}

// TotalRefs returns the sum of all reference counts.
func (g *InotifyGuard) TotalRefs() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	total := 0
	for _, w := range g.byWD {
		total += w.Refs
	}
	return total
}

// EvictRoot drops every watch at root or below it and reports how many
// descriptors were removed.
func (g *InotifyGuard) EvictRoot(root string) (int, error) {
	if !isCleanAbsPath(root) {
		return 0, ErrInvalidPath
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	prefix := root + "/"
	removed := 0
	for _, w := range g.byWD {
		if w.Path == root || strings.HasPrefix(w.Path, prefix) {
			g.dropLocked(w)
			removed++
		}
	}
	return removed, nil
}

// Snapshot serialises watches and the descriptor allocator.
func (g *InotifyGuard) Snapshot() ([]byte, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	snap := snapshotData{NextWD: g.nextWD, Watches: make([]Watch, 0, len(g.byWD))}
	for _, w := range g.byWD {
		snap.Watches = append(snap.Watches, *w)
	}
	return json.Marshal(snap)
}

// Stats reports current counters.
func (g *InotifyGuard) Stats() Stats {
	g.mu.Lock()
	defer g.mu.Unlock()
	s := Stats{Watches: len(g.byWD), Roots: len(g.rootCounts)}
	for _, w := range g.byWD {
		s.Refs += w.Refs
	}
	return s
}

// dropLocked removes w from every index. The caller must hold g.mu.
func (g *InotifyGuard) dropLocked(w *Watch) {
	delete(g.byWD, w.WD)
	delete(g.byPath, w.Path)
	root := rootOf(w.Path)
	if g.rootCounts[root] <= 1 {
		delete(g.rootCounts, root)
	} else {
		g.rootCounts[root]--
	}
}

// isCleanAbsPath reports whether p is absolute and already normalised.
func isCleanAbsPath(p string) bool {
	return strings.HasPrefix(p, "/") && pathpkg.Clean(p) == p
}

// rootOf returns the first-level directory of a clean absolute path.
func rootOf(p string) string {
	rest := strings.TrimPrefix(p, "/")
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		return "/" + rest[:i]
	}
	return p
}
