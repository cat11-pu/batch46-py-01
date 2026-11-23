package task

import "errors"

var errNotImplemented = errors.New("not implemented")

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
	cfg Config
}

// NewInotifyGuard returns an empty guard configured by cfg.
func NewInotifyGuard(cfg Config) *InotifyGuard {
	return &InotifyGuard{cfg: cfg}
}

// NewInotifyGuardFromSnapshot restores watches, reference counts and the
// descriptor allocator from a snapshot produced by Snapshot.
func NewInotifyGuardFromSnapshot(cfg Config, data []byte) (*InotifyGuard, error) {
	return nil, errNotImplemented
}

// Add subscribes to path with mask and returns its watch descriptor. A second
// Add of the same path and mask shares the descriptor and bumps its refcount.
func (g *InotifyGuard) Add(path string, mask Mask) (int, error) {
	return 0, errNotImplemented
}

// Remove drops one reference; the descriptor disappears with its last one.
func (g *InotifyGuard) Remove(wd int) error {
	return errNotImplemented
}

// HandleIgnored reacts to IN_IGNORED: the kernel dropped the watch, so it is
// removed together with every reference.
func (g *InotifyGuard) HandleIgnored(wd int) error {
	return errNotImplemented
}

// Lookup returns the descriptor watching path.
func (g *InotifyGuard) Lookup(path string) (int, error) {
	return 0, errNotImplemented
}

// Watch returns a copy of the watch registered under wd.
func (g *InotifyGuard) Watch(wd int) (Watch, error) {
	return Watch{}, errNotImplemented
}

// Len returns the number of distinct watch descriptors.
func (g *InotifyGuard) Len() int {
	return 0
}

// TotalRefs returns the sum of all reference counts.
func (g *InotifyGuard) TotalRefs() int {
	return 0
}

// EvictRoot drops every watch at root or below it and reports how many
// descriptors were removed.
func (g *InotifyGuard) EvictRoot(root string) (int, error) {
	return 0, errNotImplemented
}

// Snapshot serialises watches and the descriptor allocator.
func (g *InotifyGuard) Snapshot() ([]byte, error) {
	return nil, errNotImplemented
}

// Stats reports current counters.
func (g *InotifyGuard) Stats() Stats {
	return Stats{}
}
