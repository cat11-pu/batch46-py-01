package task

import "errors"

var errNotImplemented = errors.New("not implemented")

// Sentinel errors returned by OverlayGuard.
var (
	ErrInvalidPath      = errors.New("overlay: invalid path")
	ErrLayerOrder       = errors.New("overlay: layer id must start at 1 and increase")
	ErrDuplicateLayer   = errors.New("overlay: layer id already used")
	ErrDuplicateEntry   = errors.New("overlay: duplicate entry in layer")
	ErrWhiteoutConflict = errors.New("overlay: whiteout and entry for the same path")
	ErrOpaqueWithoutDir = errors.New("overlay: opaque path is not a directory entry")
	ErrTooManyEntries   = errors.New("overlay: layer entry budget exceeded")
	ErrTooManyLayers    = errors.New("overlay: layer budget exceeded")
	ErrNotFound         = errors.New("overlay: path not visible in the merged view")
	ErrNotDir           = errors.New("overlay: path is not a directory")
	ErrInvalidRange     = errors.New("overlay: invalid layer range")
	ErrBadSnapshot      = errors.New("overlay: malformed snapshot")
)

// Kind is the inode type of one merged entry.
type Kind int

const (
	KindFile Kind = iota
	KindDir
	KindSymlink
)

// Entry is one inode stored in a layer.
type Entry struct {
	Path string
	Kind Kind
	Size int64
}

// Layer is one read-only image layer. Paths in Whiteouts are deleted from all
// lower layers; paths in Opaque hide the content of that directory in all
// lower layers.
type Layer struct {
	ID        int
	Entries   []Entry
	Whiteouts []string
	Opaque    []string
}

// OpKind marks whether a plan step creates or deletes a path.
type OpKind string

const (
	OpCreate OpKind = "create"
	OpDelete OpKind = "delete"
)

// Op is one step of a materialisation plan.
type Op struct {
	Kind OpKind
	Path string
}

// Resolved is the entry visible for a path and the layer that provides it.
type Resolved struct {
	Entry Entry
	Layer int
}

// Config bounds the number of layers and the size of each layer.
type Config struct {
	MaxLayers          int
	MaxEntriesPerLayer int
}

// Stats is a point-in-time accounting of the merged view.
type Stats struct {
	Layers    int
	Visible   int
	Whiteouts int
}

// OverlayGuard merges image layers with overlayfs whiteout semantics.
type OverlayGuard struct {
	cfg Config
}

// NewOverlayGuard returns an empty guard configured by cfg.
func NewOverlayGuard(cfg Config) *OverlayGuard {
	return &OverlayGuard{cfg: cfg}
}

// NewOverlayGuardFromSnapshot restores every layer, including whiteouts and
// opaque directories, from a snapshot produced by Snapshot.
func NewOverlayGuardFromSnapshot(cfg Config, data []byte) (*OverlayGuard, error) {
	return nil, errNotImplemented
}

// AddLayer validates and appends one layer. Layer ids start at 1, are unique
// and strictly increase.
func (g *OverlayGuard) AddLayer(layer Layer) error {
	return errNotImplemented
}

// Resolve returns the entry visible for path in the merged view.
func (g *OverlayGuard) Resolve(path string) (Resolved, error) {
	return Resolved{}, errNotImplemented
}

// List returns the direct children of dir in the merged view, ordered by path.
func (g *OverlayGuard) List(dir string) ([]Entry, error) {
	return nil, errNotImplemented
}

// Plan returns the ordered steps that turn the merged view of layers up to
// fromLayer into the merged view up to toLayer. Deletions come first.
func (g *OverlayGuard) Plan(fromLayer, toLayer int) ([]Op, error) {
	return nil, errNotImplemented
}

// Orphans returns the whiteout paths that target nothing in a lower layer,
// ordered by path.
func (g *OverlayGuard) Orphans() []string {
	return nil
}

// Exists reports whether path is visible in the merged view.
func (g *OverlayGuard) Exists(path string) bool {
	return false
}

// Stats reports current counters.
func (g *OverlayGuard) Stats() Stats {
	return Stats{}
}

// Snapshot serialises every layer in insertion order.
func (g *OverlayGuard) Snapshot() ([]byte, error) {
	return nil, errNotImplemented
}
