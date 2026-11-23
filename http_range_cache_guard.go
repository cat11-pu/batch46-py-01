package task

import "errors"

var errNotImplemented = errors.New("not implemented")

// Sentinel errors returned by RangeCacheGuard.
var (
	// ErrInvalidRange means the range header, segment or validator is not
	// well formed.
	ErrInvalidRange = errors.New("range: invalid range header")
	// ErrUnsatisfiable means the requested range cannot exist for the size.
	ErrUnsatisfiable = errors.New("range: range not satisfiable")
	// ErrTooManyRanges means the header carries more ranges than allowed.
	ErrTooManyRanges = errors.New("range: too many ranges")
	// ErrOverlappingRanges means two requested ranges intersect.
	ErrOverlappingRanges = errors.New("range: overlapping ranges")
	// ErrValidatorConflict means an etag was registered with another size.
	ErrValidatorConflict = errors.New("range: etag already registered with another size")
	// ErrUnknownResource means the etag is not registered.
	ErrUnknownResource = errors.New("range: unknown resource")
	// ErrPartialMiss means no cached segment contains the requested range.
	ErrPartialMiss = errors.New("range: segment is not cached")
	// ErrSizeMismatch means the payload length differs from the segment span.
	ErrSizeMismatch = errors.New("range: payload length does not match segment")
	// ErrBudgetExceeded means the payload cannot fit into the cache budget.
	ErrBudgetExceeded = errors.New("range: cache budget exceeded")
	// ErrCorruptSnapshot means a snapshot could not be decoded.
	ErrCorruptSnapshot = errors.New("range: corrupt snapshot")
)

// Config holds cache policy.
type Config struct {
	// MaxRanges is the maximum number of ranges accepted in one header; zero
	// means unbounded.
	MaxRanges int
	// MaxBytes is the total payload budget of the cache.
	MaxBytes int64
}

// Segment is an inclusive byte range.
type Segment struct {
	Start int64
	End   int64
}

// Resource is one registered representation identified by a strong etag.
type Resource struct {
	ETag string
	Size int64
}

// Stats is a counter snapshot.
type Stats struct {
	Resources int
	Segments  int
	Bytes     int64
	Hits      int
	Misses    int
	Evicted   int
}

// RangeCacheGuard stores byte ranges of registered representations and only
// serves ranges fully covered by a cached segment with a matching validator.
type RangeCacheGuard struct {
	cfg Config
}

// NewRangeCacheGuard returns an empty cache governed by cfg.
func NewRangeCacheGuard(cfg Config) *RangeCacheGuard {
	return &RangeCacheGuard{cfg: cfg}
}

// NewRangeCacheGuardFromSnapshot restores registrations and cached segments
// from data produced by Snapshot.
func NewRangeCacheGuardFromSnapshot(cfg Config, data []byte) (*RangeCacheGuard, error) {
	return nil, errNotImplemented
}

// Register records a strong etag and its full representation size.
func (g *RangeCacheGuard) Register(etag string, size int64) error {
	return errNotImplemented
}

// ParseRange parses a bytes= range header for a representation of size.
func (g *RangeCacheGuard) ParseRange(header string, size int64) ([]Segment, error) {
	return nil, errNotImplemented
}

// Coverage validates segments and returns their total length.
func (g *RangeCacheGuard) Coverage(segs []Segment) (int64, error) {
	return 0, errNotImplemented
}

// Store caches data for exactly one segment of etag.
func (g *RangeCacheGuard) Store(etag string, seg Segment, data []byte) error {
	return errNotImplemented
}

// Fetch returns the exact bytes for seg from a cached segment that fully
// contains it.
func (g *RangeCacheGuard) Fetch(etag string, seg Segment) ([]byte, error) {
	return nil, errNotImplemented
}

// CachedBytes returns how many payload bytes are cached for etag.
func (g *RangeCacheGuard) CachedBytes(etag string) int64 {
	return 0
}

// TotalBytes returns how many payload bytes are cached in total.
func (g *RangeCacheGuard) TotalBytes() int64 {
	return 0
}

// ValidateIfRange reports whether an If-Range header still matches etag.
func (g *RangeCacheGuard) ValidateIfRange(etag, ifRange string) bool {
	return false
}

// Invalidate drops every cached segment of etag and returns how many were
// dropped.
func (g *RangeCacheGuard) Invalidate(etag string) int {
	return 0
}

// Len returns the number of registered resources.
func (g *RangeCacheGuard) Len() int {
	return 0
}

// Stats returns the current counters.
func (g *RangeCacheGuard) Stats() Stats {
	return Stats{}
}

// Snapshot serialises registrations and cached segments.
func (g *RangeCacheGuard) Snapshot() ([]byte, error) {
	return nil, errNotImplemented
}
