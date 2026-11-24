package task

import (
	"encoding/json"
	"errors"
	"math"
	"sort"
	"strings"
	"sync"
)

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

type cachedSegment struct {
	seg  Segment
	data []byte
}

type resourceState struct {
	etag     string
	size     int64
	segments []cachedSegment
	order    uint64
}

// RangeCacheGuard stores byte ranges of registered representations and only
// serves ranges fully covered by a cached segment with a matching validator.
type RangeCacheGuard struct {
	mu sync.Mutex

	cfg       Config
	resources map[string]*resourceState
	total     int64
	clock     uint64

	hits    int
	misses  int
	evicted int
}

const snapshotVersion = 1

type snapshot struct {
	Version   int                `json:"version"`
	Clock     uint64             `json:"clock"`
	Hits      int                `json:"hits"`
	Misses    int                `json:"misses"`
	Evicted   int                `json:"evicted"`
	Resources []snapshotResource `json:"resources"`
}

type snapshotResource struct {
	ETag     string            `json:"etag"`
	Size     int64             `json:"size"`
	Order    uint64            `json:"order"`
	Segments []snapshotSegment `json:"segments"`
}

type snapshotSegment struct {
	Start int64  `json:"start"`
	End   int64  `json:"end"`
	Data  []byte `json:"data"`
}

// NewRangeCacheGuard returns an empty cache governed by cfg.
func NewRangeCacheGuard(cfg Config) *RangeCacheGuard {
	return &RangeCacheGuard{
		cfg:       cfg,
		resources: make(map[string]*resourceState),
	}
}

// NewRangeCacheGuardFromSnapshot restores registrations and cached segments
// from data produced by Snapshot.
func NewRangeCacheGuardFromSnapshot(cfg Config, data []byte) (*RangeCacheGuard, error) {
	var snap snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, ErrCorruptSnapshot
	}
	if snap.Version != snapshotVersion || snap.Hits < 0 || snap.Misses < 0 || snap.Evicted < 0 {
		return nil, ErrCorruptSnapshot
	}

	restored := NewRangeCacheGuard(cfg)
	restored.clock = snap.Clock
	restored.hits = snap.Hits
	restored.misses = snap.Misses
	restored.evicted = snap.Evicted

	for _, sr := range snap.Resources {
		if !validStrongETag(sr.ETag) || sr.Size <= 0 {
			return nil, ErrCorruptSnapshot
		}
		if _, exists := restored.resources[sr.ETag]; exists {
			return nil, ErrCorruptSnapshot
		}

		res := &resourceState{
			etag:  sr.ETag,
			size:  sr.Size,
			order: sr.Order,
		}
		seen := make(map[Segment]struct{}, len(sr.Segments))
		for _, ss := range sr.Segments {
			seg := Segment{Start: ss.Start, End: ss.End}
			if err := validateSegment(seg, sr.Size); err != nil {
				return nil, ErrCorruptSnapshot
			}
			want, ok := segmentLen(seg)
			if !ok || int64(len(ss.Data)) != want {
				return nil, ErrCorruptSnapshot
			}
			if _, exists := seen[seg]; exists {
				return nil, ErrCorruptSnapshot
			}
			for _, prior := range res.segments {
				if segmentsOverlap(prior.seg, seg) {
					return nil, ErrCorruptSnapshot
				}
			}
			seen[seg] = struct{}{}
			res.segments = append(res.segments, cachedSegment{
				seg:  seg,
				data: append([]byte(nil), ss.Data...),
			})
		}
		sort.Slice(res.segments, func(i, j int) bool {
			return res.segments[i].seg.Start < res.segments[j].seg.Start
		})
		for _, cs := range res.segments {
			restored.total += int64(len(cs.data))
		}
		restored.resources[sr.ETag] = res
		if sr.Order > restored.clock {
			restored.clock = sr.Order
		}
	}

	if cfg.MaxBytes > 0 && restored.total > cfg.MaxBytes {
		return nil, ErrCorruptSnapshot
	}
	return restored, nil
}

// Register records a strong etag and its full representation size.
func (g *RangeCacheGuard) Register(etag string, size int64) error {
	if !validStrongETag(etag) || size <= 0 {
		return ErrInvalidRange
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	if res, exists := g.resources[etag]; exists {
		if res.size != size {
			return ErrValidatorConflict
		}
		return nil
	}
	g.resources[etag] = &resourceState{etag: etag, size: size}
	return nil
}

// ParseRange parses a bytes= range header for a representation of size.
func (g *RangeCacheGuard) ParseRange(header string, size int64) ([]Segment, error) {
	h := strings.TrimSpace(header)
	if len(h) < len("bytes=") || !strings.EqualFold(h[:len("bytes=")], "bytes=") {
		return nil, ErrInvalidRange
	}
	specs := strings.Split(h[len("bytes="):], ",")
	if g.cfg.MaxRanges > 0 && len(specs) > g.cfg.MaxRanges {
		return nil, ErrTooManyRanges
	}

	segs := make([]Segment, 0, len(specs))
	for _, raw := range specs {
		seg, err := parseRangeSpec(strings.TrimSpace(raw), size)
		if err != nil {
			return nil, err
		}
		segs = append(segs, seg)
	}

	ordered := append([]Segment(nil), segs...)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].Start == ordered[j].Start {
			return ordered[i].End < ordered[j].End
		}
		return ordered[i].Start < ordered[j].Start
	})
	for i := 1; i < len(ordered); i++ {
		if ordered[i].Start <= ordered[i-1].End {
			return nil, ErrOverlappingRanges
		}
	}
	return segs, nil
}

// Coverage validates segments and returns their total length.
func (g *RangeCacheGuard) Coverage(segs []Segment) (int64, error) {
	var total int64
	ordered := append([]Segment(nil), segs...)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].Start == ordered[j].Start {
			return ordered[i].End < ordered[j].End
		}
		return ordered[i].Start < ordered[j].Start
	})
	for i, seg := range ordered {
		n, ok := segmentLen(seg)
		if !ok {
			return 0, ErrInvalidRange
		}
		if i > 0 && seg.Start <= ordered[i-1].End {
			return 0, ErrOverlappingRanges
		}
		if total > math.MaxInt64-n {
			return 0, ErrInvalidRange
		}
		total += n
	}
	return total, nil
}

// Store caches data for exactly one segment of etag.
func (g *RangeCacheGuard) Store(etag string, seg Segment, data []byte) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	res, exists := g.resources[etag]
	if !exists {
		return ErrUnknownResource
	}
	if err := validateSegment(seg, res.size); err != nil {
		return err
	}
	want, ok := segmentLen(seg)
	if !ok || int64(len(data)) != want {
		return ErrSizeMismatch
	}
	payloadLen := int64(len(data))
	if g.cfg.MaxBytes > 0 && payloadLen > g.cfg.MaxBytes {
		return ErrBudgetExceeded
	}

	var oldBytes int64
	for _, cs := range res.segments {
		oldBytes += int64(len(cs.data))
	}
	overlap := int64(0)
	for _, cs := range res.segments {
		if n, ok := overlapLen(cs.seg, seg); ok {
			overlap += n
		}
	}

	newSegments := subtractSegment(res.segments, seg)
	newSegments = append(newSegments, cachedSegment{
		seg:  seg,
		data: append([]byte(nil), data...),
	})
	sort.Slice(newSegments, func(i, j int) bool {
		return newSegments[i].seg.Start < newSegments[j].seg.Start
	})

	newResourceBytes := oldBytes - overlap + payloadLen
	proposedTotal := g.total - oldBytes + newResourceBytes

	var victims []*resourceState
	var freed int64
	if g.cfg.MaxBytes > 0 && proposedTotal > g.cfg.MaxBytes {
		candidates := make([]*resourceState, 0, len(g.resources))
		for _, other := range g.resources {
			if other == res {
				continue
			}
			var n int64
			for _, cs := range other.segments {
				n += int64(len(cs.data))
			}
			if n > 0 {
				candidates = append(candidates, other)
			}
		}
		sort.Slice(candidates, func(i, j int) bool {
			return candidates[i].order < candidates[j].order
		})
		for _, victim := range candidates {
			if proposedTotal <= g.cfg.MaxBytes {
				break
			}
			var n int64
			for _, cs := range victim.segments {
				n += int64(len(cs.data))
			}
			victims = append(victims, victim)
			freed += n
			proposedTotal -= n
		}
		if proposedTotal > g.cfg.MaxBytes {
			newSegments = []cachedSegment{{
				seg:  seg,
				data: append([]byte(nil), data...),
			}}
			newResourceBytes = payloadLen
			proposedTotal = g.total - oldBytes - freed + newResourceBytes
		}
	}

	if g.cfg.MaxBytes > 0 && proposedTotal > g.cfg.MaxBytes {
		return ErrBudgetExceeded
	}

	if len(res.segments) == 0 && len(newSegments) > 0 {
		g.clock++
		res.order = g.clock
	}
	res.segments = newSegments
	for _, victim := range victims {
		victim.segments = nil
		g.evicted++
	}
	g.total = proposedTotal
	return nil
}

// Fetch returns the exact bytes for seg from a cached segment that fully
// contains it.
func (g *RangeCacheGuard) Fetch(etag string, seg Segment) ([]byte, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	res, exists := g.resources[etag]
	if !exists {
		return nil, ErrUnknownResource
	}
	if err := validateSegment(seg, res.size); err != nil {
		return nil, err
	}
	for _, cs := range res.segments {
		if cs.seg.Start <= seg.Start && cs.seg.End >= seg.End {
			offset := seg.Start - cs.seg.Start
			length := seg.End - seg.Start + 1
			out := make([]byte, length)
			copy(out, cs.data[offset:offset+length])
			g.hits++
			return out, nil
		}
	}
	g.misses++
	return nil, ErrPartialMiss
}

// CachedBytes returns how many payload bytes are cached for etag.
func (g *RangeCacheGuard) CachedBytes(etag string) int64 {
	g.mu.Lock()
	defer g.mu.Unlock()

	res, exists := g.resources[etag]
	if !exists {
		return 0
	}
	var total int64
	for _, cs := range res.segments {
		total += int64(len(cs.data))
	}
	return total
}

// TotalBytes returns how many payload bytes are cached in total.
func (g *RangeCacheGuard) TotalBytes() int64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.total
}

// ValidateIfRange reports whether an If-Range header still matches etag.
func (g *RangeCacheGuard) ValidateIfRange(etag, ifRange string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()

	if ifRange == "" {
		return true
	}
	if strings.HasPrefix(ifRange, "W/") {
		return false
	}
	res, exists := g.resources[etag]
	if !exists {
		return false
	}
	return res.etag == ifRange
}

// Invalidate drops every cached segment of etag and returns how many were
// dropped.
func (g *RangeCacheGuard) Invalidate(etag string) int {
	g.mu.Lock()
	defer g.mu.Unlock()

	res, exists := g.resources[etag]
	if !exists {
		return 0
	}
	dropped := len(res.segments)
	for _, cs := range res.segments {
		g.total -= int64(len(cs.data))
	}
	res.segments = nil
	res.order = 0
	return dropped
}

// Len returns the number of registered resources.
func (g *RangeCacheGuard) Len() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.resources)
}

// Stats returns the current counters.
func (g *RangeCacheGuard) Stats() Stats {
	g.mu.Lock()
	defer g.mu.Unlock()

	segments := 0
	for _, res := range g.resources {
		segments += len(res.segments)
	}
	return Stats{
		Resources: len(g.resources),
		Segments:  segments,
		Bytes:     g.total,
		Hits:      g.hits,
		Misses:    g.misses,
		Evicted:   g.evicted,
	}
}

// Snapshot serialises registrations and cached segments.
func (g *RangeCacheGuard) Snapshot() ([]byte, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	snap := snapshot{
		Version: snapshotVersion,
		Clock:   g.clock,
		Hits:    g.hits,
		Misses:  g.misses,
		Evicted: g.evicted,
	}
	etags := make([]string, 0, len(g.resources))
	for etag := range g.resources {
		etags = append(etags, etag)
	}
	sort.Strings(etags)

	for _, etag := range etags {
		res := g.resources[etag]
		sr := snapshotResource{
			ETag:  res.etag,
			Size:  res.size,
			Order: res.order,
		}
		for _, cs := range res.segments {
			sr.Segments = append(sr.Segments, snapshotSegment{
				Start: cs.seg.Start,
				End:   cs.seg.End,
				Data:  append([]byte(nil), cs.data...),
			})
		}
		snap.Resources = append(snap.Resources, sr)
	}
	return json.Marshal(snap)
}

func validStrongETag(etag string) bool {
	return etag != "" && !strings.HasPrefix(etag, "W/")
}

func parseRangeSpec(spec string, size int64) (Segment, error) {
	if spec == "" || strings.Count(spec, "-") != 1 {
		return Segment{}, ErrInvalidRange
	}
	parts := strings.SplitN(spec, "-", 2)
	left := strings.TrimSpace(parts[0])
	right := strings.TrimSpace(parts[1])

	if left == "" {
		if right == "" {
			return Segment{}, ErrInvalidRange
		}
		n, ok := parseDecimal(right)
		if !ok {
			return Segment{}, ErrInvalidRange
		}
		if n == 0 || size <= 0 {
			return Segment{}, ErrUnsatisfiable
		}
		start := size - n
		if n > size {
			start = 0
		}
		return Segment{Start: start, End: size - 1}, nil
	}

	start, ok := parseDecimal(left)
	if !ok {
		return Segment{}, ErrInvalidRange
	}
	if right == "" {
		if start >= size {
			return Segment{}, ErrUnsatisfiable
		}
		return Segment{Start: start, End: size - 1}, nil
	}

	end, ok := parseDecimal(right)
	if !ok || end < start {
		return Segment{}, ErrInvalidRange
	}
	if start >= size {
		return Segment{}, ErrUnsatisfiable
	}
	if end >= size {
		end = size - 1
	}
	return Segment{Start: start, End: end}, nil
}

func parseDecimal(s string) (int64, bool) {
	if s == "" {
		return 0, false
	}
	var n int64
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		digit := int64(c - '0')
		if n > (math.MaxInt64-digit)/10 {
			return 0, false
		}
		n = n*10 + digit
	}
	return n, true
}

func validateSegment(seg Segment, size int64) error {
	if seg.Start < 0 || seg.End < seg.Start || seg.Start >= size || seg.End >= size {
		return ErrInvalidRange
	}
	return nil
}

func segmentLen(seg Segment) (int64, bool) {
	if seg.Start < 0 || seg.End < seg.Start {
		return 0, false
	}
	diff := seg.End - seg.Start
	if diff == math.MaxInt64 {
		return 0, false
	}
	return diff + 1, true
}

func segmentsOverlap(a, b Segment) bool {
	return a.Start <= b.End && b.Start <= a.End
}

func overlapLen(a, b Segment) (int64, bool) {
	start := a.Start
	if b.Start > start {
		start = b.Start
	}
	end := a.End
	if b.End < end {
		end = b.End
	}
	if start > end {
		return 0, false
	}
	return end - start + 1, true
}

func subtractSegment(segments []cachedSegment, cut Segment) []cachedSegment {
	out := make([]cachedSegment, 0, len(segments)+1)
	for _, cs := range segments {
		if cs.seg.End < cut.Start || cs.seg.Start > cut.End {
			out = append(out, cs)
			continue
		}
		if cs.seg.Start < cut.Start {
			end := cut.Start - 1
			out = append(out, cachedSegment{
				seg:  Segment{Start: cs.seg.Start, End: end},
				data: cs.data[:end-cs.seg.Start+1],
			})
		}
		if cs.seg.End > cut.End {
			start := cut.End + 1
			offset := start - cs.seg.Start
			out = append(out, cachedSegment{
				seg:  Segment{Start: start, End: cs.seg.End},
				data: cs.data[offset:],
			})
		}
	}
	return out
}
