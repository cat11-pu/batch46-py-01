package task

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	taskpkg "gsb/batch46-safety-d-08"
)

func rangeConfig() taskpkg.Config {
	return taskpkg.Config{MaxRanges: 4, MaxBytes: 4096}
}

func mustSeg(t *testing.T, start, end int64) taskpkg.Segment {
	t.Helper()
	return taskpkg.Segment{Start: start, End: end}
}

// A single closed range keeps its exact bounds.
func TestParseSingleRange(t *testing.T) {
	g := taskpkg.NewRangeCacheGuard(rangeConfig())
	segs, err := g.ParseRange("bytes=0-99", 1000)
	if err != nil {
		t.Fatalf("ParseRange: %v", err)
	}
	if len(segs) != 1 {
		t.Fatalf("ParseRange returned %d segments, want 1", len(segs))
	}
	if segs[0].Start != 0 || segs[0].End != 99 {
		t.Fatalf("segment = %+v, want {0 99}", segs[0])
	}
}

// Multiple ranges keep their order and tolerate a space after the comma.
func TestParseMultipleRanges(t *testing.T) {
	g := taskpkg.NewRangeCacheGuard(rangeConfig())
	segs, err := g.ParseRange("bytes=0-9, 100-199", 1000)
	if err != nil {
		t.Fatalf("ParseRange: %v", err)
	}
	if len(segs) != 2 {
		t.Fatalf("ParseRange returned %d segments, want 2", len(segs))
	}
	if segs[0] != (taskpkg.Segment{Start: 0, End: 9}) {
		t.Fatalf("first segment = %+v, want {0 9}", segs[0])
	}
	if segs[1] != (taskpkg.Segment{Start: 100, End: 199}) {
		t.Fatalf("second segment = %+v, want {100 199}", segs[1])
	}
}

// Suffix and open-ended forms are resolved against the representation size.
func TestParseSuffixAndOpenEndedRanges(t *testing.T) {
	g := taskpkg.NewRangeCacheGuard(rangeConfig())
	suffix, err := g.ParseRange("bytes=-500", 1000)
	if err != nil {
		t.Fatalf("ParseRange suffix: %v", err)
	}
	if len(suffix) != 1 || suffix[0].Start != 500 || suffix[0].End != 999 {
		t.Fatalf("suffix range = %+v, want {500 999}", suffix)
	}
	open, err := g.ParseRange("bytes=990-", 1000)
	if err != nil {
		t.Fatalf("ParseRange open ended: %v", err)
	}
	if len(open) != 1 || open[0].Start != 990 || open[0].End != 999 {
		t.Fatalf("open ended range = %+v, want {990 999}", open)
	}
	huge, err := g.ParseRange("bytes=-5000", 1000)
	if err != nil {
		t.Fatalf("ParseRange huge suffix: %v", err)
	}
	if len(huge) != 1 || huge[0].Start != 0 || huge[0].End != 999 {
		t.Fatalf("huge suffix = %+v, want the whole representation", huge)
	}
}

// An end beyond the representation is clamped, not rejected.
func TestParseClampsEndBeyondSize(t *testing.T) {
	g := taskpkg.NewRangeCacheGuard(rangeConfig())
	segs, err := g.ParseRange("bytes=0-9999", 1000)
	if err != nil {
		t.Fatalf("ParseRange: %v", err)
	}
	if len(segs) != 1 || segs[0].Start != 0 || segs[0].End != 999 {
		t.Fatalf("clamped segment = %+v, want {0 999}", segs)
	}
}

// A range that starts at or beyond the size is unsatisfiable, as is a zero
// length suffix.
func TestParseRejectsUnsatisfiableStart(t *testing.T) {
	g := taskpkg.NewRangeCacheGuard(rangeConfig())
	if _, err := g.ParseRange("bytes=1000-1200", 1000); !errors.Is(err, taskpkg.ErrUnsatisfiable) {
		t.Fatalf("range starting at the size = %v, want ErrUnsatisfiable", err)
	}
	if _, err := g.ParseRange("bytes=-0", 1000); !errors.Is(err, taskpkg.ErrUnsatisfiable) {
		t.Fatalf("zero length suffix = %v, want ErrUnsatisfiable", err)
	}
}

// More ranges than MaxRanges is refused before any segment is produced.
func TestParseRejectsTooManyRanges(t *testing.T) {
	cfg := rangeConfig()
	cfg.MaxRanges = 2
	g := taskpkg.NewRangeCacheGuard(cfg)
	if _, err := g.ParseRange("bytes=0-1,2-3,4-5", 1000); !errors.Is(err, taskpkg.ErrTooManyRanges) {
		t.Fatalf("three ranges under MaxRanges 2 = %v, want ErrTooManyRanges", err)
	}
}

// Overlapping ranges are rejected while adjacent ranges remain valid.
func TestParseRejectsOverlappingRanges(t *testing.T) {
	g := taskpkg.NewRangeCacheGuard(rangeConfig())
	if _, err := g.ParseRange("bytes=0-99,50-149", 1000); !errors.Is(err, taskpkg.ErrOverlappingRanges) {
		t.Fatalf("overlapping ranges = %v, want ErrOverlappingRanges", err)
	}
	segs, err := g.ParseRange("bytes=0-99,100-199", 1000)
	if err != nil {
		t.Fatalf("adjacent ranges: %v", err)
	}
	if len(segs) != 2 {
		t.Fatalf("adjacent ranges produced %d segments, want 2", len(segs))
	}
}

// Malformed headers and inverted ranges are invalid, not unsatisfiable.
func TestParseRejectsMalformedHeader(t *testing.T) {
	g := taskpkg.NewRangeCacheGuard(rangeConfig())
	if _, err := g.ParseRange("items=0-9", 1000); !errors.Is(err, taskpkg.ErrInvalidRange) {
		t.Fatalf("non-bytes unit = %v, want ErrInvalidRange", err)
	}
	if _, err := g.ParseRange("bytes=abc", 1000); !errors.Is(err, taskpkg.ErrInvalidRange) {
		t.Fatalf("non-numeric range = %v, want ErrInvalidRange", err)
	}
	if _, err := g.ParseRange("bytes=5-2", 1000); !errors.Is(err, taskpkg.ErrInvalidRange) {
		t.Fatalf("inverted range = %v, want ErrInvalidRange", err)
	}
}

// Stored bytes come back byte for byte.
func TestStoreAndFetchExactBytes(t *testing.T) {
	g := taskpkg.NewRangeCacheGuard(rangeConfig())
	if err := g.Register("etag-a", 100); err != nil {
		t.Fatalf("Register: %v", err)
	}
	payload := []byte("0123456789")
	if err := g.Store("etag-a", mustSeg(t, 0, 9), payload); err != nil {
		t.Fatalf("Store: %v", err)
	}
	got, err := g.Fetch("etag-a", mustSeg(t, 0, 9))
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("Fetch = %q, want %q", got, payload)
	}
	if cached := g.CachedBytes("etag-a"); cached != 10 {
		t.Fatalf("CachedBytes = %d, want 10", cached)
	}
	if total := g.TotalBytes(); total != 10 {
		t.Fatalf("TotalBytes = %d, want 10", total)
	}
	if stats := g.Stats(); stats.Segments != 1 || stats.Bytes != 10 {
		t.Fatalf("Stats = %+v, want 1 segment and 10 bytes", stats)
	}
}

// A sub-range is sliced out of a containing segment; a range that pokes out
// of every cached segment misses.
func TestFetchRequiresContainingSegment(t *testing.T) {
	g := taskpkg.NewRangeCacheGuard(rangeConfig())
	if err := g.Register("etag-b", 1000); err != nil {
		t.Fatalf("Register: %v", err)
	}
	payload := make([]byte, 100)
	for i := range payload {
		payload[i] = byte(i)
	}
	if err := g.Store("etag-b", mustSeg(t, 0, 99), payload); err != nil {
		t.Fatalf("Store: %v", err)
	}
	part, err := g.Fetch("etag-b", mustSeg(t, 50, 99))
	if err != nil {
		t.Fatalf("Fetch sub-range: %v", err)
	}
	if !bytes.Equal(part, payload[50:]) {
		t.Fatalf("Fetch sub-range returned %v, want %v", part, payload[50:])
	}
	if _, err := g.Fetch("etag-b", mustSeg(t, 0, 149)); !errors.Is(err, taskpkg.ErrPartialMiss) {
		t.Fatalf("Fetch past the cached segment = %v, want ErrPartialMiss", err)
	}
	if _, err := g.Fetch("etag-missing", mustSeg(t, 0, 1)); !errors.Is(err, taskpkg.ErrUnknownResource) {
		t.Fatalf("Fetch from an unregistered etag = %v, want ErrUnknownResource", err)
	}
}

// A payload shorter than its segment must not be cached.
func TestStoreRejectsLengthMismatch(t *testing.T) {
	g := taskpkg.NewRangeCacheGuard(rangeConfig())
	if err := g.Register("etag-c", 100); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := g.Store("etag-c", mustSeg(t, 0, 9), []byte("short")); !errors.Is(err, taskpkg.ErrSizeMismatch) {
		t.Fatalf("Store with a short payload = %v, want ErrSizeMismatch", err)
	}
	if _, err := g.Fetch("etag-c", mustSeg(t, 0, 9)); !errors.Is(err, taskpkg.ErrPartialMiss) {
		t.Fatalf("Fetch after a rejected store = %v, want ErrPartialMiss", err)
	}
	if total := g.TotalBytes(); total != 0 {
		t.Fatalf("TotalBytes = %d after a rejected store, want 0", total)
	}
}

// The byte budget evicts the oldest stored resource and refuses a single
// oversized segment without touching what is already cached.
func TestBudgetEvictsOldestAndRejectsOversize(t *testing.T) {
	cfg := taskpkg.Config{MaxRanges: 4, MaxBytes: 100}
	g := taskpkg.NewRangeCacheGuard(cfg)
	for _, etag := range []string{"e1", "e2", "e3"} {
		if err := g.Register(etag, 200); err != nil {
			t.Fatalf("Register %s: %v", etag, err)
		}
	}
	if err := g.Store("e1", mustSeg(t, 0, 59), bytes.Repeat([]byte("a"), 60)); err != nil {
		t.Fatalf("Store e1: %v", err)
	}
	if err := g.Store("e2", mustSeg(t, 0, 29), bytes.Repeat([]byte("b"), 30)); err != nil {
		t.Fatalf("Store e2: %v", err)
	}
	if err := g.Store("e3", mustSeg(t, 0, 29), bytes.Repeat([]byte("c"), 30)); err != nil {
		t.Fatalf("Store e3: %v", err)
	}
	if got := g.CachedBytes("e1"); got != 0 {
		t.Fatalf("CachedBytes(e1) = %d after eviction, want 0", got)
	}
	if _, err := g.Fetch("e1", mustSeg(t, 0, 59)); !errors.Is(err, taskpkg.ErrPartialMiss) {
		t.Fatalf("Fetch of the evicted resource = %v, want ErrPartialMiss", err)
	}
	if total := g.TotalBytes(); total != 60 {
		t.Fatalf("TotalBytes = %d after eviction, want 60", total)
	}
	err := g.Store("e3", mustSeg(t, 0, 119), bytes.Repeat([]byte("d"), 120))
	if !errors.Is(err, taskpkg.ErrBudgetExceeded) {
		t.Fatalf("Store of an oversized segment = %v, want ErrBudgetExceeded", err)
	}
	if total := g.TotalBytes(); total != 60 {
		t.Fatalf("TotalBytes = %d after an oversized store, want 60", total)
	}
}

// If-Range only matches the same strong etag; weak and foreign validators
// never do.
func TestIfRangeRequiresStrongETag(t *testing.T) {
	g := taskpkg.NewRangeCacheGuard(rangeConfig())
	if err := g.Register("abc", 100); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if !g.ValidateIfRange("abc", "abc") {
		t.Fatal("If-Range with the identical etag was rejected")
	}
	if !g.ValidateIfRange("abc", "") {
		t.Fatal("If-Range with an empty validator must not block the range")
	}
	if g.ValidateIfRange("abc", "W/abc") {
		t.Fatal("If-Range accepted a weak validator")
	}
	if g.ValidateIfRange("abc", "def") {
		t.Fatal("If-Range accepted a foreign validator")
	}
	if g.ValidateIfRange("zzz", "zzz") {
		t.Fatal("If-Range accepted an unregistered etag")
	}
}

// Invalidate drops cached bytes but keeps the representation registered, and
// the surviving segments survive a restart.
func TestInvalidateAndSnapshotRoundTrip(t *testing.T) {
	g := taskpkg.NewRangeCacheGuard(rangeConfig())
	if err := g.Register("r1", 100); err != nil {
		t.Fatalf("Register r1: %v", err)
	}
	if err := g.Register("r2", 200); err != nil {
		t.Fatalf("Register r2: %v", err)
	}
	r1Payload := []byte("abcdefghij")
	if err := g.Store("r1", mustSeg(t, 0, 9), r1Payload); err != nil {
		t.Fatalf("Store r1: %v", err)
	}
	r2Payload := []byte(strings.Repeat("z", 50))
	if err := g.Store("r2", mustSeg(t, 100, 149), r2Payload); err != nil {
		t.Fatalf("Store r2: %v", err)
	}
	if dropped := g.Invalidate("r1"); dropped != 1 {
		t.Fatalf("Invalidate(r1) = %d, want 1", dropped)
	}
	if cached := g.CachedBytes("r1"); cached != 0 {
		t.Fatalf("CachedBytes(r1) = %d after invalidate, want 0", cached)
	}
	if _, err := g.Fetch("r1", mustSeg(t, 0, 9)); !errors.Is(err, taskpkg.ErrPartialMiss) {
		t.Fatalf("Fetch of invalidated bytes = %v, want ErrPartialMiss", err)
	}
	snap, err := g.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	restored, err := taskpkg.NewRangeCacheGuardFromSnapshot(rangeConfig(), snap)
	if err != nil {
		t.Fatalf("NewRangeCacheGuardFromSnapshot: %v", err)
	}
	got, err := restored.Fetch("r2", mustSeg(t, 100, 149))
	if err != nil {
		t.Fatalf("Fetch after restore: %v", err)
	}
	if !bytes.Equal(got, r2Payload) {
		t.Fatalf("restored payload mismatch")
	}
	if total := restored.TotalBytes(); total != 50 {
		t.Fatalf("TotalBytes after restore = %d, want 50", total)
	}
	if n := restored.Len(); n != 2 {
		t.Fatalf("Len after restore = %d, want 2 registrations", n)
	}
	if dropped := restored.Invalidate("r1"); dropped != 0 {
		t.Fatalf("Invalidate(r1) after restore = %d, want 0", dropped)
	}
}

// Concurrent stores of distinct etags must all be visible and accounted for.
func TestConcurrentStoresRespectBudget(t *testing.T) {
	cfg := taskpkg.Config{MaxRanges: 4, MaxBytes: 4096}
	g := taskpkg.NewRangeCacheGuard(cfg)
	const workers = 32
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			etag := fmt.Sprintf("etag-%d", i)
			if err := g.Register(etag, 100); err != nil {
				errs <- fmt.Errorf("Register %s: %w", etag, err)
				return
			}
			if err := g.Store(etag, taskpkg.Segment{Start: 0, End: 99}, bytes.Repeat([]byte{byte(i)}, 100)); err != nil {
				errs <- fmt.Errorf("Store %s: %w", etag, err)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("%v", err)
	}
	if total := g.TotalBytes(); total != workers*100 {
		t.Fatalf("TotalBytes = %d after %d stores, want %d", total, workers, workers*100)
	}
	if stats := g.Stats(); stats.Resources != workers || stats.Segments != workers {
		t.Fatalf("Stats = %+v, want %d resources and segments", stats, workers)
	}
}
