package task

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"

	taskpkg "gsb/batch46-safety-d-04"
)

func qpackSettings(capacity uint64, blocked int) taskpkg.Settings {
	return taskpkg.Settings{MaxTableCapacity: capacity, MaxBlockedStreams: blocked}
}

func mustQpackGuard(t *testing.T, s taskpkg.Settings) *taskpkg.QpackGuard {
	t.Helper()
	g := taskpkg.NewQpackGuard(s)
	if g == nil {
		t.Fatalf("NewQpackGuard returned nil")
	}
	return g
}

func field(name, value string) taskpkg.HeaderField {
	return taskpkg.HeaderField{Name: name, Value: value}
}

func entrySize(name, value string) uint64 {
	return uint64(len(name) + len(value) + taskpkg.EntryOverhead)
}

func mustInsert(t *testing.T, g *taskpkg.QpackGuard, name, value string) uint64 {
	t.Helper()
	idx, err := g.Insert(name, value, false)
	if err != nil {
		t.Fatalf("Insert(%q,%q): %v", name, value, err)
	}
	return idx
}

func mustEncode(t *testing.T, g *taskpkg.QpackGuard, stream uint64, fields ...taskpkg.HeaderField) uint64 {
	t.Helper()
	required, err := g.EncodeSection(stream, fields)
	if err != nil {
		t.Fatalf("EncodeSection(%d): %v", stream, err)
	}
	return required
}

// Dynamic table field names must be lower-case, non-empty, non-pseudo and must
// not be connection specific.
func TestInsertNameRules(t *testing.T) {
	g := mustQpackGuard(t, qpackSettings(200, 1))
	if _, err := g.Insert("Accept", "text/html", false); !errors.Is(err, taskpkg.ErrFieldInvalid) {
		t.Fatalf("uppercase name: want ErrFieldInvalid, got %v", err)
	}
	if _, err := g.Insert("connection", "keep-alive", false); !errors.Is(err, taskpkg.ErrFieldInvalid) {
		t.Fatalf("connection header: want ErrFieldInvalid, got %v", err)
	}
	if _, err := g.Insert("", "value", false); !errors.Is(err, taskpkg.ErrFieldInvalid) {
		t.Fatalf("empty name: want ErrFieldInvalid, got %v", err)
	}
	if _, err := g.Insert(":path", "/", false); !errors.Is(err, taskpkg.ErrFieldInvalid) {
		t.Fatalf("pseudo-header insert: want ErrFieldInvalid, got %v", err)
	}
	idx := mustInsert(t, g, "x-ok", "v")
	if idx != 0 {
		t.Fatalf("first valid insert index = %d, want 0", idx)
	}
	counters := g.Counters()
	if counters.FieldsRejected != 4 || counters.Inserted != 1 {
		t.Fatalf("counters = %+v, want FieldsRejected=4 Inserted=1", counters)
	}
}

// Sensitive fields may never enter the table, and an entry larger than the
// capacity is refused without clearing existing state.
func TestInsertSensitiveAndOversize(t *testing.T) {
	g := mustQpackGuard(t, qpackSettings(40, 1))
	if _, err := g.Insert("x-token", "abc", true); !errors.Is(err, taskpkg.ErrSensitiveField) {
		t.Fatalf("sensitive field: want ErrSensitiveField, got %v", err)
	}
	oversize := strings.Repeat("a", 40)
	if _, err := g.Insert("x-long", oversize, false); !errors.Is(err, taskpkg.ErrEntryTooLarge) {
		t.Fatalf("oversize entry: want ErrEntryTooLarge, got %v", err)
	}
	if got := g.InsertCount(); got != 0 {
		t.Fatalf("InsertCount = %d, want 0 after rejections", got)
	}
	if got := g.DynamicTableSize(); got != 0 {
		t.Fatalf("DynamicTableSize = %d, want 0", got)
	}
	mustInsert(t, g, "x", "1")
	if got := g.DynamicTableSize(); got != entrySize("x", "1") {
		t.Fatalf("DynamicTableSize = %d, want %d", got, entrySize("x", "1"))
	}
}

// Insertion evicts the oldest entries when the table is full, and lookup
// distinguishes evicted indices from indices that never existed.
func TestInsertEvictionAndLookup(t *testing.T) {
	g := mustQpackGuard(t, qpackSettings(80, 1))
	mustInsert(t, g, "x-a", "1")
	mustInsert(t, g, "x-b", "2")
	mustInsert(t, g, "x-c", "3")
	if _, err := g.Lookup(0); !errors.Is(err, taskpkg.ErrEvicted) {
		t.Fatalf("evicted entry: want ErrEvicted, got %v", err)
	}
	entry, err := g.Lookup(1)
	if err != nil {
		t.Fatalf("Lookup(1): %v", err)
	}
	if entry.Name != "x-b" || entry.Value != "2" {
		t.Fatalf("Lookup(1) = %+v, want x-b/2", entry)
	}
	if _, err := g.Lookup(3); !errors.Is(err, taskpkg.ErrNoEntry) {
		t.Fatalf("future index: want ErrNoEntry, got %v", err)
	}
	if got := g.DynamicTableSize(); got != 2*entrySize("x-a", "1") {
		t.Fatalf("DynamicTableSize = %d, want %d", got, 2*entrySize("x-a", "1"))
	}
	if got := g.Counters().Evicted; got != 1 {
		t.Fatalf("Evicted = %d, want 1", got)
	}
}

// Pseudo-header ordering, duplication and unknown pseudo names are rejected.
func TestPseudoHeaderValidation(t *testing.T) {
	g := mustQpackGuard(t, qpackSettings(200, 1))
	if _, err := g.EncodeSection(1, []taskpkg.HeaderField{field("x-a", "1"), field(":method", "GET")}); !errors.Is(err, taskpkg.ErrFieldInvalid) {
		t.Fatalf("regular before pseudo: want ErrFieldInvalid, got %v", err)
	}
	if _, err := g.EncodeSection(2, []taskpkg.HeaderField{field(":path", "/"), field(":path", "/x")}); !errors.Is(err, taskpkg.ErrFieldInvalid) {
		t.Fatalf("duplicate pseudo: want ErrFieldInvalid, got %v", err)
	}
	if _, err := g.EncodeSection(3, []taskpkg.HeaderField{field(":foo", "bar")}); !errors.Is(err, taskpkg.ErrFieldInvalid) {
		t.Fatalf("unknown pseudo: want ErrFieldInvalid, got %v", err)
	}
	if _, err := g.EncodeSection(4, []taskpkg.HeaderField{field(":Method", "GET")}); !errors.Is(err, taskpkg.ErrFieldInvalid) {
		t.Fatalf("uppercase pseudo: want ErrFieldInvalid, got %v", err)
	}
	required := mustEncode(t, g, 5, field(":method", "GET"), field(":path", "/"), field("x-a", "1"))
	if required != 1 {
		t.Fatalf("required insert count = %d, want 1", required)
	}
	counters := g.Counters()
	if counters.FieldsRejected != 4 || counters.Inserted != 1 || counters.SectionsEncoded != 1 {
		t.Fatalf("counters = %+v", counters)
	}
}

// Encoding inserts reusable regular fields once and reuses them on a repeated
// section.
func TestEncodeInsertsAndDedupes(t *testing.T) {
	g := mustQpackGuard(t, qpackSettings(200, 1))
	first := mustEncode(t, g, 1, field("x-a", "1"), field("x-b", "2"))
	if first != 2 {
		t.Fatalf("first required count = %d, want 2", first)
	}
	second := mustEncode(t, g, 2, field("x-a", "1"), field("x-b", "2"))
	if second != 2 {
		t.Fatalf("second required count = %d, want 2", second)
	}
	if got := g.InsertCount(); got != 2 {
		t.Fatalf("InsertCount = %d, want 2", got)
	}
	if got := g.DynamicTableSize(); got != entrySize("x-a", "1")+entrySize("x-b", "2") {
		t.Fatalf("DynamicTableSize = %d", got)
	}
	counters := g.Counters()
	if counters.SectionsEncoded != 2 || counters.Inserted != 2 {
		t.Fatalf("counters = %+v", counters)
	}
}

// Credential-bearing headers are encoded as literals and never inserted.
func TestEncodeSkipsSensitiveFields(t *testing.T) {
	g := mustQpackGuard(t, qpackSettings(200, 1))
	required := mustEncode(t, g, 1,
		field("authorization", "Bearer secret"),
		field("cookie", "sid=abc"),
		field("x-trace", "9"),
	)
	if required != 1 {
		t.Fatalf("required count = %d, want 1", required)
	}
	if got := g.InsertCount(); got != 1 {
		t.Fatalf("InsertCount = %d, want 1", got)
	}
	entry, err := g.Lookup(0)
	if err != nil {
		t.Fatalf("Lookup(0): %v", err)
	}
	if entry.Name != "x-trace" {
		t.Fatalf("only entry = %+v, want x-trace", entry)
	}
	if got := g.Counters().SensitiveFields; got != 2 {
		t.Fatalf("SensitiveFields = %d, want 2", got)
	}
}

// A stream requiring inserts that have not happened blocks, and only one
// stream may be blocked at a time under the configured limit.
func TestDecodeBlockedAndLimit(t *testing.T) {
	g := mustQpackGuard(t, qpackSettings(200, 1))
	if err := g.DecodeSection(1, 3); !errors.Is(err, taskpkg.ErrBlocked) {
		t.Fatalf("stream requiring 3 inserts: want ErrBlocked, got %v", err)
	}
	s, err := g.Stream(1)
	if err != nil {
		t.Fatalf("Stream(1): %v", err)
	}
	if !s.Blocked || s.RequiredInsertCount != 3 {
		t.Fatalf("stream 1 = %+v, want blocked on 3", s)
	}
	if err := g.DecodeSection(2, 3); !errors.Is(err, taskpkg.ErrBlockedLimit) {
		t.Fatalf("second blocked stream: want ErrBlockedLimit, got %v", err)
	}
	if _, err := g.Stream(2); !errors.Is(err, taskpkg.ErrStreamNotFound) {
		t.Fatalf("rejected stream must not be tracked: want ErrStreamNotFound, got %v", err)
	}
	counters := g.Counters()
	if counters.BlockedStreams != 1 || counters.BlockedRejected != 1 {
		t.Fatalf("counters = %+v, want BlockedStreams=1 BlockedRejected=1", counters)
	}
}

// Once the required inserts arrive, a previously blocked stream decodes
// successfully.
func TestDecodeUnblocksAfterInsert(t *testing.T) {
	g := mustQpackGuard(t, qpackSettings(200, 1))
	if err := g.DecodeSection(1, 3); !errors.Is(err, taskpkg.ErrBlocked) {
		t.Fatalf("blocked decode: want ErrBlocked, got %v", err)
	}
	mustInsert(t, g, "x-a", "1")
	mustInsert(t, g, "x-b", "2")
	mustInsert(t, g, "x-c", "3")
	if err := g.DecodeSection(1, 3); err != nil {
		t.Fatalf("decode after inserts: %v", err)
	}
	s, err := g.Stream(1)
	if err != nil {
		t.Fatalf("Stream(1): %v", err)
	}
	if s.Blocked {
		t.Fatalf("stream 1 still blocked after inserts")
	}
	if err := g.DecodeSection(2, 3); err != nil {
		t.Fatalf("second stream after slot release: %v", err)
	}
	counters := g.Counters()
	if counters.SectionsDecoded != 2 || counters.BlockedStreams != 0 {
		t.Fatalf("counters = %+v, want SectionsDecoded=2 BlockedStreams=0", counters)
	}
}

// Acknowledgements must be monotonic per stream and may not exceed the insert
// count; repeating the same acknowledgement is idempotent.
func TestAckRules(t *testing.T) {
	g := mustQpackGuard(t, qpackSettings(200, 1))
	mustInsert(t, g, "x-a", "1")
	mustEncode(t, g, 1, field("x-a", "1"))
	if err := g.AcknowledgeSection(1, 1); err != nil {
		t.Fatalf("first ack: %v", err)
	}
	if err := g.AcknowledgeSection(1, 1); err != nil {
		t.Fatalf("duplicate ack: %v", err)
	}
	if err := g.AcknowledgeSection(1, 0); !errors.Is(err, taskpkg.ErrAckRegression) {
		t.Fatalf("regressing ack: want ErrAckRegression, got %v", err)
	}
	if err := g.AcknowledgeSection(1, 5); !errors.Is(err, taskpkg.ErrAckFuture) {
		t.Fatalf("ack beyond insert count: want ErrAckFuture, got %v", err)
	}
	if err := g.AcknowledgeSection(99, 0); !errors.Is(err, taskpkg.ErrStreamNotFound) {
		t.Fatalf("ack for unknown stream: want ErrStreamNotFound, got %v", err)
	}
	if got := g.Counters().Acks; got != 1 {
		t.Fatalf("Acks = %d, want 1", got)
	}
}

// Cancelling a blocked stream releases its slot and forgets the stream.
func TestCancelStream(t *testing.T) {
	g := mustQpackGuard(t, qpackSettings(200, 1))
	if err := g.DecodeSection(1, 3); !errors.Is(err, taskpkg.ErrBlocked) {
		t.Fatalf("blocked decode: want ErrBlocked, got %v", err)
	}
	if err := g.CancelStream(1); err != nil {
		t.Fatalf("CancelStream: %v", err)
	}
	if _, err := g.Stream(1); !errors.Is(err, taskpkg.ErrStreamNotFound) {
		t.Fatalf("state after cancel: want ErrStreamNotFound, got %v", err)
	}
	counters := g.Counters()
	if counters.BlockedStreams != 0 || counters.Cancelled != 1 {
		t.Fatalf("counters = %+v, want BlockedStreams=0 Cancelled=1", counters)
	}
	if err := g.DecodeSection(2, 3); !errors.Is(err, taskpkg.ErrBlocked) {
		t.Fatalf("slot not released: want ErrBlocked, got %v", err)
	}
	if err := g.CancelStream(1); !errors.Is(err, taskpkg.ErrStreamNotFound) {
		t.Fatalf("second cancel: want ErrStreamNotFound, got %v", err)
	}
}

// Capacity may only be lowered within the negotiated maximum, and lowering it
// evicts entries until the table fits.
func TestSetCapacity(t *testing.T) {
	g := mustQpackGuard(t, qpackSettings(200, 1))
	mustInsert(t, g, "x-a", "1")
	mustInsert(t, g, "x-b", "2")
	mustInsert(t, g, "x-c", "3")
	if err := g.SetCapacity(72); err != nil {
		t.Fatalf("SetCapacity(72): %v", err)
	}
	if got := g.DynamicTableSize(); got != 72 {
		t.Fatalf("DynamicTableSize = %d, want 72", got)
	}
	if _, err := g.Lookup(0); !errors.Is(err, taskpkg.ErrEvicted) {
		t.Fatalf("entry after capacity shrink: want ErrEvicted, got %v", err)
	}
	if got := g.Counters().Inserted - g.Counters().Evicted; got != 2 {
		t.Fatalf("live entry accounting = %d, want 2", got)
	}
	if err := g.SetCapacity(1000); !errors.Is(err, taskpkg.ErrCapacityExceeded) {
		t.Fatalf("capacity above max: want ErrCapacityExceeded, got %v", err)
	}
	if err := g.SetCapacity(200); err != nil {
		t.Fatalf("SetCapacity(200): %v", err)
	}
}

// Concurrent inserts must produce unique, contiguous absolute indices and a
// consistent table size.
func TestConcurrentInsert(t *testing.T) {
	g := mustQpackGuard(t, qpackSettings(10000, 0))
	const n = 40
	var wg sync.WaitGroup
	errs := make([]error, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(idx int) {
			defer wg.Done()
			_, errs[idx] = g.Insert(fmt.Sprintf("x-%d", idx), "v", false)
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
	}
	if got := g.InsertCount(); got != n {
		t.Fatalf("InsertCount = %d, want %d", got, n)
	}
	seen := make(map[uint64]bool, n)
	for i := uint64(0); i < n; i++ {
		entry, err := g.Lookup(i)
		if err != nil {
			t.Fatalf("Lookup(%d): %v", i, err)
		}
		if seen[entry.Index] {
			t.Fatalf("duplicate absolute index %d", entry.Index)
		}
		seen[entry.Index] = true
	}
	var wantSize uint64
	for i := 0; i < n; i++ {
		wantSize += entrySize(fmt.Sprintf("x-%d", i), "v")
	}
	if got := g.DynamicTableSize(); got != wantSize {
		t.Fatalf("DynamicTableSize = %d, want %d", got, wantSize)
	}
	if got := g.Counters().Inserted; got != n {
		t.Fatalf("Inserted = %d, want %d", got, n)
	}
}

// A restart must preserve the dynamic table, the insert count and the
// negotiated capacity; corrupt snapshots are refused.
func TestSnapshotRestoresTable(t *testing.T) {
	s := qpackSettings(200, 1)
	g := mustQpackGuard(t, s)
	mustInsert(t, g, "x-a", "1")
	mustInsert(t, g, "x-b", "2")
	snap, err := g.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if _, err := taskpkg.NewQpackGuardFromSnapshot(s, []byte("not-json")); !errors.Is(err, taskpkg.ErrSnapshot) {
		t.Fatalf("corrupt snapshot: want ErrSnapshot, got %v", err)
	}
	restored, err := taskpkg.NewQpackGuardFromSnapshot(s, snap)
	if err != nil {
		t.Fatalf("NewQpackGuardFromSnapshot: %v", err)
	}
	if got := restored.InsertCount(); got != 2 {
		t.Fatalf("InsertCount after restore = %d, want 2", got)
	}
	entry, err := restored.Lookup(0)
	if err != nil {
		t.Fatalf("Lookup(0) after restore: %v", err)
	}
	if entry.Name != "x-a" {
		t.Fatalf("entry 0 after restore = %+v", entry)
	}
	if got := restored.DynamicTableSize(); got != entrySize("x-a", "1")+entrySize("x-b", "2") {
		t.Fatalf("DynamicTableSize after restore = %d", got)
	}
	if idx := mustInsert(t, restored, "x-c", "3"); idx != 2 {
		t.Fatalf("index after restore = %d, want 2", idx)
	}
}

// Blocked streams must survive a restart and unblock once the missing inserts
// are applied.
func TestSnapshotRestoresBlockedStream(t *testing.T) {
	s := qpackSettings(200, 1)
	g := mustQpackGuard(t, s)
	mustInsert(t, g, "x-a", "1")
	if err := g.DecodeSection(9, 4); !errors.Is(err, taskpkg.ErrBlocked) {
		t.Fatalf("blocked decode: want ErrBlocked, got %v", err)
	}
	snap, err := g.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	restored, err := taskpkg.NewQpackGuardFromSnapshot(s, snap)
	if err != nil {
		t.Fatalf("NewQpackGuardFromSnapshot: %v", err)
	}
	st, err := restored.Stream(9)
	if err != nil {
		t.Fatalf("Stream(9) after restore: %v", err)
	}
	if !st.Blocked || st.RequiredInsertCount != 4 {
		t.Fatalf("restored stream = %+v, want blocked on 4", st)
	}
	mustInsert(t, restored, "x-b", "2")
	mustInsert(t, restored, "x-c", "3")
	mustInsert(t, restored, "x-d", "4")
	if err := restored.DecodeSection(9, 4); err != nil {
		t.Fatalf("decode after restore and inserts: %v", err)
	}
	st, err = restored.Stream(9)
	if err != nil {
		t.Fatalf("Stream(9): %v", err)
	}
	if st.Blocked {
		t.Fatalf("stream 9 still blocked")
	}
	if got := restored.Counters().BlockedStreams; got != 0 {
		t.Fatalf("BlockedStreams = %d, want 0", got)
	}
}

// Counters must reflect exactly one of each operation.
func TestCountersExact(t *testing.T) {
	g := mustQpackGuard(t, qpackSettings(200, 1))
	mustInsert(t, g, "x-a", "1")
	if _, err := g.Insert("Bad", "1", false); !errors.Is(err, taskpkg.ErrFieldInvalid) {
		t.Fatalf("invalid name: want ErrFieldInvalid, got %v", err)
	}
	mustEncode(t, g, 1, field(":method", "GET"), field("x-a", "1"))
	if err := g.DecodeSection(1, 1); err != nil {
		t.Fatalf("decode stream 1: %v", err)
	}
	if err := g.DecodeSection(2, 5); !errors.Is(err, taskpkg.ErrBlocked) {
		t.Fatalf("blocked stream 2: want ErrBlocked, got %v", err)
	}
	if err := g.DecodeSection(3, 5); !errors.Is(err, taskpkg.ErrBlockedLimit) {
		t.Fatalf("blocked stream 3: want ErrBlockedLimit, got %v", err)
	}
	if err := g.CancelStream(2); err != nil {
		t.Fatalf("CancelStream(2): %v", err)
	}
	if err := g.AcknowledgeSection(1, 1); err != nil {
		t.Fatalf("AcknowledgeSection: %v", err)
	}
	want := taskpkg.Stats{
		Inserted:        1,
		Evicted:         0,
		FieldsRejected:  1,
		SensitiveFields: 0,
		BlockedRejected: 1,
		SectionsEncoded: 1,
		SectionsDecoded: 1,
		BlockedStreams:  0,
		Cancelled:       1,
		Acks:            1,
	}
	if got := g.Counters(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Counters = %+v, want %+v", got, want)
	}
}
