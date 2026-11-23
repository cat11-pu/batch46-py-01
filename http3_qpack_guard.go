package task

import (
	"errors"
	"sync"
)

// Sentinel errors reported by QpackGuard.
var (
	ErrFieldInvalid     = errors.New("qpack: invalid header field")
	ErrSensitiveField   = errors.New("qpack: sensitive field must not be inserted")
	ErrEntryTooLarge    = errors.New("qpack: entry larger than table capacity")
	ErrEvicted          = errors.New("qpack: entry evicted")
	ErrNoEntry          = errors.New("qpack: no such entry")
	ErrCapacityExceeded = errors.New("qpack: capacity above negotiated maximum")
	ErrBlocked          = errors.New("qpack: stream blocked on insert count")
	ErrBlockedLimit     = errors.New("qpack: blocked stream limit reached")
	ErrAckRegression    = errors.New("qpack: insert count acknowledgement regressed")
	ErrAckFuture        = errors.New("qpack: acknowledgement beyond insert count")
	ErrStreamNotFound   = errors.New("qpack: unknown stream")
	ErrSnapshot         = errors.New("qpack: invalid snapshot")
)

// EntryOverhead is the per-entry byte overhead defined by QPACK.
const EntryOverhead = 32

var errNotImplemented = errors.New("stub: not implemented")

// HeaderField is one decoded header field.
type HeaderField struct {
	Name  string
	Value string
}

// Entry is one dynamic table entry.
type Entry struct {
	Index uint64
	Name  string
	Value string
	Size  uint64
}

// Settings are the negotiated QPACK limits.
type Settings struct {
	MaxTableCapacity  uint64
	MaxBlockedStreams int
}

// StreamState is the per-request-stream QPACK bookkeeping.
type StreamState struct {
	StreamID            uint64
	RequiredInsertCount uint64
	Acknowledged        uint64
	Blocked             bool
	Sections            int
}

// Stats are cumulative guard counters plus the current blocked gauge.
type Stats struct {
	Inserted        int64
	Evicted         int64
	FieldsRejected  int64
	SensitiveFields int64
	BlockedRejected int64
	SectionsEncoded int64
	SectionsDecoded int64
	BlockedStreams  int64
	Cancelled       int64
	Acks            int64
}

// QpackGuard validates QPACK dynamic table operations and request stream
// blocking for one HTTP/3 connection.
type QpackGuard struct {
	settings      Settings
	capacity      uint64
	nextInsert    uint64
	entries       []Entry
	streams       map[uint64]*StreamState
	knownReceived uint64
	stats         Stats
	mu            sync.Mutex
}

// NewQpackGuard returns a guard configured by settings.
func NewQpackGuard(settings Settings) *QpackGuard {
	return &QpackGuard{settings: settings}
}

// NewQpackGuardFromSnapshot restores the dynamic table, stream states and
// counters from a snapshot produced by Snapshot.
func NewQpackGuardFromSnapshot(settings Settings, data []byte) (*QpackGuard, error) {
	return nil, errNotImplemented
}

// Insert adds a field to the dynamic table, evicting old entries when needed.
func (g *QpackGuard) Insert(name, value string, sensitive bool) (uint64, error) {
	return 0, errNotImplemented
}

// Lookup returns the entry at an absolute index.
func (g *QpackGuard) Lookup(absIndex uint64) (Entry, error) {
	return Entry{}, errNotImplemented
}

// DynamicTableSize returns the current dynamic table size in bytes.
func (g *QpackGuard) DynamicTableSize() uint64 {
	return 0
}

// InsertCount returns the number of successful insertions.
func (g *QpackGuard) InsertCount() uint64 {
	return 0
}

// MaxTableCapacity returns the negotiated maximum table capacity.
func (g *QpackGuard) MaxTableCapacity() uint64 {
	return 0
}

// EncodeSection validates a field section, inserts reusable regular fields and
// returns the required insert count for the stream.
func (g *QpackGuard) EncodeSection(streamID uint64, fields []HeaderField) (uint64, error) {
	return 0, errNotImplemented
}

// DecodeSection checks that a peer-provided required insert count is satisfied
// and enforces the blocked stream limit.
func (g *QpackGuard) DecodeSection(streamID uint64, requiredInsertCount uint64) error {
	return errNotImplemented
}

// AcknowledgeSection records how many inserts the peer has processed.
func (g *QpackGuard) AcknowledgeSection(streamID, insertCount uint64) error {
	return errNotImplemented
}

// CancelStream releases a blocked stream and forgets its state.
func (g *QpackGuard) CancelStream(streamID uint64) error {
	return errNotImplemented
}

// SetCapacity changes the dynamic table capacity within the negotiated limit.
func (g *QpackGuard) SetCapacity(capacity uint64) error {
	return errNotImplemented
}

// Stream returns a copy of one request stream state.
func (g *QpackGuard) Stream(streamID uint64) (StreamState, error) {
	return StreamState{}, errNotImplemented
}

// Snapshot serialises the dynamic table, stream states, capacity and counters.
func (g *QpackGuard) Snapshot() ([]byte, error) {
	return nil, errNotImplemented
}

// Counters returns a copy of the counters and the blocked stream gauge.
func (g *QpackGuard) Counters() Stats {
	return Stats{}
}
