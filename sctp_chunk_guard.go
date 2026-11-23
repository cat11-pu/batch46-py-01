package task

import (
	"errors"
	"time"
)

// Sentinel errors returned by the SCTP guard.
var (
	ErrMalformed      = errors.New("sctp: malformed packet or chunk")
	ErrPadding        = errors.New("sctp: chunk padding is not zero")
	ErrTooManyChunks  = errors.New("sctp: chunk count limit exceeded")
	ErrPacketTooLarge = errors.New("sctp: packet exceeds size limit")
	ErrBundling       = errors.New("sctp: INIT or INIT_ACK must travel alone")
	ErrVTagConflict   = errors.New("sctp: verification tag already in use")
	ErrAssocUnknown   = errors.New("sctp: association is not registered")
	ErrVTagMismatch   = errors.New("sctp: packet verification tag does not match the association")
	ErrTSNRegression  = errors.New("sctp: transmission sequence number did not advance")
	ErrMACInvalid     = errors.New("sctp: chunk authentication code is invalid")
	ErrReplay         = errors.New("sctp: authentication code already used")
)

var errNotImplemented = errors.New("not implemented")

// Config controls framing limits and chunk authentication.
//
// MaxChunksPerPacket and MaxPacketBytes bound the work one datagram may cause.
// AuthKey is the shared key used for the AUTH chunk HMAC-SHA256. AuthTTL is how
// long an accepted code is remembered for replay detection.
type Config struct {
	MaxChunksPerPacket int
	MaxPacketBytes     int
	AuthKey            []byte
	AuthTTL            time.Duration
}

// Peer is the transport address of an SCTP peer.
type Peer struct {
	Addr string
	Port int
}

// Chunk is one decoded SCTP chunk.
type Chunk struct {
	Type  uint8
	Flags uint8
	Value []byte
}

// Packet is one decoded SCTP datagram.
type Packet struct {
	SrcPort int
	DstPort int
	VTag    uint32
	Chunks  []Chunk
}

// Association is the state kept for one peer association.
type Association struct {
	ID       string
	VTag     uint32
	Peer     Peer
	TenantID string
}

// Stats counts admit and authentication outcomes.
type Stats struct {
	Accepted      int
	Dropped       int
	Authenticated int
	Replayed      int
}

// SctpGuard validates SCTP framing, associates verification tags with peers,
// tracks DATA chunk ordering and checks AUTH chunk codes.
type SctpGuard struct {
	cfg Config
}

// NewSctpGuard returns a guard configured by cfg.
func NewSctpGuard(cfg Config) *SctpGuard {
	return &SctpGuard{cfg: cfg}
}

// NewSctpGuardFromSnapshot restores associations, sequence watermarks and used
// authentication codes from data.
func NewSctpGuardFromSnapshot(cfg Config, data []byte) (*SctpGuard, error) {
	return nil, errNotImplemented
}

// RegisterAssociation records id with vtag, peer and tenantID. A verification
// tag may belong to exactly one association; repeating the same idempotent
// registration is allowed.
func (g *SctpGuard) RegisterAssociation(id string, vtag uint32, peer Peer, tenantID string) error {
	return errNotImplemented
}

// RemoveAssociation forgets id and its per association state.
func (g *SctpGuard) RemoveAssociation(id string) error {
	return errNotImplemented
}

// Association returns the registered association for id.
func (g *SctpGuard) Association(id string) (Association, error) {
	return Association{}, errNotImplemented
}

// Parse decodes one SCTP datagram.
//
// Every chunk length includes its four byte header and must not overrun the
// datagram. Padding bytes after the chunk value must be zero. A packet may not
// carry more than MaxChunksPerPacket chunks or exceed MaxPacketBytes bytes.
// INIT and INIT_ACK chunks must not be bundled with anything else.
func (g *SctpGuard) Parse(raw []byte) (Packet, error) {
	return Packet{}, errNotImplemented
}

// Admit checks a datagram against the association it claims to belong to.
//
// The association must be registered and the packet verification tag must match
// it exactly. When a DATA chunk is present its transmission sequence number
// (the first four value bytes) must be strictly greater than the last admitted
// one.
func (g *SctpGuard) Admit(assocID string, raw []byte, now time.Time) (Packet, error) {
	return Packet{}, errNotImplemented
}

// Authenticate verifies that mac is HMAC-SHA256(AuthKey, chunkValue) for the
// association and that the same code has not been used inside AuthTTL.
func (g *SctpGuard) Authenticate(assocID string, chunkValue, mac []byte, now time.Time) error {
	return errNotImplemented
}

// LastTSN returns the highest admitted transmission sequence number for id.
func (g *SctpGuard) LastTSN(assocID string) (uint32, error) {
	return 0, errNotImplemented
}

// Snapshot serialises associations, sequence watermarks and used codes.
func (g *SctpGuard) Snapshot() ([]byte, error) {
	return nil, errNotImplemented
}

// Stats returns the counters.
func (g *SctpGuard) Stats() Stats {
	return Stats{}
}
