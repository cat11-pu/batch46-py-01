package task

import (
	"errors"
	"time"
)

// Sentinel errors returned while parsing or admitting GTP-U traffic.
var (
	ErrVersion      = errors.New("gtp: unsupported version")
	ErrProtocolType = errors.New("gtp: not a GTP-U packet")
	ErrMalformed    = errors.New("gtp: malformed packet")
	ErrTEIDRange    = errors.New("gtp: teid outside the usable range")
	ErrTEIDInUse    = errors.New("gtp: teid already allocated")
	ErrTEIDUnknown  = errors.New("gtp: teid is not allocated")
	ErrPeerMismatch = errors.New("gtp: packet arrived from the wrong peer")
	ErrReplay       = errors.New("gtp: sequence number not newer than the last accepted one")
	ErrQuota        = errors.New("gtp: tenant teid quota reached")
	ErrQuarantine   = errors.New("gtp: teid still quarantined after release")
)

var errNotImplemented = errors.New("not implemented")

// Config controls TEID capacity and release behaviour.
//
// MaxTEIDsPerTenant bounds live allocations per tenant. Quarantine is how long
// a released TEID stays unusable so late packets cannot hit a new session.
type Config struct {
	MaxTEIDsPerTenant int
	Quarantine        time.Duration
}

// PeerAddr is the transport address of a GTP peer.
type PeerAddr struct {
	Addr string
	Port int
}

// Binding is one TEID allocation.
type Binding struct {
	TEID     uint32
	TenantID string
	Peer     PeerAddr
}

// Packet is a decoded GTP-U packet.
type Packet struct {
	MessageType uint8
	TEID        uint32
	Sequence    uint32
	HasSequence bool
	Payload     []byte
}

// Stats counts allocation and admission outcomes.
type Stats struct {
	Allocated int
	Released  int
	Accepted  int
	Dropped   int
}

// GtpGuard owns the TEID table and enforces that traffic for a TEID only
// arrives from the peer it was allocated to.
type GtpGuard struct {
	cfg Config
}

// NewGtpGuard returns a guard configured by cfg.
func NewGtpGuard(cfg Config) *GtpGuard {
	return &GtpGuard{cfg: cfg}
}

// NewGtpGuardFromSnapshot restores allocations, sequence watermarks and
// release quarantines from data.
func NewGtpGuardFromSnapshot(cfg Config, data []byte) (*GtpGuard, error) {
	return nil, errNotImplemented
}

// Allocate reserves teid for tenantID and peer.
//
// TEID 0 is reserved and never allocatable. Repeating the same allocation is
// idempotent; the same TEID with another tenant or another peer is refused.
// A TEID released less than Quarantine ago cannot be allocated again.
func (g *GtpGuard) Allocate(teid uint32, tenantID string, peer PeerAddr, now time.Time) (Binding, error) {
	return Binding{}, errNotImplemented
}

// Release frees teid and starts its quarantine window.
func (g *GtpGuard) Release(teid uint32, now time.Time) error {
	return errNotImplemented
}

// Binding returns the allocation for teid.
func (g *GtpGuard) Binding(teid uint32) (Binding, error) {
	return Binding{}, errNotImplemented
}

// Parse decodes one GTP-U packet.
//
// The version must be 1 and the protocol type must be GTP (not GTP'). The
// length field must match the bytes after the mandatory eight byte header. The
// sequence number is only meaningful when the S flag is set.
func (g *GtpGuard) Parse(raw []byte) (Packet, error) {
	return Packet{}, errNotImplemented
}

// Admit accepts pkt from peer if its TEID is allocated to that peer and, when
// a sequence number is present, the sequence is strictly newer than every
// sequence already accepted for the TEID.
func (g *GtpGuard) Admit(pkt Packet, peer PeerAddr, now time.Time) error {
	return errNotImplemented
}

// LastSequence returns the highest accepted sequence number for teid.
func (g *GtpGuard) LastSequence(teid uint32) (uint32, error) {
	return 0, errNotImplemented
}

// TenantTEIDCount reports live allocations held by tenantID.
func (g *GtpGuard) TenantTEIDCount(tenantID string) int {
	return 0
}

// Snapshot serialises allocations, sequence watermarks and quarantines.
func (g *GtpGuard) Snapshot() ([]byte, error) {
	return nil, errNotImplemented
}

// Stats returns the counters.
func (g *GtpGuard) Stats() Stats {
	return Stats{}
}
