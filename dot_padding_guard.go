package task

import (
	"errors"
	"time"
)

var errNotImplemented = errors.New("not implemented")

// Sentinel errors returned by DotPaddingGuard.
var (
	// ErrInvalidConfig means the padding policy or the message size is not
	// usable.
	ErrInvalidConfig = errors.New("dot: invalid padding configuration")
	// ErrTooLarge means a message cannot fit into the configured maximum.
	ErrTooLarge = errors.New("dot: padded message exceeds maximum size")
	// ErrPoolFull means every connection is at its in-flight limit and the
	// pool cannot grow.
	ErrPoolFull = errors.New("dot: connection pool is full")
	// ErrUnknownConn means the connection id is not present in the pool.
	ErrUnknownConn = errors.New("dot: unknown connection")
	// ErrQueryBudget means the connection already sent its allowed queries.
	ErrQueryBudget = errors.New("dot: connection query budget exhausted")
)

// Config holds padding and pool policy.
type Config struct {
	// BlockSize is the padding block; padded length is a multiple of it.
	BlockSize int
	// MinSize is the smallest padded length.
	MinSize int
	// MaxSize is the largest padded length; zero means unbounded.
	MaxSize int
	// MaxConns is the maximum number of pooled connections.
	MaxConns int
	// MaxOutstanding is the maximum number of in-flight queries per
	// connection.
	MaxOutstanding int
	// MaxQueriesPerConn is how many queries a connection may carry before it
	// is retired.
	MaxQueriesPerConn int
	// IdleTimeout is how long an idle connection is kept.
	IdleTimeout time.Duration
}

// Connection is the public view of one pooled connection.
type Connection struct {
	ID          string
	CreatedAt   time.Time
	LastUsed    time.Time
	Outstanding int
	Sent        int
}

// Stats is a counter snapshot.
type Stats struct {
	Conns       int
	Outstanding int
	Acquired    uint64
	Released    uint64
}

// DotPaddingGuard pads DNS-over-TLS messages to fixed blocks and hands out
// pooled connections with bounded in-flight queries.
type DotPaddingGuard struct {
	cfg Config
}

// NewDotPaddingGuard returns an empty pool governed by cfg.
func NewDotPaddingGuard(cfg Config) *DotPaddingGuard {
	return &DotPaddingGuard{cfg: cfg}
}

// NewDotPaddingGuardFromSnapshot restores pool state, including connection ids
// and in-flight accounting, from data produced by Snapshot.
func NewDotPaddingGuardFromSnapshot(cfg Config, data []byte) (*DotPaddingGuard, error) {
	return nil, errNotImplemented
}

// PadLength returns the padded wire length for a message of wireSize bytes.
func (g *DotPaddingGuard) PadLength(wireSize int) (int, error) {
	return 0, errNotImplemented
}

// PaddingBytes returns how many padding bytes PadLength adds.
func (g *DotPaddingGuard) PaddingBytes(wireSize int) (int, error) {
	return 0, errNotImplemented
}

// Acquire leases one query slot on the least loaded connection, creating a
// connection when the pool still has room.
func (g *DotPaddingGuard) Acquire(now time.Time) (string, error) {
	return "", errNotImplemented
}

// Release returns a leased query slot.
func (g *DotPaddingGuard) Release(connID string, now time.Time) error {
	return errNotImplemented
}

// MarkSent records that one query was written to the connection.
func (g *DotPaddingGuard) MarkSent(connID string) error {
	return errNotImplemented
}

// Outstanding returns the number of leased slots on a connection.
func (g *DotPaddingGuard) Outstanding(connID string) (int, error) {
	return 0, errNotImplemented
}

// ConnCount returns the number of pooled connections.
func (g *DotPaddingGuard) ConnCount() int {
	return 0
}

// CloseConn closes a known connection unconditionally.
func (g *DotPaddingGuard) CloseConn(connID string) error {
	return errNotImplemented
}

// CloseIdle closes connections that have no leases and have been idle for at
// least IdleTimeout, returning how many were closed.
func (g *DotPaddingGuard) CloseIdle(now time.Time) int {
	return 0
}

// Stats returns the current counters.
func (g *DotPaddingGuard) Stats() Stats {
	return Stats{}
}

// Snapshot serialises the pool state.
func (g *DotPaddingGuard) Snapshot() ([]byte, error) {
	return nil, errNotImplemented
}
