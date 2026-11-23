package task

import (
	"errors"
	"sync"
	"time"
)

var errNotImplemented = errors.New("not implemented")

// Sentinel errors returned by the session guard. The crypto gateway keeps its
// own metrics per error, so "handle from another session" must stay distinct
// from "handle expired" and from "operation not allowed for this key".
var (
	ErrSessionInvalid   = errors.New("hsm: invalid session")
	ErrSessionUnknown   = errors.New("hsm: unknown session")
	ErrSessionClosed    = errors.New("hsm: session closed")
	ErrDuplicateSession = errors.New("hsm: duplicate session")
	ErrNotLoggedIn      = errors.New("hsm: session not logged in")
	ErrPINInvalid       = errors.New("hsm: invalid pin")
	ErrPINLocked        = errors.New("hsm: pin locked")
	ErrKeyInvalid       = errors.New("hsm: invalid key definition")
	ErrKeyUnknown       = errors.New("hsm: unknown key label")
	ErrKeyDuplicate     = errors.New("hsm: duplicate key label")
	ErrHandleInvalid    = errors.New("hsm: invalid handle")
	ErrHandleStale      = errors.New("hsm: stale handle")
	ErrCrossSession     = errors.New("hsm: handle belongs to another session")
	ErrOpNotAllowed     = errors.New("hsm: operation not allowed for key")
	ErrHandleLimit      = errors.New("hsm: handle budget exhausted")
)

// Config holds the session policy.
type Config struct {
	// MaxLoginAttempts locks a session after this many consecutive bad PINs.
	MaxLoginAttempts int
	// HandleTTL is how long an opened key handle stays usable.
	HandleTTL time.Duration
	// MaxHandlesPerSession caps concurrently open handles in one session.
	MaxHandlesPerSession int
	// OpsPerRotation is how many successful operations a handle serves before
	// it is rotated to a fresh handle of the same key.
	OpsPerRotation int
}

// KeyInfo describes a provisioned key. Ops lists the operation names the key
// may perform ("sign", "verify", "encrypt", "decrypt", "wrap").
type KeyInfo struct {
	TenantID string
	Label    string
	Type     string
	Ops      []string
}

// Handle is a session-local key handle. IDs are never reused, including across
// restarts.
type Handle struct {
	ID       string
	KeyLabel string
	TenantID string
	Epoch    uint64
	IssuedAt time.Time
	Ops      int
}

// OpResult reports the outcome of one Perform call. Handle is the handle the
// caller must use for the next operation (it changes after a rotation) and Ops
// is the number of successful operations in the session so far.
type OpResult struct {
	Handle  string
	Ops     int
	Rotated bool
}

// HsmSessionGuard owns HSM sessions, PIN state, key handles and rotation.
type HsmSessionGuard struct {
	mu  sync.Mutex
	cfg Config
}

// NewHsmSessionGuard returns a guard configured by cfg.
func NewHsmSessionGuard(cfg Config) *HsmSessionGuard {
	return &HsmSessionGuard{cfg: cfg}
}

// NewHsmSessionGuardFromSnapshot restores keys, sessions and counters from a
// snapshot. Login state and open handles are intentionally not restorable.
func NewHsmSessionGuardFromSnapshot(cfg Config, data []byte) (*HsmSessionGuard, error) {
	return nil, errNotImplemented
}

// SetPIN installs or rotates the PIN of a tenant. An empty tenant or PIN fails
// with ErrPINInvalid.
func (g *HsmSessionGuard) SetPIN(tenantID, pin string) error {
	return errNotImplemented
}

// ProvisionKey registers a key for a tenant. Empty fields or an empty
// operation list fail with ErrKeyInvalid; a duplicate label fails with
// ErrKeyDuplicate.
func (g *HsmSessionGuard) ProvisionKey(k KeyInfo) error {
	return errNotImplemented
}

// OpenSession opens a session for a tenant. IDs are unique per tenant; a live
// duplicate fails with ErrDuplicateSession.
func (g *HsmSessionGuard) OpenSession(tenantID, sessionID string, now time.Time) error {
	return errNotImplemented
}

// Login authenticates a session. A session locked after MaxLoginAttempts
// consecutive bad PINs fails with ErrPINLocked even for the correct PIN; a
// successful login resets the attempt counter.
func (g *HsmSessionGuard) Login(tenantID, sessionID, pin string, now time.Time) error {
	return errNotImplemented
}

// OpenKey issues a handle for a provisioned key of the session's tenant. It
// requires a logged-in session (ErrNotLoggedIn), fails with ErrHandleLimit at
// MaxHandlesPerSession live handles, and drops expired handles first.
func (g *HsmSessionGuard) OpenKey(tenantID, sessionID, label string, now time.Time) (Handle, error) {
	return Handle{}, errNotImplemented
}

// Perform executes one operation on a handle. Unknown handles fail with
// ErrHandleInvalid, handles of other sessions with ErrCrossSession, handles
// past HandleTTL as well as handles already rotated with ErrHandleStale, and
// operations the key does not allow with ErrOpNotAllowed. Rotating a handle
// invalidates the old one immediately; the returned OpResult.Handle is the one
// to use next.
func (g *HsmSessionGuard) Perform(tenantID, sessionID, handleID, op string, now time.Time) (OpResult, error) {
	return OpResult{}, errNotImplemented
}

// CloseHandle removes a handle of the session.
func (g *HsmSessionGuard) CloseHandle(tenantID, sessionID, handleID string) error {
	return errNotImplemented
}

// CloseSession closes a session, drops its handles and forgets its login
// state. A second close fails with ErrSessionClosed.
func (g *HsmSessionGuard) CloseSession(tenantID, sessionID string) error {
	return errNotImplemented
}

// SessionOps reports the number of successful operations in a session.
func (g *HsmSessionGuard) SessionOps(tenantID, sessionID string) (int, error) {
	return 0, errNotImplemented
}

// Snapshot serialises keys, PINs, sessions, operation counters, lockout state
// and the handle epoch counter. Open handles are not serialised, and stale
// handle tombstones are only kept in memory.
func (g *HsmSessionGuard) Snapshot() ([]byte, error) {
	return nil, errNotImplemented
}
