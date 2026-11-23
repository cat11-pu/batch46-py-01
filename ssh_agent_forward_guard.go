package task

import (
	"errors"
	"sync"
	"time"
)

var errNotImplemented = errors.New("not implemented")

// Sentinel errors returned by AgentForwardGuard. The forwarding proxy maps
// them to audit events, so a revoked key must never be reported as a budget
// problem and an unknown session must never be reported as an expired one.
var (
	ErrSessionInvalid   = errors.New("agentforward: invalid session")
	ErrSessionUnknown   = errors.New("agentforward: unknown session")
	ErrSessionExpired   = errors.New("agentforward: session expired")
	ErrSessionDuplicate = errors.New("agentforward: duplicate session")
	ErrSessionCap       = errors.New("agentforward: session cap reached")
	ErrKeyInvalid       = errors.New("agentforward: invalid key")
	ErrKeyUnknown       = errors.New("agentforward: unknown key")
	ErrKeyRevoked       = errors.New("agentforward: key revoked")
	ErrFlagNotAllowed   = errors.New("agentforward: flags not allowed")
	ErrSignBudget       = errors.New("agentforward: sign budget exhausted")
)

// Config is the forwarding policy applied to every session.
type Config struct {
	// MaxSignsPerSession caps successful signature requests in one session.
	MaxSignsPerSession int
	// MaxSignsPerKey caps successful signature requests for one key across
	// all sessions of its tenant.
	MaxSignsPerKey int
	// MaxSessions caps concurrently live sessions; expired ones do not count.
	MaxSessions int
	// SessionTTL is used when OpenSession is given a zero ExpiresAt.
	SessionTTL time.Duration
}

// Key is an agent key that may be offered to forwarded sessions. Fingerprint
// is the SHA256 form printed by ssh-keygen. Keys are tenant scoped.
type Key struct {
	Fingerprint string
	TenantID    string
	Purpose     string
	Comment     string
}

// Session is one forwarded agent channel. IDs are globally unique. A zero
// ExpiresAt means "now + Config.SessionTTL at open time".
type Session struct {
	ID        string
	TenantID  string
	Host      string
	ExpiresAt time.Time
}

// SignRequest is one SSH_AGENTC_SIGN_REQUEST forwarded to the guard. Flags is
// the raw agent protocol flag mask (0, 2, 4 or 2|4). Flags must be non-zero
// and a subset of the mask the key was registered with.
type SignRequest struct {
	SessionID   string
	Fingerprint string
	Flags       uint32
	Data        []byte
}

// SignResult is what the agent returns to the client.
type SignResult struct {
	Fingerprint string
	// Serial is the 1-based count of successful signs in the session.
	Serial uint64
	// Data is a copy of the signed request payload.
	Data []byte
}

// AgentForwardGuard enforces key, flag and budget policy for forwarded agent
// connections.
type AgentForwardGuard struct {
	mu  sync.Mutex
	cfg Config
}

// NewAgentForwardGuard returns a guard configured by cfg.
func NewAgentForwardGuard(cfg Config) *AgentForwardGuard {
	return &AgentForwardGuard{cfg: cfg}
}

// NewAgentForwardGuardFromSnapshot restores live sessions, key counters and
// revocations from a snapshot produced by Snapshot.
func NewAgentForwardGuardFromSnapshot(cfg Config, data []byte) (*AgentForwardGuard, error) {
	return nil, errNotImplemented
}

// RegisterKey adds a key for a tenant. Re-registering the same tenant and
// fingerprint is idempotent: purpose, comment and the allowed flag mask are
// updated, while the usage counter and a revocation stay untouched.
func (g *AgentForwardGuard) RegisterKey(k Key, allowedFlags uint32) error {
	return errNotImplemented
}

// RevokeKey permanently revokes a key of a tenant. Later signs with it must
// fail with ErrKeyRevoked even if the key is registered again.
func (g *AgentForwardGuard) RevokeKey(tenantID, fingerprint string) error {
	return errNotImplemented
}

// OpenSession opens a forwarded session. It fails with ErrSessionDuplicate for
// a live ID and ErrSessionCap when MaxSessions live sessions exist. Expired
// sessions are dropped before the cap is evaluated and never occupy a slot.
func (g *AgentForwardGuard) OpenSession(s Session, now time.Time) error {
	return errNotImplemented
}

// CloseSession removes a session of the tenant. Unknown, foreign or already
// closed IDs fail with ErrSessionUnknown.
func (g *AgentForwardGuard) CloseSession(tenantID, sessionID string) error {
	return errNotImplemented
}

// ListKeys returns the tenant's non-revoked fingerprints visible to the
// session, sorted ascending. The session must exist and belong to the tenant.
func (g *AgentForwardGuard) ListKeys(tenantID, sessionID string) ([]string, error) {
	return nil, errNotImplemented
}

// Sign performs one signature request after checking session, key, flag and
// budget policy. A sign at or after ExpiresAt fails with ErrSessionExpired and
// does not consume budget.
func (g *AgentForwardGuard) Sign(req SignRequest, now time.Time) (SignResult, error) {
	return SignResult{}, errNotImplemented
}

// SessionSigns reports successful signs in a session.
func (g *AgentForwardGuard) SessionSigns(tenantID, sessionID string) (int, error) {
	return 0, errNotImplemented
}

// KeySigns reports successful signs for a key of a tenant across sessions.
func (g *AgentForwardGuard) KeySigns(tenantID, fingerprint string) (int, error) {
	return 0, errNotImplemented
}

// ActiveSessions counts live sessions at now; expired sessions are pruned.
func (g *AgentForwardGuard) ActiveSessions(now time.Time) int {
	return 0
}

// Snapshot serialises sessions, per-session and per-key counters and key state
// so that a restarted proxy keeps enforcing budgets and revocations.
func (g *AgentForwardGuard) Snapshot() ([]byte, error) {
	return nil, errNotImplemented
}
