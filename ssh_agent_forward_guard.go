package task

import (
	"encoding/json"
	"errors"
	"sort"
	"sync"
	"time"
)

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
	ErrSnapshotInvalid  = errors.New("agentforward: invalid snapshot")
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

type keyRef struct {
	tenantID    string
	fingerprint string
}

type keyState struct {
	Fingerprint  string `json:"fingerprint"`
	TenantID     string `json:"tenant_id"`
	Purpose      string `json:"purpose"`
	Comment      string `json:"comment"`
	AllowedFlags uint32 `json:"allowed_flags"`
	Revoked      bool   `json:"revoked"`
	Usage        int    `json:"usage"`
}

type sessionState struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Host      string    `json:"host"`
	ExpiresAt time.Time `json:"expires_at"`
	Signs     int       `json:"signs"`
}

const snapshotVersion = 1

type snapshotData struct {
	Version  int            `json:"version"`
	Keys     []keyState     `json:"keys"`
	Sessions []sessionState `json:"sessions"`
}

// AgentForwardGuard enforces key, flag and budget policy for forwarded agent
// connections.
type AgentForwardGuard struct {
	mu       sync.Mutex
	cfg      Config
	keys     map[keyRef]*keyState
	sessions map[string]*sessionState
}

// NewAgentForwardGuard returns a guard configured by cfg.
func NewAgentForwardGuard(cfg Config) *AgentForwardGuard {
	return &AgentForwardGuard{
		cfg:      cfg,
		keys:     make(map[keyRef]*keyState),
		sessions: make(map[string]*sessionState),
	}
}

// NewAgentForwardGuardFromSnapshot restores live sessions, key counters and
// revocations from a snapshot produced by Snapshot.
func NewAgentForwardGuardFromSnapshot(cfg Config, data []byte) (*AgentForwardGuard, error) {
	g := NewAgentForwardGuard(cfg)
	if len(data) == 0 {
		return nil, ErrSnapshotInvalid
	}

	var snap snapshotData
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, ErrSnapshotInvalid
	}
	if snap.Version != snapshotVersion {
		return nil, ErrSnapshotInvalid
	}

	for _, ks := range snap.Keys {
		if ks.TenantID == "" || ks.Fingerprint == "" || ks.Usage < 0 {
			return nil, ErrSnapshotInvalid
		}
		ref := keyRef{tenantID: ks.TenantID, fingerprint: ks.Fingerprint}
		if _, exists := g.keys[ref]; exists {
			return nil, ErrSnapshotInvalid
		}
		state := ks
		g.keys[ref] = &state
	}
	for _, ss := range snap.Sessions {
		if ss.ID == "" || ss.TenantID == "" || ss.Signs < 0 {
			return nil, ErrSnapshotInvalid
		}
		if _, exists := g.sessions[ss.ID]; exists {
			return nil, ErrSnapshotInvalid
		}
		state := ss
		g.sessions[ss.ID] = &state
	}

	return g, nil
}

// RegisterKey adds a key for a tenant. Re-registering the same tenant and
// fingerprint is idempotent: purpose, comment and the allowed flag mask are
// updated, while the usage counter and a revocation stay untouched.
func (g *AgentForwardGuard) RegisterKey(k Key, allowedFlags uint32) error {
	if k.TenantID == "" || k.Fingerprint == "" {
		return ErrKeyInvalid
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	g.initLocked()

	ref := keyRef{tenantID: k.TenantID, fingerprint: k.Fingerprint}
	if state, ok := g.keys[ref]; ok {
		state.Purpose = k.Purpose
		state.Comment = k.Comment
		state.AllowedFlags = allowedFlags
		return nil
	}

	g.keys[ref] = &keyState{
		Fingerprint:  k.Fingerprint,
		TenantID:     k.TenantID,
		Purpose:      k.Purpose,
		Comment:      k.Comment,
		AllowedFlags: allowedFlags,
	}
	return nil
}

// RevokeKey permanently revokes a key of a tenant. Later signs with it must
// fail with ErrKeyRevoked even if the key is registered again.
func (g *AgentForwardGuard) RevokeKey(tenantID, fingerprint string) error {
	if tenantID == "" || fingerprint == "" {
		return ErrKeyInvalid
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	g.initLocked()

	state, ok := g.keys[keyRef{tenantID: tenantID, fingerprint: fingerprint}]
	if !ok {
		return ErrKeyUnknown
	}
	state.Revoked = true
	return nil
}

// OpenSession opens a forwarded session. It fails with ErrSessionDuplicate for
// a live ID and ErrSessionCap when MaxSessions live sessions exist. Expired
// sessions are dropped before the cap is evaluated and never occupy a slot.
func (g *AgentForwardGuard) OpenSession(s Session, now time.Time) error {
	if s.ID == "" || s.TenantID == "" {
		return ErrSessionInvalid
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	g.initLocked()
	g.pruneExpiredLocked(now)

	if _, ok := g.sessions[s.ID]; ok {
		return ErrSessionDuplicate
	}
	if g.cfg.MaxSessions > 0 && len(g.sessions) >= g.cfg.MaxSessions {
		return ErrSessionCap
	}

	expiresAt := s.ExpiresAt
	if expiresAt.IsZero() {
		expiresAt = now.Add(g.cfg.SessionTTL)
	}
	g.sessions[s.ID] = &sessionState{
		ID:        s.ID,
		TenantID:  s.TenantID,
		Host:      s.Host,
		ExpiresAt: expiresAt,
	}
	return nil
}

// CloseSession removes a session of the tenant. Unknown, foreign or already
// closed IDs fail with ErrSessionUnknown.
func (g *AgentForwardGuard) CloseSession(tenantID, sessionID string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.initLocked()

	state, ok := g.sessions[sessionID]
	if !ok || state.TenantID != tenantID {
		return ErrSessionUnknown
	}
	delete(g.sessions, sessionID)
	return nil
}

// ListKeys returns the tenant's non-revoked fingerprints visible to the
// session, sorted ascending. The session must exist and belong to the tenant.
func (g *AgentForwardGuard) ListKeys(tenantID, sessionID string) ([]string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.initLocked()

	session, ok := g.sessions[sessionID]
	if !ok || session.TenantID != tenantID {
		return nil, ErrSessionUnknown
	}

	keys := make([]string, 0)
	for ref, state := range g.keys {
		if ref.tenantID == tenantID && !state.Revoked {
			keys = append(keys, state.Fingerprint)
		}
	}
	sort.Strings(keys)
	return keys, nil
}

// Sign performs one signature request after checking session, key, flag and
// budget policy. A sign at or after ExpiresAt fails with ErrSessionExpired and
// does not consume budget.
func (g *AgentForwardGuard) Sign(req SignRequest, now time.Time) (SignResult, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.initLocked()

	session, ok := g.sessions[req.SessionID]
	if !ok {
		return SignResult{}, ErrSessionUnknown
	}
	if !now.Before(session.ExpiresAt) {
		return SignResult{}, ErrSessionExpired
	}

	key, ok := g.keys[keyRef{tenantID: session.TenantID, fingerprint: req.Fingerprint}]
	if !ok {
		return SignResult{}, ErrKeyUnknown
	}
	if key.Revoked {
		return SignResult{}, ErrKeyRevoked
	}
	if req.Flags == 0 || req.Flags&^key.AllowedFlags != 0 {
		return SignResult{}, ErrFlagNotAllowed
	}
	if g.cfg.MaxSignsPerSession > 0 && session.Signs >= g.cfg.MaxSignsPerSession {
		return SignResult{}, ErrSignBudget
	}
	if g.cfg.MaxSignsPerKey > 0 && key.Usage >= g.cfg.MaxSignsPerKey {
		return SignResult{}, ErrSignBudget
	}

	session.Signs++
	key.Usage++
	data := make([]byte, len(req.Data))
	copy(data, req.Data)

	return SignResult{
		Fingerprint: key.Fingerprint,
		Serial:      uint64(session.Signs),
		Data:        data,
	}, nil
}

// SessionSigns reports successful signs in a session.
func (g *AgentForwardGuard) SessionSigns(tenantID, sessionID string) (int, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.initLocked()

	session, ok := g.sessions[sessionID]
	if !ok || session.TenantID != tenantID {
		return 0, ErrSessionUnknown
	}
	return session.Signs, nil
}

// KeySigns reports successful signs for a key of a tenant across sessions.
func (g *AgentForwardGuard) KeySigns(tenantID, fingerprint string) (int, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.initLocked()

	key, ok := g.keys[keyRef{tenantID: tenantID, fingerprint: fingerprint}]
	if !ok {
		return 0, ErrKeyUnknown
	}
	return key.Usage, nil
}

// ActiveSessions counts live sessions at now; expired sessions are pruned.
func (g *AgentForwardGuard) ActiveSessions(now time.Time) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.initLocked()

	g.pruneExpiredLocked(now)
	return len(g.sessions)
}

// Snapshot serialises sessions, per-session and per-key counters and key state
// so that a restarted proxy keeps enforcing budgets and revocations.
func (g *AgentForwardGuard) Snapshot() ([]byte, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.initLocked()

	snap := snapshotData{
		Version:  snapshotVersion,
		Keys:     make([]keyState, 0, len(g.keys)),
		Sessions: make([]sessionState, 0, len(g.sessions)),
	}
	for _, state := range g.keys {
		snap.Keys = append(snap.Keys, *state)
	}
	sort.Slice(snap.Keys, func(i, j int) bool {
		if snap.Keys[i].TenantID == snap.Keys[j].TenantID {
			return snap.Keys[i].Fingerprint < snap.Keys[j].Fingerprint
		}
		return snap.Keys[i].TenantID < snap.Keys[j].TenantID
	})
	for _, state := range g.sessions {
		snap.Sessions = append(snap.Sessions, *state)
	}
	sort.Slice(snap.Sessions, func(i, j int) bool {
		return snap.Sessions[i].ID < snap.Sessions[j].ID
	})

	data, err := json.Marshal(snap)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (g *AgentForwardGuard) initLocked() {
	if g.keys == nil {
		g.keys = make(map[keyRef]*keyState)
	}
	if g.sessions == nil {
		g.sessions = make(map[string]*sessionState)
	}
}

func (g *AgentForwardGuard) pruneExpiredLocked(now time.Time) {
	for id, session := range g.sessions {
		if !now.Before(session.ExpiresAt) {
			delete(g.sessions, id)
		}
	}
}
