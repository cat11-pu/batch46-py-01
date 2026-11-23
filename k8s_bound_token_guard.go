package task

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"
)

// Sentinel errors returned by BoundTokenGuard. A token for another pod, a
// rotated out token and an expired token must stay distinguishable.
var (
	ErrMalformed = errors.New("boundtoken: malformed token")
	ErrSignature = errors.New("boundtoken: token signature invalid")
	ErrAudience  = errors.New("boundtoken: audience mismatch")
	ErrExpired   = errors.New("boundtoken: token expired")
	ErrNotYet    = errors.New("boundtoken: token not yet valid")
	ErrBinding   = errors.New("boundtoken: pod binding mismatch")
	ErrRevoked   = errors.New("boundtoken: token revoked")
	ErrLimit     = errors.New("boundtoken: limit exceeded")
	ErrUnknownSA = errors.New("boundtoken: unknown service account")
)

// Config is the projection policy of one kubelet facing issuer.
type Config struct {
	// Audiences lists the audiences the issuer accepts for new tokens.
	Audiences []string
	// MaxTTL and MinTTL bound the requested token lifetime.
	MaxTTL time.Duration
	MinTTL time.Duration
	// ClockSkew is the tolerated clock difference around iat and exp. A zero
	// value means thirty seconds.
	ClockSkew time.Duration
	// MaxTokensPerPod caps concurrently live tokens of one pod. A zero value
	// means one.
	MaxTokensPerPod int
	// RefreshWindow is the remaining lifetime below which a token should be
	// rotated. A zero value means five minutes.
	RefreshWindow time.Duration
}

// PodBinding is the pod the token is bound to.
type PodBinding struct {
	Namespace string
	PodName   string
	PodUID    string
	NodeName  string
}

// TokenRequest asks the issuer for one bound token.
type TokenRequest struct {
	Namespace      string
	ServiceAccount string
	Binding        PodBinding
	Audience       string
	TTL            time.Duration
}

// Claims is the verified content of a bound token.
type Claims struct {
	Issuer string
	// Subject is "system:serviceaccount:<namespace>:<name>".
	Subject        string
	Audiences      []string
	IssuedAt       time.Time
	ExpiresAt      time.Time
	PodName        string
	PodUID         string
	NodeName       string
	JTI            string
	SignatureValid bool
}

// Token is one issued bound token.
type Token struct {
	Value          string
	JTI            string
	Namespace      string
	ServiceAccount string
	PodName        string
	PodUID         string
	NodeName       string
	Audience       string
	IssuedAt       time.Time
	ExpiresAt      time.Time
}

type guardState struct {
	Accounts map[string]struct{}   `json:"accounts"`
	Pods     map[string]PodBinding `json:"pods"`
	Tokens   map[string]Token      `json:"tokens"`
	Revoked  map[string]bool       `json:"revoked"`
}

// BoundTokenGuard issues and validates pod bound projected tokens.
type BoundTokenGuard struct {
	mu       sync.Mutex
	cfg      Config
	accounts map[string]struct{}
	pods     map[string]PodBinding
	tokens   map[string]Token
	revoked  map[string]bool
}

func normaliseConfig(cfg Config) Config {
	if cfg.ClockSkew == 0 {
		cfg.ClockSkew = 30 * time.Second
	}
	if cfg.MaxTokensPerPod == 0 {
		cfg.MaxTokensPerPod = 1
	}
	if cfg.RefreshWindow == 0 {
		cfg.RefreshWindow = 5 * time.Minute
	}
	return cfg
}

// NewBoundTokenGuard returns a guard configured by cfg.
func NewBoundTokenGuard(cfg Config) *BoundTokenGuard {
	return &BoundTokenGuard{
		cfg:      normaliseConfig(cfg),
		accounts: make(map[string]struct{}),
		pods:     make(map[string]PodBinding),
		tokens:   make(map[string]Token),
		revoked:  make(map[string]bool),
	}
}

// NewBoundTokenGuardFromSnapshot restores pod bindings, live tokens and
// revocations from a snapshot.
func NewBoundTokenGuardFromSnapshot(cfg Config, data []byte) (*BoundTokenGuard, error) {
	g := NewBoundTokenGuard(cfg)
	var state guardState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	if state.Accounts != nil {
		g.accounts = state.Accounts
	}
	if state.Pods != nil {
		g.pods = state.Pods
	}
	if state.Tokens != nil {
		g.tokens = state.Tokens
	}
	if state.Revoked != nil {
		g.revoked = state.Revoked
	}
	return g, nil
}

// RegisterServiceAccount makes namespace/name an issuable service account.
func (g *BoundTokenGuard) RegisterServiceAccount(namespace, name string) error {
	if namespace == "" || name == "" {
		return ErrMalformed
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.accounts[namespace+"\x00"+name] = struct{}{}
	return nil
}

// RegisterPod records the binding a token may be issued against.
func (g *BoundTokenGuard) RegisterPod(b PodBinding) error {
	if b.Namespace == "" || b.PodName == "" || b.PodUID == "" || b.NodeName == "" {
		return ErrMalformed
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	existing, ok := g.pods[b.PodUID]
	if ok {
		if existing == b {
			return nil
		}
		return ErrMalformed
	}
	g.pods[b.PodUID] = b
	return nil
}

func (g *BoundTokenGuard) audienceAllowed(audience string) bool {
	for _, allowed := range g.cfg.Audiences {
		if allowed == audience {
			return true
		}
	}
	return false
}

func (g *BoundTokenGuard) liveTokenCountLocked(podUID string, now time.Time) int {
	count := 0
	for jti, token := range g.tokens {
		if token.PodUID != podUID {
			continue
		}
		if !token.ExpiresAt.After(now) {
			delete(g.tokens, jti)
			continue
		}
		count++
	}
	return count
}

func (g *BoundTokenGuard) newTokenLocked(token Token) (Token, error) {
	for {
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			return Token{}, err
		}
		value := hex.EncodeToString(raw)
		if _, exists := g.tokens[value]; exists {
			continue
		}
		token.JTI = value
		token.Value = value
		g.tokens[value] = token
		return token, nil
	}
}

// RequestToken issues one bound token for a registered pod.
func (g *BoundTokenGuard) RequestToken(req TokenRequest, now time.Time) (Token, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if req.Namespace == "" || req.ServiceAccount == "" || req.Audience == "" ||
		req.Binding.Namespace == "" || req.Binding.PodName == "" ||
		req.Binding.PodUID == "" || req.Binding.NodeName == "" {
		return Token{}, ErrMalformed
	}
	if _, ok := g.accounts[req.Namespace+"\x00"+req.ServiceAccount]; !ok {
		return Token{}, ErrUnknownSA
	}
	binding, ok := g.pods[req.Binding.PodUID]
	if !ok || binding != req.Binding {
		return Token{}, ErrBinding
	}
	if g.revoked[req.Binding.PodUID] {
		return Token{}, ErrRevoked
	}
	if !g.audienceAllowed(req.Audience) {
		return Token{}, ErrAudience
	}
	if req.TTL <= 0 || req.TTL < g.cfg.MinTTL || req.TTL > g.cfg.MaxTTL {
		return Token{}, ErrLimit
	}
	if g.liveTokenCountLocked(req.Binding.PodUID, now) >= g.cfg.MaxTokensPerPod {
		return Token{}, ErrLimit
	}

	return g.newTokenLocked(Token{
		Namespace:      req.Namespace,
		ServiceAccount: req.ServiceAccount,
		PodName:        req.Binding.PodName,
		PodUID:         req.Binding.PodUID,
		NodeName:       req.Binding.NodeName,
		Audience:       req.Audience,
		IssuedAt:       now,
		ExpiresAt:      now.Add(req.TTL),
	})
}

// Validate checks a bound token against the registered pod, its node, the
// required audience and the time window.
func (g *BoundTokenGuard) Validate(c Claims, requiredAudience, nodeName string, now time.Time) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if !c.SignatureValid {
		return ErrSignature
	}
	parts := strings.Split(c.Subject, ":")
	if len(parts) != 4 || parts[0] != "system" || parts[1] != "serviceaccount" ||
		parts[2] == "" || parts[3] == "" {
		return ErrMalformed
	}
	if _, ok := g.accounts[parts[2]+"\x00"+parts[3]]; !ok {
		return ErrUnknownSA
	}
	if now.After(c.ExpiresAt.Add(g.cfg.ClockSkew)) {
		return ErrExpired
	}
	if now.Add(g.cfg.ClockSkew).Before(c.IssuedAt) {
		return ErrNotYet
	}
	if requiredAudience != "" {
		found := false
		for _, audience := range c.Audiences {
			if audience == requiredAudience {
				found = true
				break
			}
		}
		if !found {
			return ErrAudience
		}
	}
	binding, ok := g.pods[c.PodUID]
	if !ok || binding.Namespace != parts[2] || binding.PodName != c.PodName ||
		binding.PodUID != c.PodUID || binding.NodeName != c.NodeName {
		return ErrBinding
	}
	if nodeName != "" && nodeName != c.NodeName {
		return ErrBinding
	}
	if _, ok := g.tokens[c.JTI]; !ok {
		return ErrRevoked
	}
	return nil
}

func (g *BoundTokenGuard) latestTokenLocked(podUID string) (Token, bool) {
	var latest Token
	found := false
	for _, token := range g.tokens {
		if token.PodUID != podUID {
			continue
		}
		if !found || token.IssuedAt.After(latest.IssuedAt) ||
			(token.IssuedAt.Equal(latest.IssuedAt) && token.JTI > latest.JTI) {
			latest = token
			found = true
		}
	}
	return latest, found
}

// NeedsRefresh reports whether the newest token of a pod falls inside the
// refresh window.
func (g *BoundTokenGuard) NeedsRefresh(podUID string, now time.Time) (bool, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.revoked[podUID] {
		return false, ErrRevoked
	}
	token, ok := g.latestTokenLocked(podUID)
	if !ok {
		if _, registered := g.pods[podUID]; !registered {
			return false, ErrMalformed
		}
		return false, ErrRevoked
	}
	return !now.Add(g.cfg.RefreshWindow).Before(token.ExpiresAt), nil
}

// TokenFor returns the newest live token of a pod.
func (g *BoundTokenGuard) TokenFor(podUID string) (Token, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.revoked[podUID] {
		return Token{}, ErrRevoked
	}
	token, ok := g.latestTokenLocked(podUID)
	if !ok {
		return Token{}, ErrRevoked
	}
	return token, nil
}

// Rotate replaces every live token of a pod with one fresh token.
func (g *BoundTokenGuard) Rotate(podUID string, now time.Time) (Token, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.revoked[podUID] {
		return Token{}, ErrRevoked
	}
	latest, ok := g.latestTokenLocked(podUID)
	if !ok {
		return Token{}, ErrRevoked
	}
	ttl := latest.ExpiresAt.Sub(latest.IssuedAt)
	for jti, token := range g.tokens {
		if token.PodUID == podUID {
			delete(g.tokens, jti)
		}
	}
	return g.newTokenLocked(Token{
		Namespace:      latest.Namespace,
		ServiceAccount: latest.ServiceAccount,
		PodName:        latest.PodName,
		PodUID:         latest.PodUID,
		NodeName:       latest.NodeName,
		Audience:       latest.Audience,
		IssuedAt:       now,
		ExpiresAt:      now.Add(ttl),
	})
}

// RevokePod revokes a pod, drops its tokens and returns how many were dropped.
func (g *BoundTokenGuard) RevokePod(podUID string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	dropped := 0
	for jti, token := range g.tokens {
		if token.PodUID == podUID {
			delete(g.tokens, jti)
			dropped++
		}
	}
	g.revoked[podUID] = true
	return dropped
}

// ActiveTokens reports how many tokens are currently stored.
func (g *BoundTokenGuard) ActiveTokens() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.tokens)
}

// Prune drops expired tokens and returns how many were removed.
func (g *BoundTokenGuard) Prune(now time.Time) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	removed := 0
	for jti, token := range g.tokens {
		if !token.ExpiresAt.After(now) {
			delete(g.tokens, jti)
			removed++
		}
	}
	return removed
}

// Snapshot serialises pod bindings, live tokens and revocations so that a
// restarted issuer keeps the same view.
func (g *BoundTokenGuard) Snapshot() ([]byte, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	state := guardState{
		Accounts: g.accounts,
		Pods:     g.pods,
		Tokens:   g.tokens,
		Revoked:  g.revoked,
	}
	return json.Marshal(state)
}
