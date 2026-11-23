package task

import (
	"errors"
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

var errNotImplemented = errors.New("not implemented")

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

// BoundTokenGuard issues and validates pod bound projected tokens.
type BoundTokenGuard struct {
	cfg Config
}

// NewBoundTokenGuard returns a guard configured by cfg.
func NewBoundTokenGuard(cfg Config) *BoundTokenGuard {
	return &BoundTokenGuard{cfg: cfg}
}

// NewBoundTokenGuardFromSnapshot restores pod bindings, live tokens and
// revocations from a snapshot.
func NewBoundTokenGuardFromSnapshot(cfg Config, data []byte) (*BoundTokenGuard, error) {
	return nil, errNotImplemented
}

// RegisterServiceAccount makes namespace/name an issuable service account.
func (g *BoundTokenGuard) RegisterServiceAccount(namespace, name string) error {
	return errNotImplemented
}

// RegisterPod records the binding a token may be issued against.
func (g *BoundTokenGuard) RegisterPod(b PodBinding) error {
	return errNotImplemented
}

// RequestToken issues one bound token for a registered pod.
func (g *BoundTokenGuard) RequestToken(req TokenRequest, now time.Time) (Token, error) {
	return Token{}, errNotImplemented
}

// Validate checks a bound token against the registered pod, its node, the
// required audience and the time window.
func (g *BoundTokenGuard) Validate(c Claims, requiredAudience, nodeName string, now time.Time) error {
	return errNotImplemented
}

// NeedsRefresh reports whether the newest token of a pod falls inside the
// refresh window.
func (g *BoundTokenGuard) NeedsRefresh(podUID string, now time.Time) (bool, error) {
	return false, errNotImplemented
}

// TokenFor returns the newest live token of a pod.
func (g *BoundTokenGuard) TokenFor(podUID string) (Token, error) {
	return Token{}, errNotImplemented
}

// Rotate replaces every live token of a pod with one fresh token.
func (g *BoundTokenGuard) Rotate(podUID string, now time.Time) (Token, error) {
	return Token{}, errNotImplemented
}

// RevokePod revokes a pod, drops its tokens and returns how many were dropped.
func (g *BoundTokenGuard) RevokePod(podUID string) int {
	return 0
}

// ActiveTokens reports how many tokens are currently stored.
func (g *BoundTokenGuard) ActiveTokens() int {
	return 0
}

// Prune drops expired tokens and returns how many were removed.
func (g *BoundTokenGuard) Prune(now time.Time) int {
	return 0
}

// Snapshot serialises pod bindings, live tokens and revocations so that a
// restarted issuer keeps the same view.
func (g *BoundTokenGuard) Snapshot() ([]byte, error) {
	return nil, errNotImplemented
}
