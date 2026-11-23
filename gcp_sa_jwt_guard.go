package task

import (
	"errors"
	"time"
)

// Sentinel errors returned by SaJwtGuard. A bad audience, an expired assertion
// and a replayed assertion id must stay distinguishable.
var (
	ErrMalformed     = errors.New("gsa: malformed assertion")
	ErrSignature     = errors.New("gsa: assertion signature invalid")
	ErrAudience      = errors.New("gsa: audience mismatch")
	ErrExpired       = errors.New("gsa: assertion expired")
	ErrNotYet        = errors.New("gsa: assertion not yet valid")
	ErrReplay        = errors.New("gsa: replayed assertion")
	ErrScope         = errors.New("gsa: scope not allowed")
	ErrChain         = errors.New("gsa: delegation chain rejected")
	ErrQuota         = errors.New("gsa: quota exceeded")
	ErrSubject       = errors.New("gsa: subject delegation not allowed")
	ErrUnknownIssuer = errors.New("gsa: unknown service account")
	ErrTokenRevoked  = errors.New("gsa: access token revoked")
)

var errNotImplemented = errors.New("not implemented")

// Config is the exchange policy of one token broker.
type Config struct {
	// Audience is the only accepted assertion audience.
	Audience string
	// MaxSkew is the tolerated clock difference around iat and exp. A zero
	// value means sixty seconds.
	MaxSkew time.Duration
	// MaxAssertionTTL caps exp minus iat. A zero value means fifteen minutes.
	MaxAssertionTTL time.Duration
	// MaxDelegates caps the impersonation chain length. A zero value means
	// three.
	MaxDelegates int
	// AllowedScopes lists the scopes the broker may hand out.
	AllowedScopes []string
	// TokenTTL is the lifetime of an issued access token. A zero value means
	// one hour.
	TokenTTL time.Duration
	// QuotaPerWindow caps exchanges per service account inside QuotaWindow. A
	// zero value means one hundred.
	QuotaPerWindow int
	// QuotaWindow is the sliding quota window. A zero value means one minute.
	QuotaWindow time.Duration
	// JTITTL is how long an assertion id is remembered. A zero value means one
	// hour.
	JTITTL time.Duration
}

// Assertion is a self signed service account assertion as presented at the
// token endpoint.
type Assertion struct {
	Issuer string
	// Subject is set for domain wide delegation.
	Subject   string
	Audience  string
	JTI       string
	IssuedAt  time.Time
	ExpiresAt time.Time
	Scopes    []string
	Delegates []string
	// SignatureValid is the result of signature verification.
	SignatureValid bool
}

// AccessToken is the token issued for a verified assertion.
type AccessToken struct {
	Value        string
	Subject      string
	Issuer       string
	Scopes       []string
	ExpiresAt    time.Time
	Impersonated bool
}

// SaJwtGuard exchanges service account assertions for access tokens.
type SaJwtGuard struct {
	cfg Config
}

// NewSaJwtGuard returns a guard configured by cfg.
func NewSaJwtGuard(cfg Config) *SaJwtGuard {
	return &SaJwtGuard{cfg: cfg}
}

// NewSaJwtGuardFromSnapshot restores the replay set, the issued tokens and the
// revocations from a snapshot.
func NewSaJwtGuardFromSnapshot(cfg Config, data []byte) (*SaJwtGuard, error) {
	return nil, errNotImplemented
}

// RegisterServiceAccount makes email a known issuer of assertions.
func (g *SaJwtGuard) RegisterServiceAccount(email, project string) error {
	return errNotImplemented
}

// AllowSubjectDelegation records that email may impersonate subject.
func (g *SaJwtGuard) AllowSubjectDelegation(email, subject string) error {
	return errNotImplemented
}

// ScopeSet trims, deduplicates and sorts scopes. Every scope must look like an
// absolute URL and the set must not be empty.
func (g *SaJwtGuard) ScopeSet(scopes []string) ([]string, error) {
	return nil, errNotImplemented
}

// Exchange verifies an assertion and issues an access token bound to it.
func (g *SaJwtGuard) Exchange(a Assertion, now time.Time) (AccessToken, error) {
	return AccessToken{}, errNotImplemented
}

// JTIUsed reports whether an assertion id is currently remembered.
func (g *SaJwtGuard) JTIUsed(jti string) (bool, error) {
	return false, errNotImplemented
}

// QuotaRemaining reports how many exchanges an issuer may still perform inside
// the current window.
func (g *SaJwtGuard) QuotaRemaining(email string, now time.Time) (int, error) {
	return 0, errNotImplemented
}

// RevokeToken marks an issued access token as revoked. Revoking twice is not an
// error.
func (g *SaJwtGuard) RevokeToken(value string) error {
	return errNotImplemented
}

// ValidateToken authenticates an issued access token and checks a required
// scope when one is given.
func (g *SaJwtGuard) ValidateToken(value, requiredScope string, now time.Time) (AccessToken, error) {
	return AccessToken{}, errNotImplemented
}

// PruneJTIs drops remembered assertion ids whose window has passed and returns
// how many were removed.
func (g *SaJwtGuard) PruneJTIs(now time.Time) int {
	return 0
}

// Snapshot serialises the replay set, issued tokens and revocations so that a
// restarted broker keeps refusing replays and revoked tokens.
func (g *SaJwtGuard) Snapshot() ([]byte, error) {
	return nil, errNotImplemented
}
