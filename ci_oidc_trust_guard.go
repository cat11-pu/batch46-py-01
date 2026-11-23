package task

import (
	"errors"
	"time"
)

// errNotImplemented is returned by every stub that still has to be built.
var errNotImplemented = errors.New("not implemented")

// Errors returned by CiOidcGuard. Rejections of identity values (issuer,
// audience, subject, ref) are separated from timing and replay failures.
var (
	ErrPolicyNotFound   = errors.New("oidc: trust policy not found")
	ErrPolicyExists     = errors.New("oidc: trust policy already exists")
	ErrInvalidPolicy    = errors.New("oidc: invalid trust policy")
	ErrTooManyPolicies  = errors.New("oidc: trust policy limit reached")
	ErrIssuerMismatch   = errors.New("oidc: issuer not trusted")
	ErrAudienceMismatch = errors.New("oidc: audience not allowed")
	ErrSubjectMismatch  = errors.New("oidc: subject does not match policy")
	ErrRefNotAllowed    = errors.New("oidc: ref not allowed by policy")
	ErrTokenExpired     = errors.New("oidc: token expired")
	ErrTokenNotYetValid = errors.New("oidc: token issued in the future")
	ErrTokenLifetime    = errors.New("oidc: token lifetime exceeds policy")
	ErrReplay           = errors.New("oidc: token replayed")
	ErrInvalidClaims    = errors.New("oidc: invalid claims")
)

// Config bounds the trust store and the replay window.
type Config struct {
	// MaxPolicies caps the number of registered trust policies.
	MaxPolicies int
	// MaxTokenLifetime caps the lifetime of an accepted token.
	MaxTokenLifetime time.Duration
	// ClockSkew is the tolerated difference between token and server clocks.
	ClockSkew time.Duration
	// ReplayTTL is how long a consumed token id is remembered.
	ReplayTTL time.Duration
}

// TrustPolicy describes which workload identity tokens may obtain a grant.
type TrustPolicy struct {
	Name string
	// Issuer is the exact OIDC issuer URL.
	Issuer string
	// Audiences is the list of accepted audience values.
	Audiences []string
	// SubjectPatterns are colon-segment patterns. Every segment must line up;
	// a segment may contain '*' which matches any run of characters inside
	// that segment but never a ':'.
	SubjectPatterns []string
	// RefPatterns restricts the git ref. An empty list accepts any ref.
	RefPatterns []string
	// MaxTTL caps the lifetime of tokens granted by this policy.
	MaxTTL time.Duration
}

// Claims is the set of OIDC claims presented by a CI job.
type Claims struct {
	Issuer    string
	Subject   string
	Audience  string
	Ref       string
	JTI       string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// Grant is the result of a successful policy evaluation.
type Grant struct {
	Policy    string
	Subject   string
	Issuer    string
	ExpiresAt time.Time
}

// CiOidcGuard evaluates CI workload identity tokens against trust policies.
type CiOidcGuard struct {
	cfg Config
}

// NewCiOidcGuard returns an empty trust store configured by cfg.
func NewCiOidcGuard(cfg Config) *CiOidcGuard {
	return &CiOidcGuard{cfg: cfg}
}

// NewCiOidcGuardFromSnapshot restores policies and consumed token ids.
func NewCiOidcGuardFromSnapshot(cfg Config, data []byte) (*CiOidcGuard, error) {
	return nil, errNotImplemented
}

// AddPolicy validates and stores a trust policy.
func (g *CiOidcGuard) AddPolicy(p TrustPolicy) error {
	return errNotImplemented
}

// RemovePolicy deletes a trust policy by name.
func (g *CiOidcGuard) RemovePolicy(name string) error {
	return errNotImplemented
}

// Policy returns one stored trust policy.
func (g *CiOidcGuard) Policy(name string) (TrustPolicy, error) {
	return TrustPolicy{}, errNotImplemented
}

// ListPolicies returns the policy names in sorted order.
func (g *CiOidcGuard) ListPolicies() []string {
	return nil
}

// MatchPattern reports whether a colon-segment subject pattern matches value.
func (g *CiOidcGuard) MatchPattern(pattern, value string) (bool, error) {
	return false, errNotImplemented
}

// Evaluate checks claims against the trust policies and consumes the token id
// on success.
func (g *CiOidcGuard) Evaluate(c Claims, now time.Time) (Grant, error) {
	return Grant{}, errNotImplemented
}

// ReplaySeen reports whether issuer/jti was already consumed and is still
// inside the replay window.
func (g *CiOidcGuard) ReplaySeen(issuer, jti string) (bool, error) {
	return false, errNotImplemented
}

// PruneReplay drops replay entries whose window has passed.
func (g *CiOidcGuard) PruneReplay(now time.Time) int {
	return 0
}

// Snapshot serialises the trust store and the replay entries.
func (g *CiOidcGuard) Snapshot() ([]byte, error) {
	return nil, errNotImplemented
}
