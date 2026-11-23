package task

import (
	"errors"
	"time"
)

// errNotImplemented is returned by stubs whose real logic is still missing.
var errNotImplemented = errors.New("not implemented")

// Sentinel errors. Callers switch on them with errors.Is, so a replay must
// never be reported as a signature failure and vice versa.
var (
	ErrAssertionInvalid = errors.New("saml: invalid assertion")
	ErrAssertionExpired = errors.New("saml: assertion expired")
	ErrAudienceMismatch = errors.New("saml: audience mismatch")
	ErrSignature        = errors.New("saml: invalid signature")
	ErrIssuerUnknown    = errors.New("saml: unknown issuer")
	ErrDestination      = errors.New("saml: destination mismatch")
	ErrTenantMismatch   = errors.New("saml: cross tenant assertion")
	ErrUnknownRequest   = errors.New("saml: unknown request id")
	ErrReplay           = errors.New("saml: replayed assertion")
	ErrSubjectRevoked   = errors.New("saml: subject revoked")
	ErrCapacity         = errors.New("saml: replay store full")
)

// Policy is the replay and clock policy applied to every assertion.
type Policy struct {
	// MaxClockSkew is the tolerated difference between assertion times and now.
	MaxClockSkew time.Duration
	// ReplayTTL is how long an assertion id is remembered.
	ReplayTTL time.Duration
	// MaxAssertionAge rejects assertions issued too long before now.
	MaxAssertionAge time.Duration
	// MaxReplayEntries bounds the replay table.
	MaxReplayEntries int
}

// Assertion is a SAML assertion as parsed from an IdP response.
type Assertion struct {
	ID             string
	Issuer         string
	Audience       string
	Destination    string
	Subject        string
	TenantID       string
	InResponseTo   string
	NotBefore      time.Time
	NotOnOrAfter   time.Time
	IssueInstant   time.Time
	SignatureValid bool
	Attributes     map[string]string
}

// Identity is the session identity produced for a valid assertion.
type Identity struct {
	TenantID    string
	Subject     string
	Issuer      string
	AssertionID string
	IssuedAt    time.Time
	Attributes  map[string]string
}

// Stats reports guard counters.
type Stats struct {
	Accepted      int
	Rejected      int
	ReplayHits    int
	ReplayEntries int
}

// SamlReplayGuard validates assertions and keeps the replay table.
type SamlReplayGuard struct {
	policy Policy
}

// NewSamlReplayGuard returns a guard configured by p.
func NewSamlReplayGuard(p Policy) *SamlReplayGuard {
	return &SamlReplayGuard{policy: p}
}

// NewSamlReplayGuardFromSnapshot restores a guard, including unexpired
// assertion ids, from data produced by Snapshot.
func NewSamlReplayGuardFromSnapshot(p Policy, data []byte) (*SamlReplayGuard, error) {
	return nil, errNotImplemented
}

// RegisterServiceProvider records the issuer entity id, ACS URL and accepted
// audiences for one tenant.
func (g *SamlReplayGuard) RegisterServiceProvider(tenantID, entityID, acsURL string, audiences []string) error {
	return errNotImplemented
}

// TrackRequest records an outstanding authentication request id for a tenant.
func (g *SamlReplayGuard) TrackRequest(tenantID, requestID string, now time.Time) error {
	return errNotImplemented
}

// Validate checks the assertion against the request and the policy and returns
// the resulting identity. A successful assertion id is stored for ReplayTTL.
func (g *SamlReplayGuard) Validate(a Assertion, requestID string, now time.Time) (Identity, error) {
	return Identity{}, errNotImplemented
}

// AssertionSeen reports whether an assertion id is still inside its replay window.
func (g *SamlReplayGuard) AssertionSeen(tenantID, id string, now time.Time) (bool, error) {
	return false, errNotImplemented
}

// RevokeSubject rejects every assertion for subject until the given instant.
func (g *SamlReplayGuard) RevokeSubject(tenantID, subject string, until time.Time) error {
	return errNotImplemented
}

// SubjectRevoked reports whether the subject is inside an active revocation.
func (g *SamlReplayGuard) SubjectRevoked(tenantID, subject string, now time.Time) (bool, error) {
	return false, errNotImplemented
}

// Prune drops expired replay and revocation entries and returns the removed count.
func (g *SamlReplayGuard) Prune(now time.Time) int {
	return 0
}

// Stats returns the current guard counters.
func (g *SamlReplayGuard) Stats() Stats {
	return Stats{}
}

// Snapshot serialises unexpired assertion ids and revocations.
func (g *SamlReplayGuard) Snapshot(now time.Time) ([]byte, error) {
	return nil, errNotImplemented
}

// SetMaxReplayEntries changes the replay table bound at runtime.
func (g *SamlReplayGuard) SetMaxReplayEntries(n int) error {
	return errNotImplemented
}
