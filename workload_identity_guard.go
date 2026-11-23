package task

import (
	"errors"
	"sync"
	"time"
)

var errNotImplemented = errors.New("not implemented")

// Sentinel errors returned by Exchange and Validate. The federation broker
// emits one audit event per error, so a replayed workload token must stay
// distinguishable from an expired one and from a revoked workload.
var (
	ErrTokenInvalid   = errors.New("wid: invalid workload token")
	ErrTokenExpired   = errors.New("wid: workload token expired")
	ErrAudience       = errors.New("wid: audience mismatch")
	ErrTrustDomain    = errors.New("wid: untrusted trust domain")
	ErrReplay         = errors.New("wid: workload token replayed")
	ErrNoRole         = errors.New("wid: no role binding for subject")
	ErrBindingInvalid = errors.New("wid: invalid role binding")
	ErrRevoked        = errors.New("wid: workload or credential revoked")
	ErrCredCap        = errors.New("wid: outstanding credential budget exhausted")
	ErrTTLTooLong     = errors.New("wid: requested ttl out of range")
	ErrCredUnknown    = errors.New("wid: unknown credential")
	ErrCredExpired    = errors.New("wid: credential expired")
)

// Config holds the federation policy.
type Config struct {
	// TrustDomain is the SPIFFE trust domain the broker serves.
	TrustDomain string
	// Audience is the exact aud value workload tokens must carry.
	Audience string
	// MaxTokenTTL bounds the lifetime a presented token may have.
	MaxTokenTTL time.Duration
	// MaxCredTTL bounds the ttl a caller may request.
	MaxCredTTL time.Duration
	// MaxOutstanding caps unexpired credentials issued by the broker.
	MaxOutstanding int
	// ReplayTTL is how long a consumed token id is remembered.
	ReplayTTL time.Duration
}

// RoleBinding maps a subject prefix of one tenant to a cloud role. The most
// specific (longest) prefix wins.
type RoleBinding struct {
	TenantID      string
	SubjectPrefix string
	RoleARN       string
	MaxTTL        time.Duration
}

// Token is a workload token (JWT-SVID) presented by a workload.
type Token struct {
	Subject        string
	Audience       string
	Domain         string
	JTI            string
	IssuedAt       time.Time
	ExpiresAt      time.Time
	SignatureValid bool
}

// Credential is the short-lived cloud credential handed back after a
// successful exchange.
type Credential struct {
	Value     string
	RoleARN   string
	Subject   string
	TenantID  string
	ExpiresAt time.Time
}

// WorkloadIdentityGuard exchanges workload tokens for scoped credentials.
type WorkloadIdentityGuard struct {
	mu  sync.Mutex
	cfg Config
}

// NewWorkloadIdentityGuard returns a guard configured by cfg.
func NewWorkloadIdentityGuard(cfg Config) *WorkloadIdentityGuard {
	return &WorkloadIdentityGuard{cfg: cfg}
}

// NewWorkloadIdentityGuardFromSnapshot restores bindings, revocations, used
// token ids and issued credentials from a snapshot.
func NewWorkloadIdentityGuardFromSnapshot(cfg Config, data []byte) (*WorkloadIdentityGuard, error) {
	return nil, errNotImplemented
}

// BindRole installs or replaces the binding for a subject prefix of a tenant.
// Empty tenant, prefix or role or a non-positive MaxTTL fails with
// ErrBindingInvalid.
func (g *WorkloadIdentityGuard) BindRole(b RoleBinding) error {
	return errNotImplemented
}

// UnbindRole removes a binding; unknown prefixes fail with
// ErrBindingInvalid.
func (g *WorkloadIdentityGuard) UnbindRole(tenantID, subjectPrefix string) error {
	return errNotImplemented
}

// RevokeSubject revokes all future exchanges for one workload subject of a
// tenant. Revocation is idempotent.
func (g *WorkloadIdentityGuard) RevokeSubject(tenantID, subject string) error {
	return errNotImplemented
}

// ReinstateSubject lifts a subject revocation.
func (g *WorkloadIdentityGuard) ReinstateSubject(tenantID, subject string) error {
	return errNotImplemented
}

// BindingFor returns the longest matching binding for a subject, or ErrNoRole.
func (g *WorkloadIdentityGuard) BindingFor(tenantID, subject string) (RoleBinding, error) {
	return RoleBinding{}, errNotImplemented
}

// Exchange validates a workload token and returns a credential.
//
// Checks run in this order: trust domain, structural fields, signature,
// audience, expiry, token lifetime, replay, subject revocation, role binding,
// requested ttl range, outstanding credential cap. The successful call
// consumes the token id for ReplayTTL and counts the new credential.
func (g *WorkloadIdentityGuard) Exchange(tok Token, tenantID string, ttl time.Duration, now time.Time) (Credential, error) {
	return Credential{}, errNotImplemented
}

// Validate resolves a credential value: unknown values yield ErrCredUnknown,
// revoked ones ErrRevoked and expired ones ErrCredExpired.
func (g *WorkloadIdentityGuard) Validate(credValue string, now time.Time) (Credential, error) {
	return Credential{}, errNotImplemented
}

// RevokeCredential revokes one issued credential immediately.
func (g *WorkloadIdentityGuard) RevokeCredential(credValue string) error {
	return errNotImplemented
}

// Outstanding counts unexpired credentials at now.
func (g *WorkloadIdentityGuard) Outstanding(now time.Time) int {
	return 0
}

// Snapshot serialises bindings, revocations, used token ids, credentials and
// the credential counter so that a restarted broker keeps rejecting replays
// and keeps counting outstanding credentials.
func (g *WorkloadIdentityGuard) Snapshot() ([]byte, error) {
	return nil, errNotImplemented
}
