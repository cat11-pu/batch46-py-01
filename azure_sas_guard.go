package task

import (
	"errors"
	"time"
)

// Sentinel errors returned by SasGuard. A forged signature, an expired token
// and a revoked stored access policy must stay distinguishable.
var (
	ErrMalformed      = errors.New("sas: malformed token")
	ErrSignature      = errors.New("sas: signature mismatch")
	ErrExpired        = errors.New("sas: token expired")
	ErrNotYet         = errors.New("sas: token not yet valid")
	ErrPermission     = errors.New("sas: permission denied")
	ErrIP             = errors.New("sas: source ip not allowed")
	ErrRevoked        = errors.New("sas: policy revoked")
	ErrLimit          = errors.New("sas: limit exceeded")
	ErrUnknownAccount = errors.New("sas: unknown storage account")
)

var errNotImplemented = errors.New("not implemented")

// Config is the SAS policy of one storage gateway.
type Config struct {
	// MaxLifetime caps expiry minus start of one token. A zero value means
	// twenty four hours.
	MaxLifetime time.Duration
	// ClockSkew is the tolerated clock difference around start and expiry. A
	// zero value means two minutes.
	ClockSkew time.Duration
	// AllowedServices lists the accepted service letters, for example "b" and
	// "q".
	AllowedServices []string
}

// Token is the signed content of one shared access signature.
type Token struct {
	// Version is the SAS format version, currently "2022-11-02".
	Version string
	// Service is "b" (blob), "q" (queue) or "f" (file).
	Service string
	// Resource is "b" (blob), "c" (container) or "d" (directory).
	Resource string
	// Protocol must be "https".
	Protocol string
	Start    time.Time
	Expiry   time.Time
	// Permissions is a subset of "racwdl" in canonical order.
	Permissions string
	// IPRange is either "a.b.c.d" or "a.b.c.d-e.f.g.h".
	IPRange string
	// PolicyID names a stored access policy when non-empty.
	PolicyID string
	// Signature is the base64url encoded HMAC of the string to sign.
	Signature string
}

// MintRequest binds a token to one storage location.
type MintRequest struct {
	Account   string
	Container string
	Blob      string
	Token     Token
}

// SasGuard signs and validates shared access signatures for one gateway.
type SasGuard struct {
	cfg Config
}

// NewSasGuard returns a guard configured by cfg.
func NewSasGuard(cfg Config) *SasGuard {
	return &SasGuard{cfg: cfg}
}

// NewSasGuardFromSnapshot restores the stored access policies of a gateway from
// a snapshot.
func NewSasGuardFromSnapshot(cfg Config, data []byte) (*SasGuard, error) {
	return nil, errNotImplemented
}

// RegisterAccountKey stores the shared key of one storage account.
func (g *SasGuard) RegisterAccountKey(account string, key []byte) error {
	return errNotImplemented
}

// CanonicalPermissions keeps only the letters of "racwdl", removes duplicates
// and returns them in canonical order "racwdl".
func (g *SasGuard) CanonicalPermissions(perms string) (string, error) {
	return "", errNotImplemented
}

// StringToSign renders the fixed multi-line string that is signed for a token.
func (g *SasGuard) StringToSign(t Token, account, container, blob string) string {
	return ""
}

// Mint validates the policy window of req and returns the signed query string.
func (g *SasGuard) Mint(req MintRequest, now time.Time) (string, error) {
	return "", errNotImplemented
}

// Parse reads a signed query string back into a Token.
func (g *SasGuard) Parse(raw string) (Token, error) {
	return Token{}, errNotImplemented
}

// Validate checks a token for account, container, blob, permission, source IP
// and time window before the gateway serves the request.
func (g *SasGuard) Validate(raw, account, container, blob, requiredPerm, sourceIP string, now time.Time) error {
	return errNotImplemented
}

// SetPolicy registers a stored access policy on a container.
func (g *SasGuard) SetPolicy(container, policyID, perms string, start, expiry time.Time) error {
	return errNotImplemented
}

// RevokePolicy marks a stored access policy as revoked. Revoking twice is not
// an error.
func (g *SasGuard) RevokePolicy(container, policyID string) error {
	return errNotImplemented
}

// PolicyCount returns how many stored access policies are registered.
func (g *SasGuard) PolicyCount() int {
	return 0
}

// PrunePolicies drops revoked and expired policies and returns how many were
// removed.
func (g *SasGuard) PrunePolicies(now time.Time) int {
	return 0
}

// Snapshot serialises the stored access policies so that a restarted gateway
// keeps honouring revocations.
func (g *SasGuard) Snapshot() ([]byte, error) {
	return nil, errNotImplemented
}
