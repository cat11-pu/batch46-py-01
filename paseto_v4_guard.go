package task

import (
	"errors"
	"time"
)

// errNotImplemented is returned by every stub that still has to be built.
var errNotImplemented = errors.New("not implemented")

// Errors returned by PasetoGuard.
var (
	ErrKeyNotFound      = errors.New("paseto: key not found")
	ErrKeyExpired       = errors.New("paseto: key retired")
	ErrNoActiveKey      = errors.New("paseto: no active key")
	ErrKeyExists        = errors.New("paseto: key already registered")
	ErrKeyInvalid       = errors.New("paseto: invalid key")
	ErrTooManyKeys      = errors.New("paseto: key limit reached")
	ErrInvalidToken     = errors.New("paseto: invalid token")
	ErrTokenExpired     = errors.New("paseto: token expired")
	ErrTokenNotYetValid = errors.New("paseto: token not yet valid")
	ErrIssuerMismatch   = errors.New("paseto: issuer mismatch")
	ErrAudienceMismatch = errors.New("paseto: audience mismatch")
	ErrRevoked          = errors.New("paseto: token revoked")
	ErrInvalidClaims    = errors.New("paseto: invalid claims")
	ErrRateLimited      = errors.New("paseto: issuance rate limited")
	ErrTokenLifetime    = errors.New("paseto: token lifetime exceeds limit")
)

// Sealer is the symmetric sealing primitive. A token body is sealed with the
// key material identified by kid.
type Sealer interface {
	Seal(kid string, plaintext []byte) (string, error)
	Open(kid string, ciphertext string) ([]byte, error)
}

// Config is the token policy and the key/mint budget.
type Config struct {
	Issuer    string
	Audience  string
	ClockSkew time.Duration
	// MaxTTL caps the lifetime of a minted token.
	MaxTTL time.Duration
	// MaxKeys caps the number of registered keys.
	MaxKeys int
	// MintLimit is the number of tokens that may be minted per MintWindow.
	MintLimit int
	// MintWindow is the rate-limit window.
	MintWindow time.Duration
	// RevocationTTL is how long a revoked token id is remembered.
	RevocationTTL time.Duration
}

// Key is one version of the local symmetric key.
type Key struct {
	KID string
	// NotBefore is when the key may start signing and verifying tokens.
	NotBefore time.Time
	// MintUntil is when the key stops being the active signing key.
	MintUntil time.Time
	// RetireAt is when tokens sealed with the key stop verifying.
	RetireAt time.Time
}

// Claims is the payload of a local token.
type Claims struct {
	Subject   string
	Issuer    string
	Audience  string
	JTI       string
	IssuedAt  time.Time
	NotBefore time.Time
	ExpiresAt time.Time
}

// PasetoGuard mints and verifies v4.local tokens and tracks revocation.
type PasetoGuard struct {
	cfg    Config
	sealer Sealer
}

// NewPasetoGuard returns an empty guard configured by cfg.
func NewPasetoGuard(cfg Config, sealer Sealer) *PasetoGuard {
	return &PasetoGuard{cfg: cfg, sealer: sealer}
}

// NewPasetoGuardFromSnapshot restores keys, revocations and the mint window.
func NewPasetoGuardFromSnapshot(cfg Config, sealer Sealer, data []byte) (*PasetoGuard, error) {
	return nil, errNotImplemented
}

// AddKey registers a key version.
func (g *PasetoGuard) AddKey(k Key) error {
	return errNotImplemented
}

// RotateKey makes k the signing key and stops signing with the previously
// active key, atomically.
func (g *PasetoGuard) RotateKey(k Key, now time.Time) error {
	return errNotImplemented
}

// Mint validates claims, applies the rate limit and returns a v4.local token.
func (g *PasetoGuard) Mint(c Claims, now time.Time) (string, error) {
	return "", errNotImplemented
}

// Verify opens a v4.local token and checks its key, claims and revocation
// state.
func (g *PasetoGuard) Verify(token string, now time.Time) (Claims, error) {
	return Claims{}, errNotImplemented
}

// Revoke marks a token id as revoked. Repeating the call is harmless.
func (g *PasetoGuard) Revoke(jti string, now time.Time) error {
	return errNotImplemented
}

// IsRevoked reports whether a token id is still inside its revocation TTL.
func (g *PasetoGuard) IsRevoked(jti string, now time.Time) (bool, error) {
	return false, errNotImplemented
}

// PruneRevoked drops revocation entries whose TTL has passed.
func (g *PasetoGuard) PruneRevoked(now time.Time) int {
	return 0
}

// ActiveKey returns the id of the key currently used for minting.
func (g *PasetoGuard) ActiveKey(now time.Time) (string, error) {
	return "", errNotImplemented
}

// KeyCount reports the number of registered keys.
func (g *PasetoGuard) KeyCount() int {
	return 0
}

// Snapshot serialises keys, revocations and the mint window.
func (g *PasetoGuard) Snapshot() ([]byte, error) {
	return nil, errNotImplemented
}
