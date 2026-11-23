package task

import (
	"errors"
	"time"
)

// errNotImplemented is returned by every stub that still has to be built.
var errNotImplemented = errors.New("not implemented")

// Errors returned by JwksGuard.
var (
	ErrKeyNotFound      = errors.New("jwks: key not found")
	ErrKeyExpired       = errors.New("jwks: key expired")
	ErrKeyInvalid       = errors.New("jwks: invalid key")
	ErrKeyExists        = errors.New("jwks: key already published")
	ErrTooManyKeys      = errors.New("jwks: key limit reached")
	ErrAlgMismatch      = errors.New("jwks: algorithm not allowed for key")
	ErrTokenExpired     = errors.New("jwks: token expired")
	ErrIssuerMismatch   = errors.New("jwks: issuer mismatch")
	ErrAudienceMismatch = errors.New("jwks: audience mismatch")
	ErrSourceFailed     = errors.New("jwks: key source failed")
)

// Config is the verifier policy and the cache budget.
type Config struct {
	Issuer   string
	Audience string
	// KeyTTL caps the cache lifetime of a key fetched from the key source.
	KeyTTL time.Duration
	// KeyGrace is how long a retired key stays usable for already signed
	// tokens.
	KeyGrace time.Duration
	// MaxKeys caps the number of cache entries.
	MaxKeys int
	// ClockSkew is the tolerated clock difference for token expiry.
	ClockSkew time.Duration
}

// Key is one JSON Web Key as exposed by the identity provider.
type Key struct {
	KID       string
	Alg       string
	PublicKey string
	NotBefore time.Time
	ExpiresAt time.Time
	// RetiredAt is set when the provider stops signing with the key. The key
	// remains usable for verification until RetiredAt plus KeyGrace.
	RetiredAt time.Time
}

// Header is the JOSE header of a token.
type Header struct {
	KID string
	Alg string
}

// Claims is the subset of token claims the verifier checks.
type Claims struct {
	Issuer    string
	Audience  string
	ExpiresAt time.Time
}

// KeySource fetches a single key from the identity provider.
type KeySource func(kid string) (Key, error)

// JwksGuard caches keys and verifies token headers and claims.
type JwksGuard struct {
	cfg Config
	src KeySource
}

// NewJwksGuard returns an empty cache. src may be nil when the cache is filled
// directly with PublishKey or WarmCache.
func NewJwksGuard(cfg Config, src KeySource) *JwksGuard {
	return &JwksGuard{cfg: cfg, src: src}
}

// NewJwksGuardFromSnapshot restores the key cache from a snapshot.
func NewJwksGuardFromSnapshot(cfg Config, src KeySource, data []byte) (*JwksGuard, error) {
	return nil, errNotImplemented
}

// PublishKey adds one key to the cache, capping its expiry to the cache TTL.
func (g *JwksGuard) PublishKey(k Key, now time.Time) error {
	return errNotImplemented
}

// RetireKey marks a key as no longer used for signing while keeping it
// verifiable during the grace period.
func (g *JwksGuard) RetireKey(kid string, now time.Time) error {
	return errNotImplemented
}

// KeyFor returns the usable key with the given id.
func (g *JwksGuard) KeyFor(kid string, now time.Time) (Key, error) {
	return Key{}, errNotImplemented
}

// Verify checks the JOSE header and the claims and returns the matching key.
func (g *JwksGuard) Verify(h Header, c Claims, now time.Time) (Key, error) {
	return Key{}, errNotImplemented
}

// Refresh fetches one key from the key source. Concurrent refreshes of the
// same key coalesce into a single upstream call.
func (g *JwksGuard) Refresh(kid string, now time.Time) (Key, error) {
	return Key{}, errNotImplemented
}

// WarmCache publishes a batch of keys atomically: either every key is added or
// none is.
func (g *JwksGuard) WarmCache(keys []Key, now time.Time) error {
	return errNotImplemented
}

// Rotate atomically retires oldKID and publishes its replacement.
func (g *JwksGuard) Rotate(oldKID string, k Key, now time.Time) error {
	return errNotImplemented
}

// Prune drops keys that are expired or past their retirement grace.
func (g *JwksGuard) Prune(now time.Time) int {
	return 0
}

// CacheSize reports the number of cache entries.
func (g *JwksGuard) CacheSize() int {
	return 0
}

// Generation reports how many times the cache content changed.
func (g *JwksGuard) Generation() uint64 {
	return 0
}

// Snapshot serialises the key cache.
func (g *JwksGuard) Snapshot() ([]byte, error) {
	return nil, errNotImplemented
}
