package task

import (
	"errors"
	"time"
)

// errNotImplemented is returned by stubs whose real logic is still missing.
var errNotImplemented = errors.New("not implemented")

// Sentinel errors. A revoked token must stay distinguishable from an upstream
// outage so that the gateway can fail closed without paging the wrong team.
var (
	ErrUpstream    = errors.New("introspect: upstream introspection failed")
	ErrRevoked     = errors.New("introspect: token revoked")
	ErrInvalidTTL  = errors.New("introspect: invalid ttl")
	ErrBadCapacity = errors.New("introspect: invalid capacity")
)

// TokenInfo is the introspection result for one access token.
type TokenInfo struct {
	Active    bool
	Subject   string
	TenantID  string
	ClientID  string
	Scope     []string
	ExpiresAt time.Time
}

// CachePolicy controls cache lifetimes and the entry bound.
type CachePolicy struct {
	// TTL is how long an active result stays cached.
	TTL time.Duration
	// NegativeTTL is how long an inactive result stays cached.
	NegativeTTL time.Duration
	// RevocationTTL is how long a local revocation is honoured.
	RevocationTTL time.Duration
	// MaxEntries bounds the number of cached tokens.
	MaxEntries int
}

// UpstreamFunc performs one real introspection call against the identity
// provider. It is called with the token and the tenant that presents it.
type UpstreamFunc func(token, tenantID string) (TokenInfo, error)

// CacheStats reports cache counters.
type CacheStats struct {
	Hits          int
	Misses        int
	UpstreamCalls int
	Evictions     int
	Revoked       int
	Entries       int
}

// IntrospectionCache caches introspection results per token and tenant.
type IntrospectionCache struct {
	policy   CachePolicy
	upstream UpstreamFunc
}

// NewIntrospectionCache returns a cache that consults upstream on misses.
func NewIntrospectionCache(p CachePolicy, upstream UpstreamFunc) *IntrospectionCache {
	return &IntrospectionCache{policy: p, upstream: upstream}
}

// NewIntrospectionCacheFromSnapshot restores cached entries and revocation
// markers from data produced by Snapshot.
func NewIntrospectionCacheFromSnapshot(p CachePolicy, upstream UpstreamFunc, data []byte) (*IntrospectionCache, error) {
	return nil, errNotImplemented
}

// Lookup returns the introspection result for token in tenantID. A cached
// result inside its lifetime is served without calling upstream; concurrent
// lookups for the same key share one upstream call.
func (c *IntrospectionCache) Lookup(token, tenantID string, now time.Time) (TokenInfo, error) {
	return TokenInfo{}, errNotImplemented
}

// Revoke marks a token as revoked for RevocationTTL from now.
func (c *IntrospectionCache) Revoke(token, tenantID string, now time.Time) error {
	return errNotImplemented
}

// Revoked reports whether the token is inside an active revocation.
func (c *IntrospectionCache) Revoked(token, tenantID string, now time.Time) (bool, error) {
	return false, errNotImplemented
}

// Invalidate drops a cached entry without revoking the token.
func (c *IntrospectionCache) Invalidate(token, tenantID string) error {
	return errNotImplemented
}

// Warm fills the cache for one token, ignoring an existing fresh entry.
func (c *IntrospectionCache) Warm(token, tenantID string, now time.Time) error {
	return errNotImplemented
}

// Flush drops every cached entry and returns how many were removed.
func (c *IntrospectionCache) Flush() int {
	return 0
}

// Resize changes the entry bound, evicting least recently used entries.
func (c *IntrospectionCache) Resize(max int) error {
	return errNotImplemented
}

// SetTTL changes the positive cache lifetime.
func (c *IntrospectionCache) SetTTL(d time.Duration) error {
	return errNotImplemented
}

// Prune drops expired entries and returns the removed count.
func (c *IntrospectionCache) Prune(now time.Time) int {
	return 0
}

// Snapshot serialises unexpired entries and active revocations.
func (c *IntrospectionCache) Snapshot(now time.Time) ([]byte, error) {
	return nil, errNotImplemented
}

// Stats returns the current counters.
func (c *IntrospectionCache) Stats() CacheStats {
	return CacheStats{}
}
