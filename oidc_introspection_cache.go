package task

import (
	"container/list"
	"encoding/json"
	"errors"
	"sort"
	"sync"
	"time"
)

// Sentinel errors. A revoked token must stay distinguishable from an upstream
// outage so that the gateway can fail closed without paging the wrong team.
var (
	ErrUpstream        = errors.New("introspect: upstream introspection failed")
	ErrRevoked         = errors.New("introspect: token revoked")
	ErrInvalidTTL      = errors.New("introspect: invalid ttl")
	ErrBadCapacity     = errors.New("introspect: invalid capacity")
	ErrSnapshotInvalid = errors.New("introspect: invalid snapshot")
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

type cacheKey struct {
	token    string
	tenantID string
}

type cacheEntry struct {
	key       cacheKey
	info      TokenInfo
	expiresAt time.Time
}

type inflightCall struct {
	done      chan struct{}
	info      TokenInfo
	err       error
	cancelled bool
}

// IntrospectionCache caches introspection results per token and tenant.
type IntrospectionCache struct {
	policy   CachePolicy
	upstream UpstreamFunc

	mu          sync.Mutex
	lru         *list.List
	entries     map[cacheKey]*list.Element
	revocations map[cacheKey]time.Time
	inflight    map[cacheKey]*inflightCall

	hits          int
	misses        int
	upstreamCalls int
	evictions     int
}

const (
	defaultMaxEntries = 128
	snapshotVersion   = 1
)

func normalizePolicy(p CachePolicy) CachePolicy {
	if p.MaxEntries <= 0 {
		p.MaxEntries = defaultMaxEntries
	}
	if p.TTL < 0 {
		p.TTL = 0
	}
	if p.NegativeTTL < 0 {
		p.NegativeTTL = 0
	}
	if p.RevocationTTL < 0 {
		p.RevocationTTL = 0
	}
	return p
}

func newIntrospectionCache(p CachePolicy, upstream UpstreamFunc) *IntrospectionCache {
	return &IntrospectionCache{
		policy:      normalizePolicy(p),
		upstream:    upstream,
		lru:         list.New(),
		entries:     make(map[cacheKey]*list.Element),
		revocations: make(map[cacheKey]time.Time),
		inflight:    make(map[cacheKey]*inflightCall),
	}
}

// NewIntrospectionCache returns a cache that consults upstream on misses.
func NewIntrospectionCache(p CachePolicy, upstream UpstreamFunc) *IntrospectionCache {
	return newIntrospectionCache(p, upstream)
}

func cloneTokenInfo(info TokenInfo) TokenInfo {
	if info.Scope != nil {
		info.Scope = append([]string(nil), info.Scope...)
	}
	return info
}

func (c *IntrospectionCache) isRevokedLocked(key cacheKey, now time.Time) bool {
	deadline, ok := c.revocations[key]
	if !ok {
		return false
	}
	if now.Before(deadline) {
		return true
	}
	delete(c.revocations, key)
	return false
}

func (c *IntrospectionCache) removeEntryLocked(key cacheKey) bool {
	element, ok := c.entries[key]
	if !ok {
		return false
	}
	c.lru.Remove(element)
	delete(c.entries, key)
	return true
}

func (c *IntrospectionCache) freshEntryLocked(key cacheKey, now time.Time) (TokenInfo, bool) {
	element, ok := c.entries[key]
	if !ok {
		return TokenInfo{}, false
	}
	entry := element.Value.(*cacheEntry)
	if !now.Before(entry.expiresAt) {
		c.lru.Remove(element)
		delete(c.entries, key)
		return TokenInfo{}, false
	}
	c.lru.MoveToFront(element)
	return cloneTokenInfo(entry.info), true
}

func (c *IntrospectionCache) expiresAtFor(info TokenInfo, now time.Time) time.Time {
	if info.Active {
		expiresAt := now.Add(c.policy.TTL)
		if !info.ExpiresAt.IsZero() && info.ExpiresAt.Before(expiresAt) {
			expiresAt = info.ExpiresAt
		}
		return expiresAt
	}

	ttl := c.policy.NegativeTTL
	if ttl > c.policy.TTL {
		ttl = c.policy.TTL
	}
	return now.Add(ttl)
}

func (c *IntrospectionCache) evictOverflowLocked() {
	for c.lru.Len() > c.policy.MaxEntries {
		element := c.lru.Back()
		if element == nil {
			return
		}
		entry := element.Value.(*cacheEntry)
		c.lru.Remove(element)
		delete(c.entries, entry.key)
		c.evictions++
	}
}

func (c *IntrospectionCache) storeLocked(key cacheKey, info TokenInfo, expiresAt, now time.Time) {
	if !now.Before(expiresAt) {
		c.removeEntryLocked(key)
		return
	}

	stored := cloneTokenInfo(info)
	if element, ok := c.entries[key]; ok {
		entry := element.Value.(*cacheEntry)
		entry.info = stored
		entry.expiresAt = expiresAt
		c.lru.MoveToFront(element)
		return
	}

	entry := &cacheEntry{key: key, info: stored, expiresAt: expiresAt}
	element := c.lru.PushFront(entry)
	c.entries[key] = element
	c.evictOverflowLocked()
}

func (c *IntrospectionCache) callUpstream(token, tenantID string) (info TokenInfo, err error) {
	if c.upstream == nil {
		return TokenInfo{}, ErrUpstream
	}
	defer func() {
		if recover() != nil {
			info = TokenInfo{}
			err = ErrUpstream
		}
	}()
	return c.upstream(token, tenantID)
}

// Lookup returns the introspection result for token in tenantID. A cached
// result inside its lifetime is served without calling upstream; concurrent
// lookups for the same key share one upstream call.
func (c *IntrospectionCache) Lookup(token, tenantID string, now time.Time) (TokenInfo, error) {
	key := cacheKey{token: token, tenantID: tenantID}

	c.mu.Lock()
	if c.isRevokedLocked(key, now) {
		c.mu.Unlock()
		return TokenInfo{}, ErrRevoked
	}
	if info, ok := c.freshEntryLocked(key, now); ok {
		c.hits++
		c.mu.Unlock()
		return info, nil
	}

	c.misses++
	if call, ok := c.inflight[key]; ok {
		c.mu.Unlock()
		<-call.done

		c.mu.Lock()
		revoked := c.isRevokedLocked(key, now)
		c.mu.Unlock()
		if revoked {
			return TokenInfo{}, ErrRevoked
		}
		return cloneTokenInfo(call.info), call.err
	}

	call := &inflightCall{done: make(chan struct{})}
	c.inflight[key] = call
	c.mu.Unlock()

	info, err := c.callUpstream(token, tenantID)

	c.mu.Lock()
	c.upstreamCalls++
	delete(c.inflight, key)
	if err != nil {
		call.err = ErrUpstream
		close(call.done)
		c.mu.Unlock()
		return TokenInfo{}, ErrUpstream
	}
	if c.isRevokedLocked(key, now) {
		call.err = ErrRevoked
		close(call.done)
		c.mu.Unlock()
		return TokenInfo{}, ErrRevoked
	}
	if !call.cancelled {
		c.storeLocked(key, info, c.expiresAtFor(info, now), now)
	}
	call.info = cloneTokenInfo(info)
	close(call.done)
	c.mu.Unlock()

	return cloneTokenInfo(info), nil
}

// Revoke marks a token as revoked for RevocationTTL from now.
func (c *IntrospectionCache) Revoke(token, tenantID string, now time.Time) error {
	key := cacheKey{token: token, tenantID: tenantID}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.removeEntryLocked(key)
	if call, ok := c.inflight[key]; ok {
		call.cancelled = true
	}
	if c.policy.RevocationTTL > 0 {
		c.revocations[key] = now.Add(c.policy.RevocationTTL)
	} else {
		delete(c.revocations, key)
	}
	return nil
}

// Revoked reports whether the token is inside an active revocation.
func (c *IntrospectionCache) Revoked(token, tenantID string, now time.Time) (bool, error) {
	key := cacheKey{token: token, tenantID: tenantID}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.isRevokedLocked(key, now), nil
}

// Invalidate drops a cached entry without revoking the token.
func (c *IntrospectionCache) Invalidate(token, tenantID string) error {
	key := cacheKey{token: token, tenantID: tenantID}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.removeEntryLocked(key)
	if call, ok := c.inflight[key]; ok {
		call.cancelled = true
	}
	return nil
}

// Warm fills the cache for one token, ignoring an existing fresh entry.
func (c *IntrospectionCache) Warm(token, tenantID string, now time.Time) error {
	key := cacheKey{token: token, tenantID: tenantID}

	c.mu.Lock()
	if c.isRevokedLocked(key, now) {
		c.mu.Unlock()
		return ErrRevoked
	}
	if call, ok := c.inflight[key]; ok {
		c.mu.Unlock()
		<-call.done

		c.mu.Lock()
		revoked := c.isRevokedLocked(key, now)
		c.mu.Unlock()
		if revoked {
			return ErrRevoked
		}
		return call.err
	}

	call := &inflightCall{done: make(chan struct{})}
	c.inflight[key] = call
	c.mu.Unlock()

	info, err := c.callUpstream(token, tenantID)

	c.mu.Lock()
	c.upstreamCalls++
	delete(c.inflight, key)
	if err != nil {
		call.err = ErrUpstream
		close(call.done)
		c.mu.Unlock()
		return ErrUpstream
	}
	if c.isRevokedLocked(key, now) {
		call.err = ErrRevoked
		close(call.done)
		c.mu.Unlock()
		return ErrRevoked
	}
	if !call.cancelled {
		c.storeLocked(key, info, c.expiresAtFor(info, now), now)
	}
	call.info = cloneTokenInfo(info)
	close(call.done)
	c.mu.Unlock()
	return nil
}

// Flush drops every cached entry and returns how many were removed.
func (c *IntrospectionCache) Flush() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	removed := c.lru.Len()
	for _, call := range c.inflight {
		call.cancelled = true
	}
	c.lru.Init()
	c.entries = make(map[cacheKey]*list.Element)
	return removed
}

// Resize changes the entry bound, evicting least recently used entries.
func (c *IntrospectionCache) Resize(max int) error {
	if max <= 0 {
		return ErrBadCapacity
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.policy.MaxEntries = max
	c.evictOverflowLocked()
	return nil
}

// SetTTL changes the positive cache lifetime.
func (c *IntrospectionCache) SetTTL(d time.Duration) error {
	if d <= 0 {
		return ErrInvalidTTL
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.policy.TTL = d
	return nil
}

// Prune drops expired entries and returns the removed cache-entry count.
func (c *IntrospectionCache) Prune(now time.Time) int {
	c.mu.Lock()
	defer c.mu.Unlock()

	removed := 0
	for key, element := range c.entries {
		entry := element.Value.(*cacheEntry)
		if !now.Before(entry.expiresAt) {
			c.lru.Remove(element)
			delete(c.entries, key)
			removed++
		}
	}
	for key, deadline := range c.revocations {
		if !now.Before(deadline) {
			delete(c.revocations, key)
		}
	}
	return removed
}

type snapshotState struct {
	Version     int                  `json:"version"`
	SavedAt     time.Time            `json:"saved_at"`
	Entries     []snapshotEntry      `json:"entries"`
	Revocations []snapshotRevocation `json:"revocations"`
	Stats       snapshotStats        `json:"stats"`
}

type snapshotEntry struct {
	Token     string             `json:"token"`
	TenantID  string             `json:"tenant_id"`
	Result    *snapshotTokenInfo `json:"result"`
	ExpiresAt time.Time          `json:"expires_at"`
}

type snapshotTokenInfo struct {
	Active    bool      `json:"active"`
	Subject   string    `json:"subject"`
	TenantID  string    `json:"tenant_id"`
	ClientID  string    `json:"client_id"`
	Scope     []string  `json:"scope,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
}

type snapshotRevocation struct {
	Token     string    `json:"token"`
	TenantID  string    `json:"tenant_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

type snapshotStats struct {
	Hits          int `json:"hits"`
	Misses        int `json:"misses"`
	UpstreamCalls int `json:"upstream_calls"`
	Evictions     int `json:"evictions"`
	Revoked       int `json:"revoked"`
	Entries       int `json:"entries"`
}

// Snapshot serialises unexpired entries and active revocations.
func (c *IntrospectionCache) Snapshot(now time.Time) ([]byte, error) {
	c.mu.Lock()

	for key, element := range c.entries {
		entry := element.Value.(*cacheEntry)
		if !now.Before(entry.expiresAt) {
			c.lru.Remove(element)
			delete(c.entries, key)
		}
	}
	for key, deadline := range c.revocations {
		if !now.Before(deadline) {
			delete(c.revocations, key)
		}
	}

	state := snapshotState{
		Version:     snapshotVersion,
		SavedAt:     now,
		Entries:     make([]snapshotEntry, 0, c.lru.Len()),
		Revocations: make([]snapshotRevocation, 0, len(c.revocations)),
		Stats: snapshotStats{
			Hits:          c.hits,
			Misses:        c.misses,
			UpstreamCalls: c.upstreamCalls,
			Evictions:     c.evictions,
			Revoked:       len(c.revocations),
			Entries:       c.lru.Len(),
		},
	}
	for element := c.lru.Front(); element != nil; element = element.Next() {
		entry := element.Value.(*cacheEntry)
		state.Entries = append(state.Entries, snapshotEntry{
			Token:    entry.key.token,
			TenantID: entry.key.tenantID,
			Result: &snapshotTokenInfo{
				Active:    entry.info.Active,
				Subject:   entry.info.Subject,
				TenantID:  entry.info.TenantID,
				ClientID:  entry.info.ClientID,
				Scope:     append([]string(nil), entry.info.Scope...),
				ExpiresAt: entry.info.ExpiresAt,
			},
			ExpiresAt: entry.expiresAt,
		})
	}
	for key, deadline := range c.revocations {
		state.Revocations = append(state.Revocations, snapshotRevocation{
			Token:     key.token,
			TenantID:  key.tenantID,
			ExpiresAt: deadline,
		})
	}
	sort.Slice(state.Revocations, func(i, j int) bool {
		if state.Revocations[i].Token != state.Revocations[j].Token {
			return state.Revocations[i].Token < state.Revocations[j].Token
		}
		return state.Revocations[i].TenantID < state.Revocations[j].TenantID
	})

	c.mu.Unlock()
	return json.Marshal(state)
}

// NewIntrospectionCacheFromSnapshot restores cached entries and revocation
// markers from data produced by Snapshot.
func NewIntrospectionCacheFromSnapshot(p CachePolicy, upstream UpstreamFunc, data []byte) (*IntrospectionCache, error) {
	if len(data) == 0 {
		return nil, ErrSnapshotInvalid
	}

	var state snapshotState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, ErrSnapshotInvalid
	}
	if state.Version != snapshotVersion {
		return nil, ErrSnapshotInvalid
	}
	if state.Stats.Hits < 0 || state.Stats.Misses < 0 ||
		state.Stats.UpstreamCalls < 0 || state.Stats.Evictions < 0 {
		return nil, ErrSnapshotInvalid
	}

	c := newIntrospectionCache(p, upstream)
	seenEntries := make(map[cacheKey]struct{}, len(state.Entries))
	for _, se := range state.Entries {
		if se.Result == nil || se.ExpiresAt.IsZero() {
			return nil, ErrSnapshotInvalid
		}
		if !state.SavedAt.IsZero() && !se.ExpiresAt.After(state.SavedAt) {
			continue
		}
		key := cacheKey{token: se.Token, tenantID: se.TenantID}
		if _, exists := seenEntries[key]; exists {
			return nil, ErrSnapshotInvalid
		}
		seenEntries[key] = struct{}{}
		info := TokenInfo{
			Active:    se.Result.Active,
			Subject:   se.Result.Subject,
			TenantID:  se.Result.TenantID,
			ClientID:  se.Result.ClientID,
			Scope:     append([]string(nil), se.Result.Scope...),
			ExpiresAt: se.Result.ExpiresAt,
		}
		entry := &cacheEntry{key: key, info: cloneTokenInfo(info), expiresAt: se.ExpiresAt}
		c.entries[key] = c.lru.PushBack(entry)
	}

	seenRevocations := make(map[cacheKey]struct{}, len(state.Revocations))
	for _, sr := range state.Revocations {
		if sr.ExpiresAt.IsZero() {
			return nil, ErrSnapshotInvalid
		}
		if !state.SavedAt.IsZero() && !sr.ExpiresAt.After(state.SavedAt) {
			continue
		}
		key := cacheKey{token: sr.Token, tenantID: sr.TenantID}
		if _, exists := seenRevocations[key]; exists {
			return nil, ErrSnapshotInvalid
		}
		seenRevocations[key] = struct{}{}
		c.revocations[key] = sr.ExpiresAt
	}

	c.hits = state.Stats.Hits
	c.misses = state.Stats.Misses
	c.upstreamCalls = state.Stats.UpstreamCalls
	c.evictions = state.Stats.Evictions
	c.evictOverflowLocked()
	return c, nil
}

// Stats returns the current counters.
func (c *IntrospectionCache) Stats() CacheStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return CacheStats{
		Hits:          c.hits,
		Misses:        c.misses,
		UpstreamCalls: c.upstreamCalls,
		Evictions:     c.evictions,
		Revoked:       len(c.revocations),
		Entries:       c.lru.Len(),
	}
}

// ResetStats clears the cumulative cache counters. Cached entries and
// revocation markers are left untouched.
func (c *IntrospectionCache) ResetStats() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.hits = 0
	c.misses = 0
	c.upstreamCalls = 0
	c.evictions = 0
}
