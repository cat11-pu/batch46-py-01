package task

import (
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"
)

// Sentinel errors returned by DnsCacheGuard.
var (
	// ErrBailiwick means the record or question is outside the zone that
	// answered it.
	ErrBailiwick = errors.New("dns: record outside the authoritative zone")
	// ErrTTLZero means a record with TTL 0 was offered for caching.
	ErrTTLZero = errors.New("dns: zero ttl record is not cacheable")
	// ErrCacheFull means no capacity was available for a new cache key.
	ErrCacheFull = errors.New("dns: cache entry limit reached")
	// ErrNotFound means no live record matches the lookup.
	ErrNotFound = errors.New("dns: record not found")
	// ErrNXDomain means a negative cached entry is still live.
	ErrNXDomain = errors.New("dns: negatively cached name")
	// ErrBadClass means the record class is not IN.
	ErrBadClass = errors.New("dns: unsupported record class")
	// ErrCorruptSnapshot means a snapshot could not be decoded.
	ErrCorruptSnapshot = errors.New("dns: corrupt snapshot")
)

// Record types and classes used by the cache.
const (
	TypeA     uint16 = 1
	TypeNS    uint16 = 2
	TypeCNAME uint16 = 5
	TypeTXT   uint16 = 16
	TypeAAAA  uint16 = 28
	ClassIN   uint16 = 1
)

// Config holds cache policy.
type Config struct {
	// MaxEntries is the maximum number of cached keys (name, type).
	MaxEntries int
	// MinTTL is the lower bound applied to positive record TTLs.
	MinTTL time.Duration
	// MaxTTL is the upper bound applied to positive record TTLs.
	MaxTTL time.Duration
	// NegativeTTL is how long an NXDOMAIN answer is remembered.
	NegativeTTL time.Duration
}

// RR is one resource record of an upstream answer.
type RR struct {
	// Name is the owner name; matching is case-insensitive and ignores a
	// single trailing dot.
	Name string
	// Type is one of TypeA, TypeNS, TypeCNAME, TypeTXT, TypeAAAA.
	Type uint16
	// Class must be ClassIN.
	Class uint16
	// TTL is the record lifetime in seconds as sent upstream.
	TTL uint32
	// RData is the record payload.
	RData string
}

// Response is a single upstream answer for one question.
type Response struct {
	// Zone is the zone whose nameserver produced the answer.
	Zone string
	// QuestionName is the queried name.
	QuestionName string
	// QuestionType is the queried type.
	QuestionType uint16
	// Answers are the answer section records.
	Answers []RR
	// NXDomain marks a negative answer for QuestionName.
	NXDomain bool
}

// Stats is a counter snapshot.
type Stats struct {
	Entries  int
	Hits     int
	Misses   int
	Rejected int
}

// DnsCacheGuard caches DNS records but only accepts data inside the
// bailiwick of the zone that answered.
type DnsCacheGuard struct {
	cfg Config

	mu        sync.Mutex
	entries   map[cacheKey]*cacheEntry
	negatives map[string]time.Time
	hits      int
	misses    int
	rejected  int
}

// cacheKey identifies one cached RRset: owner name plus record type.
type cacheKey struct {
	name string
	typ  uint16
}

// cacheEntry is one RRset with its absolute expiry time.
type cacheEntry struct {
	records   []RR
	expiresAt time.Time
}

// NewDnsCacheGuard returns an empty cache governed by cfg.
func NewDnsCacheGuard(cfg Config) *DnsCacheGuard {
	return &DnsCacheGuard{
		cfg:       cfg,
		entries:   make(map[cacheKey]*cacheEntry),
		negatives: make(map[string]time.Time),
	}
}

// snapshotVersion tags the serialised layout so future readers can reject
// foreign data instead of mis-decoding it.
const snapshotVersion = 1

type snapshotFile struct {
	Version   int               `json:"version"`
	Entries   []snapshotEntry   `json:"entries"`
	Negatives []snapshotNegative `json:"negatives"`
	Hits      int               `json:"hits"`
	Misses    int               `json:"misses"`
	Rejected  int               `json:"rejected"`
}

type snapshotEntry struct {
	Name      string `json:"name"`
	Type      uint16 `json:"type"`
	Records   []RR   `json:"records"`
	ExpiresAt int64  `json:"expires_at_unix_nano"`
}

type snapshotNegative struct {
	Name      string `json:"name"`
	ExpiresAt int64  `json:"expires_at_unix_nano"`
}

// NewDnsCacheGuardFromSnapshot restores a cache, including absolute expiry
// times, from data produced by Snapshot.
func NewDnsCacheGuardFromSnapshot(cfg Config, data []byte) (*DnsCacheGuard, error) {
	if len(data) == 0 {
		return nil, ErrCorruptSnapshot
	}
	var file snapshotFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, ErrCorruptSnapshot
	}
	if file.Version != snapshotVersion {
		return nil, ErrCorruptSnapshot
	}
	// Build the whole state locally first: either the restore succeeds as a
	// whole or the constructor fails and no half-built cache escapes.
	entries := make(map[cacheKey]*cacheEntry, len(file.Entries))
	for _, se := range file.Entries {
		name := normalizeName(se.Name)
		if name == "" || len(se.Records) == 0 {
			return nil, ErrCorruptSnapshot
		}
		records := make([]RR, len(se.Records))
		copy(records, se.Records)
		entries[cacheKey{name: name, typ: se.Type}] = &cacheEntry{
			records:   records,
			expiresAt: time.Unix(0, se.ExpiresAt),
		}
	}
	negatives := make(map[string]time.Time, len(file.Negatives))
	for _, sn := range file.Negatives {
		name := normalizeName(sn.Name)
		if name == "" {
			return nil, ErrCorruptSnapshot
		}
		negatives[name] = time.Unix(0, sn.ExpiresAt)
	}
	return &DnsCacheGuard{
		cfg:       cfg,
		entries:   entries,
		negatives: negatives,
		hits:      file.Hits,
		misses:    file.Misses,
		rejected:  file.Rejected,
	}, nil
}

// normalizeName lowercases a DNS name and strips a single trailing dot so
// that "WWW.Example.COM." and "www.example.com" identify the same owner.
func normalizeName(name string) string {
	name = strings.TrimSuffix(name, ".")
	return strings.ToLower(name)
}

// InBailiwick reports whether name equals zone or is a label-boundary
// subdomain of zone. Comparison is case-insensitive and ignores one trailing
// dot on either argument.
func (c *DnsCacheGuard) InBailiwick(zone, name string) bool {
	zone = normalizeName(zone)
	name = normalizeName(name)
	if zone == "" || name == "" {
		return false
	}
	return name == zone || strings.HasSuffix(name, "."+zone)
}

// clampTTL bounds a positive TTL by the configured MinTTL/MaxTTL.
func (c *DnsCacheGuard) clampTTL(ttl uint32) time.Duration {
	d := time.Duration(ttl) * time.Second
	if c.cfg.MinTTL > 0 && d < c.cfg.MinTTL {
		d = c.cfg.MinTTL
	}
	if c.cfg.MaxTTL > 0 && d > c.cfg.MaxTTL {
		d = c.cfg.MaxTTL
	}
	return d
}

// validateRecord checks a single record against the answering zone. The
// caller must hold c.mu; rejections are counted here so no path can forget.
func (c *DnsCacheGuard) validateRecord(zone string, rr RR) error {
	if !c.InBailiwick(zone, rr.Name) {
		return ErrBailiwick
	}
	if rr.Class != ClassIN {
		return ErrBadClass
	}
	if rr.TTL == 0 {
		return ErrTTLZero
	}
	return nil
}

// purgeExpiredLocked drops expired entries and negatives as of now and
// returns how many keys were removed. The caller must hold c.mu.
func (c *DnsCacheGuard) purgeExpiredLocked(now time.Time) int {
	removed := 0
	for key, entry := range c.entries {
		if !now.Before(entry.expiresAt) {
			delete(c.entries, key)
			removed++
		}
	}
	for name, expiresAt := range c.negatives {
		if !now.Before(expiresAt) {
			delete(c.negatives, name)
			removed++
		}
	}
	return removed
}

// insertLocked stores rr under its (name, type) key, merging into an
// existing RRset by deduplicating on RData and keeping the earliest expiry.
// The caller must hold c.mu and must already have validated the record.
func (c *DnsCacheGuard) insertLocked(rr RR, expiresAt time.Time) {
	key := cacheKey{name: normalizeName(rr.Name), typ: rr.Type}
	stored := rr
	stored.Name = key.name
	entry, ok := c.entries[key]
	if !ok {
		c.entries[key] = &cacheEntry{records: []RR{stored}, expiresAt: expiresAt}
		return
	}
	for _, existing := range entry.records {
		if existing.RData == stored.RData {
			if expiresAt.Before(entry.expiresAt) {
				entry.expiresAt = expiresAt
			}
			return
		}
	}
	entry.records = append(entry.records, stored)
	if expiresAt.Before(entry.expiresAt) {
		entry.expiresAt = expiresAt
	}
}

// Insert caches one record that arrived from the nameserver of zone.
func (c *DnsCacheGuard) Insert(zone string, rr RR, now time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.validateRecord(zone, rr); err != nil {
		c.rejected++
		return err
	}
	c.purgeExpiredLocked(now)
	key := cacheKey{name: normalizeName(rr.Name), typ: rr.Type}
	if _, ok := c.entries[key]; !ok && c.cfg.MaxEntries > 0 && len(c.entries) >= c.cfg.MaxEntries {
		c.rejected++
		return ErrCacheFull
	}
	c.insertLocked(rr, now.Add(c.clampTTL(rr.TTL)))
	return nil
}

// InsertResponse caches every answer of resp atomically: either all answers
// are cached or none is.
func (c *DnsCacheGuard) InsertResponse(resp Response, now time.Time) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if resp.NXDomain {
		if !c.InBailiwick(resp.Zone, resp.QuestionName) {
			c.rejected++
			return 0, ErrBailiwick
		}
		c.purgeExpiredLocked(now)
		if c.cfg.NegativeTTL > 0 {
			c.negatives[normalizeName(resp.QuestionName)] = now.Add(c.cfg.NegativeTTL)
		}
		return 0, nil
	}

	// Validate the whole response before touching the cache so a single
	// poisoned record aborts everything and nothing half-lands.
	for _, rr := range resp.Answers {
		if err := c.validateRecord(resp.Zone, rr); err != nil {
			c.rejected++
			return 0, err
		}
	}
	c.purgeExpiredLocked(now)
	if c.cfg.MaxEntries > 0 {
		newKeys := make(map[cacheKey]struct{})
		for _, rr := range resp.Answers {
			key := cacheKey{name: normalizeName(rr.Name), typ: rr.Type}
			if _, ok := c.entries[key]; !ok {
				newKeys[key] = struct{}{}
			}
		}
		if len(c.entries)+len(newKeys) > c.cfg.MaxEntries {
			c.rejected++
			return 0, ErrCacheFull
		}
	}
	for _, rr := range resp.Answers {
		c.insertLocked(rr, now.Add(c.clampTTL(rr.TTL)))
	}
	return len(resp.Answers), nil
}

// Lookup returns the live records cached for name and qtype.
func (c *DnsCacheGuard) Lookup(name string, qtype uint16, now time.Time) ([]RR, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	normalized := normalizeName(name)
	key := cacheKey{name: normalized, typ: qtype}
	if entry, ok := c.entries[key]; ok {
		if now.Before(entry.expiresAt) {
			c.hits++
			records := make([]RR, len(entry.records))
			copy(records, entry.records)
			return records, nil
		}
		delete(c.entries, key)
	}
	if expiresAt, ok := c.negatives[normalized]; ok {
		if now.Before(expiresAt) {
			c.hits++
			return nil, ErrNXDomain
		}
		delete(c.negatives, normalized)
	}
	c.misses++
	return nil, ErrNotFound
}

// Delete removes every cached record and negative entry for name and returns
// how many keys were dropped.
func (c *DnsCacheGuard) Delete(name string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	normalized := normalizeName(name)
	removed := 0
	for key := range c.entries {
		if key.name == normalized {
			delete(c.entries, key)
			removed++
		}
	}
	if _, ok := c.negatives[normalized]; ok {
		delete(c.negatives, normalized)
		removed++
	}
	return removed
}

// Len returns the number of cached keys.
func (c *DnsCacheGuard) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// PurgeExpired drops expired records and negative entries, returning the
// number of keys removed.
func (c *DnsCacheGuard) PurgeExpired(now time.Time) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.purgeExpiredLocked(now)
}

// Stats returns the current counters.
func (c *DnsCacheGuard) Stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return Stats{
		Entries:  len(c.entries),
		Hits:     c.hits,
		Misses:   c.misses,
		Rejected: c.rejected,
	}
}

// Snapshot serialises all live entries with their absolute expiry times.
func (c *DnsCacheGuard) Snapshot() ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	file := snapshotFile{
		Version:   snapshotVersion,
		Entries:   make([]snapshotEntry, 0, len(c.entries)),
		Negatives: make([]snapshotNegative, 0, len(c.negatives)),
		Hits:      c.hits,
		Misses:    c.misses,
		Rejected:  c.rejected,
	}
	for key, entry := range c.entries {
		records := make([]RR, len(entry.records))
		copy(records, entry.records)
		file.Entries = append(file.Entries, snapshotEntry{
			Name:      key.name,
			Type:      key.typ,
			Records:   records,
			ExpiresAt: entry.expiresAt.UnixNano(),
		})
	}
	for name, expiresAt := range c.negatives {
		file.Negatives = append(file.Negatives, snapshotNegative{
			Name:      name,
			ExpiresAt: expiresAt.UnixNano(),
		})
	}
	return json.Marshal(file)
}
