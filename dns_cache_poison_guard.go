package task

import (
	"errors"
	"time"
)

var errNotImplemented = errors.New("not implemented")

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
}

// NewDnsCacheGuard returns an empty cache governed by cfg.
func NewDnsCacheGuard(cfg Config) *DnsCacheGuard {
	return &DnsCacheGuard{cfg: cfg}
}

// NewDnsCacheGuardFromSnapshot restores a cache, including absolute expiry
// times, from data produced by Snapshot.
func NewDnsCacheGuardFromSnapshot(cfg Config, data []byte) (*DnsCacheGuard, error) {
	return nil, errNotImplemented
}

// InBailiwick reports whether name equals zone or is a label-boundary
// subdomain of zone. Comparison is case-insensitive and ignores one trailing
// dot on either argument.
func (c *DnsCacheGuard) InBailiwick(zone, name string) bool {
	return false
}

// Insert caches one record that arrived from the nameserver of zone.
func (c *DnsCacheGuard) Insert(zone string, rr RR, now time.Time) error {
	return errNotImplemented
}

// InsertResponse caches every answer of resp atomically: either all answers
// are cached or none is.
func (c *DnsCacheGuard) InsertResponse(resp Response, now time.Time) (int, error) {
	return 0, errNotImplemented
}

// Lookup returns the live records cached for name and qtype.
func (c *DnsCacheGuard) Lookup(name string, qtype uint16, now time.Time) ([]RR, error) {
	return nil, errNotImplemented
}

// Delete removes every cached record and negative entry for name and returns
// how many keys were dropped.
func (c *DnsCacheGuard) Delete(name string) int {
	return 0
}

// Len returns the number of cached keys.
func (c *DnsCacheGuard) Len() int {
	return 0
}

// PurgeExpired drops expired records and negative entries, returning the
// number of keys removed.
func (c *DnsCacheGuard) PurgeExpired(now time.Time) int {
	return 0
}

// Stats returns the current counters.
func (c *DnsCacheGuard) Stats() Stats {
	return Stats{}
}

// Snapshot serialises all live entries with their absolute expiry times.
func (c *DnsCacheGuard) Snapshot() ([]byte, error) {
	return nil, errNotImplemented
}
