package task

import (
	"errors"
	"time"
)

// errNotImplemented is returned by every stubbed operation.
var errNotImplemented = errors.New("not implemented")

// Neighbor cache states.
const (
	StateReachable = "reachable"
	StateStale     = "stale"
	StateProbe     = "probe"
)

// Errors reported by Process, Probe and Confirm.
var (
	ErrSpoof     = errors.New("ndp: mac does not match the binding")
	ErrInterface = errors.New("ndp: address active on another interface")
	ErrTenant    = errors.New("ndp: tenant mismatch")
	ErrQuota     = errors.New("ndp: per-mac address quota exceeded")
	ErrFull      = errors.New("ndp: neighbor cache full")
	ErrNotFound  = errors.New("ndp: neighbor not found")
	ErrState     = errors.New("ndp: neighbor in the wrong state")
	ErrInvalid   = errors.New("ndp: invalid advertisement")
)

// Config is the neighbor cache policy.
type Config struct {
	// MaxEntries caps the number of cached neighbors.
	MaxEntries int
	// MaxIPsPerMAC caps how many addresses one MAC may own.
	MaxIPsPerMAC int
	// ReachableTime is how long an entry stays reachable without traffic.
	ReachableTime time.Duration
	// StaleTime is how long a stale entry is kept before it is dropped.
	StaleTime time.Duration
	// AllowOverride lets a new advertisement move a dynamic entry to a new
	// MAC after probing; static bindings are never overridden.
	AllowOverride bool
}

// Neighbor is one neighbor cache entry.
type Neighbor struct {
	IP        string
	MAC       string
	Interface string
	TenantID  string
	State     string
	UpdatedAt time.Time
	Static    bool
}

// Advertisement is one neighbor advertisement observed on the wire.
type Advertisement struct {
	IP        string
	MAC       string
	Interface string
	TenantID  string
}

// Stats reports cache occupancy.
type Stats struct {
	Entries int
	Static  int
	Probes  int
}

// NdpGuard maintains a neighbor cache that resists spoofing, cache
// exhaustion and cross-interface takeover.
type NdpGuard struct {
	cfg Config
}

// NewNdpGuard returns a guard configured by cfg.
func NewNdpGuard(cfg Config) *NdpGuard {
	return &NdpGuard{cfg: cfg}
}

// NewNdpGuardFromSnapshot restores a guard, including static bindings and
// neighbor states, from a snapshot.
func NewNdpGuardFromSnapshot(cfg Config, data []byte) (*NdpGuard, error) {
	return nil, errNotImplemented
}

// Bind installs a static IP-to-MAC binding that advertisements may not
// override.
func (g *NdpGuard) Bind(ip, mac, iface, tenantID string) error {
	return errNotImplemented
}

// Process handles one neighbor advertisement: it creates, refreshes, moves or
// rejects the cache entry.
func (g *NdpGuard) Process(adv Advertisement, now time.Time) error {
	return errNotImplemented
}

// Lookup returns the current view of an entry, with reachability decayed to
// stale by the configured timers.
func (g *NdpGuard) Lookup(ip string, now time.Time) (Neighbor, bool) {
	return Neighbor{}, false
}

// Probe moves a stale entry into the probe state.
func (g *NdpGuard) Probe(ip string, now time.Time) error {
	return errNotImplemented
}

// Confirm completes a probe for the given MAC. A wrong MAC fails the probe
// and leaves the entry stale.
func (g *NdpGuard) Confirm(ip, mac string, now time.Time) error {
	return errNotImplemented
}

// Purge drops every entry of an interface and returns how many were removed.
func (g *NdpGuard) Purge(iface string) int {
	return 0
}

// Len returns the number of cached entries.
func (g *NdpGuard) Len() int {
	return 0
}

// Stats reports cache occupancy.
func (g *NdpGuard) Stats() Stats {
	return Stats{}
}

// Snapshot serialises the neighbor cache so that a restarted guard keeps its
// static bindings and entry states.
func (g *NdpGuard) Snapshot() ([]byte, error) {
	return nil, errNotImplemented
}
