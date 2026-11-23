package task

import (
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

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
	mu      sync.Mutex
	cfg     Config
	entries map[string]*Neighbor
}

type snapshotData struct {
	Version int        `json:"version"`
	Entries []Neighbor `json:"entries"`
}

const snapshotVersion = 1

// NewNdpGuard returns a guard configured by cfg.
func NewNdpGuard(cfg Config) *NdpGuard {
	return &NdpGuard{
		cfg:     cfg,
		entries: make(map[string]*Neighbor),
	}
}

// NewNdpGuardFromSnapshot restores a guard, including static bindings and
// neighbor states, from a snapshot.
func NewNdpGuardFromSnapshot(cfg Config, data []byte) (*NdpGuard, error) {
	if len(data) == 0 {
		return nil, ErrInvalid
	}

	var snap snapshotData
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, ErrInvalid
	}
	if snap.Version != snapshotVersion {
		return nil, ErrInvalid
	}

	g := NewNdpGuard(cfg)
	for _, entry := range snap.Entries {
		ip, ok := normalizeIP(entry.IP)
		if !ok {
			return nil, ErrInvalid
		}
		mac, ok := normalizeMAC(entry.MAC)
		if !ok || entry.Interface == "" || entry.TenantID == "" {
			return nil, ErrInvalid
		}
		if entry.State != StateReachable && entry.State != StateStale && entry.State != StateProbe {
			return nil, ErrInvalid
		}
		if entry.Static && entry.State != StateReachable {
			return nil, ErrInvalid
		}
		if _, exists := g.entries[ip]; exists {
			return nil, ErrInvalid
		}

		entry.IP = ip
		entry.MAC = mac
		g.entries[ip] = &entry
	}

	if cfg.MaxEntries > 0 && len(g.entries) > cfg.MaxEntries {
		return nil, ErrInvalid
	}
	if cfg.MaxIPsPerMAC > 0 {
		perMAC := make(map[string]int)
		for _, entry := range g.entries {
			perMAC[entry.MAC]++
			if perMAC[entry.MAC] > cfg.MaxIPsPerMAC {
				return nil, ErrInvalid
			}
		}
	}

	return g, nil
}

// Bind installs a static IP-to-MAC binding that advertisements may not
// override.
func (g *NdpGuard) Bind(ip, mac, iface, tenantID string) error {
	ip, ipOK := normalizeIP(ip)
	mac, macOK := normalizeMAC(mac)
	if !ipOK || !macOK || iface == "" || tenantID == "" {
		return ErrInvalid
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	if existing, ok := g.entries[ip]; ok {
		if existing.Static {
			if existing.MAC != mac {
				return ErrSpoof
			}
			return nil
		}
		if existing.MAC != mac {
			return ErrSpoof
		}

		existing.Interface = iface
		existing.TenantID = tenantID
		existing.State = StateReachable
		existing.Static = true
		existing.UpdatedAt = time.Now()
		return nil
	}

	if g.cfg.MaxEntries > 0 && len(g.entries) >= g.cfg.MaxEntries {
		return ErrFull
	}
	if g.cfg.MaxIPsPerMAC > 0 && g.countMACLocked(mac) >= g.cfg.MaxIPsPerMAC {
		return ErrQuota
	}

	g.entries[ip] = &Neighbor{
		IP:        ip,
		MAC:       mac,
		Interface: iface,
		TenantID:  tenantID,
		State:     StateReachable,
		UpdatedAt: time.Now(),
		Static:    true,
	}
	return nil
}

// Process handles one neighbor advertisement: it creates, refreshes, moves or
// rejects the cache entry.
func (g *NdpGuard) Process(adv Advertisement, now time.Time) error {
	ip, ipOK := normalizeIP(adv.IP)
	mac, macOK := normalizeMAC(adv.MAC)
	if !ipOK || !macOK || adv.Interface == "" || adv.TenantID == "" {
		return ErrInvalid
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	if existing, ok := g.entries[ip]; ok {
		_, alive := g.effectiveStateLocked(existing, now)
		if alive {
			if existing.TenantID != adv.TenantID {
				return ErrTenant
			}
			if existing.Interface != adv.Interface {
				return ErrInterface
			}
			if existing.Static {
				if existing.MAC != mac {
					return ErrSpoof
				}
				return nil
			}
			if existing.MAC != mac {
				if !g.cfg.AllowOverride {
					return ErrSpoof
				}
				if g.cfg.MaxIPsPerMAC > 0 && g.countActiveMACLocked(mac, now) >= g.cfg.MaxIPsPerMAC {
					return ErrQuota
				}

				existing.MAC = mac
				existing.State = StateStale
				existing.UpdatedAt = now
				return nil
			}

			existing.State = StateReachable
			existing.UpdatedAt = now
			return nil
		}
	}

	if g.cfg.MaxIPsPerMAC > 0 && g.countActiveMACLocked(mac, now) >= g.cfg.MaxIPsPerMAC {
		return ErrQuota
	}
	if g.cfg.MaxEntries > 0 && len(g.entries) >= g.cfg.MaxEntries {
		if !g.evictOldestStaleLocked(now) {
			return ErrFull
		}
	}

	g.entries[ip] = &Neighbor{
		IP:        ip,
		MAC:       mac,
		Interface: adv.Interface,
		TenantID:  adv.TenantID,
		State:     StateReachable,
		UpdatedAt: now,
	}
	return nil
}

// Lookup returns the current view of an entry, with reachability decayed to
// stale by the configured timers.
func (g *NdpGuard) Lookup(ip string, now time.Time) (Neighbor, bool) {
	ip, ok := normalizeIP(ip)
	if !ok {
		return Neighbor{}, false
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	entry, ok := g.entries[ip]
	if !ok {
		return Neighbor{}, false
	}

	state, alive := g.effectiveStateLocked(entry, now)
	if !alive {
		delete(g.entries, ip)
		return Neighbor{}, false
	}
	entry.State = state

	view := *entry
	return view, true
}

// Probe moves a stale entry into the probe state.
func (g *NdpGuard) Probe(ip string, now time.Time) error {
	ip, ok := normalizeIP(ip)
	if !ok {
		return ErrInvalid
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	entry, ok := g.entries[ip]
	if !ok {
		return ErrNotFound
	}
	state, alive := g.effectiveStateLocked(entry, now)
	if !alive {
		delete(g.entries, ip)
		return ErrNotFound
	}
	if state != StateStale {
		return ErrState
	}

	entry.State = StateProbe
	return nil
}

// Confirm completes a probe for the given MAC. A wrong MAC fails the probe
// and leaves the entry stale.
func (g *NdpGuard) Confirm(ip, mac string, now time.Time) error {
	ip, ipOK := normalizeIP(ip)
	mac, macOK := normalizeMAC(mac)
	if !ipOK || !macOK {
		return ErrInvalid
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	entry, ok := g.entries[ip]
	if !ok {
		return ErrNotFound
	}
	state, alive := g.effectiveStateLocked(entry, now)
	if !alive {
		delete(g.entries, ip)
		return ErrNotFound
	}
	if state != StateProbe {
		return ErrState
	}
	if entry.MAC != mac {
		entry.State = StateStale
		return ErrSpoof
	}

	entry.State = StateReachable
	entry.UpdatedAt = now
	return nil
}

// Purge drops every entry of an interface and returns how many were removed.
func (g *NdpGuard) Purge(iface string) int {
	g.mu.Lock()
	defer g.mu.Unlock()

	removed := 0
	for ip, entry := range g.entries {
		if entry.Interface == iface {
			delete(g.entries, ip)
			removed++
		}
	}
	return removed
}

// Len returns the number of cached entries.
func (g *NdpGuard) Len() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.entries)
}

// Stats reports cache occupancy.
func (g *NdpGuard) Stats() Stats {
	g.mu.Lock()
	defer g.mu.Unlock()

	stats := Stats{Entries: len(g.entries)}
	for _, entry := range g.entries {
		if entry.Static {
			stats.Static++
		}
		if entry.State == StateProbe {
			stats.Probes++
		}
	}
	return stats
}

// Snapshot serialises the neighbor cache so that a restarted guard keeps its
// static bindings and entry states.
func (g *NdpGuard) Snapshot() ([]byte, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	ips := make([]string, 0, len(g.entries))
	for ip := range g.entries {
		ips = append(ips, ip)
	}
	sort.Strings(ips)

	snap := snapshotData{
		Version: snapshotVersion,
		Entries: make([]Neighbor, 0, len(ips)),
	}
	for _, ip := range ips {
		snap.Entries = append(snap.Entries, *g.entries[ip])
	}
	return json.Marshal(snap)
}

func (g *NdpGuard) countMACLocked(mac string) int {
	count := 0
	for _, entry := range g.entries {
		if entry.MAC == mac {
			count++
		}
	}
	return count
}

func (g *NdpGuard) countActiveMACLocked(mac string, now time.Time) int {
	count := 0
	for _, entry := range g.entries {
		if entry.MAC != mac {
			continue
		}
		if _, alive := g.effectiveStateLocked(entry, now); alive {
			count++
		}
	}
	return count
}

func (g *NdpGuard) effectiveStateLocked(entry *Neighbor, now time.Time) (string, bool) {
	if entry.Static {
		return StateReachable, true
	}

	age := now.Sub(entry.UpdatedAt)
	if age < 0 {
		age = 0
	}
	expiry := g.cfg.ReachableTime + g.cfg.StaleTime

	switch entry.State {
	case StateProbe:
		if age > expiry {
			return "", false
		}
		return StateProbe, true
	case StateStale:
		if age > expiry {
			return "", false
		}
		return StateStale, true
	case StateReachable:
		if age > expiry {
			return "", false
		}
		if age > g.cfg.ReachableTime {
			return StateStale, true
		}
		return StateReachable, true
	default:
		return "", false
	}
}

func (g *NdpGuard) evictOldestStaleLocked(now time.Time) bool {
	var candidates []*Neighbor
	for _, entry := range g.entries {
		if entry.Static {
			continue
		}
		state, alive := g.effectiveStateLocked(entry, now)
		if !alive || state == StateStale {
			candidates = append(candidates, entry)
		}
	}
	if len(candidates) == 0 {
		return false
	}

	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].UpdatedAt.Equal(candidates[j].UpdatedAt) {
			return candidates[i].IP < candidates[j].IP
		}
		return candidates[i].UpdatedAt.Before(candidates[j].UpdatedAt)
	})
	delete(g.entries, candidates[0].IP)
	return true
}

func normalizeIP(value string) (string, bool) {
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return "", false
	}
	return addr.String(), true
}

func normalizeMAC(value string) (string, bool) {
	hardware, err := net.ParseMAC(value)
	if err != nil || len(hardware) != 6 {
		return "", false
	}
	return strings.ToLower(hardware.String()), true
}
