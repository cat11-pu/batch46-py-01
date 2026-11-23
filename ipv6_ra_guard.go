package task

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

// Errors reported by Process. Each one names the policy that a rogue Router
// Advertisement violated so that the caller can count them separately.
var (
	ErrPort           = errors.New("ra: advertisement received on an untrusted port")
	ErrRouter         = errors.New("ra: router not trusted")
	ErrTenant         = errors.New("ra: tenant mismatch")
	ErrHopLimit       = errors.New("ra: hop limit is not 255")
	ErrLifetime       = errors.New("ra: router lifetime out of policy")
	ErrPrefixLen      = errors.New("ra: prefix length out of policy")
	ErrULA            = errors.New("ra: unique local prefix not allowed")
	ErrManaged        = errors.New("ra: managed flag not allowed")
	ErrPrefixLifetime = errors.New("ra: prefix lifetime inconsistent")
	ErrRate           = errors.New("ra: advertisement rate exceeded")
	ErrCapacity       = errors.New("ra: router table full")
	ErrInvalid        = errors.New("ra: invalid advertisement")
)

// Config is the Router Advertisement screening policy.
type Config struct {
	// MaxRouterLifetime caps the lifetime a router may claim.
	MaxRouterLifetime time.Duration
	// MinAdvertInterval is the minimum spacing between two advertisements
	// from the same router.
	MinAdvertInterval time.Duration
	// PrefixLength is the only prefix length accepted for SLAAC.
	PrefixLength int
	// AllowULA permits unique local prefixes.
	AllowULA bool
	// AllowManaged permits the managed address configuration flag.
	AllowManaged bool
	// MaxRouters caps the learned default router table.
	MaxRouters int
}

// PrefixInfo is one Prefix Information Option carried by an advertisement.
type PrefixInfo struct {
	CIDR              string
	ValidLifetime     time.Duration
	PreferredLifetime time.Duration
	Autonomous        bool
	OnLink            bool
}

// RouterAdvert is one Router Advertisement as seen on the wire.
type RouterAdvert struct {
	Source         string
	Interface      string
	TenantID       string
	HopLimit       int
	RouterLifetime time.Duration
	ManagedFlag    bool
	OtherFlag      bool
	Preference     string
	Prefixes       []PrefixInfo
}

// Router is one learned default router.
type Router struct {
	Address   string
	Interface string
	TenantID  string
	Lifetime  time.Duration
	LearnedAt time.Time
}

// Stats reports guard occupancy.
type Stats struct {
	Routers  int
	Prefixes int
}

// RaGuard screens Router Advertisements and keeps the learned default
// router table and prefix table.
type RaGuard struct {
	mu sync.RWMutex

	cfg Config

	trustedPorts   map[string]struct{}
	trustedRouters map[string]string
	routers        map[string]routerEntry
	prefixes       map[string]prefixEntry
	lastSeen       map[string]time.Time
}

type routerEntry struct {
	Address   string
	Interface string
	TenantID  string
	Lifetime  time.Duration
	LearnedAt time.Time
	ExpiresAt time.Time
}

type prefixEntry struct {
	CIDR           string
	ValidUntil     time.Time
	PreferredUntil time.Time
}

// NewRaGuard returns a guard configured by cfg.
func NewRaGuard(cfg Config) *RaGuard {
	return &RaGuard{
		cfg:            normalizeConfig(cfg),
		trustedPorts:   make(map[string]struct{}),
		trustedRouters: make(map[string]string),
		routers:        make(map[string]routerEntry),
		prefixes:       make(map[string]prefixEntry),
		lastSeen:       make(map[string]time.Time),
	}
}

// NewRaGuardFromSnapshot restores a guard, including trusted ports, trusted
// routers, learned routers and prefixes, from a snapshot.
func NewRaGuardFromSnapshot(cfg Config, data []byte) (*RaGuard, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: empty snapshot", ErrInvalid)
	}

	var snap snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if snap.Version != snapshotVersion {
		return nil, fmt.Errorf("%w: unsupported snapshot version %d", ErrInvalid, snap.Version)
	}

	g := NewRaGuard(cfg)
	for _, port := range snap.TrustedPorts {
		if port == "" {
			return nil, fmt.Errorf("%w: empty trusted port", ErrInvalid)
		}
		g.trustedPorts[port] = struct{}{}
	}
	for addr, tenant := range snap.TrustedRouters {
		normalized, ok := normalizeLinkLocal(addr)
		if !ok || tenant == "" {
			return nil, fmt.Errorf("%w: invalid trusted router", ErrInvalid)
		}
		g.trustedRouters[normalized] = tenant
	}
	for _, r := range snap.Routers {
		addr, ok := normalizeLinkLocal(r.Address)
		if !ok || r.Interface == "" || r.Lifetime < 0 {
			return nil, fmt.Errorf("%w: invalid router", ErrInvalid)
		}
		g.routers[addr] = routerEntry{
			Address:   addr,
			Interface: r.Interface,
			TenantID:  r.TenantID,
			Lifetime:  r.Lifetime,
			LearnedAt: r.LearnedAt,
			ExpiresAt: r.ExpiresAt,
		}
	}
	for _, p := range snap.Prefixes {
		cidr, ok := normalizeIPv6Network(p.CIDR)
		if !ok {
			return nil, fmt.Errorf("%w: invalid prefix", ErrInvalid)
		}
		g.prefixes[cidr] = prefixEntry{
			CIDR:           cidr,
			ValidUntil:     p.ValidUntil,
			PreferredUntil: p.PreferredUntil,
		}
	}
	for addr, seen := range snap.LastSeen {
		normalized, ok := normalizeLinkLocal(addr)
		if !ok {
			return nil, fmt.Errorf("%w: invalid rate limit entry", ErrInvalid)
		}
		g.lastSeen[normalized] = seen
	}

	return g, nil
}

// TrustPort allows advertisements received on the named interface.
func (g *RaGuard) TrustPort(ifName string) error {
	if ifName == "" {
		return fmt.Errorf("%w: empty interface", ErrInvalid)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.trustedPorts[ifName] = struct{}{}
	return nil
}

// UntrustPort removes an interface from the trusted set.
func (g *RaGuard) UntrustPort(ifName string) error {
	if ifName == "" {
		return fmt.Errorf("%w: empty interface", ErrInvalid)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.trustedPorts, ifName)
	return nil
}

// TrustRouter trusts the link-local address for a tenant.
func (g *RaGuard) TrustRouter(linkLocal, tenantID string) error {
	addr, ok := normalizeLinkLocal(linkLocal)
	if !ok || tenantID == "" {
		return fmt.Errorf("%w: invalid trusted router", ErrInvalid)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.trustedRouters[addr] = tenantID
	return nil
}

// Revoke removes a router from the trusted set and from the learned table.
func (g *RaGuard) Revoke(linkLocal string) error {
	addr, ok := normalizeLinkLocal(linkLocal)
	if !ok {
		return fmt.Errorf("%w: invalid router address", ErrInvalid)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.trustedRouters, addr)
	delete(g.routers, addr)
	delete(g.lastSeen, addr)
	return nil
}

// Process validates one advertisement and, when accepted, updates the
// default router table and the prefix table.
func (g *RaGuard) Process(ra RouterAdvert, now time.Time) error {
	if ra.Interface == "" {
		return fmt.Errorf("%w: empty interface", ErrInvalid)
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	if _, trusted := g.trustedPorts[ra.Interface]; !trusted {
		return ErrPort
	}
	src, ok := normalizeLinkLocal(ra.Source)
	if !ok {
		if ra.Source == "" || net.ParseIP(ra.Source) == nil {
			return fmt.Errorf("%w: invalid source", ErrInvalid)
		}
		// A syntactically valid but non-link-local address cannot be trusted.
		return ErrRouter
	}
	tenant, trusted := g.trustedRouters[src]
	if !trusted {
		return ErrRouter
	}
	if ra.TenantID == "" || ra.TenantID != tenant {
		return ErrTenant
	}
	if ra.HopLimit != 255 {
		return ErrHopLimit
	}
	if ra.RouterLifetime < 0 ||
		(g.cfg.MaxRouterLifetime > 0 && ra.RouterLifetime > g.cfg.MaxRouterLifetime) {
		return ErrLifetime
	}
	if ra.ManagedFlag && !g.cfg.AllowManaged {
		return ErrManaged
	}

	pending, err := g.validatePrefixes(ra)
	if err != nil {
		return err
	}
	for _, p := range pending {
		if !g.cfg.AllowULA && isULA(p.network) {
			return ErrULA
		}
	}

	if ra.RouterLifetime > 0 {
		if _, exists := g.routers[src]; !exists &&
			g.cfg.MaxRouters > 0 && len(g.routers) >= g.cfg.MaxRouters {
			return ErrCapacity
		}
	}

	if g.cfg.MinAdvertInterval > 0 {
		if last, seen := g.lastSeen[src]; seen &&
			now.Before(last.Add(g.cfg.MinAdvertInterval)) {
			return ErrRate
		}
	}

	// All policy checks passed. Commit the advertisement atomically.
	if ra.RouterLifetime == 0 {
		delete(g.routers, src)
	} else {
		g.routers[src] = routerEntry{
			Address:   src,
			Interface: ra.Interface,
			TenantID:  ra.TenantID,
			Lifetime:  ra.RouterLifetime,
			LearnedAt: now,
			ExpiresAt: now.Add(ra.RouterLifetime),
		}
	}

	for _, p := range pending {
		if p.info.ValidLifetime == 0 {
			delete(g.prefixes, p.cidr)
			continue
		}
		g.prefixes[p.cidr] = prefixEntry{
			CIDR:           p.cidr,
			ValidUntil:     now.Add(p.info.ValidLifetime),
			PreferredUntil: now.Add(p.info.PreferredLifetime),
		}
	}
	g.lastSeen[src] = now

	return nil
}

// DefaultRouters returns the routers that are still default at now, sorted
// by address.
func (g *RaGuard) DefaultRouters(now time.Time) []Router {
	g.mu.RLock()
	defer g.mu.RUnlock()

	out := make([]Router, 0, len(g.routers))
	for _, r := range g.routers {
		if !now.Before(r.ExpiresAt) {
			continue
		}
		out = append(out, Router{
			Address:   r.Address,
			Interface: r.Interface,
			TenantID:  r.TenantID,
			Lifetime:  r.Lifetime,
			LearnedAt: r.LearnedAt,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Address < out[j].Address })
	return out
}

// IsDefaultRouter reports whether addr is a live default router at now.
func (g *RaGuard) IsDefaultRouter(addr string, now time.Time) bool {
	normalized, ok := normalizeLinkLocal(addr)
	if !ok {
		return false
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	r, exists := g.routers[normalized]
	return exists && now.Before(r.ExpiresAt)
}

// LearnedPrefixes returns the live prefixes at now, sorted.
func (g *RaGuard) LearnedPrefixes(now time.Time) []string {
	g.mu.RLock()
	defer g.mu.RUnlock()

	out := make([]string, 0, len(g.prefixes))
	for cidr, p := range g.prefixes {
		if now.Before(p.ValidUntil) {
			out = append(out, cidr)
		}
	}
	sort.Strings(out)
	return out
}

// Sweep removes expired routers and prefixes and returns the number of
// routers removed.
func (g *RaGuard) Sweep(now time.Time) int {
	g.mu.Lock()
	defer g.mu.Unlock()

	removed := 0
	for addr, r := range g.routers {
		if !now.Before(r.ExpiresAt) {
			delete(g.routers, addr)
			removed++
		}
	}
	for cidr, p := range g.prefixes {
		if !now.Before(p.ValidUntil) {
			delete(g.prefixes, cidr)
		}
	}
	return removed
}

// Stats reports the number of learned routers and prefixes.
func (g *RaGuard) Stats() Stats {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return Stats{Routers: len(g.routers), Prefixes: len(g.prefixes)}
}

// Snapshot serialises the trusted configuration and the learned tables.
func (g *RaGuard) Snapshot() ([]byte, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	snap := snapshot{
		Version:        snapshotVersion,
		TrustedPorts:   make([]string, 0, len(g.trustedPorts)),
		TrustedRouters: make(map[string]string, len(g.trustedRouters)),
		Routers:        make([]snapshotRouter, 0, len(g.routers)),
		Prefixes:       make([]snapshotPrefix, 0, len(g.prefixes)),
		LastSeen:       make(map[string]time.Time, len(g.lastSeen)),
	}
	for port := range g.trustedPorts {
		snap.TrustedPorts = append(snap.TrustedPorts, port)
	}
	sort.Strings(snap.TrustedPorts)
	for addr, tenant := range g.trustedRouters {
		snap.TrustedRouters[addr] = tenant
	}
	for _, r := range g.routers {
		snap.Routers = append(snap.Routers, snapshotRouter{
			Address:   r.Address,
			Interface: r.Interface,
			TenantID:  r.TenantID,
			Lifetime:  r.Lifetime,
			LearnedAt: r.LearnedAt,
			ExpiresAt: r.ExpiresAt,
		})
	}
	sort.Slice(snap.Routers, func(i, j int) bool {
		return snap.Routers[i].Address < snap.Routers[j].Address
	})
	for _, p := range g.prefixes {
		snap.Prefixes = append(snap.Prefixes, snapshotPrefix{
			CIDR:           p.CIDR,
			ValidUntil:     p.ValidUntil,
			PreferredUntil: p.PreferredUntil,
		})
	}
	sort.Slice(snap.Prefixes, func(i, j int) bool {
		return snap.Prefixes[i].CIDR < snap.Prefixes[j].CIDR
	})
	for addr, seen := range g.lastSeen {
		snap.LastSeen[addr] = seen
	}

	return json.Marshal(snap)
}

const snapshotVersion = 1

type snapshot struct {
	Version        int                  `json:"version"`
	TrustedPorts   []string             `json:"trusted_ports"`
	TrustedRouters map[string]string    `json:"trusted_routers"`
	Routers        []snapshotRouter     `json:"routers"`
	Prefixes       []snapshotPrefix     `json:"prefixes"`
	LastSeen       map[string]time.Time `json:"last_seen,omitempty"`
}

type snapshotRouter struct {
	Address   string        `json:"address"`
	Interface string        `json:"interface"`
	TenantID  string        `json:"tenant_id"`
	Lifetime  time.Duration `json:"lifetime"`
	LearnedAt time.Time     `json:"learned_at"`
	ExpiresAt time.Time     `json:"expires_at"`
}

type snapshotPrefix struct {
	CIDR           string    `json:"cidr"`
	ValidUntil     time.Time `json:"valid_until"`
	PreferredUntil time.Time `json:"preferred_until"`
}

type validatedPrefix struct {
	cidr    string
	network *net.IPNet
	info    PrefixInfo
}

func (g *RaGuard) validatePrefixes(ra RouterAdvert) ([]validatedPrefix, error) {
	pending := make([]validatedPrefix, 0, len(ra.Prefixes))
	for _, p := range ra.Prefixes {
		cidr, network, ok := parseIPv6Network(p.CIDR)
		if !ok {
			return nil, fmt.Errorf("%w: invalid prefix %q", ErrInvalid, p.CIDR)
		}
		ones, bits := network.Mask.Size()
		if bits != 128 || ones != g.cfg.PrefixLength {
			return nil, ErrPrefixLen
		}
		if p.ValidLifetime < 0 || p.PreferredLifetime < 0 ||
			p.PreferredLifetime > p.ValidLifetime {
			return nil, ErrPrefixLifetime
		}
		pending = append(pending, validatedPrefix{cidr: cidr, network: network, info: p})
	}
	return pending, nil
}

func normalizeConfig(cfg Config) Config {
	if cfg.PrefixLength <= 0 || cfg.PrefixLength > 128 {
		cfg.PrefixLength = 64
	}
	return cfg
}

func normalizeLinkLocal(addr string) (string, bool) {
	ip := net.ParseIP(addr)
	if ip == nil || ip.To4() != nil || !ip.IsLinkLocalUnicast() {
		return "", false
	}
	return ip.String(), true
}

func parseIPv6Network(cidr string) (string, *net.IPNet, bool) {
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil || ip.To4() != nil {
		return "", nil, false
	}
	ones, bits := network.Mask.Size()
	if bits != 128 || ones < 0 {
		return "", nil, false
	}
	return network.String(), network, true
}

func normalizeIPv6Network(cidr string) (string, bool) {
	normalized, _, ok := parseIPv6Network(cidr)
	return normalized, ok
}

func isULA(network *net.IPNet) bool {
	ip := network.IP
	if len(ip) != net.IPv6len {
		return false
	}
	return ip[0]&0xfe == 0xfc
}
