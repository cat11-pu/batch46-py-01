package task

import (
	"errors"
	"time"
)

// errNotImplemented is returned by every stubbed operation.
var errNotImplemented = errors.New("not implemented")

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
	cfg Config
}

// NewRaGuard returns a guard configured by cfg.
func NewRaGuard(cfg Config) *RaGuard {
	return &RaGuard{cfg: cfg}
}

// NewRaGuardFromSnapshot restores a guard, including trusted ports, trusted
// routers, learned routers and prefixes, from a snapshot.
func NewRaGuardFromSnapshot(cfg Config, data []byte) (*RaGuard, error) {
	return nil, errNotImplemented
}

// TrustPort allows advertisements received on the named interface.
func (g *RaGuard) TrustPort(ifName string) error {
	return errNotImplemented
}

// UntrustPort removes an interface from the trusted set.
func (g *RaGuard) UntrustPort(ifName string) error {
	return errNotImplemented
}

// TrustRouter trusts the link-local address for a tenant.
func (g *RaGuard) TrustRouter(linkLocal, tenantID string) error {
	return errNotImplemented
}

// Revoke removes a router from the trusted set and from the learned table.
func (g *RaGuard) Revoke(linkLocal string) error {
	return errNotImplemented
}

// Process validates one advertisement and, when accepted, updates the
// default router table and the prefix table.
func (g *RaGuard) Process(ra RouterAdvert, now time.Time) error {
	return errNotImplemented
}

// DefaultRouters returns the routers that are still default at now, sorted
// by address.
func (g *RaGuard) DefaultRouters(now time.Time) []Router {
	return nil
}

// IsDefaultRouter reports whether addr is a live default router at now.
func (g *RaGuard) IsDefaultRouter(addr string, now time.Time) bool {
	return false
}

// LearnedPrefixes returns the live prefixes at now, sorted.
func (g *RaGuard) LearnedPrefixes(now time.Time) []string {
	return nil
}

// Sweep removes expired routers and prefixes and returns the number of
// routers removed.
func (g *RaGuard) Sweep(now time.Time) int {
	return 0
}

// Stats reports the number of learned routers and prefixes.
func (g *RaGuard) Stats() Stats {
	return Stats{}
}

// Snapshot serialises the trusted configuration and the learned tables.
func (g *RaGuard) Snapshot() ([]byte, error) {
	return nil, errNotImplemented
}
