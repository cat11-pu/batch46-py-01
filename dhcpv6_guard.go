package task

import (
	"errors"
	"time"
)

// errNotImplemented is returned by every stubbed operation.
var errNotImplemented = errors.New("not implemented")

// Errors reported by Screen and Commit. Callers must be able to tell a rogue
// server from a prefix that is merely out of pool, and a client that already
// holds a lease from a tenant that hit its quota.
var (
	ErrServer    = errors.New("dhcpv6: server not trusted")
	ErrPool      = errors.New("dhcpv6: delegated prefix outside pool")
	ErrPrefixLen = errors.New("dhcpv6: delegated prefix length not allowed")
	ErrTenant    = errors.New("dhcpv6: tenant mismatch")
	ErrLifetime  = errors.New("dhcpv6: invalid lifetime")
	ErrRate      = errors.New("dhcpv6: advertisement rate exceeded")
	ErrConflict  = errors.New("dhcpv6: delegated prefix overlaps an active lease")
	ErrBound     = errors.New("dhcpv6: client already bound to another prefix")
	ErrQuota     = errors.New("dhcpv6: tenant lease quota exceeded")
	ErrNoLease   = errors.New("dhcpv6: no active lease")
	ErrNoOffer   = errors.New("dhcpv6: unknown or expired offer")
	ErrInvalid   = errors.New("dhcpv6: invalid request")
)

// Config is the prefix-delegation screening policy.
type Config struct {
	// MinPrefixLen and MaxPrefixLen bound the length of a delegated prefix.
	MinPrefixLen int
	MaxPrefixLen int
	// MaxLeasesPerTenant caps concurrently active leases per tenant.
	MaxLeasesPerTenant int
	// OfferTTL is how long a screened offer stays commitable.
	OfferTTL time.Duration
	// AdvertiseInterval is the minimum spacing between two Advertise
	// messages for the same client from the same server.
	AdvertiseInterval time.Duration
	// LeaseTTL caps the lifetime granted in a lease.
	LeaseTTL time.Duration
}

// Advertise is one Advertise message received from a delegating router.
type Advertise struct {
	ServerDUID        string
	ClientDUID        string
	IAID              uint32
	TenantID          string
	Prefix            string
	ValidLifetime     time.Duration
	PreferredLifetime time.Duration
}

// Offer is a screened advertisement that may be committed once.
type Offer struct {
	ID         string
	ServerDUID string
	ClientDUID string
	IAID       uint32
	TenantID   string
	Prefix     string
	ExpiresAt  time.Time
}

// Lease is one active prefix delegation. T1 is half of the granted lifetime
// and T2 is four fifths of it.
type Lease struct {
	Prefix     string
	ClientDUID string
	IAID       uint32
	TenantID   string
	ServerDUID string
	ExpiresAt  time.Time
	T1         time.Duration
	T2         time.Duration
}

// Stats reports guard occupancy.
type Stats struct {
	Leases int
	Offers int
}

// Dhcpv6Guard screens Advertise messages from delegating routers and tracks
// the delegated prefixes handed to requesting routers.
type Dhcpv6Guard struct {
	cfg Config
}

// NewDhcpv6Guard returns a guard configured by cfg.
func NewDhcpv6Guard(cfg Config) *Dhcpv6Guard {
	return &Dhcpv6Guard{cfg: cfg}
}

// NewDhcpv6GuardFromSnapshot restores a guard, including trusted servers,
// pools and active leases, from a snapshot.
func NewDhcpv6GuardFromSnapshot(cfg Config, data []byte) (*Dhcpv6Guard, error) {
	return nil, errNotImplemented
}

// AddServer trusts the delegating router identified by duid for a tenant.
func (g *Dhcpv6Guard) AddServer(duid, tenantID string) error {
	return errNotImplemented
}

// RevokeServer removes a server from the trusted set.
func (g *Dhcpv6Guard) RevokeServer(duid string) error {
	return errNotImplemented
}

// AddPool registers a prefix pool that delegated prefixes must fall inside.
func (g *Dhcpv6Guard) AddPool(cidr string) error {
	return errNotImplemented
}

// Screen validates an Advertise message and returns an offer. It checks the
// server, tenant, prefix length, pool containment, lifetimes and the
// per-client advertisement rate.
func (g *Dhcpv6Guard) Screen(adv Advertise, now time.Time) (Offer, error) {
	return Offer{}, errNotImplemented
}

// Commit turns a screened offer into a lease. It is idempotent for the same
// client and prefix, rejects a second prefix for the same IA_PD, rejects
// prefixes overlapping another active lease and enforces the tenant quota.
func (g *Dhcpv6Guard) Commit(offerID string, now time.Time) (Lease, error) {
	return Lease{}, errNotImplemented
}

// LeaseFor returns the active lease of a client IA_PD.
func (g *Dhcpv6Guard) LeaseFor(clientDUID string, iaid uint32) (Lease, bool) {
	return Lease{}, false
}

// Release drops the lease of a client IA_PD and frees its prefix.
func (g *Dhcpv6Guard) Release(clientDUID string, iaid uint32, now time.Time) error {
	return errNotImplemented
}

// Expire removes leases and offers whose lifetime ended at now and returns
// the number of leases removed.
func (g *Dhcpv6Guard) Expire(now time.Time) int {
	return 0
}

// Stats reports the number of active leases and live offers.
func (g *Dhcpv6Guard) Stats() Stats {
	return Stats{}
}

// Snapshot serialises trusted servers, pools and active leases so that a
// restarted guard keeps rejecting conflicts and replaying clients.
func (g *Dhcpv6Guard) Snapshot() ([]byte, error) {
	return nil, errNotImplemented
}
