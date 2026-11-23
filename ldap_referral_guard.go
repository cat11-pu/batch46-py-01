package task

import (
	"errors"
	"time"
)

// errNotImplemented is returned by stubs whose real logic is still missing.
var errNotImplemented = errors.New("not implemented")

// Sentinel errors returned by LdapReferralGuard.
var (
	ErrInvalidReferral  = errors.New("ldap: invalid referral")
	ErrScheme           = errors.New("ldap: unsupported referral scheme")
	ErrDomainNotAllowed = errors.New("ldap: referral domain not allowed")
	ErrHopLimit         = errors.New("ldap: referral hop limit exceeded")
	ErrReferralLoop     = errors.New("ldap: referral loop detected")
	ErrReferralCapacity = errors.New("ldap: referral cache full")
	ErrResponseTooLarge = errors.New("ldap: response exceeds size limit")
	ErrNoCredential     = errors.New("ldap: no credential for referral host")
	ErrHomeBindMissing  = errors.New("ldap: home bind not registered")
)

// ReferralPolicy bounds referral chasing.
type ReferralPolicy struct {
	// MaxHops is the longest chain accepted in one call.
	MaxHops int
	// MaxReferrals bounds the number of remembered referral urls.
	MaxReferrals int
	// MaxResponseSize is the accepted response size in bytes.
	MaxResponseSize int
	// CacheTTL is how long a remembered referral url stays known.
	CacheTTL time.Duration
}

// Referral is one referral returned by a directory server.
type Referral struct {
	URL    string
	BaseDN string
	Scope  string
}

// ReferralHop is a validated step of a referral chain.
type ReferralHop struct {
	URL         string
	Host        string
	BaseDN      string
	Scope       string
	CrossDomain bool
}

// BindRequest is the bind a gateway must perform for one hop.
type BindRequest struct {
	Host      string
	BindDN    string
	Password  string
	Anonymous bool
}

// ReferralStats reports referral counters.
type ReferralStats struct {
	Followed    int
	Rejected    int
	SeenEntries int
	CrossDomain int
}

// LdapReferralGuard validates referral chains before the gateway follows them.
type LdapReferralGuard struct {
	policy ReferralPolicy
}

// NewLdapReferralGuard returns a guard configured by p.
func NewLdapReferralGuard(p ReferralPolicy) *LdapReferralGuard {
	return &LdapReferralGuard{policy: p}
}

// NewLdapReferralGuardFromSnapshot restores remembered referral urls from data
// produced by Snapshot.
func NewLdapReferralGuardFromSnapshot(p ReferralPolicy, data []byte) (*LdapReferralGuard, error) {
	return nil, errNotImplemented
}

// AllowDomain adds one domain whose hosts referrals may target.
func (g *LdapReferralGuard) AllowDomain(domain string) error {
	return errNotImplemented
}

// RegisterHomeBind records the bind used on the tenant's own directory host.
func (g *LdapReferralGuard) RegisterHomeBind(tenantID, host, bindDN, password string) error {
	return errNotImplemented
}

// RegisterCredential records a bind for one referral host of a tenant.
func (g *LdapReferralGuard) RegisterCredential(tenantID, host, bindDN, password string) error {
	return errNotImplemented
}

// BindPlan returns the bind the gateway must use for one referral hop. A host
// that is not the tenant home host never receives the home credentials.
func (g *LdapReferralGuard) BindPlan(tenantID string, ref Referral) (BindRequest, error) {
	return BindRequest{}, errNotImplemented
}

// ResolveChain validates a referral chain and returns the hops to follow. The
// chain is validated as a whole: on error no referral url is remembered.
func (g *LdapReferralGuard) ResolveChain(tenantID string, refs []Referral, now time.Time) ([]ReferralHop, error) {
	return nil, errNotImplemented
}

// CheckResponseSize enforces the response size budget.
func (g *LdapReferralGuard) CheckResponseSize(n int) error {
	return errNotImplemented
}

// Seen reports whether a referral url is still inside the cache window.
func (g *LdapReferralGuard) Seen(url string, now time.Time) (bool, error) {
	return false, errNotImplemented
}

// Prune drops expired referral records and returns the removed count.
func (g *LdapReferralGuard) Prune(now time.Time) int {
	return 0
}

// Snapshot serialises remembered referral urls.
func (g *LdapReferralGuard) Snapshot(now time.Time) ([]byte, error) {
	return nil, errNotImplemented
}

// Stats returns the current counters.
func (g *LdapReferralGuard) Stats() ReferralStats {
	return ReferralStats{}
}

// SetMaxHops changes the accepted chain length.
func (g *LdapReferralGuard) SetMaxHops(n int) error {
	return errNotImplemented
}
