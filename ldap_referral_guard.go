package task

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

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

type bindCredential struct {
	bindDN   string
	password string
}

type tenantDirectory struct {
	homeHost    string
	homeBind    bindCredential
	hasHomeBind bool
	credentials map[string]bindCredential
}

type parsedReferralURL struct {
	host      string
	canonical string
}

const snapshotVersion = 1

type snapshotReferral struct {
	URL       string `json:"url"`
	ExpiresAt int64  `json:"expires_at"`
}

type snapshotState struct {
	Version   int                `json:"version"`
	Referrals []snapshotReferral `json:"referrals"`
}

// LdapReferralGuard validates referral chains before the gateway follows them.
type LdapReferralGuard struct {
	mu        sync.RWMutex
	policy    ReferralPolicy
	domains   map[string]struct{}
	tenants   map[string]*tenantDirectory
	referrals map[string]time.Time
	stats     ReferralStats
}

// NewLdapReferralGuard returns a guard configured by p.
func NewLdapReferralGuard(p ReferralPolicy) *LdapReferralGuard {
	return &LdapReferralGuard{
		policy:    p,
		domains:   make(map[string]struct{}),
		tenants:   make(map[string]*tenantDirectory),
		referrals: make(map[string]time.Time),
	}
}

// NewLdapReferralGuardFromSnapshot restores remembered referral urls from data
// produced by Snapshot.
func NewLdapReferralGuardFromSnapshot(p ReferralPolicy, data []byte) (*LdapReferralGuard, error) {
	if len(data) == 0 {
		return nil, errors.New("ldap: invalid snapshot")
	}

	var state snapshotState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("ldap: invalid snapshot: %w", err)
	}
	if state.Version != snapshotVersion {
		return nil, fmt.Errorf("ldap: unsupported snapshot version %d", state.Version)
	}
	g := NewLdapReferralGuard(p)
	for _, record := range state.Referrals {
		parsed, err := parseReferralURL(record.URL)
		if err != nil {
			return nil, fmt.Errorf("ldap: invalid snapshot referral: %w", err)
		}
		expires := time.Unix(0, record.ExpiresAt)
		if current, ok := g.referrals[parsed.canonical]; !ok || expires.After(current) {
			g.referrals[parsed.canonical] = expires
		}
	}
	if p.MaxReferrals >= 0 && len(g.referrals) > p.MaxReferrals {
		return nil, errors.New("ldap: snapshot exceeds referral capacity")
	}
	return g, nil
}

// AllowDomain adds one domain whose hosts referrals may target.
func (g *LdapReferralGuard) AllowDomain(domain string) error {
	normalized, err := normalizeDomain(domain)
	if err != nil {
		return err
	}

	g.mu.Lock()
	g.domains[normalized] = struct{}{}
	g.mu.Unlock()
	return nil
}

// RegisterHomeBind records the bind used on the tenant's own directory host.
func (g *LdapReferralGuard) RegisterHomeBind(tenantID, host, bindDN, password string) error {
	normalizedHost, err := normalizeHostSpec(host)
	if err != nil {
		return err
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	tenant := g.tenantLocked(tenantID)
	tenant.homeHost = normalizedHost
	tenant.homeBind = bindCredential{bindDN: bindDN, password: password}
	tenant.hasHomeBind = true
	return nil
}

// RegisterCredential records a bind for one referral host of a tenant.
func (g *LdapReferralGuard) RegisterCredential(tenantID, host, bindDN, password string) error {
	normalizedHost, err := normalizeHostSpec(host)
	if err != nil {
		return err
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	tenant := g.tenantLocked(tenantID)
	tenant.credentials[normalizedHost] = bindCredential{bindDN: bindDN, password: password}
	return nil
}

// BindPlan returns the bind the gateway must use for one referral hop. A host
// that is not the tenant home host never receives the home credentials.
func (g *LdapReferralGuard) BindPlan(tenantID string, ref Referral) (BindRequest, error) {
	parsed, err := parseReferralURL(ref.URL)
	if err != nil {
		return BindRequest{}, err
	}

	g.mu.RLock()
	defer g.mu.RUnlock()

	if !g.hostAllowedLocked(parsed.host) {
		return BindRequest{}, ErrDomainNotAllowed
	}
	tenant, ok := g.tenants[tenantID]
	if !ok || !tenant.hasHomeBind {
		return BindRequest{}, ErrHomeBindMissing
	}

	if parsed.host == tenant.homeHost {
		return BindRequest{
			Host:     parsed.host,
			BindDN:   tenant.homeBind.bindDN,
			Password: tenant.homeBind.password,
		}, nil
	}

	credential, ok := tenant.credentials[parsed.host]
	if !ok {
		return BindRequest{}, ErrNoCredential
	}
	return BindRequest{
		Host:     parsed.host,
		BindDN:   credential.bindDN,
		Password: credential.password,
	}, nil
}

// ResolveChain validates a referral chain and returns the hops to follow. The
// chain is validated as a whole: on error no referral url is remembered.
func (g *LdapReferralGuard) ResolveChain(tenantID string, refs []Referral, now time.Time) ([]ReferralHop, error) {
	if len(refs) == 0 {
		return nil, ErrInvalidReferral
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	if g.policy.MaxHops < 0 || len(refs) > g.policy.MaxHops {
		return nil, ErrHopLimit
	}

	parsedRefs := make([]parsedReferralURL, len(refs))
	seenInChain := make(map[string]struct{}, len(refs))
	for i, ref := range refs {
		parsed, err := parseReferralURL(ref.URL)
		if err != nil {
			return nil, err
		}
		if !g.hostAllowedLocked(parsed.host) {
			g.stats.Rejected++
			return nil, ErrDomainNotAllowed
		}
		if _, duplicate := seenInChain[parsed.canonical]; duplicate {
			return nil, ErrReferralLoop
		}
		seenInChain[parsed.canonical] = struct{}{}
		parsedRefs[i] = parsed
	}

	liveCount := 0
	newKeys := make(map[string]struct{}, len(parsedRefs))
	for _, expires := range g.referrals {
		if expires.After(now) {
			liveCount++
		}
	}
	for _, parsed := range parsedRefs {
		expires, exists := g.referrals[parsed.canonical]
		if !exists || !expires.After(now) {
			newKeys[parsed.canonical] = struct{}{}
		}
	}
	if g.policy.MaxReferrals < 0 || liveCount+len(newKeys) > g.policy.MaxReferrals {
		return nil, ErrReferralCapacity
	}

	homeHost := ""
	if tenant, ok := g.tenants[tenantID]; ok && tenant.hasHomeBind {
		homeHost = tenant.homeHost
	}

	hops := make([]ReferralHop, 0, len(refs))
	for i, ref := range refs {
		parsed := parsedRefs[i]
		hops = append(hops, ReferralHop{
			URL:         ref.URL,
			Host:        parsed.host,
			BaseDN:      ref.BaseDN,
			Scope:       ref.Scope,
			CrossDomain: homeHost == "" || parsed.host != homeHost,
		})
	}

	for key, expires := range g.referrals {
		if !expires.After(now) {
			delete(g.referrals, key)
		}
	}
	for _, parsed := range parsedRefs {
		if _, exists := g.referrals[parsed.canonical]; !exists {
			g.referrals[parsed.canonical] = now.Add(g.policy.CacheTTL)
		}
	}

	for _, hop := range hops {
		if hop.CrossDomain {
			g.stats.CrossDomain++
		}
	}
	g.stats.Followed += len(hops)

	return hops, nil
}

// CheckResponseSize enforces the response size budget.
func (g *LdapReferralGuard) CheckResponseSize(n int) error {
	g.mu.RLock()
	limit := g.policy.MaxResponseSize
	g.mu.RUnlock()
	if n > limit {
		return ErrResponseTooLarge
	}
	return nil
}

// Seen reports whether a referral url is still inside the cache window.
func (g *LdapReferralGuard) Seen(url string, now time.Time) (bool, error) {
	parsed, err := parseReferralURL(url)
	if err != nil {
		return false, err
	}

	g.mu.RLock()
	expires, ok := g.referrals[parsed.canonical]
	g.mu.RUnlock()
	return ok && expires.After(now), nil
}

// Prune drops expired referral records and returns the removed count.
func (g *LdapReferralGuard) Prune(now time.Time) int {
	g.mu.Lock()
	defer g.mu.Unlock()

	removed := 0
	for key, expires := range g.referrals {
		if !expires.After(now) {
			delete(g.referrals, key)
			removed++
		}
	}
	return removed
}

// Snapshot serialises remembered referral urls.
func (g *LdapReferralGuard) Snapshot(now time.Time) ([]byte, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	state := snapshotState{
		Version:   snapshotVersion,
		Referrals: make([]snapshotReferral, 0, len(g.referrals)),
	}
	for key, expires := range g.referrals {
		if expires.After(now) {
			state.Referrals = append(state.Referrals, snapshotReferral{
				URL:       key,
				ExpiresAt: expires.UnixNano(),
			})
		}
	}
	sort.Slice(state.Referrals, func(i, j int) bool {
		return state.Referrals[i].URL < state.Referrals[j].URL
	})
	return json.Marshal(state)
}

// Stats returns the current counters.
func (g *LdapReferralGuard) Stats() ReferralStats {
	g.mu.RLock()
	defer g.mu.RUnlock()

	stats := g.stats
	stats.SeenEntries = len(g.referrals)
	return stats
}

// SetMaxHops changes the accepted chain length.
func (g *LdapReferralGuard) SetMaxHops(n int) error {
	if n < 0 {
		return errors.New("ldap: max hops must not be negative")
	}

	g.mu.Lock()
	g.policy.MaxHops = n
	g.mu.Unlock()
	return nil
}

func (g *LdapReferralGuard) tenantLocked(tenantID string) *tenantDirectory {
	tenant, ok := g.tenants[tenantID]
	if !ok {
		tenant = &tenantDirectory{credentials: make(map[string]bindCredential)}
		g.tenants[tenantID] = tenant
	}
	return tenant
}

func (g *LdapReferralGuard) hostAllowedLocked(host string) bool {
	for domain := range g.domains {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}
	return false
}

func normalizeDomain(domain string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(domain))
	normalized = strings.TrimPrefix(normalized, ".")
	normalized = strings.TrimSuffix(normalized, ".")
	if normalized == "" ||
		strings.ContainsAny(normalized, "/:@?#[]\\ \t\r\n") {
		return "", fmt.Errorf("%w: invalid domain", ErrInvalidReferral)
	}
	for _, label := range strings.Split(normalized, ".") {
		if label == "" || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", fmt.Errorf("%w: invalid domain", ErrInvalidReferral)
		}
	}
	return normalized, nil
}

func parseReferralURL(raw string) (parsedReferralURL, error) {
	if strings.TrimSpace(raw) == "" {
		return parsedReferralURL{}, ErrInvalidReferral
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return parsedReferralURL{}, fmt.Errorf("%w: %v", ErrInvalidReferral, err)
	}
	if !strings.EqualFold(parsed.Scheme, "ldaps") {
		return parsedReferralURL{}, ErrScheme
	}
	if parsed.Opaque != "" || parsed.User != nil || parsed.Host == "" {
		return parsedReferralURL{}, ErrInvalidReferral
	}
	if parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return parsedReferralURL{}, ErrInvalidReferral
	}
	if strings.HasSuffix(parsed.Host, ":") {
		return parsedReferralURL{}, fmt.Errorf("%w: empty port", ErrInvalidReferral)
	}

	host, err := normalizeHostName(parsed.Hostname())
	if err != nil {
		return parsedReferralURL{}, err
	}

	port := parsed.Port()
	if port == "" {
		port = "636"
	}
	if !validPort(port) {
		return parsedReferralURL{}, fmt.Errorf("%w: invalid port", ErrInvalidReferral)
	}
	portNumber, _ := strconv.Atoi(port)

	dn := strings.ToLower(parsed.Path)
	if dn == "" {
		dn = "/"
	}
	canonical := "ldaps://" + net.JoinHostPort(host, strconv.Itoa(portNumber)) + dn
	return parsedReferralURL{host: host, canonical: canonical}, nil
}

func normalizeHostSpec(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", ErrInvalidReferral
	}
	if strings.Contains(raw, "://") {
		parsed, err := parseReferralURL(raw)
		if err != nil {
			return "", err
		}
		return parsed.host, nil
	}

	parsed, err := url.Parse("//" + raw)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidReferral, err)
	}
	if parsed.User != nil || parsed.Host == "" || parsed.Path != "" ||
		parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", ErrInvalidReferral
	}
	if strings.HasSuffix(parsed.Host, ":") {
		return "", fmt.Errorf("%w: empty port", ErrInvalidReferral)
	}
	if port := parsed.Port(); port != "" && !validPort(port) {
		return "", fmt.Errorf("%w: invalid port", ErrInvalidReferral)
	}
	return normalizeHostName(parsed.Hostname())
}

func normalizeHostName(host string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(host))
	normalized = strings.TrimSuffix(normalized, ".")
	if normalized == "" ||
		strings.ContainsAny(normalized, "/\\?#@ \t\r\n") {
		return "", ErrInvalidReferral
	}
	return normalized, nil
}

func validPort(port string) bool {
	if port == "" {
		return false
	}
	for _, r := range port {
		if r < '0' || r > '9' {
			return false
		}
	}
	number, err := strconv.Atoi(port)
	return err == nil && number >= 1 && number <= 65535
}
