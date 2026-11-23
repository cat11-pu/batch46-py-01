package task

import (
	"errors"
	"sync"
	"testing"
	"time"

	taskpkg "gsb/batch46-safety-a-05"
)

const baseUnix = 1730000000

const (
	homeHost     = "ldap1.corp.example.com"
	homeBindDN   = "cn=svc-sync,dc=corp,dc=example,dc=com"
	homePassword = "home-secret"
	homeBaseDN   = "dc=corp,dc=example,dc=com"
)

func testPolicy() taskpkg.ReferralPolicy {
	return taskpkg.ReferralPolicy{
		MaxHops:         5,
		MaxReferrals:    32,
		MaxResponseSize: 64 * 1024,
		CacheTTL:        10 * time.Minute,
	}
}

func newGuard(t *testing.T, p taskpkg.ReferralPolicy) *taskpkg.LdapReferralGuard {
	t.Helper()
	g := taskpkg.NewLdapReferralGuard(p)
	if err := g.AllowDomain("corp.example.com"); err != nil {
		t.Fatalf("AllowDomain: %v", err)
	}
	if err := g.RegisterHomeBind("tenant-a", homeHost, homeBindDN, homePassword); err != nil {
		t.Fatalf("RegisterHomeBind: %v", err)
	}
	return g
}

func referral(host, baseDN string) taskpkg.Referral {
	return taskpkg.Referral{
		URL:    "ldaps://" + host + ":636/" + baseDN,
		BaseDN: baseDN,
		Scope:  "sub",
	}
}

func chain(hosts []string) []taskpkg.Referral {
	refs := make([]taskpkg.Referral, 0, len(hosts))
	for i, host := range hosts {
		refs = append(refs, referral(host, []string{
			"ou=people," + homeBaseDN,
			"ou=contractors," + homeBaseDN,
			"ou=partners," + homeBaseDN,
			"ou=archive," + homeBaseDN,
			"ou=legacy," + homeBaseDN,
		}[i%5]))
	}
	return refs
}

// A hop on the tenant home host keeps the home bind credentials.
func TestHomeHopUsesHomeBind(t *testing.T) {
	g := newGuard(t, testPolicy())
	bind, err := g.BindPlan("tenant-a", referral(homeHost, "ou=people,"+homeBaseDN))
	if err != nil {
		t.Fatalf("BindPlan: %v", err)
	}
	if bind.Host != homeHost {
		t.Fatalf("host should be port stripped, got %q", bind.Host)
	}
	if bind.BindDN != homeBindDN || bind.Password != homePassword {
		t.Fatalf("home bind not used: %+v", bind)
	}
	if bind.Anonymous {
		t.Fatalf("home bind reported anonymous")
	}
}

// A cross-domain hop uses the credential registered for that host.
func TestCrossDomainHopUsesRegisteredCredential(t *testing.T) {
	g := newGuard(t, testPolicy())
	const delegateHost = "ldap2.corp.example.com"
	const delegateDN = "cn=delegate,ou=svc,dc=corp,dc=example,dc=com"
	if err := g.RegisterCredential("tenant-a", delegateHost, delegateDN, "delegate-secret"); err != nil {
		t.Fatalf("RegisterCredential: %v", err)
	}
	bind, err := g.BindPlan("tenant-a", referral(delegateHost, "ou=contractors,"+homeBaseDN))
	if err != nil {
		t.Fatalf("BindPlan: %v", err)
	}
	if bind.BindDN != delegateDN || bind.Password != "delegate-secret" {
		t.Fatalf("delegate credential not used: %+v", bind)
	}
	if bind.BindDN == homeBindDN || bind.Password == homePassword {
		t.Fatalf("home credential leaked to a cross-domain host")
	}
}

// Without a per-host credential the hop must fail instead of borrowing the
// home password.
func TestCrossDomainWithoutCredentialRejected(t *testing.T) {
	g := newGuard(t, testPolicy())
	bind, err := g.BindPlan("tenant-a", referral("ldap3.corp.example.com", "ou=partners,"+homeBaseDN))
	if !errors.Is(err, taskpkg.ErrNoCredential) {
		t.Fatalf("want ErrNoCredential, got %v", err)
	}
	if bind.Password != "" || bind.BindDN != "" {
		t.Fatalf("credentials returned with an error: %+v", bind)
	}
}

// A valid chain keeps its order and marks cross-domain hops.
func TestResolveChainPreservesOrderAndScope(t *testing.T) {
	now := time.Unix(baseUnix, 0)
	g := newGuard(t, testPolicy())
	refs := chain([]string{homeHost, "ldap2.corp.example.com", "ldap3.corp.example.com"})
	hops, err := g.ResolveChain("tenant-a", refs, now)
	if err != nil {
		t.Fatalf("ResolveChain: %v", err)
	}
	if len(hops) != 3 {
		t.Fatalf("got %d hops, want 3", len(hops))
	}
	for i, hop := range hops {
		if hop.URL != refs[i].URL || hop.BaseDN != refs[i].BaseDN || hop.Scope != refs[i].Scope {
			t.Fatalf("hop %d not preserved: %+v", i, hop)
		}
	}
	if hops[0].CrossDomain {
		t.Fatalf("home hop marked cross domain")
	}
	if !hops[1].CrossDomain || !hops[2].CrossDomain {
		t.Fatalf("off-host hops not marked cross domain: %+v", hops)
	}
	stats := g.Stats()
	if stats.Followed != 3 || stats.CrossDomain != 2 || stats.SeenEntries != 3 {
		t.Fatalf("stats wrong: %+v", stats)
	}
}

// A chain longer than MaxHops must be rejected before any hop runs.
func TestMaxHopsExceeded(t *testing.T) {
	now := time.Unix(baseUnix, 0)
	p := testPolicy()
	p.MaxHops = 3
	g := newGuard(t, p)
	refs := chain([]string{homeHost, "ldap2.corp.example.com", "ldap3.corp.example.com", "ldap4.corp.example.com"})
	if _, err := g.ResolveChain("tenant-a", refs, now); !errors.Is(err, taskpkg.ErrHopLimit) {
		t.Fatalf("want ErrHopLimit, got %v", err)
	}
	if got := g.Stats().SeenEntries; got != 0 {
		t.Fatalf("rejected chain remembered %d referrals", got)
	}
}

// Repeating a referral in one chain is a loop, not a retry.
func TestReferralLoopDetected(t *testing.T) {
	now := time.Unix(baseUnix, 0)
	g := newGuard(t, testPolicy())
	first := referral(homeHost, "ou=people,"+homeBaseDN)
	second := referral("ldap2.corp.example.com", "ou=contractors,"+homeBaseDN)
	if _, err := g.ResolveChain("tenant-a", []taskpkg.Referral{first, second, first}, now); !errors.Is(err, taskpkg.ErrReferralLoop) {
		t.Fatalf("want ErrReferralLoop, got %v", err)
	}
	if got := g.Stats().SeenEntries; got != 0 {
		t.Fatalf("looping chain remembered %d referrals", got)
	}
}

// A host outside the allowlist must never be followed and is counted.
func TestDisallowedDomainRejected(t *testing.T) {
	now := time.Unix(baseUnix, 0)
	g := newGuard(t, testPolicy())
	refs := []taskpkg.Referral{referral("ldap1.evil.example.net", "ou=people,dc=evil,dc=example,dc=net")}
	if _, err := g.ResolveChain("tenant-a", refs, now); !errors.Is(err, taskpkg.ErrDomainNotAllowed) {
		t.Fatalf("want ErrDomainNotAllowed, got %v", err)
	}
	if got := g.Stats().Rejected; got != 1 {
		t.Fatalf("Rejected = %d, want 1", got)
	}
}

// Allowlisting is by DNS label suffix, so a look-alike host is still refused.
func TestSuffixBoundaryNotPrefix(t *testing.T) {
	now := time.Unix(baseUnix, 0)
	g := newGuard(t, testPolicy())
	refs := []taskpkg.Referral{referral("evilcorp.example.com", "ou=people,"+homeBaseDN)}
	if _, err := g.ResolveChain("tenant-a", refs, now); !errors.Is(err, taskpkg.ErrDomainNotAllowed) {
		t.Fatalf("want ErrDomainNotAllowed for a look-alike host, got %v", err)
	}
}

// Plaintext ldap referrals must not be followed.
func TestSchemeMustBeLdaps(t *testing.T) {
	now := time.Unix(baseUnix, 0)
	g := newGuard(t, testPolicy())
	refs := []taskpkg.Referral{{
		URL:    "ldap://ldap1.corp.example.com:389/ou=people," + homeBaseDN,
		BaseDN: "ou=people," + homeBaseDN,
		Scope:  "sub",
	}}
	if _, err := g.ResolveChain("tenant-a", refs, now); !errors.Is(err, taskpkg.ErrScheme) {
		t.Fatalf("want ErrScheme, got %v", err)
	}
}

// Empty referrals and empty chains are rejected outright.
func TestEmptyReferralRejected(t *testing.T) {
	now := time.Unix(baseUnix, 0)
	g := newGuard(t, testPolicy())
	if _, err := g.ResolveChain("tenant-a", nil, now); !errors.Is(err, taskpkg.ErrInvalidReferral) {
		t.Fatalf("want ErrInvalidReferral for an empty chain, got %v", err)
	}
	refs := []taskpkg.Referral{referral(homeHost, "ou=people,"+homeBaseDN), {}}
	if _, err := g.ResolveChain("tenant-a", refs, now); !errors.Is(err, taskpkg.ErrInvalidReferral) {
		t.Fatalf("want ErrInvalidReferral for an empty referral, got %v", err)
	}
}

// The referral store is bounded and stays untouched when the bound is hit.
func TestReferralCapacityLimit(t *testing.T) {
	now := time.Unix(baseUnix, 0)
	p := testPolicy()
	p.MaxReferrals = 2
	g := newGuard(t, p)
	refs := chain([]string{homeHost, "ldap2.corp.example.com", "ldap3.corp.example.com"})
	if _, err := g.ResolveChain("tenant-a", refs, now); !errors.Is(err, taskpkg.ErrReferralCapacity) {
		t.Fatalf("want ErrReferralCapacity, got %v", err)
	}
	if got := g.Stats().SeenEntries; got != 0 {
		t.Fatalf("rejected chain left %d entries behind", got)
	}
}

// The response size budget is inclusive and enforced before parsing.
func TestResponseSizeLimit(t *testing.T) {
	g := newGuard(t, testPolicy())
	if err := g.CheckResponseSize(64 * 1024); err != nil {
		t.Fatalf("exact budget rejected: %v", err)
	}
	if err := g.CheckResponseSize(64*1024 + 1); !errors.Is(err, taskpkg.ErrResponseTooLarge) {
		t.Fatalf("want ErrResponseTooLarge, got %v", err)
	}
}

// Concurrent resolution of one chain must remember each url exactly once.
func TestConcurrentResolveSameChainRecordsOnce(t *testing.T) {
	now := time.Unix(baseUnix, 0)
	g := newGuard(t, testPolicy())
	refs := chain([]string{homeHost, "ldap2.corp.example.com"})
	const workers = 8
	errs := make([]error, workers)
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func(idx int) {
			defer wg.Done()
			_, errs[idx] = g.ResolveChain("tenant-a", refs, now)
		}(i)
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatalf("concurrent ResolveChain failed: %v", err)
		}
	}
	stats := g.Stats()
	if stats.SeenEntries != 2 {
		t.Fatalf("SeenEntries = %d, want 2", stats.SeenEntries)
	}
	if stats.Followed != workers*2 {
		t.Fatalf("Followed = %d, want %d", stats.Followed, workers*2)
	}
}

// Remembered referrals must survive a restart and still expire by TTL.
func TestSnapshotRestoresSeenReferrals(t *testing.T) {
	now := time.Unix(baseUnix, 0)
	p := testPolicy()
	g := newGuard(t, p)
	refs := chain([]string{homeHost, "ldap2.corp.example.com"})
	if _, err := g.ResolveChain("tenant-a", refs, now); err != nil {
		t.Fatalf("ResolveChain: %v", err)
	}
	seen, err := g.Seen(refs[0].URL, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("Seen: %v", err)
	}
	if !seen {
		t.Fatalf("resolved referral not remembered")
	}
	snapshot, err := g.Snapshot(now)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	restored, err := taskpkg.NewLdapReferralGuardFromSnapshot(p, snapshot)
	if err != nil {
		t.Fatalf("NewLdapReferralGuardFromSnapshot: %v", err)
	}
	seen, err = restored.Seen(refs[1].URL, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("Seen after restore: %v", err)
	}
	if !seen {
		t.Fatalf("referral forgotten across restart")
	}
	seen, err = restored.Seen(refs[1].URL, now.Add(p.CacheTTL+time.Minute))
	if err != nil {
		t.Fatalf("Seen after TTL: %v", err)
	}
	if seen {
		t.Fatalf("restored referral outlived the cache TTL")
	}
}

// Prune removes expired referral records and reports the count.
func TestPruneExpiredReferralRecords(t *testing.T) {
	now := time.Unix(baseUnix, 0)
	p := testPolicy()
	g := newGuard(t, p)
	refs := chain([]string{homeHost, "ldap2.corp.example.com"})
	if _, err := g.ResolveChain("tenant-a", refs, now); err != nil {
		t.Fatalf("ResolveChain: %v", err)
	}
	if removed := g.Prune(now.Add(p.CacheTTL + time.Minute)); removed != 2 {
		t.Fatalf("Prune removed %d, want 2", removed)
	}
	if got := g.Stats().SeenEntries; got != 0 {
		t.Fatalf("SeenEntries = %d after prune, want 0", got)
	}
	seen, err := g.Seen(refs[0].URL, now.Add(p.CacheTTL+time.Minute))
	if err != nil {
		t.Fatalf("Seen after prune: %v", err)
	}
	if seen {
		t.Fatalf("pruned referral still reported as seen")
	}
}
