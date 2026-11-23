package task

import (
	"errors"
	"sync"
	"testing"
	"time"

	taskpkg "gsb/batch46-safety-c-02"
)

const (
	tenantA = "tenant-a"
	tenantB = "tenant-b"
	portA   = "eth0"
	srcA    = "fe80::1"
	srcB    = "fe80::2"
	pfxA    = "2001:db8:1::/64"
)

func testConfig() taskpkg.Config {
	return taskpkg.Config{
		MaxRouterLifetime: 30 * time.Minute,
		MinAdvertInterval: time.Second,
		PrefixLength:      64,
		MaxRouters:        8,
	}
}

func mustGuard(t *testing.T, cfg taskpkg.Config) *taskpkg.RaGuard {
	t.Helper()
	g := taskpkg.NewRaGuard(cfg)
	if err := g.TrustPort(portA); err != nil {
		t.Fatalf("TrustPort: %v", err)
	}
	if err := g.TrustRouter(srcA, tenantA); err != nil {
		t.Fatalf("TrustRouter: %v", err)
	}
	return g
}

func validRA() taskpkg.RouterAdvert {
	return taskpkg.RouterAdvert{
		Source:         srcA,
		Interface:      portA,
		TenantID:       tenantA,
		HopLimit:       255,
		RouterLifetime: 10 * time.Minute,
		Preference:     "medium",
		Prefixes: []taskpkg.PrefixInfo{{
			CIDR:              pfxA,
			ValidLifetime:     time.Hour,
			PreferredLifetime: 30 * time.Minute,
			Autonomous:        true,
			OnLink:            true,
		}},
	}
}

// Advertisements arriving on an untrusted port or from an untrusted router
// must be dropped.
func TestProcessRejectsUntrustedSource(t *testing.T) {
	now := time.Unix(1700000000, 0)
	g := mustGuard(t, testConfig())
	onBadPort := validRA()
	onBadPort.Interface = "eth9"
	if err := g.Process(onBadPort, now); !errors.Is(err, taskpkg.ErrPort) {
		t.Fatalf("advertisement on eth9 = %v, want ErrPort", err)
	}
	fromStranger := validRA()
	fromStranger.Source = "fe80::99"
	if err := g.Process(fromStranger, now); !errors.Is(err, taskpkg.ErrRouter) {
		t.Fatalf("advertisement from an untrusted router = %v, want ErrRouter", err)
	}
}

// A router trusted for one tenant must not speak for another tenant.
func TestProcessRejectsCrossTenant(t *testing.T) {
	now := time.Unix(1700000000, 0)
	g := mustGuard(t, testConfig())
	ra := validRA()
	ra.TenantID = tenantB
	if err := g.Process(ra, now); !errors.Is(err, taskpkg.ErrTenant) {
		t.Fatalf("cross tenant advertisement = %v, want ErrTenant", err)
	}
}

// RFC 4861 requires a hop limit of 255 on received advertisements.
func TestProcessRejectsBadHopLimit(t *testing.T) {
	now := time.Unix(1700000000, 0)
	g := mustGuard(t, testConfig())
	ra := validRA()
	ra.HopLimit = 64
	if err := g.Process(ra, now); !errors.Is(err, taskpkg.ErrHopLimit) {
		t.Fatalf("hop limit 64 = %v, want ErrHopLimit", err)
	}
}

// A router claiming a lifetime above the policy cap must be dropped.
func TestProcessRejectsRouterLifetimeAboveCap(t *testing.T) {
	now := time.Unix(1700000000, 0)
	g := mustGuard(t, testConfig())
	ra := validRA()
	ra.RouterLifetime = time.Hour
	if err := g.Process(ra, now); !errors.Is(err, taskpkg.ErrLifetime) {
		t.Fatalf("router lifetime 1h with a 30m cap = %v, want ErrLifetime", err)
	}
	ra.RouterLifetime = -time.Second
	if err := g.Process(ra, now); !errors.Is(err, taskpkg.ErrLifetime) {
		t.Fatalf("negative router lifetime = %v, want ErrLifetime", err)
	}
}

// Only the configured SLAAC prefix length is accepted.
func TestProcessRejectsNon64PrefixLength(t *testing.T) {
	now := time.Unix(1700000000, 0)
	g := mustGuard(t, testConfig())
	ra := validRA()
	ra.Prefixes[0].CIDR = "2001:db8:2::/48"
	if err := g.Process(ra, now); !errors.Is(err, taskpkg.ErrPrefixLen) {
		t.Fatalf("prefix length 48 = %v, want ErrPrefixLen", err)
	}
}

// Unique local prefixes are dropped unless the policy allows them.
func TestProcessRejectsULAUnlessAllowed(t *testing.T) {
	now := time.Unix(1700000000, 0)
	cfg := testConfig()
	g := mustGuard(t, cfg)
	ula := validRA()
	ula.Prefixes[0].CIDR = "fd12:3456:789a:1::/64"
	if err := g.Process(ula, now); !errors.Is(err, taskpkg.ErrULA) {
		t.Fatalf("ULA prefix = %v, want ErrULA", err)
	}
	cfg.AllowULA = true
	allow := mustGuard(t, cfg)
	if err := allow.Process(ula, now); err != nil {
		t.Fatalf("ULA prefix with AllowULA rejected: %v", err)
	}
	got := allow.LearnedPrefixes(now)
	if len(got) != 1 || got[0] != "fd12:3456:789a:1::/64" {
		t.Fatalf("LearnedPrefixes = %v, want the ULA prefix", got)
	}
}

// The managed address configuration flag is only allowed when configured.
func TestProcessRejectsManagedFlag(t *testing.T) {
	now := time.Unix(1700000000, 0)
	g := mustGuard(t, testConfig())
	ra := validRA()
	ra.ManagedFlag = true
	if err := g.Process(ra, now); !errors.Is(err, taskpkg.ErrManaged) {
		t.Fatalf("managed flag = %v, want ErrManaged", err)
	}
}

// A prefix option whose preferred lifetime exceeds its valid lifetime is
// inconsistent and must be dropped.
func TestProcessRejectsPreferredAboveValid(t *testing.T) {
	now := time.Unix(1700000000, 0)
	g := mustGuard(t, testConfig())
	ra := validRA()
	ra.Prefixes[0].PreferredLifetime = 2 * time.Hour
	ra.Prefixes[0].ValidLifetime = time.Hour
	if err := g.Process(ra, now); !errors.Is(err, taskpkg.ErrPrefixLifetime) {
		t.Fatalf("preferred lifetime above valid lifetime = %v, want ErrPrefixLifetime", err)
	}
}

// Repeated advertisements from one router inside the interval are dropped,
// and the router is accepted again once the interval elapsed.
func TestProcessRateLimitsDuplicateAdvertise(t *testing.T) {
	now := time.Unix(1700000000, 0)
	g := mustGuard(t, testConfig())
	ra := validRA()
	if err := g.Process(ra, now); err != nil {
		t.Fatalf("first advertisement: %v", err)
	}
	if err := g.Process(ra, now.Add(100*time.Millisecond)); !errors.Is(err, taskpkg.ErrRate) {
		t.Fatalf("second advertisement after 100ms = %v, want ErrRate", err)
	}
	if err := g.Process(ra, now.Add(2*time.Second)); err != nil {
		t.Fatalf("advertisement after the interval was rejected: %v", err)
	}
}

// A valid advertisement must install a default router and its prefix.
func TestProcessLearnsDefaultRouterAndPrefix(t *testing.T) {
	now := time.Unix(1700000000, 0)
	g := mustGuard(t, testConfig())
	if err := g.Process(validRA(), now); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if !g.IsDefaultRouter(srcA, now) {
		t.Fatalf("%s is not a default router after a valid advertisement", srcA)
	}
	routers := g.DefaultRouters(now)
	if len(routers) != 1 {
		t.Fatalf("DefaultRouters = %v, want one router", routers)
	}
	if routers[0].Address != srcA || routers[0].Lifetime != 10*time.Minute {
		t.Fatalf("learned router = %+v, want %s with a 10m lifetime", routers[0], srcA)
	}
	prefixes := g.LearnedPrefixes(now)
	if len(prefixes) != 1 || prefixes[0] != pfxA {
		t.Fatalf("LearnedPrefixes = %v, want [%s]", prefixes, pfxA)
	}
}

// A prefix option with a zero valid lifetime withdraws the prefix while the
// router stays a default router.
func TestPrefixWithdrawalRemovesPrefix(t *testing.T) {
	now := time.Unix(1700000000, 0)
	g := mustGuard(t, testConfig())
	if err := g.Process(validRA(), now); err != nil {
		t.Fatalf("first advertisement: %v", err)
	}
	withdraw := validRA()
	withdraw.Prefixes[0].ValidLifetime = 0
	withdraw.Prefixes[0].PreferredLifetime = 0
	later := now.Add(2 * time.Second)
	if err := g.Process(withdraw, later); err != nil {
		t.Fatalf("withdrawal advertisement: %v", err)
	}
	if got := g.LearnedPrefixes(later); len(got) != 0 {
		t.Fatalf("LearnedPrefixes after withdrawal = %v, want none", got)
	}
	if !g.IsDefaultRouter(srcA, later) {
		t.Fatalf("withdrawing a prefix dropped the default router")
	}
}

// The learned router table is bounded; a freed slot can be reused.
func TestRouterTableCapacity(t *testing.T) {
	now := time.Unix(1700000000, 0)
	cfg := testConfig()
	cfg.MaxRouters = 1
	g := mustGuard(t, cfg)
	if err := g.TrustRouter(srcB, tenantA); err != nil {
		t.Fatalf("TrustRouter: %v", err)
	}
	if err := g.Process(validRA(), now); err != nil {
		t.Fatalf("first router: %v", err)
	}
	second := validRA()
	second.Source = srcB
	if err := g.Process(second, now); !errors.Is(err, taskpkg.ErrCapacity) {
		t.Fatalf("second router with MaxRouters 1 = %v, want ErrCapacity", err)
	}
	if n := g.Sweep(now.Add(time.Hour)); n != 1 {
		t.Fatalf("Sweep removed %d routers, want 1", n)
	}
	if err := g.Process(second, now.Add(time.Hour)); err != nil {
		t.Fatalf("router after a slot was freed: %v", err)
	}
}

// Routers must stop being default once their lifetime ran out.
func TestSweepExpiresRouter(t *testing.T) {
	now := time.Unix(1700000000, 0)
	g := mustGuard(t, testConfig())
	if err := g.Process(validRA(), now); err != nil {
		t.Fatalf("Process: %v", err)
	}
	later := now.Add(11 * time.Minute)
	if g.IsDefaultRouter(srcA, later) {
		t.Fatalf("%s is still default after its 10m lifetime", srcA)
	}
	if n := g.Sweep(later); n != 1 {
		t.Fatalf("Sweep removed %d routers, want 1", n)
	}
	if got := g.DefaultRouters(later); len(got) != 0 {
		t.Fatalf("DefaultRouters after sweep = %v, want none", got)
	}
	if g.Stats().Routers != 0 {
		t.Fatalf("Stats().Routers = %d after sweep, want 0", g.Stats().Routers)
	}
}

// A restarted guard must keep its learned routers, prefixes and trusted
// configuration.
func TestSnapshotRestoresRouterTable(t *testing.T) {
	now := time.Unix(1700000000, 0)
	cfg := testConfig()
	g := mustGuard(t, cfg)
	if err := g.Process(validRA(), now); err != nil {
		t.Fatalf("Process: %v", err)
	}
	snap, err := g.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	restored, err := taskpkg.NewRaGuardFromSnapshot(cfg, snap)
	if err != nil {
		t.Fatalf("NewRaGuardFromSnapshot: %v", err)
	}
	if !restored.IsDefaultRouter(srcA, now) {
		t.Fatalf("restored guard lost the default router")
	}
	prefixes := restored.LearnedPrefixes(now)
	if len(prefixes) != 1 || prefixes[0] != pfxA {
		t.Fatalf("restored prefixes = %v, want [%s]", prefixes, pfxA)
	}
	if err := restored.Process(validRA(), now.Add(2*time.Second)); err != nil {
		t.Fatalf("Process after restart: %v", err)
	}
}

// Two concurrent copies of the same advertisement must not both be accepted.
func TestConcurrentDuplicateAdvertise(t *testing.T) {
	now := time.Unix(1700000000, 0)
	g := mustGuard(t, testConfig())
	ra := validRA()
	var wg sync.WaitGroup
	errs := make([]error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		errs[0] = g.Process(ra, now)
	}()
	go func() {
		defer wg.Done()
		errs[1] = g.Process(ra, now)
	}()
	wg.Wait()
	successes := 0
	for _, err := range errs {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent duplicate advertisements: %d accepted, want exactly 1", successes)
	}
	if got := len(g.DefaultRouters(now)); got != 1 {
		t.Fatalf("learned routers after the race = %d, want 1", got)
	}
}
