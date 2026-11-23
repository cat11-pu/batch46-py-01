package task

import (
	"errors"
	"sync"
	"testing"
	"time"

	taskpkg "gsb/batch46-safety-c-01"
)

const (
	tenantA = "tenant-a"
	tenantB = "tenant-b"
	serverA = "duid-server-a"
	clientA = "duid-client-a"
	clientB = "duid-client-b"
	prefixA = "2001:db8:100:100::/56"
	prefixB = "2001:db8:100:200::/56"
	prefixC = "2001:db8:100:300::/56"
)

func testConfig() taskpkg.Config {
	return taskpkg.Config{
		MinPrefixLen:       48,
		MaxPrefixLen:       64,
		MaxLeasesPerTenant: 10,
		OfferTTL:           5 * time.Minute,
		AdvertiseInterval:  time.Second,
		LeaseTTL:           time.Hour,
	}
}

func mustGuard(t *testing.T, cfg taskpkg.Config) *taskpkg.Dhcpv6Guard {
	t.Helper()
	g := taskpkg.NewDhcpv6Guard(cfg)
	if err := g.AddServer(serverA, tenantA); err != nil {
		t.Fatalf("AddServer: %v", err)
	}
	if err := g.AddPool("2001:db8:100::/48"); err != nil {
		t.Fatalf("AddPool: %v", err)
	}
	return g
}

func advertise(server, client string, iaid uint32, prefix string) taskpkg.Advertise {
	return taskpkg.Advertise{
		ServerDUID:        server,
		ClientDUID:        client,
		IAID:              iaid,
		TenantID:          tenantA,
		Prefix:            prefix,
		ValidLifetime:     2 * time.Hour,
		PreferredLifetime: time.Hour,
	}
}

func mustScreen(t *testing.T, g *taskpkg.Dhcpv6Guard, adv taskpkg.Advertise, now time.Time) taskpkg.Offer {
	t.Helper()
	offer, err := g.Screen(adv, now)
	if err != nil {
		t.Fatalf("Screen(%s, %s): %v", adv.ClientDUID, adv.Prefix, err)
	}
	return offer
}

// An advertisement from a server that was never trusted must be dropped.
func TestScreenRejectsUntrustedServer(t *testing.T) {
	now := time.Unix(1700000000, 0)
	g := mustGuard(t, testConfig())
	adv := advertise("duid-rogue", clientA, 1, prefixA)
	if _, err := g.Screen(adv, now); !errors.Is(err, taskpkg.ErrServer) {
		t.Fatalf("advertisement from an unknown server = %v, want ErrServer", err)
	}
}

// A prefix outside every registered pool must be dropped.
func TestScreenRejectsPrefixOutsidePool(t *testing.T) {
	now := time.Unix(1700000000, 0)
	g := mustGuard(t, testConfig())
	adv := advertise(serverA, clientA, 1, "2001:db8:dead::/56")
	if _, err := g.Screen(adv, now); !errors.Is(err, taskpkg.ErrPool) {
		t.Fatalf("prefix outside the pool = %v, want ErrPool", err)
	}
}

// A delegated block larger than the configured minimum must be dropped.
func TestScreenRejectsPrefixTooShort(t *testing.T) {
	now := time.Unix(1700000000, 0)
	g := mustGuard(t, testConfig())
	adv := advertise(serverA, clientA, 1, "2001:db8::/40")
	if _, err := g.Screen(adv, now); !errors.Is(err, taskpkg.ErrPrefixLen) {
		t.Fatalf("prefix length 40 = %v, want ErrPrefixLen", err)
	}
}

// A delegated block smaller than the configured maximum must be dropped.
func TestScreenRejectsPrefixTooLong(t *testing.T) {
	now := time.Unix(1700000000, 0)
	g := mustGuard(t, testConfig())
	adv := advertise(serverA, clientA, 1, "2001:db8:100:100::/72")
	if _, err := g.Screen(adv, now); !errors.Is(err, taskpkg.ErrPrefixLen) {
		t.Fatalf("prefix length 72 = %v, want ErrPrefixLen", err)
	}
}

// A server trusted for one tenant must not answer clients of another tenant.
func TestScreenRejectsCrossTenantServer(t *testing.T) {
	now := time.Unix(1700000000, 0)
	g := mustGuard(t, testConfig())
	adv := advertise(serverA, clientA, 1, prefixA)
	adv.TenantID = tenantB
	if _, err := g.Screen(adv, now); !errors.Is(err, taskpkg.ErrTenant) {
		t.Fatalf("cross tenant advertisement = %v, want ErrTenant", err)
	}
}

// Zero or inconsistent lifetimes must be dropped instead of clamped silently.
func TestScreenRejectsInvalidLifetime(t *testing.T) {
	now := time.Unix(1700000000, 0)
	g := mustGuard(t, testConfig())
	zero := advertise(serverA, clientA, 1, prefixA)
	zero.ValidLifetime = 0
	if _, err := g.Screen(zero, now); !errors.Is(err, taskpkg.ErrLifetime) {
		t.Fatalf("zero valid lifetime = %v, want ErrLifetime", err)
	}
	inverted := advertise(serverA, clientB, 2, prefixB)
	inverted.PreferredLifetime = 90 * time.Minute
	inverted.ValidLifetime = time.Hour
	if _, err := g.Screen(inverted, now); !errors.Is(err, taskpkg.ErrLifetime) {
		t.Fatalf("preferred lifetime above valid lifetime = %v, want ErrLifetime", err)
	}
}

// Two advertisements for the same client from the same server inside the
// configured interval must be rate limited.
func TestScreenRateLimitsRapidAdvertise(t *testing.T) {
	now := time.Unix(1700000000, 0)
	g := mustGuard(t, testConfig())
	adv := advertise(serverA, clientA, 1, prefixA)
	mustScreen(t, g, adv, now)
	if _, err := g.Screen(adv, now.Add(500*time.Millisecond)); !errors.Is(err, taskpkg.ErrRate) {
		t.Fatalf("second advertisement after 500ms = %v, want ErrRate", err)
	}
	if _, err := g.Screen(adv, now.Add(2*time.Second)); err != nil {
		t.Fatalf("advertisement after the interval was rejected: %v", err)
	}
}

// Committing a screened offer must produce a lease with T1/T2 timers and a
// lifetime capped by the lease TTL, and the lease must be queryable.
func TestCommitCreatesLeaseAndLookup(t *testing.T) {
	now := time.Unix(1700000000, 0)
	cfg := testConfig()
	g := mustGuard(t, cfg)
	offer := mustScreen(t, g, advertise(serverA, clientA, 7, prefixA), now)
	lease, err := g.Commit(offer.ID, now)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if lease.Prefix != prefixA {
		t.Fatalf("lease prefix = %q, want %q", lease.Prefix, prefixA)
	}
	if lease.ClientDUID != clientA || lease.IAID != 7 {
		t.Fatalf("lease identity = %q/%d, want %q/7", lease.ClientDUID, lease.IAID, clientA)
	}
	if !lease.ExpiresAt.Equal(now.Add(cfg.LeaseTTL)) {
		t.Fatalf("lease expiry = %v, want %v", lease.ExpiresAt, now.Add(cfg.LeaseTTL))
	}
	if lease.T1 != cfg.LeaseTTL/2 {
		t.Fatalf("T1 = %v, want %v", lease.T1, cfg.LeaseTTL/2)
	}
	if lease.T2 != cfg.LeaseTTL*4/5 {
		t.Fatalf("T2 = %v, want %v", lease.T2, cfg.LeaseTTL*4/5)
	}
	got, ok := g.LeaseFor(clientA, 7)
	if !ok || got.Prefix != prefixA {
		t.Fatalf("LeaseFor = %+v, %v; want the committed lease", got, ok)
	}
}

// Re-committing the same offer must return the same lease and must not create
// a second one.
func TestCommitIsIdempotent(t *testing.T) {
	now := time.Unix(1700000000, 0)
	g := mustGuard(t, testConfig())
	offer := mustScreen(t, g, advertise(serverA, clientA, 1, prefixA), now)
	first, err := g.Commit(offer.ID, now)
	if err != nil {
		t.Fatalf("first Commit: %v", err)
	}
	second, err := g.Commit(offer.ID, now.Add(10*time.Second))
	if err != nil {
		t.Fatalf("idempotent Commit: %v", err)
	}
	if second.Prefix != first.Prefix || !second.ExpiresAt.Equal(first.ExpiresAt) {
		t.Fatalf("second commit changed the lease: %+v vs %+v", second, first)
	}
	if got := g.Stats().Leases; got != 1 {
		t.Fatalf("active leases after double commit = %d, want 1", got)
	}
}

// A client may hold only one delegated prefix per IA_PD.
func TestCommitRejectsSecondPrefixForSameIAID(t *testing.T) {
	now := time.Unix(1700000000, 0)
	g := mustGuard(t, testConfig())
	first := mustScreen(t, g, advertise(serverA, clientA, 1, prefixA), now)
	if _, err := g.Commit(first.ID, now); err != nil {
		t.Fatalf("first Commit: %v", err)
	}
	second := mustScreen(t, g, advertise(serverA, clientA, 1, prefixB), now.Add(2*time.Second))
	if _, err := g.Commit(second.ID, now.Add(2*time.Second)); !errors.Is(err, taskpkg.ErrBound) {
		t.Fatalf("second prefix for one IA_PD = %v, want ErrBound", err)
	}
}

// A prefix overlapping an active lease must not be handed to another client.
func TestCommitRejectsOverlappingPrefix(t *testing.T) {
	now := time.Unix(1700000000, 0)
	g := mustGuard(t, testConfig())
	first := mustScreen(t, g, advertise(serverA, clientA, 1, prefixA), now)
	if _, err := g.Commit(first.ID, now); err != nil {
		t.Fatalf("Commit %s: %v", prefixA, err)
	}
	overlap := mustScreen(t, g, advertise(serverA, clientB, 1, "2001:db8:100:100::/57"), now)
	if _, err := g.Commit(overlap.ID, now); !errors.Is(err, taskpkg.ErrConflict) {
		t.Fatalf("overlapping prefix = %v, want ErrConflict", err)
	}
}

// The per-tenant lease quota must stop new clients, and a release must hand
// the slot back so the pending offer can still be committed.
func TestTenantLeaseQuota(t *testing.T) {
	now := time.Unix(1700000000, 0)
	cfg := testConfig()
	cfg.MaxLeasesPerTenant = 2
	g := mustGuard(t, cfg)
	o1 := mustScreen(t, g, advertise(serverA, clientA, 1, prefixA), now)
	o2 := mustScreen(t, g, advertise(serverA, clientB, 1, prefixB), now)
	o3 := mustScreen(t, g, advertise(serverA, "duid-client-c", 1, prefixC), now)
	if _, err := g.Commit(o1.ID, now); err != nil {
		t.Fatalf("Commit client-a: %v", err)
	}
	if _, err := g.Commit(o2.ID, now); err != nil {
		t.Fatalf("Commit client-b: %v", err)
	}
	if _, err := g.Commit(o3.ID, now); !errors.Is(err, taskpkg.ErrQuota) {
		t.Fatalf("third tenant lease = %v, want ErrQuota", err)
	}
	if err := g.Release(clientB, 1, now); err != nil {
		t.Fatalf("Release client-b: %v", err)
	}
	if _, err := g.Commit(o3.ID, now); err != nil {
		t.Fatalf("Commit after release: %v", err)
	}
}

// Expired leases must disappear and free their prefix for another client.
func TestExpireFreesPrefix(t *testing.T) {
	now := time.Unix(1700000000, 0)
	cfg := testConfig()
	g := mustGuard(t, cfg)
	offer := mustScreen(t, g, advertise(serverA, clientA, 1, prefixA), now)
	if _, err := g.Commit(offer.ID, now); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if n := g.Expire(now.Add(cfg.LeaseTTL / 2)); n != 0 {
		t.Fatalf("Expire before the deadline removed %d leases, want 0", n)
	}
	if n := g.Expire(now.Add(cfg.LeaseTTL + time.Second)); n != 1 {
		t.Fatalf("Expire after the deadline removed %d leases, want 1", n)
	}
	if _, ok := g.LeaseFor(clientA, 1); ok {
		t.Fatalf("expired lease is still visible")
	}
	next := now.Add(cfg.LeaseTTL + 2*time.Second)
	second := mustScreen(t, g, advertise(serverA, clientB, 1, prefixA), next)
	if _, err := g.Commit(second.ID, next); err != nil {
		t.Fatalf("Commit on the freed prefix: %v", err)
	}
}

// A restarted guard must still know its leases, trusted servers and pools.
func TestSnapshotRestoresLeasesAndPools(t *testing.T) {
	now := time.Unix(1700000000, 0)
	cfg := testConfig()
	g := mustGuard(t, cfg)
	offer := mustScreen(t, g, advertise(serverA, clientA, 1, prefixA), now)
	if _, err := g.Commit(offer.ID, now); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	snap, err := g.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	restored, err := taskpkg.NewDhcpv6GuardFromSnapshot(cfg, snap)
	if err != nil {
		t.Fatalf("NewDhcpv6GuardFromSnapshot: %v", err)
	}
	lease, ok := restored.LeaseFor(clientA, 1)
	if !ok || lease.Prefix != prefixA {
		t.Fatalf("restored LeaseFor = %+v, %v; want %q", lease, ok, prefixA)
	}
	if lease.T1 != cfg.LeaseTTL/2 || lease.T2 != cfg.LeaseTTL*4/5 {
		t.Fatalf("restored timers = %v/%v", lease.T1, lease.T2)
	}
	later := now.Add(time.Minute)
	again := mustScreen(t, restored, advertise(serverA, clientA, 1, prefixA), later)
	if _, err := restored.Commit(again.ID, later); err != nil {
		t.Fatalf("Commit after restart: %v", err)
	}
	if got := restored.Stats().Leases; got != 1 {
		t.Fatalf("leases after restart = %d, want 1", got)
	}
}

// Two commits racing on overlapping prefixes must not both succeed.
func TestConcurrentCommitSingleWinner(t *testing.T) {
	now := time.Unix(1700000000, 0)
	g := mustGuard(t, testConfig())
	first := mustScreen(t, g, advertise(serverA, clientA, 1, prefixA), now)
	second := mustScreen(t, g, advertise(serverA, clientB, 1, "2001:db8:100:100::/57"), now)
	var wg sync.WaitGroup
	errs := make([]error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, errs[0] = g.Commit(first.ID, now)
	}()
	go func() {
		defer wg.Done()
		_, errs[1] = g.Commit(second.ID, now)
	}()
	wg.Wait()
	successes := 0
	for _, err := range errs {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent overlapping commits: %d succeeded, want exactly 1", successes)
	}
	if got := g.Stats().Leases; got != 1 {
		t.Fatalf("leases after the race = %d, want 1", got)
	}
}
