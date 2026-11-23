package task

import (
	"errors"
	"sync"
	"testing"
	"time"

	taskpkg "gsb/batch46-safety-c-03"
)

const (
	tenantA = "tenant-a"
	tenantB = "tenant-b"
	ifaceA  = "eth0"
	ifaceB  = "eth1"
	macA    = "00:11:22:33:44:01"
	macB    = "00:11:22:33:44:02"
	macC    = "00:11:22:33:44:03"
	ipA     = "2001:db8::10"
	ipB     = "2001:db8::20"
	ipC     = "2001:db8::30"
)

func testConfig() taskpkg.Config {
	return taskpkg.Config{
		MaxEntries:    8,
		MaxIPsPerMAC:  8,
		ReachableTime: 30 * time.Second,
		StaleTime:     5 * time.Minute,
	}
}

func advertise(ip, mac, iface, tenant string) taskpkg.Advertisement {
	return taskpkg.Advertisement{IP: ip, MAC: mac, Interface: iface, TenantID: tenant}
}

func mustProcess(t *testing.T, g *taskpkg.NdpGuard, adv taskpkg.Advertisement, now time.Time) {
	t.Helper()
	if err := g.Process(adv, now); err != nil {
		t.Fatalf("Process(%s, %s): %v", adv.IP, adv.MAC, err)
	}
}

// The first advertisement for an address installs a reachable entry.
func TestFirstAdvertisementCreatesReachableEntry(t *testing.T) {
	now := time.Unix(1700000000, 0)
	g := taskpkg.NewNdpGuard(testConfig())
	mustProcess(t, g, advertise(ipA, macA, ifaceA, tenantA), now)
	n, ok := g.Lookup(ipA, now)
	if !ok {
		t.Fatalf("Lookup(%s) found nothing after the first advertisement", ipA)
	}
	if n.MAC != macA || n.Interface != ifaceA || n.TenantID != tenantA {
		t.Fatalf("entry = %+v, want %s/%s/%s", n, macA, ifaceA, tenantA)
	}
	if n.State != taskpkg.StateReachable {
		t.Fatalf("state = %q, want %q", n.State, taskpkg.StateReachable)
	}
	if g.Len() != 1 {
		t.Fatalf("Len = %d, want 1", g.Len())
	}
}

// Repeating the same advertisement refreshes the entry instead of adding a
// second one.
func TestDuplicateAdvertisementIsIdempotent(t *testing.T) {
	now := time.Unix(1700000000, 0)
	g := taskpkg.NewNdpGuard(testConfig())
	mustProcess(t, g, advertise(ipA, macA, ifaceA, tenantA), now)
	later := now.Add(time.Second)
	mustProcess(t, g, advertise(ipA, macA, ifaceA, tenantA), later)
	if g.Len() != 1 {
		t.Fatalf("Len after duplicate advertisement = %d, want 1", g.Len())
	}
	n, ok := g.Lookup(ipA, later)
	if !ok || !n.UpdatedAt.Equal(later) {
		t.Fatalf("entry was not refreshed: %+v, %v", n, ok)
	}
}

// A dynamic entry must not move to another MAC when override is disabled.
func TestMacChangeRejectedWhenOverrideDisabled(t *testing.T) {
	now := time.Unix(1700000000, 0)
	g := taskpkg.NewNdpGuard(testConfig())
	mustProcess(t, g, advertise(ipA, macA, ifaceA, tenantA), now)
	if err := g.Process(advertise(ipA, macB, ifaceA, tenantA), now.Add(time.Second)); !errors.Is(err, taskpkg.ErrSpoof) {
		t.Fatalf("MAC change with override disabled = %v, want ErrSpoof", err)
	}
	n, ok := g.Lookup(ipA, now.Add(time.Second))
	if !ok || n.MAC != macA {
		t.Fatalf("entry moved despite the rejection: %+v, %v", n, ok)
	}
}

// With override enabled the entry moves, but only into the stale state so it
// must be confirmed before it is trusted again.
func TestMacChangeAcceptedWhenOverrideEnabled(t *testing.T) {
	now := time.Unix(1700000000, 0)
	cfg := testConfig()
	cfg.AllowOverride = true
	g := taskpkg.NewNdpGuard(cfg)
	mustProcess(t, g, advertise(ipA, macA, ifaceA, tenantA), now)
	later := now.Add(time.Second)
	if err := g.Process(advertise(ipA, macB, ifaceA, tenantA), later); err != nil {
		t.Fatalf("MAC change with override enabled: %v", err)
	}
	n, ok := g.Lookup(ipA, later)
	if !ok || n.MAC != macB {
		t.Fatalf("entry = %+v, %v; want the new MAC", n, ok)
	}
	if n.State != taskpkg.StateStale {
		t.Fatalf("state after an override = %q, want %q", n.State, taskpkg.StateStale)
	}
}

// Static bindings may never be overridden, even with AllowOverride set.
func TestStaticBindingBlocksSpoof(t *testing.T) {
	now := time.Unix(1700000000, 0)
	cfg := testConfig()
	cfg.AllowOverride = true
	g := taskpkg.NewNdpGuard(cfg)
	if err := g.Bind(ipA, macA, ifaceA, tenantA); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if err := g.Process(advertise(ipA, macB, ifaceA, tenantA), now); !errors.Is(err, taskpkg.ErrSpoof) {
		t.Fatalf("advertisement against a static binding = %v, want ErrSpoof", err)
	}
	n, ok := g.Lookup(ipA, now)
	if !ok || n.MAC != macA || !n.Static {
		t.Fatalf("static entry was mutated: %+v, %v", n, ok)
	}
}

// One address must not be claimed from two interfaces.
func TestInterfaceConflictRejected(t *testing.T) {
	now := time.Unix(1700000000, 0)
	g := taskpkg.NewNdpGuard(testConfig())
	mustProcess(t, g, advertise(ipA, macA, ifaceA, tenantA), now)
	if err := g.Process(advertise(ipA, macA, ifaceB, tenantA), now.Add(time.Second)); !errors.Is(err, taskpkg.ErrInterface) {
		t.Fatalf("same address on another interface = %v, want ErrInterface", err)
	}
}

// An entry owned by one tenant must not be taken over by another tenant.
func TestCrossTenantRejected(t *testing.T) {
	now := time.Unix(1700000000, 0)
	g := taskpkg.NewNdpGuard(testConfig())
	mustProcess(t, g, advertise(ipA, macA, ifaceA, tenantA), now)
	if err := g.Process(advertise(ipA, macB, ifaceA, tenantB), now.Add(time.Second)); !errors.Is(err, taskpkg.ErrTenant) {
		t.Fatalf("cross tenant advertisement = %v, want ErrTenant", err)
	}
}

// One MAC may own only MaxIPsPerMAC addresses.
func TestPerMacQuotaEnforced(t *testing.T) {
	now := time.Unix(1700000000, 0)
	cfg := testConfig()
	cfg.MaxIPsPerMAC = 2
	g := taskpkg.NewNdpGuard(cfg)
	mustProcess(t, g, advertise(ipA, macA, ifaceA, tenantA), now)
	mustProcess(t, g, advertise(ipB, macA, ifaceA, tenantA), now)
	if err := g.Process(advertise(ipC, macA, ifaceA, tenantA), now); !errors.Is(err, taskpkg.ErrQuota) {
		t.Fatalf("third address for one MAC = %v, want ErrQuota", err)
	}
	mustProcess(t, g, advertise(ipC, macB, ifaceA, tenantA), now)
	if g.Len() != 3 {
		t.Fatalf("Len = %d, want 3", g.Len())
	}
}

// A full cache with no stale entry must reject a new address instead of
// growing without bound.
func TestCacheFullRejectsNewEntry(t *testing.T) {
	now := time.Unix(1700000000, 0)
	cfg := testConfig()
	cfg.MaxEntries = 2
	g := taskpkg.NewNdpGuard(cfg)
	mustProcess(t, g, advertise(ipA, macA, ifaceA, tenantA), now)
	mustProcess(t, g, advertise(ipB, macB, ifaceA, tenantA), now)
	if err := g.Process(advertise(ipC, macC, ifaceA, tenantA), now); !errors.Is(err, taskpkg.ErrFull) {
		t.Fatalf("new address into a full cache = %v, want ErrFull", err)
	}
	if g.Len() != 2 {
		t.Fatalf("Len = %d, want 2", g.Len())
	}
}

// A stale entry is evicted before any reachable one when the cache is full.
func TestEvictionPrefersStaleEntry(t *testing.T) {
	now := time.Unix(1700000000, 0)
	cfg := testConfig()
	cfg.MaxEntries = 2
	g := taskpkg.NewNdpGuard(cfg)
	mustProcess(t, g, advertise(ipA, macA, ifaceA, tenantA), now)
	mustProcess(t, g, advertise(ipB, macB, ifaceA, tenantA), now)
	mustProcess(t, g, advertise(ipA, macA, ifaceA, tenantA), now.Add(20*time.Second))
	later := now.Add(31 * time.Second)
	mustProcess(t, g, advertise(ipC, macC, ifaceA, tenantA), later)
	if _, ok := g.Lookup(ipB, later); ok {
		t.Fatalf("stale entry %s was not evicted", ipB)
	}
	if _, ok := g.Lookup(ipA, later); !ok {
		t.Fatalf("reachable entry %s was evicted", ipA)
	}
	if g.Len() != 2 {
		t.Fatalf("Len = %d, want 2", g.Len())
	}
}

// An entry decays from reachable to stale after ReachableTime without traffic.
func TestReachableExpiresToStale(t *testing.T) {
	now := time.Unix(1700000000, 0)
	cfg := testConfig()
	g := taskpkg.NewNdpGuard(cfg)
	mustProcess(t, g, advertise(ipA, macA, ifaceA, tenantA), now)
	n, ok := g.Lookup(ipA, now.Add(cfg.ReachableTime+time.Second))
	if !ok {
		t.Fatalf("entry expired too early")
	}
	if n.State != taskpkg.StateStale {
		t.Fatalf("state after ReachableTime = %q, want %q", n.State, taskpkg.StateStale)
	}
}

// A stale entry must survive the probe lifecycle and only become reachable
// after a confirmation from the bound MAC.
func TestProbeConfirmLifecycle(t *testing.T) {
	now := time.Unix(1700000000, 0)
	cfg := testConfig()
	g := taskpkg.NewNdpGuard(cfg)
	mustProcess(t, g, advertise(ipA, macA, ifaceA, tenantA), now)
	later := now.Add(cfg.ReachableTime + time.Second)
	if err := g.Probe(ipA, later); err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if n, _ := g.Lookup(ipA, later); n.State != taskpkg.StateProbe {
		t.Fatalf("state after Probe = %q, want %q", n.State, taskpkg.StateProbe)
	}
	if err := g.Confirm(ipA, macB, later); !errors.Is(err, taskpkg.ErrSpoof) {
		t.Fatalf("wrong MAC confirmation = %v, want ErrSpoof", err)
	}
	if n, _ := g.Lookup(ipA, later); n.State != taskpkg.StateStale {
		t.Fatalf("state after a failed probe = %q, want %q", n.State, taskpkg.StateStale)
	}
	if err := g.Probe(ipA, later); err != nil {
		t.Fatalf("second Probe: %v", err)
	}
	if err := g.Confirm(ipA, macA, later); err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	if n, ok := g.Lookup(ipA, later); !ok || n.State != taskpkg.StateReachable || n.MAC != macA {
		t.Fatalf("state after confirmation = %+v, %v", n, ok)
	}
}

// Purging an interface drops its entries and releases the per-MAC quota.
func TestPurgeByInterfaceFreesQuota(t *testing.T) {
	now := time.Unix(1700000000, 0)
	cfg := testConfig()
	cfg.MaxIPsPerMAC = 2
	g := taskpkg.NewNdpGuard(cfg)
	mustProcess(t, g, advertise(ipA, macA, ifaceA, tenantA), now)
	mustProcess(t, g, advertise(ipB, macA, ifaceA, tenantA), now)
	mustProcess(t, g, advertise(ipC, macB, ifaceB, tenantA), now)
	if err := g.Process(advertise("2001:db8::40", macA, ifaceA, tenantA), now); !errors.Is(err, taskpkg.ErrQuota) {
		t.Fatalf("quota check before purge = %v, want ErrQuota", err)
	}
	if n := g.Purge(ifaceA); n != 2 {
		t.Fatalf("Purge(%s) = %d, want 2", ifaceA, n)
	}
	if g.Len() != 1 {
		t.Fatalf("Len after purge = %d, want 1", g.Len())
	}
	mustProcess(t, g, advertise("2001:db8::40", macA, ifaceA, tenantA), now)
	if g.Len() != 2 {
		t.Fatalf("Len after re-adding = %d, want 2", g.Len())
	}
}

// A restarted guard must keep entry states and still enforce static bindings.
func TestSnapshotRestoresEntriesAndBindings(t *testing.T) {
	now := time.Unix(1700000000, 0)
	cfg := testConfig()
	g := taskpkg.NewNdpGuard(cfg)
	if err := g.Bind(ipA, macA, ifaceA, tenantA); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	mustProcess(t, g, advertise(ipB, macB, ifaceA, tenantA), now)
	snap, err := g.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	restored, err := taskpkg.NewNdpGuardFromSnapshot(cfg, snap)
	if err != nil {
		t.Fatalf("NewNdpGuardFromSnapshot: %v", err)
	}
	later := now.Add(cfg.ReachableTime + time.Second)
	n, ok := restored.Lookup(ipB, later)
	if !ok || n.MAC != macB || n.State != taskpkg.StateStale {
		t.Fatalf("restored dynamic entry = %+v, %v", n, ok)
	}
	if err := restored.Process(advertise(ipA, macB, ifaceA, tenantA), later); !errors.Is(err, taskpkg.ErrSpoof) {
		t.Fatalf("restored static binding allowed a MAC change: %v", err)
	}
}

// Two advertisements racing to bind the same address must produce exactly one
// entry.
func TestConcurrentMacChangeSingleWinner(t *testing.T) {
	now := time.Unix(1700000000, 0)
	g := taskpkg.NewNdpGuard(testConfig())
	errs := make([]error, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		errs[0] = g.Process(advertise(ipA, macA, ifaceA, tenantA), now)
	}()
	go func() {
		defer wg.Done()
		errs[1] = g.Process(advertise(ipA, macB, ifaceA, tenantA), now)
	}()
	wg.Wait()
	successes := 0
	for _, err := range errs {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent bindings: %d accepted, want exactly 1", successes)
	}
	if g.Len() != 1 {
		t.Fatalf("Len = %d, want 1", g.Len())
	}
	n, ok := g.Lookup(ipA, now)
	if !ok || (n.MAC != macA && n.MAC != macB) {
		t.Fatalf("final entry = %+v, %v", n, ok)
	}
}
