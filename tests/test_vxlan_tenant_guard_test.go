package task

import (
	"errors"
	"sync"
	"testing"
	"time"

	taskpkg "gsb/batch46-safety-c-07"
)

func testConfig() taskpkg.Config {
	return taskpkg.Config{MaxMACsPerTenant: 8, LearnTTL: 5 * time.Minute}
}

func newGuard(t *testing.T, cfg taskpkg.Config) *taskpkg.VxlanGuard {
	t.Helper()
	g := taskpkg.NewVxlanGuard(cfg)
	if g == nil {
		t.Fatalf("NewVxlanGuard returned nil")
	}
	return g
}

func mustBind(t *testing.T, g *taskpkg.VxlanGuard, vni int, tenant string) {
	t.Helper()
	if err := g.BindVNI(vni, tenant); err != nil {
		t.Fatalf("BindVNI(%d, %q): %v", vni, tenant, err)
	}
}

// VNI 0 and 16777215 are reserved and must never be usable for a tenant.
func TestBindVNIRejectsReservedVNIs(t *testing.T) {
	g := newGuard(t, testConfig())
	for _, vni := range []int{-1, 0, 16777215, 16777216} {
		if err := g.BindVNI(vni, "tenant-a"); !errors.Is(err, taskpkg.ErrVNIRange) {
			t.Fatalf("BindVNI(%d) must be ErrVNIRange, got %v", vni, err)
		}
	}
	if err := g.BindVNI(16777214, "tenant-a"); err != nil {
		t.Fatalf("BindVNI(16777214) rejected: %v", err)
	}
	if err := g.BindVNI(4096, "tenant-b"); err != nil {
		t.Fatalf("BindVNI(4096) rejected: %v", err)
	}
}

// A VNI already owned by one tenant must not be handed to another.
func TestBindVNIConflictAcrossTenants(t *testing.T) {
	g := newGuard(t, testConfig())
	mustBind(t, g, 5000, "tenant-a")
	if err := g.BindVNI(5000, "tenant-b"); !errors.Is(err, taskpkg.ErrVNIBound) {
		t.Fatalf("cross tenant bind must be ErrVNIBound, got %v", err)
	}
	owner, err := g.TenantForVNI(5000)
	if err != nil {
		t.Fatalf("TenantForVNI: %v", err)
	}
	if owner != "tenant-a" {
		t.Fatalf("owner after refused rebind = %q, want tenant-a", owner)
	}
}

// Rebinding the same VNI to its current tenant is idempotent.
func TestBindVNIIdempotentSameTenant(t *testing.T) {
	g := newGuard(t, testConfig())
	mustBind(t, g, 5001, "tenant-a")
	mustBind(t, g, 5001, "tenant-a")
	owner, err := g.TenantForVNI(5001)
	if err != nil {
		t.Fatalf("TenantForVNI: %v", err)
	}
	if owner != "tenant-a" {
		t.Fatalf("owner = %q, want tenant-a", owner)
	}
}

// An unbound VNI carries no tenant.
func TestTenantForUnboundVNI(t *testing.T) {
	g := newGuard(t, testConfig())
	if _, err := g.TenantForVNI(4096); !errors.Is(err, taskpkg.ErrTenantUnknown) {
		t.Fatalf("unbound VNI must be ErrTenantUnknown, got %v", err)
	}
}

// Learning is only possible on a VNI bound to a tenant.
func TestLearnRequiresBoundVNI(t *testing.T) {
	g := newGuard(t, testConfig())
	now := time.Unix(1700000000, 0)
	err := g.Learn(taskpkg.Frame{VNI: 4096, SrcMAC: "02:00:00:00:00:01", DstMAC: "02:00:00:00:00:02"}, now)
	if !errors.Is(err, taskpkg.ErrTenantUnknown) {
		t.Fatalf("learn on unbound VNI must be ErrTenantUnknown, got %v", err)
	}
	if got := g.TenantMACCount("tenant-a"); got != 0 {
		t.Fatalf("tenant-a mac count = %d, want 0", got)
	}
}

// A learned entry must round-trip every field it was taught.
func TestLookupReturnsLearnedEntry(t *testing.T) {
	g := newGuard(t, testConfig())
	now := time.Unix(1700000000, 0)
	mustBind(t, g, 7000, "tenant-a")
	frame := taskpkg.Frame{VNI: 7000, SrcMAC: "02:00:00:00:10:01", DstMAC: "02:00:00:00:10:02", SrcIP: "10.20.0.11"}
	if err := g.Learn(frame, now); err != nil {
		t.Fatalf("Learn: %v", err)
	}
	entry, err := g.Lookup(7000, "02:00:00:00:10:01", now)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if entry.TenantID != "tenant-a" || entry.VNI != 7000 || entry.SrcIP != "10.20.0.11" {
		t.Fatalf("unexpected entry: %+v", entry)
	}
	if !entry.LearnedAt.Equal(now) {
		t.Fatalf("LearnedAt = %v, want %v", entry.LearnedAt, now)
	}
}

// A MAC seen in one tenant must not be learned by another tenant.
func TestCrossTenantMACMoveRejected(t *testing.T) {
	g := newGuard(t, testConfig())
	now := time.Unix(1700000000, 0)
	mustBind(t, g, 100, "tenant-a")
	mustBind(t, g, 200, "tenant-b")
	const mac = "02:00:00:00:aa:01"
	if err := g.Learn(taskpkg.Frame{VNI: 100, SrcMAC: mac, SrcIP: "10.1.0.5"}, now); err != nil {
		t.Fatalf("Learn tenant-a: %v", err)
	}
	err := g.Learn(taskpkg.Frame{VNI: 200, SrcMAC: mac, SrcIP: "10.2.0.5"}, now)
	if !errors.Is(err, taskpkg.ErrMACConflict) {
		t.Fatalf("cross tenant learn must be ErrMACConflict, got %v", err)
	}
	if got := g.TenantMACCount("tenant-a"); got != 1 {
		t.Fatalf("tenant-a mac count = %d, want 1", got)
	}
	if got := g.TenantMACCount("tenant-b"); got != 0 {
		t.Fatalf("tenant-b mac count = %d, want 0", got)
	}
}

// Even inside one tenant a MAC may not hop between VNIs.
func TestSameTenantMACMoveAcrossVNIRejected(t *testing.T) {
	g := newGuard(t, testConfig())
	now := time.Unix(1700000000, 0)
	mustBind(t, g, 100, "tenant-a")
	mustBind(t, g, 101, "tenant-a")
	const mac = "02:00:00:00:aa:02"
	if err := g.Learn(taskpkg.Frame{VNI: 100, SrcMAC: mac}, now); err != nil {
		t.Fatalf("Learn on vni 100: %v", err)
	}
	if err := g.Learn(taskpkg.Frame{VNI: 101, SrcMAC: mac}, now); !errors.Is(err, taskpkg.ErrMACConflict) {
		t.Fatalf("VNI hop must be ErrMACConflict, got %v", err)
	}
	if _, err := g.Lookup(100, mac, now); err != nil {
		t.Fatalf("original entry lost: %v", err)
	}
}

// One tenant may not hold more than its configured number of MACs.
func TestPerTenantMACLimit(t *testing.T) {
	cfg := testConfig()
	cfg.MaxMACsPerTenant = 2
	g := newGuard(t, cfg)
	now := time.Unix(1700000000, 0)
	mustBind(t, g, 300, "tenant-a")
	for _, mac := range []string{"02:00:00:00:bb:01", "02:00:00:00:bb:02"} {
		if err := g.Learn(taskpkg.Frame{VNI: 300, SrcMAC: mac}, now); err != nil {
			t.Fatalf("Learn %s: %v", mac, err)
		}
	}
	err := g.Learn(taskpkg.Frame{VNI: 300, SrcMAC: "02:00:00:00:bb:03"}, now)
	if !errors.Is(err, taskpkg.ErrMACLimit) {
		t.Fatalf("third MAC must be ErrMACLimit, got %v", err)
	}
	if got := g.TenantMACCount("tenant-a"); got != 2 {
		t.Fatalf("tenant-a mac count = %d, want 2", got)
	}
	if _, err := g.Lookup(300, "02:00:00:00:bb:03", now); !errors.Is(err, taskpkg.ErrNotFound) {
		t.Fatalf("over-limit MAC must not be stored, got %v", err)
	}
}

// Re-learning a MAC on its own VNI refreshes the entry instead of adding one.
func TestRelearnRefreshesEntry(t *testing.T) {
	g := newGuard(t, testConfig())
	start := time.Unix(1700000000, 0)
	mustBind(t, g, 400, "tenant-a")
	const mac = "02:00:00:00:cc:01"
	if err := g.Learn(taskpkg.Frame{VNI: 400, SrcMAC: mac, SrcIP: "10.4.0.1"}, start); err != nil {
		t.Fatalf("first Learn: %v", err)
	}
	later := start.Add(2 * time.Minute)
	if err := g.Learn(taskpkg.Frame{VNI: 400, SrcMAC: mac, SrcIP: "10.4.0.9"}, later); err != nil {
		t.Fatalf("refresh Learn: %v", err)
	}
	entry, err := g.Lookup(400, mac, later)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if entry.SrcIP != "10.4.0.9" || !entry.LearnedAt.Equal(later) {
		t.Fatalf("entry not refreshed: %+v", entry)
	}
	if got := g.TenantMACCount("tenant-a"); got != 1 {
		t.Fatalf("mac count = %d, want 1", got)
	}
	if got := g.Stats().Learned; got != 1 {
		t.Fatalf("learned counter = %d, want 1", got)
	}
}

// Expire must drop every entry at or past its TTL and report the count.
func TestExpireRemovesStaleEntries(t *testing.T) {
	g := newGuard(t, testConfig())
	now := time.Unix(1700000000, 0)
	mustBind(t, g, 500, "tenant-a")
	if err := g.Learn(taskpkg.Frame{VNI: 500, SrcMAC: "02:00:00:00:dd:01"}, now); err != nil {
		t.Fatalf("Learn 1: %v", err)
	}
	if err := g.Learn(taskpkg.Frame{VNI: 500, SrcMAC: "02:00:00:00:dd:02"}, now); err != nil {
		t.Fatalf("Learn 2: %v", err)
	}
	if got := g.Expire(now.Add(5 * time.Minute)); got != 2 {
		t.Fatalf("Expire removed %d entries, want 2", got)
	}
	if got := g.TenantMACCount("tenant-a"); got != 0 {
		t.Fatalf("mac count after expire = %d, want 0", got)
	}
	if got := g.Stats().Evicted; got != 2 {
		t.Fatalf("evicted counter = %d, want 2", got)
	}
}

// The TTL boundary itself counts as expired; one tick earlier does not.
func TestLookupAtTTLBoundaryExpired(t *testing.T) {
	cfg := testConfig()
	g := newGuard(t, cfg)
	now := time.Unix(1700000000, 0)
	mustBind(t, g, 600, "tenant-a")
	const mac = "02:00:00:00:ee:01"
	if err := g.Learn(taskpkg.Frame{VNI: 600, SrcMAC: mac}, now); err != nil {
		t.Fatalf("Learn: %v", err)
	}
	if _, err := g.Lookup(600, mac, now.Add(cfg.LearnTTL-time.Nanosecond)); err != nil {
		t.Fatalf("entry expired early: %v", err)
	}
	if _, err := g.Lookup(600, mac, now.Add(cfg.LearnTTL)); !errors.Is(err, taskpkg.ErrNotFound) {
		t.Fatalf("entry at TTL must be ErrNotFound, got %v", err)
	}
}

// Unbinding a VNI releases the tenant binding and all entries on it.
func TestUnbindVNIReleasesEntries(t *testing.T) {
	g := newGuard(t, testConfig())
	now := time.Unix(1700000000, 0)
	mustBind(t, g, 700, "tenant-a")
	for _, mac := range []string{"02:00:00:00:ff:01", "02:00:00:00:ff:02"} {
		if err := g.Learn(taskpkg.Frame{VNI: 700, SrcMAC: mac}, now); err != nil {
			t.Fatalf("Learn %s: %v", mac, err)
		}
	}
	removed, err := g.UnbindVNI(700)
	if err != nil {
		t.Fatalf("UnbindVNI: %v", err)
	}
	if removed != 2 {
		t.Fatalf("UnbindVNI removed %d entries, want 2", removed)
	}
	if _, err := g.TenantForVNI(700); !errors.Is(err, taskpkg.ErrTenantUnknown) {
		t.Fatalf("binding survived unbind: %v", err)
	}
	if _, err := g.Lookup(700, "02:00:00:00:ff:01", now); !errors.Is(err, taskpkg.ErrTenantUnknown) {
		t.Fatalf("lookup on unbound VNI must be ErrTenantUnknown, got %v", err)
	}
	if got := g.TenantMACCount("tenant-a"); got != 0 {
		t.Fatalf("tenant-a mac count after unbind = %d, want 0", got)
	}
}

// The same MAC raced into two tenants: exactly one learn may succeed.
func TestConcurrentLearnSameMACTwoTenantsSingleWinner(t *testing.T) {
	g := newGuard(t, testConfig())
	now := time.Unix(1700000000, 0)
	mustBind(t, g, 100, "tenant-a")
	mustBind(t, g, 200, "tenant-b")
	const mac = "02:00:00:00:ab:cd"
	var wg sync.WaitGroup
	errs := make([]error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		errs[0] = g.Learn(taskpkg.Frame{VNI: 100, SrcMAC: mac, SrcIP: "10.1.0.7"}, now)
	}()
	go func() {
		defer wg.Done()
		errs[1] = g.Learn(taskpkg.Frame{VNI: 200, SrcMAC: mac, SrcIP: "10.2.0.7"}, now)
	}()
	wg.Wait()
	success, conflict := 0, 0
	for _, err := range errs {
		switch {
		case err == nil:
			success++
		case errors.Is(err, taskpkg.ErrMACConflict):
			conflict++
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatalf("want one winner and one ErrMACConflict, got successes=%d conflicts=%d errors=%v", success, conflict, errs)
	}
	total := g.TenantMACCount("tenant-a") + g.TenantMACCount("tenant-b")
	if total != 1 {
		t.Fatalf("winner count total = %d, want 1", total)
	}
}

// A restarted guard must keep both bindings and learned MACs.
func TestSnapshotRestoresBindingsAndMACs(t *testing.T) {
	g := newGuard(t, testConfig())
	now := time.Unix(1700000000, 0)
	mustBind(t, g, 800, "tenant-c")
	if err := g.Learn(taskpkg.Frame{VNI: 800, SrcMAC: "02:00:00:00:9a:01", SrcIP: "10.8.0.21"}, now); err != nil {
		t.Fatalf("Learn: %v", err)
	}
	snap, err := g.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	restored, err := taskpkg.NewVxlanGuardFromSnapshot(testConfig(), snap)
	if err != nil {
		t.Fatalf("NewVxlanGuardFromSnapshot: %v", err)
	}
	owner, err := restored.TenantForVNI(800)
	if err != nil {
		t.Fatalf("TenantForVNI after restore: %v", err)
	}
	if owner != "tenant-c" {
		t.Fatalf("restored owner = %q, want tenant-c", owner)
	}
	entry, err := restored.Lookup(800, "02:00:00:00:9a:01", now)
	if err != nil {
		t.Fatalf("Lookup after restore: %v", err)
	}
	if entry.SrcIP != "10.8.0.21" {
		t.Fatalf("restored entry = %+v", entry)
	}
}
