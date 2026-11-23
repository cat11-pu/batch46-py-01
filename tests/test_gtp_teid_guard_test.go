package task

import (
	"errors"
	"sync"
	"testing"
	"time"

	taskpkg "gsb/batch46-safety-c-09"
)

func testConfig() taskpkg.Config {
	return taskpkg.Config{MaxTEIDsPerTenant: 8, Quarantine: 30 * time.Second}
}

func newGuard(t *testing.T, cfg taskpkg.Config) *taskpkg.GtpGuard {
	t.Helper()
	g := taskpkg.NewGtpGuard(cfg)
	if g == nil {
		t.Fatalf("NewGtpGuard returned nil")
	}
	return g
}

func peer(addr string, port int) taskpkg.PeerAddr {
	return taskpkg.PeerAddr{Addr: addr, Port: port}
}

// gtpTPDU builds a T-PDU with the S flag set, so it carries a sequence number.
func gtpTPDU(teid, seq uint32, payload string) []byte {
	body := []byte{byte(seq >> 8), byte(seq), 0x00, 0x00}
	body = append(body, []byte(payload)...)
	raw := []byte{
		0x32, 0xFF,
		byte(len(body) >> 8), byte(len(body)),
		byte(teid >> 24), byte(teid >> 16), byte(teid >> 8), byte(teid),
	}
	return append(raw, body...)
}

func mustParse(t *testing.T, g *taskpkg.GtpGuard, raw []byte) taskpkg.Packet {
	t.Helper()
	pkt, err := g.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return pkt
}

func mustAllocate(t *testing.T, g *taskpkg.GtpGuard, teid uint32, tenant string, p taskpkg.PeerAddr, now time.Time) {
	t.Helper()
	if _, err := g.Allocate(teid, tenant, p, now); err != nil {
		t.Fatalf("Allocate(%#x, %q): %v", teid, tenant, err)
	}
}

// A T-PDU must expose its message type, TEID, sequence and payload.
func TestParseTPDUFields(t *testing.T) {
	g := newGuard(t, testConfig())
	pkt := mustParse(t, g, gtpTPDU(0x11223344, 1000, "hello"))
	if pkt.MessageType != 0xFF {
		t.Fatalf("message type = %#x, want 0xFF", pkt.MessageType)
	}
	if pkt.TEID != 0x11223344 {
		t.Fatalf("teid = %#x, want 0x11223344", pkt.TEID)
	}
	if !pkt.HasSequence || pkt.Sequence != 1000 {
		t.Fatalf("sequence = %d (present=%v), want 1000", pkt.Sequence, pkt.HasSequence)
	}
	if string(pkt.Payload) != "hello" {
		t.Fatalf("payload = %q, want hello", string(pkt.Payload))
	}
}

// Only GTP version 1 is spoken on this interface.
func TestParseRejectsWrongVersion(t *testing.T) {
	g := newGuard(t, testConfig())
	raw := []byte{0x60, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	if _, err := g.Parse(raw); !errors.Is(err, taskpkg.ErrVersion) {
		t.Fatalf("version 3 must be ErrVersion, got %v", err)
	}
}

// The PT bit must mark GTP (GTP-U), not GTP'.
func TestParseRejectsGTPPrime(t *testing.T) {
	g := newGuard(t, testConfig())
	raw := []byte{0x20, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	if _, err := g.Parse(raw); !errors.Is(err, taskpkg.ErrProtocolType) {
		t.Fatalf("GTP' must be ErrProtocolType, got %v", err)
	}
}

// A length field that disagrees with the delivered bytes is a framing error.
func TestParseRejectsLengthMismatch(t *testing.T) {
	g := newGuard(t, testConfig())
	raw := gtpTPDU(0x00000010, 7, "abc")
	raw[2] = 0x00
	raw[3] = byte(len(raw) - 8 + 8)
	if _, err := g.Parse(raw); !errors.Is(err, taskpkg.ErrMalformed) {
		t.Fatalf("short body must be ErrMalformed, got %v", err)
	}
}

// TEID 0 is reserved and cannot be allocated.
func TestAllocateRejectsZeroTEID(t *testing.T) {
	g := newGuard(t, testConfig())
	now := time.Unix(1700000000, 0)
	if _, err := g.Allocate(0, "tenant-a", peer("10.1.1.1", 2152), now); !errors.Is(err, taskpkg.ErrTEIDRange) {
		t.Fatalf("TEID 0 must be ErrTEIDRange, got %v", err)
	}
	if _, err := g.Allocate(0xFFFFFFFF, "tenant-a", peer("10.1.1.1", 2152), now); err != nil {
		t.Fatalf("TEID 0xFFFFFFFF rejected: %v", err)
	}
}

// One TEID cannot belong to two tenants at the same time.
func TestAllocateConflictAcrossTenants(t *testing.T) {
	g := newGuard(t, testConfig())
	now := time.Unix(1700000000, 0)
	mustAllocate(t, g, 0x00000001, "tenant-a", peer("10.1.1.1", 2152), now)
	if _, err := g.Allocate(0x00000001, "tenant-b", peer("10.2.2.2", 2152), now); !errors.Is(err, taskpkg.ErrTEIDInUse) {
		t.Fatalf("cross tenant allocation must be ErrTEIDInUse, got %v", err)
	}
	if got := g.TenantTEIDCount("tenant-a"); got != 1 {
		t.Fatalf("tenant-a teid count = %d, want 1", got)
	}
	if got := g.TenantTEIDCount("tenant-b"); got != 0 {
		t.Fatalf("tenant-b teid count = %d, want 0", got)
	}
}

// Repeating the identical allocation is idempotent; changing the peer is not.
func TestAllocateIdempotentSamePeer(t *testing.T) {
	g := newGuard(t, testConfig())
	now := time.Unix(1700000000, 0)
	p := peer("10.1.1.1", 2152)
	first, err := g.Allocate(0x00000002, "tenant-a", p, now)
	if err != nil {
		t.Fatalf("first Allocate: %v", err)
	}
	second, err := g.Allocate(0x00000002, "tenant-a", p, now)
	if err != nil {
		t.Fatalf("idempotent Allocate: %v", err)
	}
	if first != second {
		t.Fatalf("idempotent allocation returned %+v, want %+v", second, first)
	}
	if _, err := g.Allocate(0x00000002, "tenant-a", peer("10.1.1.1", 2153), now); !errors.Is(err, taskpkg.ErrTEIDInUse) {
		t.Fatalf("peer change must be ErrTEIDInUse, got %v", err)
	}
	if got := g.TenantTEIDCount("tenant-a"); got != 1 {
		t.Fatalf("tenant-a teid count = %d, want 1", got)
	}
}

// A packet for an allocated TEID from its peer must be admitted.
func TestAdmitAcceptsRegisteredTEID(t *testing.T) {
	g := newGuard(t, testConfig())
	now := time.Unix(1700000000, 0)
	p := peer("10.1.1.1", 2152)
	mustAllocate(t, g, 0x00000003, "tenant-a", p, now)
	pkt := mustParse(t, g, gtpTPDU(0x00000003, 500, "payload"))
	if err := g.Admit(pkt, p, now); err != nil {
		t.Fatalf("Admit: %v", err)
	}
	seq, err := g.LastSequence(0x00000003)
	if err != nil {
		t.Fatalf("LastSequence: %v", err)
	}
	if seq != 500 {
		t.Fatalf("last sequence = %d, want 500", seq)
	}
	if got := g.Stats().Accepted; got != 1 {
		t.Fatalf("accepted counter = %d, want 1", got)
	}
}

// Traffic for a TEID must come from the peer the TEID was allocated to.
func TestAdmitRejectsWrongPeer(t *testing.T) {
	g := newGuard(t, testConfig())
	now := time.Unix(1700000000, 0)
	owner := peer("10.1.1.1", 2152)
	mustAllocate(t, g, 0x00000004, "tenant-a", owner, now)
	pkt := mustParse(t, g, gtpTPDU(0x00000004, 1, "x"))
	if err := g.Admit(pkt, peer("10.9.9.9", 2152), now); !errors.Is(err, taskpkg.ErrPeerMismatch) {
		t.Fatalf("wrong peer must be ErrPeerMismatch, got %v", err)
	}
	if got := g.Stats().Dropped; got != 1 {
		t.Fatalf("dropped counter = %d, want 1", got)
	}
}

// A TEID nobody allocated must never be admitted.
func TestAdmitRejectsUnknownTEID(t *testing.T) {
	g := newGuard(t, testConfig())
	now := time.Unix(1700000000, 0)
	pkt := mustParse(t, g, gtpTPDU(0x00007777, 1, "x"))
	if err := g.Admit(pkt, peer("10.1.1.1", 2152), now); !errors.Is(err, taskpkg.ErrTEIDUnknown) {
		t.Fatalf("unallocated TEID must be ErrTEIDUnknown, got %v", err)
	}
}

// Sequence numbers must strictly increase per TEID.
func TestAdmitRejectsNonIncreasingSequence(t *testing.T) {
	g := newGuard(t, testConfig())
	now := time.Unix(1700000000, 0)
	p := peer("10.1.1.1", 2152)
	mustAllocate(t, g, 0x00000005, "tenant-a", p, now)
	if err := g.Admit(mustParse(t, g, gtpTPDU(0x00000005, 100, "a")), p, now); err != nil {
		t.Fatalf("first Admit: %v", err)
	}
	if err := g.Admit(mustParse(t, g, gtpTPDU(0x00000005, 100, "b")), p, now); !errors.Is(err, taskpkg.ErrReplay) {
		t.Fatalf("equal sequence must be ErrReplay, got %v", err)
	}
	if err := g.Admit(mustParse(t, g, gtpTPDU(0x00000005, 99, "c")), p, now); !errors.Is(err, taskpkg.ErrReplay) {
		t.Fatalf("older sequence must be ErrReplay, got %v", err)
	}
	if err := g.Admit(mustParse(t, g, gtpTPDU(0x00000005, 101, "d")), p, now); err != nil {
		t.Fatalf("newer sequence rejected: %v", err)
	}
}

// A tenant may not hold more than its configured number of TEIDs.
func TestTenantTEIDQuota(t *testing.T) {
	cfg := testConfig()
	cfg.MaxTEIDsPerTenant = 2
	g := newGuard(t, cfg)
	now := time.Unix(1700000000, 0)
	mustAllocate(t, g, 0x00000010, "tenant-a", peer("10.1.1.1", 2152), now)
	mustAllocate(t, g, 0x00000011, "tenant-a", peer("10.1.1.1", 2152), now)
	if _, err := g.Allocate(0x00000012, "tenant-a", peer("10.1.1.1", 2152), now); !errors.Is(err, taskpkg.ErrQuota) {
		t.Fatalf("third TEID must be ErrQuota, got %v", err)
	}
	if got := g.TenantTEIDCount("tenant-a"); got != 2 {
		t.Fatalf("tenant-a teid count = %d, want 2", got)
	}
	// Another tenant is unaffected by tenant-a's quota.
	if _, err := g.Allocate(0x00000012, "tenant-b", peer("10.2.2.2", 2152), now); err != nil {
		t.Fatalf("tenant-b allocation rejected: %v", err)
	}
}

// A released TEID is quarantined before it can be reused.
func TestReleaseQuarantineBlocksReuse(t *testing.T) {
	cfg := testConfig()
	g := newGuard(t, cfg)
	now := time.Unix(1700000000, 0)
	p := peer("10.1.1.1", 2152)
	if err := g.Release(0x00000020, now); !errors.Is(err, taskpkg.ErrTEIDUnknown) {
		t.Fatalf("releasing an unknown TEID must be ErrTEIDUnknown, got %v", err)
	}
	mustAllocate(t, g, 0x00000020, "tenant-a", p, now)
	if err := g.Release(0x00000020, now); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if got := g.TenantTEIDCount("tenant-a"); got != 0 {
		t.Fatalf("tenant-a teid count after release = %d, want 0", got)
	}
	if _, err := g.Allocate(0x00000020, "tenant-b", peer("10.2.2.2", 2152), now.Add(cfg.Quarantine-time.Second)); !errors.Is(err, taskpkg.ErrQuarantine) {
		t.Fatalf("reuse inside quarantine must be ErrQuarantine, got %v", err)
	}
	if _, err := g.Allocate(0x00000020, "tenant-b", peer("10.2.2.2", 2152), now.Add(cfg.Quarantine)); err != nil {
		t.Fatalf("reuse after quarantine rejected: %v", err)
	}
}

// A restarted guard must still reject sequence numbers it saw before.
func TestSnapshotRestoresReplayWindow(t *testing.T) {
	cfg := testConfig()
	g := newGuard(t, cfg)
	now := time.Unix(1700000000, 0)
	p := peer("10.1.1.1", 2152)
	mustAllocate(t, g, 0x00000030, "tenant-a", p, now)
	if err := g.Admit(mustParse(t, g, gtpTPDU(0x00000030, 50, "a")), p, now); err != nil {
		t.Fatalf("Admit: %v", err)
	}
	snap, err := g.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	restored, err := taskpkg.NewGtpGuardFromSnapshot(cfg, snap)
	if err != nil {
		t.Fatalf("NewGtpGuardFromSnapshot: %v", err)
	}
	if _, err := restored.Binding(0x00000030); err != nil {
		t.Fatalf("binding lost across restart: %v", err)
	}
	if err := restored.Admit(mustParse(t, restored, gtpTPDU(0x00000030, 49, "b")), p, now); !errors.Is(err, taskpkg.ErrReplay) {
		t.Fatalf("replay across restart must be ErrReplay, got %v", err)
	}
	if err := restored.Admit(mustParse(t, restored, gtpTPDU(0x00000030, 51, "c")), p, now); err != nil {
		t.Fatalf("new sequence after restart rejected: %v", err)
	}
}

// Two tenants racing for one TEID: exactly one allocation may succeed.
func TestConcurrentAllocationSingleWinner(t *testing.T) {
	g := newGuard(t, testConfig())
	now := time.Unix(1700000000, 0)
	var wg sync.WaitGroup
	errs := make([]error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, errs[0] = g.Allocate(0x00000040, "tenant-a", peer("10.1.1.1", 2152), now)
	}()
	go func() {
		defer wg.Done()
		_, errs[1] = g.Allocate(0x00000040, "tenant-b", peer("10.2.2.2", 2152), now)
	}()
	wg.Wait()
	success, inUse := 0, 0
	for _, err := range errs {
		switch {
		case err == nil:
			success++
		case errors.Is(err, taskpkg.ErrTEIDInUse):
			inUse++
		}
	}
	if success != 1 || inUse != 1 {
		t.Fatalf("want one winner and one ErrTEIDInUse, got successes=%d inUse=%d errors=%v", success, inUse, errs)
	}
	if total := g.TenantTEIDCount("tenant-a") + g.TenantTEIDCount("tenant-b"); total != 1 {
		t.Fatalf("allocated TEID total = %d, want 1", total)
	}
}
