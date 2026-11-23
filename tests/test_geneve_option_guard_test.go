package task

import (
	"errors"
	"sync"
	"testing"

	taskpkg "gsb/batch46-safety-c-08"
)

func testPolicy() taskpkg.Policy {
	return taskpkg.Policy{
		Rules: []taskpkg.OptionRule{
			{Class: 0x0108, Type: 0x01, MaxValueBytes: 16},
			{Class: 0x0108, Type: 0x02, MaxValueBytes: 64},
		},
		MaxOptions:    8,
		MaxValueBytes: 64,
	}
}

func newGuard(t *testing.T, policy taskpkg.Policy) *taskpkg.GeneveGuard {
	t.Helper()
	g := taskpkg.NewGeneveGuard(policy)
	if g == nil {
		t.Fatalf("NewGeneveGuard returned nil")
	}
	return g
}

// geneveRaw builds a header. version is the raw two bit version field.
func geneveRaw(version, optWords byte, proto uint16, vni int, opts []byte) []byte {
	raw := []byte{
		version<<6 | optWords,
		0x00,
		byte(proto >> 8), byte(proto),
		byte(vni >> 16), byte(vni >> 8), byte(vni),
		0x00,
	}
	return append(raw, opts...)
}

// opt builds one option; words is the length field in four byte units.
func opt(class uint16, typ byte, words int, value []byte) []byte {
	b := []byte{byte(class >> 8), byte(class), typ, byte(words)}
	return append(b, value...)
}

// A header without options must expose VNI and protocol.
func TestParsePlainHeader(t *testing.T) {
	g := newGuard(t, testPolicy())
	h, err := g.ParseHeader(geneveRaw(0, 0, 0x6558, 100, nil))
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	if h.VNI != 100 || h.Protocol != 0x6558 {
		t.Fatalf("unexpected header: %+v", h)
	}
	if len(h.Options) != 0 {
		t.Fatalf("plain header carried %d options", len(h.Options))
	}
}

// An option with the critical bit set must decode class, type and value.
func TestParseWithOptionValue(t *testing.T) {
	g := newGuard(t, testPolicy())
	opts := opt(0x0108, 0x80, 1, []byte("abcd"))
	h, err := g.ParseHeader(geneveRaw(0, 2, 0x0800, 70000, opts))
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	if h.Protocol != 0x0800 || h.VNI != 70000 {
		t.Fatalf("unexpected header: %+v", h)
	}
	if len(h.Options) != 1 {
		t.Fatalf("options = %d, want 1", len(h.Options))
	}
	o := h.Options[0]
	if o.Class != 0x0108 || o.Type != 0x00 || !o.Critical {
		t.Fatalf("unexpected option identity: %+v", o)
	}
	if string(o.Value) != "abcd" {
		t.Fatalf("option value = %q, want abcd", string(o.Value))
	}
}

// Only version 0 exists; anything else is refused before options are read.
func TestParseRejectsNonZeroVersion(t *testing.T) {
	g := newGuard(t, testPolicy())
	for _, version := range []byte{1, 2, 3} {
		if _, err := g.ParseHeader(geneveRaw(version, 0, 0x6558, 100, nil)); !errors.Is(err, taskpkg.ErrVersion) {
			t.Fatalf("version %d must be ErrVersion, got %v", version, err)
		}
	}
}

// The declared option area must be present in full.
func TestParseRejectsTruncatedOptions(t *testing.T) {
	g := newGuard(t, testPolicy())
	opts := opt(0x0108, 0x01, 0, nil)
	if _, err := g.ParseHeader(geneveRaw(0, 2, 0x6558, 100, opts)); !errors.Is(err, taskpkg.ErrMalformed) {
		t.Fatalf("short option area must be ErrMalformed, got %v", err)
	}
}

// One option may not claim bytes outside the declared option area.
func TestParseRejectsOptionLengthOverrun(t *testing.T) {
	g := newGuard(t, testPolicy())
	opts := append(opt(0x0108, 0x01, 2, []byte("abcdefgh")), 0, 0, 0, 0)
	if _, err := g.ParseHeader(geneveRaw(0, 2, 0x6558, 100, opts)); !errors.Is(err, taskpkg.ErrMalformed) {
		t.Fatalf("option overrun must be ErrMalformed, got %v", err)
	}
}

// A (class, type) pair may only occur once per header.
func TestParseRejectsDuplicateOption(t *testing.T) {
	g := newGuard(t, testPolicy())
	opts := append(opt(0x0108, 0x01, 0, nil), opt(0x0108, 0x81, 0, nil)...)
	if _, err := g.ParseHeader(geneveRaw(0, 2, 0x6558, 100, opts)); !errors.Is(err, taskpkg.ErrDuplicateOption) {
		t.Fatalf("duplicate option must be ErrDuplicateOption, got %v", err)
	}
}

// The option count cap is structural and applies before policy checks.
func TestParseEnforcesOptionCountLimit(t *testing.T) {
	policy := testPolicy()
	policy.MaxOptions = 2
	g := newGuard(t, policy)
	opts := append(append(opt(0x0108, 0x01, 0, nil), opt(0x0108, 0x02, 0, nil)...), opt(0x0108, 0x03, 0, nil)...)
	if _, err := g.ParseHeader(geneveRaw(0, 3, 0x6558, 100, opts)); !errors.Is(err, taskpkg.ErrTooManyOptions) {
		t.Fatalf("three options with cap two must be ErrTooManyOptions, got %v", err)
	}
}

// An unknown option with the critical bit set must drop the packet.
func TestValidateRejectsUnknownCriticalOption(t *testing.T) {
	g := newGuard(t, testPolicy())
	if err := g.RegisterVNI(100, "tenant-a"); err != nil {
		t.Fatalf("RegisterVNI: %v", err)
	}
	h := taskpkg.Header{
		VNI:      100,
		Protocol: 0x6558,
		Options:  []taskpkg.Option{{Class: 0x0999, Type: 0x05, Critical: true, Value: []byte{0x01}}},
	}
	if err := g.Validate(h, "tenant-a"); !errors.Is(err, taskpkg.ErrCriticalOption) {
		t.Fatalf("unknown critical option must be ErrCriticalOption, got %v", err)
	}
}

// An unknown option without the critical bit is skipped and counted.
func TestValidateIgnoresUnknownNonCriticalOption(t *testing.T) {
	g := newGuard(t, testPolicy())
	if err := g.RegisterVNI(100, "tenant-a"); err != nil {
		t.Fatalf("RegisterVNI: %v", err)
	}
	h := taskpkg.Header{
		VNI:      100,
		Protocol: 0x6558,
		Options:  []taskpkg.Option{{Class: 0x0999, Type: 0x05, Value: []byte{0x01}}},
	}
	if err := g.Validate(h, "tenant-a"); err != nil {
		t.Fatalf("unknown non-critical option must be ignored, got %v", err)
	}
	stats := g.Stats()
	if stats.Validated != 1 || stats.IgnoredOptions != 1 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
}

// The absolute value cap applies even to options covered by a rule.
func TestValidateEnforcesGlobalValueLengthLimit(t *testing.T) {
	policy := testPolicy()
	policy.MaxValueBytes = 4
	g := newGuard(t, policy)
	if err := g.RegisterVNI(100, "tenant-a"); err != nil {
		t.Fatalf("RegisterVNI: %v", err)
	}
	h := taskpkg.Header{
		VNI:      100,
		Protocol: 0x6558,
		Options:  []taskpkg.Option{{Class: 0x0108, Type: 0x02, Value: []byte("12345678")}},
	}
	if err := g.Validate(h, "tenant-a"); !errors.Is(err, taskpkg.ErrOptionTooLong) {
		t.Fatalf("eight byte value under a four byte cap must be ErrOptionTooLong, got %v", err)
	}
}

// A rule may impose a tighter cap for its own option.
func TestValidateEnforcesRuleValueLengthLimit(t *testing.T) {
	policy := testPolicy()
	policy.Rules = []taskpkg.OptionRule{{Class: 0x0108, Type: 0x02, MaxValueBytes: 4}}
	g := newGuard(t, policy)
	if err := g.RegisterVNI(100, "tenant-a"); err != nil {
		t.Fatalf("RegisterVNI: %v", err)
	}
	h := taskpkg.Header{
		VNI:      100,
		Protocol: 0x6558,
		Options:  []taskpkg.Option{{Class: 0x0108, Type: 0x02, Value: []byte("12345678")}},
	}
	if err := g.Validate(h, "tenant-a"); !errors.Is(err, taskpkg.ErrOptionTooLong) {
		t.Fatalf("rule cap must be ErrOptionTooLong, got %v", err)
	}
}

// VNI 0 and 16777215 are reserved and cannot be assigned.
func TestRegisterVNIRejectsReservedRange(t *testing.T) {
	g := newGuard(t, testPolicy())
	for _, vni := range []int{-1, 0, 16777215, 16777216} {
		if err := g.RegisterVNI(vni, "tenant-a"); !errors.Is(err, taskpkg.ErrVNIRange) {
			t.Fatalf("RegisterVNI(%d) must be ErrVNIRange, got %v", vni, err)
		}
	}
	if err := g.RegisterVNI(16777214, "tenant-a"); err != nil {
		t.Fatalf("RegisterVNI(16777214) rejected: %v", err)
	}
}

// A packet for an unregistered VNI is dropped; a packet for another tenant's
// VNI is dropped for a different, reportable reason.
func TestValidateRejectsCrossTenantVNI(t *testing.T) {
	g := newGuard(t, testPolicy())
	h := taskpkg.Header{VNI: 4095, Protocol: 0x6558}
	if err := g.Validate(h, "tenant-a"); !errors.Is(err, taskpkg.ErrVNIUnknown) {
		t.Fatalf("unregistered VNI must be ErrVNIUnknown, got %v", err)
	}
	if err := g.RegisterVNI(4095, "tenant-a"); err != nil {
		t.Fatalf("RegisterVNI: %v", err)
	}
	if err := g.Validate(h, "tenant-b"); !errors.Is(err, taskpkg.ErrTenantMismatch) {
		t.Fatalf("foreign tenant must be ErrTenantMismatch, got %v", err)
	}
	if err := g.Validate(h, "tenant-a"); err != nil {
		t.Fatalf("owning tenant rejected: %v", err)
	}
}

// Two tenants racing for the same VNI: exactly one registration may win.
func TestRegisterVNIRejectsDuplicateOwnerConcurrent(t *testing.T) {
	g := newGuard(t, testPolicy())
	var wg sync.WaitGroup
	errs := make([]error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		errs[0] = g.RegisterVNI(777, "tenant-a")
	}()
	go func() {
		defer wg.Done()
		errs[1] = g.RegisterVNI(777, "tenant-b")
	}()
	wg.Wait()
	success, bound := 0, 0
	for _, err := range errs {
		switch {
		case err == nil:
			success++
		case errors.Is(err, taskpkg.ErrVNIBound):
			bound++
		}
	}
	if success != 1 || bound != 1 {
		t.Fatalf("want one winner and one ErrVNIBound, got successes=%d bound=%d errors=%v", success, bound, errs)
	}
}

// A restarted guard must still know which tenant owns each VNI.
func TestSnapshotRestoresVNIBindings(t *testing.T) {
	g := newGuard(t, testPolicy())
	if err := g.RegisterVNI(5000, "tenant-a"); err != nil {
		t.Fatalf("RegisterVNI 5000: %v", err)
	}
	if err := g.RegisterVNI(5001, "tenant-b"); err != nil {
		t.Fatalf("RegisterVNI 5001: %v", err)
	}
	snap, err := g.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	restored, err := taskpkg.NewGeneveGuardFromSnapshot(testPolicy(), snap)
	if err != nil {
		t.Fatalf("NewGeneveGuardFromSnapshot: %v", err)
	}
	owner, err := restored.TenantForVNI(5001)
	if err != nil {
		t.Fatalf("TenantForVNI after restore: %v", err)
	}
	if owner != "tenant-b" {
		t.Fatalf("restored owner = %q, want tenant-b", owner)
	}
	if got := restored.RegisteredVNIs(); len(got) != 2 || got[0] != 5000 || got[1] != 5001 {
		t.Fatalf("RegisteredVNIs = %v, want [5000 5001]", got)
	}
}
