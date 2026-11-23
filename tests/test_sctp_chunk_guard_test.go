package task

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sync"
	"testing"
	"time"

	taskpkg "gsb/batch46-safety-c-10"
)

var authKey = []byte("gsb-sctp-shared-key-2026")

func testConfig() taskpkg.Config {
	return taskpkg.Config{
		MaxChunksPerPacket: 4,
		MaxPacketBytes:     128,
		AuthKey:            authKey,
		AuthTTL:            time.Minute,
	}
}

func newGuard(t *testing.T, cfg taskpkg.Config) *taskpkg.SctpGuard {
	t.Helper()
	g := taskpkg.NewSctpGuard(cfg)
	if g == nil {
		t.Fatalf("NewSctpGuard returned nil")
	}
	return g
}

// sctpPacket builds the common header followed by the given encoded chunks.
func sctpPacket(srcPort, dstPort int, vtag uint32, chunks ...[]byte) []byte {
	raw := []byte{
		byte(srcPort >> 8), byte(srcPort),
		byte(dstPort >> 8), byte(dstPort),
		byte(vtag >> 24), byte(vtag >> 16), byte(vtag >> 8), byte(vtag),
		0x00, 0x00, 0x00, 0x00,
	}
	for _, c := range chunks {
		raw = append(raw, c...)
	}
	return raw
}

// chunk encodes one chunk with zero padding to a four byte boundary.
func chunk(typ, flags byte, value []byte) []byte {
	length := 4 + len(value)
	out := []byte{typ, flags, byte(length >> 8), byte(length)}
	out = append(out, value...)
	for len(out)%4 != 0 {
		out = append(out, 0x00)
	}
	return out
}

func dataValue(tsn uint32, streamID, streamSeq uint16, payload string) []byte {
	out := make([]byte, 8, 8+len(payload))
	binary.BigEndian.PutUint32(out[0:4], tsn)
	binary.BigEndian.PutUint16(out[4:6], streamID)
	binary.BigEndian.PutUint16(out[6:8], streamSeq)
	return append(out, []byte(payload)...)
}

func hmacFor(value []byte) []byte {
	mac := hmac.New(sha256.New, authKey)
	mac.Write(value)
	return mac.Sum(nil)
}

func mustRegister(t *testing.T, g *taskpkg.SctpGuard, id string, vtag uint32, p taskpkg.Peer, tenant string) {
	t.Helper()
	if err := g.RegisterAssociation(id, vtag, p, tenant); err != nil {
		t.Fatalf("RegisterAssociation(%q, %#x): %v", id, vtag, err)
	}
}

// A datagram with one DATA chunk must expose ports, tag and chunk fields.
func TestParseSingleDataChunk(t *testing.T) {
	g := newGuard(t, testConfig())
	raw := sctpPacket(5000, 5001, 0xABCDEF01, chunk(0, 0x03, dataValue(12345, 1, 2, "hi")))
	pkt, err := g.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if pkt.SrcPort != 5000 || pkt.DstPort != 5001 || pkt.VTag != 0xABCDEF01 {
		t.Fatalf("unexpected common header: %+v", pkt)
	}
	if len(pkt.Chunks) != 1 {
		t.Fatalf("chunks = %d, want 1", len(pkt.Chunks))
	}
	c := pkt.Chunks[0]
	if c.Type != 0 || c.Flags != 0x03 || len(c.Value) != 10 {
		t.Fatalf("unexpected chunk: type=%d flags=%#x len=%d", c.Type, c.Flags, len(c.Value))
	}
	if tsn := binary.BigEndian.Uint32(c.Value[0:4]); tsn != 12345 {
		t.Fatalf("tsn = %d, want 12345", tsn)
	}
}

// A chunk length below the four byte header size is invalid.
func TestParseRejectsShortChunkLength(t *testing.T) {
	g := newGuard(t, testConfig())
	raw := sctpPacket(5000, 5001, 0x01, []byte{0x00, 0x00, 0x00, 0x02})
	if _, err := g.Parse(raw); !errors.Is(err, taskpkg.ErrMalformed) {
		t.Fatalf("short chunk length must be ErrMalformed, got %v", err)
	}
}

// A chunk length may not claim bytes beyond the datagram.
func TestParseRejectsChunkOverrun(t *testing.T) {
	g := newGuard(t, testConfig())
	raw := sctpPacket(5000, 5001, 0x01, []byte{0x00, 0x00, 0x00, 0x28, 0x01, 0x02, 0x03, 0x04})
	if _, err := g.Parse(raw); !errors.Is(err, taskpkg.ErrMalformed) {
		t.Fatalf("chunk overrun must be ErrMalformed, got %v", err)
	}
}

// Padding after an odd sized chunk value must be zero.
func TestParseRejectsNonZeroPadding(t *testing.T) {
	g := newGuard(t, testConfig())
	raw := sctpPacket(5000, 5001, 0x01, []byte{0x00, 0x00, 0x00, 0x05, 0xAA, 0xFF, 0x00, 0x00})
	if _, err := g.Parse(raw); !errors.Is(err, taskpkg.ErrPadding) {
		t.Fatalf("non zero padding must be ErrPadding, got %v", err)
	}
}

// A datagram may not carry more chunks than the configured cap.
func TestParseEnforcesChunkCountLimit(t *testing.T) {
	cfg := testConfig()
	cfg.MaxChunksPerPacket = 2
	g := newGuard(t, cfg)
	raw := sctpPacket(5000, 5001, 0x01,
		chunk(0, 0, nil), chunk(0, 0, nil), chunk(0, 0, nil))
	if _, err := g.Parse(raw); !errors.Is(err, taskpkg.ErrTooManyChunks) {
		t.Fatalf("three chunks with cap two must be ErrTooManyChunks, got %v", err)
	}
}

// A datagram larger than the configured byte budget is refused.
func TestParseEnforcesPacketSizeLimit(t *testing.T) {
	cfg := testConfig()
	cfg.MaxPacketBytes = 32
	g := newGuard(t, cfg)
	raw := sctpPacket(5000, 5001, 0x01, chunk(0, 0, make([]byte, 40)))
	if len(raw) <= cfg.MaxPacketBytes {
		t.Fatalf("fixture is %d bytes, must exceed %d", len(raw), cfg.MaxPacketBytes)
	}
	if _, err := g.Parse(raw); !errors.Is(err, taskpkg.ErrPacketTooLarge) {
		t.Fatalf("oversized packet must be ErrPacketTooLarge, got %v", err)
	}
}

// INIT must not be bundled with any other chunk.
func TestParseRejectsBundledInit(t *testing.T) {
	g := newGuard(t, testConfig())
	raw := sctpPacket(5000, 5001, 0x01,
		chunk(1, 0, make([]byte, 16)), chunk(0, 0x03, dataValue(1, 1, 1, "x")))
	if _, err := g.Parse(raw); !errors.Is(err, taskpkg.ErrBundling) {
		t.Fatalf("bundled INIT must be ErrBundling, got %v", err)
	}
}

// One verification tag may only be registered to one association.
func TestRegisterAssociationVTagConflict(t *testing.T) {
	g := newGuard(t, testConfig())
	mustRegister(t, g, "assoc-a", 0x1001, taskpkg.Peer{Addr: "10.1.0.1", Port: 9000}, "tenant-a")
	err := g.RegisterAssociation("assoc-b", 0x1001, taskpkg.Peer{Addr: "10.2.0.1", Port: 9000}, "tenant-b")
	if !errors.Is(err, taskpkg.ErrVTagConflict) {
		t.Fatalf("duplicate verification tag must be ErrVTagConflict, got %v", err)
	}
	if _, err := g.Association("assoc-a"); err != nil {
		t.Fatalf("original association lost: %v", err)
	}
	if _, err := g.Association("assoc-b"); !errors.Is(err, taskpkg.ErrAssocUnknown) {
		t.Fatalf("conflicting association must not exist, got %v", err)
	}
}

// Two associations racing for one verification tag: exactly one may win.
func TestRegisterAssociationConcurrentSingleWinner(t *testing.T) {
	g := newGuard(t, testConfig())
	var wg sync.WaitGroup
	errs := make([]error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		errs[0] = g.RegisterAssociation("assoc-race-a", 0x3003, taskpkg.Peer{Addr: "10.1.0.1", Port: 9000}, "tenant-a")
	}()
	go func() {
		defer wg.Done()
		errs[1] = g.RegisterAssociation("assoc-race-b", 0x3003, taskpkg.Peer{Addr: "10.2.0.1", Port: 9000}, "tenant-b")
	}()
	wg.Wait()
	success, conflict := 0, 0
	for _, err := range errs {
		switch {
		case err == nil:
			success++
		case errors.Is(err, taskpkg.ErrVTagConflict):
			conflict++
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatalf("want one winner and one ErrVTagConflict, got successes=%d conflicts=%d errors=%v", success, conflict, errs)
	}
}

// A datagram for an unregistered association must be dropped.
func TestAdmitRejectsUnknownAssociation(t *testing.T) {
	g := newGuard(t, testConfig())
	raw := sctpPacket(5000, 5001, 0x4004, chunk(0, 0x03, dataValue(1, 1, 1, "x")))
	if _, err := g.Admit("ghost", raw, time.Unix(1700000000, 0)); !errors.Is(err, taskpkg.ErrAssocUnknown) {
		t.Fatalf("unknown association must be ErrAssocUnknown, got %v", err)
	}
}

// The verification tag in the datagram must match the association.
func TestAdmitRejectsVTagMismatch(t *testing.T) {
	g := newGuard(t, testConfig())
	now := time.Unix(1700000000, 0)
	mustRegister(t, g, "assoc-tag", 0x2002, taskpkg.Peer{Addr: "10.1.0.1", Port: 9000}, "tenant-a")
	raw := sctpPacket(5000, 5001, 0x2003, chunk(0, 0x03, dataValue(10, 1, 1, "x")))
	if _, err := g.Admit("assoc-tag", raw, now); !errors.Is(err, taskpkg.ErrVTagMismatch) {
		t.Fatalf("foreign verification tag must be ErrVTagMismatch, got %v", err)
	}
}

// A wrong HMAC must never be accepted.
func TestAuthenticateRejectsBadMAC(t *testing.T) {
	g := newGuard(t, testConfig())
	now := time.Unix(1700000000, 0)
	mustRegister(t, g, "assoc-mac", 0x5005, taskpkg.Peer{Addr: "10.1.0.1", Port: 9000}, "tenant-a")
	value := []byte("chunk-one-value")
	bad := hmacFor(value)
	bad[0] ^= 0xFF
	if err := g.Authenticate("assoc-mac", value, bad, now); !errors.Is(err, taskpkg.ErrMACInvalid) {
		t.Fatalf("wrong code must be ErrMACInvalid, got %v", err)
	}
}

// A correct code is accepted once and only once inside its TTL.
func TestAuthenticateReplayRejected(t *testing.T) {
	g := newGuard(t, testConfig())
	now := time.Unix(1700000000, 0)
	mustRegister(t, g, "assoc-replay", 0x5006, taskpkg.Peer{Addr: "10.1.0.1", Port: 9000}, "tenant-a")
	value := []byte("chunk-two-value")
	code := hmacFor(value)
	if err := g.Authenticate("assoc-replay", value, code, now); err != nil {
		t.Fatalf("first Authenticate: %v", err)
	}
	if err := g.Authenticate("assoc-replay", value, code, now.Add(10*time.Second)); !errors.Is(err, taskpkg.ErrReplay) {
		t.Fatalf("replayed code must be ErrReplay, got %v", err)
	}
	stats := g.Stats()
	if stats.Authenticated != 1 || stats.Replayed != 1 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
}

// DATA transmission sequence numbers must strictly increase.
func TestAdmitRejectsTSNRegression(t *testing.T) {
	g := newGuard(t, testConfig())
	now := time.Unix(1700000000, 0)
	mustRegister(t, g, "assoc-tsn", 0x6006, taskpkg.Peer{Addr: "10.1.0.1", Port: 9000}, "tenant-a")
	admit := func(tsn uint32) error {
		raw := sctpPacket(5000, 5001, 0x6006, chunk(0, 0x03, dataValue(tsn, 1, 1, "x")))
		_, err := g.Admit("assoc-tsn", raw, now)
		return err
	}
	if err := admit(100); err != nil {
		t.Fatalf("first Admit: %v", err)
	}
	if err := admit(100); !errors.Is(err, taskpkg.ErrTSNRegression) {
		t.Fatalf("repeated TSN must be ErrTSNRegression, got %v", err)
	}
	if err := admit(99); !errors.Is(err, taskpkg.ErrTSNRegression) {
		t.Fatalf("older TSN must be ErrTSNRegression, got %v", err)
	}
	if err := admit(101); err != nil {
		t.Fatalf("newer TSN rejected: %v", err)
	}
	tsn, err := g.LastTSN("assoc-tsn")
	if err != nil {
		t.Fatalf("LastTSN: %v", err)
	}
	if tsn != 101 {
		t.Fatalf("last TSN = %d, want 101", tsn)
	}
}

// A restarted guard must still reject replayed codes and old TSNs.
func TestSnapshotRestoresReplayState(t *testing.T) {
	cfg := testConfig()
	g := newGuard(t, cfg)
	now := time.Unix(1700000000, 0)
	p := taskpkg.Peer{Addr: "10.1.0.1", Port: 9000}
	mustRegister(t, g, "assoc-persist", 0x51515151, p, "tenant-a")
	if _, err := g.Admit("assoc-persist", sctpPacket(5000, 5001, 0x51515151,
		chunk(0, 0x03, dataValue(500, 1, 1, "x"))), now); err != nil {
		t.Fatalf("Admit: %v", err)
	}
	value := []byte("persisted-chunk-value")
	code := hmacFor(value)
	if err := g.Authenticate("assoc-persist", value, code, now); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	snap, err := g.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	restored, err := taskpkg.NewSctpGuardFromSnapshot(cfg, snap)
	if err != nil {
		t.Fatalf("NewSctpGuardFromSnapshot: %v", err)
	}
	if _, err := restored.Admit("assoc-persist", sctpPacket(5000, 5001, 0x51515151,
		chunk(0, 0x03, dataValue(499, 1, 1, "y"))), now); !errors.Is(err, taskpkg.ErrTSNRegression) {
		t.Fatalf("regressed TSN after restart must be ErrTSNRegression, got %v", err)
	}
	if err := restored.Authenticate("assoc-persist", value, code, now); !errors.Is(err, taskpkg.ErrReplay) {
		t.Fatalf("replayed code after restart must be ErrReplay, got %v", err)
	}
	if err := restored.Authenticate("assoc-persist", []byte("fresh-chunk"), hmacFor([]byte("fresh-chunk")), now); err != nil {
		t.Fatalf("fresh code after restart rejected: %v", err)
	}
}
