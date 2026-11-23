package task

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	taskpkg "gsb/batch46-safety-c-06"
)

func testPolicy() taskpkg.TrustPolicy {
	return taskpkg.TrustPolicy{
		TrustedCIDRs:   []string{"10.0.0.0/8", "192.0.2.0/24"},
		MaxHeaderBytes: 512,
		MaxChainHops:   2,
		AllowedTLVs:    []string{"authority", "unique_id"},
	}
}

func newGuard(t *testing.T) *taskpkg.ProxyProtocolGuard {
	t.Helper()
	g, err := taskpkg.NewProxyProtocolGuard(testPolicy())
	if err != nil {
		t.Fatalf("NewProxyProtocolGuard: %v", err)
	}
	if g == nil {
		t.Fatalf("NewProxyProtocolGuard returned nil guard")
	}
	return g
}

func v1Line(src, dst string, sport, dport int) []byte {
	return []byte(fmt.Sprintf("PROXY TCP4 %s %s %d %d\r\n", src, dst, sport, dport))
}

func v2AddrBody(src, dst string, sport, dport int, tlvs []byte) []byte {
	s := net.ParseIP(src).To4()
	d := net.ParseIP(dst).To4()
	if s == nil || d == nil {
		panic("v2AddrBody needs IPv4 fixtures")
	}
	body := append(append([]byte{}, s...), d...)
	body = append(body, byte(sport>>8), byte(sport), byte(dport>>8), byte(dport))
	return append(body, tlvs...)
}

func v2Raw(verCmd, famProto byte, declared int, body []byte) []byte {
	sig := []byte("\r\n\r\n\x00\r\nQUIT\n")
	raw := append([]byte{}, sig...)
	raw = append(raw, verCmd, famProto, byte(declared>>8), byte(declared))
	return append(raw, body...)
}

func tlv(typ byte, val string) []byte {
	return append([]byte{typ, byte(len(val))}, []byte(val)...)
}

// A plain version 1 TCP4 line must decode into all address fields.
func TestParseV1TCP4Fields(t *testing.T) {
	g := newGuard(t)
	hdr, err := g.Parse(v1Line("203.0.113.7", "198.51.100.9", 51234, 443))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if hdr.Version != 1 || hdr.Command != "PROXY" || hdr.Family != "TCP4" {
		t.Fatalf("unexpected header identity: %+v", hdr)
	}
	if hdr.SrcAddr != "203.0.113.7" || hdr.SrcPort != 51234 {
		t.Fatalf("source mismatch: %s:%d", hdr.SrcAddr, hdr.SrcPort)
	}
	if hdr.DstAddr != "198.51.100.9" || hdr.DstPort != 443 {
		t.Fatalf("destination mismatch: %s:%d", hdr.DstAddr, hdr.DstPort)
	}
}

// Out-of-range or missing address fields must be framing errors.
func TestParseV1RejectsMalformed(t *testing.T) {
	g := newGuard(t)
	cases := [][]byte{
		[]byte("PROXY TCP4 203.0.113.7 198.51.100.9 99999 443\r\n"),
		[]byte("PROXY TCP4 203.0.113.7 198.51.100.9 51234\r\n"),
		[]byte("PROXY TCP4 203.0.113.7 198.51.100.9 abc 443\r\n"),
	}
	for _, raw := range cases {
		if _, err := g.Parse(raw); !errors.Is(err, taskpkg.ErrMalformed) {
			t.Fatalf("%q must be ErrMalformed, got %v", raw, err)
		}
	}
}

// Bytes that are not a PROXY header at all must not be parsed as one.
func TestParseRejectsMissingSignature(t *testing.T) {
	g := newGuard(t)
	if _, err := g.Parse([]byte("GET /health HTTP/1.1\r\nHost: x\r\n")); !errors.Is(err, taskpkg.ErrNotProxy) {
		t.Fatalf("plain HTTP must be ErrNotProxy, got %v", err)
	}
	body := v2AddrBody("203.0.113.7", "198.51.100.9", 51234, 443, nil)
	bad := v2Raw(0x21, 0x11, len(body), body)
	bad[8] = 'X'
	if _, err := g.Parse(bad); !errors.Is(err, taskpkg.ErrNotProxy) {
		t.Fatalf("corrupt v2 signature must be ErrNotProxy, got %v", err)
	}
}

// A version 2 header must decode its address block and permitted TLVs.
func TestParseV2TCP4WithAuthorityTLV(t *testing.T) {
	g := newGuard(t)
	body := v2AddrBody("203.0.113.7", "198.51.100.9", 51234, 443, tlv(0x02, "api"))
	hdr, err := g.Parse(v2Raw(0x21, 0x11, len(body), body))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if hdr.Version != 2 || hdr.Command != "PROXY" || hdr.Family != "TCP4" {
		t.Fatalf("unexpected header identity: %+v", hdr)
	}
	if hdr.SrcAddr != "203.0.113.7" || hdr.DstAddr != "198.51.100.9" || hdr.SrcPort != 51234 {
		t.Fatalf("address mismatch: %+v", hdr)
	}
	if got := hdr.TLVs["authority"]; got != "api" {
		t.Fatalf("authority TLV = %q, want %q", got, "api")
	}
}

// Only TCP over IPv4/IPv6 is a supported family for a PROXY command.
func TestParseV2RejectsUnsupportedFamily(t *testing.T) {
	g := newGuard(t)
	body := v2AddrBody("203.0.113.7", "198.51.100.9", 51234, 443, nil)
	if _, err := g.Parse(v2Raw(0x21, 0x31, len(body), body)); !errors.Is(err, taskpkg.ErrUnknownFamily) {
		t.Fatalf("AF_UNIX header must be ErrUnknownFamily, got %v", err)
	}
}

// The size cap is enforced before any field validation.
func TestParseRejectsOversizedHeader(t *testing.T) {
	policy := testPolicy()
	policy.MaxHeaderBytes = 64
	g, err := taskpkg.NewProxyProtocolGuard(policy)
	if err != nil {
		t.Fatalf("NewProxyProtocolGuard: %v", err)
	}
	long := []byte("PROXY UNKNOWN " + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n")
	if len(long) <= policy.MaxHeaderBytes {
		t.Fatalf("fixture is %d bytes, must exceed %d", len(long), policy.MaxHeaderBytes)
	}
	if _, err := g.Parse(long); !errors.Is(err, taskpkg.ErrHeaderTooLarge) {
		t.Fatalf("oversized header must be ErrHeaderTooLarge, got %v", err)
	}
}

// A version 2 length field larger than the delivered bytes is a framing error.
func TestParseRejectsTruncatedV2(t *testing.T) {
	g := newGuard(t)
	body := v2AddrBody("203.0.113.7", "198.51.100.9", 51234, 443, nil)
	if _, err := g.Parse(v2Raw(0x21, 0x11, len(body)+16, body)); !errors.Is(err, taskpkg.ErrMalformed) {
		t.Fatalf("truncated header must be ErrMalformed, got %v", err)
	}
}

// A header from an address outside the trust table must be refused.
func TestAdmitRejectsUntrustedPeer(t *testing.T) {
	g := newGuard(t)
	now := time.Unix(1700000000, 0)
	peer := taskpkg.Peer{Addr: "203.0.113.9", Port: 40000}
	_, err := g.Admit("conn-1", peer, v1Line("198.51.100.7", "10.0.0.5", 51234, 443), now)
	if !errors.Is(err, taskpkg.ErrUntrustedPeer) {
		t.Fatalf("untrusted peer must be ErrUntrustedPeer, got %v", err)
	}
	if g.ActiveConns() != 0 {
		t.Fatalf("refused admission must not create a connection, have %d", g.ActiveConns())
	}
}

// The client address comes from the header, not from the transport peer.
func TestAdmitFromTrustedPeerUsesHeaderSource(t *testing.T) {
	g := newGuard(t)
	now := time.Unix(1700000000, 0)
	peer := taskpkg.Peer{Addr: "10.1.2.3", Port: 40000}
	client, err := g.Admit("conn-2", peer, v1Line("198.51.100.7", "10.0.0.5", 51234, 443), now)
	if err != nil {
		t.Fatalf("Admit: %v", err)
	}
	if client.SrcAddr != "198.51.100.7" || client.SrcPort != 51234 {
		t.Fatalf("client source = %s:%d", client.SrcAddr, client.SrcPort)
	}
	if client.DstAddr != "10.0.0.5" || client.DstPort != 443 || client.ConnID != "conn-2" {
		t.Fatalf("unexpected client: %+v", client)
	}
	if got := g.Stats(); got.Admitted != 1 || got.Rejected != 0 {
		t.Fatalf("stats after admit: %+v", got)
	}
}

// Revoking a CIDR must take effect for later connections immediately.
func TestTrustRevokeTakesEffect(t *testing.T) {
	policy := testPolicy()
	policy.TrustedCIDRs = nil
	g, err := taskpkg.NewProxyProtocolGuard(policy)
	if err != nil {
		t.Fatalf("NewProxyProtocolGuard: %v", err)
	}
	if err := g.TrustPeer("203.0.113.0/24"); err != nil {
		t.Fatalf("TrustPeer: %v", err)
	}
	if !g.IsTrusted("203.0.113.44") {
		t.Fatalf("203.0.113.44 must be trusted after TrustPeer")
	}
	if err := g.UntrustPeer("203.0.113.0/24"); err != nil {
		t.Fatalf("UntrustPeer: %v", err)
	}
	if g.IsTrusted("203.0.113.44") {
		t.Fatalf("203.0.113.44 must not be trusted after UntrustPeer")
	}
	_, err = g.Admit("conn-3", taskpkg.Peer{Addr: "203.0.113.44", Port: 40000},
		v1Line("198.51.100.7", "10.0.0.5", 51234, 443), time.Unix(1700000000, 0))
	if !errors.Is(err, taskpkg.ErrUntrustedPeer) {
		t.Fatalf("revoked peer must be refused, got %v", err)
	}
}

// A chain carries one header per proxy; the innermost header names the real
// client and the configured hop limit caps the chain length.
func TestChainRespectsHopLimitAndInnerSource(t *testing.T) {
	g := newGuard(t)
	now := time.Unix(1700000000, 0)
	peer := taskpkg.Peer{Addr: "10.9.9.9", Port: 40000}
	h1 := v1Line("192.0.2.1", "10.0.0.5", 40000, 443)
	h2 := v1Line("198.51.100.7", "192.0.2.1", 51234, 40000)
	raw := append(append([]byte{}, h1...), h2...)
	client, err := g.Admit("conn-4", peer, raw, now)
	if err != nil {
		t.Fatalf("two hop chain: %v", err)
	}
	if client.SrcAddr != "198.51.100.7" || client.SrcPort != 51234 {
		t.Fatalf("innermost source not used: %+v", client)
	}
	three := append(append(append([]byte{}, h1...), h1...), h2...)
	if _, err := g.Admit("conn-5", peer, three, now); !errors.Is(err, taskpkg.ErrLimit) {
		t.Fatalf("three hop chain must be ErrLimit, got %v", err)
	}
}

// TLVs outside the policy allowlist must be refused rather than surfaced.
func TestTLVNotInAllowlistRejected(t *testing.T) {
	g := newGuard(t)
	body := v2AddrBody("203.0.113.7", "198.51.100.9", 51234, 443, tlv(0xEE, "x"))
	if _, err := g.Parse(v2Raw(0x21, 0x11, len(body), body)); !errors.Is(err, taskpkg.ErrTLVInvalid) {
		t.Fatalf("private TLV must be ErrTLVInvalid, got %v", err)
	}
}

// Replaying the identical chain on the same connection is idempotent.
func TestRepeatedHeaderIsIdempotent(t *testing.T) {
	g := newGuard(t)
	now := time.Unix(1700000000, 0)
	peer := taskpkg.Peer{Addr: "10.1.2.3", Port: 40000}
	raw := v1Line("198.51.100.7", "10.0.0.5", 51234, 443)
	first, err := g.Admit("conn-6", peer, raw, now)
	if err != nil {
		t.Fatalf("first Admit: %v", err)
	}
	second, err := g.Admit("conn-6", peer, raw, now)
	if err != nil {
		t.Fatalf("identical replay must be idempotent, got %v", err)
	}
	if second != first {
		t.Fatalf("idempotent replay returned %+v, want %+v", second, first)
	}
	stats := g.Stats()
	if stats.Admitted != 1 || stats.Idempotent != 1 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
	if g.ActiveConns() != 1 {
		t.Fatalf("active connections = %d, want 1", g.ActiveConns())
	}
}

// Two conflicting chains raced on one connection: exactly one may win.
func TestConcurrentConflictingHeadersSingleWinner(t *testing.T) {
	g := newGuard(t)
	now := time.Unix(1700000000, 0)
	peer := taskpkg.Peer{Addr: "10.1.2.3", Port: 40000}
	rawA := v1Line("198.51.100.7", "10.0.0.5", 51234, 443)
	rawB := v1Line("203.0.113.77", "10.0.0.5", 51235, 443)
	var wg sync.WaitGroup
	errs := make([]error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, errs[0] = g.Admit("conn-7", peer, rawA, now)
	}()
	go func() {
		defer wg.Done()
		_, errs[1] = g.Admit("conn-7", peer, rawB, now)
	}()
	wg.Wait()
	success, conflict := 0, 0
	for _, err := range errs {
		switch {
		case err == nil:
			success++
		case errors.Is(err, taskpkg.ErrBrokenChain):
			conflict++
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatalf("want one winner and one ErrBrokenChain, got successes=%d conflicts=%d errors=%v", success, conflict, errs)
	}
	if g.ActiveConns() != 1 {
		t.Fatalf("active connections = %d, want 1", g.ActiveConns())
	}
}

// A restored guard must still know the client address of open connections.
func TestSnapshotRestoresActiveConn(t *testing.T) {
	g := newGuard(t)
	now := time.Unix(1700000000, 0)
	peer := taskpkg.Peer{Addr: "10.1.2.3", Port: 40000}
	raw := v1Line("198.51.100.7", "10.0.0.5", 51234, 443)
	if _, err := g.Admit("conn-8", peer, raw, now); err != nil {
		t.Fatalf("Admit: %v", err)
	}
	snap, err := g.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	restored, err := taskpkg.NewProxyProtocolGuardFromSnapshot(testPolicy(), snap)
	if err != nil {
		t.Fatalf("NewProxyProtocolGuardFromSnapshot: %v", err)
	}
	client, err := restored.Client("conn-8")
	if err != nil {
		t.Fatalf("Client after restore: %v", err)
	}
	if client.SrcAddr != "198.51.100.7" || client.SrcPort != 51234 {
		t.Fatalf("restored client = %+v", client)
	}
	if restored.ActiveConns() != 1 {
		t.Fatalf("restored active connections = %d, want 1", restored.ActiveConns())
	}
}
