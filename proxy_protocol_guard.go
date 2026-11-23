package task

import (
	"errors"
	"time"
)

// Sentinel errors returned by ProxyProtocolGuard. Rejection causes are kept
// distinct so that operators can tell a spoofing attempt from a framing bug.
var (
	ErrNotProxy       = errors.New("proxyproto: missing or unrecognised header")
	ErrMalformed      = errors.New("proxyproto: malformed header")
	ErrUntrustedPeer  = errors.New("proxyproto: peer is not a trusted proxy")
	ErrUnknownFamily  = errors.New("proxyproto: unsupported address family")
	ErrTLVInvalid     = errors.New("proxyproto: tlv not permitted or invalid")
	ErrHeaderTooLarge = errors.New("proxyproto: header exceeds size limit")
	ErrBrokenChain    = errors.New("proxyproto: conflicting header for connection")
	ErrLimit          = errors.New("proxyproto: chain hop limit exceeded")
	ErrConnUnknown    = errors.New("proxyproto: unknown connection")
)

var errNotImplemented = errors.New("not implemented")

// Peer is the transport peer that opened the connection.
type Peer struct {
	Addr string
	Port int
}

// Header is one parsed PROXY protocol header.
//
// Version is 1 or 2. Command is "PROXY", "LOCAL" or "UNKNOWN". Family is
// "TCP4", "TCP6" or empty for addresses the header does not carry. TLVs holds
// the permitted type-length-value pairs of a version 2 header keyed by TLV
// name; version 1 headers have an empty map.
type Header struct {
	Version int
	Command string
	Family  string
	SrcAddr string
	SrcPort int
	DstAddr string
	DstPort int
	TLVs    map[string]string
}

// Client is the address decision stored for one accepted connection.
type Client struct {
	ConnID  string
	SrcAddr string
	SrcPort int
	DstAddr string
	DstPort int
	Family  string
}

// Stats counts admission outcomes since start or restore.
type Stats struct {
	Admitted   int
	Idempotent int
	Rejected   int
}

// TrustPolicy configures header parsing and peer trust.
//
// TrustedCIDRs are the only peers allowed to present a header. MaxHeaderBytes
// bounds the bytes consumed by all headers of one connection. MaxChainHops
// bounds how many concatenated headers are accepted. AllowedTLVs names the
// version 2 TLV types that parsers may surface to callers.
type TrustPolicy struct {
	TrustedCIDRs   []string
	MaxHeaderBytes int
	MaxChainHops   int
	AllowedTLVs    []string
}

// ProxyProtocolGuard validates PROXY protocol headers and remembers, per
// connection, which client address was trusted.
type ProxyProtocolGuard struct {
	policy TrustPolicy
}

// NewProxyProtocolGuard returns a guard configured by policy.
func NewProxyProtocolGuard(policy TrustPolicy) (*ProxyProtocolGuard, error) {
	return &ProxyProtocolGuard{policy: policy}, nil
}

// NewProxyProtocolGuardFromSnapshot restores a guard, including active
// connections, from a snapshot produced by Snapshot.
func NewProxyProtocolGuardFromSnapshot(policy TrustPolicy, data []byte) (*ProxyProtocolGuard, error) {
	return nil, errNotImplemented
}

// Parse decodes exactly one header. It applies the policy size limit, family
// check and TLV allowlist but never consults the peer trust table.
func (g *ProxyProtocolGuard) Parse(raw []byte) (Header, error) {
	return Header{}, errNotImplemented
}

// ParseChain decodes one or more concatenated headers in wire order, outermost
// header first. It fails with ErrLimit when the count exceeds MaxChainHops.
func (g *ProxyProtocolGuard) ParseChain(raw []byte) ([]Header, error) {
	return nil, errNotImplemented
}

// TrustPeer adds a CIDR to the trusted proxy set.
func (g *ProxyProtocolGuard) TrustPeer(cidr string) error {
	return errNotImplemented
}

// UntrustPeer removes a CIDR from the trusted proxy set.
func (g *ProxyProtocolGuard) UntrustPeer(cidr string) error {
	return errNotImplemented
}

// IsTrusted reports whether addr falls inside a trusted CIDR.
func (g *ProxyProtocolGuard) IsTrusted(addr string) bool {
	return false
}

// Admit validates the header chain sent by peer on connID.
//
// The peer must be trusted, the chain must fit the hop limit, and every hop
// address must be trustworthy framing. On success the client address is the
// innermost header source. Re-sending the identical chain on connID is
// idempotent; a different chain on the same connID is ErrBrokenChain.
func (g *ProxyProtocolGuard) Admit(connID string, peer Peer, raw []byte, now time.Time) (Client, error) {
	return Client{}, errNotImplemented
}

// Client returns the accepted client address for connID.
func (g *ProxyProtocolGuard) Client(connID string) (Client, error) {
	return Client{}, errNotImplemented
}

// CloseConn forgets connID.
func (g *ProxyProtocolGuard) CloseConn(connID string) error {
	return errNotImplemented
}

// ActiveConns reports how many connections have an accepted client address.
func (g *ProxyProtocolGuard) ActiveConns() int {
	return 0
}

// Snapshot serialises the trusted proxy set and active connection decisions.
func (g *ProxyProtocolGuard) Snapshot() ([]byte, error) {
	return nil, errNotImplemented
}

// Stats returns the admission counters.
func (g *ProxyProtocolGuard) Stats() Stats {
	return Stats{}
}
