package task

import "errors"

// Sentinel errors returned while decoding or validating a Geneve header.
var (
	ErrVersion         = errors.New("geneve: unsupported version")
	ErrProtocol        = errors.New("geneve: unsupported protocol type")
	ErrMalformed       = errors.New("geneve: malformed header or option")
	ErrTooManyOptions  = errors.New("geneve: option count limit exceeded")
	ErrDuplicateOption = errors.New("geneve: duplicate option in one header")
	ErrCriticalOption  = errors.New("geneve: unknown critical option")
	ErrOptionTooLong   = errors.New("geneve: option value exceeds length limit")
	ErrVNIRange        = errors.New("geneve: vni outside the usable range")
	ErrVNIBound        = errors.New("geneve: vni already owned by another tenant")
	ErrVNIUnknown      = errors.New("geneve: vni is not registered")
	ErrTenantMismatch  = errors.New("geneve: vni belongs to another tenant")
)

var errNotImplemented = errors.New("not implemented")

// Option is one decoded Geneve option. The critical bit is split out of the
// wire type byte; Type holds the lower seven bits.
type Option struct {
	Class    uint16
	Type     uint8
	Critical bool
	Value    []byte
}

// Header is a decoded Geneve encapsulation header.
type Header struct {
	VNI      int
	Protocol uint16
	OAM      bool
	Options  []Option
}

// OptionRule is the policy for one (class, type) pair.
type OptionRule struct {
	Class         uint16
	Type          uint8
	MaxValueBytes int
}

// Policy drives structural and semantic validation.
//
// MaxOptions caps how many options one header may carry. MaxValueBytes is the
// absolute cap for every option value. Rules describe the options this
// deployment understands; an option without a rule is unknown.
type Policy struct {
	Rules         []OptionRule
	MaxOptions    int
	MaxValueBytes int
}

// Stats counts validation outcomes.
type Stats struct {
	Validated      int
	Rejected       int
	IgnoredOptions int
}

// GeneveGuard parses Geneve headers and enforces VNI tenant ownership plus the
// option policy.
type GeneveGuard struct {
	policy Policy
}

// NewGeneveGuard returns a guard configured by policy.
func NewGeneveGuard(policy Policy) *GeneveGuard {
	return &GeneveGuard{policy: policy}
}

// NewGeneveGuardFromSnapshot restores the VNI ownership table from data.
func NewGeneveGuardFromSnapshot(policy Policy, data []byte) (*GeneveGuard, error) {
	return nil, errNotImplemented
}

// ParseHeader decodes one Geneve header including its option area.
//
// The version must be 0, the declared option area must be fully present, every
// option must fit inside it, at most MaxOptions options may appear, and a
// (class, type) pair may appear once.
func (g *GeneveGuard) ParseHeader(raw []byte) (Header, error) {
	return Header{}, errNotImplemented
}

// Validate checks h against the option policy and the tenant that owns its
// VNI. Unknown critical options are refused; unknown non-critical options are
// counted and skipped.
func (g *GeneveGuard) Validate(h Header, tenantID string) error {
	return errNotImplemented
}

// RegisterVNI binds vni to tenantID. VNI 0 and 16777215 are reserved.
func (g *GeneveGuard) RegisterVNI(vni int, tenantID string) error {
	return errNotImplemented
}

// UnregisterVNI removes the binding for vni.
func (g *GeneveGuard) UnregisterVNI(vni int) error {
	return errNotImplemented
}

// TenantForVNI returns the tenant that owns vni.
func (g *GeneveGuard) TenantForVNI(vni int) (string, error) {
	return "", errNotImplemented
}

// RegisteredVNIs returns the bound VNIs in ascending order.
func (g *GeneveGuard) RegisteredVNIs() []int {
	return nil
}

// ProtocolAllowed reports whether proto may be encapsulated.
func (g *GeneveGuard) ProtocolAllowed(proto uint16) bool {
	return false
}

// Snapshot serialises the VNI ownership table and counters.
func (g *GeneveGuard) Snapshot() ([]byte, error) {
	return nil, errNotImplemented
}

// Stats returns the validation counters.
func (g *GeneveGuard) Stats() Stats {
	return Stats{}
}
