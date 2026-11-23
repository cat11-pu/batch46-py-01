package task

import (
	"errors"
	"sync"
	"time"
)

// Sentinel errors reported by MplsGuard. Callers branch on these values to
// decide whether a packet is dropped, counted, or forwarded.
var (
	ErrLabelInvalid    = errors.New("mpls: invalid label")
	ErrLabelNotAllowed = errors.New("mpls: label not permitted by policy")
	ErrReserved        = errors.New("mpls: reserved label misuse")
	ErrTTL             = errors.New("mpls: ttl violation")
	ErrStackDepth      = errors.New("mpls: stack depth violation")
	ErrReplay          = errors.New("mpls: duplicate stack observed")
	ErrFlowLimit       = errors.New("mpls: flow tracking limit reached")
	ErrNotFound        = errors.New("mpls: unknown nexthop")
	ErrSnapshot        = errors.New("mpls: invalid snapshot")
)

const (
	// MaxLabelValue is the largest 20-bit MPLS label value.
	MaxLabelValue = 1<<20 - 1
	// ReservedBase is the first value of the reserved label range.
	ReservedBase = 16
)

var errNotImplemented = errors.New("stub: not implemented")

// Label is one entry of an MPLS label stack. The stack is ordered outermost
// first: index 0 is the top label and the final element is the bottom label.
type Label struct {
	// Value is the 20-bit label value.
	Value uint32
	// TC is the 3-bit traffic class.
	TC uint8
	// S is the bottom-of-stack bit; only the final element may set it.
	S bool
	// TTL is the 8-bit time to live.
	TTL uint8
}

// Policy is the validation policy applied by one guard instance.
type Policy struct {
	// MaxDepth is the largest accepted label stack depth.
	MaxDepth int
	// MinTTL is the smallest accepted TTL on any label.
	MinTTL uint8
	// AllowedLabels restricts normal label values. Empty means all values.
	AllowedLabels []uint32
	// ReplayWindow is how long a stack observation is remembered.
	ReplayWindow time.Duration
	// MaxFlows bounds the number of live observation entries.
	MaxFlows int
}

// Stats are cumulative guard counters.
type Stats struct {
	Accepted       int64
	Rejected       int64
	DepthRejected  int64
	ReplayRejected int64
	FlowRejected   int64
}

// MplsGuard validates label stacks at an ingress PE and remembers recently
// observed stacks per attachment circuit.
type MplsGuard struct {
	policy   Policy
	nexthops map[string][]uint32
	seen     map[string]time.Time
	stats    Stats
	mu       sync.Mutex
}

// NewMplsGuard returns a guard configured by policy.
func NewMplsGuard(policy Policy) *MplsGuard {
	return &MplsGuard{policy: policy}
}

// NewMplsGuardFromSnapshot restores nexthop expectations, replay state and
// counters from a snapshot produced by Snapshot.
func NewMplsGuardFromSnapshot(policy Policy, data []byte) (*MplsGuard, error) {
	return nil, errNotImplemented
}

// AddNexthop records the expected label value sequence for a nexthop. Adding
// the same name with an identical stack is idempotent; a different stack is
// rejected.
func (g *MplsGuard) AddNexthop(name string, stack []uint32) error {
	return errNotImplemented
}

// RemoveNexthop deletes a nexthop expectation. Removing an unknown name is a
// no-op.
func (g *MplsGuard) RemoveNexthop(name string) error {
	return errNotImplemented
}

// NexthopStack returns the expected label values for a nexthop.
func (g *MplsGuard) NexthopStack(name string) ([]uint32, error) {
	return nil, errNotImplemented
}

// ValidateStack checks depth, label ranges, traffic class, reserved labels,
// TTL limits, the policy allow list and the bottom-of-stack bit.
func (g *MplsGuard) ValidateStack(stack []Label) error {
	return errNotImplemented
}

// ValidateNexthop checks that the stack matches the expected label sequence
// for the nexthop and then validates the stack itself.
func (g *MplsGuard) ValidateNexthop(name string, stack []Label) error {
	return errNotImplemented
}

// Pop removes n labels from the top, decrements the TTL of the new top label
// and leaves the input stack untouched.
func (g *MplsGuard) Pop(stack []Label, n int) ([]Label, error) {
	return nil, errNotImplemented
}

// Push adds labels above the stack, enforcing depth, reserved-label and
// bottom-of-stack rules, and leaves the input stack untouched.
func (g *MplsGuard) Push(stack []Label, add []Label) ([]Label, error) {
	return nil, errNotImplemented
}

// Observe validates a stack seen on an attachment circuit and records its
// fingerprint for the replay window.
func (g *MplsGuard) Observe(sourceID string, stack []Label, now time.Time) error {
	return errNotImplemented
}

// IsReserved reports whether v belongs to the reserved label range.
func (g *MplsGuard) IsReserved(v uint32) bool {
	return false
}

// Counters returns a copy of the cumulative counters.
func (g *MplsGuard) Counters() Stats {
	return Stats{}
}

// ResetCounters zeroes the cumulative counters.
func (g *MplsGuard) ResetCounters() {
}

// Snapshot serialises nexthop expectations, replay state and counters.
func (g *MplsGuard) Snapshot() ([]byte, error) {
	return nil, errNotImplemented
}
