package task

import "errors"

var errNotImplemented = errors.New("not implemented")

// Sentinel errors returned by SelinuxGuard.
var (
	ErrBoolExists         = errors.New("selinux: boolean already registered")
	ErrInvalidBoolName    = errors.New("selinux: invalid boolean name")
	ErrUnknownBool        = errors.New("selinux: unknown boolean")
	ErrCapReached         = errors.New("selinux: pending capacity reached")
	ErrTooManyChanges     = errors.New("selinux: change budget exceeded")
	ErrNothingToApply     = errors.New("selinux: no pending changes")
	ErrInvalidPath        = errors.New("selinux: invalid file path")
	ErrInvalidContextType = errors.New("selinux: invalid context type")
	ErrConflict           = errors.New("selinux: conflicting context for path")
	ErrDuplicateContext   = errors.New("selinux: context already staged")
	ErrNotFound           = errors.New("selinux: path has no context")
	ErrBadSnapshot        = errors.New("selinux: malformed snapshot")
)

// Default SELinux user and role applied when a ContextSpec leaves them empty.
const (
	DefaultUser = "system_u"
	DefaultRole = "object_r"
)

// Config bounds the staging area and the size of one atomic apply.
type Config struct {
	// MaxPending caps the number of distinct staged boolean changes.
	MaxPending int
	// MaxChanges caps booleans plus contexts touched by one Apply.
	MaxChanges int
}

// BoolState is the policy view of one boolean.
type BoolState struct {
	Name       string
	Value      bool
	Persistent bool
	// Revision counts how many times this boolean was applied.
	Revision int
}

// BoolChange is one staged boolean flip.
type BoolChange struct {
	Name       string
	Value      bool
	Persistent bool
}

// ContextSpec is the SELinux label wanted for a path. Empty User and Role are
// filled with DefaultUser and DefaultRole.
type ContextSpec struct {
	Path string
	User string
	Role string
	Type string
}

// Report describes what one successful Apply committed.
type Report struct {
	Bools    []BoolChange
	Contexts []ContextSpec
	Removed  []string
	Revision int
}

// Stats is a point-in-time accounting of the guard.
type Stats struct {
	Registered      int
	PendingBools    int
	PendingContexts int
	Contexts        int
	Revision        int
}

// SelinuxGuard stages and atomically applies SELinux policy changes.
type SelinuxGuard struct {
	cfg Config
}

// NewSelinuxGuard returns an empty guard configured by cfg.
func NewSelinuxGuard(cfg Config) *SelinuxGuard {
	return &SelinuxGuard{cfg: cfg}
}

// NewSelinuxGuardFromSnapshot restores registered booleans, applied labels and
// revisions from a snapshot produced by Snapshot.
func NewSelinuxGuardFromSnapshot(cfg Config, data []byte) (*SelinuxGuard, error) {
	return nil, errNotImplemented
}

// RegisterBool declares a boolean known to the local policy with its boot
// default. Registering the same name twice is an error.
func (g *SelinuxGuard) RegisterBool(name string, def bool) error {
	return errNotImplemented
}

// SetBool stages a flip. Setting a boolean to the value and persistence it
// already has is a no-op and stages nothing.
func (g *SelinuxGuard) SetBool(name string, want, persistent bool) error {
	return errNotImplemented
}

// Bool returns the applied state of one boolean.
func (g *SelinuxGuard) Bool(name string) (BoolState, error) {
	return BoolState{}, errNotImplemented
}

// Pending returns the staged boolean names in ascending order.
func (g *SelinuxGuard) Pending() []string {
	return nil
}

// Discard drops every staged change and reports how many were dropped.
func (g *SelinuxGuard) Discard() int {
	return 0
}

// AddContext stages a label for an absolute, clean path.
func (g *SelinuxGuard) AddContext(spec ContextSpec) error {
	return errNotImplemented
}

// RemoveContext stages the removal of the label of an applied path.
func (g *SelinuxGuard) RemoveContext(path string) error {
	return errNotImplemented
}

// ContextAt returns the applied label of path.
func (g *SelinuxGuard) ContextAt(path string) (ContextSpec, error) {
	return ContextSpec{}, errNotImplemented
}

// Apply commits every staged change in one step. On any error nothing is
// applied and the staging area is left untouched.
func (g *SelinuxGuard) Apply() (Report, error) {
	return Report{}, errNotImplemented
}

// Revision returns how many Apply calls have succeeded.
func (g *SelinuxGuard) Revision() int {
	return 0
}

// Snapshot serialises persistent booleans, labels and revisions.
func (g *SelinuxGuard) Snapshot() ([]byte, error) {
	return nil, errNotImplemented
}

// Stats reports current counters.
func (g *SelinuxGuard) Stats() Stats {
	return Stats{}
}
