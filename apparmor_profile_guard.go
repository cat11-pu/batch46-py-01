package task

import "errors"

var errNotImplemented = errors.New("not implemented")

// Sentinel errors returned by AppArmorGuard. Callers branch on them, so every
// rejection has to map onto exactly one of these values.
var (
	ErrInvalidName     = errors.New("apparmor: invalid profile name")
	ErrInvalidMode     = errors.New("apparmor: invalid profile mode")
	ErrInvalidRule     = errors.New("apparmor: invalid rule")
	ErrDuplicateRule   = errors.New("apparmor: duplicate rule in profile")
	ErrTooManyRules    = errors.New("apparmor: too many rules")
	ErrCapReached      = errors.New("apparmor: profile capacity reached")
	ErrStagedExists    = errors.New("apparmor: profile already staged")
	ErrNotStaged       = errors.New("apparmor: no staged profile")
	ErrVersionConflict = errors.New("apparmor: version does not advance")
	ErrProfileNotFound = errors.New("apparmor: profile not found")
	ErrNoHistory       = errors.New("apparmor: no previous version")
	ErrAlreadyAttached = errors.New("apparmor: process already attached")
	ErrNotAttached     = errors.New("apparmor: process not attached")
	ErrAttachCap       = errors.New("apparmor: attachment capacity reached")
	ErrBadSnapshot     = errors.New("apparmor: malformed snapshot")
)

// Mode is an AppArmor enforcement mode.
type Mode string

const (
	ModeEnforce  Mode = "enforce"
	ModeComplain Mode = "complain"
)

// Config bounds the memory and attachment fan-out of the guard.
type Config struct {
	// MaxProfiles caps the number of distinct profiles (staged and active).
	MaxProfiles int
	// MaxRulesPerProfile caps len(Profile.Rules).
	MaxRulesPerProfile int
	// MaxAttachments caps the processes attached to one active profile.
	MaxAttachments int
	// MaxHistory caps how many superseded versions are kept per profile.
	MaxHistory int
}

// Profile is one rendered AppArmor profile.
type Profile struct {
	Tenant string
	// Name must be prefixed with Tenant + ".".
	Name    string
	Version int
	Mode    Mode
	Rules   []string
	// Generation counts successful swaps and rollbacks; it is monotonic and
	// survives a snapshot restore.
	Generation int
}

// Stats is a point-in-time accounting of the guard.
type Stats struct {
	Active   int
	Staged   int
	History  int
	Attached int
}

// AppArmorGuard stages and hot-swaps profiles for a set of tenants.
type AppArmorGuard struct {
	cfg Config
}

// NewAppArmorGuard returns an empty guard configured by cfg.
func NewAppArmorGuard(cfg Config) *AppArmorGuard {
	return &AppArmorGuard{cfg: cfg}
}

// NewAppArmorGuardFromSnapshot restores active profiles, staged profiles,
// history and attachments from a snapshot produced by Snapshot.
func NewAppArmorGuardFromSnapshot(cfg Config, data []byte) (*AppArmorGuard, error) {
	return nil, errNotImplemented
}

// Stage validates p and parks it for a later Commit. One staged profile per
// (tenant, name) may exist at a time.
func (g *AppArmorGuard) Stage(p Profile) error {
	return errNotImplemented
}

// Unstage discards the staged profile for (tenant, name).
func (g *AppArmorGuard) Unstage(tenant, name string) error {
	return errNotImplemented
}

// Commit promotes the staged profile to active, pushing the previous active
// version into history and dropping all its attachments. Exactly one caller
// wins when the same staged profile is committed concurrently.
func (g *AppArmorGuard) Commit(tenant, name string) (Profile, error) {
	return Profile{}, errNotImplemented
}

// Rollback restores the most recent superseded version and drops attachments.
func (g *AppArmorGuard) Rollback(tenant, name string) (Profile, error) {
	return Profile{}, errNotImplemented
}

// Active returns the active profile for (tenant, name).
func (g *AppArmorGuard) Active(tenant, name string) (Profile, error) {
	return Profile{}, errNotImplemented
}

// Attach binds pid to the active profile of (tenant, name).
func (g *AppArmorGuard) Attach(tenant, name string, pid int) error {
	return errNotImplemented
}

// Detach releases pid from the active profile of (tenant, name).
func (g *AppArmorGuard) Detach(tenant, name string, pid int) error {
	return errNotImplemented
}

// Attachments returns the attached pids in ascending order.
func (g *AppArmorGuard) Attachments(tenant, name string) ([]int, error) {
	return nil, errNotImplemented
}

// SetMode switches an active profile between enforce and complain.
func (g *AppArmorGuard) SetMode(tenant, name string, mode Mode) error {
	return errNotImplemented
}

// History returns the superseded version numbers, oldest first, bounded by
// Config.MaxHistory.
func (g *AppArmorGuard) History(tenant, name string) ([]int, error) {
	return nil, errNotImplemented
}

// Snapshot serialises the whole guard so a restarted agent keeps its staged,
// active, historical and attached state.
func (g *AppArmorGuard) Snapshot() ([]byte, error) {
	return nil, errNotImplemented
}

// Stats reports current counters.
func (g *AppArmorGuard) Stats() Stats {
	return Stats{}
}
