package task

import (
	"bytes"
	"encoding/json"
	"errors"
	"path"
	"sort"
	"strings"
	"sync"
)

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

type boolEntry struct {
	name       string
	defaultVal bool
	value      bool
	persistent bool
	revision   int
}

// SelinuxGuard stages and atomically applies SELinux policy changes.
type SelinuxGuard struct {
	mu sync.Mutex

	cfg Config

	bools   map[string]*boolEntry
	pending map[string]BoolChange

	stagedContexts map[string]ContextSpec
	applied        map[string]ContextSpec
	removed        map[string]struct{}

	revision int
}

// NewSelinuxGuard returns an empty guard configured by cfg.
func NewSelinuxGuard(cfg Config) *SelinuxGuard {
	return &SelinuxGuard{
		cfg:            cfg,
		bools:          make(map[string]*boolEntry),
		pending:        make(map[string]BoolChange),
		stagedContexts: make(map[string]ContextSpec),
		applied:        make(map[string]ContextSpec),
		removed:        make(map[string]struct{}),
	}
}

type snapshotBool struct {
	Name       string `json:"name"`
	Default    bool   `json:"default"`
	Value      bool   `json:"value"`
	Persistent bool   `json:"persistent"`
	Revision   int    `json:"revision"`
}

type snapshotData struct {
	Version  int            `json:"version"`
	Revision int            `json:"revision"`
	Bools    []snapshotBool `json:"bools"`
	Contexts []ContextSpec  `json:"contexts"`
}

// NewSelinuxGuardFromSnapshot restores registered booleans, applied labels and
// revisions from a snapshot produced by Snapshot.
func NewSelinuxGuardFromSnapshot(cfg Config, data []byte) (*SelinuxGuard, error) {
	var snap snapshotData
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&snap); err != nil {
		return nil, ErrBadSnapshot
	}
	if snap.Version != 1 || snap.Revision < 0 {
		return nil, ErrBadSnapshot
	}

	g := NewSelinuxGuard(cfg)
	g.revision = snap.Revision
	for _, b := range snap.Bools {
		if b.Name == "" || b.Revision < 0 {
			return nil, ErrBadSnapshot
		}
		if _, exists := g.bools[b.Name]; exists {
			return nil, ErrBadSnapshot
		}
		entry := &boolEntry{
			name:       b.Name,
			defaultVal: b.Default,
			value:      b.Default,
			persistent: b.Persistent,
			revision:   b.Revision,
		}
		if b.Persistent {
			entry.value = b.Value
		}
		g.bools[b.Name] = entry
	}
	for _, c := range snap.Contexts {
		if err := validateContext(c); err != nil {
			return nil, ErrBadSnapshot
		}
		c = normalizeContext(c)
		if _, exists := g.applied[c.Path]; exists {
			return nil, ErrBadSnapshot
		}
		g.applied[c.Path] = c
	}
	return g, nil
}

// RegisterBool declares a boolean known to the local policy with its boot
// default. Registering the same name twice is an error.
func (g *SelinuxGuard) RegisterBool(name string, def bool) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if name == "" {
		return ErrInvalidBoolName
	}
	if _, exists := g.bools[name]; exists {
		return ErrBoolExists
	}
	g.bools[name] = &boolEntry{
		name:       name,
		defaultVal: def,
		value:      def,
	}
	return nil
}

// SetBool stages a flip. Setting a boolean to the value and persistence it
// already has is a no-op and stages nothing.
func (g *SelinuxGuard) SetBool(name string, want, persistent bool) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	entry, ok := g.bools[name]
	if !ok {
		return ErrUnknownBool
	}
	staged, hasStaged := g.pending[name]
	if !hasStaged && want == entry.value && persistent == entry.persistent {
		return nil
	}
	if !hasStaged && limitReached(len(g.pending), g.cfg.MaxPending) {
		return ErrCapReached
	}
	if hasStaged && staged.Value == want && staged.Persistent == persistent {
		return nil
	}
	g.pending[name] = BoolChange{Name: name, Value: want, Persistent: persistent}
	return nil
}

// Bool returns the applied state of one boolean.
func (g *SelinuxGuard) Bool(name string) (BoolState, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	entry, ok := g.bools[name]
	if !ok {
		return BoolState{}, ErrUnknownBool
	}
	return BoolState{
		Name:       entry.name,
		Value:      entry.value,
		Persistent: entry.persistent,
		Revision:   entry.revision,
	}, nil
}

// Pending returns the staged boolean names in ascending order.
func (g *SelinuxGuard) Pending() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	names := make([]string, 0, len(g.pending))
	for name := range g.pending {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Discard drops every staged change and reports how many were dropped.
func (g *SelinuxGuard) Discard() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	n := len(g.pending) + len(g.stagedContexts) + len(g.removed)
	g.pending = make(map[string]BoolChange)
	g.stagedContexts = make(map[string]ContextSpec)
	g.removed = make(map[string]struct{})
	return n
}

// AddContext stages a label for an absolute, clean path.
func (g *SelinuxGuard) AddContext(spec ContextSpec) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if err := validateContext(spec); err != nil {
		return err
	}
	spec = normalizeContext(spec)
	if existing, ok := g.stagedContexts[spec.Path]; ok {
		if existing == spec {
			return ErrDuplicateContext
		}
		return ErrConflict
	}
	delete(g.removed, spec.Path)
	g.stagedContexts[spec.Path] = spec
	return nil
}

// RemoveContext stages the removal of the label of an applied path.
func (g *SelinuxGuard) RemoveContext(path string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, exists := g.applied[path]; !exists {
		return ErrNotFound
	}
	if _, exists := g.removed[path]; exists {
		return ErrNotFound
	}
	delete(g.stagedContexts, path)
	g.removed[path] = struct{}{}
	return nil
}

// ContextAt returns the applied label of path.
func (g *SelinuxGuard) ContextAt(path string) (ContextSpec, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	spec, ok := g.applied[path]
	if !ok {
		return ContextSpec{}, ErrNotFound
	}
	return spec, nil
}

// Apply commits every staged change in one step. On any error nothing is
// applied and the staging area is left untouched.
func (g *SelinuxGuard) Apply() (Report, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	total := len(g.pending) + len(g.stagedContexts) + len(g.removed)
	if total == 0 {
		return Report{}, ErrNothingToApply
	}
	if limitReached(total, g.cfg.MaxChanges) {
		return Report{}, ErrTooManyChanges
	}

	names := make([]string, 0, len(g.pending))
	for name := range g.pending {
		names = append(names, name)
	}
	sort.Strings(names)

	contextPaths := make([]string, 0, len(g.stagedContexts))
	for p := range g.stagedContexts {
		contextPaths = append(contextPaths, p)
	}
	sort.Strings(contextPaths)

	removedPaths := make([]string, 0, len(g.removed))
	for p := range g.removed {
		removedPaths = append(removedPaths, p)
	}
	sort.Strings(removedPaths)

	report := Report{
		Bools:    make([]BoolChange, 0, len(names)),
		Contexts: make([]ContextSpec, 0, len(contextPaths)),
		Removed:  append([]string(nil), removedPaths...),
	}

	g.revision++
	for _, name := range names {
		change := g.pending[name]
		entry := g.bools[name]
		entry.value = change.Value
		entry.persistent = change.Persistent
		entry.revision++
		report.Bools = append(report.Bools, change)
	}
	for _, p := range contextPaths {
		spec := g.stagedContexts[p]
		g.applied[p] = spec
		report.Contexts = append(report.Contexts, spec)
	}
	for _, p := range removedPaths {
		delete(g.applied, p)
	}
	report.Revision = g.revision

	g.pending = make(map[string]BoolChange)
	g.stagedContexts = make(map[string]ContextSpec)
	g.removed = make(map[string]struct{})
	return report, nil
}

// Revision returns how many Apply calls have succeeded.
func (g *SelinuxGuard) Revision() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.revision
}

// Snapshot serialises persistent booleans, labels and revisions.
func (g *SelinuxGuard) Snapshot() ([]byte, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	snap := snapshotData{
		Version:  1,
		Revision: g.revision,
		Bools:    make([]snapshotBool, 0, len(g.bools)),
		Contexts: make([]ContextSpec, 0, len(g.applied)),
	}
	names := make([]string, 0, len(g.bools))
	for name := range g.bools {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		entry := g.bools[name]
		item := snapshotBool{
			Name:       entry.name,
			Default:    entry.defaultVal,
			Value:      entry.defaultVal,
			Persistent: entry.persistent,
			Revision:   entry.revision,
		}
		if entry.persistent {
			item.Value = entry.value
		}
		snap.Bools = append(snap.Bools, item)
	}
	paths := make([]string, 0, len(g.applied))
	for p := range g.applied {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		snap.Contexts = append(snap.Contexts, g.applied[p])
	}
	data, err := json.Marshal(snap)
	if err != nil {
		return nil, ErrBadSnapshot
	}
	return data, nil
}

// Stats reports current counters.
func (g *SelinuxGuard) Stats() Stats {
	g.mu.Lock()
	defer g.mu.Unlock()
	return Stats{
		Registered:      len(g.bools),
		PendingBools:    len(g.pending),
		PendingContexts: len(g.stagedContexts) + len(g.removed),
		Contexts:        len(g.applied),
		Revision:        g.revision,
	}
}

func validateContext(spec ContextSpec) error {
	if spec.Path == "" || !strings.HasPrefix(spec.Path, "/") || path.Clean(spec.Path) != spec.Path {
		return ErrInvalidPath
	}
	if spec.Type == "" || !strings.HasSuffix(spec.Type, "_t") {
		return ErrInvalidContextType
	}
	return nil
}

func normalizeContext(spec ContextSpec) ContextSpec {
	if spec.User == "" {
		spec.User = DefaultUser
	}
	if spec.Role == "" {
		spec.Role = DefaultRole
	}
	return spec
}

func limitReached(n, max int) bool {
	return max > 0 && n >= max
}
