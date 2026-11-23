package task

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
)

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

// ErrBusy is returned when a mode change would affect live processes. It also
// matches ErrAlreadyAttached for callers that only know the attachment sentinel.
var ErrBusy = fmt.Errorf("apparmor: profile busy: %w", ErrAlreadyAttached)

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

type profileKey struct {
	tenant string
	name   string
}

type attachment struct {
	tenant string
	name   string
}

// AppArmorGuard stages and hot-swaps profiles for a set of tenants.
//
// Every table is guarded by mu. Exported methods never call one another while
// holding the lock; they all use the *Locked helpers instead.
type AppArmorGuard struct {
	cfg Config

	mu          sync.RWMutex
	active      map[profileKey]Profile
	staged      map[profileKey]Profile
	history     map[profileKey][]Profile
	attachments map[int]attachment
}

// NewAppArmorGuard returns an empty guard configured by cfg.
func NewAppArmorGuard(cfg Config) *AppArmorGuard {
	cfg = normalizeConfig(cfg)
	return &AppArmorGuard{
		cfg:         cfg,
		active:      make(map[profileKey]Profile),
		staged:      make(map[profileKey]Profile),
		history:     make(map[profileKey][]Profile),
		attachments: make(map[int]attachment),
	}
}

func normalizeConfig(cfg Config) Config {
	if cfg.MaxProfiles < 0 {
		cfg.MaxProfiles = 0
	}
	if cfg.MaxRulesPerProfile < 0 {
		cfg.MaxRulesPerProfile = 0
	}
	if cfg.MaxAttachments < 0 {
		cfg.MaxAttachments = 0
	}
	if cfg.MaxHistory < 0 {
		cfg.MaxHistory = 0
	}
	return cfg
}

func keyOf(p Profile) profileKey {
	return profileKey{tenant: p.Tenant, name: p.Name}
}

func cloneProfile(p Profile) Profile {
	p.Rules = append([]string(nil), p.Rules...)
	return p
}

func (g *AppArmorGuard) validateProfile(p Profile) error {
	if p.Tenant == "" {
		return ErrInvalidName
	}
	prefix := p.Tenant + "."
	if !strings.HasPrefix(p.Name, prefix) || len(p.Name) == len(prefix) {
		return ErrInvalidName
	}
	if p.Mode != ModeEnforce && p.Mode != ModeComplain {
		return ErrInvalidMode
	}
	if len(p.Rules) > g.cfg.MaxRulesPerProfile {
		return ErrTooManyRules
	}
	seen := make(map[string]struct{}, len(p.Rules))
	for _, rule := range p.Rules {
		if rule == "" {
			return ErrInvalidRule
		}
		if _, ok := seen[rule]; ok {
			return ErrDuplicateRule
		}
		seen[rule] = struct{}{}
	}
	return nil
}

func (g *AppArmorGuard) profileCountLocked() int {
	seen := make(map[profileKey]struct{}, len(g.active)+len(g.staged))
	for key := range g.active {
		seen[key] = struct{}{}
	}
	for key := range g.staged {
		seen[key] = struct{}{}
	}
	return len(seen)
}

func (g *AppArmorGuard) attachmentCountLocked(key profileKey) int {
	count := 0
	for _, bound := range g.attachments {
		if bound.tenant == key.tenant && bound.name == key.name {
			count++
		}
	}
	return count
}

func (g *AppArmorGuard) clearAttachmentsLocked(key profileKey) {
	for pid, bound := range g.attachments {
		if bound.tenant == key.tenant && bound.name == key.name {
			delete(g.attachments, pid)
		}
	}
}

func (g *AppArmorGuard) trimHistoryLocked(key profileKey) {
	if g.cfg.MaxHistory == 0 {
		delete(g.history, key)
		return
	}
	entries := g.history[key]
	if len(entries) > g.cfg.MaxHistory {
		entries = append([]Profile(nil), entries[len(entries)-g.cfg.MaxHistory:]...)
		g.history[key] = entries
	}
}

// Stage validates p and parks it for a later Commit. One staged profile per
// (tenant, name) may exist at a time.
func (g *AppArmorGuard) Stage(p Profile) error {
	if err := g.validateProfile(p); err != nil {
		return err
	}
	key := keyOf(p)

	g.mu.Lock()
	defer g.mu.Unlock()

	if _, ok := g.staged[key]; ok {
		return ErrStagedExists
	}
	if _, ok := g.active[key]; !ok && g.profileCountLocked() >= g.cfg.MaxProfiles {
		return ErrCapReached
	}
	g.staged[key] = cloneProfile(p)
	return nil
}

// Unstage discards the staged profile for (tenant, name).
func (g *AppArmorGuard) Unstage(tenant, name string) error {
	key := profileKey{tenant: tenant, name: name}

	g.mu.Lock()
	defer g.mu.Unlock()

	if _, ok := g.staged[key]; !ok {
		return ErrNotStaged
	}
	delete(g.staged, key)
	return nil
}

// Commit promotes the staged profile to active, pushing the previous active
// version into history and dropping all its attachments. Exactly one caller
// wins when the same staged profile is committed concurrently.
func (g *AppArmorGuard) Commit(tenant, name string) (Profile, error) {
	key := profileKey{tenant: tenant, name: name}

	g.mu.Lock()
	defer g.mu.Unlock()

	staged, ok := g.staged[key]
	if !ok {
		return Profile{}, ErrNotStaged
	}

	active, hasActive := g.active[key]
	if staged.Version <= 0 || (hasActive && staged.Version <= active.Version) {
		// The staged profile can never be committed. Discard it so a corrected
		// version can be staged without an intervening manual cleanup.
		delete(g.staged, key)
		return Profile{}, ErrVersionConflict
	}

	generation := 1
	if hasActive {
		generation = active.Generation + 1
		entries := append(g.history[key], cloneProfile(active))
		g.history[key] = entries
		g.trimHistoryLocked(key)
	}

	promoted := cloneProfile(staged)
	promoted.Tenant = key.tenant
	promoted.Name = key.name
	promoted.Generation = generation

	delete(g.staged, key)
	g.active[key] = promoted
	g.clearAttachmentsLocked(key)
	return cloneProfile(promoted), nil
}

// Rollback restores the most recent superseded version and drops attachments.
func (g *AppArmorGuard) Rollback(tenant, name string) (Profile, error) {
	key := profileKey{tenant: tenant, name: name}

	g.mu.Lock()
	defer g.mu.Unlock()

	active, ok := g.active[key]
	if !ok {
		return Profile{}, ErrProfileNotFound
	}
	entries := g.history[key]
	if len(entries) == 0 {
		return Profile{}, ErrNoHistory
	}

	target := entries[len(entries)-1]
	entries = append([]Profile(nil), entries[:len(entries)-1]...)
	if len(entries) == 0 {
		delete(g.history, key)
	} else {
		g.history[key] = entries
	}

	restored := cloneProfile(target)
	restored.Tenant = key.tenant
	restored.Name = key.name
	restored.Generation = active.Generation + 1
	g.active[key] = restored
	g.clearAttachmentsLocked(key)
	return cloneProfile(restored), nil
}

// Active returns the active profile for (tenant, name).
func (g *AppArmorGuard) Active(tenant, name string) (Profile, error) {
	key := profileKey{tenant: tenant, name: name}

	g.mu.RLock()
	defer g.mu.RUnlock()

	p, ok := g.active[key]
	if !ok {
		return Profile{}, ErrProfileNotFound
	}
	return cloneProfile(p), nil
}

// Attach binds pid to the active profile of (tenant, name).
func (g *AppArmorGuard) Attach(tenant, name string, pid int) error {
	key := profileKey{tenant: tenant, name: name}

	g.mu.Lock()
	defer g.mu.Unlock()

	if _, ok := g.active[key]; !ok {
		return ErrProfileNotFound
	}
	if _, ok := g.attachments[pid]; ok {
		return ErrAlreadyAttached
	}
	if g.attachmentCountLocked(key) >= g.cfg.MaxAttachments {
		return ErrAttachCap
	}
	g.attachments[pid] = attachment{tenant: tenant, name: name}
	return nil
}

// Detach releases pid from the active profile of (tenant, name).
func (g *AppArmorGuard) Detach(tenant, name string, pid int) error {
	key := profileKey{tenant: tenant, name: name}

	g.mu.Lock()
	defer g.mu.Unlock()

	if _, ok := g.active[key]; !ok {
		return ErrProfileNotFound
	}
	bound, ok := g.attachments[pid]
	if !ok || bound.tenant != key.tenant || bound.name != key.name {
		return ErrNotAttached
	}
	delete(g.attachments, pid)
	return nil
}

// Attachments returns the attached pids in ascending order.
func (g *AppArmorGuard) Attachments(tenant, name string) ([]int, error) {
	key := profileKey{tenant: tenant, name: name}

	g.mu.RLock()
	defer g.mu.RUnlock()

	if _, ok := g.active[key]; !ok {
		return nil, ErrProfileNotFound
	}
	pids := make([]int, 0)
	for pid, bound := range g.attachments {
		if bound.tenant == key.tenant && bound.name == key.name {
			pids = append(pids, pid)
		}
	}
	sort.Ints(pids)
	return pids, nil
}

// SetMode switches an active profile between enforce and complain.
func (g *AppArmorGuard) SetMode(tenant, name string, mode Mode) error {
	if mode != ModeEnforce && mode != ModeComplain {
		return ErrInvalidMode
	}
	key := profileKey{tenant: tenant, name: name}

	g.mu.Lock()
	defer g.mu.Unlock()

	active, ok := g.active[key]
	if !ok {
		return ErrProfileNotFound
	}
	if active.Mode == mode {
		return nil
	}
	if mode == ModeComplain && g.attachmentCountLocked(key) > 0 {
		return ErrBusy
	}
	active.Mode = mode
	active.Generation++
	g.active[key] = active
	return nil
}

// History returns the superseded version numbers, oldest first, bounded by
// Config.MaxHistory.
func (g *AppArmorGuard) History(tenant, name string) ([]int, error) {
	key := profileKey{tenant: tenant, name: name}

	g.mu.RLock()
	defer g.mu.RUnlock()

	if _, ok := g.active[key]; !ok {
		return nil, ErrProfileNotFound
	}
	entries := g.history[key]
	versions := make([]int, 0, len(entries))
	for _, entry := range entries {
		versions = append(versions, entry.Version)
	}
	return versions, nil
}

const snapshotSchema = 1

type snapshotHistory struct {
	Tenant   string    `json:"tenant"`
	Name     string    `json:"name"`
	Profiles []Profile `json:"profiles"`
}

type snapshotAttachment struct {
	Tenant string `json:"tenant"`
	Name   string `json:"name"`
	PID    int    `json:"pid"`
}

type snapshotDoc struct {
	Schema      int                  `json:"schema"`
	Active      []Profile            `json:"active"`
	Staged      []Profile            `json:"staged"`
	History     []snapshotHistory    `json:"history"`
	Attachments []snapshotAttachment `json:"attachments"`
}

func sortedProfileKeys(active map[profileKey]Profile, staged map[profileKey]Profile) []profileKey {
	seen := make(map[profileKey]struct{}, len(active)+len(staged))
	for key := range active {
		seen[key] = struct{}{}
	}
	for key := range staged {
		seen[key] = struct{}{}
	}
	keys := make([]profileKey, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].tenant != keys[j].tenant {
			return keys[i].tenant < keys[j].tenant
		}
		return keys[i].name < keys[j].name
	})
	return keys
}

func (g *AppArmorGuard) snapshotLocked() snapshotDoc {
	doc := snapshotDoc{Schema: snapshotSchema}
	keys := sortedProfileKeys(g.active, g.staged)
	for _, key := range keys {
		if p, ok := g.active[key]; ok {
			doc.Active = append(doc.Active, cloneProfile(p))
		}
		if p, ok := g.staged[key]; ok {
			doc.Staged = append(doc.Staged, cloneProfile(p))
		}
	}

	historyKeys := make([]profileKey, 0, len(g.history))
	for key := range g.history {
		historyKeys = append(historyKeys, key)
	}
	sort.Slice(historyKeys, func(i, j int) bool {
		if historyKeys[i].tenant != historyKeys[j].tenant {
			return historyKeys[i].tenant < historyKeys[j].tenant
		}
		return historyKeys[i].name < historyKeys[j].name
	})
	for _, key := range historyKeys {
		entry := snapshotHistory{Tenant: key.tenant, Name: key.name}
		for _, p := range g.history[key] {
			entry.Profiles = append(entry.Profiles, cloneProfile(p))
		}
		doc.History = append(doc.History, entry)
	}

	pids := make([]int, 0, len(g.attachments))
	for pid := range g.attachments {
		pids = append(pids, pid)
	}
	sort.Ints(pids)
	for _, pid := range pids {
		bound := g.attachments[pid]
		doc.Attachments = append(doc.Attachments, snapshotAttachment{
			Tenant: bound.tenant,
			Name:   bound.name,
			PID:    pid,
		})
	}
	return doc
}

// Snapshot serialises the whole guard so a restarted agent keeps its staged,
// active, historical and attached state.
func (g *AppArmorGuard) Snapshot() ([]byte, error) {
	g.mu.RLock()
	doc := g.snapshotLocked()
	g.mu.RUnlock()
	return json.Marshal(doc)
}

// NewAppArmorGuardFromSnapshot restores active profiles, staged profiles,
// history and attachments from a snapshot produced by Snapshot.
func NewAppArmorGuardFromSnapshot(cfg Config, data []byte) (*AppArmorGuard, error) {
	var doc snapshotDoc
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&doc); err != nil {
		return nil, ErrBadSnapshot
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, ErrBadSnapshot
	}
	if doc.Schema != snapshotSchema {
		return nil, ErrBadSnapshot
	}

	g := NewAppArmorGuard(cfg)
	bad := func() (*AppArmorGuard, error) {
		return nil, ErrBadSnapshot
	}

	for _, p := range doc.Active {
		if err := g.validateProfile(p); err != nil || p.Generation <= 0 {
			return bad()
		}
		key := keyOf(p)
		if _, ok := g.active[key]; ok {
			return bad()
		}
		g.active[key] = cloneProfile(p)
	}
	for _, p := range doc.Staged {
		if err := g.validateProfile(p); err != nil {
			return bad()
		}
		key := keyOf(p)
		if _, ok := g.staged[key]; ok {
			return bad()
		}
		g.staged[key] = cloneProfile(p)
	}
	if g.profileCountLocked() > g.cfg.MaxProfiles {
		return bad()
	}

	seenHistory := make(map[profileKey]struct{}, len(doc.History))
	for _, entry := range doc.History {
		key := profileKey{tenant: entry.Tenant, name: entry.Name}
		if _, ok := g.active[key]; !ok {
			return bad()
		}
		if _, ok := seenHistory[key]; ok {
			return bad()
		}
		seenHistory[key] = struct{}{}
		if len(entry.Profiles) > g.cfg.MaxHistory {
			return bad()
		}
		lastVersion := 0
		profiles := make([]Profile, 0, len(entry.Profiles))
		for _, p := range entry.Profiles {
			if err := g.validateProfile(p); err != nil {
				return bad()
			}
			if p.Tenant != entry.Tenant || p.Name != entry.Name {
				return bad()
			}
			if p.Version <= lastVersion || p.Version >= g.active[key].Version {
				return bad()
			}
			lastVersion = p.Version
			profiles = append(profiles, cloneProfile(p))
		}
		if len(profiles) != 0 {
			g.history[key] = profiles
		}
	}

	attachmentCounts := make(map[profileKey]int, len(g.active))
	for _, entry := range doc.Attachments {
		key := profileKey{tenant: entry.Tenant, name: entry.Name}
		if _, ok := g.active[key]; !ok {
			return bad()
		}
		if _, ok := g.attachments[entry.PID]; ok {
			return bad()
		}
		if attachmentCounts[key] >= g.cfg.MaxAttachments {
			return bad()
		}
		attachmentCounts[key]++
		g.attachments[entry.PID] = attachment{tenant: entry.Tenant, name: entry.Name}
	}

	return g, nil
}

// Restore atomically replaces the guard's state with a validated snapshot.
// Invalid snapshots leave every table unchanged.
func (g *AppArmorGuard) Restore(data []byte) error {
	restored, err := NewAppArmorGuardFromSnapshot(g.cfg, data)
	if err != nil {
		return err
	}

	g.mu.Lock()
	g.active = restored.active
	g.staged = restored.staged
	g.history = restored.history
	g.attachments = restored.attachments
	g.mu.Unlock()
	return nil
}

// Stats reports current counters.
func (g *AppArmorGuard) Stats() Stats {
	g.mu.RLock()
	defer g.mu.RUnlock()

	stats := Stats{
		Active:   len(g.active),
		Staged:   len(g.staged),
		Attached: len(g.attachments),
	}
	for _, entries := range g.history {
		stats.History += len(entries)
	}
	return stats
}
