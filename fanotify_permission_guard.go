package task

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

var errNotImplemented = errors.New("not implemented")

// Sentinel errors returned by FanotifyGuard.
var (
	ErrInvalidPath     = errors.New("fanotify: invalid path")
	ErrInvalidMask     = errors.New("fanotify: mask has no permission bit")
	ErrAlreadyMarked   = errors.New("fanotify: path already marked")
	ErrCapReached      = errors.New("fanotify: mark capacity reached")
	ErrUnknownMark     = errors.New("fanotify: unknown mark")
	ErrNoMark          = errors.New("fanotify: no matching mark")
	ErrQueueFull       = errors.New("fanotify: pending event queue full")
	ErrUnknownEvent    = errors.New("fanotify: unknown permission event")
	ErrAlreadyAnswered = errors.New("fanotify: event already answered")
	ErrExpired         = errors.New("fanotify: permission event expired")
	ErrInvalidDecision = errors.New("fanotify: invalid decision")
	ErrBusy            = errors.New("fanotify: mark still has pending events")
	ErrBadSnapshot     = errors.New("fanotify: malformed snapshot")
)

// Mask selects which permission events a mark subscribes to.
type Mask uint32

const (
	MaskOpenPerm Mask = 1 << iota
	MaskAccessPerm

	validMasks = MaskOpenPerm | MaskAccessPerm
)

// Op is the operation the kernel is blocking on.
type Op string

const (
	OpOpen   Op = "open"
	OpAccess Op = "access"
)

// Decision is the verdict userspace writes back to the kernel.
type Decision string

const (
	DecisionAllow Decision = "allow"
	DecisionDeny  Decision = "deny"
)

// EventID identifies one pending permission event.
type EventID uint64

// Config holds the responder policy.
type Config struct {
	// ResponseTimeout is how long the kernel waits before the event is denied.
	ResponseTimeout time.Duration
	// MaxMarks caps the number of marks the guard accepts.
	MaxMarks int
	// MaxPending caps the permission events blocked at any one time.
	MaxPending int
}

// Mark is one fanotify mark.
type Mark struct {
	ID   int
	Path string
	Mask Mask
}

// Event is one permission event waiting for a verdict.
type Event struct {
	ID       EventID
	Path     string
	Op       Op
	Deadline time.Time
}

// Stats is a point-in-time accounting of the guard.
type Stats struct {
	Marks   int
	Pending int
	Allowed int
	Denied  int
	Expired int
}

type eventState uint8

const (
	eventPending eventState = iota
	eventAllowed
	eventDenied
	eventExpired
)

type eventRecord struct {
	id       EventID
	path     string
	op       Op
	deadline time.Time
	markID   int
	seq      uint64
	state    eventState
	decision Decision
}

// FanotifyGuard tracks marks and permission events for one responder.
type FanotifyGuard struct {
	mu sync.Mutex

	cfg Config

	marks      map[int]*Mark
	markByPath map[string]int
	nextMarkID int

	pending     map[EventID]*eventRecord
	decisions   map[EventID]*eventRecord
	nextEventID EventID
	seq         uint64

	allowed int
	denied  int
	expired int
}

// NewFanotifyGuard returns an empty guard configured by cfg.
func NewFanotifyGuard(cfg Config) *FanotifyGuard {
	return &FanotifyGuard{
		cfg:        normalizeConfig(cfg),
		marks:      make(map[int]*Mark),
		markByPath: make(map[string]int),
		pending:    make(map[EventID]*eventRecord),
		decisions:  make(map[EventID]*eventRecord),
	}
}

func normalizeConfig(cfg Config) Config {
	if cfg.ResponseTimeout <= 0 {
		cfg.ResponseTimeout = 5 * time.Second
	}
	if cfg.MaxMarks < 0 {
		cfg.MaxMarks = 0
	}
	if cfg.MaxPending < 0 {
		cfg.MaxPending = 0
	}
	return cfg
}

func validPath(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path
}

func validMask(mask Mask) bool {
	return mask != 0 && mask&^validMasks == 0
}

func maskForOp(op Op) (Mask, bool) {
	switch op {
	case OpOpen:
		return MaskOpenPerm, true
	case OpAccess:
		return MaskAccessPerm, true
	default:
		return 0, false
	}
}

func pathCovers(markPath, path string) bool {
	if markPath == path {
		return true
	}
	if markPath == "/" {
		return strings.HasPrefix(path, "/")
	}
	return strings.HasPrefix(path, markPath+"/")
}

func (g *FanotifyGuard) matchMark(path string) *Mark {
	var best *Mark
	for _, mark := range g.marks {
		if !pathCovers(mark.Path, path) {
			continue
		}
		if best == nil || len(mark.Path) > len(best.Path) {
			best = mark
		}
	}
	return best
}

// NewFanotifyGuardFromSnapshot restores marks, counters and the event id
// counter from a snapshot produced by Snapshot.
func NewFanotifyGuardFromSnapshot(cfg Config, data []byte) (*FanotifyGuard, error) {
	if len(data) == 0 {
		return nil, ErrBadSnapshot
	}

	var snap snapshotData
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, ErrBadSnapshot
	}
	if snap.Version != snapshotVersion {
		return nil, ErrBadSnapshot
	}

	g := NewFanotifyGuard(cfg)
	if snap.Allowed < 0 || snap.Denied < 0 || snap.Expired < 0 {
		return nil, ErrBadSnapshot
	}

	seenIDs := make(map[int]struct{}, len(snap.Marks))
	seenPaths := make(map[string]struct{}, len(snap.Marks))
	maxMarkID := 0
	for _, mark := range snap.Marks {
		if mark.ID <= 0 || !validPath(mark.Path) || !validMask(mark.Mask) {
			return nil, ErrBadSnapshot
		}
		if _, ok := seenIDs[mark.ID]; ok {
			return nil, ErrBadSnapshot
		}
		if _, ok := seenPaths[mark.Path]; ok {
			return nil, ErrBadSnapshot
		}
		seenIDs[mark.ID] = struct{}{}
		seenPaths[mark.Path] = struct{}{}
		if mark.ID > maxMarkID {
			maxMarkID = mark.ID
		}
	}
	if len(snap.Marks) > g.cfg.MaxMarks {
		return nil, ErrBadSnapshot
	}
	if snap.NextMarkID < maxMarkID {
		return nil, ErrBadSnapshot
	}
	if snap.NextEventID == ^EventID(0) {
		return nil, ErrBadSnapshot
	}

	for _, mark := range snap.Marks {
		copy := mark
		g.marks[copy.ID] = &copy
		g.markByPath[copy.Path] = copy.ID
	}
	g.nextMarkID = snap.NextMarkID
	g.nextEventID = snap.NextEventID
	g.seq = snap.Seq
	g.allowed = snap.Allowed
	g.denied = snap.Denied
	g.expired = snap.Expired

	return g, nil
}

// Mark subscribes to permission events for an absolute, clean path.
func (g *FanotifyGuard) Mark(path string, mask Mask) (int, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if !validPath(path) {
		return 0, ErrInvalidPath
	}
	if !validMask(mask) {
		return 0, ErrInvalidMask
	}
	if _, ok := g.markByPath[path]; ok {
		return 0, ErrAlreadyMarked
	}
	if len(g.marks) >= g.cfg.MaxMarks {
		return 0, ErrCapReached
	}

	g.nextMarkID++
	mark := &Mark{ID: g.nextMarkID, Path: path, Mask: mask}
	g.marks[mark.ID] = mark
	g.markByPath[mark.Path] = mark.ID
	return mark.ID, nil
}

// Unmark removes a mark. A mark with blocked events is busy until they are
// answered or swept.
func (g *FanotifyGuard) Unmark(id int) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	mark, ok := g.marks[id]
	if !ok {
		return ErrUnknownMark
	}
	for _, ev := range g.pending {
		if ev.markID == id {
			return ErrBusy
		}
	}
	delete(g.marks, id)
	delete(g.markByPath, mark.Path)
	return nil
}

// Marks returns the marks ordered by path.
func (g *FanotifyGuard) Marks() []Mark {
	g.mu.Lock()
	defer g.mu.Unlock()

	marks := make([]Mark, 0, len(g.marks))
	for _, mark := range g.marks {
		marks = append(marks, *mark)
	}
	sort.Slice(marks, func(i, j int) bool {
		return marks[i].Path < marks[j].Path
	})
	return marks
}

// Begin records a permission event raised by the kernel. The caller is blocked
// until Respond or Sweep resolves it.
func (g *FanotifyGuard) Begin(path string, op Op, now time.Time) (Event, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if !validPath(path) {
		return Event{}, ErrInvalidPath
	}
	mask, ok := maskForOp(op)
	if !ok {
		return Event{}, ErrNoMark
	}
	mark := g.matchMark(path)
	if mark == nil || mark.Mask&mask == 0 {
		return Event{}, ErrNoMark
	}
	if len(g.pending) >= g.cfg.MaxPending {
		return Event{}, ErrQueueFull
	}

	g.nextEventID++
	g.seq++
	record := &eventRecord{
		id:       g.nextEventID,
		path:     path,
		op:       op,
		deadline: now.Add(g.cfg.ResponseTimeout),
		markID:   mark.ID,
		seq:      g.seq,
		state:    eventPending,
	}
	g.pending[record.id] = record

	return Event{
		ID:       record.id,
		Path:     record.path,
		Op:       record.op,
		Deadline: record.deadline,
	}, nil
}

func (g *FanotifyGuard) expireRecord(rec *eventRecord) {
	rec.state = eventExpired
	rec.decision = DecisionDeny
	delete(g.pending, rec.id)
	g.denied++
	g.expired++
}

// Respond writes a verdict back for one event.
func (g *FanotifyGuard) Respond(id EventID, d Decision, now time.Time) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if d != DecisionAllow && d != DecisionDeny {
		return ErrInvalidDecision
	}

	rec, ok := g.pending[id]
	if !ok {
		rec, ok = g.decisions[id]
		if !ok {
			return ErrUnknownEvent
		}
		if rec.state == eventExpired {
			return ErrExpired
		}
		return ErrAlreadyAnswered
	}

	if !now.Before(rec.deadline) {
		g.expireRecord(rec)
		g.decisions[id] = rec
		return ErrExpired
	}

	rec.decision = d
	delete(g.pending, id)
	g.decisions[id] = rec
	if d == DecisionAllow {
		rec.state = eventAllowed
		g.allowed++
	} else {
		rec.state = eventDenied
		g.denied++
	}
	return nil
}

// Sweep denies every event whose deadline has passed and returns how many were
// denied.
func (g *FanotifyGuard) Sweep(now time.Time) int {
	g.mu.Lock()
	defer g.mu.Unlock()

	expired := make([]*eventRecord, 0)
	for _, rec := range g.pending {
		if !now.Before(rec.deadline) {
			expired = append(expired, rec)
		}
	}
	sort.Slice(expired, func(i, j int) bool {
		if expired[i].deadline.Equal(expired[j].deadline) {
			return expired[i].id < expired[j].id
		}
		return expired[i].deadline.Before(expired[j].deadline)
	})
	for _, rec := range expired {
		g.expireRecord(rec)
		g.decisions[rec.id] = rec
	}
	return len(expired)
}

// PendingCount returns how many events are currently blocked.
func (g *FanotifyGuard) PendingCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.pending)
}

// Stats reports current counters.
func (g *FanotifyGuard) Stats() Stats {
	g.mu.Lock()
	defer g.mu.Unlock()
	return Stats{
		Marks:   len(g.marks),
		Pending: len(g.pending),
		Allowed: g.allowed,
		Denied:  g.denied,
		Expired: g.expired,
	}
}

const snapshotVersion = 1

type snapshotData struct {
	Version     int     `json:"version"`
	Marks       []Mark  `json:"marks"`
	NextMarkID  int     `json:"next_mark_id"`
	NextEventID EventID `json:"next_event_id"`
	Seq         uint64  `json:"seq"`
	Allowed     int     `json:"allowed"`
	Denied      int     `json:"denied"`
	Expired     int     `json:"expired"`
}

// Snapshot serialises marks and counters. Pending events are deliberately not
// persisted: after a restart nothing is blocked any more.
func (g *FanotifyGuard) Snapshot() ([]byte, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	snap := snapshotData{
		Version:     snapshotVersion,
		Marks:       make([]Mark, 0, len(g.marks)),
		NextMarkID:  g.nextMarkID,
		NextEventID: g.nextEventID,
		Seq:         g.seq,
		Allowed:     g.allowed,
		Denied:      g.denied,
		Expired:     g.expired,
	}
	for _, mark := range g.marks {
		snap.Marks = append(snap.Marks, *mark)
	}
	sort.Slice(snap.Marks, func(i, j int) bool {
		return snap.Marks[i].Path < snap.Marks[j].Path
	})
	data, err := json.Marshal(snap)
	if err != nil {
		return nil, err
	}
	return data, nil
}
