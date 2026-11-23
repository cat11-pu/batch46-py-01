package task

import (
	"errors"
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

// FanotifyGuard tracks marks and permission events for one responder.
type FanotifyGuard struct {
	cfg Config
}

// NewFanotifyGuard returns an empty guard configured by cfg.
func NewFanotifyGuard(cfg Config) *FanotifyGuard {
	return &FanotifyGuard{cfg: cfg}
}

// NewFanotifyGuardFromSnapshot restores marks, counters and the event id
// counter from a snapshot produced by Snapshot.
func NewFanotifyGuardFromSnapshot(cfg Config, data []byte) (*FanotifyGuard, error) {
	return nil, errNotImplemented
}

// Mark subscribes to permission events for an absolute, clean path.
func (g *FanotifyGuard) Mark(path string, mask Mask) (int, error) {
	return 0, errNotImplemented
}

// Unmark removes a mark. A mark with blocked events is busy until they are
// answered or swept.
func (g *FanotifyGuard) Unmark(id int) error {
	return errNotImplemented
}

// Marks returns the marks ordered by path.
func (g *FanotifyGuard) Marks() []Mark {
	return nil
}

// Begin records a permission event raised by the kernel. The caller is blocked
// until Respond or Sweep resolves it.
func (g *FanotifyGuard) Begin(path string, op Op, now time.Time) (Event, error) {
	return Event{}, errNotImplemented
}

// Respond writes a verdict back for one event.
func (g *FanotifyGuard) Respond(id EventID, d Decision, now time.Time) error {
	return errNotImplemented
}

// Sweep denies every event whose deadline has passed and returns how many were
// denied.
func (g *FanotifyGuard) Sweep(now time.Time) int {
	return 0
}

// PendingCount returns how many events are currently blocked.
func (g *FanotifyGuard) PendingCount() int {
	return 0
}

// Stats reports current counters.
func (g *FanotifyGuard) Stats() Stats {
	return Stats{}
}

// Snapshot serialises marks and counters. Pending events are deliberately not
// persisted: after a restart nothing is blocked any more.
func (g *FanotifyGuard) Snapshot() ([]byte, error) {
	return nil, errNotImplemented
}
