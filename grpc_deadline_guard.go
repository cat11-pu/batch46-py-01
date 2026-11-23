package task

import (
	"errors"
	"time"
)

var errNotImplemented = errors.New("not implemented")

// Sentinel errors returned by DeadlineGuard.
var (
	// ErrDeadlineExceeded means a call or its parent has no budget left.
	ErrDeadlineExceeded = errors.New("deadline: budget exhausted")
	// ErrBudgetBelowMinimum means the remaining budget is too small to be
	// handed to another call.
	ErrBudgetBelowMinimum = errors.New("deadline: budget below minimum")
	// ErrUnknownCall means the call id is not tracked.
	ErrUnknownCall = errors.New("deadline: unknown call")
	// ErrDuplicateCall means the call id is already tracked.
	ErrDuplicateCall = errors.New("deadline: duplicate call id")
	// ErrMaxHops means the call chain is deeper than allowed.
	ErrMaxHops = errors.New("deadline: hop limit exceeded")
	// ErrInvalidAttempt means the retry attempt index is outside the plan.
	ErrInvalidAttempt = errors.New("deadline: invalid retry attempt")
)

// Config holds deadline policy.
type Config struct {
	// MaxDeadline caps any requested deadline.
	MaxDeadline time.Duration
	// MinBudget is the smallest usable budget for a call or retry slice.
	MinBudget time.Duration
	// DefaultTimeout applies when a caller requests no budget.
	DefaultTimeout time.Duration
	// HopReserve is held back from the parent budget on each hop.
	HopReserve time.Duration
	// MaxHops limits the call tree depth; zero means unbounded.
	MaxHops int
}

// Deadline is the effective deadline of one call.
type Deadline struct {
	CallID string
	At     time.Time
	// Remaining is the budget granted at start time.
	Remaining time.Duration
	// Hop is 1 for a root call.
	Hop int
}

// Stats is a counter snapshot.
type Stats struct {
	Active   int
	Started  uint64
	Expired  uint64
	Finished uint64
}

// DeadlineGuard tracks parent/child deadline budgets across service hops.
type DeadlineGuard struct {
	cfg Config
}

// NewDeadlineGuard returns an empty tracker governed by cfg.
func NewDeadlineGuard(cfg Config) *DeadlineGuard {
	return &DeadlineGuard{cfg: cfg}
}

// NewDeadlineGuardFromSnapshot restores absolute deadlines and parent links
// from data produced by Snapshot.
func NewDeadlineGuardFromSnapshot(cfg Config, data []byte) (*DeadlineGuard, error) {
	return nil, errNotImplemented
}

// StartCall derives the deadline for callID from parentID.
func (g *DeadlineGuard) StartCall(callID, parentID string, requested time.Duration, now time.Time) (Deadline, error) {
	return Deadline{}, errNotImplemented
}

// Deadline returns the absolute deadline of a tracked call.
func (g *DeadlineGuard) Deadline(callID string) (time.Time, error) {
	return time.Time{}, errNotImplemented
}

// Remaining returns the budget left at now, never below zero.
func (g *DeadlineGuard) Remaining(callID string, now time.Time) (time.Duration, error) {
	return 0, errNotImplemented
}

// Finish closes a call and every descendant, returning how many descendants
// were closed with it.
func (g *DeadlineGuard) Finish(callID string) (int, error) {
	return 0, errNotImplemented
}

// IsActive reports whether a call is still tracked.
func (g *DeadlineGuard) IsActive(callID string) bool {
	return false
}

// ActiveCount returns how many calls are tracked.
func (g *DeadlineGuard) ActiveCount() int {
	return 0
}

// RetrySlice returns the budget one attempt may use: the remaining budget cut
// into maxAttempts equal parts.
func (g *DeadlineGuard) RetrySlice(callID string, attempt, maxAttempts int, now time.Time) (time.Duration, error) {
	return 0, errNotImplemented
}

// Expire drops every call whose deadline already passed and returns how many
// were dropped.
func (g *DeadlineGuard) Expire(now time.Time) int {
	return 0
}

// Stats returns the current counters.
func (g *DeadlineGuard) Stats() Stats {
	return Stats{}
}

// Snapshot serialises tracked calls with their absolute deadlines.
func (g *DeadlineGuard) Snapshot() ([]byte, error) {
	return nil, errNotImplemented
}
