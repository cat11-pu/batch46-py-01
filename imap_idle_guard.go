package task

import (
	"errors"
	"sync"
	"time"
)

// Sentinel errors reported by ImapIdleGuard.
var (
	ErrMailboxInvalid  = errors.New("imap: invalid mailbox")
	ErrMailboxNotFound = errors.New("imap: unknown mailbox")
	ErrSessionNotFound = errors.New("imap: unknown session")
	ErrSessionState    = errors.New("imap: invalid session state")
	ErrSessionLimit    = errors.New("imap: session limit reached")
	ErrStaleUpdate     = errors.New("imap: stale mailbox update")
	ErrUpdateInvalid   = errors.New("imap: invalid mailbox update")
	ErrIdleTimeout     = errors.New("imap: idle timeout")
	ErrSnapshot        = errors.New("imap: invalid snapshot")
)

// Session states used by IdleSession.State.
const (
	SessionActive = "active"
	SessionIdle   = "idle"
	SessionClosed = "closed"
)

// Notification kinds delivered by Poll.
const (
	KindExists      = "EXISTS"
	KindUIDValidity = "UIDVALIDITY"
)

var errNotImplemented = errors.New("stub: not implemented")

// Mailbox is the server-side state of one mailbox.
type Mailbox struct {
	Name          string
	UIDValidity   uint32
	Messages      int
	HighestModSeq uint64
}

// Update is one mailbox change published by the mail store.
type Update struct {
	Account       string
	Mailbox       string
	UIDValidity   uint32
	Messages      int
	HighestModSeq uint64
	ArrivedAt     time.Time
}

// Notification is one pending IDLE update for a session.
type Notification struct {
	Kind   string
	Value  int64
	ModSeq uint64
}

// IdleSession is the visible state of one IDLE session.
type IdleSession struct {
	ID          string
	Account     string
	Mailbox     string
	State       string
	LastSeq     int
	LastModSeq  uint64
	UIDValidity uint32
	IdleSince   time.Time
}

// Policy controls IDLE session limits and batching.
type Policy struct {
	IdleTimeout time.Duration
	MaxSessions int
	MaxPending  int
	BatchSize   int
}

// Stats are cumulative guard counters.
type Stats struct {
	Published int64
	Delivered int64
	Dropped   int64
	Expired   int64
	Rejected  int64
}

type sessionState struct {
	IdleSession
	pending []Notification
}

// ImapIdleGuard tracks IDLE sessions and their per-session notification queues.
type ImapIdleGuard struct {
	policy    Policy
	mailboxes map[string]Mailbox
	sessions  map[string]*sessionState
	stats     Stats
	mu        sync.Mutex
}

// NewImapIdleGuard returns a guard configured by policy.
func NewImapIdleGuard(policy Policy) *ImapIdleGuard {
	return &ImapIdleGuard{policy: policy}
}

// NewImapIdleGuardFromSnapshot restores mailboxes, sessions, pending queues and
// counters from a snapshot produced by Snapshot.
func NewImapIdleGuardFromSnapshot(policy Policy, data []byte) (*ImapIdleGuard, error) {
	return nil, errNotImplemented
}

// SetMailbox registers or replaces the state of account's mailbox.
func (g *ImapIdleGuard) SetMailbox(account string, m Mailbox) error {
	return errNotImplemented
}

// Mailbox returns the stored state of account's mailbox.
func (g *ImapIdleGuard) Mailbox(account, name string) (Mailbox, error) {
	return Mailbox{}, errNotImplemented
}

// RegisterSession creates an active session whose cursor starts at the current
// mailbox state.
func (g *ImapIdleGuard) RegisterSession(account, sessionID, mailbox string, now time.Time) (IdleSession, error) {
	return IdleSession{}, errNotImplemented
}

// BeginIdle moves an active session into the idle state.
func (g *ImapIdleGuard) BeginIdle(sessionID string, now time.Time) error {
	return errNotImplemented
}

// EndIdle returns an idle session to the active state.
func (g *ImapIdleGuard) EndIdle(sessionID string) error {
	return errNotImplemented
}

// Publish records a mailbox change and fans notifications out to idle sessions.
func (g *ImapIdleGuard) Publish(u Update, now time.Time) error {
	return errNotImplemented
}

// Poll returns at most BatchSize queued notifications for an idle session.
func (g *ImapIdleGuard) Poll(sessionID string, now time.Time) ([]Notification, error) {
	return nil, errNotImplemented
}

// CloseSession removes a session and releases its slot.
func (g *ImapIdleGuard) CloseSession(sessionID string) error {
	return errNotImplemented
}

// SessionsFor returns the sorted session ids of one account.
func (g *ImapIdleGuard) SessionsFor(account string) []string {
	return nil
}

// Seq returns the session's last delivered message count.
func (g *ImapIdleGuard) Seq(sessionID string) (int, error) {
	return 0, errNotImplemented
}

// Snapshot serialises mailboxes, sessions with pending queues, and counters.
func (g *ImapIdleGuard) Snapshot() ([]byte, error) {
	return nil, errNotImplemented
}

// Counters returns a copy of the cumulative counters.
func (g *ImapIdleGuard) Counters() Stats {
	return Stats{}
}
