package task

import (
	"errors"
	"time"
)

// Sentinel errors returned by TacacsGuard. Callers must be able to tell a
// missing or expired session from a denied command and from a rejected
// accounting record.
var (
	ErrUnauthenticated = errors.New("tacacs: unauthenticated session")
	ErrNotAuthorized   = errors.New("tacacs: command not authorized")
	ErrArgInvalid      = errors.New("tacacs: invalid argument")
	ErrLimit           = errors.New("tacacs: limit exceeded")
	ErrAccounting      = errors.New("tacacs: accounting record rejected")
	ErrRuleExists      = errors.New("tacacs: duplicate rule name")
)

var errNotImplemented = errors.New("not implemented")

// Config is the policy applied by the AAA server.
type Config struct {
	// SessionTTL is how long an authenticated session stays usable. A zero
	// value means five minutes.
	SessionTTL time.Duration
	// MaxSessions caps concurrently live sessions per network device. A zero
	// value means no cap.
	MaxSessions int
	// MaxArgs caps the argument count of one authorized command. A zero value
	// means sixteen.
	MaxArgs int
	// AcctRetention is how long a closed accounting task is kept after its
	// stop record. A zero value means one hour.
	AcctRetention time.Duration
}

// AV is one TACACS+ attribute/value pair.
type AV struct {
	Name  string
	Value string
}

// Rule is one ordered command authorization rule. Rules are evaluated by
// ascending Order; the first match decides. TenantID "*" applies to every
// tenant. Command "*" matches every command. A nil Args slice matches any
// arguments; otherwise each element must match, with "*" as a single-argument
// wildcard.
type Rule struct {
	Name     string
	TenantID string
	Command  string
	Args     []string
	Permit   bool
	Order    int
	AVs      []AV
}

// AuthorizeRequest is the command a device asks the server to authorize.
type AuthorizeRequest struct {
	SessionID string
	User      string
	TenantID  string
	Command   string
	Args      []string
}

// Decision is the outcome of one authorization request.
type Decision struct {
	Allowed bool
	Rule    string
	AVs     []AV
}

// AcctRecord is one accounting event. Flags is "start", "watchdog" or "stop".
type AcctRecord struct {
	TaskID    string
	SessionID string
	User      string
	Flags     string
	Command   string
	Bytes     int64
	At        time.Time
}

// TacacsGuard keeps sessions, authorization rules and accounting tasks for one
// AAA server instance.
type TacacsGuard struct {
	cfg Config
}

// NewTacacsGuard returns a guard configured by cfg.
func NewTacacsGuard(cfg Config) *TacacsGuard {
	return &TacacsGuard{cfg: cfg}
}

// NewTacacsGuardFromSnapshot restores sessions, rules and accounting state from
// a snapshot produced by Snapshot.
func NewTacacsGuardFromSnapshot(cfg Config, data []byte) (*TacacsGuard, error) {
	return nil, errNotImplemented
}

// Authenticate opens a session for user on deviceID inside tenantID. Empty
// identifiers, a duplicate live session id and an exhausted per-device session
// cap are refused.
func (g *TacacsGuard) Authenticate(sessionID, user, deviceID, tenantID string, now time.Time) error {
	return errNotImplemented
}

// SessionActive reports whether sessionID is known and not yet expired. An
// empty id is an invalid argument.
func (g *TacacsGuard) SessionActive(sessionID string, now time.Time) (bool, error) {
	return false, errNotImplemented
}

// ExpireSessions drops sessions whose deadline has passed and returns how many
// records were removed.
func (g *TacacsGuard) ExpireSessions(now time.Time) int {
	return 0
}

// AddRule registers one authorization rule.
func (g *TacacsGuard) AddRule(r Rule) error {
	return errNotImplemented
}

// RuleCount returns the number of registered rules.
func (g *TacacsGuard) RuleCount() int {
	return 0
}

// Authorize evaluates req against the registered rules. The session must be
// live, belong to the same user and tenant, and the argument count must stay
// inside the configured cap. A permit returns a nil error; a deny or a request
// with no matching rule returns ErrNotAuthorized together with a Decision that
// names the rule that decided.
func (g *TacacsGuard) Authorize(req AuthorizeRequest, now time.Time) (Decision, error) {
	return Decision{}, errNotImplemented
}

// Accounting records one start, watchdog or stop event for a task. Watchdog
// and stop byte counters accumulate onto the task.
func (g *TacacsGuard) Accounting(rec AcctRecord, now time.Time) error {
	return errNotImplemented
}

// AcctUsage returns the accumulated byte counter of taskID.
func (g *TacacsGuard) AcctUsage(taskID string) (int64, error) {
	return 0, errNotImplemented
}

// Prune drops expired sessions and closed accounting tasks older than the
// retention window, returning the total number of removed records.
func (g *TacacsGuard) Prune(now time.Time) int {
	return 0
}

// Snapshot serialises sessions, rules and accounting state so that a restarted
// server keeps authorizing and accounting consistently.
func (g *TacacsGuard) Snapshot() ([]byte, error) {
	return nil, errNotImplemented
}
