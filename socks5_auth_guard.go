package task

import (
	"errors"
	"time"
)

// errNotImplemented is returned by every stubbed operation.
var errNotImplemented = errors.New("not implemented")

// Errors reported by the handshake, authentication and forwarding calls.
var (
	ErrVersion  = errors.New("socks5: unsupported protocol version")
	ErrMethod   = errors.New("socks5: no acceptable authentication method")
	ErrAuth     = errors.New("socks5: authentication failed")
	ErrLocked   = errors.New("socks5: user temporarily locked")
	ErrState    = errors.New("socks5: operation not allowed in this state")
	ErrSession  = errors.New("socks5: unknown session")
	ErrCapacity = errors.New("socks5: session capacity reached")
	ErrQuota    = errors.New("socks5: per-user session quota reached")
	ErrPort     = errors.New("socks5: destination port not allowed")
	ErrAddress  = errors.New("socks5: destination address not allowed")
	ErrHost     = errors.New("socks5: host cannot be resolved")
	ErrBudget   = errors.New("socks5: session byte budget exceeded")
	ErrInvalid  = errors.New("socks5: invalid argument")
)

// Config is the proxy policy.
type Config struct {
	// MaxSessions caps concurrently open sessions.
	MaxSessions int
	// MaxSessionsPerUser caps concurrently open sessions of one user.
	MaxSessionsPerUser int
	// IdleTimeout is how long a session may stay idle before it is swept.
	IdleTimeout time.Duration
	// MaxBytesPerSession caps the summed upload and download bytes.
	MaxBytesPerSession int64
	// AllowedPorts lists the destination ports that may be dialed.
	AllowedPorts []int
	// MaxAuthFailures is how many failed attempts lock a user.
	MaxAuthFailures int
	// LockoutDuration is how long a user stays locked.
	LockoutDuration time.Duration
}

// Greeting is the method negotiation sent by the client.
type Greeting struct {
	Version int
	Methods []byte
}

// Session is one proxy session.
type Session struct {
	ID         string
	User       string
	State      string
	Target     string
	BytesUp    int64
	BytesDown  int64
	OpenedAt   time.Time
	LastActive time.Time
}

// Target is the resolved destination of a CONNECT.
type Target struct {
	Host string
	IP   string
	Port int
}

// Stats reports proxy counters.
type Stats struct {
	Sessions  int
	Active    int
	BytesUp   int64
	BytesDown int64
	AuthFails int
}

// Socks5Guard runs the SOCKS5 handshake, enforces authentication and per-user
// limits, and accounts for forwarded bytes.
type Socks5Guard struct {
	cfg Config
}

// NewSocks5Guard returns a guard configured by cfg.
func NewSocks5Guard(cfg Config) *Socks5Guard {
	return &Socks5Guard{cfg: cfg}
}

// NewSocks5GuardFromSnapshot restores a guard, including users, lockouts and
// byte counters, from a snapshot.
func NewSocks5GuardFromSnapshot(cfg Config, data []byte) (*Socks5Guard, error) {
	return nil, errNotImplemented
}

// SetResolver installs the host resolver used by Connect. When it is not set,
// only literal IP addresses may be dialed.
func (g *Socks5Guard) SetResolver(fn func(host string) ([]string, error)) error {
	return errNotImplemented
}

// AddUser registers a user with its authentication proof and tenant.
func (g *Socks5Guard) AddUser(username, proof, tenantID string) error {
	return errNotImplemented
}

// Open allocates a new session in the "new" state.
func (g *Socks5Guard) Open(now time.Time) (Session, error) {
	return Session{}, errNotImplemented
}

// Greet negotiates the authentication method. Only username/password is
// acceptable; the no-authentication method is never selected.
func (g *Socks5Guard) Greet(sessionID string, gr Greeting, now time.Time) error {
	return errNotImplemented
}

// Authenticate verifies the username and proof of a greeted session and
// applies the lockout policy.
func (g *Socks5Guard) Authenticate(sessionID, username, proof string, now time.Time) error {
	return errNotImplemented
}

// Connect resolves and validates the destination of an authenticated session.
func (g *Socks5Guard) Connect(sessionID, host string, port int, now time.Time) (Target, error) {
	return Target{}, errNotImplemented
}

// Transfer accounts for forwarded bytes and enforces the per-session budget.
func (g *Socks5Guard) Transfer(sessionID string, up, down int64, now time.Time) error {
	return errNotImplemented
}

// Close closes a session. Closing an already closed session is a no-op.
func (g *Socks5Guard) Close(sessionID string, now time.Time) error {
	return errNotImplemented
}

// Sweep closes sessions idle longer than IdleTimeout and returns how many
// were closed.
func (g *Socks5Guard) Sweep(now time.Time) int {
	return 0
}

// Stats reports session and byte counters.
func (g *Socks5Guard) Stats() Stats {
	return Stats{}
}

// Snapshot serialises users, lockouts and counters.
func (g *Socks5Guard) Snapshot() ([]byte, error) {
	return nil, errNotImplemented
}
