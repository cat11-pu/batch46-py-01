package task

import (
	"errors"
	"time"
)

// errNotImplemented is returned by every stubbed operation.
var errNotImplemented = errors.New("not implemented")

// Errors reported by Submit, SelectedServer and Apply.
var (
	ErrAuth       = errors.New("ntp: unauthenticated response")
	ErrKey        = errors.New("ntp: key id not accepted")
	ErrPacket     = errors.New("ntp: unusable packet")
	ErrStale      = errors.New("ntp: response does not match an outstanding query")
	ErrReplay     = errors.New("ntp: replayed response")
	ErrOffset     = errors.New("ntp: offset beyond the allowed limit")
	ErrNoSource   = errors.New("ntp: no usable time source")
	ErrDivergence = errors.New("ntp: sources disagree beyond the allowed skew")
	ErrNoSample   = errors.New("ntp: no time sample yet")
)

// Config is the time-source policy.
type Config struct {
	// MaxOffset is the largest offset a single response may imply.
	MaxOffset time.Duration
	// MinRounds is how many accepted samples a server needs before it may
	// be selected.
	MinRounds int
	// MaxSkew is the largest disagreement tolerated between selectable
	// servers.
	MaxSkew time.Duration
	// MaxSlewPPM is how fast the correction may be applied, in parts per
	// million of elapsed time.
	MaxSlewPPM int64
	// ServerMaxAge is how long a sample keeps a server selectable.
	ServerMaxAge time.Duration
}

// Response is one authenticated time response. The four timestamps are the
// client originate time (echoed), the server receive time, the server
// transmit time and the client destination time.
type Response struct {
	Server      string
	KeyID       uint32
	AuthOK      bool
	Version     int
	Leap        int
	Stratum     int
	Originate   time.Time
	Receive     time.Time
	Transmit    time.Time
	Destination time.Time
	Nonce       string
}

// Query is an outstanding request.
type Query struct {
	Server string
	T1     time.Time
	Nonce  string
}

// Sample is one accepted measurement.
type Sample struct {
	Server  string
	Offset  time.Duration
	Delay   time.Duration
	Stratum int
	TakenAt time.Time
}

// Correction is the part of the pending offset applied by one call, and the
// part that is still pending.
type Correction struct {
	Applied   time.Duration
	Remaining time.Duration
}

// Stats reports how many servers have samples and how many rounds were
// accepted.
type Stats struct {
	Servers int
	Rounds  int
}

// NtpAuthGuard verifies authenticated responses, tracks per-server samples
// and applies corrections within a slew budget.
type NtpAuthGuard struct {
	cfg Config
}

// NewNtpAuthGuard returns a guard configured by cfg.
func NewNtpAuthGuard(cfg Config) *NtpAuthGuard {
	return &NtpAuthGuard{cfg: cfg}
}

// NewNtpAuthGuardFromSnapshot restores a guard, including keys, round counts,
// last samples and the pending correction, from a snapshot.
func NewNtpAuthGuardFromSnapshot(cfg Config, data []byte) (*NtpAuthGuard, error) {
	return nil, errNotImplemented
}

// AddKey registers the key id accepted for a server.
func (g *NtpAuthGuard) AddKey(server string, keyID uint32) error {
	return errNotImplemented
}

// RevokeKey removes a key id; responses carrying it are then rejected.
func (g *NtpAuthGuard) RevokeKey(server string, keyID uint32) error {
	return errNotImplemented
}

// Query records an outstanding request to a server and returns the originate
// timestamp and nonce that the response must echo.
func (g *NtpAuthGuard) Query(server string, now time.Time) (Query, error) {
	return Query{}, errNotImplemented
}

// Submit validates one response against the outstanding query, computes the
// offset and delay and records a sample when the packet is usable.
func (g *NtpAuthGuard) Submit(resp Response, now time.Time) (Sample, error) {
	return Sample{}, errNotImplemented
}

// SelectedServer returns the best selectable server at now, or an error when
// no server qualifies or the candidates disagree too much.
func (g *NtpAuthGuard) SelectedServer(now time.Time) (string, error) {
	return "", errNotImplemented
}

// Offset returns the last accepted offset of a server.
func (g *NtpAuthGuard) Offset(server string) (time.Duration, bool) {
	return 0, false
}

// Apply applies at most MaxSlewPPM of the elapsed time towards the pending
// offset and returns how much was applied.
func (g *NtpAuthGuard) Apply(now time.Time) (Correction, error) {
	return Correction{}, errNotImplemented
}

// Sweep forgets servers whose last sample is older than ServerMaxAge and
// returns how many were forgotten.
func (g *NtpAuthGuard) Sweep(now time.Time) int {
	return 0
}

// Stats reports how many servers have samples and how many rounds were
// accepted.
func (g *NtpAuthGuard) Stats() Stats {
	return Stats{}
}

// Snapshot serialises keys, samples and the pending correction.
func (g *NtpAuthGuard) Snapshot() ([]byte, error) {
	return nil, errNotImplemented
}
