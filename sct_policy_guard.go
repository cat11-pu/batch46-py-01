package task

import (
	"errors"
	"time"
)

// errNotImplemented is returned by every stub that still has to be built.
var errNotImplemented = errors.New("not implemented")

// Errors returned by SctGuard.
var (
	ErrLogExists         = errors.New("sct: log already registered")
	ErrLogNotFound       = errors.New("sct: log not found")
	ErrLogInvalid        = errors.New("sct: invalid log")
	ErrTooManyLogs       = errors.New("sct: log limit reached")
	ErrUnknownLog        = errors.New("sct: sct from unknown log")
	ErrTooFewSCTs        = errors.New("sct: not enough distinct scts")
	ErrOperatorDiversity = errors.New("sct: operator diversity not met")
	ErrSCTTimestamp      = errors.New("sct: sct timestamp outside policy")
	ErrCertExpired       = errors.New("sct: certificate expired")
	ErrCertNotYetValid   = errors.New("sct: certificate not yet valid")
	ErrBadSCTSignature   = errors.New("sct: invalid sct signature")
)

// LogState is the policy state of a certificate transparency log.
type LogState string

const (
	// LogUsable logs count towards the SCT policy.
	LogUsable LogState = "usable"
	// LogDisqualified logs are ignored even when an SCT carries their id.
	LogDisqualified LogState = "disqualified"
)

// Config is the SCT policy.
type Config struct {
	// MinDistinctLogs is the number of distinct usable logs required.
	MinDistinctLogs int
	// MinOperators is the number of distinct log operators required.
	MinOperators int
	// MaxLogs caps the number of registered logs.
	MaxLogs int
	// MaxSCTAge is the maximum age of an SCT timestamp at validation time.
	MaxSCTAge time.Duration
	// ClockSkew is the tolerated clock difference for timestamps.
	ClockSkew time.Duration
}

// Log is one certificate transparency log in the policy registry.
type Log struct {
	ID       string
	Operator string
	State    LogState
}

// Cert is the certificate whose SCTs are evaluated.
type Cert struct {
	Serial    string
	Issuer    string
	NotBefore time.Time
	NotAfter  time.Time
}

// SCT is one signed certificate timestamp presented with a certificate.
type SCT struct {
	LogID          string
	Timestamp      time.Time
	SignatureValid bool
	// Source is where the SCT was delivered: "embedded", "tls" or "ocsp".
	Source string
}

// Verdict is the result of an evaluation. On a policy failure Accepted is
// false and Count/Logs/Operators describe the SCTs that were counted before the
// rejection.
type Verdict struct {
	Accepted  bool
	Logs      []string
	Operators []string
	Count     int
}

// SctGuard evaluates certificate transparency SCT policies.
type SctGuard struct {
	cfg Config
}

// NewSctGuard returns an empty policy registry configured by cfg.
func NewSctGuard(cfg Config) *SctGuard {
	return &SctGuard{cfg: cfg}
}

// NewSctGuardFromSnapshot restores the log registry from a snapshot.
func NewSctGuardFromSnapshot(cfg Config, data []byte) (*SctGuard, error) {
	return nil, errNotImplemented
}

// AddLog registers a certificate transparency log.
func (g *SctGuard) AddLog(l Log) error {
	return errNotImplemented
}

// SetLogState changes the policy state of a registered log.
func (g *SctGuard) SetLogState(id string, state LogState) error {
	return errNotImplemented
}

// RemoveLog deletes a log from the registry.
func (g *SctGuard) RemoveLog(id string) error {
	return errNotImplemented
}

// GetLog returns one registered log.
func (g *SctGuard) GetLog(id string) (Log, error) {
	return Log{}, errNotImplemented
}

// Evaluate applies the SCT policy to the certificate and its SCTs.
func (g *SctGuard) Evaluate(cert Cert, scts []SCT, now time.Time) (Verdict, error) {
	return Verdict{}, errNotImplemented
}

// LogCount reports the number of registered logs.
func (g *SctGuard) LogCount() int {
	return 0
}

// ListLogs returns the registered log ids in sorted order.
func (g *SctGuard) ListLogs() []string {
	return nil
}

// Snapshot serialises the log registry.
func (g *SctGuard) Snapshot() ([]byte, error) {
	return nil, errNotImplemented
}
