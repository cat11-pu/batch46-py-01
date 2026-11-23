package task

import (
	"errors"
	"sync"
	"time"
)

var errNotImplemented = errors.New("not implemented")

// Sentinel errors returned by Appraise and the state getters. The admission
// controller treats a tampered measurement list as a node failure, while a bad
// file hash is only a policy violation, so the two must never be conflated.
var (
	ErrEntryInvalid   = errors.New("ima: invalid measurement entry")
	ErrListTampered   = errors.New("ima: measurement list aggregate mismatch")
	ErrSeqOrder       = errors.New("ima: measurement sequence out of order")
	ErrMissingCritical = errors.New("ima: critical file not measured")
	ErrQuarantined    = errors.New("ima: node quarantined")
	ErrRuleInvalid    = errors.New("ima: invalid appraisal rule")
	ErrNoVerdict      = errors.New("ima: no appraisal verdict for node")
)

// Config holds the appraisal policy.
type Config struct {
	// ViolationBudget is the number of cumulative violations a node may have
	// before it is quarantined; the next violating appraisal quarantines it.
	ViolationBudget int
	// MaxEntries caps how many measurements one Appraise call accepts.
	MaxEntries int
	// MaxStoredViolations caps how many violation strings are kept per node.
	MaxStoredViolations int
	// RequireSigned rejects ima-ng entries and entries without a signer.
	RequireSigned bool
}

// Rule is the appraisal policy for one file path of one tenant.
type Rule struct {
	TenantID      string
	Path          string
	Label         string
	AllowedHashes []string
	// Critical files must appear in every measurement list.
	Critical bool
}

// Entry is one IMA measurement list record.
type Entry struct {
	Seq        uint64
	Path       string
	Hash       string
	// Template is the IMA template name, e.g. "ima-ng" or "ima-sig".
	Template   string
	Signer     string
	MeasuredAt time.Time
}

// Assessment is the outcome of one appraisal run for a node.
type Assessment struct {
	NodeID     string
	Evaluated  int
	Violations []string
	Quarantined bool
}

// ImaGuard appraises IMA measurement lists against per-tenant rules.
type ImaGuard struct {
	mu  sync.Mutex
	cfg Config
}

// NewImaGuard returns a guard configured by cfg.
func NewImaGuard(cfg Config) *ImaGuard {
	return &ImaGuard{cfg: cfg}
}

// NewImaGuardFromSnapshot restores rules and per-node violation state from a
// snapshot.
func NewImaGuardFromSnapshot(cfg Config, data []byte) (*ImaGuard, error) {
	return nil, errNotImplemented
}

// AddRule installs or replaces the rule for r.TenantID and r.Path. An empty
// tenant, path or allowed hash list fails with ErrRuleInvalid.
func (g *ImaGuard) AddRule(r Rule) error {
	return errNotImplemented
}

// RemoveRule deletes the rule for a path of a tenant; unknown paths fail with
// ErrRuleInvalid.
func (g *ImaGuard) RemoveRule(tenantID, path string) error {
	return errNotImplemented
}

// Appraise verifies one measurement list.
//
// Structural problems (empty list, more than MaxEntries, missing path, hash or
// template, zero sequence) fail with ErrEntryInvalid. The aggregate argument
// must be the lowercase hex SHA-256 of the concatenation of
// "<seq>:<path>:<hash>\n" for every entry in list order; a mismatch fails with
// ErrListTampered. Sequences must strictly increase, otherwise ErrSeqOrder.
// Critical rules missing from the list fail with ErrMissingCritical, and a
// quarantined node fails with ErrQuarantined. Per-file policy problems are
// collected in Assessment.Violations in list order ("duplicate:<path>",
// "no-policy:<path>", "hash:<path>", "unsigned:<path>") and do not return an
// error. Rejected lists never change stored state.
func (g *ImaGuard) Appraise(tenantID, nodeID string, entries []Entry, aggregate string, now time.Time) (Assessment, error) {
	return Assessment{}, errNotImplemented
}

// Verdict returns the last assessment stored for a node, or ErrNoVerdict.
func (g *ImaGuard) Verdict(tenantID, nodeID string) (Assessment, error) {
	return Assessment{}, errNotImplemented
}

// Violations returns the stored (capped) violation list of a node.
func (g *ImaGuard) Violations(tenantID, nodeID string) []string {
	return nil
}

// ViolationCount returns the cumulative violation count of a node.
func (g *ImaGuard) ViolationCount(tenantID, nodeID string) int {
	return 0
}

// IsQuarantined reports whether the node is currently quarantined.
func (g *ImaGuard) IsQuarantined(tenantID, nodeID string) bool {
	return false
}

// Reset clears the violation count, stored violations and quarantine of a
// node after remediation.
func (g *ImaGuard) Reset(tenantID, nodeID string) error {
	return errNotImplemented
}

// Snapshot serialises rules and per-node counts so that a restart keeps
// quarantines in force.
func (g *ImaGuard) Snapshot() ([]byte, error) {
	return nil, errNotImplemented
}
