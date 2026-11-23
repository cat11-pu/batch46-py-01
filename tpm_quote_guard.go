package task

import (
	"errors"
	"sync"
	"time"
)

var errNotImplemented = errors.New("not implemented")

// Sentinel errors returned by Verify. The attestation pipeline maps them to
// node state transitions, so a stale quote must never look like a PCR policy
// mismatch and a replayed nonce must never look like an unknown one.
var (
	ErrQuoteInvalid     = errors.New("tpmquote: invalid quote")
	ErrAKUnknown        = errors.New("tpmquote: unknown attestation key")
	ErrAKDuplicate      = errors.New("tpmquote: duplicate attestation key")
	ErrAKRevoked        = errors.New("tpmquote: attestation key revoked")
	ErrTenantMismatch   = errors.New("tpmquote: tenant mismatch")
	ErrSignatureInvalid = errors.New("tpmquote: invalid quote signature")
	ErrQuoteStale       = errors.New("tpmquote: quote outside freshness window")
	ErrNonceUnknown     = errors.New("tpmquote: unknown nonce")
	ErrNonceReplay      = errors.New("tpmquote: nonce replay")
	ErrPolicyMissing    = errors.New("tpmquote: no pcr policy for node")
	ErrClockRollback    = errors.New("tpmquote: tpm clock rollback")
	ErrPCRMismatch      = errors.New("tpmquote: pcr digest mismatch")
	ErrNoVerdict        = errors.New("tpmquote: no verdict for node")
)

// Config holds the verification policy knobs.
type Config struct {
	// MaxQuoteAge bounds how old (or how far in the future) AttestedAt may be.
	MaxQuoteAge time.Duration
	// NonceTTL is how long an issued nonce stays usable and how long a used
	// nonce is remembered for replay detection.
	NonceTTL time.Duration
	// MaxPCRsPerQuote caps how many PCR entries one quote may carry.
	MaxPCRsPerQuote int
}

// AK is an attestation key allowed to sign quotes for one tenant. Quotes name
// the AK by Name, not by PublicHash.
type AK struct {
	Name       string
	TenantID   string
	PublicHash string
}

// PCRPolicy is the golden measurement set for one node of one tenant.
// Expected maps PCR index to the lowercase hex digest measured at boot.
type PCRPolicy struct {
	TenantID string
	NodeID   string
	Expected map[int]string
}

// Quote is a TPMS_ATTEST plus its signature result as delivered by the node.
// SignatureValid is the result of checking the quote against the AK.
type Quote struct {
	TenantID       string
	NodeID         string
	AKName         string
	Nonce          string
	Firmware       string
	Clock          uint64
	AttestedAt     time.Time
	SignatureValid bool
	PCRs           map[int]string
}

// Verdict is the outcome recorded for a node after a successful verify.
type Verdict struct {
	NodeID      string
	Firmware    string
	Clock       uint64
	PCRsChecked int
	At          time.Time
}

// TpmQuoteGuard verifies remote attestation quotes against per-node PCR
// policies, single-use nonces and a monotonic TPM clock.
type TpmQuoteGuard struct {
	mu  sync.Mutex
	cfg Config
}

// NewTpmQuoteGuard returns a guard configured by cfg.
func NewTpmQuoteGuard(cfg Config) *TpmQuoteGuard {
	return &TpmQuoteGuard{cfg: cfg}
}

// NewTpmQuoteGuardFromSnapshot restores AKs, policies, pending and used
// nonces, clock baselines and verdicts from a snapshot.
func NewTpmQuoteGuardFromSnapshot(cfg Config, data []byte) (*TpmQuoteGuard, error) {
	return nil, errNotImplemented
}

// RegisterAK registers an attestation key for its tenant. Registering the same
// name twice for one tenant fails with ErrAKDuplicate; an empty name, tenant
// or public hash fails with ErrQuoteInvalid.
func (g *TpmQuoteGuard) RegisterAK(ak AK) error {
	return errNotImplemented
}

// RevokeAK revokes an attestation key. Later quotes naming it fail with
// ErrAKRevoked even if the key is registered again.
func (g *TpmQuoteGuard) RevokeAK(tenantID, name string) error {
	return errNotImplemented
}

// SetPolicy installs the golden PCR set for one node. An empty tenant, node or
// expected set fails with ErrQuoteInvalid. Replacing a policy keeps the node's
// clock baseline.
func (g *TpmQuoteGuard) SetPolicy(p PCRPolicy) error {
	return errNotImplemented
}

// Policy returns a copy of the node's policy, or ErrPolicyMissing.
func (g *TpmQuoteGuard) Policy(tenantID, nodeID string) (PCRPolicy, error) {
	return PCRPolicy{}, errNotImplemented
}

// IssueNonce mints a single-use nonce bound to one node of one tenant.
func (g *TpmQuoteGuard) IssueNonce(tenantID, nodeID string, now time.Time) (string, error) {
	return "", errNotImplemented
}

// Verify checks a quote in this order: structural fields, AK existence,
// revocation, tenant, signature, freshness, nonce, policy, TPM clock, PCR
// digests. A nonce is consumed only on success; a rejected quote never moves
// the clock baseline and never overwrites the stored verdict.
func (g *TpmQuoteGuard) Verify(q Quote, now time.Time) (Verdict, error) {
	return Verdict{}, errNotImplemented
}

// LastVerdict returns the last successful verdict for a node, or ErrNoVerdict.
func (g *TpmQuoteGuard) LastVerdict(tenantID, nodeID string) (Verdict, error) {
	return Verdict{}, errNotImplemented
}

// Evaluations counts successfully verified quotes since the guard was created
// or restored.
func (g *TpmQuoteGuard) Evaluations() int {
	return 0
}

// Snapshot serialises all state so that a restarted verifier still rejects
// replayed nonces and rolled-back clocks.
func (g *TpmQuoteGuard) Snapshot() ([]byte, error) {
	return nil, errNotImplemented
}
