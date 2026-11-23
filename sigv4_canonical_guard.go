package task

import (
	"errors"
	"time"
)

// Sentinel errors returned by SigV4Guard. A tampered request, a stale clock
// and a replayed signature must all be distinguishable by the caller.
var (
	ErrMalformed     = errors.New("sigv4: malformed request")
	ErrSignature     = errors.New("sigv4: signature mismatch")
	ErrClockSkew     = errors.New("sigv4: request time outside skew")
	ErrExpired       = errors.New("sigv4: presigned url expired")
	ErrMissingHeader = errors.New("sigv4: missing required header")
	ErrReplay        = errors.New("sigv4: replayed signature")
	ErrUnknownKey    = errors.New("sigv4: unknown access key")
	ErrLimit         = errors.New("sigv4: limit exceeded")
)

var errNotImplemented = errors.New("not implemented")

// Config is the signing policy of one service endpoint.
type Config struct {
	// Region and Service appear in the credential scope and are compared on
	// every verification.
	Region  string
	Service string
	// MaxSkew is the tolerated absolute clock difference for x-amz-date. A
	// zero value means five minutes.
	MaxSkew time.Duration
	// PresignLimit is the largest accepted X-Amz-Expires. A zero value means
	// one hour.
	PresignLimit time.Duration
	// ReplayTTL is how long a consumed signature is remembered. A zero value
	// means ten minutes.
	ReplayTTL time.Duration
	// MaxHeaders caps how many headers may be signed. A zero value means
	// sixteen.
	MaxHeaders int
}

// Request is one HTTP request as it arrives at the edge.
type Request struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    []byte
}

// Credentials bind an access key to a tenant.
type Credentials struct {
	AccessKeyID string
	SecretKey   string
	TenantID    string
}

// SigV4Guard canonicalises and verifies signed requests for one endpoint.
type SigV4Guard struct {
	cfg Config
}

// NewSigV4Guard returns a guard configured by cfg.
func NewSigV4Guard(cfg Config) *SigV4Guard {
	return &SigV4Guard{cfg: cfg}
}

// NewSigV4GuardFromSnapshot restores a guard, including the consumed
// signature set, from a snapshot.
func NewSigV4GuardFromSnapshot(cfg Config, data []byte) (*SigV4Guard, error) {
	return nil, errNotImplemented
}

// RegisterKey stores the secret of one access key.
func (g *SigV4Guard) RegisterKey(id, secret, tenantID string) error {
	return errNotImplemented
}

// CanonicalQuery returns the canonical query string: names and values
// percent-encoded with upper-case hex, sorted by encoded name and then by
// encoded value, joined with "&". A parameter without "=" keeps an empty
// value.
func (g *SigV4Guard) CanonicalQuery(rawQuery string) (string, error) {
	return "", errNotImplemented
}

// CanonicalURI encodes every path segment of a decoded path and rejects
// relative paths and dot segments.
func (g *SigV4Guard) CanonicalURI(path string) (string, error) {
	return "", errNotImplemented
}

// CanonicalHeaders returns the canonical header block (each line ends with a
// newline), the semicolon separated signed header list, and an error. Names are
// lower-cased, values are trimmed and inner whitespace runs collapsed, lines
// are sorted by name. The Host value is lower-cased as well. The Authorization
// header is never signed and Host is mandatory.
func (g *SigV4Guard) CanonicalHeaders(headers map[string]string) (string, string, error) {
	return "", "", errNotImplemented
}

// CanonicalRequest renders the canonical request of req, including the
// lower-case hex SHA-256 of the body.
func (g *SigV4Guard) CanonicalRequest(req Request) (string, error) {
	return "", errNotImplemented
}

// HashPayload returns the lower-case hex SHA-256 of body.
func (g *SigV4Guard) HashPayload(body []byte) string {
	return ""
}

// Sign returns the Authorization header value for req at the given instant.
func (g *SigV4Guard) Sign(req Request, accessKeyID string, at time.Time) (string, error) {
	return "", errNotImplemented
}

// Verify authenticates req, returns the access key id and records the
// signature so that a second use inside the replay window is refused.
func (g *SigV4Guard) Verify(req Request, now time.Time) (string, error) {
	return "", errNotImplemented
}

// Presign returns a query-signed URL valid for expires.
func (g *SigV4Guard) Presign(req Request, accessKeyID string, at time.Time, expires time.Duration) (string, error) {
	return "", errNotImplemented
}

// VerifyPresigned authenticates a presigned URL for the given HTTP method.
func (g *SigV4Guard) VerifyPresigned(method, rawURL string, now time.Time) error {
	return errNotImplemented
}

// ReplaySize reports how many signatures are currently remembered.
func (g *SigV4Guard) ReplaySize() int {
	return 0
}

// PruneReplay drops consumed signatures whose replay window has passed and
// returns how many were removed.
func (g *SigV4Guard) PruneReplay(now time.Time) int {
	return 0
}

// Snapshot serialises the consumed signature set so that a restarted edge keeps
// refusing replays.
func (g *SigV4Guard) Snapshot() ([]byte, error) {
	return nil, errNotImplemented
}
