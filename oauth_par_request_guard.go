package task

import (
	"errors"
	"time"
)

// errNotImplemented is returned by stubs whose real logic is still missing.
var errNotImplemented = errors.New("not implemented")

// RequestURIPrefix is the fixed prefix of every pushed request uri.
const RequestURIPrefix = "urn:ietf:params:oauth:request_uri:"

// Sentinel errors returned by ParGuard.
var (
	ErrClientUnknown    = errors.New("par: unknown client")
	ErrClientExists     = errors.New("par: client already registered")
	ErrClientRevoked    = errors.New("par: client revoked")
	ErrClientAuth       = errors.New("par: client authentication failed")
	ErrRedirectMismatch = errors.New("par: redirect uri mismatch")
	ErrScopeNotAllowed  = errors.New("par: scope not allowed")
	ErrResponseType     = errors.New("par: response type not allowed")
	ErrPKCE             = errors.New("par: invalid code challenge")
	ErrState            = errors.New("par: state required")
	ErrCapacity         = errors.New("par: too many pending requests")
	ErrRequestUnknown   = errors.New("par: unknown request uri")
	ErrRequestExpired   = errors.New("par: request uri expired")
	ErrRequestConsumed  = errors.New("par: request uri already used")
	ErrRequestOwner     = errors.New("par: request uri belongs to another client")
)

// Client is a registered OAuth client.
type Client struct {
	ID            string
	TenantID      string
	RedirectURIs  []string
	AllowedScopes []string
	Confidential  bool
	// SecretHash is the lower-case hex SHA-256 of the client secret. It is
	// only required for confidential clients.
	SecretHash string
}

// PARRequest is a pushed authorization request as submitted by a client.
type PARRequest struct {
	ClientID            string
	ClientSecret        string
	RedirectURI         string
	ResponseType        string
	Scope               string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
	Nonce               string
}

// PushedRequest is the server-side record behind a request uri.
type PushedRequest struct {
	RequestURI          string
	ClientID            string
	TenantID            string
	RedirectURI         string
	ResponseType        string
	Scopes              []string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
	Nonce               string
	ExpiresAt           time.Time
}

// ParPolicy is the validation policy for pushed requests.
type ParPolicy struct {
	// RequestURITTL is how long a request uri stays usable.
	RequestURITTL time.Duration
	// MaxPending bounds the number of outstanding request uris.
	MaxPending int
	// MinChallengeLen is the shortest accepted PKCE S256 challenge.
	MinChallengeLen int
	// AllowedResponseTypes lists the accepted response_type values.
	AllowedResponseTypes []string
}

// ParStats reports guard counters.
type ParStats struct {
	Pushed   int
	Consumed int
	Rejected int
	Pending  int
}

// ParGuard validates pushed authorization requests and tracks their use.
type ParGuard struct {
	policy ParPolicy
}

// NewParGuard returns a guard configured by p.
func NewParGuard(p ParPolicy) *ParGuard {
	return &ParGuard{policy: p}
}

// NewParGuardFromSnapshot restores registered clients, pending request uris and
// consumed markers from data produced by Snapshot.
func NewParGuardFromSnapshot(p ParPolicy, data []byte) (*ParGuard, error) {
	return nil, errNotImplemented
}

// RegisterClient records a client and its allowed redirect uris and scopes.
func (g *ParGuard) RegisterClient(c Client) error {
	return errNotImplemented
}

// RevokeClient rejects further pushes for a client.
func (g *ParGuard) RevokeClient(clientID string) error {
	return errNotImplemented
}

// Push validates req and returns a fresh request uri.
func (g *ParGuard) Push(req PARRequest, now time.Time) (string, error) {
	return "", errNotImplemented
}

// Consume returns the stored request and marks the request uri as used. The
// caller must present the client id the request uri was minted for.
func (g *ParGuard) Consume(requestURI, clientID string, now time.Time) (PushedRequest, error) {
	return PushedRequest{}, errNotImplemented
}

// Pending reports whether the request uri is still usable.
func (g *ParGuard) Pending(requestURI string, now time.Time) (bool, error) {
	return false, errNotImplemented
}

// Prune drops expired pending requests and old consumed markers, returning the count.
func (g *ParGuard) Prune(now time.Time) int {
	return 0
}

// Snapshot serialises clients, pending requests and consumed markers.
func (g *ParGuard) Snapshot(now time.Time) ([]byte, error) {
	return nil, errNotImplemented
}

// Stats returns the current counters.
func (g *ParGuard) Stats() ParStats {
	return ParStats{}
}

// SetRequestTTL changes the request uri lifetime.
func (g *ParGuard) SetRequestTTL(d time.Duration) error {
	return errNotImplemented
}

// RequestURIPrefix returns the fixed prefix used for minted request uris.
func (g *ParGuard) RequestURIPrefix() string {
	return RequestURIPrefix
}
