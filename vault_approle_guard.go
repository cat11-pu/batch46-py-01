package task

import (
	"errors"
	"time"
)

// errNotImplemented is returned by every stub that still has to be built.
var errNotImplemented = errors.New("not implemented")

// Errors returned by AppRoleGuard. A caller must be able to tell an expired
// SecretID from a revoked one and from a SecretID that still has uses left.
var (
	ErrRoleNotFound      = errors.New("approle: role not found")
	ErrRoleExists        = errors.New("approle: role already exists")
	ErrInvalidPolicy     = errors.New("approle: invalid role policy")
	ErrTooManyRoles      = errors.New("approle: role limit reached")
	ErrSecretIDNotFound  = errors.New("approle: secret id not found")
	ErrSecretIDExpired   = errors.New("approle: secret id expired")
	ErrSecretIDExhausted = errors.New("approle: secret id uses exhausted")
	ErrTooManySecretIDs  = errors.New("approle: secret id limit reached")
	ErrCIDRMismatch      = errors.New("approle: cidr not allowed")
	ErrRoleMismatch      = errors.New("approle: secret id belongs to another role")
	ErrSecretIDWrapped   = errors.New("approle: secret id is response wrapped")
	ErrWrapTokenUsed     = errors.New("approle: wrap token already used")
	ErrWrapTokenInvalid  = errors.New("approle: wrap token invalid")
)

// Config bounds the AppRole mount.
type Config struct {
	// MaxRoles is the maximum number of roles that may be registered.
	MaxRoles int
	// MaxSecretIDsPerRole caps the live SecretIDs of one role.
	MaxSecretIDsPerRole int
	// MaxSecretIDTTL caps the requested SecretID TTL.
	MaxSecretIDTTL time.Duration
	// MaxSecretIDUses caps the requested number of logins per SecretID.
	MaxSecretIDUses int
	// MaxTokenTTL caps the TTL of issued tokens.
	MaxTokenTTL time.Duration
}

// RolePolicy is the login policy of one AppRole.
type RolePolicy struct {
	RoleID string
	// BoundCIDRs is the list of networks logins may come from. An empty list
	// means the role is not CIDR bound.
	BoundCIDRs []string
	// SecretIDTTL is the lifetime of a freshly issued SecretID.
	SecretIDTTL time.Duration
	// SecretIDUses is the number of logins a SecretID allows.
	SecretIDUses int
	// TokenTTL is the lifetime of a token issued by Login.
	TokenTTL time.Duration
}

// SecretID is a login credential issued for one role and one CIDR.
type SecretID struct {
	Value     string
	Accessor  string
	RoleID    string
	CIDR      string
	ExpiresAt time.Time
	UsesLeft  int
	// Wrapped reports that the SecretID was handed out response-wrapped and
	// must be unwrapped before it can be used to log in.
	Wrapped bool
}

// Token is a login token.
type Token struct {
	Value     string
	RoleID    string
	ExpiresAt time.Time
}

// LoginRequest carries the credentials presented to Login.
type LoginRequest struct {
	RoleID     string
	SecretID   string
	ClientCIDR string
}

// AppRoleGuard validates AppRole logins and tracks SecretID use.
type AppRoleGuard struct {
	cfg Config
}

// NewAppRoleGuard returns an empty guard configured by cfg.
func NewAppRoleGuard(cfg Config) *AppRoleGuard {
	return &AppRoleGuard{cfg: cfg}
}

// NewAppRoleGuardFromSnapshot restores roles and SecretIDs from a snapshot.
func NewAppRoleGuardFromSnapshot(cfg Config, data []byte) (*AppRoleGuard, error) {
	return nil, errNotImplemented
}

// RegisterRole validates a policy, caps its TTL and use count, and stores it.
func (g *AppRoleGuard) RegisterRole(p RolePolicy) error {
	return errNotImplemented
}

// GetRole returns the stored policy of roleID.
func (g *AppRoleGuard) GetRole(roleID string) (RolePolicy, error) {
	return RolePolicy{}, errNotImplemented
}

// DeleteRole removes a role together with all of its SecretIDs.
func (g *AppRoleGuard) DeleteRole(roleID string) error {
	return errNotImplemented
}

// IssueSecretID mints a SecretID for roleID bound to cidr.
func (g *AppRoleGuard) IssueSecretID(roleID, cidr string, now time.Time) (SecretID, error) {
	return SecretID{}, errNotImplemented
}

// WrapSecretID marks the SecretID with the given accessor as response-wrapped
// and returns a single-use wrap token.
func (g *AppRoleGuard) WrapSecretID(accessor string, now time.Time) (string, error) {
	return "", errNotImplemented
}

// UnwrapSecretID exchanges a wrap token for the wrapped SecretID.
func (g *AppRoleGuard) UnwrapSecretID(wrapToken string, now time.Time) (SecretID, error) {
	return SecretID{}, errNotImplemented
}

// RevokeSecretID destroys one SecretID and any wrap token pointing at it.
func (g *AppRoleGuard) RevokeSecretID(accessor string) error {
	return errNotImplemented
}

// LookupSecretID returns the metadata of a live SecretID.
func (g *AppRoleGuard) LookupSecretID(accessor string, now time.Time) (SecretID, error) {
	return SecretID{}, errNotImplemented
}

// Login consumes one use of the SecretID and returns a token.
func (g *AppRoleGuard) Login(req LoginRequest, now time.Time) (Token, error) {
	return Token{}, errNotImplemented
}

// CountSecretIDs returns the number of live SecretIDs of roleID.
func (g *AppRoleGuard) CountSecretIDs(roleID string) (int, error) {
	return 0, errNotImplemented
}

// PruneExpired drops expired SecretIDs and their wrap tokens.
func (g *AppRoleGuard) PruneExpired(now time.Time) int {
	return 0
}

// Snapshot serialises roles, SecretIDs and wrap tokens.
func (g *AppRoleGuard) Snapshot() ([]byte, error) {
	return nil, errNotImplemented
}
