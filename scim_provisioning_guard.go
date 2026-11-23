package task

import (
	"errors"
	"time"
)

// errNotImplemented is returned by stubs whose real logic is still missing.
var errNotImplemented = errors.New("not implemented")

// Sentinel errors returned by ScimGuard.
var (
	ErrInvalidUser     = errors.New("scim: invalid user")
	ErrVersionConflict = errors.New("scim: version conflict")
	ErrNotFound        = errors.New("scim: user not found")
	ErrDuplicateEmail  = errors.New("scim: duplicate email in tenant")
	ErrCapacity        = errors.New("scim: user limit reached")
	ErrBatchTooLarge   = errors.New("scim: batch too large")
	ErrInvalidPatch    = errors.New("scim: invalid patch operation")
	ErrDeleted         = errors.New("scim: user is deleted")
	ErrInvalidCursor   = errors.New("scim: invalid page cursor")
)

// User is one SCIM user resource as pushed by the identity provider.
type User struct {
	ID         string
	ExternalID string
	UserName   string
	Emails     []string
	Active     bool
	Groups     []string
	TenantID   string
	Version    int
	UpdatedAt  time.Time
}

// PatchOperation is one SCIM patch op. Path is "groups" or "userName"; Op is
// "add", "replace" or "remove".
type PatchOperation struct {
	Op    string
	Path  string
	Value string
}

// ApplyResult describes the outcome of an upsert.
type ApplyResult struct {
	UserID  string
	Version int
	Created bool
	Deleted bool
}

// ScimPolicy bounds the provisioning store.
type ScimPolicy struct {
	// MaxUsers bounds the number of live users across tenants.
	MaxUsers int
	// MaxBatch bounds one Batch call.
	MaxBatch int
	// TombstoneTTL is how long a deleted external id stays unusable.
	TombstoneTTL time.Duration
}

// ScimStats reports provisioning counters.
type ScimStats struct {
	Users      int
	Tombstones int
	Created    int
	Updated    int
	Deleted    int
}

// ScimGuard is an idempotent, versioned user store for incremental sync.
type ScimGuard struct {
	policy ScimPolicy
}

// NewScimGuard returns a guard configured by p.
func NewScimGuard(p ScimPolicy) *ScimGuard {
	return &ScimGuard{policy: p}
}

// NewScimGuardFromSnapshot restores users and tombstones from data produced by
// Snapshot.
func NewScimGuardFromSnapshot(p ScimPolicy, data []byte) (*ScimGuard, error) {
	return nil, errNotImplemented
}

// Apply upserts a user keyed by tenant and external id. When the payload is
// identical to the stored user the version is left untouched. A negative
// expectedVersion skips the optimistic concurrency check.
func (g *ScimGuard) Apply(user User, expectedVersion int) (ApplyResult, error) {
	return ApplyResult{}, errNotImplemented
}

// Patch applies group and user name operations to one user.
func (g *ScimGuard) Patch(tenantID, userID string, ops []PatchOperation, expectedVersion int) (ApplyResult, error) {
	return ApplyResult{}, errNotImplemented
}

// Delete tombstones a user identified by external id at the given instant.
func (g *ScimGuard) Delete(tenantID, externalID string, expectedVersion int, now time.Time) error {
	return errNotImplemented
}

// Get returns one user by id.
func (g *ScimGuard) Get(tenantID, userID string) (User, error) {
	return User{}, errNotImplemented
}

// ByExternalID returns one user by external id.
func (g *ScimGuard) ByExternalID(tenantID, externalID string) (User, error) {
	return User{}, errNotImplemented
}

// Batch applies every user or none of them.
func (g *ScimGuard) Batch(tenantID string, users []User) ([]ApplyResult, error) {
	return nil, errNotImplemented
}

// Page returns users ordered by user id after cursor. An empty next cursor
// means the last page was returned.
func (g *ScimGuard) Page(tenantID, cursor string, limit int) ([]User, string, error) {
	return nil, "", errNotImplemented
}

// Tombstoned reports whether the external id is inside an active tombstone.
func (g *ScimGuard) Tombstoned(tenantID, externalID string, now time.Time) (bool, error) {
	return false, errNotImplemented
}

// PruneTombstones drops expired tombstones and returns the removed count.
func (g *ScimGuard) PruneTombstones(now time.Time) int {
	return 0
}

// Snapshot serialises live users and tombstones.
func (g *ScimGuard) Snapshot(now time.Time) ([]byte, error) {
	return nil, errNotImplemented
}

// Stats returns the current counters.
func (g *ScimGuard) Stats() ScimStats {
	return ScimStats{}
}
