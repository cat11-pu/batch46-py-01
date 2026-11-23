package task

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	taskpkg "gsb/batch46-safety-a-04"
)

const baseUnix = 1730000000

func testPolicy() taskpkg.ScimPolicy {
	return taskpkg.ScimPolicy{
		MaxUsers:     100,
		MaxBatch:     10,
		TombstoneTTL: 24 * time.Hour,
	}
}

func newUser(externalID, userName string, emails, groups []string) taskpkg.User {
	return taskpkg.User{
		ExternalID: externalID,
		UserName:   userName,
		Emails:     emails,
		Active:     true,
		Groups:     groups,
		TenantID:   "tenant-a",
	}
}

func alice() taskpkg.User {
	return newUser(
		"ext-1",
		"alice@corp.example.com",
		[]string{"alice@corp.example.com", "a.liu@corp.example.com"},
		[]string{"sre", "eng"},
	)
}

// A first apply creates the user with a derived id and normalised lists.
func TestApplyCreatesUserWithDerivedID(t *testing.T) {
	g := taskpkg.NewScimGuard(testPolicy())
	result, err := g.Apply(alice(), 0)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !result.Created || result.Deleted {
		t.Fatalf("unexpected flags: %+v", result)
	}
	if result.UserID != "tenant-a/ext-1" || result.Version != 1 {
		t.Fatalf("derived id or version wrong: %+v", result)
	}
	stored, err := g.ByExternalID("tenant-a", "ext-1")
	if err != nil {
		t.Fatalf("ByExternalID: %v", err)
	}
	if stored.UserName != "alice@corp.example.com" {
		t.Fatalf("user name mismatch: %q", stored.UserName)
	}
	if len(stored.Emails) != 2 || stored.Emails[0] != "a.liu@corp.example.com" || stored.Emails[1] != "alice@corp.example.com" {
		t.Fatalf("emails not normalised: %#v", stored.Emails)
	}
	if len(stored.Groups) != 2 || stored.Groups[0] != "eng" || stored.Groups[1] != "sre" {
		t.Fatalf("groups not normalised: %#v", stored.Groups)
	}
	if got := g.Stats().Users; got != 1 {
		t.Fatalf("Users = %d, want 1", got)
	}
}

// Re-applying an identical payload must not bump the version even when the
// caller sends a stale expected version.
func TestApplyIdenticalPayloadKeepsVersion(t *testing.T) {
	g := taskpkg.NewScimGuard(testPolicy())
	if _, err := g.Apply(alice(), 0); err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	result, err := g.Apply(alice(), 0)
	if err != nil {
		t.Fatalf("idempotent Apply: %v", err)
	}
	if result.Created || result.Version != 1 {
		t.Fatalf("identical payload changed the user: %+v", result)
	}
	if got := g.Stats().Updated; got != 0 {
		t.Fatalf("Updated = %d, want 0", got)
	}
	if got := g.Stats().Users; got != 1 {
		t.Fatalf("duplicate user created, Users = %d", got)
	}
}

// A real change with the current version bumps the version once.
func TestApplyChangedPayloadBumpsVersion(t *testing.T) {
	g := taskpkg.NewScimGuard(testPolicy())
	if _, err := g.Apply(alice(), 0); err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	changed := alice()
	changed.UserName = "alice.liu@corp.example.com"
	changed.Groups = []string{"sre", "platform", "eng"}
	result, err := g.Apply(changed, 1)
	if err != nil {
		t.Fatalf("update Apply: %v", err)
	}
	if result.Created || result.Version != 2 {
		t.Fatalf("update result wrong: %+v", result)
	}
	stored, err := g.Get("tenant-a", "tenant-a/ext-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if stored.UserName != "alice.liu@corp.example.com" {
		t.Fatalf("user name not updated: %q", stored.UserName)
	}
	if len(stored.Groups) != 3 || stored.Groups[1] != "platform" {
		t.Fatalf("groups not updated or not sorted: %#v", stored.Groups)
	}
	if got := g.Stats().Updated; got != 1 {
		t.Fatalf("Updated = %d, want 1", got)
	}
}

// A stale version on a real change must be rejected without a write.
func TestStaleVersionRejected(t *testing.T) {
	g := taskpkg.NewScimGuard(testPolicy())
	if _, err := g.Apply(alice(), 0); err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	changed := alice()
	changed.UserName = "alice.liu@corp.example.com"
	if _, err := g.Apply(changed, 0); !errors.Is(err, taskpkg.ErrVersionConflict) {
		t.Fatalf("want ErrVersionConflict, got %v", err)
	}
	stored, err := g.Get("tenant-a", "tenant-a/ext-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if stored.Version != 1 || stored.UserName != "alice@corp.example.com" {
		t.Fatalf("conflicting update was applied: %+v", stored)
	}
}

// Two users in one tenant must not share an email address.
func TestDuplicateEmailInTenantRejected(t *testing.T) {
	g := taskpkg.NewScimGuard(testPolicy())
	if _, err := g.Apply(alice(), 0); err != nil {
		t.Fatalf("Apply(alice): %v", err)
	}
	bob := newUser("ext-2", "bob@corp.example.com", []string{"alice@corp.example.com"}, []string{"eng"})
	if _, err := g.Apply(bob, 0); !errors.Is(err, taskpkg.ErrDuplicateEmail) {
		t.Fatalf("want ErrDuplicateEmail, got %v", err)
	}
	if _, err := g.ByExternalID("tenant-a", "ext-2"); !errors.Is(err, taskpkg.ErrNotFound) {
		t.Fatalf("rejected user was stored anyway: %v", err)
	}
	if got := g.Stats().Users; got != 1 {
		t.Fatalf("Users = %d, want 1", got)
	}
}

// Email uniqueness is scoped to a tenant.
func TestSameEmailAcrossTenantsAllowed(t *testing.T) {
	g := taskpkg.NewScimGuard(testPolicy())
	if _, err := g.Apply(alice(), 0); err != nil {
		t.Fatalf("Apply(tenant-a): %v", err)
	}
	other := alice()
	other.TenantID = "tenant-b"
	other.ExternalID = "ext-1"
	result, err := g.Apply(other, 0)
	if err != nil {
		t.Fatalf("Apply(tenant-b): %v", err)
	}
	if result.UserID != "tenant-b/ext-1" || !result.Created {
		t.Fatalf("tenant-b user not created independently: %+v", result)
	}
	if _, err := g.Get("tenant-b", "tenant-b/ext-1"); err != nil {
		t.Fatalf("Get(tenant-b): %v", err)
	}
	if got := g.Stats().Users; got != 2 {
		t.Fatalf("Users = %d, want 2", got)
	}
}

// Deleting a user leaves a tombstone and removes it from the live store.
func TestDeleteCreatesTombstone(t *testing.T) {
	now := time.Unix(baseUnix, 0)
	g := taskpkg.NewScimGuard(testPolicy())
	result, err := g.Apply(alice(), 0)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if err := g.Delete("tenant-a", "ext-1", result.Version, now); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := g.Get("tenant-a", result.UserID); !errors.Is(err, taskpkg.ErrNotFound) {
		t.Fatalf("deleted user still readable: %v", err)
	}
	tombstoned, err := g.Tombstoned("tenant-a", "ext-1", now)
	if err != nil {
		t.Fatalf("Tombstoned: %v", err)
	}
	if !tombstoned {
		t.Fatalf("delete did not leave a tombstone")
	}
	stats := g.Stats()
	if stats.Users != 0 || stats.Tombstones != 1 || stats.Deleted != 1 {
		t.Fatalf("stats after delete wrong: %+v", stats)
	}
}

// A tombstoned external id must not be recreated while the tombstone is live.
func TestApplyAfterDeleteRejectedWhileTombstoned(t *testing.T) {
	g := taskpkg.NewScimGuard(testPolicy())
	result, err := g.Apply(alice(), 0)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if err := g.Delete("tenant-a", "ext-1", result.Version, time.Unix(baseUnix, 0)); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := g.Apply(alice(), 0); !errors.Is(err, taskpkg.ErrDeleted) {
		t.Fatalf("want ErrDeleted, got %v", err)
	}
}

// Patch adds and removes groups, sorting the result and bumping once.
func TestPatchAddsAndRemovesGroups(t *testing.T) {
	g := taskpkg.NewScimGuard(testPolicy())
	result, err := g.Apply(alice(), 0)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	patched, err := g.Patch("tenant-a", result.UserID, []taskpkg.PatchOperation{
		{Op: "add", Path: "groups", Value: "team-x"},
		{Op: "remove", Path: "groups", Value: "eng"},
	}, result.Version)
	if err != nil {
		t.Fatalf("Patch: %v", err)
	}
	if patched.Version != 2 || patched.Created {
		t.Fatalf("patch result wrong: %+v", patched)
	}
	stored, err := g.Get("tenant-a", result.UserID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(stored.Groups) != 2 || stored.Groups[0] != "sre" || stored.Groups[1] != "team-x" {
		t.Fatalf("groups after patch: %#v", stored.Groups)
	}
	if got := g.Stats().Updated; got != 1 {
		t.Fatalf("Updated = %d, want 1", got)
	}
}

// Unknown patch ops or paths must be rejected before mutating the user.
func TestPatchUnknownOperationRejected(t *testing.T) {
	g := taskpkg.NewScimGuard(testPolicy())
	result, err := g.Apply(alice(), 0)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if _, err := g.Patch("tenant-a", result.UserID, []taskpkg.PatchOperation{
		{Op: "merge", Path: "groups", Value: "team-x"},
	}, result.Version); !errors.Is(err, taskpkg.ErrInvalidPatch) {
		t.Fatalf("want ErrInvalidPatch for an unknown op, got %v", err)
	}
	if _, err := g.Patch("tenant-a", result.UserID, []taskpkg.PatchOperation{
		{Op: "add", Path: "title", Value: "staff"},
	}, result.Version); !errors.Is(err, taskpkg.ErrInvalidPatch) {
		t.Fatalf("want ErrInvalidPatch for an unknown path, got %v", err)
	}
	stored, err := g.Get("tenant-a", result.UserID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if stored.Version != 1 {
		t.Fatalf("rejected patch bumped the version to %d", stored.Version)
	}
}

// A batch that fails validation must not write any of its users.
func TestBatchAllOrNothing(t *testing.T) {
	g := taskpkg.NewScimGuard(testPolicy())
	if _, err := g.Apply(alice(), 0); err != nil {
		t.Fatalf("Apply(alice): %v", err)
	}
	carol := newUser("ext-2", "carol@corp.example.com", []string{"carol@corp.example.com"}, []string{"eng"})
	duplicate := newUser("ext-3", "dave@corp.example.com", []string{"alice@corp.example.com"}, []string{"eng"})
	if _, err := g.Batch("tenant-a", []taskpkg.User{carol, duplicate}); !errors.Is(err, taskpkg.ErrDuplicateEmail) {
		t.Fatalf("want ErrDuplicateEmail, got %v", err)
	}
	if _, err := g.ByExternalID("tenant-a", "ext-2"); !errors.Is(err, taskpkg.ErrNotFound) {
		t.Fatalf("batch partially applied: %v", err)
	}
	if got := g.Stats().Users; got != 1 {
		t.Fatalf("Users = %d, want 1", got)
	}
}

// A batch larger than MaxBatch is rejected up front.
func TestBatchSizeLimit(t *testing.T) {
	p := testPolicy()
	p.MaxBatch = 2
	g := taskpkg.NewScimGuard(p)
	users := []taskpkg.User{
		newUser("ext-1", "u1@corp.example.com", []string{"u1@corp.example.com"}, nil),
		newUser("ext-2", "u2@corp.example.com", []string{"u2@corp.example.com"}, nil),
		newUser("ext-3", "u3@corp.example.com", []string{"u3@corp.example.com"}, nil),
	}
	if _, err := g.Batch("tenant-a", users); !errors.Is(err, taskpkg.ErrBatchTooLarge) {
		t.Fatalf("want ErrBatchTooLarge, got %v", err)
	}
	if got := g.Stats().Users; got != 0 {
		t.Fatalf("oversized batch wrote users: %d", got)
	}
}

// Paging must follow user id order and hand back a stable cursor.
func TestPaginationStableOrder(t *testing.T) {
	g := taskpkg.NewScimGuard(testPolicy())
	for i := 1; i <= 5; i++ {
		user := newUser(
			fmt.Sprintf("ext-%d", i),
			fmt.Sprintf("user%d@corp.example.com", i),
			[]string{fmt.Sprintf("user%d@corp.example.com", i)},
			[]string{"eng"},
		)
		if _, err := g.Apply(user, 0); err != nil {
			t.Fatalf("Apply ext-%d: %v", i, err)
		}
	}
	first, cursor1, err := g.Page("tenant-a", "", 2)
	if err != nil {
		t.Fatalf("Page 1: %v", err)
	}
	if len(first) != 2 || first[0].ID != "tenant-a/ext-1" || first[1].ID != "tenant-a/ext-2" {
		t.Fatalf("page 1 wrong: %+v", first)
	}
	if cursor1 != "tenant-a/ext-2" {
		t.Fatalf("cursor 1 = %q, want tenant-a/ext-2", cursor1)
	}
	second, cursor2, err := g.Page("tenant-a", cursor1, 2)
	if err != nil {
		t.Fatalf("Page 2: %v", err)
	}
	if len(second) != 2 || second[0].ID != "tenant-a/ext-3" || second[1].ID != "tenant-a/ext-4" {
		t.Fatalf("page 2 wrong: %+v", second)
	}
	third, cursor3, err := g.Page("tenant-a", cursor2, 2)
	if err != nil {
		t.Fatalf("Page 3: %v", err)
	}
	if len(third) != 1 || third[0].ID != "tenant-a/ext-5" {
		t.Fatalf("page 3 wrong: %+v", third)
	}
	if cursor3 != "" {
		t.Fatalf("final cursor = %q, want empty", cursor3)
	}
}

// Concurrent upserts of one external id must create the user exactly once.
func TestConcurrentApplySameExternalIDSingleCreate(t *testing.T) {
	g := taskpkg.NewScimGuard(testPolicy())
	const workers = 8
	results := make([]taskpkg.ApplyResult, workers)
	errs := make([]error, workers)
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func(idx int) {
			defer wg.Done()
			results[idx], errs[idx] = g.Apply(alice(), -1)
		}(i)
	}
	wg.Wait()
	created := 0
	for i := 0; i < workers; i++ {
		if errs[i] != nil {
			t.Fatalf("worker %d failed: %v", i, errs[i])
		}
		if results[i].Created {
			created++
		}
		if results[i].Version != 1 {
			t.Fatalf("worker %d saw version %d, want 1", i, results[i].Version)
		}
	}
	if created != 1 {
		t.Fatalf("want exactly one create, got %d", created)
	}
	stats := g.Stats()
	if stats.Users != 1 || stats.Created != 1 {
		t.Fatalf("stats after concurrent upsert: %+v", stats)
	}
}

// Users and tombstones must survive a restart.
func TestSnapshotRestoresUsersAndTombstones(t *testing.T) {
	now := time.Unix(baseUnix, 0)
	g := taskpkg.NewScimGuard(testPolicy())
	live, err := g.Apply(alice(), 0)
	if err != nil {
		t.Fatalf("Apply(alice): %v", err)
	}
	bob := newUser("ext-2", "bob@corp.example.com", []string{"bob@corp.example.com"}, []string{"eng"})
	gone, err := g.Apply(bob, 0)
	if err != nil {
		t.Fatalf("Apply(bob): %v", err)
	}
	if err := g.Delete("tenant-a", "ext-2", gone.Version, now); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	snapshot, err := g.Snapshot(now)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	restored, err := taskpkg.NewScimGuardFromSnapshot(testPolicy(), snapshot)
	if err != nil {
		t.Fatalf("NewScimGuardFromSnapshot: %v", err)
	}
	got, err := restored.ByExternalID("tenant-a", "ext-1")
	if err != nil {
		t.Fatalf("ByExternalID after restart: %v", err)
	}
	if got.ID != live.UserID || got.Version != 1 {
		t.Fatalf("restored user mismatch: %+v", got)
	}
	if _, err := restored.Get("tenant-a", gone.UserID); !errors.Is(err, taskpkg.ErrNotFound) {
		t.Fatalf("deleted user came back after restart: %v", err)
	}
	tombstoned, err := restored.Tombstoned("tenant-a", "ext-2", now)
	if err != nil {
		t.Fatalf("Tombstoned: %v", err)
	}
	if !tombstoned {
		t.Fatalf("tombstone lost across restart")
	}
	stats := restored.Stats()
	if stats.Users != 1 || stats.Tombstones != 1 {
		t.Fatalf("restored stats wrong: %+v", stats)
	}
	if removed := restored.PruneTombstones(now.Add(25 * time.Hour)); removed != 1 {
		t.Fatalf("PruneTombstones removed %d, want 1", removed)
	}
	tombstoned, err = restored.Tombstoned("tenant-a", "ext-2", now.Add(25*time.Hour))
	if err != nil {
		t.Fatalf("Tombstoned after prune: %v", err)
	}
	if tombstoned {
		t.Fatalf("expired tombstone was not pruned")
	}
}
