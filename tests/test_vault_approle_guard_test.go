package task

import (
	"errors"
	"sync"
	"testing"
	"time"

	taskpkg "gsb/batch46-safety-b-01"
)

func approleConfig() taskpkg.Config {
	return taskpkg.Config{
		MaxRoles:            8,
		MaxSecretIDsPerRole: 16,
		MaxSecretIDTTL:      24 * time.Hour,
		MaxSecretIDUses:     10,
		MaxTokenTTL:         time.Hour,
	}
}

func baseRole(id string) taskpkg.RolePolicy {
	return taskpkg.RolePolicy{
		RoleID:       id,
		SecretIDTTL:  30 * time.Minute,
		SecretIDUses: 2,
		TokenTTL:     15 * time.Minute,
	}
}

func mustRegisterRole(t *testing.T, g *taskpkg.AppRoleGuard, p taskpkg.RolePolicy) {
	t.Helper()
	if err := g.RegisterRole(p); err != nil {
		t.Fatalf("RegisterRole(%s): %v", p.RoleID, err)
	}
}

func mustIssue(t *testing.T, g *taskpkg.AppRoleGuard, roleID, cidr string, now time.Time) taskpkg.SecretID {
	t.Helper()
	sid, err := g.IssueSecretID(roleID, cidr, now)
	if err != nil {
		t.Fatalf("IssueSecretID(%s, %q): %v", roleID, cidr, err)
	}
	if sid.Value == "" || sid.Accessor == "" {
		t.Fatalf("IssueSecretID returned an incomplete credential: %+v", sid)
	}
	return sid
}

// A requested TTL above the mount limit must be stored capped.
func TestRegisterRoleCapsSecretIDTTL(t *testing.T) {
	g := taskpkg.NewAppRoleGuard(approleConfig())
	p := baseRole("payments")
	p.SecretIDTTL = 48 * time.Hour
	mustRegisterRole(t, g, p)

	got, err := g.GetRole("payments")
	if err != nil {
		t.Fatalf("GetRole: %v", err)
	}
	if got.SecretIDTTL != 24*time.Hour {
		t.Fatalf("stored SecretIDTTL = %v, want the 24h mount cap", got.SecretIDTTL)
	}
}

// Registering the same role twice must not overwrite the first policy.
func TestRegisterRoleRejectsDuplicate(t *testing.T) {
	g := taskpkg.NewAppRoleGuard(approleConfig())
	p := baseRole("payments")
	if err := g.RegisterRole(p); err != nil {
		t.Fatalf("first RegisterRole: %v", err)
	}
	p.SecretIDUses = 9
	if err := g.RegisterRole(p); !errors.Is(err, taskpkg.ErrRoleExists) {
		t.Fatalf("duplicate RegisterRole err = %v, want ErrRoleExists", err)
	}
}

// A malformed bound network must be rejected at registration time.
func TestRegisterRoleRejectsMalformedCIDR(t *testing.T) {
	g := taskpkg.NewAppRoleGuard(approleConfig())
	p := baseRole("payments")
	p.BoundCIDRs = []string{"10.0.0.0/33"}
	if err := g.RegisterRole(p); !errors.Is(err, taskpkg.ErrInvalidPolicy) {
		t.Fatalf("RegisterRole with 10.0.0.0/33 err = %v, want ErrInvalidPolicy", err)
	}
}

// The mount-wide role limit must be enforced.
func TestRegisterRoleEnforcesMaxRoles(t *testing.T) {
	cfg := approleConfig()
	cfg.MaxRoles = 1
	g := taskpkg.NewAppRoleGuard(cfg)
	mustRegisterRole(t, g, baseRole("role-a"))
	if err := g.RegisterRole(baseRole("role-b")); !errors.Is(err, taskpkg.ErrTooManyRoles) {
		t.Fatalf("second role err = %v, want ErrTooManyRoles", err)
	}
}

// A SecretID must not be issued for a client network outside the role binding.
func TestIssueSecretIDRejectsCIDROutsideRoleBinding(t *testing.T) {
	g := taskpkg.NewAppRoleGuard(approleConfig())
	p := baseRole("payments")
	p.BoundCIDRs = []string{"10.0.0.0/8"}
	mustRegisterRole(t, g, p)

	if _, err := g.IssueSecretID("payments", "192.168.1.5", time.Unix(1700000000, 0)); !errors.Is(err, taskpkg.ErrCIDRMismatch) {
		t.Fatalf("issue for 192.168.1.5 err = %v, want ErrCIDRMismatch", err)
	}
}

// The per-SecretID use count must be capped by the mount configuration.
func TestIssueSecretIDCapsUses(t *testing.T) {
	cfg := approleConfig()
	cfg.MaxSecretIDUses = 5
	g := taskpkg.NewAppRoleGuard(cfg)
	p := baseRole("payments")
	p.SecretIDUses = 50
	mustRegisterRole(t, g, p)

	sid := mustIssue(t, g, "payments", "", time.Unix(1700000000, 0))
	if sid.UsesLeft != 5 {
		t.Fatalf("UsesLeft = %d, want the 5 use mount cap", sid.UsesLeft)
	}
}

// A role must not hold more live SecretIDs than the mount allows.
func TestIssueSecretIDEnforcesPerRoleLimit(t *testing.T) {
	cfg := approleConfig()
	cfg.MaxSecretIDsPerRole = 1
	g := taskpkg.NewAppRoleGuard(cfg)
	mustRegisterRole(t, g, baseRole("payments"))
	now := time.Unix(1700000000, 0)
	mustIssue(t, g, "payments", "", now)

	if _, err := g.IssueSecretID("payments", "", now); !errors.Is(err, taskpkg.ErrTooManySecretIDs) {
		t.Fatalf("second issue err = %v, want ErrTooManySecretIDs", err)
	}
}

// A single-use SecretID must allow exactly one login.
func TestLoginConsumesUsesAndRejectsExhaustedSecretID(t *testing.T) {
	g := taskpkg.NewAppRoleGuard(approleConfig())
	p := baseRole("payments")
	p.SecretIDUses = 1
	mustRegisterRole(t, g, p)
	now := time.Unix(1700000000, 0)
	sid := mustIssue(t, g, "payments", "", now)

	tok, err := g.Login(taskpkg.LoginRequest{RoleID: "payments", SecretID: sid.Value}, now)
	if err != nil {
		t.Fatalf("first Login: %v", err)
	}
	if tok.Value == "" || tok.RoleID != "payments" {
		t.Fatalf("Login returned an unexpected token: %+v", tok)
	}
	if _, err := g.Login(taskpkg.LoginRequest{RoleID: "payments", SecretID: sid.Value}, now); !errors.Is(err, taskpkg.ErrSecretIDExhausted) {
		t.Fatalf("second Login err = %v, want ErrSecretIDExhausted", err)
	}
}

// An expired SecretID must not produce a token.
func TestLoginRejectsExpiredSecretID(t *testing.T) {
	g := taskpkg.NewAppRoleGuard(approleConfig())
	p := baseRole("payments")
	p.SecretIDTTL = 10 * time.Minute
	mustRegisterRole(t, g, p)
	now := time.Unix(1700000000, 0)
	sid := mustIssue(t, g, "payments", "", now)

	if _, err := g.Login(taskpkg.LoginRequest{RoleID: "payments", SecretID: sid.Value}, now.Add(11*time.Minute)); !errors.Is(err, taskpkg.ErrSecretIDExpired) {
		t.Fatalf("Login after expiry err = %v, want ErrSecretIDExpired", err)
	}
}

// The login client address must equal the address the SecretID was issued for.
func TestLoginRejectsClientCIDRMismatch(t *testing.T) {
	g := taskpkg.NewAppRoleGuard(approleConfig())
	mustRegisterRole(t, g, baseRole("payments"))
	now := time.Unix(1700000000, 0)
	sid := mustIssue(t, g, "payments", "10.1.2.3", now)

	req := taskpkg.LoginRequest{RoleID: "payments", SecretID: sid.Value, ClientCIDR: "10.1.2.4"}
	if _, err := g.Login(req, now); !errors.Is(err, taskpkg.ErrCIDRMismatch) {
		t.Fatalf("Login from 10.1.2.4 err = %v, want ErrCIDRMismatch", err)
	}
}

// A SecretID issued for one role must not authenticate another role.
func TestLoginRejectsSecretIDOfAnotherRole(t *testing.T) {
	g := taskpkg.NewAppRoleGuard(approleConfig())
	mustRegisterRole(t, g, baseRole("role-a"))
	mustRegisterRole(t, g, baseRole("role-b"))
	now := time.Unix(1700000000, 0)
	sid := mustIssue(t, g, "role-b", "", now)

	req := taskpkg.LoginRequest{RoleID: "role-a", SecretID: sid.Value}
	if _, err := g.Login(req, now); !errors.Is(err, taskpkg.ErrRoleMismatch) {
		t.Fatalf("cross-role Login err = %v, want ErrRoleMismatch", err)
	}
}

// A response-wrapped SecretID cannot log in until it is unwrapped, and the
// wrap token works only once.
func TestWrappedSecretIDMustBeUnwrappedBeforeLogin(t *testing.T) {
	g := taskpkg.NewAppRoleGuard(approleConfig())
	mustRegisterRole(t, g, baseRole("payments"))
	now := time.Unix(1700000000, 0)
	sid := mustIssue(t, g, "payments", "", now)

	wrapToken, err := g.WrapSecretID(sid.Accessor, now)
	if err != nil {
		t.Fatalf("WrapSecretID: %v", err)
	}
	req := taskpkg.LoginRequest{RoleID: "payments", SecretID: sid.Value}
	if _, err := g.Login(req, now); !errors.Is(err, taskpkg.ErrSecretIDWrapped) {
		t.Fatalf("Login with wrapped SecretID err = %v, want ErrSecretIDWrapped", err)
	}

	unwrapped, err := g.UnwrapSecretID(wrapToken, now)
	if err != nil {
		t.Fatalf("UnwrapSecretID: %v", err)
	}
	if unwrapped.Wrapped || unwrapped.Value != sid.Value {
		t.Fatalf("unwrapped credential = %+v, want the original value and Wrapped=false", unwrapped)
	}
	if _, err := g.Login(req, now); err != nil {
		t.Fatalf("Login after unwrap: %v", err)
	}
	if _, err := g.UnwrapSecretID(wrapToken, now); !errors.Is(err, taskpkg.ErrWrapTokenUsed) {
		t.Fatalf("second UnwrapSecretID err = %v, want ErrWrapTokenUsed", err)
	}
}

// Revoking a SecretID must immediately stop logins with it.
func TestRevokeSecretIDBlocksLogin(t *testing.T) {
	g := taskpkg.NewAppRoleGuard(approleConfig())
	mustRegisterRole(t, g, baseRole("payments"))
	now := time.Unix(1700000000, 0)
	sid := mustIssue(t, g, "payments", "", now)

	if err := g.RevokeSecretID(sid.Accessor); err != nil {
		t.Fatalf("RevokeSecretID: %v", err)
	}
	req := taskpkg.LoginRequest{RoleID: "payments", SecretID: sid.Value}
	if _, err := g.Login(req, now); !errors.Is(err, taskpkg.ErrSecretIDNotFound) {
		t.Fatalf("Login after revocation err = %v, want ErrSecretIDNotFound", err)
	}
}

// Concurrent logins with a one-use SecretID must produce exactly one token.
func TestConcurrentLoginsUseSecretIDOnce(t *testing.T) {
	g := taskpkg.NewAppRoleGuard(approleConfig())
	p := baseRole("payments")
	p.SecretIDUses = 1
	mustRegisterRole(t, g, p)
	now := time.Unix(1700000000, 0)
	sid := mustIssue(t, g, "payments", "", now)

	const workers = 8
	errs := make([]error, workers)
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func(idx int) {
			defer wg.Done()
			_, errs[idx] = g.Login(taskpkg.LoginRequest{RoleID: "payments", SecretID: sid.Value}, now)
		}(i)
	}
	wg.Wait()

	successes := 0
	for _, err := range errs {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent logins obtained %d tokens, want exactly 1", successes)
	}
}

// A restart must not hand back uses that were already consumed.
func TestSnapshotRestoresConsumedUses(t *testing.T) {
	g := taskpkg.NewAppRoleGuard(approleConfig())
	mustRegisterRole(t, g, baseRole("payments"))
	now := time.Unix(1700000000, 0)
	sid := mustIssue(t, g, "payments", "", now)
	req := taskpkg.LoginRequest{RoleID: "payments", SecretID: sid.Value}
	if _, err := g.Login(req, now); err != nil {
		t.Fatalf("first Login: %v", err)
	}

	snap, err := g.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	restored, err := taskpkg.NewAppRoleGuardFromSnapshot(approleConfig(), snap)
	if err != nil {
		t.Fatalf("NewAppRoleGuardFromSnapshot: %v", err)
	}
	if n, err := restored.CountSecretIDs("payments"); err != nil || n != 1 {
		t.Fatalf("restored secret id count = %d (err %v), want 1", n, err)
	}
	if _, err := restored.Login(req, now); err != nil {
		t.Fatalf("restored Login with one use left: %v", err)
	}
	if _, err := restored.Login(req, now); !errors.Is(err, taskpkg.ErrSecretIDExhausted) {
		t.Fatalf("second restored Login err = %v, want ErrSecretIDExhausted", err)
	}
}
