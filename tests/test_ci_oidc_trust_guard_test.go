package task

import (
	"errors"
	"sync"
	"testing"
	"time"

	taskpkg "gsb/batch46-safety-b-02"
)

const ghaIssuer = "https://token.actions.githubusercontent.com"

func oidcConfig() taskpkg.Config {
	return taskpkg.Config{
		MaxPolicies:      6,
		MaxTokenLifetime: 15 * time.Minute,
		ClockSkew:        30 * time.Second,
		ReplayTTL:        time.Hour,
	}
}

func githubPolicy() taskpkg.TrustPolicy {
	return taskpkg.TrustPolicy{
		Name:            "gha-payments",
		Issuer:          ghaIssuer,
		Audiences:       []string{"sts.example.com"},
		SubjectPatterns: []string{"repo:acme/payments:ref:refs/heads/*", "repo:acme/payments:pull_request"},
		RefPatterns:     []string{"refs/heads/main"},
		MaxTTL:          10 * time.Minute,
	}
}

func oidcClaims(now time.Time) taskpkg.Claims {
	return taskpkg.Claims{
		Issuer:    ghaIssuer,
		Subject:   "repo:acme/payments:ref:refs/heads/main",
		Audience:  "sts.example.com",
		Ref:       "refs/heads/main",
		JTI:       "jti-1",
		IssuedAt:  now,
		ExpiresAt: now.Add(5 * time.Minute),
	}
}

func mustAddPolicy(t *testing.T, g *taskpkg.CiOidcGuard, p taskpkg.TrustPolicy) {
	t.Helper()
	if err := g.AddPolicy(p); err != nil {
		t.Fatalf("AddPolicy(%s): %v", p.Name, err)
	}
}

// Two policies with the same name must not silently replace each other.
func TestAddPolicyRejectsDuplicateName(t *testing.T) {
	g := taskpkg.NewCiOidcGuard(oidcConfig())
	p := githubPolicy()
	if err := g.AddPolicy(p); err != nil {
		t.Fatalf("first AddPolicy: %v", err)
	}
	if err := g.AddPolicy(p); !errors.Is(err, taskpkg.ErrPolicyExists) {
		t.Fatalf("duplicate AddPolicy err = %v, want ErrPolicyExists", err)
	}
}

// A trailing double wildcard is not a supported subject pattern.
func TestAddPolicyRejectsUnsupportedPattern(t *testing.T) {
	g := taskpkg.NewCiOidcGuard(oidcConfig())
	p := githubPolicy()
	p.SubjectPatterns = []string{"repo:acme/**"}
	if err := g.AddPolicy(p); !errors.Is(err, taskpkg.ErrInvalidPolicy) {
		t.Fatalf("AddPolicy with ** pattern err = %v, want ErrInvalidPolicy", err)
	}
}

// The trust store must stop accepting new policies at the configured limit.
func TestAddPolicyEnforcesMaxPolicies(t *testing.T) {
	cfg := oidcConfig()
	cfg.MaxPolicies = 1
	g := taskpkg.NewCiOidcGuard(cfg)
	mustAddPolicy(t, g, githubPolicy())

	second := githubPolicy()
	second.Name = "gha-other"
	if err := g.AddPolicy(second); !errors.Is(err, taskpkg.ErrTooManyPolicies) {
		t.Fatalf("second AddPolicy err = %v, want ErrTooManyPolicies", err)
	}
}

// A token from an issuer with no policy must not be evaluated at all.
func TestEvaluateRejectsUntrustedIssuer(t *testing.T) {
	g := taskpkg.NewCiOidcGuard(oidcConfig())
	mustAddPolicy(t, g, githubPolicy())
	now := time.Unix(1700000000, 0)
	c := oidcClaims(now)
	c.Issuer = "https://gitlab.example.com"

	if _, err := g.Evaluate(c, now); !errors.Is(err, taskpkg.ErrIssuerMismatch) {
		t.Fatalf("Evaluate untrusted issuer err = %v, want ErrIssuerMismatch", err)
	}
}

// The audience claim must be one of the audiences allowed by the policy.
func TestEvaluateRejectsForeignAudience(t *testing.T) {
	g := taskpkg.NewCiOidcGuard(oidcConfig())
	mustAddPolicy(t, g, githubPolicy())
	now := time.Unix(1700000000, 0)
	c := oidcClaims(now)
	c.Audience = "sts.other.example.com"

	if _, err := g.Evaluate(c, now); !errors.Is(err, taskpkg.ErrAudienceMismatch) {
		t.Fatalf("Evaluate foreign audience err = %v, want ErrAudienceMismatch", err)
	}
}

// A wildcard may not absorb the colon boundary, so a lookalike repository is
// not covered by the payments policy.
func TestEvaluateSubjectWildcardStopsAtSegmentBoundary(t *testing.T) {
	g := taskpkg.NewCiOidcGuard(oidcConfig())
	mustAddPolicy(t, g, githubPolicy())
	now := time.Unix(1700000000, 0)
	c := oidcClaims(now)
	c.Subject = "repo:acme/payments-evil:ref:refs/heads/main"

	if _, err := g.Evaluate(c, now); !errors.Is(err, taskpkg.ErrSubjectMismatch) {
		t.Fatalf("Evaluate lookalike subject err = %v, want ErrSubjectMismatch", err)
	}
}

// A token for a feature branch must not satisfy a main-only policy.
func TestEvaluateRejectsRefOutsidePolicy(t *testing.T) {
	g := taskpkg.NewCiOidcGuard(oidcConfig())
	mustAddPolicy(t, g, githubPolicy())
	now := time.Unix(1700000000, 0)
	c := oidcClaims(now)
	c.Ref = "refs/heads/feature/payouts"

	if _, err := g.Evaluate(c, now); !errors.Is(err, taskpkg.ErrRefNotAllowed) {
		t.Fatalf("Evaluate feature ref err = %v, want ErrRefNotAllowed", err)
	}
}

// An already expired token must be rejected before any grant is written.
func TestEvaluateRejectsExpiredToken(t *testing.T) {
	g := taskpkg.NewCiOidcGuard(oidcConfig())
	mustAddPolicy(t, g, githubPolicy())
	now := time.Unix(1700000000, 0)
	c := oidcClaims(now)
	c.IssuedAt = now.Add(-time.Hour)
	c.ExpiresAt = now.Add(-30 * time.Minute)

	if _, err := g.Evaluate(c, now); !errors.Is(err, taskpkg.ErrTokenExpired) {
		t.Fatalf("Evaluate expired token err = %v, want ErrTokenExpired", err)
	}
}

// A token that lives longer than the policy permits must not be shortened
// silently; it is rejected.
func TestEvaluateRejectsOverlongTokenLifetime(t *testing.T) {
	g := taskpkg.NewCiOidcGuard(oidcConfig())
	mustAddPolicy(t, g, githubPolicy())
	now := time.Unix(1700000000, 0)
	c := oidcClaims(now)
	c.ExpiresAt = now.Add(time.Hour)

	if _, err := g.Evaluate(c, now); !errors.Is(err, taskpkg.ErrTokenLifetime) {
		t.Fatalf("Evaluate 1h token err = %v, want ErrTokenLifetime", err)
	}
}

// A token issued slightly ahead of the server clock is still usable inside the
// skew, and the grant carries the policy identity.
func TestEvaluateAcceptsIssuedAtInsideClockSkew(t *testing.T) {
	g := taskpkg.NewCiOidcGuard(oidcConfig())
	mustAddPolicy(t, g, githubPolicy())
	now := time.Unix(1700000000, 0)
	c := oidcClaims(now)
	c.IssuedAt = now.Add(20 * time.Second)

	grant, err := g.Evaluate(c, now)
	if err != nil {
		t.Fatalf("Evaluate inside skew: %v", err)
	}
	if grant.Policy != "gha-payments" || grant.Subject != c.Subject || grant.ExpiresAt != c.ExpiresAt {
		t.Fatalf("grant = %+v, want policy gha-payments and the claim subject/expiry", grant)
	}
}

// The same token id must not be exchanged twice inside the replay window.
func TestEvaluateRejectsReplayedToken(t *testing.T) {
	g := taskpkg.NewCiOidcGuard(oidcConfig())
	mustAddPolicy(t, g, githubPolicy())
	now := time.Unix(1700000000, 0)
	c := oidcClaims(now)
	if _, err := g.Evaluate(c, now); err != nil {
		t.Fatalf("first Evaluate: %v", err)
	}
	if _, err := g.Evaluate(c, now); !errors.Is(err, taskpkg.ErrReplay) {
		t.Fatalf("second Evaluate err = %v, want ErrReplay", err)
	}
}

// Token ids are scoped to an issuer: the same id from another trusted issuer
// is a different token.
func TestReplayWindowIsScopedPerIssuer(t *testing.T) {
	g := taskpkg.NewCiOidcGuard(oidcConfig())
	mustAddPolicy(t, g, githubPolicy())
	gitlab := githubPolicy()
	gitlab.Name = "gitlab-payments"
	gitlab.Issuer = "https://gitlab.example.com"
	mustAddPolicy(t, g, gitlab)
	now := time.Unix(1700000000, 0)

	first := oidcClaims(now)
	second := oidcClaims(now)
	second.Issuer = gitlab.Issuer
	second.JTI = first.JTI
	if _, err := g.Evaluate(first, now); err != nil {
		t.Fatalf("Evaluate github token: %v", err)
	}
	if _, err := g.Evaluate(second, now); err != nil {
		t.Fatalf("Evaluate gitlab token with the same jti: %v", err)
	}
}

// Concurrent submissions of one token must produce a single grant.
func TestConcurrentEvaluateGrantsTokenOnce(t *testing.T) {
	g := taskpkg.NewCiOidcGuard(oidcConfig())
	mustAddPolicy(t, g, githubPolicy())
	now := time.Unix(1700000000, 0)
	c := oidcClaims(now)

	const workers = 12
	errs := make([]error, workers)
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func(idx int) {
			defer wg.Done()
			_, errs[idx] = g.Evaluate(c, now)
		}(i)
	}
	wg.Wait()

	grants := 0
	for _, err := range errs {
		if err == nil {
			grants++
		}
	}
	if grants != 1 {
		t.Fatalf("concurrent Evaluate produced %d grants, want exactly 1", grants)
	}
}

// The replay store must survive a restart so an old token cannot be exchanged
// again after the process comes back.
func TestSnapshotRestoresTrustStoreAndReplayWindow(t *testing.T) {
	g := taskpkg.NewCiOidcGuard(oidcConfig())
	mustAddPolicy(t, g, githubPolicy())
	now := time.Unix(1700000000, 0)
	c := oidcClaims(now)
	c.JTI = "jti-persist"
	if _, err := g.Evaluate(c, now); err != nil {
		t.Fatalf("Evaluate before snapshot: %v", err)
	}
	snap, err := g.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	restored, err := taskpkg.NewCiOidcGuardFromSnapshot(oidcConfig(), snap)
	if err != nil {
		t.Fatalf("NewCiOidcGuardFromSnapshot: %v", err)
	}
	if _, err := restored.Evaluate(c, now); !errors.Is(err, taskpkg.ErrReplay) {
		t.Fatalf("restored replay err = %v, want ErrReplay", err)
	}
	fresh := c
	fresh.JTI = "jti-after-restart"
	if _, err := restored.Evaluate(fresh, now); err != nil {
		t.Fatalf("restored policy rejected a fresh token: %v", err)
	}
}

// Deleting a policy must immediately stop grants for its issuer.
func TestRemovePolicyStopsFutureGrants(t *testing.T) {
	g := taskpkg.NewCiOidcGuard(oidcConfig())
	mustAddPolicy(t, g, githubPolicy())
	now := time.Unix(1700000000, 0)
	if err := g.RemovePolicy("gha-payments"); err != nil {
		t.Fatalf("RemovePolicy: %v", err)
	}
	if _, err := g.Evaluate(oidcClaims(now), now); !errors.Is(err, taskpkg.ErrIssuerMismatch) {
		t.Fatalf("Evaluate after policy removal err = %v, want ErrIssuerMismatch", err)
	}
	if _, err := g.Policy("gha-payments"); !errors.Is(err, taskpkg.ErrPolicyNotFound) {
		t.Fatalf("Policy after removal err = %v, want ErrPolicyNotFound", err)
	}
}
