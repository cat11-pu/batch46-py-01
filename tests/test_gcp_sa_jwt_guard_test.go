package task

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	taskpkg "gsb/batch46-safety-a-09"
)

const (
	saEmail    = "etl-runner@data-platform.iam.gserviceaccount.com"
	audience   = "https://oauth2.googleapis.com/token"
	scopeRead  = "https://www.googleapis.com/auth/devstorage.read_only"
	scopeWrite = "https://www.googleapis.com/auth/devstorage.read_write"
	scopeCloud = "https://www.googleapis.com/auth/cloud-platform"
)

var t0 = time.Unix(1735689600, 0).UTC() // 2025-01-01T00:00:00Z

func gsaConfig() taskpkg.Config {
	return taskpkg.Config{
		Audience:        audience,
		MaxSkew:         time.Minute,
		MaxAssertionTTL: 15 * time.Minute,
		MaxDelegates:    3,
		AllowedScopes:   []string{scopeRead, scopeWrite, scopeCloud},
		TokenTTL:        time.Hour,
		QuotaPerWindow:  100,
		QuotaWindow:     time.Minute,
		JTITTL:          time.Hour,
	}
}

func gsaGuard(t *testing.T) *taskpkg.SaJwtGuard {
	t.Helper()
	g := taskpkg.NewSaJwtGuard(gsaConfig())
	if err := g.RegisterServiceAccount(saEmail, "data-platform"); err != nil {
		t.Fatalf("RegisterServiceAccount: %v", err)
	}
	return g
}

func assertion(jti string, now time.Time) taskpkg.Assertion {
	return taskpkg.Assertion{
		Issuer:         saEmail,
		Audience:       audience,
		JTI:            jti,
		IssuedAt:       now,
		ExpiresAt:      now.Add(5 * time.Minute),
		Scopes:         []string{scopeRead},
		SignatureValid: true,
	}
}

func exchange(t *testing.T, g *taskpkg.SaJwtGuard, a taskpkg.Assertion, now time.Time) taskpkg.AccessToken {
	t.Helper()
	tok, err := g.Exchange(a, now)
	if err != nil {
		t.Fatalf("Exchange(%s): %v", a.JTI, err)
	}
	return tok
}

func TestScopeSetDedupesAndSorts(t *testing.T) {
	g := gsaGuard(t)
	got, err := g.ScopeSet([]string{scopeWrite, scopeCloud, scopeWrite, " " + scopeRead + " "})
	if err != nil {
		t.Fatalf("ScopeSet: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("ScopeSet returned %d scopes, want 3: %v", len(got), got)
	}
	if got[0] != scopeCloud || got[1] != scopeRead || got[2] != scopeWrite {
		t.Fatalf("ScopeSet = %v, want [%s %s %s]", got, scopeCloud, scopeRead, scopeWrite)
	}
}

func TestScopeSetRejectsBadScopes(t *testing.T) {
	g := gsaGuard(t)
	for _, bad := range [][]string{nil, {}, {""}, {"   "}, {"not a url"}, {"no-slash"}} {
		if _, err := g.ScopeSet(bad); !errors.Is(err, taskpkg.ErrScope) {
			t.Fatalf("ScopeSet(%v) = %v, want ErrScope", bad, err)
		}
	}
}

func TestExchangeIssuesToken(t *testing.T) {
	g := gsaGuard(t)
	tok := exchange(t, g, assertion("jti-1", t0), t0)
	if tok.Issuer != saEmail || tok.Subject != saEmail {
		t.Fatalf("token identity = issuer %q subject %q, want both %q", tok.Issuer, tok.Subject, saEmail)
	}
	if len(tok.Scopes) != 1 || tok.Scopes[0] != scopeRead {
		t.Fatalf("token scopes = %v, want [%s]", tok.Scopes, scopeRead)
	}
	if !tok.ExpiresAt.Equal(t0.Add(time.Hour)) {
		t.Fatalf("token expiry = %v, want %v", tok.ExpiresAt, t0.Add(time.Hour))
	}
	if tok.Impersonated {
		t.Fatalf("plain exchange reported as impersonated")
	}
	if len(tok.Value) != 64 || strings.Trim(tok.Value, "0123456789abcdef") != "" {
		t.Fatalf("token value %q is not 64 lower-case hex characters", tok.Value)
	}
	other := exchange(t, g, assertion("jti-2", t0), t0)
	if other.Value == tok.Value {
		t.Fatalf("two exchanges produced the same token value %q", tok.Value)
	}
}

func TestAudienceMismatchRejected(t *testing.T) {
	g := gsaGuard(t)
	a := assertion("jti-aud", t0)
	a.Audience = "https://sts.example.com/v1/token"
	if _, err := g.Exchange(a, t0); !errors.Is(err, taskpkg.ErrAudience) {
		t.Fatalf("Exchange with a foreign audience = %v, want ErrAudience", err)
	}
}

func TestExpiredAndNotYetAssertions(t *testing.T) {
	g := gsaGuard(t)
	stale := assertion("jti-stale", t0)
	stale.IssuedAt = t0.Add(-10 * time.Minute)
	stale.ExpiresAt = t0.Add(-5 * time.Minute)
	if _, err := g.Exchange(stale, t0); !errors.Is(err, taskpkg.ErrExpired) {
		t.Fatalf("Exchange of a stale assertion = %v, want ErrExpired", err)
	}
	early := assertion("jti-early", t0.Add(10*time.Minute))
	if _, err := g.Exchange(early, t0); !errors.Is(err, taskpkg.ErrNotYet) {
		t.Fatalf("Exchange before iat minus skew = %v, want ErrNotYet", err)
	}
	if _, err := g.Exchange(early, t0.Add(9*time.Minute)); err != nil {
		t.Fatalf("Exchange exactly at iat minus skew = %v, want no error", err)
	}
}

func TestAssertionTTLBounds(t *testing.T) {
	g := gsaGuard(t)
	long := assertion("jti-long", t0)
	long.ExpiresAt = t0.Add(30 * time.Minute)
	if _, err := g.Exchange(long, t0); !errors.Is(err, taskpkg.ErrMalformed) {
		t.Fatalf("assertion with a thirty minute TTL = %v, want ErrMalformed", err)
	}
	backwards := assertion("jti-backwards", t0)
	backwards.ExpiresAt = t0
	if _, err := g.Exchange(backwards, t0); !errors.Is(err, taskpkg.ErrMalformed) {
		t.Fatalf("assertion that expires at iat = %v, want ErrMalformed", err)
	}
}

func TestSignatureAndUnknownIssuer(t *testing.T) {
	g := gsaGuard(t)
	bad := assertion("jti-sig", t0)
	bad.SignatureValid = false
	if _, err := g.Exchange(bad, t0); !errors.Is(err, taskpkg.ErrSignature) {
		t.Fatalf("Exchange of a bad signature = %v, want ErrSignature", err)
	}
	foreign := assertion("jti-foreign", t0)
	foreign.Issuer = "unknown@other-project.iam.gserviceaccount.com"
	if _, err := g.Exchange(foreign, t0); !errors.Is(err, taskpkg.ErrUnknownIssuer) {
		t.Fatalf("Exchange from an unregistered account = %v, want ErrUnknownIssuer", err)
	}
}

func TestReplaySingleUse(t *testing.T) {
	g := gsaGuard(t)
	exchange(t, g, assertion("jti-once", t0), t0)
	if _, err := g.Exchange(assertion("jti-once", t0.Add(time.Minute)), t0.Add(time.Minute)); !errors.Is(err, taskpkg.ErrReplay) {
		t.Fatalf("second exchange of the same jti = %v, want ErrReplay", err)
	}
	used, err := g.JTIUsed("jti-once")
	if err != nil || !used {
		t.Fatalf("JTIUsed = %v err=%v, want true", used, err)
	}
	if used, err := g.JTIUsed("jti-never"); err != nil || used {
		t.Fatalf("JTIUsed for an unseen id = %v err=%v, want false", used, err)
	}
	if _, err := g.JTIUsed(""); !errors.Is(err, taskpkg.ErrMalformed) {
		t.Fatalf("JTIUsed with an empty id = %v, want ErrMalformed", err)
	}
}

func TestConcurrentSameJTIYieldsOneToken(t *testing.T) {
	g := gsaGuard(t)
	const workers = 16
	var wg sync.WaitGroup
	tokens := make([]taskpkg.AccessToken, workers)
	errs := make([]error, workers)
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func(i int) {
			defer wg.Done()
			tokens[i], errs[i] = g.Exchange(assertion("jti-race", t0), t0)
		}(i)
	}
	wg.Wait()
	successes := 0
	for i, err := range errs {
		if err == nil {
			successes++
			continue
		}
		if !errors.Is(err, taskpkg.ErrReplay) {
			t.Fatalf("worker %d failed with %v, want ErrReplay", i, err)
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent exchanges with one jti succeeded %d times, want exactly 1", successes)
	}
}

func TestScopeAllowList(t *testing.T) {
	g := gsaGuard(t)
	a := assertion("jti-scopes", t0)
	a.Scopes = []string{scopeCloud, scopeRead, scopeRead}
	tok := exchange(t, g, a, t0)
	if len(tok.Scopes) != 2 || tok.Scopes[0] != scopeCloud || tok.Scopes[1] != scopeRead {
		t.Fatalf("token scopes = %v, want [%s %s]", tok.Scopes, scopeCloud, scopeRead)
	}
	denied := assertion("jti-bq", t0)
	denied.Scopes = []string{"https://www.googleapis.com/auth/bigquery"}
	if _, err := g.Exchange(denied, t0); !errors.Is(err, taskpkg.ErrScope) {
		t.Fatalf("Exchange with a scope outside the allow list = %v, want ErrScope", err)
	}
}

func TestDelegationChainBounds(t *testing.T) {
	cfg := gsaConfig()
	cfg.MaxDelegates = 1
	g := taskpkg.NewSaJwtGuard(cfg)
	if err := g.RegisterServiceAccount(saEmail, "data-platform"); err != nil {
		t.Fatalf("RegisterServiceAccount: %v", err)
	}
	two := assertion("jti-chain-2", t0)
	two.Delegates = []string{"sa-a@data-platform.iam.gserviceaccount.com", "sa-b@data-platform.iam.gserviceaccount.com"}
	if _, err := g.Exchange(two, t0); !errors.Is(err, taskpkg.ErrChain) {
		t.Fatalf("chain of two against a cap of one = %v, want ErrChain", err)
	}
	dup := assertion("jti-chain-dup", t0)
	dup.Delegates = []string{"sa-a@data-platform.iam.gserviceaccount.com", "sa-a@data-platform.iam.gserviceaccount.com"}
	if _, err := g.Exchange(dup, t0); !errors.Is(err, taskpkg.ErrChain) {
		t.Fatalf("chain with a repeated member = %v, want ErrChain", err)
	}
	single := assertion("jti-chain-1", t0)
	single.Delegates = []string{"sa-a@data-platform.iam.gserviceaccount.com"}
	tok := exchange(t, g, single, t0)
	if !tok.Impersonated || tok.Subject != saEmail {
		t.Fatalf("impersonated token = %+v, want Impersonated and subject %q", tok, saEmail)
	}
}

func TestSubjectDelegationNeedsAllowList(t *testing.T) {
	g := gsaGuard(t)
	a := assertion("jti-subject", t0)
	a.Subject = "alice@example.com"
	if _, err := g.Exchange(a, t0); !errors.Is(err, taskpkg.ErrSubject) {
		t.Fatalf("subject delegation without an allow entry = %v, want ErrSubject", err)
	}
	if err := g.AllowSubjectDelegation(saEmail, "alice@example.com"); err != nil {
		t.Fatalf("AllowSubjectDelegation: %v", err)
	}
	tok := exchange(t, g, a, t0)
	if tok.Subject != "alice@example.com" || !tok.Impersonated {
		t.Fatalf("subject token = %+v, want subject alice@example.com and Impersonated", tok)
	}
	if err := g.AllowSubjectDelegation("ghost@nowhere.iam.gserviceaccount.com", "bob@example.com"); !errors.Is(err, taskpkg.ErrUnknownIssuer) {
		t.Fatalf("AllowSubjectDelegation for an unknown account = %v, want ErrUnknownIssuer", err)
	}
}

func TestQuotaWindowSlides(t *testing.T) {
	cfg := gsaConfig()
	cfg.QuotaPerWindow = 3
	cfg.QuotaWindow = time.Minute
	g := taskpkg.NewSaJwtGuard(cfg)
	if err := g.RegisterServiceAccount(saEmail, "data-platform"); err != nil {
		t.Fatalf("RegisterServiceAccount: %v", err)
	}
	for i, jti := range []string{"jti-q1", "jti-q2", "jti-q3"} {
		exchange(t, g, assertion(jti, t0), t0)
		if remaining, err := g.QuotaRemaining(saEmail, t0); err != nil || remaining != 2-i {
			t.Fatalf("QuotaRemaining after %d exchanges = %d err=%v, want %d", i+1, remaining, err, 2-i)
		}
	}
	if _, err := g.Exchange(assertion("jti-q4", t0), t0); !errors.Is(err, taskpkg.ErrQuota) {
		t.Fatalf("fourth exchange against a quota of three = %v, want ErrQuota", err)
	}
	later := t0.Add(61 * time.Second)
	if remaining, err := g.QuotaRemaining(saEmail, later); err != nil || remaining != 3 {
		t.Fatalf("QuotaRemaining after the window = %d err=%v, want 3", remaining, err)
	}
	exchange(t, g, assertion("jti-q5", later), later)
}

func TestValidateAndRevokeToken(t *testing.T) {
	g := gsaGuard(t)
	tok := exchange(t, g, assertion("jti-validate", t0), t0)
	got, err := g.ValidateToken(tok.Value, scopeRead, t0.Add(time.Minute))
	if err != nil || got.Subject != saEmail {
		t.Fatalf("ValidateToken = %+v err=%v, want subject %q", got, err, saEmail)
	}
	if _, err := g.ValidateToken(tok.Value, "https://www.googleapis.com/auth/bigquery", t0); !errors.Is(err, taskpkg.ErrScope) {
		t.Fatalf("ValidateToken with a missing scope = %v, want ErrScope", err)
	}
	if _, err := g.ValidateToken(tok.Value, scopeRead, t0.Add(2*time.Hour)); !errors.Is(err, taskpkg.ErrExpired) {
		t.Fatalf("ValidateToken after expiry = %v, want ErrExpired", err)
	}
	if _, err := g.ValidateToken("deadbeef", scopeRead, t0); !errors.Is(err, taskpkg.ErrMalformed) {
		t.Fatalf("ValidateToken of an unknown value = %v, want ErrMalformed", err)
	}
	if err := g.RevokeToken("deadbeef"); !errors.Is(err, taskpkg.ErrMalformed) {
		t.Fatalf("RevokeToken of an unknown value = %v, want ErrMalformed", err)
	}
	if err := g.RevokeToken(tok.Value); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}
	if err := g.RevokeToken(tok.Value); err != nil {
		t.Fatalf("second RevokeToken = %v, want no error", err)
	}
	if _, err := g.ValidateToken(tok.Value, scopeRead, t0.Add(time.Minute)); !errors.Is(err, taskpkg.ErrTokenRevoked) {
		t.Fatalf("ValidateToken after revocation = %v, want ErrTokenRevoked", err)
	}
}

func TestSnapshotKeepsReplayAndRevocations(t *testing.T) {
	g := gsaGuard(t)
	revoked := exchange(t, g, assertion("jti-r1", t0), t0)
	if err := g.RevokeToken(revoked.Value); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}
	live := exchange(t, g, assertion("jti-r2", t0), t0)
	snap, err := g.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	restored, err := taskpkg.NewSaJwtGuardFromSnapshot(gsaConfig(), snap)
	if err != nil {
		t.Fatalf("NewSaJwtGuardFromSnapshot: %v", err)
	}
	if _, err := restored.ValidateToken(revoked.Value, scopeRead, t0); !errors.Is(err, taskpkg.ErrTokenRevoked) {
		t.Fatalf("revoked token after restart = %v, want ErrTokenRevoked", err)
	}
	if _, err := restored.ValidateToken(live.Value, scopeRead, t0); err != nil {
		t.Fatalf("live token after restart = %v, want no error", err)
	}
	if err := restored.RegisterServiceAccount(saEmail, "data-platform"); err != nil {
		t.Fatalf("RegisterServiceAccount after restart: %v", err)
	}
	if _, err := restored.Exchange(assertion("jti-r2", t0.Add(time.Minute)), t0.Add(time.Minute)); !errors.Is(err, taskpkg.ErrReplay) {
		t.Fatalf("replayed assertion after restart = %v, want ErrReplay", err)
	}
	if n := restored.PruneJTIs(t0.Add(2 * time.Hour)); n != 2 {
		t.Fatalf("PruneJTIs removed %d ids, want 2", n)
	}
	if used, err := restored.JTIUsed("jti-r2"); err != nil || used {
		t.Fatalf("JTIUsed after prune = %v err=%v, want false", used, err)
	}
}
