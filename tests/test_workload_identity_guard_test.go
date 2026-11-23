package task

import (
	"errors"
	"sync"
	"testing"
	"time"

	taskpkg "gsb/batch46-safety-b-10"
)

const prodSubject = "spiffe://corp.example/ns/prod/sa/api"

func widConfig() taskpkg.Config {
	return taskpkg.Config{
		TrustDomain:    "corp.example",
		Audience:       "sts.corp.example",
		MaxTokenTTL:    time.Hour,
		MaxCredTTL:     time.Hour,
		MaxOutstanding: 16,
		ReplayTTL:      10 * time.Minute,
	}
}

func widToken(jti string, now time.Time) taskpkg.Token {
	return taskpkg.Token{
		Subject:        prodSubject,
		Audience:       "sts.corp.example",
		Domain:         "corp.example",
		JTI:            jti,
		IssuedAt:       now.Add(-10 * time.Second),
		ExpiresAt:      now.Add(5 * time.Minute),
		SignatureValid: true,
	}
}

func newGuard(t *testing.T, cfg taskpkg.Config) *taskpkg.WorkloadIdentityGuard {
	t.Helper()
	g := taskpkg.NewWorkloadIdentityGuard(cfg)
	if g == nil {
		t.Fatal("NewWorkloadIdentityGuard returned nil")
	}
	return g
}

func bindProd(t *testing.T, g *taskpkg.WorkloadIdentityGuard) {
	t.Helper()
	if err := g.BindRole(taskpkg.RoleBinding{
		TenantID:      "tenant-a",
		SubjectPrefix: "spiffe://corp.example/ns/prod",
		RoleARN:       "arn:aws:iam::111122223333:role/prod-reader",
		MaxTTL:        30 * time.Minute,
	}); err != nil {
		t.Fatalf("BindRole: %v", err)
	}
}

func mustExchange(t *testing.T, g *taskpkg.WorkloadIdentityGuard, tok taskpkg.Token, tenantID string, ttl time.Duration, now time.Time) taskpkg.Credential {
	t.Helper()
	cred, err := g.Exchange(tok, tenantID, ttl, now)
	if err != nil {
		t.Fatalf("Exchange(%s): %v", tok.JTI, err)
	}
	return cred
}

// A valid token yields a credential scoped to the bound role and is
// immediately resolvable.
func TestValidExchange(t *testing.T) {
	now := time.Unix(1726800000, 0)
	g := newGuard(t, widConfig())
	bindProd(t, g)
	cred := mustExchange(t, g, widToken("jti-1", now), "tenant-a", 15*time.Minute, now)
	if cred.RoleARN != "arn:aws:iam::111122223333:role/prod-reader" {
		t.Fatalf("RoleARN=%q, want the bound role", cred.RoleARN)
	}
	if cred.TenantID != "tenant-a" {
		t.Fatalf("TenantID=%q, want tenant-a", cred.TenantID)
	}
	if cred.Subject != prodSubject {
		t.Fatalf("Subject=%q, want %q", cred.Subject, prodSubject)
	}
	if cred.Value == "" {
		t.Fatal("Exchange returned an empty credential value")
	}
	if !cred.ExpiresAt.Equal(now.Add(15 * time.Minute)) {
		t.Fatalf("ExpiresAt=%v, want %v", cred.ExpiresAt, now.Add(15*time.Minute))
	}
	got, err := g.Validate(cred.Value, now)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if got.RoleARN != cred.RoleARN || got.Subject != cred.Subject {
		t.Fatalf("Validate=%+v, want %+v", got, cred)
	}
	if n := g.Outstanding(now); n != 1 {
		t.Fatalf("Outstanding=%d, want 1", n)
	}
}

// The audience of the token must match the configured broker audience.
func TestAudienceMismatch(t *testing.T) {
	now := time.Unix(1726800000, 0)
	g := newGuard(t, widConfig())
	bindProd(t, g)
	tok := widToken("jti-aud", now)
	tok.Audience = "sts.other.example"
	if _, err := g.Exchange(tok, "tenant-a", 10*time.Minute, now); !errors.Is(err, taskpkg.ErrAudience) {
		t.Fatalf("token for another audience: got %v, want ErrAudience", err)
	}
}

// Tokens from a foreign trust domain are refused, whether the domain field or
// the subject carries the mismatch.
func TestUntrustedDomain(t *testing.T) {
	now := time.Unix(1726800000, 0)
	g := newGuard(t, widConfig())
	bindProd(t, g)
	tok := widToken("jti-dom", now)
	tok.Domain = "evil.example"
	if _, err := g.Exchange(tok, "tenant-a", 10*time.Minute, now); !errors.Is(err, taskpkg.ErrTrustDomain) {
		t.Fatalf("token with a foreign domain: got %v, want ErrTrustDomain", err)
	}
	other := widToken("jti-dom-2", now)
	other.Subject = "spiffe://evil.example/ns/prod/sa/api"
	if _, err := g.Exchange(other, "tenant-a", 10*time.Minute, now); !errors.Is(err, taskpkg.ErrTrustDomain) {
		t.Fatalf("token with a foreign subject: got %v, want ErrTrustDomain", err)
	}
}

// An expired token is expired, not invalid.
func TestExpiredToken(t *testing.T) {
	now := time.Unix(1726800000, 0)
	g := newGuard(t, widConfig())
	bindProd(t, g)
	tok := widToken("jti-exp", now)
	tok.ExpiresAt = now
	if _, err := g.Exchange(tok, "tenant-a", 10*time.Minute, now); !errors.Is(err, taskpkg.ErrTokenExpired) {
		t.Fatalf("expired token: got %v, want ErrTokenExpired", err)
	}
}

// A token issued with a lifetime above MaxTokenTTL is refused even while it is
// still valid.
func TestTokenLifetimeTooLong(t *testing.T) {
	now := time.Unix(1726800000, 0)
	g := newGuard(t, widConfig())
	bindProd(t, g)
	tok := widToken("jti-long", now)
	tok.IssuedAt = now.Add(-2 * time.Hour)
	tok.ExpiresAt = now.Add(time.Minute)
	if _, err := g.Exchange(tok, "tenant-a", 10*time.Minute, now); !errors.Is(err, taskpkg.ErrTokenInvalid) {
		t.Fatalf("token with a two hour lifetime: got %v, want ErrTokenInvalid", err)
	}
}

// A token whose signature does not verify is invalid.
func TestSignatureInvalid(t *testing.T) {
	now := time.Unix(1726800000, 0)
	g := newGuard(t, widConfig())
	bindProd(t, g)
	tok := widToken("jti-sig", now)
	tok.SignatureValid = false
	if _, err := g.Exchange(tok, "tenant-a", 10*time.Minute, now); !errors.Is(err, taskpkg.ErrTokenInvalid) {
		t.Fatalf("unsigned token: got %v, want ErrTokenInvalid", err)
	}
}

// The same token id must not be exchanged twice inside the replay window.
func TestReplayRejected(t *testing.T) {
	now := time.Unix(1726800000, 0)
	g := newGuard(t, widConfig())
	bindProd(t, g)
	tok := widToken("jti-replay", now)
	mustExchange(t, g, tok, "tenant-a", 10*time.Minute, now)
	if _, err := g.Exchange(tok, "tenant-a", 10*time.Minute, now); !errors.Is(err, taskpkg.ErrReplay) {
		t.Fatalf("replayed token id: got %v, want ErrReplay", err)
	}
}

// A subject without a binding in its own tenant cannot exchange, even when
// another tenant has a matching binding.
func TestNoRoleBinding(t *testing.T) {
	now := time.Unix(1726800000, 0)
	g := newGuard(t, widConfig())
	if _, err := g.Exchange(widToken("jti-norole", now), "tenant-a", 10*time.Minute, now); !errors.Is(err, taskpkg.ErrNoRole) {
		t.Fatalf("exchange without any binding: got %v, want ErrNoRole", err)
	}
	bindProd(t, g)
	if _, err := g.Exchange(widToken("jti-norole-2", now), "tenant-b", 10*time.Minute, now); !errors.Is(err, taskpkg.ErrNoRole) {
		t.Fatalf("exchange in another tenant: got %v, want ErrNoRole", err)
	}
}

// The most specific subject prefix wins.
func TestLongestPrefixWins(t *testing.T) {
	now := time.Unix(1726800000, 0)
	g := newGuard(t, widConfig())
	bindProd(t, g)
	if err := g.BindRole(taskpkg.RoleBinding{
		TenantID:      "tenant-a",
		SubjectPrefix: "spiffe://corp.example/ns/prod/payments",
		RoleARN:       "arn:aws:iam::111122223333:role/payments-writer",
		MaxTTL:        20 * time.Minute,
	}); err != nil {
		t.Fatalf("BindRole(payments): %v", err)
	}
	prod := mustExchange(t, g, widToken("jti-prefix-1", now), "tenant-a", 5*time.Minute, now)
	if prod.RoleARN != "arn:aws:iam::111122223333:role/prod-reader" {
		t.Fatalf("prod subject got role %q, want prod-reader", prod.RoleARN)
	}
	payments := widToken("jti-prefix-2", now)
	payments.Subject = "spiffe://corp.example/ns/prod/payments/sa/api"
	got := mustExchange(t, g, payments, "tenant-a", 5*time.Minute, now)
	if got.RoleARN != "arn:aws:iam::111122223333:role/payments-writer" {
		t.Fatalf("payments subject got role %q, want payments-writer", got.RoleARN)
	}
}

// The binding's MaxTTL caps the requested ttl without failing the call.
func TestTTLCappedByBinding(t *testing.T) {
	now := time.Unix(1726800000, 0)
	g := newGuard(t, widConfig())
	if err := g.BindRole(taskpkg.RoleBinding{
		TenantID:      "tenant-a",
		SubjectPrefix: "spiffe://corp.example/ns/prod",
		RoleARN:       "arn:aws:iam::111122223333:role/short",
		MaxTTL:        10 * time.Minute,
	}); err != nil {
		t.Fatalf("BindRole: %v", err)
	}
	cred := mustExchange(t, g, widToken("jti-cap", now), "tenant-a", 30*time.Minute, now)
	if !cred.ExpiresAt.Equal(now.Add(10 * time.Minute)) {
		t.Fatalf("ExpiresAt=%v, want the binding cap %v", cred.ExpiresAt, now.Add(10*time.Minute))
	}
}

// A requested ttl outside (0, MaxCredTTL] is rejected.
func TestTTLOverGlobalLimit(t *testing.T) {
	now := time.Unix(1726800000, 0)
	g := newGuard(t, widConfig())
	bindProd(t, g)
	if _, err := g.Exchange(widToken("jti-ttl-long", now), "tenant-a", 2*time.Hour, now); !errors.Is(err, taskpkg.ErrTTLTooLong) {
		t.Fatalf("two hour ttl: got %v, want ErrTTLTooLong", err)
	}
	if _, err := g.Exchange(widToken("jti-ttl-zero", now), "tenant-a", 0, now); !errors.Is(err, taskpkg.ErrTTLTooLong) {
		t.Fatalf("zero ttl: got %v, want ErrTTLTooLong", err)
	}
}

// Subject revocation blocks new exchanges until it is lifted.
func TestRevokedSubject(t *testing.T) {
	now := time.Unix(1726800000, 0)
	g := newGuard(t, widConfig())
	bindProd(t, g)
	if err := g.RevokeSubject("tenant-a", prodSubject); err != nil {
		t.Fatalf("RevokeSubject: %v", err)
	}
	if _, err := g.Exchange(widToken("jti-rev", now), "tenant-a", 10*time.Minute, now); !errors.Is(err, taskpkg.ErrRevoked) {
		t.Fatalf("exchange for a revoked subject: got %v, want ErrRevoked", err)
	}
	if err := g.ReinstateSubject("tenant-a", prodSubject); err != nil {
		t.Fatalf("ReinstateSubject: %v", err)
	}
	mustExchange(t, g, widToken("jti-rev-2", now), "tenant-a", 10*time.Minute, now)
}

// The outstanding credential cap holds, and expired credentials free the
// budget.
func TestOutstandingCapAndExpiry(t *testing.T) {
	now := time.Unix(1726800000, 0)
	cfg := widConfig()
	cfg.MaxOutstanding = 2
	g := newGuard(t, cfg)
	bindProd(t, g)
	mustExchange(t, g, widToken("jti-out-1", now), "tenant-a", 15*time.Minute, now)
	mustExchange(t, g, widToken("jti-out-2", now), "tenant-a", 15*time.Minute, now)
	if _, err := g.Exchange(widToken("jti-out-3", now), "tenant-a", 15*time.Minute, now); !errors.Is(err, taskpkg.ErrCredCap) {
		t.Fatalf("third credential with a cap of two: got %v, want ErrCredCap", err)
	}
	if n := g.Outstanding(now); n != 2 {
		t.Fatalf("Outstanding=%d, want 2", n)
	}
	later := now.Add(20 * time.Minute)
	if n := g.Outstanding(later); n != 0 {
		t.Fatalf("Outstanding after expiry=%d, want 0", n)
	}
	mustExchange(t, g, widToken("jti-out-3", later), "tenant-a", 15*time.Minute, later)
}

// Two concurrent exchanges of one token id may only produce one credential.
func TestConcurrentSameJTI(t *testing.T) {
	now := time.Unix(1726800000, 0)
	g := newGuard(t, widConfig())
	bindProd(t, g)
	tok := widToken("jti-race", now)
	var wg sync.WaitGroup
	var mu sync.Mutex
	successes := 0
	wg.Add(2)
	for i := 0; i < 2; i++ {
		go func() {
			defer wg.Done()
			if _, err := g.Exchange(tok, "tenant-a", 10*time.Minute, now); err == nil {
				mu.Lock()
				successes++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if successes != 1 {
		t.Fatalf("concurrent exchanges of one token: %d successes, want exactly 1", successes)
	}
	if n := g.Outstanding(now); n != 1 {
		t.Fatalf("Outstanding=%d, want 1", n)
	}
}

// Used token ids, subject revocations and credentials must survive a restart.
func TestReplayAndRevocationSurviveRestart(t *testing.T) {
	now := time.Unix(1726800000, 0)
	cfg := widConfig()
	g := newGuard(t, cfg)
	bindProd(t, g)
	cred := mustExchange(t, g, widToken("jti-persist", now), "tenant-a", 10*time.Minute, now)
	if err := g.RevokeSubject("tenant-a", prodSubject); err != nil {
		t.Fatalf("RevokeSubject: %v", err)
	}
	snap, err := g.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	restored, err := taskpkg.NewWorkloadIdentityGuardFromSnapshot(cfg, snap)
	if err != nil {
		t.Fatalf("NewWorkloadIdentityGuardFromSnapshot: %v", err)
	}
	if _, err := restored.Validate(cred.Value, now); err != nil {
		t.Fatalf("Validate after restore: %v", err)
	}
	if n := restored.Outstanding(now); n != 1 {
		t.Fatalf("Outstanding after restore=%d, want 1", n)
	}
	if _, err := restored.Exchange(widToken("jti-persist", now), "tenant-a", 10*time.Minute, now); !errors.Is(err, taskpkg.ErrReplay) {
		t.Fatalf("replayed token after restore: got %v, want ErrReplay", err)
	}
	if _, err := restored.Exchange(widToken("jti-persist-2", now), "tenant-a", 10*time.Minute, now); !errors.Is(err, taskpkg.ErrRevoked) {
		t.Fatalf("revoked subject after restore: got %v, want ErrRevoked", err)
	}
	if err := restored.RevokeCredential(cred.Value); err != nil {
		t.Fatalf("RevokeCredential: %v", err)
	}
	if _, err := restored.Validate(cred.Value, now); !errors.Is(err, taskpkg.ErrRevoked) {
		t.Fatalf("Validate after credential revocation: got %v, want ErrRevoked", err)
	}
}
