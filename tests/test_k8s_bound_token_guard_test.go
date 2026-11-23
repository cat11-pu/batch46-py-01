package task

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	taskpkg "gsb/batch46-safety-a-10"
)

const (
	saName   = "vault-agent"
	audK8s   = "https://kubernetes.default.svc"
	audVault = "vault-aud"
)

var t0 = time.Unix(1735689600, 0).UTC() // 2025-01-01T00:00:00Z

func btConfig() taskpkg.Config {
	return taskpkg.Config{
		Audiences:       []string{audK8s, audVault},
		MaxTTL:          10 * time.Minute,
		MinTTL:          time.Minute,
		ClockSkew:       30 * time.Second,
		MaxTokensPerPod: 2,
		RefreshWindow:   5 * time.Minute,
	}
}

func binding(uid, node string) taskpkg.PodBinding {
	return taskpkg.PodBinding{Namespace: "prod", PodName: "web-" + uid, PodUID: uid, NodeName: node}
}

func btGuard(t *testing.T) *taskpkg.BoundTokenGuard {
	t.Helper()
	g := taskpkg.NewBoundTokenGuard(btConfig())
	if err := g.RegisterServiceAccount("prod", saName); err != nil {
		t.Fatalf("RegisterServiceAccount: %v", err)
	}
	for _, b := range []taskpkg.PodBinding{binding("uid-1", "node-1"), binding("uid-2", "node-2")} {
		if err := g.RegisterPod(b); err != nil {
			t.Fatalf("RegisterPod(%s): %v", b.PodUID, err)
		}
	}
	return g
}

func tokenReq(uid, node, aud string, ttl time.Duration) taskpkg.TokenRequest {
	return taskpkg.TokenRequest{
		Namespace:      "prod",
		ServiceAccount: saName,
		Binding:        binding(uid, node),
		Audience:       aud,
		TTL:            ttl,
	}
}

func issue(t *testing.T, g *taskpkg.BoundTokenGuard, uid, node, aud string, ttl time.Duration, now time.Time) taskpkg.Token {
	t.Helper()
	tok, err := g.RequestToken(tokenReq(uid, node, aud, ttl), now)
	if err != nil {
		t.Fatalf("RequestToken(%s): %v", uid, err)
	}
	return tok
}

func claimsOf(tok taskpkg.Token) taskpkg.Claims {
	return taskpkg.Claims{
		Issuer:         "https://kubernetes.default.svc.cluster.local",
		Subject:        "system:serviceaccount:" + tok.Namespace + ":" + tok.ServiceAccount,
		Audiences:      []string{tok.Audience},
		IssuedAt:       tok.IssuedAt,
		ExpiresAt:      tok.ExpiresAt,
		PodName:        tok.PodName,
		PodUID:         tok.PodUID,
		NodeName:       tok.NodeName,
		JTI:            tok.JTI,
		SignatureValid: true,
	}
}

func TestRequestTokenAndValidate(t *testing.T) {
	g := btGuard(t)
	tok := issue(t, g, "uid-1", "node-1", audK8s, 5*time.Minute, t0)
	if tok.Namespace != "prod" || tok.ServiceAccount != saName || tok.PodUID != "uid-1" || tok.NodeName != "node-1" {
		t.Fatalf("token binding = %+v, want prod/%s/uid-1/node-1", tok, saName)
	}
	if !tok.ExpiresAt.Equal(t0.Add(5 * time.Minute)) {
		t.Fatalf("token expiry = %v, want %v", tok.ExpiresAt, t0.Add(5*time.Minute))
	}
	if len(tok.JTI) != 64 || strings.Trim(tok.JTI, "0123456789abcdef") != "" {
		t.Fatalf("token id %q is not 64 lower-case hex characters", tok.JTI)
	}
	if tok.Value != tok.JTI {
		t.Fatalf("token value %q and id %q differ", tok.Value, tok.JTI)
	}
	if err := g.Validate(claimsOf(tok), audK8s, "node-1", t0.Add(time.Minute)); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestAudienceMustBeAllowed(t *testing.T) {
	g := btGuard(t)
	if _, err := g.RequestToken(tokenReq("uid-1", "node-1", "other-aud", 5*time.Minute), t0); !errors.Is(err, taskpkg.ErrAudience) {
		t.Fatalf("RequestToken with a foreign audience = %v, want ErrAudience", err)
	}
	tok := issue(t, g, "uid-1", "node-1", audVault, 5*time.Minute, t0)
	claims := claimsOf(tok)
	claims.Audiences = []string{"other-aud"}
	if err := g.Validate(claims, audVault, "node-1", t0); !errors.Is(err, taskpkg.ErrAudience) {
		t.Fatalf("Validate with a foreign audience = %v, want ErrAudience", err)
	}
}

func TestSubjectMustNameRegisteredServiceAccount(t *testing.T) {
	g := btGuard(t)
	tok := issue(t, g, "uid-1", "node-1", audK8s, 5*time.Minute, t0)
	ghost := claimsOf(tok)
	ghost.Subject = "system:serviceaccount:prod:ghost-agent"
	if err := g.Validate(ghost, audK8s, "node-1", t0); !errors.Is(err, taskpkg.ErrUnknownSA) {
		t.Fatalf("Validate for an unregistered account = %v, want ErrUnknownSA", err)
	}
	for _, bad := range []string{"ghost", "system:serviceaccount:prod"} {
		claims := claimsOf(tok)
		claims.Subject = bad
		if err := g.Validate(claims, audK8s, "node-1", t0); !errors.Is(err, taskpkg.ErrMalformed) {
			t.Fatalf("Validate with subject %q = %v, want ErrMalformed", bad, err)
		}
	}
}

func TestExpiryAndStartSkew(t *testing.T) {
	g := btGuard(t)
	tok := issue(t, g, "uid-1", "node-1", audK8s, 5*time.Minute, t0)
	claims := claimsOf(tok)
	claims.ExpiresAt = t0.Add(time.Minute)
	if err := g.Validate(claims, audK8s, "node-1", t0.Add(time.Minute+30*time.Second)); err != nil {
		t.Fatalf("Validate exactly at expiry plus skew = %v, want no error", err)
	}
	if err := g.Validate(claims, audK8s, "node-1", t0.Add(time.Minute+31*time.Second)); !errors.Is(err, taskpkg.ErrExpired) {
		t.Fatalf("Validate past expiry plus skew = %v, want ErrExpired", err)
	}
	early := claimsOf(tok)
	early.IssuedAt = t0.Add(5 * time.Minute)
	if err := g.Validate(early, audK8s, "node-1", t0); !errors.Is(err, taskpkg.ErrNotYet) {
		t.Fatalf("Validate before iat minus skew = %v, want ErrNotYet", err)
	}
	if err := g.Validate(early, audK8s, "node-1", t0.Add(4*time.Minute+30*time.Second)); err != nil {
		t.Fatalf("Validate exactly at iat minus skew = %v, want no error", err)
	}
}

func TestRequestedTTLBounds(t *testing.T) {
	g := btGuard(t)
	if _, err := g.RequestToken(tokenReq("uid-1", "node-1", audK8s, 20*time.Minute), t0); !errors.Is(err, taskpkg.ErrLimit) {
		t.Fatalf("RequestToken with a twenty minute TTL = %v, want ErrLimit", err)
	}
	if _, err := g.RequestToken(tokenReq("uid-1", "node-1", audK8s, 30*time.Second), t0); !errors.Is(err, taskpkg.ErrLimit) {
		t.Fatalf("RequestToken with a thirty second TTL = %v, want ErrLimit", err)
	}
	issue(t, g, "uid-1", "node-1", audK8s, 10*time.Minute, t0)
	issue(t, g, "uid-2", "node-2", audK8s, time.Minute, t0)
}

func TestPodBindingMustMatch(t *testing.T) {
	g := btGuard(t)
	ghost := tokenReq("uid-ghost", "node-1", audK8s, 5*time.Minute)
	if _, err := g.RequestToken(ghost, t0); !errors.Is(err, taskpkg.ErrBinding) {
		t.Fatalf("RequestToken for an unregistered pod = %v, want ErrBinding", err)
	}
	wrongName := tokenReq("uid-1", "node-1", audK8s, 5*time.Minute)
	wrongName.Binding.PodName = "web-other"
	if _, err := g.RequestToken(wrongName, t0); !errors.Is(err, taskpkg.ErrBinding) {
		t.Fatalf("RequestToken with a foreign pod name = %v, want ErrBinding", err)
	}
	tok := issue(t, g, "uid-1", "node-1", audK8s, 5*time.Minute, t0)
	foreign := claimsOf(tok)
	foreign.PodUID = "uid-ghost"
	if err := g.Validate(foreign, audK8s, "node-1", t0); !errors.Is(err, taskpkg.ErrBinding) {
		t.Fatalf("Validate for an unregistered pod = %v, want ErrBinding", err)
	}
	renamed := claimsOf(tok)
	renamed.PodName = "web-other"
	if err := g.Validate(renamed, audK8s, "node-1", t0); !errors.Is(err, taskpkg.ErrBinding) {
		t.Fatalf("Validate with a foreign pod name = %v, want ErrBinding", err)
	}
}

func TestTokenMustBeUsedOnItsNode(t *testing.T) {
	g := btGuard(t)
	tok := issue(t, g, "uid-1", "node-1", audK8s, 5*time.Minute, t0)
	if err := g.Validate(claimsOf(tok), audK8s, "node-2", t0); !errors.Is(err, taskpkg.ErrBinding) {
		t.Fatalf("token presented on another node = %v, want ErrBinding", err)
	}
	moved := claimsOf(tok)
	moved.NodeName = "node-3"
	if err := g.Validate(moved, audK8s, "", t0); !errors.Is(err, taskpkg.ErrBinding) {
		t.Fatalf("token with a rewritten node claim = %v, want ErrBinding", err)
	}
	if err := g.Validate(claimsOf(tok), audK8s, "", t0); err != nil {
		t.Fatalf("token with no node hint = %v, want no error", err)
	}
	if err := g.Validate(claimsOf(tok), audK8s, "node-1", t0); err != nil {
		t.Fatalf("token on its own node = %v, want no error", err)
	}
}

func TestRevokePodDropsEveryToken(t *testing.T) {
	g := btGuard(t)
	first := issue(t, g, "uid-1", "node-1", audK8s, 5*time.Minute, t0)
	issue(t, g, "uid-1", "node-1", audK8s, 5*time.Minute, t0)
	if _, err := g.RequestToken(tokenReq("uid-1", "node-1", audK8s, 5*time.Minute), t0); !errors.Is(err, taskpkg.ErrLimit) {
		t.Fatalf("third token against a cap of two = %v, want ErrLimit", err)
	}
	if got := g.ActiveTokens(); got != 2 {
		t.Fatalf("ActiveTokens = %d, want 2", got)
	}
	if n := g.RevokePod("uid-1"); n != 2 {
		t.Fatalf("RevokePod dropped %d tokens, want 2", n)
	}
	if got := g.ActiveTokens(); got != 0 {
		t.Fatalf("ActiveTokens after revoke = %d, want 0", got)
	}
	if err := g.Validate(claimsOf(first), audK8s, "node-1", t0); !errors.Is(err, taskpkg.ErrRevoked) {
		t.Fatalf("token of a revoked pod = %v, want ErrRevoked", err)
	}
	if _, err := g.RequestToken(tokenReq("uid-1", "node-1", audK8s, 5*time.Minute), t0); !errors.Is(err, taskpkg.ErrRevoked) {
		t.Fatalf("RequestToken for a revoked pod = %v, want ErrRevoked", err)
	}
	if _, err := g.TokenFor("uid-1"); !errors.Is(err, taskpkg.ErrRevoked) {
		t.Fatalf("TokenFor a revoked pod = %v, want ErrRevoked", err)
	}
}

func TestRotationInvalidatesPreviousToken(t *testing.T) {
	g := btGuard(t)
	old := issue(t, g, "uid-1", "node-1", audK8s, 5*time.Minute, t0)
	fresh, err := g.Rotate("uid-1", t0.Add(time.Minute))
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if fresh.JTI == old.JTI {
		t.Fatalf("rotation reused the token id %q", old.JTI)
	}
	if err := g.Validate(claimsOf(old), audK8s, "node-1", t0.Add(time.Minute)); !errors.Is(err, taskpkg.ErrRevoked) {
		t.Fatalf("old token after rotation = %v, want ErrRevoked", err)
	}
	if err := g.Validate(claimsOf(fresh), audK8s, "node-1", t0.Add(time.Minute)); err != nil {
		t.Fatalf("fresh token after rotation = %v, want no error", err)
	}
	if got := g.ActiveTokens(); got != 1 {
		t.Fatalf("ActiveTokens after rotation = %d, want 1", got)
	}
	latest, err := g.TokenFor("uid-1")
	if err != nil || latest.JTI != fresh.JTI {
		t.Fatalf("TokenFor = %+v err=%v, want the fresh token", latest, err)
	}
}

func TestSingleLiveTokenPerPod(t *testing.T) {
	cfg := btConfig()
	cfg.MaxTokensPerPod = 1
	g := taskpkg.NewBoundTokenGuard(cfg)
	if err := g.RegisterServiceAccount("prod", saName); err != nil {
		t.Fatalf("RegisterServiceAccount: %v", err)
	}
	if err := g.RegisterPod(binding("uid-1", "node-1")); err != nil {
		t.Fatalf("RegisterPod: %v", err)
	}
	issue(t, g, "uid-1", "node-1", audK8s, 5*time.Minute, t0)
	if _, err := g.RequestToken(tokenReq("uid-1", "node-1", audK8s, 5*time.Minute), t0); !errors.Is(err, taskpkg.ErrLimit) {
		t.Fatalf("second token against a cap of one = %v, want ErrLimit", err)
	}
	if _, err := g.Rotate("uid-1", t0.Add(time.Minute)); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if got := g.ActiveTokens(); got != 1 {
		t.Fatalf("ActiveTokens after rotation = %d, want 1", got)
	}
}

func TestNeedsRefresh(t *testing.T) {
	g := btGuard(t)
	issue(t, g, "uid-1", "node-1", audK8s, 10*time.Minute, t0)
	if need, err := g.NeedsRefresh("uid-1", t0.Add(4*time.Minute)); err != nil || need {
		t.Fatalf("NeedsRefresh with six minutes left = %v err=%v, want false", need, err)
	}
	if need, err := g.NeedsRefresh("uid-1", t0.Add(6*time.Minute)); err != nil || !need {
		t.Fatalf("NeedsRefresh with four minutes left = %v err=%v, want true", need, err)
	}
	if _, err := g.NeedsRefresh("uid-ghost", t0); !errors.Is(err, taskpkg.ErrMalformed) {
		t.Fatalf("NeedsRefresh for an unknown pod = %v, want ErrMalformed", err)
	}
}

func TestRegistrationValidation(t *testing.T) {
	g := btGuard(t)
	ghost := tokenReq("uid-1", "node-1", audK8s, 5*time.Minute)
	ghost.ServiceAccount = "ghost-agent"
	if _, err := g.RequestToken(ghost, t0); !errors.Is(err, taskpkg.ErrUnknownSA) {
		t.Fatalf("RequestToken for an unregistered account = %v, want ErrUnknownSA", err)
	}
	if err := g.RegisterServiceAccount("", "x"); !errors.Is(err, taskpkg.ErrMalformed) {
		t.Fatalf("RegisterServiceAccount with no namespace = %v, want ErrMalformed", err)
	}
	if err := g.RegisterServiceAccount("prod", ""); !errors.Is(err, taskpkg.ErrMalformed) {
		t.Fatalf("RegisterServiceAccount with no name = %v, want ErrMalformed", err)
	}
	if err := g.RegisterServiceAccount("prod", saName); err != nil {
		t.Fatalf("re-registering the same account = %v, want no error", err)
	}
	if err := g.RegisterPod(binding("uid-1", "node-1")); err != nil {
		t.Fatalf("re-registering the same binding = %v, want no error", err)
	}
	if err := g.RegisterPod(binding("uid-1", "node-9")); !errors.Is(err, taskpkg.ErrMalformed) {
		t.Fatalf("re-registering a pod with another node = %v, want ErrMalformed", err)
	}
}

func TestSignatureAndRequiredAudience(t *testing.T) {
	g := btGuard(t)
	tok := issue(t, g, "uid-1", "node-1", audVault, 5*time.Minute, t0)
	bad := claimsOf(tok)
	bad.SignatureValid = false
	if err := g.Validate(bad, audVault, "node-1", t0); !errors.Is(err, taskpkg.ErrSignature) {
		t.Fatalf("Validate with a broken signature = %v, want ErrSignature", err)
	}
	if err := g.Validate(claimsOf(tok), audVault, "node-1", t0); err != nil {
		t.Fatalf("Validate for the requested audience = %v, want no error", err)
	}
	if err := g.Validate(claimsOf(tok), audK8s, "node-1", t0); !errors.Is(err, taskpkg.ErrAudience) {
		t.Fatalf("Validate for an audience the token lacks = %v, want ErrAudience", err)
	}
}

func TestConcurrentRotationLeavesOneToken(t *testing.T) {
	g := btGuard(t)
	issue(t, g, "uid-1", "node-1", audK8s, 5*time.Minute, t0)
	const workers = 32
	var wg sync.WaitGroup
	tokens := make([]taskpkg.Token, workers)
	errs := make([]error, workers)
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func(i int) {
			defer wg.Done()
			tokens[i], errs[i] = g.Rotate("uid-1", t0.Add(time.Minute))
		}(i)
	}
	wg.Wait()
	seen := map[string]bool{}
	for i := 0; i < workers; i++ {
		if errs[i] != nil {
			t.Fatalf("rotation %d: %v", i, errs[i])
		}
		if seen[tokens[i].JTI] {
			t.Fatalf("rotation %d reused token id %q", i, tokens[i].JTI)
		}
		seen[tokens[i].JTI] = true
	}
	if got := g.ActiveTokens(); got != 1 {
		t.Fatalf("ActiveTokens after concurrent rotation = %d, want 1", got)
	}
	valid := 0
	for i, tok := range tokens {
		err := g.Validate(claimsOf(tok), audK8s, "node-1", t0.Add(2*time.Minute))
		if err == nil {
			valid++
			continue
		}
		if !errors.Is(err, taskpkg.ErrRevoked) {
			t.Fatalf("token %d from rotation failed with %v, want ErrRevoked", i, err)
		}
	}
	if valid != 1 {
		t.Fatalf("%d rotated tokens validate, want exactly 1", valid)
	}
}

func TestSnapshotRestoresBindingsAndRevocations(t *testing.T) {
	g := btGuard(t)
	live := issue(t, g, "uid-1", "node-1", audK8s, 5*time.Minute, t0)
	dead := issue(t, g, "uid-2", "node-2", audK8s, 5*time.Minute, t0)
	if n := g.RevokePod("uid-2"); n != 1 {
		t.Fatalf("RevokePod dropped %d tokens, want 1", n)
	}
	snap, err := g.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	restored, err := taskpkg.NewBoundTokenGuardFromSnapshot(btConfig(), snap)
	if err != nil {
		t.Fatalf("NewBoundTokenGuardFromSnapshot: %v", err)
	}
	if err := restored.Validate(claimsOf(live), audK8s, "node-1", t0); err != nil {
		t.Fatalf("live token after restart = %v, want no error", err)
	}
	if err := restored.Validate(claimsOf(dead), audK8s, "node-2", t0); !errors.Is(err, taskpkg.ErrRevoked) {
		t.Fatalf("revoked pod after restart = %v, want ErrRevoked", err)
	}
	if n := restored.Prune(t0.Add(6 * time.Minute)); n != 1 {
		t.Fatalf("Prune removed %d tokens, want 1", n)
	}
	if got := restored.ActiveTokens(); got != 0 {
		t.Fatalf("ActiveTokens after prune = %d, want 0", got)
	}
}
