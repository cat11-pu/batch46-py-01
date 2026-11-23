package task

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	taskpkg "gsb/batch46-safety-a-03"
)

const (
	publicClient       = "client-web"
	confidentialClient = "client-batch"
	webRedirect        = "https://app.example.com/cb"
	batchRedirect      = "https://batch.example.com/oauth/cb"
	baseUnix           = 1730000000
)

func testPolicy() taskpkg.ParPolicy {
	return taskpkg.ParPolicy{
		RequestURITTL:        time.Minute,
		MaxPending:           16,
		MinChallengeLen:      43,
		AllowedResponseTypes: []string{"code"},
	}
}

func secretHash(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

func newGuard(t *testing.T, p taskpkg.ParPolicy) *taskpkg.ParGuard {
	t.Helper()
	g := taskpkg.NewParGuard(p)
	if err := g.RegisterClient(taskpkg.Client{
		ID:            publicClient,
		TenantID:      "tenant-a",
		RedirectURIs:  []string{webRedirect},
		AllowedScopes: []string{"openid", "profile", "offline_access"},
	}); err != nil {
		t.Fatalf("RegisterClient(public): %v", err)
	}
	if err := g.RegisterClient(taskpkg.Client{
		ID:            confidentialClient,
		TenantID:      "tenant-a",
		RedirectURIs:  []string{batchRedirect},
		AllowedScopes: []string{"openid", "profile"},
		Confidential:  true,
		SecretHash:    secretHash("batch-secret"),
	}); err != nil {
		t.Fatalf("RegisterClient(confidential): %v", err)
	}
	return g
}

func newRequest() taskpkg.PARRequest {
	return taskpkg.PARRequest{
		ClientID:            publicClient,
		RedirectURI:         webRedirect,
		ResponseType:        "code",
		Scope:               "openid profile",
		State:               "st-9f1c2a",
		CodeChallenge:       strings.Repeat("a", 43),
		CodeChallengeMethod: "S256",
		Nonce:               "n-77a1",
	}
}

func mustPush(t *testing.T, g *taskpkg.ParGuard, req taskpkg.PARRequest, now time.Time) string {
	t.Helper()
	uri, err := g.Push(req, now)
	if err != nil {
		t.Fatalf("Push: %v", err)
	}
	return uri
}

// Every push must mint a fresh uri with the documented shape.
func TestPushReturnsUniquePrefixedURI(t *testing.T) {
	now := time.Unix(baseUnix, 0)
	g := newGuard(t, testPolicy())
	req := newRequest()
	first := mustPush(t, g, req, now)
	second := mustPush(t, g, req, now)
	prefix := g.RequestURIPrefix()
	if !strings.HasPrefix(first, prefix) {
		t.Fatalf("request uri %q lacks prefix %q", first, prefix)
	}
	if first == second {
		t.Fatalf("two pushes returned the same request uri %q", first)
	}
	if len(first) != len(prefix)+32 {
		t.Fatalf("request uri %q length = %d, want %d", first, len(first), len(prefix)+32)
	}
	if got := g.Stats().Pushed; got != 2 {
		t.Fatalf("Pushed = %d, want 2", got)
	}
}

// Consuming a request returns the stored request, scopes normalised in order.
func TestConsumeReturnsStoredRequest(t *testing.T) {
	now := time.Unix(baseUnix, 0)
	g := newGuard(t, testPolicy())
	req := newRequest()
	req.Scope = "profile  openid profile"
	uri := mustPush(t, g, req, now)
	stored, err := g.Consume(uri, publicClient, now)
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if stored.RequestURI != uri {
		t.Fatalf("stored uri mismatch: %q", stored.RequestURI)
	}
	if stored.ClientID != publicClient || stored.TenantID != "tenant-a" {
		t.Fatalf("stored owner mismatch: %+v", stored)
	}
	if stored.RedirectURI != webRedirect || stored.State != "st-9f1c2a" {
		t.Fatalf("stored request fields mismatch: %+v", stored)
	}
	if len(stored.Scopes) != 2 || stored.Scopes[0] != "profile" || stored.Scopes[1] != "openid" {
		t.Fatalf("scopes not normalised: %#v", stored.Scopes)
	}
	if stored.CodeChallenge != req.CodeChallenge || stored.CodeChallengeMethod != "S256" || stored.Nonce != "n-77a1" {
		t.Fatalf("pkce fields lost: %+v", stored)
	}
	if !stored.ExpiresAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("ExpiresAt = %v, want %v", stored.ExpiresAt, now.Add(time.Minute))
	}
}

// A request uri may be redeemed exactly once.
func TestRequestURISingleUse(t *testing.T) {
	now := time.Unix(baseUnix, 0)
	g := newGuard(t, testPolicy())
	uri := mustPush(t, g, newRequest(), now)
	if _, err := g.Consume(uri, publicClient, now); err != nil {
		t.Fatalf("first Consume: %v", err)
	}
	if _, err := g.Consume(uri, publicClient, now); !errors.Is(err, taskpkg.ErrRequestConsumed) {
		t.Fatalf("want ErrRequestConsumed, got %v", err)
	}
}

// An expired request uri must be rejected and stop being pending.
func TestExpiredRequestURIRejected(t *testing.T) {
	now := time.Unix(baseUnix, 0)
	g := newGuard(t, testPolicy())
	uri := mustPush(t, g, newRequest(), now)
	later := now.Add(61 * time.Second)
	if _, err := g.Consume(uri, publicClient, later); !errors.Is(err, taskpkg.ErrRequestExpired) {
		t.Fatalf("want ErrRequestExpired, got %v", err)
	}
	pending, err := g.Pending(uri, later)
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	if pending {
		t.Fatalf("expired request uri still reported pending")
	}
}

// redirect_uri must match a registered value exactly.
func TestRedirectURIExactMatch(t *testing.T) {
	now := time.Unix(baseUnix, 0)
	g := newGuard(t, testPolicy())
	req := newRequest()
	req.RedirectURI = webRedirect + "/evil"
	if _, err := g.Push(req, now); !errors.Is(err, taskpkg.ErrRedirectMismatch) {
		t.Fatalf("want ErrRedirectMismatch, got %v", err)
	}
}

// Requested scopes must be a subset of the client's allowed scopes.
func TestScopeSubsetEnforced(t *testing.T) {
	now := time.Unix(baseUnix, 0)
	g := newGuard(t, testPolicy())
	req := newRequest()
	req.Scope = "openid admin"
	if _, err := g.Push(req, now); !errors.Is(err, taskpkg.ErrScopeNotAllowed) {
		t.Fatalf("want ErrScopeNotAllowed, got %v", err)
	}
	req.Scope = "profile openid"
	if _, err := g.Push(req, now); err != nil {
		t.Fatalf("allowed scope was rejected: %v", err)
	}
}

// Only PKCE S256 is accepted; plain and empty methods are rejected.
func TestPKCEMethodMustBeS256(t *testing.T) {
	now := time.Unix(baseUnix, 0)
	g := newGuard(t, testPolicy())
	req := newRequest()
	req.CodeChallengeMethod = "plain"
	if _, err := g.Push(req, now); !errors.Is(err, taskpkg.ErrPKCE) {
		t.Fatalf("want ErrPKCE for plain, got %v", err)
	}
	req.CodeChallengeMethod = ""
	if _, err := g.Push(req, now); !errors.Is(err, taskpkg.ErrPKCE) {
		t.Fatalf("want ErrPKCE for an empty method, got %v", err)
	}
}

// A challenge shorter than the policy minimum must be rejected.
func TestCodeChallengeTooShort(t *testing.T) {
	now := time.Unix(baseUnix, 0)
	g := newGuard(t, testPolicy())
	req := newRequest()
	req.CodeChallenge = strings.Repeat("b", 42)
	if _, err := g.Push(req, now); !errors.Is(err, taskpkg.ErrPKCE) {
		t.Fatalf("want ErrPKCE for a 42 byte challenge, got %v", err)
	}
}

// An unregistered client id must be rejected before anything is stored.
func TestUnknownClientRejected(t *testing.T) {
	now := time.Unix(baseUnix, 0)
	g := newGuard(t, testPolicy())
	req := newRequest()
	req.ClientID = "client-ghost"
	if _, err := g.Push(req, now); !errors.Is(err, taskpkg.ErrClientUnknown) {
		t.Fatalf("want ErrClientUnknown, got %v", err)
	}
	if got := g.Stats().Pushed; got != 0 {
		t.Fatalf("rejected push counted as Pushed: %d", got)
	}
}

// Only response_type values listed in the policy are accepted.
func TestResponseTypeMustBeAllowed(t *testing.T) {
	now := time.Unix(baseUnix, 0)
	g := newGuard(t, testPolicy())
	req := newRequest()
	req.ResponseType = "token"
	if _, err := g.Push(req, now); !errors.Is(err, taskpkg.ErrResponseType) {
		t.Fatalf("want ErrResponseType, got %v", err)
	}
}

// Confidential clients must present the right secret.
func TestConfidentialClientSecretChecked(t *testing.T) {
	now := time.Unix(baseUnix, 0)
	g := newGuard(t, testPolicy())
	req := taskpkg.PARRequest{
		ClientID:            confidentialClient,
		ClientSecret:        "wrong-secret",
		RedirectURI:         batchRedirect,
		ResponseType:        "code",
		Scope:               "openid",
		State:               "st-batch",
		CodeChallenge:       strings.Repeat("c", 43),
		CodeChallengeMethod: "S256",
	}
	if _, err := g.Push(req, now); !errors.Is(err, taskpkg.ErrClientAuth) {
		t.Fatalf("want ErrClientAuth, got %v", err)
	}
	req.ClientSecret = "batch-secret"
	if _, err := g.Push(req, now); err != nil {
		t.Fatalf("correct secret rejected: %v", err)
	}
}

// A request uri minted for one client must not be redeemable by another.
func TestCrossClientConsumeRejected(t *testing.T) {
	now := time.Unix(baseUnix, 0)
	g := newGuard(t, testPolicy())
	uri := mustPush(t, g, newRequest(), now)
	if _, err := g.Consume(uri, confidentialClient, now); !errors.Is(err, taskpkg.ErrRequestOwner) {
		t.Fatalf("want ErrRequestOwner, got %v", err)
	}
	if _, err := g.Consume(uri, publicClient, now); err != nil {
		t.Fatalf("owner could not redeem after a foreign attempt: %v", err)
	}
}

// Concurrent redemption of one request uri may succeed only once.
func TestConcurrentConsumeSingleWinner(t *testing.T) {
	now := time.Unix(baseUnix, 0)
	g := newGuard(t, testPolicy())
	uri := mustPush(t, g, newRequest(), now)
	const workers = 6
	errs := make([]error, workers)
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func(idx int) {
			defer wg.Done()
			_, errs[idx] = g.Consume(uri, publicClient, now)
		}(i)
	}
	wg.Wait()
	winners := 0
	for _, err := range errs {
		if err == nil {
			winners++
		} else if !errors.Is(err, taskpkg.ErrRequestConsumed) {
			t.Fatalf("loser got %v, want ErrRequestConsumed", err)
		}
	}
	if winners != 1 {
		t.Fatalf("want exactly one winner, got %d", winners)
	}
}

// Outstanding requests must be bounded by MaxPending.
func TestCapacityLimitRejected(t *testing.T) {
	now := time.Unix(baseUnix, 0)
	p := testPolicy()
	p.MaxPending = 2
	g := newGuard(t, p)
	mustPush(t, g, newRequest(), now)
	mustPush(t, g, newRequest(), now)
	if _, err := g.Push(newRequest(), now); !errors.Is(err, taskpkg.ErrCapacity) {
		t.Fatalf("want ErrCapacity, got %v", err)
	}
	if got := g.Stats().Pending; got != 2 {
		t.Fatalf("Pending = %d, want 2", got)
	}
}

// Consumed markers and pending requests must survive a restart.
func TestSnapshotKeepsConsumedAndPending(t *testing.T) {
	now := time.Unix(baseUnix, 0)
	g := newGuard(t, testPolicy())
	first := mustPush(t, g, newRequest(), now)
	second := mustPush(t, g, newRequest(), now)
	if _, err := g.Consume(first, publicClient, now); err != nil {
		t.Fatalf("Consume: %v", err)
	}
	snapshot, err := g.Snapshot(now)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	restored, err := taskpkg.NewParGuardFromSnapshot(testPolicy(), snapshot)
	if err != nil {
		t.Fatalf("NewParGuardFromSnapshot: %v", err)
	}
	used, err := restored.Pending(first, now)
	if err != nil {
		t.Fatalf("Pending(consumed): %v", err)
	}
	if used {
		t.Fatalf("consumed request uri became pending after restart")
	}
	waiting, err := restored.Pending(second, now)
	if err != nil {
		t.Fatalf("Pending(pending): %v", err)
	}
	if !waiting {
		t.Fatalf("pending request uri lost across restart")
	}
	if _, err := restored.Consume(second, publicClient, now); err != nil {
		t.Fatalf("restored guard could not redeem the pending request: %v", err)
	}
}
