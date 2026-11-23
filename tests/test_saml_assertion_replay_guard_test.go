package task

import (
	"errors"
	"sync"
	"testing"
	"time"

	taskpkg "gsb/batch46-safety-a-01"
)

const (
	acsURL    = "https://sp.example.com/saml/acs"
	issuerID  = "https://idp.example.com/metadata"
	subjectID = "alice@corp.example.com"
)

func testPolicy() taskpkg.Policy {
	return taskpkg.Policy{
		MaxClockSkew:     30 * time.Second,
		ReplayTTL:        time.Hour,
		MaxAssertionAge:  10 * time.Minute,
		MaxReplayEntries: 64,
	}
}

func newGuard(t *testing.T, p taskpkg.Policy) *taskpkg.SamlReplayGuard {
	t.Helper()
	g := taskpkg.NewSamlReplayGuard(p)
	if err := g.RegisterServiceProvider("tenant-a", issuerID, acsURL, []string{"sp-a"}); err != nil {
		t.Fatalf("RegisterServiceProvider: %v", err)
	}
	return g
}

func trackRequest(t *testing.T, g *taskpkg.SamlReplayGuard, requestID string, now time.Time) {
	t.Helper()
	if err := g.TrackRequest("tenant-a", requestID, now); err != nil {
		t.Fatalf("TrackRequest(%q): %v", requestID, err)
	}
}

func newAssertion(id, requestID string, now time.Time) taskpkg.Assertion {
	return taskpkg.Assertion{
		ID:             id,
		Issuer:         issuerID,
		Audience:       "sp-a",
		Destination:    acsURL,
		Subject:        subjectID,
		TenantID:       "tenant-a",
		InResponseTo:   requestID,
		NotBefore:      now.Add(-2 * time.Minute),
		NotOnOrAfter:   now.Add(5 * time.Minute),
		IssueInstant:   now.Add(-10 * time.Second),
		SignatureValid: true,
		Attributes:     map[string]string{"role": "admin", "dept": "sre"},
	}
}

func mustAccept(t *testing.T, g *taskpkg.SamlReplayGuard, a taskpkg.Assertion, requestID string, now time.Time) taskpkg.Identity {
	t.Helper()
	identity, err := g.Validate(a, requestID, now)
	if err != nil {
		t.Fatalf("valid assertion was rejected: %v", err)
	}
	return identity
}

// A correct assertion must produce an identity carrying the attributes.
func TestValidAssertionAccepted(t *testing.T) {
	now := time.Unix(1730000000, 0)
	g := newGuard(t, testPolicy())
	trackRequest(t, g, "req-1", now)
	identity := mustAccept(t, g, newAssertion("a-1", "req-1", now), "req-1", now)
	if identity.TenantID != "tenant-a" {
		t.Fatalf("tenant mismatch: %q", identity.TenantID)
	}
	if identity.Subject != subjectID {
		t.Fatalf("subject mismatch: %q", identity.Subject)
	}
	if identity.AssertionID != "a-1" {
		t.Fatalf("assertion id not recorded: %q", identity.AssertionID)
	}
	if identity.Attributes["role"] != "admin" || identity.Attributes["dept"] != "sre" {
		t.Fatalf("attributes not copied: %+v", identity.Attributes)
	}
}

// The same assertion id must not be usable twice inside the replay window.
func TestAssertionIDReplayRejected(t *testing.T) {
	now := time.Unix(1730000000, 0)
	g := newGuard(t, testPolicy())
	trackRequest(t, g, "req-1", now)
	mustAccept(t, g, newAssertion("a-replay", "req-1", now), "req-1", now)
	trackRequest(t, g, "req-2", now)
	if _, err := g.Validate(newAssertion("a-replay", "req-2", now), "req-2", now); !errors.Is(err, taskpkg.ErrReplay) {
		t.Fatalf("want ErrReplay for a reused assertion id, got %v", err)
	}
	if got := g.Stats().ReplayHits; got != 1 {
		t.Fatalf("ReplayHits = %d, want 1", got)
	}
}

// The audience must be one registered for the relying party.
func TestAudienceMustBeAllowed(t *testing.T) {
	now := time.Unix(1730000000, 0)
	g := newGuard(t, testPolicy())
	trackRequest(t, g, "req-1", now)
	a := newAssertion("a-aud", "req-1", now)
	a.Audience = "sp-other"
	if _, err := g.Validate(a, "req-1", now); !errors.Is(err, taskpkg.ErrAudienceMismatch) {
		t.Fatalf("want ErrAudienceMismatch, got %v", err)
	}
}

// InResponseTo must reference a tracked authentication request.
func TestUnknownRequestReferenceRejected(t *testing.T) {
	now := time.Unix(1730000000, 0)
	g := newGuard(t, testPolicy())
	if _, err := g.Validate(newAssertion("a-req", "req-missing", now), "req-missing", now); !errors.Is(err, taskpkg.ErrUnknownRequest) {
		t.Fatalf("want ErrUnknownRequest, got %v", err)
	}
}

// An assertion whose NotOnOrAfter is outside the skew must expire.
func TestExpiredAssertionRejected(t *testing.T) {
	now := time.Unix(1730000000, 0)
	g := newGuard(t, testPolicy())
	trackRequest(t, g, "req-1", now)
	a := newAssertion("a-exp", "req-1", now)
	a.NotOnOrAfter = now.Add(-time.Minute)
	if _, err := g.Validate(a, "req-1", now); !errors.Is(err, taskpkg.ErrAssertionExpired) {
		t.Fatalf("want ErrAssertionExpired, got %v", err)
	}
}

// A not-yet-valid assertion must be invalid, not accepted early.
func TestNotBeforeInFutureRejected(t *testing.T) {
	now := time.Unix(1730000000, 0)
	g := newGuard(t, testPolicy())
	trackRequest(t, g, "req-1", now)
	a := newAssertion("a-nbf", "req-1", now)
	a.NotBefore = now.Add(2 * time.Minute)
	if _, err := g.Validate(a, "req-1", now); !errors.Is(err, taskpkg.ErrAssertionInvalid) {
		t.Fatalf("want ErrAssertionInvalid, got %v", err)
	}
}

// Times inside the allowed skew must still be accepted.
func TestClockSkewToleratedAtBoundary(t *testing.T) {
	now := time.Unix(1730000000, 0)
	g := newGuard(t, testPolicy())
	trackRequest(t, g, "req-1", now)
	a := newAssertion("a-skew", "req-1", now)
	a.NotOnOrAfter = now.Add(-10 * time.Second)
	a.NotBefore = now.Add(-3 * time.Minute)
	identity := mustAccept(t, g, a, "req-1", now)
	if identity.Subject != subjectID {
		t.Fatalf("subject mismatch: %q", identity.Subject)
	}
}

// When the signature does not verify the error must be ErrSignature.
func TestTamperedSignatureRejected(t *testing.T) {
	now := time.Unix(1730000000, 0)
	g := newGuard(t, testPolicy())
	trackRequest(t, g, "req-1", now)
	a := newAssertion("a-sig", "req-1", now)
	a.SignatureValid = false
	if _, err := g.Validate(a, "req-1", now); !errors.Is(err, taskpkg.ErrSignature) {
		t.Fatalf("want ErrSignature, got %v", err)
	} else if errors.Is(err, taskpkg.ErrReplay) {
		t.Fatalf("signature failure reported as a replay")
	}
}

// The issuer must be the entity id registered for the tenant.
func TestUnregisteredIssuerRejected(t *testing.T) {
	now := time.Unix(1730000000, 0)
	g := newGuard(t, testPolicy())
	trackRequest(t, g, "req-1", now)
	a := newAssertion("a-issuer", "req-1", now)
	a.Issuer = "https://evil.example.com/metadata"
	if _, err := g.Validate(a, "req-1", now); !errors.Is(err, taskpkg.ErrIssuerUnknown) {
		t.Fatalf("want ErrIssuerUnknown, got %v", err)
	}
}

// Destination must equal the registered ACS URL, not merely share a prefix.
func TestDestinationMismatchRejected(t *testing.T) {
	now := time.Unix(1730000000, 0)
	g := newGuard(t, testPolicy())
	trackRequest(t, g, "req-1", now)
	a := newAssertion("a-dest", "req-1", now)
	a.Destination = acsURL + "/other"
	if _, err := g.Validate(a, "req-1", now); !errors.Is(err, taskpkg.ErrDestination) {
		t.Fatalf("want ErrDestination, got %v", err)
	}
}

// A tenant must not be able to consume another tenant's assertion.
func TestCrossTenantAssertionRejected(t *testing.T) {
	now := time.Unix(1730000000, 0)
	g := newGuard(t, testPolicy())
	trackRequest(t, g, "req-1", now)
	a := newAssertion("a-tenant", "req-1", now)
	a.TenantID = "tenant-b"
	if _, err := g.Validate(a, "req-1", now); !errors.Is(err, taskpkg.ErrTenantMismatch) {
		t.Fatalf("want ErrTenantMismatch, got %v", err)
	}
}

// Concurrent submissions of one assertion id may succeed only once.
func TestConcurrentSameAssertionSingleAccept(t *testing.T) {
	now := time.Unix(1730000000, 0)
	g := newGuard(t, testPolicy())
	trackRequest(t, g, "req-race", now)
	a := newAssertion("a-race", "req-race", now)
	const workers = 8
	errs := make([]error, workers)
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func(idx int) {
			defer wg.Done()
			_, errs[idx] = g.Validate(a, "req-race", now)
		}(i)
	}
	wg.Wait()
	accepted := 0
	for _, err := range errs {
		if err == nil {
			accepted++
		} else if !errors.Is(err, taskpkg.ErrReplay) {
			t.Fatalf("concurrent loser got %v, want ErrReplay", err)
		}
	}
	if accepted != 1 {
		t.Fatalf("want exactly one accepted assertion, got %d", accepted)
	}
}

// Replay knowledge must survive a restart through the snapshot round trip.
func TestReplayStateSurvivesRestart(t *testing.T) {
	now := time.Unix(1730000000, 0)
	g := newGuard(t, testPolicy())
	trackRequest(t, g, "req-1", now)
	mustAccept(t, g, newAssertion("a-snap", "req-1", now), "req-1", now)
	snapshot, err := g.Snapshot(now)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	restored, err := taskpkg.NewSamlReplayGuardFromSnapshot(testPolicy(), snapshot)
	if err != nil {
		t.Fatalf("NewSamlReplayGuardFromSnapshot: %v", err)
	}
	seen, err := restored.AssertionSeen("tenant-a", "a-snap", now.Add(time.Minute))
	if err != nil {
		t.Fatalf("AssertionSeen: %v", err)
	}
	if !seen {
		t.Fatalf("assertion id forgotten across restart")
	}
	if removed := restored.Prune(now.Add(2 * time.Hour)); removed != 1 {
		t.Fatalf("Prune removed %d entries, want 1", removed)
	}
	seen, err = restored.AssertionSeen("tenant-a", "a-snap", now.Add(2*time.Hour))
	if err != nil {
		t.Fatalf("AssertionSeen after prune: %v", err)
	}
	if seen {
		t.Fatalf("prune left an expired assertion id behind")
	}
}

// The replay table must honour its bound instead of silently dropping history.
func TestReplayStoreCapacityLimit(t *testing.T) {
	now := time.Unix(1730000000, 0)
	p := testPolicy()
	p.MaxReplayEntries = 2
	g := newGuard(t, p)
	for i, id := range []string{"a-1", "a-2"} {
		req := []string{"req-1", "req-2"}[i]
		trackRequest(t, g, req, now)
		mustAccept(t, g, newAssertion(id, req, now), req, now)
	}
	trackRequest(t, g, "req-3", now)
	if _, err := g.Validate(newAssertion("a-3", "req-3", now), "req-3", now); !errors.Is(err, taskpkg.ErrCapacity) {
		t.Fatalf("want ErrCapacity when the replay table is full, got %v", err)
	}
	if got := g.Stats().ReplayEntries; got != 2 {
		t.Fatalf("ReplayEntries = %d, want 2", got)
	}
}

// A revoked subject must be rejected until the revocation expires.
func TestRevokedSubjectRejectedUntilExpiry(t *testing.T) {
	now := time.Unix(1730000000, 0)
	g := newGuard(t, testPolicy())
	until := now.Add(10 * time.Minute)
	if err := g.RevokeSubject("tenant-a", "bob@corp.example.com", until); err != nil {
		t.Fatalf("RevokeSubject: %v", err)
	}
	revoked, err := g.SubjectRevoked("tenant-a", "bob@corp.example.com", now)
	if err != nil {
		t.Fatalf("SubjectRevoked: %v", err)
	}
	if !revoked {
		t.Fatalf("subject was not reported as revoked")
	}
	trackRequest(t, g, "req-1", now)
	a := newAssertion("a-revoked", "req-1", now)
	a.Subject = "bob@corp.example.com"
	if _, err := g.Validate(a, "req-1", now); !errors.Is(err, taskpkg.ErrSubjectRevoked) {
		t.Fatalf("want ErrSubjectRevoked, got %v", err)
	}
	stillRevoked, err := g.SubjectRevoked("tenant-a", "bob@corp.example.com", until.Add(time.Second))
	if err != nil {
		t.Fatalf("SubjectRevoked after expiry: %v", err)
	}
	if stillRevoked {
		t.Fatalf("revocation did not expire at its deadline")
	}
}
