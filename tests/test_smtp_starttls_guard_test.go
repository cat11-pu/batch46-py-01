package task

import (
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	taskpkg "gsb/batch46-safety-d-02"
)

func smtpPolicy() taskpkg.Policy {
	return taskpkg.Policy{
		RequireTLS:    true,
		MinTLSVersion: "1.2",
		CapabilityTTL: time.Minute,
		MaxRecipients: 3,
		MaxSessions:   4,
	}
}

func mustGuard(t *testing.T, p taskpkg.Policy) *taskpkg.StarttlsGuard {
	t.Helper()
	g := taskpkg.NewStarttlsGuard(p)
	if g == nil {
		t.Fatalf("NewStarttlsGuard returned nil")
	}
	return g
}

func mustAdvertise(t *testing.T, g *taskpkg.StarttlsGuard, host string, caps []string, now time.Time) {
	t.Helper()
	if err := g.Advertise(host, caps, now); err != nil {
		t.Fatalf("Advertise(%q): %v", host, err)
	}
}

func mustSession(t *testing.T, g *taskpkg.StarttlsGuard, id, host string, now time.Time) taskpkg.Session {
	t.Helper()
	s, err := g.BeginSession(id, host, now)
	if err != nil {
		t.Fatalf("BeginSession(%q): %v", id, err)
	}
	return s
}

// mustTLSSession walks a session through EHLO and STARTTLS up to an
// established TLS channel.
func mustTLSSession(t *testing.T, g *taskpkg.StarttlsGuard, id, host string, now time.Time) {
	t.Helper()
	mustSession(t, g, id, host, now)
	if err := g.RequireStartTLS(id, now); err != nil {
		t.Fatalf("RequireStartTLS: %v", err)
	}
	if err := g.MarkTLS(id, "1.2", now); err != nil {
		t.Fatalf("MarkTLS: %v", err)
	}
}

// Capability lines carrying CRLF are a response-splitting attempt and must be
// refused before they enter the cache.
func TestAdvertiseRejectsInjection(t *testing.T) {
	g := mustGuard(t, smtpPolicy())
	now := time.Unix(1700000000, 0)
	if err := g.Advertise("mx.example.com", []string{"STARTTLS\r\n250 AUTH PLAIN"}, now); !errors.Is(err, taskpkg.ErrInjection) {
		t.Fatalf("CRLF in capability: want ErrInjection, got %v", err)
	}
	if err := g.Advertise("mx\r\n.example.com", []string{"STARTTLS"}, now); !errors.Is(err, taskpkg.ErrInjection) {
		t.Fatalf("CRLF in host: want ErrInjection, got %v", err)
	}
	mustAdvertise(t, g, "mx.example.com", []string{"STARTTLS", "AUTH PLAIN", "STARTTLS"}, now)
	caps, err := g.Capabilities("mx.example.com", now)
	if err != nil {
		t.Fatalf("Capabilities: %v", err)
	}
	if !reflect.DeepEqual(caps.Lines, []string{"STARTTLS", "AUTH PLAIN"}) {
		t.Fatalf("cached lines = %v, want deduplicated [STARTTLS AUTH PLAIN]", caps.Lines)
	}
}

// Cached capabilities expire after CapabilityTTL and unknown hosts are
// reported separately from stale hosts.
func TestCapabilityTTLAndUnknownHost(t *testing.T) {
	g := mustGuard(t, smtpPolicy())
	now := time.Unix(1700000000, 0)
	if _, err := g.Capabilities("ghost.example.com", now); !errors.Is(err, taskpkg.ErrCapabilityMissing) {
		t.Fatalf("unknown host: want ErrCapabilityMissing, got %v", err)
	}
	mustAdvertise(t, g, "mx.example.com", []string{"STARTTLS"}, now)
	if _, err := g.Capabilities("mx.example.com", now.Add(30*time.Second)); err != nil {
		t.Fatalf("fresh cache: %v", err)
	}
	if _, err := g.Capabilities("mx.example.com", now.Add(61*time.Second)); !errors.Is(err, taskpkg.ErrCapabilityStale) {
		t.Fatalf("expired cache: want ErrCapabilityStale, got %v", err)
	}
}

// Negotiate puts STARTTLS first, removes unknown lines and deduplicates.
func TestNegotiateOrderAndFilter(t *testing.T) {
	g := mustGuard(t, smtpPolicy())
	now := time.Unix(1700000000, 0)
	mustAdvertise(t, g, "mx.example.com", []string{"AUTH PLAIN LOGIN", "STARTTLS", "XTRN", "SIZE 102400", "STARTTLS"}, now)
	got, err := g.Negotiate("mx.example.com", now)
	if err != nil {
		t.Fatalf("Negotiate: %v", err)
	}
	want := []string{"STARTTLS", "AUTH PLAIN LOGIN", "SIZE 102400"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Negotiate = %v, want %v", got, want)
	}
}

// A host that no longer advertises STARTTLS must not be negotiated down to
// plaintext when the policy requires TLS.
func TestNegotiateRejectsDowngrade(t *testing.T) {
	g := mustGuard(t, smtpPolicy())
	now := time.Unix(1700000000, 0)
	mustAdvertise(t, g, "mx.example.com", []string{"AUTH PLAIN", "SIZE 102400"}, now)
	if _, err := g.Negotiate("mx.example.com", now); !errors.Is(err, taskpkg.ErrDowngrade) {
		t.Fatalf("missing STARTTLS: want ErrDowngrade, got %v", err)
	}
	if got := g.Counters().DowngradesRejected; got != 1 {
		t.Fatalf("DowngradesRejected = %d, want 1", got)
	}
}

// STARTTLS is issued at most once per session and moves the session to the
// greeted state.
func TestRequireStartTLSSingleIssue(t *testing.T) {
	g := mustGuard(t, smtpPolicy())
	now := time.Unix(1700000000, 0)
	mustAdvertise(t, g, "mx.example.com", []string{"STARTTLS", "AUTH PLAIN"}, now)
	mustSession(t, g, "s1", "mx.example.com", now)
	if err := g.RequireStartTLS("s1", now); err != nil {
		t.Fatalf("RequireStartTLS: %v", err)
	}
	if err := g.RequireStartTLS("s1", now); !errors.Is(err, taskpkg.ErrSessionState) {
		t.Fatalf("second STARTTLS: want ErrSessionState, got %v", err)
	}
	s, err := g.Session("s1")
	if err != nil {
		t.Fatalf("Session: %v", err)
	}
	if s.State != taskpkg.StateGreeted || !s.StartTLSIssued {
		t.Fatalf("session after STARTTLS = %+v, want greeted with StartTLSIssued", s)
	}
}

// Requiring STARTTLS against a host that never advertised it is a downgrade,
// not a state error.
func TestRequireStartTLSWithoutAdvertisement(t *testing.T) {
	g := mustGuard(t, smtpPolicy())
	now := time.Unix(1700000000, 0)
	mustAdvertise(t, g, "mx.example.com", []string{"AUTH PLAIN"}, now)
	mustSession(t, g, "s1", "mx.example.com", now)
	if err := g.RequireStartTLS("s1", now); !errors.Is(err, taskpkg.ErrDowngrade) {
		t.Fatalf("host without STARTTLS: want ErrDowngrade, got %v", err)
	}
}

// The TLS version must meet the policy floor, and a session may complete TLS
// only once.
func TestTLSVersionPolicy(t *testing.T) {
	g := mustGuard(t, smtpPolicy())
	now := time.Unix(1700000000, 0)
	mustAdvertise(t, g, "mx.example.com", []string{"STARTTLS", "AUTH PLAIN"}, now)
	mustSession(t, g, "s1", "mx.example.com", now)
	if err := g.RequireStartTLS("s1", now); err != nil {
		t.Fatalf("RequireStartTLS: %v", err)
	}
	if err := g.MarkTLS("s1", "1.0", now); !errors.Is(err, taskpkg.ErrTLSVersion) {
		t.Fatalf("TLS 1.0: want ErrTLSVersion, got %v", err)
	}
	if err := g.MarkTLS("s1", "1.2", now); err != nil {
		t.Fatalf("TLS 1.2: %v", err)
	}
	if err := g.MarkTLS("s1", "1.2", now); !errors.Is(err, taskpkg.ErrSessionState) {
		t.Fatalf("second handshake: want ErrSessionState, got %v", err)
	}
	s, err := g.Session("s1")
	if err != nil {
		t.Fatalf("Session: %v", err)
	}
	if s.State != taskpkg.StateTLS || s.TLSVersion != "1.2" {
		t.Fatalf("session after handshake = %+v", s)
	}
	if got := g.Counters().TLSCompleted; got != 1 {
		t.Fatalf("TLSCompleted = %d, want 1", got)
	}
}

// Dropping a session releases its identifier and later commands must report an
// unknown session.
func TestDropSessionReleasesState(t *testing.T) {
	g := mustGuard(t, smtpPolicy())
	now := time.Unix(1700000000, 0)
	mustAdvertise(t, g, "mx.example.com", []string{"STARTTLS", "AUTH PLAIN"}, now)
	mustSession(t, g, "s1", "mx.example.com", now)
	if err := g.DropSession("s1"); err != nil {
		t.Fatalf("DropSession: %v", err)
	}
	if _, err := g.Session("s1"); !errors.Is(err, taskpkg.ErrSessionNotFound) {
		t.Fatalf("Session after drop: want ErrSessionNotFound, got %v", err)
	}
	if err := g.RequireStartTLS("s1", now); !errors.Is(err, taskpkg.ErrSessionNotFound) {
		t.Fatalf("STARTTLS after drop: want ErrSessionNotFound, got %v", err)
	}
	if err := g.DropSession("s1"); !errors.Is(err, taskpkg.ErrSessionNotFound) {
		t.Fatalf("second drop: want ErrSessionNotFound, got %v", err)
	}
}

// AUTH before the handshake would leak the password and must be rejected.
func TestPlaintextAuthRejected(t *testing.T) {
	g := mustGuard(t, smtpPolicy())
	now := time.Unix(1700000000, 0)
	mustAdvertise(t, g, "mx.example.com", []string{"STARTTLS", "AUTH PLAIN"}, now)
	mustSession(t, g, "s1", "mx.example.com", now)
	if err := g.RequireStartTLS("s1", now); err != nil {
		t.Fatalf("RequireStartTLS: %v", err)
	}
	if err := g.Authenticate("s1", "PLAIN", "ops"); !errors.Is(err, taskpkg.ErrPlaintextAuth) {
		t.Fatalf("AUTH before TLS: want ErrPlaintextAuth, got %v", err)
	}
	if got := g.Counters().PlaintextAuthRejected; got != 1 {
		t.Fatalf("PlaintextAuthRejected = %d, want 1", got)
	}
}

// Only a mechanism the host advertised may be used.
func TestAuthMechanismMustBeAdvertised(t *testing.T) {
	g := mustGuard(t, smtpPolicy())
	now := time.Unix(1700000000, 0)
	mustAdvertise(t, g, "mx.example.com", []string{"STARTTLS", "AUTH PLAIN"}, now)
	mustTLSSession(t, g, "s1", "mx.example.com", now)
	if err := g.Authenticate("s1", "LOGIN", "ops"); !errors.Is(err, taskpkg.ErrAuthMechanism) {
		t.Fatalf("unadvertised LOGIN: want ErrAuthMechanism, got %v", err)
	}
	if err := g.Authenticate("s1", "PLAIN", "ops"); err != nil {
		t.Fatalf("advertised PLAIN: %v", err)
	}
	s, err := g.Session("s1")
	if err != nil {
		t.Fatalf("Session: %v", err)
	}
	if s.State != taskpkg.StateAuthenticated {
		t.Fatalf("state after AUTH = %q, want authenticated", s.State)
	}
}

// A session must not authenticate twice.
func TestAuthenticateDoubleRejected(t *testing.T) {
	g := mustGuard(t, smtpPolicy())
	now := time.Unix(1700000000, 0)
	mustAdvertise(t, g, "mx.example.com", []string{"STARTTLS", "AUTH PLAIN"}, now)
	mustTLSSession(t, g, "s1", "mx.example.com", now)
	if err := g.Authenticate("s1", "PLAIN", "ops"); err != nil {
		t.Fatalf("first AUTH: %v", err)
	}
	if err := g.Authenticate("s1", "PLAIN", "ops"); !errors.Is(err, taskpkg.ErrSessionState) {
		t.Fatalf("second AUTH: want ErrSessionState, got %v", err)
	}
}

// Recipients are deduplicated case-insensitively and keep their first order.
func TestRecipientsDedupedOrderPreserved(t *testing.T) {
	g := mustGuard(t, smtpPolicy())
	now := time.Unix(1700000000, 0)
	mustAdvertise(t, g, "mx.example.com", []string{"STARTTLS", "AUTH PLAIN"}, now)
	mustTLSSession(t, g, "s1", "mx.example.com", now)
	got, err := g.CheckRecipients("s1", []string{"a@example.com", "b@example.com", "A@Example.com", "b@example.com"})
	if err != nil {
		t.Fatalf("CheckRecipients: %v", err)
	}
	want := []string{"a@example.com", "b@example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("recipients = %v, want %v", got, want)
	}
	s, err := g.Session("s1")
	if err != nil {
		t.Fatalf("Session: %v", err)
	}
	if !reflect.DeepEqual(s.Recipients, want) {
		t.Fatalf("stored recipients = %v, want %v", s.Recipients, want)
	}
}

// The number of distinct recipients per message is capped.
func TestRecipientLimit(t *testing.T) {
	g := mustGuard(t, smtpPolicy())
	now := time.Unix(1700000000, 0)
	mustAdvertise(t, g, "mx.example.com", []string{"STARTTLS", "AUTH PLAIN"}, now)
	mustTLSSession(t, g, "s1", "mx.example.com", now)
	rcpts := []string{"a@example.com", "b@example.com", "c@example.com", "d@example.com"}
	if _, err := g.CheckRecipients("s1", rcpts); !errors.Is(err, taskpkg.ErrRecipientLimit) {
		t.Fatalf("4 recipients over limit 3: want ErrRecipientLimit, got %v", err)
	}
	if got := g.Counters().RecipientsRejected; got != 1 {
		t.Fatalf("RecipientsRejected = %d, want 1", got)
	}
	s, err := g.Session("s1")
	if err != nil {
		t.Fatalf("Session: %v", err)
	}
	if len(s.Recipients) != 0 {
		t.Fatalf("rejected recipient list was stored: %v", s.Recipients)
	}
}

// Two clients racing to issue STARTTLS on one session must not both win.
func TestConcurrentStartTLSSingleWinner(t *testing.T) {
	g := mustGuard(t, smtpPolicy())
	now := time.Unix(1700000000, 0)
	mustAdvertise(t, g, "mx.example.com", []string{"STARTTLS", "AUTH PLAIN"}, now)
	mustSession(t, g, "s1", "mx.example.com", now)
	var wg sync.WaitGroup
	errs := make([]error, 2)
	wg.Add(2)
	for i := 0; i < 2; i++ {
		go func(idx int) {
			defer wg.Done()
			errs[idx] = g.RequireStartTLS("s1", now)
		}(i)
	}
	wg.Wait()
	success := 0
	stateErrors := 0
	for _, err := range errs {
		switch {
		case err == nil:
			success++
		case errors.Is(err, taskpkg.ErrSessionState):
			stateErrors++
		}
	}
	if success != 1 || stateErrors != 1 {
		t.Fatalf("want one success and one state error, got success=%d state=%d errs=%v", success, stateErrors, errs)
	}
}

// A restart must retain the capability cache and each session's TLS state;
// corrupt snapshots are refused.
func TestSnapshotRestoresTLSStateAndCache(t *testing.T) {
	p := smtpPolicy()
	g := mustGuard(t, p)
	now := time.Unix(1700000000, 0)
	mustAdvertise(t, g, "mx.example.com", []string{"STARTTLS", "AUTH PLAIN"}, now)
	mustTLSSession(t, g, "s1", "mx.example.com", now)
	snap, err := g.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if _, err := taskpkg.NewStarttlsGuardFromSnapshot(p, []byte("not-json")); !errors.Is(err, taskpkg.ErrSnapshot) {
		t.Fatalf("corrupt snapshot: want ErrSnapshot, got %v", err)
	}
	restored, err := taskpkg.NewStarttlsGuardFromSnapshot(p, snap)
	if err != nil {
		t.Fatalf("NewStarttlsGuardFromSnapshot: %v", err)
	}
	s, err := restored.Session("s1")
	if err != nil {
		t.Fatalf("Session after restore: %v", err)
	}
	if s.State != taskpkg.StateTLS || s.TLSVersion != "1.2" {
		t.Fatalf("restored session = %+v, want tls/1.2", s)
	}
	if _, err := restored.Capabilities("mx.example.com", now.Add(20*time.Second)); err != nil {
		t.Fatalf("capability cache after restore: %v", err)
	}
	if err := restored.Authenticate("s1", "PLAIN", "ops"); err != nil {
		t.Fatalf("AUTH after restore: %v", err)
	}
}
