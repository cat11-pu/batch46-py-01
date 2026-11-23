package task

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	taskpkg "gsb/batch46-safety-a-02"
)

const baseUnix = 1730000000

func testPolicy() taskpkg.CachePolicy {
	return taskpkg.CachePolicy{
		TTL:           5 * time.Minute,
		NegativeTTL:   30 * time.Second,
		RevocationTTL: 2 * time.Minute,
		MaxEntries:    64,
	}
}

// fakeUpstream counts calls and returns canned introspection results.
type fakeUpstream struct {
	calls int32
	fn    func(token, tenantID string) (taskpkg.TokenInfo, error)
}

func (f *fakeUpstream) call(token, tenantID string) (taskpkg.TokenInfo, error) {
	atomic.AddInt32(&f.calls, 1)
	return f.fn(token, tenantID)
}

func (f *fakeUpstream) count() int {
	return int(atomic.LoadInt32(&f.calls))
}

func defaultUpstream() *fakeUpstream {
	return &fakeUpstream{fn: func(token, tenantID string) (taskpkg.TokenInfo, error) {
		switch token {
		case "tok-bad":
			return taskpkg.TokenInfo{}, errors.New("dial tcp 10.0.0.4:443: connection refused")
		case "tok-ghost":
			return taskpkg.TokenInfo{Active: false, TenantID: tenantID, ClientID: "client-pay"}, nil
		case "tok-short":
			return taskpkg.TokenInfo{
				Active:    true,
				Subject:   "svc-reports",
				TenantID:  tenantID,
				ClientID:  "client-reports",
				ExpiresAt: time.Unix(baseUnix+5, 0),
			}, nil
		case "tok-shared":
			return taskpkg.TokenInfo{
				Active:   tenantID == "tenant-a",
				Subject:  "svc-shared",
				TenantID: tenantID,
			}, nil
		default:
			return taskpkg.TokenInfo{
				Active:    true,
				Subject:   "svc-payments",
				TenantID:  tenantID,
				ClientID:  "client-pay",
				Scope:     []string{"pay:read", "pay:write"},
				ExpiresAt: time.Unix(baseUnix+3600, 0),
			}, nil
		}
	}}
}

// A positive result must be reused inside its lifetime.
func TestLookupCachesPositiveResult(t *testing.T) {
	now := time.Unix(baseUnix, 0)
	up := defaultUpstream()
	c := taskpkg.NewIntrospectionCache(testPolicy(), up.call)
	info, err := c.Lookup("tok-1", "tenant-a", now)
	if err != nil {
		t.Fatalf("first lookup: %v", err)
	}
	if !info.Active || info.Subject != "svc-payments" || len(info.Scope) != 2 {
		t.Fatalf("unexpected introspection result: %+v", info)
	}
	again, err := c.Lookup("tok-1", "tenant-a", now.Add(time.Minute))
	if err != nil {
		t.Fatalf("cached lookup: %v", err)
	}
	if again.ClientID != "client-pay" {
		t.Fatalf("cached client mismatch: %q", again.ClientID)
	}
	if up.count() != 1 {
		t.Fatalf("upstream called %d times, want 1", up.count())
	}
	if got := c.Stats().Hits; got != 1 {
		t.Fatalf("Hits = %d, want 1", got)
	}
}

// A result older than TTL must be fetched again.
func TestExpiredEntryRefetched(t *testing.T) {
	now := time.Unix(baseUnix, 0)
	up := defaultUpstream()
	c := taskpkg.NewIntrospectionCache(testPolicy(), up.call)
	if _, err := c.Lookup("tok-1", "tenant-a", now); err != nil {
		t.Fatalf("first lookup: %v", err)
	}
	if _, err := c.Lookup("tok-1", "tenant-a", now.Add(6*time.Minute)); err != nil {
		t.Fatalf("lookup after expiry: %v", err)
	}
	if up.count() != 2 {
		t.Fatalf("upstream called %d times, want 2", up.count())
	}
	if got := c.Stats().Misses; got != 2 {
		t.Fatalf("Misses = %d, want 2", got)
	}
}

// Inactive results are cached with the shorter negative lifetime.
func TestInactiveResultCachedWithNegativeTTL(t *testing.T) {
	now := time.Unix(baseUnix, 0)
	up := defaultUpstream()
	c := taskpkg.NewIntrospectionCache(testPolicy(), up.call)
	info, err := c.Lookup("tok-ghost", "tenant-a", now)
	if err != nil {
		t.Fatalf("first lookup: %v", err)
	}
	if info.Active {
		t.Fatalf("ghost token reported active")
	}
	if _, err := c.Lookup("tok-ghost", "tenant-a", now.Add(10*time.Second)); err != nil {
		t.Fatalf("cached negative lookup: %v", err)
	}
	if up.count() != 1 {
		t.Fatalf("negative entry not cached, upstream calls = %d", up.count())
	}
	if _, err := c.Lookup("tok-ghost", "tenant-a", now.Add(31*time.Second)); err != nil {
		t.Fatalf("lookup after negative TTL: %v", err)
	}
	if up.count() != 2 {
		t.Fatalf("expired negative entry was reused, upstream calls = %d", up.count())
	}
}

// An upstream failure must not be cached and must surface as ErrUpstream.
func TestUpstreamErrorNotCached(t *testing.T) {
	now := time.Unix(baseUnix, 0)
	up := defaultUpstream()
	c := taskpkg.NewIntrospectionCache(testPolicy(), up.call)
	if _, err := c.Lookup("tok-bad", "tenant-a", now); !errors.Is(err, taskpkg.ErrUpstream) {
		t.Fatalf("want ErrUpstream, got %v", err)
	}
	if _, err := c.Lookup("tok-bad", "tenant-a", now); !errors.Is(err, taskpkg.ErrUpstream) {
		t.Fatalf("second want ErrUpstream, got %v", err)
	}
	if up.count() != 2 {
		t.Fatalf("failed introspection was cached, upstream calls = %d", up.count())
	}
	if got := c.Stats().Entries; got != 0 {
		t.Fatalf("Entries = %d after failures, want 0", got)
	}
}

// A locally revoked token is rejected before any upstream call.
func TestRevokedTokenRejectedWithoutUpstream(t *testing.T) {
	now := time.Unix(baseUnix, 0)
	up := defaultUpstream()
	c := taskpkg.NewIntrospectionCache(testPolicy(), up.call)
	if err := c.Revoke("tok-1", "tenant-a", now); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := c.Lookup("tok-1", "tenant-a", now); !errors.Is(err, taskpkg.ErrRevoked) {
		t.Fatalf("want ErrRevoked, got %v", err)
	}
	if up.count() != 0 {
		t.Fatalf("upstream was called for a revoked token: %d", up.count())
	}
	revoked, err := c.Revoked("tok-1", "tenant-a", now)
	if err != nil {
		t.Fatalf("Revoked: %v", err)
	}
	if !revoked {
		t.Fatalf("token not reported as revoked")
	}
}

// Revocation must outlive the positive cache entry.
func TestRevocationSurvivesCacheExpiry(t *testing.T) {
	now := time.Unix(baseUnix, 0)
	pol := testPolicy()
	pol.TTL = 30 * time.Second
	pol.RevocationTTL = 5 * time.Minute
	up := defaultUpstream()
	c := taskpkg.NewIntrospectionCache(pol, up.call)
	if _, err := c.Lookup("tok-1", "tenant-a", now); err != nil {
		t.Fatalf("first lookup: %v", err)
	}
	if err := c.Revoke("tok-1", "tenant-a", now); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := c.Lookup("tok-1", "tenant-a", now.Add(time.Minute)); !errors.Is(err, taskpkg.ErrRevoked) {
		t.Fatalf("want ErrRevoked after cache expiry, got %v", err)
	}
	if up.count() != 1 {
		t.Fatalf("upstream was consulted during revocation: %d calls", up.count())
	}
}

// Once the revocation deadline passes the token may be introspected again.
func TestRevocationExpires(t *testing.T) {
	now := time.Unix(baseUnix, 0)
	pol := testPolicy()
	pol.RevocationTTL = time.Minute
	up := defaultUpstream()
	c := taskpkg.NewIntrospectionCache(pol, up.call)
	if _, err := c.Lookup("tok-1", "tenant-a", now); err != nil {
		t.Fatalf("first lookup: %v", err)
	}
	if err := c.Revoke("tok-1", "tenant-a", now); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	info, err := c.Lookup("tok-1", "tenant-a", now.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("lookup after revocation expiry: %v", err)
	}
	if !info.Active {
		t.Fatalf("token still inactive after revocation expiry")
	}
	if up.count() != 2 {
		t.Fatalf("upstream calls = %d, want 2", up.count())
	}
}

// A cached result must not outlive the token's own expiry.
func TestAccessTokenExpiryClampsTTL(t *testing.T) {
	now := time.Unix(baseUnix, 0)
	up := defaultUpstream()
	c := taskpkg.NewIntrospectionCache(testPolicy(), up.call)
	if _, err := c.Lookup("tok-short", "tenant-a", now); err != nil {
		t.Fatalf("first lookup: %v", err)
	}
	if _, err := c.Lookup("tok-short", "tenant-a", now.Add(4*time.Second)); err != nil {
		t.Fatalf("lookup before token expiry: %v", err)
	}
	if up.count() != 1 {
		t.Fatalf("entry expired too early, upstream calls = %d", up.count())
	}
	if _, err := c.Lookup("tok-short", "tenant-a", now.Add(6*time.Second)); err != nil {
		t.Fatalf("lookup after token expiry: %v", err)
	}
	if up.count() != 2 {
		t.Fatalf("entry outlived the token, upstream calls = %d", up.count())
	}
}

// Concurrent lookups of one key must share a single upstream call.
func TestSingleFlightCoalescesConcurrentLookups(t *testing.T) {
	now := time.Unix(baseUnix, 0)
	up := defaultUpstream()
	slow := &fakeUpstream{fn: func(token, tenantID string) (taskpkg.TokenInfo, error) {
		time.Sleep(20 * time.Millisecond)
		return up.call(token, tenantID)
	}}
	c := taskpkg.NewIntrospectionCache(testPolicy(), slow.call)
	const workers = 8
	errs := make([]error, workers)
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func(idx int) {
			defer wg.Done()
			_, errs[idx] = c.Lookup("tok-1", "tenant-a", now)
		}(i)
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatalf("concurrent lookup failed: %v", err)
		}
	}
	if up.count() != 1 {
		t.Fatalf("upstream called %d times, want 1", up.count())
	}
}

// The cache key must include the tenant, not only the token string.
func TestTenantIsolationInCacheKey(t *testing.T) {
	now := time.Unix(baseUnix, 0)
	up := defaultUpstream()
	c := taskpkg.NewIntrospectionCache(testPolicy(), up.call)
	a, err := c.Lookup("tok-shared", "tenant-a", now)
	if err != nil {
		t.Fatalf("tenant-a lookup: %v", err)
	}
	b, err := c.Lookup("tok-shared", "tenant-b", now)
	if err != nil {
		t.Fatalf("tenant-b lookup: %v", err)
	}
	if !a.Active || b.Active {
		t.Fatalf("tenant results crossed: a=%v b=%v", a.Active, b.Active)
	}
	if up.count() != 2 {
		t.Fatalf("tenants shared one entry, upstream calls = %d", up.count())
	}
	if _, err := c.Lookup("tok-shared", "tenant-a", now.Add(time.Second)); err != nil {
		t.Fatalf("repeat tenant-a lookup: %v", err)
	}
	if up.count() != 2 {
		t.Fatalf("per-tenant entry was not cached, upstream calls = %d", up.count())
	}
}

// At capacity the least recently used entry is evicted.
func TestLRUEvictionAtCapacity(t *testing.T) {
	now := time.Unix(baseUnix, 0)
	pol := testPolicy()
	pol.MaxEntries = 2
	up := defaultUpstream()
	c := taskpkg.NewIntrospectionCache(pol, up.call)
	for _, tok := range []string{"tok-a", "tok-b", "tok-c"} {
		if _, err := c.Lookup(tok, "tenant-a", now); err != nil {
			t.Fatalf("lookup %s: %v", tok, err)
		}
	}
	if got := c.Stats().Entries; got != 2 {
		t.Fatalf("Entries = %d, want 2", got)
	}
	if got := c.Stats().Evictions; got != 1 {
		t.Fatalf("Evictions = %d, want 1", got)
	}
	if _, err := c.Lookup("tok-a", "tenant-a", now); err != nil {
		t.Fatalf("lookup evicted token: %v", err)
	}
	if up.count() != 4 {
		t.Fatalf("evicted entry was served from cache, upstream calls = %d", up.count())
	}
}

// Cached entries and revocation markers must survive a restart.
func TestSnapshotRestoresCacheAcrossRestart(t *testing.T) {
	now := time.Unix(baseUnix, 0)
	pol := testPolicy()
	up := defaultUpstream()
	c := taskpkg.NewIntrospectionCache(pol, up.call)
	if _, err := c.Lookup("tok-1", "tenant-a", now); err != nil {
		t.Fatalf("first lookup: %v", err)
	}
	if err := c.Revoke("tok-2", "tenant-a", now); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	snapshot, err := c.Snapshot(now)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	restored, err := taskpkg.NewIntrospectionCacheFromSnapshot(pol, up.call, snapshot)
	if err != nil {
		t.Fatalf("NewIntrospectionCacheFromSnapshot: %v", err)
	}
	info, err := restored.Lookup("tok-1", "tenant-a", now.Add(time.Minute))
	if err != nil {
		t.Fatalf("restored lookup: %v", err)
	}
	if !info.Active || info.Subject != "svc-payments" {
		t.Fatalf("restored entry mismatch: %+v", info)
	}
	if up.count() != 1 {
		t.Fatalf("restored entry was not used, upstream calls = %d", up.count())
	}
	if _, err := restored.Lookup("tok-2", "tenant-a", now); !errors.Is(err, taskpkg.ErrRevoked) {
		t.Fatalf("revocation marker lost across restart: %v", err)
	}
}

// Prune drops everything that has expired and reports the count.
func TestPruneRemovesExpiredEntries(t *testing.T) {
	now := time.Unix(baseUnix, 0)
	up := defaultUpstream()
	c := taskpkg.NewIntrospectionCache(testPolicy(), up.call)
	for _, tok := range []string{"tok-a", "tok-b"} {
		if _, err := c.Lookup(tok, "tenant-a", now); err != nil {
			t.Fatalf("lookup %s: %v", tok, err)
		}
	}
	if removed := c.Prune(now.Add(10 * time.Minute)); removed != 2 {
		t.Fatalf("Prune removed %d, want 2", removed)
	}
	if got := c.Stats().Entries; got != 0 {
		t.Fatalf("Entries = %d after prune, want 0", got)
	}
	if removed := c.Prune(now.Add(10 * time.Minute)); removed != 0 {
		t.Fatalf("second Prune removed %d, want 0", removed)
	}
}

// Shrinking the cache evicts the oldest entries and rejects invalid bounds.
func TestResizeEvictsOldestEntries(t *testing.T) {
	now := time.Unix(baseUnix, 0)
	up := defaultUpstream()
	c := taskpkg.NewIntrospectionCache(testPolicy(), up.call)
	for _, tok := range []string{"tok-a", "tok-b", "tok-c"} {
		if _, err := c.Lookup(tok, "tenant-a", now); err != nil {
			t.Fatalf("lookup %s: %v", tok, err)
		}
	}
	if err := c.Resize(1); err != nil {
		t.Fatalf("Resize: %v", err)
	}
	if got := c.Stats().Entries; got != 1 {
		t.Fatalf("Entries = %d after resize, want 1", got)
	}
	if _, err := c.Lookup("tok-a", "tenant-a", now); err != nil {
		t.Fatalf("lookup after resize: %v", err)
	}
	if up.count() != 4 {
		t.Fatalf("shrunk cache served an evicted entry, upstream calls = %d", up.count())
	}
	if err := c.Resize(0); !errors.Is(err, taskpkg.ErrBadCapacity) {
		t.Fatalf("want ErrBadCapacity for a zero bound, got %v", err)
	}
}

// Flush empties the cache and the next lookup goes upstream again.
func TestFlushClearsEntries(t *testing.T) {
	now := time.Unix(baseUnix, 0)
	up := defaultUpstream()
	c := taskpkg.NewIntrospectionCache(testPolicy(), up.call)
	for _, tok := range []string{"tok-a", "tok-b"} {
		if _, err := c.Lookup(tok, "tenant-a", now); err != nil {
			t.Fatalf("lookup %s: %v", tok, err)
		}
	}
	if removed := c.Flush(); removed != 2 {
		t.Fatalf("Flush removed %d, want 2", removed)
	}
	if got := c.Stats().Entries; got != 0 {
		t.Fatalf("Entries = %d after flush, want 0", got)
	}
	if _, err := c.Lookup("tok-a", "tenant-a", now); err != nil {
		t.Fatalf("lookup after flush: %v", err)
	}
	if up.count() != 3 {
		t.Fatalf("lookup after flush hit cache, upstream calls = %d", up.count())
	}
}
