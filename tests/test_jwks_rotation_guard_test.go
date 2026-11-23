package task

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	taskpkg "gsb/batch46-safety-b-03"
)

func jwksConfig() taskpkg.Config {
	return taskpkg.Config{
		Issuer:    "https://issuer.example.com",
		Audience:  "api://payments",
		KeyTTL:    time.Hour,
		KeyGrace:  5 * time.Minute,
		MaxKeys:   8,
		ClockSkew: 30 * time.Second,
	}
}

func testKey(kid, alg string, now time.Time) taskpkg.Key {
	return taskpkg.Key{
		KID:       kid,
		Alg:       alg,
		PublicKey: "pk-" + kid,
		NotBefore: now.Add(-time.Minute),
		ExpiresAt: now.Add(time.Hour),
	}
}

func jwksClaims(exp time.Time) taskpkg.Claims {
	return taskpkg.Claims{
		Issuer:    "https://issuer.example.com",
		Audience:  "api://payments",
		ExpiresAt: exp,
	}
}

func mustPublish(t *testing.T, g *taskpkg.JwksGuard, k taskpkg.Key, now time.Time) {
	t.Helper()
	if err := g.PublishKey(k, now); err != nil {
		t.Fatalf("PublishKey(%s): %v", k.KID, err)
	}
}

// The "none" algorithm must never enter the key cache.
func TestPublishKeyRejectsAlgNone(t *testing.T) {
	g := taskpkg.NewJwksGuard(jwksConfig(), nil)
	now := time.Unix(1700000000, 0)
	if err := g.PublishKey(testKey("k-none", "none", now), now); !errors.Is(err, taskpkg.ErrKeyInvalid) {
		t.Fatalf("PublishKey alg none err = %v, want ErrKeyInvalid", err)
	}
}

// A provider key with a longer lifetime than the cache TTL is trimmed to the
// TTL.
func TestPublishKeyCapsExpiryToCacheTTL(t *testing.T) {
	cfg := jwksConfig()
	cfg.KeyTTL = 10 * time.Minute
	g := taskpkg.NewJwksGuard(cfg, nil)
	now := time.Unix(1700000000, 0)
	k := testKey("k-long", "ES256", now)
	k.ExpiresAt = now.Add(48 * time.Hour)
	mustPublish(t, g, k, now)

	if _, err := g.KeyFor("k-long", now.Add(11*time.Minute)); !errors.Is(err, taskpkg.ErrKeyExpired) {
		t.Fatalf("KeyFor after the 10m TTL err = %v, want ErrKeyExpired", err)
	}
}

// The cache must refuse keys beyond its size budget.
func TestPublishKeyEnforcesMaxKeys(t *testing.T) {
	cfg := jwksConfig()
	cfg.MaxKeys = 2
	g := taskpkg.NewJwksGuard(cfg, nil)
	now := time.Unix(1700000000, 0)
	mustPublish(t, g, testKey("k1", "ES256", now), now)
	mustPublish(t, g, testKey("k2", "RS256", now), now)

	if err := g.PublishKey(testKey("k3", "ES256", now), now); !errors.Is(err, taskpkg.ErrTooManyKeys) {
		t.Fatalf("third PublishKey err = %v, want ErrTooManyKeys", err)
	}
}

// An unknown key id must be reported as missing, not as an expired key.
func TestKeyForUnknownKID(t *testing.T) {
	g := taskpkg.NewJwksGuard(jwksConfig(), nil)
	if _, err := g.KeyFor("kid-ghost", time.Unix(1700000000, 0)); !errors.Is(err, taskpkg.ErrKeyNotFound) {
		t.Fatalf("KeyFor(ghost) err = %v, want ErrKeyNotFound", err)
	}
}

// A token header must use the algorithm bound to the key the header names.
func TestVerifyRejectsHeaderAlgorithmMismatch(t *testing.T) {
	g := taskpkg.NewJwksGuard(jwksConfig(), nil)
	now := time.Unix(1700000000, 0)
	mustPublish(t, g, testKey("k1", "ES256", now), now)

	h := taskpkg.Header{KID: "k1", Alg: "RS256"}
	if _, err := g.Verify(h, jwksClaims(now.Add(5*time.Minute)), now); !errors.Is(err, taskpkg.ErrAlgMismatch) {
		t.Fatalf("Verify with a foreign alg err = %v, want ErrAlgMismatch", err)
	}
}

// Verification must reject an expired token.
func TestVerifyRejectsExpiredToken(t *testing.T) {
	g := taskpkg.NewJwksGuard(jwksConfig(), nil)
	now := time.Unix(1700000000, 0)
	mustPublish(t, g, testKey("k1", "ES256", now), now)

	h := taskpkg.Header{KID: "k1", Alg: "ES256"}
	if _, err := g.Verify(h, jwksClaims(now.Add(-10*time.Minute)), now); !errors.Is(err, taskpkg.ErrTokenExpired) {
		t.Fatalf("Verify expired token err = %v, want ErrTokenExpired", err)
	}
}

// A token from another issuer must not verify against this cache.
func TestVerifyRejectsForeignIssuer(t *testing.T) {
	g := taskpkg.NewJwksGuard(jwksConfig(), nil)
	now := time.Unix(1700000000, 0)
	mustPublish(t, g, testKey("k1", "ES256", now), now)
	c := jwksClaims(now.Add(5 * time.Minute))
	c.Issuer = "https://evil.example.com"

	h := taskpkg.Header{KID: "k1", Alg: "ES256"}
	if _, err := g.Verify(h, c, now); !errors.Is(err, taskpkg.ErrIssuerMismatch) {
		t.Fatalf("Verify foreign issuer err = %v, want ErrIssuerMismatch", err)
	}
}

// A retired key must stay usable through the grace period and then stop.
func TestRetiredKeyUsableOnlyDuringGrace(t *testing.T) {
	g := taskpkg.NewJwksGuard(jwksConfig(), nil)
	now := time.Unix(1700000000, 0)
	mustPublish(t, g, testKey("k1", "ES256", now), now)
	if err := g.RetireKey("k1", now); err != nil {
		t.Fatalf("RetireKey: %v", err)
	}
	if _, err := g.KeyFor("k1", now.Add(2*time.Minute)); err != nil {
		t.Fatalf("KeyFor inside grace: %v", err)
	}
	if _, err := g.KeyFor("k1", now.Add(6*time.Minute)); !errors.Is(err, taskpkg.ErrKeyExpired) {
		t.Fatalf("KeyFor after grace err = %v, want ErrKeyExpired", err)
	}
}

// A batch warm-up with one bad key must leave the cache untouched.
func TestWarmCacheIsAllOrNothing(t *testing.T) {
	cfg := jwksConfig()
	cfg.MaxKeys = 4
	g := taskpkg.NewJwksGuard(cfg, nil)
	now := time.Unix(1700000000, 0)
	keys := []taskpkg.Key{
		testKey("k1", "ES256", now),
		testKey("k2", "none", now),
	}
	if err := g.WarmCache(keys, now); !errors.Is(err, taskpkg.ErrKeyInvalid) {
		t.Fatalf("WarmCache err = %v, want ErrKeyInvalid", err)
	}
	if size := g.CacheSize(); size != 0 {
		t.Fatalf("cache size after rejected warm-up = %d, want 0", size)
	}
	if _, err := g.KeyFor("k1", now); !errors.Is(err, taskpkg.ErrKeyNotFound) {
		t.Fatalf("k1 leaked into the cache: %v", err)
	}
}

// A failed rotation must not retire the old key.
func TestRotateAtomicOnInvalidReplacement(t *testing.T) {
	g := taskpkg.NewJwksGuard(jwksConfig(), nil)
	now := time.Unix(1700000000, 0)
	mustPublish(t, g, testKey("k1", "ES256", now), now)

	bad := testKey("k2", "none", now)
	if err := g.Rotate("k1", bad, now); !errors.Is(err, taskpkg.ErrKeyInvalid) {
		t.Fatalf("Rotate with invalid key err = %v, want ErrKeyInvalid", err)
	}
	if _, err := g.KeyFor("k1", now.Add(30*time.Minute)); err != nil {
		t.Fatalf("old key after failed rotation: %v", err)
	}
}

// Many concurrent refreshes of one missing key must hit the source once.
func TestRefreshCoalescesConcurrentCalls(t *testing.T) {
	now := time.Unix(1700000000, 0)
	var calls atomic.Int64
	src := func(kid string) (taskpkg.Key, error) {
		calls.Add(1)
		return testKey(kid, "ES256", now), nil
	}
	g := taskpkg.NewJwksGuard(jwksConfig(), src)

	const workers = 16
	errs := make([]error, workers)
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func(idx int) {
			defer wg.Done()
			_, errs[idx] = g.Refresh("kid-remote", now)
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("Refresh worker %d: %v", i, err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("key source called %d times, want exactly 1", got)
	}
	if _, err := g.KeyFor("kid-remote", now); err != nil {
		t.Fatalf("refreshed key is not cached: %v", err)
	}
}

// A failing key source must surface its error to the caller.
func TestRefreshPropagatesSourceError(t *testing.T) {
	src := func(kid string) (taskpkg.Key, error) {
		return taskpkg.Key{}, taskpkg.ErrSourceFailed
	}
	g := taskpkg.NewJwksGuard(jwksConfig(), src)
	if _, err := g.Refresh("kid-lost", time.Unix(1700000000, 0)); !errors.Is(err, taskpkg.ErrSourceFailed) {
		t.Fatalf("Refresh err = %v, want ErrSourceFailed", err)
	}
}

// The cache and its generation counter must survive a restart.
func TestSnapshotRestoresKeysAndGeneration(t *testing.T) {
	g := taskpkg.NewJwksGuard(jwksConfig(), nil)
	now := time.Unix(1700000000, 0)
	mustPublish(t, g, testKey("k1", "ES256", now), now)
	gen := g.Generation()
	if gen == 0 {
		t.Fatal("Generation did not advance after publishing a key")
	}
	snap, err := g.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	restored, err := taskpkg.NewJwksGuardFromSnapshot(jwksConfig(), nil, snap)
	if err != nil {
		t.Fatalf("NewJwksGuardFromSnapshot: %v", err)
	}
	if size := restored.CacheSize(); size != 1 {
		t.Fatalf("restored cache size = %d, want 1", size)
	}
	if got := restored.Generation(); got != gen {
		t.Fatalf("restored generation = %d, want %d", got, gen)
	}
	if _, err := restored.KeyFor("k1", now); err != nil {
		t.Fatalf("restored KeyFor: %v", err)
	}
}

// Tokens signed by the old and the new key must both verify across a
// rotation, until the old key leaves its grace period.
func TestVerifyAcrossRotation(t *testing.T) {
	g := taskpkg.NewJwksGuard(jwksConfig(), nil)
	now := time.Unix(1700000000, 0)
	mustPublish(t, g, testKey("k1", "ES256", now), now)
	if err := g.RetireKey("k1", now); err != nil {
		t.Fatalf("RetireKey: %v", err)
	}
	mustPublish(t, g, testKey("k2", "ES256", now), now)
	claims := jwksClaims(now.Add(30 * time.Minute))

	if _, err := g.Verify(taskpkg.Header{KID: "k1", Alg: "ES256"}, claims, now.Add(2*time.Minute)); err != nil {
		t.Fatalf("Verify old key inside grace: %v", err)
	}
	if _, err := g.Verify(taskpkg.Header{KID: "k2", Alg: "ES256"}, claims, now.Add(2*time.Minute)); err != nil {
		t.Fatalf("Verify new key: %v", err)
	}
	if _, err := g.Verify(taskpkg.Header{KID: "k1", Alg: "ES256"}, claims, now.Add(6*time.Minute)); !errors.Is(err, taskpkg.ErrKeyExpired) {
		t.Fatalf("Verify old key after grace err = %v, want ErrKeyExpired", err)
	}
}

// Concurrent publishers must not overshoot the cache size budget.
func TestConcurrentPublishRespectsMaxKeys(t *testing.T) {
	const maxKeys = 10
	cfg := jwksConfig()
	cfg.MaxKeys = maxKeys
	g := taskpkg.NewJwksGuard(cfg, nil)
	now := time.Unix(1700000000, 0)

	const workers = 50
	errs := make([]error, workers)
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func(idx int) {
			defer wg.Done()
			errs[idx] = g.PublishKey(testKey(fmt.Sprintf("kid-%02d", idx), "ES256", now), now)
		}(i)
	}
	wg.Wait()

	successes := 0
	for _, err := range errs {
		if err == nil {
			successes++
		}
	}
	if successes != maxKeys {
		t.Fatalf("%d publishers succeeded, want exactly %d", successes, maxKeys)
	}
	if size := g.CacheSize(); size != maxKeys {
		t.Fatalf("cache size = %d, want %d", size, maxKeys)
	}
}
