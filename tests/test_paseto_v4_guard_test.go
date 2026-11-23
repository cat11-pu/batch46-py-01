package task

import (
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	taskpkg "gsb/batch46-safety-b-04"
)

// fakeSealer is a deterministic stand-in for the v4.local XChaCha20 sealing
// primitive. It prefixes the plaintext with the key id so a token opened with
// the wrong key or a tampered body fails.
type fakeSealer struct {
	mu    sync.Mutex
	seals int
}

func (f *fakeSealer) Seal(kid string, plaintext []byte) (string, error) {
	if kid == "" {
		return "", errors.New("sealer: empty kid")
	}
	f.mu.Lock()
	f.seals++
	f.mu.Unlock()
	body := append([]byte("sealed|"+kid+"|"), plaintext...)
	return base64.RawURLEncoding.EncodeToString(body), nil
}

func (f *fakeSealer) Open(kid string, ciphertext string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, err
	}
	prefix := "sealed|" + kid + "|"
	if !strings.HasPrefix(string(raw), prefix) {
		return nil, errors.New("sealer: body was not sealed with this key")
	}
	return raw[len(prefix):], nil
}

func pasetoConfig() taskpkg.Config {
	return taskpkg.Config{
		Issuer:        "https://auth.example.com",
		Audience:      "api://ledger",
		ClockSkew:     30 * time.Second,
		MaxTTL:        15 * time.Minute,
		MaxKeys:       6,
		MintLimit:     4,
		MintWindow:    time.Minute,
		RevocationTTL: time.Hour,
	}
}

func pasetoKey(kid string, now time.Time) taskpkg.Key {
	return taskpkg.Key{
		KID:       kid,
		NotBefore: now.Add(-time.Hour),
		MintUntil: now.Add(time.Hour),
		RetireAt:  now.Add(2 * time.Hour),
	}
}

func basePasetoClaims(now time.Time) taskpkg.Claims {
	return taskpkg.Claims{
		Subject:   "user-42",
		Issuer:    "https://auth.example.com",
		Audience:  "api://ledger",
		JTI:       "jti-1",
		IssuedAt:  now,
		ExpiresAt: now.Add(5 * time.Minute),
	}
}

func mustAddKey(t *testing.T, g *taskpkg.PasetoGuard, k taskpkg.Key) {
	t.Helper()
	if err := g.AddKey(k); err != nil {
		t.Fatalf("AddKey(%s): %v", k.KID, err)
	}
}

func mustMint(t *testing.T, g *taskpkg.PasetoGuard, c taskpkg.Claims, now time.Time) string {
	t.Helper()
	token, err := g.Mint(c, now)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if token == "" {
		t.Fatal("Mint returned an empty token")
	}
	return token
}

// Claims without a subject must not be sealed into a token.
func TestMintRejectsMissingSubject(t *testing.T) {
	g := taskpkg.NewPasetoGuard(pasetoConfig(), &fakeSealer{})
	now := time.Unix(1700000000, 0)
	c := basePasetoClaims(now)
	c.Subject = ""
	if _, err := g.Mint(c, now); !errors.Is(err, taskpkg.ErrInvalidClaims) {
		t.Fatalf("Mint without subject err = %v, want ErrInvalidClaims", err)
	}
}

// A requested lifetime above the policy limit must be rejected, not trimmed.
func TestMintRejectsOverlongLifetime(t *testing.T) {
	g := taskpkg.NewPasetoGuard(pasetoConfig(), &fakeSealer{})
	now := time.Unix(1700000000, 0)
	c := basePasetoClaims(now)
	c.ExpiresAt = now.Add(24 * time.Hour)
	if _, err := g.Mint(c, now); !errors.Is(err, taskpkg.ErrTokenLifetime) {
		t.Fatalf("Mint with 24h lifetime err = %v, want ErrTokenLifetime", err)
	}
}

// The mint quota must reset when the window rolls over.
func TestMintEnforcesRateLimitPerWindow(t *testing.T) {
	cfg := pasetoConfig()
	cfg.MintLimit = 2
	g := taskpkg.NewPasetoGuard(cfg, &fakeSealer{})
	now := time.Unix(1700000000, 0)
	mustAddKey(t, g, pasetoKey("k1", now))

	first := basePasetoClaims(now)
	mustMint(t, g, first, now)
	second := basePasetoClaims(now)
	second.JTI = "jti-2"
	mustMint(t, g, second, now)
	third := basePasetoClaims(now)
	third.JTI = "jti-3"
	if _, err := g.Mint(third, now); !errors.Is(err, taskpkg.ErrRateLimited) {
		t.Fatalf("third Mint in the window err = %v, want ErrRateLimited", err)
	}

	next := now.Add(time.Minute + time.Second)
	afterWindow := basePasetoClaims(next)
	afterWindow.JTI = "jti-4"
	if _, err := g.Mint(afterWindow, next); err != nil {
		t.Fatalf("Mint after the window rolled over: %v", err)
	}
}

// A token is bound to the configured audience.
func TestMintRejectsForeignAudience(t *testing.T) {
	g := taskpkg.NewPasetoGuard(pasetoConfig(), &fakeSealer{})
	now := time.Unix(1700000000, 0)
	c := basePasetoClaims(now)
	c.Audience = "api://other"
	if _, err := g.Mint(c, now); !errors.Is(err, taskpkg.ErrAudienceMismatch) {
		t.Fatalf("Mint for another audience err = %v, want ErrAudienceMismatch", err)
	}
}

// A token is bound to the configured issuer.
func TestMintRejectsForeignIssuer(t *testing.T) {
	g := taskpkg.NewPasetoGuard(pasetoConfig(), &fakeSealer{})
	now := time.Unix(1700000000, 0)
	c := basePasetoClaims(now)
	c.Issuer = "https://evil.example.com"
	if _, err := g.Mint(c, now); !errors.Is(err, taskpkg.ErrIssuerMismatch) {
		t.Fatalf("Mint for another issuer err = %v, want ErrIssuerMismatch", err)
	}
}

// Verification must reject a token whose expiry has passed.
func TestVerifyRejectsExpiredToken(t *testing.T) {
	g := taskpkg.NewPasetoGuard(pasetoConfig(), &fakeSealer{})
	now := time.Unix(1700000000, 0)
	mustAddKey(t, g, pasetoKey("k1", now))
	token := mustMint(t, g, basePasetoClaims(now), now)

	if _, err := g.Verify(token, now.Add(10*time.Minute)); !errors.Is(err, taskpkg.ErrTokenExpired) {
		t.Fatalf("Verify expired token err = %v, want ErrTokenExpired", err)
	}
}

// A token issued for a future not-before must wait until that instant.
func TestVerifyRejectsNotYetValidToken(t *testing.T) {
	g := taskpkg.NewPasetoGuard(pasetoConfig(), &fakeSealer{})
	now := time.Unix(1700000000, 0)
	mustAddKey(t, g, pasetoKey("k1", now))
	c := basePasetoClaims(now)
	c.NotBefore = now.Add(2 * time.Minute)
	token := mustMint(t, g, c, now)

	if _, err := g.Verify(token, now); !errors.Is(err, taskpkg.ErrTokenNotYetValid) {
		t.Fatalf("Verify before not-before err = %v, want ErrTokenNotYetValid", err)
	}
	if _, err := g.Verify(token, now.Add(2*time.Minute)); err != nil {
		t.Fatalf("Verify after not-before: %v", err)
	}
}

// A modified token body must not open.
func TestVerifyRejectsTamperedToken(t *testing.T) {
	g := taskpkg.NewPasetoGuard(pasetoConfig(), &fakeSealer{})
	now := time.Unix(1700000000, 0)
	mustAddKey(t, g, pasetoKey("k1", now))
	token := mustMint(t, g, basePasetoClaims(now), now)

	parts := strings.Split(token, ".")
	if len(parts) != 4 {
		t.Fatalf("token has %d parts, want 4", len(parts))
	}
	body := []byte(parts[3])
	if body[0] == 'A' {
		body[0] = 'B'
	} else {
		body[0] = 'A'
	}
	parts[3] = string(body)
	if _, err := g.Verify(strings.Join(parts, "."), now); !errors.Is(err, taskpkg.ErrInvalidToken) {
		t.Fatalf("Verify tampered token err = %v, want ErrInvalidToken", err)
	}
}

// A token whose kid is not registered must be rejected before opening.
func TestVerifyRejectsUnknownKey(t *testing.T) {
	sealer := &fakeSealer{}
	g := taskpkg.NewPasetoGuard(pasetoConfig(), sealer)
	now := time.Unix(1700000000, 0)
	mustAddKey(t, g, pasetoKey("k1", now))
	body, err := sealer.Seal("kid-ghost", []byte(`{"subject":"user-42"}`))
	if err != nil {
		t.Fatalf("seal for the test token: %v", err)
	}
	token := "v4.local.kid-ghost." + body

	if _, err := g.Verify(token, now); !errors.Is(err, taskpkg.ErrKeyNotFound) {
		t.Fatalf("Verify unknown kid err = %v, want ErrKeyNotFound", err)
	}
}

// Rotation must move minting to the new key while old tokens keep verifying
// inside the retirement window.
func TestRotationKeepsOldTokensUntilRetireAt(t *testing.T) {
	cfg := pasetoConfig()
	cfg.MaxTTL = time.Hour
	g := taskpkg.NewPasetoGuard(cfg, &fakeSealer{})
	now := time.Unix(1700000000, 0)

	old := pasetoKey("k1", now)
	old.MintUntil = now.Add(5 * time.Minute)
	old.RetireAt = now.Add(10 * time.Minute)
	mustAddKey(t, g, old)
	c1 := basePasetoClaims(now)
	c1.ExpiresAt = now.Add(45 * time.Minute)
	oldToken := mustMint(t, g, c1, now)

	newKey := taskpkg.Key{
		KID:       "k2",
		NotBefore: now,
		MintUntil: now.Add(2 * time.Hour),
		RetireAt:  now.Add(2 * time.Hour),
	}
	if err := g.RotateKey(newKey, now); err != nil {
		t.Fatalf("RotateKey: %v", err)
	}
	if active, err := g.ActiveKey(now); err != nil || active != "k2" {
		t.Fatalf("ActiveKey = %q (err %v), want k2", active, err)
	}

	c2 := basePasetoClaims(now)
	c2.JTI = "jti-2"
	c2.ExpiresAt = now.Add(45 * time.Minute)
	newToken := mustMint(t, g, c2, now)
	if parts := strings.Split(newToken, "."); len(parts) != 4 || parts[2] != "k2" {
		t.Fatalf("minted token did not use k2: %q", newToken)
	}
	if _, err := g.Verify(oldToken, now.Add(5*time.Minute)); err != nil {
		t.Fatalf("old token inside the retirement window: %v", err)
	}
	if _, err := g.Verify(newToken, now.Add(5*time.Minute)); err != nil {
		t.Fatalf("new token: %v", err)
	}
	if _, err := g.Verify(oldToken, now.Add(11*time.Minute)); !errors.Is(err, taskpkg.ErrKeyExpired) {
		t.Fatalf("old token after RetireAt err = %v, want ErrKeyExpired", err)
	}
}

// A rejected rotation must leave the previous key signing.
func TestRotateAtomicOnInvalidKey(t *testing.T) {
	g := taskpkg.NewPasetoGuard(pasetoConfig(), &fakeSealer{})
	now := time.Unix(1700000000, 0)
	mustAddKey(t, g, pasetoKey("k1", now))

	bad := taskpkg.Key{
		KID:       "k2",
		NotBefore: now,
		MintUntil: now.Add(-time.Minute),
		RetireAt:  now.Add(time.Hour),
	}
	if err := g.RotateKey(bad, now); !errors.Is(err, taskpkg.ErrKeyInvalid) {
		t.Fatalf("RotateKey with invalid key err = %v, want ErrKeyInvalid", err)
	}
	if active, err := g.ActiveKey(now); err != nil || active != "k1" {
		t.Fatalf("ActiveKey after rejected rotation = %q (err %v), want k1", active, err)
	}
	mustMint(t, g, basePasetoClaims(now), now)
}

// Revoking a token id must stop verification immediately.
func TestRevokeBlocksVerification(t *testing.T) {
	g := taskpkg.NewPasetoGuard(pasetoConfig(), &fakeSealer{})
	now := time.Unix(1700000000, 0)
	mustAddKey(t, g, pasetoKey("k1", now))
	c := basePasetoClaims(now)
	token := mustMint(t, g, c, now)

	if err := g.Revoke(c.JTI, now); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := g.Verify(token, now); !errors.Is(err, taskpkg.ErrRevoked) {
		t.Fatalf("Verify revoked token err = %v, want ErrRevoked", err)
	}
	revoked, err := g.IsRevoked(c.JTI, now)
	if err != nil || !revoked {
		t.Fatalf("IsRevoked = %v (err %v), want true", revoked, err)
	}
}

// Revocation is idempotent and its entry expires with the revocation TTL.
func TestRevokeIdempotentAndPrunesAfterTTL(t *testing.T) {
	cfg := pasetoConfig()
	cfg.RevocationTTL = time.Minute
	g := taskpkg.NewPasetoGuard(cfg, &fakeSealer{})
	now := time.Unix(1700000000, 0)
	mustAddKey(t, g, pasetoKey("k1", now))
	c := basePasetoClaims(now)
	token := mustMint(t, g, c, now)

	if err := g.Revoke(c.JTI, now); err != nil {
		t.Fatalf("first Revoke: %v", err)
	}
	if err := g.Revoke(c.JTI, now); err != nil {
		t.Fatalf("second Revoke is not idempotent: %v", err)
	}
	if _, err := g.Verify(token, now.Add(time.Second)); !errors.Is(err, taskpkg.ErrRevoked) {
		t.Fatalf("Verify right after revoke err = %v, want ErrRevoked", err)
	}
	if removed := g.PruneRevoked(now.Add(2 * time.Minute)); removed != 1 {
		t.Fatalf("PruneRevoked removed %d entries, want 1", removed)
	}
	if _, err := g.Verify(token, now.Add(2*time.Minute)); err != nil {
		t.Fatalf("Verify after the revocation TTL: %v", err)
	}
}

// The mint quota must hold under concurrent mint attempts.
func TestConcurrentMintRespectsRateLimit(t *testing.T) {
	cfg := pasetoConfig()
	cfg.MintLimit = 5
	g := taskpkg.NewPasetoGuard(cfg, &fakeSealer{})
	now := time.Unix(1700000000, 0)
	mustAddKey(t, g, pasetoKey("k1", now))

	const workers = 20
	errs := make([]error, workers)
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func(idx int) {
			defer wg.Done()
			c := basePasetoClaims(now)
			c.JTI = "jti-" + strings.Repeat("x", idx%3+1) + string(rune('a'+idx))
			_, errs[idx] = g.Mint(c, now)
		}(i)
	}
	wg.Wait()

	successes := 0
	limited := 0
	for _, err := range errs {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, taskpkg.ErrRateLimited):
			limited++
		}
	}
	if successes != 5 || limited != 15 {
		t.Fatalf("concurrent mints: %d succeeded, %d rate limited; want 5 and 15", successes, limited)
	}
}

// The key set, revocations and the mint window must survive a restart.
func TestSnapshotRestoresKeysRevocationsAndQuota(t *testing.T) {
	cfg := pasetoConfig()
	cfg.MintLimit = 2
	sealer := &fakeSealer{}
	g := taskpkg.NewPasetoGuard(cfg, sealer)
	now := time.Unix(1700000000, 0)
	mustAddKey(t, g, pasetoKey("k1", now))

	c1 := basePasetoClaims(now)
	token := mustMint(t, g, c1, now)
	if err := g.Revoke(c1.JTI, now); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	snap, err := g.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	restored, err := taskpkg.NewPasetoGuardFromSnapshot(cfg, sealer, snap)
	if err != nil {
		t.Fatalf("NewPasetoGuardFromSnapshot: %v", err)
	}
	if n := restored.KeyCount(); n != 1 {
		t.Fatalf("restored key count = %d, want 1", n)
	}
	if _, err := restored.Verify(token, now); !errors.Is(err, taskpkg.ErrRevoked) {
		t.Fatalf("restored revocation err = %v, want ErrRevoked", err)
	}

	c2 := basePasetoClaims(now)
	c2.JTI = "jti-2"
	if _, err := restored.Mint(c2, now); err != nil {
		t.Fatalf("Mint after restore: %v", err)
	}
	c3 := basePasetoClaims(now)
	c3.JTI = "jti-3"
	if _, err := restored.Mint(c3, now); !errors.Is(err, taskpkg.ErrRateLimited) {
		t.Fatalf("Mint beyond the restored quota err = %v, want ErrRateLimited", err)
	}
}
