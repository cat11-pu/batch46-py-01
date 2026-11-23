package task

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	taskpkg "gsb/batch46-safety-a-08"
)

var t0 = time.Unix(1735689600, 0).UTC() // 2025-01-01T00:00:00Z

func sasConfig() taskpkg.Config {
	return taskpkg.Config{
		MaxLifetime:     time.Hour,
		ClockSkew:       2 * time.Minute,
		AllowedServices: []string{"b", "q"},
	}
}

func sasGuard(t *testing.T) *taskpkg.SasGuard {
	t.Helper()
	g := taskpkg.NewSasGuard(sasConfig())
	if err := g.RegisterAccountKey("acctlogs", []byte("c2VjcmV0LWtleS1tYXRlcmlhbA==")); err != nil {
		t.Fatalf("RegisterAccountKey: %v", err)
	}
	return g
}

func baseToken() taskpkg.Token {
	return taskpkg.Token{
		Version:     "2022-11-02",
		Service:     "b",
		Resource:    "b",
		Protocol:    "https",
		Start:       t0,
		Expiry:      t0.Add(time.Hour),
		Permissions: "r",
	}
}

func mint(t *testing.T, g *taskpkg.SasGuard, tok taskpkg.Token, container, blob string) string {
	t.Helper()
	raw, err := g.Mint(taskpkg.MintRequest{Account: "acctlogs", Container: container, Blob: blob, Token: tok}, t0)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	return raw
}

func TestCanonicalPermissionsOrdersAndDedupes(t *testing.T) {
	g := sasGuard(t)
	for in, want := range map[string]string{
		"wrac":   "racw",
		"lr":     "rl",
		"rr":     "r",
		"dlcwar": "racwdl",
	} {
		got, err := g.CanonicalPermissions(in)
		if err != nil {
			t.Fatalf("CanonicalPermissions(%q): %v", in, err)
		}
		if got != want {
			t.Fatalf("CanonicalPermissions(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCanonicalPermissionsRejectsUnknownLetters(t *testing.T) {
	g := sasGuard(t)
	for _, in := range []string{"rx", "", "R", "rac wdl"} {
		if _, err := g.CanonicalPermissions(in); !errors.Is(err, taskpkg.ErrMalformed) {
			t.Fatalf("CanonicalPermissions(%q) = %v, want ErrMalformed", in, err)
		}
	}
}

func TestMintReturnsDeterministicSortedQuery(t *testing.T) {
	g := sasGuard(t)
	tok := baseToken()
	raw := mint(t, g, tok, "logs", "logs/app.log")
	wantPrefix := "se=2025-01-01T01%3A00%3A00Z&sp=r&spr=https&sr=b&ss=b&st=2025-01-01T00%3A00%3A00Z&sv=2022-11-02&sig="
	if !strings.HasPrefix(raw, wantPrefix) {
		t.Fatalf("Mint returned %q, want prefix %q", raw, wantPrefix)
	}
	if again := mint(t, g, tok, "logs", "logs/app.log"); again != raw {
		t.Fatalf("Mint is not deterministic:\n%q\n%q", again, raw)
	}
	parsed, err := g.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if parsed.Service != "b" || parsed.Resource != "b" || parsed.Permissions != "r" {
		t.Fatalf("Parse lost fields: %+v", parsed)
	}
	if !parsed.Expiry.Equal(t0.Add(time.Hour)) {
		t.Fatalf("Parse expiry = %v, want %v", parsed.Expiry, t0.Add(time.Hour))
	}
	wantToSign := "acctlogs\nb\nb\nlogs\nlogs/app.log\nr\n2025-01-01T00:00:00Z\n2025-01-01T01:00:00Z\nhttps\n-\n-\n2022-11-02"
	if got := g.StringToSign(tok, "acctlogs", "logs", "logs/app.log"); got != wantToSign {
		t.Fatalf("StringToSign =\n%q\nwant\n%q", got, wantToSign)
	}
	if _, err := g.Parse("garbage"); !errors.Is(err, taskpkg.ErrMalformed) {
		t.Fatalf("Parse of garbage = %v, want ErrMalformed", err)
	}
	if _, err := g.Parse("sv=2022-11-02&sig=abc"); !errors.Is(err, taskpkg.ErrMalformed) {
		t.Fatalf("Parse of an incomplete token = %v, want ErrMalformed", err)
	}
}

func TestTamperedSignatureRejected(t *testing.T) {
	g := sasGuard(t)
	raw := mint(t, g, baseToken(), "logs", "logs/app.log")
	last := raw[len(raw)-1]
	replacement := byte('A')
	if last == 'A' {
		replacement = 'B'
	}
	tampered := raw[:len(raw)-1] + string(replacement)
	err := g.Validate(tampered, "acctlogs", "logs", "logs/app.log", "r", "", t0)
	if !errors.Is(err, taskpkg.ErrSignature) {
		t.Fatalf("Validate of a tampered signature = %v, want ErrSignature", err)
	}
}

func TestExpiryWindowEnforced(t *testing.T) {
	g := sasGuard(t)
	raw := mint(t, g, baseToken(), "logs", "logs/app.log")
	if err := g.Validate(raw, "acctlogs", "logs", "logs/app.log", "r", "", t0.Add(time.Hour+2*time.Minute)); err != nil {
		t.Fatalf("Validate exactly at expiry plus skew = %v, want no error", err)
	}
	if err := g.Validate(raw, "acctlogs", "logs", "logs/app.log", "r", "", t0.Add(time.Hour+2*time.Minute+time.Second)); !errors.Is(err, taskpkg.ErrExpired) {
		t.Fatalf("Validate past expiry plus skew = %v, want ErrExpired", err)
	}
}

func TestStartIsNotYetValid(t *testing.T) {
	g := sasGuard(t)
	tok := baseToken()
	tok.Start = t0.Add(10 * time.Minute)
	tok.Expiry = t0.Add(50 * time.Minute)
	raw := mint(t, g, tok, "logs", "logs/app.log")
	if err := g.Validate(raw, "acctlogs", "logs", "logs/app.log", "r", "", t0); !errors.Is(err, taskpkg.ErrNotYet) {
		t.Fatalf("Validate before start minus skew = %v, want ErrNotYet", err)
	}
	if err := g.Validate(raw, "acctlogs", "logs", "logs/app.log", "r", "", t0.Add(8*time.Minute+time.Second)); err != nil {
		t.Fatalf("Validate just inside the start skew = %v, want no error", err)
	}
}

func TestMaxLifetimeRejected(t *testing.T) {
	g := sasGuard(t)
	tok := baseToken()
	tok.Expiry = t0.Add(2 * time.Hour)
	if _, err := g.Mint(taskpkg.MintRequest{Account: "acctlogs", Container: "logs", Blob: "logs/app.log", Token: tok}, t0); !errors.Is(err, taskpkg.ErrLimit) {
		t.Fatalf("Mint with a two hour lifetime against a one hour cap = %v, want ErrLimit", err)
	}
}

func TestProtocolMustBeHTTPS(t *testing.T) {
	g := sasGuard(t)
	for _, proto := range []string{"https,http", "http", ""} {
		tok := baseToken()
		tok.Protocol = proto
		if _, err := g.Mint(taskpkg.MintRequest{Account: "acctlogs", Container: "logs", Blob: "logs/app.log", Token: tok}, t0); !errors.Is(err, taskpkg.ErrMalformed) {
			t.Fatalf("Mint with protocol %q = %v, want ErrMalformed", proto, err)
		}
	}
}

func TestRequiredPermissionSubset(t *testing.T) {
	g := sasGuard(t)
	raw := mint(t, g, baseToken(), "logs", "logs/app.log")
	if err := g.Validate(raw, "acctlogs", "logs", "logs/app.log", "rl", "", t0); !errors.Is(err, taskpkg.ErrPermission) {
		t.Fatalf("Validate requiring rl on an r token = %v, want ErrPermission", err)
	}
	if err := g.Validate(raw, "acctlogs", "logs", "logs/app.log", "r", "", t0); err != nil {
		t.Fatalf("Validate requiring r = %v, want no error", err)
	}
	full := baseToken()
	full.Permissions = "rl"
	fullRaw := mint(t, g, full, "logs", "logs/app.log")
	if err := g.Validate(fullRaw, "acctlogs", "logs", "logs/app.log", "l", "", t0); err != nil {
		t.Fatalf("Validate requiring l on an rl token = %v, want no error", err)
	}
}

func TestSourceIPRange(t *testing.T) {
	g := sasGuard(t)
	tok := baseToken()
	tok.IPRange = "10.0.0.0-10.0.0.255"
	raw := mint(t, g, tok, "logs", "logs/app.log")
	if err := g.Validate(raw, "acctlogs", "logs", "logs/app.log", "r", "10.0.0.7", t0); err != nil {
		t.Fatalf("Validate from an allowed address = %v, want no error", err)
	}
	for _, ip := range []string{"10.0.1.7", "", "not-an-ip"} {
		if err := g.Validate(raw, "acctlogs", "logs", "logs/app.log", "r", ip, t0); !errors.Is(err, taskpkg.ErrIP) {
			t.Fatalf("Validate from %q = %v, want ErrIP", ip, err)
		}
	}
	bad := baseToken()
	bad.IPRange = "10.0.0.0-"
	if _, err := g.Mint(taskpkg.MintRequest{Account: "acctlogs", Container: "logs", Blob: "logs/app.log", Token: bad}, t0); !errors.Is(err, taskpkg.ErrMalformed) {
		t.Fatalf("Mint with a broken IP range = %v, want ErrMalformed", err)
	}
}

func TestResourceTypeMustMatch(t *testing.T) {
	g := sasGuard(t)
	containerTok := baseToken()
	containerTok.Resource = "c"
	containerRaw := mint(t, g, containerTok, "logs", "")
	if err := g.Validate(containerRaw, "acctlogs", "logs", "app.log", "r", "", t0); !errors.Is(err, taskpkg.ErrPermission) {
		t.Fatalf("container SAS used on one blob = %v, want ErrPermission", err)
	}
	blobRaw := mint(t, g, baseToken(), "logs", "app.log")
	if err := g.Validate(blobRaw, "acctlogs", "logs", "", "r", "", t0); !errors.Is(err, taskpkg.ErrPermission) {
		t.Fatalf("blob SAS used on the whole container = %v, want ErrPermission", err)
	}
	if err := g.Validate(blobRaw, "acctlogs", "logs", "app.log", "r", "", t0); err != nil {
		t.Fatalf("blob SAS used on its blob = %v, want no error", err)
	}
}

func TestServiceAllowList(t *testing.T) {
	g := sasGuard(t)
	tok := baseToken()
	tok.Service = "f"
	if _, err := g.Mint(taskpkg.MintRequest{Account: "acctlogs", Container: "logs", Blob: "logs/app.log", Token: tok}, t0); !errors.Is(err, taskpkg.ErrMalformed) {
		t.Fatalf("Mint with the file service = %v, want ErrMalformed", err)
	}
	raw := mint(t, g, baseToken(), "logs", "logs/app.log")
	tampered := strings.Replace(raw, "ss=b&", "ss=f&", 1)
	if err := g.Validate(tampered, "acctlogs", "logs", "logs/app.log", "r", "", t0); !errors.Is(err, taskpkg.ErrMalformed) {
		t.Fatalf("Validate of a token for a disabled service = %v, want ErrMalformed", err)
	}
}

func TestStoredPolicyBounds(t *testing.T) {
	g := taskpkg.NewSasGuard(taskpkg.Config{
		MaxLifetime:     4 * time.Hour,
		ClockSkew:       2 * time.Minute,
		AllowedServices: []string{"b"},
	})
	if err := g.RegisterAccountKey("acctlogs", []byte("c2VjcmV0LWtleS1tYXRlcmlhbA==")); err != nil {
		t.Fatalf("RegisterAccountKey: %v", err)
	}
	if err := g.SetPolicy("logs", "readonly", "rl", t0, t0.Add(2*time.Hour)); err != nil {
		t.Fatalf("SetPolicy: %v", err)
	}
	tok := baseToken()
	tok.Permissions = "rl"
	tok.PolicyID = "readonly"
	raw, err := g.Mint(taskpkg.MintRequest{Account: "acctlogs", Container: "logs", Blob: "logs/app.log", Token: tok}, t0)
	if err != nil {
		t.Fatalf("Mint under a policy: %v", err)
	}
	if err := g.Validate(raw, "acctlogs", "logs", "logs/app.log", "rl", "", t0); err != nil {
		t.Fatalf("Validate under a policy: %v", err)
	}
	wide := tok
	wide.Permissions = "rlw"
	if _, err := g.Mint(taskpkg.MintRequest{Account: "acctlogs", Container: "logs", Blob: "logs/app.log", Token: wide}, t0); !errors.Is(err, taskpkg.ErrPermission) {
		t.Fatalf("Mint with permissions wider than the policy = %v, want ErrPermission", err)
	}
	long := tok
	long.Expiry = t0.Add(3 * time.Hour)
	if _, err := g.Mint(taskpkg.MintRequest{Account: "acctlogs", Container: "logs", Blob: "logs/app.log", Token: long}, t0); !errors.Is(err, taskpkg.ErrExpired) {
		t.Fatalf("Mint outliving the policy = %v, want ErrExpired", err)
	}
	if err := g.RevokePolicy("logs", "readonly"); err != nil {
		t.Fatalf("RevokePolicy: %v", err)
	}
	if err := g.Validate(raw, "acctlogs", "logs", "logs/app.log", "rl", "", t0); !errors.Is(err, taskpkg.ErrRevoked) {
		t.Fatalf("Validate after revocation = %v, want ErrRevoked", err)
	}
	if _, err := g.Mint(taskpkg.MintRequest{Account: "acctlogs", Container: "logs", Blob: "logs/app.log", Token: tok}, t0); !errors.Is(err, taskpkg.ErrRevoked) {
		t.Fatalf("Mint against a revoked policy = %v, want ErrRevoked", err)
	}
}

func TestSnapshotKeepsRevocations(t *testing.T) {
	g := sasGuard(t)
	for _, p := range []struct {
		id     string
		perms  string
		expiry time.Time
	}{
		{"live", "rl", t0.Add(5 * time.Hour)},
		{"kill", "r", t0.Add(5 * time.Hour)},
		{"old", "r", t0.Add(time.Hour)},
	} {
		if err := g.SetPolicy("logs", p.id, p.perms, t0, p.expiry); err != nil {
			t.Fatalf("SetPolicy(%s): %v", p.id, err)
		}
	}
	live := baseToken()
	live.Permissions = "rl"
	live.PolicyID = "live"
	liveRaw := mint(t, g, live, "logs", "logs/app.log")
	kill := baseToken()
	kill.PolicyID = "kill"
	killRaw := mint(t, g, kill, "logs", "logs/app.log")
	if err := g.RevokePolicy("logs", "kill"); err != nil {
		t.Fatalf("RevokePolicy: %v", err)
	}
	snap, err := g.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	restored, err := taskpkg.NewSasGuardFromSnapshot(sasConfig(), snap)
	if err != nil {
		t.Fatalf("NewSasGuardFromSnapshot: %v", err)
	}
	if err := restored.RegisterAccountKey("acctlogs", []byte("c2VjcmV0LWtleS1tYXRlcmlhbA==")); err != nil {
		t.Fatalf("RegisterAccountKey: %v", err)
	}
	if err := restored.Validate(liveRaw, "acctlogs", "logs", "logs/app.log", "rl", "", t0); err != nil {
		t.Fatalf("Validate after restart: %v", err)
	}
	if err := restored.Validate(killRaw, "acctlogs", "logs", "logs/app.log", "r", "", t0); !errors.Is(err, taskpkg.ErrRevoked) {
		t.Fatalf("revocation lost across restart: %v, want ErrRevoked", err)
	}
	if n := restored.PrunePolicies(t0.Add(3 * time.Hour)); n != 2 {
		t.Fatalf("PrunePolicies removed %d policies, want 2 (revoked and expired)", n)
	}
	if got := restored.PolicyCount(); got != 1 {
		t.Fatalf("PolicyCount after prune = %d, want 1", got)
	}
}

func TestConcurrentValidationAndRevoke(t *testing.T) {
	g := sasGuard(t)
	if err := g.SetPolicy("logs", "p1", "rl", t0, t0.Add(2*time.Hour)); err != nil {
		t.Fatalf("SetPolicy: %v", err)
	}
	tok := baseToken()
	tok.Permissions = "rl"
	tok.PolicyID = "p1"
	raw := mint(t, g, tok, "logs", "logs/app.log")
	const readers = 80
	const revokers = 20
	var wg sync.WaitGroup
	errs := make([]error, readers)
	wg.Add(readers)
	for i := 0; i < readers; i++ {
		go func(i int) {
			defer wg.Done()
			errs[i] = g.Validate(raw, "acctlogs", "logs", "logs/app.log", "rl", "", t0)
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent Validate %d: %v", i, err)
		}
	}
	revokeErrs := make([]error, revokers)
	wg.Add(revokers)
	for i := 0; i < revokers; i++ {
		go func(i int) {
			defer wg.Done()
			revokeErrs[i] = g.RevokePolicy("logs", "p1")
		}(i)
	}
	wg.Wait()
	for i, err := range revokeErrs {
		if err != nil {
			t.Fatalf("concurrent RevokePolicy %d: %v", i, err)
		}
	}
	if err := g.Validate(raw, "acctlogs", "logs", "logs/app.log", "rl", "", t0); !errors.Is(err, taskpkg.ErrRevoked) {
		t.Fatalf("Validate after concurrent revocation = %v, want ErrRevoked", err)
	}
}
