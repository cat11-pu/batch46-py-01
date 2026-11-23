package task

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	taskpkg "gsb/batch46-safety-a-07"
)

var t0 = time.Unix(1735689600, 0).UTC() // 2025-01-01T00:00:00Z

func amz(t time.Time) string {
	return t.UTC().Format("20060102T150405Z")
}

func cfg() taskpkg.Config {
	return taskpkg.Config{
		Region:       "us-east-1",
		Service:      "execute-api",
		MaxSkew:      5 * time.Minute,
		PresignLimit: 10 * time.Minute,
		ReplayTTL:    10 * time.Minute,
		MaxHeaders:   8,
	}
}

func guard(t *testing.T) *taskpkg.SigV4Guard {
	t.Helper()
	g := taskpkg.NewSigV4Guard(cfg())
	if err := g.RegisterKey("AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "tenant-a"); err != nil {
		t.Fatalf("RegisterKey: %v", err)
	}
	return g
}

func signedReq(at time.Time) taskpkg.Request {
	return taskpkg.Request{
		Method: "GET",
		URL:    "https://api.example.com/photos/My%20Photo.jpg?b=2&a=1",
		Headers: map[string]string{
			"Host":       "api.example.com",
			"X-Amz-Date": amz(at),
		},
	}
}

func withAuth(t *testing.T, g *taskpkg.SigV4Guard, req taskpkg.Request, at time.Time) taskpkg.Request {
	t.Helper()
	auth, err := g.Sign(req, "AKIDEXAMPLE", at)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	req.Headers["Authorization"] = auth
	return req
}

func TestCanonicalQuerySortsByNameThenValue(t *testing.T) {
	g := guard(t)
	got, err := g.CanonicalQuery("b=2&a=2&a=1&c")
	if err != nil {
		t.Fatalf("CanonicalQuery: %v", err)
	}
	want := "a=1&a=2&b=2&c="
	if got != want {
		t.Fatalf("CanonicalQuery = %q, want %q", got, want)
	}
}

func TestCanonicalQueryEncodesReservedCharacters(t *testing.T) {
	g := guard(t)
	got, err := g.CanonicalQuery("sym=~/x+y&file=My Photo.jpg&raw=%2f&plus=a%2Bb")
	if err != nil {
		t.Fatalf("CanonicalQuery: %v", err)
	}
	want := "file=My%20Photo.jpg&plus=a%2Bb&raw=%2F&sym=~%2Fx%2By"
	if got != want {
		t.Fatalf("CanonicalQuery = %q, want %q", got, want)
	}
	if _, err := g.CanonicalQuery("bad=%zz"); !errors.Is(err, taskpkg.ErrMalformed) {
		t.Fatalf("CanonicalQuery with a broken escape = %v, want ErrMalformed", err)
	}
}

func TestCanonicalQueryKeepsEmptyValues(t *testing.T) {
	g := guard(t)
	got, err := g.CanonicalQuery("x=&acl&&z=9")
	if err != nil {
		t.Fatalf("CanonicalQuery: %v", err)
	}
	if want := "acl=&x=&z=9"; got != want {
		t.Fatalf("CanonicalQuery = %q, want %q", got, want)
	}
	if got, err := g.CanonicalQuery(""); err != nil || got != "" {
		t.Fatalf("CanonicalQuery of an empty query = %q err=%v, want empty and no error", got, err)
	}
}

func TestCanonicalURIEncodesSegmentsAndRejectsTraversal(t *testing.T) {
	g := guard(t)
	got, err := g.CanonicalURI("/photos/My Photo.jpg")
	if err != nil || got != "/photos/My%20Photo.jpg" {
		t.Fatalf("CanonicalURI = %q err=%v, want /photos/My%%20Photo.jpg", got, err)
	}
	if got, err := g.CanonicalURI("/v1//notes/"); err != nil || got != "/v1//notes/" {
		t.Fatalf("CanonicalURI kept empty segments? got %q err=%v", got, err)
	}
	if got, err := g.CanonicalURI(""); err != nil || got != "/" {
		t.Fatalf("CanonicalURI of an empty path = %q err=%v, want /", got, err)
	}
	for _, bad := range []string{"photos/a", "/a/../b", "/a/./b"} {
		if _, err := g.CanonicalURI(bad); !errors.Is(err, taskpkg.ErrMalformed) {
			t.Fatalf("CanonicalURI(%q) = %v, want ErrMalformed", bad, err)
		}
	}
}

func TestCanonicalHeadersNormalizesAndSorts(t *testing.T) {
	g := guard(t)
	block, signed, err := g.CanonicalHeaders(map[string]string{
		"Host":          "Example.COM",
		"X-Amz-Date":    " 20250101T000000Z ",
		"x-custom":      "a   b\tc",
		"User-Agent":    "curl/8",
		"Authorization": "AWS4-HMAC-SHA256 Credential=ignored",
	})
	if err != nil {
		t.Fatalf("CanonicalHeaders: %v", err)
	}
	if signed != "host;user-agent;x-amz-date;x-custom" {
		t.Fatalf("signed headers = %q, want host;user-agent;x-amz-date;x-custom", signed)
	}
	want := "host:example.com\nuser-agent:curl/8\nx-amz-date:20250101T000000Z\nx-custom:a b c\n"
	if block != want {
		t.Fatalf("header block = %q, want %q", block, want)
	}
	if _, _, err := g.CanonicalHeaders(map[string]string{"Host": "a", "host": "b"}); !errors.Is(err, taskpkg.ErrMalformed) {
		t.Fatalf("duplicate header names = %v, want ErrMalformed", err)
	}
}

func TestCanonicalHeadersRequiresHostAndCapsCount(t *testing.T) {
	g := guard(t)
	if _, _, err := g.CanonicalHeaders(map[string]string{"X-Amz-Date": "20250101T000000Z"}); !errors.Is(err, taskpkg.ErrMissingHeader) {
		t.Fatalf("headers without host = %v, want ErrMissingHeader", err)
	}
	smallCfg := cfg()
	smallCfg.MaxHeaders = 2
	small := taskpkg.NewSigV4Guard(smallCfg)
	_, _, err := small.CanonicalHeaders(map[string]string{"Host": "h", "X-A": "1", "X-B": "2"})
	if !errors.Is(err, taskpkg.ErrLimit) {
		t.Fatalf("three headers against a cap of two = %v, want ErrLimit", err)
	}
}

func TestCanonicalRequestCarriesPayloadHash(t *testing.T) {
	g := guard(t)
	req := taskpkg.Request{
		Method:  "post",
		URL:     "https://api.example.com/photos/My Photo.jpg?b=2&a=1",
		Headers: map[string]string{"Host": "api.example.com", "X-Amz-Date": "20250101T000000Z"},
		Body:    []byte("hello"),
	}
	got, err := g.CanonicalRequest(req)
	if err != nil {
		t.Fatalf("CanonicalRequest: %v", err)
	}
	want := "POST\n" +
		"/photos/My%20Photo.jpg\n" +
		"a=1&b=2\n" +
		"host:api.example.com\nx-amz-date:20250101T000000Z\n\n" +
		"host;x-amz-date\n" +
		"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if got != want {
		t.Fatalf("CanonicalRequest =\n%q\nwant\n%q", got, want)
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	g := guard(t)
	req := signedReq(t0)
	auth, err := g.Sign(req, "AKIDEXAMPLE", t0)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	prefix := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20250101/us-east-1/execute-api/aws4_request, SignedHeaders=host;x-amz-date, Signature="
	if !strings.HasPrefix(auth, prefix) {
		t.Fatalf("Authorization = %q, want prefix %q", auth, prefix)
	}
	sig := strings.TrimPrefix(auth, prefix)
	if len(sig) != 64 || strings.Trim(sig, "0123456789abcdef") != "" {
		t.Fatalf("signature %q is not 64 lower-case hex characters", sig)
	}
	again, err := g.Sign(req, "AKIDEXAMPLE", t0)
	if err != nil || again != auth {
		t.Fatalf("Sign is not deterministic: %q vs %q (err=%v)", again, auth, err)
	}
	if _, err := g.Sign(req, "AKID-MISSING", t0); !errors.Is(err, taskpkg.ErrUnknownKey) {
		t.Fatalf("Sign with an unregistered key = %v, want ErrUnknownKey", err)
	}
	req.Headers["Authorization"] = auth
	akid, err := g.Verify(req, t0)
	if err != nil || akid != "AKIDEXAMPLE" {
		t.Fatalf("Verify = %q err=%v, want AKIDEXAMPLE and no error", akid, err)
	}
}

func TestVerifyRejectsTamperedRequest(t *testing.T) {
	g := guard(t)
	req := withAuth(t, g, signedReq(t0), t0)
	body := req
	body.Body = []byte("tampered")
	if _, err := g.Verify(body, t0); !errors.Is(err, taskpkg.ErrSignature) {
		t.Fatalf("Verify with a changed body = %v, want ErrSignature", err)
	}
	req.URL = "https://api.example.com/photos/My%20Photo.jpg?b=3&a=1"
	if _, err := g.Verify(req, t0); !errors.Is(err, taskpkg.ErrSignature) {
		t.Fatalf("Verify with a changed query = %v, want ErrSignature", err)
	}
}

func TestVerifyRejectsClockSkew(t *testing.T) {
	g := guard(t)
	req := withAuth(t, g, signedReq(t0), t0)
	if _, err := g.Verify(req, t0.Add(20*time.Minute)); !errors.Is(err, taskpkg.ErrClockSkew) {
		t.Fatalf("Verify twenty minutes late = %v, want ErrClockSkew", err)
	}
	if _, err := g.Verify(req, t0.Add(-6*time.Minute)); !errors.Is(err, taskpkg.ErrClockSkew) {
		t.Fatalf("Verify six minutes early = %v, want ErrClockSkew", err)
	}
	if _, err := g.Verify(req, t0.Add(4*time.Minute)); err != nil {
		t.Fatalf("Verify inside the skew = %v, want no error", err)
	}
}

func TestVerifyRequiresAuthorizationDateAndKnownKey(t *testing.T) {
	g := guard(t)
	req := signedReq(t0)
	if _, err := g.Verify(req, t0); !errors.Is(err, taskpkg.ErrMissingHeader) {
		t.Fatalf("Verify without Authorization = %v, want ErrMissingHeader", err)
	}
	req = withAuth(t, g, req, t0)
	delete(req.Headers, "X-Amz-Date")
	if _, err := g.Verify(req, t0); !errors.Is(err, taskpkg.ErrMissingHeader) {
		t.Fatalf("Verify without x-amz-date = %v, want ErrMissingHeader", err)
	}
	empty := taskpkg.NewSigV4Guard(cfg())
	signed := withAuth(t, g, signedReq(t0), t0)
	if _, err := empty.Verify(signed, t0); !errors.Is(err, taskpkg.ErrUnknownKey) {
		t.Fatalf("Verify against a guard with no keys = %v, want ErrUnknownKey", err)
	}
}

func TestVerifyRejectsForeignCredentialScope(t *testing.T) {
	g := guard(t)
	req := withAuth(t, g, signedReq(t0), t0)
	auth := req.Headers["Authorization"]
	req.Headers["Authorization"] = strings.Replace(auth, "/execute-api/", "/s3/", 1)
	if _, err := g.Verify(req, t0); !errors.Is(err, taskpkg.ErrMalformed) {
		t.Fatalf("Verify with a foreign service scope = %v, want ErrMalformed", err)
	}
	req.Headers["Authorization"] = strings.Replace(auth, "/us-east-1/", "/eu-west-1/", 1)
	if _, err := g.Verify(req, t0); !errors.Is(err, taskpkg.ErrMalformed) {
		t.Fatalf("Verify with a foreign region scope = %v, want ErrMalformed", err)
	}
}

func TestPresignedURLExpires(t *testing.T) {
	g := guard(t)
	req := taskpkg.Request{
		Method:  "GET",
		URL:     "https://api.example.com/report.csv?version=2",
		Headers: map[string]string{"Host": "api.example.com"},
	}
	raw, err := g.Presign(req, "AKIDEXAMPLE", t0, 9*time.Minute)
	if err != nil {
		t.Fatalf("Presign: %v", err)
	}
	if !strings.Contains(raw, "X-Amz-Expires=540") || !strings.Contains(raw, "X-Amz-Signature=") {
		t.Fatalf("presigned URL %q is missing its expiry or signature", raw)
	}
	if err := g.VerifyPresigned("GET", raw, t0.Add(8*time.Minute)); err != nil {
		t.Fatalf("VerifyPresigned inside the window: %v", err)
	}
	if err := g.VerifyPresigned("GET", raw, t0.Add(9*time.Minute+time.Second)); !errors.Is(err, taskpkg.ErrExpired) {
		t.Fatalf("VerifyPresigned after expiry = %v, want ErrExpired", err)
	}
}

func TestPresignExpiryLimit(t *testing.T) {
	g := guard(t)
	req := taskpkg.Request{
		Method:  "PUT",
		URL:     "https://api.example.com/upload/data.bin",
		Headers: map[string]string{"Host": "api.example.com"},
	}
	if _, err := g.Presign(req, "AKIDEXAMPLE", t0, 11*time.Minute); !errors.Is(err, taskpkg.ErrLimit) {
		t.Fatalf("Presign for eleven minutes against a ten minute cap = %v, want ErrLimit", err)
	}
	raw, err := g.Presign(req, "AKIDEXAMPLE", t0, 10*time.Minute)
	if err != nil {
		t.Fatalf("Presign at the cap: %v", err)
	}
	if err := g.VerifyPresigned("PUT", raw, t0.Add(10*time.Minute)); err != nil {
		t.Fatalf("VerifyPresigned exactly at expiry = %v, want no error", err)
	}
	if err := g.VerifyPresigned("GET", raw, t0.Add(time.Minute)); !errors.Is(err, taskpkg.ErrSignature) {
		t.Fatalf("VerifyPresigned with a different method = %v, want ErrSignature", err)
	}
	tampered := strings.Replace(raw, "/upload/data.bin", "/upload/other.bin", 1)
	if err := g.VerifyPresigned("PUT", tampered, t0.Add(time.Minute)); !errors.Is(err, taskpkg.ErrSignature) && !errors.Is(err, taskpkg.ErrMalformed) {
		t.Fatalf("VerifyPresigned of a tampered URL = %v, want ErrSignature or ErrMalformed", err)
	}
}

func TestReplayIsSingleUseAcrossRestart(t *testing.T) {
	g := guard(t)
	req := withAuth(t, g, signedReq(t0), t0)
	const workers = 24
	var wg sync.WaitGroup
	errs := make([]error, workers)
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func(i int) {
			defer wg.Done()
			_, errs[i] = g.Verify(req, t0)
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
		t.Fatalf("concurrent verification succeeded %d times, want exactly 1", successes)
	}
	if size := g.ReplaySize(); size != 1 {
		t.Fatalf("ReplaySize = %d, want 1", size)
	}
	snap, err := g.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	restored, err := taskpkg.NewSigV4GuardFromSnapshot(cfg(), snap)
	if err != nil {
		t.Fatalf("NewSigV4GuardFromSnapshot: %v", err)
	}
	if err := restored.RegisterKey("AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "tenant-a"); err != nil {
		t.Fatalf("RegisterKey after restart: %v", err)
	}
	if _, err := restored.Verify(req, t0); !errors.Is(err, taskpkg.ErrReplay) {
		t.Fatalf("replay after restart = %v, want ErrReplay", err)
	}
	if n := restored.PruneReplay(t0.Add(11 * time.Minute)); n != 1 {
		t.Fatalf("PruneReplay removed %d signatures, want 1", n)
	}
}
