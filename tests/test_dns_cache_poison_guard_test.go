package task

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	taskpkg "gsb/batch46-safety-d-06"
)

func dnsConfig() taskpkg.Config {
	return taskpkg.Config{
		MaxEntries:  16,
		MinTTL:      30 * time.Second,
		MaxTTL:      time.Hour,
		NegativeTTL: time.Minute,
	}
}

func dnsRR(name string, typ uint16, ttl uint32, rdata string) taskpkg.RR {
	return taskpkg.RR{
		Name:  name,
		Type:  typ,
		Class: taskpkg.ClassIN,
		TTL:   ttl,
		RData: rdata,
	}
}

// Names must be inside the zone on a label boundary, not just a string suffix.
func TestInBailiwickLabelBoundary(t *testing.T) {
	g := taskpkg.NewDnsCacheGuard(dnsConfig())
	cases := []struct {
		zone string
		name string
		want bool
	}{
		{"example.com", "example.com", true},
		{"example.com", "Api.Example.COM.", true},
		{"example.com", "a.b.example.com", true},
		{"example.com", "notexample.com", false},
		{"example.com", "example.com.evil.net", false},
		{"corp.internal", "example.com", false},
	}
	for _, c := range cases {
		if got := g.InBailiwick(c.zone, c.name); got != c.want {
			t.Fatalf("InBailiwick(%q, %q) = %v, want %v", c.zone, c.name, got, c.want)
		}
	}
}

// An answer whose owner is outside the answering zone must never enter the
// cache and must be counted as rejected.
func TestInsertRejectsOutOfBailiwickAnswer(t *testing.T) {
	g := taskpkg.NewDnsCacheGuard(dnsConfig())
	now := time.Unix(1700000000, 0)
	rr := dnsRR("bank.example.net", taskpkg.TypeA, 300, "203.0.113.9")
	if err := g.Insert("example.com", rr, now); !errors.Is(err, taskpkg.ErrBailiwick) {
		t.Fatalf("Insert of a foreign owner = %v, want ErrBailiwick", err)
	}
	if n := g.Len(); n != 0 {
		t.Fatalf("cache holds %d keys after a rejected insert, want 0", n)
	}
	if rejected := g.Stats().Rejected; rejected != 1 {
		t.Fatalf("Rejected = %d after one poisoned record, want 1", rejected)
	}
}

// A zero TTL record must be refused instead of being cached forever.
func TestInsertRejectsZeroTTL(t *testing.T) {
	g := taskpkg.NewDnsCacheGuard(dnsConfig())
	now := time.Unix(1700000000, 0)
	rr := dnsRR("ttl0.example.com", taskpkg.TypeA, 0, "198.51.100.7")
	if err := g.Insert("example.com", rr, now); !errors.Is(err, taskpkg.ErrTTLZero) {
		t.Fatalf("Insert with TTL 0 = %v, want ErrTTLZero", err)
	}
	if n := g.Len(); n != 0 {
		t.Fatalf("cache holds %d keys after a zero TTL insert, want 0", n)
	}
}

// Only class IN records are cacheable.
func TestInsertRejectsNonInternetClass(t *testing.T) {
	g := taskpkg.NewDnsCacheGuard(dnsConfig())
	now := time.Unix(1700000000, 0)
	rr := dnsRR("chaos.example.com", taskpkg.TypeTXT, 300, "version.bind")
	rr.Class = 3
	if err := g.Insert("example.com", rr, now); !errors.Is(err, taskpkg.ErrBadClass) {
		t.Fatalf("Insert of a CHAOS record = %v, want ErrBadClass", err)
	}
	if n := g.Len(); n != 0 {
		t.Fatalf("cache holds %d keys after a class rejection, want 0", n)
	}
}

// One bad answer must abort the whole response: the good answers next to it
// must not be cached either.
func TestInsertResponseIsAtomic(t *testing.T) {
	g := taskpkg.NewDnsCacheGuard(dnsConfig())
	now := time.Unix(1700000000, 0)
	resp := taskpkg.Response{
		Zone:         "example.com",
		QuestionName: "api.example.com",
		QuestionType: taskpkg.TypeA,
		Answers: []taskpkg.RR{
			dnsRR("api.example.com", taskpkg.TypeA, 300, "192.0.2.10"),
			dnsRR("cdn.example.com", taskpkg.TypeA, 300, "192.0.2.11"),
			dnsRR("evil.attacker.net", taskpkg.TypeA, 300, "203.0.113.66"),
		},
	}
	inserted, err := g.InsertResponse(resp, now)
	if !errors.Is(err, taskpkg.ErrBailiwick) {
		t.Fatalf("InsertResponse with one poisoned answer = %v, want ErrBailiwick", err)
	}
	if inserted != 0 {
		t.Fatalf("InsertResponse reported %d inserted records, want 0", inserted)
	}
	if n := g.Len(); n != 0 {
		t.Fatalf("cache holds %d keys after an aborted response, want 0", n)
	}
	if _, err := g.Lookup("api.example.com", taskpkg.TypeA, now); !errors.Is(err, taskpkg.ErrNotFound) {
		t.Fatalf("Lookup after an aborted response = %v, want ErrNotFound", err)
	}
}

// Owner names are case-insensitive and a single trailing dot is ignored.
func TestLookupIsCaseInsensitive(t *testing.T) {
	g := taskpkg.NewDnsCacheGuard(dnsConfig())
	now := time.Unix(1700000000, 0)
	if err := g.Insert("example.com", dnsRR("WWW.Example.COM.", taskpkg.TypeA, 600, "192.0.2.20"), now); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	recs, err := g.Lookup("www.example.com", taskpkg.TypeA, now.Add(30*time.Second))
	if err != nil {
		t.Fatalf("Lookup lower-case name: %v", err)
	}
	if len(recs) != 1 || recs[0].RData != "192.0.2.20" {
		t.Fatalf("Lookup returned %+v, want the 192.0.2.20 A record", recs)
	}
	if upper, err := g.Lookup("WWW.EXAMPLE.COM", taskpkg.TypeA, now.Add(30*time.Second)); err != nil || len(upper) != 1 {
		t.Fatalf("Lookup upper-case name = %v, %d records; want one hit", err, len(upper))
	}
}

// Records are keyed by owner and type; an A record must not answer an AAAA
// or TXT query.
func TestLookupTypeIsolation(t *testing.T) {
	g := taskpkg.NewDnsCacheGuard(dnsConfig())
	now := time.Unix(1700000000, 0)
	if err := g.Insert("example.com", dnsRR("host.example.com", taskpkg.TypeA, 300, "192.0.2.30"), now); err != nil {
		t.Fatalf("Insert A: %v", err)
	}
	if err := g.Insert("example.com", dnsRR("host.example.com", taskpkg.TypeAAAA, 300, "2001:db8::30"), now); err != nil {
		t.Fatalf("Insert AAAA: %v", err)
	}
	a, err := g.Lookup("host.example.com", taskpkg.TypeA, now)
	if err != nil || len(a) != 1 || a[0].Type != taskpkg.TypeA {
		t.Fatalf("Lookup A = %+v, %v; want exactly one A record", a, err)
	}
	aaaa, err := g.Lookup("host.example.com", taskpkg.TypeAAAA, now)
	if err != nil || len(aaaa) != 1 || aaaa[0].Type != taskpkg.TypeAAAA {
		t.Fatalf("Lookup AAAA = %+v, %v; want exactly one AAAA record", aaaa, err)
	}
	if _, err := g.Lookup("host.example.com", taskpkg.TypeTXT, now); !errors.Is(err, taskpkg.ErrNotFound) {
		t.Fatalf("Lookup TXT = %v, want ErrNotFound", err)
	}
}

// A tiny upstream TTL is raised to MinTTL.
func TestTTLClampedToMinimum(t *testing.T) {
	cfg := taskpkg.Config{MaxEntries: 8, MinTTL: 30 * time.Second, MaxTTL: time.Hour, NegativeTTL: time.Minute}
	g := taskpkg.NewDnsCacheGuard(cfg)
	now := time.Unix(1700000000, 0)
	if err := g.Insert("example.com", dnsRR("short.example.com", taskpkg.TypeA, 2, "192.0.2.40"), now); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if recs, err := g.Lookup("short.example.com", taskpkg.TypeA, now.Add(10*time.Second)); err != nil || len(recs) != 1 {
		t.Fatalf("Lookup at +10s = %v, %d records; want one hit under MinTTL", err, len(recs))
	}
	if _, err := g.Lookup("short.example.com", taskpkg.TypeA, now.Add(31*time.Second)); !errors.Is(err, taskpkg.ErrNotFound) {
		t.Fatalf("Lookup at +31s = %v, want ErrNotFound after MinTTL expired", err)
	}
}

// A huge upstream TTL is cut down to MaxTTL.
func TestTTLClampedToMaximum(t *testing.T) {
	cfg := taskpkg.Config{MaxEntries: 8, MaxTTL: time.Hour}
	g := taskpkg.NewDnsCacheGuard(cfg)
	now := time.Unix(1700000000, 0)
	if err := g.Insert("example.com", dnsRR("long.example.com", taskpkg.TypeA, 86400, "192.0.2.50"), now); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if recs, err := g.Lookup("long.example.com", taskpkg.TypeA, now.Add(3599*time.Second)); err != nil || len(recs) != 1 {
		t.Fatalf("Lookup at +3599s = %v, %d records; want one hit inside MaxTTL", err, len(recs))
	}
	if _, err := g.Lookup("long.example.com", taskpkg.TypeA, now.Add(3601*time.Second)); !errors.Is(err, taskpkg.ErrNotFound) {
		t.Fatalf("Lookup at +3601s = %v, want ErrNotFound after MaxTTL", err)
	}
}

// An expired entry is not served and is counted as a miss.
func TestExpiredEntryNotServed(t *testing.T) {
	cfg := taskpkg.Config{MaxEntries: 8, MaxTTL: time.Hour}
	g := taskpkg.NewDnsCacheGuard(cfg)
	now := time.Unix(1700000000, 0)
	if err := g.Insert("example.com", dnsRR("ttl.example.com", taskpkg.TypeA, 60, "192.0.2.60"), now); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if recs, err := g.Lookup("ttl.example.com", taskpkg.TypeA, now.Add(30*time.Second)); err != nil || len(recs) != 1 {
		t.Fatalf("Lookup at +30s = %v, %d records; want one hit", err, len(recs))
	}
	if hits := g.Stats().Hits; hits != 1 {
		t.Fatalf("Hits = %d after one successful lookup, want 1", hits)
	}
	if _, err := g.Lookup("ttl.example.com", taskpkg.TypeA, now.Add(61*time.Second)); !errors.Is(err, taskpkg.ErrNotFound) {
		t.Fatalf("Lookup at +61s = %v, want ErrNotFound", err)
	}
	if misses := g.Stats().Misses; misses != 1 {
		t.Fatalf("Misses = %d after one expired lookup, want 1", misses)
	}
}

// A full cache refuses a new key instead of silently evicting live data.
func TestCacheCapacityRejectsNewName(t *testing.T) {
	cfg := taskpkg.Config{MaxEntries: 2, MaxTTL: time.Hour}
	g := taskpkg.NewDnsCacheGuard(cfg)
	now := time.Unix(1700000000, 0)
	if err := g.Insert("example.com", dnsRR("a.example.com", taskpkg.TypeA, 300, "192.0.2.1"), now); err != nil {
		t.Fatalf("Insert a: %v", err)
	}
	if err := g.Insert("example.com", dnsRR("b.example.com", taskpkg.TypeA, 300, "192.0.2.2"), now); err != nil {
		t.Fatalf("Insert b: %v", err)
	}
	err := g.Insert("example.com", dnsRR("c.example.com", taskpkg.TypeA, 300, "192.0.2.3"), now)
	if !errors.Is(err, taskpkg.ErrCacheFull) {
		t.Fatalf("Insert into a full cache = %v, want ErrCacheFull", err)
	}
	if n := g.Len(); n != 2 {
		t.Fatalf("Len = %d after a full-cache rejection, want 2", n)
	}
}

// Expired entries must free capacity for new names.
func TestExpiredEntriesFreeCapacity(t *testing.T) {
	cfg := taskpkg.Config{MaxEntries: 2, MaxTTL: time.Hour}
	g := taskpkg.NewDnsCacheGuard(cfg)
	now := time.Unix(1700000000, 0)
	if err := g.Insert("example.com", dnsRR("a.example.com", taskpkg.TypeA, 10, "192.0.2.1"), now); err != nil {
		t.Fatalf("Insert a: %v", err)
	}
	if err := g.Insert("example.com", dnsRR("b.example.com", taskpkg.TypeA, 10, "192.0.2.2"), now); err != nil {
		t.Fatalf("Insert b: %v", err)
	}
	if err := g.Insert("example.com", dnsRR("c.example.com", taskpkg.TypeA, 300, "192.0.2.3"), now.Add(11*time.Second)); err != nil {
		t.Fatalf("Insert after expiry = %v, want capacity to be reclaimed", err)
	}
	if n := g.Len(); n != 1 {
		t.Fatalf("Len = %d after reclaiming two expired keys, want 1", n)
	}
	if recs, err := g.Lookup("c.example.com", taskpkg.TypeA, now.Add(11*time.Second)); err != nil || len(recs) != 1 {
		t.Fatalf("Lookup of the new key = %v, %d records; want one hit", err, len(recs))
	}
}

// NXDOMAIN answers are cached negatively for NegativeTTL and then forgotten.
func TestNegativeCachingNXDomain(t *testing.T) {
	cfg := taskpkg.Config{MaxEntries: 8, MaxTTL: time.Hour, NegativeTTL: time.Minute}
	g := taskpkg.NewDnsCacheGuard(cfg)
	now := time.Unix(1700000000, 0)
	resp := taskpkg.Response{
		Zone:         "example.com",
		QuestionName: "gone.example.com",
		QuestionType: taskpkg.TypeA,
		NXDomain:     true,
	}
	inserted, err := g.InsertResponse(resp, now)
	if err != nil {
		t.Fatalf("InsertResponse NXDOMAIN: %v", err)
	}
	if inserted != 0 {
		t.Fatalf("InsertResponse NXDOMAIN inserted %d records, want 0", inserted)
	}
	if _, err := g.Lookup("gone.example.com", taskpkg.TypeA, now.Add(30*time.Second)); !errors.Is(err, taskpkg.ErrNXDomain) {
		t.Fatalf("Lookup inside NegativeTTL = %v, want ErrNXDomain", err)
	}
	if _, err := g.Lookup("gone.example.com", taskpkg.TypeA, now.Add(61*time.Second)); !errors.Is(err, taskpkg.ErrNotFound) {
		t.Fatalf("Lookup after NegativeTTL = %v, want ErrNotFound", err)
	}
}

// Absolute expiry survives a restart: a record cached for 120s is still live
// 60s after the restore and gone after 121s.
func TestSnapshotRestoresEntriesAndTTL(t *testing.T) {
	g := taskpkg.NewDnsCacheGuard(dnsConfig())
	now := time.Unix(1700000000, 0)
	if err := g.Insert("example.com", dnsRR("persist.example.com", taskpkg.TypeA, 120, "192.0.2.70"), now); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	snap, err := g.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	restored, err := taskpkg.NewDnsCacheGuardFromSnapshot(dnsConfig(), snap)
	if err != nil {
		t.Fatalf("NewDnsCacheGuardFromSnapshot: %v", err)
	}
	if recs, err := restored.Lookup("persist.example.com", taskpkg.TypeA, now.Add(60*time.Second)); err != nil || len(recs) != 1 {
		t.Fatalf("Lookup 60s after restore = %v, %d records; want one hit", err, len(recs))
	}
	if _, err := restored.Lookup("persist.example.com", taskpkg.TypeA, now.Add(121*time.Second)); !errors.Is(err, taskpkg.ErrNotFound) {
		t.Fatalf("Lookup 121s after restore = %v, want ErrNotFound", err)
	}
}

// Concurrent writers of distinct names must all land and be readable.
func TestConcurrentDistinctInsertsStayConsistent(t *testing.T) {
	cfg := taskpkg.Config{MaxEntries: 40, MaxTTL: time.Hour}
	g := taskpkg.NewDnsCacheGuard(cfg)
	now := time.Unix(1700000000, 0)
	const workers = 40
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			name := fmt.Sprintf("h%d.example.com", i)
			rr := dnsRR(name, taskpkg.TypeA, 300, fmt.Sprintf("192.0.2.%d", i+1))
			if err := g.Insert("example.com", rr, now); err != nil {
				errs <- fmt.Errorf("Insert %s: %w", name, err)
				return
			}
			recs, err := g.Lookup(name, taskpkg.TypeA, now)
			if err != nil {
				errs <- fmt.Errorf("Lookup %s: %w", name, err)
				return
			}
			if len(recs) != 1 || recs[0].RData != rr.RData {
				errs <- fmt.Errorf("Lookup %s returned %+v", name, recs)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("%v", err)
	}
	if n := g.Len(); n != workers {
		t.Fatalf("Len = %d after %d concurrent inserts, want %d", n, workers, workers)
	}
}
