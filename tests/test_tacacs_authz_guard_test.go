package task

import (
	"errors"
	"sync"
	"testing"
	"time"

	taskpkg "gsb/batch46-safety-a-06"
)

var base = time.Unix(1735689600, 0) // 2025-01-01T00:00:00Z

func guard(t *testing.T, maxSessions, maxArgs int, ttl, retention time.Duration) *taskpkg.TacacsGuard {
	t.Helper()
	return taskpkg.NewTacacsGuard(taskpkg.Config{
		SessionTTL:    ttl,
		MaxSessions:   maxSessions,
		MaxArgs:       maxArgs,
		AcctRetention: retention,
	})
}

func login(t *testing.T, g *taskpkg.TacacsGuard, id string, now time.Time) {
	t.Helper()
	if err := g.Authenticate(id, "alice", "sw-core-1", "tenant-a", now); err != nil {
		t.Fatalf("Authenticate(%q): %v", id, err)
	}
}

func showVersion() taskpkg.AuthorizeRequest {
	return taskpkg.AuthorizeRequest{
		SessionID: "sess-1",
		User:      "alice",
		TenantID:  "tenant-a",
		Command:   "show version",
	}
}

func permitAll() taskpkg.Rule {
	return taskpkg.Rule{
		Name:     "permit-ops",
		TenantID: "tenant-a",
		Command:  "*",
		Permit:   true,
		Order:    10,
		AVs:      []taskpkg.AV{{Name: "priv-lvl", Value: "15"}, {Name: "timeout", Value: "300"}},
	}
}

func TestAuthorizeWithoutSessionIsUnauthenticated(t *testing.T) {
	g := guard(t, 4, 8, 5*time.Minute, time.Hour)
	req := showVersion()
	_, err := g.Authorize(req, base)
	if !errors.Is(err, taskpkg.ErrUnauthenticated) {
		t.Fatalf("Authorize without a live session = %v, want ErrUnauthenticated", err)
	}
}

func TestSessionExpiresExactlyAtTTL(t *testing.T) {
	g := guard(t, 4, 8, 5*time.Minute, time.Hour)
	login(t, g, "sess-1", base)
	if active, err := g.SessionActive("sess-1", base.Add(4*time.Minute+59*time.Second)); err != nil || !active {
		t.Fatalf("session inside its TTL: active=%v err=%v, want active and no error", active, err)
	}
	atDeadline := base.Add(5 * time.Minute)
	if active, err := g.SessionActive("sess-1", atDeadline); err != nil || active {
		t.Fatalf("session at its deadline: active=%v err=%v, want inactive and no error", active, err)
	}
	if _, err := g.Authorize(showVersion(), atDeadline); !errors.Is(err, taskpkg.ErrUnauthenticated) {
		t.Fatalf("Authorize at the session deadline = %v, want ErrUnauthenticated", err)
	}
}

func TestExpiredSessionIDIsReusable(t *testing.T) {
	g := guard(t, 4, 8, 5*time.Minute, time.Hour)
	login(t, g, "sess-1", base)
	later := base.Add(6 * time.Minute)
	login(t, g, "sess-1", later)
	if active, err := g.SessionActive("sess-1", later); err != nil || !active {
		t.Fatalf("reopened session: active=%v err=%v, want active", active, err)
	}
	if active, err := g.SessionActive("sess-1", base.Add(11*time.Minute-1)); err != nil || !active {
		t.Fatalf("reopened session must live five more minutes: active=%v err=%v", active, err)
	}
	if active, err := g.SessionActive("sess-1", base.Add(11*time.Minute)); err != nil || active {
		t.Fatalf("reopened session at its new deadline: active=%v err=%v, want inactive", active, err)
	}
}

func TestPerDeviceSessionCapIgnoresExpiredSessions(t *testing.T) {
	g := guard(t, 2, 8, 5*time.Minute, time.Hour)
	login(t, g, "sess-1", base)
	login(t, g, "sess-2", base)
	if err := g.Authenticate("sess-3", "bob", "sw-core-1", "tenant-a", base); !errors.Is(err, taskpkg.ErrLimit) {
		t.Fatalf("third session on a capped device = %v, want ErrLimit", err)
	}
	later := base.Add(6 * time.Minute)
	login(t, g, "sess-3", later)
	if n := g.ExpireSessions(later); n != 2 {
		t.Fatalf("ExpireSessions removed %d records, want 2", n)
	}
}

func TestDuplicateLiveSessionRejected(t *testing.T) {
	g := guard(t, 4, 8, 5*time.Minute, time.Hour)
	login(t, g, "sess-1", base)
	if err := g.Authenticate("sess-1", "bob", "sw-core-2", "tenant-a", base); !errors.Is(err, taskpkg.ErrArgInvalid) {
		t.Fatalf("duplicate live session id = %v, want ErrArgInvalid", err)
	}
	if active, err := g.SessionActive("sess-1", base); err != nil || !active {
		t.Fatalf("original session was disturbed: active=%v err=%v", active, err)
	}
}

func TestDenyRuleWinsOverWildcardPermitByOrder(t *testing.T) {
	g := guard(t, 4, 8, 5*time.Minute, time.Hour)
	login(t, g, "sess-1", base)
	if err := g.AddRule(permitAll()); err != nil {
		t.Fatalf("AddRule(permit): %v", err)
	}
	deny := taskpkg.Rule{Name: "deny-reload", TenantID: "tenant-a", Command: "reload", Permit: false, Order: 1}
	if err := g.AddRule(deny); err != nil {
		t.Fatalf("AddRule(deny): %v", err)
	}
	req := showVersion()
	req.Command = "reload"
	dec, err := g.Authorize(req, base)
	if !errors.Is(err, taskpkg.ErrNotAuthorized) {
		t.Fatalf("denied command = %v, want ErrNotAuthorized", err)
	}
	if dec.Allowed || dec.Rule != "deny-reload" || len(dec.AVs) != 0 {
		t.Fatalf("deny decision = %+v, want Allowed=false Rule=deny-reload and no AVs", dec)
	}
	req.Command = "show version"
	dec, err = g.Authorize(req, base)
	if err != nil || !dec.Allowed || dec.Rule != "permit-ops" {
		t.Fatalf("permitted command = %+v err=%v, want permit-ops", dec, err)
	}
	if len(dec.AVs) != 2 || dec.AVs[0] != (taskpkg.AV{Name: "priv-lvl", Value: "15"}) || dec.AVs[1].Name != "timeout" {
		t.Fatalf("permit AVs = %+v, want priv-lvl then timeout in declaration order", dec.AVs)
	}
}

func TestRuleArgumentsMustMatchExactly(t *testing.T) {
	g := guard(t, 4, 8, 5*time.Minute, time.Hour)
	login(t, g, "sess-1", base)
	rule := taskpkg.Rule{
		Name:     "permit-iface",
		TenantID: "tenant-a",
		Command:  "configure",
		Args:     []string{"interface", "Gi0/1"},
		Permit:   true,
		Order:    5,
		AVs:      []taskpkg.AV{{Name: "role", Value: "netops"}},
	}
	if err := g.AddRule(rule); err != nil {
		t.Fatalf("AddRule: %v", err)
	}
	req := showVersion()
	req.Command = "configure"
	req.Args = []string{"interface", "Gi0/1"}
	dec, err := g.Authorize(req, base)
	if err != nil || !dec.Allowed || dec.Rule != "permit-iface" {
		t.Fatalf("matching arguments = %+v err=%v, want permit-iface", dec, err)
	}
	req.Args = []string{"interface", "Gi0/2"}
	dec, err = g.Authorize(req, base)
	if !errors.Is(err, taskpkg.ErrNotAuthorized) || dec.Rule != "default-deny" || dec.Allowed {
		t.Fatalf("mismatched arguments = %+v err=%v, want default deny", dec, err)
	}
}

func TestArgumentCountLimit(t *testing.T) {
	g := guard(t, 4, 3, 5*time.Minute, time.Hour)
	login(t, g, "sess-1", base)
	if err := g.AddRule(permitAll()); err != nil {
		t.Fatalf("AddRule: %v", err)
	}
	req := showVersion()
	req.Command = "configure"
	req.Args = []string{"a", "b", "c", "d"}
	if _, err := g.Authorize(req, base); !errors.Is(err, taskpkg.ErrLimit) {
		t.Fatalf("four arguments against a cap of three = %v, want ErrLimit", err)
	}
	req.Args = []string{"a", "b", "c"}
	if dec, err := g.Authorize(req, base); err != nil || !dec.Allowed {
		t.Fatalf("three arguments at the cap = %+v err=%v, want allowed", dec, err)
	}
}

func TestCrossTenantRulesAndSessionsAreIsolated(t *testing.T) {
	g := guard(t, 4, 8, 5*time.Minute, time.Hour)
	login(t, g, "sess-1", base)
	foreign := taskpkg.Rule{Name: "tenant-b-read", TenantID: "tenant-b", Command: "show run", Permit: true, Order: 1}
	if err := g.AddRule(foreign); err != nil {
		t.Fatalf("AddRule: %v", err)
	}
	req := showVersion()
	req.Command = "show run"
	dec, err := g.Authorize(req, base)
	if !errors.Is(err, taskpkg.ErrNotAuthorized) || dec.Rule != "default-deny" {
		t.Fatalf("tenant-a request hit a tenant-b rule: %+v err=%v", dec, err)
	}
	req.TenantID = "tenant-b"
	if _, err := g.Authorize(req, base); !errors.Is(err, taskpkg.ErrUnauthenticated) {
		t.Fatalf("session reused across tenants = %v, want ErrUnauthenticated", err)
	}
}

func TestAccountingAccumulatesWatchdogAndStop(t *testing.T) {
	g := guard(t, 4, 8, time.Hour, time.Hour)
	login(t, g, "sess-1", base)
	recs := []taskpkg.AcctRecord{
		{TaskID: "task-9", SessionID: "sess-1", User: "alice", Flags: "start", Command: "copy run start", At: base},
		{TaskID: "task-9", SessionID: "sess-1", User: "alice", Flags: "watchdog", Bytes: 100, At: base.Add(time.Minute)},
		{TaskID: "task-9", SessionID: "sess-1", User: "alice", Flags: "watchdog", Bytes: 50, At: base.Add(2 * time.Minute)},
		{TaskID: "task-9", SessionID: "sess-1", User: "alice", Flags: "stop", Bytes: 25, At: base.Add(3 * time.Minute)},
	}
	for i, rec := range recs {
		if err := g.Accounting(rec, rec.At); err != nil {
			t.Fatalf("Accounting record %d (%s): %v", i, rec.Flags, err)
		}
	}
	usage, err := g.AcctUsage("task-9")
	if err != nil || usage != 175 {
		t.Fatalf("AcctUsage = %d err=%v, want 175", usage, err)
	}
	late := recs[3]
	late.At = base.Add(4 * time.Minute)
	late.Bytes = 999
	if err := g.Accounting(late, late.At); !errors.Is(err, taskpkg.ErrAccounting) {
		t.Fatalf("second stop record = %v, want ErrAccounting", err)
	}
	if usage, _ := g.AcctUsage("task-9"); usage != 175 {
		t.Fatalf("usage after a rejected stop = %d, want 175", usage)
	}
}

func TestAccountingWithoutStartRejected(t *testing.T) {
	g := guard(t, 4, 8, time.Hour, time.Hour)
	login(t, g, "sess-1", base)
	wd := taskpkg.AcctRecord{TaskID: "task-x", SessionID: "sess-1", User: "alice", Flags: "watchdog", Bytes: 5, At: base}
	if err := g.Accounting(wd, base); !errors.Is(err, taskpkg.ErrAccounting) {
		t.Fatalf("watchdog before start = %v, want ErrAccounting", err)
	}
	stop := wd
	stop.Flags = "stop"
	if err := g.Accounting(stop, base); !errors.Is(err, taskpkg.ErrAccounting) {
		t.Fatalf("stop before start = %v, want ErrAccounting", err)
	}
	if _, err := g.AcctUsage("task-x"); !errors.Is(err, taskpkg.ErrAccounting) {
		t.Fatalf("AcctUsage for an unknown task = %v, want ErrAccounting", err)
	}
	unknown := wd
	unknown.TaskID = "task-y"
	unknown.SessionID = "sess-missing"
	if err := g.Accounting(unknown, base); !errors.Is(err, taskpkg.ErrUnauthenticated) {
		t.Fatalf("accounting on an unknown session = %v, want ErrUnauthenticated", err)
	}
}

func TestAccountingDuplicateStartRejected(t *testing.T) {
	g := guard(t, 4, 8, time.Hour, time.Hour)
	login(t, g, "sess-1", base)
	start := taskpkg.AcctRecord{TaskID: "task-1", SessionID: "sess-1", User: "alice", Flags: "start", At: base}
	if err := g.Accounting(start, base); err != nil {
		t.Fatalf("first start: %v", err)
	}
	if err := g.Accounting(start, base.Add(time.Second)); !errors.Is(err, taskpkg.ErrAccounting) {
		t.Fatalf("duplicate start = %v, want ErrAccounting", err)
	}
	if usage, err := g.AcctUsage("task-1"); err != nil || usage != 0 {
		t.Fatalf("usage after duplicate start = %d err=%v, want 0", usage, err)
	}
	bad := start
	bad.TaskID = "task-2"
	bad.Flags = "pause"
	if err := g.Accounting(bad, base); !errors.Is(err, taskpkg.ErrArgInvalid) {
		t.Fatalf("unknown accounting flag = %v, want ErrArgInvalid", err)
	}
}

func TestConcurrentAuthorizeAndAccountingStayConsistent(t *testing.T) {
	g := guard(t, 4, 8, time.Hour, time.Hour)
	login(t, g, "sess-1", base)
	if err := g.AddRule(permitAll()); err != nil {
		t.Fatalf("AddRule: %v", err)
	}
	start := taskpkg.AcctRecord{TaskID: "task-race", SessionID: "sess-1", User: "alice", Flags: "start", At: base}
	if err := g.Accounting(start, base); err != nil {
		t.Fatalf("start: %v", err)
	}
	const authz = 60
	const acct = 40
	var wg sync.WaitGroup
	authzErrs := make([]error, authz)
	acctErrs := make([]error, acct)
	wg.Add(authz + acct)
	for i := 0; i < authz; i++ {
		go func(i int) {
			defer wg.Done()
			_, authzErrs[i] = g.Authorize(showVersion(), base)
		}(i)
	}
	for i := 0; i < acct; i++ {
		go func(i int) {
			defer wg.Done()
			acctErrs[i] = g.Accounting(taskpkg.AcctRecord{
				TaskID: "task-race", SessionID: "sess-1", User: "alice", Flags: "watchdog", Bytes: 10, At: base,
			}, base)
		}(i)
	}
	wg.Wait()
	for i, err := range authzErrs {
		if err != nil {
			t.Fatalf("concurrent Authorize %d: %v", i, err)
		}
	}
	for i, err := range acctErrs {
		if err != nil {
			t.Fatalf("concurrent Accounting %d: %v", i, err)
		}
	}
	if usage, err := g.AcctUsage("task-race"); err != nil || usage != 400 {
		t.Fatalf("usage after 40 concurrent watchdogs of 10 bytes = %d err=%v, want 400", usage, err)
	}
}

func TestSnapshotRestoresSessionsRulesAndUsage(t *testing.T) {
	g := guard(t, 4, 8, time.Hour, time.Hour)
	login(t, g, "sess-1", base)
	if err := g.AddRule(permitAll()); err != nil {
		t.Fatalf("AddRule: %v", err)
	}
	if err := g.Accounting(taskpkg.AcctRecord{TaskID: "task-7", SessionID: "sess-1", User: "alice", Flags: "start", At: base}, base); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := g.Accounting(taskpkg.AcctRecord{TaskID: "task-7", SessionID: "sess-1", User: "alice", Flags: "stop", Bytes: 64, At: base.Add(time.Minute)}, base.Add(time.Minute)); err != nil {
		t.Fatalf("stop: %v", err)
	}
	snap, err := g.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	restored, err := taskpkg.NewTacacsGuardFromSnapshot(taskpkg.Config{
		SessionTTL: time.Hour, MaxSessions: 4, MaxArgs: 8, AcctRetention: time.Hour,
	}, snap)
	if err != nil {
		t.Fatalf("NewTacacsGuardFromSnapshot: %v", err)
	}
	if active, err := restored.SessionActive("sess-1", base.Add(2*time.Minute)); err != nil || !active {
		t.Fatalf("session after restart: active=%v err=%v, want active", active, err)
	}
	if restored.RuleCount() != 1 {
		t.Fatalf("RuleCount after restart = %d, want 1", restored.RuleCount())
	}
	dec, err := restored.Authorize(showVersion(), base.Add(2*time.Minute))
	if err != nil || !dec.Allowed || dec.Rule != "permit-ops" {
		t.Fatalf("Authorize after restart = %+v err=%v, want permit-ops", dec, err)
	}
	if usage, err := restored.AcctUsage("task-7"); err != nil || usage != 64 {
		t.Fatalf("usage after restart = %d err=%v, want 64", usage, err)
	}
}

func TestPruneDropsExpiredSessionsAndRetainedTasks(t *testing.T) {
	g := guard(t, 4, 8, 5*time.Minute, 30*time.Minute)
	login(t, g, "sess-1", base)
	login(t, g, "sess-2", base)
	if err := g.Accounting(taskpkg.AcctRecord{TaskID: "task-old", SessionID: "sess-1", User: "alice", Flags: "start", At: base}, base); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := g.Accounting(taskpkg.AcctRecord{TaskID: "task-old", SessionID: "sess-1", User: "alice", Flags: "stop", Bytes: 12, At: base}, base); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if n := g.Prune(base.Add(4 * time.Minute)); n != 0 {
		t.Fatalf("Prune inside retention removed %d records, want 0", n)
	}
	if usage, err := g.AcctUsage("task-old"); err != nil || usage != 12 {
		t.Fatalf("usage inside retention = %d err=%v, want 12", usage, err)
	}
	if n := g.Prune(base.Add(31 * time.Minute)); n != 3 {
		t.Fatalf("Prune after retention removed %d records, want 3 (two sessions and one task)", n)
	}
	if _, err := g.AcctUsage("task-old"); !errors.Is(err, taskpkg.ErrAccounting) {
		t.Fatalf("usage of a pruned task = %v, want ErrAccounting", err)
	}
}
