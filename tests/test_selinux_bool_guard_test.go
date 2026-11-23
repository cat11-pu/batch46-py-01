package task

import (
	"errors"
	"reflect"
	"sync"
	"testing"

	taskpkg "gsb/batch46-safety-e-02"
)

func newGuard() *taskpkg.SelinuxGuard {
	return taskpkg.NewSelinuxGuard(taskpkg.Config{MaxPending: 6, MaxChanges: 4})
}

func register(t *testing.T, g *taskpkg.SelinuxGuard, name string, def bool) {
	t.Helper()
	if err := g.RegisterBool(name, def); err != nil {
		t.Fatalf("RegisterBool %q: %v", name, err)
	}
}

func setBool(t *testing.T, g *taskpkg.SelinuxGuard, name string, want, persistent bool) {
	t.Helper()
	if err := g.SetBool(name, want, persistent); err != nil {
		t.Fatalf("SetBool %q=%v: %v", name, want, err)
	}
}

func apply(t *testing.T, g *taskpkg.SelinuxGuard) taskpkg.Report {
	t.Helper()
	rep, err := g.Apply()
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	return rep
}

// A boolean may be declared once; a second declaration is a policy bug.
func TestRegisterBoolDuplicateRejected(t *testing.T) {
	g := newGuard()
	register(t, g, "httpd_use_nfs", false)
	if err := g.RegisterBool("httpd_use_nfs", true); !errors.Is(err, taskpkg.ErrBoolExists) {
		t.Fatalf("re-registering a boolean: want ErrBoolExists, got %v", err)
	}
	if err := g.RegisterBool("", false); !errors.Is(err, taskpkg.ErrInvalidBoolName) {
		t.Fatalf("empty boolean name: want ErrInvalidBoolName, got %v", err)
	}
}

// Flipping an undeclared boolean must not silently invent policy.
func TestSetBoolUnknownRejected(t *testing.T) {
	g := newGuard()
	if err := g.SetBool("samba_export_all_rw", true, true); !errors.Is(err, taskpkg.ErrUnknownBool) {
		t.Fatalf("unknown boolean: want ErrUnknownBool, got %v", err)
	}
	if got := len(g.Pending()); got != 0 {
		t.Fatalf("rejected flip left %d pending entries", got)
	}
}

// Re-setting the exact applied value and persistence stages nothing.
func TestSetBoolIdempotentNoOp(t *testing.T) {
	g := newGuard()
	register(t, g, "httpd_use_nfs", false)
	setBool(t, g, "httpd_use_nfs", false, false)
	if got := g.Pending(); len(got) != 0 {
		t.Fatalf("no-op flip staged %v, want nothing", got)
	}
	setBool(t, g, "httpd_use_nfs", true, true)
	apply(t, g)
	setBool(t, g, "httpd_use_nfs", true, true)
	if got := g.Pending(); len(got) != 0 {
		t.Fatalf("repeat of applied state staged %v, want nothing", got)
	}
}

// Asking for a persistence upgrade while keeping the value is a real change.
func TestSetBoolPersistenceUpgradeStaged(t *testing.T) {
	g := newGuard()
	register(t, g, "httpd_use_nfs", false)
	setBool(t, g, "httpd_use_nfs", false, true)
	if got := g.Pending(); !reflect.DeepEqual(got, []string{"httpd_use_nfs"}) {
		t.Fatalf("pending = %v, want [httpd_use_nfs]", got)
	}
	apply(t, g)
	st, err := g.Bool("httpd_use_nfs")
	if err != nil {
		t.Fatalf("Bool: %v", err)
	}
	if st.Value || !st.Persistent {
		t.Fatalf("state = %+v, want value=false persistent=true", st)
	}
}

// The staging area must stay bounded even when the caller keeps flipping.
func TestPendingCapEnforced(t *testing.T) {
	g := taskpkg.NewSelinuxGuard(taskpkg.Config{MaxPending: 2, MaxChanges: 4})
	register(t, g, "httpd_use_nfs", false)
	register(t, g, "httpd_can_network_connect", false)
	register(t, g, "samba_export_all_ro", false)
	setBool(t, g, "httpd_use_nfs", true, false)
	setBool(t, g, "httpd_can_network_connect", true, false)
	if err := g.SetBool("samba_export_all_ro", true, false); !errors.Is(err, taskpkg.ErrCapReached) {
		t.Fatalf("third staged boolean: want ErrCapReached, got %v", err)
	}
	// Re-staging an already pending name does not consume another slot.
	setBool(t, g, "httpd_use_nfs", false, false)
	if got := len(g.Pending()); got != 2 {
		t.Fatalf("pending count = %d, want 2", got)
	}
}

// Applying an empty staging area is a caller bug, not a silent success.
func TestApplyWithoutPendingRejected(t *testing.T) {
	g := newGuard()
	register(t, g, "httpd_use_nfs", false)
	if _, err := g.Apply(); !errors.Is(err, taskpkg.ErrNothingToApply) {
		t.Fatalf("empty apply: want ErrNothingToApply, got %v", err)
	}
}

// Exceeding MaxChanges rejects the whole batch and keeps it recoverable.
func TestApplyBudgetExceededLeavesNothingApplied(t *testing.T) {
	g := taskpkg.NewSelinuxGuard(taskpkg.Config{MaxPending: 6, MaxChanges: 2})
	register(t, g, "httpd_use_nfs", false)
	register(t, g, "httpd_can_network_connect", false)
	register(t, g, "samba_export_all_ro", false)
	setBool(t, g, "httpd_use_nfs", true, false)
	setBool(t, g, "httpd_can_network_connect", true, false)
	setBool(t, g, "samba_export_all_ro", true, false)
	if _, err := g.Apply(); !errors.Is(err, taskpkg.ErrTooManyChanges) {
		t.Fatalf("over-budget apply: want ErrTooManyChanges, got %v", err)
	}
	for _, name := range []string{"httpd_use_nfs", "httpd_can_network_connect", "samba_export_all_ro"} {
		st, err := g.Bool(name)
		if err != nil {
			t.Fatalf("Bool %q: %v", name, err)
		}
		if st.Value || st.Revision != 0 {
			t.Fatalf("%s changed despite the rejected batch: %+v", name, st)
		}
	}
	if got := len(g.Pending()); got != 3 {
		t.Fatalf("pending after rejected batch = %d, want 3", got)
	}
}

// One apply commits every staged boolean and bumps each revision once.
func TestApplyCommitsBoolsWithRevision(t *testing.T) {
	g := newGuard()
	register(t, g, "httpd_use_nfs", false)
	register(t, g, "httpd_can_network_connect", false)
	register(t, g, "samba_export_all_ro", true)
	setBool(t, g, "httpd_use_nfs", true, true)
	setBool(t, g, "httpd_can_network_connect", true, false)
	setBool(t, g, "samba_export_all_ro", false, true)
	rep := apply(t, g)
	if rep.Revision != 1 {
		t.Fatalf("report revision = %d, want 1", rep.Revision)
	}
	names := make([]string, 0, len(rep.Bools))
	for _, ch := range rep.Bools {
		names = append(names, ch.Name)
	}
	want := []string{"httpd_can_network_connect", "httpd_use_nfs", "samba_export_all_ro"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("report order = %v, want %v", names, want)
	}
	checks := map[string]taskpkg.BoolState{
		"httpd_use_nfs":            {Name: "httpd_use_nfs", Value: true, Persistent: true, Revision: 1},
		"httpd_can_network_connect": {Name: "httpd_can_network_connect", Value: true, Persistent: false, Revision: 1},
		"samba_export_all_ro":      {Name: "samba_export_all_ro", Value: false, Persistent: true, Revision: 1},
	}
	for name, wantState := range checks {
		st, err := g.Bool(name)
		if err != nil {
			t.Fatalf("Bool %q: %v", name, err)
		}
		if st != wantState {
			t.Fatalf("%s = %+v, want %+v", name, st, wantState)
		}
	}
	if g.Revision() != 1 || g.Stats().PendingBools != 0 {
		t.Fatalf("revision=%d pending=%d, want 1/0", g.Revision(), g.Stats().PendingBools)
	}
}

// File labels only make sense for absolute, clean paths.
func TestAddContextRejectsRelativePath(t *testing.T) {
	g := newGuard()
	err := g.AddContext(taskpkg.ContextSpec{Path: "var/www/html", Type: "httpd_sys_content_t"})
	if !errors.Is(err, taskpkg.ErrInvalidPath) {
		t.Fatalf("relative path: want ErrInvalidPath, got %v", err)
	}
	err = g.AddContext(taskpkg.ContextSpec{Path: "/var/www/html/../html", Type: "httpd_sys_content_t"})
	if !errors.Is(err, taskpkg.ErrInvalidPath) {
		t.Fatalf("uncleaned path: want ErrInvalidPath, got %v", err)
	}
}

// Every SELinux type ends with _t; anything else is a typo.
func TestAddContextRejectsBadType(t *testing.T) {
	g := newGuard()
	err := g.AddContext(taskpkg.ContextSpec{Path: "/var/www/html", Type: "httpd_sys_content"})
	if !errors.Is(err, taskpkg.ErrInvalidContextType) {
		t.Fatalf("type without _t suffix: want ErrInvalidContextType, got %v", err)
	}
}

// One path with two different labels in the same batch is ambiguous.
func TestAddContextConflictingTypeRejected(t *testing.T) {
	g := newGuard()
	if err := g.AddContext(taskpkg.ContextSpec{Path: "/var/www/html", Type: "httpd_sys_content_t"}); err != nil {
		t.Fatalf("first AddContext: %v", err)
	}
	err := g.AddContext(taskpkg.ContextSpec{Path: "/var/www/html", Type: "var_t"})
	if !errors.Is(err, taskpkg.ErrConflict) {
		t.Fatalf("conflicting label: want ErrConflict, got %v", err)
	}
}

// Applying a label fills the default user and role and publishes the path.
func TestApplyPublishesContextWithDefaults(t *testing.T) {
	g := newGuard()
	if err := g.AddContext(taskpkg.ContextSpec{Path: "/var/www/html", Type: "httpd_sys_content_t"}); err != nil {
		t.Fatalf("AddContext html: %v", err)
	}
	if err := g.AddContext(taskpkg.ContextSpec{Path: "/srv/nfs", User: "staff_u", Type: "nfs_t"}); err != nil {
		t.Fatalf("AddContext nfs: %v", err)
	}
	rep := apply(t, g)
	if len(rep.Contexts) != 2 || rep.Contexts[0].Path != "/srv/nfs" || rep.Contexts[1].Path != "/var/www/html" {
		t.Fatalf("report contexts = %+v, want /srv/nfs first", rep.Contexts)
	}
	got, err := g.ContextAt("/var/www/html")
	if err != nil {
		t.Fatalf("ContextAt: %v", err)
	}
	want := taskpkg.ContextSpec{Path: "/var/www/html", User: taskpkg.DefaultUser, Role: taskpkg.DefaultRole, Type: "httpd_sys_content_t"}
	if got != want {
		t.Fatalf("context = %+v, want %+v", got, want)
	}
	if _, err := g.ContextAt("/srv/nfs"); err != nil {
		t.Fatalf("ContextAt nfs: %v", err)
	}
}

// Removing a label that was never applied must fail, and only a second apply
// makes the removal visible.
func TestRemoveContextUnknownPathRejected(t *testing.T) {
	g := newGuard()
	if err := g.RemoveContext("/etc/nginx/nginx.conf"); !errors.Is(err, taskpkg.ErrNotFound) {
		t.Fatalf("removing an unlabeled path: want ErrNotFound, got %v", err)
	}
	if err := g.AddContext(taskpkg.ContextSpec{Path: "/etc/nginx/nginx.conf", Type: "httpd_config_t"}); err != nil {
		t.Fatalf("AddContext: %v", err)
	}
	apply(t, g)
	if err := g.RemoveContext("/etc/nginx/nginx.conf"); err != nil {
		t.Fatalf("staged removal: %v", err)
	}
	if err := g.RemoveContext("/etc/nginx/nginx.conf"); !errors.Is(err, taskpkg.ErrNotFound) {
		t.Fatalf("removing twice: want ErrNotFound, got %v", err)
	}
	rep := apply(t, g)
	if !reflect.DeepEqual(rep.Removed, []string{"/etc/nginx/nginx.conf"}) {
		t.Fatalf("report removed = %v, want the nginx path", rep.Removed)
	}
	if _, err := g.ContextAt("/etc/nginx/nginx.conf"); !errors.Is(err, taskpkg.ErrNotFound) {
		t.Fatalf("label survived removal: %v", err)
	}
}

// A restart keeps persistent booleans and labels, and drops volatile ones.
func TestSnapshotDropsVolatileBools(t *testing.T) {
	g := newGuard()
	register(t, g, "httpd_can_network_connect", false)
	register(t, g, "httpd_use_nfs", false)
	setBool(t, g, "httpd_can_network_connect", true, false)
	apply(t, g)
	setBool(t, g, "httpd_use_nfs", true, true)
	apply(t, g)
	if err := g.AddContext(taskpkg.ContextSpec{Path: "/var/www/html", Type: "httpd_sys_content_t"}); err != nil {
		t.Fatalf("AddContext: %v", err)
	}
	apply(t, g)
	snap, err := g.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	restored, err := taskpkg.NewSelinuxGuardFromSnapshot(taskpkg.Config{MaxPending: 6, MaxChanges: 4}, snap)
	if err != nil {
		t.Fatalf("NewSelinuxGuardFromSnapshot: %v", err)
	}
	volatile, err := restored.Bool("httpd_can_network_connect")
	if err != nil {
		t.Fatalf("Bool volatile: %v", err)
	}
	if volatile.Value || volatile.Persistent {
		t.Fatalf("volatile boolean survived restart: %+v", volatile)
	}
	persisted, err := restored.Bool("httpd_use_nfs")
	if err != nil {
		t.Fatalf("Bool persistent: %v", err)
	}
	if !persisted.Value || !persisted.Persistent {
		t.Fatalf("persistent boolean lost: %+v", persisted)
	}
	if restored.Revision() != 3 {
		t.Fatalf("restored revision = %d, want 3", restored.Revision())
	}
	if _, err := restored.ContextAt("/var/www/html"); err != nil {
		t.Fatalf("label lost across restart: %v", err)
	}
}

// Two workers applying the same batch must not both report success.
func TestConcurrentApplySingleWinner(t *testing.T) {
	g := newGuard()
	register(t, g, "httpd_use_nfs", false)
	setBool(t, g, "httpd_use_nfs", true, true)
	errs := make([]error, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	for i := range errs {
		go func(i int) {
			defer wg.Done()
			_, errs[i] = g.Apply()
		}(i)
	}
	wg.Wait()
	wins := 0
	for _, err := range errs {
		if err == nil {
			wins++
		} else if !errors.Is(err, taskpkg.ErrNothingToApply) {
			t.Fatalf("loser returned %v, want ErrNothingToApply", err)
		}
	}
	if wins != 1 {
		t.Fatalf("concurrent applies: %d winners, want exactly 1", wins)
	}
}
