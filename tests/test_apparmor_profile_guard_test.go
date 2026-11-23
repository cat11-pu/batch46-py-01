package task

import (
	"errors"
	"reflect"
	"sync"
	"testing"

	taskpkg "gsb/batch46-safety-e-01"
)

func testCfg() taskpkg.Config {
	return taskpkg.Config{
		MaxProfiles:        6,
		MaxRulesPerProfile: 4,
		MaxAttachments:     2,
		MaxHistory:         2,
	}
}

const tenant = "tenant-a"

func named(name string, version int, rules ...string) taskpkg.Profile {
	return taskpkg.Profile{
		Tenant:  tenant,
		Name:    tenant + "." + name,
		Version: version,
		Mode:    taskpkg.ModeEnforce,
		Rules:   rules,
	}
}

func stageOK(t *testing.T, g *taskpkg.AppArmorGuard, p taskpkg.Profile) {
	t.Helper()
	if err := g.Stage(p); err != nil {
		t.Fatalf("Stage %q v%d: %v", p.Name, p.Version, err)
	}
}

func commitOK(t *testing.T, g *taskpkg.AppArmorGuard, name string) taskpkg.Profile {
	t.Helper()
	p, err := g.Commit(tenant, tenant+"."+name)
	if err != nil {
		t.Fatalf("Commit %q: %v", name, err)
	}
	return p
}

// A profile name that is not scoped to the tenant must never be staged.
func TestStageRejectsNameOutsideTenantPrefix(t *testing.T) {
	g := taskpkg.NewAppArmorGuard(testCfg())
	err := g.Stage(named("web", 1, "allow /tmp/** rw"))
	if !errors.Is(err, taskpkg.ErrInvalidName) {
		t.Fatalf("unprefixed name: want ErrInvalidName, got %v", err)
	}
	if err := g.Stage(taskpkg.Profile{Tenant: tenant, Name: "web", Version: 1, Mode: taskpkg.ModeEnforce}); !errors.Is(err, taskpkg.ErrInvalidName) {
		t.Fatalf("bare name: want ErrInvalidName, got %v", err)
	}
}

// Only enforce and complain are legitimate modes.
func TestStageRejectsUnknownMode(t *testing.T) {
	g := taskpkg.NewAppArmorGuard(testCfg())
	p := named("web", 1, "allow /tmp/** rw")
	p.Mode = taskpkg.Mode("unconfined")
	if err := g.Stage(p); !errors.Is(err, taskpkg.ErrInvalidMode) {
		t.Fatalf("unconfined mode: want ErrInvalidMode, got %v", err)
	}
}

// A rule repeated inside one profile is a configuration mistake, not a no-op.
func TestStageRejectsDuplicateRule(t *testing.T) {
	g := taskpkg.NewAppArmorGuard(testCfg())
	p := named("web", 1, "allow /var/www/** r", "allow /var/www/** r")
	if err := g.Stage(p); !errors.Is(err, taskpkg.ErrDuplicateRule) {
		t.Fatalf("duplicate rules: want ErrDuplicateRule, got %v", err)
	}
}

// The per-profile rule budget must be enforced at stage time.
func TestStageEnforcesRuleBudget(t *testing.T) {
	g := taskpkg.NewAppArmorGuard(testCfg())
	p := named("web", 1,
		"allow /a/** r", "allow /b/** r", "allow /c/** r", "allow /d/** r", "allow /e/** r")
	if err := g.Stage(p); !errors.Is(err, taskpkg.ErrTooManyRules) {
		t.Fatalf("five rules with budget four: want ErrTooManyRules, got %v", err)
	}
}

// Distinct profiles, staged or active, count against MaxProfiles.
func TestStageEnforcesProfileCap(t *testing.T) {
	cfg := testCfg()
	cfg.MaxProfiles = 2
	g := taskpkg.NewAppArmorGuard(cfg)
	stageOK(t, g, named("web", 1, "allow /srv/web/** r"))
	stageOK(t, g, named("api", 1, "allow /srv/api/** r"))
	if err := g.Stage(named("db", 1, "allow /srv/db/** r")); !errors.Is(err, taskpkg.ErrCapReached) {
		t.Fatalf("third profile over the cap: want ErrCapReached, got %v", err)
	}
}

// A second staged profile for the same name must be refused, not merged.
func TestStageRejectsSecondStagedProfile(t *testing.T) {
	g := taskpkg.NewAppArmorGuard(testCfg())
	stageOK(t, g, named("web", 1, "allow /srv/web/** r"))
	if err := g.Stage(named("web", 2, "allow /srv/web/** rw")); !errors.Is(err, taskpkg.ErrStagedExists) {
		t.Fatalf("restaging the same name: want ErrStagedExists, got %v", err)
	}
}

// Commit without a staged profile has nothing to promote.
func TestCommitRequiresStagedProfile(t *testing.T) {
	g := taskpkg.NewAppArmorGuard(testCfg())
	if _, err := g.Commit(tenant, tenant+".web"); !errors.Is(err, taskpkg.ErrNotStaged) {
		t.Fatalf("commit with nothing staged: want ErrNotStaged, got %v", err)
	}
}

// A staged version must be strictly greater than the active one.
func TestCommitRejectsNonAdvancingVersion(t *testing.T) {
	g := taskpkg.NewAppArmorGuard(testCfg())
	stageOK(t, g, named("web", 2, "allow /srv/web/** r"))
	commitOK(t, g, "web")
	stageOK(t, g, named("web", 2, "allow /srv/web/** rw"))
	if _, err := g.Commit(tenant, tenant+".web"); !errors.Is(err, taskpkg.ErrVersionConflict) {
		t.Fatalf("same version again: want ErrVersionConflict, got %v", err)
	}
	stageOK(t, g, named("web", 1, "allow /srv/web/** rw"))
	if _, err := g.Commit(tenant, tenant+".web"); !errors.Is(err, taskpkg.ErrVersionConflict) {
		t.Fatalf("older version: want ErrVersionConflict, got %v", err)
	}
}

// Swapping a profile invalidates every process attached to the old one.
func TestCommitClearsAttachments(t *testing.T) {
	g := taskpkg.NewAppArmorGuard(testCfg())
	stageOK(t, g, named("web", 1, "allow /srv/web/** r"))
	commitOK(t, g, "web")
	if err := g.Attach(tenant, tenant+".web", 4242); err != nil {
		t.Fatalf("Attach 4242: %v", err)
	}
	if err := g.Attach(tenant, tenant+".web", 5151); err != nil {
		t.Fatalf("Attach 5151: %v", err)
	}
	stageOK(t, g, named("web", 2, "allow /srv/web/** rw"))
	got := commitOK(t, g, "web")
	if got.Version != 2 || got.Generation != 2 {
		t.Fatalf("promoted profile: version=%d generation=%d, want 2/2", got.Version, got.Generation)
	}
	atts, err := g.Attachments(tenant, tenant+".web")
	if err != nil {
		t.Fatalf("Attachments: %v", err)
	}
	if len(atts) != 0 {
		t.Fatalf("attachments survived the swap: %v", atts)
	}
}

// The same staged profile committed from two goroutines must yield one winner.
func TestConcurrentCommitSingleWinner(t *testing.T) {
	g := taskpkg.NewAppArmorGuard(testCfg())
	stageOK(t, g, named("web", 1, "allow /srv/web/** r"))
	errs := make([]error, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	for i := range errs {
		go func(i int) {
			defer wg.Done()
			_, errs[i] = g.Commit(tenant, tenant+".web")
		}(i)
	}
	wg.Wait()
	wins := 0
	for _, err := range errs {
		if err == nil {
			wins++
		} else if !errors.Is(err, taskpkg.ErrNotStaged) {
			t.Fatalf("loser returned %v, want ErrNotStaged", err)
		}
	}
	if wins != 1 {
		t.Fatalf("concurrent commits: %d winners, want exactly 1", wins)
	}
}

// Rolling back restores the most recent superseded version.
func TestRollbackRestoresPreviousVersion(t *testing.T) {
	g := taskpkg.NewAppArmorGuard(testCfg())
	stageOK(t, g, named("web", 1, "allow /srv/web/** r"))
	commitOK(t, g, "web")
	stageOK(t, g, named("web", 2, "allow /srv/web/** rw"))
	commitOK(t, g, "web")
	back, err := g.Rollback(tenant, tenant+".web")
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if back.Version != 1 || back.Generation != 3 {
		t.Fatalf("rolled back profile: version=%d generation=%d, want 1/3", back.Version, back.Generation)
	}
	hist, err := g.History(tenant, tenant+".web")
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if len(hist) != 0 {
		t.Fatalf("history after rollback: %v, want empty", hist)
	}
}

// A profile that was never superseded has nothing to roll back to.
func TestRollbackWithoutHistoryFails(t *testing.T) {
	g := taskpkg.NewAppArmorGuard(testCfg())
	stageOK(t, g, named("web", 1, "allow /srv/web/** r"))
	commitOK(t, g, "web")
	if _, err := g.Rollback(tenant, tenant+".web"); !errors.Is(err, taskpkg.ErrNoHistory) {
		t.Fatalf("rollback without history: want ErrNoHistory, got %v", err)
	}
}

// Attaching the same pid twice is a bug; attaching past the cap is refused.
func TestAttachDuplicateAndCapRejected(t *testing.T) {
	g := taskpkg.NewAppArmorGuard(testCfg())
	stageOK(t, g, named("web", 1, "allow /srv/web/** r"))
	commitOK(t, g, "web")
	if err := g.Attach(tenant, tenant+".web", 10); err != nil {
		t.Fatalf("Attach 10: %v", err)
	}
	if err := g.Attach(tenant, tenant+".web", 10); !errors.Is(err, taskpkg.ErrAlreadyAttached) {
		t.Fatalf("duplicate pid: want ErrAlreadyAttached, got %v", err)
	}
	if err := g.Attach(tenant, tenant+".web", 11); err != nil {
		t.Fatalf("Attach 11: %v", err)
	}
	if err := g.Attach(tenant, tenant+".web", 12); !errors.Is(err, taskpkg.ErrAttachCap) {
		t.Fatalf("third pid over the cap: want ErrAttachCap, got %v", err)
	}
}

// History must stay bounded and keep the newest superseded versions.
func TestHistoryTrimmedToBudget(t *testing.T) {
	g := taskpkg.NewAppArmorGuard(testCfg())
	for v := 1; v <= 4; v++ {
		stageOK(t, g, named("web", v, "allow /srv/web/** r"))
		commitOK(t, g, "web")
	}
	hist, err := g.History(tenant, tenant+".web")
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if !reflect.DeepEqual(hist, []int{2, 3}) {
		t.Fatalf("history = %v, want [2 3]", hist)
	}
	if got := g.Stats().History; got != 2 {
		t.Fatalf("Stats().History = %d, want 2", got)
	}
}

// A restarted agent must come back with staged, active and attached state.
func TestSnapshotRestoresActiveStagedAndAttachments(t *testing.T) {
	g := taskpkg.NewAppArmorGuard(testCfg())
	stageOK(t, g, named("web", 1, "allow /srv/web/** r"))
	commitOK(t, g, "web")
	stageOK(t, g, named("web", 2, "allow /srv/web/** rw"))
	commitOK(t, g, "web")
	if err := g.Attach(tenant, tenant+".web", 7001); err != nil {
		t.Fatalf("Attach 7001: %v", err)
	}
	if err := g.Attach(tenant, tenant+".web", 7002); err != nil {
		t.Fatalf("Attach 7002: %v", err)
	}
	stageOK(t, g, named("web", 3, "allow /srv/web/** rwx"))
	snap, err := g.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	restored, err := taskpkg.NewAppArmorGuardFromSnapshot(testCfg(), snap)
	if err != nil {
		t.Fatalf("NewAppArmorGuardFromSnapshot: %v", err)
	}
	active, err := restored.Active(tenant, tenant+".web")
	if err != nil {
		t.Fatalf("restored Active: %v", err)
	}
	if active.Version != 2 || active.Generation != 2 {
		t.Fatalf("restored active: version=%d generation=%d, want 2/2", active.Version, active.Generation)
	}
	atts, err := restored.Attachments(tenant, tenant+".web")
	if err != nil {
		t.Fatalf("restored Attachments: %v", err)
	}
	if !reflect.DeepEqual(atts, []int{7001, 7002}) {
		t.Fatalf("restored attachments = %v, want [7001 7002]", atts)
	}
	promoted, err := restored.Commit(tenant, tenant+".web")
	if err != nil {
		t.Fatalf("commit staged profile after restore: %v", err)
	}
	if promoted.Version != 3 || promoted.Generation != 3 {
		t.Fatalf("promoted staged profile: version=%d generation=%d, want 3/3", promoted.Version, promoted.Generation)
	}
}
