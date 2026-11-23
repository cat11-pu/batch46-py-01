package task

import (
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	taskpkg "gsb/batch46-safety-d-03"
)

func imapPolicy() taskpkg.Policy {
	return taskpkg.Policy{
		IdleTimeout: time.Minute,
		MaxSessions: 8,
		MaxPending:  10,
		BatchSize:   5,
	}
}

func baseMailbox() taskpkg.Mailbox {
	return taskpkg.Mailbox{Name: "INBOX", UIDValidity: 100, Messages: 3, HighestModSeq: 100}
}

func mustImapGuard(t *testing.T, p taskpkg.Policy) *taskpkg.ImapIdleGuard {
	t.Helper()
	g := taskpkg.NewImapIdleGuard(p)
	if g == nil {
		t.Fatalf("NewImapIdleGuard returned nil")
	}
	return g
}

func mustSetMailbox(t *testing.T, g *taskpkg.ImapIdleGuard, account string, m taskpkg.Mailbox) {
	t.Helper()
	if err := g.SetMailbox(account, m); err != nil {
		t.Fatalf("SetMailbox(%q): %v", m.Name, err)
	}
}

func imapSetup(t *testing.T, p taskpkg.Policy, m taskpkg.Mailbox, now time.Time) (*taskpkg.ImapIdleGuard, string) {
	t.Helper()
	g := mustImapGuard(t, p)
	mustSetMailbox(t, g, "acct-a", m)
	sess, err := g.RegisterSession("acct-a", "s1", m.Name, now)
	if err != nil {
		t.Fatalf("RegisterSession: %v", err)
	}
	if err := g.BeginIdle(sess.ID, now); err != nil {
		t.Fatalf("BeginIdle: %v", err)
	}
	return g, sess.ID
}

func notificationValues(t *testing.T, ns []taskpkg.Notification) []int64 {
	t.Helper()
	out := make([]int64, 0, len(ns))
	for _, n := range ns {
		out = append(out, n.Value)
	}
	return out
}

// Mailbox registration validates its fields and unknown names are reported.
func TestMailboxValidationAndLookup(t *testing.T) {
	g := mustImapGuard(t, imapPolicy())
	if err := g.SetMailbox("acct-a", taskpkg.Mailbox{Name: "INBOX", UIDValidity: 0, Messages: 3, HighestModSeq: 100}); !errors.Is(err, taskpkg.ErrMailboxInvalid) {
		t.Fatalf("zero UIDVALIDITY: want ErrMailboxInvalid, got %v", err)
	}
	m := baseMailbox()
	mustSetMailbox(t, g, "acct-a", m)
	got, err := g.Mailbox("acct-a", "INBOX")
	if err != nil {
		t.Fatalf("Mailbox: %v", err)
	}
	if !reflect.DeepEqual(got, m) {
		t.Fatalf("Mailbox = %+v, want %+v", got, m)
	}
	if _, err := g.Mailbox("acct-a", "Archive"); !errors.Is(err, taskpkg.ErrMailboxNotFound) {
		t.Fatalf("unknown mailbox: want ErrMailboxNotFound, got %v", err)
	}
	if err := g.Publish(taskpkg.Update{Account: "acct-a", Mailbox: "Archive", UIDValidity: 100, Messages: 1, HighestModSeq: 101}, time.Unix(1700000000, 0)); !errors.Is(err, taskpkg.ErrMailboxNotFound) {
		t.Fatalf("publish to unknown mailbox: want ErrMailboxNotFound, got %v", err)
	}
}

// Duplicate session ids and the per-account session cap are enforced.
func TestRegisterSessionLimits(t *testing.T) {
	p := imapPolicy()
	p.MaxSessions = 1
	g := mustImapGuard(t, p)
	now := time.Unix(1700000000, 0)
	mustSetMailbox(t, g, "acct-a", baseMailbox())
	if _, err := g.RegisterSession("acct-a", "s1", "INBOX", now); err != nil {
		t.Fatalf("first session: %v", err)
	}
	if _, err := g.RegisterSession("acct-a", "s1", "INBOX", now); !errors.Is(err, taskpkg.ErrSessionState) {
		t.Fatalf("duplicate id: want ErrSessionState, got %v", err)
	}
	if _, err := g.RegisterSession("acct-a", "s2", "INBOX", now); !errors.Is(err, taskpkg.ErrSessionLimit) {
		t.Fatalf("session over cap: want ErrSessionLimit, got %v", err)
	}
}

// Poll only works while IDLE is active, and IDLE cannot be entered twice.
func TestSessionStateMachine(t *testing.T) {
	g := mustImapGuard(t, imapPolicy())
	now := time.Unix(1700000000, 0)
	mustSetMailbox(t, g, "acct-a", baseMailbox())
	if _, err := g.RegisterSession("acct-a", "s1", "INBOX", now); err != nil {
		t.Fatalf("RegisterSession: %v", err)
	}
	if _, err := g.Poll("s1", now); !errors.Is(err, taskpkg.ErrSessionState) {
		t.Fatalf("Poll before IDLE: want ErrSessionState, got %v", err)
	}
	if err := g.BeginIdle("s1", now); err != nil {
		t.Fatalf("BeginIdle: %v", err)
	}
	if err := g.BeginIdle("s1", now); !errors.Is(err, taskpkg.ErrSessionState) {
		t.Fatalf("second BeginIdle: want ErrSessionState, got %v", err)
	}
	if err := g.EndIdle("s1"); err != nil {
		t.Fatalf("EndIdle: %v", err)
	}
	if _, err := g.Poll("s1", now); !errors.Is(err, taskpkg.ErrSessionState) {
		t.Fatalf("Poll after EndIdle: want ErrSessionState, got %v", err)
	}
}

// MODSEQ must increase strictly; equal or older updates are stale.
func TestPublishMonotonicModSeq(t *testing.T) {
	now := time.Unix(1700000000, 0)
	g, _ := imapSetup(t, imapPolicy(), baseMailbox(), now)
	ok := taskpkg.Update{Account: "acct-a", Mailbox: "INBOX", UIDValidity: 100, Messages: 4, HighestModSeq: 101}
	if err := g.Publish(ok, now); err != nil {
		t.Fatalf("first publish: %v", err)
	}
	equal := ok
	equal.Messages = 5
	if err := g.Publish(equal, now); !errors.Is(err, taskpkg.ErrStaleUpdate) {
		t.Fatalf("equal MODSEQ: want ErrStaleUpdate, got %v", err)
	}
	older := ok
	older.Messages = 6
	older.HighestModSeq = 100
	if err := g.Publish(older, now); !errors.Is(err, taskpkg.ErrStaleUpdate) {
		t.Fatalf("older MODSEQ: want ErrStaleUpdate, got %v", err)
	}
	mb, err := g.Mailbox("acct-a", "INBOX")
	if err != nil {
		t.Fatalf("Mailbox: %v", err)
	}
	if mb.HighestModSeq != 101 || mb.Messages != 4 {
		t.Fatalf("mailbox after stale updates = %+v, want modseq 101 messages 4", mb)
	}
}

// A message count may only shrink when UIDVALIDITY changed.
func TestPublishMessageCountRegression(t *testing.T) {
	now := time.Unix(1700000000, 0)
	g, _ := imapSetup(t, imapPolicy(), baseMailbox(), now)
	shrink := taskpkg.Update{Account: "acct-a", Mailbox: "INBOX", UIDValidity: 100, Messages: 2, HighestModSeq: 101}
	if err := g.Publish(shrink, now); !errors.Is(err, taskpkg.ErrStaleUpdate) {
		t.Fatalf("message count regression: want ErrStaleUpdate, got %v", err)
	}
	reset := taskpkg.Update{Account: "acct-a", Mailbox: "INBOX", UIDValidity: 200, Messages: 1, HighestModSeq: 150}
	if err := g.Publish(reset, now); err != nil {
		t.Fatalf("UIDVALIDITY reset with smaller count: %v", err)
	}
	mb, err := g.Mailbox("acct-a", "INBOX")
	if err != nil {
		t.Fatalf("Mailbox: %v", err)
	}
	if mb.UIDValidity != 200 || mb.Messages != 1 {
		t.Fatalf("mailbox after reset = %+v", mb)
	}
}

// A new message generates one EXISTS notification and advances the cursor.
func TestExistsNotificationDelivered(t *testing.T) {
	now := time.Unix(1700000000, 0)
	g, id := imapSetup(t, imapPolicy(), baseMailbox(), now)
	if err := g.Publish(taskpkg.Update{Account: "acct-a", Mailbox: "INBOX", UIDValidity: 100, Messages: 5, HighestModSeq: 101}, now); err != nil {
		t.Fatalf("publish: %v", err)
	}
	ns, err := g.Poll(id, now)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(ns) != 1 || ns[0].Kind != taskpkg.KindExists || ns[0].Value != 5 || ns[0].ModSeq != 101 {
		t.Fatalf("notifications = %+v, want one EXISTS 5 modseq 101", ns)
	}
	seq, err := g.Seq(id)
	if err != nil {
		t.Fatalf("Seq: %v", err)
	}
	if seq != 5 {
		t.Fatalf("Seq = %d, want 5", seq)
	}
	again, err := g.Poll(id, now)
	if err != nil {
		t.Fatalf("second Poll: %v", err)
	}
	if len(again) != 0 {
		t.Fatalf("second Poll returned %d notifications, want 0", len(again))
	}
	counters := g.Counters()
	if counters.Published != 1 || counters.Delivered != 1 {
		t.Fatalf("counters = %+v, want Published=1 Delivered=1", counters)
	}
}

// Poll drains in publish order and respects BatchSize.
func TestBatchLimitAndOrder(t *testing.T) {
	p := imapPolicy()
	p.BatchSize = 2
	p.MaxPending = 20
	now := time.Unix(1700000000, 0)
	g, id := imapSetup(t, p, baseMailbox(), now)
	for i := 4; i <= 8; i++ {
		if err := g.Publish(taskpkg.Update{Account: "acct-a", Mailbox: "INBOX", UIDValidity: 100, Messages: i, HighestModSeq: uint64(100 + i - 3)}, now); err != nil {
			t.Fatalf("publish messages=%d: %v", i, err)
		}
	}
	wantBatches := [][]int64{{4, 5}, {6, 7}, {8}}
	for _, want := range wantBatches {
		ns, err := g.Poll(id, now)
		if err != nil {
			t.Fatalf("Poll: %v", err)
		}
		if got := notificationValues(t, ns); !reflect.DeepEqual(got, want) {
			t.Fatalf("batch = %v, want %v", got, want)
		}
	}
	empty, err := g.Poll(id, now)
	if err != nil {
		t.Fatalf("final Poll: %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("final Poll returned %d notifications", len(empty))
	}
}

// A UIDVALIDITY change resets the cursor and must not emit a stale EXISTS for
// the old mailbox generation.
func TestUIDValidityChangeResetsCursor(t *testing.T) {
	now := time.Unix(1700000000, 0)
	g, id := imapSetup(t, imapPolicy(), baseMailbox(), now)
	if err := g.Publish(taskpkg.Update{Account: "acct-a", Mailbox: "INBOX", UIDValidity: 200, Messages: 1, HighestModSeq: 101}, now); err != nil {
		t.Fatalf("publish validity change: %v", err)
	}
	ns, err := g.Poll(id, now)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(ns) != 1 || ns[0].Kind != taskpkg.KindUIDValidity || ns[0].Value != 200 {
		t.Fatalf("notifications = %+v, want one UIDVALIDITY 200", ns)
	}
	seq, err := g.Seq(id)
	if err != nil {
		t.Fatalf("Seq: %v", err)
	}
	if seq != 1 {
		t.Fatalf("Seq = %d, want 1 after reset", seq)
	}
	if err := g.Publish(taskpkg.Update{Account: "acct-a", Mailbox: "INBOX", UIDValidity: 200, Messages: 2, HighestModSeq: 102}, now); err != nil {
		t.Fatalf("publish after reset: %v", err)
	}
	next, err := g.Poll(id, now)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if got := notificationValues(t, next); !reflect.DeepEqual(got, []int64{2}) {
		t.Fatalf("post-reset notifications = %v, want [2]", got)
	}
}

// Sessions of another account must not see updates for the same mailbox name.
func TestCrossAccountIsolation(t *testing.T) {
	g := mustImapGuard(t, imapPolicy())
	now := time.Unix(1700000000, 0)
	mustSetMailbox(t, g, "acct-a", baseMailbox())
	mustSetMailbox(t, g, "acct-b", baseMailbox())
	for _, id := range []string{"sa", "sb"} {
		account := "acct-a"
		if id == "sb" {
			account = "acct-b"
		}
		if _, err := g.RegisterSession(account, id, "INBOX", now); err != nil {
			t.Fatalf("RegisterSession(%s): %v", id, err)
		}
		if err := g.BeginIdle(id, now); err != nil {
			t.Fatalf("BeginIdle(%s): %v", id, err)
		}
	}
	if err := g.Publish(taskpkg.Update{Account: "acct-a", Mailbox: "INBOX", UIDValidity: 100, Messages: 4, HighestModSeq: 101}, now); err != nil {
		t.Fatalf("publish: %v", err)
	}
	na, err := g.Poll("sa", now)
	if err != nil {
		t.Fatalf("Poll sa: %v", err)
	}
	if got := notificationValues(t, na); !reflect.DeepEqual(got, []int64{4}) {
		t.Fatalf("acct-a notifications = %v, want [4]", got)
	}
	nb, err := g.Poll("sb", now)
	if err != nil {
		t.Fatalf("Poll sb: %v", err)
	}
	if len(nb) != 0 {
		t.Fatalf("acct-b saw %d notifications from acct-a", len(nb))
	}
}

// A session only sees updates for the mailbox it selected.
func TestCrossMailboxIsolation(t *testing.T) {
	g := mustImapGuard(t, imapPolicy())
	now := time.Unix(1700000000, 0)
	mustSetMailbox(t, g, "acct-a", baseMailbox())
	sent := taskpkg.Mailbox{Name: "Sent", UIDValidity: 100, Messages: 0, HighestModSeq: 100}
	mustSetMailbox(t, g, "acct-a", sent)
	if _, err := g.RegisterSession("acct-a", "s1", "INBOX", now); err != nil {
		t.Fatalf("RegisterSession: %v", err)
	}
	if err := g.BeginIdle("s1", now); err != nil {
		t.Fatalf("BeginIdle: %v", err)
	}
	if err := g.Publish(taskpkg.Update{Account: "acct-a", Mailbox: "Sent", UIDValidity: 100, Messages: 1, HighestModSeq: 101}, now); err != nil {
		t.Fatalf("publish Sent: %v", err)
	}
	ns, err := g.Poll("s1", now)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(ns) != 0 {
		t.Fatalf("INBOX session saw %d Sent notifications", len(ns))
	}
}

// The pending queue is bounded and drops the oldest notifications first.
func TestPendingQueueCap(t *testing.T) {
	p := imapPolicy()
	p.MaxPending = 2
	p.BatchSize = 5
	now := time.Unix(1700000000, 0)
	m := baseMailbox()
	m.Messages = 0
	g, id := imapSetup(t, p, m, now)
	for i := 1; i <= 4; i++ {
		if err := g.Publish(taskpkg.Update{Account: "acct-a", Mailbox: "INBOX", UIDValidity: 100, Messages: i, HighestModSeq: uint64(100 + i)}, now); err != nil {
			t.Fatalf("publish %d: %v", i, err)
		}
	}
	ns, err := g.Poll(id, now)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if got := notificationValues(t, ns); !reflect.DeepEqual(got, []int64{3, 4}) {
		t.Fatalf("notifications = %v, want [3 4]", got)
	}
	if got := g.Counters().Dropped; got != 2 {
		t.Fatalf("Dropped = %d, want 2", got)
	}
}

// An IDLE session older than IdleTimeout is expired and cannot be polled again.
func TestIdleTimeoutClosesSession(t *testing.T) {
	now := time.Unix(1700000000, 0)
	g, id := imapSetup(t, imapPolicy(), baseMailbox(), now)
	if _, err := g.Poll(id, now.Add(61*time.Second)); !errors.Is(err, taskpkg.ErrIdleTimeout) {
		t.Fatalf("expired IDLE: want ErrIdleTimeout, got %v", err)
	}
	if got := g.Counters().Expired; got != 1 {
		t.Fatalf("Expired = %d, want 1", got)
	}
	if _, err := g.Poll(id, now.Add(62*time.Second)); !errors.Is(err, taskpkg.ErrSessionState) {
		t.Fatalf("Poll after expiry: want ErrSessionState, got %v", err)
	}
}

// Concurrent publishes to different mailboxes must not lose or cross
// notifications.
func TestConcurrentPublishAcrossMailboxes(t *testing.T) {
	p := imapPolicy()
	p.MaxSessions = 20
	p.MaxPending = 2
	now := time.Unix(1700000000, 0)
	g := mustImapGuard(t, p)
	const n = 20
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("BOX-%d", i)
		mustSetMailbox(t, g, "acct-a", taskpkg.Mailbox{Name: name, UIDValidity: 100, Messages: 0, HighestModSeq: 100})
		if _, err := g.RegisterSession("acct-a", fmt.Sprintf("s-%d", i), name, now); err != nil {
			t.Fatalf("RegisterSession %d: %v", i, err)
		}
		if err := g.BeginIdle(fmt.Sprintf("s-%d", i), now); err != nil {
			t.Fatalf("BeginIdle %d: %v", i, err)
		}
	}
	var wg sync.WaitGroup
	errs := make([]error, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(idx int) {
			defer wg.Done()
			errs[idx] = g.Publish(taskpkg.Update{
				Account:       "acct-a",
				Mailbox:       fmt.Sprintf("BOX-%d", idx),
				UIDValidity:   100,
				Messages:      idx + 1,
				HighestModSeq: 101,
			}, now)
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("publish %d: %v", i, err)
		}
	}
	for i := 0; i < n; i++ {
		ns, err := g.Poll(fmt.Sprintf("s-%d", i), now)
		if err != nil {
			t.Fatalf("Poll %d: %v", i, err)
		}
		if len(ns) != 1 || ns[0].Value != int64(i+1) {
			t.Fatalf("session %d notifications = %+v, want one EXISTS %d", i, ns, i+1)
		}
	}
}

// A restart must keep undelivered notifications and the cursor; corrupt
// snapshots are refused.
func TestSnapshotRestoresPendingQueue(t *testing.T) {
	p := imapPolicy()
	p.BatchSize = 1
	now := time.Unix(1700000000, 0)
	m := baseMailbox()
	m.Messages = 0
	g, id := imapSetup(t, p, m, now)
	for i := 1; i <= 2; i++ {
		if err := g.Publish(taskpkg.Update{Account: "acct-a", Mailbox: "INBOX", UIDValidity: 100, Messages: i, HighestModSeq: uint64(100 + i)}, now); err != nil {
			t.Fatalf("publish %d: %v", i, err)
		}
	}
	first, err := g.Poll(id, now)
	if err != nil {
		t.Fatalf("first Poll: %v", err)
	}
	if got := notificationValues(t, first); !reflect.DeepEqual(got, []int64{1}) {
		t.Fatalf("first batch = %v, want [1]", got)
	}
	snap, err := g.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if _, err := taskpkg.NewImapIdleGuardFromSnapshot(p, []byte("broken")); !errors.Is(err, taskpkg.ErrSnapshot) {
		t.Fatalf("corrupt snapshot: want ErrSnapshot, got %v", err)
	}
	restored, err := taskpkg.NewImapIdleGuardFromSnapshot(p, snap)
	if err != nil {
		t.Fatalf("NewImapIdleGuardFromSnapshot: %v", err)
	}
	second, err := restored.Poll(id, now)
	if err != nil {
		t.Fatalf("Poll after restore: %v", err)
	}
	if got := notificationValues(t, second); !reflect.DeepEqual(got, []int64{2}) {
		t.Fatalf("post-restore batch = %v, want [2]", got)
	}
	seq, err := restored.Seq(id)
	if err != nil {
		t.Fatalf("Seq: %v", err)
	}
	if seq != 2 {
		t.Fatalf("Seq after restore = %d, want 2", seq)
	}
	counters := restored.Counters()
	if counters.Published != 2 || counters.Delivered != 2 {
		t.Fatalf("counters after restore = %+v, want Published=2 Delivered=2", counters)
	}
}

// Closing a session frees its slot and removes it from account listings.
func TestCloseSessionReleasesSlot(t *testing.T) {
	p := imapPolicy()
	p.MaxSessions = 1
	g := mustImapGuard(t, p)
	now := time.Unix(1700000000, 0)
	mustSetMailbox(t, g, "acct-a", baseMailbox())
	if _, err := g.RegisterSession("acct-a", "s1", "INBOX", now); err != nil {
		t.Fatalf("RegisterSession s1: %v", err)
	}
	if err := g.CloseSession("s1"); err != nil {
		t.Fatalf("CloseSession: %v", err)
	}
	if _, err := g.Poll("s1", now); !errors.Is(err, taskpkg.ErrSessionNotFound) {
		t.Fatalf("Poll after close: want ErrSessionNotFound, got %v", err)
	}
	if _, err := g.RegisterSession("acct-a", "s2", "INBOX", now); err != nil {
		t.Fatalf("RegisterSession s2 after close: %v", err)
	}
	if got := g.SessionsFor("acct-a"); !reflect.DeepEqual(got, []string{"s2"}) {
		t.Fatalf("SessionsFor = %v, want [s2]", got)
	}
	if err := g.CloseSession("nope"); !errors.Is(err, taskpkg.ErrSessionNotFound) {
		t.Fatalf("CloseSession unknown: want ErrSessionNotFound, got %v", err)
	}
}
