package task

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	taskpkg "gsb/batch46-safety-d-10"
)

func mqttConfig() taskpkg.Config {
	return taskpkg.Config{
		MaxQueued:     10,
		SessionExpiry: time.Minute,
		WillDelay:     30 * time.Second,
		MaxInflight:   5,
	}
}

func mqttMsg(topic string, packetID uint16) taskpkg.Message {
	return taskpkg.Message{
		Topic:    topic,
		Payload:  "payload-for-" + topic,
		QoS:      1,
		PacketID: packetID,
	}
}

// A first connect creates a connected session without taking anything over.
func TestConnectCreatesSession(t *testing.T) {
	g := taskpkg.NewMqttSessionGuard(mqttConfig())
	now := time.Unix(1700000000, 0)
	takeover, err := g.Connect("client-a", false, taskpkg.Will{}, now)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if takeover.ClientID != "client-a" || takeover.Replaced {
		t.Fatalf("Takeover = %+v, want client-a without replacement", takeover)
	}
	if n := g.SessionCount(); n != 1 {
		t.Fatalf("SessionCount = %d after connect, want 1", n)
	}
	info, err := g.Info("client-a")
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if !info.Connected || info.Queued != 0 || info.Inflight != 0 || len(info.Subscriptions) != 0 {
		t.Fatalf("Info = %+v, want a fresh connected session", info)
	}
	if stats := g.Stats(); stats.Sessions != 1 {
		t.Fatalf("Stats.Sessions = %d, want 1", stats.Sessions)
	}
}

// A clean start wipes queued messages and subscriptions of a resumed session.
func TestCleanStartDiscardsPersistedState(t *testing.T) {
	g := taskpkg.NewMqttSessionGuard(mqttConfig())
	now := time.Unix(1700000000, 0)
	if _, err := g.Connect("c", false, taskpkg.Will{}, now); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if err := g.Subscribe("c", "sensors/temp"); err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	if err := g.Disconnect("c", false, now); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	if err := g.Queue("c", mqttMsg("sensors/temp", 11), now); err != nil {
		t.Fatalf("Queue 1: %v", err)
	}
	if err := g.Queue("c", mqttMsg("sensors/temp", 12), now); err != nil {
		t.Fatalf("Queue 2: %v", err)
	}
	takeover, err := g.Connect("c", true, taskpkg.Will{}, now.Add(time.Second))
	if err != nil {
		t.Fatalf("clean Connect: %v", err)
	}
	if takeover.Replaced {
		t.Fatalf("clean start of a disconnected session reported a takeover")
	}
	info, err := g.Info("c")
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if info.Queued != 0 || len(info.Subscriptions) != 0 {
		t.Fatalf("Info = %+v after clean start, want empty session state", info)
	}
	pending, err := g.Pending("c")
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	if len(pending) != 0 {
		t.Fatalf("Pending = %+v after clean start, want none", pending)
	}
}

// A persistent session keeps its queue across a reconnect in FIFO order.
func TestReconnectResumesQueuedMessagesInOrder(t *testing.T) {
	g := taskpkg.NewMqttSessionGuard(mqttConfig())
	now := time.Unix(1700000000, 0)
	if _, err := g.Connect("c", false, taskpkg.Will{}, now); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if err := g.Disconnect("c", false, now); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	if err := g.Queue("c", mqttMsg("jobs/a", 21), now); err != nil {
		t.Fatalf("Queue 1: %v", err)
	}
	if err := g.Queue("c", mqttMsg("jobs/b", 22), now); err != nil {
		t.Fatalf("Queue 2: %v", err)
	}
	if _, err := g.Connect("c", false, taskpkg.Will{}, now.Add(time.Second)); err != nil {
		t.Fatalf("reconnect: %v", err)
	}
	pending, err := g.Pending("c")
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	if len(pending) != 2 || pending[0].Topic != "jobs/a" || pending[1].Topic != "jobs/b" {
		t.Fatalf("Pending = %+v, want jobs/a then jobs/b", pending)
	}
	first, err := g.Next("c", now.Add(2*time.Second))
	if err != nil {
		t.Fatalf("Next 1: %v", err)
	}
	if first.PacketID != 21 {
		t.Fatalf("first delivered packet = %d, want 21", first.PacketID)
	}
	second, err := g.Next("c", now.Add(2*time.Second))
	if err != nil {
		t.Fatalf("Next 2: %v", err)
	}
	if second.PacketID != 22 {
		t.Fatalf("second delivered packet = %d, want 22", second.PacketID)
	}
}

// The offline queue refuses messages beyond MaxQueued instead of dropping the
// oldest.
func TestQueueHonorsMaxQueued(t *testing.T) {
	cfg := mqttConfig()
	cfg.MaxQueued = 2
	g := taskpkg.NewMqttSessionGuard(cfg)
	now := time.Unix(1700000000, 0)
	if _, err := g.Connect("c", false, taskpkg.Will{}, now); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if err := g.Queue("c", mqttMsg("t/1", 31), now); err != nil {
		t.Fatalf("Queue 1: %v", err)
	}
	if err := g.Queue("c", mqttMsg("t/2", 32), now); err != nil {
		t.Fatalf("Queue 2: %v", err)
	}
	if err := g.Queue("c", mqttMsg("t/3", 33), now); !errors.Is(err, taskpkg.ErrQueueFull) {
		t.Fatalf("Queue 3 = %v, want ErrQueueFull", err)
	}
	pending, err := g.Pending("c")
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	if len(pending) != 2 || pending[0].PacketID != 31 || pending[1].PacketID != 32 {
		t.Fatalf("Pending = %+v, want the first two messages intact", pending)
	}
	if info, err := g.Info("c"); err != nil || info.Queued != 2 {
		t.Fatalf("Info.Queued = %d, %v; want 2", info.Queued, err)
	}
}

// A packet id must be unique across the queue and the in-flight window.
func TestDuplicatePacketIDRejected(t *testing.T) {
	g := taskpkg.NewMqttSessionGuard(mqttConfig())
	now := time.Unix(1700000000, 0)
	if _, err := g.Connect("c", false, taskpkg.Will{}, now); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if err := g.Queue("c", mqttMsg("t/1", 7), now); err != nil {
		t.Fatalf("Queue 7: %v", err)
	}
	if err := g.Queue("c", mqttMsg("t/2", 7), now); !errors.Is(err, taskpkg.ErrDuplicatePacketID) {
		t.Fatalf("duplicate queued packet id = %v, want ErrDuplicatePacketID", err)
	}
	if err := g.Queue("c", mqttMsg("t/3", 8), now); err != nil {
		t.Fatalf("Queue 8: %v", err)
	}
	if _, err := g.Next("c", now); err != nil {
		t.Fatalf("Next: %v", err)
	}
	if err := g.Queue("c", mqttMsg("t/4", 7), now); !errors.Is(err, taskpkg.ErrDuplicatePacketID) {
		t.Fatalf("packet id reused while in flight = %v, want ErrDuplicatePacketID", err)
	}
	if err := g.Ack("c", 7); err != nil {
		t.Fatalf("Ack 7: %v", err)
	}
	if err := g.Queue("c", mqttMsg("t/5", 7), now); err != nil {
		t.Fatalf("packet id after ack = %v, want it reusable", err)
	}
}

// An expired persistent session must not accept new queued messages.
func TestQueueAfterSessionExpiryFails(t *testing.T) {
	cfg := mqttConfig()
	cfg.SessionExpiry = time.Minute
	g := taskpkg.NewMqttSessionGuard(cfg)
	now := time.Unix(1700000000, 0)
	if _, err := g.Connect("c", false, taskpkg.Will{}, now); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if err := g.Disconnect("c", false, now); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	if err := g.Queue("c", mqttMsg("t/1", 41), now.Add(30*time.Second)); err != nil {
		t.Fatalf("Queue inside expiry: %v", err)
	}
	if err := g.Queue("c", mqttMsg("t/2", 42), now.Add(61*time.Second)); !errors.Is(err, taskpkg.ErrSessionAbsent) {
		t.Fatalf("Queue after expiry = %v, want ErrSessionAbsent", err)
	}
	if n := g.SessionCount(); n != 0 {
		t.Fatalf("SessionCount = %d after the session expired, want 0", n)
	}
}

// A graceful DISCONNECT never publishes the will, whether or not the session
// is kept.
func TestGracefulDisconnectSuppressesWill(t *testing.T) {
	g := taskpkg.NewMqttSessionGuard(mqttConfig())
	now := time.Unix(1700000000, 0)
	will := taskpkg.Will{Topic: "will/c", Payload: "offline", QoS: 1}
	if _, err := g.Connect("c", false, will, now); err != nil {
		t.Fatalf("Connect c: %v", err)
	}
	if err := g.Disconnect("c", true, now); err != nil {
		t.Fatalf("Disconnect clean: %v", err)
	}
	if wills := g.DueWills(now.Add(time.Hour)); len(wills) != 0 {
		t.Fatalf("DueWills after a clean disconnect = %+v, want none", wills)
	}
	if n := g.SessionCount(); n != 0 {
		t.Fatalf("SessionCount = %d after a clean disconnect, want 0", n)
	}
	if _, err := g.Connect("d", false, will, now); err != nil {
		t.Fatalf("Connect d: %v", err)
	}
	if err := g.Disconnect("d", false, now); err != nil {
		t.Fatalf("Disconnect persistent: %v", err)
	}
	if wills := g.DueWills(now.Add(time.Hour)); len(wills) != 0 {
		t.Fatalf("DueWills after a persistent disconnect = %+v, want none", wills)
	}
	if n := g.SessionCount(); n != 1 {
		t.Fatalf("SessionCount = %d after a persistent disconnect, want 1", n)
	}
}

// Taking over a live connection publishes that connection's will
// immediately, ignoring the will delay.
func TestTakeoverPublishesOldWillImmediately(t *testing.T) {
	g := taskpkg.NewMqttSessionGuard(mqttConfig())
	now := time.Unix(1700000000, 0)
	oldWill := taskpkg.Will{Topic: "will/c", Payload: "gone", QoS: 1, Delay: time.Hour}
	if _, err := g.Connect("c", false, oldWill, now); err != nil {
		t.Fatalf("Connect old: %v", err)
	}
	takeover, err := g.Connect("c", false, taskpkg.Will{Topic: "will/new"}, now.Add(time.Second))
	if err != nil {
		t.Fatalf("Connect takeover: %v", err)
	}
	if !takeover.Replaced {
		t.Fatal("second connect did not report a takeover")
	}
	wills := g.DueWills(now.Add(time.Second))
	if len(wills) != 1 {
		t.Fatalf("DueWills = %+v, want the displaced connection will", wills)
	}
	if wills[0].Topic != "will/c" || wills[0].Payload != "gone" {
		t.Fatalf("published will = %+v, want will/c gone", wills[0])
	}
	if stats := g.Stats(); stats.Takeovers != 1 {
		t.Fatalf("Takeovers = %d, want 1", stats.Takeovers)
	}
}

// A will uses its own delay and falls back to the configured default.
func TestWillDelayRespected(t *testing.T) {
	cfg := mqttConfig()
	cfg.WillDelay = 30 * time.Second
	g := taskpkg.NewMqttSessionGuard(cfg)
	now := time.Unix(1700000000, 0)
	if _, err := g.Connect("c", false, taskpkg.Will{Topic: "will/c", Payload: "late", Delay: 60 * time.Second}, now); err != nil {
		t.Fatalf("Connect c: %v", err)
	}
	if err := g.Lose("c", now); err != nil {
		t.Fatalf("Lose c: %v", err)
	}
	if wills := g.DueWills(now.Add(30 * time.Second)); len(wills) != 0 {
		t.Fatalf("DueWills before the will delay = %+v, want none", wills)
	}
	if wills := g.DueWills(now.Add(61 * time.Second)); len(wills) != 1 || wills[0].Payload != "late" {
		t.Fatalf("DueWills after the will delay = %+v, want the late will", wills)
	}
	if _, err := g.Connect("d", false, taskpkg.Will{Topic: "will/d", Payload: "default"}, now); err != nil {
		t.Fatalf("Connect d: %v", err)
	}
	if err := g.Lose("d", now); err != nil {
		t.Fatalf("Lose d: %v", err)
	}
	if wills := g.DueWills(now.Add(29 * time.Second)); len(wills) != 0 {
		t.Fatalf("DueWills before the default delay = %+v, want none", wills)
	}
	if wills := g.DueWills(now.Add(31 * time.Second)); len(wills) != 1 || wills[0].Topic != "will/d" {
		t.Fatalf("DueWills after the default delay = %+v, want will/d", wills)
	}
}

// The in-flight window caps unacknowledged messages and reopens after an ack.
func TestInflightLimitEnforced(t *testing.T) {
	cfg := mqttConfig()
	cfg.MaxInflight = 2
	g := taskpkg.NewMqttSessionGuard(cfg)
	now := time.Unix(1700000000, 0)
	if _, err := g.Connect("c", false, taskpkg.Will{}, now); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	for id := uint16(1); id <= 3; id++ {
		if err := g.Queue("c", mqttMsg("t", id), now); err != nil {
			t.Fatalf("Queue %d: %v", id, err)
		}
	}
	if _, err := g.Next("c", now); err != nil {
		t.Fatalf("Next 1: %v", err)
	}
	if _, err := g.Next("c", now); err != nil {
		t.Fatalf("Next 2: %v", err)
	}
	if _, err := g.Next("c", now); !errors.Is(err, taskpkg.ErrInflightLimit) {
		t.Fatalf("Next past MaxInflight = %v, want ErrInflightLimit", err)
	}
	if n, err := g.Inflight("c"); err != nil || n != 2 {
		t.Fatalf("Inflight = %d, %v; want 2", n, err)
	}
	if err := g.Ack("c", 1); err != nil {
		t.Fatalf("Ack 1: %v", err)
	}
	third, err := g.Next("c", now)
	if err != nil {
		t.Fatalf("Next after ack: %v", err)
	}
	if third.PacketID != 3 {
		t.Fatalf("delivered packet = %d after ack, want 3", third.PacketID)
	}
}

// Ack releases exactly one in-flight slot and cannot be repeated.
func TestAckReleasesInflightSlot(t *testing.T) {
	g := taskpkg.NewMqttSessionGuard(mqttConfig())
	now := time.Unix(1700000000, 0)
	if _, err := g.Connect("c", false, taskpkg.Will{}, now); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if err := g.Queue("c", mqttMsg("t", 5), now); err != nil {
		t.Fatalf("Queue: %v", err)
	}
	if _, err := g.Next("c", now); err != nil {
		t.Fatalf("Next: %v", err)
	}
	if n, err := g.Inflight("c"); err != nil || n != 1 {
		t.Fatalf("Inflight before ack = %d, %v; want 1", n, err)
	}
	if err := g.Ack("c", 5); err != nil {
		t.Fatalf("Ack: %v", err)
	}
	if n, err := g.Inflight("c"); err != nil || n != 0 {
		t.Fatalf("Inflight after ack = %d, %v; want 0", n, err)
	}
	if err := g.Ack("c", 5); !errors.Is(err, taskpkg.ErrUnknownPacketID) {
		t.Fatalf("second Ack = %v, want ErrUnknownPacketID", err)
	}
	if err := g.Ack("c", 99); !errors.Is(err, taskpkg.ErrUnknownPacketID) {
		t.Fatalf("Ack of an unknown packet = %v, want ErrUnknownPacketID", err)
	}
}

// Expiry purge drops the session and everything attached to it.
func TestExpiryPurgeDropsSessionAndSubscriptions(t *testing.T) {
	cfg := mqttConfig()
	cfg.SessionExpiry = time.Minute
	g := taskpkg.NewMqttSessionGuard(cfg)
	now := time.Unix(1700000000, 0)
	if _, err := g.Connect("c", false, taskpkg.Will{}, now); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if err := g.Subscribe("c", "plant/line1"); err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	if err := g.Disconnect("c", false, now); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	if purged := g.PurgeExpired(now.Add(30 * time.Second)); purged != 0 {
		t.Fatalf("PurgeExpired before expiry dropped %d sessions, want 0", purged)
	}
	if n := g.SessionCount(); n != 1 {
		t.Fatalf("SessionCount inside the expiry window = %d, want 1", n)
	}
	if purged := g.PurgeExpired(now.Add(61 * time.Second)); purged != 1 {
		t.Fatalf("PurgeExpired after expiry dropped %d sessions, want 1", purged)
	}
	if n := g.SessionCount(); n != 0 {
		t.Fatalf("SessionCount after purge = %d, want 0", n)
	}
	if _, err := g.Subscriptions("c"); !errors.Is(err, taskpkg.ErrSessionAbsent) {
		t.Fatalf("Subscriptions after purge = %v, want ErrSessionAbsent", err)
	}
}

// A takeover discards the old in-flight window but keeps the persistent
// queue.
func TestTakeoverResetsInflight(t *testing.T) {
	g := taskpkg.NewMqttSessionGuard(mqttConfig())
	now := time.Unix(1700000000, 0)
	if _, err := g.Connect("c", false, taskpkg.Will{}, now); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if err := g.Queue("c", mqttMsg("jobs/1", 51), now); err != nil {
		t.Fatalf("Queue 1: %v", err)
	}
	if err := g.Queue("c", mqttMsg("jobs/2", 52), now); err != nil {
		t.Fatalf("Queue 2: %v", err)
	}
	if _, err := g.Next("c", now); err != nil {
		t.Fatalf("Next: %v", err)
	}
	if _, err := g.Connect("c", false, taskpkg.Will{}, now.Add(time.Second)); err != nil {
		t.Fatalf("takeover Connect: %v", err)
	}
	if n, err := g.Inflight("c"); err != nil || n != 0 {
		t.Fatalf("Inflight after takeover = %d, %v; want 0", n, err)
	}
	pending, err := g.Pending("c")
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	if len(pending) != 1 || pending[0].PacketID != 52 {
		t.Fatalf("Pending after takeover = %+v, want the unstarted message 52", pending)
	}
	if next, err := g.Next("c", now.Add(2*time.Second)); err != nil || next.PacketID != 52 {
		t.Fatalf("Next after takeover = %+v, %v; want packet 52", next, err)
	}
}

// Sessions, queues, subscriptions and pending wills survive a restart.
func TestSnapshotRestoresSessionsAndWills(t *testing.T) {
	cfg := mqttConfig()
	cfg.SessionExpiry = time.Minute
	cfg.WillDelay = 30 * time.Second
	g := taskpkg.NewMqttSessionGuard(cfg)
	now := time.Unix(1700000000, 0)
	will := taskpkg.Will{Topic: "will/a", Payload: "lost", QoS: 1, Delay: 45 * time.Second}
	if _, err := g.Connect("a", false, will, now); err != nil {
		t.Fatalf("Connect a: %v", err)
	}
	if err := g.Subscribe("a", "t/1"); err != nil {
		t.Fatalf("Subscribe t/1: %v", err)
	}
	if err := g.Subscribe("a", "t/0"); err != nil {
		t.Fatalf("Subscribe t/0: %v", err)
	}
	if err := g.Queue("a", mqttMsg("t/0", 61), now); err != nil {
		t.Fatalf("Queue 1: %v", err)
	}
	if err := g.Queue("a", mqttMsg("t/1", 62), now); err != nil {
		t.Fatalf("Queue 2: %v", err)
	}
	if _, err := g.Connect("b", false, taskpkg.Will{}, now); err != nil {
		t.Fatalf("Connect b: %v", err)
	}
	if err := g.Disconnect("b", false, now); err != nil {
		t.Fatalf("Disconnect b: %v", err)
	}
	if err := g.Lose("a", now); err != nil {
		t.Fatalf("Lose a: %v", err)
	}
	snap, err := g.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	restored, err := taskpkg.NewMqttSessionGuardFromSnapshot(cfg, snap)
	if err != nil {
		t.Fatalf("NewMqttSessionGuardFromSnapshot: %v", err)
	}
	if n := restored.SessionCount(); n != 2 {
		t.Fatalf("SessionCount after restore = %d, want 2", n)
	}
	pending, err := restored.Pending("a")
	if err != nil || len(pending) != 2 {
		t.Fatalf("Pending(a) after restore = %+v, %v; want 2 messages", pending, err)
	}
	subs, err := restored.Subscriptions("a")
	if err != nil {
		t.Fatalf("Subscriptions(a): %v", err)
	}
	if len(subs) != 2 || subs[0] != "t/0" || subs[1] != "t/1" {
		t.Fatalf("Subscriptions(a) = %v, want [t/0 t/1]", subs)
	}
	info, err := restored.Info("b")
	if err != nil || info.Connected {
		t.Fatalf("Info(b) = %+v, %v; want a disconnected session", info, err)
	}
	if !info.ExpiresAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("Info(b).ExpiresAt = %v, want %v", info.ExpiresAt, now.Add(time.Minute))
	}
	if wills := restored.DueWills(now.Add(30 * time.Second)); len(wills) != 0 {
		t.Fatalf("DueWills before the restored delay = %+v, want none", wills)
	}
	if wills := restored.DueWills(now.Add(46 * time.Second)); len(wills) != 1 || wills[0].Topic != "will/a" {
		t.Fatalf("DueWills after the restored delay = %+v, want will/a", wills)
	}
}

// Only one of many concurrent connects may create the session; every other
// one is a takeover that publishes the previous will.
func TestConcurrentTakeoverSingleWinner(t *testing.T) {
	cfg := taskpkg.Config{
		MaxQueued:     10,
		SessionExpiry: 5 * time.Minute,
		WillDelay:     0,
		MaxInflight:   5,
	}
	g := taskpkg.NewMqttSessionGuard(cfg)
	now := time.Unix(1700000000, 0)
	const workers = 20
	var mu sync.Mutex
	replaced, created := 0, 0
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			will := taskpkg.Will{Topic: "will/c", Payload: fmt.Sprintf("p%d", i), QoS: 1}
			takeover, err := g.Connect("c", false, will, now)
			if err != nil {
				errs <- err
				return
			}
			mu.Lock()
			if takeover.Replaced {
				replaced++
			} else {
				created++
			}
			mu.Unlock()
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent connect: %v", err)
	}
	if created != 1 || replaced != workers-1 {
		t.Fatalf("created=%d replaced=%d, want 1 and %d", created, replaced, workers-1)
	}
	if n := g.SessionCount(); n != 1 {
		t.Fatalf("SessionCount = %d after concurrent connects, want 1", n)
	}
	if wills := g.DueWills(now); len(wills) != workers-1 {
		t.Fatalf("DueWills = %d, want %d displaced wills", len(wills), workers-1)
	}
	if stats := g.Stats(); stats.Takeovers != uint64(workers-1) {
		t.Fatalf("Takeovers = %d, want %d", stats.Takeovers, workers-1)
	}
}
