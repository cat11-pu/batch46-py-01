import json
import threading

import pytest

import mqtt_session_guard as mqtt


class Clock:
    def __init__(self, value=0.0):
        self.value = value

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += seconds


def make(clock=None, **kwargs):
    return mqtt.MqttSessionGuard(clock=clock or Clock(), **kwargs)


def will(topic="clients/1/status", payload=b"offline", delay=0.0, qos=1,
         retain=False):
    return {
        "topic": topic,
        "payload": payload,
        "delay": delay,
        "qos": qos,
        "retain": retain,
    }


def test_topic_filter_matching_handles_wildcards():
    guard = make()
    assert guard.match("sport/tennis/player1", "sport/+/player1") is True
    assert guard.match("sport/tennis/player1", "sport/#") is True
    assert guard.match("sport", "sport/#") is True
    assert guard.match("sport/tennis/player1", "#") is True
    assert guard.match("/finance", "+/+") is True
    assert guard.match("sport/tennis/player1", "sport/+") is False
    assert guard.match("sport", "sport/+") is False
    assert guard.match("sport/tennis", "sport") is False


def test_invalid_names_and_qos_are_rejected():
    guard = make()
    guard.connect("c1")
    with pytest.raises(mqtt.MqttSessionError) as exc:
        guard.subscribe("c1", "a/#/b", 0)
    assert exc.value.code == "MQTT_INVALID_FILTER"
    with pytest.raises(mqtt.MqttSessionError) as exc:
        guard.subscribe("c1", "", 0)
    assert exc.value.code == "MQTT_INVALID_FILTER"
    with pytest.raises(mqtt.MqttSessionError) as exc:
        guard.subscribe("c1", "a/+b", 0)
    assert exc.value.code == "MQTT_INVALID_FILTER"
    with pytest.raises(mqtt.MqttSessionError) as exc:
        guard.subscribe("c1", "a/b", 3)
    assert exc.value.code == "MQTT_INVALID_QOS"
    with pytest.raises(mqtt.MqttSessionError) as exc:
        guard.deliver("c1", "a/+", b"x")
    assert exc.value.code == "MQTT_INVALID_TOPIC"
    with pytest.raises(mqtt.MqttSessionError) as exc:
        guard.connect("")
    assert exc.value.code == "MQTT_INVALID_CLIENT"


def test_clean_start_discards_previous_session_state():
    guard = make()
    guard.connect("c1", clean_start=True)
    guard.subscribe("c1", "room/#", 1)
    out = guard.disconnect("c1", graceful=True)
    assert out["session_removed"] is True
    again = guard.connect("c1", clean_start=False)
    assert again["session_present"] is False
    assert again["replayed"] == []
    assert guard.session_state("c1")["subscriptions"] == {}
    assert guard.pending("c1")["queued"] == []


def test_persistent_reconnect_replays_queued_messages_in_order():
    guard = make()
    guard.connect("c1")
    guard.subscribe("c1", "room/#", 0)
    guard.disconnect("c1", graceful=True)
    for body in (b"m1", b"m2", b"m3"):
        queued = guard.deliver("c1", "room/a", body)
        assert queued["status"] == "queued"
    out = guard.connect("c1", clean_start=False)
    assert out["session_present"] is True
    assert [row["payload"] for row in out["replayed"]] == [b"m1", b"m2", b"m3"]
    assert guard.pending("c1")["queued"] == []
    assert guard.stats()["replayed"] == 3


def test_offline_queue_drops_oldest_beyond_limit():
    guard = make(max_offline=2)
    guard.connect("c1")
    guard.subscribe("c1", "room/#", 1)
    guard.disconnect("c1", graceful=False)
    for body in (b"p1", b"p2", b"p3"):
        guard.deliver("c1", "room/a", body, qos=1)
    row = guard.pending("c1")
    assert [msg["payload"] for msg in row["queued"]] == [b"p2", b"p3"]
    assert guard.stats()["offline_dropped"] == 1


def test_delivery_is_downgraded_to_subscription_qos():
    guard = make()
    guard.connect("c1")
    guard.subscribe("c1", "room/+", 1)
    guard.subscribe("c1", "room/a", 0)
    out = guard.deliver("c1", "room/a", b"payload", qos=2)
    assert out["status"] == "delivered"
    assert out["qos"] == 1
    assert out["packet_id"] == 1
    assert guard.pending("c1")["inflight"] == [1]


def test_acknowledge_rejects_unknown_packet_and_clears_known_one():
    guard = make()
    guard.connect("c1")
    guard.subscribe("c1", "room/#", 0)
    with pytest.raises(mqtt.MqttSessionError) as exc:
        guard.acknowledge("c1", 99)
    assert exc.value.code == "MQTT_PACKET_UNKNOWN"
    out = guard.deliver("c1", "room/a", b"x", qos=1)
    ack = guard.acknowledge("c1", out["packet_id"])
    assert ack["status"] == "acknowledged"
    assert guard.pending("c1")["inflight"] == []


def test_duplicate_qos2_pubrec_is_idempotent():
    guard = make()
    guard.connect("c1")
    guard.subscribe("c1", "room/#", 2)
    out = guard.deliver("c1", "room/a", b"x", qos=2)
    packet_id = out["packet_id"]
    first = guard.acknowledge("c1", packet_id, kind="pubrec")
    assert first["status"] == "acknowledged"
    duplicate = guard.acknowledge("c1", packet_id, kind="pubrec")
    assert duplicate["status"] == "duplicate"
    assert guard.stats()["duplicates"] == 1
    assert guard.pending("c1")["inflight"] == [packet_id]
    final = guard.acknowledge("c1", packet_id, kind="pubrel")
    assert final["status"] == "acknowledged"
    assert guard.pending("c1")["inflight"] == []


def test_packet_ids_reuse_the_lowest_free_number():
    guard = make(max_inflight=3)
    guard.connect("c1")
    guard.subscribe("c1", "room/#", 1)
    first = [guard.deliver("c1", "room/a", b"x", qos=1)["packet_id"]
             for _ in range(3)]
    assert first == [1, 2, 3]
    guard.acknowledge("c1", 2)
    assert guard.deliver("c1", "room/a", b"x", qos=1)["packet_id"] == 2
    guard.acknowledge("c1", 1)
    guard.acknowledge("c1", 3)
    assert guard.deliver("c1", "room/a", b"x", qos=1)["packet_id"] == 1


def test_graceful_disconnect_suppresses_will_and_ungraceful_publishes():
    guard = make()
    guard.connect("c1", will=will())
    graceful = guard.disconnect("c1", graceful=True)
    assert graceful["will"] == "suppressed"
    assert guard.wills() == []
    assert guard.stats()["wills_published"] == 0

    guard.connect("c1", will=will())
    abrupt = guard.disconnect("c1", graceful=False)
    assert abrupt["will"] == "published"
    published = guard.wills()
    assert len(published) == 1
    assert published[0]["topic"] == "clients/1/status"
    assert published[0]["payload"] == b"offline"
    assert guard.stats()["wills_published"] == 1
    assert guard.will_for("c1") is None


def test_delayed_will_is_cancelled_on_reconnect_and_purge_handles_due():
    clock = Clock()
    guard = make(clock=clock)
    guard.connect("a", will=will(topic="a/status", delay=10))
    guard.disconnect("a", graceful=False)
    assert guard.stats()["wills_scheduled"] == 1
    assert guard.will_for("a")["topic"] == "a/status"
    clock.advance(5)
    guard.connect("a", clean_start=False)
    assert guard.stats()["wills_cancelled"] == 1
    assert guard.will_for("a") is None

    guard.connect("b", will=will(topic="b/status", delay=10))
    guard.disconnect("b", graceful=False)
    clock.advance(5)
    report = guard.purge()
    assert report["wills"] == 1
    assert [row["topic"] for row in guard.wills()] == ["b/status"]

    guard.subscribe("b", "jobs/#", 0)
    guard.deliver("b", "jobs/1", b"job", expire_at=20)
    clock.advance(11)
    report = guard.purge()
    assert report["expired"] == 1
    assert guard.pending("b")["queued"] == []
    assert guard.stats()["expired"] == 1


def test_keepalive_timeout_publishes_will_and_closes_connection():
    clock = Clock()
    guard = make(clock=clock)
    guard.connect("c1", will=will(), keepalive=10)
    alive = guard.keepalive_check("c1", now=14)
    assert alive["alive"] is True
    dead = guard.keepalive_check("c1", now=30)
    assert dead["alive"] is False
    assert dead["action"] == "will_published"
    assert guard.stats()["wills_published"] == 1
    assert [row["payload"] for row in guard.wills()] == [b"offline"]
    assert guard.session_state("c1")["connected"] is False


def test_takeover_publishes_old_will_and_resumes_subscriptions():
    guard = make()
    guard.connect("c1", will=will(topic="c1/status", payload=b"bye"))
    guard.subscribe("c1", "room/#", 1)
    out = guard.connect("c1", clean_start=False)
    assert out["session_present"] is True
    assert guard.stats()["takeovers"] == 1
    assert guard.stats()["wills_published"] == 1
    assert [row["payload"] for row in guard.wills()] == [b"bye"]
    assert guard.session_state("c1")["subscriptions"] == {"room/#": 1}
    assert guard.will_for("c1") is None


def test_snapshot_restore_keeps_queues_inflight_and_rejects_bad_version():
    guard = make()
    guard.connect("c1")
    guard.subscribe("c1", "room/#", 1)
    guard.deliver("c1", "room/a", b"one", qos=1)
    guard.disconnect("c1", graceful=True)
    guard.deliver("c1", "room/b", b"two", qos=0)
    snap = guard.snapshot()
    assert snap["version"] == mqtt.MqttSessionGuard.SNAPSHOT_VERSION
    json.dumps(snap)

    restored = make()
    restored.restore(snap)
    assert restored.session_state("c1")["subscriptions"] == {"room/#": 1}
    assert restored.pending("c1")["inflight"] == [1]
    assert [row["payload"] for row in restored.pending("c1")["queued"]] == [b"two"]
    replayed = restored.connect("c1", clean_start=False)
    assert replayed["session_present"] is True
    assert [row["payload"] for row in replayed["replayed"]] == [b"two"]

    bad = dict(snap)
    bad["version"] = snap["version"] + 1
    with pytest.raises(mqtt.MqttSessionError) as exc:
        restored.restore(bad)
    assert exc.value.code == "MQTT_SNAPSHOT_VERSION"
    assert restored.session_state("c1")["connected"] is True


def test_concurrent_offline_deliveries_are_all_queued():
    guard = make(max_offline=50)
    guard.connect("c1")
    guard.subscribe("c1", "bench/#", 0)
    guard.disconnect("c1", graceful=True)
    payloads = [("m%02d" % index).encode() for index in range(20)]
    errors = []
    lock = threading.Lock()
    barrier = threading.Barrier(20)

    def worker(body):
        barrier.wait()
        try:
            guard.deliver("c1", "bench/x", body)
        except Exception as exc:  # pragma: no cover - surfaced through errors
            with lock:
                errors.append(exc)

    threads = [threading.Thread(target=worker, args=(body,)) for body in payloads]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    queued = [row["payload"] for row in guard.pending("c1")["queued"]]
    assert len(queued) == 20
    assert set(queued) == set(payloads)
    assert guard.stats()["offline_dropped"] == 0
