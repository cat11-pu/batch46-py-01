import json
import threading

import pytest

import hsm_session_guard as hsm

T0 = "2026-11-23T09:00:00+00:00"
PIN = "a" * 64
PIN2 = "b" * 64
DIGEST = "c" * 64


def make(**kwargs):
    return hsm.HsmSessionGuard(**kwargs)


def logged(**kwargs):
    g = kwargs.pop("guard", None) or make(**kwargs)
    reply = g.login("pay", pin_digest=PIN, now=T0)
    return g, reply["session"]


def test_login_validates_pin_and_creates_deterministic_session():
    g = make()
    with pytest.raises(hsm.HsmError) as bad_pin:
        g.login("pay", pin_digest="xyz", now=T0)
    assert bad_pin.value.code == "HSM_PIN_INVALID"
    first = g.login("pay", pin_digest=PIN, now=T0)
    assert first["session"] == "pay-1"
    assert first["status"] == "created"
    reused = g.login("pay", pin_digest=PIN, now=T0)
    assert reused["session"] == "pay-1"
    assert reused["status"] == "reused"
    second = g.login("pay", pin_digest=PIN, slot="slot-1", now=T0)
    assert second["session"] == "pay-2"
    assert g.stats()["sessions"] == 2
    assert g.session_state("pay-2")["slot"] == "slot-1"


def test_wrong_pin_locks_the_app_and_success_resets_counter():
    g = make()
    assert g.login("pay", pin_digest=PIN, now=T0)["status"] == "created"
    for _ in range(2):
        with pytest.raises(hsm.HsmError) as wrong:
            g.login("pay", pin_digest=PIN2, now=T0)
        assert wrong.value.code == "HSM_AUTH_FAILED"
    reused = g.login("pay", pin_digest=PIN, now=T0)
    assert reused["session"] == "pay-1"
    assert reused["status"] == "reused"
    for _ in range(3):
        with pytest.raises(hsm.HsmError) as wrong:
            g.login("pay", pin_digest=PIN2, now=T0)
        assert wrong.value.code == "HSM_AUTH_FAILED"
    with pytest.raises(hsm.HsmError) as locked:
        g.login("pay", pin_digest=PIN, now=T0)
    assert locked.value.code == "HSM_PIN_LOCKED"
    unlocked = g.unlock_app("pay")
    assert unlocked["locked"] is False
    assert g.login("pay", pin_digest=PIN, now=T0)["session"] == "pay-1"


def test_session_cap_per_app_and_logout_frees_a_slot():
    g = make(max_sessions_per_app=2)
    assert g.login("pay", pin_digest=PIN, slot="slot-0", now=T0)["session"] == "pay-1"
    assert g.login("pay", pin_digest=PIN, slot="slot-1", now=T0)["session"] == "pay-2"
    with pytest.raises(hsm.HsmError) as limited:
        g.login("pay", pin_digest=PIN, slot="slot-2", now=T0)
    assert limited.value.code == "HSM_SESSION_LIMIT"
    g.logout("pay-1", now=T0)
    assert g.login("pay", pin_digest=PIN, slot="slot-2", now=T0)["session"] == "pay-3"


def test_logout_destroys_session_objects_but_keeps_token_objects():
    g, session = logged()
    keep = g.open_object(session, label="wrap-key", value_digest=DIGEST, kind="token")
    drop = g.open_object(session, label="nonce", value_digest=DIGEST, kind="session")
    out = g.logout(session, now=T0)
    assert out["destroyed"] == 1
    with pytest.raises(hsm.HsmError) as gone:
        g.use_object(session, drop["handle"], now=T0)
    assert gone.value.code == "HSM_SESSION_CLOSED"
    other = g.login("pay", pin_digest=PIN, slot="slot-1", now=T0)["session"]
    rows = g.find_objects(other, now=T0)
    assert [row["handle"] for row in rows] == [keep["handle"]]
    assert g.use_object(other, keep["handle"], now=T0)["uses"] == 1


def test_open_object_validates_arguments_and_global_cap():
    g, session = logged(guard=make(max_objects=2))
    with pytest.raises(hsm.HsmError) as kind:
        g.open_object(session, label="x", value_digest=DIGEST, kind="magic", now=T0)
    assert kind.value.code == "HSM_OBJECT_KIND_INVALID"
    with pytest.raises(hsm.HsmError) as label:
        g.open_object(session, label="", value_digest=DIGEST, now=T0)
    assert label.value.code == "HSM_LABEL_INVALID"
    with pytest.raises(hsm.HsmError) as digest:
        g.open_object(session, label="x", value_digest="zz", now=T0)
    assert digest.value.code == "HSM_DIGEST_INVALID"
    with pytest.raises(hsm.HsmError) as uses:
        g.open_object(session, label="x", value_digest=DIGEST, max_uses=0, now=T0)
    assert uses.value.code == "HSM_USE_LIMIT_INVALID"
    first = g.open_object(session, label="a", value_digest=DIGEST, now=T0)
    second = g.open_object(session, label="b", value_digest=DIGEST, now=T0)
    assert first["handle"] == 1000
    assert second["handle"] == 1001
    with pytest.raises(hsm.HsmError) as limit:
        g.open_object(session, label="c", value_digest=DIGEST, now=T0)
    assert limit.value.code == "HSM_OBJECT_LIMIT"
    g.destroy_object(session, first["handle"], now=T0)
    assert g.open_object(session, label="c", value_digest=DIGEST, now=T0)["handle"] == 1002


def test_handles_are_monotonic_and_never_reused_after_destroy():
    g, session = logged()
    handles = [g.open_object(session, label="k%d" % index,
                             value_digest=DIGEST, now=T0)["handle"]
               for index in range(3)]
    assert handles == [1000, 1001, 1002]
    g.destroy_object(session, handles[0], now=T0)
    assert g.open_object(session, label="later", value_digest=DIGEST, now=T0)["handle"] == 1003
    with pytest.raises(hsm.HsmError) as unknown:
        g.use_object(session, handles[0], now=T0)
    assert unknown.value.code == "HSM_HANDLE_UNKNOWN"
    with pytest.raises(hsm.HsmError) as twice:
        g.destroy_object(session, handles[0], now=T0)
    assert twice.value.code == "HSM_HANDLE_UNKNOWN"
    assert g.stats()["handles"] == 4


def test_session_object_handle_is_not_usable_from_another_session():
    g, first = logged()
    private = g.open_object(first, label="private", value_digest=DIGEST, kind="session")
    shared = g.open_object(first, label="shared", value_digest=DIGEST, kind="token")
    second = g.login("pay", pin_digest=PIN, slot="slot-1", now=T0)["session"]
    with pytest.raises(hsm.HsmError) as foreign:
        g.use_object(second, private["handle"], now=T0)
    assert foreign.value.code == "HSM_HANDLE_FOREIGN"
    assert g.use_object(second, shared["handle"], now=T0)["uses"] == 1


def test_use_object_enforces_max_uses_exactly():
    g, session = logged()
    handle = g.open_object(session, label="limited", value_digest=DIGEST,
                           max_uses=2, now=T0)["handle"]
    assert g.use_object(session, handle, now=T0)["uses"] == 1
    assert g.use_object(session, handle, now=T0)["uses"] == 2
    with pytest.raises(hsm.HsmError) as capped:
        g.use_object(session, handle, now=T0)
    assert capped.value.code == "HSM_USE_LIMIT"
    rows = g.find_objects(session, label="limited", now=T0)
    assert rows == [{"handle": handle, "label": "limited", "kind": "session", "uses": 2}]


def test_rotate_handles_remaps_visible_objects_and_stales_old_handles():
    g, session = logged()
    local = g.open_object(session, label="local", value_digest=DIGEST, kind="session")
    token = g.open_object(session, label="token", value_digest=DIGEST, kind="token")
    out = g.rotate_handles(session, now=T0)
    assert out["rotated"] == 2
    assert out["handles"] == [
        {"from": local["handle"], "to": 1002},
        {"from": token["handle"], "to": 1003},
    ]
    with pytest.raises(hsm.HsmError) as stale:
        g.use_object(session, local["handle"], now=T0)
    assert stale.value.code == "HSM_HANDLE_STALE"
    assert g.use_object(session, 1002, now=T0)["uses"] == 1
    assert [row["handle"] for row in g.find_objects(session, now=T0)] == [1002, 1003]
    again = g.rotate_handles(session, now=T0)
    assert again["handles"] == [{"from": 1002, "to": 1004}, {"from": 1003, "to": 1005}]
    with pytest.raises(hsm.HsmError) as older:
        g.use_object(session, 1002, now=T0)
    assert older.value.code == "HSM_HANDLE_STALE"


def test_idle_timeout_expires_session_and_sweep_counts_it():
    g = make(idle_timeout=600)
    session = g.login("pay", pin_digest=PIN, now=T0)["session"]
    assert g.heartbeat(session, now="2026-11-23T09:05:00+00:00")["status"] == "open"
    with pytest.raises(hsm.HsmError) as expired:
        g.heartbeat(session, now="2026-11-23T09:15:00+00:00")
    assert expired.value.code == "HSM_SESSION_EXPIRED"
    assert g.session_state(session)["status"] == "closed"
    other = g.login("pay", pin_digest=PIN, slot="slot-1", now="2026-11-23T09:15:00+00:00")
    report = g.sweep(now="2026-11-23T09:30:00+00:00")
    assert report["sessions"] == 1
    assert g.session_state(other["session"])["status"] == "closed"


def test_sweep_destroys_session_objects_but_keeps_tokens():
    g, session = logged()
    g.open_object(session, label="nonce", value_digest=DIGEST, kind="session")
    token = g.open_object(session, label="wrap", value_digest=DIGEST, kind="token")
    report = g.sweep(now="2026-11-23T09:16:00+00:00")
    assert report == {"sessions": 1, "objects": 1}
    with pytest.raises(hsm.HsmError) as closed:
        g.use_object(session, 1000, now="2026-11-23T09:16:00+00:00")
    assert closed.value.code == "HSM_SESSION_CLOSED"
    other = g.login("pay", pin_digest=PIN, slot="slot-1",
                    now="2026-11-23T09:16:00+00:00")["session"]
    assert [row["handle"] for row in g.find_objects(other, now="2026-11-23T09:16:00+00:00")] == [token["handle"]]


def test_snapshot_restore_preserves_next_handle_and_live_sessions():
    g, session = logged()
    first = g.open_object(session, label="a", value_digest=DIGEST, now=T0)
    second = g.open_object(session, label="b", value_digest=DIGEST, now=T0)
    snap = json.loads(json.dumps(g.snapshot()))
    g.restore(snap)
    assert g.session_state(session)["objects"] == 2
    assert g.use_object(session, first["handle"], now=T0)["uses"] == 1
    fresh = g.open_object(session, label="c", value_digest=DIGEST, now=T0)
    assert fresh["handle"] == 1002
    assert g.stats()["handles"] == 3
    with pytest.raises(hsm.HsmError) as invalid:
        g.restore({"version": 4})
    assert invalid.value.code == "HSM_SNAPSHOT_INVALID"
    assert second["handle"] == 1001


def test_stale_snapshot_cannot_roll_back_handle_counter():
    g, session = logged()
    g.open_object(session, label="a", value_digest=DIGEST, now=T0)
    g.open_object(session, label="b", value_digest=DIGEST, now=T0)
    snap = g.snapshot()
    g.open_object(session, label="c", value_digest=DIGEST, now=T0)
    with pytest.raises(hsm.HsmError) as stale:
        g.restore(snap)
    assert stale.value.code == "HSM_SNAPSHOT_STALE"
    assert g.open_object(session, label="d", value_digest=DIGEST, now=T0)["handle"] == 1003


def test_audit_is_newest_first_and_capped():
    g = make(audit_capacity=4)
    session = g.login("pay", pin_digest=PIN, now=T0)["session"]
    handle = g.open_object(session, label="k", value_digest=DIGEST, now=T0)["handle"]
    g.use_object(session, handle, now=T0)
    g.rotate_handles(session, now=T0)
    entries = g.audit(10)
    assert len(entries) == 4
    assert [row["action"] for row in entries] == [
        "object.rotate", "object.use", "object.open", "session.login",
    ]
    seqs = [row["seq"] for row in entries]
    assert seqs == sorted(seqs, reverse=True)
    assert entries[0]["session"] == session


def test_concurrent_use_object_never_exceeds_use_limit():
    g, session = logged()
    handle = g.open_object(session, label="hot", value_digest=DIGEST,
                           max_uses=10, now=T0)["handle"]
    barrier = threading.Barrier(24)
    allowed = []
    denied = []
    errors = []

    def worker():
        try:
            barrier.wait(timeout=10)
            allowed.append(g.use_object(session, handle, now=T0)["uses"])
        except hsm.HsmError as exc:
            denied.append(exc.code)
        except Exception as exc:  # pragma: no cover - defensive
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker) for _ in range(24)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=20)
    assert errors == []
    assert sorted(allowed) == list(range(1, 11))
    assert len(denied) == 14
    assert set(denied) == {"HSM_USE_LIMIT"}
    assert g.find_objects(session, label="hot", now=T0)[0]["uses"] == 10
