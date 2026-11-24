import threading

import pytest

import fanotify_permission_guard as fpg


def make(**kwargs):
    return fpg.FanotifyGuard(**kwargs)


def test_marks_add_merge_and_remove():
    guard = make()
    out = guard.add_mark("/data", ("open_perm", "access_perm"))
    assert out["status"] == "added"
    assert out["mask"] == ["access_perm", "open_perm"]
    assert guard.status()["marks"] == 1
    same = guard.add_mark("/data", ("open_perm", "access_perm"))
    assert same["status"] == "unchanged"
    merged = guard.add_mark("/data", ("exec_perm",))
    assert merged["status"] == "updated"
    assert merged["mask"] == ["access_perm", "exec_perm", "open_perm"]
    removed = guard.remove_mark("/data")
    assert removed["status"] == "removed"
    assert guard.status()["marks"] == 0
    with pytest.raises(fpg.FanotifyError) as exc:
        guard.remove_mark("/data")
    assert exc.value.code == "FAN_MARK_UNKNOWN"


def test_invalid_path_mask_and_mark_cap():
    guard = make()
    with pytest.raises(fpg.FanotifyError) as exc:
        guard.add_mark("relative/path", ("open_perm",))
    assert exc.value.code == "FAN_PATH_INVALID"
    with pytest.raises(fpg.FanotifyError) as exc:
        guard.add_mark("/ok", ("bogus_perm",))
    assert exc.value.code == "FAN_MASK_INVALID"
    with pytest.raises(fpg.FanotifyError) as exc:
        guard.add_mark("/ok", ())
    assert exc.value.code == "FAN_MASK_INVALID"
    limited = make(max_marks=1)
    limited.add_mark("/one", ("open_perm",))
    with pytest.raises(fpg.FanotifyError) as exc:
        limited.add_mark("/two", ("open_perm",))
    assert exc.value.code == "FAN_LIMIT"
    assert limited.status()["marks"] == 1


def test_event_on_unmarked_path_is_ignored():
    guard = make()
    out = guard.submit_event("e1", "/var/lib/x", "open_perm")
    assert out["status"] == "ignored"
    assert out["code"] == "FAN_NO_MARK"
    assert guard.pending() == []
    assert guard.metrics()["ignored"] == 1


def test_event_on_marked_path_enters_pending_with_deadline():
    guard = make()
    guard.add_mark("/data", ("open_perm", "access_perm"))
    out = guard.submit_event("e1", "/data/a", "open_perm")
    assert out["status"] == "pending"
    assert out["deadline"] == 5
    assert out["seq"] == 1
    assert out["queue"] == 1
    rows = guard.pending()
    assert [row["event_id"] for row in rows] == ["e1"]
    assert rows[0]["mask"] == "open_perm"
    skipped = guard.submit_event("e2", "/data/b", "exec_perm")
    assert skipped["status"] == "ignored"
    assert skipped["code"] == "FAN_MASK_UNWATCHED"
    assert guard.status()["pending"] == 1


def test_decide_is_idempotent_and_first_decision_wins():
    guard = make()
    guard.add_mark("/data", ("open_perm",))
    guard.submit_event("e1", "/data/a", "open_perm")
    first = guard.decide("e1", "allow", reason="signed")
    assert first["status"] == "decided"
    assert first["decision"] == "allow"
    assert guard.status()["pending"] == 0
    second = guard.decide("e1", "deny")
    assert second["status"] == "duplicate"
    assert second["code"] == "FAN_DECISION_DUP"
    assert second["decision"] == "allow"
    metrics = guard.metrics()
    assert metrics["allowed"] == 1
    assert metrics["denied"] == 0


def test_decision_errors_do_not_consume_the_event():
    guard = make()
    guard.add_mark("/data", ("open_perm",))
    guard.submit_event("e1", "/data/a", "open_perm", pid=55)
    with pytest.raises(fpg.FanotifyError) as exc:
        guard.decide("e1", "allow", pid=99)
    assert exc.value.code == "FAN_PID_MISMATCH"
    assert guard.status()["pending"] == 1
    with pytest.raises(fpg.FanotifyError) as exc:
        guard.decide("e1", "maybe")
    assert exc.value.code == "FAN_DECISION_INVALID"
    with pytest.raises(fpg.FanotifyError) as exc:
        guard.decide("ghost", "allow")
    assert exc.value.code == "FAN_EVENT_UNKNOWN"
    out = guard.decide("e1", "allow", pid=55)
    assert out["status"] == "decided"


def test_full_queue_denies_new_event_without_enqueueing():
    guard = make(max_pending=1)
    guard.add_mark("/data", ("open_perm",))
    guard.submit_event("first", "/data/a", "open_perm")
    out = guard.submit_event("second", "/data/b", "open_perm")
    assert out["status"] == "denied"
    assert out["decision"] == "deny"
    assert out["code"] == "FAN_QUEUE_FULL"
    assert [row["event_id"] for row in guard.pending()] == ["first"]
    assert guard.metrics()["queue_full"] == 1
    late = guard.decide("second", "deny")
    assert late["status"] == "duplicate"
    assert late["decision"] == "deny"


def test_expire_denies_in_deadline_order_and_late_decide_is_rejected():
    guard = make(max_pending=5)
    guard.add_mark("/data", ("open_perm",))
    guard.submit_event("slow", "/data/s", "open_perm", timeout=10)
    guard.submit_event("fast", "/data/f", "open_perm", timeout=2)
    guard.submit_event("mid", "/data/m", "open_perm", timeout=5)
    results = guard.expire(6)
    assert [row["event_id"] for row in results] == ["fast", "mid"]
    assert all(row["code"] == "FAN_TIMEOUT" for row in results)
    assert all(row["decision"] == "deny" for row in results)
    assert [row["event_id"] for row in guard.pending()] == ["slow"]
    assert guard.metrics()["expired"] == 2
    late = guard.decide("fast", "allow", now=6)
    assert late["status"] == "expired"
    assert late["code"] == "FAN_EVENT_EXPIRED"
    assert guard.expire(6) == []


def test_cookie_coalesces_duplicate_kernel_resend():
    guard = make()
    guard.add_mark("/data", ("open_perm",))
    first = guard.submit_event("e1", "/data/a", "open_perm", cookie="ck-1")
    assert first["status"] == "pending"
    again = guard.submit_event("e2", "/data/a", "open_perm", cookie="ck-1")
    assert again["status"] == "coalesced"
    assert again["code"] == "FAN_COOKIE_COALESCED"
    assert again["event_id"] == "e1"
    assert guard.status()["pending"] == 1
    assert guard.metrics()["coalesced"] == 1
    other = guard.submit_event("e3", "/data/b", "open_perm", cookie="ck-2")
    assert other["status"] == "pending"
    guard.decide("e1", "allow")
    after = guard.submit_event("e4", "/data/c", "open_perm", cookie="ck-1")
    assert after["status"] == "pending"


def test_snapshot_keeps_pending_events_and_cookie_index_after_restart():
    guard = make()
    guard.add_mark("/data", ("open_perm",))
    guard.submit_event("e1", "/data/a", "open_perm", cookie="ck-1")
    snap = guard.snapshot()
    guard.remove_mark("/data")
    assert "/data" in snap["marks"]
    assert guard.status()["marks"] == 0
    guard.restore(snap)
    coalesced = guard.submit_event("e2", "/data/b", "open_perm",
                                   cookie="ck-1")
    assert coalesced["status"] == "coalesced"
    assert coalesced["event_id"] == "e1"
    guard.submit_event("e3", "/data/c", "open_perm")
    assert len(guard.pending()) == 2
    guard.restore(snap)
    assert [row["event_id"] for row in guard.pending()] == ["e1"]
    assert guard.metrics()["submitted"] == 1
    assert guard.status()["decided"] == 0


def test_allowlisted_paths_are_allowed_without_queueing():
    guard = make()
    out = guard.allowlist_add("/cache")
    assert out["status"] == "added"
    assert guard.allowlist_add("/cache")["status"] == "unchanged"
    allowed = guard.submit_event("e1", "/cache/blob", "open_perm")
    assert allowed["status"] == "allowed"
    assert allowed["decision"] == "allow"
    assert allowed["code"] == "FAN_ALLOWLISTED"
    assert guard.status()["pending"] == 0
    assert guard.metrics()["suppressed"] == 1
    assert guard.metrics()["allowed"] == 1
    removed = guard.allowlist_remove("/cache")
    assert removed["status"] == "removed"
    with pytest.raises(fpg.FanotifyError) as exc:
        guard.allowlist_remove("/cache")
    assert exc.value.code == "FAN_ALLOWLIST_UNKNOWN"
    ignored = guard.submit_event("e2", "/cache/blob", "open_perm")
    assert ignored["code"] == "FAN_NO_MARK"


def test_longest_mark_wins_and_removal_falls_back_to_parent():
    guard = make()
    guard.add_mark("/data", ("open_perm",))
    guard.add_mark("/data/secure", ("access_perm",))
    out = guard.submit_event("e1", "/data/secure/f", "access_perm")
    assert out["status"] == "pending"
    blocked = guard.submit_event("e2", "/data/secure/f", "open_perm")
    assert blocked["code"] == "FAN_MASK_UNWATCHED"
    parent = guard.submit_event("e3", "/data/other/f", "open_perm")
    assert parent["status"] == "pending"
    guard.remove_mark("/data/secure")
    denied = guard.submit_event("e4", "/data/secure/f", "access_perm")
    assert denied["code"] == "FAN_MASK_UNWATCHED"
    fallback = guard.submit_event("e5", "/data/secure/f", "open_perm")
    assert fallback["status"] == "pending"


def test_duplicate_event_id_is_ignored():
    guard = make()
    guard.add_mark("/data", ("open_perm",))
    guard.submit_event("e1", "/data/a", "open_perm")
    out = guard.submit_event("e1", "/data/a", "open_perm")
    assert out["status"] == "ignored"
    assert out["code"] == "FAN_EVENT_DUP"
    assert guard.status()["pending"] == 1
    assert guard.metrics()["submitted"] == 2
    assert guard.metrics()["ignored"] == 1


def test_close_blocks_new_work_and_restore_reopens_the_group():
    guard = make()
    guard.add_mark("/data", ("open_perm",))
    snap = guard.snapshot()
    assert guard.close()["status"] == "closed"
    assert guard.status()["closed"] is True
    with pytest.raises(fpg.FanotifyError) as exc:
        guard.submit_event("e1", "/data/a", "open_perm")
    assert exc.value.code == "FAN_CLOSED"
    with pytest.raises(fpg.FanotifyError) as exc:
        guard.decide("ghost", "allow")
    assert exc.value.code == "FAN_CLOSED"
    guard.restore(snap)
    assert guard.status()["closed"] is False
    assert guard.submit_event("e2", "/data/a", "open_perm")["status"] == "pending"


def test_concurrent_decide_has_one_winner_and_one_counted_decision():
    guard = make()
    guard.add_mark("/data", ("open_perm",))
    guard.submit_event("e1", "/data/a", "open_perm")
    barrier = threading.Barrier(6)
    results = []
    lock = threading.Lock()

    def worker():
        barrier.wait()
        out = guard.decide("e1", "allow")
        with lock:
            results.append(out["status"])

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert results.count("decided") == 1
    assert results.count("duplicate") == 5
    assert guard.metrics()["allowed"] == 1
    assert guard.metrics()["denied"] == 0
    assert guard.status()["pending"] == 0
