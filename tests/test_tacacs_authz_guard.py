import threading

import pytest

import tacacs_authz_guard as tg


def ops_guard(**kwargs):
    g = tg.TacacsGuard(**kwargs)
    g.define_command_set("ops", rules=[{"pattern": "show *", "action": "permit"}])
    g.register_user("netops", privilege=5, groups=["ops"])
    return g


def test_wildcard_rule_permits_and_unmatched_command_uses_default_deny():
    g = ops_guard()
    ok = g.authorize("netops", "show version")
    assert ok["status"] == "permit"
    assert ok["code"] == "TAC_PERMIT"
    assert ok["rule"] == 0
    assert ok["command_set"] == "ops"
    denied = g.authorize("netops", "configure terminal")
    assert denied["status"] == "deny"
    assert denied["code"] == "TAC_DENY_DEFAULT"
    assert denied["rule"] is None


def test_deny_rule_before_wildcard_permit_wins_on_first_match():
    g = tg.TacacsGuard()
    g.define_command_set(
        "ops",
        rules=[
            {"pattern": "show running-config", "action": "deny"},
            {"pattern": "show *", "action": "permit"},
        ],
    )
    g.register_user("u", groups=["ops"])
    denied = g.authorize("u", "show running-config")
    assert denied["status"] == "deny"
    assert denied["code"] == "TAC_DENY_RULE"
    assert denied["rule"] == 0
    allowed = g.authorize("u", "show ip route")
    assert allowed["status"] == "permit"
    assert allowed["code"] == "TAC_PERMIT"
    assert allowed["rule"] == 1


def test_rule_above_user_privilege_is_skipped_not_rejected():
    g = tg.TacacsGuard()
    g.define_command_set(
        "ops",
        rules=[{"pattern": "reload", "action": "permit", "min_privilege": 15}],
    )
    g.register_user("junior", privilege=7, groups=["ops"])
    denied = g.authorize("junior", "reload")
    assert denied["status"] == "deny"
    assert denied["code"] == "TAC_DENY_DEFAULT"
    assert denied["rule"] is None
    updated = g.set_privilege("junior", 15)
    assert updated["privilege"] == 15
    allowed = g.authorize("junior", "reload")
    assert allowed["status"] == "permit"
    assert allowed["rule"] == 0


def test_group_rules_concatenate_in_listed_order():
    g = tg.TacacsGuard()
    g.define_command_set("base", rules=[{"pattern": "show *", "action": "permit"}])
    g.define_command_set("locked", rules=[{"pattern": "show clock", "action": "deny"}])
    g.register_user("first", groups=["base", "locked"])
    g.register_user("second", groups=["locked", "base"])
    assert g.authorize("first", "show clock")["status"] == "permit"
    second = g.authorize("second", "show clock")
    assert second["status"] == "deny"
    assert second["rule"] == 0


def test_unknown_user_raises_deny_unknown_user():
    g = ops_guard()
    with pytest.raises(tg.TacacsError) as exc:
        g.authorize("ghost", "show version")
    assert exc.value.code == "TAC_DENY_UNKNOWN_USER"


def test_duplicate_session_start_is_rejected_without_overwriting():
    g = ops_guard()
    started = g.account_start("netops", "s-1", device="r1", started_at=1000)
    assert started["status"] == "open"
    assert started["started_at"] == 1000
    with pytest.raises(tg.TacacsError) as exc:
        g.account_start("netops", "s-1", device="r2", started_at=1001)
    assert exc.value.code == "TAC_DUP_SESSION"
    rows = g.sessions()
    assert len(rows) == 1
    assert rows[0]["device"] == "r1"


def test_stop_computes_elapsed_and_unknown_session_is_rejected():
    g = ops_guard()
    g.account_start("netops", "s-1", device="r1", started_at=1000)
    closed = g.account_stop("s-1", stopped_at=1015)
    assert closed["status"] == "closed"
    assert closed["elapsed"] == 15
    assert closed["reason"] == "normal"
    with pytest.raises(tg.TacacsError) as exc:
        g.account_stop("s-404", stopped_at=1020)
    assert exc.value.code == "TAC_NO_SESSION"


def test_counters_are_monotonic_and_closed_sessions_are_frozen():
    g = ops_guard()
    g.account_start("netops", "s-1", device="r1", started_at=1000)
    first = g.account_update("s-1", bytes_in=100, bytes_out=50)
    assert first["bytes_in"] == 100
    assert first["bytes_out"] == 50
    with pytest.raises(tg.TacacsError) as exc:
        g.account_update("s-1", bytes_in=90)
    assert exc.value.code == "TAC_COUNTER_REGRESS"
    assert g.sessions()[0]["bytes_in"] == 100
    second = g.account_update("s-1", bytes_out=80)
    assert second["bytes_out"] == 80
    g.account_stop("s-1", stopped_at=1100)
    with pytest.raises(tg.TacacsError) as exc:
        g.account_update("s-1", bytes_in=200)
    assert exc.value.code == "TAC_SESSION_CLOSED"


def test_session_limit_rejects_new_sessions_until_a_slot_frees():
    g = ops_guard(max_sessions=2)
    g.account_start("netops", "a", device="r1", started_at=1000)
    g.account_start("netops", "b", device="r2", started_at=1000)
    with pytest.raises(tg.TacacsError) as exc:
        g.account_start("netops", "c", device="r3", started_at=1000)
    assert exc.value.code == "TAC_SESSION_LIMIT"
    g.account_stop("a", stopped_at=1005)
    opened = g.account_start("netops", "c", device="r3", started_at=1006)
    assert opened["status"] == "open"


def test_sessions_are_sorted_and_filtered_by_username():
    g = ops_guard()
    g.register_user("viewer", privilege=1, groups=["ops"])
    g.account_start("viewer", "s-2", device="r2", started_at=1000)
    g.account_start("netops", "s-1", device="r1", started_at=1000)
    g.account_start("viewer", "s-3", device="r3", started_at=1000)
    g.account_stop("s-1", stopped_at=1002)
    rows = g.sessions()
    assert [row["session_id"] for row in rows] == ["s-1", "s-2", "s-3"]
    closed = [row for row in rows if row["session_id"] == "s-1"][0]
    assert closed["status"] == "closed"
    viewer_rows = g.sessions("viewer")
    assert [row["session_id"] for row in viewer_rows] == ["s-2", "s-3"]
    assert all(row["user"] == "viewer" for row in viewer_rows)


def test_snapshot_is_deep_and_restore_replaces_everything():
    g = ops_guard()
    g.account_start("netops", "s-1", device="r1", started_at=1000)
    g.authorize("netops", "show version")
    snap = g.snapshot()
    g.account_stop("s-1", stopped_at=1100)
    g.register_user("late", groups=["ops"])
    g.define_command_set("ops", rules=[])
    target = tg.TacacsGuard()
    target.register_user("stale")
    target.restore(snap)
    rows = target.sessions()
    assert [row["session_id"] for row in rows] == ["s-1"]
    assert rows[0]["status"] == "open"
    assert target.authorize("netops", "show version")["status"] == "permit"
    with pytest.raises(tg.TacacsError) as exc:
        target.authorize("late", "show version")
    assert exc.value.code == "TAC_DENY_UNKNOWN_USER"
    with pytest.raises(tg.TacacsError) as exc:
        target.authorize("stale", "show version")
    assert exc.value.code == "TAC_DENY_UNKNOWN_USER"
    replay = tg.TacacsGuard()
    replay.restore(snap)
    assert replay.sessions()[0]["status"] == "open"


def test_redefining_command_set_invalidates_previous_decisions():
    g = ops_guard()
    assert g.authorize("netops", "show version")["status"] == "permit"
    g.define_command_set("ops", rules=[{"pattern": "show *", "action": "deny"}])
    after = g.authorize("netops", "show version")
    assert after["status"] == "deny"
    assert after["code"] == "TAC_DENY_RULE"
    assert after["rule"] == 0


def test_audit_keeps_only_latest_entries_in_chronological_order():
    g = tg.TacacsGuard(max_audit=3)
    g.define_command_set("ops", rules=[{"pattern": "show *", "action": "permit"}])
    g.register_user("u", groups=["ops"])
    for command in ("show a", "show b", "show c", "show d", "show e"):
        g.authorize("u", command)
    log = g.audit()
    assert [row["command"] for row in log] == ["show c", "show d", "show e"]
    assert all(row["code"] == "TAC_PERMIT" for row in log)
    assert [row["command"] for row in g.audit(limit=1)] == ["show e"]
    assert [row["command"] for row in g.audit(limit=2)] == ["show d", "show e"]


def test_concurrent_authorization_is_consistent():
    g = tg.TacacsGuard(max_audit=10000)
    g.define_command_set("ops", rules=[{"pattern": "show *", "action": "permit"}])
    g.register_user("u", privilege=5, groups=["ops"])
    results = []
    errors = []
    lock = threading.Lock()

    def worker():
        local = []
        try:
            for _ in range(200):
                local.append(g.authorize("u", "show version"))
        except Exception as exc:  # pragma: no cover - only on failure
            with lock:
                errors.append(exc)
            return
        with lock:
            results.extend(local)

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    assert len(results) == 1200
    assert all(row["status"] == "permit" for row in results)
    assert len(g.audit(limit=2000)) == 1200


def test_concurrent_session_id_is_claimed_exactly_once():
    g = tg.TacacsGuard(max_sessions=16)
    g.register_user("u")
    outcomes = []
    lock = threading.Lock()

    def claim():
        try:
            g.account_start("u", "shared", device="r9", started_at=1000)
        except tg.TacacsError as exc:
            with lock:
                outcomes.append(exc.code)
        else:
            with lock:
                outcomes.append("ok")

    threads = [threading.Thread(target=claim) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert outcomes.count("ok") == 1
    assert outcomes.count("TAC_DUP_SESSION") == 7
    assert len(g.sessions()) == 1
