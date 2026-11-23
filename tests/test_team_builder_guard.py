import threading

import pytest

import team_builder_guard as tbg


def make(**kwargs):
    return tbg.TeamBuilder(**kwargs)


def test_join_beyond_capacity_raises_team_full():
    b = make(capacity=3)
    b.create_team("t1", "lead")
    b.join("t1", "a", role="dps")
    b.join("t1", "b", role="dps")
    with pytest.raises(tbg.TeamError) as exc:
        b.join("t1", "c", role="dps")
    assert exc.value.code == "TEAM_FULL"
    assert b.stats("t1")["member_count"] == 3


def test_duplicate_join_is_ignored_without_state_change():
    b = make()
    b.create_team("t1", "lead")
    first = b.join("t1", "a", role="dps", event_id="e1")
    second = b.join("t1", "a", role="tank", event_id="e2")
    assert first["status"] == "applied"
    assert second["status"] == "ignored"
    assert second["code"] == "TEAM_DUP_MEMBER"
    assert [m["member"] for m in b.members("t1")] == ["lead", "a"]
    assert b.members("t1")[1]["role"] == "dps"
    assert len(b.audit("t1")) == 1


def test_role_limit_rule_is_reported_by_validate():
    b = make()
    b.define_rule("heal-cap", kind="role_limit", value="healer", limit=1)
    b.create_team("t1", "lead")
    b.join("t1", "a", role="healer", power=100)
    b.join("t1", "b", role="healer", power=120)
    out = b.validate("t1")
    assert out["ok"] is False
    assert [v["rule"] for v in out["violations"]] == ["heal-cap"]
    assert out["violations"][0]["code"] == "TEAM_ROLE_LIMIT"
    assert out["violations"][0]["members"] == ["a", "b"]


def test_relic_unique_rule_rejects_second_holder():
    b = make()
    b.define_rule("relic-uniq", kind="relic_unique")
    b.create_team("t1", "lead")
    b.join("t1", "a", role="dps", relic="sword")
    with pytest.raises(tbg.TeamError) as exc:
        b.join("t1", "b", role="dps", relic="sword")
    assert exc.value.code == "TEAM_DUP_RELIC"
    assert [m["member"] for m in b.members("t1")] == ["lead", "a"]


def test_power_cap_rejects_join_and_keeps_total():
    b = make(power_cap=100)
    b.create_team("t1", "lead")
    b.join("t1", "a", role="dps", power=60)
    with pytest.raises(tbg.TeamError) as exc:
        b.join("t1", "b", role="dps", power=60)
    assert exc.value.code == "TEAM_POWER_CAP"
    assert b.stats("t1")["total_power"] == 60


def test_power_min_rule_is_reported_by_validate():
    b = make()
    b.define_rule("min-power", kind="power_min", value=50)
    b.create_team("t1", "lead")
    b.join("t1", "a", role="dps", power=10)
    b.join("t1", "b", role="dps", power=80)
    out = b.validate("t1")
    assert out["ok"] is False
    assert [v["member"] for v in out["violations"]] == ["a"]
    assert out["violations"][0]["code"] == "TEAM_POWER_MIN"


def test_cross_server_join_requires_allow_rule():
    b = make()
    b.create_team("t1", "lead", server="s1")
    with pytest.raises(tbg.TeamError) as exc:
        b.join("t1", "x", role="dps", server="s2")
    assert exc.value.code == "TEAM_CROSS_SERVER"
    b.define_rule("xserver", kind="cross_server", value="allow")
    out = b.join("t1", "x", role="dps", server="s2")
    assert out["status"] == "applied"
    assert b.members("t1")[-1]["server"] == "s2"


def test_snapshot_restore_reverts_membership_and_stats():
    b = make()
    b.create_team("t1", "lead")
    b.join("t1", "a", role="dps", power=10)
    b.join("t1", "b", role="tank", power=20)
    snap = b.snapshot("t1")
    b.join("t1", "c", role="dps", power=30)
    assert b.stats("t1")["member_count"] == 4
    out = b.restore("t1", snap)
    assert out["status"] == "restored"
    assert [m["member"] for m in b.members("t1")] == ["lead", "a", "b"]
    assert b.stats("t1")["total_power"] == 30


def test_restore_rejects_stale_snapshot():
    b = make()
    b.create_team("t1", "lead")
    b.join("t1", "a", role="dps")
    snap = b.snapshot("t1")
    b.join("t1", "b", role="dps")
    b.join("t1", "c", role="dps")
    with pytest.raises(tbg.TeamError) as exc:
        b.restore("t1", snap)
    assert exc.value.code == "TEAM_SNAPSHOT_STALE"
    assert b.stats("t1")["member_count"] == 4


def test_audit_log_is_bounded_and_newest_first():
    b = make(audit_limit=3)
    b.create_team("t1", "lead")
    for name in ["a", "b", "c", "d"]:
        b.join("t1", name, role="dps")
    log = b.audit("t1")
    assert len(log) == 3
    assert [row["member"] for row in log] == ["d", "c", "b"]
    assert all(row["action"] == "join" for row in log)
    assert [row["member"] for row in b.audit("t1", limit=2)] == ["d", "c"]


def test_concurrent_joins_never_exceed_capacity():
    b = make(capacity=3)
    b.create_team("t1", "lead")
    barrier = threading.Barrier(8)
    results = []
    lock = threading.Lock()

    def worker(name):
        barrier.wait()
        try:
            out = b.join("t1", name, role="dps")
            outcome = ("ok", out["status"])
        except tbg.TeamError as exc:
            outcome = ("error", exc.code)
        except Exception as exc:  # unexpected failures must fail the test
            outcome = ("unexpected", type(exc).__name__)
        with lock:
            results.append(outcome)

    threads = [threading.Thread(target=worker, args=("m%d" % i,))
               for i in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    ok = [row for row in results if row[0] == "ok"]
    full = [row for row in results if row == ("error", "TEAM_FULL")]
    assert len(ok) == 2
    assert len(full) == 6
    assert b.stats("t1")["member_count"] == 3
    assert len({m["member"] for m in b.members("t1")}) == 3


def test_stats_counts_roles_and_total_power():
    b = make()
    b.create_team("t1", "lead")
    b.join("t1", "a", role="tank", power=100)
    b.join("t1", "b", role="dps", power=200)
    b.join("t1", "c", role="dps", power=300)
    stats = b.stats("t1")
    assert stats["member_count"] == 4
    assert stats["total_power"] == 600
    assert stats["roles"] == {"leader": 1, "tank": 1, "dps": 2}


def test_change_role_enforces_role_limit():
    b = make()
    b.define_rule("heal-cap", kind="role_limit", value="healer", limit=1)
    b.create_team("t1", "lead")
    b.join("t1", "a", role="healer", power=100)
    b.join("t1", "b", role="dps", power=100)
    with pytest.raises(tbg.TeamError) as exc:
        b.change_role("t1", "b", "healer")
    assert exc.value.code == "TEAM_ROLE_LIMIT"
    out = b.change_role("t1", "b", "tank")
    assert out["status"] == "applied"
    assert b.members("t1")[2]["role"] == "tank"


def test_matchmaking_ticket_is_an_immutable_snapshot():
    b = make()
    b.create_team("t1", "lead")
    b.join("t1", "a", role="dps", power=100)
    ticket = b.matchmaking_ticket("t1")
    assert ticket["member_count"] == 2
    assert ticket["total_power"] == 100
    version = ticket["version"]
    b.join("t1", "b", role="dps", power=50)
    assert ticket["member_count"] == 2
    assert ticket["version"] == version
    ticket["roles"]["dps"] = 99
    assert b.stats("t1")["roles"]["dps"] == 2
    assert b.matchmaking_ticket("t1")["member_count"] == 3


def test_leave_promotes_earliest_member_and_rejects_unknown():
    b = make()
    b.create_team("t1", "lead")
    b.join("t1", "a", role="dps")
    b.join("t1", "b", role="tank")
    out = b.leave("t1", "lead")
    assert out["status"] == "applied"
    assert b.stats("t1")["owner"] == "a"
    assert [m["member"] for m in b.members("t1")] == ["a", "b"]
    with pytest.raises(tbg.TeamError) as exc:
        b.leave("t1", "ghost")
    assert exc.value.code == "TEAM_NOT_MEMBER"
    assert b.audit("t1")[0]["action"] == "leave"
