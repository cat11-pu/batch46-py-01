import threading

import pytest

import tournament_bracket_guard as tbg


def make(**kwargs):
    return tbg.BracketGuard(**kwargs)


def fill(guard, count, base=2000):
    names = []
    for index in range(1, count + 1):
        name = "s%d" % index
        guard.register(name, rating=base - index * 10)
        names.append(name)
    return names


def test_duplicate_registration_is_ignored():
    g = make(size=4, max_rounds=2)
    first = g.register("alpha", rating=1200)
    second = g.register("alpha", rating=1300)
    assert first["status"] == "applied"
    assert first["count"] == 1
    assert second["status"] == "ignored"
    assert second["code"] == "BKT_DUP_PLAYER"
    assert g.seed_order() == ["alpha"]


def test_registration_closes_after_first_round_built():
    g = make(size=4, max_rounds=2)
    fill(g, 4)
    g.build_round(1)
    with pytest.raises(tbg.BracketError) as exc:
        g.register("late", rating=3000)
    assert exc.value.code == "BKT_LOCKED"
    assert g.seed_order() == ["s1", "s2", "s3", "s4"]


def test_seed_order_breaks_ties_by_registration_sequence():
    g = make(size=8, max_rounds=3)
    g.register("zeta", rating=1000)
    g.register("alpha", rating=1000)
    g.register("mid", rating=1100)
    assert g.seed_order() == ["mid", "zeta", "alpha"]


def test_first_round_pairs_follow_standard_seed_layout():
    g = make(size=8, max_rounds=3)
    fill(g, 8)
    matches = g.build_round(1)
    pairs = [(m["player_a"], m["player_b"]) for m in matches]
    assert pairs == [("s1", "s8"), ("s4", "s5"), ("s2", "s7"), ("s3", "s6")]
    assert [m["match_id"] for m in matches] == ["r1-m1", "r1-m2", "r1-m3", "r1-m4"]
    assert g.current_round() == 1


def test_byes_go_to_top_seeds_when_field_is_short():
    g = make(size=8, max_rounds=3)
    fill(g, 6)
    matches = g.build_round(1)
    assert len(matches) == 4
    assert g.byes(1) == ["s1", "s2"]
    empty_slots = [m for m in matches if m["player_b"] is None]
    assert len(empty_slots) == 2
    standings = {row["player"]: row for row in g.standings()}
    assert standings["s1"]["wins"] == 1
    assert standings["s2"]["wins"] == 1
    assert standings["s3"]["wins"] == 0


def test_build_round_is_idempotent_and_returns_copies():
    g = make(size=4, max_rounds=2)
    fill(g, 4)
    first = g.build_round(1)
    second = g.build_round(1)
    assert [m["match_id"] for m in first] == [m["match_id"] for m in second]
    first[0]["player_a"] = "tampered"
    assert g.matches(1)[0]["player_a"] == "s1"


def test_recording_same_match_twice_is_rejected():
    g = make(size=4, max_rounds=2)
    fill(g, 4)
    g.build_round(1)
    first = g.record_result("r1-m1", "s1", score="2-0")
    assert first["status"] == "applied"
    with pytest.raises(tbg.BracketError) as exc:
        g.record_result("r1-m1", "s4", score="2-1")
    assert exc.value.code == "BKT_MATCH_DONE"
    standings = {row["player"]: row for row in g.standings()}
    assert standings["s1"]["wins"] == 1
    assert standings["s4"]["wins"] == 0


def test_winner_must_be_match_participant():
    g = make(size=4, max_rounds=2)
    fill(g, 4)
    g.build_round(1)
    with pytest.raises(tbg.BracketError) as exc:
        g.record_result("r1-m1", "s3")
    assert exc.value.code == "BKT_UNKNOWN_WINNER"
    with pytest.raises(tbg.BracketError) as exc2:
        g.record_result("r9-m9", "s1")
    assert exc2.value.code == "BKT_UNKNOWN_MATCH"


def test_winners_advance_and_final_crowns_champion():
    g = make(size=4, max_rounds=2)
    fill(g, 4)
    g.build_round(1)
    g.record_result("r1-m1", "s1")
    g.record_result("r1-m2", "s2")
    round_two = g.build_round(2)
    assert [(m["player_a"], m["player_b"]) for m in round_two] == [("s1", "s2")]
    assert g.champion() is None
    g.record_result("r2-m1", "s1")
    assert g.champion() == "s1"
    assert g.current_round() == 2


def test_results_are_closed_once_champion_is_crowned():
    g = make(size=4, max_rounds=2)
    fill(g, 4)
    g.build_round(1)
    g.record_result("r1-m1", "s1")
    g.record_result("r1-m2", "s2")
    g.build_round(2)
    g.record_result("r2-m1", "s1")
    with pytest.raises(tbg.BracketError) as exc:
        g.record_result("r2-m1", "s2")
    assert exc.value.code == "BKT_SEASON_CLOSED"


def test_round_limit_and_audit_log_bound():
    g = make(size=8, max_rounds=2)
    fill(g, 8)
    with pytest.raises(tbg.BracketError) as exc:
        g.build_round(3)
    assert exc.value.code == "BKT_ROUND_LIMIT"
    small = make(size=8, max_rounds=3, audit_limit=3)
    fill(small, 5)
    log = small.audit()
    assert len(log) == 3
    assert log[0]["player"] == "s5"
    assert all(row["action"] == "register" for row in log)


def test_withdraw_rules_before_and_after_build():
    g = make(size=4, max_rounds=2)
    fill(g, 4)
    out = g.withdraw("s2")
    assert out["status"] == "applied"
    assert g.seed_order() == ["s1", "s3", "s4"]
    with pytest.raises(tbg.BracketError) as exc:
        g.withdraw("nobody")
    assert exc.value.code == "BKT_UNKNOWN_PLAYER"
    g.build_round(1)
    with pytest.raises(tbg.BracketError) as exc2:
        g.withdraw("s1")
    assert exc2.value.code == "BKT_LOCKED"


def test_standings_sort_by_wins_then_seed():
    g = make(size=4, max_rounds=2)
    fill(g, 4)
    g.build_round(1)
    g.record_result("r1-m1", "s1")
    g.record_result("r1-m2", "s3")
    rows = g.standings()
    assert [row["player"] for row in rows] == ["s1", "s3", "s2", "s4"]
    assert [row["wins"] for row in rows] == [1, 1, 0, 0]
    assert [row["seed"] for row in rows] == [1, 3, 2, 4]


def test_snapshot_restore_rolls_back_round_two():
    g = make(size=4, max_rounds=2)
    fill(g, 4)
    g.build_round(1)
    g.record_result("r1-m1", "s1")
    g.record_result("r1-m2", "s2")
    snap = g.snapshot()
    g.build_round(2)
    g.record_result("r2-m1", "s1")
    assert g.champion() == "s1"
    out = g.restore(snap)
    assert out["status"] == "restored"
    assert g.champion() is None
    assert g.current_round() == 1
    assert g.matches(2) == []
    standings = {row["player"]: row for row in g.standings()}
    assert standings["s1"]["wins"] == 1


def test_concurrent_registration_is_single_instance():
    g = make(size=16, max_rounds=4)
    barrier = threading.Barrier(12)
    errors = []
    lock = threading.Lock()

    def worker(index):
        barrier.wait()
        try:
            g.register("p%d" % index, rating=1000 + index)
        except Exception as exc:  # unexpected failures must fail the test
            with lock:
                errors.append(type(exc).__name__)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(12)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    assert errors == []
    order = g.seed_order()
    assert len(order) == 12
    assert len(set(order)) == 12
    assert order[0] == "p11"
    assert order[-1] == "p0"
