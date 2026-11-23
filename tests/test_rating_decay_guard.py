import threading

import pytest

import rating_decay_guard as rd

T0 = "2026-11-01T00:00:00+00:00"


def make():
    return rd.RatingDecay()


def test_equal_rating_match_is_zero_sum_with_provisional_k():
    a = make()
    a.register("x", 1500, now=T0)
    a.register("y", 1500, now=T0)
    out = a.record_match("m1", "x", "y", occurred_at="2026-11-01T10:00:00+00:00")
    assert out["status"] == "applied"
    assert out["winner_delta"] == 32
    assert out["loser_delta"] == -32
    assert a.rating("x") == 1532
    assert a.rating("y") == 1468


def test_underdog_win_scores_far_more_than_favourite_win():
    a = make()
    a.register("strong-one", 1900, now=T0)
    a.register("weak-one", 1500, now=T0)
    a.register("strong-two", 1900, now=T0)
    a.register("weak-two", 1500, now=T0)
    favourite = a.record_match("fav", "strong-one", "weak-one",
                               occurred_at="2026-11-01T10:00:00+00:00")
    underdog = a.record_match("und", "weak-two", "strong-two",
                              occurred_at="2026-11-01T10:05:00+00:00")
    assert favourite["winner_delta"] == 6
    assert underdog["winner_delta"] == 58
    assert underdog["winner_delta"] > favourite["winner_delta"]
    assert a.rating("weak-two") == 1558


def test_rating_floor_clamps_loser_below_one_hundred():
    a = make()
    a.register("floor-peer", 100, now=T0)
    a.register("low", 105, now=T0)
    out = a.record_match("m1", "floor-peer", "low",
                         occurred_at="2026-11-01T10:00:00+00:00")
    assert out["winner_delta"] == 32
    assert out["loser_delta"] == -5
    assert a.rating("low") == 100
    assert a.rating("floor-peer") == 132


def test_rating_ceiling_clamps_winner_at_three_thousand():
    a = make()
    a.register("top", 2995, now=T0)
    a.register("apex", 3000, now=T0)
    out = a.record_match("m1", "top", "apex", occurred_at="2026-11-01T10:00:00+00:00")
    assert out["winner_delta"] == 5
    assert a.rating("top") == 3000
    assert a.rating("apex") == 2968


def test_provisional_matches_use_double_k_for_first_five():
    a = make()
    a.register("p1", 1500, now=T0)
    first_delta = None
    for i in range(5):
        a.register(f"o{i}", 1500, now=T0)
        out = a.record_match(f"q{i}", "p1", f"o{i}",
                             occurred_at=f"2026-11-01T1{i}:00:00+00:00")
        if first_delta is None:
            first_delta = out["winner_delta"]
    assert first_delta == 32
    assert a.snapshot()["players"]["p1"]["provisional_left"] == 0
    a.register("equal", a.rating("p1"), now=T0)
    settled = a.record_match("q5", "p1", "equal",
                             occurred_at="2026-11-01T20:00:00+00:00")
    assert settled["k"] == 32
    assert settled["winner_delta"] == 16


def test_duplicate_match_id_is_ignored_and_rated_only_once():
    a = make()
    a.register("x", 1500, now=T0)
    a.register("y", 1500, now=T0)
    first = a.record_match("m1", "x", "y", occurred_at="2026-11-01T10:00:00+00:00")
    assert first["status"] == "applied"
    second = a.record_match("m1", "y", "x", occurred_at="2026-11-01T11:00:00+00:00")
    assert second["status"] == "ignored"
    assert second["code"] == "RATING_DUP_MATCH"
    assert a.rating("x") == 1532
    assert a.rating("y") == 1468
    assert len(a.history("x")) == 1


def test_decay_starts_only_after_fourteen_idle_days():
    a = make()
    a.register("idle-fourteen", 1500, now="2026-01-01T00:00:00+00:00")
    a.register("idle-thirteen", 1500, now="2026-01-02T00:00:00+00:00")
    report = {row["player"]: row for row in
              a.apply_decay("s1", "2026-01-15T00:00:00+00:00")}
    assert report["idle-fourteen"]["status"] == "applied"
    assert report["idle-fourteen"]["delta"] == -25
    assert a.rating("idle-fourteen") == 1475
    assert report["idle-thirteen"]["status"] == "skipped"
    assert report["idle-thirteen"]["code"] == "RATING_DECAY_GRACE"
    assert a.rating("idle-thirteen") == 1500


def test_decay_never_pushes_rating_below_protection_floor():
    a = make()
    a.register("protected", 1010, now="2026-01-01T00:00:00+00:00")
    report = a.apply_decay("s1", "2026-01-15T00:00:00+00:00")
    assert report[0]["status"] == "applied"
    assert report[0]["delta"] == -10
    assert a.rating("protected") == 1000


def test_decay_is_capped_per_season_and_never_applied_twice():
    a = make()
    a.register("long-idle", 1500, now="2026-01-01T00:00:00+00:00")
    first = a.apply_decay("s1", "2026-02-20T00:00:00+00:00")
    assert first[0]["delta"] == -100
    assert a.rating("long-idle") == 1400
    again = a.apply_decay("s1", "2026-02-21T00:00:00+00:00")
    assert again[0]["status"] == "skipped"
    assert again[0]["code"] == "RATING_DECAY_APPLIED"
    assert a.rating("long-idle") == 1400


def test_comeback_refund_is_half_of_decay_capped_and_paid_once():
    a = make()
    a.register("returning", 1500, now="2026-01-01T00:00:00+00:00")
    for name in ("o1", "o2", "o3"):
        a.register(name, 1400, now="2026-01-01T00:00:00+00:00")
    a.apply_decay("s1", "2026-02-20T00:00:00+00:00")
    assert a.rating("returning") == 1400
    a.record_match("r1", "returning", "o1", occurred_at="2026-02-21T10:00:00+00:00")
    a.record_match("r2", "returning", "o2", occurred_at="2026-02-21T10:01:00+00:00")
    with pytest.raises(rd.RatingError) as exc:
        a.claim_comeback("returning")
    assert exc.value.code == "RATING_COMEBACK_NOT_READY"
    a.record_match("r3", "returning", "o3", occurred_at="2026-02-21T10:02:00+00:00")
    before = a.rating("returning")
    out = a.claim_comeback("returning", now="2026-02-21T10:03:00+00:00")
    assert out["status"] == "applied"
    assert out["refund"] == 50
    assert a.rating("returning") == before + 50
    second = a.claim_comeback("returning", now="2026-02-21T10:04:00+00:00")
    assert second["status"] == "empty"
    assert second["code"] == "RATING_NO_COMEBACK"
    assert second["refund"] == 0


def test_unknown_and_malformed_operations_raise_structured_errors():
    a = make()
    a.register("only", 1500, now=T0)
    with pytest.raises(rd.RatingError) as exc:
        a.rating("ghost")
    assert exc.value.code == "RATING_UNKNOWN_PLAYER"
    with pytest.raises(rd.RatingError) as exc:
        a.register("only", 1500, now=T0)
    assert exc.value.code == "RATING_DUPLICATE_PLAYER"
    with pytest.raises(rd.RatingError) as exc:
        a.record_match("m1", "only", "ghost", occurred_at="2026-11-01T10:00:00+00:00")
    assert exc.value.code == "RATING_UNKNOWN_PLAYER"
    with pytest.raises(rd.RatingError) as exc:
        a.record_match("m2", "only", "only", occurred_at="2026-11-01T10:00:00+00:00")
    assert exc.value.code == "RATING_SELF_MATCH"


def test_snapshot_restore_keeps_ratings_ledger_and_provisional_state():
    a = make()
    a.register("p1", 1500, now=T0)
    a.register("p2", 1600, now=T0)
    results = a.record_matches([
        {"match_id": "late", "winner": "p2", "loser": "p1",
         "occurred_at": "2026-11-01T12:00:00+00:00"},
        {"match_id": "early", "winner": "p1", "loser": "p2",
         "occurred_at": "2026-11-01T11:00:00+00:00"},
    ])
    assert [row["match_id"] for row in results] == ["early", "late"]
    snap = a.snapshot()
    assert snap["version"] == 1
    saved_p1 = snap["players"]["p1"]["rating"]
    a.record_match("after", "p1", "p2", occurred_at="2026-11-02T10:00:00+00:00")
    assert snap["players"]["p1"]["rating"] == saved_p1
    assert a.rating("p1") != saved_p1
    restored = rd.RatingDecay()
    restored.restore(snap)
    assert restored.rating("p1") == saved_p1
    assert len(restored.history("p1")) == 2
    assert restored.snapshot()["players"]["p1"]["provisional_left"] == 3
    assert restored.stats()["matches"] == 2


def test_restore_rejects_bad_snapshot_without_mutating_state():
    a = make()
    a.register("p1", 1500, now=T0)
    a.register("p1b", 1500, now=T0)
    a.record_match("m1", "p1", "p1b", occurred_at="2026-11-01T10:00:00+00:00")
    saved = a.rating("p1")
    with pytest.raises(rd.RatingError) as exc:
        a.restore({"version": 99, "players": {}, "matches": {}, "history": [],
                   "decay": {}, "seq": 0})
    assert exc.value.code == "RATING_BAD_SNAPSHOT"
    with pytest.raises(rd.RatingError) as exc:
        a.restore({"version": 1, "players": {}})
    assert exc.value.code == "RATING_BAD_SNAPSHOT"
    assert a.rating("p1") == saved


def test_concurrent_duplicate_match_is_rated_exactly_once():
    a = make()
    a.register("a", 1500, now=T0)
    a.register("b", 1500, now=T0)
    distinct = [None] * 8
    dup = [None] * 8

    def play(index, barrier):
        barrier.wait()
        winner, loser = ("a", "b") if index % 2 == 0 else ("b", "a")
        distinct[index] = a.record_match(
            f"m{index}", winner, loser,
            occurred_at=f"2026-11-01T10:0{index}:00+00:00")

    def race(index, barrier):
        barrier.wait()
        dup[index] = a.record_match(
            "race", "a", "b", occurred_at="2026-11-01T11:00:00+00:00")

    first_barrier = threading.Barrier(8)
    threads = [threading.Thread(target=play, args=(i, first_barrier)) for i in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert all(row["status"] == "applied" for row in distinct)
    second_barrier = threading.Barrier(8)
    threads = [threading.Thread(target=race, args=(i, second_barrier)) for i in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    applied = [row for row in dup if row["status"] == "applied"]
    ignored = [row for row in dup if row["status"] == "ignored"]
    assert len(applied) == 1
    assert len(ignored) == 7
    assert all(row["code"] == "RATING_DUP_MATCH" for row in ignored)
    assert a.rating("a") + a.rating("b") == 3000


def test_leaderboard_orders_by_rating_then_player_id_and_filters_region():
    a = make()
    a.register("beta", 1700, region="na", now=T0)
    a.register("alpha", 1700, region="eu", now=T0)
    a.register("delta", 1500, region="na", now=T0)
    a.register("charlie", 1200, region="eu", now=T0)
    top = a.leaderboard()
    assert [row["player"] for row in top] == ["alpha", "beta", "delta", "charlie"]
    assert [row["player"] for row in a.leaderboard(limit=2)] == ["alpha", "beta"]
    assert [row["player"] for row in a.leaderboard(region="na")] == ["beta", "delta"]
    a.retire("beta")
    assert [row["player"] for row in a.leaderboard(region="na")] == ["delta"]
    assert a.rating("beta") == 1700
