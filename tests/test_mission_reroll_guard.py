import json
import threading

import pytest

import mission_reroll_guard as mrg


POOL = ["m1", "m2", "m3", "m4", "m5"]


def make(**kwargs):
    guard = mrg.MissionReroll(**kwargs)
    guard.define_pool("daily", POOL)
    return guard


def test_assign_day_is_deterministic_and_does_not_reshuffle():
    guard = make()
    first = guard.assign_day("acct", "2026-11-23", slots=3, seed=1)
    assert first["created"] is True
    assert [row["mission"] for row in first["slots"].values()] == ["m2", "m3", "m4"]
    second = guard.assign_day("acct", "2026-11-23", slots=3, seed=4)
    assert second["created"] is False
    assert [row["mission"] for row in second["slots"].values()] == ["m2", "m3", "m4"]


def test_assign_day_rejects_malformed_day():
    guard = make()
    with pytest.raises(mrg.MissionError) as exc:
        guard.assign_day("acct", "2026-13-01")
    assert exc.value.code == "MISSION_BAD_DAY"
    with pytest.raises(mrg.MissionError) as other:
        guard.assign_day("acct", "23/11/2026")
    assert other.value.code == "MISSION_BAD_DAY"


def test_assign_day_rejects_board_larger_than_pool():
    guard = make()
    with pytest.raises(mrg.MissionError) as exc:
        guard.assign_day("acct", "2026-11-23", slots=6)
    assert exc.value.code == "MISSION_POOL_TOO_SMALL"
    with pytest.raises(mrg.MissionError) as other:
        guard.assign_day("acct", "2026-11-23", slots=0)
    assert other.value.code == "MISSION_BAD_SLOTS"


def test_reroll_consumes_one_token_and_picks_next_free_mission():
    guard = make()
    guard.assign_day("acct", "2026-11-23", slots=3, seed=0)
    guard.grant_tokens("acct", 2)
    out = guard.reroll("acct", "2026-11-23", "slot-1", "r1")
    assert out["status"] == "applied"
    assert out["mission"] == "m4"
    assert out["tokens"] == 1
    assert out["rerolls_used"] == 1
    again = guard.reroll("acct", "2026-11-23", "slot-1", "r2")
    assert again["mission"] == "m5"
    assert guard.tokens("acct") == 0
    assert guard.current("acct", "2026-11-23")["slots"]["slot-1"]["mission"] == "m5"


def test_reroll_without_token_keeps_board_unchanged():
    guard = make()
    guard.assign_day("acct", "2026-11-23", slots=3, seed=0)
    with pytest.raises(mrg.MissionError) as exc:
        guard.reroll("acct", "2026-11-23", "slot-2", "r1")
    assert exc.value.code == "MISSION_NO_TOKEN"
    assert guard.current("acct", "2026-11-23")["slots"]["slot-2"]["mission"] == "m2"
    assert guard.tokens("acct") == 0


def test_reroll_request_id_is_idempotent():
    guard = make()
    guard.assign_day("acct", "2026-11-23", slots=3, seed=0)
    guard.grant_tokens("acct", 3)
    first = guard.reroll("acct", "2026-11-23", "slot-1", "same")
    second = guard.reroll("acct", "2026-11-23", "slot-1", "same")
    assert first["status"] == "applied"
    assert second["status"] == "duplicate"
    assert second["mission"] == first["mission"]
    assert guard.tokens("acct") == 2
    assert guard.current("acct", "2026-11-23")["rerolls_used"] == 1


def test_reroll_limit_is_enforced_per_day():
    guard = make(daily_limit=2)
    guard.assign_day("acct", "2026-11-23", slots=1, seed=0)
    guard.grant_tokens("acct", 5)
    guard.reroll("acct", "2026-11-23", "slot-1", "a")
    guard.reroll("acct", "2026-11-23", "slot-1", "b")
    with pytest.raises(mrg.MissionError) as exc:
        guard.reroll("acct", "2026-11-23", "slot-1", "c")
    assert exc.value.code == "MISSION_REROLL_LIMIT"
    assert guard.tokens("acct") == 3


def test_locked_slot_cannot_be_rerolled():
    guard = make()
    guard.assign_day("acct", "2026-11-23", slots=2, seed=0)
    guard.grant_tokens("acct", 3)
    assert guard.lock_slot("acct", "2026-11-23", "slot-2")["status"] == "locked"
    assert guard.lock_slot("acct", "2026-11-23", "slot-2")["status"] == "duplicate"
    with pytest.raises(mrg.MissionError) as exc:
        guard.reroll("acct", "2026-11-23", "slot-2", "x")
    assert exc.value.code == "MISSION_SLOT_LOCKED"
    assert guard.tokens("acct") == 3


def test_completed_slot_cannot_be_rerolled():
    guard = make()
    guard.assign_day("acct", "2026-11-23", slots=2, seed=0)
    guard.grant_tokens("acct", 2)
    guard.complete("acct", "2026-11-23", "slot-1", "e1")
    with pytest.raises(mrg.MissionError) as exc:
        guard.reroll("acct", "2026-11-23", "slot-1", "x")
    assert exc.value.code == "MISSION_SLOT_COMPLETED"
    assert guard.tokens("acct") == 3


def test_reroll_on_rolled_over_day_is_stale():
    guard = make()
    guard.assign_day("acct", "2026-11-23", slots=2, seed=0)
    guard.grant_tokens("acct", 10)
    out = guard.rollover("acct", "2026-11-23", "2026-11-24")
    assert out["carried"] == 5
    assert out["discarded"] == 5
    guard.assign_day("acct", "2026-11-24", slots=2, seed=0)
    with pytest.raises(mrg.MissionError) as exc:
        guard.reroll("acct", "2026-11-23", "slot-1", "old")
    assert exc.value.code == "MISSION_STALE_DAY"
    fresh = guard.reroll("acct", "2026-11-24", "slot-1", "new")
    assert fresh["status"] == "applied"
    assert fresh["tokens"] == 4


def test_completion_rewards_once_and_dedupes_events():
    guard = make()
    guard.assign_day("acct", "2026-11-23", slots=2, seed=0)
    first = guard.complete("acct", "2026-11-23", "slot-1", "e1")
    assert first["status"] == "applied"
    assert first["reward"] == 1
    assert guard.tokens("acct") == 1
    dup = guard.complete("acct", "2026-11-23", "slot-1", "e1")
    assert dup["status"] == "ignored"
    assert dup["code"] == "MISSION_DUP_EVENT"
    claimed = guard.complete("acct", "2026-11-23", "slot-1", "e2")
    assert claimed["status"] == "ignored"
    assert claimed["code"] == "MISSION_ALREADY_CLAIMED"
    second = guard.complete("acct", "2026-11-23", "slot-2", "e3")
    assert second["status"] == "applied"
    assert guard.tokens("acct") == 2
    assert len(guard.claims("acct", "2026-11-23")) == 2
    assert guard.stats("acct")["claims"] == 2


def test_rollover_is_idempotent_and_resets_reroll_counter():
    guard = make()
    guard.assign_day("acct", "2026-11-23", slots=2, seed=0)
    guard.grant_tokens("acct", 4)
    guard.reroll("acct", "2026-11-23", "slot-1", "r1")
    out = guard.rollover("acct", "2026-11-23", "2026-11-24")
    assert out["status"] == "applied"
    assert out["carried"] == 3
    again = guard.rollover("acct", "2026-11-23", "2026-11-24")
    assert again["status"] == "ignored"
    assert again["code"] == "MISSION_DUP_ROLLOVER"
    assert guard.tokens("acct") == 3
    board = guard.assign_day("acct", "2026-11-24", slots=2, seed=0)
    assert board["rerolls_used"] == 0
    nxt = guard.reroll("acct", "2026-11-24", "slot-1", "r2")
    assert nxt["status"] == "applied"
    assert nxt["rerolls_used"] == 1


def test_concurrent_token_grants_do_not_lose_updates():
    guard = make()
    guard.assign_day("acct", "2026-11-23", slots=1, seed=0)
    barrier = threading.Barrier(8)
    errors = []

    def worker():
        try:
            barrier.wait()
            for _ in range(10):
                guard.grant_tokens("acct", 1, reason="thread")
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    assert guard.tokens("acct") == 80


def test_concurrent_rerolls_consume_exactly_the_daily_limit():
    guard = mrg.MissionReroll(daily_limit=3)
    guard.define_pool("daily", [f"m{i}" for i in range(1, 9)])
    guard.assign_day("acct", "2026-11-23", slots=1, seed=0)
    guard.grant_tokens("acct", 10)
    barrier = threading.Barrier(6)
    applied = []
    limited = []
    lock = threading.Lock()

    def worker(index):
        barrier.wait()
        try:
            out = guard.reroll("acct", "2026-11-23", "slot-1", f"req-{index}")
            with lock:
                applied.append(out["mission"])
        except mrg.MissionError as exc:
            with lock:
                limited.append(exc.code)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(applied) == 3
    assert sorted(limited) == ["MISSION_REROLL_LIMIT"] * 3
    assert guard.tokens("acct") == 7
    assert len(set(applied)) == 3
    assert guard.current("acct", "2026-11-23")["rerolls_used"] == 3


def test_snapshot_round_trip_preserves_boards_tokens_and_counters():
    guard = make()
    guard.assign_day("acct", "2026-11-23", slots=3, seed=0)
    guard.grant_tokens("acct", 5)
    guard.reroll("acct", "2026-11-23", "slot-1", "r1")
    guard.complete("acct", "2026-11-23", "slot-2", "e1")
    payload = json.loads(json.dumps(guard.snapshot()))

    restored = mrg.MissionReroll()
    restored.restore(payload)
    view = restored.current("acct", "2026-11-23")
    assert view["slots"]["slot-1"]["mission"] == "m4"
    assert view["slots"]["slot-2"]["completed"] is True
    assert view["rerolls_used"] == 1
    assert restored.tokens("acct") == 5
    dup = restored.complete("acct", "2026-11-23", "slot-2", "e1")
    assert dup["code"] == "MISSION_DUP_EVENT"
    replay = restored.reroll("acct", "2026-11-23", "slot-1", "r1")
    assert replay["status"] == "duplicate"
    nxt = restored.reroll("acct", "2026-11-23", "slot-1", "r2")
    assert nxt["status"] == "applied"
    assert restored.tokens("acct") == 4
    with pytest.raises(mrg.MissionError) as exc:
        mrg.MissionReroll().restore({"version": 99})
    assert exc.value.code == "MISSION_BAD_SNAPSHOT"
