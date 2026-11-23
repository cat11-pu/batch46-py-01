import threading
from datetime import datetime, timedelta, timezone

import pytest

import raid_roster_guard as rr

T0 = datetime(2026, 11, 23, 19, 0, 0, tzinfo=timezone.utc)


def make(size=5, tanks=2, healers=2, dps=2, bench=2, window=60):
    return rr.RaidRoster(rr.RaidConfig(
        size=size,
        max_tanks=tanks,
        max_healers=healers,
        max_dps=dps,
        bench_size=bench,
        swap_window_seconds=window,
    ), "raid-1")


def seed(r):
    r.add(rr.Raider("d2", rr.Role.DPS, 550), T0)
    r.add(rr.Raider("h1", rr.Role.HEALER, 580), T0)
    r.add(rr.Raider("t1", rr.Role.TANK, 600), T0)
    r.add(rr.Raider("d1", rr.Role.DPS, 560), T0)
    r.add(rr.Raider("h2", rr.Role.HEALER, 570), T0)


def test_add_members_and_roster_sorts_by_role_then_name():
    r = make()
    seed(r)
    rows = r.roster()
    assert rows == [
        rr.Slot("t1", rr.Role.TANK, 600, False),
        rr.Slot("h1", rr.Role.HEALER, 580, False),
        rr.Slot("h2", rr.Role.HEALER, 570, False),
        rr.Slot("d1", rr.Role.DPS, 560, False),
        rr.Slot("d2", rr.Role.DPS, 550, False),
    ]
    assert r.count(rr.Role.TANK) == 1
    assert r.count(rr.Role.HEALER) == 2
    assert r.count(rr.Role.DPS) == 2
    assert r.bench_list() == []
    assert r.locked() is False
    rows.clear()
    assert len(r.roster()) == 5


def test_duplicate_member_is_refused_on_roster_and_bench():
    r = make()
    seed(r)
    with pytest.raises(rr.RaidError) as exc:
        r.add(rr.Raider("t1", rr.Role.TANK, 1), T0)
    assert exc.value.code == rr.ERR_DUPLICATE_MEMBER
    r.bench("t1", T0)
    with pytest.raises(rr.RaidError) as exc:
        r.add(rr.Raider("t1", rr.Role.TANK, 1), T0)
    assert exc.value.code == rr.ERR_DUPLICATE_MEMBER
    assert r.bench_list() == ["t1"]


def test_raid_size_limit():
    r = make(size=2, tanks=1, healers=1, dps=1)
    r.add(rr.Raider("t1", rr.Role.TANK, 600), T0)
    r.add(rr.Raider("h1", rr.Role.HEALER, 600), T0)
    with pytest.raises(rr.RaidError) as exc:
        r.add(rr.Raider("d1", rr.Role.DPS, 600), T0)
    assert exc.value.code == rr.ERR_RAID_FULL
    assert len(r.roster()) == 2
    assert r.count(rr.Role.DPS) == 0


def test_role_quotas_are_enforced_per_role():
    r = make(size=10, tanks=1, healers=1, dps=2)
    r.add(rr.Raider("t1", rr.Role.TANK, 600), T0)
    with pytest.raises(rr.RaidError) as exc:
        r.add(rr.Raider("t2", rr.Role.TANK, 610), T0)
    assert exc.value.code == rr.ERR_ROLE_QUOTA
    r.add(rr.Raider("h1", rr.Role.HEALER, 600), T0)
    with pytest.raises(rr.RaidError) as exc:
        r.add(rr.Raider("h2", rr.Role.HEALER, 610), T0)
    assert exc.value.code == rr.ERR_ROLE_QUOTA
    r.add(rr.Raider("d1", rr.Role.DPS, 600), T0)
    r.add(rr.Raider("d2", rr.Role.DPS, 600), T0)
    assert r.count(rr.Role.TANK) == 1
    assert r.count(rr.Role.DPS) == 2


def test_bench_moves_a_member_out_of_the_active_roster():
    r = make()
    seed(r)
    r.bench("d2", T0)
    assert r.count(rr.Role.DPS) == 1
    assert r.bench_list() == ["d2"]
    rows = r.roster()
    assert len(rows) == 5
    assert rows[-1] == rr.Slot("d2", rr.Role.DPS, 550, True)
    assert rows[0] == rr.Slot("t1", rr.Role.TANK, 600, False)


def test_bench_rejects_strangers_and_respects_the_bench_cap():
    r = make(bench=1)
    seed(r)
    with pytest.raises(rr.RaidError) as exc:
        r.bench("ghost", T0)
    assert exc.value.code == rr.ERR_NOT_IN_RAID
    r.bench("d1", T0)
    with pytest.raises(rr.RaidError) as exc:
        r.bench("d2", T0)
    assert exc.value.code == rr.ERR_BENCH_FULL
    assert r.count(rr.Role.DPS) == 1
    assert r.bench_list() == ["d1"]


def test_lock_freezes_adds_and_bench_moves():
    r = make()
    seed(r)
    r.lock(T0)
    assert r.locked() is True
    with pytest.raises(rr.RaidError) as exc:
        r.add(rr.Raider("d3", rr.Role.DPS, 500), T0)
    assert exc.value.code == rr.ERR_ROSTER_LOCKED
    with pytest.raises(rr.RaidError) as exc:
        r.bench("d1", T0)
    assert exc.value.code == rr.ERR_ROSTER_LOCKED
    with pytest.raises(rr.RaidError) as exc:
        r.lock(T0)
    assert exc.value.code == rr.ERR_ALREADY_LOCKED
    assert len(r.roster()) == 5


def test_swap_within_the_window_exchanges_bench_and_active():
    r = make(window=60)
    seed(r)
    r.bench("d2", T0)
    r.lock(T0)
    r.swap("d2", "d1", T0 + timedelta(seconds=60))
    assert r.bench_list() == ["d1"]
    rows = r.roster()
    assert rows[-1] == rr.Slot("d1", rr.Role.DPS, 560, True)
    assert rows[-2] == rr.Slot("d2", rr.Role.DPS, 550, False)
    assert r.count(rr.Role.DPS) == 1


def test_swap_is_closed_when_unlocked_or_past_the_window():
    r = make(window=60)
    seed(r)
    r.bench("d2", T0)
    with pytest.raises(rr.RaidError) as exc:
        r.swap("d2", "d1", T0)
    assert exc.value.code == rr.ERR_SWAP_CLOSED
    r.lock(T0)
    with pytest.raises(rr.RaidError) as exc:
        r.swap("d2", "d1", T0 + timedelta(seconds=61))
    assert exc.value.code == rr.ERR_SWAP_CLOSED
    assert r.bench_list() == ["d2"]
    assert r.count(rr.Role.DPS) == 1


def test_unlock_reopens_the_roster():
    r = make(size=6, dps=3)
    seed(r)
    with pytest.raises(rr.RaidError) as exc:
        r.unlock()
    assert exc.value.code == rr.ERR_ROSTER_UNLOCKED
    r.lock(T0)
    r.unlock()
    assert r.locked() is False
    r.add(rr.Raider("d3", rr.Role.DPS, 500), T0)
    assert r.count(rr.Role.DPS) == 3


def test_pull_needs_a_lock_and_records_sorted_attendance():
    r = make()
    seed(r)
    with pytest.raises(rr.RaidError) as exc:
        r.pull("b1", T0)
    assert exc.value.code == rr.ERR_ROSTER_UNLOCKED
    r.lock(T0)
    record = r.pull("b1", T0 + timedelta(seconds=5))
    assert record.boss_id == "b1"
    assert record.at == T0 + timedelta(seconds=5)
    assert record.members == ("d1", "d2", "h1", "h2", "t1")
    assert r.attendance("b1") == ["d1", "d2", "h1", "h2", "t1"]
    with pytest.raises(rr.RaidError) as exc:
        r.pull("b1", T0 + timedelta(seconds=6))
    assert exc.value.code == rr.ERR_LOCKOUT_ACTIVE


def test_unknown_boss_and_empty_roster_are_distinguished():
    r = make()
    with pytest.raises(rr.RaidError) as exc:
        r.attendance("nope")
    assert exc.value.code == rr.ERR_UNKNOWN_BOSS
    with pytest.raises(rr.RaidError) as exc:
        r.unlock_boss("nope")
    assert exc.value.code == rr.ERR_UNKNOWN_BOSS
    r.lock(T0)
    with pytest.raises(rr.RaidError) as exc:
        r.pull("b1", T0)
    assert exc.value.code == rr.ERR_EMPTY_ROSTER
    with pytest.raises(rr.RaidError) as exc:
        r.unlock_boss("b1")
    assert exc.value.code == rr.ERR_UNKNOWN_BOSS


def test_unlock_boss_clears_only_that_lockout():
    r = make()
    seed(r)
    r.lock(T0)
    r.pull("b1", T0 + timedelta(seconds=1))
    r.pull("b2", T0 + timedelta(seconds=2))
    r.unlock_boss("b1")
    again = r.pull("b1", T0 + timedelta(seconds=3))
    assert again.at == T0 + timedelta(seconds=3)
    assert r.attendance("b1") == ["d1", "d2", "h1", "h2", "t1"]
    with pytest.raises(rr.RaidError) as exc:
        r.pull("b2", T0 + timedelta(seconds=4))
    assert exc.value.code == rr.ERR_LOCKOUT_ACTIVE


def test_snapshot_restore_keeps_lock_window_and_lockouts():
    r = make(window=60)
    seed(r)
    r.bench("d2", T0)
    r.lock(T0)
    r.pull("b1", T0 + timedelta(seconds=5))
    blob = r.snapshot()
    assert isinstance(blob, bytes)
    restored = rr.RaidRoster.from_snapshot(rr.RaidConfig(
        size=5, max_tanks=2, max_healers=2, max_dps=2,
        bench_size=2, swap_window_seconds=60), blob)
    assert restored.locked() is True
    assert restored.roster() == r.roster()
    assert restored.bench_list() == ["d2"]
    assert restored.attendance("b1") == ["d1", "h1", "h2", "t1"]
    with pytest.raises(rr.RaidError) as exc:
        restored.pull("b1", T0 + timedelta(seconds=50))
    assert exc.value.code == rr.ERR_LOCKOUT_ACTIVE
    restored.swap("d2", "d1", T0 + timedelta(seconds=50))
    assert restored.bench_list() == ["d1"]
    assert restored.count(rr.Role.DPS) == 1
    with pytest.raises(rr.RaidError) as exc:
        restored.add(rr.Raider("d3", rr.Role.DPS, 500), T0)
    assert exc.value.code == rr.ERR_ROSTER_LOCKED


def test_concurrent_pull_records_attendance_once():
    r = make()
    seed(r)
    r.lock(T0)
    barrier = threading.Barrier(8)
    results = []
    results_lock = threading.Lock()

    def worker():
        barrier.wait(timeout=10)
        try:
            r.pull("b1", T0)
            code = "ok"
        except rr.RaidError as exc:
            code = exc.code
        with results_lock:
            results.append(code)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=20)
    assert len(results) == 8
    assert results.count("ok") == 1
    assert results.count(rr.ERR_LOCKOUT_ACTIVE) == 7
    assert r.attendance("b1") == ["d1", "d2", "h1", "h2", "t1"]
