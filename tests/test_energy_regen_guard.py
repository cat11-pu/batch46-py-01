import json
import threading

import pytest

import energy_regen_guard as energy

T0 = "2026-11-23T10:00:00+00:00"


def make(energy_value=0, cap=120, now=T0):
    a = energy.EnergyRegen()
    a.create_account("acct", energy=energy_value, cap=cap, now=now)
    return a


def test_regen_ticks_every_five_minutes_and_keeps_remainder():
    a = make()
    first = a.state("acct", now="2026-11-23T10:04:59+00:00")
    assert first["energy"] == 0
    assert first["remainder"] == 299
    tick = a.state("acct", now="2026-11-23T10:05:00+00:00")
    assert tick["energy"] == 1
    assert tick["remainder"] == 0
    later = a.state("acct", now="2026-11-23T10:12:30+00:00")
    assert later["energy"] == 2
    assert later["remainder"] == 150
    assert later["next_full_at"] == "2026-11-23T20:00:00+00:00"


def test_regen_stops_at_cap_and_clears_partial_progress():
    a = make(energy_value=118)
    full = a.state("acct", now="2026-11-23T10:50:00+00:00")
    assert full["energy"] == 120
    assert full["remainder"] == 0
    assert full["next_full_at"] is None
    stayed = a.state("acct", now="2026-11-23T12:30:00+00:00")
    assert stayed["energy"] == 120
    assert stayed["remainder"] == 0


def test_offline_catch_up_is_capped_at_twelve_hours():
    a = make(cap=500)
    out = a.state("acct", now="2026-11-24T10:00:00+00:00")
    assert out["energy"] == 144
    assert out["remainder"] == 0


def test_clock_regression_is_rejected_without_mutating_state():
    a = make()
    a.state("acct", now="2026-11-23T10:05:00+00:00")
    with pytest.raises(energy.EnergyError) as exc:
        a.regen("acct", "2026-11-23T10:04:59+00:00")
    assert exc.value.code == "ENERGY_CLOCK_REGRESSION"
    current = a.state("acct")
    assert current["energy"] == 1
    assert current["last_at"] == "2026-11-23T10:05:00+00:00"


def test_spend_decrements_and_preserves_regen_remainder():
    a = make()
    a.state("acct", now="2026-11-23T10:11:40+00:00")
    out = a.spend("acct", 1, now="2026-11-23T10:11:40+00:00", ref="spend-1")
    assert out["status"] == "applied"
    assert out["spent"] == 1
    assert out["energy"] == 1
    replay = a.spend("acct", 1, now="2026-11-23T10:11:40+00:00", ref="spend-1")
    assert replay["status"] == "replayed"
    assert replay["energy"] == 1
    mid = a.state("acct", now="2026-11-23T10:13:20+00:00")
    assert mid["energy"] == 1
    assert mid["remainder"] == 200
    next_point = a.state("acct", now="2026-11-23T10:15:00+00:00")
    assert next_point["energy"] == 2
    assert next_point["remainder"] == 0


def test_spend_more_than_available_is_rejected():
    a = make(energy_value=1)
    with pytest.raises(energy.EnergyError) as exc:
        a.spend("acct", 2, now=T0)
    assert exc.value.code == "ENERGY_INSUFFICIENT"
    assert a.state("acct")["energy"] == 1
    ok = a.spend("acct", 1, now=T0)
    assert ok["energy"] == 0


def test_spend_rejects_zero_negative_and_non_integer_amounts():
    a = make(energy_value=10)
    for bad in (0, -5, 1.5, True):
        with pytest.raises(energy.EnergyError) as exc:
            a.spend("acct", bad, now=T0)
        assert exc.value.code == "ENERGY_INVALID_AMOUNT"
    assert a.state("acct")["energy"] == 10


def test_daily_reset_refills_once_per_utc_day():
    a = make(energy_value=10, now="2026-11-23T01:00:00+00:00")
    first = a.daily_reset("acct", "2026-11-23T05:00:00+00:00")
    assert first["status"] == "applied"
    assert first["energy"] == 120
    second = a.daily_reset("acct", "2026-11-23T06:00:00+00:00")
    assert second["status"] == "skipped"
    assert second["code"] == "ENERGY_RESET_DONE"
    assert second["energy"] == 120
    tomorrow = a.daily_reset("acct", "2026-11-24T00:00:00+00:00")
    assert tomorrow["status"] == "applied"
    assert tomorrow["energy"] == 120


def test_same_day_spend_is_not_refilled_by_another_reset():
    a = make(energy_value=10, now="2026-11-23T01:00:00+00:00")
    a.daily_reset("acct", "2026-11-23T05:00:00+00:00")
    a.spend("acct", 50, now="2026-11-23T05:00:00+00:00")
    assert a.state("acct")["energy"] == 70
    again = a.daily_reset("acct", "2026-11-23T05:00:00+00:00")
    assert again["status"] == "skipped"
    assert again["energy"] == 70


def test_daily_reset_uses_utc_day_not_local_offset():
    a = make(energy_value=0, now="2026-11-23T00:00:00+00:00")
    first = a.daily_reset("acct", "2026-11-23T23:30:00+08:00")
    assert first["status"] == "applied"
    a.spend("acct", 40, now="2026-11-23T23:35:00+08:00")
    same_utc_day = a.daily_reset("acct", "2026-11-24T01:00:00+08:00")
    assert same_utc_day["status"] == "skipped"
    assert same_utc_day["energy"] == 97
    next_day = a.daily_reset("acct", "2026-11-24T08:00:00+08:00")
    assert next_day["status"] == "applied"
    assert next_day["energy"] == 120


def test_grant_without_overflow_wastes_the_excess():
    a = make(energy_value=115)
    out = a.grant("acct", 10, now=T0)
    assert out["granted"] == 5
    assert out["wasted"] == 5
    assert out["energy"] == 120
    assert a.state("acct")["remainder"] == 0


def test_grant_with_overflow_allows_sixty_extra_points():
    a = make(energy_value=120)
    out = a.grant("acct", 100, now=T0, allow_overflow=True)
    assert out["granted"] == 60
    assert out["wasted"] == 40
    assert out["energy"] == 180
    overflowed = a.grant("acct", 1, now=T0, allow_overflow=True)
    assert overflowed["granted"] == 0
    assert overflowed["wasted"] == 1
    assert a.state("acct")["energy"] == 180


def test_refill_requires_missing_energy_and_has_a_daily_limit():
    a = make(energy_value=120)
    with pytest.raises(energy.EnergyError) as exc:
        a.buy_refill("acct", now=T0)
    assert exc.value.code == "ENERGY_ALREADY_FULL"
    for expected in (1, 2, 3):
        a.spend("acct", 10, now=T0)
        out = a.buy_refill("acct", now=T0)
        assert out["refills_today"] == expected
        assert out["energy"] == 120
    a.spend("acct", 10, now=T0)
    with pytest.raises(energy.EnergyError) as exc:
        a.buy_refill("acct", now=T0)
    assert exc.value.code == "ENERGY_REFILL_LIMIT"


def test_concurrent_spend_never_drives_energy_negative():
    a = make(energy_value=10)
    outcomes = [None] * 20

    def worker(index, barrier):
        barrier.wait()
        try:
            outcomes[index] = a.spend("acct", 1, now=T0)
        except energy.EnergyError as error:
            outcomes[index] = error

    barrier = threading.Barrier(20)
    threads = [threading.Thread(target=worker, args=(i, barrier)) for i in range(20)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    applied = [row for row in outcomes if isinstance(row, dict)]
    rejected = [row for row in outcomes if isinstance(row, energy.EnergyError)]
    assert len(applied) == 10
    assert len(rejected) == 10
    assert all(row.code == "ENERGY_INSUFFICIENT" for row in rejected)
    assert a.state("acct")["energy"] == 0


def test_snapshot_restore_keeps_remainder_and_rejects_bad_state():
    a = make()
    a.state("acct", now="2026-11-23T10:11:40+00:00")
    a.spend("acct", 1, now="2026-11-23T10:11:40+00:00")
    snapshot = a.snapshot()
    json.dumps(snapshot)
    a.spend("acct", 1, now="2026-11-23T10:11:40+00:00")
    assert a.state("acct")["energy"] == 0
    restored = energy.EnergyRegen()
    restored.restore(snapshot)
    recovered = restored.state("acct")
    assert recovered["energy"] == 1
    assert recovered["remainder"] == 100
    point = restored.regen("acct", "2026-11-23T10:15:00+00:00")
    assert point["energy"] == 2
    with pytest.raises(energy.EnergyError) as exc:
        restored.restore({"version": 2})
    assert exc.value.code == "ENERGY_BAD_SNAPSHOT"
    assert restored.state("acct")["energy"] == 2
    assert restored.history("acct", limit=1)[0]["event"] == "spend"
