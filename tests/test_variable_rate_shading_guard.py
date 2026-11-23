import copy
import json
import threading

import pytest

import variable_rate_shading_guard as vrs


def make(**kwargs):
    kwargs.setdefault("memory_budget", 10 ** 9)
    return vrs.VrsGuard(**kwargs)


def test_normalize_rate_accepts_case_and_rejects_bad_input():
    a = make()
    assert a.normalize_rate("2X2") == "2x2"
    assert a.normalize_rate(" 1x1 ") == "1x1"
    with pytest.raises(vrs.VrsError) as exc:
        a.normalize_rate("3x3")
    assert exc.value.code == "VRS_BAD_RATE"
    assert a.supported_rates() == ["1x1", "1x2", "2x1", "2x2"]


def test_rate_at_uses_base_rate_and_tile_size():
    a = make(tile_size=8)
    assert a.rate_at((0, 0)) == "1x1"
    assert a.set_tile_rate((1, 1), "2x2")["rate"] == "2x2"
    assert a.rate_at((15, 15)) == "2x2"
    assert a.rate_at((7, 7)) == "1x1"
    with pytest.raises(vrs.VrsError) as exc:
        a.rate_at((-1, 0))
    assert exc.value.code == "VRS_BAD_PIXEL"


def test_set_tile_rate_rejects_bad_tile_and_keeps_state():
    a = make()
    with pytest.raises(vrs.VrsError) as exc:
        a.set_tile_rate((-1, 0), "2x2")
    assert exc.value.code == "VRS_BAD_TILE"
    with pytest.raises(vrs.VrsError) as exc:
        a.set_tile_rate((0, 0), "3x2")
    assert exc.value.code == "VRS_BAD_RATE"
    assert a.stats()["tiles"] == 0
    assert a.stats()["changes"] == 0


def test_unsupported_rate_falls_back_to_largest_fitting_supported_rate():
    a = make()
    out = a.set_tile_rate((0, 0), "4x4")
    assert out["fallback"] is True
    assert out["rate"] == "2x2"
    assert a.rate_at((0, 0)) == "2x2"
    out = a.set_tile_rate((1, 0), "2x4")
    assert out["fallback"] is True
    assert out["rate"] == "2x2"
    assert a.stats()["fallback_count"] == 2


def test_set_rate_map_is_atomic_when_one_rate_is_malformed():
    a = make()
    with pytest.raises(vrs.VrsError) as exc:
        a.set_rate_map({(0, 0): "2x2", (1, 0): "9x9"})
    assert exc.value.code == "VRS_BAD_RATE"
    assert a.stats()["tiles"] == 0
    assert a.stats()["changes"] == 0
    assert a.flush() == []
    out = a.set_rate_map({(0, 0): "2x2", (1, 0): "1x2"})
    assert out["applied"] == 2
    assert a.rate_at((0, 0)) == "2x2"
    assert a.flush() == [(0, 0), (1, 0)]


def test_memory_budget_blocks_new_tile_entries_atomically():
    a = make(memory_budget=64)
    a.set_tile_rate((0, 0), "2x2")
    a.set_tile_rate((1, 0), "2x2")
    with pytest.raises(vrs.VrsError) as exc:
        a.set_tile_rate((2, 0), "2x2")
    assert exc.value.code == "VRS_MEMORY_BUDGET"
    assert a.stats()["tiles"] == 2
    with pytest.raises(vrs.VrsError) as exc:
        a.set_rate_map({(2, 0): "2x2", (3, 0): "2x2"})
    assert exc.value.code == "VRS_MEMORY_BUDGET"
    assert a.memory_usage() == 64
    assert a.set_tile_rate((0, 0), "1x2")["rate"] == "1x2"
    assert a.memory_usage() == 64


def test_base_rate_change_marks_known_tiles_dirty():
    a = make()
    a.set_tile_rate((0, 1), "2x2")
    assert a.flush() == [(0, 1)]
    out = a.set_base_rate("1x2")
    assert out["changed"] is True
    assert out["epoch"] == 1
    assert a.stats()["epoch"] == 1
    assert a.flush() == [(0, 1)]
    again = a.set_base_rate("1x2")
    assert again["changed"] is False
    assert a.flush() == []
    assert a.rate_at((500, 0)) == "1x2"


def test_derive_rates_applies_thresholds_and_motion_override():
    a = make()
    out = a.derive_rates([
        {"tile": (0, 0), "variance": 0.5, "motion": 1.0},
        {"tile": (1, 0), "variance": 4.0, "motion": 2.0},
        {"tile": (2, 0), "variance": 12.0, "motion": 1.0},
        {"tile": (3, 0), "variance": 0.1, "motion": 99.0},
    ])
    assert [row["rate"] for row in out["rates"]] == ["2x2", "1x2", "1x1", "1x1"]
    assert out["applied"] == 4
    assert a.rate_at((5, 0)) == "2x2"
    assert a.rate_at((20, 0)) == "1x2"
    assert a.rate_at((40, 0)) == "1x1"
    with pytest.raises(vrs.VrsError) as exc:
        a.derive_rates([{"tile": (0, 0), "variance": -1.0}])
    assert exc.value.code == "VRS_BAD_STATS"


def test_flush_returns_row_major_tiles_and_clears():
    a = make()
    a.set_tile_rate((3, 0), "2x2")
    a.set_tile_rate((0, 2), "2x2")
    a.set_tile_rate((0, 0), "2x2")
    assert a.flush() == [(0, 0), (3, 0), (0, 2)]
    assert a.flush() == []
    assert a.stats()["flushes"] == 1


def test_apply_attachment_prefers_priority_then_finer_rate():
    a = make()
    first = a.apply_attachment([{"tile": (0, 0), "rate": "2x2", "priority": 1}])
    assert first["applied"] == 1
    a.apply_attachment([{"tile": (0, 0), "rate": "1x2", "priority": 2}])
    assert a.rate_at((0, 0)) == "1x2"
    tie = a.apply_attachment([{"tile": (0, 0), "rate": "2x2", "priority": 2}])
    assert tie["skipped"] == 1
    assert a.rate_at((0, 0)) == "1x2"
    lower = a.apply_attachment([{"tile": (0, 0), "rate": "1x1", "priority": 1}])
    assert lower["skipped"] == 1
    assert a.rate_at((0, 0)) == "1x2"


def test_coverage_image_size_counts_shading_invocations():
    a = make(tile_size=16)
    a.set_tile_rate((0, 0), "2x2")
    out = a.coverage_image_size(32, 32)
    assert out["invocations"] == 832
    assert out["max_invocations"] == 1024
    assert out["ratio"] == 0.8125
    partial = a.coverage_image_size(24, 16)
    assert partial["max_invocations"] == 384
    assert partial["invocations"] == 192


def test_snapshot_restore_round_trips_through_json():
    a = make(tile_size=8, memory_budget=1024)
    a.set_base_rate("1x2")
    a.set_tile_rate((2, 1), "4x4")
    a.apply_attachment([{"tile": (0, 0), "rate": "2x2", "priority": 5}])
    snap = json.loads(json.dumps(a.snapshot()))
    b = make()
    out = b.restore(snap)
    assert out["tiles"] == 2
    assert b.rate_at((16, 8)) == "2x2"
    assert b.rate_at((0, 0)) == "2x2"
    assert b.stats() == a.stats()
    assert b.flush() == a.flush()


def test_invalid_snapshot_is_rejected_without_mutating():
    a = make()
    a.set_tile_rate((0, 0), "2x2")
    before = a.stats()
    with pytest.raises(vrs.VrsError) as exc:
        a.restore({"version": 7})
    assert exc.value.code == "VRS_SNAPSHOT_INVALID"
    broken = copy.deepcopy(a.snapshot())
    broken["entries"][0]["rate"] = "3x3"
    with pytest.raises(vrs.VrsError) as exc:
        a.restore(broken)
    assert exc.value.code == "VRS_SNAPSHOT_INVALID"
    assert a.stats() == before
    assert a.rate_at((0, 0)) == "2x2"


def test_concurrent_tile_writes_keep_every_entry():
    a = make()
    errors = []

    def worker(row):
        try:
            for column in range(25):
                a.set_tile_rate((column, row), "2x2")
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(row,)) for row in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    assert a.stats()["tiles"] == 200
    assert a.stats()["changes"] == 200
    assert len(a.flush()) == 200


def test_constructor_validation_and_reset():
    with pytest.raises(vrs.VrsError) as exc:
        vrs.VrsGuard(base_rate="4x4")
    assert exc.value.code == "VRS_BAD_RATE"
    with pytest.raises(vrs.VrsError) as exc:
        vrs.VrsGuard(supported_rates=("2x2",))
    assert exc.value.code == "VRS_BAD_RATE"
    a = make()
    a.set_tile_rate((0, 0), "2x2")
    assert a.reset() == 1
    assert a.stats()["tiles"] == 0
    assert a.flush() == []
