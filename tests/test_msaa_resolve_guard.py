import json
import threading

import pytest

import msaa_resolve_guard as msaa


def make(sample_count=4, **kwargs):
    kwargs.setdefault("memory_budget", 10 ** 9)
    return msaa.MsaaResolve(sample_count=sample_count, **kwargs)


def col(r, g, b, a=1.0):
    return (r, g, b, a)


def test_configure_rejects_unsupported_sample_count_and_bumps_epoch():
    a = make()
    with pytest.raises(msaa.MsaaError) as exc:
        a.configure(sample_count=3)
    assert exc.value.code == "MSAA_BAD_SAMPLE_COUNT"
    assert a.stats()["epoch"] == 0
    out = a.configure(sample_count=8)
    assert out["sample_count"] == 8
    assert a.stats()["epoch"] == 1


def test_sample_index_and_pixel_bounds_are_validated():
    a = make()
    assert a.resize(4, 4)["dropped"] == 0
    with pytest.raises(msaa.MsaaError) as exc:
        a.add_sample((0, 0), 4, col(1.0, 0.0, 0.0))
    assert exc.value.code == "MSAA_SAMPLE_INDEX"
    with pytest.raises(msaa.MsaaError) as exc:
        a.add_sample((4, 0), 0, col(1.0, 0.0, 0.0))
    assert exc.value.code == "MSAA_PIXEL_OOB"
    with pytest.raises(msaa.MsaaError) as exc:
        a.add_sample((0, 0), 0, (1.0, 0.0, 0.0))
    assert exc.value.code == "MSAA_BAD_COLOR"
    assert a.stats()["samples"] == 0


def test_depth_test_keeps_the_nearer_sample():
    a = make()
    a.add_sample((1, 1), 0, col(0.2, 0.2, 0.2), depth=0.40)
    out = a.add_sample((1, 1), 0, col(0.9, 0.9, 0.9), depth=0.60)
    assert out["status"] == "rejected"
    assert out["code"] == "MSAA_DEPTH_REJECT"
    assert a.resolve_pixel((1, 1))["color"] == (0.2, 0.2, 0.2, 1.0)
    assert a.stats()["rejected_depth"] == 1
    nearer = a.add_sample((1, 1), 0, col(0.5, 0.5, 0.5), depth=0.25)
    assert nearer["status"] == "replaced"
    assert a.resolve_pixel((1, 1))["depth"] == 0.25


def test_identical_rewrite_counts_as_duplicate_without_extra_dirty():
    a = make()
    payload = col(0.1, 0.2, 0.3)
    a.add_sample((0, 0), 0, payload, depth=0.5)
    out = a.add_sample((0, 0), 0, payload, depth=0.5)
    assert out["status"] == "unchanged"
    assert out["code"] == "MSAA_DUP_WRITE"
    assert a.stats()["samples"] == 1
    assert a.stats()["duplicate_writes"] == 1
    assert a.flush_dirty() == [(0, 0)]
    assert a.flush_dirty() == []


def test_resolve_averages_covered_samples_weighted_by_coverage():
    a = make()
    a.add_sample((0, 0), 0, col(0.0, 0.0, 0.0), coverage=1.0, depth=0.9)
    a.add_sample((0, 0), 1, col(1.0, 1.0, 1.0), coverage=1.0, depth=0.4)
    a.add_sample((0, 0), 2, col(1.0, 0.0, 0.0), coverage=0.5, depth=0.6)
    out = a.resolve_pixel((0, 0))
    assert out["color"] == (0.6, 0.4, 0.4, 1.0)
    assert out["coverage"] == 0.625
    assert out["samples"] == 3
    assert out["resolved"] is True
    empty = a.resolve_pixel((7, 7))
    assert empty["resolved"] is False
    assert empty["color"] == (0.0, 0.0, 0.0, 0.0)


def test_min_mode_resolves_per_channel_minimum():
    a = make(resolve_mode="min")
    a.add_sample((0, 0), 0, col(0.2, 0.9, 0.1), depth=0.8)
    a.add_sample((0, 0), 1, col(0.7, 0.3, 0.5), depth=0.2)
    out = a.resolve_pixel((0, 0))
    assert out["color"] == (0.2, 0.3, 0.1, 1.0)
    assert out["depth"] == 0.2


def test_resolve_depth_ignores_uncovered_samples():
    a = make()
    a.add_sample((2, 2), 0, col(0.0, 0.0, 0.0), depth=0.9, stencil=7)
    a.add_sample((2, 2), 1, col(0.0, 0.0, 0.0), coverage=0.0, depth=0.1, stencil=3)
    out = a.resolve_depth((2, 2))
    assert out["depth"] == 0.9
    assert out["stencil"] == 7
    assert out["samples"] == 1


def test_alpha_to_coverage_quantizes_alpha_to_sample_steps():
    a = make(sample_count=4)
    assert a.set_alpha_to_coverage(True) is True
    a.add_sample((0, 0), 0, col(0.0, 0.0, 0.0, 0.3), coverage=1.0)
    a.add_sample((0, 0), 1, col(0.0, 0.0, 0.0, 0.6), coverage=1.0)
    out = a.resolve_pixel((0, 0))
    assert out["coverage"] == 0.1875
    a.add_sample((1, 1), 0, col(0.0, 0.0, 0.0, 0.1))
    assert a.resolve_pixel((1, 1))["resolved"] is False


def test_flush_dirty_returns_tiles_in_row_major_order():
    a = make(tile_size=4)
    a.add_sample((5, 1), 0, col(0.0, 0.0, 0.0))
    a.add_sample((1, 9), 0, col(0.0, 0.0, 0.0))
    a.add_sample((0, 0), 0, col(0.0, 0.0, 0.0))
    assert a.flush_dirty() == [(0, 0), (1, 0), (0, 2)]
    assert a.flush_dirty() == []
    assert a.stats()["tiles_resolved"] == 3


def test_memory_budget_evicts_least_recent_tile():
    a = make(tile_size=2, memory_budget=96)
    a.add_sample((0, 0), 0, col(0.0, 0.0, 0.0))
    a.add_sample((0, 0), 1, col(0.0, 0.0, 0.0))
    a.add_sample((4, 0), 0, col(0.0, 0.0, 0.0))
    a.add_sample((4, 0), 1, col(0.0, 0.0, 0.0))
    assert a.memory_usage() == 96
    a.add_sample((8, 0), 0, col(0.0, 0.0, 0.0))
    assert a.stats()["evictions"] == 1
    assert a.stats()["samples"] == 3
    assert a.memory_usage() <= 96
    assert a.resolve_pixel((0, 0))["samples"] == 0
    assert a.resolve_pixel((8, 0))["samples"] == 1
    with pytest.raises(msaa.MsaaError) as exc:
        make(tile_size=2, memory_budget=12).add_sample((0, 0), 0, col(0.0, 0.0, 0.0))
    assert exc.value.code == "MSAA_MEMORY_BUDGET"


def test_snapshot_restore_round_trips_through_json():
    a = make(tile_size=4)
    a.add_sample((1, 1), 0, col(0.25, 0.5, 0.75, 0.5), coverage=0.5, depth=0.3, stencil=2)
    a.add_sample((1, 1), 3, col(1.0, 0.0, 0.0, 1.0), depth=0.1)
    a.set_alpha_to_coverage(False)
    snap = json.loads(json.dumps(a.snapshot()))
    b = make()
    out = b.restore(snap)
    assert out["samples"] == 2
    assert b.resolve_pixel((1, 1)) == a.resolve_pixel((1, 1))
    assert b.stats()["samples_written"] == a.stats()["samples_written"]
    assert b.flush_dirty() == a.flush_dirty()
    assert b.stats()["tiles_resolved"] == 1


def test_invalid_snapshot_is_rejected_without_mutating():
    a = make()
    a.add_sample((0, 0), 0, col(1.0, 0.0, 0.0))
    before = a.stats()
    bad_snapshots = [
        {"version": 99},
        {"version": 1, "config": {"sample_count": 3}, "samples": {}},
        {"version": 1, "config": {"sample_count": 4}, "samples": {"0,0": {"9": {}}}},
    ]
    for bad in bad_snapshots:
        with pytest.raises(msaa.MsaaError) as exc:
            a.restore(bad)
        assert exc.value.code == "MSAA_SNAPSHOT_INVALID"
    assert a.stats() == before
    assert a.resolve_pixel((0, 0))["color"] == (1.0, 0.0, 0.0, 1.0)


def test_concurrent_writes_do_not_lose_samples():
    a = make(sample_count=4)
    errors = []

    def worker(base):
        try:
            for offset in range(25):
                a.add_sample((base + offset, 0), 0, col(0.5, 0.5, 0.5))
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(index * 100,))
               for index in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    assert a.stats()["samples"] == 200
    assert a.stats()["pixels"] == 200
    assert len(a.snapshot()["samples"]) == 200


def test_resolve_all_counts_pixels_tiles_and_samples():
    a = make(tile_size=4)
    a.add_sample((0, 0), 0, col(0.0, 0.0, 0.0))
    a.add_sample((5, 5), 0, col(0.0, 0.0, 0.0))
    a.add_sample((5, 5), 1, col(0.0, 0.0, 0.0))
    a.add_sample((5, 6), 0, col(0.0, 0.0, 0.0))
    out = a.resolve_all()
    assert out == {"pixels": 3, "tiles": 2, "samples": 4}
    assert a.flush_dirty() == []


def test_reconfigure_and_reset_advance_epoch_and_drop_samples():
    a = make()
    assert a.stats()["epoch"] == 0
    a.configure(tile_size=4)
    assert a.stats()["epoch"] == 0
    a.add_sample((0, 0), 0, col(0.0, 0.0, 0.0))
    a.configure(sample_count=8)
    assert a.stats()["epoch"] == 1
    assert a.stats()["samples"] == 0
    a.add_sample((0, 0), 7, col(0.0, 0.0, 0.0))
    assert a.reset() == 2
    assert a.stats()["samples"] == 0
    assert a.snapshot()["config"]["sample_count"] == 8
