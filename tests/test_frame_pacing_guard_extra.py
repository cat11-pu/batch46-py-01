"""Supplementary concurrency, boundary and snapshot restore tests."""

import json
import math
import threading

import pytest

import frame_pacing_guard as fpg


def make(**kwargs):
    options = {"target_fps": 60.0, "vsync_hz": 100.0, "max_late_ms": 8.0,
               "max_in_flight": 4, "history": 240, "min_fps": 30.0}
    options.update(kwargs)
    return fpg.FramePacer(**options)


def test_deadline_exactly_on_boundary_is_on_time():
    eng = make()
    eng.begin_frame("a")
    eng.advance(10000)
    out = eng.end_frame("a")
    assert out["late_us"] == 0
    assert out["missed"] is False
    assert out["action"] == "present"


def test_late_tolerance_boundary_inclusive():
    eng = make()
    eng.begin_frame("a")
    eng.advance(18000)
    out = eng.end_frame("a")
    assert out["late_us"] == 8000
    assert out["missed"] is True
    assert out["action"] == "present"

    eng2 = make()
    eng2.begin_frame("b")
    eng2.advance(18001)
    out = eng2.end_frame("b")
    assert out["late_us"] == 8001
    assert out["action"] == "drop"
    assert eng2.stats()["dropped"] == 1


def test_high_refresh_144hz_deadline_advances_per_vsync():
    eng = make(vsync_hz=144.0)
    first = eng.begin_frame("a")
    period = 1_000_000 / 144.0
    assert first["deadline_us"] == int(period)
    eng.advance(first["deadline_us"])
    second = eng.begin_frame("b")
    expected = int((math.floor(second["start_us"] / period) + 1) * period)
    assert second["deadline_us"] == expected


def test_clock_regression_changes_nothing():
    eng = make()
    eng.begin_frame("a")
    eng.advance(1000)
    with pytest.raises(fpg.FramePacerError) as exc:
        eng.advance(500)
    assert exc.value.code == "PAC_CLOCK_REGRESS"
    assert eng.now_us() == 1000
    assert eng.in_flight() == ["a"]
    assert eng.advance(2000) == 1000
    out = eng.end_frame("a")
    assert out["duration_us"] == 2000


def test_equal_timestamp_advance_is_noop():
    eng = make()
    assert eng.advance(1000) == 1000
    assert eng.advance(1000) == 0
    assert eng.now_us() == 1000


def test_downgrade_floored_at_min_fps():
    eng = make(min_fps=30.0)
    for index in range(12):
        eng.begin_frame("m%d" % index)
        eng.advance((index + 1) * 20000)
        eng.end_frame("m%d" % index)
    assert eng.adaptive_fps() == pytest.approx(30.0)


def test_upgrade_capped_at_configured_fps():
    eng = make(target_fps=45.0)
    for index in range(3):
        eng.begin_frame("bad%d" % index)
        eng.advance((index + 1) * 20000)
        eng.end_frame("bad%d" % index)
    assert eng.adaptive_fps() == pytest.approx(35.0)
    total = 0
    while eng.adaptive_fps() < 45.0:
        frame_id = "ok%d" % total
        eng.begin_frame(frame_id)
        eng.advance(eng.now_us() + 1000)
        result = eng.end_frame(frame_id)
        assert result["missed"] is False
        total += 1
        assert total < 1000
    assert eng.adaptive_fps() == pytest.approx(45.0)
    eng.begin_frame("more")
    eng.advance(eng.now_us() + 1000)
    eng.end_frame("more")
    assert eng.adaptive_fps() == pytest.approx(45.0)


def test_set_target_fps_resets_miss_streak():
    eng = make()
    for index in range(3):
        eng.begin_frame("bad%d" % index)
        eng.advance((index + 1) * 20000)
        eng.end_frame("bad%d" % index)
    assert eng.adaptive_fps() == pytest.approx(50.0)
    eng.set_target_fps(60.0)
    assert eng.adaptive_fps() == pytest.approx(60.0)
    eng.start(0)
    eng.begin_frame("one-miss")
    eng.advance(4000)
    eng.end_frame("one-miss")
    assert eng.adaptive_fps() == pytest.approx(60.0)


def test_configure_updates_vsync_and_caps_history():
    eng = make(vsync_hz=50.0)
    config = eng.configure()
    assert config["vsync_hz"] == 50.0
    out = eng.begin_frame("a")
    assert out["deadline_us"] == 20000
    eng.advance(1000)
    eng.end_frame("a")
    eng.configure(history=1)
    eng.begin_frame("b")
    eng.advance(2000)
    eng.end_frame("b")
    eng.begin_frame("c")
    eng.advance(3000)
    eng.end_frame("c")
    assert eng.percentile(100) == pytest.approx(1000.0)


def test_empty_stats_and_percentile():
    eng = make()
    stats = eng.stats()
    assert stats["frames"] == 0
    assert stats["miss_rate"] == 0.0
    assert stats["p95_us"] == 0.0
    assert stats["in_flight"] == 0
    assert eng.percentile(50) == 0.0


def test_restore_continues_counters_and_keeps_known_ids():
    eng = make()
    eng.begin_frame("a")
    eng.advance(4000)
    eng.end_frame("a")
    eng.begin_frame("b")
    assert eng.drop_frame("b") is True
    eng.begin_frame("c")
    eng.advance(6000)
    snap = json.loads(json.dumps(eng.snapshot()))

    eng.advance(50000)
    eng.end_frame("c")
    eng.begin_frame("extra")
    eng.end_frame("extra")

    eng.restore(snap)
    assert eng.now_us() == 6000
    assert eng.in_flight() == ["c"]
    stats = eng.stats()
    assert stats["frames"] == 2
    assert stats["presented"] == 1
    assert stats["dropped"] == 1
    assert eng.percentile(95) == pytest.approx(4000.0)

    out = eng.end_frame("c")
    assert out["duration_us"] == 2000
    assert eng.stats()["presented"] == 2

    with pytest.raises(fpg.FramePacerError) as exc:
        eng.begin_frame("a")
    assert exc.value.code == "PAC_FRAME_EXISTS"


def test_concurrent_lifecycle_under_inflight_limit():
    eng = make(max_in_flight=4)
    errors = []

    def worker(index):
        try:
            for step in range(20):
                frame_id = "t%d-%d" % (index, step)
                while True:
                    try:
                        eng.begin_frame(frame_id)
                        break
                    except fpg.FramePacerError as exc:
                        if exc.code != "PAC_INFLIGHT_LIMIT":
                            raise
                eng.end_frame(frame_id)
        except BaseException as exc:  # pragma: no cover - failure path
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    stats = eng.stats()
    assert stats["frames"] == 160
    assert stats["presented"] == 160
    assert stats["dropped"] == 0
    assert stats["in_flight"] == 0


def test_concurrent_present_and_drop_paths():
    eng = make(max_in_flight=8)
    errors = []

    def worker(index):
        try:
            for step in range(20):
                frame_id = "t%d-%d" % (index, step)
                while True:
                    try:
                        eng.begin_frame(frame_id)
                        break
                    except fpg.FramePacerError as exc:
                        if exc.code != "PAC_INFLIGHT_LIMIT":
                            raise
                if step % 2 == 0:
                    assert eng.drop_frame(frame_id) is True
                else:
                    eng.end_frame(frame_id)
        except BaseException as exc:  # pragma: no cover - failure path
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    stats = eng.stats()
    assert stats["frames"] == 160
    assert stats["presented"] == 80
    assert stats["dropped"] == 80
    assert stats["missed"] == 80
    assert stats["in_flight"] == 0


def test_snapshot_preserves_inflight_order():
    eng = make(max_in_flight=4)
    for frame_id in ("a", "b", "c"):
        eng.begin_frame(frame_id)
        eng.advance(1000)
    snap = json.loads(json.dumps(eng.snapshot()))
    restored = make()
    restored.restore(snap)
    assert restored.in_flight() == ["a", "b", "c"]
    out = restored.end_frame("a")
    assert out["start_us"] == 0
    assert out["deadline_us"] == 10000
