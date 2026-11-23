import json
import threading

import pytest

import frame_pacing_guard as fpg


def make(**kwargs):
    options = {"target_fps": 60.0, "vsync_hz": 100.0, "max_late_ms": 8.0,
               "max_in_flight": 4, "history": 240, "min_fps": 30.0}
    options.update(kwargs)
    return fpg.FramePacer(**options)


def test_begin_frame_deadline_is_next_vsync_boundary():
    eng = make()
    first = eng.begin_frame("a")
    assert first["start_us"] == 0
    assert first["deadline_us"] == 10000
    eng.advance(5000)
    second = eng.begin_frame("b")
    assert second["start_us"] == 5000
    assert second["deadline_us"] == 10000
    eng.advance(10000)
    third = eng.begin_frame("c")
    assert third["start_us"] == 10000
    assert third["deadline_us"] == 20000


def test_end_frame_within_deadline_is_present():
    eng = make()
    eng.begin_frame("a")
    eng.advance(4000)
    out = eng.end_frame("a")
    assert out["duration_us"] == 4000
    assert out["late_us"] == -6000
    assert out["missed"] is False
    assert out["action"] == "present"
    assert out["target_fps"] == pytest.approx(60.0)


def test_end_frame_after_deadline_is_missed():
    eng = make()
    eng.begin_frame("a")
    eng.advance(12000)
    out = eng.end_frame("a")
    assert out["late_us"] == 2000
    assert out["missed"] is True
    assert out["action"] == "present"
    assert eng.stats()["missed"] == 1


def test_very_late_frame_is_dropped():
    eng = make()
    eng.begin_frame("a")
    eng.advance(25000)
    out = eng.end_frame("a")
    assert out["late_us"] == 15000
    assert out["action"] == "drop"
    assert out["target_fps"] == pytest.approx(60.0)
    assert eng.stats()["dropped"] == 1
    assert eng.percentile(95) == pytest.approx(0.0)


def test_unknown_and_duplicate_frames():
    eng = make()
    with pytest.raises(fpg.FramePacerError) as exc:
        eng.end_frame("ghost")
    assert exc.value.code == "PAC_FRAME_UNKNOWN"
    eng.begin_frame("a")
    with pytest.raises(fpg.FramePacerError) as exc:
        eng.begin_frame("a")
    assert exc.value.code == "PAC_FRAME_EXISTS"
    eng.end_frame("a")
    with pytest.raises(fpg.FramePacerError) as exc:
        eng.begin_frame("a")
    assert exc.value.code == "PAC_FRAME_EXISTS"
    eng.begin_frame("b")
    assert eng.drop_frame("b") is True
    assert eng.drop_frame("ghost") is False
    assert eng.in_flight() == []
    stats = eng.stats()
    assert stats["dropped"] == 1
    assert stats["missed"] == 1
    assert stats["frames"] == 2


def test_in_flight_capacity_enforced():
    eng = make(max_in_flight=2)
    eng.begin_frame("a")
    eng.begin_frame("b")
    assert eng.in_flight() == ["a", "b"]
    with pytest.raises(fpg.FramePacerError) as exc:
        eng.begin_frame("c")
    assert exc.value.code == "PAC_INFLIGHT_LIMIT"
    eng.advance(1000)
    eng.end_frame("a")
    eng.begin_frame("c")
    assert eng.in_flight() == ["b", "c"]


def test_clock_regression_rejected():
    eng = make()
    assert eng.advance(1000) == 1000
    with pytest.raises(fpg.FramePacerError) as exc:
        eng.advance(500)
    assert exc.value.code == "PAC_CLOCK_REGRESS"
    assert eng.now_us() == 1000


def test_percentile_nearest_rank():
    eng = make(vsync_hz=1.0)
    for frame_id, now in (("a", 1000), ("b", 3000),
                          ("c", 6000), ("d", 10000)):
        eng.begin_frame(frame_id)
        eng.advance(now)
        eng.end_frame(frame_id)
    assert eng.percentile(0) == pytest.approx(1000)
    assert eng.percentile(50) == pytest.approx(2000)
    assert eng.percentile(95) == pytest.approx(4000)


def test_history_is_capped():
    eng = make(vsync_hz=1.0, history=3)
    for index, now in enumerate((1000, 3000, 6000, 10000, 15000)):
        frame_id = "f%d" % index
        eng.begin_frame(frame_id)
        eng.advance(now)
        eng.end_frame(frame_id)
    assert eng.stats()["frames"] == 5
    assert eng.percentile(0) == pytest.approx(3000)
    assert eng.percentile(100) == pytest.approx(5000)


def test_miss_streak_reduces_target_fps():
    eng = make()
    for index in range(3):
        frame_id = "m%d" % index
        eng.begin_frame(frame_id)
        eng.advance((index + 1) * 20000)
        result = eng.end_frame(frame_id)
        assert result["action"] == "drop"
    assert eng.adaptive_fps() == pytest.approx(50.0)
    assert eng.stats()["dropped"] == 3


def test_stable_frames_raise_target_fps_to_configured_cap():
    eng = make()
    for index in range(3):
        eng.begin_frame("bad%d" % index)
        eng.advance((index + 1) * 20000)
        eng.end_frame("bad%d" % index)
    assert eng.adaptive_fps() == pytest.approx(50.0)
    for index in range(120):
        eng.begin_frame("ok%d" % index)
        eng.advance(60000 + (index + 1) * 1000)
        result = eng.end_frame("ok%d" % index)
        assert result["missed"] is False
    assert eng.adaptive_fps() == pytest.approx(55.0)
    for index in range(120):
        eng.begin_frame("ok2-%d" % index)
        eng.advance(180000 + (index + 1) * 1000)
        result = eng.end_frame("ok2-%d" % index)
        assert result["missed"] is False
    assert eng.adaptive_fps() == pytest.approx(60.0)


def test_set_target_fps_range_and_cap():
    eng = make()
    for bad in (0, -1, 1000, 10):
        with pytest.raises(fpg.FramePacerError) as exc:
            eng.set_target_fps(bad)
        assert exc.value.code == "PAC_FPS_RANGE"
    eng.set_target_fps(75.0)
    assert eng.adaptive_fps() == pytest.approx(75.0)
    for index in range(3):
        eng.begin_frame("bad%d" % index)
        eng.advance((index + 1) * 20000)
        eng.end_frame("bad%d" % index)
    assert eng.adaptive_fps() == pytest.approx(65.0)


def test_stats_counts_and_miss_rate():
    eng = make()
    eng.begin_frame("a")
    eng.advance(1000)
    eng.end_frame("a")
    eng.begin_frame("b")
    eng.advance(2000)
    eng.end_frame("b")
    eng.begin_frame("c")
    eng.advance(14000)
    eng.end_frame("c")
    eng.begin_frame("d")
    eng.advance(34000)
    eng.end_frame("d")
    stats = eng.stats()
    assert stats["frames"] == 4
    assert stats["presented"] == 3
    assert stats["dropped"] == 1
    assert stats["missed"] == 2
    assert stats["miss_rate"] == pytest.approx(0.5)
    assert stats["p95_us"] == pytest.approx(12000)


def test_snapshot_restore_via_json():
    eng = make()
    eng.begin_frame("a")
    eng.advance(4000)
    eng.begin_frame("b")
    eng.advance(5000)
    eng.end_frame("b")
    snap = json.loads(json.dumps(eng.snapshot()))
    eng.advance(10000)
    eng.begin_frame("c")
    eng.advance(11000)
    eng.end_frame("c")
    eng.restore(snap)
    assert eng.now_us() == 5000
    assert eng.in_flight() == ["a"]
    assert eng.stats()["frames"] == 1
    out = eng.end_frame("a")
    assert out["duration_us"] == 5000
    assert out["missed"] is False
    assert out["action"] == "present"


def test_concurrent_frame_lifecycle_is_counted():
    eng = make(max_in_flight=256, history=512)
    errors = []

    def worker(index):
        try:
            for step in range(20):
                frame_id = "t%d-%d" % (index, step)
                eng.begin_frame(frame_id)
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
    assert stats["missed"] == 0
    assert stats["in_flight"] == 0
