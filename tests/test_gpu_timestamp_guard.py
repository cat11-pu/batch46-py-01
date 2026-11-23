import threading

import pytest

import gpu_timestamp_guard as gts


def make(**kwargs):
    return gts.GpuTimestamp(**kwargs)


def record(a, frame_id, total, start=0):
    a.begin_frame(frame_id)
    a.write_timestamp(frame_id, "begin", start)
    a.write_timestamp(frame_id, "end", start + total)
    return a.end_frame(frame_id)


def test_stage_durations_and_frame_total():
    a = make()
    a.begin_frame(1)
    for stage, ticks in (
        ("begin", 1000),
        ("shadow", 1100),
        ("main", 1300),
        ("post", 1400),
        ("end", 1500),
    ):
        a.write_timestamp(1, stage, ticks)
    stats = a.end_frame(1)
    assert stats["completed"] is True
    assert stats["stages"] == ["begin", "shadow", "main", "post", "end"]
    assert stats["durations_ns"] == {
        "begin": 0,
        "shadow": 100,
        "main": 200,
        "post": 100,
        "end": 100,
    }
    assert stats["gpu_ns"] == 500
    assert a.frame_stats(1)["gpu_ns"] == 500
    assert a.frames() == [1]


def test_out_of_order_stage_is_rejected_without_corrupting_frame():
    a = make()
    a.begin_frame(1)
    a.write_timestamp(1, "begin", 1000)
    a.write_timestamp(1, "main", 1200)
    a.write_timestamp(1, "end", 1500)
    with pytest.raises(gts.GpuTimestampError) as exc:
        a.write_timestamp(1, "post", 1600)
    assert exc.value.code == "GTS_STAGE_ORDER"
    live = a.frame_stats(1)
    assert live["stages"] == ["begin", "main", "end"]
    assert live["durations_ns"] == {}
    assert live["gpu_ns"] == 0
    stats = a.end_frame(1)
    assert stats["durations_ns"] == {"begin": 0, "main": 200, "end": 300}
    assert stats["gpu_ns"] == 500


def test_duplicate_and_unknown_stage_are_rejected():
    a = make()
    a.begin_frame(1)
    a.write_timestamp(1, "begin", 0)
    with pytest.raises(gts.GpuTimestampError) as exc:
        a.write_timestamp(1, "begin", 10)
    assert exc.value.code == "GTS_DUP_STAGE"
    with pytest.raises(gts.GpuTimestampError) as exc:
        a.write_timestamp(1, "frag", 20)
    assert exc.value.code == "GTS_UNKNOWN_STAGE"
    assert a.frame_stats(1)["stages"] == ["begin"]


def test_non_wrap_tick_rewind_is_rejected():
    a = make()
    a.begin_frame(1)
    a.write_timestamp(1, "begin", 1000)
    a.write_timestamp(1, "main", 1500)
    with pytest.raises(gts.GpuTimestampError) as exc:
        a.write_timestamp(1, "end", 1400)
    assert exc.value.code == "GTS_TIME_REWIND"
    assert a.frame_stats(1)["stages"] == ["begin", "main"]
    a.write_timestamp(1, "post", 1600)
    stats = a.end_frame(1)
    assert stats["gpu_ns"] == 600
    assert stats["durations_ns"]["post"] == 100


def test_48_bit_tick_wrap_is_unrolled_to_positive_duration():
    a = make(wrap_bits=48)
    a.begin_frame(1)
    a.write_timestamp(1, "begin", 2 ** 48 - 100)
    second = a.write_timestamp(1, "main", 2 ** 48 - 20)
    third = a.write_timestamp(1, "end", 50)
    assert second["ticks"] == 2 ** 48 - 20
    assert third["ticks"] == 2 ** 48 + 50
    assert third["wrap_count"] == 1
    stats = a.end_frame(1)
    assert stats["gpu_ns"] == 150
    assert stats["durations_ns"] == {"begin": 0, "main": 80, "end": 70}
    assert stats["wrap_count"] == 1


def test_calibration_converts_ticks_to_nanoseconds():
    a = make()
    calibrated = a.calibrate(2_000_000, 500_000)
    assert calibrated["ticks_per_ns"] == 4.0
    assert a.tick_rate() == 4.0
    a.begin_frame(1)
    a.write_timestamp(1, "begin", 0)
    a.write_timestamp(1, "main", 800)
    a.write_timestamp(1, "end", 1600)
    stats = a.end_frame(1)
    assert stats["durations_ns"] == {"begin": 0, "main": 200, "end": 200}
    assert stats["gpu_ns"] == 400
    with pytest.raises(gts.GpuTimestampError) as exc:
        a.calibrate(0, 100)
    assert exc.value.code == "GTS_CALIBRATION_INVALID"


def test_unknown_and_closed_frame_errors():
    a = make()
    with pytest.raises(gts.GpuTimestampError) as exc:
        a.write_timestamp(9, "begin", 1)
    assert exc.value.code == "GTS_UNKNOWN_FRAME"
    with pytest.raises(gts.GpuTimestampError) as exc:
        a.end_frame(9)
    assert exc.value.code == "GTS_UNKNOWN_FRAME"
    record(a, 1, 10)
    with pytest.raises(gts.GpuTimestampError) as exc:
        a.begin_frame(1)
    assert exc.value.code == "GTS_FRAME_CLOSED"
    with pytest.raises(gts.GpuTimestampError) as exc:
        a.write_timestamp(1, "main", 20)
    assert exc.value.code == "GTS_FRAME_CLOSED"
    with pytest.raises(gts.GpuTimestampError) as exc:
        a.end_frame(1)
    assert exc.value.code == "GTS_FRAME_CLOSED"


def test_query_slot_is_reused_only_after_frame_retires():
    a = make(query_pool_size=2, max_frames_in_flight=4)
    first = a.begin_frame(1)
    second = a.begin_frame(2)
    assert (first["slot"], second["slot"]) == (0, 1)
    with pytest.raises(gts.GpuTimestampError) as exc:
        a.begin_frame(3)
    assert exc.value.code == "GTS_POOL_EXHAUSTED"
    a.end_frame(1)
    third = a.begin_frame(3)
    assert third["slot"] == 0
    assert a.pool_usage() == {"slots": 2, "in_flight": 2, "free": 0}


def test_frames_in_flight_limit_is_enforced():
    a = make(query_pool_size=8, max_frames_in_flight=2)
    a.begin_frame(1)
    a.begin_frame(2)
    with pytest.raises(gts.GpuTimestampError) as exc:
        a.begin_frame(3)
    assert exc.value.code == "GTS_FRAME_BUSY"
    a.end_frame(1)
    a.begin_frame(3)
    assert a.pool_usage()["in_flight"] == 2


def test_percentiles_use_nearest_rank_over_frame_totals():
    a = make()
    for frame_id, total in ((2, 20), (1, 10), (3, 30), (4, 40)):
        record(a, frame_id, total)
    stats = a.percentiles()
    assert stats["count"] == 4
    assert stats["p50"] == 20
    assert stats["p95"] == 40
    assert stats["p99"] == 40
    assert stats["frames"] == [1, 2, 3, 4]


def test_incomplete_frame_is_excluded_from_percentiles():
    a = make()
    record(a, 1, 100)
    a.begin_frame(2)
    a.write_timestamp(2, "begin", 0)
    a.write_timestamp(2, "main", 50)
    stats = a.end_frame(2, completed=False)
    assert stats["completed"] is False
    assert stats["gpu_ns"] == 0
    assert stats["durations_ns"] == {}
    assert a.frame_stats(2)["completed"] is False
    result = a.percentiles()
    assert result["count"] == 1
    assert result["p50"] == 100
    assert result["frames"] == [1]
    assert a.pool_usage()["in_flight"] == 0


def test_concurrent_frame_recording_keeps_durations_separate():
    a = make(query_pool_size=16, max_frames_in_flight=8)
    errors = []

    def worker(frame_id):
        try:
            a.begin_frame(frame_id)
            a.write_timestamp(frame_id, "begin", frame_id * 1000)
            a.write_timestamp(frame_id, "main", frame_id * 1000 + 100)
            a.write_timestamp(frame_id, "end", frame_id * 1000 + 300)
            a.end_frame(frame_id)
        except Exception as exc:  # pragma: no cover - collected below
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(1, 7)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    for frame_id in range(1, 7):
        assert a.frame_stats(frame_id)["gpu_ns"] == 300
    assert a.percentiles()["count"] == 6
    assert a.percentiles()["p50"] == 300


def test_concurrent_begin_of_same_frame_allows_one_winner():
    a = make()
    barrier = threading.Barrier(2)
    results = []

    def worker():
        barrier.wait()
        try:
            a.begin_frame(7)
            results.append("ok")
        except gts.GpuTimestampError as exc:
            results.append(exc.code)
        except Exception as exc:  # pragma: no cover - collected below
            results.append(str(exc))

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(results) == ["GTS_DUP_FRAME", "ok"]
    a.write_timestamp(7, "begin", 0)
    a.end_frame(7)
    assert a.frames() == [7]


def test_snapshot_restore_keeps_completed_history_and_drops_open_frames():
    a = make()
    record(a, 1, 10)
    record(a, 2, 20)
    record(a, 3, 30)
    a.begin_frame(4)
    a.write_timestamp(4, "begin", 0)
    snapshot = a.snapshot()
    b = make()
    assert b.restore(snapshot) == {"restored": 3}
    assert b.percentiles()["p95"] == 30
    assert b.frames() == [1, 2, 3]
    assert b.pool_usage() == {"slots": 64, "in_flight": 0, "free": 64}
    b.begin_frame(4)
    assert b.pool_usage()["in_flight"] == 1


def test_invalid_snapshot_is_rejected_and_pool_usage_tracks_slots():
    a = make(query_pool_size=4, max_frames_in_flight=2)
    a.begin_frame(1)
    assert a.pool_usage() == {"slots": 4, "in_flight": 1, "free": 3}
    record(a, 2, 50)
    assert a.pool_usage() == {"slots": 4, "in_flight": 1, "free": 3}
    with pytest.raises(gts.GpuTimestampError) as exc:
        a.restore({"version": 0})
    assert exc.value.code == "GTS_SNAPSHOT_INVALID"
    with pytest.raises(gts.GpuTimestampError) as exc:
        a.restore("nope")
    assert exc.value.code == "GTS_SNAPSHOT_INVALID"
    assert a.pool_usage() == {"slots": 4, "in_flight": 1, "free": 3}
    assert a.frame_stats(1)["stages"] == []
