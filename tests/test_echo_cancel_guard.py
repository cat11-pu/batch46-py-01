import json
import math
import threading

import pytest

import echo_cancel_guard as ecg


def make(**kwargs):
    options = {"max_sessions": 8, "max_push_samples": 4096,
               "filter_len": 128, "max_delay_ms": 50.0}
    options.update(kwargs)
    return ecg.EchoCancel(**options)


def pattern(count=64):
    return [0.35 * math.sin(i * 0.7) + 0.25 * math.sin(i * 2.9)
            + 0.15 * math.cos(i * 1.3) + 0.1 * math.sin(i * 0.31)
            for i in range(count)]


def test_reference_ring_keeps_newest_and_counts_drops():
    eng = make(filter_len=8)
    eng.create_session("s")
    first = eng.push_reference("s", [1.0, 2.0, 3.0, 4.0, 5.0, 6.0])
    assert first["buffered"] == 6
    assert first["dropped"] == 0
    second = eng.push_reference("s", [7.0, 8.0, 1.0, 2.0])
    assert second["dropped"] == 2
    assert second["total_dropped"] == 2
    assert second["buffered"] == 8
    assert eng.reference("s") == [3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 1.0, 2.0]
    assert eng.reference("s", 3) == [8.0, 1.0, 2.0]


def test_push_over_budget_is_rejected_atomically():
    eng = make(max_push_samples=16)
    eng.create_session("s")
    with pytest.raises(ecg.EchoCancelError) as exc:
        eng.push_reference("s", [0.1] * 17)
    assert exc.value.code == "ECH_BUDGET_EXCEEDED"
    assert eng.reference("s") == []
    assert eng.stats("s")["pushed_samples"] == 0
    eng.push_reference("s", [0.1] * 16)
    assert eng.stats("s")["pushed_samples"] == 16


def test_empty_and_non_numeric_samples_rejected():
    eng = make()
    eng.create_session("s")
    with pytest.raises(ecg.EchoCancelError) as exc:
        eng.push_reference("s", [])
    assert exc.value.code == "ECH_SAMPLES_INVALID"
    with pytest.raises(ecg.EchoCancelError) as exc:
        eng.push_capture("s", ["loud"])
    assert exc.value.code == "ECH_SAMPLES_INVALID"
    with pytest.raises(ecg.EchoCancelError) as exc:
        eng.push_reference("s", [float("nan")])
    assert exc.value.code == "ECH_SAMPLES_INVALID"


def test_alignment_finds_injected_delay():
    eng = make()
    eng.create_session("s")
    data = pattern()
    eng.push_reference("s", data)
    eng.push_capture("s", data[43:59])
    result = eng.align("s")
    assert result["aligned"] is True
    assert result["delay"] == 5
    assert result["score"] == pytest.approx(1.0, abs=1e-6)
    assert eng.delay_samples("s") == 5


def test_alignment_returns_hint_when_insufficient():
    eng = make()
    created = eng.create_session("s", delay_hint_ms=10.0)
    assert created["delay_samples"] == 160
    result = eng.align("s")
    assert result["aligned"] is False
    assert result["delay"] == 160
    assert result["score"] == pytest.approx(0.0)
    assert result["candidates"] == 0


def test_alignment_picks_zero_for_tail_capture():
    eng = make()
    eng.create_session("s")
    data = pattern()
    eng.push_reference("s", data)
    eng.push_capture("s", data[48:64])
    result = eng.align("s")
    assert result["aligned"] is True
    assert result["delay"] == 0
    assert result["score"] > 0.99


def test_set_delay_validates_range():
    eng = make()
    eng.create_session("s")
    with pytest.raises(ecg.EchoCancelError) as exc:
        eng.set_delay("s", -1)
    assert exc.value.code == "ECH_DELAY_RANGE"
    with pytest.raises(ecg.EchoCancelError) as exc:
        eng.set_delay("s", 801)
    assert exc.value.code == "ECH_DELAY_RANGE"
    eng.set_delay("s", 100)
    assert eng.delay_samples("s") == 100


def test_capture_without_reference_reports_underrun():
    eng = make()
    eng.create_session("s")
    out = eng.push_capture("s", [0.1] * 16)
    assert out["underrun"] is True
    assert out["buffered_ref"] == 0
    assert eng.stats("s")["underruns"] == 1
    eng.push_reference("s", [0.1] * 32)
    again = eng.push_capture("s", [0.1] * 16)
    assert again["underrun"] is False
    assert eng.stats("s")["underruns"] == 1


def test_double_talk_detected_with_loud_capture():
    eng = make()
    eng.create_session("s")
    eng.push_reference("s", [0.1] * 64)
    eng.push_capture("s", [0.3] * 16)
    assert eng.double_talk("s") is True
    eng.push_capture("s", [0.15] * 16)
    assert eng.double_talk("s") is False


def test_reference_level_db_floor_and_value():
    eng = make()
    eng.create_session("s")
    assert eng.reference_level_db("s") == pytest.approx(-180.0)
    eng.push_reference("s", [0.5] * 8)
    assert eng.reference_level_db("s") == pytest.approx(-6.021, abs=0.01)


def test_session_capacity_and_close_frees_slot():
    eng = make(max_sessions=2)
    eng.create_session("a")
    eng.create_session("b")
    with pytest.raises(ecg.EchoCancelError) as exc:
        eng.create_session("c")
    assert exc.value.code == "ECH_SESSION_LIMIT"
    with pytest.raises(ecg.EchoCancelError) as exc:
        eng.create_session("a")
    assert exc.value.code == "ECH_SESSION_EXISTS"
    assert eng.close_session("ghost") is False
    assert eng.close_session("b") is True
    eng.create_session("c")
    assert eng.sessions() == ["a", "c"]


def test_unknown_session_errors():
    eng = make()
    eng.create_session("s")
    for call in (lambda: eng.push_reference("ghost", [0.1]),
                 lambda: eng.align("ghost"),
                 lambda: eng.stats("ghost"),
                 lambda: eng.reference("ghost")):
        with pytest.raises(ecg.EchoCancelError) as exc:
            call()
        assert exc.value.code == "ECH_SESSION_UNKNOWN"


def test_flush_clears_buffer_but_keeps_counters():
    eng = make()
    eng.create_session("s")
    eng.push_capture("s", [0.1] * 16)
    eng.push_reference("s", [0.5] * 8)
    assert eng.reference_level_db("s") == pytest.approx(-6.021, abs=0.01)
    flushed = eng.flush("s")
    assert flushed["flushed"] == 8
    assert flushed["buffered"] == 0
    assert eng.reference("s") == []
    assert eng.reference_level_db("s") == pytest.approx(-180.0)
    stats = eng.stats("s")
    assert stats["pushed_samples"] == 8
    assert stats["underruns"] == 1


def test_snapshot_restore_preserves_reference_and_delay():
    eng = make()
    eng.create_session("s")
    data = pattern()
    eng.push_reference("s", data)
    eng.push_capture("s", data[43:59])
    snap = json.loads(json.dumps(eng.snapshot()))
    eng.push_reference("s", [0.0] * 20)
    eng.push_capture("s", [0.0] * 16)
    eng.restore(snap)
    assert eng.reference("s") == data
    result = eng.align("s")
    assert result["aligned"] is True
    assert result["delay"] == 5
    assert eng.stats("s")["pushed_samples"] == 64


def test_concurrent_pushes_do_not_lose_samples():
    eng = make(max_sessions=8, filter_len=64, max_push_samples=64)
    for index in range(8):
        eng.create_session("s%d" % index)
    errors = []

    def worker(index):
        try:
            for _ in range(50):
                eng.push_reference("s%d" % index, [0.01 * (index + 1)])
        except BaseException as exc:  # pragma: no cover - failure path
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    for index in range(8):
        stats = eng.stats("s%d" % index)
        assert stats["pushed_samples"] == 50
        assert stats["buffered"] == 50
