import json
import threading

import pytest

import voice_activity_guard as vag


def make(**kwargs):
    return vag.VoiceActivity(**kwargs)


def frame(value=0.0, size=320):
    return [value] * size


def test_frame_size_must_match_stream_rate():
    eng = make()
    created = eng.create_stream("s", sample_rate=16000)
    assert created["frame_size"] == 320
    assert eng.frame_size("s") == 320
    with pytest.raises(vag.VoiceActivityError) as exc:
        eng.feed("s", frame(size=100))
    assert exc.value.code == "VAD_FRAME_SIZE"
    out = eng.feed("s", frame())
    assert out["energy_db"] == pytest.approx(-180.0)


def test_silent_frame_energy_floor_and_state():
    eng = make()
    eng.create_stream("s")
    out = eng.feed("s", frame())
    assert out["energy_db"] == pytest.approx(-180.0)
    assert out["speech"] is False
    assert out["state"] == "silence"
    assert out["segment"] is None
    snap = eng.state("s")
    assert snap["index"] == 0
    assert snap["state"] == "silence"


def test_loud_frame_starts_segment_at_min_speech():
    eng = make(min_speech_ms=60)
    eng.create_stream("s")
    first = eng.feed("s", frame(0.5))
    second = eng.feed("s", frame(0.5))
    assert first["speech"] is True
    assert first["segment"] is None
    assert second["segment"] is None
    third = eng.feed("s", frame(0.5))
    assert third["energy_db"] == pytest.approx(-6.021, abs=0.01)
    assert third["state"] == "speech"
    assert third["segment"] == 1


def test_hangover_keeps_speech_true_for_configured_frames():
    eng = make(hangover_ms=60, min_speech_ms=20)
    eng.create_stream("s")
    eng.feed("s", frame(0.5))
    results = [eng.feed("s", frame()) for _ in range(4)]
    assert [row["state"] for row in results] == [
        "hangover", "hangover", "hangover", "silence"]
    assert [row["speech"] for row in results] == [True, True, True, False]


def test_segment_recorded_with_start_end_and_frame_count():
    eng = make(hangover_ms=60, min_speech_ms=60)
    eng.create_stream("s")
    for _ in range(4):
        eng.feed("s", frame(0.5))
    for _ in range(4):
        eng.feed("s", frame())
    assert eng.segments("s") == [
        {"id": 1, "start": 0, "end": 6, "frames": 7, "speech_frames": 4}]


def test_short_burst_is_discarded():
    eng = make(hangover_ms=40, min_speech_ms=60)
    eng.create_stream("s")
    eng.feed("s", frame(0.5))
    for _ in range(3):
        eng.feed("s", frame())
    assert eng.segments("s") == []
    stats = eng.stats()
    assert stats["segments"] == 0
    assert stats["discarded"] == 1


def test_threshold_change_affects_next_frame():
    eng = make()
    eng.create_stream("s")
    quiet = eng.feed("s", frame(0.01))
    assert quiet["energy_db"] == pytest.approx(-40.0, abs=0.01)
    assert quiet["speech"] is False
    changed = eng.set_threshold("s", -45.0)
    assert changed["threshold_db"] == pytest.approx(-45.0)
    loud_enough = eng.feed("s", frame(0.01))
    assert loud_enough["speech"] is True
    assert loud_enough["state"] == "speech"


def test_calibration_sets_effective_threshold():
    eng = make()
    eng.create_stream("s")
    calibrated = eng.calibrate("s", [frame(0.003) for _ in range(4)])
    assert calibrated["noise_floor_db"] == pytest.approx(-50.458, abs=0.01)
    assert calibrated["threshold_db"] == pytest.approx(-41.458, abs=0.01)
    below = eng.feed("s", frame(0.005))
    assert below["speech"] is False
    above = eng.feed("s", frame(0.01))
    assert above["speech"] is True
    assert eng.state("s")["noise_floor_db"] == pytest.approx(-50.458, abs=0.01)


def test_threshold_range_and_unknown_stream_errors():
    eng = make()
    eng.create_stream("s")
    with pytest.raises(vag.VoiceActivityError) as exc:
        eng.set_threshold("s", -120.0)
    assert exc.value.code == "VAD_THRESHOLD_RANGE"
    with pytest.raises(vag.VoiceActivityError) as exc:
        eng.feed("ghost", frame())
    assert exc.value.code == "VAD_STREAM_UNKNOWN"
    with pytest.raises(vag.VoiceActivityError) as exc:
        eng.state("ghost")
    assert exc.value.code == "VAD_STREAM_UNKNOWN"


def test_stream_capacity_and_drop_frees_slot():
    eng = make(max_streams=2)
    eng.create_stream("a")
    eng.create_stream("b")
    with pytest.raises(vag.VoiceActivityError) as exc:
        eng.create_stream("c")
    assert exc.value.code == "VAD_STREAM_LIMIT"
    with pytest.raises(vag.VoiceActivityError) as exc:
        eng.create_stream("a")
    assert exc.value.code == "VAD_STREAM_EXISTS"
    assert eng.drop_stream("ghost") is False
    assert eng.drop_stream("b") is True
    eng.create_stream("c")
    assert eng.streams() == ["a", "c"]


def test_feed_batch_atomic_on_bad_frame():
    eng = make()
    eng.create_stream("s")
    with pytest.raises(vag.VoiceActivityError) as exc:
        eng.feed_batch("s", [frame(0.5), frame(size=100)])
    assert exc.value.code == "VAD_FRAME_SIZE"
    assert eng.stats()["frames"] == 0
    assert eng.state("s")["index"] == -1


def test_invalid_sample_value_rejected():
    eng = make()
    eng.create_stream("s")
    with pytest.raises(vag.VoiceActivityError) as exc:
        eng.feed("s", frame(1.5))
    assert exc.value.code == "VAD_FRAME_INVALID"
    with pytest.raises(vag.VoiceActivityError) as exc:
        eng.feed("s", [float("nan")] * 320)
    assert exc.value.code == "VAD_FRAME_INVALID"
    assert eng.stats()["frames"] == 0


def test_close_segment_forces_finalize():
    eng = make(min_speech_ms=60, hangover_ms=200)
    eng.create_stream("s")
    for _ in range(3):
        eng.feed("s", frame(0.5))
    eng.feed("s", frame())
    closed = eng.close_segment("s")
    assert closed["closed"] is True
    assert closed["segment"] == {
        "id": 1, "start": 0, "end": 3, "frames": 4, "speech_frames": 3}
    assert eng.state("s")["state"] == "silence"
    again = eng.close_segment("s")
    assert again["closed"] is False
    assert again["segment"] is None


def test_snapshot_restore_preserves_hangover():
    eng = make(min_speech_ms=60, hangover_ms=60)
    eng.create_stream("s")
    for _ in range(3):
        eng.feed("s", frame(0.5))
    eng.feed("s", frame())
    snap = json.loads(json.dumps(eng.snapshot()))
    eng.feed("s", frame())
    eng.feed("s", frame())
    eng.feed("s", frame())
    assert eng.segments("s") == [
        {"id": 1, "start": 0, "end": 5, "frames": 6, "speech_frames": 3}]
    eng.restore(snap)
    state = eng.state("s")
    assert state["index"] == 3
    assert state["state"] == "hangover"
    assert eng.segments("s") == []
    for _ in range(3):
        eng.feed("s", frame())
    assert eng.segments("s") == [
        {"id": 1, "start": 0, "end": 5, "frames": 6, "speech_frames": 3}]


def test_concurrent_feeds_are_serialized():
    eng = make(max_streams=8)
    for index in range(8):
        eng.create_stream("s%d" % index)
    errors = []

    def worker(index):
        try:
            for _ in range(8):
                eng.feed("s%d" % index, frame(0.05))
        except BaseException as exc:  # pragma: no cover - failure path
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    stats = eng.stats()
    assert stats["frames"] == 64
    assert stats["speech_frames"] == 64
    for index in range(8):
        assert eng.state("s%d" % index)["index"] == 7
