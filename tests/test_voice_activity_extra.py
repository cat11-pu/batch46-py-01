import json
import threading

import pytest

import voice_activity_guard as vag


def make(**kwargs):
    return vag.VoiceActivity(**kwargs)


def frame(value=0.0, size=320):
    return [value] * size


def test_quiet_room_noise_floor_keeps_silence():
    eng = make()
    eng.create_stream("room")
    eng.calibrate("room", [frame(0.003) for _ in range(8)])
    # A frame below the calibrated threshold must not open a segment.
    for _ in range(10):
        out = eng.feed("room", frame(0.005))
        assert out["speech"] is False
        assert out["segment"] is None
    assert eng.segments("room") == []
    assert eng.stats()["discarded"] == 0


def test_noisy_meeting_room_splits_speakers_with_hangover():
    eng = make(hangover_ms=60, min_speech_ms=60)
    eng.create_stream("meet")
    # Speaker A: four loud frames, one breath gap shorter than hangover,
    # speaker B: another four loud frames. Hangover must bridge the gap.
    for _ in range(4):
        eng.feed("meet", frame(0.5))
    eng.feed("meet", frame())
    for _ in range(4):
        eng.feed("meet", frame(0.4))
    for _ in range(4):
        eng.feed("meet", frame())
    segments = eng.segments("meet")
    assert len(segments) == 1
    assert segments[0]["speech_frames"] == 8
    assert segments[0]["start"] == 0


def test_single_streamer_long_silence_then_speech():
    eng = make()
    eng.create_stream("live")
    for _ in range(20):
        assert eng.feed("live", frame())["speech"] is False
    for _ in range(5):
        eng.feed("live", frame(0.5))
    for _ in range(12):
        eng.feed("live", frame())
    segments = eng.segments("live")
    assert len(segments) == 1
    assert segments[0]["start"] == 20
    assert segments[0]["speech_frames"] == 5
    stats = eng.stats()
    assert stats["frames"] == 37
    assert stats["speech_frames"] == 5
    assert stats["segments"] == 1


def test_concurrent_feeds_totals_exact_and_indices_ordered():
    eng = make(max_streams=8)
    stream_ids = ["c%d" % i for i in range(8)]
    for stream_id in stream_ids:
        eng.create_stream(stream_id)
    errors = []

    def worker(stream_id):
        try:
            for i in range(50):
                value = 0.5 if i % 3 else 0.0
                eng.feed(stream_id, frame(value))
        except BaseException as exc:  # pragma: no cover - failure path
            errors.append(exc)

    threads = [
        threading.Thread(target=worker, args=(stream_id,))
        for stream_id in stream_ids
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    stats = eng.stats()
    assert stats["frames"] == 400
    assert stats["speech_frames"] == 400 * 33 // 50
    for stream_id in stream_ids:
        assert eng.state(stream_id)["index"] == 49


def test_snapshot_restore_matches_uninterrupted_run():
    kwargs = {"min_speech_ms": 60, "hangover_ms": 60}
    reference = make(**kwargs)
    restored = make(**kwargs)
    reference.create_stream("s")
    restored.create_stream("s")
    for _ in range(3):
        reference.feed("s", frame(0.5))
        restored.feed("s", frame(0.5))
    reference.feed("s", frame())
    restored.feed("s", frame())
    snap = json.loads(json.dumps(restored.snapshot()))
    restored.restore(snap)
    state = restored.state("s")
    assert state["index"] == 3
    assert state["state"] == "hangover"
    assert state["hangover_left"] == 3
    for _ in range(3):
        reference.feed("s", frame())
        restored.feed("s", frame())
    assert restored.segments("s") == reference.segments("s")
    assert restored.stats() == reference.stats()


def test_feed_batch_rolls_back_on_invalid_sample():
    eng = make()
    eng.create_stream("s")
    bad = [1.5] * 320
    with pytest.raises(vag.VoiceActivityError) as exc:
        eng.feed_batch("s", [frame(0.5), bad])
    assert exc.value.code == "VAD_FRAME_INVALID"
    assert eng.stats()["frames"] == 0
    assert eng.state("s")["index"] == -1


def test_set_threshold_clears_calibrated_noise_floor():
    eng = make()
    eng.create_stream("s")
    eng.calibrate("s", [frame(0.003)])
    assert eng.state("s")["noise_floor_db"] is not None
    eng.set_threshold("s", -30.0)
    assert eng.state("s")["noise_floor_db"] is None
    assert eng.state("s")["threshold_db"] == -30.0


def test_close_segment_discards_unconfirmed_burst():
    eng = make(min_speech_ms=60)
    eng.create_stream("s")
    eng.feed("s", frame(0.5))
    closed = eng.close_segment("s")
    assert closed["closed"] is False
    assert closed["segment"] is None
    assert eng.segments("s") == []
    assert eng.stats()["discarded"] == 1
    assert eng.state("s")["state"] == "silence"
