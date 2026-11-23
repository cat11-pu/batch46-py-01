import threading

import pytest

import hls_playlist_guard as hpg


def make(**kwargs):
    return hpg.HlsPlaylist(**kwargs)


def seg(uri, duration=4.0, discontinuity=False):
    return {"uri": uri, "duration": duration, "discontinuity": discontinuity}


def playlist(prefix, count, duration=4.0):
    return [seg("%s-%d.ts" % (prefix, i), duration) for i in range(count)]


def test_register_variant_validates_and_reports_unknown():
    p = make()
    info = p.register_variant("a", bandwidth=800000, codecs="avc1.4d401f,mp4a.40.2",
                              resolution=(1280, 720))
    assert info["variant"] == "a"
    assert info["bandwidth"] == 800000
    assert info["resolution"] == (1280, 720)
    assert p.variant_info("a")["codecs"] == "avc1.4d401f,mp4a.40.2"
    with pytest.raises(hpg.HlsError) as exc:
        p.register_variant("a", bandwidth=900000)
    assert exc.value.code == "HLS_VARIANT_DUP"
    with pytest.raises(hpg.HlsError) as exc:
        p.register_variant("b", bandwidth=0)
    assert exc.value.code == "HLS_BAD_VARIANT"
    with pytest.raises(hpg.HlsError) as exc:
        p.variant_info("ghost")
    assert exc.value.code == "HLS_VARIANT_UNKNOWN"


def test_variant_limit_is_enforced():
    p = make(max_variants=2)
    p.register_variant("a", bandwidth=100000)
    p.register_variant("b", bandwidth=200000)
    with pytest.raises(hpg.HlsError) as exc:
        p.register_variant("c", bandwidth=300000)
    assert exc.value.code == "HLS_VARIANT_LIMIT"
    assert p.variant_info("b")["bandwidth"] == 200000


def test_duration_drift_rejects_update_atomically():
    p = make(target_duration=6.0)
    p.register_variant("a", bandwidth=100000)
    with pytest.raises(hpg.HlsError) as exc:
        p.update_media_playlist("a", media_sequence=0, segments=[seg("x.ts", 6.5)])
    assert exc.value.code == "HLS_DURATION_DRIFT"
    assert p.segments("a") == []
    assert p.stats()["updates_applied"] == 0
    out = p.update_media_playlist("a", media_sequence=0, segments=[seg("y.ts", 6.0)])
    assert out["status"] == "applied"
    assert [row["uri"] for row in p.segments("a")] == ["y.ts"]


def test_window_oversize_is_rejected_without_partial_state():
    p = make(window_size=3, target_duration=10.0)
    p.register_variant("a", bandwidth=100000)
    with pytest.raises(hpg.HlsError) as exc:
        p.update_media_playlist("a", media_sequence=0, segments=playlist("a", 4))
    assert exc.value.code == "HLS_WINDOW_OVERSIZE"
    assert p.segments("a") == []
    out = p.update_media_playlist("a", media_sequence=0, segments=playlist("a", 3))
    assert out["segment_count"] == 3


def test_media_sequence_regression_is_ignored():
    p = make(target_duration=10.0)
    p.register_variant("a", bandwidth=100000)
    p.update_media_playlist("a", media_sequence=0, segments=playlist("a", 2))
    out = p.update_media_playlist("a", media_sequence=1, segments=[seg("stale.ts")])
    assert out["status"] == "ignored"
    assert out["code"] == "HLS_SEQ_REGRESS"
    assert out["media_sequence"] == 2
    assert [row["uri"] for row in p.segments("a")] == ["a-0.ts", "a-1.ts"]
    assert p.stats()["updates_ignored"] == 1


def test_media_sequence_gap_is_ignored_until_contiguous():
    p = make(target_duration=10.0)
    p.register_variant("a", bandwidth=100000)
    p.update_media_playlist("a", media_sequence=0, segments=[seg("a-0.ts")])
    gap = p.update_media_playlist("a", media_sequence=5, segments=[seg("a-5.ts")])
    assert gap["status"] == "ignored"
    assert gap["code"] == "HLS_SEQ_GAP"
    assert gap["media_sequence"] == 1
    out = p.update_media_playlist("a", media_sequence=1, segments=[seg("a-1.ts")])
    assert out["status"] == "applied"
    assert [row["media_sequence"] for row in p.segments("a")] == [0, 1]


def test_sliding_window_trims_numbers_and_expiry():
    p = make(window_size=3, target_duration=10.0)
    p.register_variant("a", bandwidth=100000)
    p.update_media_playlist("a", media_sequence=0, segments=playlist("a", 3))
    out = p.update_media_playlist("a", media_sequence=3, segments=playlist("b", 2))
    assert out["trimmed"] == 2
    assert out["trimmed_uris"] == ["a-0.ts", "a-1.ts"]
    rows = p.segments("a")
    assert [row["uri"] for row in rows] == ["a-2.ts", "b-0.ts", "b-1.ts"]
    assert [row["media_sequence"] for row in rows] == [2, 3, 4]
    assert p.expire_before(4) == 2
    assert [row["media_sequence"] for row in p.segments("a")] == [4]
    assert p.stats()["expired"] == 2


def test_switch_requires_discontinuity_when_codecs_differ():
    p = make(target_duration=10.0)
    p.register_variant("a", bandwidth=100000, codecs="avc1.4d401f,mp4a.40.2")
    p.register_variant("b", bandwidth=900000, codecs="avc1.4d401f,ac-3")
    out = p.switch_variant("a", "b", at_sequence=0)
    assert out["status"] == "switched"
    assert out["discontinuity"] is True
    assert p.current()["variant"] == "b"
    assert p.pending_discontinuity("b") is True
    p.update_media_playlist("b", media_sequence=0,
                            segments=[seg("b-0.ts"), seg("b-1.ts")])
    rows = p.segments("b")
    assert rows[0]["discontinuity"] is True
    assert rows[1]["discontinuity"] is False
    assert p.pending_discontinuity("b") is False


def test_switch_with_same_codecs_needs_no_discontinuity():
    p = make(target_duration=10.0)
    p.register_variant("a", bandwidth=100000, codecs="avc1.4d401f,mp4a.40.2")
    p.register_variant("b", bandwidth=400000, codecs="avc1.4d401f,mp4a.40.2")
    out = p.switch_variant("a", "b", at_sequence=0)
    assert out["discontinuity"] is False
    assert p.pending_discontinuity("b") is False
    p.update_media_playlist("b", media_sequence=0, segments=[seg("b-0.ts")])
    assert p.segments("b")[0]["discontinuity"] is False


def test_switch_thrash_budget_same_variant_and_unknown():
    p = make(switch_budget=2, target_duration=10.0)
    p.register_variant("a", bandwidth=100000)
    p.register_variant("b", bandwidth=200000)
    p.switch_variant("a", "b", at_sequence=0)
    p.switch_variant("b", "a", at_sequence=0)
    with pytest.raises(hpg.HlsError) as exc:
        p.switch_variant("a", "b", at_sequence=0)
    assert exc.value.code == "HLS_SWITCH_THRASH"
    with pytest.raises(hpg.HlsError) as exc:
        p.switch_variant("a", "a", at_sequence=0)
    assert exc.value.code == "HLS_SWITCH_SAME"
    with pytest.raises(hpg.HlsError) as exc:
        p.switch_variant("a", "ghost", at_sequence=0)
    assert exc.value.code == "HLS_VARIANT_UNKNOWN"
    p.update_media_playlist("a", media_sequence=0, segments=playlist("a", 3))
    out = p.switch_variant("a", "b", at_sequence=3)
    assert out["status"] == "switched"
    assert p.stats()["switches"] == 3


def test_stats_are_copies_and_close_blocks_writes():
    p = make(target_duration=10.0)
    p.register_variant("a", bandwidth=100000)
    p.update_media_playlist("a", media_sequence=0, segments=[seg("x.ts")])
    snapshot = p.stats()
    assert snapshot["updates_applied"] == 1
    snapshot["updates_applied"] = 99
    assert p.stats()["updates_applied"] == 1
    p.close()
    p.close()
    with pytest.raises(hpg.HlsError) as exc:
        p.update_media_playlist("a", media_sequence=1, segments=[seg("y.ts")])
    assert exc.value.code == "HLS_CLOSED"
    assert [row["uri"] for row in p.segments("a")] == ["x.ts"]


def test_snapshot_restore_roundtrip_preserves_pending_state():
    p = make(window_size=4, target_duration=10.0)
    p.register_variant("a", bandwidth=100000, codecs="avc1.4d401f,mp4a.40.2")
    p.register_variant("b", bandwidth=900000, codecs="avc1.4d401f,ac-3")
    p.update_media_playlist("a", media_sequence=0, segments=playlist("a", 2))
    p.switch_variant("a", "b", at_sequence=2)
    snap = p.snapshot()
    fresh = make()
    fresh.restore(snap)
    assert fresh.current()["variant"] == "b"
    assert fresh.pending_discontinuity("b") is True
    assert [row["uri"] for row in fresh.segments("a")] == ["a-0.ts", "a-1.ts"]
    assert fresh.stats()["restores"] == 1
    fresh.update_media_playlist("b", media_sequence=0, segments=[seg("b-0.ts")])
    assert fresh.segments("b")[0]["discontinuity"] is True


def test_restore_rejects_bad_snapshot_without_mutation():
    p = make(target_duration=10.0)
    p.register_variant("a", bandwidth=100000)
    p.update_media_playlist("a", media_sequence=0, segments=[seg("keep.ts")])
    bad = p.snapshot()
    bad["version"] = 99
    with pytest.raises(hpg.HlsError) as exc:
        p.restore(bad)
    assert exc.value.code == "HLS_SNAPSHOT_INVALID"
    broken = p.snapshot()
    broken["state"] = ["not-a-dict"]
    with pytest.raises(hpg.HlsError) as exc:
        p.restore(broken)
    assert exc.value.code == "HLS_SNAPSHOT_INVALID"
    assert [row["uri"] for row in p.segments("a")] == ["keep.ts"]
    assert p.variant_info("a")["bandwidth"] == 100000


def test_concurrent_updates_keep_contiguous_window():
    p = make(window_size=6, target_duration=10.0)
    p.register_variant("a", bandwidth=100000)
    results = []
    guard = threading.Lock()

    def worker(seq):
        out = p.update_media_playlist(
            "a", media_sequence=seq, segments=[seg("s%d.ts" % seq)], target_duration=10.0)
        with guard:
            results.append(out)

    threads = [threading.Thread(target=worker, args=(i,)) for i in (7, 3, 0, 5, 1, 6, 2, 4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    applied = [row for row in results if row["status"] == "applied"]
    ignored = [row for row in results if row["status"] == "ignored"]
    assert len(applied) + len(ignored) == 8
    assert len(applied) >= 1
    assert p.stats()["updates_applied"] == len(applied)
    assert p.stats()["updates_ignored"] == len(ignored)
    assert max(row["media_sequence"] for row in applied) == len(applied)
    rows = p.segments("a")
    assert len(rows) == min(len(applied), 6)
    assert [row["media_sequence"] for row in rows] == list(
        range(len(applied) - len(rows), len(applied)))


def test_concurrent_snapshots_are_internally_consistent():
    p = make(window_size=4, target_duration=10.0)
    p.register_variant("a", bandwidth=100000)
    p.update_media_playlist("a", media_sequence=0, segments=playlist("a", 4))
    errors = []
    stop = threading.Event()

    def writer():
        seq = 4
        for _ in range(40):
            p.update_media_playlist("a", media_sequence=seq,
                                    segments=[seg("w%d.ts" % seq)], target_duration=10.0)
            seq += 1
        stop.set()

    def reader():
        while not stop.is_set():
            snap = p.snapshot()
            state = snap["state"]["a"]
            rows = state["segments"]
            if len(rows) > 4:
                errors.append("window")
            numbers = [row["media_sequence"] for row in rows]
            if numbers and numbers != list(range(numbers[0], numbers[0] + len(numbers))):
                errors.append("contiguous")
            if rows and state["media_sequence"] != numbers[-1] + 1:
                errors.append("sequence")
            replay = make()
            replay.restore(snap)
            if replay.segments("a") != rows:
                errors.append("replay")

    threads = [threading.Thread(target=writer)]
    threads += [threading.Thread(target=reader) for _ in range(3)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert p.stats()["updates_applied"] == 41
    assert len(p.segments("a")) == 4
