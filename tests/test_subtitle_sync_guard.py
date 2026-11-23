import threading

import pytest

import subtitle_sync_guard as ssg


def make(**kwargs):
    return ssg.SubtitleSync(**kwargs)


def cue(start, end, text="line"):
    return {"start_ms": start, "end_ms": end, "text": text}


def three_cues():
    return [cue(0, 1000, "one"), cue(1000, 1500, "two"), cue(2000, 2500, "three")]


def test_load_rejects_overlap_transactionally():
    p = make()
    assert p.load_cues([cue(0, 1000, "a"), cue(1000, 2000, "b")]) == 2
    with pytest.raises(ssg.SubtitleError) as exc:
        p.load_cues([cue(0, 1000, "a"), cue(900, 2000, "b")])
    assert exc.value.code == "SUB_OVERLAP"
    assert [row["text"] for row in p.window(0, 5000)] == ["a", "b"]
    assert p.stats()["loads"] == 1


def test_load_rejects_unsorted_negative_and_short_cues():
    p = make()
    with pytest.raises(ssg.SubtitleError) as exc:
        p.load_cues([cue(1000, 2000, "a"), cue(500, 1500, "b")])
    assert exc.value.code == "SUB_ORDER"
    with pytest.raises(ssg.SubtitleError) as exc:
        p.load_cues([cue(-100, 500, "a")])
    assert exc.value.code == "SUB_BAD_CUE"
    with pytest.raises(ssg.SubtitleError) as exc:
        p.load_cues([cue(0, 100, "short")])
    assert exc.value.code == "SUB_BAD_CUE"
    assert p.window(0, 10000) == []
    assert p.load_cues([cue(0, 500, "ok")]) == 1


def test_load_enforces_limit_and_replaces_document():
    p = make(max_cues=2)
    with pytest.raises(ssg.SubtitleError) as exc:
        p.load_cues([cue(0, 500), cue(500, 1000), cue(1000, 1500)])
    assert exc.value.code == "SUB_LIMIT"
    assert p.load_cues([cue(0, 500, "a"), cue(500, 1000, "b")]) == 2
    assert p.load_cues([cue(3000, 4000, "fresh")]) == 1
    assert [row["text"] for row in p.window(0, 5000)] == ["fresh"]
    assert p.window(0, 3000) == []


def test_cue_at_uses_half_open_intervals():
    p = make()
    p.load_cues([cue(0, 1000, "a"), cue(1000, 2000, "b")])
    assert p.cue_at(0)["text"] == "a"
    assert p.cue_at(999)["text"] == "a"
    assert p.cue_at(1000)["text"] == "b"
    assert p.cue_at(1999)["text"] == "b"
    assert p.cue_at(2000) is None
    assert p.cue_at(-1) is None


def test_shift_moves_all_cues_and_rejects_negative_start():
    p = make()
    p.load_cues([cue(1000, 2000, "a"), cue(2000, 3000, "b")])
    assert p.shift(500) == 500
    rows = p.window(0, 5000)
    assert [(row["start_ms"], row["end_ms"]) for row in rows] == [(1500, 2500), (2500, 3500)]
    with pytest.raises(ssg.SubtitleError) as exc:
        p.shift(-2000)
    assert exc.value.code == "SUB_NEGATIVE_TIME"
    assert p.cue_at(1500)["text"] == "a"
    assert p.stats()["shifts"] == 1


def test_shift_is_bounded_by_absolute_and_cumulative_limits():
    p = make(max_shift_ms=1000)
    p.load_cues([cue(1000, 2000, "a")])
    assert p.shift(800) == 800
    with pytest.raises(ssg.SubtitleError) as exc:
        p.shift(400)
    assert exc.value.code == "SUB_SHIFT_LIMIT"
    with pytest.raises(ssg.SubtitleError) as exc:
        p.shift(-1200)
    assert exc.value.code == "SUB_SHIFT_LIMIT"
    assert p.window(0, 5000)[0]["start_ms"] == 1800


def test_retime_fps_scales_with_rounding():
    p = make()
    p.load_cues([cue(1000, 3000, "a")])
    out = p.retime_fps(23.976, 25.0)
    assert out["status"] == "applied"
    assert out["scale"] == pytest.approx(0.95904, abs=1e-9)
    row = p.window(0, 5000)[0]
    assert row["start_ms"] == 959
    assert row["end_ms"] == 2877
    assert p.stats()["retimes"] == 1


def test_retime_same_pair_is_idempotent_and_other_pair_composes():
    p = make()
    p.load_cues([cue(1000, 3000, "a")])
    p.retime_fps(23.976, 25.0)
    again = p.retime_fps(23.976, 25.0)
    assert again["status"] == "ignored"
    assert again["code"] == "SUB_RETIME_DUP"
    assert p.window(0, 5000)[0]["start_ms"] == 959
    assert p.stats()["retimes"] == 1
    assert p.stats()["ignored"] == 1
    out = p.retime_fps(25.0, 50.0)
    assert out["status"] == "applied"
    row = p.window(0, 5000)[0]
    assert row["start_ms"] == 480
    assert row["end_ms"] == 1439


def test_retime_failure_is_transactional():
    p = make(min_duration_ms=500)
    p.load_cues([cue(0, 600, "a")])
    with pytest.raises(ssg.SubtitleError) as exc:
        p.retime_fps(25.0, 50.0)
    assert exc.value.code == "SUB_BAD_CUE"
    assert p.window(0, 5000)[0]["end_ms"] == 600
    assert p.stats()["retimes"] == 0
    assert p.retime_fps(25.0, 25.0)["status"] == "applied"


def test_merge_overlaps_chains_and_renumbers():
    p = make()
    p.load_cues(three_cues())
    assert p.merge_overlaps(0) == 1
    rows = p.window(0, 5000)
    assert len(rows) == 2
    assert rows[0]["text"] == "one\ntwo"
    assert (rows[0]["start_ms"], rows[0]["end_ms"]) == (0, 1500)
    assert rows[1]["text"] == "three"
    assert [row["index"] for row in rows] == [0, 1]
    assert p.merge_overlaps(500) == 1
    rows = p.window(0, 5000)
    assert len(rows) == 1
    assert rows[0]["text"] == "one\ntwo\nthree"
    assert (rows[0]["start_ms"], rows[0]["end_ms"]) == (0, 2500)
    with pytest.raises(ssg.SubtitleError) as exc:
        p.merge_overlaps(-1)
    assert exc.value.code == "SUB_BAD_ARG"


def test_split_cue_renumbers_and_validates_halves():
    p = make()
    p.load_cues([cue(0, 2000, "a"), cue(2000, 3000, "b")])
    out = p.split_cue(0, 1000)
    assert out == {"first": 0, "second": 1, "count": 3}
    rows = p.window(0, 5000)
    assert [(row["start_ms"], row["end_ms"], row["text"]) for row in rows] == [
        (0, 1000, "a"), (1000, 2000, "a"), (2000, 3000, "b")]
    assert [row["index"] for row in rows] == [0, 1, 2]
    with pytest.raises(ssg.SubtitleError) as exc:
        p.split_cue(0, 100)
    assert exc.value.code == "SUB_BAD_CUE"
    with pytest.raises(ssg.SubtitleError) as exc:
        p.split_cue(99, 500)
    assert exc.value.code == "SUB_INDEX_UNKNOWN"
    assert p.stats()["splits"] == 1


def test_window_returns_intersecting_cues_only():
    p = make()
    p.load_cues([cue(0, 1000, "a"), cue(2000, 3000, "b")])
    assert p.window(1000, 2000) == []
    assert [row["text"] for row in p.window(999, 2001)] == ["a", "b"]
    assert [row["text"] for row in p.window(0, 1000)] == ["a"]
    assert [row["text"] for row in p.window(1500, 2500)] == ["b"]
    with pytest.raises(ssg.SubtitleError) as exc:
        p.window(1000, 1000)
    assert exc.value.code == "SUB_BAD_ARG"


def test_validate_reports_clean_state_and_stats_are_copies():
    p = make()
    p.load_cues(three_cues())
    assert p.validate() == []
    stats = p.stats()
    stats["loads"] = 42
    assert p.stats()["loads"] == 1
    p.close()
    p.close()


def test_snapshot_restore_roundtrip_and_bad_version():
    p = make()
    p.load_cues(three_cues())
    p.shift(500)
    p.retime_fps(25.0, 50.0)
    snap = p.snapshot()
    fresh = make()
    fresh.restore(snap)
    assert fresh.window(0, 5000) == p.window(0, 5000)
    assert fresh.stats()["restores"] == 1
    assert fresh.retime_fps(25.0, 50.0)["code"] == "SUB_RETIME_DUP"
    bad = p.snapshot()
    bad["version"] = 9
    with pytest.raises(ssg.SubtitleError) as exc:
        fresh.restore(bad)
    assert exc.value.code == "SUB_SNAPSHOT_INVALID"
    broken = p.snapshot()
    broken["cues"] = "not-a-list"
    with pytest.raises(ssg.SubtitleError) as exc:
        fresh.restore(broken)
    assert exc.value.code == "SUB_SNAPSHOT_INVALID"
    assert len(fresh.window(0, 10000)) == 3
    assert fresh.stats()["restores"] == 1


def test_concurrent_readers_never_see_torn_shift():
    p = make()
    base = [cue(0, 1000, "a"), cue(2000, 3000, "b"), cue(4000, 5000, "c")]
    p.load_cues(base)
    errors = []
    stop = threading.Event()

    def writer():
        for _ in range(20):
            p.shift(100)
        stop.set()

    def reader():
        while not stop.is_set():
            snap = p.snapshot()
            offsets = {row["start_ms"] - base[i]["start_ms"]
                       for i, row in enumerate(snap["cues"])}
            if len(offsets) != 1 or offsets.pop() != snap["offset_ms"]:
                errors.append("torn")
            moment = p.cue_at(2500)
            if moment is not None and not (moment["start_ms"] <= 2500 < moment["end_ms"]):
                errors.append("cue")

    threads = [threading.Thread(target=writer)]
    threads += [threading.Thread(target=reader) for _ in range(3)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert p.stats()["shifts"] == 20
    assert p.window(0, 10000)[0]["start_ms"] == 2000
