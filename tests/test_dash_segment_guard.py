import threading

import pytest

import dash_segment_guard as dsg


def make(**kwargs):
    return dsg.DashSegment(**kwargs)


def rep(p, name="hd", bandwidth=3000000, width=1920, height=1080):
    p.add_representation(name, bandwidth=bandwidth, width=width, height=height)


def test_align_computes_ms_boundaries_from_timescale():
    p = make(timescale=90000)
    rep(p)
    out = p.align_representation("hd", start_number=1,
                                 durations=[180000, 90000, 180000], timescale=90000)
    assert out["status"] == "applied"
    assert out["segment_count"] == 3
    first = p.segment_at("hd", 1)
    second = p.segment_at("hd", 2)
    third = p.segment_at("hd", 3)
    assert (first["start_ms"], first["end_ms"], first["duration_ms"]) == (0, 2000, 2000)
    assert (second["start_ms"], second["end_ms"]) == (2000, 3000)
    assert (third["start_ms"], third["end_ms"]) == (3000, 5000)
    assert first["uri"] == "hd/seg-1.m4s"


def test_segment_at_rejects_unknown_and_expired_numbers():
    p = make()
    rep(p)
    p.align_representation("hd", start_number=1, durations=[2000, 2000, 2000])
    with pytest.raises(dsg.DashError) as exc:
        p.segment_at("hd", 99)
    assert exc.value.code == "DASH_SEGMENT_UNKNOWN"
    assert p.expire_before(2) == 1
    with pytest.raises(dsg.DashError) as exc:
        p.segment_at("hd", 1)
    assert exc.value.code == "DASH_SEGMENT_EXPIRED"
    assert p.segment_at("hd", 2)["start_ms"] == 2000


def test_align_rejects_bad_durations_atomically():
    p = make()
    rep(p)
    with pytest.raises(dsg.DashError) as exc:
        p.align_representation("hd", start_number=1, durations=[2000, 0, 2000])
    assert exc.value.code == "DASH_BAD_SEGMENT"
    with pytest.raises(dsg.DashError) as exc:
        p.segment_at("hd", 1)
    assert exc.value.code == "DASH_REP_UNAVAILABLE"
    out = p.align_representation("hd", start_number=1, durations=[2000, 2000])
    assert out["status"] == "applied"
    assert p.segment_at("hd", 2)["end_ms"] == 4000
    assert p.stats()["alignments"] == 1


def test_segment_limit_and_start_number():
    p = make(max_segments=3)
    rep(p)
    with pytest.raises(dsg.DashError) as exc:
        p.align_representation("hd", start_number=1, durations=[1000, 1000, 1000, 1000])
    assert exc.value.code == "DASH_SEGMENT_LIMIT"
    out = p.align_representation("hd", start_number=5, durations=[2000, 2000])
    assert out["start_number"] == 5
    assert p.segment_at("hd", 5)["start_ms"] == 0
    assert p.segment_at("hd", 6)["start_ms"] == 2000
    with pytest.raises(dsg.DashError) as exc:
        p.segment_at("hd", 4)
    assert exc.value.code == "DASH_SEGMENT_EXPIRED"


def test_duplicate_bad_and_unknown_representations():
    p = make(max_representations=2)
    rep(p, "a")
    with pytest.raises(dsg.DashError) as exc:
        p.add_representation("a", bandwidth=1000)
    assert exc.value.code == "DASH_REP_DUP"
    with pytest.raises(dsg.DashError) as exc:
        p.add_representation("bad", bandwidth=0)
    assert exc.value.code == "DASH_BAD_REP"
    rep(p, "b")
    with pytest.raises(dsg.DashError) as exc:
        p.add_representation("c", bandwidth=1000)
    assert exc.value.code == "DASH_REP_LIMIT"
    with pytest.raises(dsg.DashError) as exc:
        p.segment_at("ghost", 1)
    assert exc.value.code == "DASH_REP_UNKNOWN"


def test_segment_for_time_half_open_boundaries():
    p = make()
    rep(p)
    p.align_representation("hd", start_number=1, durations=[2000, 1000, 2000])
    assert p.segment_for_time("hd", 0)["number"] == 1
    assert p.segment_for_time("hd", 1999)["number"] == 1
    assert p.segment_for_time("hd", 2000)["number"] == 2
    assert p.segment_for_time("hd", 3000)["number"] == 3
    assert p.segment_for_time("hd", 4999)["number"] == 3
    assert p.segment_for_time("hd", 5000) is None
    with pytest.raises(dsg.DashError) as exc:
        p.segment_for_time("hd", -1)
    assert exc.value.code == "DASH_BAD_TIME"


def test_gap_report_lists_missing_numbers():
    p = make()
    rep(p)
    p.align_representation("hd", start_number=1, durations=[1000, 1000, 1000])
    assert p.gap_report("hd", [1, 2, 3, 5]) == [5]
    assert p.gap_report("hd", [0, 2, 4]) == [0, 4]
    assert p.gap_report("hd", [1, 2, 3]) == []


def test_alignment_report_detects_boundary_mismatch():
    p = make()
    rep(p, "a")
    rep(p, "b")
    rep(p, "c")
    p.align_representation("a", start_number=1, durations=[2000, 2000, 2000])
    p.align_representation("b", start_number=1, durations=[1500, 2500, 2000])
    p.align_representation("c", start_number=1, durations=[2000, 2000, 2000])
    mismatch = p.alignment_report("a", "b")
    assert mismatch["aligned"] is False
    assert mismatch["mismatch_ms"] == 1500
    matched = p.alignment_report("a", "c")
    assert matched["aligned"] is True
    assert matched["mismatch_ms"] is None
    assert matched["a_segments"] == 3


def test_switch_requires_shared_boundary():
    p = make()
    rep(p, "a")
    rep(p, "b")
    p.align_representation("a", start_number=1, durations=[2000, 2000, 2000])
    p.align_representation("b", start_number=1, durations=[1500, 2500, 2000])
    with pytest.raises(dsg.DashError) as exc:
        p.switch_representation("a", "b", at_number=2)
    assert exc.value.code == "DASH_SWITCH_MISALIGN"
    out = p.switch_representation("a", "b", at_number=3)
    assert out["status"] == "switched"
    assert out["number"] == 3
    assert out["start_ms"] == 4000
    assert p.current() == {"representation": "b", "number": 3, "start_ms": 4000}
    assert p.stats()["switches"] == 1


def test_switch_rejects_unaligned_and_missing_segments():
    p = make()
    rep(p, "a")
    rep(p, "b")
    p.align_representation("a", start_number=1, durations=[2000, 2000])
    with pytest.raises(dsg.DashError) as exc:
        p.switch_representation("a", "b", at_number=1)
    assert exc.value.code == "DASH_REP_UNAVAILABLE"
    with pytest.raises(dsg.DashError) as exc:
        p.switch_representation("a", "ghost", at_number=1)
    assert exc.value.code == "DASH_REP_UNKNOWN"
    with pytest.raises(dsg.DashError) as exc:
        p.switch_representation("a", "a", at_number=9)
    assert exc.value.code == "DASH_SEGMENT_UNKNOWN"


def test_timescale_is_locked_and_realign_rebuilds_window():
    p = make()
    rep(p)
    p.align_representation("hd", start_number=1, durations=[2000, 2000], timescale=1000)
    with pytest.raises(dsg.DashError) as exc:
        p.align_representation("hd", start_number=1, durations=[180000], timescale=90000)
    assert exc.value.code == "DASH_TIMESCALE_LOCK"
    out = p.align_representation("hd", start_number=1, durations=[1000, 1000])
    assert out["status"] == "applied"
    assert p.segment_at("hd", 1)["end_ms"] == 1000
    assert p.segment_at("hd", 2)["start_ms"] == 1000
    assert p.stats()["alignments"] == 2


def test_realign_with_lower_start_number_is_ignored():
    p = make()
    rep(p)
    p.align_representation("hd", start_number=5, durations=[2000])
    out = p.align_representation("hd", start_number=3, durations=[1000, 1000, 1000])
    assert out["status"] == "ignored"
    assert out["code"] == "DASH_SEQ_REGRESS"
    assert out["start_number"] == 5
    assert p.segment_at("hd", 5)["end_ms"] == 2000
    with pytest.raises(dsg.DashError) as exc:
        p.segment_at("hd", 3)
    assert exc.value.code == "DASH_SEGMENT_EXPIRED"
    applied = p.align_representation("hd", start_number=5, durations=[1000, 1000])
    assert applied["status"] == "applied"
    assert p.segment_at("hd", 6)["start_ms"] == 1000
    assert p.stats()["ignored"] == 1


def test_expire_before_trims_all_representations():
    p = make()
    rep(p, "a")
    rep(p, "b")
    p.align_representation("a", start_number=1, durations=[2000, 2000, 2000, 2000])
    p.align_representation("b", start_number=1, durations=[2000, 2000, 2000, 2000])
    removed = p.expire_before(3)
    assert removed == 4
    assert p.stats()["expired"] == 4
    assert p.segment_at("a", 3)["start_ms"] == 4000
    assert p.segment_at("b", 3)["start_ms"] == 4000
    assert p.segment_at("a", 4)["end_ms"] == 8000
    with pytest.raises(dsg.DashError) as exc:
        p.segment_at("b", 2)
    assert exc.value.code == "DASH_SEGMENT_EXPIRED"


def test_snapshot_restore_roundtrip_and_bad_version():
    p = make()
    rep(p, "a")
    rep(p, "b")
    p.align_representation("a", start_number=1, durations=[2000, 2000])
    p.align_representation("b", start_number=1, durations=[2000, 2000])
    p.switch_representation("a", "b", at_number=2)
    snap = p.snapshot()
    fresh = make()
    fresh.restore(snap)
    assert fresh.current() == {"representation": "b", "number": 2, "start_ms": 2000}
    assert fresh.segment_at("a", 1)["end_ms"] == 2000
    assert fresh.stats()["restores"] == 1
    assert fresh.alignment_report("a", "b")["aligned"] is True
    bad = p.snapshot()
    bad["version"] = 7
    with pytest.raises(dsg.DashError) as exc:
        fresh.restore(bad)
    assert exc.value.code == "DASH_SNAPSHOT_INVALID"
    assert fresh.current()["number"] == 2


def test_concurrent_alignments_are_atomic():
    p = make(max_representations=8)
    names = ["r%d" % i for i in range(6)]
    for name in names:
        rep(p, name, bandwidth=100000)
    results = []
    guard = threading.Lock()
    snapshots = []
    stop = threading.Event()

    def worker(name):
        out = p.align_representation(name, start_number=1, durations=[1000, 2000, 1000])
        with guard:
            results.append(out)

    def reader():
        while not stop.is_set():
            snap = p.snapshot()
            for name in names:
                row = snap["representations"].get(name)
                if row and row["durations"]:
                    snapshots.append((name, tuple(row["durations"])))

    threads = [threading.Thread(target=worker, args=(name,)) for name in names]
    watch = threading.Thread(target=reader)
    watch.start()
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    stop.set()
    watch.join()

    assert len(results) == 6
    assert all(row["status"] == "applied" for row in results)
    assert p.stats()["alignments"] == 6
    boundaries = set()
    for name in names:
        seg = p.segment_at(name, 2)
        boundaries.add((seg["start_ms"], seg["end_ms"]))
    assert boundaries == {(1000, 3000)}
    assert all(durations == (1000, 2000, 1000) for _, durations in snapshots)
