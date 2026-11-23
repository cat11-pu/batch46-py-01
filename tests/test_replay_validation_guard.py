import copy
import threading

import pytest

import replay_validation_guard as rv


def make(**kwargs):
    return rv.ReplayValidator(**kwargs)


def frame(seq, tick=None, red=1, blue=0):
    return {
        "seq": seq,
        "tick": seq * 2 if tick is None else tick,
        "input": {"score": {"red": red, "blue": blue}},
    }


def frames(count, **kwargs):
    return [frame(index, **kwargs) for index in range(count)]


def record(v, raw):
    for item in raw:
        v.append(copy.deepcopy(item))


def test_identical_replays_produce_identical_digests():
    a = make()
    b = make()
    for validator in (a, b):
        validator.begin("m1", players=("zoe", "amy"))
        record(validator, frames(6))
    summary_a = a.finish()
    summary_b = b.finish()
    assert summary_a["final_digest"] == summary_b["final_digest"]
    assert len(summary_a["final_digest"]) == 64
    assert summary_a["frames"] == 6
    assert summary_a["players"] == ["amy", "zoe"]
    assert summary_a["match_id"] == "m1"
    assert summary_a["ruleset"] == "v1"


def test_header_changes_the_digest_and_mismatches_are_reported():
    v1 = make()
    v2 = make()
    v1.begin("m1", players=("amy",), ruleset="v1")
    v2.begin("m1", players=("amy",), ruleset="v2")
    record(v1, frames(4))
    record(v2, frames(4))
    assert v1.digest() != v2.digest()
    result = make().verify(v1.frames(), header=v2.header())
    assert result["ok"] is False
    assert result["code"] == "REPLAY_HEADER_MISMATCH"
    assert result["index"] == 0


def test_sequence_gaps_are_detected_at_the_offending_frame():
    v = make()
    header = v.begin("m1")
    record(v, frames(4))
    stored = v.frames()
    stored[2]["seq"] = 3
    result = make().verify(stored, header=header)
    assert result["ok"] is False
    assert result["code"] == "REPLAY_SEQ_GAP"
    assert result["index"] == 2
    broken = frames(3)
    broken[0]["seq"] = 5
    first = make().verify(broken, header=header)
    assert first["ok"] is False
    assert first["code"] == "REPLAY_SEQ_GAP"
    assert first["index"] == 0


def test_tick_regression_is_rejected_but_equal_ticks_are_allowed():
    v = make()
    header = v.begin("m1")
    record(v, [frame(0, tick=0), frame(1, tick=5), frame(2, tick=5)])
    assert make().verify(v.frames(), header=header)["ok"] is True
    stored = v.frames()
    stored[2]["tick"] = 1
    result = make().verify(stored, header=header)
    assert result["ok"] is False
    assert result["code"] == "REPLAY_TICK_REGRESS"
    assert result["index"] == 2


def test_tampered_frame_payload_breaks_the_hash_chain():
    v = make()
    header = v.begin("m1")
    record(v, frames(4))
    stored = v.frames()
    stored[2]["input"]["score"]["red"] = 999
    result = make().verify(stored, header=header)
    assert result["ok"] is False
    assert result["code"] == "REPLAY_CHECKSUM_MISMATCH"
    assert result["index"] == 2


def test_session_calls_require_an_open_recording():
    v = make()
    with pytest.raises(rv.ReplayError) as exc:
        v.append(frame(0))
    assert exc.value.code == "REPLAY_NO_SESSION"
    with pytest.raises(rv.ReplayError) as exc:
        v.finish()
    assert exc.value.code == "REPLAY_NO_SESSION"
    with pytest.raises(rv.ReplayError) as exc:
        v.digest()
    assert exc.value.code == "REPLAY_NO_SESSION"
    with pytest.raises(rv.ReplayError) as exc:
        v.checkpoint()
    assert exc.value.code == "REPLAY_NO_SESSION"
    with pytest.raises(rv.ReplayError) as exc:
        v.abort()
    assert exc.value.code == "REPLAY_NO_SESSION"
    v.begin("m1")
    v.append(frame(0))
    v.finish()
    with pytest.raises(rv.ReplayError) as exc:
        v.append(frame(1))
    assert exc.value.code == "REPLAY_NO_SESSION"
    with pytest.raises(rv.ReplayError) as exc:
        v.finish()
    assert exc.value.code == "REPLAY_NO_SESSION"


def test_rerecording_requires_finish_or_abort_and_gets_a_fresh_chain():
    v = make()
    v.begin("m1")
    with pytest.raises(rv.ReplayError) as exc:
        v.begin("m2")
    assert exc.value.code == "REPLAY_ACTIVE"
    v.append(frame(0))
    first = v.finish()
    v.begin("m2")
    v.append(frame(0))
    second = v.finish()
    assert first["match_id"] == "m1"
    assert second["match_id"] == "m2"
    assert first["final_digest"] != second["final_digest"]
    v.begin("m3")
    assert v.abort() is True
    with pytest.raises(rv.ReplayError) as exc:
        v.finish()
    assert exc.value.code == "REPLAY_NO_SESSION"
    v.begin("m4")
    v.append(frame(0))
    assert v.finish()["match_id"] == "m4"


def test_frame_limit_is_enforced_without_touching_the_chain():
    v = make(max_frames=3)
    v.begin("m1")
    record(v, frames(3))
    before = v.digest()
    with pytest.raises(rv.ReplayError) as exc:
        v.append(frame(3))
    assert exc.value.code == "REPLAY_FRAME_LIMIT"
    assert v.digest() == before
    assert len(v.frames()) == 3


def test_checkpoint_resume_continues_the_same_chain():
    raw = [frame(index, tick=index * 3, red=index % 2, blue=1)
           for index in range(8)]
    v = make()
    v.begin("m1", players=("amy", "zoe"), ruleset="v2")
    for item in raw[:3]:
        v.append(copy.deepcopy(item))
    checkpoint = v.checkpoint()
    for item in raw[3:]:
        v.append(copy.deepcopy(item))
    summary = v.finish()
    resumed = make()
    resumed.resume(checkpoint)
    for item in raw[3:]:
        resumed.append(copy.deepcopy(item))
    summary_two = resumed.finish()
    assert summary_two["final_digest"] == summary["final_digest"]
    assert summary_two["frames"] == 8
    assert summary_two["players"] == ["amy", "zoe"]
    assert summary_two["ruleset"] == "v2"


def test_tampered_checkpoint_and_busy_resume_are_rejected():
    v = make()
    v.begin("m1")
    record(v, frames(3))
    checkpoint = v.checkpoint()
    bad = copy.deepcopy(checkpoint)
    bad["frames"] = 99
    with pytest.raises(rv.ReplayError) as exc:
        make().resume(bad)
    assert exc.value.code == "REPLAY_CHECKPOINT_INVALID"
    busy = make()
    busy.begin("other")
    with pytest.raises(rv.ReplayError) as exc:
        busy.resume(checkpoint)
    assert exc.value.code == "REPLAY_ACTIVE"


def test_outcome_aggregates_scores_and_breaks_ties():
    v = make()
    v.begin("m1")
    v.append(frame(0, red=2, blue=0))
    v.append(frame(1, red=0, blue=3))
    v.append(frame(2, red=1, blue=0))
    drawn = v.outcome()
    assert drawn["scores"] == {"red": 3, "blue": 3}
    assert drawn["winner"] == "draw"
    u = make()
    u.begin("m2")
    u.append(frame(0, red=2, blue=0))
    u.append(frame(1, red=0, blue=1))
    won = u.outcome()
    assert won["scores"] == {"red": 2, "blue": 1}
    assert won["winner"] == "red"


def test_verify_rejects_empty_replays_and_accepts_valid_ones():
    v = make()
    header = v.begin("m1", players=("amy",))
    record(v, frames(5))
    stored = v.frames()
    final = v.digest()
    empty = make().verify([], header=header)
    assert empty["ok"] is False
    assert empty["code"] == "REPLAY_EMPTY"
    result = make().verify(stored, header=header)
    assert result["ok"] is True
    assert result["frames"] == 5
    assert result["digest"] == final


def test_frames_are_returned_as_isolated_copies():
    v = make()
    v.begin("m1")
    record(v, frames(5))
    final = v.digest()
    stored = v.frames()
    stored[0]["input"]["score"]["red"] = 999
    stored.append("junk")
    fresh = v.frames()
    assert len(fresh) == 5
    assert fresh[0]["input"]["score"]["red"] == 1
    assert v.digest() == final


def test_malformed_frames_are_rejected_before_they_enter_the_chain():
    v = make()
    v.begin("m1")
    with pytest.raises(rv.ReplayError) as exc:
        v.append({"seq": 0, "input": {}})
    assert exc.value.code == "REPLAY_FRAME_INVALID"
    with pytest.raises(rv.ReplayError) as exc:
        v.append("not-a-frame")
    assert exc.value.code == "REPLAY_FRAME_INVALID"
    with pytest.raises(rv.ReplayError) as exc:
        v.append({"seq": 1, "tick": 0, "input": {}})
    assert exc.value.code == "REPLAY_SEQ_GAP"
    assert len(v.frames()) == 0
    accepted = v.append({"seq": 0, "tick": 0, "input": {}})
    assert len(accepted["digest"]) == 64
    assert accepted["digest"] == v.digest()


def test_concurrent_verification_is_stable():
    v = make()
    v.begin("m1", players=("amy",))
    record(v, frames(30, red=2, blue=1))
    stored = v.frames()
    header = v.header()
    expected = v.digest()
    results = []
    errors = []
    lock = threading.Lock()

    def worker():
        try:
            result = v.verify(copy.deepcopy(stored),
                              header=copy.deepcopy(header))
            with lock:
                results.append(result)
        except Exception as exc:  # pragma: no cover - diagnostic path
            with lock:
                errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    assert len(results) == 6
    assert all(result["ok"] is True for result in results)
    assert {result["digest"] for result in results} == {expected}
