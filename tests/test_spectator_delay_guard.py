import threading
from datetime import datetime

import pytest

import spectator_delay_guard as tbg


def make(**kwargs):
    return tbg.SpectatorDelay(**kwargs)


def frame(seq, occurred_at):
    return {"seq": seq, "occurred_at": occurred_at, "payload": {"n": seq}}


def ts(value):
    return datetime.fromisoformat(value).timestamp()


def test_frame_is_held_until_delay_elapses():
    s = make(delay_seconds=30)
    s.subscribe("v1", match="m1")
    s.ingest("m1", frame(1, "2026-11-23T10:00:00+00:00"))
    assert s.poll("v1", now="2026-11-23T10:00:20+00:00") == []
    out = s.poll("v1", now="2026-11-23T10:00:31+00:00")
    assert [row["seq"] for row in out] == [1]
    assert out[0]["payload"] == {"n": 1}


def test_delay_change_applies_only_to_later_frames():
    s = make(delay_seconds=30)
    s.subscribe("v1", match="m1")
    s.ingest("m1", frame(1, "2026-11-23T10:00:00+00:00"))
    s.set_delay("m1", 0)
    s.ingest("m1", frame(2, "2026-11-23T10:00:20+00:00"))
    marks = {row["seq"]: row["deadline_ts"] for row in s.timeline("m1")}
    assert marks[1] == ts("2026-11-23T10:00:30+00:00")
    assert marks[2] == ts("2026-11-23T10:00:20+00:00")
    assert s.poll("v1", now="2026-11-23T10:00:29+00:00") == []
    out = s.poll("v1", now="2026-11-23T10:00:31+00:00")
    assert [row["seq"] for row in out] == [1, 2]


def test_duplicate_sequence_ingest_is_ignored():
    s = make(delay_seconds=0)
    s.subscribe("v1", match="m1")
    first = s.ingest("m1", frame(1, "2026-11-23T10:00:00+00:00"))
    second = s.ingest("m1", frame(1, "2026-11-23T10:00:00+00:00"))
    assert first["status"] == "applied"
    assert second["status"] == "ignored"
    assert second["code"] == "SPECT_DUP_SEQ"
    assert s.queue_depth("m1")["buffered"] == 1


def test_out_of_order_ingest_is_delivered_in_sequence_order():
    s = make(delay_seconds=0)
    s.subscribe("v1", match="m1")
    for seq in (3, 2, 1):
        s.ingest("m1", frame(seq, "2026-11-23T10:00:00+00:00"))
    out = s.poll("v1", now="2026-11-23T10:00:05+00:00", max_items=10)
    assert [row["seq"] for row in out] == [1, 2, 3]


def test_pause_holds_delivery_until_resume():
    s = make(delay_seconds=0)
    s.subscribe("v1", match="m1")
    s.ingest("m1", frame(1, "2026-11-23T10:00:00+00:00"))
    s.pause("m1")
    assert s.poll("v1", now="2026-11-23T10:10:00+00:00") == []
    s.resume("m1")
    out = s.poll("v1", now="2026-11-23T10:10:00+00:00")
    assert [row["seq"] for row in out] == [1]
    with pytest.raises(tbg.SpectatorError) as exc:
        s.pause("nope")
    assert exc.value.code == "SPECT_UNKNOWN_MATCH"


def test_queue_cap_drops_oldest_buffer_entries():
    s = make(delay_seconds=0, queue_cap=3)
    s.subscribe("v1", match="m1")
    for seq in range(1, 6):
        s.ingest("m1", frame(seq, "2026-11-23T10:00:00+00:00"))
    depth = s.queue_depth("m1")
    assert depth["buffered"] == 3
    assert depth["dropped"] == 2
    out = s.poll("v1", now="2026-11-23T10:00:01+00:00")
    assert [row["seq"] for row in out] == [3, 4, 5]


def test_viewer_cap_rejects_extra_subscribers():
    s = make(viewer_cap=2)
    s.subscribe("v1", match="m1")
    s.subscribe("v2", match="m1")
    with pytest.raises(tbg.SpectatorError) as exc:
        s.subscribe("v3", match="m1")
    assert exc.value.code == "SPECT_FULL"
    assert s.stats()["viewers"] == 2


def test_duplicate_subscription_returns_existing_cursor():
    s = make(delay_seconds=0)
    first = s.subscribe("v1", match="m1")
    s.ingest("m1", frame(1, "2026-11-23T10:00:00+00:00"))
    s.poll("v1", now="2026-11-23T10:00:05+00:00")
    again = s.subscribe("v1", match="m1")
    assert first["status"] == "applied"
    assert again["status"] == "existing"
    assert again["cursor"] == 1
    assert s.stats()["viewers"] == 1


def test_unsubscribe_frees_slot_and_unknown_viewer_errors():
    s = make(viewer_cap=1)
    s.subscribe("v1", match="m1")
    out = s.unsubscribe("v1")
    assert out["status"] == "applied"
    with pytest.raises(tbg.SpectatorError) as exc:
        s.poll("v1", now="2026-11-23T10:00:00+00:00")
    assert exc.value.code == "SPECT_UNKNOWN_VIEWER"
    s.subscribe("v2", match="m1")
    assert s.stats()["viewers"] == 1


def test_poll_respects_max_items_and_keeps_backlog():
    s = make(delay_seconds=0)
    s.subscribe("v1", match="m1")
    for seq in range(1, 6):
        s.ingest("m1", frame(seq, "2026-11-23T10:00:00+00:00"))
    first = s.poll("v1", now="2026-11-23T10:00:05+00:00", max_items=2)
    assert [row["seq"] for row in first] == [1, 2]
    assert s.backlog("v1") == 3
    second = s.poll("v1", now="2026-11-23T10:00:05+00:00", max_items=10)
    assert [row["seq"] for row in second] == [3, 4, 5]
    assert s.backlog("v1") == 0


def test_reconnect_keeps_cursor_and_does_not_replay():
    s = make(delay_seconds=0)
    s.subscribe("v1", match="m1")
    for seq in (1, 2):
        s.ingest("m1", frame(seq, "2026-11-23T10:00:00+00:00"))
    assert [r["seq"] for r in s.poll("v1", now="2026-11-23T10:00:05+00:00")] == [1, 2]
    s.unsubscribe("v1")
    again = s.subscribe("v1", match="m1")
    assert again["cursor"] == 2
    assert s.poll("v1", now="2026-11-23T10:00:06+00:00") == []
    s.ingest("m1", frame(3, "2026-11-23T10:00:07+00:00"))
    assert [r["seq"] for r in s.poll("v1", now="2026-11-23T10:00:08+00:00")] == [3]


def test_concurrent_polling_delivers_each_frame_once():
    s = make(delay_seconds=0)
    s.subscribe("v1", match="m1")
    for seq in range(1, 21):
        s.ingest("m1", frame(seq, "2026-11-23T10:00:00+00:00"))
    barrier = threading.Barrier(8)
    seen = []
    errors = []
    lock = threading.Lock()

    def worker():
        barrier.wait()
        try:
            for _ in range(200):
                batch = s.poll("v1", now="2026-11-23T10:05:00+00:00", max_items=1)
                if not batch:
                    return
                with lock:
                    seen.extend(row["seq"] for row in batch)
        except Exception as exc:  # unexpected failures must fail the test
            with lock:
                errors.append(type(exc).__name__)

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    assert errors == []
    assert sorted(seen) == list(range(1, 21))
    assert len(seen) == 20


def test_snapshot_restore_replays_only_undelivered_frames():
    s = make(delay_seconds=0)
    s.subscribe("v1", match="m1")
    for seq in (1, 2, 3):
        s.ingest("m1", frame(seq, "2026-11-23T10:00:00+00:00"))
    assert [r["seq"] for r in s.poll("v1", now="2026-11-23T10:00:01+00:00",
                                     max_items=1)] == [1]
    snap = s.snapshot()
    assert [r["seq"] for r in s.poll("v1", now="2026-11-23T10:00:02+00:00")] == [2, 3]
    out = s.restore(snap)
    assert out["status"] == "restored"
    assert s.backlog("v1") == 2
    assert [r["seq"] for r in s.poll("v1", now="2026-11-23T10:00:03+00:00")] == [2, 3]


def test_delay_window_is_computed_in_utc():
    s = make(delay_seconds=30)
    s.subscribe("v1", match="m1")
    s.ingest("m1", frame(1, "2026-11-23T10:00:00-05:00"))
    marks = s.timeline("m1")
    assert marks[0]["deadline_ts"] == ts("2026-11-23T15:00:30+00:00")
    assert s.poll("v1", now="2026-11-23T15:00:29+00:00") == []
    out = s.poll("v1", now="2026-11-23T15:00:31+00:00")
    assert [r["seq"] for r in out] == [1]


def test_stats_and_unknown_match_guards():
    s = make(delay_seconds=0)
    s.subscribe("v1", match="m1")
    s.subscribe("v2", match="m2")
    s.ingest("m1", frame(1, "2026-11-23T10:00:00+00:00"))
    s.ingest("m2", frame(1, "2026-11-23T10:00:00+00:00"))
    s.poll("v1", now="2026-11-23T10:00:01+00:00")
    stats = s.stats()
    assert stats["viewers"] == 2
    assert stats["matches"] == 2
    assert stats["delivered"] == 1
    with pytest.raises(tbg.SpectatorError) as exc:
        s.queue_depth("m9")
    assert exc.value.code == "SPECT_UNKNOWN_MATCH"
