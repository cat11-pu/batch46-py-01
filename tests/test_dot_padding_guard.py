import json
import threading

import pytest

import dot_padding_guard as dot


class Clock:
    def __init__(self, value=0.0):
        self.value = value

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += seconds


def make(clock=None, **kwargs):
    return dot.DotPaddingGuard(clock=clock or Clock(), **kwargs)


def message(message_id, payload=b"abcd"):
    return {"message_id": message_id, "payload": payload}


def test_encode_pads_frame_to_block_multiple():
    guard = make()
    frame = guard.encode(message(7, b"abcd"))
    assert len(frame) == 468
    assert int.from_bytes(frame[:2], "big") == 466
    decoded = guard.decode(frame)
    assert decoded["message_id"] == 7
    assert decoded["payload"] == b"abcd"
    assert decoded["padding"] == 456
    assert decoded["frame_size"] == 468

    small = guard.encode(message(9, b"abcd"), block=128)
    assert len(small) == 128
    assert len(small) % 128 == 0


def test_decode_rejects_declared_length_mismatch():
    guard = make(block=16)
    frame = guard.encode(message(3, b"a"))
    with pytest.raises(dot.DotGuardError) as exc:
        guard.decode(frame[:-1])
    assert exc.value.code == "DOT_LENGTH_MISMATCH"


def test_decode_rejects_padding_option_not_last():
    guard = make(block=16)
    body = (b"\x00\x01a" + b"\x00\x0c\x00\x03" + b"\x00\x00\x00"
            + b"\x00\x01\x00\x00")
    frame = len(body).to_bytes(2, "big") + body
    assert len(frame) == 16
    with pytest.raises(dot.DotGuardError) as exc:
        guard.decode(frame)
    assert exc.value.code == "DOT_PADDING_NOT_LAST"


def test_decode_rejects_non_zero_padding_bytes():
    guard = make(block=16)
    frame = bytearray(guard.encode(message(3, b"a")))
    frame[-1] = 1
    with pytest.raises(dot.DotGuardError) as exc:
        guard.decode(bytes(frame))
    assert exc.value.code == "DOT_PADDING_NOT_ZERO"


def test_encode_rejects_invalid_block_and_message():
    guard = make()
    with pytest.raises(dot.DotGuardError) as exc:
        guard.encode(message(1), block=100)
    assert exc.value.code == "DOT_INVALID_BLOCK"
    with pytest.raises(dot.DotGuardError) as exc:
        guard.encode(message(1), block=12)
    assert exc.value.code == "DOT_INVALID_BLOCK"
    with pytest.raises(dot.DotGuardError) as exc:
        guard.encode(message(70000))
    assert exc.value.code == "DOT_INVALID_MESSAGE_ID"
    with pytest.raises(dot.DotGuardError) as exc:
        guard.encode({"message_id": 1, "payload": "text"})
    assert exc.value.code == "DOT_INVALID_PAYLOAD"


def test_open_reuses_connection_only_within_tenant():
    guard = make()
    first = guard.open("tenant-a", "192.0.2.10")
    again = guard.open("tenant-a", "192.0.2.10")
    other = guard.open("tenant-b", "192.0.2.10")
    assert first == again == "conn-1"
    assert other == "conn-2"
    assert guard.stats()["reused"] == 1
    assert guard.stats()["connections"] == 2


def test_connection_limit_evicts_idle_before_raising():
    guard = make(max_connections=2)
    guard.open("tenant-a", "peer-a")
    guard.open("tenant-a", "peer-b")
    third = guard.open("tenant-a", "peer-c")
    assert third == "conn-3"
    assert guard.stats()["closed"] == 1
    assert guard.stats()["evicted"] == 1
    guard.submit("conn-2", message(20))
    guard.submit("conn-3", message(21))
    with pytest.raises(dot.DotGuardError) as exc:
        guard.open("tenant-a", "peer-d")
    assert exc.value.code == "DOT_CONN_LIMIT"
    with pytest.raises(dot.DotGuardError) as exc:
        guard.pending("conn-1")
    assert exc.value.code == "DOT_NO_CONNECTION"


def test_pending_limit_per_connection_is_enforced():
    guard = make(max_pending=2)
    conn = guard.open("tenant-a", "peer-a")
    guard.submit(conn, message(1))
    guard.submit(conn, message(2))
    with pytest.raises(dot.DotGuardError) as exc:
        guard.submit(conn, message(3))
    assert exc.value.code == "DOT_PENDING_LIMIT"
    assert guard.pending(conn) == [1, 2]


def test_complete_matches_out_of_order_responses_by_message_id():
    guard = make()
    conn = guard.open("tenant-a", "peer-a")
    for message_id in (10, 11, 12):
        guard.submit(conn, message(message_id, b"q%d" % message_id))
    third = guard.complete(
        conn, guard.encode(message(12, b"r12"), block=guard.block)
    )
    first = guard.complete(
        conn, guard.encode(message(10, b"r10"), block=guard.block)
    )
    assert third["status"] == "delivered"
    assert third["payload"] == b"r12"
    assert first["payload"] == b"r10"
    assert guard.pending(conn) == [11]
    assert guard.stats()["received"] == 2


def test_duplicate_completion_is_reported_without_error():
    guard = make()
    conn = guard.open("tenant-a", "peer-a")
    guard.submit(conn, message(10))
    reply = guard.encode(message(10, b"done"), block=guard.block)
    first = guard.complete(conn, reply)
    second = guard.complete(conn, reply)
    assert first["status"] == "delivered"
    assert second["status"] == "duplicate"
    assert guard.stats()["received"] == 1
    assert guard.stats()["duplicates"] == 1
    assert guard.pending(conn) == []


def test_cross_connection_response_is_rejected():
    guard = make()
    first = guard.open("tenant-a", "peer-a")
    second = guard.open("tenant-a", "peer-b")
    guard.submit(first, message(10))
    with pytest.raises(dot.DotGuardError) as exc:
        guard.complete(second, guard.encode(message(10, b"wrong")))
    assert exc.value.code == "DOT_CROSS_CONNECTION"
    assert guard.pending(first) == [10]


def test_sweep_expires_overdue_messages_and_closes_idle_connections():
    clock = Clock()
    guard = make(clock=clock, idle_timeout=30.0)
    conn = guard.open("tenant-a", "peer-a")
    guard.submit(conn, message(1), timeout=5)
    clock.advance(5)
    report = guard.sweep()
    assert report["expired"] == 1
    assert report["closed"] == []
    assert guard.pending(conn) == []
    assert guard.stats()["expired"] == 1
    clock.advance(100)
    report = guard.sweep()
    assert report["closed"] == [conn]
    assert guard.stats()["closed_idle"] == 1


def test_snapshot_restore_keeps_pending_messages_and_counters():
    clock = Clock()
    guard = make(clock=clock)
    conn = guard.open("tenant-a", "peer-a")
    guard.submit(conn, message(10, b"one"))
    guard.submit(conn, message(11, b"two"))
    snap = guard.snapshot()
    assert snap["version"] == dot.DotPaddingGuard.SNAPSHOT_VERSION
    json.dumps(snap)

    restored = make(clock=clock)
    restored.restore(snap)
    assert restored.pending(conn) == [10, 11]
    assert restored.stats()["sent"] == 2
    out = restored.complete(conn, restored.encode(message(11, b"ok")))
    assert out["status"] == "delivered"
    assert out["payload"] == b"ok"


def test_restore_with_bad_version_leaves_connection_state_intact():
    guard = make()
    conn = guard.open("tenant-a", "peer-a")
    guard.submit(conn, message(5))
    snap = guard.snapshot()
    bad = dict(snap)
    bad["version"] = snap["version"] + 1
    with pytest.raises(dot.DotGuardError) as exc:
        guard.restore(bad)
    assert exc.value.code == "DOT_SNAPSHOT_VERSION"
    assert guard.pending(conn) == [5]
    assert guard.stats()["sent"] == 1


def test_concurrent_submit_of_same_message_id_succeeds_once():
    guard = make(max_pending=8)
    conn = guard.open("tenant-a", "peer-a")
    successes = []
    failures = []
    barrier = threading.Barrier(8)
    lock = threading.Lock()

    def worker():
        barrier.wait()
        try:
            out = guard.submit(conn, message(7, b"x"))
        except dot.DotGuardError as exc:
            with lock:
                failures.append(exc.code)
        else:
            with lock:
                successes.append(out)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(successes) == 1
    assert failures == ["DOT_DUPLICATE_MESSAGE"] * 7
    assert guard.stats()["sent"] == 1
    assert guard.pending(conn) == [7]
