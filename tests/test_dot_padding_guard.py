import json
import struct
import threading
import time

import pytest

import dot_padding_guard as dpg


def make(**kwargs):
    return dpg.DotPaddingGuard(**kwargs)


def msg(mid, payload=b"\x01\x02\x03\x04"):
    return {"message_id": mid, "payload": payload}


def test_encode_produces_aligned_frame_with_minimal_padding():
    g = make()
    frame = g.encode(msg(7, b"a" * 45))
    assert len(frame) == 468
    assert len(frame) % 468 == 0
    (declared,) = struct.unpack(">H", frame[:2])
    assert declared == len(frame) - 2
    (mid,) = struct.unpack(">H", frame[2:4])
    assert mid == 7
    assert frame[4:49] == b"a" * 45
    code, opt_len = struct.unpack(">HH", frame[49:53])
    assert code == 12
    assert opt_len == 468 - 53
    assert frame[53:] == b"\x00" * opt_len
    # exact multiple of the block gets a zero-length option, not a new block
    exact = g.encode(msg(1, b"x" * (468 - 8)))
    assert len(exact) == 468
    # one byte more must spill into exactly one extra block
    over = g.encode(msg(1, b"x" * (468 - 7)))
    assert len(over) == 468 * 2


def test_encode_decode_round_trip_and_custom_block():
    g = make(block=64)
    for payload in (b"", b"\x00", b"\x00\x00\x00", b"q" * 100,
                    bytes(range(256))):
        frame = g.encode(msg(513, payload))
        assert len(frame) % 64 == 0
        decoded = g.decode(frame)
        assert decoded["message_id"] == 513
        assert decoded["payload"] == payload
        assert decoded["padding"] == len(frame) - 8 - len(payload)
    other = make(block=128)
    frame = other.encode(msg(3, b"abc"), block=256)
    assert len(frame) % 256 == 0


def test_invalid_block_is_rejected():
    with pytest.raises(dpg.DotPaddingError) as exc:
        make(block=8)
    assert exc.value.code == "DOT_INVALID_BLOCK"
    g = make()
    for bad in (15, 18, 0, -16, 12.5):
        with pytest.raises(dpg.DotPaddingError) as exc:
            g.encode(msg(1), block=bad)
        assert exc.value.code == "DOT_INVALID_BLOCK"
    g.encode(msg(1), block=16)


def test_invalid_message_id_and_payload_are_rejected():
    g = make()
    for bad in (-1, 65536, "7", 1.5, None, True):
        with pytest.raises(dpg.DotPaddingError) as exc:
            g.encode(msg(bad))
        assert exc.value.code == "DOT_INVALID_MESSAGE_ID"
    for bad in ("text", None, 123, [1, 2]):
        with pytest.raises(dpg.DotPaddingError) as exc:
            g.encode(msg(1, bad))
        assert exc.value.code == "DOT_INVALID_PAYLOAD"
    g.encode(msg(0))
    g.encode(msg(65535))


def test_decode_rejects_length_mismatch():
    g = make(block=16)
    frame = bytearray(g.encode(msg(9)))
    frame[1] += 1
    with pytest.raises(dpg.DotPaddingError) as exc:
        g.decode(bytes(frame))
    assert exc.value.code == "DOT_LENGTH_MISMATCH"
    with pytest.raises(dpg.DotPaddingError) as exc:
        g.decode(b"\x00")
    assert exc.value.code == "DOT_LENGTH_MISMATCH"


def test_decode_rejects_misaligned_frame():
    g = make(block=16)
    frame = bytearray(g.encode(msg(9)))
    frame += b"\x00"
    frame[:2] = struct.pack(">H", len(frame) - 2)
    with pytest.raises(dpg.DotPaddingError) as exc:
        g.decode(bytes(frame))
    assert exc.value.code == "DOT_PADDING_MISALIGNED"


def test_decode_rejects_padding_not_last():
    g = make(block=16)
    frame = bytearray(g.encode(msg(9)))
    frame += b"\x01" * 16
    frame[:2] = struct.pack(">H", len(frame) - 2)
    with pytest.raises(dpg.DotPaddingError) as exc:
        g.decode(bytes(frame))
    assert exc.value.code == "DOT_PADDING_NOT_LAST"


def test_decode_rejects_non_zero_padding():
    g = make(block=16)
    frame = bytearray(g.encode(msg(9)))
    frame[-1] = 1
    with pytest.raises(dpg.DotPaddingError) as exc:
        g.decode(bytes(frame))
    assert exc.value.code == "DOT_PADDING_NOT_ZERO"


def test_connections_reuse_per_tenant_and_peer():
    g = make()
    c1 = g.open("tenant-a", "dot.example.com:853")
    assert g.open("tenant-a", "dot.example.com:853") == c1
    assert g.open("tenant-a", "dot.example.com:853") == c1
    c2 = g.open("tenant-b", "dot.example.com:853")
    assert c2 != c1
    c3 = g.open("tenant-a", "other.example.com:853")
    assert c3 not in (c1, c2)
    stats = g.stats()
    assert stats["reused"] == 2
    assert stats["connections"] == 3


def test_pool_limit_evicts_oldest_idle_then_raises():
    g = make(max_connections=2)
    c1 = g.open("t", "p1")
    g.submit(c1, msg(1))
    c2 = g.open("t", "p2")
    c3 = g.open("t", "p3")
    assert c3 != c2
    with pytest.raises(dpg.DotPaddingError) as exc:
        g.pending(c2)
    assert exc.value.code == "DOT_UNKNOWN_CONNECTION"
    assert g.stats()["evicted"] == 1
    assert g.stats()["connections"] == 2
    g.submit(c1, msg(2))
    g.submit(c3, msg(3))
    with pytest.raises(dpg.DotPaddingError) as exc:
        g.open("t", "p4")
    assert exc.value.code == "DOT_CONN_LIMIT"
    assert g.stats()["connections"] == 2


def test_pending_limit_and_duplicate_message():
    g = make(max_pending=2)
    c1 = g.open("t", "p")
    g.submit(c1, msg(1))
    g.submit(c1, msg(2))
    with pytest.raises(dpg.DotPaddingError) as exc:
        g.submit(c1, msg(3))
    assert exc.value.code == "DOT_PENDING_LIMIT"
    with pytest.raises(dpg.DotPaddingError) as exc:
        g.submit(c1, msg(1))
    assert exc.value.code == "DOT_DUPLICATE_MESSAGE"
    assert g.pending(c1) == [1, 2]
    assert g.stats()["sent"] == 2
    assert g.stats()["pending"] == 2


def test_complete_out_of_order_duplicate_and_cross_connection():
    g = make()
    c1 = g.open("t", "p1")
    c2 = g.open("t", "p2")
    first = g.submit(c1, msg(1, b"one"))
    second = g.submit(c1, msg(2, b"two"))
    assert first["conn_id"] == c1
    assert first["padded_to"] == len(first["frame"])
    assert first["deadline"] > time.time()
    done2 = g.complete(c1, second["frame"])
    assert done2["status"] == "ok"
    assert done2["message_id"] == 2
    assert done2["payload"] == b"two"
    assert done2["padding"] >= 0
    assert done2["wait"] >= 0
    with pytest.raises(dpg.DotPaddingError) as exc:
        g.complete(c2, first["frame"])
    assert exc.value.code == "DOT_CROSS_CONNECTION"
    assert g.pending(c1) == [1]
    done1 = g.complete(c1, first["frame"])
    assert done1["status"] == "ok"
    again = g.complete(c1, first["frame"])
    assert again["status"] == "duplicate"
    assert again["message_id"] == 1
    stats = g.stats()
    assert stats["received"] == 2
    assert stats["duplicates"] == 1
    assert stats["pending"] == 0


def test_sweep_expires_pending_and_closes_idle_connections():
    g = make(idle_timeout=0.05)
    busy = g.open("t", "busy")
    idle = g.open("t", "idle")
    g.submit(busy, msg(1), timeout=0.05)
    g.submit(busy, msg(2), timeout=30.0)
    time.sleep(0.1)
    result = g.sweep()
    assert result["expired"] == 1
    assert result["closed"] == [idle]
    assert g.pending(busy) == [2]
    stats = g.stats()
    assert stats["expired"] == 1
    assert stats["closed_idle"] == 1
    assert stats["connections"] == 1
    assert g.sweep() == {"closed": [], "expired": 0}


def test_close_reports_dropped_pending():
    g = make()
    c1 = g.open("t", "p")
    g.submit(c1, msg(1))
    g.submit(c1, msg(2))
    result = g.close(c1)
    assert result["dropped"] == 2
    stats = g.stats()
    assert stats["dropped"] == 2
    assert stats["closed"] == 1
    assert stats["connections"] == 0
    assert stats["pending"] == 0
    with pytest.raises(dpg.DotPaddingError) as exc:
        g.close(c1)
    assert exc.value.code == "DOT_UNKNOWN_CONNECTION"
    with pytest.raises(dpg.DotPaddingError) as exc:
        g.submit(c1, msg(3))
    assert exc.value.code == "DOT_UNKNOWN_CONNECTION"


def test_snapshot_restore_round_trip_preserves_state():
    g = make(block=64, timeout=10.0)
    c1 = g.open("tenant", "peer")
    sent = g.submit(c1, msg(42, b"hello"))
    g.submit(c1, msg(43), timeout=30.0)
    done = g.submit(c1, msg(44))
    g.complete(c1, done["frame"])
    snap = g.snapshot()
    json.dumps(snap)
    restored = make()
    restored.restore(json.loads(json.dumps(snap)))
    assert restored.stats() == g.stats()
    assert restored.pending(c1) == [42, 43]
    snap2 = restored.snapshot()
    conn = snap2["connections"][0]
    deadlines = {e["message_id"]: e["deadline"] for e in conn["pending"]}
    assert deadlines[42] == sent["deadline"]
    again = restored.open("tenant", "peer")
    assert again == c1
    out = restored.complete(c1, sent["frame"])
    assert out["status"] == "ok"
    assert out["payload"] == b"hello"
    assert restored.stats()["received"] == g.stats()["received"] + 1


def test_restore_rejects_bad_version_without_touching_state():
    g = make()
    c1 = g.open("t", "p")
    g.submit(c1, msg(1))
    before = g.stats()
    snap = g.snapshot()
    snap["version"] = 999
    with pytest.raises(dpg.DotPaddingError) as exc:
        g.restore(snap)
    assert exc.value.code == "DOT_SNAPSHOT_VERSION"
    assert g.stats() == before
    assert g.pending(c1) == [1]
    with pytest.raises(dpg.DotPaddingError) as exc:
        g.restore({"version": "1"})
    assert exc.value.code == "DOT_SNAPSHOT_VERSION"
    assert g.stats() == before


def test_concurrent_duplicate_submit_succeeds_exactly_once():
    g = make(max_pending=64)
    c1 = g.open("t", "p")
    results = []
    errors = []

    def worker():
        try:
            results.append(g.submit(c1, msg(7)))
        except dpg.DotPaddingError as exc:
            errors.append(exc.code)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(results) == 1
    assert errors == ["DOT_DUPLICATE_MESSAGE"] * 7
    assert g.pending(c1) == [7]
    stats = g.stats()
    assert stats["sent"] == 1
    assert stats["pending"] == 1


def test_concurrent_mixed_load_keeps_counters_consistent():
    g = make(max_connections=4, max_pending=8)
    conns = [g.open("t%d" % i, "peer") for i in range(4)]
    errors = []

    def worker(index):
        conn = conns[index % len(conns)]
        try:
            sent = g.submit(conn, msg(index, b"payload-%d" % index))
            out = g.complete(conn, sent["frame"])
            assert out["status"] == "ok"
        except dpg.DotPaddingError as exc:
            errors.append(exc.code)

    threads = [threading.Thread(target=worker, args=(i,))
               for i in range(64)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    stats = g.stats()
    assert not errors
    assert stats["sent"] == 64
    assert stats["received"] == 64
    assert stats["pending"] == 0
    assert stats["connections"] <= 4
    for key in dpg.DotPaddingGuard.COUNTER_KEYS:
        assert stats[key] >= 0
