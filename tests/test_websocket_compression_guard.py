import threading
import zlib

import pytest

import websocket_compression_guard as ws


def make(**kwargs):
    return ws.WsCompressionGuard(**kwargs)


def negotiated(g, sid="s", params=None):
    g.open_session(sid)
    return g.negotiate(sid, params or {})


def test_round_trip_strips_the_sync_flush_tail():
    g = make()
    info = negotiated(g)
    assert info["status"] == "negotiated"
    assert info["server_max_window_bits"] == 15
    data = g.compress("s", b"hello hello hello")
    assert isinstance(data, bytes)
    assert not data.endswith(b"\x00\x00\xff\xff")
    assert g.decompress("s", data) == b"hello hello hello"
    state = g.context_state("s")
    assert state["out_messages"] == 1
    assert state["in_messages"] == 1
    assert state["resets"] == 0


def test_negotiation_validates_parameters():
    g = make()
    g.open_session("s")
    with pytest.raises(ws.WsCompressionError) as exc:
        g.negotiate("s", {"server_max_window_bits": 7})
    assert exc.value.code == "WS_PARAM_INVALID"
    with pytest.raises(ws.WsCompressionError) as exc:
        g.negotiate("s", {"server_max_window_bits": 16})
    assert exc.value.code == "WS_PARAM_INVALID"
    with pytest.raises(ws.WsCompressionError) as exc:
        g.negotiate("s", {"unknown_flag": True})
    assert exc.value.code == "WS_PARAM_INVALID"
    with pytest.raises(ws.WsCompressionError) as exc:
        g.negotiate("s", {"server_no_context_takeover": "yes"})
    assert exc.value.code == "WS_PARAM_INVALID"
    with pytest.raises(ws.WsCompressionError) as exc:
        g.negotiate("s", {"server_max_window_bits": "abc"})
    assert exc.value.code == "WS_PARAM_INVALID"
    assert g.context_state("s")["state"] == "new"
    g.open_session("s2")
    ok = g.negotiate("s2", {"server_no_context_takeover": True,
                            "client_max_window_bits": "12"})
    assert ok["server_no_context_takeover"] is True
    assert ok["client_max_window_bits"] == 12


def test_renegotiation_is_limited_to_identical_parameters():
    g = make()
    negotiated(g)
    again = g.negotiate("s", {})
    assert again["status"] == "duplicate"
    with pytest.raises(ws.WsCompressionError) as exc:
        g.negotiate("s", {"server_no_context_takeover": True})
    assert exc.value.code == "WS_ALREADY_NEGOTIATED"
    assert g.metrics()["duplicates"] == 1


def test_compression_requires_negotiation():
    g = make()
    g.open_session("s")
    with pytest.raises(ws.WsCompressionError) as exc:
        g.compress("s", b"x")
    assert exc.value.code == "WS_STATE_ORDER"
    with pytest.raises(ws.WsCompressionError) as exc:
        g.decompress("s", b"x")
    assert exc.value.code == "WS_STATE_ORDER"
    g.negotiate("s", {})
    assert g.decompress("s", g.compress("s", b"x")) == b"x"


def test_message_size_limit_is_enforced_per_session():
    g = make(max_message=100)
    negotiated(g)
    with pytest.raises(ws.WsCompressionError) as exc:
        g.compress("s", b"a" * 101)
    assert exc.value.code == "WS_MESSAGE_TOO_LARGE"
    payload = b"a" * 100
    assert g.decompress("s", g.compress("s", payload)) == payload
    g.set_limit("s", 10)
    with pytest.raises(ws.WsCompressionError) as exc:
        g.compress("s", b"a" * 11)
    assert exc.value.code == "WS_MESSAGE_TOO_LARGE"
    with pytest.raises(ws.WsCompressionError) as exc:
        g.set_limit("s", 0)
    assert exc.value.code == "WS_LIMIT_INVALID"
    assert g.context_state("s")["max_message"] == 10


def test_decompression_bomb_kills_the_context_until_reset():
    g = make(max_message=1000)
    negotiated(g)
    obj = zlib.compressobj(6, zlib.DEFLATED, -15)
    bomb = obj.compress(b"a" * 50000) + obj.flush(zlib.Z_SYNC_FLUSH)
    assert bomb.endswith(b"\x00\x00\xff\xff")
    bomb = bomb[:-4]
    with pytest.raises(ws.WsCompressionError) as exc:
        g.decompress("s", bomb)
    assert exc.value.code == "WS_DECOMPRESS_BOMB"
    assert g.context_state("s")["failed"] is True
    with pytest.raises(ws.WsCompressionError) as exc:
        g.compress("s", b"x")
    assert exc.value.code == "WS_CONTEXT_FAILED"
    with pytest.raises(ws.WsCompressionError) as exc:
        g.decompress("s", b"x")
    assert exc.value.code == "WS_CONTEXT_FAILED"
    assert g.reset_context("s")["failed"] is False
    assert g.decompress("s", g.compress("s", b"ok")) == b"ok"


def test_invalid_deflate_stream_marks_the_context_failed():
    g = make()
    negotiated(g)
    with pytest.raises(ws.WsCompressionError) as exc:
        g.decompress("s", b"\xff\xff\xff\xff")
    assert exc.value.code == "WS_DEFLATE_INVALID"
    assert g.context_state("s")["failed"] is True
    g.reset_context("s")
    assert g.decompress("s", g.compress("s", b"payload")) == b"payload"


def test_context_takeover_keeps_dictionary_across_messages():
    g = make()
    negotiated(g)
    first = b"the quick brown fox jumps over the lazy dog"
    second = b"the quick brown fox jumps over the lazy dog again"
    compressed_first = g.compress("s", first)
    compressed_second = g.compress("s", second)
    assert g.decompress("s", compressed_first) == first
    assert g.decompress("s", compressed_second) == second
    state = g.context_state("s")
    assert state["out_messages"] == 2
    assert state["in_messages"] == 2
    assert state["resets"] == 0


def test_no_context_takeover_resets_after_every_message():
    g = make()
    g.open_session("s")
    g.negotiate("s", {"server_no_context_takeover": True,
                      "client_no_context_takeover": True})
    payload = b"repeat me repeat me"
    for _ in range(2):
        assert g.decompress("s", g.compress("s", payload)) == payload
    state = g.context_state("s")
    assert state["server_resets"] == 2
    assert state["client_resets"] == 2
    assert state["resets"] == 4


def test_context_table_is_capped_and_slots_are_reusable():
    g = make(max_contexts=2)
    g.open_session("a")
    g.open_session("b")
    with pytest.raises(ws.WsCompressionError) as exc:
        g.open_session("c")
    assert exc.value.code == "WS_CONTEXT_LIMIT"
    with pytest.raises(ws.WsCompressionError) as exc:
        g.open_session("a")
    assert exc.value.code == "WS_SESSION_EXISTS"
    assert g.inflight() == ["a", "b"]
    g.close_session("a")
    g.open_session("c")
    assert g.inflight() == ["b", "c"]


def test_closed_session_cannot_be_used():
    g = make()
    negotiated(g)
    assert g.close_session("s") is True
    assert g.close_session("s") is False
    with pytest.raises(ws.WsCompressionError) as exc:
        g.compress("s", b"x")
    assert exc.value.code == "WS_SESSION_MISSING"
    with pytest.raises(ws.WsCompressionError) as exc:
        g.decompress("s", b"x")
    assert exc.value.code == "WS_SESSION_MISSING"
    with pytest.raises(ws.WsCompressionError) as exc:
        g.context_state("s")
    assert exc.value.code == "WS_SESSION_MISSING"


def test_snapshot_restores_config_counters_and_bounded_history():
    g = make(history=2)
    g.open_session("s")
    g.negotiate("s", {"server_no_context_takeover": True})
    for payload in (b"one", b"two", b"three"):
        assert g.decompress("s", g.compress("s", payload)) == payload
    data = g.snapshot()
    row = data["sessions"][0]
    assert len(row["sent"]) == 2
    assert len(row["recv"]) == 2
    h = make(history=2)
    h.restore(data)
    state = h.context_state("s")
    assert state["out_messages"] == 3
    assert state["in_messages"] == 3
    assert state["server_no_context_takeover"] is True
    assert state["resets"] == 3
    assert h.metrics()["sent_messages"] == 3
    assert h.decompress("s", h.compress("s", b"four")) == b"four"


def test_restore_of_corrupt_snapshot_leaves_state_intact():
    g = make()
    negotiated(g)
    g.compress("s", b"keep")
    with pytest.raises(ws.WsCompressionError) as exc:
        g.restore({"version": 9})
    assert exc.value.code == "WS_SNAPSHOT_INVALID"
    with pytest.raises(ws.WsCompressionError) as exc:
        g.restore({"version": 1, "sessions": "bad"})
    assert exc.value.code == "WS_SNAPSHOT_INVALID"
    assert g.context_state("s")["out_messages"] == 1
    assert g.inflight() == ["s"]


def test_concurrent_sessions_compress_independently():
    g = make(max_contexts=16)
    for n in range(6):
        g.open_session("s%d" % n)
        g.negotiate("s%d" % n, {})
    errors = []

    def worker(n):
        sid = "s%d" % n
        try:
            for i in range(15):
                payload = ("payload-%d-%d" % (n, i)).encode()
                if g.decompress(sid, g.compress(sid, payload)) != payload:
                    errors.append((sid, i))
        except Exception as err:  # pragma: no cover - failure path
            errors.append(err)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    for n in range(6):
        assert g.context_state("s%d" % n)["out_messages"] == 15
    assert g.metrics()["sent_messages"] == 90
    assert g.metrics()["received_messages"] == 90


def test_metrics_track_compressed_bytes_and_messages():
    g = make()
    negotiated(g)
    data = g.compress("s", b"abcdef")
    g.decompress("s", data)
    m = g.metrics()
    assert m["contexts"] == 1
    assert m["negotiated"] == 1
    assert m["sent_messages"] == 1
    assert m["received_messages"] == 1
    assert m["bytes_sent"] == len(data)
    assert m["bytes_received"] == len(data)
    assert m["failures"] == 0
