import threading

import pytest

import http3_qpack_guard as qpack


def make(**kwargs):
    return qpack.QpackGuard(**kwargs)


def test_insert_assigns_absolute_index_and_tracks_used_bytes():
    g = make(capacity=100)
    first = g.insert("x-trace", "abc")
    assert first["status"] == "inserted"
    assert first["index"] == 0
    assert first["size"] == 42
    assert first["used"] == 42
    assert first["insert_count"] == 1
    second = g.insert("x-mode", "fast")
    assert second["index"] == 1
    assert second["used"] == 84
    with pytest.raises(qpack.QpackError) as exc:
        g.insert("x-big", "z" * 200)
    assert exc.value.code == "QPACK_ENTRY_TOO_LARGE"
    assert g.table_state()["used"] == 84


def test_duplicate_field_is_not_inserted_twice():
    g = make()
    first = g.insert("accept", "*/*")
    again = g.insert("accept", "*/*")
    assert again["status"] == "duplicate"
    assert again["index"] == first["index"]
    assert again["insert_count"] == 1
    m = g.metrics()
    assert m["inserts"] == 1
    assert m["duplicates"] == 1


def test_eviction_removes_the_oldest_entries():
    g = make(capacity=100)
    g.insert("a", "1" * 60)
    g.insert("b", "2" * 60)
    state = g.table_state()
    assert state["insert_count"] == 2
    assert state["used"] == 93
    with pytest.raises(qpack.QpackError) as exc:
        g.lookup_absolute(0)
    assert exc.value.code == "QPACK_EVICTED"
    assert g.lookup_absolute(1)["name"] == "b"
    assert g.lookup_relative(0)["index"] == 1
    with pytest.raises(qpack.QpackError) as exc:
        g.lookup_relative(1)
    assert exc.value.code == "QPACK_EVICTED"


def test_capacity_update_evicts_and_is_bounded():
    g = make(capacity=200)
    g.insert("a", "1" * 60)
    g.insert("b", "2" * 60)
    out = g.set_capacity(100)
    assert out["evicted"] == 1
    assert out["used"] == 93
    with pytest.raises(qpack.QpackError) as exc:
        g.set_capacity(999999)
    assert exc.value.code == "QPACK_CAPACITY"
    assert g.table_state()["capacity"] == 100
    assert g.set_capacity(300)["capacity"] == 300


def test_lookup_rejects_negative_and_out_of_range_indices():
    g = make()
    g.insert("a", "b")
    with pytest.raises(qpack.QpackError) as exc:
        g.lookup_absolute(-1)
    assert exc.value.code == "QPACK_INDEX"
    with pytest.raises(qpack.QpackError) as exc:
        g.lookup_absolute(1)
    assert exc.value.code == "QPACK_INDEX"
    with pytest.raises(qpack.QpackError) as exc:
        g.lookup_relative(1)
    assert exc.value.code == "QPACK_INDEX"
    assert g.lookup_absolute(0)["value"] == "b"


def test_encode_then_decode_returns_the_original_headers():
    g = make()
    g.insert("accept", "*/*")
    block = g.encode([("accept", "*/*"), ("x-new", "v1")])
    assert block["required_insert_count"] == 2
    assert len(block["fields"]) == 2
    assert block["fields"][0]["literal"] is False
    assert block["fields"][0]["index"] == 0
    assert block["fields"][1]["literal"] is True
    decoded = g.decode(block)
    assert decoded["headers"] == [["accept", "*/*"], ["x-new", "v1"]]
    assert decoded["fields"] == 2


def test_decode_is_blocked_until_required_inserts_arrive():
    g = make()
    g.insert("a", "b")
    block = {
        "required_insert_count": 5,
        "fields": [{"name": "a", "value": "b", "index": None, "literal": True}],
    }
    with pytest.raises(qpack.QpackError) as exc:
        g.decode(block)
    assert exc.value.code == "QPACK_BLOCKED"
    with pytest.raises(qpack.QpackError) as exc:
        g.decode({"required_insert_count": 0})
    assert exc.value.code == "QPACK_BLOCK_INVALID"


def test_decode_rejects_entries_evicted_since_encoding():
    g = make(capacity=100)
    g.insert("a", "1" * 60)
    block = g.encode([("a", "1" * 60)])
    g.insert("b", "2" * 60)
    with pytest.raises(qpack.QpackError) as exc:
        g.decode(block)
    assert exc.value.code == "QPACK_EVICTED"


def test_blocked_stream_becomes_ready_only_when_inserts_catch_up():
    g = make()
    out = g.open_stream("s1", required_insert_count=2)
    assert out["state"] == "blocked"
    assert g.blocked_streams() == ["s1"]
    g.insert("a", "b")
    with pytest.raises(qpack.QpackError) as exc:
        g.unblock("s1")
    assert exc.value.code == "QPACK_NOT_READY"
    g.insert("c", "d")
    assert g.unblock("s1")["state"] == "ready"
    assert g.blocked_streams() == []


def test_blocked_stream_count_is_capped():
    g = make(max_blocked=2)
    g.open_stream("s1", required_insert_count=5)
    g.open_stream("s2", required_insert_count=5)
    with pytest.raises(qpack.QpackError) as exc:
        g.open_stream("s3", required_insert_count=5)
    assert exc.value.code == "QPACK_BLOCKED_LIMIT"
    assert g.blocked_streams() == ["s1", "s2"]
    assert g.metrics()["blocked_count"] == 2


def test_acknowledgement_must_be_monotonic_and_known():
    g = make()
    with pytest.raises(qpack.QpackError) as exc:
        g.acknowledge("missing", 0)
    assert exc.value.code == "QPACK_STREAM_UNKNOWN"
    g.open_stream("s1", required_insert_count=0)
    with pytest.raises(qpack.QpackError) as exc:
        g.acknowledge("s1", 1)
    assert exc.value.code == "QPACK_ACK_INVALID"
    assert g.acknowledge("s1", 0)["ack"] == 0
    with pytest.raises(qpack.QpackError) as exc:
        g.acknowledge("s1", -1)
    assert exc.value.code == "QPACK_ACK_INVALID"
    g.insert("a", "b")
    assert g.acknowledge("s1", 1)["ack"] == 1
    with pytest.raises(qpack.QpackError) as exc:
        g.acknowledge("s1", 0)
    assert exc.value.code == "QPACK_ACK_INVALID"


def test_table_state_reports_entries_in_insertion_order():
    g = make(capacity=300)
    g.insert("a", "1" * 10)
    g.insert("b", "2" * 10)
    state = g.table_state()
    assert state["capacity"] == 300
    assert state["used"] == 86
    assert state["insert_count"] == 2
    assert [row["name"] for row in state["entries"]] == ["a", "b"]
    assert [row["size"] for row in state["entries"]] == [43, 43]


def test_snapshot_restores_table_streams_and_counters():
    g = make(max_blocked=4)
    g.insert("a", "b")
    g.insert("c", "d")
    g.open_stream("s1", required_insert_count=5)
    block = g.encode([("a", "b")])
    data = g.snapshot()
    h = make()
    h.restore(data)
    assert h.table_state()["insert_count"] == 2
    assert h.lookup_absolute(0)["name"] == "a"
    assert h.blocked_streams() == ["s1"]
    assert h.metrics()["inserts"] == 2
    assert h.insert("e", "f")["index"] == 2
    assert h.decode(block)["headers"] == [["a", "b"]]


def test_restore_of_corrupt_snapshot_leaves_state_intact():
    g = make()
    g.insert("a", "b")
    with pytest.raises(qpack.QpackError) as exc:
        g.restore({"version": 2})
    assert exc.value.code == "QPACK_SNAPSHOT_INVALID"
    with pytest.raises(qpack.QpackError) as exc:
        g.restore({"version": 1, "entries": "bad"})
    assert exc.value.code == "QPACK_SNAPSHOT_INVALID"
    assert g.table_state()["insert_count"] == 1
    assert g.lookup_absolute(0)["name"] == "a"


def test_concurrent_inserts_get_unique_indices():
    g = make(capacity=1000000, max_capacity=1000000)
    errors = []

    def worker(n):
        try:
            for i in range(20):
                g.insert("h-%d-%d" % (n, i), "v")
        except Exception as err:  # pragma: no cover - failure path
            errors.append(err)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    state = g.table_state()
    assert state["insert_count"] == 160
    assert len(state["entries"]) == 160
    assert len({row["name"] for row in state["entries"]}) == 160
    assert state["used"] <= state["capacity"]
    assert g.metrics()["inserts"] == 160
