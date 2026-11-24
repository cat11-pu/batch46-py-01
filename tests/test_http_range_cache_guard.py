import json
import threading

import pytest

import http_range_cache_guard as rcg


URL = "https://cdn.example.com/dataset.bin"
BODY = b"0123456789"


class Clock:
    def __init__(self, value=0.0):
        self.value = value

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += seconds


def make(clock=None, **kwargs):
    return rcg.RangeCacheGuard(clock=clock or Clock(), **kwargs)


def store(guard, url=URL, body=BODY, etag='"v1"', ttl=None):
    return guard.store(url, body=body, etag=etag, ttl=ttl)


def get(guard, **extra):
    request = {"url": URL}
    request.update(extra)
    return guard.handle(request)


def test_parse_range_accepts_common_forms_and_clamps():
    guard = make()
    assert guard.parse_range("bytes=0-99", 1000) == [(0, 99)]
    assert guard.parse_range("bytes=950-", 1000) == [(950, 999)]
    assert guard.parse_range("bytes=-100", 1000) == [(900, 999)]
    assert guard.parse_range("bytes=900-2000", 1000) == [(900, 999)]
    assert guard.parse_range("bytes=-2000", 1000) == [(0, 999)]
    assert guard.parse_range(" bytes=1-2 , 4-5 ", 10) == [(1, 2), (4, 5)]


def test_parse_range_rejects_invalid_unsatisfiable_and_too_many():
    guard = make()
    with pytest.raises(rcg.RangeCacheError) as exc:
        guard.parse_range("items=0-1", 10)
    assert exc.value.code == "RANGE_INVALID"
    with pytest.raises(rcg.RangeCacheError) as exc:
        guard.parse_range("bytes=5-2", 10)
    assert exc.value.code == "RANGE_INVALID"
    with pytest.raises(rcg.RangeCacheError) as exc:
        guard.parse_range("bytes=10-12", 10)
    assert exc.value.code == "RANGE_UNSATISFIABLE"
    with pytest.raises(rcg.RangeCacheError) as exc:
        guard.parse_range("bytes=-0", 10)
    assert exc.value.code == "RANGE_UNSATISFIABLE"
    tight = make(max_ranges=2)
    with pytest.raises(rcg.RangeCacheError) as exc:
        tight.parse_range("bytes=0-1,2-3,4-5", 10)
    assert exc.value.code == "RANGE_TOO_MANY"


def test_coalesce_merges_overlaps_and_adjacent_ranges():
    guard = make()
    merged = guard.coalesce([(0, 10), (5, 20), (21, 30), (40, 50)])
    assert merged == [(0, 30), (40, 50)]
    assert guard.coalesce([(5, 9), (0, 4)]) == [(0, 9)]
    assert guard.coalesce([]) == []


def test_full_object_serves_200_with_validators():
    guard = make()
    stored = store(guard)
    assert stored["total"] == 10
    assert stored["etag"] == '"v1"'
    out = get(guard)
    assert out["status"] == 200
    assert out["body"] == BODY
    assert out["headers"]["Content-Length"] == "10"
    assert out["headers"]["ETag"] == '"v1"'
    assert out["headers"]["Accept-Ranges"] == "bytes"
    assert guard.stats()["hits"] == 1


def test_single_range_serves_206_with_content_range():
    guard = make()
    store(guard)
    out = get(guard, range="bytes=2-5")
    assert out["status"] == 206
    assert out["body"] == b"2345"
    assert out["headers"]["Content-Range"] == "bytes 2-5/10"
    assert out["headers"]["Content-Length"] == "4"
    assert guard.stats()["partial_206"] == 1


def test_suffix_and_open_ended_ranges():
    guard = make()
    store(guard)
    tail = get(guard, range="bytes=-3")
    assert tail["status"] == 206
    assert tail["body"] == b"789"
    assert tail["headers"]["Content-Range"] == "bytes 7-9/10"
    rest = get(guard, range="bytes=7-")
    assert rest["status"] == 206
    assert rest["body"] == b"789"


def test_unsatisfiable_range_returns_416_with_total():
    guard = make()
    store(guard)
    out = get(guard, range="bytes=20-30")
    assert out["status"] == 416
    assert out["body"] == b""
    assert out["headers"]["Content-Range"] == "bytes */10"
    assert out["code"] == "RANGE_UNSATISFIABLE"
    assert guard.stats()["unsatisfiable"] == 1


def test_if_none_match_returns_304_for_current_etag():
    guard = make()
    store(guard)
    out = get(guard, if_none_match='"v1"')
    assert out["status"] == 304
    assert out["body"] == b""
    assert out["headers"]["ETag"] == '"v1"'
    assert guard.stats()["not_modified"] == 1
    stale = get(guard, if_none_match='"v0"')
    assert stale["status"] == 200


def test_if_range_mismatch_and_weak_etag_force_full_response():
    guard = make()
    store(guard)
    mismatch = get(guard, range="bytes=0-2", if_range='"other"')
    assert mismatch["status"] == 200
    assert mismatch["body"] == BODY
    weak = get(guard, range="bytes=0-2", if_range='W/"v1"')
    assert weak["status"] == 200
    assert weak["body"] == BODY
    matched = get(guard, range="bytes=0-2", if_range='"v1"')
    assert matched["status"] == 206
    assert matched["body"] == b"012"


def test_partial_store_serves_only_covered_range():
    guard = make()
    out = guard.store_partial(URL, body=b"01234", etag='"p1"', start=0, total=10)
    assert out["complete"] is False
    assert out["covered"] == 5
    covered = get(guard, range="bytes=0-4")
    assert covered["status"] == 206
    assert covered["body"] == b"01234"
    full = get(guard)
    assert full["status"] == "miss"
    assert full["code"] == "RANGE_INCOMPLETE"
    hole = get(guard, range="bytes=5-9")
    assert hole["status"] == "miss"


def test_partial_stores_merge_into_complete_representation():
    guard = make()
    guard.store_partial(URL, body=b"01234", etag='"p1"', start=0, total=10)
    second = guard.store_partial(URL, body=b"56789", etag='"p1"', start=5, total=10)
    assert second["complete"] is True
    assert second["covered"] == 10
    out = get(guard)
    assert out["status"] == 200
    assert out["body"] == BODY
    assert guard.stats()["partial_stored"] == 2


def test_expired_entry_misses_and_expire_drops_it():
    clock = Clock()
    guard = make(clock=clock)
    store(guard, ttl=10)
    clock.advance(10)
    out = get(guard)
    assert out["status"] == "miss"
    assert out["code"] == "RANGE_EXPIRED"
    assert guard.stats()["expired"] == 1
    store(guard, ttl=10)
    clock.advance(5)
    assert guard.expire() == 0
    clock.advance(5)
    assert guard.expire() == 1
    assert guard.entries() == []


def test_capacity_evicts_least_recently_used_entry():
    clock = Clock()
    guard = make(clock=clock, max_entries=2)
    store(guard, url="https://cdn.example.com/a", etag='"a"')
    clock.advance(1)
    store(guard, url="https://cdn.example.com/b", etag='"b"')
    clock.advance(1)
    guard.handle({"url": "https://cdn.example.com/a"})
    clock.advance(1)
    result = store(guard, url="https://cdn.example.com/c", etag='"c"')
    assert result["evicted"] == 1
    assert guard.entries() == ["https://cdn.example.com/a",
                               "https://cdn.example.com/c"]
    assert guard.handle({"url": "https://cdn.example.com/b"})["code"] == "RANGE_MISS"
    assert guard.stats()["evicted"] == 1


def test_snapshot_restore_preserves_partial_coverage_and_rejects_bad_version():
    guard = make()
    guard.store_partial(URL, body=b"01234", etag='"p1"', start=0, total=10)
    snap = guard.snapshot()
    assert snap["version"] == rcg.RangeCacheGuard.SNAPSHOT_VERSION
    json.dumps(snap)

    restored = make()
    restored.restore(snap)
    assert restored.entries() == [URL]
    assert restored.handle({"url": URL})["code"] == "RANGE_INCOMPLETE"
    part = restored.handle({"url": URL, "range": "bytes=0-4"})
    assert part["status"] == 206
    assert part["body"] == b"01234"

    restored.store_partial(URL, body=b"56789", etag='"p1"', start=5, total=10)
    assert restored.handle({"url": URL})["body"] == BODY

    bad = dict(snap)
    bad["version"] = snap["version"] - 1
    with pytest.raises(rcg.RangeCacheError) as exc:
        restored.restore(bad)
    assert exc.value.code == "RANGE_SNAPSHOT_VERSION"
    assert restored.entries() == [URL]


def test_concurrent_partial_stores_form_one_complete_body():
    guard = make()
    payload = b"0123456789" * 10
    results = []
    errors = []
    lock = threading.Lock()
    barrier = threading.Barrier(10)

    def worker(index):
        barrier.wait()
        try:
            row = guard.store_partial(URL, body=payload[index * 10:(index + 1) * 10],
                                      etag='"c1"', start=index * 10, total=100)
        except Exception as exc:  # pragma: no cover - surfaced through errors
            with lock:
                errors.append(exc)
        else:
            with lock:
                results.append(row)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert len(results) == 10
    out = guard.handle({"url": URL})
    assert out["status"] == 200
    assert out["body"] == payload
    assert guard.stats()["partial_stored"] == 10
