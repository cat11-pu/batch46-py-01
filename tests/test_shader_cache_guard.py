import threading

import pytest

import shader_cache_guard as shc


def make(**kwargs):
    return shc.ShaderCache(**kwargs)


def test_define_order_is_normalized_in_key():
    a = make()
    first = a.compose_key("abc123", "drv-1", ["B=2", "A=1", "A=1"])
    assert first == "abc123|drv-1|A=1,B=2"
    assert a.compose_key("abc123", "drv-1", ("A=1", "B=2")) == first
    assert a.compose_key("abc123", "drv-2", ["A=1", "B=2"]) != first
    assert a.compose_key("abc123", "drv-1", []) == "abc123|drv-1|"


def test_malformed_and_conflicting_defines_rejected():
    a = make()
    with pytest.raises(shc.ShaderCacheError) as exc:
        a.compose_key("abc", "drv", ["NOEQUALS"])
    assert exc.value.code == "SHC_DEFINE_FORMAT"
    with pytest.raises(shc.ShaderCacheError) as exc:
        a.compose_key("abc", "drv", ["A="])
    assert exc.value.code == "SHC_DEFINE_FORMAT"
    with pytest.raises(shc.ShaderCacheError) as exc:
        a.compose_key("abc", "drv", ["A=1", "A=2"])
    assert exc.value.code == "SHC_DEFINE_CONFLICT"
    with pytest.raises(shc.ShaderCacheError) as exc:
        a.compose_key("", "drv", [])
    assert exc.value.code == "SHC_KEY_INVALID"
    with pytest.raises(shc.ShaderCacheError) as exc:
        a.compose_key("abc", "", [])
    assert exc.value.code == "SHC_KEY_INVALID"


def test_put_get_and_stats_roundtrip():
    a = make()
    stored = a.put("s1", "d1", ["A=1"], 100)
    assert stored["status"] == "stored"
    assert stored["key"] == "s1|d1|A=1"
    assert stored["entries"] == 1
    assert stored["bytes"] == 100
    hit = a.get("s1|d1|A=1")
    assert hit["hit"] is True
    assert hit["byte_size"] == 100
    assert hit["defines"] == ["A=1"]
    miss = a.get("missing|d|x")
    assert miss["hit"] is False
    stats = a.stats()
    assert stats["hits"] == 1
    assert stats["misses"] == 1
    assert stats["hit_rate"] == 0.5
    assert stats["entries"] == 1
    assert stats["bytes"] == 100


def test_duplicate_put_is_idempotent_and_size_conflict_rejected():
    a = make()
    a.put("s", "d", ["A=1"], 100)
    duplicate = a.put("s", "d", ["A=1"], 100)
    assert duplicate["status"] == "duplicate"
    assert duplicate["bytes"] == 100
    assert duplicate["entries"] == 1
    with pytest.raises(shc.ShaderCacheError) as exc:
        a.put("s", "d", ["A=1"], 120)
    assert exc.value.code == "SHC_SIZE_CONFLICT"
    assert a.stats()["entries"] == 1
    assert a.stats()["bytes"] == 100


def test_trim_evicts_least_recently_used_first():
    a = make(byte_budget=250, entry_budget=10, variant_limit=10)
    ka = a.put("sa", "d", [], 100)["key"]
    kb = a.put("sb", "d", [], 100)["key"]
    kc = a.put("sc", "d", [], 100)["key"]
    a.get(ka)
    first = a.trim()
    assert first["evicted"] == [kb]
    assert first["bytes"] == 200
    assert first["entries"] == 2
    kd = a.put("sd", "d", [], 100)["key"]
    second = a.trim()
    assert second["evicted"] == [kc]
    assert second["bytes"] == 200
    assert a.keys() == [ka, kd]


def test_entry_budget_evicts_oldest_entries():
    a = make(byte_budget=10_000, entry_budget=2, variant_limit=10)
    ka = a.put("sa", "d", [], 10)["key"]
    kb = a.put("sb", "d", [], 10)["key"]
    kc = a.put("sc", "d", [], 10)["key"]
    first = a.trim()
    assert first["evicted"] == [ka]
    assert first["entries"] == 2
    a.get(kb)
    kd = a.put("sd", "d", [], 10)["key"]
    second = a.trim()
    assert second["evicted"] == [kc]
    assert a.keys() == [kb, kd]


def test_pinned_entries_survive_trim_until_budget_is_stuck():
    a = make(byte_budget=150, entry_budget=10, variant_limit=10)
    ka = a.put("sa", "d", [], 100, pinned=True)["key"]
    kb = a.put("sb", "d", [], 100)["key"]
    first = a.trim()
    assert first["evicted"] == [kb]
    assert first["bytes"] == 100
    kc = a.put("sc", "d", [], 100)["key"]
    second = a.trim()
    assert second["evicted"] == [kc]
    assert second["bytes"] == 100
    stuck = make(byte_budget=150, entry_budget=10, variant_limit=10)
    kx = stuck.put("sx", "d", [], 100, pinned=True)["key"]
    stuck.put("sy", "d", [], 100, pinned=True)
    with pytest.raises(shc.ShaderCacheError) as exc:
        stuck.trim()
    assert exc.value.code == "SHC_BUDGET_STUCK"
    assert stuck.stats()["entries"] == 2
    assert stuck.stats()["bytes"] == 200
    stuck.unpin(kx)
    freed = stuck.trim()
    assert freed["evicted"] == [kx]
    assert freed["bytes"] == 100


def test_variant_limit_evicts_oldest_and_pinned_variants_block():
    a = make(byte_budget=10_000, entry_budget=10, variant_limit=2)
    k1 = a.put("s", "d", ["A=1"], 10)["key"]
    k2 = a.put("s", "d", ["A=2"], 10)["key"]
    k3 = a.put("s", "d", ["A=3"], 10)["key"]
    assert a.variants("s") == [k2, k3]
    assert a.stats()["evictions"] == 1
    assert a.stats()["entries"] == 2
    blocked = make(byte_budget=10_000, entry_budget=10, variant_limit=2)
    p1 = blocked.put("s", "d", ["A=1"], 10, pinned=True)["key"]
    p2 = blocked.put("s", "d", ["A=2"], 10, pinned=True)["key"]
    with pytest.raises(shc.ShaderCacheError) as exc:
        blocked.put("s", "d", ["A=3"], 10)
    assert exc.value.code == "SHC_VARIANT_LIMIT"
    assert blocked.variants("s") == [p1, p2]
    assert k1 not in a.keys()


def test_put_does_not_evict_before_trim():
    a = make(byte_budget=100, entry_budget=10, variant_limit=10)
    ka = a.put("sa", "d", [], 60)["key"]
    a.put("sb", "d", [], 60)
    stats = a.stats()
    assert stats["entries"] == 2
    assert stats["bytes"] == 120
    assert stats["evictions"] == 0
    out = a.trim()
    assert out["evicted"] == [ka]
    assert out["bytes"] == 60


def test_compile_dedupe_and_finish():
    a = make()
    first = a.begin_compile("s", "d", ["A=1"])
    assert first["status"] == "compile"
    second = a.begin_compile("s", "d", ["A=1"])
    assert second["status"] == "joined"
    stored = a.finish_compile(first["key"], 64)
    assert stored["status"] == "stored"
    assert stored["byte_size"] == 64
    assert a.begin_compile("s", "d", ["A=1"])["status"] == "hit"
    assert a.get(first["key"])["hit"] is True
    assert a.stats()["compiles"] == 1
    assert a.stats()["entries"] == 1


def test_compile_state_errors_and_retry():
    a = make()
    with pytest.raises(shc.ShaderCacheError) as exc:
        a.finish_compile("s|d|", 10)
    assert exc.value.code == "SHC_NOT_COMPILING"
    with pytest.raises(shc.ShaderCacheError) as exc:
        a.fail_compile("s|d|")
    assert exc.value.code == "SHC_NOT_COMPILING"
    started = a.begin_compile("s", "d", [])
    assert a.fail_compile(started["key"])["status"] == "failed"
    assert a.begin_compile("s", "d", [])["status"] == "compile"
    assert a.finish_compile(started["key"], 32)["status"] == "stored"


def test_invalidate_driver_drops_stale_entries():
    a = make()
    k1 = a.put("s1", "d1", [], 100)["key"]
    k2 = a.put("s2", "d1", [], 100, pinned=True)["key"]
    k3 = a.put("s3", "d2", [], 100)["key"]
    out = a.invalidate_driver("d2")
    assert out["removed"] == [k1, k2]
    assert out["bytes"] == 100
    assert a.keys() == [k3]
    assert a.get(k1)["hit"] is False
    with pytest.raises(shc.ShaderCacheError) as exc:
        a.invalidate_driver("")
    assert exc.value.code == "SHC_KEY_INVALID"


def test_snapshot_restore_preserves_lru_and_validates():
    a = make(byte_budget=1000, entry_budget=10, variant_limit=10)
    ka = a.put("sa", "d", [], 100)["key"]
    kb = a.put("sb", "d", [], 200)["key"]
    a.get(ka)
    snapshot = a.snapshot()
    b = make(byte_budget=250, entry_budget=10, variant_limit=10)
    restored = b.restore(snapshot)
    assert restored["restored"] == 2
    assert restored["bytes"] == 300
    assert b.keys() == [ka, kb]
    assert b.stats()["hits"] == 1
    trimmed = b.trim()
    assert trimmed["evicted"] == [kb]
    assert trimmed["bytes"] == 100
    bad = a.snapshot()
    bad["version"] = 1
    with pytest.raises(shc.ShaderCacheError) as exc:
        b.restore(bad)
    assert exc.value.code == "SHC_SNAPSHOT_INVALID"
    tampered = a.snapshot()
    tampered["entries"][0]["key"] = "bogus|d|x"
    with pytest.raises(shc.ShaderCacheError) as exc:
        b.restore(tampered)
    assert exc.value.code == "SHC_SNAPSHOT_INVALID"
    zero = a.snapshot()
    zero["entries"][0]["byte_size"] = 0
    with pytest.raises(shc.ShaderCacheError) as exc:
        b.restore(zero)
    assert exc.value.code == "SHC_SNAPSHOT_INVALID"


def test_concurrent_begin_compile_allows_one_compiler():
    a = make()
    barrier = threading.Barrier(5)
    results = []

    def worker():
        barrier.wait()
        try:
            results.append(a.begin_compile("s", "d", ["A=1"])["status"])
        except Exception as exc:  # pragma: no cover - collected below
            results.append(str(exc))

    threads = [threading.Thread(target=worker) for _ in range(5)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(results) == ["compile", "joined", "joined", "joined", "joined"]
    assert a.stats()["compiles"] == 1
    key = a.compose_key("s", "d", ["A=1"])
    a.finish_compile(key, 128)
    assert a.get(key)["hit"] is True


def test_concurrent_reads_count_hits_atomically():
    a = make()
    key = a.put("s", "d", [], 64)["key"]
    results = []

    def worker():
        results.append(a.get(key)["hit"])

    threads = [threading.Thread(target=worker) for _ in range(32)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert results == [True] * 32
    stats = a.stats()
    assert stats["hits"] == 32
    assert stats["misses"] == 0
    assert stats["hit_rate"] == 1.0
    assert stats["bytes"] == 64
