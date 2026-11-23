import threading

import pytest

import pipeline_cache_guard as plc


def make(**kwargs):
    return plc.PipelineCache(**kwargs)


def define(a, pipeline_id, **kwargs):
    kwargs.setdefault("vs", "vs_main")
    kwargs.setdefault("fs", "fs_main")
    return a.define_pipeline(pipeline_id, **kwargs)


def test_hash_ignores_vertex_layout_and_tag_order():
    a = make()
    first = define(
        a, "p1", vertex_layout=[("pos", "RGBA32F"), ("uv", "RG32F")],
        tags=["beta", "alpha"],
    )
    second = define(
        a, "p2", vertex_layout=[("uv", "RG32F"), ("pos", "RGBA32F")],
        tags=["alpha", "beta"],
    )
    assert first["hash"] == second["hash"]
    assert first["group"] == second["group"] == 1
    assert define(a, "p3", render_pass="shadow")["group"] == 2


def test_hash_changes_with_pipeline_state():
    a = make()
    base = define(a, "base")["hash"]
    assert define(a, "t1", depth_test=False)["hash"] != base
    assert define(a, "t2", blend="alpha")["hash"] != base
    assert define(a, "t3", render_pass="shadow")["hash"] != base
    assert define(a, "t4", vs="vs_other")["hash"] != base


def test_hash_is_sixteen_lowercase_hex_characters():
    a = make()
    digest = define(a, "p")["hash"]
    assert len(digest) == 16
    assert digest == digest.lower()
    assert all(char in "0123456789abcdef" for char in digest)


def test_descriptor_validation_errors():
    a = make()
    with pytest.raises(plc.PipelineCacheError) as exc:
        a.define_pipeline("", vs="v", fs="f")
    assert exc.value.code == "PLC_ID_INVALID"
    with pytest.raises(plc.PipelineCacheError) as exc:
        a.define_pipeline("x", vs="", fs="f")
    assert exc.value.code == "PLC_DESCRIPTOR_INVALID"
    with pytest.raises(plc.PipelineCacheError) as exc:
        a.define_pipeline(
            "x", vs="v", fs="f",
            vertex_layout=[("pos", "f"), ("pos", "g")],
        )
    assert exc.value.code == "PLC_LAYOUT_INVALID"
    with pytest.raises(plc.PipelineCacheError) as exc:
        a.define_pipeline("x", vs="v", fs="f", vertex_layout=[("pos",)])
    assert exc.value.code == "PLC_LAYOUT_INVALID"
    define(a, "x")
    with pytest.raises(plc.PipelineCacheError) as exc:
        a.define_pipeline("x", vs="v2", fs="f")
    assert exc.value.code == "PLC_ID_CONFLICT"


def test_register_dedupes_by_pipeline_hash():
    a = make()
    define(a, "p1")
    define(a, "p2")
    first = a.register("p1")
    assert first["status"] == "stored"
    assert first["group"] == 1
    assert a.register("p1")["status"] == "duplicate"
    duplicate = a.register("p2")
    assert duplicate["status"] == "duplicate"
    assert duplicate["hash"] == first["hash"]
    assert a.stats()["entries"] == 1
    with pytest.raises(plc.PipelineCacheError) as exc:
        a.register("nope")
    assert exc.value.code == "PLC_UNKNOWN"


def test_get_reports_hit_and_miss():
    a = make()
    define(a, "p1")
    a.register("p1")
    hit = a.get("p1")
    assert hit["hit"] is True
    assert hit["bytes"] == 0
    assert hit["group"] == 1
    assert hit["generation"] == 1
    define(a, "p2", vs="vs_other")
    miss = a.get("p2")
    assert miss["hit"] is False
    with pytest.raises(plc.PipelineCacheError) as exc:
        a.get("nope")
    assert exc.value.code == "PLC_UNKNOWN"
    stats = a.stats()
    assert stats["hits"] == 1
    assert stats["misses"] == 1
    assert stats["entries"] == 1


def test_entry_budget_trims_oldest_pipeline():
    a = make(entry_budget=2)
    for pipeline_id in ("p1", "p2", "p3"):
        define(a, pipeline_id, vs="vs_" + pipeline_id)
        a.register(pipeline_id)
    out = a.trim()
    assert out["evicted"] == ["p1"]
    assert out["entries"] == 2
    assert a.register("p1")["status"] == "stored"
    out = a.trim()
    assert out["evicted"] == ["p2"]
    assert a.keys() == ["p3", "p1"]


def test_get_refreshes_lru_position():
    a = make(entry_budget=1)
    define(a, "p1")
    define(a, "p2", vs="vs_p2")
    a.register("p1")
    a.register("p2")
    a.get("p1")
    out = a.trim()
    assert out["evicted"] == ["p2"]
    assert a.keys() == ["p1"]


def test_byte_budget_accounts_for_blobs_and_evicts_lru():
    a = make(entry_budget=10, byte_budget=300)
    for pipeline_id in ("p1", "p2", "p3"):
        define(a, pipeline_id, vs="vs_" + pipeline_id)
        a.register(pipeline_id)
    a.store_blob("p1", b"a" * 100)
    a.store_blob("p2", b"b" * 100)
    a.store_blob("p3", b"c" * 100)
    assert a.stats()["bytes"] == 300
    a.store_blob("p1", b"z" * 200)
    assert a.stats()["bytes"] == 400
    out = a.trim()
    assert out["evicted"] == ["p2"]
    assert out["bytes"] == 300
    assert out["entries"] == 2
    assert a.blob("p1") == b"z" * 200
    assert a.blob("p3") == b"c" * 100


def test_blob_size_and_presence_errors():
    a = make(entry_budget=10, byte_budget=64)
    define(a, "p1")
    a.register("p1")
    with pytest.raises(plc.PipelineCacheError) as exc:
        a.blob("p1")
    assert exc.value.code == "PLC_NO_BLOB"
    with pytest.raises(plc.PipelineCacheError) as exc:
        a.store_blob("p1", b"a" * 65)
    assert exc.value.code == "PLC_BLOB_TOO_LARGE"
    assert a.stats()["bytes"] == 0
    with pytest.raises(plc.PipelineCacheError) as exc:
        a.store_blob("p1", "text")
    assert exc.value.code == "PLC_BLOB_INVALID"
    with pytest.raises(plc.PipelineCacheError) as exc:
        a.store_blob("p1", b"")
    assert exc.value.code == "PLC_BLOB_INVALID"
    a.store_blob("p1", b"a" * 32)
    assert a.blob("p1") == b"a" * 32
    define(a, "p2", vs="vs_p2")
    with pytest.raises(plc.PipelineCacheError) as exc:
        a.blob("p2")
    assert exc.value.code == "PLC_UNKNOWN"


def test_compatibility_groups_follow_layout_and_render_pass():
    a = make()
    first = define(a, "p1")["group"]
    second = define(a, "p2")["group"]
    third = define(a, "p3", layout="alt")["group"]
    fourth = define(a, "p4", render_pass="shadow")["group"]
    assert first == second == 1
    assert third == 2
    assert fourth == 3
    assert a.compat_group("p1") == 1
    with pytest.raises(plc.PipelineCacheError) as exc:
        a.compat_group("nope")
    assert exc.value.code == "PLC_UNKNOWN"


def test_binding_validation_checks_layout():
    a = make()
    define(a, "p1")
    a.register("p1")
    assert a.validate_bindings("p1", "default")["compatible"] is True
    with pytest.raises(plc.PipelineCacheError) as exc:
        a.validate_bindings("p1", "alt")
    assert exc.value.code == "PLC_LAYOUT_MISMATCH"
    with pytest.raises(plc.PipelineCacheError) as exc:
        a.validate_bindings("nope", "default")
    assert exc.value.code == "PLC_UNKNOWN"


def test_generation_invalidation_is_monotonic():
    a = make()
    define(a, "p1")
    define(a, "p2", vs="vs_p2")
    a.register("p1")
    a.register("p2")
    out = a.invalidate_generation(2)
    assert out["removed"] == ["p1", "p2"]
    assert out["entries"] == 0
    assert out["generation"] == 2
    stored = a.register("p1")
    assert stored["status"] == "stored"
    assert stored["generation"] == 2
    with pytest.raises(plc.PipelineCacheError) as exc:
        a.invalidate_generation(2)
    assert exc.value.code == "PLC_GENERATION_REGRESS"
    with pytest.raises(plc.PipelineCacheError) as exc:
        a.invalidate_generation(1)
    assert exc.value.code == "PLC_GENERATION_REGRESS"
    out = a.invalidate_generation(3)
    assert out["removed"] == ["p1"]
    assert a.stats()["generation"] == 3


def test_snapshot_restore_preserves_cache_and_validates_hashes():
    a = make(entry_budget=10, byte_budget=1000)
    define(a, "p1")
    define(a, "p2", vs="vs_p2")
    a.register("p1")
    a.register("p2")
    a.store_blob("p1", b"z" * 40)
    snapshot = a.snapshot()
    b = make(entry_budget=1, byte_budget=1000)
    restored = b.restore(snapshot)
    assert restored["restored"] == 2
    assert restored["generation"] == 1
    assert b.get("p1")["hit"] is True
    assert b.blob("p1") == b"z" * 40
    assert b.compat_group("p2") == a.compat_group("p2")
    out = b.trim()
    assert out["evicted"] == ["p2"]
    assert out["entries"] == 1
    tampered = a.snapshot()
    tampered["entries"][0]["hash"] = "0000000000000000"
    with pytest.raises(plc.PipelineCacheError) as exc:
        b.restore(tampered)
    assert exc.value.code == "PLC_HASH_MISMATCH"
    bad = a.snapshot()
    bad["version"] = 2
    with pytest.raises(plc.PipelineCacheError) as exc:
        b.restore(bad)
    assert exc.value.code == "PLC_SNAPSHOT_INVALID"


def test_concurrent_register_and_get_are_atomic():
    a = make()
    define(a, "p1")
    barrier = threading.Barrier(6)
    statuses = []

    def register_worker():
        barrier.wait()
        try:
            statuses.append(a.register("p1")["status"])
        except Exception as exc:  # pragma: no cover - collected below
            statuses.append(str(exc))

    threads = [threading.Thread(target=register_worker) for _ in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(statuses) == [
        "duplicate", "duplicate", "duplicate", "duplicate", "duplicate", "stored",
    ]
    assert a.stats()["entries"] == 1
    hits = []

    def get_worker():
        hits.append(a.get("p1")["hit"])

    threads = [threading.Thread(target=get_worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert hits == [True] * 8
    assert a.stats()["hits"] == 8
    assert a.stats()["misses"] == 0
