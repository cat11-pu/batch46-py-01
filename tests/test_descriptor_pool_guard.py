import threading

import pytest

import descriptor_pool_guard as dsc


def make(**kwargs):
    kwargs.setdefault("budgets", {"uniform": 8, "sampler": 4, "storage": 4})
    return dsc.DescriptorPool(**kwargs)


def test_layout_definition_and_allocation_counts():
    a = make(max_sets=10)
    defined = a.define_layout("frame_ubo", counts={"uniform": 2, "sampler": 1})
    assert defined["counts"] == {"uniform": 2, "sampler": 1}
    a.begin_frame(1)
    out = a.allocate(1, "s1", "frame_ubo")
    assert out["counts"] == {"uniform": 2, "sampler": 1}
    assert out["generation"] == 1
    assert out["sets"] == 1
    assert a.usage() == {
        "sets": 1,
        "free_sets": 9,
        "types": {"uniform": 2, "sampler": 1, "storage": 0},
        "frames": 1,
    }


def test_layout_definition_errors():
    a = make()
    with pytest.raises(dsc.DescriptorPoolError) as exc:
        a.define_layout("", counts={"uniform": 1})
    assert exc.value.code == "DSC_LAYOUT_INVALID"
    with pytest.raises(dsc.DescriptorPoolError) as exc:
        a.define_layout("x", counts={})
    assert exc.value.code == "DSC_LAYOUT_INVALID"
    with pytest.raises(dsc.DescriptorPoolError) as exc:
        a.define_layout("x", counts={"uniform": 0})
    assert exc.value.code == "DSC_LAYOUT_INVALID"
    with pytest.raises(dsc.DescriptorPoolError) as exc:
        a.define_layout("x", counts={"push": 1})
    assert exc.value.code == "DSC_UNKNOWN_TYPE"
    a.define_layout("x", counts={"uniform": 1})
    with pytest.raises(dsc.DescriptorPoolError) as exc:
        a.define_layout("x", counts={"uniform": 2})
    assert exc.value.code == "DSC_DUP_LAYOUT"


def test_allocation_precondition_errors():
    a = make()
    a.define_layout("l", counts={"uniform": 1})
    with pytest.raises(dsc.DescriptorPoolError) as exc:
        a.allocate(9, "s1", "l")
    assert exc.value.code == "DSC_FRAME_UNKNOWN"
    a.begin_frame(1)
    with pytest.raises(dsc.DescriptorPoolError) as exc:
        a.allocate(1, "s1", "nope")
    assert exc.value.code == "DSC_UNKNOWN_LAYOUT"
    a.retire_frame(1)
    with pytest.raises(dsc.DescriptorPoolError) as exc:
        a.allocate(1, "s1", "l")
    assert exc.value.code == "DSC_NO_ARENA"
    with pytest.raises(dsc.DescriptorPoolError) as exc:
        a.allocate(7, "s2", "l")
    assert exc.value.code == "DSC_FRAME_UNKNOWN"


def test_duplicate_set_id_and_reuse_after_free():
    a = make(max_sets=4)
    a.define_layout("l", counts={"uniform": 1})
    a.begin_frame(1)
    a.allocate(1, "s1", "l")
    with pytest.raises(dsc.DescriptorPoolError) as exc:
        a.allocate(1, "s1", "l")
    assert exc.value.code == "DSC_DUP_SET"
    assert a.usage()["sets"] == 1
    assert a.usage()["types"]["uniform"] == 1
    a.free("s1")
    again = a.allocate(1, "s1", "l")
    assert again["generation"] == 1
    assert a.usage()["types"]["uniform"] == 1


def test_per_type_budget_exhaustion_is_atomic():
    a = make(max_sets=10, budgets={"uniform": 2, "sampler": 4})
    a.define_layout("l", counts={"uniform": 1, "sampler": 1})
    a.begin_frame(1)
    a.allocate(1, "s1", "l")
    a.allocate(1, "s2", "l")
    with pytest.raises(dsc.DescriptorPoolError) as exc:
        a.allocate(1, "s3", "l")
    assert exc.value.code == "DSC_POOL_EXHAUSTED"
    assert exc.value.detail["kind"] == "type"
    assert exc.value.detail["type"] == "uniform"
    usage = a.usage()
    assert usage["sets"] == 2
    assert usage["types"] == {"uniform": 2, "sampler": 2}


def test_set_count_cap_is_enforced():
    a = make(max_sets=1, budgets={"uniform": 10})
    a.define_layout("l", counts={"uniform": 1})
    a.begin_frame(1)
    a.allocate(1, "s1", "l")
    with pytest.raises(dsc.DescriptorPoolError) as exc:
        a.allocate(1, "s2", "l")
    assert exc.value.code == "DSC_POOL_EXHAUSTED"
    assert exc.value.detail["kind"] == "sets"
    assert a.usage()["sets"] == 1
    assert a.usage()["types"]["uniform"] == 1


def test_free_returns_descriptors_and_invalidates_handle():
    a = make(max_sets=4, budgets={"uniform": 4})
    a.define_layout("l", counts={"uniform": 2})
    a.begin_frame(1)
    a.allocate(1, "s1", "l")
    freed = a.free("s1")
    assert freed["freed"] == {"uniform": 2}
    assert freed["sets"] == 0
    assert a.usage()["types"]["uniform"] == 0
    with pytest.raises(dsc.DescriptorPoolError) as exc:
        a.set_of("s1")
    assert exc.value.code == "DSC_SET_INVALID"
    with pytest.raises(dsc.DescriptorPoolError) as exc:
        a.free("s1")
    assert exc.value.code == "DSC_SET_INVALID"


def test_reset_is_rejected_while_frame_is_recording():
    a = make(max_sets=4)
    a.define_layout("l", counts={"uniform": 2})
    a.begin_frame(1)
    a.allocate(1, "s1", "l")
    with pytest.raises(dsc.DescriptorPoolError) as exc:
        a.reset_frame(1)
    assert exc.value.code == "DSC_FRAME_IN_FLIGHT"
    assert a.set_of("s1")["generation"] == 1
    retired = a.retire_frame(1)
    assert retired["reclaimed"] == ["s1"]
    assert retired["generation"] == 1
    assert a.reset_frame(1)["reclaimed"] == []
    with pytest.raises(dsc.DescriptorPoolError) as exc:
        a.set_of("s1")
    assert exc.value.code == "DSC_SET_INVALID"


def test_reallocation_after_retire_bumps_generation():
    a = make(max_sets=4)
    a.define_layout("l", counts={"uniform": 1})
    a.begin_frame(1)
    a.allocate(1, "s1", "l")
    assert a.generation_of("s1") == 1
    retired = a.retire_frame(1)
    assert retired["reclaimed"] == ["s1"]
    with pytest.raises(dsc.DescriptorPoolError) as exc:
        a.generation_of("s1")
    assert exc.value.code == "DSC_SET_INVALID"
    begun = a.begin_frame(1)
    assert begun["generation"] == 2
    again = a.allocate(1, "s1", "l")
    assert again["generation"] == 2
    assert a.generation_of("s1") == 2
    assert a.usage()["types"]["uniform"] == 1


def test_frames_in_flight_limit_and_double_retire():
    a = make(max_frames_in_flight=2)
    a.begin_frame(1)
    a.begin_frame(2)
    with pytest.raises(dsc.DescriptorPoolError) as exc:
        a.begin_frame(3)
    assert exc.value.code == "DSC_FRAME_IN_FLIGHT"
    a.retire_frame(1)
    a.begin_frame(3)
    assert a.usage()["frames"] == 2
    with pytest.raises(dsc.DescriptorPoolError) as exc:
        a.retire_frame(1)
    assert exc.value.code == "DSC_FRAME_RETIRED"


def test_retiring_one_frame_does_not_touch_another_frame():
    a = make(max_sets=4)
    a.define_layout("l", counts={"uniform": 1})
    a.begin_frame(1)
    a.begin_frame(2)
    a.allocate(1, "s1", "l")
    a.allocate(2, "s2", "l")
    retired = a.retire_frame(1)
    assert retired["reclaimed"] == ["s1"]
    usage = a.usage()
    assert usage["sets"] == 1
    assert usage["types"]["uniform"] == 1
    assert a.set_of("s2")["frame"] == 2
    with pytest.raises(dsc.DescriptorPoolError) as exc:
        a.set_of("s1")
    assert exc.value.code == "DSC_SET_INVALID"


def test_snapshot_restore_keeps_open_frame_and_usage():
    a = make(max_sets=4, budgets={"uniform": 4, "sampler": 2},
             max_frames_in_flight=2)
    a.define_layout("l", counts={"uniform": 2})
    a.begin_frame(1)
    a.allocate(1, "s1", "l")
    snapshot = a.snapshot()
    b = make()
    restored = b.restore(snapshot)
    assert restored == {"restored": 1, "frames": 1}
    assert b.usage() == a.usage()
    assert b.set_of("s1")["generation"] == 1
    b.allocate(1, "s2", "l")
    assert b.usage()["types"]["uniform"] == 4
    retired = b.retire_frame(1)
    assert retired["reclaimed"] == ["s1", "s2"]
    assert b.usage()["sets"] == 0


def test_snapshot_validation_rejects_tampering():
    a = make(max_sets=4, budgets={"uniform": 4})
    a.define_layout("l", counts={"uniform": 2})
    a.begin_frame(1)
    a.allocate(1, "s1", "l")
    snapshot = a.snapshot()
    bad = dict(snapshot)
    bad["version"] = 3
    with pytest.raises(dsc.DescriptorPoolError) as exc:
        a.restore(bad)
    assert exc.value.code == "DSC_SNAPSHOT_INVALID"
    tampered = a.snapshot()
    tampered["used"]["uniform"] += 1
    with pytest.raises(dsc.DescriptorPoolError) as exc:
        a.restore(tampered)
    assert exc.value.code == "DSC_SNAPSHOT_INVALID"
    broken = a.snapshot()
    broken["sets"]["s1"]["counts"]["uniform"] = 1
    with pytest.raises(dsc.DescriptorPoolError) as exc:
        a.restore(broken)
    assert exc.value.code == "DSC_SNAPSHOT_INVALID"


def test_concurrent_distinct_allocations_are_counted_once():
    a = make(max_sets=16, budgets={"uniform": 32, "sampler": 4})
    a.define_layout("l", counts={"uniform": 1})
    a.begin_frame(1)
    barrier = threading.Barrier(8)
    errors = []

    def worker(index):
        barrier.wait()
        try:
            a.allocate(1, f"s{index}", "l")
        except Exception as exc:  # pragma: no cover - collected below
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    usage = a.usage()
    assert usage["sets"] == 8
    assert usage["types"]["uniform"] == 8
    assert a.stats()["allocations"] == 8


def test_concurrent_same_set_id_has_one_winner():
    a = make(max_sets=8, budgets={"uniform": 8})
    a.define_layout("l", counts={"uniform": 1})
    a.begin_frame(2)
    barrier = threading.Barrier(6)
    results = []

    def worker():
        barrier.wait()
        try:
            a.allocate(2, "dup", "l")
            results.append("ok")
        except dsc.DescriptorPoolError as exc:
            results.append(exc.code)
        except Exception as exc:  # pragma: no cover - collected below
            results.append(str(exc))

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert results.count("ok") == 1
    assert results.count("DSC_DUP_SET") == 5
    assert a.usage()["sets"] == 1
    assert a.usage()["types"]["uniform"] == 1
