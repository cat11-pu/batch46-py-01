import threading
import time

import pytest

import kvm_msr_guard as kg


def make(**kwargs):
    return kg.KvmMsrGuard(**kwargs)


def open_vm(guard, vm="vm1", rules=None):
    return guard.define_policy(vm, rules or [(0, 0xFFFFFFFF, "allow")])


def test_vcpu_lifecycle_limits_and_errors():
    g = make(max_vcpus=2)
    open_vm(g)
    assert g.create_vcpu("vm1", 0) == {"vm": "vm1", "vcpu": 0}
    g.create_vcpu("vm1", 1)
    with pytest.raises(kg.MsrGuardError) as exc:
        g.create_vcpu("vm1", 1)
    assert exc.value.code == "MSR_VCPU_EXISTS"
    with pytest.raises(kg.MsrGuardError) as exc:
        g.create_vcpu("vm1", 2)
    assert exc.value.code == "MSR_VCPU_LIMIT"
    with pytest.raises(kg.MsrGuardError) as exc:
        g.create_vcpu("ghost", 0)
    assert exc.value.code == "MSR_VM_UNKNOWN"
    assert g.remove_vcpu("vm1", 0) is True
    with pytest.raises(kg.MsrGuardError) as exc:
        g.remove_vcpu("vm1", 0)
    assert exc.value.code == "MSR_VCPU_UNKNOWN"


def test_exact_rule_wins_over_catch_all_deny():
    g = make()
    g.define_policy("vm1", [(0, 0xFFFFFFFF, "deny"), (0x1B, 0x1B, "allow")],
                    default="deny")
    g.create_vcpu("vm1", 0)
    out = g.check("vm1", 0, 0x1B, 0x1234)
    assert out["allowed"] is True
    assert out["action"] == "allow"
    assert out["value"] == 0x1234
    with pytest.raises(kg.MsrGuardError) as exc:
        g.check("vm1", 0, 0x10, 1)
    assert exc.value.code == "MSR_DENIED"
    assert exc.value.detail == 0x10


def test_mask_action_filters_write_and_read():
    g = make()
    g.define_policy("vm1", [(0x100, 0x1FF, "mask", 0xF0)])
    g.create_vcpu("vm1", 0)
    written = g.set_msr("vm1", 0, 0x100, 0xAB)
    assert written["value"] == 0xA0
    assert g.read_msr("vm1", 0, 0x100) == 0xA0
    assert g.read_msr("vm1", 0, 0x101) == 0
    with pytest.raises(kg.MsrGuardError) as exc:
        g.set_msr("vm1", 0, 0x200, 1)
    assert exc.value.code == "MSR_DENIED"


def test_checks_require_policy_vcpu_and_valid_index():
    g = make()
    with pytest.raises(kg.MsrGuardError) as exc:
        g.create_vcpu("vm1", 0)
    assert exc.value.code == "MSR_VM_UNKNOWN"
    g.define_policy("vm1", [])
    with pytest.raises(kg.MsrGuardError) as exc:
        g.check("vm1", 0, 0x10, 0)
    assert exc.value.code == "MSR_VCPU_UNKNOWN"
    g.create_vcpu("vm1", 0)
    with pytest.raises(kg.MsrGuardError) as exc:
        g.check("vm1", 0, -1, 0)
    assert exc.value.code == "MSR_BAD_INDEX"
    with pytest.raises(kg.MsrGuardError) as exc:
        g.check("vm1", 0, 0x10, 0)
    assert exc.value.code == "MSR_DENIED"


def test_batch_rolls_back_when_any_access_denied():
    g = make()
    g.define_policy("vm1", [(0x1B, 0x1B, "allow"), (0x10, 0x10, "deny")])
    g.create_vcpu("vm1", 0)
    g.set_msr("vm1", 0, 0x1B, 7)
    before = g.stats()
    with pytest.raises(kg.MsrGuardError) as exc:
        g.apply_batch("vm1", 0, [
            {"index": 0x1B, "value": 99},
            {"index": 0x10, "value": 5},
        ], batch_id="b1")
    assert exc.value.code == "MSR_BATCH_REJECTED"
    assert exc.value.detail == 1
    after = g.stats()
    assert after["checks"] == before["checks"]
    assert after["allowed"] == before["allowed"]
    assert after["denied_batches"] == before["denied_batches"] + 1
    assert g.read_msr("vm1", 0, 0x1B) == 7
    g.define_policy("vm1", [(0, 0xFFFFFFFF, "allow")])
    out = g.apply_batch("vm1", 0, [
        {"index": 0x1B, "value": 99},
        {"index": 0x10, "value": 5},
    ], batch_id="b1")
    assert out["status"] == "applied"
    assert g.read_msr("vm1", 0, 0x1B) == 99
    assert g.read_msr("vm1", 0, 0x10) == 5


def test_same_batch_id_is_applied_once():
    g = make()
    open_vm(g)
    g.create_vcpu("vm1", 0)
    accesses = [{"index": 0x1B, "value": 1},
                {"index": 0x1C, "value": 2}]
    first = g.apply_batch("vm1", 0, accesses, batch_id="boot-1")
    assert first["status"] == "applied"
    assert len(first["results"]) == 2
    before = g.stats()
    second = g.apply_batch("vm1", 0, accesses, batch_id="boot-1")
    assert second["status"] == "duplicate"
    assert second["results"] == []
    after = g.stats()
    assert after["duplicates"] == before["duplicates"] + 1
    assert after["checks"] == before["checks"]
    with pytest.raises(kg.MsrGuardError) as exc:
        g.apply_batch("vm1", 0, [{"index": 0x1B, "value": 3}],
                      batch_id="boot-1")
    assert exc.value.code == "MSR_BATCH_CONFLICT"


def test_batch_applies_accesses_in_given_order():
    g = make()
    open_vm(g)
    g.create_vcpu("vm1", 0)
    out = g.apply_batch("vm1", 0, [
        {"index": 0x1B, "value": 1},
        {"index": 0x1B, "value": 2},
        {"index": 0x1B, "write": False},
    ])
    assert [row["index"] for row in out["results"]] == [0x1B, 0x1B, 0x1B]
    assert [row["value"] for row in out["results"]] == [1, 2, 2]
    assert g.read_msr("vm1", 0, 0x1B) == 2


def test_msr_values_and_policies_are_isolated_between_vms():
    g = make()
    open_vm(g, "vm1")
    open_vm(g, "vm2")
    g.create_vcpu("vm1", 0)
    g.create_vcpu("vm2", 0)
    g.set_msr("vm1", 0, 0x1B, 11)
    g.set_msr("vm2", 0, 0x1B, 22)
    assert g.read_msr("vm1", 0, 0x1B) == 11
    assert g.read_msr("vm2", 0, 0x1B) == 22
    g.define_policy("vm1", [(0, 0xFFFFFFFF, "deny")])
    with pytest.raises(kg.MsrGuardError):
        g.set_msr("vm1", 0, 0x1B, 33)
    assert g.read_msr("vm2", 0, 0x1B) == 22


def test_removing_vcpu_drops_values_but_keeps_history():
    g = make()
    open_vm(g)
    g.create_vcpu("vm1", 3)
    g.set_msr("vm1", 3, 0x1B, 5)
    checks = g.stats()["checks"]
    assert g.remove_vcpu("vm1", 3) is True
    with pytest.raises(kg.MsrGuardError) as exc:
        g.read_msr("vm1", 3, 0x1B)
    assert exc.value.code == "MSR_VCPU_UNKNOWN"
    g.create_vcpu("vm1", 3)
    assert g.read_msr("vm1", 3, 0x1B) == 0
    assert g.stats()["checks"] == checks + 1
    assert len(g.audit()) == 2


def test_audit_ring_and_counters_are_bounded():
    g = make(audit_capacity=4)
    g.define_policy("vm1", [(0x1B, 0x1B, "allow")])
    g.create_vcpu("vm1", 0)
    for value in range(3):
        g.set_msr("vm1", 0, 0x1B, value)
    for value in range(3):
        with pytest.raises(kg.MsrGuardError):
            g.set_msr("vm1", 0, 0x10, value)
    audit = g.audit()
    assert len(audit) == 4
    assert [row["allowed"] for row in audit] == [True, False, False, False]
    assert audit[-1]["code"] == "MSR_DENIED"
    assert len(g.audit(2)) == 2
    counts = g.stats()
    assert counts["checks"] == 6
    assert counts["allowed"] == 3
    assert counts["denied"] == 3


def test_decision_cache_is_bounded_and_invalidated():
    g = make(cache_capacity=2)
    g.define_policy("vm1", [(0, 0xFFFFFFFF, "deny")])
    g.create_vcpu("vm1", 0)
    for index in range(10):
        with pytest.raises(kg.MsrGuardError):
            g.check("vm1", 0, index, 0)
    assert g.cache_size("vm1") == 2
    g.define_policy("vm1", [(0, 0xFFFFFFFF, "allow")])
    assert g.cache_size("vm1") == 0
    assert g.check("vm1", 0, 5, 5)["allowed"] is True


def test_snapshot_restore_keeps_values_quota_and_batch_ledger():
    g = make(max_vcpus=4, cache_capacity=2)
    g.define_policy("vm1", [(0, 0xFFFFFFFF, "allow"),
                            (0x300, 0x300, "mask", 0xFF)])
    g.create_vcpu("vm1", 2)
    g.set_msr("vm1", 2, 0x1B, 0xDEAD)
    g.apply_batch("vm1", 2, [{"index": 0x300, "value": 0x1AB}],
                  batch_id="snap-b")
    blob = g.snapshot()
    restored = kg.KvmMsrGuard.restore(blob)
    assert restored.cache_size("vm1") == 0
    assert restored.read_msr("vm1", 2, 0x1B) == 0xDEAD
    assert restored.read_msr("vm1", 2, 0x300) == 0xAB
    assert restored.stats()["batches"] == 1
    again = restored.apply_batch(
        "vm1", 2, [{"index": 0x300, "value": 0x1AB}], batch_id="snap-b")
    assert again["status"] == "duplicate"
    with pytest.raises(kg.MsrGuardError) as exc:
        kg.KvmMsrGuard.restore("{not json")
    assert exc.value.code == "MSR_SNAPSHOT_INVALID"


def test_closed_vm_rejects_writes_but_allows_snapshot():
    g = make()
    open_vm(g)
    g.create_vcpu("vm1", 0)
    g.set_msr("vm1", 0, 0x1B, 1)
    assert g.close_vm("vm1") is True
    assert g.close_vm("vm1") is False
    calls = (
        lambda: g.set_msr("vm1", 0, 0x1B, 2),
        lambda: g.read_msr("vm1", 0, 0x1B),
        lambda: g.create_vcpu("vm1", 1),
        lambda: g.remove_vcpu("vm1", 0),
        lambda: g.define_policy("vm1", []),
        lambda: g.apply_batch("vm1", 0, [{"index": 0x1B, "value": 3}]),
    )
    for call in calls:
        with pytest.raises(kg.MsrGuardError) as exc:
            call()
        assert exc.value.code == "MSR_VM_CLOSED"
    assert "vm1" in g.snapshot()
    with pytest.raises(kg.MsrGuardError) as exc:
        g.close_vm("ghost")
    assert exc.value.code == "MSR_VM_UNKNOWN"


def test_concurrent_msr_writes_are_serialized():
    g = make(audit_capacity=1024)
    open_vm(g)
    g.create_vcpu("vm1", 0)
    barrier = threading.Barrier(8)
    errors = []
    values = []

    def worker(worker_id):
        try:
            barrier.wait()
            for round_no in range(25):
                g.set_msr("vm1", 0, 0x400 + worker_id,
                          worker_id * 100 + round_no)
                values.append(g.read_msr("vm1", 0, 0x400 + worker_id))
        except Exception as exc:  # pragma: no cover - failure path
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    assert len(values) == 200
    assert g.stats()["allowed"] == 400
    for n in range(8):
        assert g.read_msr("vm1", 0, 0x400 + n) == n * 100 + 24


def test_cached_checks_stay_within_budget():
    g = make(cache_capacity=16, audit_capacity=16)
    open_vm(g)
    g.create_vcpu("vm1", 0)
    start = time.monotonic()
    for value in range(20000):
        g.check("vm1", 0, 0x1B, value)
    elapsed = time.monotonic() - start
    assert elapsed < 2.0
    assert g.stats()["allowed"] == 20000
    assert len(g.audit()) == 16
