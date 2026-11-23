import threading
import time

import pytest

import ptrace_scope_guard as pt


def make(**kwargs):
    return pt.PtraceGuard(**kwargs)


def register_chain(guard, root, depth, *, uid=0, privileged=False):
    guard.register_process(root, uid=uid, ppid=1, privileged=privileged)
    for offset in range(1, depth):
        guard.register_process(root + offset, uid=uid,
                               ppid=root + offset - 1)
    return root + depth - 1


def test_self_attach_is_rejected():
    g = make(scope=0)
    g.register_process(10, uid=0)
    decision = g.check_attach(10, 10)
    assert decision["allowed"] is False
    assert decision["code"] == "PT_SELF"
    with pytest.raises(pt.PtraceError) as exc:
        g.attach(10, 10)
    assert exc.value.code == "PT_SELF"
    assert g.stats()["denied"] == 1
    assert g.attachments() == {}


def test_scope_zero_allows_same_uid_and_privileged_cross_uid():
    g = make(scope=0)
    g.register_process(20, uid=1000)
    g.register_process(21, uid=1000)
    g.register_process(22, uid=1001)
    g.register_process(23, uid=0, privileged=True)
    assert g.attach(20, 21)["allowed"] is True
    assert g.detach(20, 21) is True
    assert g.check_attach(22, 21)["code"] == "PT_DAC_DENY"
    with pytest.raises(pt.PtraceError) as exc:
        g.attach(22, 21)
    assert exc.value.code == "PT_DAC_DENY"
    assert g.attach(22, 23)["allowed"] is True


def test_scope_one_requires_ancestor_unless_privileged():
    g = make(scope=1)
    g.register_process(100, uid=7)
    g.register_process(101, uid=7, ppid=100)
    g.register_process(102, uid=7, ppid=101)
    g.register_process(200, uid=7, ppid=1)
    g.register_process(300, uid=7, ppid=1, privileged=True)
    assert g.attach(102, 100)["allowed"] is True
    assert g.detach(102, 100) is True
    assert g.attach(102, 101)["allowed"] is True
    assert g.detach(102, 101) is True
    assert g.check_attach(102, 200)["code"] == "PT_NOT_ANCESTOR"
    with pytest.raises(pt.PtraceError) as exc:
        g.attach(102, 200)
    assert exc.value.code == "PT_NOT_ANCESTOR"
    assert g.attach(102, 300)["allowed"] is True
    assert g.ancestors(102) == [101, 100, 1]


def test_scope_two_allows_only_privileged_tracers():
    g = make(scope=2)
    g.register_process(400, uid=5)
    g.register_process(401, uid=5, ppid=400)
    g.register_process(402, uid=5, ppid=1, privileged=True)
    assert g.check_attach(401, 400)["code"] == "PT_SCOPE_DENY"
    with pytest.raises(pt.PtraceError) as exc:
        g.attach(401, 400)
    assert exc.value.code == "PT_SCOPE_DENY"
    assert g.attach(401, 402)["allowed"] is True


def test_scope_three_denies_everyone():
    g = make(scope=3)
    g.register_process(450, uid=0)
    g.register_process(451, uid=0, privileged=True)
    decision = g.check_attach(450, 451)
    assert decision["allowed"] is False
    assert decision["code"] == "PT_SCOPE_DENY"
    with pytest.raises(pt.PtraceError) as exc:
        g.attach(450, 451)
    assert exc.value.code == "PT_SCOPE_DENY"
    assert g.attachments() == {}


def test_unknown_and_exited_pids_are_reported():
    g = make(scope=0)
    g.register_process(500, uid=0)
    g.register_process(10, uid=0)
    with pytest.raises(pt.PtraceError) as exc:
        g.attach(999, 10)
    assert exc.value.code == "PT_UNKNOWN"
    assert g.unregister_process(500) == {"reparented": 0, "detached": 0}
    with pytest.raises(pt.PtraceError) as exc:
        g.attach(500, 10)
    assert exc.value.code == "PT_UNKNOWN"
    with pytest.raises(pt.PtraceError):
        g.process_info(500)
    with pytest.raises(pt.PtraceError):
        g.unregister_process(500)
    assert g.stats()["exits"] == 1


def test_pid_reuse_starts_with_clean_state():
    g = make(scope=0)
    g.register_process(600, uid=1)
    g.register_process(601, uid=1)
    g.attach(600, 601)
    g.unregister_process(600)
    assert g.attachments() == {}
    g.register_process(600, uid=1)
    assert g.process_info(600)["attached_by"] is None
    again = g.attach(600, 601)
    assert again["already"] is False
    assert g.stats()["attaches"] == 2


def test_attach_is_exclusive_but_idempotent_for_same_tracer():
    g = make(scope=0)
    for pid in (610, 611, 612):
        g.register_process(pid, uid=2)
    first = g.attach(610, 611)
    assert first["allowed"] is True
    assert first["already"] is False
    again = g.attach(610, 611)
    assert again["allowed"] is True
    assert again["already"] is True
    with pytest.raises(pt.PtraceError) as exc:
        g.attach(610, 612)
    assert exc.value.code == "PT_BUSY"
    assert g.detach(610, 611) is True
    assert g.detach(610, 612) is False
    assert g.attach(610, 612)["already"] is False
    assert g.detach(610, 612) is True
    counts = g.stats()
    assert counts["attaches"] == 2
    assert counts["already"] == 1
    assert counts["denied"] == 1
    assert counts["detaches"] == 2


def test_parent_exit_reparents_children_and_drops_attachments():
    g = make(scope=0)
    g.register_process(700, uid=0)
    g.register_process(701, uid=0, ppid=700)
    g.register_process(702, uid=0)
    g.attach(700, 702)
    out = g.unregister_process(700)
    assert out == {"reparented": 1, "detached": 1}
    assert g.children(1) == [701, 702]
    assert g.ancestors(701) == [1]
    assert g.attachments() == {}
    assert g.stats()["exits"] == 1


def test_reparent_rejects_cycles_and_noop():
    g = make(scope=0)
    g.register_process(800, uid=0)
    g.register_process(801, uid=0, ppid=800)
    g.register_process(802, uid=0, ppid=801)
    with pytest.raises(pt.PtraceError) as exc:
        g.reparent(800, 802)
    assert exc.value.code == "PT_CYCLE"
    with pytest.raises(pt.PtraceError):
        g.reparent(800, 800)
    assert g.reparent(800, 1) is False
    assert g.ancestors(802) == [801, 800, 1]
    assert g.reparent(801, 1) is True
    assert g.ancestors(802) == [801, 1]
    assert g.reparent(801, 800) is True
    assert g.ancestors(802) == [801, 800, 1]


def test_detach_all_only_affects_given_tracer():
    g = make(scope=0)
    for pid in (900, 901, 902, 903, 904):
        g.register_process(pid, uid=0)
    g.attach(901, 900)
    g.attach(902, 900)
    g.attach(904, 903)
    assert g.detach_all(900) == 2
    assert g.attachments() == {904: 903}
    assert g.detach_all(900) == 0
    with pytest.raises(pt.PtraceError) as exc:
        g.detach_all(999)
    assert exc.value.code == "PT_UNKNOWN"


def test_audit_ring_and_counters():
    g = make(scope=0, audit_capacity=5)
    for pid in (950, 951, 952):
        g.register_process(pid, uid=0)
    g.attach(950, 951)
    g.attach(950, 951)
    with pytest.raises(pt.PtraceError):
        g.attach(950, 952)
    g.detach(950, 951)
    g.attach(950, 952)
    rows = g.audit()
    assert len(rows) == 5
    assert [row["event"] for row in rows] == ["attach", "attach_already",
                                             "attach_denied", "detach",
                                             "attach"]
    assert rows[2]["code"] == "PT_BUSY"
    assert len(g.audit(2)) == 2
    counts = g.stats()
    assert counts["attaches"] == 2
    assert counts["already"] == 1
    assert counts["denied"] == 1
    assert counts["detaches"] == 1


def test_snapshot_restore_preserves_tree_scope_and_busy():
    g = make(scope=2)
    g.register_process(1000, uid=3)
    g.register_process(1001, uid=3, ppid=1000)
    g.register_process(1002, uid=3, ppid=1, privileged=True)
    g.register_process(1003, uid=3, privileged=True)
    g.attach(1001, 1002)
    blob = g.snapshot()
    restored = pt.PtraceGuard.restore(blob)
    assert restored.scope() == 2
    assert restored.ancestors(1001) == [1000, 1]
    assert restored.attachments() == {1001: 1002}
    assert restored.process_info(1001)["attached_by"] == 1002
    assert restored.process_info(1002)["privileged"] is True
    with pytest.raises(pt.PtraceError) as exc:
        restored.attach(1001, 1003)
    assert exc.value.code == "PT_BUSY"
    assert restored.stats()["attaches"] == 1
    with pytest.raises(pt.PtraceError) as exc:
        pt.PtraceGuard.restore("{broken")
    assert exc.value.code == "PT_SNAPSHOT_INVALID"


def test_concurrent_attach_has_a_single_winner():
    g = make(scope=0)
    g.register_process(5000, uid=0)
    for offset in range(1, 9):
        g.register_process(5000 + offset, uid=0)
    barrier = threading.Barrier(8)
    wins = []
    busy = []
    errors = []

    def worker(offset):
        try:
            barrier.wait()
            g.attach(5000, 5000 + offset)
            wins.append(offset)
        except pt.PtraceError as exc:
            if exc.code == "PT_BUSY":
                busy.append(offset)
            else:  # pragma: no cover - unexpected code
                errors.append(exc.code)
        except Exception as exc:  # pragma: no cover - failure path
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(offset,))
               for offset in range(1, 9)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    assert len(wins) == 1
    assert len(busy) == 7
    assert len(g.attachments()) == 1
    counts = g.stats()
    assert counts["attaches"] == 1
    assert counts["denied"] == 7


def test_deep_tree_attach_stays_within_budget():
    g = make(scope=1)
    deepest = register_chain(g, 1000, 600)
    start = time.monotonic()
    for _ in range(300):
        decision = g.check_attach(deepest, 1000)
        assert decision["allowed"] is True
    elapsed = time.monotonic() - start
    assert elapsed < 2.0
    assert g.attachments() == {}
    assert g.stats()["attaches"] == 0
    assert g.attach(deepest, 1000)["allowed"] is True
    assert g.attachments() == {deepest: 1000}
