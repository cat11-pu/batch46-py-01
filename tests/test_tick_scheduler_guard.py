import copy
import threading

import pytest

import tick_scheduler_guard as tick


def make(**kwargs):
    return tick.TickScheduler(**kwargs)


def test_advance_executes_due_ticks_and_tick_runs_one_more():
    h = make(tick_ms=50)
    reports = h.advance(50)
    assert len(reports) == 1
    assert reports[0]["tick"] == 1
    assert h.current_tick() == 1
    assert h.now() == 50
    assert h.drift() == 0
    assert h.stats()["ticks"] == 1
    report = h.tick()
    assert report["tick"] == 2
    assert h.current_tick() == 2
    assert h.now() == 100


def test_partial_elapsed_accumulates_before_the_next_tick():
    h = make(tick_ms=50)
    assert h.advance(20) == []
    assert h.current_tick() == 0
    assert h.now() == 20
    assert h.drift() == 20
    reports = h.advance(30)
    assert len(reports) == 1
    assert h.current_tick() == 1
    assert h.drift() == 0


def test_catchup_is_capped_and_dropped_ticks_are_counted():
    h = make(tick_ms=50, max_catchup=5)
    reports = h.advance(1000)
    assert [row["tick"] for row in reports] == [16, 17, 18, 19, 20]
    assert h.current_tick() == 20
    assert h.drift() == 0
    assert h.stats()["dropped"] == 15
    assert h.stats()["ticks"] == 5


def test_recurring_task_runs_on_its_own_cadence():
    h = make(tick_ms=10)
    calls = []
    h.schedule("every2", lambda: calls.append(h.current_tick()), every=2)
    h.advance(50)
    assert calls == [1, 3, 5]


def test_same_tick_tasks_run_by_priority_then_id():
    h = make(tick_ms=10)
    calls = []
    h.schedule("p-low", lambda: calls.append("p-low"), priority=0)
    h.schedule("p-high", lambda: calls.append("p-high"), priority=5)
    h.schedule("b", lambda: calls.append("b"), priority=1)
    h.schedule("a", lambda: calls.append("a"), priority=1)
    h.advance(10)
    assert calls == ["p-high", "a", "b", "p-low"]


def test_invalid_task_definitions_and_duplicates_are_rejected():
    h = make()
    h.schedule("x", lambda: None)
    with pytest.raises(tick.TickError) as exc:
        h.schedule("x", lambda: None)
    assert exc.value.code == "TICK_TASK_DUP"
    with pytest.raises(tick.TickError) as exc:
        h.cancel("nope")
    assert exc.value.code == "TICK_UNKNOWN_TASK"
    with pytest.raises(tick.TickError) as exc:
        h.schedule("y", lambda: None, every=0)
    assert exc.value.code == "TICK_INVALID_TASK"
    with pytest.raises(tick.TickError) as exc:
        h.schedule("z", lambda: None, delay=-1)
    assert exc.value.code == "TICK_INVALID_TASK"
    with pytest.raises(tick.TickError) as exc:
        h.schedule("w", "not-callable")
    assert exc.value.code == "TICK_INVALID_TASK"
    assert h.pending() == ["x"]


def test_cancelled_task_never_runs_again():
    h = make(tick_ms=10)
    calls = []
    h.schedule("c1", lambda: calls.append("c1"))
    h.schedule("c2", lambda: calls.append("c2"))
    assert h.cancel("c1") is True
    h.advance(30)
    assert calls == ["c2", "c2", "c2"]
    assert h.pending() == ["c2"]


def test_handler_exception_disables_only_that_task():
    h = make(tick_ms=10)
    runs = {"bad": 0, "good": 0}

    def bad():
        runs["bad"] += 1
        raise RuntimeError("boom")

    def good():
        runs["good"] += 1

    h.schedule("bad", bad)
    h.schedule("good", good)
    h.advance(30)
    assert runs == {"bad": 1, "good": 3}
    assert h.stats()["failures"] == 1
    assert h.pending() == ["good"]


def test_tick_budget_defers_the_remaining_tasks_to_later_ticks():
    h = make(tick_ms=10, budget_ms=10)
    calls = []
    h.schedule("A", lambda: calls.append("A"), priority=5, cost=6)
    h.schedule("B", lambda: calls.append("B"), priority=4, cost=6)
    h.advance(30)
    assert calls == ["A", "B", "A"]
    assert h.stats()["overruns"] == 3
    assert h.stats()["deferred"] == 3


def test_max_tasks_limit_is_enforced_and_a_slot_frees_on_cancel():
    h = make(max_tasks=2)
    h.schedule("a", lambda: None)
    h.schedule("b", lambda: None)
    with pytest.raises(tick.TickError) as exc:
        h.schedule("c", lambda: None)
    assert exc.value.code == "TICK_TASK_LIMIT"
    assert h.pending() == ["a", "b"]
    h.cancel("a")
    h.schedule("c", lambda: None)
    assert h.pending() == ["b", "c"]


def test_task_scheduled_inside_a_tick_starts_on_the_next_tick():
    h = make(tick_ms=10)
    calls = []

    def parent():
        calls.append("parent")
        if h.current_tick() == 1:
            h.schedule("child", lambda: calls.append("child"), priority=-1)

    h.schedule("parent", parent)
    h.advance(10)
    assert calls == ["parent"]
    h.advance(10)
    assert calls == ["parent", "parent", "child"]


def test_snapshot_restores_the_loop_and_task_table():
    h = make(tick_ms=10)
    calls = []
    h.schedule("a", lambda: calls.append(h.current_tick()))
    h.advance(20)
    assert calls == [1, 2]
    snap = h.snapshot()
    assert snap["version"] == 1
    h.advance(20)
    assert calls == [1, 2, 3, 4]
    calls.clear()
    h.restore(snap)
    assert h.current_tick() == 2
    assert h.now() == 20
    h.advance(20)
    assert calls == [3, 4]


def test_restore_rejects_a_foreign_snapshot_version():
    h = make(tick_ms=10)
    h.schedule("a", lambda: None)
    h.advance(20)
    bad = copy.deepcopy(h.snapshot())
    bad["version"] = 99
    with pytest.raises(tick.TickError) as exc:
        h.restore(bad)
    assert exc.value.code == "TICK_SNAPSHOT_VERSION"
    assert h.current_tick() == 2


def test_negative_elapsed_is_rejected_and_partial_time_becomes_drift():
    h = make(tick_ms=50)
    with pytest.raises(tick.TickError) as exc:
        h.advance(-1)
    assert exc.value.code == "TICK_INVALID_ELAPSED"
    assert h.now() == 0
    assert len(h.advance(125)) == 2
    assert h.current_tick() == 2
    assert h.drift() == 25
    assert len(h.advance(25)) == 1
    assert h.current_tick() == 3
    assert h.drift() == 0


def test_concurrent_scheduling_registers_every_task_once():
    h = make(tick_ms=10)
    calls = []
    lock = threading.Lock()

    def handler(tag):
        def run():
            with lock:
                calls.append(tag)
        return run

    def worker(base):
        for index in range(5):
            h.schedule("t-%d-%d" % (base, index), handler("%d-%d" % (base, index)))

    threads = [threading.Thread(target=worker, args=(base,))
               for base in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(h.pending()) == 20
    h.advance(10)
    assert len(calls) == 20
    assert len(set(calls)) == 20
    assert h.stats()["tasks_run"] == 20
