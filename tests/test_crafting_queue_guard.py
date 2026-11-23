import json
import threading

import pytest

import crafting_queue_guard as cq

T0 = "2026-11-23T10:00:00+00:00"


def make():
    q = cq.CraftingQueue()
    q.add_station("forge", capacity=3, parallel=1)
    q.register_recipe("smelt", {"ore": 2}, {"ingot": 1}, 10, "forge")
    q.deposit("acct", "ore", 10)
    return q


def test_enqueue_reserves_materials_without_consuming_them():
    q = make()
    job = q.enqueue("acct", "smelt", 1, now=T0)
    assert job["status"] == "running"
    assert job["reserved"] == {"ore": 2}
    assert q.inventory("acct") == {"ore": 10}
    assert q.available("acct") == {"ore": 8}


def test_enqueue_without_materials_reserves_nothing():
    q = cq.CraftingQueue()
    q.add_station("forge", capacity=3, parallel=1)
    q.register_recipe("smelt", {"ore": 2}, {"ingot": 1}, 10, "forge")
    q.deposit("acct", "ore", 1)
    with pytest.raises(cq.CraftError) as exc:
        q.enqueue("acct", "smelt", 1, now=T0)
    assert exc.value.code == "CRAFT_INSUFFICIENT_MATERIALS"
    assert q.inventory("acct") == {"ore": 1}
    assert q.available("acct") == {"ore": 1}
    assert q.stats()["jobs"] == 0


def test_station_capacity_rejects_extra_jobs():
    q = cq.CraftingQueue()
    q.add_station("forge", capacity=2, parallel=1)
    q.register_recipe("smelt", {"ore": 1}, {"ingot": 1}, 10, "forge")
    q.deposit("acct", "ore", 10)
    q.enqueue("acct", "smelt", 1, now=T0)
    q.enqueue("acct", "smelt", 1, now=T0)
    with pytest.raises(cq.CraftError) as exc:
        q.enqueue("acct", "smelt", 1, now=T0)
    assert exc.value.code == "CRAFT_QUEUE_FULL"
    assert len(q.queue_view("acct")) == 2


def test_priority_starts_before_older_low_priority_job():
    q = cq.CraftingQueue()
    q.add_station("forge", capacity=5, parallel=1)
    q.register_recipe("smelt", {"ore": 1}, {"ingot": 1}, 10, "forge")
    q.deposit("acct", "ore", 10)
    first = q.enqueue("acct", "smelt", 1, now=T0)
    urgent = q.enqueue("acct", "smelt", 1, priority=5, now=T0)
    normal = q.enqueue("acct", "smelt", 1, priority=0, now=T0)
    also_urgent = q.enqueue("acct", "smelt", 1, priority=5, now=T0)
    out = q.tick("2026-11-23T10:00:10+00:00")
    assert out["completed"] == [first["job_id"]]
    assert out["started"] == [urgent["job_id"]]
    assert q.job(urgent["job_id"])["started_at"] == "2026-11-23T10:00:10+00:00"
    assert q.job(normal["job_id"])["status"] == "pending"
    out = q.tick("2026-11-23T10:00:20+00:00")
    assert out["started"] == [also_urgent["job_id"]]
    assert q.job(normal["job_id"])["status"] == "pending"


def test_same_priority_starts_in_fifo_order():
    q = cq.CraftingQueue()
    q.add_station("forge", capacity=5, parallel=1)
    q.register_recipe("smelt", {"ore": 1}, {"ingot": 1}, 10, "forge")
    q.deposit("acct", "ore", 10)
    q.enqueue("acct", "smelt", 1, now=T0)
    second = q.enqueue("acct", "smelt", 1, now=T0)
    third = q.enqueue("acct", "smelt", 1, now=T0)
    out = q.tick("2026-11-23T10:00:10+00:00")
    assert out["started"] == [second["job_id"]]
    out = q.tick("2026-11-23T10:00:20+00:00")
    assert out["started"] == [third["job_id"]]


def test_completion_grants_output_exactly_once():
    q = make()
    job = q.enqueue("acct", "smelt", 1, now=T0)
    early = q.tick("2026-11-23T10:00:09+00:00")
    assert early["completed"] == []
    assert q.inventory("acct").get("ingot", 0) == 0
    done = q.tick("2026-11-23T10:00:10+00:00")
    assert done["completed"] == [job["job_id"]]
    assert q.inventory("acct")["ore"] == 8
    assert q.inventory("acct")["ingot"] == 1
    assert q.available("acct")["ore"] == 8
    again = q.tick("2026-11-23T10:00:11+00:00")
    assert again["completed"] == []
    assert q.inventory("acct")["ingot"] == 1


def test_cancel_pending_refunds_everything_and_releases_reservation():
    q = make()
    running = q.enqueue("acct", "smelt", 1, now=T0)
    waiting = q.enqueue("acct", "smelt", 1, now=T0)
    assert q.available("acct") == {"ore": 6}
    out = q.cancel("acct", waiting["job_id"], now=T0)
    assert out["status"] == "cancelled"
    assert out["refund"] == {"ore": 2}
    assert q.job(waiting["job_id"])["status"] == "cancelled"
    assert q.inventory("acct") == {"ore": 10}
    assert q.available("acct") == {"ore": 8}
    assert q.job(running["job_id"])["status"] == "running"
    with pytest.raises(cq.CraftError) as exc:
        q.cancel("acct", waiting["job_id"], now=T0)
    assert exc.value.code == "CRAFT_JOB_CLOSED"


def test_cancel_running_burns_half_of_each_reserved_material():
    q = cq.CraftingQueue()
    q.add_station("forge", capacity=3, parallel=1)
    q.register_recipe("blade", {"ore": 2, "coal": 1}, {"sword": 1}, 10, "forge")
    q.deposit("acct", "ore", 10)
    q.deposit("acct", "coal", 3)
    job = q.enqueue("acct", "blade", 1, now=T0)
    out = q.cancel("acct", job["job_id"], now=T0)
    assert out["refund"] == {"ore": 1}
    assert q.inventory("acct") == {"ore": 9, "coal": 2}
    assert q.available("acct") == {"ore": 9, "coal": 2}
    assert q.snapshot()["reserved"]["acct"] == {"ore": 0, "coal": 0}


def test_withdraw_cannot_take_reserved_materials():
    q = make()
    q.enqueue("acct", "smelt", 1, now=T0)
    assert q.available("acct") == {"ore": 8}
    with pytest.raises(cq.CraftError) as exc:
        q.withdraw("acct", "ore", 9)
    assert exc.value.code == "CRAFT_INSUFFICIENT_AVAILABLE"
    q.withdraw("acct", "ore", 8)
    assert q.inventory("acct") == {"ore": 2}
    assert q.available("acct") == {"ore": 0}


def test_duplicate_request_id_replays_the_same_job():
    q = make()
    first = q.enqueue("acct", "smelt", 1, request_id="req-1", now=T0)
    second = q.enqueue("acct", "smelt", 1, request_id="req-1", now=T0)
    assert second["job_id"] == first["job_id"]
    assert second["replayed"] is True
    assert len(q.queue_view("acct")) == 1
    assert q.stats()["jobs"] == 1
    assert q.available("acct") == {"ore": 8}


def test_account_job_limit_rejects_new_enqueue():
    q = cq.CraftingQueue(max_jobs_per_account=3)
    q.add_station("forge", capacity=10, parallel=1)
    q.register_recipe("smelt", {"ore": 1}, {"ingot": 1}, 10, "forge")
    q.deposit("acct", "ore", 100)
    for _ in range(3):
        q.enqueue("acct", "smelt", 1, now=T0)
    with pytest.raises(cq.CraftError) as exc:
        q.enqueue("acct", "smelt", 1, now=T0)
    assert exc.value.code == "CRAFT_ACCOUNT_LIMIT"
    assert q.stats()["jobs"] == 3


def test_fail_running_job_refunds_half_and_grants_nothing():
    q = cq.CraftingQueue()
    q.add_station("forge", capacity=3, parallel=1)
    q.register_recipe("smelt", {"ore": 2}, {"ingot": 1}, 20, "forge")
    q.deposit("acct", "ore", 6)
    job = q.enqueue("acct", "smelt", 2, now=T0)
    assert job["reserved"] == {"ore": 4}
    out = q.fail(job["job_id"], reason="bellows ruptured", now=T0)
    assert out["status"] == "failed"
    assert out["refund"] == {"ore": 2}
    assert q.inventory("acct") == {"ore": 4}
    assert q.available("acct") == {"ore": 4}
    q.tick("2026-11-23T11:00:00+00:00")
    assert q.inventory("acct").get("ingot", 0) == 0
    with pytest.raises(cq.CraftError) as exc:
        q.fail(job["job_id"], now=T0)
    assert exc.value.code == "CRAFT_JOB_CLOSED"


def test_snapshot_restore_resumes_job_and_sequence():
    q = make()
    job = q.enqueue("acct", "smelt", 1, now=T0)
    snapshot = q.snapshot()
    json.dumps(snapshot)
    restored = cq.CraftingQueue()
    restored.restore(snapshot)
    view = restored.job(job["job_id"])
    assert view["status"] == "running"
    assert view["ready_at"] == "2026-11-23T10:00:10+00:00"
    done = restored.tick("2026-11-23T10:00:10+00:00")
    assert done["completed"] == [job["job_id"]]
    assert restored.inventory("acct")["ingot"] == 1
    fresh = restored.enqueue("acct", "smelt", 1, now="2026-11-23T10:00:11+00:00")
    assert fresh["job_id"] == "job-0002"


def test_restore_rejects_bad_snapshot_without_mutating_state():
    q = make()
    job = q.enqueue("acct", "smelt", 1, now=T0)
    with pytest.raises(cq.CraftError) as exc:
        q.restore({"version": 99})
    assert exc.value.code == "CRAFT_BAD_SNAPSHOT"
    with pytest.raises(cq.CraftError) as exc:
        q.restore({"version": 1, "seq": 1})
    assert exc.value.code == "CRAFT_BAD_SNAPSHOT"
    assert q.job(job["job_id"])["status"] == "running"
    assert q.inventory("acct") == {"ore": 10}


def test_concurrent_enqueue_never_over_reserves_materials():
    q = cq.CraftingQueue(max_jobs_per_account=20)
    q.add_station("forge", capacity=20, parallel=4)
    q.register_recipe("smelt", {"ore": 2}, {"ingot": 1}, 100, "forge")
    q.deposit("acct", "ore", 10)
    outcomes = [None] * 8

    def worker(index, barrier):
        barrier.wait()
        try:
            outcomes[index] = q.enqueue("acct", "smelt", 1,
                                        request_id=f"r{index}", now=T0)
        except cq.CraftError as error:
            outcomes[index] = error

    barrier = threading.Barrier(8)
    threads = [threading.Thread(target=worker, args=(i, barrier)) for i in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    accepted = [row for row in outcomes if isinstance(row, dict)]
    rejected = [row for row in outcomes if isinstance(row, cq.CraftError)]
    assert len(accepted) == 5
    assert len(rejected) == 3
    assert all(row.code == "CRAFT_INSUFFICIENT_MATERIALS" for row in rejected)
    assert q.inventory("acct")["ore"] == 10
    assert q.available("acct")["ore"] == 0
    assert q.stats()["jobs"] == 5
