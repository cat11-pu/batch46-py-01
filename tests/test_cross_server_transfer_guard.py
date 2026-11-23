import threading

import pytest

import cross_server_transfer_guard as tbg


def make(**kwargs):
    return tbg.CrossServerTransfer(**kwargs)


def payload(size=1):
    return {"bag": [{"id": index} for index in range(size)]}


def send(m, transfer_id, account, source="s1", target="s2",
         created_at="2026-11-23T10:00:00+00:00", data=None):
    return m.begin(transfer_id, account=account, character="chr-" + account,
                   source=source, target=target,
                   payload=payload() if data is None else data,
                   created_at=created_at)


def test_begin_rejects_unregistered_server():
    m = make()
    m.register_server("s1", capacity=10)
    with pytest.raises(tbg.TransferError) as exc:
        send(m, "t1", "acc")
    assert exc.value.code == "TRF_UNKNOWN_SERVER"
    assert m.metrics()["pending"] == 0


def test_begin_rejects_same_source_and_target():
    m = make()
    m.register_server("s1", capacity=10)
    m.register_server("s2", capacity=10)
    with pytest.raises(tbg.TransferError) as exc:
        send(m, "t1", "acc", source="s1", target="s1")
    assert exc.value.code == "TRF_SAME_SERVER"
    assert m.pending() == []


def test_begin_rejects_oversized_payload():
    m = make(payload_limit=64)
    m.register_server("s1", capacity=10)
    m.register_server("s2", capacity=10)
    with pytest.raises(tbg.TransferError) as exc:
        send(m, "t1", "acc", data={"blob": "x" * 200})
    assert exc.value.code == "TRF_PAYLOAD_TOO_LARGE"
    assert m.pending() == []


def test_duplicate_transfer_id_returns_existing_record():
    m = make()
    m.register_server("s1", capacity=10)
    m.register_server("s2", capacity=10)
    first = send(m, "t1", "acc")
    second = send(m, "t1", "acc")
    assert first["status"] == "pending"
    assert second["status"] == "existing"
    assert second["transfer_id"] == "t1"
    assert len(m.pending()) == 1


def test_second_pending_transfer_for_same_account_is_rejected():
    m = make()
    m.register_server("s1", capacity=10)
    m.register_server("s2", capacity=10)
    send(m, "t1", "acc")
    with pytest.raises(tbg.TransferError) as exc:
        send(m, "t2", "acc")
    assert exc.value.code == "TRF_PENDING_CONFLICT"
    assert len(m.pending()) == 1


def test_source_quota_limits_pending_transfers():
    m = make(quota_per_source=2)
    m.register_server("s1", capacity=10)
    m.register_server("s2", capacity=10)
    send(m, "t1", "acc1")
    send(m, "t2", "acc2")
    with pytest.raises(tbg.TransferError) as exc:
        send(m, "t3", "acc3")
    assert exc.value.code == "TRF_QUOTA_EXCEEDED"
    report = m.quota("s1")
    assert report["pending"] == 2
    assert report["remaining"] == 0


def test_global_pending_queue_is_capped():
    m = make(max_pending=2, quota_per_source=10)
    for server in ("s1", "s2", "s3"):
        m.register_server(server, capacity=10)
    send(m, "t1", "acc1", source="s1", target="s2")
    send(m, "t2", "acc2", source="s2", target="s3")
    with pytest.raises(tbg.TransferError) as exc:
        send(m, "t3", "acc3", source="s3", target="s1")
    assert exc.value.code == "TRF_QUEUE_FULL"
    assert m.metrics()["pending"] == 2


def test_commit_moves_home_and_updates_capacity():
    m = make()
    m.register_server("s1", capacity=10, used=3)
    m.register_server("s2", capacity=10, used=0)
    send(m, "t1", "acc")
    assert m.account_home("acc") == "s1"
    out = m.commit("t1")
    assert out["status"] == "committed"
    assert m.account_home("acc") == "s2"
    rows = {row["server"]: row for row in m.servers()}
    assert rows["s1"]["used"] == 2
    assert rows["s2"]["used"] == 1
    assert m.metrics()["committed"] == 1
    assert len(m.history("acc")) == 1


def test_commit_twice_is_rejected_and_capacity_counted_once():
    m = make()
    m.register_server("s1", capacity=10, used=3)
    m.register_server("s2", capacity=10, used=0)
    send(m, "t1", "acc")
    m.commit("t1")
    with pytest.raises(tbg.TransferError) as exc:
        m.commit("t1")
    assert exc.value.code == "TRF_ALREADY_COMMITTED"
    assert m.account_home("acc") == "s2"
    rows = {row["server"]: row for row in m.servers()}
    assert rows["s1"]["used"] == 2
    assert rows["s2"]["used"] == 1


def test_rollback_pending_transfer_keeps_player_at_source():
    m = make()
    m.register_server("s1", capacity=10, used=4)
    m.register_server("s2", capacity=10, used=0)
    send(m, "t1", "acc")
    out = m.rollback("t1", reason="player cancelled")
    assert out["status"] == "rolled_back"
    assert m.account_home("acc") == "s1"
    rows = {row["server"]: row for row in m.servers()}
    assert rows["s1"]["used"] == 4
    assert rows["s2"]["used"] == 0
    with pytest.raises(tbg.TransferError) as exc:
        m.rollback("t1")
    assert exc.value.code == "TRF_NOT_PENDING"


def test_rollback_committed_transfer_is_rejected():
    m = make()
    m.register_server("s1", capacity=10, used=2)
    m.register_server("s2", capacity=10, used=0)
    send(m, "t1", "acc")
    m.commit("t1")
    with pytest.raises(tbg.TransferError) as exc:
        m.rollback("t1")
    assert exc.value.code == "TRF_NOT_PENDING"
    assert m.account_home("acc") == "s2"


def test_expire_uses_ttl_and_is_idempotent():
    m = make(ttl_seconds=60)
    m.register_server("s1", capacity=10, used=2)
    m.register_server("s2", capacity=10)
    send(m, "t1", "acc", created_at="2026-11-23T10:00:00+00:00")
    expired = m.expire(now="2026-11-23T10:02:00+00:00")
    assert expired == ["t1"]
    assert m.status("t1")["status"] == "expired"
    assert m.account_home("acc") == "s1"
    assert m.expire(now="2026-11-23T10:03:00+00:00") == []
    rows = {row["server"]: row for row in m.servers()}
    assert rows["s1"]["used"] == 2


def test_target_capacity_is_arbitrated_at_commit_time():
    m = make()
    m.register_server("s1", capacity=10, used=1)
    m.register_server("s2", capacity=1, used=0)
    send(m, "t1", "acc1")
    send(m, "t2", "acc2")
    m.commit("t1")
    with pytest.raises(tbg.TransferError) as exc:
        m.commit("t2")
    assert exc.value.code == "TRF_TARGET_FULL"
    assert m.status("t2")["status"] == "pending"
    assert m.account_home("acc2") == "s1"
    rows = {row["server"]: row for row in m.servers()}
    assert rows["s2"]["used"] == 1


def test_audit_is_bounded_and_snapshot_restore_reverts_commit():
    m = make(history_limit=3)
    m.register_server("s1", capacity=10, used=5)
    m.register_server("s2", capacity=10, used=0)
    for index in range(1, 5):
        send(m, "t%d" % index, "acc%d" % index)
        m.commit("t%d" % index)
    log = m.audit()
    assert len(log) == 3
    assert [row["transfer_id"] for row in log] == ["t4", "t3", "t2"]
    snap = m.snapshot()
    send(m, "t5", "acc5")
    m.commit("t5")
    assert m.account_home("acc5") == "s2"
    out = m.restore(snap)
    assert out["status"] == "restored"
    assert m.account_home("acc5") is None
    with pytest.raises(tbg.TransferError) as exc:
        m.status("t5")
    assert exc.value.code == "TRF_UNKNOWN_TRANSFER"
    rows = {row["server"]: row for row in m.servers()}
    assert rows["s1"]["used"] == 1
    assert rows["s2"]["used"] == 4


def test_concurrent_commit_applies_exactly_once():
    m = make()
    m.register_server("s1", capacity=10, used=1)
    m.register_server("s2", capacity=10, used=0)
    send(m, "t1", "acc")
    barrier = threading.Barrier(8)
    outcomes = []
    lock = threading.Lock()

    def worker():
        barrier.wait()
        try:
            m.commit("t1")
            outcome = "committed"
        except tbg.TransferError as exc:
            outcome = exc.code
        except Exception as exc:  # unexpected failures must fail the test
            outcome = type(exc).__name__
        with lock:
            outcomes.append(outcome)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    assert outcomes.count("committed") == 1
    assert outcomes.count("TRF_ALREADY_COMMITTED") == 7
    assert m.account_home("acc") == "s2"
    rows = {row["server"]: row for row in m.servers()}
    assert rows["s2"]["used"] == 1
    assert m.metrics()["committed"] == 1
