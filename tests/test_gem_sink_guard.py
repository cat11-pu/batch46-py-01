import json
import threading

import pytest

import gem_sink_guard as gsg


AT0 = "2026-11-23T10:00:00+00:00"
AT1 = "2026-11-23T12:00:00+00:00"


def make(**kwargs):
    return gsg.GemSink(**kwargs)


def test_grant_is_idempotent_and_lot_count_is_capped():
    sink = make(max_lots=2)
    out = sink.grant("acct", 100, "g1")
    assert out["status"] == "granted"
    dup = sink.grant("acct", 100, "g1")
    assert dup["status"] == "duplicate"
    assert sink.balance("acct", AT0)["total"] == 100
    sink.grant("acct", 50, "g2")
    with pytest.raises(gsg.GemError) as exc:
        sink.grant("acct", 50, "g3")
    assert exc.value.code == "GEM_TOO_MANY_LOTS"
    assert sink.balance("acct", AT0)["total"] == 150


def test_spend_consumes_oldest_lots_first():
    sink = make()
    sink.grant("acct", 100, "g1")
    sink.grant("acct", 50, "g2")
    out = sink.spend("acct", 120, "s1", AT0)
    assert out["status"] == "spent"
    rows = sink.lots("acct", AT0)
    assert [(row["grant_id"], row["remaining"]) for row in rows] == [("g2", 30)]
    assert sink.balance("acct", AT0)["total"] == 30


def test_expired_lots_are_excluded_from_balance_and_spending():
    sink = make()
    sink.grant("acct", 100, "g1", expires_at="2026-11-20T00:00:00+00:00")
    sink.grant("acct", 40, "g2")
    assert sink.balance("acct", "2026-11-21T00:00:00+00:00")["total"] == 40
    with pytest.raises(gsg.GemError) as exc:
        sink.spend("acct", 50, "s1", "2026-11-21T00:00:00+00:00")
    assert exc.value.code == "GEM_INSUFFICIENT"
    ok = sink.spend("acct", 40, "s2", "2026-11-21T00:00:00+00:00")
    assert ok["status"] == "spent"


def test_spend_beyond_balance_leaves_state_unchanged():
    sink = make()
    sink.grant("acct", 10, "g1")
    with pytest.raises(gsg.GemError) as exc:
        sink.spend("acct", 11, "s1", AT0)
    assert exc.value.code == "GEM_INSUFFICIENT"
    assert sink.balance("acct", AT0)["total"] == 10
    assert [row["kind"] for row in sink.history("acct")] == ["grant"]


def test_daily_cap_is_enforced_per_utc_day():
    sink = make(daily_cap=500)
    sink.grant("acct", 1000, "g1")
    sink.spend("acct", 300, "s1", "2026-11-23T10:00:00+00:00")
    with pytest.raises(gsg.GemError) as exc:
        sink.spend("acct", 201, "s2", "2026-11-23T23:00:00+00:00")
    assert exc.value.code == "GEM_DAILY_CAP"
    ok = sink.spend("acct", 200, "s3", "2026-11-23T23:30:00+00:00")
    assert ok["daily_spent"] == 500
    nxt = sink.spend("acct", 400, "s4", "2026-11-24T00:30:00+00:00")
    assert nxt["status"] == "spent"
    assert sink.daily_spent("acct", "2026-11-24T01:00:00+00:00") == 400
    assert sink.balance("acct", "2026-11-24T01:00:00+00:00")["available"] == 100


def test_reserve_reduces_available_and_release_restores_expiry():
    sink = make()
    sink.grant("acct", 100, "g1", expires_at="2026-12-01T00:00:00+00:00")
    res = sink.reserve("acct", 60, "r1", AT0)
    assert res["status"] == "reserved"
    bal = sink.balance("acct", AT0)
    assert (bal["total"], bal["reserved"], bal["available"]) == (100, 60, 40)
    dup = sink.reserve("acct", 60, "r1", AT0)
    assert dup["status"] == "duplicate"
    rel = sink.release("acct", "r1", AT0)
    assert rel["status"] == "released"
    assert rel["expires_at"] == "2026-12-01T00:00:00+00:00"
    again = sink.release("acct", "r1", AT0)
    assert again["status"] == "ignored"
    assert again["code"] == "GEM_RESERVATION_CLOSED"
    assert sink.balance("acct", AT0)["available"] == 100


def test_commit_spends_reserved_gems_and_counts_against_daily_cap():
    sink = make(daily_cap=100)
    sink.grant("acct", 500, "g1")
    sink.reserve("acct", 80, "r1", AT0)
    out = sink.commit("acct", "r1", AT0)
    assert out["status"] == "spent"
    assert out["daily_spent"] == 80
    assert sink.balance("acct", AT0)["available"] == 420
    assert sink.balance("acct", AT0)["reserved"] == 0
    sink.reserve("acct", 50, "r2", AT0)
    with pytest.raises(gsg.GemError) as exc:
        sink.commit("acct", "r2", AT0)
    assert exc.value.code == "GEM_DAILY_CAP"
    assert sink.balance("acct", AT0)["reserved"] == 50


def test_commit_after_lot_expiry_is_stale_and_reservation_stays_releasable():
    sink = make()
    sink.grant("acct", 100, "g1", expires_at="2026-11-24T00:00:00+00:00")
    sink.reserve("acct", 50, "r1", "2026-11-23T00:00:00+00:00")
    with pytest.raises(gsg.GemError) as exc:
        sink.commit("acct", "r1", "2026-11-24T00:00:00+00:00")
    assert exc.value.code == "GEM_RESERVATION_STALE"
    rel = sink.release("acct", "r1", "2026-11-24T00:00:00+00:00")
    assert rel["status"] == "released"
    assert rel["expires_at"] == "2026-11-24T00:00:00+00:00"
    assert sink.balance("acct", "2026-11-24T00:00:00+00:00")["available"] == 0


def test_expire_drops_old_lots_and_open_reservations_once():
    sink = make()
    sink.grant("acct", 100, "g1", expires_at="2026-11-20T00:00:00+00:00")
    sink.grant("acct", 200, "g2", expires_at="2026-11-20T00:00:00+00:00")
    sink.grant("acct", 50, "g3")
    sink.reserve("acct", 40, "r1", "2026-11-19T00:00:00+00:00")
    sink.reserve("acct", 100, "r2", "2026-11-19T00:00:00+00:00")
    out = sink.expire("acct", "2026-11-21T00:00:00+00:00")
    assert out["lots"] == 1
    assert out["gems"] == 160
    assert out["reservations"] == 2
    assert out["reserved_gems"] == 140
    bal = sink.balance("acct", "2026-11-21T00:00:00+00:00")
    assert (bal["total"], bal["reserved"], bal["available"]) == (50, 0, 50)
    again = sink.expire("acct", "2026-11-21T00:00:00+00:00")
    assert again["lots"] == 0
    assert again["gems"] == 0
    assert again["reservations"] == 0


def test_refund_creates_lot_with_retention_expiry():
    sink = make(retention_days=30)
    sink.grant("acct", 100, "g1")
    sink.spend("acct", 60, "s1", "2026-11-10T00:00:00+00:00")
    out = sink.refund("acct", "s1", 60, "rf1", "2026-11-12T00:00:00+00:00")
    assert out["status"] == "refunded"
    assert out["expires_at"] == "2026-12-12T00:00:00+00:00"
    assert sink.balance("acct", "2026-11-13T00:00:00+00:00")["available"] == 100
    expired = sink.balance("acct", "2026-12-12T00:00:00+00:00")
    assert expired["available"] == 40


def test_refund_rejects_unknown_over_and_duplicate_requests():
    sink = make()
    sink.grant("acct", 100, "g1")
    sink.spend("acct", 50, "s1", AT0)
    with pytest.raises(gsg.GemError) as missing:
        sink.refund("acct", "nope", 10, "rf0", AT1)
    assert missing.value.code == "GEM_SPEND_NOT_FOUND"
    with pytest.raises(gsg.GemError) as over:
        sink.refund("acct", "s1", 60, "rf1", AT1)
    assert over.value.code == "GEM_OVER_REFUND"
    first = sink.refund("acct", "s1", 20, "rf2", AT1)
    assert first["status"] == "refunded"
    dup = sink.refund("acct", "s1", 20, "rf2", AT1)
    assert dup["status"] == "duplicate"
    assert sink.balance("acct", AT1)["available"] == 70


def test_refund_window_boundary_uses_utc():
    sink = make()
    sink.grant("acct", 200, "g1")
    sink.spend("acct", 100, "s1", "2026-11-10T12:00:00+00:00")
    exact = sink.refund("acct", "s1", 10, "rf1", "2026-11-17T12:00:00+00:00")
    assert exact["status"] == "refunded"
    with pytest.raises(gsg.GemError) as late:
        sink.refund("acct", "s1", 10, "rf2", "2026-11-17T12:00:01+00:00")
    assert late.value.code == "GEM_REFUND_WINDOW"
    with pytest.raises(gsg.GemError) as shifted:
        sink.refund("acct", "s1", 10, "rf3", "2026-11-18T07:59:59+08:00")
    assert shifted.value.code == "GEM_REFUND_WINDOW"


def test_accounts_are_isolated_for_balances_spends_and_reservations():
    sink = make(daily_cap=100)
    sink.grant("alice", 100, "ga")
    sink.grant("bob", 200, "gb")
    sink.spend("alice", 100, "sa", AT0)
    assert sink.balance("alice", AT0)["available"] == 0
    assert sink.balance("bob", AT0)["available"] == 200
    with pytest.raises(gsg.GemError) as exc:
        sink.refund("bob", "sa", 10, "rf", AT1)
    assert exc.value.code == "GEM_SPEND_NOT_FOUND"
    sink.reserve("bob", 60, "rb", AT0)
    assert sink.balance("bob", AT0)["reserved"] == 60
    assert sink.balance("alice", AT0)["reserved"] == 0
    out = sink.spend("bob", 100, "sb", AT0)
    assert out["status"] == "spent"
    assert sink.balance("bob", AT0)["available"] == 40
    sink.grant("alice", 10, "ga2")
    with pytest.raises(gsg.GemError) as cap:
        sink.spend("alice", 1, "sa2", AT0)
    assert cap.value.code == "GEM_DAILY_CAP"


def test_concurrent_spends_respect_daily_cap_and_balance():
    sink = make(daily_cap=500)
    sink.grant("acct", 1000, "g1")
    barrier = threading.Barrier(20)
    spent = []
    refused = []
    lock = threading.Lock()

    def worker(index):
        barrier.wait()
        try:
            sink.spend("acct", 100, f"s{index}", AT0)
            with lock:
                spent.append(index)
        except gsg.GemError as exc:
            with lock:
                refused.append(exc.code)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(spent) == 5
    assert sorted(refused) == ["GEM_DAILY_CAP"] * 15
    assert sink.balance("acct", AT0)["available"] == 500
    assert sink.daily_spent("acct", AT0) == 500


def test_snapshot_round_trip_preserves_lots_reservations_and_daily_totals():
    sink = make(daily_cap=500)
    sink.grant("acct", 300, "g1", expires_at="2026-12-01T00:00:00+00:00")
    sink.grant("acct", 200, "g2")
    sink.spend("acct", 100, "s1", AT0)
    sink.reserve("acct", 150, "r1", AT0)
    sink.refund("acct", "s1", 40, "rf1", AT1)
    payload = json.loads(json.dumps(sink.snapshot()))
    clone = gsg.GemSink(daily_cap=500)
    clone.restore(payload)
    bal = clone.balance("acct", AT1)
    assert bal == {"total": 440, "reserved": 150, "available": 290}
    assert clone.daily_spent("acct", AT1) == 100
    dup = clone.spend("acct", 100, "s1", AT1)
    assert dup["status"] == "duplicate"
    commit = clone.commit("acct", "r1", AT1)
    assert commit["status"] == "spent"
    assert clone.daily_spent("acct", AT1) == 250
    with pytest.raises(gsg.GemError) as bad:
        gsg.GemSink().restore({"version": 7})
    assert bad.value.code == "GEM_BAD_SNAPSHOT"
