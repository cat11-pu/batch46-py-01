import json
import threading

import pytest

import refund_ledger_guard as rlg


AT0 = "2026-11-01T00:00:00+00:00"
AT1 = "2026-11-02T00:00:00+00:00"
AT2 = "2026-11-03T00:00:00+00:00"
AT3 = "2026-11-04T00:00:00+00:00"
AT4 = "2026-11-05T00:00:00+00:00"


def make(**kwargs):
    return rlg.RefundLedger(**kwargs)


def test_debit_beyond_credit_limit_is_rejected():
    led = make(credit_limit=50)
    led.credit("acct", 100, "c1", AT0)
    out = led.debit("acct", 140, "d1", AT1)
    assert out["status"] == "applied"
    assert led.balance("acct")["balance"] == -40
    with pytest.raises(rlg.RefundError) as exc:
        led.debit("acct", 20, "d2", AT2)
    assert exc.value.code == "REFUND_CREDIT_LIMIT"
    assert led.balance("acct")["balance"] == -40


def test_credit_tx_id_is_idempotent():
    led = make()
    first = led.credit("acct", 500, "c1", AT0)
    assert first["status"] == "applied"
    second = led.credit("acct", 500, "c1", AT0)
    assert second["status"] == "duplicate"
    assert led.balance("acct")["balance"] == 500


def test_debit_tx_id_is_idempotent_and_shares_the_namespace():
    led = make()
    led.credit("acct", 100, "x1", AT0)
    dup = led.debit("acct", 10, "x1", AT1)
    assert dup["status"] == "duplicate"
    assert led.balance("acct")["balance"] == 100
    applied = led.debit("acct", 30, "x2", AT1)
    assert applied["status"] == "applied"
    assert applied["balance"] == 70
    again = led.debit("acct", 30, "x2", AT2)
    assert again["status"] == "duplicate"
    assert led.balance("acct")["balance"] == 70


def test_partial_refunds_accumulate_and_over_refund_is_rejected():
    led = make()
    led.credit("acct", 200, "c1", AT0)
    led.debit("acct", 100, "d1", AT1)
    first = led.refund("acct", "d1", 40, "r1", AT2)
    assert first["status"] == "applied"
    assert first["refunded_total"] == 40
    assert led.balance("acct")["balance"] == 140
    second = led.refund("acct", "d1", 60, "r2", AT3)
    assert second["refunded_total"] == 100
    assert led.balance("acct")["balance"] == 200
    with pytest.raises(rlg.RefundError) as exc:
        led.refund("acct", "d1", 1, "r3", AT4)
    assert exc.value.code == "REFUND_OVER_REFUND"


def test_refund_window_boundary_is_measured_in_utc():
    led = make(window_days=14)
    led.credit("acct", 1000, "c1", "2026-11-01T00:00:00+00:00")
    led.debit("acct", 100, "d1", "2026-11-01T12:00:00+00:00")
    exact = led.refund("acct", "d1", 10, "r1", "2026-11-15T07:00:00-05:00")
    assert exact["status"] == "applied"
    with pytest.raises(rlg.RefundError) as late:
        led.refund("acct", "d1", 10, "r2", "2026-11-15T12:00:01+00:00")
    assert late.value.code == "REFUND_WINDOW_EXPIRED"
    with pytest.raises(rlg.RefundError) as shifted:
        led.refund("acct", "d1", 10, "r3", "2026-11-15T23:59:00+08:00")
    assert shifted.value.code == "REFUND_WINDOW_EXPIRED"


def test_refund_id_is_idempotent():
    led = make()
    led.credit("acct", 100, "c1", AT0)
    led.debit("acct", 50, "d1", AT1)
    first = led.refund("acct", "d1", 20, "rf", AT2)
    second = led.refund("acct", "d1", 20, "rf", AT3)
    assert first["status"] == "applied"
    assert second["status"] == "duplicate"
    assert led.balance("acct")["balance"] == 70


def test_refund_of_unknown_or_credit_transaction_is_rejected():
    led = make()
    led.credit("acct", 100, "c1", AT0)
    with pytest.raises(rlg.RefundError) as missing:
        led.refund("acct", "nope", 1, "r1", AT1)
    assert missing.value.code == "REFUND_TX_NOT_FOUND"
    with pytest.raises(rlg.RefundError) as credit:
        led.refund("acct", "c1", 1, "r2", AT1)
    assert credit.value.code == "REFUND_NOT_REFUNDABLE"
    led.credit("other", 100, "c2", AT0)
    led.debit("other", 10, "d2", AT1)
    with pytest.raises(rlg.RefundError) as owner:
        led.refund("acct", "d2", 1, "r3", AT2)
    assert owner.value.code == "REFUND_TX_ACCOUNT"


def test_hold_reduces_available_and_release_restores_it():
    led = make()
    led.credit("acct", 100, "c1", AT0)
    out = led.hold("acct", 60, "h1")
    assert out["status"] == "held"
    bal = led.balance("acct")
    assert (bal["balance"], bal["held"], bal["available"]) == (100, 60, 40)
    dup = led.hold("acct", 60, "h1")
    assert dup["status"] == "duplicate"
    rel = led.release("acct", "h1")
    assert rel["status"] == "released"
    assert led.balance("acct")["available"] == 100
    again = led.release("acct", "h1")
    assert again["status"] == "ignored"
    assert again["code"] == "REFUND_HOLD_CLOSED"


def test_settle_turns_hold_into_debit_entry():
    led = make()
    led.credit("acct", 100, "c1", AT0)
    led.hold("acct", 30, "h1")
    out = led.settle("acct", "h1", AT1)
    assert out["status"] == "settled"
    assert out["amount"] == 30
    bal = led.balance("acct")
    assert (bal["balance"], bal["held"], bal["available"]) == (70, 0, 70)
    kinds = [row["kind"] for row in led.history("acct")]
    assert kinds == ["credit", "settle"]
    assert led.history("acct")[-1]["balance_after"] == 70
    again = led.settle("acct", "h1", AT2)
    assert again["status"] == "ignored"
    assert again["code"] == "REFUND_HOLD_CLOSED"


def test_hold_limits_and_insufficient_available_are_enforced():
    led = make(max_holds=2)
    led.credit("acct", 100, "c1", AT0)
    led.hold("acct", 10, "h1")
    led.hold("acct", 10, "h2")
    with pytest.raises(rlg.RefundError) as many:
        led.hold("acct", 10, "h3")
    assert many.value.code == "REFUND_TOO_MANY_HOLDS"
    with pytest.raises(rlg.RefundError) as short:
        led.hold("acct", 95, "h4")
    assert short.value.code == "REFUND_INSUFFICIENT_AVAILABLE"
    assert led.balance("acct")["held"] == 20


def test_chargeback_reverses_credit_and_guards_duplicates():
    led = make(credit_limit=600)
    led.credit("acct", 500, "c1", AT0)
    led.debit("acct", 450, "d1", AT1)
    assert led.balance("acct")["balance"] == 50
    cb = led.chargeback("acct", "c1", "cb1", AT2)
    assert cb["status"] == "applied"
    assert cb["amount"] == 500
    assert led.balance("acct")["balance"] == -450
    again = led.chargeback("acct", "c1", "cb2", AT3)
    assert again["status"] == "ignored"
    assert again["code"] == "REFUND_ALREADY_REVERSED"
    with pytest.raises(rlg.RefundError) as exc:
        led.chargeback("acct", "d1", "cb3", AT3)
    assert exc.value.code == "REFUND_NOT_CHARGEABLE"


def test_history_sequence_and_balance_chain_are_consistent():
    led = make()
    led.credit("acct", 300, "c1", AT0)
    led.debit("acct", 100, "d1", AT1)
    led.refund("acct", "d1", 40, "r1", AT2)
    rows = led.history("acct")
    assert [row["kind"] for row in rows] == ["credit", "debit", "refund"]
    assert [row["balance_after"] for row in rows] == [300, 200, 240]
    assert [row["seq"] for row in rows] == [1, 2, 3]
    assert led.balance("acct")["balance"] == 240
    assert led.outstanding("acct") == 0


def test_statement_bounds_are_inclusive_and_totals_reconcile():
    led = make()
    led.credit("acct", 300, "c1", "2026-11-01T00:00:00+00:00")
    led.debit("acct", 100, "d1", "2026-11-05T00:00:00+00:00")
    led.debit("acct", 20, "d2", "2026-11-10T00:00:00+00:00")
    led.credit("acct", 50, "c2", "2026-11-20T00:00:00+00:00")
    st = led.statement("acct", "2026-11-05T00:00:00+00:00",
                       "2026-11-10T00:00:00+00:00")
    assert st["opening"] == 300
    assert st["total"] == -120
    assert st["closing"] == 180
    assert st["entries"] == 2
    assert led.balance("acct")["balance"] == 230
    full = led.statement("acct", "2026-11-01T00:00:00+00:00",
                         "2026-11-30T00:00:00+00:00")
    assert full["opening"] == 0
    assert full["closing"] == 230
    with pytest.raises(rlg.RefundError) as exc:
        led.statement("acct", "2026-11-30T00:00:00+00:00",
                      "2026-11-01T00:00:00+00:00")
    assert exc.value.code == "REFUND_BAD_TIME"


def test_concurrent_debits_never_exceed_credit_limit():
    led = make(credit_limit=50)
    led.credit("acct", 100, "c0", AT0)
    barrier = threading.Barrier(30)
    applied = []
    refused = []
    lock = threading.Lock()

    def worker(index):
        barrier.wait()
        try:
            led.debit("acct", 10, f"d{index}", AT1)
            with lock:
                applied.append(index)
        except rlg.RefundError as exc:
            with lock:
                refused.append(exc.code)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(30)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(applied) == 15
    assert sorted(refused) == ["REFUND_CREDIT_LIMIT"] * 15
    assert led.balance("acct")["balance"] == -50


def test_snapshot_round_trip_preserves_holds_and_refund_totals():
    led = make()
    led.credit("acct", 500, "c1", AT0)
    led.debit("acct", 200, "d1", AT1)
    led.refund("acct", "d1", 50, "r1", AT2)
    led.hold("acct", 30, "h1")
    payload = json.loads(json.dumps(led.snapshot()))
    clone = rlg.RefundLedger()
    clone.restore(payload)
    bal = clone.balance("acct")
    assert (bal["balance"], bal["held"], bal["available"]) == (350, 30, 320)
    assert clone.history("acct")[-1]["seq"] == 3
    with pytest.raises(rlg.RefundError) as exc:
        clone.refund("acct", "d1", 200, "r2", AT3)
    assert exc.value.code == "REFUND_OVER_REFUND"
    assert clone.release("acct", "h1")["status"] == "released"
    assert clone.balance("acct")["available"] == 350
    with pytest.raises(rlg.RefundError) as bad:
        rlg.RefundLedger().restore({"version": 0})
    assert bad.value.code == "REFUND_BAD_SNAPSHOT"
