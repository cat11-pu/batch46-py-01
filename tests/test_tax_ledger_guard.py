import json
import threading

import pytest

import tax_ledger_guard as tlg


AT0 = "2026-11-20T00:00:00+00:00"
AT1 = "2026-11-21T00:00:00+00:00"
AT2 = "2026-11-22T00:00:00+00:00"
AT3 = "2026-11-23T00:00:00+00:00"
AT4 = "2026-11-24T00:00:00+00:00"
CUTOFF = "2026-11-30T00:00:00+00:00"


def make(**kwargs):
    return tlg.TaxLedger(**kwargs)


def test_tax_for_applies_floor_minimum_and_exemption():
    led = make(rate_bps=250, min_fee=1, exempt_below=5)
    assert led.tax_for(99) == 2
    assert led.tax_for(3) == 0
    assert led.tax_for(4) == 0
    assert led.tax_for(5) == 1
    assert led.tax_for(0) == 0
    with pytest.raises(tlg.TaxError) as exc:
        led.tax_for(-1)
    assert exc.value.code == "TAX_BAD_AMOUNT"


def test_tax_for_is_capped():
    led = make(rate_bps=5000, cap=100)
    assert led.tax_for(1000) == 100
    assert led.tax_for(200) == 100
    assert led.tax_for(199) == 99


def test_category_specific_rates_override_defaults():
    led = make(rate_bps=500, min_fee=1, exempt_below=0)
    led.set_category_rate("consumable", 300, exempt_below=10)
    assert led.tax_for(100, "consumable") == 3
    assert led.tax_for(9, "consumable") == 0
    assert led.tax_for(100, "item") == 5
    assert led.tax_for(100, "unknown") == 5
    led.record_sale("s1", "seller", "buyer", 100, AT0, category="consumable")
    assert led.totals("seller")["tax_accrued"] == 3
    with pytest.raises(tlg.TaxError) as exc:
        led.set_category_rate("weird", 10001)
    assert exc.value.code == "TAX_BAD_RATE"


def test_record_sale_is_idempotent_by_sale_id():
    led = make()
    first = led.record_sale("s1", "seller", "buyer", 100, AT0)
    assert first["status"] == "accrued"
    assert first["tax"] == 5
    second = led.record_sale("s1", "seller", "buyer", 100, AT0)
    assert second["status"] == "duplicate"
    assert led.totals("seller")["gross"] == 100
    assert len(led.pending("seller")) == 1


def test_record_sale_rejects_bad_amounts_and_self_trades():
    led = make()
    for gross in (0, -5):
        with pytest.raises(tlg.TaxError) as exc:
            led.record_sale(f"bad{gross}", "seller", "buyer", gross, AT0)
        assert exc.value.code == "TAX_BAD_AMOUNT"
    with pytest.raises(tlg.TaxError) as self_trade:
        led.record_sale("self", "seller", "seller", 100, AT0)
    assert self_trade.value.code == "TAX_SELF_TRADE"
    with pytest.raises(tlg.TaxError) as bad_id:
        led.record_sale("", "seller", "buyer", 100, AT0)
    assert bad_id.value.code == "TAX_BAD_SALE"
    with pytest.raises(tlg.TaxError) as bad_time:
        led.record_sale("t", "seller", "buyer", 100, "not-a-time")
    assert bad_time.value.code == "TAX_BAD_TIME"
    assert led.pending() == []
    assert led.totals("seller")["gross"] == 0


def test_pending_orders_by_occurrence_then_insertion():
    led = make()
    led.record_sale("late", "seller", "buyer", 100, "2026-11-22T09:00:00+00:00")
    led.record_sale("early-a", "seller", "buyer", 100, "2026-11-21T09:00:00+00:00")
    led.record_sale("early-b", "seller", "buyer", 100, "2026-11-21T09:00:00+00:00")
    led.record_sale("other", "seller-2", "buyer", 100, "2026-11-20T09:00:00+00:00")
    assert [row["sale_id"] for row in led.pending("seller")] == [
        "early-a", "early-b", "late"]
    assert [row["sale_id"] for row in led.pending()] == [
        "other", "early-a", "early-b", "late"]


def test_settle_only_bills_sales_up_to_the_cutoff_inclusive():
    led = make()
    led.record_sale("a1", "seller-a", "buyer", 100, "2026-11-20T10:00:00+00:00")
    led.record_sale("a2", "seller-a", "buyer", 200, "2026-11-21T10:00:00+00:00")
    led.record_sale("b1", "seller-b", "buyer", 300, "2026-11-21T23:59:59+00:00")
    led.record_sale("a3", "seller-a", "buyer", 400, "2026-11-21T10:00:01+00:00")
    out = led.settle_all("2026-11-21T10:00:00+00:00", "b-all")
    assert out["settled"] == 2
    assert out["tax"] == 15
    assert [row["sale_id"] for row in led.pending()] == ["a3", "b1"]
    assert led.totals("seller-a")["tax_settled"] == 15
    assert led.totals("seller-a")["pending"] == 1
    assert led.totals("seller-a")["outstanding"] == 15
    dup = led.settle_all("2026-11-21T10:00:00+00:00", "b-all")
    assert dup["status"] == "duplicate"
    assert led.totals("seller-a")["tax_settled"] == 15


def test_settle_batch_id_is_idempotent_across_callers():
    led = make()
    led.record_sale("s1", "seller", "buyer", 1000, AT0)
    first = led.settle("seller", CUTOFF, "batch-1")
    assert first["status"] == "settled"
    assert first["tax"] == 50
    second = led.settle("seller", CUTOFF, "batch-1")
    assert second["status"] == "duplicate"
    assert led.totals("seller")["tax_settled"] == 50


def test_settle_respects_batch_budget_and_keeps_the_rest_pending():
    led = make()
    for i in range(5):
        led.record_sale(f"s{i}", "seller", "buyer", 100,
                        f"2026-11-2{i}T00:00:00+00:00")
    out = led.settle("seller", CUTOFF, "b1", limit=3)
    assert out["settled"] == 3
    assert out["remaining"] == 2
    assert out["tax"] == 15
    assert led.totals("seller")["tax_settled"] == 15
    assert led.totals("seller")["pending"] == 2
    out2 = led.settle("seller", CUTOFF, "b2")
    assert out2["settled"] == 2
    assert out2["remaining"] == 0
    assert led.totals("seller")["tax_settled"] == 25


def test_waiver_zeroes_tax_before_settlement_only():
    led = make()
    led.record_sale("s1", "seller", "buyer", 1000, AT0)
    out = led.waiver("seller", "s1", "promo")
    assert out["status"] == "waived"
    assert out["tax"] == 0
    assert led.totals("seller")["tax_accrued"] == 0
    assert led.totals("seller")["gross"] == 1000
    dup = led.waiver("seller", "s1", "promo")
    assert dup["status"] == "duplicate"
    led.record_sale("s2", "seller", "buyer", 1000, AT1)
    led.settle("seller", CUTOFF, "b1")
    with pytest.raises(tlg.TaxError) as exc:
        led.waiver("seller", "s2", "late")
    assert exc.value.code == "TAX_ALREADY_SETTLED"


def test_reversal_of_settled_sale_creates_one_negative_adjustment():
    led = make()
    led.record_sale("s1", "seller", "buyer", 1000, AT0)
    led.settle("seller", AT1, "b1")
    assert led.totals("seller")["outstanding"] == 50
    out = led.reversal("s1", "rv1", AT2)
    assert out["status"] == "adjusted"
    assert out["amount"] == -50
    totals = led.totals("seller")
    assert totals["adjustments"] == -50
    assert totals["outstanding"] == 0
    dup = led.reversal("s1", "rv2", AT3)
    assert dup["status"] == "duplicate"
    assert led.totals("seller")["outstanding"] == 0


def test_reversal_voids_pending_sales_and_rejects_backdating():
    led = make()
    led.record_sale("s1", "seller", "buyer", 1000, AT0)
    out = led.reversal("s1", "rv1", AT1)
    assert out["status"] == "voided"
    assert out["amount"] == 0
    assert led.pending("seller") == []
    assert led.totals("seller")["tax_accrued"] == 0
    assert led.totals("seller")["gross"] == 0
    led.record_sale("s2", "seller", "buyer", 1000, AT3)
    with pytest.raises(tlg.TaxError) as backdated:
        led.reversal("s2", "rv2", "2026-11-22T23:59:59+00:00")
    assert backdated.value.code == "TAX_BAD_ORDER"
    with pytest.raises(tlg.TaxError) as missing:
        led.reversal("missing", "rv3", AT4)
    assert missing.value.code == "TAX_SALE_NOT_FOUND"


def test_payments_track_outstanding_and_reject_overpay():
    led = make()
    led.record_sale("s1", "seller", "buyer", 1000, AT0)
    led.settle("seller", CUTOFF, "b1")
    first = led.pay("seller", 20, "p1", AT1)
    assert first["status"] == "paid"
    assert first["outstanding"] == 30
    dup = led.pay("seller", 20, "p1", AT1)
    assert dup["status"] == "duplicate"
    assert led.totals("seller")["paid"] == 20
    second = led.pay("seller", 30, "p2", AT2)
    assert second["outstanding"] == 0
    with pytest.raises(tlg.TaxError) as exc:
        led.pay("seller", 1, "p3", AT3)
    assert exc.value.code == "TAX_OVERPAY"
    assert led.totals("seller")["paid"] == 50


def test_concurrent_sales_and_settlements_do_not_double_bill():
    led = make(rate_bps=500)
    barrier = threading.Barrier(10)
    errors = []

    def worker(index):
        try:
            barrier.wait()
            for step in range(10):
                led.record_sale(f"s{index}-{step}", "seller", "buyer", 100, AT0)
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    assert led.totals("seller")["gross"] == 10000
    assert len(led.pending("seller")) == 100

    settle_barrier = threading.Barrier(4)
    results = []

    def settler():
        settle_barrier.wait()
        results.append(led.settle("seller", CUTOFF, "batch-x"))

    settler_threads = [threading.Thread(target=settler) for _ in range(4)]
    for thread in settler_threads:
        thread.start()
    for thread in settler_threads:
        thread.join()
    assert sorted(row["status"] for row in results) == [
        "duplicate", "duplicate", "duplicate", "settled"]
    assert led.totals("seller")["tax_settled"] == 500
    assert led.totals("seller")["pending"] == 0


def test_snapshot_round_trip_preserves_pending_batches_and_totals():
    led = make()
    led.record_sale("s1", "seller", "buyer", 1000, AT0)
    led.record_sale("s2", "seller", "buyer", 200, AT1)
    led.waiver("seller", "s2", "promo")
    led.settle("seller", AT1, "b1")
    led.record_sale("s3", "seller", "buyer", 400, AT2)
    payload = json.loads(json.dumps(led.snapshot()))
    clone = tlg.TaxLedger()
    clone.restore(payload)
    assert clone.totals("seller")["tax_settled"] == 50
    assert [row["sale_id"] for row in clone.pending("seller")] == ["s3"]
    out = clone.settle("seller", CUTOFF, "b2")
    assert out["tax"] == 20
    assert clone.totals("seller")["tax_settled"] == 70
    assert clone.totals("seller")["gross"] == 1600
    with pytest.raises(tlg.TaxError) as exc:
        clone.waiver("seller", "s2", "promo")
    assert exc.value.code == "TAX_ALREADY_SETTLED"
    with pytest.raises(tlg.TaxError) as bad:
        tlg.TaxLedger().restore({"version": 0})
    assert bad.value.code == "TAX_BAD_SNAPSHOT"
