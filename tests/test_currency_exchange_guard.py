import json
import threading
from decimal import Decimal

import pytest

import currency_exchange_guard as fx

T0 = "2026-11-23T10:00:00+00:00"


def test_direct_and_inverse_rate_lookup():
    a = fx.CurrencyExchange()
    a.add_rate("GOLD", "SILVER", 20)
    assert a.rate("GOLD", "SILVER") == Decimal("20")
    assert a.rate("SILVER", "GOLD") == Decimal("0.05")
    assert a.rate("GOLD", "GOLD") == Decimal("1")
    with pytest.raises(fx.CurrencyError) as exc:
        a.rate("GOLD", "COPPER")
    assert exc.value.code == "FX_UNKNOWN_RATE"
    with pytest.raises(fx.CurrencyError) as exc:
        a.add_rate("GOLD", "GOLD", 1)
    assert exc.value.code == "FX_BAD_CURRENCY"


def test_cross_rate_is_derived_through_base_currency():
    a = fx.CurrencyExchange()
    a.add_rate("GOLD", "SILVER", 20)
    a.add_rate("GOLD", "GEM", 1000)
    assert a.rate("SILVER", "GEM") == Decimal("50")
    assert a.rate("GEM", "SILVER") == Decimal("0.02")


def test_quote_keeps_its_rate_after_market_update():
    a = fx.CurrencyExchange()
    a.add_rate("GOLD", "SILVER", 20)
    a.open_wallet("acct", {"GOLD": "1000"})
    q = a.quote("acct", "GOLD", "SILVER", "100", now=T0)
    a.add_rate("GOLD", "SILVER", 25)
    out = a.exchange("acct", q["quote_id"], now=T0)
    assert out["status"] == "applied"
    assert out["rate"] == Decimal("20")
    assert out["received"] == Decimal("1990.00")
    assert a.balance("acct")["GOLD"] == Decimal("900.00")
    assert a.balance("acct")["SILVER"] == Decimal("1990.00")


def test_expired_quote_is_rejected_without_moving_funds():
    a = fx.CurrencyExchange()
    a.add_rate("GOLD", "SILVER", 20)
    a.open_wallet("acct", {"GOLD": "1000"})
    good = a.quote("acct", "GOLD", "SILVER", "100", now=T0)
    stale = a.quote("acct", "GOLD", "SILVER", "100", now=T0)
    ok = a.exchange("acct", good["quote_id"], now="2026-11-23T10:00:59+00:00")
    assert ok["status"] == "applied"
    with pytest.raises(fx.CurrencyError) as exc:
        a.exchange("acct", stale["quote_id"], now="2026-11-23T10:01:00+00:00")
    assert exc.value.code == "FX_QUOTE_EXPIRED"
    assert a.balance("acct")["GOLD"] == Decimal("900.00")


def test_quote_is_single_use_and_bound_to_owner():
    a = fx.CurrencyExchange()
    a.add_rate("GOLD", "SILVER", 20)
    a.open_wallet("acct", {"GOLD": "1000"})
    a.open_wallet("other", {"GOLD": "1000"})
    q = a.quote("acct", "GOLD", "SILVER", "10", now=T0)
    with pytest.raises(fx.CurrencyError) as exc:
        a.exchange("other", q["quote_id"], now=T0)
    assert exc.value.code == "FX_QUOTE_OWNER"
    a.exchange("acct", q["quote_id"], now=T0)
    with pytest.raises(fx.CurrencyError) as exc:
        a.exchange("acct", q["quote_id"], now=T0)
    assert exc.value.code == "FX_QUOTE_USED"
    assert a.balance("acct")["SILVER"] == Decimal("199.00")
    assert a.balance("other")["GOLD"] == Decimal("1000.00")


def test_fee_uses_half_up_rounding_and_minimum_charge():
    a = fx.CurrencyExchange()
    a.add_rate("GOLD", "SILVER", 20)
    a.add_rate("GOLD", "COPPER", 3)
    a.open_wallet("acct", {"GOLD": "1000"})
    big = a.quote("acct", "GOLD", "SILVER", "100", now=T0)
    assert big["gross"] == Decimal("2000.00")
    assert big["fee"] == Decimal("10.00")
    assert big["net"] == Decimal("1990.00")
    tiny = a.quote("acct", "GOLD", "SILVER", "0.05", now=T0)
    assert tiny["gross"] == Decimal("1.00")
    assert tiny["fee"] == Decimal("0.01")
    assert tiny["net"] == Decimal("0.99")
    odd = a.quote("acct", "GOLD", "COPPER", "0.333", now=T0)
    assert odd["gross"] == Decimal("0.99")
    assert odd["fee"] == Decimal("0.01")
    assert odd["net"] == Decimal("0.98")


def test_exchange_moves_exact_balances_for_both_currencies():
    a = fx.CurrencyExchange()
    a.add_rate("GOLD", "SILVER", 20)
    a.open_wallet("acct", {"GOLD": "1000.00", "SILVER": "5.00"})
    q = a.quote("acct", "GOLD", "SILVER", "100", now=T0)
    a.exchange("acct", q["quote_id"], now=T0)
    assert a.balance("acct") == {"GOLD": Decimal("900.00"),
                                 "SILVER": Decimal("1995.00")}
    assert a.available("acct") == {"GOLD": Decimal("900.00"),
                                   "SILVER": Decimal("1995.00")}
    assert len(a.history("acct")) == 1


def test_freeze_reduces_available_but_not_total_balance():
    a = fx.CurrencyExchange()
    a.open_wallet("acct", {"GOLD": "100.00"})
    a.freeze("acct", "GOLD", "30", reason="auction", now=T0)
    assert a.balance("acct")["GOLD"] == Decimal("100.00")
    assert a.available("acct")["GOLD"] == Decimal("70.00")
    assert a.stats()["freezes"] == 1


def test_freeze_beyond_available_is_rejected():
    a = fx.CurrencyExchange()
    a.open_wallet("acct", {"GOLD": "100.00"})
    a.freeze("acct", "GOLD", "80", now=T0)
    with pytest.raises(fx.CurrencyError) as exc:
        a.freeze("acct", "GOLD", "30", now=T0)
    assert exc.value.code == "FX_INSUFFICIENT_AVAILABLE"
    a.freeze("acct", "GOLD", "20", now=T0)
    assert a.available("acct")["GOLD"] == Decimal("0.00")
    with pytest.raises(fx.CurrencyError) as exc:
        a.freeze("acct", "GOLD", "0.01", now=T0)
    assert exc.value.code == "FX_INSUFFICIENT_AVAILABLE"


def test_settle_spends_frozen_funds_permanently():
    a = fx.CurrencyExchange()
    a.open_wallet("acct", {"GOLD": "100.00"})
    frozen = a.freeze("acct", "GOLD", "30", now=T0)
    out = a.settle(frozen["freeze_id"], now=T0)
    assert out["status"] == "settled"
    assert out["balance"] == Decimal("70.00")
    assert a.balance("acct")["GOLD"] == Decimal("70.00")
    assert a.available("acct")["GOLD"] == Decimal("70.00")
    with pytest.raises(fx.CurrencyError) as exc:
        a.settle(frozen["freeze_id"], now=T0)
    assert exc.value.code == "FX_FREEZE_CLOSED"


def test_release_returns_frozen_funds_to_available():
    a = fx.CurrencyExchange()
    a.open_wallet("acct", {"GOLD": "100.00"})
    frozen = a.freeze("acct", "GOLD", "30", now=T0)
    a.release(frozen["freeze_id"])
    assert a.balance("acct")["GOLD"] == Decimal("100.00")
    assert a.available("acct")["GOLD"] == Decimal("100.00")
    with pytest.raises(fx.CurrencyError) as exc:
        a.release(frozen["freeze_id"])
    assert exc.value.code == "FX_FREEZE_CLOSED"


def test_settle_with_wrong_currency_keeps_freeze_open():
    a = fx.CurrencyExchange()
    a.open_wallet("acct", {"GOLD": "100.00"})
    frozen = a.freeze("acct", "GOLD", "30", now=T0)
    with pytest.raises(fx.CurrencyError) as exc:
        a.settle(frozen["freeze_id"], currency="SILVER", now=T0)
    assert exc.value.code == "FX_CURRENCY_MISMATCH"
    assert a.available("acct")["GOLD"] == Decimal("70.00")
    with pytest.raises(fx.CurrencyError) as exc:
        a.settle(frozen["freeze_id"], amount="29", now=T0)
    assert exc.value.code == "FX_AMOUNT_MISMATCH"
    a.settle(frozen["freeze_id"], currency="GOLD", amount="30", now=T0)
    assert a.balance("acct")["GOLD"] == Decimal("70.00")


def test_concurrent_exchanges_never_overdraw_the_wallet():
    a = fx.CurrencyExchange()
    a.add_rate("GOLD", "SILVER", 20)
    a.open_wallet("acct", {"GOLD": "100.00"})
    quotes = [a.quote("acct", "GOLD", "SILVER", "10", now=T0)["quote_id"]
              for _ in range(12)]
    outcomes = [None] * 12

    def worker(index, barrier):
        barrier.wait()
        try:
            outcomes[index] = a.exchange("acct", quotes[index], now=T0)
        except fx.CurrencyError as error:
            outcomes[index] = error

    barrier = threading.Barrier(12)
    threads = [threading.Thread(target=worker, args=(i, barrier)) for i in range(12)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    applied = [row for row in outcomes if isinstance(row, dict)]
    rejected = [row for row in outcomes if isinstance(row, fx.CurrencyError)]
    assert len(applied) == 10
    assert len(rejected) == 2
    assert all(row.code == "FX_INSUFFICIENT_FUNDS" for row in rejected)
    assert a.balance("acct")["GOLD"] == Decimal("0.00")
    assert a.balance("acct")["SILVER"] == Decimal("1990.00")


def test_quote_limit_counts_only_active_quotes():
    a = fx.CurrencyExchange(max_quotes=3)
    a.add_rate("GOLD", "SILVER", 20)
    a.open_wallet("acct", {"GOLD": "1000"})
    for _ in range(3):
        a.quote("acct", "GOLD", "SILVER", "10", now=T0)
    with pytest.raises(fx.CurrencyError) as exc:
        a.quote("acct", "GOLD", "SILVER", "10", now=T0)
    assert exc.value.code == "FX_QUOTE_LIMIT"
    fresh = a.quote("acct", "GOLD", "SILVER", "10",
                    now="2026-11-23T10:01:01+00:00")
    assert fresh["quote_id"]


def test_snapshot_restore_roundtrip_and_bad_snapshot_is_atomic():
    a = fx.CurrencyExchange()
    a.add_rate("GOLD", "SILVER", 20)
    a.open_wallet("acct", {"GOLD": "100.00", "SILVER": "0.00"})
    q = a.quote("acct", "GOLD", "SILVER", "10", now=T0)
    a.exchange("acct", q["quote_id"], now=T0)
    a.freeze("acct", "GOLD", "30", now=T0)
    saved_gold = a.balance("acct")["GOLD"]
    saved_available = a.available("acct")["GOLD"]
    snapshot = a.snapshot()
    json.dumps(snapshot)
    a.freeze("acct", "GOLD", "20", now=T0)
    assert a.available("acct")["GOLD"] != saved_available
    restored = fx.CurrencyExchange()
    restored.restore(snapshot)
    assert restored.balance("acct")["GOLD"] == saved_gold
    assert restored.available("acct")["GOLD"] == saved_available
    assert len(restored.history("acct")) == 1
    with pytest.raises(fx.CurrencyError) as exc:
        restored.restore({"version": 2})
    assert exc.value.code == "FX_BAD_SNAPSHOT"
    assert restored.balance("acct")["GOLD"] == saved_gold
