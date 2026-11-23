import json
import threading

import pytest

import market_orderbook_guard as mob


def make(**kwargs):
    return mob.OrderBook(**kwargs)


def funded(book, account, gold=0, ore=0):
    if gold:
        book.deposit(account, "gold", gold)
    if ore:
        book.deposit(account, "ore", ore)


def test_crossing_trade_uses_maker_price_and_settles_both_sides():
    book = make()
    funded(book, "alice", ore=10)
    funded(book, "bob", gold=100)
    book.place("o1", "alice", "sell", 5, 10)
    book.place("o2", "bob", "buy", 6, 10)
    fills = book.match()
    assert len(fills) == 1
    fill = fills[0]
    assert (fill["price"], fill["qty"], fill["maker_order"]) == (5, 10, "o1")
    assert book.balance("bob", "gold") == 50
    assert book.balance("bob", "ore") == 10
    assert book.balance("alice", "gold") == 50
    assert book.balance("alice", "ore") == 0
    assert book.open_orders("bob") == []


def test_price_then_time_priority_determines_fill_order():
    book = make()
    funded(book, "seller_a", ore=20)
    funded(book, "seller_b", ore=20)
    funded(book, "buyer", gold=200)
    book.place("a1", "seller_a", "sell", 5, 10)
    book.place("b1", "seller_b", "sell", 4, 10)
    book.place("a2", "seller_a", "sell", 4, 10)
    book.place("t1", "buyer", "buy", 5, 15)
    fills = book.match()
    assert [f["maker_order"] for f in fills] == ["b1", "a2"]
    assert [f["qty"] for f in fills] == [10, 5]
    assert [f["price"] for f in fills] == [4, 4]


def test_partial_fill_keeps_remainder_resting():
    book = make()
    funded(book, "alice", ore=10)
    funded(book, "bob", gold=50)
    book.place("ask", "alice", "sell", 5, 10)
    book.place("bid", "bob", "buy", 5, 4)
    fills = book.match()
    assert len(fills) == 1
    assert fills[0]["qty"] == 4
    assert book.order("ask")["remaining"] == 6
    assert book.order("ask")["status"] == "open"
    assert book.order("bid")["status"] == "filled"
    assert book.depth("sell") == [{"price": 5, "qty": 6}]
    assert book.balance("bob", "gold") == 30
    assert book.balance("bob", "ore") == 4


def test_cancel_refunds_unfilled_escrow_and_guards_ownership():
    book = make()
    funded(book, "alice", ore=8, gold=100)
    book.place("buy1", "alice", "buy", 10, 5)
    book.place("sell1", "alice", "sell", 12, 3)
    assert book.balance("alice", "gold") == 50
    assert book.balance("alice", "ore") == 5
    out = book.cancel("buy1", "alice")
    assert out["status"] == "cancelled"
    assert out["refund_amount"] == 50
    assert book.balance("alice", "gold") == 100
    out2 = book.cancel("sell1", "alice")
    assert out2["refund_amount"] == 3
    assert book.balance("alice", "ore") == 8
    with pytest.raises(mob.OrderError) as exc:
        book.cancel("missing", "alice")
    assert exc.value.code == "ORDER_NOT_FOUND"
    book.place("buy2", "alice", "buy", 3, 2)
    with pytest.raises(mob.OrderError) as other:
        book.cancel("buy2", "bob")
    assert other.value.code == "ORDER_NOT_OWNER"


def test_duplicate_order_id_is_idempotent_and_does_not_escrow_twice():
    book = make()
    funded(book, "alice", gold=100)
    first = book.place("dup", "alice", "buy", 10, 5)
    assert first["status"] == "open"
    second = book.place("dup", "alice", "buy", 20, 5)
    assert second["status"] == "duplicate"
    assert book.balance("alice", "gold") == 50
    assert book.order("dup")["price"] == 10
    assert len(book.open_orders("alice")) == 1


def test_insufficient_balance_rejects_order_without_side_effects():
    book = make()
    funded(book, "alice", gold=40, ore=1)
    with pytest.raises(mob.OrderError) as exc:
        book.place("b1", "alice", "buy", 10, 5)
    assert exc.value.code == "ORDER_INSUFFICIENT_FUNDS"
    assert book.balance("alice", "gold") == 40
    with pytest.raises(mob.OrderError) as other:
        book.place("s1", "alice", "sell", 10, 2)
    assert other.value.code == "ORDER_INSUFFICIENT_FUNDS"
    assert book.open_orders("alice") == []
    assert book.book() == {"buy": [], "sell": []}


def test_self_trade_is_prevented_and_next_counterparty_is_used():
    book = make()
    funded(book, "alice", ore=10, gold=100)
    funded(book, "carol", ore=10)
    book.place("a-sell", "alice", "sell", 5, 10)
    book.place("c-sell", "carol", "sell", 5, 10)
    book.place("a-buy", "alice", "buy", 5, 10)
    fills = book.match()
    assert len(fills) == 1
    assert fills[0]["maker_order"] == "c-sell"
    assert fills[0]["seller"] == "carol"
    assert book.order("a-sell")["remaining"] == 10
    assert book.order("a-buy")["status"] == "filled"
    assert book.balance("carol", "gold") == 50
    assert book.balance("alice", "ore") == 10


def test_invalid_order_parameters_are_rejected():
    book = make()
    funded(book, "alice", gold=100, ore=10)
    for args in (("x1", "alice", "buy", 0, 1), ("x2", "alice", "buy", 5, 0),
                 ("x3", "alice", "hold", 5, 1), ("", "alice", "buy", 5, 1)):
        with pytest.raises(mob.OrderError) as exc:
            book.place(*args)
        assert exc.value.code == "ORDER_BAD_ORDER"
    with pytest.raises(mob.OrderError) as other:
        book.deposit("alice", "gold", 0)
    assert other.value.code == "ORDER_BAD_AMOUNT"


def test_open_order_cap_rejects_new_orders():
    book = make(max_open_orders=2)
    funded(book, "alice", gold=100, ore=10)
    book.place("o1", "alice", "buy", 1, 1)
    book.place("o2", "alice", "sell", 100, 1)
    with pytest.raises(mob.OrderError) as exc:
        book.place("o3", "alice", "buy", 1, 1)
    assert exc.value.code == "ORDER_BOOK_FULL"
    assert len(book.open_orders("alice")) == 2


def test_match_budget_limits_work_per_call_and_keeps_remaining_cross():
    book = make()
    funded(book, "seller", ore=30)
    funded(book, "buyer", gold=300)
    book.place("s1", "seller", "sell", 4, 10)
    book.place("s2", "seller", "sell", 4, 10)
    book.place("s3", "seller", "sell", 4, 10)
    book.place("b1", "buyer", "buy", 4, 30)
    first = book.match(max_fills=2)
    assert len(first) == 2
    assert book.order("b1")["remaining"] == 10
    second = book.match()
    assert [fill["seq"] for fill in second] == [3]
    assert book.order("b1")["status"] == "filled"
    assert book.balance("buyer", "ore") == 30
    assert book.balance("buyer", "gold") == 180
    assert book.balance("seller", "gold") == 120


def test_depth_aggregates_and_sorts_levels():
    book = make()
    funded(book, "a", gold=1000, ore=100)
    book.place("b1", "a", "buy", 5, 3)
    book.place("b2", "a", "buy", 7, 2)
    book.place("b3", "a", "buy", 7, 4)
    book.place("s1", "a", "sell", 9, 1)
    book.place("s2", "a", "sell", 8, 5)
    assert book.depth("buy", levels=2) == [{"price": 7, "qty": 6},
                                           {"price": 5, "qty": 3}]
    assert book.depth("sell", levels=1) == [{"price": 8, "qty": 5}]
    assert book.book()["buy"][0]["order_id"] == "b2"
    assert [row["order_id"] for row in book.book("sell")] == ["s2", "s1"]


def test_snapshot_round_trip_preserves_book_and_totals():
    book = make(fee_bps=250)
    funded(book, "alice", ore=10)
    funded(book, "bob", gold=100)
    book.place("s", "alice", "sell", 5, 10)
    book.place("b", "bob", "buy", 6, 4)
    book.match()
    payload = json.loads(json.dumps(book.snapshot()))
    clone = mob.OrderBook(fee_bps=250)
    clone.restore(payload)
    assert clone.balance("bob", "gold") == 80
    assert clone.balance("bob", "ore") == 4
    assert clone.order("s")["remaining"] == 6
    assert [trade["seq"] for trade in clone.trades()] == [1]
    clone.place("s2", "bob", "sell", 5, 4)
    clone.place("b2", "alice", "buy", 5, 2)
    fills = clone.match()
    assert fills[0]["seq"] == 2
    assert clone.balance("alice", "ore") == 2
    with pytest.raises(mob.OrderError) as exc:
        mob.OrderBook().restore({"version": 42})
    assert exc.value.code == "ORDER_BAD_SNAPSHOT"


def test_concurrent_deposits_and_orders_keep_audit_balanced():
    book = make()
    barrier = threading.Barrier(8)
    errors = []

    def worker(index):
        try:
            barrier.wait()
            book.deposit(f"p{index}", "gold", 10)
            book.place(f"o{index}", f"p{index}", "buy", 1, 10)
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    assert len(book.open_orders()) == 8
    audit = book.audit()
    assert audit["gold_total"] == 80
    assert audit["gold_locked"] == 80
    assert book.balance("p0", "gold") == 0


def test_seller_pays_fee_and_fee_sink_is_tracked():
    book = make(fee_bps=250)
    funded(book, "seller", ore=10)
    funded(book, "buyer", gold=100)
    book.place("s", "seller", "sell", 50, 2)
    book.place("b", "buyer", "buy", 50, 2)
    fills = book.match()
    assert fills[0]["notional"] == 100
    assert fills[0]["fee"] == 2
    assert book.balance("seller", "gold") == 98
    assert book.fees_collected("gold") == 2
    assert book.audit()["gold_total"] == 100


def test_trades_since_and_invariants_after_mixed_flow():
    book = make(fee_bps=100)
    funded(book, "maker", ore=20)
    funded(book, "taker", gold=200)
    book.place("m1", "maker", "sell", 10, 5)
    book.place("m2", "maker", "sell", 11, 5)
    book.place("t1", "taker", "buy", 11, 8)
    book.match()
    assert [trade["seq"] for trade in book.trades(since=1)] == [2]
    assert book.balance("taker", "ore") == 8
    assert book.balance("maker", "ore") == 10
    out = book.cancel("m2", "maker")
    assert out["remaining"] == 2
    assert book.balance("maker", "ore") == 12
    audit = book.audit()
    assert audit["gold_total"] == 200
    assert audit["item_total"] == 20
    assert audit["open_orders"] == 0
