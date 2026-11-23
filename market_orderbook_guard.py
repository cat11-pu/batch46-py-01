"""Auction-house order book with escrow, price-time priority and audits.

The order book keeps a single ledger for deposits, resting orders, fills and
fees.  Every public operation is serialised by one re-entrant lock so freezing
funds, settling a trade and updating the book cannot be observed half done.
"""

from __future__ import annotations

import threading
from bisect import insort
from collections import deque
from copy import deepcopy
from typing import Any, Mapping


SNAPSHOT_VERSION = 1


class OrderError(ValueError):
    def __init__(self, code: str, detail: Any = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class OrderBook:
    def __init__(self, max_open_orders: int = 1000, fee_bps: int = 0) -> None:
        self.max_open_orders = max_open_orders
        self.fee_bps = fee_bps

        # (account, currency) -> available amount
        self._balances: dict[tuple[str, str], int] = {}
        # currency -> fees collected in that currency
        self._fees: dict[str, int] = {}

        self._orders: dict[str, dict[str, Any]] = {}
        # Open orders that have not finished their taker pass.  Activated
        # orders are eligible to act as makers; pending orders are not, which
        # keeps the taker budget from exposing half-processed work.
        self._pending: deque[str] = deque()
        self._buy_book: list[tuple[int, int, str]] = []
        self._sell_book: list[tuple[int, int, str]] = []

        self._order_seq = 0
        self._trade_seq = 0
        self._trades: list[dict[str, Any]] = []
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # Small helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _is_int(value: Any) -> bool:
        return isinstance(value, int) and not isinstance(value, bool)

    def _require_side(self, side: str) -> str:
        if side not in ("buy", "sell"):
            raise OrderError("ORDER_BAD_ORDER", {"side": side})
        return side

    def _open_count(self) -> int:
        return sum(1 for order in self._orders.values()
                   if order["status"] == "open")

    def _copy_order(self, order: Mapping[str, Any]) -> dict[str, Any]:
        return deepcopy(dict(order))

    def _public_order(self, order: Mapping[str, Any]) -> dict[str, Any]:
        return self._copy_order(order)

    def _balance_ref(self, account: str, currency: str) -> int:
        return self._balances.get((account, currency), 0)

    def _credit(self, account: str, currency: str, amount: int) -> None:
        key = (account, currency)
        self._balances[key] = self._balances.get(key, 0) + amount

    def _debit(self, account: str, currency: str, amount: int) -> None:
        key = (account, currency)
        self._balances[key] = self._balances.get(key, 0) - amount

    def _remove_from_book(self, order: Mapping[str, Any]) -> None:
        key = (-order["price"], order["seq"], order["order_id"]) \
            if order["side"] == "buy" \
            else (order["price"], order["seq"], order["order_id"])
        book = self._buy_book if order["side"] == "buy" else self._sell_book
        try:
            book.remove(key)
        except ValueError:
            pass

    def _insert_into_book(self, order: Mapping[str, Any]) -> None:
        if order["status"] != "open" or not order["activated"]:
            return
        if order["side"] == "buy":
            insort(self._buy_book,
                   (-order["price"], order["seq"], order["order_id"]))
        else:
            insort(self._sell_book,
                   (order["price"], order["seq"], order["order_id"]))

    def _same_market(self, first: Mapping[str, Any],
                     second: Mapping[str, Any]) -> bool:
        return (first["item"] == second["item"]
                and first["quote"] == second["quote"])

    def _find_maker(self, taker: Mapping[str, Any]) -> dict[str, Any] | None:
        """Return the best eligible resting counter-order for ``taker``.

        Same-account orders are skipped rather than treated as a wall, so a
        wash order can never consume itself and the next counterparty is used.
        """
        if taker["side"] == "buy":
            book = self._sell_book
            for _neg_price, _seq, oid in list(book):
                maker = self._orders.get(oid)
                if maker is None or maker["status"] != "open":
                    try:
                        book.remove((_neg_price, _seq, oid))
                    except ValueError:
                        pass
                    continue
                if maker["price"] > taker["price"]:
                    break
                if not self._same_market(taker, maker):
                    continue
                if maker["account"] == taker["account"]:
                    continue
                return maker
        else:
            book = self._buy_book
            for neg_price, _seq, oid in list(book):
                maker = self._orders.get(oid)
                if maker is None or maker["status"] != "open":
                    try:
                        book.remove((neg_price, _seq, oid))
                    except ValueError:
                        pass
                    continue
                if maker["price"] < taker["price"]:
                    break
                if not self._same_market(taker, maker):
                    continue
                if maker["account"] == taker["account"]:
                    continue
                return maker
        return None

    # ------------------------------------------------------------------
    # Funds and orders
    # ------------------------------------------------------------------
    def deposit(self, account: str, currency: str, amount: int) -> int:
        if not self._is_int(amount) or amount <= 0:
            raise OrderError("ORDER_BAD_AMOUNT", {"amount": amount})
        with self._lock:
            self._credit(account, currency, amount)
            return self._balance_ref(account, currency)

    def balance(self, account: str, currency: str) -> int:
        with self._lock:
            return self._balance_ref(account, currency)

    def place(self, order_id: str, account: str, side: str, price: int,
              qty: int, item: str = "ore",
              quote: str = "gold") -> dict[str, Any]:
        with self._lock:
            if not isinstance(order_id, str) or not order_id:
                raise OrderError("ORDER_BAD_ORDER", {"order_id": order_id})

            # Idempotency wins over validation: the first accepted order is
            # the canonical one, and a duplicate never escrows again.
            existing = self._orders.get(order_id)
            if existing is not None:
                result = self._public_order(existing)
                result["status"] = "duplicate"
                return result

            if (not isinstance(account, str) or not account
                    or side not in ("buy", "sell")
                    or not self._is_int(price) or price <= 0
                    or not self._is_int(qty) or qty <= 0
                    or not isinstance(item, str) or not item
                    or not isinstance(quote, str) or not quote):
                raise OrderError("ORDER_BAD_ORDER", {
                    "order_id": order_id,
                    "account": account,
                    "side": side,
                    "price": price,
                    "qty": qty,
                    "item": item,
                    "quote": quote,
                })

            if self._open_count() >= self.max_open_orders:
                raise OrderError("ORDER_BOOK_FULL",
                                 {"max_open_orders": self.max_open_orders})

            if side == "buy":
                escrow_currency = quote
                escrow_amount = price * qty
            else:
                escrow_currency = item
                escrow_amount = qty

            if self._balance_ref(account, escrow_currency) < escrow_amount:
                raise OrderError("ORDER_INSUFFICIENT_FUNDS", {
                    "account": account,
                    "currency": escrow_currency,
                    "required": escrow_amount,
                    "available": self._balance_ref(account, escrow_currency),
                })

            self._debit(account, escrow_currency, escrow_amount)
            self._order_seq += 1
            order = {
                "order_id": order_id,
                "account": account,
                "side": side,
                "price": price,
                "qty": qty,
                "remaining": qty,
                "status": "open",
                "item": item,
                "quote": quote,
                "seq": self._order_seq,
                "locked": escrow_amount,
                "activated": False,
            }
            self._orders[order_id] = order
            self._pending.append(order_id)
            return self._public_order(order)

    def cancel(self, order_id: str, account: str) -> dict[str, Any]:
        with self._lock:
            order = self._orders.get(order_id)
            if order is None:
                raise OrderError("ORDER_NOT_FOUND", {"order_id": order_id})
            if order["account"] != account:
                raise OrderError("ORDER_NOT_OWNER", {"order_id": order_id})
            if order["status"] != "open":
                raise OrderError("ORDER_NOT_OPEN", {
                    "order_id": order_id,
                    "status": order["status"],
                })

            remaining = order["remaining"]
            if order["side"] == "buy":
                refund = order["price"] * remaining
                self._credit(order["account"], order["quote"], refund)
            else:
                refund = remaining
                self._credit(order["account"], order["item"], refund)

            order["status"] = "cancelled"
            order["locked"] = 0
            order["activated"] = True
            self._remove_from_book(order)
            try:
                self._pending.remove(order_id)
            except ValueError:
                pass

            result = self._public_order(order)
            result["status"] = "cancelled"
            result["refund_amount"] = refund
            return result

    # ------------------------------------------------------------------
    # Matching
    # ------------------------------------------------------------------
    def _fee_for(self, notional: int) -> int:
        if self.fee_bps <= 0:
            return 0
        fee = notional * self.fee_bps // 10000
        return min(notional, max(0, fee))

    def _execute_fill(self, taker: dict[str, Any], maker: dict[str, Any],
                      qty: int) -> dict[str, Any]:
        if taker["side"] == "buy":
            buy, sell = taker, maker
        else:
            buy, sell = maker, taker

        price = maker["price"]
        notional = price * qty
        fee = self._fee_for(notional)

        # Buyer's escrow was taken at the buy limit.  Release exactly the
        # portion that belongs to this fill and return any price improvement.
        release = buy["price"] * qty
        refund = (buy["price"] - price) * qty
        self._credit(buy["account"], buy["quote"], refund)
        buy["locked"] -= release

        self._credit(sell["account"], sell["quote"], notional - fee)
        self._fees[sell["quote"]] = self._fees.get(sell["quote"], 0) + fee

        self._credit(buy["account"], buy["item"], qty)

        for order in (buy, sell):
            order["remaining"] -= qty
            if order["side"] == "sell":
                order["locked"] -= qty
            if order["remaining"] == 0:
                order["status"] = "filled"
                order["locked"] = 0
                self._remove_from_book(order)

        self._trade_seq += 1
        fill = {
            "seq": self._trade_seq,
            "maker_order": maker["order_id"],
            "taker_order": taker["order_id"],
            "buyer": buy["account"],
            "seller": sell["account"],
            "price": price,
            "qty": qty,
            "notional": notional,
            "fee": fee,
            "item": buy["item"],
            "quote": buy["quote"],
        }
        self._trades.append(fill)
        return deepcopy(fill)

    def match(self, max_fills: int | None = None) -> list[dict[str, Any]]:
        if max_fills is not None and (
                not self._is_int(max_fills) or max_fills < 0):
            raise OrderError("ORDER_BAD_ORDER", {"max_fills": max_fills})

        with self._lock:
            if max_fills == 0:
                return []

            fills: list[dict[str, Any]] = []
            while self._pending and (
                    max_fills is None or len(fills) < max_fills):
                order = self._orders.get(self._pending[0])
                if (order is None or order["status"] != "open"
                        or order["activated"]):
                    self._pending.popleft()
                    continue

                while (order["status"] == "open"
                       and order["remaining"] > 0
                       and (max_fills is None or len(fills) < max_fills)):
                    maker = self._find_maker(order)
                    if maker is None:
                        break
                    qty = min(order["remaining"], maker["remaining"])
                    fills.append(self._execute_fill(order, maker, qty))

                if order["status"] != "open":
                    self._pending.popleft()
                    continue

                if max_fills is not None and len(fills) >= max_fills:
                    # Budget exhausted mid-taker.  Keep it pending and out of
                    # the maker book; the next match call resumes it first.
                    break

                order["activated"] = True
                self._insert_into_book(order)
                self._pending.popleft()

            return fills

    # ------------------------------------------------------------------
    # Read models
    # ------------------------------------------------------------------
    def order(self, order_id: str) -> dict[str, Any]:
        with self._lock:
            order = self._orders.get(order_id)
            if order is None:
                raise OrderError("ORDER_NOT_FOUND", {"order_id": order_id})
            return self._public_order(order)

    def open_orders(self, account: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            orders = [order for order in self._orders.values()
                      if order["status"] == "open"
                      and (account is None or order["account"] == account)]
            orders.sort(key=lambda item: item["seq"])
            return [self._public_order(order) for order in orders]

    def _sorted_open(self, side: str) -> list[dict[str, Any]]:
        orders = [order for order in self._orders.values()
                  if order["status"] == "open" and order["side"] == side]
        if side == "buy":
            orders.sort(key=lambda item: (-item["price"], item["seq"]))
        else:
            orders.sort(key=lambda item: (item["price"], item["seq"]))
        return orders

    def book(self, side: str | None = None) -> Any:
        with self._lock:
            if side is None:
                return {
                    "buy": [self._public_order(order)
                            for order in self._sorted_open("buy")],
                    "sell": [self._public_order(order)
                             for order in self._sorted_open("sell")],
                }
            self._require_side(side)
            return [self._public_order(order)
                    for order in self._sorted_open(side)]

    def depth(self, side: str, levels: int = 5) -> list[dict[str, int]]:
        with self._lock:
            self._require_side(side)
            if not self._is_int(levels):
                raise OrderError("ORDER_BAD_ORDER", {"levels": levels})
            if levels <= 0:
                return []

            aggregated: dict[int, int] = {}
            for order in self._sorted_open(side):
                aggregated[order["price"]] = (
                    aggregated.get(order["price"], 0) + order["remaining"])

            prices = sorted(aggregated, reverse=(side == "buy"))
            return [{"price": price, "qty": aggregated[price]}
                    for price in prices[:levels]]

    def trades(self, since: int = 0) -> list[dict[str, Any]]:
        with self._lock:
            return [deepcopy(trade) for trade in self._trades
                    if trade["seq"] > since]

    def fees_collected(self, currency: str = "gold") -> int:
        with self._lock:
            return self._fees.get(currency, 0)

    def audit(self) -> dict[str, Any]:
        with self._lock:
            open_orders = [order for order in self._orders.values()
                           if order["status"] == "open"]

            gold_balance = sum(
                amount for (_account, currency), amount
                in self._balances.items() if currency == "gold")
            gold_locked = sum(
                order["locked"] for order in open_orders
                if order["side"] == "buy" and order["quote"] == "gold")
            item_balance = sum(
                amount for (_account, currency), amount
                in self._balances.items() if currency == "ore")
            item_locked = sum(
                order["remaining"] for order in open_orders
                if order["side"] == "sell" and order["item"] == "ore")
            fees = self._fees.get("gold", 0)

            return {
                "gold_total": gold_balance + gold_locked + fees,
                "gold_locked": gold_locked,
                "item_total": item_balance + item_locked,
                "item_locked": item_locked,
                "fees": fees,
                "open_orders": len(open_orders),
            }

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------
    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "version": SNAPSHOT_VERSION,
                "max_open_orders": self.max_open_orders,
                "fee_bps": self.fee_bps,
                "balances": [
                    [account, currency, amount]
                    for (account, currency), amount in sorted(
                        self._balances.items())
                ],
                "fees": dict(self._fees),
                "orders": [deepcopy(order)
                           for order in sorted(
                               self._orders.values(),
                               key=lambda item: item["seq"])],
                "pending": [
                    order_id for order_id in self._pending
                    if (order_id in self._orders
                        and self._orders[order_id]["status"] == "open"
                        and not self._orders[order_id]["activated"])
                ],
                "order_seq": self._order_seq,
                "trade_seq": self._trade_seq,
                "trades": deepcopy(self._trades),
            }

    def restore(self, payload: Mapping[str, Any]) -> None:
        with self._lock:
            try:
                if (not isinstance(payload, Mapping)
                        or payload.get("version") != SNAPSHOT_VERSION):
                    raise OrderError("ORDER_BAD_SNAPSHOT")

                max_open_orders = int(payload["max_open_orders"])
                fee_bps = int(payload["fee_bps"])
                order_seq = int(payload["order_seq"])
                trade_seq = int(payload["trade_seq"])

                balances: dict[tuple[str, str], int] = {}
                for row in payload["balances"]:
                    if len(row) != 3:
                        raise ValueError("bad balance row")
                    account, currency, amount = row
                    amount = int(amount)
                    if amount < 0:
                        raise ValueError("negative balance")
                    balances[(account, currency)] = amount

                fees: dict[str, int] = {}
                for currency, amount in payload.get("fees", {}).items():
                    amount = int(amount)
                    if amount < 0:
                        raise ValueError("negative fee")
                    fees[currency] = amount

                orders: dict[str, dict[str, Any]] = {}
                for raw in payload["orders"]:
                    order = deepcopy(dict(raw))
                    required = {
                        "order_id", "account", "side", "price", "qty",
                        "remaining", "status", "item", "quote", "seq",
                        "locked", "activated",
                    }
                    if not required.issubset(order):
                        raise ValueError("incomplete order")
                    order["order_id"] = str(order["order_id"])
                    order["account"] = str(order["account"])
                    order["side"] = str(order["side"])
                    order["status"] = str(order["status"])
                    order["item"] = str(order["item"])
                    order["quote"] = str(order["quote"])
                    order["price"] = int(order["price"])
                    order["qty"] = int(order["qty"])
                    order["remaining"] = int(order["remaining"])
                    order["seq"] = int(order["seq"])
                    order["locked"] = int(order["locked"])
                    order["activated"] = bool(order["activated"])
                    if (order["side"] not in ("buy", "sell")
                            or order["status"] not in
                            ("open", "filled", "cancelled")
                            or order["price"] <= 0 or order["qty"] <= 0
                            or not 0 <= order["remaining"] <= order["qty"]):
                        raise ValueError("invalid order")
                    if order["locked"] < 0:
                        raise ValueError("negative lock")
                    if order["status"] == "open":
                        expected_lock = (
                            order["price"] * order["remaining"]
                            if order["side"] == "buy"
                            else order["remaining"])
                        if order["locked"] != expected_lock:
                            raise ValueError("inconsistent lock")
                    elif order["locked"] != 0:
                        raise ValueError("locked closed order")
                    orders[order["order_id"]] = order

                trades: list[dict[str, Any]] = []
                for raw in payload.get("trades", []):
                    trade = deepcopy(dict(raw))
                    trade["seq"] = int(trade["seq"])
                    trade["price"] = int(trade["price"])
                    trade["qty"] = int(trade["qty"])
                    trade["notional"] = int(trade["notional"])
                    trade["fee"] = int(trade["fee"])
                    trades.append(trade)
                trades.sort(key=lambda item: item["seq"])

                pending_raw = payload.get("pending")
                if pending_raw is None:
                    pending_ids = [
                        order["order_id"] for order in sorted(
                            orders.values(), key=lambda item: item["seq"])
                        if order["status"] == "open"
                        and not order["activated"]
                    ]
                else:
                    pending_ids = [str(order_id) for order_id in pending_raw]
                for order_id in pending_ids:
                    order = orders.get(order_id)
                    if (order is None or order["status"] != "open"
                            or order["activated"]):
                        raise ValueError("invalid pending order")
                if len(set(pending_ids)) != len(pending_ids):
                    raise ValueError("duplicate pending order")

                buy_book: list[tuple[int, int, str]] = []
                sell_book: list[tuple[int, int, str]] = []
                for order in sorted(orders.values(),
                                    key=lambda item: item["seq"]):
                    if order["status"] != "open" or not order["activated"]:
                        continue
                    if order["side"] == "buy":
                        buy_book.append(
                            (-order["price"], order["seq"],
                             order["order_id"]))
                    else:
                        sell_book.append(
                            (order["price"], order["seq"],
                             order["order_id"]))
                buy_book.sort()
                sell_book.sort()

                if order_seq < max((order["seq"] for order in orders.values()),
                                   default=0):
                    raise ValueError("order sequence regression")
                if trade_seq < max((trade["seq"] for trade in trades),
                                   default=0):
                    raise ValueError("trade sequence regression")
            except OrderError:
                raise
            except Exception as exc:
                raise OrderError("ORDER_BAD_SNAPSHOT", {"error": str(exc)})

            self.max_open_orders = max_open_orders
            self.fee_bps = fee_bps
            self._balances = balances
            self._fees = fees
            self._orders = orders
            self._pending = deque(pending_ids)
            self._buy_book = buy_book
            self._sell_book = sell_book
            self._order_seq = order_seq
            self._trade_seq = trade_seq
            self._trades = trades
