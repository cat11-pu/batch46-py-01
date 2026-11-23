"""Auction-house order book with escrow, price-time priority and audits.

Skeleton only: every public operation is a stub that must be implemented.
"""

from __future__ import annotations

from typing import Any, Mapping


class OrderError(ValueError):
    def __init__(self, code: str, detail: Any = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class OrderBook:
    def __init__(self, max_open_orders: int = 1000, fee_bps: int = 0) -> None:
        self.max_open_orders = max_open_orders
        self.fee_bps = fee_bps

    def deposit(self, account: str, currency: str, amount: int) -> int:
        raise NotImplementedError

    def balance(self, account: str, currency: str) -> int:
        raise NotImplementedError

    def place(self, order_id: str, account: str, side: str, price: int,
              qty: int, item: str = "ore", quote: str = "gold") -> dict[str, Any]:
        raise NotImplementedError

    def cancel(self, order_id: str, account: str) -> dict[str, Any]:
        raise NotImplementedError

    def match(self, max_fills: int | None = None) -> list[dict[str, Any]]:
        raise NotImplementedError

    def order(self, order_id: str) -> dict[str, Any]:
        raise NotImplementedError

    def open_orders(self, account: str | None = None) -> list[dict[str, Any]]:
        raise NotImplementedError

    def book(self, side: str | None = None) -> dict[str, list[dict[str, Any]]]:
        raise NotImplementedError

    def depth(self, side: str, levels: int = 5) -> list[dict[str, int]]:
        raise NotImplementedError

    def trades(self, since: int = 0) -> list[dict[str, Any]]:
        raise NotImplementedError

    def fees_collected(self, currency: str = "gold") -> int:
        raise NotImplementedError

    def audit(self) -> dict[str, Any]:
        raise NotImplementedError

    def snapshot(self) -> dict[str, Any]:
        raise NotImplementedError

    def restore(self, payload: Mapping[str, Any]) -> None:
        raise NotImplementedError
