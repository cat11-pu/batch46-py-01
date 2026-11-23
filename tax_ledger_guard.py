"""Auction tax accrual, batching, waivers, reversals and payments.

Skeleton only: every public operation is a stub that must be implemented.
"""

from __future__ import annotations

from typing import Any, Mapping


class TaxError(ValueError):
    def __init__(self, code: str, detail: Any = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class TaxLedger:
    def __init__(self, rate_bps: int = 500, min_fee: int = 1, cap: int = 100000,
                 exempt_below: int = 0, batch_limit: int = 500,
                 max_pending: int = 2000) -> None:
        self.rate_bps = rate_bps
        self.min_fee = min_fee
        self.cap = cap
        self.exempt_below = exempt_below
        self.batch_limit = batch_limit
        self.max_pending = max_pending

    def tax_for(self, gross: int, category: str = "item") -> int:
        raise NotImplementedError

    def set_category_rate(self, category: str, rate_bps: int,
                          exempt_below: int = 0) -> dict[str, Any]:
        raise NotImplementedError

    def record_sale(self, sale_id: str, seller: str, buyer: str, gross: int,
                    occurred_at: str,
                    category: str = "item") -> dict[str, Any]:
        raise NotImplementedError

    def pending(self, seller: str | None = None) -> list[dict[str, Any]]:
        raise NotImplementedError

    def settle(self, seller: str, upto: str, batch_id: str,
               limit: int | None = None) -> dict[str, Any]:
        raise NotImplementedError

    def settle_all(self, upto: str, batch_id: str,
                   limit: int | None = None) -> dict[str, Any]:
        raise NotImplementedError

    def waiver(self, seller: str, sale_id: str,
               reason: str) -> dict[str, Any]:
        raise NotImplementedError

    def reversal(self, sale_id: str, reversal_id: str,
                 at: str) -> dict[str, Any]:
        raise NotImplementedError

    def pay(self, seller: str, amount: int, payment_id: str,
            at: str) -> dict[str, Any]:
        raise NotImplementedError

    def totals(self, seller: str) -> dict[str, Any]:
        raise NotImplementedError

    def batches(self, seller: str | None = None) -> list[dict[str, Any]]:
        raise NotImplementedError

    def ledger(self, seller: str) -> list[dict[str, Any]]:
        raise NotImplementedError

    def snapshot(self) -> dict[str, Any]:
        raise NotImplementedError

    def restore(self, payload: Mapping[str, Any]) -> None:
        raise NotImplementedError
