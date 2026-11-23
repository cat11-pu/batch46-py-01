"""Refund ledger with holds, credit limits, windows and chargebacks.

Skeleton only: every public operation is a stub that must be implemented.
"""

from __future__ import annotations

from typing import Any, Mapping


class RefundError(ValueError):
    def __init__(self, code: str, detail: Any = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class RefundLedger:
    def __init__(self, credit_limit: int = 500, window_days: int = 14,
                 max_holds: int = 32, max_entries: int = 5000) -> None:
        self.credit_limit = credit_limit
        self.window_days = window_days
        self.max_holds = max_holds
        self.max_entries = max_entries

    def credit(self, account: str, amount: int, tx_id: str,
               at: str) -> dict[str, Any]:
        raise NotImplementedError

    def debit(self, account: str, amount: int, tx_id: str, at: str,
              reason: str = "purchase") -> dict[str, Any]:
        raise NotImplementedError

    def refund(self, account: str, tx_id: str, amount: int, refund_id: str,
               at: str) -> dict[str, Any]:
        raise NotImplementedError

    def chargeback(self, account: str, tx_id: str, chargeback_id: str,
                   at: str) -> dict[str, Any]:
        raise NotImplementedError

    def balance(self, account: str) -> dict[str, int]:
        raise NotImplementedError

    def outstanding(self, account: str) -> int:
        raise NotImplementedError

    def hold(self, account: str, amount: int, hold_id: str) -> dict[str, Any]:
        raise NotImplementedError

    def release(self, account: str, hold_id: str) -> dict[str, Any]:
        raise NotImplementedError

    def settle(self, account: str, hold_id: str, at: str) -> dict[str, Any]:
        raise NotImplementedError

    def history(self, account: str) -> list[dict[str, Any]]:
        raise NotImplementedError

    def statement(self, account: str, from_at: str,
                  to_at: str) -> dict[str, Any]:
        raise NotImplementedError

    def snapshot(self) -> dict[str, Any]:
        raise NotImplementedError

    def restore(self, payload: Mapping[str, Any]) -> None:
        raise NotImplementedError
