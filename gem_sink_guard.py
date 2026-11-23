"""Premium gem grants, reservations, spending, expiry and refunds.

Skeleton only: every public operation is a stub that must be implemented.
"""

from __future__ import annotations

from typing import Any, Mapping


class GemError(ValueError):
    def __init__(self, code: str, detail: Any = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class GemSink:
    def __init__(self, daily_cap: int = 2000, retention_days: int = 30,
                 max_lots: int = 200, max_history: int = 5000) -> None:
        self.daily_cap = daily_cap
        self.retention_days = retention_days
        self.max_lots = max_lots
        self.max_history = max_history

    def grant(self, account: str, amount: int, grant_id: str,
              expires_at: str | None = None) -> dict[str, Any]:
        raise NotImplementedError

    def balance(self, account: str, at: str) -> dict[str, int]:
        raise NotImplementedError

    def lots(self, account: str, at: str) -> list[dict[str, Any]]:
        raise NotImplementedError

    def reserve(self, account: str, amount: int, reservation_id: str,
                at: str) -> dict[str, Any]:
        raise NotImplementedError

    def commit(self, account: str, reservation_id: str,
               at: str) -> dict[str, Any]:
        raise NotImplementedError

    def release(self, account: str, reservation_id: str,
                at: str) -> dict[str, Any]:
        raise NotImplementedError

    def spend(self, account: str, amount: int, spend_id: str,
              at: str) -> dict[str, Any]:
        raise NotImplementedError

    def refund(self, account: str, spend_id: str, amount: int, refund_id: str,
               at: str) -> dict[str, Any]:
        raise NotImplementedError

    def expire(self, account: str, at: str) -> dict[str, Any]:
        raise NotImplementedError

    def daily_spent(self, account: str, at: str) -> int:
        raise NotImplementedError

    def history(self, account: str) -> list[dict[str, Any]]:
        raise NotImplementedError

    def snapshot(self) -> dict[str, Any]:
        raise NotImplementedError

    def restore(self, payload: Mapping[str, Any]) -> None:
        raise NotImplementedError
