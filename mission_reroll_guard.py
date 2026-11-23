"""Daily mission board and reroll guard.

Skeleton only: every public operation is a stub that must be implemented.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence


class MissionError(ValueError):
    def __init__(self, code: str, detail: Any = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class MissionReroll:
    def __init__(self, daily_limit: int = 3, carry_cap: int = 5,
                 max_pool: int = 200) -> None:
        self.daily_limit = daily_limit
        self.carry_cap = carry_cap
        self.max_pool = max_pool

    def define_pool(self, slot_kind: str,
                    missions: Sequence[str]) -> dict[str, Any]:
        raise NotImplementedError

    def assign_day(self, account: str, day: str, slots: int = 3,
                   seed: int = 0) -> dict[str, Any]:
        raise NotImplementedError

    def current(self, account: str, day: str) -> dict[str, Any]:
        raise NotImplementedError

    def reroll(self, account: str, day: str, slot: str,
               request_id: str) -> dict[str, Any]:
        raise NotImplementedError

    def lock_slot(self, account: str, day: str, slot: str) -> dict[str, Any]:
        raise NotImplementedError

    def complete(self, account: str, day: str, slot: str,
                 event_id: str) -> dict[str, Any]:
        raise NotImplementedError

    def claims(self, account: str, day: str) -> list[dict[str, Any]]:
        raise NotImplementedError

    def grant_tokens(self, account: str, amount: int,
                     reason: str = "grant") -> dict[str, Any]:
        raise NotImplementedError

    def tokens(self, account: str) -> int:
        raise NotImplementedError

    def rollover(self, account: str, from_day: str,
                 to_day: str) -> dict[str, Any]:
        raise NotImplementedError

    def stats(self, account: str) -> dict[str, Any]:
        raise NotImplementedError

    def snapshot(self) -> dict[str, Any]:
        raise NotImplementedError

    def restore(self, payload: Mapping[str, Any]) -> None:
        raise NotImplementedError
