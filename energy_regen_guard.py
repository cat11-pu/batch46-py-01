"""Stamina regeneration: timed accrual, caps, daily resets and refills."""

from __future__ import annotations


class EnergyError(ValueError):
    """Structured error carrying a machine readable code."""

    def __init__(self, code: str, detail=None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class EnergyRegen:
    SECONDS_PER_POINT = 300
    MAX_OFFLINE_SECONDS = 43200
    OVERFLOW_MARGIN = 60
    REFILLS_PER_DAY = 3
    SNAPSHOT_VERSION = 1

    def __init__(self, *, default_cap: int = 120) -> None:
        self._accounts: dict = {}
        self._refs: dict = {}
        self._history: list = []

    def create_account(self, account_id: str, *, energy: int | None = None,
                       cap: int | None = None, now=None) -> dict:
        raise NotImplementedError

    def regen(self, account_id: str, now) -> dict:
        raise NotImplementedError

    def state(self, account_id: str, now=None) -> dict:
        raise NotImplementedError

    def next_full_at(self, account_id: str, now=None):
        raise NotImplementedError

    def spend(self, account_id: str, amount: int, *, now=None,
              ref: str | None = None) -> dict:
        raise NotImplementedError

    def grant(self, account_id: str, amount: int, *, now=None,
              allow_overflow: bool = False) -> dict:
        raise NotImplementedError

    def daily_reset(self, account_id: str, now) -> dict:
        raise NotImplementedError

    def buy_refill(self, account_id: str, *, now=None) -> dict:
        raise NotImplementedError

    def history(self, account_id: str, limit: int = 10) -> list:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError
