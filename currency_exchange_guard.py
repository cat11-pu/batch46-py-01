"""Multi-currency wallet: quoted exchange, frozen funds and settlement."""

from __future__ import annotations


class CurrencyError(ValueError):
    """Structured error carrying a machine readable code."""

    def __init__(self, code: str, detail=None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class CurrencyExchange:
    SNAPSHOT_VERSION = 1

    def __init__(self, *, base_currency: str = "GOLD", fee_rate="0.005",
                 fee_min="0.01", quote_ttl: int = 60, max_quotes: int = 32) -> None:
        self._rates: dict = {}
        self._wallets: dict = {}
        self._freezes: dict = {}
        self._quotes: dict = {}
        self._history: list = []
        self._seq = 0

    def add_rate(self, base: str, quote: str, rate, *, effective_at=None) -> dict:
        raise NotImplementedError

    def rate(self, base: str, quote: str):
        raise NotImplementedError

    def open_wallet(self, account_id: str, balances: dict | None = None) -> dict:
        raise NotImplementedError

    def balance(self, account_id: str) -> dict:
        raise NotImplementedError

    def available(self, account_id: str) -> dict:
        raise NotImplementedError

    def quote(self, account_id: str, from_currency: str, to_currency: str,
              amount, *, now=None) -> dict:
        raise NotImplementedError

    def exchange(self, account_id: str, quote_id: str, *, now=None) -> dict:
        raise NotImplementedError

    def freeze(self, account_id: str, currency: str, amount, *,
               reason: str = "hold", now=None) -> dict:
        raise NotImplementedError

    def release(self, freeze_id: str) -> dict:
        raise NotImplementedError

    def settle(self, freeze_id: str, *, currency: str | None = None,
               amount=None, now=None) -> dict:
        raise NotImplementedError

    def history(self, account_id: str, limit: int = 10) -> list:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError
