"""Raid loot: claims, deterministic conflict resolution, awards and trades."""

from __future__ import annotations


class LootError(ValueError):
    """Structured error carrying a machine readable code."""

    def __init__(self, code: str, detail=None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class LootDistributor:
    CLAIM_WINDOW = 300
    TRADE_WINDOW = 1800
    MAX_DROPS = 40
    MAX_CLAIMS = 200
    OVERRIDE_LIMIT = 2
    SNAPSHOT_VERSION = 1

    def __init__(self) -> None:
        self._raids: dict = {}
        self._copies: dict = {}
        self._seq = 0

    def open_raid(self, raid_id: str, *, now=None) -> dict:
        raise NotImplementedError

    def add_player(self, raid_id: str, player_id: str, *, need_score: int = 0,
                   role: str = "dps") -> dict:
        raise NotImplementedError

    def add_drop(self, raid_id: str, drop_id: str, items: list, *,
                 now=None) -> dict:
        raise NotImplementedError

    def claim(self, raid_id: str, drop_id: str, item_id: str, player_id: str, *,
              mode: str = "need", roll: int, now=None) -> dict:
        raise NotImplementedError

    def resolve(self, raid_id: str, drop_id: str, item_id: str, *,
                now=None) -> dict:
        raise NotImplementedError

    def award(self, raid_id: str, drop_id: str, item_id: str, player_id: str, *,
              reason: str, now=None) -> dict:
        raise NotImplementedError

    def trade(self, from_player: str, to_player: str, copy_id: str, *,
              now=None) -> dict:
        raise NotImplementedError

    def bind(self, player_id: str, copy_id: str) -> dict:
        raise NotImplementedError

    def inventory(self, player_id: str) -> list:
        raise NotImplementedError

    def ledger(self, raid_id: str) -> dict:
        raise NotImplementedError

    def unclaimed(self, raid_id: str) -> list:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError
