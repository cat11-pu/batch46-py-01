"""Season reward granting and reissue (implementation skeleton)."""

from __future__ import annotations

import threading

SNAPSHOT_VERSION = 1
SEASON_STATUSES = ("open", "closed", "expired")


class SeasonRewardError(ValueError):
    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class SeasonReward:
    """Season windows, tier ladders, point ledger, claims, revoke and reissue."""

    def __init__(self, *, max_tiers: int = 20, max_claims_per_batch: int = 50,
                 max_points: int = 10_000_000) -> None:
        self.max_tiers = max_tiers
        self.max_claims_per_batch = max_claims_per_batch
        self.max_points = max_points
        self._lock = threading.RLock()
        self._seasons = {}
        self._tiers = {}
        self._points = {}
        self._claims = {}
        self._events = set()

    def open_season(self, season: str, *, starts_at: int, ends_at: int,
                    grace: int = 0, name: str | None = None) -> dict:
        raise NotImplementedError

    def define_tier(self, season: str, tier: int, *, requirement: int,
                    rewards: tuple = (),
                    exclusive_group: str | None = None) -> dict:
        raise NotImplementedError

    def grant_points(self, account: str, season: str, points: int, *,
                     event_id: str | None = None, reason: str = "match",
                     now: int | None = None) -> dict:
        raise NotImplementedError

    def claim(self, account: str, season: str, tier: int, *,
              now: int | None = None) -> dict:
        raise NotImplementedError

    def claim_batch(self, accounts: list, season: str, tier: int, *,
                    now: int | None = None) -> list:
        raise NotImplementedError

    def revoke(self, account: str, season: str, tier: int, *, reason: str,
               now: int | None = None) -> dict:
        raise NotImplementedError

    def reissue(self, account: str, season: str, tier: int, *, reason: str,
                now: int | None = None) -> dict:
        raise NotImplementedError

    def points(self, account: str, season: str) -> dict:
        raise NotImplementedError

    def claims(self, account: str, season: str | None = None) -> list:
        raise NotImplementedError

    def season_state(self, season: str, *, now: int | None = None) -> dict:
        raise NotImplementedError

    def close_season(self, season: str, *, now: int | None = None) -> dict:
        raise NotImplementedError

    def expire(self, now: int) -> list:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, snapshot: dict) -> None:
        raise NotImplementedError
