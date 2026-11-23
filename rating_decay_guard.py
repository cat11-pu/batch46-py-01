"""PvP rating bookkeeping: zero-sum Elo, inactivity decay and comeback refunds."""

from __future__ import annotations


class RatingError(ValueError):
    """Structured error carrying a machine readable code."""

    def __init__(self, code: str, detail=None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class RatingDecay:
    FLOOR = 100
    CEILING = 3000
    BASE_K = 32
    PROVISIONAL_K = 64
    PROVISIONAL_MATCHES = 5
    DECAY_GRACE_DAYS = 14
    DECAY_PER_WEEK = 25
    DECAY_CAP = 100
    DECAY_PROTECT_BELOW = 1000
    COMEBACK_MATCHES = 3
    COMEBACK_RATE = 0.5
    COMEBACK_CAP = 60
    SNAPSHOT_VERSION = 1

    def __init__(self, policy: dict | None = None) -> None:
        self._players: dict = {}
        self._matches: dict = {}
        self._history: list = []
        self._decay: dict = {}
        self._seq = 0

    def register(self, player_id: str, rating: int = 1500, region: str = "global",
                 *, now=None) -> dict:
        raise NotImplementedError

    def record_match(self, match_id: str, winner: str, loser: str, *,
                     occurred_at=None, season: str = "s1") -> dict:
        raise NotImplementedError

    def record_matches(self, matches) -> list:
        raise NotImplementedError

    def rating(self, player_id: str) -> int:
        raise NotImplementedError

    def history(self, player_id: str, limit: int = 10) -> list:
        raise NotImplementedError

    def leaderboard(self, region: str | None = None, limit: int = 10) -> list:
        raise NotImplementedError

    def apply_decay(self, season: str, now) -> list:
        raise NotImplementedError

    def claim_comeback(self, player_id: str, *, now=None) -> dict:
        raise NotImplementedError

    def retire(self, player_id: str) -> dict:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError
