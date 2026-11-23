"""PvP draft guard: ban/pick order, champion availability and turn deadlines."""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum

KIND_BAN = "ban"
KIND_PICK = "pick"

ERR_INVALID_PHASE = "DRAFT_INVALID_PHASE"
ERR_CHAMPION_TAKEN = "DRAFT_CHAMPION_TAKEN"
ERR_UNKNOWN_CHAMPION = "DRAFT_UNKNOWN_CHAMPION"
ERR_NOT_YOUR_TURN = "DRAFT_NOT_YOUR_TURN"
ERR_DUPLICATE_ACTION = "DRAFT_DUPLICATE_ACTION"
ERR_CLOSED = "DRAFT_CLOSED"
ERR_TURN_NOT_EXPIRED = "DRAFT_TURN_NOT_EXPIRED"
ERR_DUPLICATE_CHAMPION = "DRAFT_DUPLICATE_CHAMPION"


class DraftError(Exception):
    """Domain error with a stable ``code``."""

    def __init__(self, code: str, detail: str | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class Team(str, Enum):
    BLUE = "blue"
    RED = "red"


class Phase(str, Enum):
    BAN = "ban"
    PICK = "pick"
    DONE = "done"


@dataclass(frozen=True)
class DraftConfig:
    """Draft policy; ``turn_seconds`` is the deadline budget of one turn."""

    bans_per_team: int = 0
    picks_per_team: int = 0
    turn_seconds: int = 30


@dataclass(frozen=True)
class Champion:
    champion_id: str
    role: str


@dataclass(frozen=True)
class Action:
    """One submitted ban or pick. ``kind`` is ``KIND_BAN`` or ``KIND_PICK``."""

    action_id: str
    team: Team
    kind: str
    champion_id: str
    at: datetime


@dataclass(frozen=True)
class DraftState:
    """Immutable view; picks and bans keep submission order."""

    phase: Phase
    turn: int
    team: Team | None
    bans: tuple[str, ...]
    blue_picks: tuple[str, ...]
    red_picks: tuple[str, ...]


class PvpDraft:
    """Runs one draft: alternating bans, snake picks and per-turn deadlines."""

    def __init__(
        self,
        config: DraftConfig,
        champions: list[Champion],
        now: datetime,
    ) -> None:
        self._config = config
        self._champions = list(champions)
        self._now = now

    @classmethod
    def from_snapshot(
        cls,
        config: DraftConfig,
        champions: list[Champion],
        data: bytes,
    ) -> "PvpDraft":
        """Restore turn index, accepted actions, action ids and the deadline."""
        raise NotImplementedError

    def submit(self, action: Action, now: datetime) -> DraftState:
        """Apply one ban or pick and advance the turn."""
        raise NotImplementedError

    def state(self) -> DraftState:
        """Return a copy of the current draft state."""
        raise NotImplementedError

    def timeout(self, now: datetime) -> DraftState:
        """Advance a turn whose deadline has passed, without recording history."""
        raise NotImplementedError

    def deadline(self) -> datetime | None:
        """Deadline of the current turn; ``None`` once the draft is done."""
        raise NotImplementedError

    def available(self, role: str | None = None) -> list[str]:
        """Sorted champion ids not banned or picked, optionally by role."""
        raise NotImplementedError

    def champions(self) -> list[Champion]:
        """Return a copy of the champion pool."""
        raise NotImplementedError

    def history(self) -> list[Action]:
        """Return a copy of the accepted actions in submission order."""
        raise NotImplementedError

    def remaining_bans(self, team: Team) -> int:
        """How many bans the team still owns."""
        raise NotImplementedError

    def picks(self, team: Team) -> list[str]:
        """Champion ids picked by the team, in submission order."""
        raise NotImplementedError

    def snapshot(self) -> bytes:
        """Serialise turn index, history, accepted action ids and the deadline."""
        raise NotImplementedError
