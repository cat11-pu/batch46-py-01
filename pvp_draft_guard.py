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
        seen: set[str] = set()
        for champion in champions:
            if champion.champion_id in seen:
                raise DraftError(ERR_DUPLICATE_CHAMPION)
            seen.add(champion.champion_id)

        self._config = config
        self._champions = list(champions)
        self._champion_by_id = {
            champion.champion_id: champion for champion in self._champions
        }
        self._now = now
        self._lock = threading.RLock()
        self._turn = 0
        self._history: list[Action] = []
        self._action_ids: set[str] = set()
        self._taken: set[str] = set()
        self._deadline = (
            None
            if self._total_turns() == 0
            else now + timedelta(seconds=config.turn_seconds)
        )

    @classmethod
    def from_snapshot(
        cls,
        config: DraftConfig,
        champions: list[Champion],
        data: bytes,
    ) -> "PvpDraft":
        """Restore turn index, accepted actions, action ids and the deadline."""
        payload = json.loads(data.decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("invalid draft snapshot")

        deadline_raw = payload.get("deadline")
        restored_deadline = (
            datetime.fromisoformat(deadline_raw)
            if deadline_raw is not None
            else None
        )
        init_now = restored_deadline if restored_deadline is not None else datetime.min
        draft = cls(config, champions, init_now)

        history: list[Action] = []
        for item in payload.get("history", []):
            history.append(
                Action(
                    action_id=item["action_id"],
                    team=Team(item["team"]),
                    kind=item["kind"],
                    champion_id=item["champion_id"],
                    at=datetime.fromisoformat(item["at"]),
                )
            )

        action_ids = set(payload.get("action_ids", []))
        action_ids.update(action.action_id for action in history)

        draft._turn = int(payload["turn"])
        draft._history = history
        draft._action_ids = action_ids
        draft._taken = {action.champion_id for action in history}
        draft._deadline = restored_deadline
        return draft

    def submit(self, action: Action, now: datetime) -> DraftState:
        """Apply one ban or pick and advance the turn."""
        with self._lock:
            if self._phase() == Phase.DONE:
                raise DraftError(ERR_CLOSED)
            if action.action_id in self._action_ids:
                raise DraftError(ERR_DUPLICATE_ACTION)

            phase = self._phase()
            expected_kind = KIND_BAN if phase == Phase.BAN else KIND_PICK
            if action.kind != expected_kind:
                raise DraftError(ERR_INVALID_PHASE)
            if action.team != self._team():
                raise DraftError(ERR_NOT_YOUR_TURN)
            if action.champion_id not in self._champion_by_id:
                raise DraftError(ERR_UNKNOWN_CHAMPION)
            if action.champion_id in self._taken:
                raise DraftError(ERR_CHAMPION_TAKEN)

            self._history.append(action)
            self._action_ids.add(action.action_id)
            self._taken.add(action.champion_id)
            self._advance(now)
            return self._build_state()

    def state(self) -> DraftState:
        """Return a copy of the current draft state."""
        with self._lock:
            return self._build_state()

    def timeout(self, now: datetime) -> DraftState:
        """Advance a turn whose deadline has passed, without recording history."""
        with self._lock:
            if self._phase() == Phase.DONE:
                raise DraftError(ERR_CLOSED)
            if self._deadline is None or now < self._deadline:
                raise DraftError(ERR_TURN_NOT_EXPIRED)

            self._advance(now)
            return self._build_state()

    def deadline(self) -> datetime | None:
        """Deadline of the current turn; ``None`` once the draft is done."""
        with self._lock:
            return self._deadline

    def available(self, role: str | None = None) -> list[str]:
        """Sorted champion ids not banned or picked, optionally by role."""
        with self._lock:
            return sorted(
                champion.champion_id
                for champion in self._champions
                if champion.champion_id not in self._taken
                and (role is None or role == "" or champion.role == role)
            )

    def champions(self) -> list[Champion]:
        """Return a copy of the champion pool."""
        with self._lock:
            return list(self._champions)

    def history(self) -> list[Action]:
        """Return a copy of the accepted actions in submission order."""
        with self._lock:
            return list(self._history)

    def remaining_bans(self, team: Team) -> int:
        """How many bans the team still owns."""
        with self._lock:
            used = sum(
                1
                for action in self._history
                if action.kind == KIND_BAN and action.team == team
            )
            return self._config.bans_per_team - used

    def picks(self, team: Team) -> list[str]:
        """Champion ids picked by the team, in submission order."""
        with self._lock:
            return [
                action.champion_id
                for action in self._history
                if action.kind == KIND_PICK and action.team == team
            ]

    def snapshot(self) -> bytes:
        """Serialise turn index, history, accepted action ids and the deadline."""
        with self._lock:
            payload = {
                "version": 1,
                "turn": self._turn,
                "deadline": (
                    self._deadline.isoformat()
                    if self._deadline is not None
                    else None
                ),
                "action_ids": sorted(self._action_ids),
                "history": [
                    {
                        "action_id": action.action_id,
                        "team": action.team.value,
                        "kind": action.kind,
                        "champion_id": action.champion_id,
                        "at": action.at.isoformat(),
                    }
                    for action in self._history
                ],
            }
            return json.dumps(
                payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True
            ).encode("utf-8")

    def _total_turns(self) -> int:
        return 2 * (self._config.bans_per_team + self._config.picks_per_team)

    def _phase(self) -> Phase:
        ban_turns = 2 * self._config.bans_per_team
        pick_turns = 2 * self._config.picks_per_team
        if self._turn < ban_turns:
            return Phase.BAN
        if self._turn < ban_turns + pick_turns:
            return Phase.PICK
        return Phase.DONE

    def _team(self) -> Team | None:
        phase = self._phase()
        if phase == Phase.DONE:
            return None
        if phase == Phase.BAN:
            return Team.BLUE if self._turn % 2 == 0 else Team.RED

        pick_index = self._turn - 2 * self._config.bans_per_team
        group, offset = divmod(pick_index, 2)
        if group % 2 == 0:
            return Team.BLUE if offset == 0 else Team.RED
        return Team.RED if offset == 0 else Team.BLUE

    def _advance(self, now: datetime) -> None:
        self._turn += 1
        if self._phase() == Phase.DONE:
            self._deadline = None
        else:
            self._deadline = now + timedelta(seconds=self._config.turn_seconds)

    def _build_state(self) -> DraftState:
        return DraftState(
            phase=self._phase(),
            turn=self._turn,
            team=self._team(),
            bans=tuple(
                action.champion_id
                for action in self._history
                if action.kind == KIND_BAN
            ),
            blue_picks=tuple(
                action.champion_id
                for action in self._history
                if action.kind == KIND_PICK and action.team == Team.BLUE
            ),
            red_picks=tuple(
                action.champion_id
                for action in self._history
                if action.kind == KIND_PICK and action.team == Team.RED
            ),
        )
