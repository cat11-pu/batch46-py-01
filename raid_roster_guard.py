"""Raid roster guard: size and role quotas, bench rules, locks and lockouts."""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum

ROLE_ORDER = ("tank", "healer", "dps")

ERR_ROSTER_LOCKED = "RAID_LOCKED"
ERR_ALREADY_LOCKED = "RAID_ALREADY_LOCKED"
ERR_RAID_FULL = "RAID_FULL"
ERR_ROLE_QUOTA = "RAID_ROLE_QUOTA"
ERR_DUPLICATE_MEMBER = "RAID_DUP_MEMBER"
ERR_NOT_IN_RAID = "RAID_NOT_IN_RAID"
ERR_BENCH_FULL = "RAID_BENCH_FULL"
ERR_SWAP_CLOSED = "RAID_SWAP_CLOSED"
ERR_ROSTER_UNLOCKED = "RAID_ROSTER_UNLOCKED"
ERR_LOCKOUT_ACTIVE = "RAID_LOCKOUT"
ERR_UNKNOWN_BOSS = "RAID_UNKNOWN_BOSS"
ERR_EMPTY_ROSTER = "RAID_EMPTY_ROSTER"


class RaidError(Exception):
    """Domain error with a stable ``code``."""

    def __init__(self, code: str, detail: str | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class Role(str, Enum):
    TANK = "tank"
    HEALER = "healer"
    DPS = "dps"


@dataclass(frozen=True)
class RaidConfig:
    """Roster policy; ``swap_window_seconds`` starts at lock time."""

    size: int = 0
    max_tanks: int = 0
    max_healers: int = 0
    max_dps: int = 0
    bench_size: int = 0
    swap_window_seconds: int = 0


@dataclass(frozen=True)
class Raider:
    name: str
    role: Role
    gear_score: int = 0


@dataclass(frozen=True)
class Slot:
    """One roster row; ``bench`` marks a benched raider."""

    name: str
    role: Role
    gear_score: int
    bench: bool


@dataclass(frozen=True)
class PullRecord:
    """Attendance of one boss pull; ``members`` is sorted at pull time."""

    boss_id: str
    at: datetime
    members: tuple[str, ...]


class RaidRoster:
    """Owns the active roster, the bench, the lock window and boss lockouts."""

    def __init__(self, config: RaidConfig, raid_id: str) -> None:
        self._config = config
        self._raid_id = raid_id
        self._mutex = threading.RLock()
        self._active: dict[str, Raider] = {}
        self._bench: dict[str, Raider] = {}
        self._locked = False
        self._locked_at: datetime | None = None
        self._pulls: dict[str, PullRecord] = {}

    @classmethod
    def from_snapshot(cls, config: RaidConfig, data: bytes) -> "RaidRoster":
        """Restore active members, bench, lock time and boss lockouts."""
        payload = json.loads(data.decode("utf-8"))
        roster = cls(config, payload["raid_id"])
        for entry in payload["active"]:
            raider = Raider(entry["name"], Role(entry["role"]), entry["gear_score"])
            roster._active[raider.name] = raider
        for entry in payload["bench"]:
            raider = Raider(entry["name"], Role(entry["role"]), entry["gear_score"])
            roster._bench[raider.name] = raider
        roster._locked = payload["locked"]
        locked_at = payload["locked_at"]
        roster._locked_at = datetime.fromisoformat(locked_at) if locked_at else None
        for boss_id, record in payload["pulls"].items():
            roster._pulls[boss_id] = PullRecord(
                boss_id=boss_id,
                at=datetime.fromisoformat(record["at"]),
                members=tuple(record["members"]),
            )
        return roster

    def _role_limit(self, role: Role) -> int:
        if role is Role.TANK:
            return self._config.max_tanks
        if role is Role.HEALER:
            return self._config.max_healers
        return self._config.max_dps

    def add(self, raider: Raider, now: datetime) -> None:
        """Place a raider on the active roster."""
        with self._mutex:
            if self._locked:
                raise RaidError(ERR_ROSTER_LOCKED, raider.name)
            if raider.name in self._active or raider.name in self._bench:
                raise RaidError(ERR_DUPLICATE_MEMBER, raider.name)
            if len(self._active) >= self._config.size:
                raise RaidError(ERR_RAID_FULL, raider.name)
            active_of_role = sum(1 for r in self._active.values() if r.role is raider.role)
            if active_of_role >= self._role_limit(raider.role):
                raise RaidError(ERR_ROLE_QUOTA, raider.name)
            self._active[raider.name] = raider

    def bench(self, name: str, now: datetime) -> None:
        """Move an active raider to the bench."""
        with self._mutex:
            if self._locked:
                raise RaidError(ERR_ROSTER_LOCKED, name)
            if name not in self._active:
                raise RaidError(ERR_NOT_IN_RAID, name)
            if len(self._bench) >= self._config.bench_size:
                raise RaidError(ERR_BENCH_FULL, name)
            self._bench[name] = self._active.pop(name)

    def swap(self, benched_name: str, active_name: str, now: datetime) -> None:
        """Exchange a benched raider with an active one, atomically."""
        with self._mutex:
            window_open = (
                self._locked
                and self._locked_at is not None
                and now <= self._locked_at + timedelta(seconds=self._config.swap_window_seconds)
            )
            if not window_open:
                raise RaidError(ERR_SWAP_CLOSED, benched_name)
            if benched_name not in self._bench or active_name not in self._active:
                raise RaidError(ERR_NOT_IN_RAID, f"{benched_name}/{active_name}")
            incoming = self._bench.pop(benched_name)
            outgoing = self._active.pop(active_name)
            self._active[incoming.name] = incoming
            self._bench[outgoing.name] = outgoing

    def lock(self, now: datetime) -> None:
        """Freeze the roster and open the swap window."""
        with self._mutex:
            if self._locked:
                raise RaidError(ERR_ALREADY_LOCKED, self._raid_id)
            self._locked = True
            self._locked_at = now

    def unlock(self) -> None:
        """Reopen the roster for adds and bench moves."""
        with self._mutex:
            if not self._locked:
                raise RaidError(ERR_ROSTER_UNLOCKED, self._raid_id)
            self._locked = False
            self._locked_at = None

    def locked(self) -> bool:
        """Whether the roster is currently locked."""
        with self._mutex:
            return self._locked

    def pull(self, boss_id: str, now: datetime) -> PullRecord:
        """Record a boss pull and return its attendance snapshot."""
        with self._mutex:
            if not self._locked:
                raise RaidError(ERR_ROSTER_UNLOCKED, boss_id)
            if not self._active:
                raise RaidError(ERR_EMPTY_ROSTER, boss_id)
            if boss_id in self._pulls:
                raise RaidError(ERR_LOCKOUT_ACTIVE, boss_id)
            record = PullRecord(
                boss_id=boss_id,
                at=now,
                members=tuple(sorted(self._active)),
            )
            self._pulls[boss_id] = record
            return record

    def unlock_boss(self, boss_id: str) -> None:
        """Clear the lockout of a boss so it may be pulled again."""
        with self._mutex:
            if boss_id not in self._pulls:
                raise RaidError(ERR_UNKNOWN_BOSS, boss_id)
            del self._pulls[boss_id]

    def roster(self) -> list[Slot]:
        """Active rows by role then name, benched rows last by name."""
        with self._mutex:
            active = sorted(
                self._active.values(),
                key=lambda r: (ROLE_ORDER.index(r.role.value), r.name),
            )
            benched = sorted(self._bench.values(), key=lambda r: r.name)
            return [
                Slot(r.name, r.role, r.gear_score, False) for r in active
            ] + [
                Slot(r.name, r.role, r.gear_score, True) for r in benched
            ]

    def bench_list(self) -> list[str]:
        """Sorted names currently on the bench."""
        with self._mutex:
            return sorted(self._bench)

    def attendance(self, boss_id: str) -> list[str]:
        """Sorted members recorded by the most recent pull of a boss."""
        with self._mutex:
            record = self._pulls.get(boss_id)
            if record is None:
                raise RaidError(ERR_UNKNOWN_BOSS, boss_id)
            return list(record.members)

    def count(self, role: Role) -> int:
        """Number of active raiders with the given role."""
        with self._mutex:
            return sum(1 for r in self._active.values() if r.role is role)

    def snapshot(self) -> bytes:
        """Serialise active members, bench, lock time and boss lockouts."""
        with self._mutex:
            payload = {
                "raid_id": self._raid_id,
                "active": [
                    {"name": r.name, "role": r.role.value, "gear_score": r.gear_score}
                    for r in self._active.values()
                ],
                "bench": [
                    {"name": r.name, "role": r.role.value, "gear_score": r.gear_score}
                    for r in self._bench.values()
                ],
                "locked": self._locked,
                "locked_at": self._locked_at.isoformat() if self._locked_at else None,
                "pulls": {
                    boss_id: {
                        "at": record.at.isoformat(),
                        "members": list(record.members),
                    }
                    for boss_id, record in self._pulls.items()
                },
            }
            return json.dumps(payload, sort_keys=True).encode("utf-8")
