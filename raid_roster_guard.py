"""Raid roster guard: size and role quotas, bench rules, locks and lockouts."""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from datetime import datetime
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

    @classmethod
    def from_snapshot(cls, config: RaidConfig, data: bytes) -> "RaidRoster":
        """Restore active members, bench, lock time and boss lockouts."""
        raise NotImplementedError

    def add(self, raider: Raider, now: datetime) -> None:
        """Place a raider on the active roster."""
        raise NotImplementedError

    def bench(self, name: str, now: datetime) -> None:
        """Move an active raider to the bench."""
        raise NotImplementedError

    def swap(self, benched_name: str, active_name: str, now: datetime) -> None:
        """Exchange a benched raider with an active one, atomically."""
        raise NotImplementedError

    def lock(self, now: datetime) -> None:
        """Freeze the roster and open the swap window."""
        raise NotImplementedError

    def unlock(self) -> None:
        """Reopen the roster for adds and bench moves."""
        raise NotImplementedError

    def locked(self) -> bool:
        """Whether the roster is currently locked."""
        raise NotImplementedError

    def pull(self, boss_id: str, now: datetime) -> PullRecord:
        """Record a boss pull and return its attendance snapshot."""
        raise NotImplementedError

    def unlock_boss(self, boss_id: str) -> None:
        """Clear the lockout of a boss so it may be pulled again."""
        raise NotImplementedError

    def roster(self) -> list[Slot]:
        """Active rows by role then name, benched rows last by name."""
        raise NotImplementedError

    def bench_list(self) -> list[str]:
        """Sorted names currently on the bench."""
        raise NotImplementedError

    def attendance(self, boss_id: str) -> list[str]:
        """Sorted members recorded by the most recent pull of a boss."""
        raise NotImplementedError

    def count(self, role: Role) -> int:
        """Number of active raiders with the given role."""
        raise NotImplementedError

    def snapshot(self) -> bytes:
        """Serialise active members, bench, lock time and boss lockouts."""
        raise NotImplementedError
