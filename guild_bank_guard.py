"""Guild bank guard: rank gates, UTC daily quota and a tamper-evident ledger."""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass
from datetime import date, datetime, timezone
from enum import IntEnum

GENESIS_HASH = "0" * 64
KIND_DEPOSIT = "deposit"
KIND_WITHDRAW = "withdraw"

ERR_UNKNOWN_MEMBER = "BANK_UNKNOWN_MEMBER"
ERR_UNKNOWN_TAB = "BANK_UNKNOWN_TAB"
ERR_MEMBER_EXISTS = "BANK_MEMBER_EXISTS"
ERR_TAB_EXISTS = "BANK_TAB_EXISTS"
ERR_TAB_LOCKED = "BANK_TAB_LOCKED"
ERR_RANK_DENIED = "BANK_RANK_DENIED"
ERR_INVALID_COUNT = "BANK_INVALID_COUNT"
ERR_INSUFFICIENT = "BANK_INSUFFICIENT"
ERR_QUOTA_EXCEEDED = "BANK_QUOTA_EXCEEDED"
ERR_DUPLICATE_OP = "BANK_DUPLICATE_OP"
ERR_LEDGER_FULL = "BANK_LEDGER_FULL"
ERR_CHAIN_BROKEN = "BANK_CHAIN_BROKEN"


class GuildBankError(Exception):
    """Domain error carrying a stable ``code`` the callers switch on."""

    def __init__(self, code: str, detail: str | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class Rank(IntEnum):
    """Guild permission level; higher numbers may open more tabs."""

    MEMBER = 1
    OFFICER = 2
    GUILD_MASTER = 3


@dataclass(frozen=True)
class BankConfig:
    """Bank policy. ``daily_quota`` counts item units per member per UTC day."""

    daily_quota: int = 0
    ledger_capacity: int = 0


@dataclass(frozen=True)
class Member:
    name: str
    rank: Rank = Rank.MEMBER


@dataclass(frozen=True)
class Item:
    item_id: str
    count: int


@dataclass(frozen=True)
class AuditEntry:
    """One immutable ledger row; ``entry_hash`` chains over ``prev_hash``."""

    seq: int
    op_id: str
    kind: str
    member: str
    tab_index: int
    item_id: str
    count: int
    at: datetime
    prev_hash: str
    entry_hash: str


class GuildBankGuard:
    """Enforces rank, quota and audit rules for one guild bank."""

    def __init__(self, config: BankConfig) -> None:
        self._config = config

    @classmethod
    def from_snapshot(cls, config: BankConfig, data: bytes) -> "GuildBankGuard":
        """Restore members, tabs, stock, ledger, quota counters and used op ids."""
        raise NotImplementedError

    def add_member(self, member: Member) -> None:
        """Register a member; the same name may not be added twice."""
        raise NotImplementedError

    def set_rank(self, name: str, rank: Rank) -> None:
        """Change the rank of an existing member."""
        raise NotImplementedError

    def create_tab(self, index: int, min_rank: Rank = Rank.MEMBER) -> None:
        """Create an empty tab guarded by ``min_rank``; indexes are unique."""
        raise NotImplementedError

    def lock_tab(self, index: int) -> None:
        """Freeze a tab: later deposits and withdrawals are refused."""
        raise NotImplementedError

    def deposit(
        self,
        op_id: str,
        member: str,
        tab_index: int,
        item: Item,
        at: datetime,
    ) -> AuditEntry:
        """Store item units and append one audit row, atomically."""
        raise NotImplementedError

    def withdraw(
        self,
        op_id: str,
        member: str,
        tab_index: int,
        item_id: str,
        count: int,
        at: datetime,
    ) -> AuditEntry:
        """Remove item units after rank, stock, quota and capacity checks."""
        raise NotImplementedError

    def tab_contents(self, index: int) -> list[Item]:
        """Return a copy of the stacks of one tab in stack order."""
        raise NotImplementedError

    def ledger(self) -> list[AuditEntry]:
        """Return a copy of the audit rows in sequence order."""
        raise NotImplementedError

    def verify_chain(self) -> bool:
        """Recompute every hash; raise ``BANK_CHAIN_BROKEN`` on a mismatch."""
        raise NotImplementedError

    def snapshot(self) -> bytes:
        """Serialise members, tabs, stock, ledger, quota and used op ids."""
        raise NotImplementedError

    def daily_total(self, member: str, day: date) -> int:
        """Item units the member withdrew on the given UTC calendar day."""
        raise NotImplementedError
