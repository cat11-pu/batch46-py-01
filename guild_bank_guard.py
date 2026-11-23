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


class _Tab:
    """Mutable internal tab state; never exposed directly to callers."""

    __slots__ = ("min_rank", "locked", "items")

    def __init__(self, min_rank: Rank) -> None:
        self.min_rank = min_rank
        self.locked = False
        self.items: list[Item] = []


def _hash_entry(
    prev_hash: str,
    op_id: str,
    member: str,
    tab_index: int,
    item_id: str,
    count: int,
) -> str:
    raw = "|".join(
        [prev_hash, op_id, member, str(tab_index), item_id, str(count)]
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _utc_day(at: datetime) -> date:
    if at.tzinfo is None:
        return at.date()
    return at.astimezone(timezone.utc).date()


class GuildBankGuard:
    """Enforces rank, quota and audit rules for one guild bank."""

    def __init__(self, config: BankConfig) -> None:
        self._config = config
        self._members: dict[str, Rank] = {}
        self._tabs: dict[int, _Tab] = {}
        self._ledger: list[AuditEntry] = []
        self._daily: dict[tuple[str, date], int] = {}
        self._used_ops: set[str] = set()
        self._lock = threading.RLock()

    @classmethod
    def from_snapshot(cls, config: BankConfig, data: bytes) -> "GuildBankGuard":
        """Restore members, tabs, stock, ledger, quota counters and used op ids."""
        try:
            payload = json.loads(data.decode("utf-8"))
            guard = cls(config)

            guard._members = {
                name: Rank(int(rank))
                for name, rank in payload["members"].items()
            }
            guard._tabs = {}
            for tab_data in payload["tabs"]:
                index = int(tab_data["index"])
                tab = _Tab(Rank(int(tab_data["min_rank"])))
                tab.locked = bool(tab_data["locked"])
                tab.items = [
                    Item(str(item["item_id"]), int(item["count"]))
                    for item in tab_data["items"]
                ]
                guard._tabs[index] = tab

            guard._ledger = [
                AuditEntry(
                    seq=int(row["seq"]),
                    op_id=str(row["op_id"]),
                    kind=str(row["kind"]),
                    member=str(row["member"]),
                    tab_index=int(row["tab_index"]),
                    item_id=str(row["item_id"]),
                    count=int(row["count"]),
                    at=datetime.fromisoformat(row["at"]),
                    prev_hash=str(row["prev_hash"]),
                    entry_hash=str(row["entry_hash"]),
                )
                for row in payload["ledger"]
            ]
            guard._daily = {
                (str(row["member"]), date.fromisoformat(row["day"])): int(
                    row["total"]
                )
                for row in payload["daily"]
            }
            guard._used_ops = {str(op_id) for op_id in payload["used_ops"]}
            guard.verify_chain()
            return guard
        except GuildBankError:
            raise
        except Exception as exc:
            raise GuildBankError(ERR_CHAIN_BROKEN, str(exc)) from exc

    def add_member(self, member: Member) -> None:
        """Register a member; the same name may not be added twice."""
        with self._lock:
            if member.name in self._members:
                raise GuildBankError(ERR_MEMBER_EXISTS)
            self._members[member.name] = member.rank

    def set_rank(self, name: str, rank: Rank) -> None:
        """Change the rank of an existing member."""
        with self._lock:
            if name not in self._members:
                raise GuildBankError(ERR_UNKNOWN_MEMBER)
            self._members[name] = rank

    def create_tab(self, index: int, min_rank: Rank = Rank.MEMBER) -> None:
        """Create an empty tab guarded by ``min_rank``; indexes are unique."""
        with self._lock:
            if index in self._tabs:
                raise GuildBankError(ERR_TAB_EXISTS)
            self._tabs[index] = _Tab(min_rank)

    def lock_tab(self, index: int) -> None:
        """Freeze a tab: later deposits and withdrawals are refused."""
        with self._lock:
            tab = self._tabs.get(index)
            if tab is None:
                raise GuildBankError(ERR_UNKNOWN_TAB)
            tab.locked = True

    def deposit(
        self,
        op_id: str,
        member: str,
        tab_index: int,
        item: Item,
        at: datetime,
    ) -> AuditEntry:
        """Store item units and append one audit row, atomically."""
        with self._lock:
            if op_id in self._used_ops:
                raise GuildBankError(ERR_DUPLICATE_OP)
            rank = self._members.get(member)
            if rank is None:
                raise GuildBankError(ERR_UNKNOWN_MEMBER)
            tab = self._tabs.get(tab_index)
            if tab is None:
                raise GuildBankError(ERR_UNKNOWN_TAB)
            if tab.locked:
                raise GuildBankError(ERR_TAB_LOCKED)
            if rank < tab.min_rank:
                raise GuildBankError(ERR_RANK_DENIED)
            if item.count <= 0:
                raise GuildBankError(ERR_INVALID_COUNT)
            if len(self._ledger) >= self._config.ledger_capacity:
                raise GuildBankError(ERR_LEDGER_FULL)

            new_items = list(tab.items)
            for position, stack in enumerate(new_items):
                if stack.item_id == item.item_id:
                    new_items[position] = Item(
                        stack.item_id, stack.count + item.count
                    )
                    break
            else:
                new_items.append(item)

            entry = self._new_entry(
                op_id=op_id,
                kind=KIND_DEPOSIT,
                member=member,
                tab_index=tab_index,
                item_id=item.item_id,
                count=item.count,
                at=at,
            )

            tab.items = new_items
            self._ledger.append(entry)
            self._used_ops.add(op_id)
            return entry

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
        with self._lock:
            if op_id in self._used_ops:
                raise GuildBankError(ERR_DUPLICATE_OP)
            rank = self._members.get(member)
            if rank is None:
                raise GuildBankError(ERR_UNKNOWN_MEMBER)
            tab = self._tabs.get(tab_index)
            if tab is None:
                raise GuildBankError(ERR_UNKNOWN_TAB)
            if tab.locked:
                raise GuildBankError(ERR_TAB_LOCKED)
            if rank < tab.min_rank:
                raise GuildBankError(ERR_RANK_DENIED)
            if count <= 0:
                raise GuildBankError(ERR_INVALID_COUNT)
            if len(self._ledger) >= self._config.ledger_capacity:
                raise GuildBankError(ERR_LEDGER_FULL)

            position = next(
                (
                    index
                    for index, stack in enumerate(tab.items)
                    if stack.item_id == item_id
                ),
                None,
            )
            if position is None or tab.items[position].count < count:
                raise GuildBankError(ERR_INSUFFICIENT)

            day = _utc_day(at)
            quota_key = (member, day)
            used_today = self._daily.get(quota_key, 0)
            if used_today + count > self._config.daily_quota:
                raise GuildBankError(ERR_QUOTA_EXCEEDED)

            new_items = list(tab.items)
            stack = new_items[position]
            remaining = stack.count - count
            if remaining == 0:
                del new_items[position]
            else:
                new_items[position] = Item(stack.item_id, remaining)

            entry = self._new_entry(
                op_id=op_id,
                kind=KIND_WITHDRAW,
                member=member,
                tab_index=tab_index,
                item_id=item_id,
                count=count,
                at=at,
            )

            tab.items = new_items
            self._daily[quota_key] = used_today + count
            self._ledger.append(entry)
            self._used_ops.add(op_id)
            return entry

    def tab_contents(self, index: int) -> list[Item]:
        """Return a copy of the stacks of one tab in stack order."""
        with self._lock:
            tab = self._tabs.get(index)
            if tab is None:
                raise GuildBankError(ERR_UNKNOWN_TAB)
            return list(tab.items)

    def ledger(self) -> list[AuditEntry]:
        """Return a copy of the audit rows in sequence order."""
        with self._lock:
            return list(self._ledger)

    def verify_chain(self) -> bool:
        """Recompute every hash; raise ``BANK_CHAIN_BROKEN`` on a mismatch."""
        with self._lock:
            previous = GENESIS_HASH
            for expected_seq, entry in enumerate(self._ledger, start=1):
                if entry.seq != expected_seq or entry.prev_hash != previous:
                    raise GuildBankError(ERR_CHAIN_BROKEN)
                expected_hash = _hash_entry(
                    previous,
                    entry.op_id,
                    entry.member,
                    entry.tab_index,
                    entry.item_id,
                    entry.count,
                )
                if entry.entry_hash != expected_hash:
                    raise GuildBankError(ERR_CHAIN_BROKEN)
                previous = entry.entry_hash
            return True

    def snapshot(self) -> bytes:
        """Serialise members, tabs, stock, ledger, quota and used op ids."""
        with self._lock:
            payload = {
                "version": 1,
                "members": {
                    name: int(rank) for name, rank in self._members.items()
                },
                "tabs": [
                    {
                        "index": index,
                        "min_rank": int(tab.min_rank),
                        "locked": tab.locked,
                        "items": [
                            {"item_id": stack.item_id, "count": stack.count}
                            for stack in tab.items
                        ],
                    }
                    for index, tab in sorted(self._tabs.items())
                ],
                "ledger": [
                    {
                        "seq": entry.seq,
                        "op_id": entry.op_id,
                        "kind": entry.kind,
                        "member": entry.member,
                        "tab_index": entry.tab_index,
                        "item_id": entry.item_id,
                        "count": entry.count,
                        "at": entry.at.isoformat(),
                        "prev_hash": entry.prev_hash,
                        "entry_hash": entry.entry_hash,
                    }
                    for entry in self._ledger
                ],
                "daily": [
                    {
                        "member": member,
                        "day": day.isoformat(),
                        "total": total,
                    }
                    for (member, day), total in sorted(
                        self._daily.items(),
                        key=lambda item: (item[0][0], item[0][1]),
                    )
                ],
                "used_ops": sorted(self._used_ops),
            }
            return json.dumps(
                payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")

    def daily_total(self, member: str, day: date) -> int:
        """Item units the member withdrew on the given UTC calendar day."""
        with self._lock:
            return self._daily.get((member, day), 0)

    def _new_entry(
        self,
        *,
        op_id: str,
        kind: str,
        member: str,
        tab_index: int,
        item_id: str,
        count: int,
        at: datetime,
    ) -> AuditEntry:
        seq = len(self._ledger) + 1
        prev_hash = self._ledger[-1].entry_hash if self._ledger else GENESIS_HASH
        entry_hash = _hash_entry(
            prev_hash, op_id, member, tab_index, item_id, count
        )
        return AuditEntry(
            seq=seq,
            op_id=op_id,
            kind=kind,
            member=member,
            tab_index=tab_index,
            item_id=item_id,
            count=count,
            at=at,
            prev_hash=prev_hash,
            entry_hash=entry_hash,
        )
