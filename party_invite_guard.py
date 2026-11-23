"""Party invite guard: invite dedupe, cooldown, capacity and expiry."""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from datetime import datetime

ERR_UNKNOWN_PARTY = "PARTY_UNKNOWN"
ERR_DUPLICATE_PARTY = "PARTY_DUP_ID"
ERR_NOT_LEADER = "PARTY_NOT_LEADER"
ERR_SELF_INVITE = "PARTY_SELF_INVITE"
ERR_PARTY_FULL = "PARTY_FULL"
ERR_INVITE_PENDING = "PARTY_INVITE_PENDING"
ERR_COOLDOWN = "PARTY_COOLDOWN"
ERR_PLAYER_BUSY = "PARTY_PLAYER_BUSY"
ERR_INBOX_FULL = "PARTY_INBOX_FULL"
ERR_CROSS_REALM = "PARTY_CROSS_REALM"
ERR_INVITE_EXPIRED = "PARTY_INVITE_EXPIRED"
ERR_INVITE_NOT_FOUND = "PARTY_INVITE_NOT_FOUND"
ERR_NOT_IN_PARTY = "PARTY_NOT_IN_PARTY"


class PartyError(Exception):
    """Domain error with a stable ``code``."""

    def __init__(self, code: str, detail: str | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class PartyConfig:
    """Invite policy; durations are in seconds."""

    max_size: int = 0
    invite_ttl_seconds: int = 0
    cooldown_seconds: int = 0
    max_pending_per_invitee: int = 0


@dataclass(frozen=True)
class Invite:
    invite_id: str
    party_id: str
    inviter: str
    invitee: str
    realm: str
    created_at: datetime
    expires_at: datetime


@dataclass(frozen=True)
class Party:
    """``members`` keeps join order and ``members[0]`` is the leader."""

    party_id: str
    leader: str
    realm: str
    members: tuple[str, ...]


class PartyInviteGuard:
    """Owns parties, pending invitations and inviter cooldowns."""

    def __init__(self, config: PartyConfig) -> None:
        self._config = config

    @classmethod
    def from_snapshot(cls, config: PartyConfig, data: bytes) -> "PartyInviteGuard":
        """Restore parties, pending invites, cooldowns and the id counter."""
        raise NotImplementedError

    def create_party(
        self,
        party_id: str,
        leader: str,
        realm: str,
        now: datetime,
    ) -> None:
        """Create a party with ``leader`` as its only member."""
        raise NotImplementedError

    def invite(
        self,
        party_id: str,
        inviter: str,
        invitee: str,
        realm: str,
        now: datetime,
    ) -> Invite:
        """Issue an invitation from the party leader to ``invitee``."""
        raise NotImplementedError

    def accept(self, invite_id: str, now: datetime) -> Party:
        """Consume an invitation and join the invitee to the party."""
        raise NotImplementedError

    def decline(self, invite_id: str, now: datetime) -> None:
        """Reject an invitation and start the inviter cooldown."""
        raise NotImplementedError

    def cancel(self, party_id: str, invitee: str) -> None:
        """Withdraw the pending invitation the party holds for ``invitee``."""
        raise NotImplementedError

    def pending_for(self, invitee: str) -> list[Invite]:
        """Stored invitations of one player, oldest first."""
        raise NotImplementedError

    def party_of(self, player: str) -> Party | None:
        """Party of a player, or ``None`` when the player is unattached."""
        raise NotImplementedError

    def leader(self, party_id: str) -> str:
        """Current leader of a party."""
        raise NotImplementedError

    def promote(self, party_id: str, new_leader: str) -> None:
        """Move leadership to an existing member of the party."""
        raise NotImplementedError

    def leave(self, player: str, now: datetime) -> None:
        """Remove a player; a departing leader hands over or dissolves."""
        raise NotImplementedError

    def expire(self, now: datetime) -> int:
        """Drop every invitation whose ``expires_at`` is not after ``now``."""
        raise NotImplementedError

    def snapshot(self) -> bytes:
        """Serialise parties, pending invitations and cooldowns."""
        raise NotImplementedError
