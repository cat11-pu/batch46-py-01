"""Party invite guard: invite dedupe, cooldown, capacity and expiry."""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta

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


@dataclass
class _PartyState:
    party_id: str
    realm: str
    members: list[str]
    joined_at: dict[str, int]


class PartyInviteGuard:
    """Owns parties, pending invitations and inviter cooldowns."""

    def __init__(self, config: PartyConfig) -> None:
        self._config = config
        self._lock = threading.RLock()
        self._parties: dict[str, _PartyState] = {}
        self._player_party: dict[str, str] = {}
        self._invites: dict[str, Invite] = {}
        self._cooldowns: dict[tuple[str, str], datetime] = {}
        self._invite_seq = 0
        self._join_seq = 0

    @classmethod
    def from_snapshot(cls, config: PartyConfig, data: bytes) -> "PartyInviteGuard":
        """Restore parties, pending invites, cooldowns and the id counter."""
        payload = json.loads(data.decode("utf-8"))
        guard = cls(config)

        guard._invite_seq = int(payload.get("invite_seq", 0))
        guard._join_seq = int(payload.get("join_seq", 0))

        for row in payload.get("parties", []):
            party_id = row["party_id"]
            realm = row["realm"]
            members = list(row["members"])
            joined_at = {name: int(value) for name, value in row.get("joined_at", {}).items()}
            for member in members:
                if member not in joined_at:
                    joined_at[member] = guard._join_seq
                    guard._join_seq += 1
            guard._parties[party_id] = _PartyState(party_id, realm, members, joined_at)
            for member in members:
                guard._player_party[member] = party_id
            if joined_at:
                guard._join_seq = max(guard._join_seq, max(joined_at.values()) + 1)

        for row in payload.get("invites", []):
            invite = Invite(
                invite_id=row["invite_id"],
                party_id=row["party_id"],
                inviter=row["inviter"],
                invitee=row["invitee"],
                realm=row["realm"],
                created_at=datetime.fromisoformat(row["created_at"]),
                expires_at=datetime.fromisoformat(row["expires_at"]),
            )
            guard._invites[invite.invite_id] = invite

        for inviter, invitee, expires_at in payload.get("cooldowns", []):
            guard._cooldowns[(inviter, invitee)] = datetime.fromisoformat(expires_at)

        while f"inv-{guard._invite_seq + 1}" in guard._invites:
            guard._invite_seq += 1
        return guard

    def create_party(
        self,
        party_id: str,
        leader: str,
        realm: str,
        now: datetime,
    ) -> None:
        """Create a party with ``leader`` as its only member."""
        with self._lock:
            if party_id in self._parties:
                raise PartyError(ERR_DUPLICATE_PARTY)
            if leader in self._player_party:
                raise PartyError(ERR_PLAYER_BUSY)

            self._parties[party_id] = _PartyState(
                party_id=party_id,
                realm=realm,
                members=[leader],
                joined_at={leader: self._join_seq},
            )
            self._join_seq += 1
            self._player_party[leader] = party_id

    def invite(
        self,
        party_id: str,
        inviter: str,
        invitee: str,
        realm: str,
        now: datetime,
    ) -> Invite:
        """Issue an invitation from the party leader to ``invitee``."""
        with self._lock:
            party = self._parties.get(party_id)
            if party is None:
                raise PartyError(ERR_UNKNOWN_PARTY)
            if inviter != party.members[0]:
                raise PartyError(ERR_NOT_LEADER)
            if invitee == inviter:
                raise PartyError(ERR_SELF_INVITE)
            if realm != party.realm:
                raise PartyError(ERR_CROSS_REALM)

            self._remove_expired_for(invitee, now)

            if len(party.members) >= self._config.max_size:
                raise PartyError(ERR_PARTY_FULL)
            if invitee in self._player_party:
                raise PartyError(ERR_PLAYER_BUSY)

            cooldown_key = (inviter, invitee)
            cooldown_until = self._cooldowns.get(cooldown_key)
            if cooldown_until is not None:
                if now < cooldown_until:
                    raise PartyError(ERR_COOLDOWN)
                del self._cooldowns[cooldown_key]

            if any(
                row.party_id == party_id and row.invitee == invitee
                for row in self._invites.values()
            ):
                raise PartyError(ERR_INVITE_PENDING)

            inbox = [row for row in self._invites.values() if row.invitee == invitee]
            if len(inbox) >= self._config.max_pending_per_invitee:
                raise PartyError(ERR_INBOX_FULL)

            self._invite_seq += 1
            invite_id = f"inv-{self._invite_seq}"
            while invite_id in self._invites:
                self._invite_seq += 1
                invite_id = f"inv-{self._invite_seq}"

            invite = Invite(
                invite_id=invite_id,
                party_id=party_id,
                inviter=inviter,
                invitee=invitee,
                realm=realm,
                created_at=now,
                expires_at=now + timedelta(seconds=self._config.invite_ttl_seconds),
            )
            self._invites[invite_id] = invite
            return invite

    def accept(self, invite_id: str, now: datetime) -> Party:
        """Consume an invitation and join the invitee to the party."""
        with self._lock:
            invite = self._invites.get(invite_id)
            if invite is None:
                raise PartyError(ERR_INVITE_NOT_FOUND)

            if invite.expires_at <= now:
                del self._invites[invite_id]
                raise PartyError(ERR_INVITE_EXPIRED)

            party = self._parties.get(invite.party_id)
            if party is None:
                del self._invites[invite_id]
                raise PartyError(ERR_UNKNOWN_PARTY)

            if invite.invitee in self._player_party:
                raise PartyError(ERR_PLAYER_BUSY)
            if len(party.members) >= self._config.max_size:
                raise PartyError(ERR_PARTY_FULL)

            del self._invites[invite_id]
            party.members.append(invite.invitee)
            party.joined_at[invite.invitee] = self._join_seq
            self._join_seq += 1
            self._player_party[invite.invitee] = party.party_id
            return self._party_view(party)

    def decline(self, invite_id: str, now: datetime) -> None:
        """Reject an invitation and start the inviter cooldown."""
        with self._lock:
            invite = self._invites.pop(invite_id, None)
            if invite is None:
                raise PartyError(ERR_INVITE_NOT_FOUND)
            self._cooldowns[(invite.inviter, invite.invitee)] = (
                now + timedelta(seconds=self._config.cooldown_seconds)
            )

    def cancel(self, party_id: str, invitee: str) -> None:
        """Withdraw the pending invitation the party holds for ``invitee``."""
        with self._lock:
            if party_id not in self._parties:
                raise PartyError(ERR_UNKNOWN_PARTY)
            matches = [
                invite_id
                for invite_id, row in self._invites.items()
                if row.party_id == party_id and row.invitee == invitee
            ]
            if not matches:
                raise PartyError(ERR_INVITE_NOT_FOUND)
            for invite_id in matches:
                del self._invites[invite_id]

    def pending_for(self, invitee: str) -> list[Invite]:
        """Stored invitations of one player, oldest first."""
        with self._lock:
            rows = [row for row in self._invites.values() if row.invitee == invitee]
            rows.sort(key=lambda row: row.created_at)
            return [
                Invite(
                    invite_id=row.invite_id,
                    party_id=row.party_id,
                    inviter=row.inviter,
                    invitee=row.invitee,
                    realm=row.realm,
                    created_at=row.created_at,
                    expires_at=row.expires_at,
                )
                for row in rows
            ]

    def party_of(self, player: str) -> Party | None:
        """Party of a player, or ``None`` when the player is unattached."""
        with self._lock:
            party_id = self._player_party.get(player)
            if party_id is None:
                return None
            return self._party_view(self._parties[party_id])

    def leader(self, party_id: str) -> str:
        """Current leader of a party."""
        with self._lock:
            party = self._parties.get(party_id)
            if party is None:
                raise PartyError(ERR_UNKNOWN_PARTY)
            return party.members[0]

    def promote(self, party_id: str, new_leader: str) -> None:
        """Move leadership to an existing member of the party."""
        with self._lock:
            party = self._parties.get(party_id)
            if party is None:
                raise PartyError(ERR_UNKNOWN_PARTY)
            if new_leader not in party.joined_at:
                raise PartyError(ERR_NOT_IN_PARTY)
            if party.members[0] == new_leader:
                return
            party.members = [new_leader] + [
                member for member in party.members if member != new_leader
            ]

    def leave(self, player: str, now: datetime) -> None:
        """Remove a player; a departing leader hands over or dissolves."""
        with self._lock:
            party_id = self._player_party.get(player)
            if party_id is None:
                raise PartyError(ERR_NOT_IN_PARTY)

            party = self._parties[party_id]
            remaining = [member for member in party.members if member != player]
            if not remaining:
                del self._parties[party_id]
                del self._player_party[player]
                for invite_id, row in list(self._invites.items()):
                    if row.party_id == party_id:
                        del self._invites[invite_id]
                return

            del self._player_party[player]
            del party.joined_at[player]
            if party.members[0] == player:
                next_leader = min(remaining, key=lambda member: party.joined_at[member])
                remaining = [next_leader] + [
                    member for member in remaining if member != next_leader
                ]
            party.members = remaining

    def expire(self, now: datetime) -> int:
        """Drop every invitation whose ``expires_at`` is not after ``now``."""
        with self._lock:
            expired = [
                invite_id
                for invite_id, row in self._invites.items()
                if row.expires_at <= now
            ]
            for invite_id in expired:
                del self._invites[invite_id]
            return len(expired)

    def snapshot(self) -> bytes:
        """Serialise parties, pending invitations and cooldowns."""
        with self._lock:
            payload = {
                "version": 1,
                "invite_seq": self._invite_seq,
                "join_seq": self._join_seq,
                "parties": [
                    {
                        "party_id": party.party_id,
                        "realm": party.realm,
                        "members": list(party.members),
                        "joined_at": dict(party.joined_at),
                    }
                    for party in self._parties.values()
                ],
                "invites": [
                    {
                        "invite_id": row.invite_id,
                        "party_id": row.party_id,
                        "inviter": row.inviter,
                        "invitee": row.invitee,
                        "realm": row.realm,
                        "created_at": row.created_at.isoformat(),
                        "expires_at": row.expires_at.isoformat(),
                    }
                    for row in self._invites.values()
                ],
                "cooldowns": [
                    [inviter, invitee, expires_at.isoformat()]
                    for (inviter, invitee), expires_at in self._cooldowns.items()
                ],
            }
            return json.dumps(
                payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True
            ).encode("utf-8")

    def _party_view(self, party: _PartyState) -> Party:
        members = tuple(party.members)
        return Party(
            party_id=party.party_id,
            leader=members[0],
            realm=party.realm,
            members=members,
        )

    def _remove_expired_for(self, invitee: str, now: datetime) -> None:
        expired = [
            invite_id
            for invite_id, row in self._invites.items()
            if row.invitee == invitee and row.expires_at <= now
        ]
        for invite_id in expired:
            del self._invites[invite_id]
