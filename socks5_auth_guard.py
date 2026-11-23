"""SOCKS5 authentication, target-policy, and accounting guard.

The class in this module is a policy/accounting model rather than a socket
server.  All public operations take the guard lock, so state transitions and
quota accounting remain correct when callers drive sessions concurrently.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import ipaddress
import json
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Callable


FAILURE_LIMIT = 3
LOCK_SECONDS = 300
MAX_CREDENTIAL_LENGTH = 255
MAX_HOST_LENGTH = 255
MAX_CLOSED_HISTORY = 1024

_STATE_NEW = "new"
_STATE_GREETED = "greeted"
_STATE_AUTHENTICATED = "authenticated"
_STATE_CONNECTED = "connected"
_STATE_CLOSED = "closed"
_ONLINE_STATES = (_STATE_CONNECTED,)
_OPEN_STATES = (_STATE_NEW, _STATE_GREETED, _STATE_AUTHENTICATED, _STATE_CONNECTED)


class Socks5Error(Exception):
    """A policy failure carrying a stable SOCKS5 error code."""

    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        message = f"{code}: {detail}" if detail else code
        super().__init__(message)


@dataclass
class _User:
    username: str
    password_hash: bytes | None
    max_sessions: int | None
    quota_bytes: int | None
    allow_targets: tuple[str, ...]
    allow_private: bool
    failures: int = 0
    locked_until: int | None = None


@dataclass
class _Session:
    session_id: str
    seq: int
    state: str = _STATE_NEW
    username: str | None = None
    method: int | None = None
    cmd: int | None = None
    host: str | None = None
    port: int | None = None
    up: int = 0
    down: int = 0
    created_at: int = 0
    last_active: int = 0
    closed_reason: str | None = None

    @property
    def online(self) -> bool:
        return self.state in _ONLINE_STATES


class Socks5Guard:
    """Stateful SOCKS5 guard implementing the policy described by the task."""

    def __init__(
        self,
        *,
        max_sessions: int = 64,
        require_auth: bool = True,
        default_max_sessions: int = 4,
        clock: Callable[[], Any] | Any | None = None,
    ) -> None:
        if type(max_sessions) is not int:
            raise ValueError("max_sessions must be an integer")
        if type(default_max_sessions) is not int:
            raise ValueError("default_max_sessions must be an integer")
        if not isinstance(require_auth, bool):
            raise ValueError("require_auth must be a boolean")
        if max_sessions < 0 or default_max_sessions < 0:
            raise ValueError("session limits cannot be negative")

        self.max_sessions = max_sessions
        self.require_auth = require_auth
        self.default_max_sessions = default_max_sessions
        self._clock = clock
        self._lock = threading.RLock()

        self._users: dict[str, _User] = {}
        self._sessions: "OrderedDict[str, _Session]" = OrderedDict()
        self._closed_order: list[str] = []
        self._usage: dict[str, dict[str, int]] = {}
        self._online_by_user: dict[str, int] = {}
        self._online_total = 0
        self._open_total = 0
        self._sequence = 0

    # ------------------------------------------------------------------
    # Clock and small helpers
    # ------------------------------------------------------------------
    def _now(self) -> int:
        value = self._clock
        if value is None:
            return int(time.time())
        if callable(value):
            value = value()
        if hasattr(value, "timestamp"):
            value = value.timestamp()
        return int(value)

    @staticmethod
    def _error(code: str, detail: str) -> Socks5Error:
        return Socks5Error(code, detail)

    @staticmethod
    def _hash_password(password: str) -> bytes:
        return hashlib.sha256(password.encode("utf-8")).digest()

    def _effective_user_limit(self, user: _User) -> int:
        limit = user.max_sessions
        if limit is None:
            limit = self.default_max_sessions
        return max(0, limit)

    def _user_online(self, username: str | None) -> int:
        if username is None:
            return 0
        return self._online_by_user.get(username, 0)

    def _usage_for(self, username: str) -> dict[str, int]:
        usage = self._usage.get(username)
        if usage is None:
            usage = {"total": 0, "up": 0, "down": 0}
            self._usage[username] = usage
        return usage

    def _increment_online(self, session: _Session) -> None:
        self._online_total += 1
        if session.username is not None:
            self._online_by_user[session.username] = (
                self._online_by_user.get(session.username, 0) + 1
            )

    def _decrement_online(self, session: _Session) -> None:
        if not session.online:
            return
        if self._online_total > 0:
            self._online_total -= 1
        username = session.username
        if username is not None:
            count = self._online_by_user.get(username, 0)
            if count <= 1:
                self._online_by_user.pop(username, None)
            else:
                self._online_by_user[username] = count - 1

    def _close_locked(self, session: _Session, reason: str) -> bool:
        if session.state == _STATE_CLOSED:
            return False
        self._decrement_online(session)
        session.state = _STATE_CLOSED
        if session.closed_reason is None:
            session.closed_reason = reason
        if self._open_total > 0:
            self._open_total -= 1
        self._closed_order.append(session.session_id)
        if len(self._closed_order) > MAX_CLOSED_HISTORY:
            oldest = self._closed_order.pop(0)
            old_session = self._sessions.get(oldest)
            if old_session is not None and old_session.state == _STATE_CLOSED:
                self._sessions.pop(oldest, None)
        return True

    def _session_view(self, session: _Session) -> dict[str, Any]:
        target = None
        if session.host is not None:
            target = {"host": session.host, "port": session.port}
        view: dict[str, Any] = {
            "session_id": session.session_id,
            "username": session.username,
            "user": session.username,
            "state": session.state,
            "status": session.state,
            "method": session.method,
            "cmd": session.cmd,
            "host": session.host,
            "port": session.port,
            "target": target,
            "up": session.up,
            "down": session.down,
            "created_at": session.created_at,
            "last_active": session.last_active,
            "closed_reason": session.closed_reason,
        }
        if session.username is not None:
            user = self._users.get(session.username)
            if user is not None:
                view["quota"] = user.quota_bytes
        return view

    # ------------------------------------------------------------------
    # User registration
    # ------------------------------------------------------------------
    def add_user(
        self,
        username: str,
        password: str,
        *,
        max_sessions: int | None = None,
        quota_bytes: int | None = None,
        allow_targets: tuple = (),
        allow_private: bool = False,
    ) -> dict:
        if not isinstance(username, str) or not (1 <= len(username) <= MAX_CREDENTIAL_LENGTH):
            raise self._error("SOCKS_BAD_CREDENTIAL_FORMAT", "invalid username")
        if not isinstance(password, str) or not (1 <= len(password) <= MAX_CREDENTIAL_LENGTH):
            raise self._error("SOCKS_BAD_CREDENTIAL_FORMAT", "invalid password")
        if max_sessions is not None:
            if type(max_sessions) is not int or max_sessions < 0:
                raise self._error("SOCKS_BAD_CREDENTIAL_FORMAT", "invalid session limit")
        if quota_bytes is not None:
            if type(quota_bytes) is not int or quota_bytes < 0:
                raise self._error("SOCKS_BAD_CREDENTIAL_FORMAT", "invalid quota")
        if not isinstance(allow_private, bool):
            raise self._error("SOCKS_BAD_CREDENTIAL_FORMAT", "invalid private-address policy")
        if isinstance(allow_targets, str):
            raise self._error("SOCKS_BAD_CREDENTIAL_FORMAT", "allow_targets must be a sequence")
        try:
            targets = tuple(str(item).strip() for item in allow_targets)
        except TypeError as exc:
            raise self._error("SOCKS_BAD_CREDENTIAL_FORMAT", "invalid target list") from exc
        if any(not item for item in targets):
            raise self._error("SOCKS_BAD_CREDENTIAL_FORMAT", "empty target rule")

        with self._lock:
            user = self._users.get(username)
            if user is None:
                user = _User(
                    username=username,
                    password_hash=self._hash_password(password),
                    max_sessions=max_sessions,
                    quota_bytes=quota_bytes,
                    allow_targets=targets,
                    allow_private=allow_private,
                )
                self._users[username] = user
                self._usage[username] = {"total": 0, "up": 0, "down": 0}
            else:
                user.password_hash = self._hash_password(password)
                user.max_sessions = max_sessions
                user.quota_bytes = quota_bytes
                user.allow_targets = targets
                user.allow_private = allow_private
                user.failures = 0
                user.locked_until = None

            return {
                "username": username,
                "status": "registered",
                "max_sessions": user.max_sessions,
                "quota_bytes": user.quota_bytes,
                "allow_targets": list(user.allow_targets),
                "allow_private": user.allow_private,
            }

    def set_password(self, username: str, password: str) -> dict:
        if not isinstance(username, str) or not username:
            raise self._error("SOCKS_BAD_CREDENTIAL_FORMAT", "invalid username")
        if not isinstance(password, str) or not (1 <= len(password) <= MAX_CREDENTIAL_LENGTH):
            raise self._error("SOCKS_BAD_CREDENTIAL_FORMAT", "invalid password")
        with self._lock:
            user = self._users.get(username)
            if user is None:
                raise self._error("SOCKS_USER_UNKNOWN", "unknown user")
            user.password_hash = self._hash_password(password)
            user.failures = 0
            user.locked_until = None
            return {"username": username, "status": "updated"}

    # ------------------------------------------------------------------
    # Handshake and authentication
    # ------------------------------------------------------------------
    def hello(self, session_id: str, methods: list) -> dict:
        if not isinstance(session_id, str) or not session_id:
            raise self._error("SOCKS_BAD_STATE", "invalid session id")
        if not isinstance(methods, (list, tuple)):
            raise self._error("SOCKS_BAD_METHODS", "methods must be a sequence")
        checked: list[int] = []
        for method in methods:
            if type(method) is not int or method < 0 or method > 0xFF:
                raise self._error("SOCKS_BAD_METHODS", "method byte out of range")
            checked.append(method)
        if not checked:
            raise self._error("SOCKS_BAD_METHODS", "empty method list")

        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                self._sequence += 1
                now = self._now()
                session = _Session(
                    session_id=session_id,
                    seq=self._sequence,
                    created_at=now,
                    last_active=now,
                )
                self._sessions[session_id] = session
                self._open_total += 1
            elif session.state != _STATE_NEW or session.method is not None:
                raise self._error("SOCKS_BAD_STATE", "session already negotiated")

            if self.require_auth:
                selected = 0x02 if 0x02 in checked else None
            else:
                if 0x00 in checked:
                    selected = 0x00
                elif 0x02 in checked:
                    selected = 0x02
                else:
                    selected = None

            if selected is None:
                return {
                    "method": 0xFF,
                    "status": "rejected",
                    "code": "SOCKS_NO_METHOD",
                }

            session.method = selected
            session.last_active = self._now()
            if selected == 0x02:
                session.state = _STATE_GREETED
            else:
                session.username = None
                session.state = _STATE_AUTHENTICATED

            return {
                "method": selected,
                "status": "accepted",
            }

    def authenticate(self, session_id: str, username: str, password: str) -> dict:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                raise self._error("SOCKS_SESSION_UNKNOWN", "unknown session")
            if session.state != _STATE_GREETED or session.method != 0x02:
                raise self._error("SOCKS_BAD_STATE", "authentication not negotiated")
            if (
                not isinstance(username, str)
                or not isinstance(password, str)
                or not (1 <= len(username) <= MAX_CREDENTIAL_LENGTH)
                or not (1 <= len(password) <= MAX_CREDENTIAL_LENGTH)
            ):
                raise self._error("SOCKS_BAD_CREDENTIAL_FORMAT", "credential length must be 1..255")

            now = self._now()
            user = self._users.get(username)
            if user is not None and user.locked_until is not None:
                if now < user.locked_until:
                    raise self._error("SOCKS_USER_LOCKED", "user temporarily locked")
                user.locked_until = None
                user.failures = 0

            supplied = self._hash_password(password)
            if user is not None and user.password_hash is not None:
                expected = user.password_hash
                valid = hmac.compare_digest(supplied, expected)
            else:
                hmac.compare_digest(supplied, b"\x00" * hashlib.sha256().digest_size)
                valid = False

            if not valid:
                if user is not None:
                    user.failures += 1
                    if user.failures >= FAILURE_LIMIT:
                        user.locked_until = now + LOCK_SECONDS
                        raise self._error("SOCKS_USER_LOCKED", "too many failed attempts")
                raise self._error("SOCKS_AUTH_FAILED", "invalid credentials")

            user.failures = 0
            user.locked_until = None
            session.username = username
            session.state = _STATE_AUTHENTICATED
            session.last_active = now
            return {
                "session_id": session_id,
                "username": username,
                "status": "authenticated",
            }

    # ------------------------------------------------------------------
    # CONNECT policy
    # ------------------------------------------------------------------
    @staticmethod
    def _target_matches(host: str, rules: tuple[str, ...]) -> bool:
        candidate = host.lower().rstrip(".")
        for rule in rules:
            normalized = rule.lower().rstrip(".")
            if not normalized:
                continue
            if normalized.startswith("."):
                base = normalized[1:]
                if candidate == base or candidate.endswith(normalized):
                    return True
            else:
                if candidate == normalized or candidate.endswith("." + normalized):
                    return True
        return False

    @staticmethod
    def _parse_ip(host: str) -> ipaddress._BaseAddress | None:
        candidate = host
        if candidate.startswith("[") and candidate.endswith("]"):
            candidate = candidate[1:-1]
        # A scope identifier is not part of the IP for policy checks.
        candidate = candidate.split("%", 1)[0]
        try:
            return ipaddress.ip_address(candidate)
        except ValueError:
            return None

    @staticmethod
    def _blocked_address(address: ipaddress._BaseAddress) -> bool:
        return bool(
            address.is_loopback
            or address.is_private
            or address.is_link_local
            or address.is_reserved
            or address.is_multicast
            or address.is_unspecified
        )

    def connect(self, session_id: str, cmd: int, host: str, port: int) -> dict:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                raise self._error("SOCKS_SESSION_UNKNOWN", "unknown session")
            if type(cmd) is not int or cmd != 0x01:
                raise self._error("SOCKS_CMD_UNSUPPORTED", "only CONNECT is supported")
            if (
                not isinstance(host, str)
                or not host
                or len(host) > MAX_HOST_LENGTH
                or type(port) is not int
                or port < 1
                or port > 65535
            ):
                raise self._error("SOCKS_BAD_ADDRESS", "invalid destination")

            if session.state == _STATE_CLOSED:
                raise self._error("SOCKS_BAD_STATE", "session is closed")
            if session.state == _STATE_CONNECTED:
                raise self._error("SOCKS_ALREADY_CONNECTED", "session already connected")
            if session.state != _STATE_AUTHENTICATED:
                raise self._error("SOCKS_NOT_AUTHENTICATED", "authenticate first")

            user = self._users.get(session.username) if session.username is not None else None
            if user is not None:
                if user.allow_targets and not self._target_matches(host, user.allow_targets):
                    raise self._error("SOCKS_TARGET_DENIED", "target not in allowlist")
            address = self._parse_ip(host)
            if (
                address is not None
                and (user is None or not user.allow_private)
                and self._blocked_address(address)
            ):
                raise self._error("SOCKS_TARGET_DENIED", "private address blocked")

            if user is not None:
                if self._user_online(session.username) >= self._effective_user_limit(user):
                    raise self._error("SOCKS_SESSION_LIMIT", "per-user session limit reached")
            if self._online_total >= self.max_sessions:
                raise self._error("SOCKS_SERVER_BUSY", "global session limit reached")

            session.cmd = cmd
            session.host = host
            session.port = port
            session.state = _STATE_CONNECTED
            session.last_active = self._now()
            self._increment_online(session)
            if session.username is not None:
                self._usage_for(session.username)["total"] += 1
            return {
                "session_id": session_id,
                "status": "connected",
                "cmd": cmd,
                "host": host,
                "port": port,
            }

    # ------------------------------------------------------------------
    # Traffic accounting and lifecycle
    # ------------------------------------------------------------------
    def record_traffic(self, session_id: str, *, up: int = 0, down: int = 0) -> dict:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                raise self._error("SOCKS_SESSION_UNKNOWN", "unknown session")
            if session.state != _STATE_CONNECTED:
                raise self._error("SOCKS_NOT_OPEN", "session is not open")
            if type(up) is not int or type(down) is not int or up < 0 or down < 0:
                raise self._error("SOCKS_BAD_TRAFFIC", "traffic counters cannot be negative")

            session.up += up
            session.down += down
            session.last_active = self._now()

            usage = None
            user = None
            if session.username is not None:
                user = self._users.get(session.username)
                usage = self._usage_for(session.username)
                usage["up"] += up
                usage["down"] += down

            quota = user.quota_bytes if user is not None else None
            used = usage["up"] + usage["down"] if usage is not None else session.up + session.down
            if quota is not None and used > quota:
                self._close_locked(session, "SOCKS_QUOTA_EXCEEDED")
                raise self._error("SOCKS_QUOTA_EXCEEDED", "traffic quota exceeded")

            remaining = max(0, quota - used) if quota is not None else 0
            return {
                "session_id": session_id,
                "status": "ok",
                "up": session.up,
                "down": session.down,
                "accepted_up": up,
                "accepted_down": down,
                "used": used,
                "remaining": remaining,
            }

    def close(self, session_id: str) -> dict:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                raise self._error("SOCKS_SESSION_UNKNOWN", "unknown session")
            if session.state == _STATE_CLOSED:
                return {
                    "status": "noop",
                    "code": "SOCKS_ALREADY_CLOSED",
                }
            self._close_locked(session, "closed")
            return {"status": "closed"}

    def session(self, session_id: str) -> dict:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                raise self._error("SOCKS_SESSION_UNKNOWN", "unknown session")
            return copy.deepcopy(self._session_view(session))

    def list_sessions(self, username: str | None = None) -> list:
        with self._lock:
            rows = []
            for session in self._sessions.values():
                if session.state == _STATE_CLOSED:
                    continue
                if username is not None and session.username != username:
                    continue
                rows.append(self._session_view(session))
            rows.sort(key=lambda item: self._sessions[item["session_id"]].seq)
            return copy.deepcopy(rows)

    def usage(self, username: str) -> dict:
        with self._lock:
            user = self._users.get(username)
            if user is None:
                raise self._error("SOCKS_USER_UNKNOWN", "unknown user")
            usage = self._usage_for(username)
            total_used = usage["up"] + usage["down"]
            quota = user.quota_bytes
            remaining = max(0, quota - total_used) if quota is not None else 0
            return {
                "sessions": self._user_online(username),
                "total": usage["total"],
                "up": usage["up"],
                "down": usage["down"],
                "quota": quota,
                "remaining": remaining,
            }

    def expire(self, now: int | None = None) -> list:
        with self._lock:
            if now is None:
                now = self._now()
            else:
                now = int(now)
            expired = []
            for username, user in self._users.items():
                if user.locked_until is not None and user.locked_until <= now:
                    user.locked_until = None
                    user.failures = 0
                    expired.append(username)
            return sorted(expired)

    def unlock(self, username: str) -> dict:
        with self._lock:
            user = self._users.get(username)
            if user is None:
                raise self._error("SOCKS_USER_UNKNOWN", "unknown user")
            user.failures = 0
            user.locked_until = None
            return {"username": username, "status": "unlocked"}

    # ------------------------------------------------------------------
    # Snapshot / restore
    # ------------------------------------------------------------------
    def snapshot(self) -> dict:
        with self._lock:
            users: dict[str, Any] = {}
            for username, user in self._users.items():
                users[username] = {
                    "username": username,
                    "max_sessions": user.max_sessions,
                    "quota_bytes": user.quota_bytes,
                    "allow_targets": list(user.allow_targets),
                    "allow_private": user.allow_private,
                    "failures": user.failures,
                    "locked_until": user.locked_until,
                }

            sessions = []
            for session in self._sessions.values():
                if session.state == _STATE_CLOSED:
                    continue
                sessions.append(
                    {
                        "session_id": session.session_id,
                        "username": session.username,
                        "state": session.state,
                        "method": session.method,
                        "cmd": session.cmd,
                        "host": session.host,
                        "port": session.port,
                        "up": session.up,
                        "down": session.down,
                        "created_at": session.created_at,
                        "last_active": session.last_active,
                        "closed_reason": session.closed_reason,
                    }
                )

            usage = {
                username: {
                    "total": values["total"],
                    "up": values["up"],
                    "down": values["down"],
                }
                for username, values in self._usage.items()
            }

            # A JSON round-trip both proves serialisability and makes the result
            # independent of all internal mutable objects.
            return json.loads(
                json.dumps(
                    {
                        "version": 1,
                        "users": users,
                        "sessions": sessions,
                        "usage": usage,
                    },
                    sort_keys=True,
                )
            )

    def restore(self, snapshot: dict) -> None:
        with self._lock:
            try:
                data = json.loads(json.dumps(snapshot))
            except (TypeError, ValueError) as exc:
                raise self._error("SOCKS_SNAPSHOT_CORRUPT", "snapshot is not serialisable") from exc

            if not isinstance(data, dict) or type(data.get("version")) is not int or data.get("version") != 1:
                raise self._error("SOCKS_SNAPSHOT_CORRUPT", "unsupported snapshot version")

            new_users: dict[str, _User] = {}
            new_usage: dict[str, dict[str, int]] = {}
            try:
                raw_users = data.get("users", {})
                if isinstance(raw_users, dict):
                    user_items = list(raw_users.items())
                elif isinstance(raw_users, list):
                    user_items = []
                    for entry in raw_users:
                        if not isinstance(entry, dict) or not isinstance(entry.get("username"), str):
                            raise ValueError("invalid user entry")
                        user_items.append((entry["username"], entry))
                else:
                    raise ValueError("invalid users section")

                for key, entry in user_items:
                    if not isinstance(entry, dict):
                        raise ValueError("invalid user entry")
                    username = entry.get("username", key)
                    if not isinstance(username, str) or not username or len(username) > MAX_CREDENTIAL_LENGTH:
                        raise ValueError("invalid username")
                    if username in new_users:
                        raise ValueError("duplicate user")

                    max_sessions = entry.get("max_sessions")
                    quota_bytes = entry.get("quota_bytes")
                    failures = entry.get("failures", entry.get("failed_attempts", 0))
                    locked_until = entry.get("locked_until", entry.get("locked_till"))
                    allow_targets = entry.get("allow_targets", [])
                    allow_private = entry.get("allow_private", False)

                    if max_sessions is not None and (type(max_sessions) is not int or max_sessions < 0):
                        raise ValueError("invalid user session limit")
                    if quota_bytes is not None and (type(quota_bytes) is not int or quota_bytes < 0):
                        raise ValueError("invalid user quota")
                    if type(failures) is not int or failures < 0:
                        raise ValueError("invalid failure count")
                    if locked_until is not None and type(locked_until) is not int:
                        raise ValueError("invalid lock deadline")
                    if not isinstance(allow_targets, (list, tuple)) or any(
                        not isinstance(item, str) or not item for item in allow_targets
                    ):
                        raise ValueError("invalid target rules")
                    if not isinstance(allow_private, bool):
                        raise ValueError("invalid private-address policy")

                    # Restored records deliberately have no credential.  The
                    # administrator must call set_password() after a restore.
                    new_users[username] = _User(
                        username=username,
                        password_hash=None,
                        max_sessions=max_sessions,
                        quota_bytes=quota_bytes,
                        allow_targets=tuple(item.strip() for item in allow_targets),
                        allow_private=allow_private,
                        failures=failures,
                        locked_until=locked_until,
                    )

                raw_usage = data.get("usage", {})
                if raw_usage is None:
                    raw_usage = {}
                if not isinstance(raw_usage, dict):
                    raise ValueError("invalid usage section")
                for username, values in raw_usage.items():
                    if username not in new_users:
                        raise ValueError("usage references unknown user")
                    if not isinstance(values, dict):
                        raise ValueError("invalid usage entry")
                    total = values.get("total", 0)
                    up = values.get("up", 0)
                    down = values.get("down", 0)
                    if any(type(value) is not int or value < 0 for value in (total, up, down)):
                        raise ValueError("invalid usage counter")
                    new_usage[username] = {"total": total, "up": up, "down": down}
                for username in new_users:
                    new_usage.setdefault(username, {"total": 0, "up": 0, "down": 0})

                raw_sessions = data.get("sessions", [])
                if isinstance(raw_sessions, dict):
                    session_items = list(raw_sessions.values())
                elif isinstance(raw_sessions, list):
                    session_items = raw_sessions
                else:
                    raise ValueError("invalid sessions section")

                new_sessions: "OrderedDict[str, _Session]" = OrderedDict()
                online_by_user: dict[str, int] = {}
                online_total = 0
                for entry in session_items:
                    if not isinstance(entry, dict):
                        raise ValueError("invalid session entry")
                    session_id = entry.get("session_id", entry.get("id"))
                    state = entry.get("state")
                    username = entry.get("username", entry.get("user"))
                    if not isinstance(session_id, str) or not session_id:
                        raise ValueError("invalid session id")
                    if session_id in new_sessions:
                        raise ValueError("duplicate session")
                    if state not in _OPEN_STATES and state != _STATE_CLOSED:
                        raise ValueError("invalid session state")
                    if username is not None and not isinstance(username, str):
                        raise ValueError("invalid session user")
                    if username is not None and username not in new_users:
                        raise ValueError("session references unknown user")
                    if state in (_STATE_NEW, _STATE_GREETED) and username is not None:
                        raise ValueError("unauthenticated session has a user")

                    up = entry.get("up", 0)
                    down = entry.get("down", 0)
                    method = entry.get("method")
                    cmd = entry.get("cmd")
                    host = entry.get("host")
                    port = entry.get("port")
                    created_at = entry.get("created_at", 0)
                    last_active = entry.get("last_active", created_at)
                    closed_reason = entry.get("closed_reason")
                    if any(type(value) is not int or value < 0 for value in (up, down, created_at, last_active)):
                        raise ValueError("invalid session counter")
                    if method is not None and (type(method) is not int or method < 0 or method > 0xFF):
                        raise ValueError("invalid session method")
                    if cmd is not None and type(cmd) is not int:
                        raise ValueError("invalid session command")
                    if host is not None and not isinstance(host, str):
                        raise ValueError("invalid session host")
                    if port is not None and type(port) is not int:
                        raise ValueError("invalid session port")
                    if closed_reason is not None and not isinstance(closed_reason, str):
                        raise ValueError("invalid close reason")

                    session = _Session(
                        session_id=session_id,
                        seq=len(new_sessions) + 1,
                        state=state,
                        username=username,
                        method=method,
                        cmd=cmd,
                        host=host,
                        port=port,
                        up=up,
                        down=down,
                        created_at=created_at,
                        last_active=last_active,
                        closed_reason=closed_reason,
                    )
                    new_sessions[session_id] = session
                    if session.online:
                        online_total += 1
                        if username is not None:
                            online_by_user[username] = online_by_user.get(username, 0) + 1
            except (TypeError, ValueError, KeyError) as exc:
                raise self._error("SOCKS_SNAPSHOT_CORRUPT", str(exc) or "corrupt snapshot") from exc

            # Commit only after every section has validated.
            self._users = new_users
            self._usage = new_usage
            self._sessions = new_sessions
            self._closed_order = [
                session.session_id
                for session in new_sessions.values()
                if session.state == _STATE_CLOSED
            ][-MAX_CLOSED_HISTORY:]
            self._online_by_user = online_by_user
            self._online_total = online_total
            self._open_total = sum(
                1 for session in new_sessions.values() if session.state != _STATE_CLOSED
            )
            self._sequence = len(new_sessions)
