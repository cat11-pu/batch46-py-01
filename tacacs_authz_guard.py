"""TACACS+ command authorization and session accounting guard."""

from __future__ import annotations

import copy
import fnmatch
import threading
import time
from typing import Any, Iterable, Mapping, Sequence


class TacacsError(ValueError):
    """Raised for rejected TACACS+ authorization or accounting requests."""

    def __init__(self, code: str, detail: str | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class TacacsGuard:
    """Command-set policy evaluation plus session accounting.

    The public surface below is what the device-facing gateway binds to.
    Implementations must keep authorization decisions and accounting state
    consistent under concurrent access.
    """

    def __init__(self, *, max_sessions: int = 4, max_audit: int = 100) -> None:
        self.max_sessions = max_sessions
        self.max_audit = max_audit
        self._lock = threading.RLock()
        self._users: dict[str, dict[str, Any]] = {}
        self._command_sets: dict[str, dict[str, Any]] = {}
        self._sessions: dict[str, dict[str, Any]] = {}
        self._audit: list[dict[str, Any]] = []
        self._audit_seq = 0

    def _match_rule(self, command: str, rule: Mapping[str, Any]) -> bool:
        pattern = rule.get("pattern", "*")
        if command == pattern or pattern == "*":
            return True
        return fnmatch.fnmatchcase(command, pattern)

    def _record_audit(self, entry: Mapping[str, Any]) -> None:
        self._audit_seq += 1
        record = dict(entry)
        record.setdefault("seq", self._audit_seq)
        record.setdefault("ts", time.time())
        self._audit.append(record)
        overflow = len(self._audit) - self.max_audit
        if overflow > 0:
            del self._audit[:overflow]

    def _evaluate(
        self, user: Mapping[str, Any], command: str
    ) -> tuple[str, str, int | None, str | None]:
        privilege = user["privilege"]
        global_index = 0
        default_action = "deny"
        default_set: str | None = None
        for group_name in user["groups"]:
            command_set = self._command_sets.get(group_name)
            if command_set is None:
                continue
            default_action = command_set["default"]
            default_set = group_name
            for rule in command_set["rules"]:
                min_privilege = rule.get("min_privilege")
                if min_privilege is not None and privilege < min_privilege:
                    global_index += 1
                    continue
                if self._match_rule(command, rule):
                    action = rule.get("action", "deny")
                    if action == "permit":
                        return "permit", "TAC_PERMIT", global_index, group_name
                    return "deny", "TAC_DENY_RULE", global_index, group_name
                global_index += 1
        if default_action == "permit":
            return "permit", "TAC_PERMIT", None, default_set
        return "deny", "TAC_DENY_DEFAULT", None, default_set

    def define_command_set(
        self,
        name: str,
        *,
        rules: Sequence[Mapping[str, Any]],
        default: str = "deny",
    ) -> dict[str, Any]:
        with self._lock:
            stored_rules = [copy.deepcopy(dict(rule)) for rule in rules]
            command_set = {
                "name": name,
                "rules": stored_rules,
                "default": default,
            }
            self._command_sets[name] = command_set
            return copy.deepcopy(command_set)

    def register_user(
        self,
        username: str,
        *,
        privilege: int = 1,
        groups: Sequence[str] = (),
    ) -> dict[str, Any]:
        with self._lock:
            user = {
                "username": username,
                "privilege": privilege,
                "groups": list(groups),
            }
            self._users[username] = user
            return copy.deepcopy(user)

    def set_privilege(self, username: str, privilege: int) -> dict[str, Any]:
        with self._lock:
            user = self._users.get(username)
            if user is None:
                raise TacacsError(
                    "TAC_DENY_UNKNOWN_USER", f"unknown user: {username}"
                )
            user["privilege"] = privilege
            return copy.deepcopy(user)

    def authorize(
        self,
        username: str,
        command: str,
        *,
        device: str | None = None,
    ) -> dict[str, Any]:
        with self._lock:
            user = self._users.get(username)
            if user is None:
                self._record_audit(
                    {
                        "username": username,
                        "command": command,
                        "device": device,
                        "status": "deny",
                        "code": "TAC_DENY_UNKNOWN_USER",
                        "rule": None,
                        "command_set": None,
                    }
                )
                raise TacacsError(
                    "TAC_DENY_UNKNOWN_USER", f"unknown user: {username}"
                )
            status, code, rule_index, command_set = self._evaluate(user, command)
            result = {
                "username": username,
                "command": command,
                "device": device,
                "status": status,
                "code": code,
                "rule": rule_index,
                "command_set": command_set,
            }
            self._record_audit(result)
            return copy.deepcopy(result)

    def account_start(
        self,
        username: str,
        session_id: str,
        *,
        device: str,
        started_at: int | None = None,
    ) -> dict[str, Any]:
        with self._lock:
            if session_id in self._sessions:
                raise TacacsError(
                    "TAC_DUP_SESSION", f"duplicate session id: {session_id}"
                )
            active = sum(
                1
                for session in self._sessions.values()
                if session["status"] == "open"
            )
            if active >= self.max_sessions:
                raise TacacsError(
                    "TAC_SESSION_LIMIT",
                    f"session limit reached: {self.max_sessions}",
                )
            session = {
                "session_id": session_id,
                "user": username,
                "device": device,
                "status": "open",
                "started_at": time.time() if started_at is None else started_at,
                "stopped_at": None,
                "elapsed": None,
                "reason": None,
                "bytes_in": 0,
                "bytes_out": 0,
            }
            self._sessions[session_id] = session
            return copy.deepcopy(session)

    def account_update(
        self,
        session_id: str,
        *,
        bytes_in: int | None = None,
        bytes_out: int | None = None,
    ) -> dict[str, Any]:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                raise TacacsError(
                    "TAC_NO_SESSION", f"unknown session id: {session_id}"
                )
            if session["status"] != "open":
                raise TacacsError(
                    "TAC_SESSION_CLOSED",
                    f"session already closed: {session_id}",
                )
            if bytes_in is not None and bytes_in < session["bytes_in"]:
                raise TacacsError(
                    "TAC_COUNTER_REGRESS",
                    f"bytes_in regress: {bytes_in} < {session['bytes_in']}",
                )
            if bytes_out is not None and bytes_out < session["bytes_out"]:
                raise TacacsError(
                    "TAC_COUNTER_REGRESS",
                    f"bytes_out regress: {bytes_out} < {session['bytes_out']}",
                )
            if bytes_in is not None:
                session["bytes_in"] = bytes_in
            if bytes_out is not None:
                session["bytes_out"] = bytes_out
            return copy.deepcopy(session)

    def account_stop(
        self,
        session_id: str,
        *,
        stopped_at: int | None = None,
        reason: str = "normal",
    ) -> dict[str, Any]:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                raise TacacsError(
                    "TAC_NO_SESSION", f"unknown session id: {session_id}"
                )
            if session["status"] != "open":
                raise TacacsError(
                    "TAC_SESSION_CLOSED",
                    f"session already closed: {session_id}",
                )
            stop_time = time.time() if stopped_at is None else stopped_at
            session["status"] = "closed"
            session["stopped_at"] = stop_time
            session["elapsed"] = stop_time - session["started_at"]
            session["reason"] = reason
            return copy.deepcopy(session)

    def sessions(self, username: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            rows = [
                copy.deepcopy(session)
                for session_id, session in self._sessions.items()
                if username is None or session["user"] == username
            ]
            rows.sort(key=lambda row: row["session_id"])
            return rows

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "users": copy.deepcopy(self._users),
                "command_sets": copy.deepcopy(self._command_sets),
                "sessions": copy.deepcopy(self._sessions),
                "audit": copy.deepcopy(self._audit),
                "counters": {"audit_seq": self._audit_seq},
            }

    def restore(self, state: Mapping[str, Any]) -> None:
        with self._lock:
            state = dict(state)
            self._users = copy.deepcopy(state.get("users", {}))
            self._command_sets = copy.deepcopy(state.get("command_sets", {}))
            self._sessions = copy.deepcopy(state.get("sessions", {}))
            self._audit = copy.deepcopy(state.get("audit", []))
            counters = state.get("counters", {}) or {}
            self._audit_seq = counters.get("audit_seq", 0)

    def purge_closed(self) -> int:
        with self._lock:
            closed_ids = [
                session_id
                for session_id, session in self._sessions.items()
                if session["status"] != "open"
            ]
            for session_id in closed_ids:
                del self._sessions[session_id]
            return len(closed_ids)

    def audit(self, limit: int | None = None) -> list[dict[str, Any]]:
        with self._lock:
            if limit is None:
                return copy.deepcopy(self._audit)
            if limit <= 0:
                return []
            return copy.deepcopy(self._audit[-limit:])
