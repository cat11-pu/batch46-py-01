"""SOCKS5 authentication and session-policy guard (implementation skeleton)."""

from __future__ import annotations

import threading

SNAPSHOT_VERSION = 1
METHOD_NO_AUTH = 0x00
METHOD_USERPASS = 0x02
METHOD_NONE = 0xFF
CMD_CONNECT = 0x01
MAX_FAILURES = 3
LOCK_SECONDS = 300
DEFAULT_MAX_SESSIONS = 4


class Socks5Error(ValueError):
    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class Socks5Guard:
    """User registry, method negotiation, connect policy, quotas and snapshots."""

    def __init__(self, *, max_sessions: int = 64, require_auth: bool = True,
                 default_max_sessions: int = DEFAULT_MAX_SESSIONS,
                 clock=None) -> None:
        self.max_sessions = max_sessions
        self.require_auth = require_auth
        self.default_max_sessions = default_max_sessions
        self._clock = clock
        self._lock = threading.RLock()

    def add_user(self, username: str, password: str, *,
                 max_sessions: int | None = None,
                 quota_bytes: int | None = None,
                 allow_targets: tuple = (),
                 allow_private: bool = False) -> dict:
        raise NotImplementedError

    def set_password(self, username: str, password: str) -> dict:
        raise NotImplementedError

    def hello(self, session_id: str, methods: list) -> dict:
        raise NotImplementedError

    def authenticate(self, session_id: str, username: str,
                     password: str) -> dict:
        raise NotImplementedError

    def connect(self, session_id: str, cmd: int, host: str, port: int) -> dict:
        raise NotImplementedError

    def record_traffic(self, session_id: str, *, up: int = 0,
                       down: int = 0) -> dict:
        raise NotImplementedError

    def close(self, session_id: str) -> dict:
        raise NotImplementedError

    def session(self, session_id: str) -> dict:
        raise NotImplementedError

    def list_sessions(self, username: str | None = None) -> list:
        raise NotImplementedError

    def usage(self, username: str) -> dict:
        raise NotImplementedError

    def expire(self, now: int | None = None) -> list:
        raise NotImplementedError

    def unlock(self, username: str) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, snapshot: dict) -> None:
        raise NotImplementedError
