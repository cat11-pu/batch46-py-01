"""TACACS+ command authorization and session accounting guard."""

from __future__ import annotations

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

    def define_command_set(
        self,
        name: str,
        *,
        rules: Sequence[Mapping[str, Any]],
        default: str = "deny",
    ) -> dict[str, Any]:
        raise NotImplementedError

    def register_user(
        self,
        username: str,
        *,
        privilege: int = 1,
        groups: Sequence[str] = (),
    ) -> dict[str, Any]:
        raise NotImplementedError

    def set_privilege(self, username: str, privilege: int) -> dict[str, Any]:
        raise NotImplementedError

    def authorize(
        self,
        username: str,
        command: str,
        *,
        device: str | None = None,
    ) -> dict[str, Any]:
        raise NotImplementedError

    def account_start(
        self,
        username: str,
        session_id: str,
        *,
        device: str,
        started_at: int | None = None,
    ) -> dict[str, Any]:
        raise NotImplementedError

    def account_update(
        self,
        session_id: str,
        *,
        bytes_in: int | None = None,
        bytes_out: int | None = None,
    ) -> dict[str, Any]:
        raise NotImplementedError

    def account_stop(
        self,
        session_id: str,
        *,
        stopped_at: int | None = None,
        reason: str = "normal",
    ) -> dict[str, Any]:
        raise NotImplementedError

    def sessions(self, username: str | None = None) -> list[dict[str, Any]]:
        raise NotImplementedError

    def snapshot(self) -> dict[str, Any]:
        raise NotImplementedError

    def restore(self, state: Mapping[str, Any]) -> None:
        raise NotImplementedError

    def purge_closed(self) -> int:
        raise NotImplementedError

    def audit(self, limit: int | None = None) -> list[dict[str, Any]]:
        raise NotImplementedError
