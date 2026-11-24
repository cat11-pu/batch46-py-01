"""GCP service-account JWT assertion exchange and access token guard."""

from __future__ import annotations

from typing import Any, Mapping, Sequence


class SaJwtError(ValueError):
    """Raised when an assertion cannot be issued or exchanged."""

    def __init__(self, code: str, detail: str | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class SaJwtGuard:
    """Self-signed JWT assertion issuance, exchange and token introspection."""

    def __init__(
        self,
        *,
        clock_skew: int = 60,
        max_lifetime: int = 3600,
        max_tokens: int = 50,
        replay_retention: int = 3600,
    ) -> None:
        self.clock_skew = clock_skew
        self.max_lifetime = max_lifetime
        self.max_tokens = max_tokens
        self.replay_retention = replay_retention

    def register_service_account(
        self,
        email: str,
        *,
        secret: str,
        scopes: Sequence[str],
    ) -> dict[str, Any]:
        raise NotImplementedError

    def allow_delegation(self, email: str, subject: str) -> dict[str, Any]:
        raise NotImplementedError

    def create_assertion(
        self,
        email: str,
        *,
        audience: str,
        scope: Sequence[str] | None = None,
        now: int,
        lifetime: int = 3600,
        subject: str | None = None,
        jwt_id: str | None = None,
    ) -> dict[str, Any]:
        raise NotImplementedError

    def decode_assertion(self, token: str) -> dict[str, Any]:
        raise NotImplementedError

    def exchange(
        self,
        assertion: str,
        *,
        audience: str,
        requested_scope: Sequence[str],
        now: int,
    ) -> dict[str, Any]:
        raise NotImplementedError

    def introspect(self, access_token: str, *, now: int) -> dict[str, Any]:
        raise NotImplementedError

    def revoke_token(self, access_token: str) -> dict[str, Any]:
        raise NotImplementedError

    def purge_replays(self, cutoff: int) -> int:
        raise NotImplementedError

    def purge_expired_tokens(self, *, now: int) -> int:
        raise NotImplementedError

    def snapshot(self) -> dict[str, Any]:
        raise NotImplementedError

    def restore(self, state: Mapping[str, Any]) -> None:
        raise NotImplementedError

    def stats(self) -> dict[str, int]:
        raise NotImplementedError
