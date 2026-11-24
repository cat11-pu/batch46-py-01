"""Kubernetes bound service account token audience and binding guard."""

from __future__ import annotations

from typing import Any, Mapping, Sequence


class BoundTokenError(ValueError):
    """Raised when a bound token cannot be issued or validated."""

    def __init__(self, code: str, detail: str | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class BoundTokenGuard:
    """Issue, validate, refresh and revoke projected service account tokens."""

    def __init__(
        self,
        *,
        secret: str = "bound-token-secret",
        clock_skew: int = 60,
        max_token_lifetime: int = 3600,
        max_tokens: int = 100,
        key_grace: int = 300,
    ) -> None:
        self.clock_skew = clock_skew
        self.max_token_lifetime = max_token_lifetime
        self.max_tokens = max_tokens
        self.key_grace = key_grace

    def issue(
        self,
        subject: str,
        *,
        audiences: Sequence[str],
        now: int,
        ttl: int = 600,
        pod: str | None = None,
        node: str | None = None,
        uid: str | None = None,
        not_before: int | None = None,
    ) -> dict[str, Any]:
        raise NotImplementedError

    def decode(self, token: str) -> dict[str, Any]:
        raise NotImplementedError

    def validate(
        self,
        token: str,
        *,
        now: int,
        audiences: Sequence[str] = (),
        pod: str | None = None,
        node: str | None = None,
    ) -> dict[str, Any]:
        raise NotImplementedError

    def refresh(
        self,
        token: str,
        *,
        now: int,
        ttl: int = 600,
    ) -> dict[str, Any]:
        raise NotImplementedError

    def revoke(self, subject: str, *, now: int) -> dict[str, Any]:
        raise NotImplementedError

    def rotate_key(self, *, now: int) -> dict[str, Any]:
        raise NotImplementedError

    def purge_expired(self, *, now: int) -> int:
        raise NotImplementedError

    def snapshot(self) -> dict[str, Any]:
        raise NotImplementedError

    def restore(self, state: Mapping[str, Any]) -> None:
        raise NotImplementedError

    def stats(self) -> dict[str, int]:
        raise NotImplementedError
