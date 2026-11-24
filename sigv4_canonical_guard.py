"""AWS Signature Version 4 canonicalization, signing and replay guard."""

from __future__ import annotations

from typing import Any, Mapping, Sequence


class SigV4Error(ValueError):
    """Raised when a request cannot be canonicalized or signed."""

    def __init__(self, code: str, detail: str | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class SigV4Guard:
    """Canonical request construction, signing, verification and replay cache."""

    def __init__(
        self,
        *,
        clock_skew: int = 300,
        max_presign: int = 604800,
        max_replays: int = 1000,
    ) -> None:
        self.clock_skew = clock_skew
        self.max_presign = max_presign
        self.max_replays = max_replays

    def canonical_query(self, query: Mapping[str, Any]) -> str:
        raise NotImplementedError

    def canonical_headers(self, headers: Mapping[str, str]) -> tuple[str, str]:
        raise NotImplementedError

    def canonical_uri(self, path: str, *, normalize: bool = True) -> str:
        raise NotImplementedError

    def build_canonical_request(self, request: Mapping[str, Any]) -> dict[str, Any]:
        raise NotImplementedError

    def string_to_sign(
        self,
        request: Mapping[str, Any],
        *,
        timestamp: str,
        scope: str,
        algorithm: str = "AWS4-HMAC-SHA256",
    ) -> dict[str, Any]:
        raise NotImplementedError

    def signing_key(
        self,
        secret_key: str,
        *,
        date: str,
        region: str,
        service: str,
    ) -> str:
        raise NotImplementedError

    def sign(
        self,
        request: Mapping[str, Any],
        credentials: Mapping[str, str],
        *,
        now: int,
    ) -> dict[str, Any]:
        raise NotImplementedError

    def verify(
        self,
        request: Mapping[str, Any],
        credentials: Mapping[str, str],
        *,
        now: int,
    ) -> dict[str, Any]:
        raise NotImplementedError

    def presign(
        self,
        request: Mapping[str, Any],
        credentials: Mapping[str, str],
        *,
        expires: int,
        now: int,
    ) -> dict[str, Any]:
        raise NotImplementedError

    def verify_presigned(
        self,
        request: Mapping[str, Any],
        credentials: Mapping[str, str],
        *,
        now: int,
    ) -> dict[str, Any]:
        raise NotImplementedError

    def purge_replays(self, cutoff: int) -> int:
        raise NotImplementedError

    def snapshot(self) -> dict[str, Any]:
        raise NotImplementedError

    def restore(self, state: Mapping[str, Any]) -> None:
        raise NotImplementedError

    def stats(self) -> dict[str, int]:
        raise NotImplementedError
