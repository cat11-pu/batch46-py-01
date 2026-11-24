"""Azure shared access signature permission, scope, expiry and key guard."""

from __future__ import annotations

from typing import Any, Mapping


class SasError(ValueError):
    """Raised when a SAS cannot be issued or parsed."""

    def __init__(self, code: str, detail: str | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class SasGuard:
    """Issue and verify SAS tokens backed by stored access policies."""

    def __init__(self, *, max_records: int = 100, max_lifetime: int = 604800) -> None:
        self.max_records = max_records
        self.max_lifetime = max_lifetime

    def register_key(self, version: str, secret: str) -> dict[str, Any]:
        raise NotImplementedError

    def rotate_key(
        self,
        version: str,
        *,
        now: int,
        overlap: int = 300,
    ) -> dict[str, Any]:
        raise NotImplementedError

    def define_policy(
        self,
        name: str,
        *,
        permissions: str,
        start: int,
        expiry: int,
    ) -> dict[str, Any]:
        raise NotImplementedError

    def revoke_policy(self, name: str, *, now: int) -> dict[str, Any]:
        raise NotImplementedError

    def check_permissions(self, granted: str, required: str) -> dict[str, Any]:
        raise NotImplementedError

    def build_sas(
        self,
        account: str,
        *,
        resource: str,
        permissions: str | None = None,
        start: int,
        expiry: int,
        key_version: str | None = None,
        policy: str | None = None,
        ip: str | None = None,
        protocol: str = "https",
    ) -> dict[str, Any]:
        raise NotImplementedError

    def string_to_sign(self, fields: Mapping[str, str]) -> str:
        raise NotImplementedError

    def verify(
        self,
        sas: Mapping[str, Any] | str,
        *,
        operation: str,
        now: int,
        target: str,
        client_ip: str | None = None,
        protocol: str = "https",
    ) -> dict[str, Any]:
        raise NotImplementedError

    def snapshot(self) -> dict[str, Any]:
        raise NotImplementedError

    def restore(self, state: Mapping[str, Any]) -> None:
        raise NotImplementedError

    def purge_expired(self, *, now: int) -> int:
        raise NotImplementedError

    def stats(self) -> dict[str, int]:
        raise NotImplementedError
