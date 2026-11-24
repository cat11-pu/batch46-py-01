"""LDAP referral traversal guard (implementation skeleton)."""

from __future__ import annotations

import threading


class LdapError(ValueError):
    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class LdapReferralGuard:
    """Follow LDAP referrals under host, hop, entry and time budgets."""

    def __init__(self, *, max_hops: int = 3, deadline_seconds: float = 5.0,
                 max_entries: int = 100, clock=None) -> None:
        self.max_hops = max_hops
        self.deadline_seconds = deadline_seconds
        self.max_entries = max_entries
        self._clock = clock
        self._lock = threading.RLock()

    def allow_host(self, host: str, *, allow_auth: bool = True) -> dict:
        raise NotImplementedError

    def revoke_host(self, host: str) -> None:
        raise NotImplementedError

    def validate_url(self, url: str) -> str:
        raise NotImplementedError

    def search(self, base_url: str, *, dn: str, scope: str = "sub",
               filter: str = "(objectClass=*)", resolver,
               bind_dn: str | None = None, now=None) -> dict:
        raise NotImplementedError

    def resume(self, continuation: dict, *, resolver,
               bind_dn: str | None = None, now=None) -> dict:
        raise NotImplementedError

    def continuation(self) -> dict | None:
        raise NotImplementedError

    def visited(self) -> list:
        raise NotImplementedError

    def budget(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def reset_stats(self) -> None:
        raise NotImplementedError
