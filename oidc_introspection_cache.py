"""OIDC token introspection cache with revocation (implementation skeleton)."""

from __future__ import annotations

import threading


class IntrospectionError(ValueError):
    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class IntrospectionCache:
    """Cache introspection results, revocations and upstream call statistics."""

    def __init__(self, introspect_fn, *, max_entries: int = 128,
                 max_ttl: float = 60.0, negative_ttl: float = 5.0,
                 clock=None) -> None:
        self._introspect = introspect_fn
        self.max_entries = max_entries
        self.max_ttl = max_ttl
        self.negative_ttl = negative_ttl
        self._clock = clock
        self._lock = threading.RLock()

    def check(self, token: str, *, scopes=None, now=None) -> dict:
        raise NotImplementedError

    def prefetch(self, tokens, *, now=None) -> dict:
        raise NotImplementedError

    def revoke(self, token: str, *, expires_at=None, now=None) -> bool:
        raise NotImplementedError

    def is_revoked(self, token: str, now=None) -> bool:
        raise NotImplementedError

    def invalidate(self, token: str) -> bool:
        raise NotImplementedError

    def purge(self, now=None) -> int:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def reset_stats(self) -> None:
        raise NotImplementedError

    def usage(self) -> dict:
        raise NotImplementedError
