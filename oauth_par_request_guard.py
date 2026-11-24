"""OAuth pushed authorization request guard (implementation skeleton)."""

from __future__ import annotations

import threading


class ParError(ValueError):
    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class ParGuard:
    """Validate pushed authorization requests and redeem request URIs once."""

    def __init__(self, *, request_ttl: float = 60.0, max_pending: int = 100,
                 max_per_client: int = 10, clock=None) -> None:
        self.request_ttl = request_ttl
        self.max_pending = max_pending
        self.max_per_client = max_per_client
        self._clock = clock
        self._lock = threading.RLock()

    def register_client(self, client_id: str, *, redirect_uris,
                        confidential: bool = True, allowed_scopes=(),
                        require_pkce=None) -> dict:
        raise NotImplementedError

    def revoke_client(self, client_id: str) -> None:
        raise NotImplementedError

    def push(self, request: dict, *, now=None) -> dict:
        raise NotImplementedError

    def redeem(self, request_uri: str, *, client_id: str, now=None) -> dict:
        raise NotImplementedError

    def peek(self, request_uri: str) -> dict:
        raise NotImplementedError

    def quota(self, client_id: str) -> dict:
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
