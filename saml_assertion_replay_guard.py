"""SAML assertion replay and audience guard (implementation skeleton)."""

from __future__ import annotations

import threading


class SamlError(ValueError):
    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class SamlReplayGuard:
    """Validate inbound SAML assertions and keep a bounded replay cache."""

    def __init__(self, *, clock_skew: int = 120, max_seen: int = 1000,
                 batch_limit: int = 100, clock=None) -> None:
        self.clock_skew = clock_skew
        self.max_seen = max_seen
        self.batch_limit = batch_limit
        self._clock = clock
        self._lock = threading.RLock()

    def register_service_provider(self, sp_id: str, *, entity_id: str,
                                  audiences, acs_url: str) -> dict:
        raise NotImplementedError

    def trust_issuer(self, issuer: str, *, fingerprints,
                     allowed_audiences=None) -> dict:
        raise NotImplementedError

    def revoke_issuer(self, issuer: str) -> None:
        raise NotImplementedError

    def consume(self, assertion: dict, *, sp_id: str, now=None,
                request_id: str | None = None) -> dict:
        raise NotImplementedError

    def consume_batch(self, assertions, *, sp_id: str, now=None) -> list:
        raise NotImplementedError

    def is_seen(self, assertion_id: str) -> bool:
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
