"""IPv6 router-advertisement guard (implementation skeleton)."""

from __future__ import annotations

import threading

SNAPSHOT_VERSION = 1
HOP_LIMIT = 255
MIN_VALID_LIFETIME = 600
MAX_PREFIXES = 8
ALLOWED_ROLES = ("uplink", "host", "untrusted")
VIOLATION_WINDOW = 60


class RaError(ValueError):
    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class RaGuard:
    """Port roles, RA validation, prefix table, rate limiting, quarantine."""

    def __init__(self, *, rate_limit: int = 5, rate_window: int = 1,
                 violation_threshold: int = 3,
                 quarantine_seconds: int = 300) -> None:
        self.rate_limit = rate_limit
        self.rate_window = rate_window
        self.violation_threshold = violation_threshold
        self.quarantine_seconds = quarantine_seconds
        self._lock = threading.RLock()

    def configure_port(self, port: str, role: str, *, vlan: int = 1,
                       allowed_prefixes: tuple = (),
                       default_route: bool = False) -> dict:
        raise NotImplementedError

    def ingest(self, packet: dict) -> dict:
        raise NotImplementedError

    def ingest_batch(self, packets: list) -> list:
        raise NotImplementedError

    def port_stats(self, port: str) -> dict:
        raise NotImplementedError

    def violations(self, port: str | None = None) -> list:
        raise NotImplementedError

    def prefix_table(self, vlan: int) -> list:
        raise NotImplementedError

    def effective_prefixes(self, port: str, *, now: int | None = None) -> list:
        raise NotImplementedError

    def quarantine(self, port: str, seconds: int) -> dict:
        raise NotImplementedError

    def release_port(self, port: str) -> dict:
        raise NotImplementedError

    def expire(self, now: int) -> list:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, snapshot: dict) -> None:
        raise NotImplementedError
