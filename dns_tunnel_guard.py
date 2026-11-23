"""DNS tunnel traffic detector (implementation skeleton)."""

from __future__ import annotations

import threading

SNAPSHOT_VERSION = 1
SUSPICIOUS_QTYPES = ("TXT", "NULL")
DEFAULT_SUFFIXES = ("com", "net", "org", "io", "co.uk")
REASONS = ("LONG_LABEL", "SUSPICIOUS_QTYPE", "HIGH_UNIQUE", "LARGE_RESPONSE")


class DnsTunnelError(ValueError):
    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class DnsTunnelGuard:
    """Allowlist, per-client sliding window, scoring, blocking and snapshots."""

    def __init__(self, *, window: int = 60, unique_threshold: int = 20,
                 label_threshold: int = 30, max_events: int = 500,
                 block_seconds: int = 300, max_alerts: int = 200,
                 public_suffixes: tuple = DEFAULT_SUFFIXES) -> None:
        self.window = window
        self.unique_threshold = unique_threshold
        self.label_threshold = label_threshold
        self.max_events = max_events
        self.block_seconds = block_seconds
        self.max_alerts = max_alerts
        self.public_suffixes = tuple(public_suffixes)
        self._lock = threading.RLock()
        self._allowlist = {}
        self._clients = {}
        self._alerts = []
        self._blocked = {}

    def allow_domain(self, domain: str, *, note: str = "") -> dict:
        raise NotImplementedError

    def revoke_domain(self, domain: str) -> None:
        raise NotImplementedError

    def base_domain(self, qname: str) -> str:
        raise NotImplementedError

    def ingest(self, event: dict, *, now: int | None = None) -> dict:
        raise NotImplementedError

    def ingest_batch(self, events: list, *, now: int | None = None) -> list:
        raise NotImplementedError

    def client_state(self, client: str, *, now: int | None = None) -> dict:
        raise NotImplementedError

    def alerts(self, *, client: str | None = None,
               limit: int | None = None) -> list:
        raise NotImplementedError

    def block_client(self, client: str, seconds: int, *,
                     now: int | None = None) -> dict:
        raise NotImplementedError

    def unblock_client(self, client: str) -> dict:
        raise NotImplementedError

    def blocked(self, *, now: int | None = None) -> list:
        raise NotImplementedError

    def expire(self, now: int) -> list:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, snapshot: dict) -> None:
        raise NotImplementedError
