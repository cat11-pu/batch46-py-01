"""IPv6 neighbor-discovery cache guard (implementation skeleton)."""

from __future__ import annotations

import threading

SNAPSHOT_VERSION = 1
STALE_AFTER = 300
PENDING_TTL = 3
MAX_ENTRIES = 256
MAX_PER_MAC = 4


class NdpError(ValueError):
    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class NdpGuard:
    """Neighbor cache bindings, solicitation gate, eviction and snapshots."""

    def __init__(self, *, max_entries: int = MAX_ENTRIES,
                 max_per_mac: int = MAX_PER_MAC, stale_after: int = STALE_AFTER,
                 pending_ttl: int = PENDING_TTL, clock=None) -> None:
        self.max_entries = max_entries
        self.max_per_mac = max_per_mac
        self.stale_after = stale_after
        self.pending_ttl = pending_ttl
        self._clock = clock
        self._lock = threading.RLock()

    def configure_iface(self, iface: str, *, max_entries: int | None = None,
                        max_per_mac: int | None = None) -> dict:
        raise NotImplementedError

    def bind_static(self, iface: str, address: str, mac: str) -> dict:
        raise NotImplementedError

    def solicit(self, iface: str, address: str) -> dict:
        raise NotImplementedError

    def learn(self, packet: dict) -> dict:
        raise NotImplementedError

    def lookup(self, iface: str, address: str, *, now: int | None = None) -> dict:
        raise NotImplementedError

    def purge(self, now: int) -> list:
        raise NotImplementedError

    def link_change(self, iface: str) -> list:
        raise NotImplementedError

    def entries(self, iface: str | None = None) -> list:
        raise NotImplementedError

    def stats(self, iface: str | None = None) -> dict:
        raise NotImplementedError

    def violations(self, iface: str | None = None) -> list:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, snapshot: dict) -> None:
        raise NotImplementedError
