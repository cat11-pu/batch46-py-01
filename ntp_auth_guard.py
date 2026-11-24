"""NTP symmetric-key authentication and clock-drift guard (skeleton)."""

from __future__ import annotations

import threading

SNAPSHOT_VERSION = 1
MAX_SERVERS = 8
MIN_KEY_LENGTH = 8
MAX_ROOT_DELAY = 1.5
MAX_SLEW = 0.5
MAX_SLEW_STEP = 0.1
MAX_STEP = 128.0
LOCK_THRESHOLD = 0.01
MAX_DISPERSION = 0.25


class NtpError(ValueError):
    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class NtpAuthGuard:
    """Keyed NTP responses, replay window, drift policy, voting and snapshots."""

    def __init__(self, *, clock=None, max_servers: int = MAX_SERVERS) -> None:
        self.max_servers = max_servers
        self._clock = clock
        self._lock = threading.RLock()

    def add_key(self, key_id: int, secret: str, *,
                algorithm: str = "sha256") -> dict:
        raise NotImplementedError

    def add_server(self, server: str, *, key_id: int, stratum: int = 2,
                   max_root_delay: float = MAX_ROOT_DELAY) -> dict:
        raise NotImplementedError

    def make_request(self, server: str, *,
                     transmit_time: float | None = None) -> dict:
        raise NotImplementedError

    def receive(self, packet: dict) -> dict:
        raise NotImplementedError

    def offset(self) -> float:
        raise NotImplementedError

    def state(self) -> dict:
        raise NotImplementedError

    def adjust(self, *, steps: int = 1) -> dict:
        raise NotImplementedError

    def clear_panic(self) -> dict:
        raise NotImplementedError

    def health(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, snapshot: dict) -> None:
        raise NotImplementedError
