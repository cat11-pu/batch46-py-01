"""HTTP/3 QPACK dynamic table synchronization guard."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

ENTRY_OVERHEAD = 32
STREAM_STATES = ("blocked", "ready", "acked")


class QpackError(ValueError):
    def __init__(self, code: str, detail: str | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class QpackGuard:
    ENTRY_OVERHEAD = ENTRY_OVERHEAD

    def __init__(self, *, capacity: int = 4096, max_capacity: int = 8192,
                 max_blocked: int = 8) -> None:
        self.capacity = capacity
        self.max_capacity = max_capacity
        self.max_blocked = max_blocked

    def set_capacity(self, capacity: int) -> dict:
        raise NotImplementedError

    def insert(self, name: str, value: str) -> dict:
        raise NotImplementedError

    def lookup_absolute(self, index: int) -> dict:
        raise NotImplementedError

    def lookup_relative(self, index: int) -> dict:
        raise NotImplementedError

    def encode(self, headers: Sequence[Sequence[str]]) -> dict:
        raise NotImplementedError

    def decode(self, block: Mapping[str, object] | None) -> dict:
        raise NotImplementedError

    def open_stream(self, stream_id: str, *, required_insert_count: int) -> dict:
        raise NotImplementedError

    def acknowledge(self, stream_id: str, section_ack: int) -> dict:
        raise NotImplementedError

    def unblock(self, stream_id: str) -> dict:
        raise NotImplementedError

    def blocked_streams(self) -> list[str]:
        raise NotImplementedError

    def table_state(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, payload: Mapping[str, object] | None) -> dict:
        raise NotImplementedError

    def metrics(self) -> dict:
        raise NotImplementedError
