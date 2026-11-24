"""MPLS label stack validation guard."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

MAX_LABEL = (1 << 20) - 1
RESERVED_LABELS = frozenset(range(0, 16))
NULL_LABELS = frozenset({0, 3})
ENTROPY_LABEL = 7


class MplsError(ValueError):
    def __init__(self, code: str, detail: str | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class MplsGuard:
    MAX_LABEL = MAX_LABEL
    RESERVED_LABELS = RESERVED_LABELS

    def __init__(self, *, max_depth: int = 8, max_sessions: int = 64) -> None:
        self.max_depth = max_depth
        self.max_sessions = max_sessions

    def register_tenant(self, tenant: str, *, label_min: int = 16,
                        label_max: int = MAX_LABEL,
                        max_depth: int | None = None) -> dict:
        raise NotImplementedError

    def validate_stack(self, tenant: str, labels: Sequence[int]) -> dict:
        raise NotImplementedError

    def push(self, tenant: str, session: str, label: int, *,
             token: str | None = None) -> dict:
        raise NotImplementedError

    def pop(self, tenant: str, session: str, count: int = 1) -> dict:
        raise NotImplementedError

    def swap_top(self, tenant: str, session: str, label: int) -> dict:
        raise NotImplementedError

    def read_stack(self, tenant: str, session: str) -> list[int]:
        raise NotImplementedError

    def close_session(self, tenant: str, session: str) -> bool:
        raise NotImplementedError

    def audit(self, tenant: str | None = None, limit: int = 100) -> list[dict]:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, payload: Mapping[str, object] | None) -> dict:
        raise NotImplementedError

    def metrics(self) -> dict:
        raise NotImplementedError
