"""WebSocket permessage-deflate context guard."""

from __future__ import annotations

from collections.abc import Mapping

TAIL = b"\x00\x00\xff\xff"
PARAM_KEYS = frozenset({
    "server_no_context_takeover",
    "client_no_context_takeover",
    "server_max_window_bits",
    "client_max_window_bits",
})


class WsCompressionError(ValueError):
    def __init__(self, code: str, detail: str | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class WsCompressionGuard:
    def __init__(self, *, max_message: int = 65536, max_contexts: int = 16,
                 history: int = 8) -> None:
        self.max_message = max_message
        self.max_contexts = max_contexts
        self.history = history

    def open_session(self, session: str) -> dict:
        raise NotImplementedError

    def negotiate(self, session: str, params: Mapping[str, object] | None) -> dict:
        raise NotImplementedError

    def compress(self, session: str, payload: bytes) -> bytes:
        raise NotImplementedError

    def decompress(self, session: str, data: bytes) -> bytes:
        raise NotImplementedError

    def context_state(self, session: str) -> dict:
        raise NotImplementedError

    def set_limit(self, session: str, max_message: int) -> dict:
        raise NotImplementedError

    def reset_context(self, session: str) -> dict:
        raise NotImplementedError

    def close_session(self, session: str) -> bool:
        raise NotImplementedError

    def inflight(self) -> list[str]:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, payload: Mapping[str, object] | None) -> dict:
        raise NotImplementedError

    def metrics(self) -> dict:
        raise NotImplementedError
