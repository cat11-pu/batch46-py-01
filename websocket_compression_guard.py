"""Bounded permessage-deflate context management.

The guard owns both directions of a WebSocket compression context.  Server
parameters apply to :meth:`WsCompressionGuard.compress`; client parameters
apply to :meth:`WsCompressionGuard.decompress`.  A single lock serializes
operations so each per-session context and its counters advance atomically.
"""

from __future__ import annotations

import re
import threading
import zlib
from collections import deque
from collections.abc import Mapping


WS_SESSION_INVALID = "WS_SESSION_INVALID"
WS_SESSION_MISSING = "WS_SESSION_MISSING"
WS_SESSION_EXISTS = "WS_SESSION_EXISTS"
WS_STATE_ORDER = "WS_STATE_ORDER"
WS_PARAM_INVALID = "WS_PARAM_INVALID"
WS_ALREADY_NEGOTIATED = "WS_ALREADY_NEGOTIATED"
WS_MESSAGE_TOO_LARGE = "WS_MESSAGE_TOO_LARGE"
WS_DECOMPRESS_BOMB = "WS_DECOMPRESS_BOMB"
WS_DEFLATE_INVALID = "WS_DEFLATE_INVALID"
WS_CONTEXT_FAILED = "WS_CONTEXT_FAILED"
WS_LIMIT_INVALID = "WS_LIMIT_INVALID"
WS_CONTEXT_LIMIT = "WS_CONTEXT_LIMIT"
WS_SNAPSHOT_INVALID = "WS_SNAPSHOT_INVALID"


_SYNC_MARKER = b"\x00\x00\xff\xff"
_PARAM_NAMES = (
    "server_no_context_takeover",
    "client_no_context_takeover",
    "server_max_window_bits",
    "client_max_window_bits",
)
_NCT_PARAMS = _PARAM_NAMES[:2]
_ALLOWED_PARAMS = frozenset(_PARAM_NAMES)
_DECIMAL = re.compile(r"^[0-9]+$")
_HEX = re.compile(r"^[0-9a-fA-F]*$")
_STATE_VERSION = 1
_MAX_LIMIT = 1_048_576
_DEFLATE_WINDOW = 32_768


class WsCompressionError(ValueError):
    """Validation failure carrying a stable machine-readable ``code``."""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class _Session:
    """Mutable compression state for one open session."""

    __slots__ = (
        "session",
        "max_message",
        "negotiated",
        "params",
        "request",
        "sent_messages",
        "received_messages",
        "bytes_sent",
        "bytes_received",
        "server_resets",
        "client_resets",
        "failed",
        "sent_history",
        "received_history",
        "server_reset_seq",
        "client_reset_seq",
        "sent_window",
        "received_window",
        "compressor",
        "decompressor",
    )

    def __init__(self, session, max_message, history):
        self.session = session
        self.max_message = max_message
        self.negotiated = False
        self.params = {}
        self.request = {}
        self.sent_messages = 0
        self.received_messages = 0
        self.bytes_sent = 0
        self.bytes_received = 0
        self.server_resets = 0
        self.client_resets = 0
        self.failed = False
        self.sent_history = deque(maxlen=history)
        self.received_history = deque(maxlen=history)
        self.server_reset_seq = 0
        self.client_reset_seq = 0
        self.sent_window = b""
        self.received_window = b""
        self.compressor = None
        self.decompressor = None


class WsCompressionGuard:
    """Serialize and bound permessage-deflate operations per session."""

    SNAPSHOT_VERSION = _STATE_VERSION

    def __init__(
        self,
        *,
        max_message: int = 65536,
        max_contexts: int = 16,
        history: int = 8,
    ) -> None:
        self.max_message = self._message_limit(max_message)
        if isinstance(max_contexts, bool) or not isinstance(max_contexts, int):
            raise WsCompressionError(
                WS_LIMIT_INVALID, "max_contexts must be a non-negative integer"
            )
        if max_contexts < 0:
            raise WsCompressionError(
                WS_LIMIT_INVALID, "max_contexts must be non-negative"
            )
        if isinstance(history, bool) or not isinstance(history, int):
            raise WsCompressionError(
                WS_LIMIT_INVALID, "history must be a non-negative integer"
            )
        if history < 0:
            raise WsCompressionError(
                WS_LIMIT_INVALID, "history must be non-negative"
            )

        self.max_contexts = max_contexts
        self.history = history
        self._sessions = {}
        self._metric_sent_messages = 0
        self._metric_received_messages = 0
        self._metric_bytes_sent = 0
        self._metric_bytes_received = 0
        self._metric_resets = 0
        self._metric_failures = 0
        self._metric_duplicates = 0
        self._lock = threading.RLock()

    @staticmethod
    def _message_limit(value):
        if isinstance(value, bool) or not isinstance(value, int):
            raise WsCompressionError(
                WS_LIMIT_INVALID, "max_message must be an integer"
            )
        if not 1 <= value <= _MAX_LIMIT:
            raise WsCompressionError(
                WS_LIMIT_INVALID,
                "max_message must be between 1 and %d" % _MAX_LIMIT,
            )
        return value

    @staticmethod
    def _session_id(session):
        if not isinstance(session, str) or not session:
            raise WsCompressionError(
                WS_SESSION_INVALID, "session id must be a non-empty string"
            )
        return session

    def _require(self, session):
        session = self._session_id(session)
        state = self._sessions.get(session)
        if state is None:
            raise WsCompressionError(
                WS_SESSION_MISSING, "session is not open"
            )
        return state

    @staticmethod
    def _params_for_negotiation(params):
        if not isinstance(params, Mapping):
            raise WsCompressionError(
                WS_PARAM_INVALID, "negotiation parameters must be a mapping"
            )
        request = {}
        try:
            items = list(params.items())
        except Exception as exc:
            raise WsCompressionError(
                WS_PARAM_INVALID, "invalid negotiation parameters"
            ) from exc

        for key, value in items:
            if not isinstance(key, str) or key not in _ALLOWED_PARAMS:
                raise WsCompressionError(
                    WS_PARAM_INVALID, "unknown parameter %r" % (key,)
                )
            if key in _NCT_PARAMS:
                if type(value) is not bool:
                    raise WsCompressionError(
                        WS_PARAM_INVALID,
                        "%s must be a boolean" % key,
                    )
                request[key] = value
                continue

            parsed = None
            if isinstance(value, str):
                text = value.strip()
                if _DECIMAL.fullmatch(text):
                    parsed = int(text, 10)
            elif isinstance(value, int) and not isinstance(value, bool):
                parsed = value
            if parsed is None or not 8 <= parsed <= 15:
                raise WsCompressionError(
                    WS_PARAM_INVALID,
                    "%s must be an integer from 8 through 15" % key,
                )
            request[key] = parsed
        return request

    @staticmethod
    def _effective_params(request):
        return {
            "server_no_context_takeover": request.get(
                "server_no_context_takeover", False
            ),
            "client_no_context_takeover": request.get(
                "client_no_context_takeover", False
            ),
            "server_max_window_bits": request.get(
                "server_max_window_bits", 15
            ),
            "client_max_window_bits": request.get(
                "client_max_window_bits", 15
            ),
        }

    @staticmethod
    def _response(request):
        parts = ["permessage-deflate"]
        if request.get("server_no_context_takeover", False):
            parts.append("server_no_context_takeover")
        if request.get("client_no_context_takeover", False):
            parts.append("client_no_context_takeover")
        if "server_max_window_bits" in request:
            parts.append(
                "server_max_window_bits=%d"
                % request["server_max_window_bits"]
            )
        if "client_max_window_bits" in request:
            parts.append(
                "client_max_window_bits=%d"
                % request["client_max_window_bits"]
            )
        return "; ".join(parts)

    @staticmethod
    def _zlib_bits(bits):
        return 9 if bits == 8 else bits

    def _new_compressor(self, state):
        return zlib.compressobj(
            level=zlib.Z_DEFAULT_COMPRESSION,
            wbits=-self._zlib_bits(state.params["server_max_window_bits"]),
        )

    def _new_decompressor(self, state):
        return zlib.decompressobj(
            wbits=-self._zlib_bits(state.params["client_max_window_bits"])
        )

    def _install_contexts(self, state):
        state.compressor = self._new_compressor(state)
        state.decompressor = self._new_decompressor(state)

    @staticmethod
    def _append_window(window, data):
        if not data:
            return window
        if len(data) >= _DEFLATE_WINDOW:
            return data[-_DEFLATE_WINDOW:]
        return (window + data)[-_DEFLATE_WINDOW:]

    @staticmethod
    def _state_dict(state):
        params = dict(state.params) if state.negotiated else {}
        return {
            "params": params,
            "server_resets": state.server_resets,
            "client_resets": state.client_resets,
            "resets": state.server_resets + state.client_resets,
            "failed": state.failed,
            "max_message": state.max_message,
            "sent_messages": state.sent_messages,
            "received_messages": state.received_messages,
        }

    def open_session(self, session: str) -> dict:
        """Open one session and reserve its compression context."""
        with self._lock:
            session = self._session_id(session)
            if session in self._sessions:
                raise WsCompressionError(
                    WS_SESSION_EXISTS, "session is already open"
                )
            if len(self._sessions) >= self.max_contexts:
                raise WsCompressionError(
                    WS_CONTEXT_LIMIT, "compression context limit reached"
                )
            self._sessions[session] = _Session(
                session, self.max_message, self.history
            )
            return {
                "session": session,
                "status": "opened",
                "max_message": self.max_message,
                "contexts": len(self._sessions),
            }

    def negotiate(self, session: str, params: Mapping[str, object]) -> dict:
        """Negotiate compression parameters and create both contexts."""
        with self._lock:
            state = self._require(session)
            request = self._params_for_negotiation(params)

            if state.negotiated:
                if request == state.request:
                    self._metric_duplicates += 1
                    return {
                        "session": state.session,
                        "status": "duplicate",
                        "response": self._response(request),
                        "params": dict(state.params),
                    }
                raise WsCompressionError(
                    WS_ALREADY_NEGOTIATED,
                    "session already negotiated different parameters",
                )

            effective = self._effective_params(request)
            state.request = dict(request)
            state.params = effective
            state.negotiated = True
            state.failed = False
            state.server_reset_seq = state.sent_messages
            state.client_reset_seq = state.received_messages
            self._install_contexts(state)
            return {
                "session": state.session,
                "status": "negotiated",
                "response": self._response(request),
                "params": dict(effective),
            }

    def compress(self, session: str, payload: bytes) -> bytes:
        """Compress one message using raw DEFLATE without its flush marker."""
        with self._lock:
            state = self._require(session)
            if not state.negotiated:
                raise WsCompressionError(
                    WS_STATE_ORDER, "compression has not been negotiated"
                )
            if state.failed:
                raise WsCompressionError(
                    WS_CONTEXT_FAILED, "compression context has failed"
                )
            if not isinstance(payload, (bytes, bytearray, memoryview)):
                raise WsCompressionError(
                    WS_MESSAGE_TOO_LARGE, "payload must be bytes-like"
                )
            payload = bytes(payload)

            candidate = state.compressor.copy()
            try:
                compressed = candidate.compress(payload)
                compressed += candidate.flush(zlib.Z_SYNC_FLUSH)
            except zlib.error as exc:
                raise WsCompressionError(
                    WS_DEFLATE_INVALID, "compression failed"
                ) from exc
            if compressed.endswith(_SYNC_MARKER):
                wire = compressed[: -len(_SYNC_MARKER)]
            else:
                wire = compressed
            if len(wire) > state.max_message:
                raise WsCompressionError(
                    WS_MESSAGE_TOO_LARGE,
                    "compressed message exceeds session limit",
                )

            state.compressor = candidate
            state.sent_messages += 1
            state.bytes_sent += len(wire)
            state.sent_history.append(payload)
            state.sent_window = self._append_window(
                state.sent_window, payload
            )
            self._metric_sent_messages += 1
            self._metric_bytes_sent += len(wire)

            if state.params["server_no_context_takeover"]:
                state.compressor = self._new_compressor(state)
                state.sent_window = b""
                state.server_resets += 1
                state.server_reset_seq = state.sent_messages
                self._metric_resets += 1
            return wire

    def _mark_failed(self, state):
        if not state.failed:
            state.failed = True
            self._metric_failures += 1

    def decompress(self, session: str, data: bytes) -> bytes:
        """Inflate one message and reject expansion or framing violations."""
        with self._lock:
            state = self._require(session)
            if not state.negotiated:
                raise WsCompressionError(
                    WS_STATE_ORDER, "compression has not been negotiated"
                )
            if state.failed:
                raise WsCompressionError(
                    WS_CONTEXT_FAILED, "decompression context has failed"
                )
            if not isinstance(data, (bytes, bytearray, memoryview)):
                self._mark_failed(state)
                raise WsCompressionError(
                    WS_DEFLATE_INVALID, "compressed data must be bytes-like"
                )
            wire = bytes(data)
            try:
                output = state.decompressor.decompress(
                    wire + _SYNC_MARKER,
                    state.max_message + 1,
                )
            except zlib.error as exc:
                self._mark_failed(state)
                raise WsCompressionError(
                    WS_DEFLATE_INVALID, "invalid deflate stream"
                ) from exc

            if (
                len(output) > state.max_message
                or state.decompressor.unconsumed_tail
                or state.decompressor.unused_data
            ):
                self._mark_failed(state)
                raise WsCompressionError(
                    WS_DECOMPRESS_BOMB,
                    "decompressed message exceeds limit or has trailing input",
                )

            state.received_messages += 1
            state.bytes_received += len(wire)
            state.received_history.append(wire)
            state.received_window = self._append_window(
                state.received_window, output
            )
            self._metric_received_messages += 1
            self._metric_bytes_received += len(wire)

            if state.params["client_no_context_takeover"]:
                state.decompressor = self._new_decompressor(state)
                state.received_window = b""
                state.client_resets += 1
                state.client_reset_seq = state.received_messages
                self._metric_resets += 1
            return output

    def context_state(self, session: str) -> dict:
        """Return a copy of one session's observable compression state."""
        with self._lock:
            return self._state_dict(self._require(session))

    def set_limit(self, session: str, max_message: int) -> dict:
        """Change the maximum message size for only one session."""
        with self._lock:
            state = self._require(session)
            limit = self._message_limit(max_message)
            state.max_message = limit
            result = self._state_dict(state)
            result["status"] = "updated"
            return result

    def reset_context(self, session: str) -> dict:
        """Clear a failure and rebuild both directions of the context."""
        with self._lock:
            state = self._require(session)
            if not state.negotiated:
                raise WsCompressionError(
                    WS_STATE_ORDER, "compression has not been negotiated"
                )
            state.failed = False
            state.server_reset_seq = state.sent_messages
            state.client_reset_seq = state.received_messages
            state.sent_window = b""
            state.received_window = b""
            self._install_contexts(state)
            state.server_resets += 1
            state.client_resets += 1
            self._metric_resets += 2
            result = self._state_dict(state)
            result["status"] = "reset"
            return result

    def close_session(self, session: str) -> bool:
        """Close a session; return whether it was actually open."""
        with self._lock:
            session = self._session_id(session)
            return self._sessions.pop(session, None) is not None

    def inflight(self) -> list[str]:
        """Return the currently open session ids in deterministic order."""
        with self._lock:
            return sorted(self._sessions)

    @staticmethod
    def _hex_history(entries):
        return [entry.hex() for entry in entries]

    def snapshot(self) -> dict:
        """Serialize active sessions and cumulative metrics."""
        with self._lock:
            sessions = {}
            for session, state in self._sessions.items():
                sessions[session] = {
                    "max_message": state.max_message,
                    "negotiated": state.negotiated,
                    "params": dict(state.params),
                    "request": dict(state.request),
                    "sent_messages": state.sent_messages,
                    "received_messages": state.received_messages,
                    "bytes_sent": state.bytes_sent,
                    "bytes_received": state.bytes_received,
                    "server_resets": state.server_resets,
                    "client_resets": state.client_resets,
                    "server_reset_seq": state.server_reset_seq,
                    "client_reset_seq": state.client_reset_seq,
                    "sent_window": state.sent_window.hex(),
                    "received_window": state.received_window.hex(),
                    "failed": state.failed,
                    "sent_history": self._hex_history(state.sent_history),
                    "received_history": self._hex_history(
                        state.received_history
                    ),
                }
            return {
                "version": _STATE_VERSION,
                "sessions": sessions,
                "metrics": self._metrics_locked(),
            }

    @staticmethod
    def _count(value):
        return isinstance(value, int) and not isinstance(value, bool) and value >= 0

    @classmethod
    def _snapshot_bytes(cls, encoded, limit=None):
        if not isinstance(encoded, str) or len(encoded) % 2:
            raise WsCompressionError(
                WS_SNAPSHOT_INVALID, "history entries must be even-length hex"
            )
        if _HEX.fullmatch(encoded) is None:
            raise WsCompressionError(
                WS_SNAPSHOT_INVALID, "history contains invalid hex"
            )
        try:
            raw = bytes.fromhex(encoded)
        except ValueError as exc:
            raise WsCompressionError(
                WS_SNAPSHOT_INVALID, "history contains invalid hex"
            ) from exc
        if limit is not None and len(raw) > limit:
            raise WsCompressionError(
                WS_SNAPSHOT_INVALID, "history entry exceeds session limit"
            )
        return raw

    @classmethod
    def _snapshot_params(cls, raw):
        if not isinstance(raw, Mapping):
            raise WsCompressionError(
                WS_SNAPSHOT_INVALID, "session params must be a mapping"
            )
        request = {}
        for key, value in raw.items():
            if not isinstance(key, str) or key not in _ALLOWED_PARAMS:
                raise WsCompressionError(
                    WS_SNAPSHOT_INVALID, "unknown snapshot parameter"
                )
            if key in _NCT_PARAMS:
                if type(value) is not bool:
                    raise WsCompressionError(
                        WS_SNAPSHOT_INVALID, "invalid snapshot boolean"
                    )
            else:
                if (
                    isinstance(value, bool)
                    or not isinstance(value, int)
                    or not 8 <= value <= 15
                ):
                    raise WsCompressionError(
                        WS_SNAPSHOT_INVALID, "invalid snapshot window bits"
                    )
            request[key] = value
        return request

    def _restore_session(self, session, raw):
        if not isinstance(raw, Mapping):
            raise WsCompressionError(
                WS_SNAPSHOT_INVALID, "session snapshot must be a mapping"
            )
        max_message = self._message_limit(raw.get("max_message"))
        negotiated = raw.get("negotiated")
        if type(negotiated) is not bool:
            raise WsCompressionError(
                WS_SNAPSHOT_INVALID, "negotiated must be a boolean"
            )

        request = self._snapshot_params(raw.get("request", {}))
        params_raw = raw.get("params", {})
        params = self._snapshot_params(params_raw)
        if negotiated:
            expected = self._effective_params(request)
            if params != expected:
                raise WsCompressionError(
                    WS_SNAPSHOT_INVALID,
                    "effective params do not match the negotiation request",
                )
        elif request or params:
            raise WsCompressionError(
                WS_SNAPSHOT_INVALID,
                "unnegotiated session cannot carry compression parameters",
            )

        counters = {}
        for name in (
            "sent_messages",
            "received_messages",
            "bytes_sent",
            "bytes_received",
            "server_resets",
            "client_resets",
            "server_reset_seq",
            "client_reset_seq",
        ):
            value = raw.get(name)
            if not self._count(value):
                raise WsCompressionError(
                    WS_SNAPSHOT_INVALID, "%s must be a non-negative integer" % name
                )
            counters[name] = value
        if counters["server_reset_seq"] > counters["sent_messages"]:
            raise WsCompressionError(
                WS_SNAPSHOT_INVALID, "server reset sequence is out of range"
            )
        if counters["client_reset_seq"] > counters["received_messages"]:
            raise WsCompressionError(
                WS_SNAPSHOT_INVALID, "client reset sequence is out of range"
            )

        failed = raw.get("failed")
        if type(failed) is not bool:
            raise WsCompressionError(
                WS_SNAPSHOT_INVALID, "failed must be a boolean"
            )

        sent_encoded = raw.get("sent_history")
        received_encoded = raw.get("received_history")
        if not isinstance(sent_encoded, list) or not isinstance(
            received_encoded, list
        ):
            raise WsCompressionError(
                WS_SNAPSHOT_INVALID, "history must be a list"
            )
        if len(sent_encoded) > self.history or len(received_encoded) > self.history:
            raise WsCompressionError(
                WS_SNAPSHOT_INVALID, "history exceeds configured capacity"
            )
        if len(sent_encoded) > counters["sent_messages"]:
            raise WsCompressionError(
                WS_SNAPSHOT_INVALID, "sent history is longer than its counter"
            )
        if len(received_encoded) > counters["received_messages"]:
            raise WsCompressionError(
                WS_SNAPSHOT_INVALID,
                "received history is longer than its counter",
            )
        if len(sent_encoded) != min(
            self.history, counters["sent_messages"]
        ):
            raise WsCompressionError(
                WS_SNAPSHOT_INVALID, "sent history has an invalid length"
            )
        if len(received_encoded) != min(
            self.history, counters["received_messages"]
        ):
            raise WsCompressionError(
                WS_SNAPSHOT_INVALID,
                "received history has an invalid length",
            )

        sent_plain = [
            self._snapshot_bytes(item) for item in sent_encoded
        ]
        received_wire = [
            self._snapshot_bytes(item) for item in received_encoded
        ]
        if counters["bytes_received"] < sum(
            len(item) for item in received_wire
        ):
            raise WsCompressionError(
                WS_SNAPSHOT_INVALID,
                "received byte count is smaller than retained history",
            )
        sent_window = self._snapshot_bytes(
            raw.get("sent_window"), _DEFLATE_WINDOW
        )
        received_window = self._snapshot_bytes(
            raw.get("received_window"), _DEFLATE_WINDOW
        )
        if (
            params.get("server_no_context_takeover", False)
            and sent_window
        ):
            raise WsCompressionError(
                WS_SNAPSHOT_INVALID,
                "no-context-takeover session has a stale send window",
            )
        if (
            params.get("client_no_context_takeover", False)
            and received_window
        ):
            raise WsCompressionError(
                WS_SNAPSHOT_INVALID,
                "no-context-takeover session has a stale receive window",
            )
        if not negotiated and (
            sent_window
            or received_window
            or failed
            or any(counters.values())
            or sent_plain
            or received_wire
        ):
            raise WsCompressionError(
                WS_SNAPSHOT_INVALID,
                "unnegotiated session carries unexpected state",
            )
        if (
            params.get("server_no_context_takeover", False)
            and counters["server_reset_seq"] != counters["sent_messages"]
        ):
            raise WsCompressionError(
                WS_SNAPSHOT_INVALID,
                "server reset sequence violates no-context-takeover",
            )
        if (
            params.get("client_no_context_takeover", False)
            and counters["client_reset_seq"]
            != counters["received_messages"]
        ):
            raise WsCompressionError(
                WS_SNAPSHOT_INVALID,
                "client reset sequence violates no-context-takeover",
            )

        state = _Session(session, max_message, self.history)
        state.negotiated = negotiated
        state.request = dict(request)
        state.params = dict(params)
        for name, value in counters.items():
            setattr(state, name, value)
        state.failed = failed
        state.sent_history.extend(sent_plain)
        state.received_history.extend(received_wire)
        state.sent_window = sent_window
        state.received_window = received_window
        if not negotiated:
            return state

        self._install_contexts(state)
        sent_start = state.sent_messages - len(sent_plain)
        sent_since_reset = (
            state.sent_messages - state.server_reset_seq
        )
        replay_sent = sent_since_reset <= len(sent_plain)
        if state.params["server_no_context_takeover"]:
            state.compressor = self._new_compressor(state)
            state.sent_window = b""
        elif replay_sent:
            replayed_window = b""
            for offset, payload in enumerate(sent_plain):
                if sent_start + offset < state.server_reset_seq:
                    continue
                state.compressor.compress(payload)
                state.compressor.flush(zlib.Z_SYNC_FLUSH)
                replayed_window = self._append_window(
                    replayed_window, payload
                )
            if replayed_window != sent_window:
                raise WsCompressionError(
                    WS_SNAPSHOT_INVALID,
                    "sent history is inconsistent with its window",
                )
        elif sent_window:
            try:
                state.compressor.compress(sent_window)
                state.compressor.flush(zlib.Z_SYNC_FLUSH)
            except zlib.error as exc:
                raise WsCompressionError(
                    WS_SNAPSHOT_INVALID,
                    "cannot rebuild the deflate context",
                ) from exc

        received_start = state.received_messages - len(received_wire)
        received_since_reset = (
            state.received_messages - state.client_reset_seq
        )
        replay_received = received_since_reset <= len(received_wire)
        if state.params["client_no_context_takeover"]:
            state.decompressor = self._new_decompressor(state)
            state.received_window = b""
        elif replay_received:
            replayed_window = b""
            for offset, wire in enumerate(received_wire):
                if received_start + offset < state.client_reset_seq:
                    continue
                try:
                    output = state.decompressor.decompress(
                        wire + _SYNC_MARKER, _MAX_LIMIT + 1
                    )
                except zlib.error as exc:
                    raise WsCompressionError(
                        WS_SNAPSHOT_INVALID,
                        "received history is not valid deflate data",
                    ) from exc
                if (
                    len(output) > _MAX_LIMIT
                    or state.decompressor.unconsumed_tail
                    or state.decompressor.unused_data
                ):
                    raise WsCompressionError(
                        WS_SNAPSHOT_INVALID,
                        "received history exceeds the allowed limit",
                    )
                replayed_window = self._append_window(
                    replayed_window, output
                )
            if replayed_window != received_window:
                raise WsCompressionError(
                    WS_SNAPSHOT_INVALID,
                    "received history is inconsistent with its window",
                )
        elif received_window:
            seed = zlib.compressobj(
                level=zlib.Z_DEFAULT_COMPRESSION,
                wbits=-self._zlib_bits(
                    state.params["client_max_window_bits"]
                ),
            )
            try:
                seed_wire = seed.compress(received_window)
                seed_wire += seed.flush(zlib.Z_SYNC_FLUSH)
                output = state.decompressor.decompress(
                    seed_wire, _DEFLATE_WINDOW + 1
                )
            except zlib.error as exc:
                raise WsCompressionError(
                    WS_SNAPSHOT_INVALID,
                    "cannot rebuild the inflate context",
                ) from exc
            if (
                output != received_window
                or state.decompressor.unconsumed_tail
                or state.decompressor.unused_data
            ):
                raise WsCompressionError(
                    WS_SNAPSHOT_INVALID,
                    "inflate context seed is invalid",
                )
        return state

    def restore(self, payload: Mapping[str, object]) -> dict:
        """Atomically replace all state from a snapshot."""
        with self._lock:
            if not isinstance(payload, Mapping):
                raise WsCompressionError(
                    WS_SNAPSHOT_INVALID, "snapshot must be a mapping"
                )
            version = payload.get("version")
            if (
                isinstance(version, bool)
                or not isinstance(version, int)
                or version != _STATE_VERSION
            ):
                raise WsCompressionError(
                    WS_SNAPSHOT_INVALID, "unsupported snapshot version"
                )
            raw_sessions = payload.get("sessions")
            if not isinstance(raw_sessions, Mapping):
                raise WsCompressionError(
                    WS_SNAPSHOT_INVALID, "sessions must be a mapping"
                )
            if len(raw_sessions) > self.max_contexts:
                raise WsCompressionError(
                    WS_SNAPSHOT_INVALID, "snapshot exceeds context capacity"
                )

            metrics = payload.get("metrics")
            if not isinstance(metrics, Mapping):
                raise WsCompressionError(
                    WS_SNAPSHOT_INVALID, "metrics must be a mapping"
                )
            required_metrics = (
                "contexts",
                "negotiated",
                "sent_messages",
                "received_messages",
                "bytes_sent",
                "bytes_received",
                "resets",
                "failures",
                "duplicates",
            )
            checked_metrics = {}
            for name in required_metrics:
                value = metrics.get(name)
                if not self._count(value):
                    raise WsCompressionError(
                        WS_SNAPSHOT_INVALID,
                        "metric %s must be a non-negative integer" % name,
                    )
                checked_metrics[name] = value

            rebuilt = {}
            for session, raw in raw_sessions.items():
                try:
                    session = self._session_id(session)
                except WsCompressionError as exc:
                    raise WsCompressionError(
                        WS_SNAPSHOT_INVALID, "invalid session id in snapshot"
                    ) from exc
                if session in rebuilt:
                    raise WsCompressionError(
                        WS_SNAPSHOT_INVALID, "duplicate session id"
                    )
                try:
                    rebuilt[session] = self._restore_session(session, raw)
                except WsCompressionError as exc:
                    if exc.code == WS_SNAPSHOT_INVALID:
                        raise
                    raise WsCompressionError(
                        WS_SNAPSHOT_INVALID,
                        "invalid session state in snapshot",
                    ) from exc

            negotiated = sum(
                1 for state in rebuilt.values() if state.negotiated
            )
            active_bytes_sent = sum(
                state.bytes_sent for state in rebuilt.values()
            )
            active_bytes_received = sum(
                state.bytes_received for state in rebuilt.values()
            )
            active_resets = sum(
                state.server_resets + state.client_resets
                for state in rebuilt.values()
            )
            failed_sessions = sum(
                1 for state in rebuilt.values() if state.failed
            )
            if (
                checked_metrics["contexts"] != len(rebuilt)
                or checked_metrics["negotiated"] != negotiated
                or checked_metrics["sent_messages"]
                < sum(state.sent_messages for state in rebuilt.values())
                or checked_metrics["received_messages"]
                < sum(
                    state.received_messages for state in rebuilt.values()
                )
                or checked_metrics["bytes_sent"] < active_bytes_sent
                or checked_metrics["bytes_received"] < active_bytes_received
                or checked_metrics["resets"] < active_resets
                or checked_metrics["failures"] < failed_sessions
            ):
                raise WsCompressionError(
                    WS_SNAPSHOT_INVALID,
                    "snapshot metrics do not match its sessions",
                )

            self._sessions = rebuilt
            self._metric_sent_messages = checked_metrics["sent_messages"]
            self._metric_received_messages = checked_metrics[
                "received_messages"
            ]
            self._metric_bytes_sent = checked_metrics["bytes_sent"]
            self._metric_bytes_received = checked_metrics["bytes_received"]
            self._metric_resets = checked_metrics["resets"]
            self._metric_failures = checked_metrics["failures"]
            self._metric_duplicates = checked_metrics["duplicates"]
            return {
                "status": "restored",
                "restored": len(rebuilt),
                "contexts": len(rebuilt),
            }

    def _metrics_locked(self):
        return {
            "contexts": len(self._sessions),
            "negotiated": sum(
                1 for state in self._sessions.values() if state.negotiated
            ),
            "sent_messages": self._metric_sent_messages,
            "received_messages": self._metric_received_messages,
            "bytes_sent": self._metric_bytes_sent,
            "bytes_received": self._metric_bytes_received,
            "resets": self._metric_resets,
            "failures": self._metric_failures,
            "duplicates": self._metric_duplicates,
        }

    def metrics(self) -> dict:
        """Return cumulative compression metrics."""
        with self._lock:
            return self._metrics_locked()
