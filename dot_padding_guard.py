"""DoT padding, framing and tenant-scoped connection reuse guard.

Frame layout (all integers big-endian):

    len(2) | mid(2) | payload (n) | padding option
    padding option = code(2)=12 | optlen(2) | zero bytes (optlen)

The length prefix covers everything after itself.  The whole frame is
padded with the RFC 7830 padding option (code 12) so that its total
length is a multiple of the block size (default 468, RFC 8467), using
the smallest possible amount of padding.
"""

from __future__ import annotations

import struct
import threading
import time

SNAPSHOT_VERSION = 1
PADDING_OPTION_CODE = 12
DEFAULT_BLOCK = 468
MIN_BLOCK = 16
MAX_MESSAGE_ID = 65535
MAX_WIRE_LENGTH = 0xFFFF


class DotPaddingError(ValueError):
    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


def _check_block(block: object) -> int:
    if (not isinstance(block, int)) or isinstance(block, bool) \
            or block < MIN_BLOCK or block % 4 != 0:
        raise DotPaddingError("DOT_INVALID_BLOCK", block)
    return block


def _check_message(message: object) -> tuple[int, bytes]:
    if not isinstance(message, dict):
        raise DotPaddingError("DOT_INVALID_PAYLOAD", message)
    mid = message.get("message_id")
    if (not isinstance(mid, int)) or isinstance(mid, bool) \
            or mid < 0 or mid > MAX_MESSAGE_ID:
        raise DotPaddingError("DOT_INVALID_MESSAGE_ID", mid)
    payload = message.get("payload")
    if not isinstance(payload, (bytes, bytearray)):
        raise DotPaddingError("DOT_INVALID_PAYLOAD", payload)
    return mid, bytes(payload)


def _new_conn(conn_id: str, tenant: str, peer: str, seq: int,
              now: float) -> dict:
    return {
        "conn_id": conn_id,
        "tenant": tenant,
        "peer": peer,
        "seq": seq,
        "created": now,
        "last_active": now,
        "pending": {},
        "completed": set(),
    }


class DotPaddingGuard:
    """Frame encoder/decoder plus a tenant-aware DoT connection pool."""

    COUNTER_KEYS = ("sent", "received", "duplicates", "expired", "reused",
                    "dropped", "closed", "closed_idle", "evicted")

    def __init__(self, *, block: int = DEFAULT_BLOCK,
                 max_connections: int = 8, max_pending: int = 16,
                 idle_timeout: float = 30.0, timeout: float = 5.0) -> None:
        self._block = _check_block(block)
        self._max_connections = max_connections
        self._max_pending = max_pending
        self._idle_timeout = idle_timeout
        self._timeout = timeout
        self._lock = threading.RLock()
        self._conns: dict[str, dict] = {}
        self._by_key: dict[tuple[str, str], str] = {}
        self._next_seq = 1
        self._stats = {key: 0 for key in self.COUNTER_KEYS}

    def encode(self, message: dict, *, block: int | None = None) -> bytes:
        blk = self._block if block is None else _check_block(block)
        mid, payload = _check_message(message)
        base = 2 + 2 + len(payload) + 4
        padded = ((base + blk - 1) // blk) * blk
        pad_len = padded - base
        if padded - 2 > MAX_WIRE_LENGTH:
            raise DotPaddingError("DOT_INVALID_PAYLOAD", len(payload))
        return b"".join((
            struct.pack(">H", padded - 2),
            struct.pack(">H", mid),
            payload,
            struct.pack(">HH", PADDING_OPTION_CODE, pad_len),
            b"\x00" * pad_len,
        ))

    def decode(self, frame: bytes) -> dict:
        with self._lock:
            blk = self._block
        if isinstance(frame, bytearray):
            frame = bytes(frame)
        if not isinstance(frame, bytes):
            raise DotPaddingError("DOT_INVALID_PAYLOAD", frame)
        if len(frame) < 2:
            raise DotPaddingError("DOT_LENGTH_MISMATCH", len(frame))
        (declared,) = struct.unpack(">H", frame[:2])
        if declared != len(frame) - 2:
            raise DotPaddingError("DOT_LENGTH_MISMATCH",
                                  {"declared": declared,
                                   "actual": len(frame) - 2})
        if len(frame) % blk != 0:
            raise DotPaddingError("DOT_PADDING_MISALIGNED", len(frame))
        total = len(frame)
        trailing_zeros = 0
        for byte in reversed(frame):
            if byte != 0:
                break
            trailing_zeros += 1
        not_zero = False
        # The padding option must sit at the very tail: try each candidate
        # option length N; the option starts at total - 4 - N and may not
        # overlap the 2-byte prefix or the 2-byte message id.
        for pad_len in range(0, total - 8 + 1):
            start = total - 4 - pad_len
            code, opt_len = struct.unpack(">HH", frame[start:start + 4])
            if code != PADDING_OPTION_CODE or opt_len != pad_len:
                continue
            if pad_len <= trailing_zeros:
                (mid,) = struct.unpack(">H", frame[2:4])
                return {
                    "message_id": mid,
                    "payload": frame[4:start],
                    "padding": pad_len,
                }
            not_zero = True
        if not_zero:
            raise DotPaddingError("DOT_PADDING_NOT_ZERO")
        raise DotPaddingError("DOT_PADDING_NOT_LAST")

    def open(self, tenant: str, peer: str) -> str:
        with self._lock:
            now = time.time()
            conn_id = self._by_key.get((tenant, peer))
            if conn_id is not None and conn_id in self._conns:
                self._conns[conn_id]["last_active"] = now
                self._stats["reused"] += 1
                return conn_id
            if len(self._conns) >= self._max_connections:
                idle = [c for c in self._conns.values() if not c["pending"]]
                if not idle:
                    raise DotPaddingError("DOT_CONN_LIMIT",
                                          self._max_connections)
                victim = min(idle, key=lambda c: (c["created"], c["seq"]))
                self._remove_conn(victim)
                self._stats["evicted"] += 1
            conn_id = "conn-%d" % self._next_seq
            self._next_seq += 1
            conn = _new_conn(conn_id, tenant, peer, self._next_seq, now)
            self._conns[conn_id] = conn
            self._by_key[(tenant, peer)] = conn_id
            return conn_id

    def submit(self, conn_id: str, message: dict, *,
               timeout: float | None = None) -> dict:
        with self._lock:
            conn = self._conns.get(conn_id)
            if conn is None:
                raise DotPaddingError("DOT_UNKNOWN_CONNECTION", conn_id)
            frame = self.encode(message)
            mid = message["message_id"]
            if mid in conn["pending"]:
                raise DotPaddingError("DOT_DUPLICATE_MESSAGE", mid)
            if len(conn["pending"]) >= self._max_pending:
                raise DotPaddingError("DOT_PENDING_LIMIT", self._max_pending)
            now = time.time()
            deadline = now + (self._timeout if timeout is None else timeout)
            conn["pending"][mid] = {"submitted_at": now, "deadline": deadline}
            conn["last_active"] = now
            self._stats["sent"] += 1
            return {
                "conn_id": conn_id,
                "message_id": mid,
                "frame": frame,
                "padded_to": len(frame),
                "deadline": deadline,
            }

    def complete(self, conn_id: str, frame: bytes) -> dict:
        with self._lock:
            conn = self._conns.get(conn_id)
            if conn is None:
                raise DotPaddingError("DOT_UNKNOWN_CONNECTION", conn_id)
            decoded = self.decode(frame)
            mid = decoded["message_id"]
            now = time.time()
            conn["last_active"] = now
            entry = conn["pending"].pop(mid, None)
            if entry is not None:
                conn["completed"].add(mid)
                self._stats["received"] += 1
                return {
                    "status": "ok",
                    "message_id": mid,
                    "payload": decoded["payload"],
                    "padding": decoded["padding"],
                    "wait": now - entry["submitted_at"],
                }
            for other in self._conns.values():
                if other is not conn and mid in other["pending"]:
                    raise DotPaddingError("DOT_CROSS_CONNECTION", mid)
            if mid in conn["completed"]:
                self._stats["duplicates"] += 1
                return {
                    "status": "duplicate",
                    "message_id": mid,
                    "payload": decoded["payload"],
                    "padding": decoded["padding"],
                    "wait": 0.0,
                }
            raise DotPaddingError("DOT_UNKNOWN_MESSAGE", mid)

    def close(self, conn_id: str) -> dict:
        with self._lock:
            conn = self._conns.get(conn_id)
            if conn is None:
                raise DotPaddingError("DOT_UNKNOWN_CONNECTION", conn_id)
            dropped = len(conn["pending"])
            self._remove_conn(conn)
            self._stats["dropped"] += dropped
            self._stats["closed"] += 1
            return {"conn_id": conn_id, "dropped": dropped}

    def pending(self, conn_id: str) -> list[int]:
        with self._lock:
            conn = self._conns.get(conn_id)
            if conn is None:
                raise DotPaddingError("DOT_UNKNOWN_CONNECTION", conn_id)
            return list(conn["pending"].keys())

    def sweep(self) -> dict:
        with self._lock:
            now = time.time()
            expired = 0
            for conn in self._conns.values():
                keep = {}
                for mid, entry in conn["pending"].items():
                    if entry["deadline"] < now:
                        expired += 1
                    else:
                        keep[mid] = entry
                conn["pending"] = keep
            self._stats["expired"] += expired
            closed = []
            for conn in list(self._conns.values()):
                if conn["pending"]:
                    continue
                if now - conn["last_active"] > self._idle_timeout:
                    self._remove_conn(conn)
                    closed.append(conn["conn_id"])
                    self._stats["closed_idle"] += 1
            return {"closed": closed, "expired": expired}

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": SNAPSHOT_VERSION,
                "config": {
                    "block": self._block,
                    "max_connections": self._max_connections,
                    "max_pending": self._max_pending,
                    "idle_timeout": self._idle_timeout,
                    "timeout": self._timeout,
                },
                "next_seq": self._next_seq,
                "stats": dict(self._stats),
                "connections": [
                    {
                        "conn_id": conn["conn_id"],
                        "tenant": conn["tenant"],
                        "peer": conn["peer"],
                        "seq": conn["seq"],
                        "created": conn["created"],
                        "last_active": conn["last_active"],
                        "pending": [
                            {"message_id": mid,
                             "submitted_at": entry["submitted_at"],
                             "deadline": entry["deadline"]}
                            for mid, entry in conn["pending"].items()
                        ],
                        "completed": sorted(conn["completed"]),
                    }
                    for conn in self._conns.values()
                ],
            }

    def restore(self, state: dict) -> None:
        if not isinstance(state, dict) \
                or state.get("version") != SNAPSHOT_VERSION:
            raise DotPaddingError("DOT_SNAPSHOT_VERSION",
                                  None if not isinstance(state, dict)
                                  else state.get("version"))
        try:
            config = state["config"]
            block = _check_block(config["block"])
            max_connections = int(config["max_connections"])
            max_pending = int(config["max_pending"])
            idle_timeout = float(config["idle_timeout"])
            timeout = float(config["timeout"])
            next_seq = int(state["next_seq"])
            stats = {key: int(state["stats"][key])
                     for key in self.COUNTER_KEYS}
            conns: dict[str, dict] = {}
            by_key: dict[tuple[str, str], str] = {}
            for raw in state["connections"]:
                conn = _new_conn(raw["conn_id"], raw["tenant"], raw["peer"],
                                 int(raw["seq"]), float(raw["created"]))
                conn["last_active"] = float(raw["last_active"])
                for entry in raw["pending"]:
                    mid = int(entry["message_id"])
                    conn["pending"][mid] = {
                        "submitted_at": float(entry["submitted_at"]),
                        "deadline": float(entry["deadline"]),
                    }
                conn["completed"] = {int(mid) for mid in raw["completed"]}
                conns[conn["conn_id"]] = conn
                by_key[(conn["tenant"], conn["peer"])] = conn["conn_id"]
        except DotPaddingError:
            raise
        except (KeyError, TypeError, ValueError) as exc:
            raise DotPaddingError("DOT_SNAPSHOT_CORRUPT", str(exc)) from exc
        with self._lock:
            self._block = block
            self._max_connections = max_connections
            self._max_pending = max_pending
            self._idle_timeout = idle_timeout
            self._timeout = timeout
            self._next_seq = next_seq
            self._stats = stats
            self._conns = conns
            self._by_key = by_key

    def stats(self) -> dict:
        with self._lock:
            result = dict(self._stats)
            result["connections"] = len(self._conns)
            result["pending"] = sum(len(c["pending"])
                                    for c in self._conns.values())
            return result

    def _remove_conn(self, conn: dict) -> None:
        self._conns.pop(conn["conn_id"], None)
        self._by_key.pop((conn["tenant"], conn["peer"]), None)
