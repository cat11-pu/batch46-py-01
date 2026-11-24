"""SCTP chunk parsing and AUTH verification guard."""

from __future__ import annotations

import hashlib
import hmac
import struct
import threading
from collections import deque
from typing import Any


STATE_VERSION = 1
KNOWN_CHUNK_TYPES = frozenset(range(12)) | {14, 15}
AUTH_CHUNK_TYPE = 15
AUTH_PAYLOAD_SIZE = 24


class SctpError(ValueError):
    def __init__(self, code: str, detail: str | None = None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class SctpGuard:
    """Parses SCTP bundles, verifies AUTH chunks and bounds the replay cache."""

    def __init__(self, *, max_chunks: int = 16, max_bundle_bytes: int = 1200,
                 replay_window: int = 256, key_grace: float = 300.0) -> None:
        self.max_chunks = max_chunks
        self.max_bundle_bytes = max_bundle_bytes
        self.replay_window = replay_window
        self.key_grace = key_grace

        self._lock = threading.RLock()
        self._keys: dict[int, dict[str, Any]] = {}
        self._active_key_id: int | None = None
        self._replay: dict[str, deque[str]] = {}
        self._parsed_bundles = 0
        self._verified = 0
        self._rejected = 0
        self._replayed = 0
        self._codes: dict[str, int] = {}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _error(self, code: str, detail: str | None = None, *,
               reject: bool = False) -> None:
        if reject:
            self._rejected += 1
            self._codes[code] = self._codes.get(code, 0) + 1
            if code == "SCTP_REPLAY":
                self._replayed += 1
        raise SctpError(code, detail)

    @staticmethod
    def _key_meta(key_id: int, entry: dict[str, Any]) -> dict[str, Any]:
        return {
            "key_id": key_id,
            "active": bool(entry["active"]),
            "added_at": entry["added_at"],
            "retired_at": entry["retired_at"],
        }

    def _retire_active(self, now: float) -> int | None:
        old_id = self._active_key_id
        if old_id is None:
            return None
        old = self._keys.get(old_id)
        if old is not None:
            old["active"] = False
            old["retired_at"] = now
        self._active_key_id = None
        return old_id

    # ------------------------------------------------------------------
    # Key table
    # ------------------------------------------------------------------
    def add_key(self, key_id: int, key: bytes, *, active: bool = False,
                now: float = 0.0) -> dict:
        with self._lock:
            if (not isinstance(key_id, int) or isinstance(key_id, bool)
                    or not 0 <= key_id <= 0xFFFF):
                self._error("SCTP_BAD_KEY_ID")
            if not isinstance(key, (bytes, bytearray, memoryview)):
                self._error("SCTP_BAD_KEY")
            key_bytes = bytes(key)
            if not 16 <= len(key_bytes) <= 64:
                self._error("SCTP_BAD_KEY")
            if key_id in self._keys:
                self._error("SCTP_KEY_CONFLICT")

            is_first = not self._keys
            if active or is_first:
                self._retire_active(now)

            entry = {
                "key": key_bytes,
                "active": bool(active or is_first),
                "added_at": now,
                "retired_at": None,
            }
            self._keys[key_id] = entry
            if entry["active"]:
                self._active_key_id = key_id
            return self._key_meta(key_id, entry)

    def rotate_key(self, key_id: int, *, now: float = 0.0) -> dict:
        with self._lock:
            if (not isinstance(key_id, int) or isinstance(key_id, bool)
                    or not 0 <= key_id <= 0xFFFF):
                self._error("SCTP_BAD_KEY_ID")
            entry = self._keys.get(key_id)
            if entry is None:
                self._error("SCTP_UNKNOWN_KEY")

            previous = self._active_key_id
            changed = previous != key_id
            if changed:
                self._retire_active(now)
                entry["active"] = True
                entry["retired_at"] = None
                self._active_key_id = key_id

            result = self._key_meta(key_id, entry)
            result["changed"] = changed
            result["previous_key_id"] = previous
            return result

    def remove_key(self, key_id: int, *, now: float = 0.0) -> bool:
        del now
        with self._lock:
            entry = self._keys.pop(key_id, None)
            if entry is None:
                return False
            if self._active_key_id == key_id:
                self._active_key_id = None
            return True

    def active_key_id(self) -> int | None:
        with self._lock:
            return self._active_key_id

    def keys(self) -> list[dict]:
        with self._lock:
            return [
                self._key_meta(key_id, self._keys[key_id])
                for key_id in sorted(self._keys)
            ]

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------
    def parse_bundle(self, raw: bytes) -> list[dict]:
        with self._lock:
            if len(raw) > self.max_bundle_bytes:
                self._error("SCTP_BUNDLE_TOO_LARGE")

            chunks: list[dict] = []
            offset = 0
            total = len(raw)
            while offset < total:
                if len(chunks) >= self.max_chunks:
                    self._error("SCTP_CHUNK_LIMIT")
                if total - offset < 4:
                    self._error("SCTP_TRUNCATED")

                chunk_type, flags, length = struct.unpack_from(
                    "!BBH", raw, offset
                )
                if length < 4:
                    self._error("SCTP_BAD_LENGTH")

                padded = (length + 3) & ~3
                if total - offset < length or total - offset < padded:
                    self._error("SCTP_TRUNCATED")

                payload = raw[offset + 4:offset + length]
                padding = raw[offset + length:offset + padded]
                if any(padding):
                    self._error("SCTP_BAD_PADDING")

                chunks.append({
                    "type": chunk_type,
                    "flags": flags,
                    "length": length,
                    "payload": payload,
                    "raw": raw[offset:offset + padded],
                })
                offset += padded

            self._parsed_bundles += 1
            return chunks

    # ------------------------------------------------------------------
    # Verification and replay protection
    # ------------------------------------------------------------------
    def verify(self, chunks: list[dict], *, assoc: str,
               now: float = 0.0) -> dict:
        with self._lock:
            auth_indices = [
                index for index, chunk in enumerate(chunks)
                if chunk.get("type") == AUTH_CHUNK_TYPE
            ]
            if not auth_indices:
                self._error("SCTP_NO_AUTH", reject=True)
            if len(auth_indices) > 1:
                self._error("SCTP_AUTH_DUP", reject=True)
            auth_index = auth_indices[0]
            if auth_index != 0:
                self._error("SCTP_AUTH_NOT_FIRST", reject=True)

            auth = chunks[0]
            payload = auth.get("payload", b"")
            if len(payload) != AUTH_PAYLOAD_SIZE:
                self._error("SCTP_AUTH_FORMAT", reject=True)
            key_id, hmac_id = struct.unpack_from("!HH", payload, 0)
            if hmac_id != 1:
                self._error("SCTP_AUTH_FORMAT", reject=True)
            received = payload[4:24]

            entry = self._keys.get(key_id)
            if entry is None:
                self._error("SCTP_UNKNOWN_KEY", reject=True)
            if self._active_key_id is None:
                self._error("SCTP_NO_ACTIVE_KEY", reject=True)

            active = bool(entry["active"])
            retired_at = entry["retired_at"]
            if not active:
                if retired_at is None:
                    self._error("SCTP_KEY_INACTIVE", reject=True)
                if now - retired_at > self.key_grace:
                    self._error("SCTP_KEY_EXPIRED", reject=True)

            signed = b"".join(
                chunk.get("raw", b"") for chunk in chunks[1:]
            )
            expected = hmac.new(entry["key"], signed, hashlib.sha1).digest()
            if not hmac.compare_digest(expected, received):
                self._error("SCTP_BAD_SIGNATURE", reject=True)

            reported: list[int] = []
            for chunk in chunks[1:]:
                chunk_type = chunk.get("type")
                if chunk_type in KNOWN_CHUNK_TYPES:
                    continue
                action = chunk.get("flags", 0) & 0xC0
                if action == 0xC0:
                    self._error("SCTP_UNKNOWN_ABORT", reject=True)
                if action == 0x80:
                    self._error("SCTP_UNKNOWN_ERROR", reject=True)
                if action == 0x40:
                    reported.append(chunk_type)

            digest_hex = received.hex()
            history = self._replay.get(assoc)
            if history is not None and digest_hex in history:
                self._error("SCTP_REPLAY", reject=True)

            if history is None:
                history = deque(maxlen=max(0, self.replay_window))
                self._replay[assoc] = history
            history.append(digest_hex)
            if not history:
                self._replay.pop(assoc, None)

            self._verified += 1
            return {
                "status": "accepted",
                "code": None,
                "assoc": assoc,
                "key_id": key_id,
                "chunk_count": len(chunks),
                "auth_index": auth_index,
                "reported": reported,
                "replay_entries": len(history),
            }

    def replay_count(self, assoc: str) -> int:
        with self._lock:
            history = self._replay.get(assoc)
            return len(history) if history is not None else 0

    def clear_replay(self, assoc: str) -> int:
        with self._lock:
            history = self._replay.pop(assoc, None)
            return len(history) if history is not None else 0

    # ------------------------------------------------------------------
    # Statistics and persistence
    # ------------------------------------------------------------------
    def stats(self) -> dict:
        with self._lock:
            return {
                "parsed_bundles": self._parsed_bundles,
                "verified": self._verified,
                "rejected": self._rejected,
                "replayed": self._replayed,
                "keys": len(self._keys),
                "replay_entries": sum(
                    len(history) for history in self._replay.values()
                ),
                "codes": dict(self._codes),
            }

    def snapshot(self) -> dict:
        with self._lock:
            keys = {
                str(key_id): {
                    "key_id": key_id,
                    "key_hex": entry["key"].hex(),
                    "active": bool(entry["active"]),
                    "added_at": entry["added_at"],
                    "retired_at": entry["retired_at"],
                }
                for key_id, entry in self._keys.items()
            }
            return {
                "version": STATE_VERSION,
                "keys": keys,
                "active_key_id": self._active_key_id,
                "replay": {
                    assoc: list(history)
                    for assoc, history in self._replay.items()
                },
                "counters": {
                    "parsed_bundles": self._parsed_bundles,
                    "verified": self._verified,
                    "rejected": self._rejected,
                    "replayed": self._replayed,
                    "codes": dict(self._codes),
                },
            }

    def restore(self, state: dict) -> None:
        with self._lock:
            if not isinstance(state, dict) or state.get("version") != STATE_VERSION:
                self._error("SCTP_STATE_VERSION")

            keys: dict[int, dict[str, Any]] = {}
            raw_keys = state.get("keys", {})
            if isinstance(raw_keys, dict):
                key_items = raw_keys.items()
            else:
                key_items = (
                    (str(item.get("key_id")), item) for item in raw_keys
                )

            for raw_id, raw_entry in key_items:
                if not isinstance(raw_entry, dict):
                    self._error("SCTP_BAD_KEY")
                key_id = int(raw_entry.get("key_id", raw_id))
                if not 0 <= key_id <= 0xFFFF:
                    self._error("SCTP_BAD_KEY_ID")
                key_hex = raw_entry.get("key_hex", "")
                try:
                    key_bytes = bytes.fromhex(key_hex)
                except (TypeError, ValueError):
                    self._error("SCTP_BAD_KEY")
                if not 16 <= len(key_bytes) <= 64:
                    self._error("SCTP_BAD_KEY")
                keys[key_id] = {
                    "key": key_bytes,
                    "active": bool(raw_entry.get("active", False)),
                    "added_at": raw_entry.get("added_at", 0.0),
                    "retired_at": raw_entry.get("retired_at"),
                }

            active_key_id = state.get("active_key_id")
            if active_key_id is not None:
                active_key_id = int(active_key_id)

            replay: dict[str, deque[str]] = {}
            maxlen = max(0, self.replay_window)
            for assoc, history in state.get("replay", {}).items():
                items = [str(item) for item in history]
                if maxlen == 0:
                    items = []
                elif len(items) > maxlen:
                    items = items[-maxlen:]
                if items:
                    replay[str(assoc)] = deque(items, maxlen=maxlen)

            counters = state.get("counters", {})
            self._keys = keys
            self._active_key_id = active_key_id
            self._replay = replay
            self._parsed_bundles = int(counters.get("parsed_bundles", 0))
            self._verified = int(counters.get("verified", 0))
            self._rejected = int(counters.get("rejected", 0))
            self._replayed = int(counters.get("replayed", 0))
            self._codes = {
                str(code): int(count)
                for code, count in counters.get("codes", {}).items()
            }
