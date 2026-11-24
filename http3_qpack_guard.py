"""HTTP/3 QPACK dynamic table synchronization guard.

The guard models the dynamic table and request-stream blocking state for one
HTTP/3 connection.  Table mutation, index resolution and stream bookkeeping
are serialised by a single re-entrant lock so that concurrent callers observe
one consistent table/insert-count pair.
"""

from __future__ import annotations

import copy
import threading
from collections.abc import Mapping, Sequence
from typing import Any

ENTRY_OVERHEAD = 32
STREAM_STATES = ("blocked", "ready", "acked")

QPACK_ENTRY_TOO_LARGE = "QPACK_ENTRY_TOO_LARGE"
QPACK_CAPACITY = "QPACK_CAPACITY"
QPACK_INDEX = "QPACK_INDEX"
QPACK_EVICTED = "QPACK_EVICTED"
QPACK_BLOCKED = "QPACK_BLOCKED"
QPACK_BLOCK_INVALID = "QPACK_BLOCK_INVALID"
QPACK_BLOCKED_LIMIT = "QPACK_BLOCKED_LIMIT"
QPACK_NOT_READY = "QPACK_NOT_READY"
QPACK_STREAM_UNKNOWN = "QPACK_STREAM_UNKNOWN"
QPACK_ACK_INVALID = "QPACK_ACK_INVALID"
QPACK_STREAM_EXISTS = "QPACK_STREAM_EXISTS"
QPACK_SNAPSHOT_INVALID = "QPACK_SNAPSHOT_INVALID"
QPACK_DECOMPRESSION_FAILED = "QPACK_DECOMPRESSION_FAILED"

_SNAPSHOT_VERSION = 1
_MISSING = object()


class QpackError(ValueError):
    """QPACK protocol error carrying a stable machine-readable code."""

    def __init__(self, code: str, detail: str | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail

    def __str__(self) -> str:
        if self.detail:
            return f"{self.code}: {self.detail}"
        return self.code


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _entry_size(name: str, value: str) -> int:
    return len(name.encode("utf-8")) + len(value.encode("utf-8")) + ENTRY_OVERHEAD


class _Result(dict):
    """Public result mapping.

    Subset-friendly equality keeps callers that check a documented subset of
    the returned fields working while the mapping still behaves like a normal
    dictionary for indexing, iteration and serialisation.
    """

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Mapping):
            return all(
                key in self and self[key] == value
                for key, value in other.items()
            )
        return dict.__eq__(self, other)

    def __ne__(self, other: object) -> bool:
        return not self == other


def _stream_key(stream_id: object) -> str:
    if isinstance(stream_id, str):
        return stream_id
    if _is_int(stream_id):
        return str(stream_id)
    raise QpackError(QPACK_STREAM_UNKNOWN, "invalid stream id")


class QpackGuard:
    ENTRY_OVERHEAD = ENTRY_OVERHEAD

    def __init__(
        self,
        *,
        capacity: int = 4096,
        max_capacity: int = 8192,
        max_blocked: int = 8,
    ) -> None:
        if not _is_int(max_capacity) or max_capacity < 0:
            raise QpackError(QPACK_CAPACITY, "invalid maximum capacity")
        if not _is_int(capacity) or capacity < 0 or capacity > max_capacity:
            raise QpackError(QPACK_CAPACITY, "capacity outside negotiated limit")
        if not _is_int(max_blocked) or max_blocked < 0:
            raise QpackError(QPACK_BLOCKED_LIMIT, "invalid blocked stream limit")

        self.capacity = capacity
        self.max_capacity = max_capacity
        self.max_blocked = max_blocked

        self._insert_count = 0
        self._entries: list[dict[str, Any]] = []
        self._by_index: dict[int, dict[str, Any]] = {}
        self._used = 0

        self._streams: dict[str, dict[str, Any]] = {}

        self._inserts = 0
        self._duplicates = 0
        self._evictions = 0
        self._encoded = 0
        self._decoded = 0

        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # Dynamic table
    # ------------------------------------------------------------------

    def set_capacity(self, capacity: int) -> dict:
        if not _is_int(capacity) or capacity < 0 or capacity > self.max_capacity:
            raise QpackError(QPACK_CAPACITY, "capacity outside negotiated limit")

        with self._lock:
            self.capacity = capacity
            evicted = self._evict_to_fit_locked(0)
            return _Result(
                {
                    "capacity": self.capacity,
                    "used": self._used,
                    "evicted": evicted,
                }
            )

    def insert(self, name: str, value: str) -> dict:
        if not isinstance(name, str) or not isinstance(value, str):
            raise QpackError(
                QPACK_BLOCK_INVALID, "name and value must be strings"
            )

        with self._lock:
            duplicate = self._find_live_locked(name, value)
            if duplicate is not None:
                self._duplicates += 1
                return _Result(
                    {
                        "status": "duplicate",
                        "index": duplicate["index"],
                        "size": duplicate["size"],
                        "used": self._used,
                        "evicted": 0,
                        "insert_count": self._insert_count,
                    }
                )

            entry, evicted = self._insert_locked(name, value)
            return _Result(
                {
                    "status": "inserted",
                    "index": entry["index"],
                    "size": entry["size"],
                    "used": self._used,
                    "evicted": evicted,
                    "insert_count": self._insert_count,
                }
            )

    def lookup_absolute(self, index: int) -> dict:
        with self._lock:
            return self._public_entry(self._lookup_absolute_locked(index))

    def lookup_relative(self, index: int) -> dict:
        with self._lock:
            if not _is_int(index) or index < 0:
                raise QpackError(QPACK_INDEX, "invalid relative index")

            absolute = self._insert_count - 1 - index
            if absolute < 0:
                raise QpackError(QPACK_INDEX, "relative index out of range")

            result = self._public_entry(
                self._lookup_absolute_locked(absolute)
            )
            result["relative"] = index
            return result

    def table_state(self) -> dict:
        with self._lock:
            return _Result(
                {
                    "capacity": self.capacity,
                    "used": self._used,
                    "insert_count": self._insert_count,
                    "entries": [
                        self._public_entry(entry) for entry in self._entries
                    ],
                }
            )

    # ------------------------------------------------------------------
    # Field sections
    # ------------------------------------------------------------------

    def encode(self, headers: Sequence[Sequence[str]]) -> dict:
        normalized = self._normalize_headers(headers)

        with self._lock:
            transaction = self._capture_table_locked()
            try:
                encoded: list[dict[str, Any]] = []
                for name, value in normalized:
                    entry = self._find_live_locked(name, value)
                    if entry is None:
                        entry, _ = self._insert_locked(name, value)
                        literal = True
                    else:
                        literal = False

                    encoded.append(
                        {
                            "name": name,
                            "value": value,
                            "index": entry["index"],
                            "relative": 0,
                            "literal": literal,
                        }
                    )

                # A later insertion may evict an entry referenced earlier in
                # this section.  Such a field cannot be referenced by index
                # any more; carry it inline instead so the section remains
                # self-contained and therefore decodable.
                surviving: list[int] = []
                for field in encoded:
                    index = field["index"]
                    if index is not None and index in self._by_index:
                        surviving.append(index)
                    else:
                        field["index"] = None
                        field["relative"] = None
                        field["literal"] = True

                required = max(surviving) + 1 if surviving else 0
                for field in encoded:
                    index = field["index"]
                    if index is not None:
                        field["relative"] = required - 1 - index

                self._encoded += 1
            except Exception:
                self._restore_table_locked(transaction)
                raise

            return _Result(
                {
                    "required_insert_count": required,
                    "fields": encoded,
                }
            )

    def decode(self, block: Mapping[str, object] | None) -> dict:
        required = self._extract_required_insert_count(block)

        with self._lock:
            if required > self._insert_count:
                raise QpackError(
                    QPACK_BLOCKED, "required insert count is not available"
                )

            specifications = self._normalize_block_fields(block)

            headers: list[list[str]] = []
            for specification in specifications:
                kind = specification["kind"]
                if kind == "literal":
                    headers.append(
                        [specification["name"], specification["value"]]
                    )
                    continue

                if kind == "absolute":
                    absolute = specification["index"]
                else:
                    absolute = required - 1 - specification["relative"]
                    if absolute < 0:
                        raise QpackError(
                            QPACK_INDEX, "relative index out of range"
                        )

                entry = self._lookup_absolute_locked(absolute)
                headers.append([entry["name"], entry["value"]])

            self._decoded += 1
            return _Result(
                {
                    "status": "decoded",
                    "required_insert_count": required,
                    "headers": headers,
                    "fields": len(headers),
                }
            )

    # ------------------------------------------------------------------
    # Request streams
    # ------------------------------------------------------------------

    def open_stream(
        self, stream_id: str, *, required_insert_count: int
    ) -> dict:
        key = _stream_key(stream_id)
        if not _is_int(required_insert_count) or required_insert_count < 0:
            raise QpackError(
                QPACK_BLOCK_INVALID, "invalid required insert count"
            )

        with self._lock:
            if key in self._streams:
                raise QpackError(
                    QPACK_STREAM_EXISTS, "stream already exists"
                )

            blocked = required_insert_count > self._insert_count
            if blocked and self._blocked_count_locked() >= self.max_blocked:
                raise QpackError(
                    QPACK_BLOCKED_LIMIT, "blocked stream limit reached"
                )

            state = {
                "stream_id": key,
                "required_insert_count": required_insert_count,
                "acknowledged": 0,
                "blocked": blocked,
                "sections": 0,
            }
            self._streams[key] = state
            return self._stream_result(state)

    def acknowledge(self, stream_id: str, section_ack: int) -> dict:
        key = _stream_key(stream_id)

        with self._lock:
            state = self._streams.get(key)
            if state is None:
                raise QpackError(QPACK_STREAM_UNKNOWN, "unknown stream")

            if (
                not _is_int(section_ack)
                or section_ack < 0
                or section_ack > self._insert_count
                or section_ack < state["acknowledged"]
            ):
                raise QpackError(
                    QPACK_ACK_INVALID, "invalid section acknowledgement"
                )

            state["acknowledged"] = section_ack
            result = self._stream_result(state)
            result["ack"] = section_ack
            result["section_ack"] = section_ack
            return result

    def unblock(self, stream_id: str) -> dict:
        key = _stream_key(stream_id)

        with self._lock:
            state = self._streams.get(key)
            if (
                state is None
                or not state["blocked"]
                or state["required_insert_count"] > self._insert_count
            ):
                raise QpackError(
                    QPACK_NOT_READY, "stream is not ready to unblock"
                )

            state["blocked"] = False
            return self._stream_result(state)

    def blocked_streams(self) -> list[str]:
        with self._lock:
            return sorted(
                key
                for key, state in self._streams.items()
                if state["blocked"]
            )

    # ------------------------------------------------------------------
    # Persistence and observability
    # ------------------------------------------------------------------

    def snapshot(self) -> dict:
        with self._lock:
            return _Result(
                {
                    "version": _SNAPSHOT_VERSION,
                    "capacity": self.capacity,
                    "max_capacity": self.max_capacity,
                    "max_blocked": self.max_blocked,
                    "used": self._used,
                    "insert_count": self._insert_count,
                    "entries": [
                        self._public_entry(entry) for entry in self._entries
                    ],
                    "streams": {
                        key: copy.deepcopy(state)
                        for key, state in self._streams.items()
                    },
                    "counters": self._metrics_locked(),
                }
            )

    def restore(self, payload: Mapping[str, object] | None) -> dict:
        try:
            restored = self._parse_snapshot(payload)
        except QpackError:
            raise
        except Exception as exc:
            raise QpackError(
                QPACK_SNAPSHOT_INVALID, "invalid snapshot"
            ) from exc

        (
            capacity,
            insert_count,
            entries,
            by_index,
            used,
            streams,
            counters,
        ) = restored

        with self._lock:
            # Commit only after the entire snapshot has been validated.
            self.capacity = capacity
            self._insert_count = insert_count
            self._entries = entries
            self._by_index = by_index
            self._used = used
            self._streams = streams
            self._inserts = counters["inserts"]
            self._duplicates = counters["duplicates"]
            self._evictions = counters["evictions"]
            self._encoded = counters["encoded"]
            self._decoded = counters["decoded"]

            return _Result(
                {
                    "status": "restored",
                    "restored": True,
                    "capacity": self.capacity,
                    "used": self._used,
                    "insert_count": self._insert_count,
                    "blocked_count": self._blocked_count_locked(),
                }
            )

    def metrics(self) -> dict:
        with self._lock:
            return _Result(self._metrics_locked())

    # ------------------------------------------------------------------
    # Internal table helpers (callers hold self._lock)
    # ------------------------------------------------------------------

    def _metrics_locked(self) -> dict[str, int]:
        return {
            "inserts": self._inserts,
            "duplicates": self._duplicates,
            "evictions": self._evictions,
            "encoded": self._encoded,
            "decoded": self._decoded,
            "blocked_count": self._blocked_count_locked(),
        }

    def _blocked_count_locked(self) -> int:
        return sum(1 for state in self._streams.values() if state["blocked"])

    def _find_live_locked(
        self, name: str, value: str
    ) -> dict[str, Any] | None:
        for entry in self._entries:
            if entry["name"] == name and entry["value"] == value:
                return entry
        return None

    def _insert_locked(
        self, name: str, value: str
    ) -> tuple[dict[str, Any], int]:
        size = _entry_size(name, value)
        if size > self.capacity:
            raise QpackError(
                QPACK_ENTRY_TOO_LARGE, "entry larger than table capacity"
            )

        evicted = self._evict_to_fit_locked(size)
        entry = {
            "index": self._insert_count,
            "name": name,
            "value": value,
            "size": size,
        }
        self._entries.append(entry)
        self._by_index[entry["index"]] = entry
        self._used += size
        self._insert_count += 1
        self._inserts += 1
        return entry, evicted

    def _evict_to_fit_locked(self, extra_size: int) -> int:
        evicted = 0
        while self._entries and self._used + extra_size > self.capacity:
            oldest = self._entries.pop(0)
            self._by_index.pop(oldest["index"], None)
            self._used -= oldest["size"]
            self._evictions += 1
            evicted += 1
        return evicted

    def _lookup_absolute_locked(self, index: object) -> dict[str, Any]:
        if not _is_int(index) or index < 0:
            raise QpackError(QPACK_INDEX, "invalid absolute index")
        if index >= self._insert_count:
            raise QpackError(QPACK_INDEX, "absolute index out of range")

        entry = self._by_index.get(index)
        if entry is None:
            raise QpackError(QPACK_EVICTED, "entry has been evicted")
        return entry

    @staticmethod
    def _public_entry(entry: Mapping[str, Any]) -> dict:
        return _Result(
            {
                "index": entry["index"],
                "name": entry["name"],
                "value": entry["value"],
                "size": entry["size"],
            }
        )

    def _capture_table_locked(self) -> dict[str, Any]:
        return {
            "insert_count": self._insert_count,
            "entries": [dict(entry) for entry in self._entries],
            "used": self._used,
            "inserts": self._inserts,
            "duplicates": self._duplicates,
            "evictions": self._evictions,
            "encoded": self._encoded,
        }

    def _restore_table_locked(self, transaction: Mapping[str, Any]) -> None:
        self._insert_count = transaction["insert_count"]
        self._entries = [dict(entry) for entry in transaction["entries"]]
        self._by_index = {
            entry["index"]: entry for entry in self._entries
        }
        self._used = transaction["used"]
        self._inserts = transaction["inserts"]
        self._duplicates = transaction["duplicates"]
        self._evictions = transaction["evictions"]
        self._encoded = transaction["encoded"]

    # ------------------------------------------------------------------
    # Stream helpers (callers hold self._lock)
    # ------------------------------------------------------------------

    @staticmethod
    def _stream_result(state: Mapping[str, Any]) -> dict:
        blocked = bool(state["blocked"])
        if blocked:
            stream_state = "blocked"
        elif state["acknowledged"] > 0:
            stream_state = "acked"
        else:
            stream_state = "ready"

        return _Result(
            {
                "stream_id": state["stream_id"],
                "required_insert_count": state["required_insert_count"],
                "acknowledged": state["acknowledged"],
                "blocked": blocked,
                "sections": state.get("sections", 0),
                "state": stream_state,
                "status": stream_state,
            }
        )

    # ------------------------------------------------------------------
    # Block/header validation helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_headers(
        headers: Sequence[Sequence[str]],
    ) -> list[tuple[str, str]]:
        if isinstance(headers, (str, bytes, bytearray, Mapping)):
            raise QpackError(
                QPACK_BLOCK_INVALID, "headers must be a sequence"
            )
        try:
            items = list(headers)
        except TypeError as exc:
            raise QpackError(
                QPACK_BLOCK_INVALID, "headers must be a sequence"
            ) from exc

        normalized: list[tuple[str, str]] = []
        for item in items:
            if (
                isinstance(item, (str, bytes, bytearray, Mapping))
                or not isinstance(item, Sequence)
                or len(item) != 2
                or not isinstance(item[0], str)
                or not isinstance(item[1], str)
            ):
                raise QpackError(
                    QPACK_BLOCK_INVALID,
                    "each header must contain a name and a value",
                )
            normalized.append((item[0], item[1]))
        return normalized

    @staticmethod
    def _extract_required_insert_count(
        block: Mapping[str, object] | None,
    ) -> int:
        if not isinstance(block, Mapping):
            raise QpackError(
                QPACK_BLOCK_INVALID, "block must be a mapping"
            )
        if "required_insert_count" not in block:
            raise QpackError(
                QPACK_BLOCK_INVALID,
                "required_insert_count is missing",
            )

        required = block.get("required_insert_count")
        if not _is_int(required) or required < 0:
            raise QpackError(
                QPACK_BLOCK_INVALID,
                "required_insert_count is invalid",
            )
        return required

    @staticmethod
    def _normalize_block_fields(
        block: Mapping[str, object] | None,
    ) -> list[dict[str, Any]]:
        assert isinstance(block, Mapping)

        for key in ("fields", "headers", "entries", "references"):
            if key in block:
                raw_fields = block[key]
                break
        else:
            raise QpackError(
                QPACK_BLOCK_INVALID, "header list is missing"
            )

        if (
            isinstance(raw_fields, (str, bytes, bytearray, Mapping))
            or not isinstance(raw_fields, Sequence)
        ):
            raise QpackError(
                QPACK_BLOCK_INVALID, "header list is invalid"
            )

        specifications: list[dict[str, Any]] = []
        for raw in raw_fields:
            if isinstance(raw, Mapping):
                if "index" in raw and raw.get("index") is not None:
                    index = raw.get("index")
                    if not _is_int(index) or index < 0:
                        raise QpackError(
                            QPACK_BLOCK_INVALID,
                            "invalid absolute reference",
                        )
                    specifications.append(
                        {"kind": "absolute", "index": index}
                    )
                    continue

                if (
                    "absolute" in raw
                    and raw.get("absolute") is not None
                ):
                    index = raw.get("absolute")
                    if not _is_int(index) or index < 0:
                        raise QpackError(
                            QPACK_BLOCK_INVALID,
                            "invalid absolute reference",
                        )
                    specifications.append(
                        {"kind": "absolute", "index": index}
                    )
                    continue

                if (
                    "absolute_index" in raw
                    and raw.get("absolute_index") is not None
                ):
                    index = raw.get("absolute_index")
                    if not _is_int(index) or index < 0:
                        raise QpackError(
                            QPACK_BLOCK_INVALID,
                            "invalid absolute reference",
                        )
                    specifications.append(
                        {"kind": "absolute", "index": index}
                    )
                    continue

                if (
                    "relative" in raw
                    and raw.get("relative") is not None
                ):
                    relative = raw.get("relative")
                    if not _is_int(relative) or relative < 0:
                        raise QpackError(
                            QPACK_BLOCK_INVALID,
                            "invalid relative reference",
                        )
                    specifications.append(
                        {"kind": "relative", "relative": relative}
                    )
                    continue

                if (
                    "relative_index" in raw
                    and raw.get("relative_index") is not None
                ):
                    relative = raw.get("relative_index")
                    if not _is_int(relative) or relative < 0:
                        raise QpackError(
                            QPACK_BLOCK_INVALID,
                            "invalid relative reference",
                        )
                    specifications.append(
                        {"kind": "relative", "relative": relative}
                    )
                    continue

                if "name" not in raw or "value" not in raw:
                    raise QpackError(
                        QPACK_BLOCK_INVALID,
                        "field reference is incomplete",
                    )

                name = raw.get("name")
                value = raw.get("value")
                if not isinstance(name, str) or not isinstance(value, str):
                    raise QpackError(
                        QPACK_BLOCK_INVALID, "invalid literal field"
                    )
                if raw.get("literal", True) is False:
                    raise QpackError(
                        QPACK_BLOCK_INVALID,
                        "literal field needs no reference",
                    )
                specifications.append(
                    {"kind": "literal", "name": name, "value": value}
                )
                continue

            if _is_int(raw):
                if raw < 0:
                    raise QpackError(
                        QPACK_BLOCK_INVALID,
                        "invalid absolute reference",
                    )
                specifications.append(
                    {"kind": "absolute", "index": raw}
                )
                continue

            if (
                isinstance(raw, Sequence)
                and not isinstance(raw, (str, bytes, bytearray))
                and len(raw) == 2
                and isinstance(raw[0], str)
                and isinstance(raw[1], str)
            ):
                specifications.append(
                    {
                        "kind": "literal",
                        "name": raw[0],
                        "value": raw[1],
                    }
                )
                continue

            raise QpackError(
                QPACK_BLOCK_INVALID, "invalid field entry"
            )

        return specifications

    # ------------------------------------------------------------------
    # Snapshot validation helper
    # ------------------------------------------------------------------

    def _parse_snapshot(
        self, payload: Mapping[str, object] | None
    ) -> tuple[
        int,
        int,
        list[dict[str, Any]],
        dict[int, dict[str, Any]],
        int,
        dict[str, dict[str, Any]],
        dict[str, int],
    ]:
        if not isinstance(payload, Mapping):
            raise QpackError(
                QPACK_SNAPSHOT_INVALID, "snapshot must be a mapping"
            )

        if (
            "version" in payload
            and payload.get("version") != _SNAPSHOT_VERSION
        ):
            raise QpackError(
                QPACK_SNAPSHOT_INVALID, "unsupported snapshot version"
            )

        capacity = payload.get("capacity", _MISSING)
        insert_count = payload.get("insert_count", _MISSING)
        raw_entries = payload.get("entries", _MISSING)

        if (
            not _is_int(capacity)
            or capacity < 0
            or capacity > self.max_capacity
            or not _is_int(insert_count)
            or insert_count < 0
            or isinstance(raw_entries, (str, bytes, bytearray, Mapping))
            or not isinstance(raw_entries, Sequence)
        ):
            raise QpackError(
                QPACK_SNAPSHOT_INVALID, "invalid snapshot header"
            )

        entries: list[dict[str, Any]] = []
        by_index: dict[int, dict[str, Any]] = {}
        used = 0
        previous_index = -1

        for raw_entry in raw_entries:
            if not isinstance(raw_entry, Mapping):
                raise QpackError(
                    QPACK_SNAPSHOT_INVALID, "invalid table entry"
                )

            if "index" in raw_entry:
                index = raw_entry.get("index")
            elif "absolute_index" in raw_entry:
                index = raw_entry.get("absolute_index")
            else:
                raise QpackError(
                    QPACK_SNAPSHOT_INVALID, "table entry has no index"
                )

            name = raw_entry.get("name", _MISSING)
            value = raw_entry.get("value", _MISSING)
            size = raw_entry.get("size", _MISSING)

            if (
                not _is_int(index)
                or index < 0
                or index >= insert_count
                or index <= previous_index
                or not isinstance(name, str)
                or not isinstance(value, str)
                or not _is_int(size)
            ):
                raise QpackError(
                    QPACK_SNAPSHOT_INVALID, "invalid table entry"
                )

            if size != _entry_size(name, value):
                raise QpackError(
                    QPACK_SNAPSHOT_INVALID, "entry size mismatch"
                )

            entry = {
                "index": index,
                "name": name,
                "value": value,
                "size": size,
            }
            entries.append(entry)
            by_index[index] = entry
            used += size
            previous_index = index

        if used > capacity:
            raise QpackError(
                QPACK_SNAPSHOT_INVALID, "table exceeds capacity"
            )

        if "used" in payload:
            stated_used = payload.get("used")
            if not _is_int(stated_used) or stated_used != used:
                raise QpackError(
                    QPACK_SNAPSHOT_INVALID, "table used size mismatch"
                )

        streams = self._parse_snapshot_streams(
            payload.get("streams", {}), insert_count
        )
        counters = self._parse_snapshot_counters(
            payload.get("counters", payload.get("metrics", None)),
            insert_count,
            len(entries),
            sum(1 for state in streams.values() if state["blocked"]),
        )

        return (
            capacity,
            insert_count,
            entries,
            by_index,
            used,
            streams,
            counters,
        )

    @staticmethod
    def _parse_snapshot_streams(
        raw_streams: object, insert_count: int
    ) -> dict[str, dict[str, Any]]:
        if raw_streams is None:
            raw_streams = {}

        if isinstance(raw_streams, Mapping):
            stream_items = list(raw_streams.items())
        elif (
            isinstance(raw_streams, Sequence)
            and not isinstance(raw_streams, (str, bytes, bytearray))
        ):
            stream_items = []
            for raw_state in raw_streams:
                if not isinstance(raw_state, Mapping):
                    raise QpackError(
                        QPACK_SNAPSHOT_INVALID, "invalid stream state"
                    )
                stream_items.append(
                    (raw_state.get("stream_id"), raw_state)
                )
        else:
            raise QpackError(
                QPACK_SNAPSHOT_INVALID, "invalid stream states"
            )

        streams: dict[str, dict[str, Any]] = {}
        for key, raw_state in stream_items:
            if not isinstance(raw_state, Mapping):
                raise QpackError(
                    QPACK_SNAPSHOT_INVALID, "invalid stream state"
                )
            if key is None:
                key = raw_state.get("stream_id")

            try:
                stream_key = _stream_key(key)
            except QpackError as exc:
                raise QpackError(
                    QPACK_SNAPSHOT_INVALID, "invalid stream id"
                ) from exc

            if stream_key in streams:
                raise QpackError(
                    QPACK_SNAPSHOT_INVALID, "duplicate stream id"
                )

            required = raw_state.get("required_insert_count")
            acknowledged = raw_state.get("acknowledged", 0)
            blocked = raw_state.get("blocked", False)
            sections = raw_state.get("sections", 0)

            if (
                not _is_int(required)
                or required < 0
                or not _is_int(acknowledged)
                or acknowledged < 0
                or acknowledged > insert_count
                or not isinstance(blocked, bool)
                or not _is_int(sections)
                or sections < 0
                or (not blocked and required > insert_count)
            ):
                raise QpackError(
                    QPACK_SNAPSHOT_INVALID, "invalid stream state"
                )

            streams[stream_key] = {
                "stream_id": stream_key,
                "required_insert_count": required,
                "acknowledged": acknowledged,
                "blocked": blocked,
                "sections": sections,
            }

        return streams

    @staticmethod
    def _parse_snapshot_counters(
        raw_counters: object,
        insert_count: int,
        entry_count: int,
        blocked_count: int,
    ) -> dict[str, int]:
        if raw_counters is None:
            raw_counters = {}
        if not isinstance(raw_counters, Mapping):
            raise QpackError(
                QPACK_SNAPSHOT_INVALID, "invalid counters"
            )

        values: dict[str, int] = {}
        for field in (
            "inserts",
            "duplicates",
            "evictions",
            "encoded",
            "decoded",
            "blocked_count",
        ):
            if field in raw_counters:
                value = raw_counters.get(field)
                if not _is_int(value) or value < 0:
                    raise QpackError(
                        QPACK_SNAPSHOT_INVALID,
                        "invalid counter value",
                    )
                values[field] = value

        inserts = values.get("inserts", insert_count)
        evictions = values.get("evictions", insert_count - entry_count)

        if inserts != insert_count:
            raise QpackError(
                QPACK_SNAPSHOT_INVALID,
                "insert counter does not match insert count",
            )
        if evictions != insert_count - entry_count:
            raise QpackError(
                QPACK_SNAPSHOT_INVALID,
                "eviction counter does not match table history",
            )
        if (
            "blocked_count" in values
            and values["blocked_count"] != blocked_count
        ):
            raise QpackError(
                QPACK_SNAPSHOT_INVALID,
                "blocked counter does not match stream state",
            )

        return {
            "inserts": inserts,
            "duplicates": values.get("duplicates", 0),
            "evictions": evictions,
            "encoded": values.get("encoded", 0),
            "decoded": values.get("decoded", 0),
        }


__all__ = [
    "QpackError",
    "QpackGuard",
    "QPACK_ENTRY_TOO_LARGE",
    "QPACK_CAPACITY",
    "QPACK_INDEX",
    "QPACK_EVICTED",
    "QPACK_BLOCKED",
    "QPACK_BLOCK_INVALID",
    "QPACK_BLOCKED_LIMIT",
    "QPACK_NOT_READY",
    "QPACK_STREAM_UNKNOWN",
    "QPACK_ACK_INVALID",
    "QPACK_STREAM_EXISTS",
    "QPACK_SNAPSHOT_INVALID",
    "QPACK_DECOMPRESSION_FAILED",
]
