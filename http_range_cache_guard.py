"""Thread-safe HTTP range cache with strict validator and snapshot handling."""

from __future__ import annotations

import base64
import binascii
import copy
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Iterable


class RangeError(ValueError):
    """Error carrying a stable machine-readable code."""

    def __init__(self, code: str, message: str | None = None) -> None:
        self.code = code
        super().__init__(message or code)


RangeCacheError = RangeError

RANGE_INVALID = "RANGE_INVALID"
RANGE_UNSATISFIABLE = "RANGE_UNSATISFIABLE"
RANGE_TOO_MANY = "RANGE_TOO_MANY"
RANGE_INCOMPLETE = "RANGE_INCOMPLETE"
RANGE_MISS = "RANGE_MISS"
RANGE_EXPIRED = "RANGE_EXPIRED"
RANGE_TOO_LARGE = "RANGE_TOO_LARGE"
RANGE_SNAPSHOT_VERSION = "RANGE_SNAPSHOT_VERSION"
RANGE_SNAPSHOT_CORRUPT = "RANGE_SNAPSHOT_CORRUPT"

SNAPSHOT_VERSION = 1


@dataclass
class Config:
    max_entries: int = 256
    max_ranges: int = 16
    max_bytes: int = 64 * 1024 * 1024
    max_object_size: int = 1 << 30


@dataclass
class _Part:
    start: int
    end: int
    data: bytes

    @property
    def size(self) -> int:
        return self.end - self.start + 1


@dataclass
class _Object:
    url: str
    etag: str
    total: int
    last_modified: str = ""
    expires: float | None = None
    last_access: int = 0
    body: bytes | None = None
    parts: list[_Part] = field(default_factory=list)

    def cached_size(self) -> int:
        if self.body is not None:
            return len(self.body)
        return sum(part.size for part in self.parts)

    def complete(self) -> bool:
        if self.body is not None:
            return len(self.body) == self.total
        return (
            self.total > 0
            and len(self.parts) == 1
            and self.parts[0].start == 0
            and self.parts[0].end == self.total - 1
            and self.parts[0].size == self.total
        )

    def full_body(self) -> bytes | None:
        if self.body is not None:
            return self.body
        if self.complete():
            return self.parts[0].data
        return None

    def covered(self) -> list[tuple[int, int]]:
        if self.body is not None:
            return [(0, self.total - 1)] if self.total > 0 else []
        return [(part.start, part.end) for part in self.parts]

    def find_part(self, start: int, end: int) -> bytes | None:
        if self.body is not None:
            if start >= 0 and end < len(self.body):
                return self.body[start : end + 1]
            return None
        for part in self.parts:
            if part.start <= start and part.end >= end:
                offset = start - part.start
                return part.data[offset : offset + end - start + 1]
        return None


class RangeCacheGuard:
    """Parse ranges and cache complete or partial representation bytes."""

    def __init__(
        self,
        max_entries: int = 256,
        max_ranges: int = 16,
        max_bytes: int = 64 * 1024 * 1024,
        max_object_size: int | None = None,
        **kwargs: Any,
    ) -> None:
        if isinstance(max_entries, dict):
            config = max_entries
            max_entries = int(config.get("max_entries", 256))
            max_ranges = int(config.get("max_ranges", 16))
            max_bytes = int(config.get("max_bytes", 64 * 1024 * 1024))
            max_object_size = config.get("max_object_size", max_object_size)
        elif isinstance(max_entries, Config):
            config = max_entries
            max_entries = config.max_entries
            max_ranges = config.max_ranges
            max_bytes = config.max_bytes
            max_object_size = config.max_object_size

        if "max_total_bytes" in kwargs:
            max_bytes = int(kwargs["max_total_bytes"])
        if "max_total_size" in kwargs:
            max_bytes = int(kwargs["max_total_size"])
        if "capacity" in kwargs:
            max_bytes = int(kwargs["capacity"])
        if "max_segments" in kwargs:
            max_ranges = int(kwargs["max_segments"])
        if "object_size_limit" in kwargs:
            max_object_size = int(kwargs["object_size_limit"])
        if "max_object_bytes" in kwargs:
            max_object_size = int(kwargs["max_object_bytes"])

        self.max_entries = int(max_entries)
        self.max_ranges = int(max_ranges)
        self.max_bytes = int(max_bytes)
        self.max_object_size = (
            int(max_object_size) if max_object_size is not None else 1 << 30
        )
        self._lock = threading.RLock()
        self._objects: dict[str, _Object] = {}
        self._clock = 0
        self._stats: dict[str, int] = {
            "stored": 0,
            "partial_stored": 0,
            "hits": 0,
            "misses": 0,
            "partial_206": 0,
            "not_modified": 0,
            "unsatisfiable": 0,
            "multipart": 0,
            "evicted": 0,
            "expired": 0,
            "bytes_served": 0,
        }

    # ------------------------------------------------------------------
    # Range handling
    def parse_range(self, header: str, total: int) -> list[tuple[int, int]]:
        if not isinstance(header, str):
            raise RangeError(RANGE_INVALID)
        text = header.strip()
        if not text.startswith("bytes="):
            raise RangeError(RANGE_INVALID)
        total = int(total)
        raw_specs = text[len("bytes=") :].split(",")
        if self.max_ranges > 0 and len(raw_specs) > self.max_ranges:
            raise RangeError(RANGE_TOO_MANY)

        ranges: list[tuple[int, int]] = []
        for raw in raw_specs:
            spec = raw.strip()
            if spec.count("-") != 1:
                raise RangeError(RANGE_INVALID)
            left, right = (part.strip() for part in spec.split("-", 1))

            if left == "":
                if right == "" or not right.isdigit():
                    raise RangeError(RANGE_INVALID)
                suffix = int(right)
                if suffix == 0 or total <= 0:
                    raise RangeError(RANGE_UNSATISFIABLE)
                start = max(0, total - suffix)
                ranges.append((start, total - 1))
                continue

            if not left.isdigit():
                raise RangeError(RANGE_INVALID)
            start = int(left)

            if right == "":
                if start >= total:
                    raise RangeError(RANGE_UNSATISFIABLE)
                ranges.append((start, total - 1))
                continue

            if not right.isdigit():
                raise RangeError(RANGE_INVALID)
            end = int(right)
            if end < start:
                raise RangeError(RANGE_INVALID)
            if start >= total:
                raise RangeError(RANGE_UNSATISFIABLE)
            ranges.append((start, min(end, total - 1)))
        return ranges

    def coalesce(
        self, ranges: Iterable[tuple[int, int] | list[int]]
    ) -> list[tuple[int, int]]:
        normalized: list[tuple[int, int]] = []
        for item in ranges:
            if not isinstance(item, (tuple, list)) or len(item) != 2:
                raise RangeError(RANGE_INVALID)
            start, end = int(item[0]), int(item[1])
            if start < 0 or end < start:
                raise RangeError(RANGE_INVALID)
            normalized.append((start, end))
        normalized.sort()

        merged: list[tuple[int, int]] = []
        for start, end in normalized:
            if not merged or start > merged[-1][1] + 1:
                merged.append((start, end))
            elif end > merged[-1][1]:
                merged[-1] = (merged[-1][0], end)
        return merged

    # ------------------------------------------------------------------
    # Cache writes
    def store(
        self,
        url: str,
        *,
        body: bytes,
        etag: str,
        last_modified: str = "",
        ttl: float | None = None,
    ) -> dict[str, Any]:
        payload = bytes(body)
        self._validate_etag(etag)
        if len(payload) > self.max_object_size:
            raise RangeError(RANGE_TOO_LARGE)
        if self.max_bytes > 0 and len(payload) > self.max_bytes:
            raise RangeError(RANGE_TOO_LARGE)

        with self._lock:
            self._expire_locked(time.time())
            self._clock += 1
            entry = _Object(
                url=url,
                etag=etag,
                total=len(payload),
                last_modified=last_modified,
                expires=self._expiry(ttl),
                last_access=self._clock,
                body=payload,
            )
            self._objects[url] = entry
            self._stats["stored"] += 1
            evicted = self._enforce_limits_locked(protected=url)
            return {
                "url": url,
                "total": entry.total,
                "etag": entry.etag,
                "evicted": evicted,
            }

    def store_partial(
        self,
        url: str,
        *,
        body: bytes,
        etag: str,
        start: int,
        total: int,
        ttl: float | None = None,
    ) -> dict[str, Any]:
        payload = bytes(body)
        self._validate_etag(etag)
        start = int(start)
        total = int(total)
        if total <= 0 or start < 0 or not payload or start >= total:
            raise RangeError(RANGE_INVALID)
        if start + len(payload) > total:
            raise RangeError(RANGE_INVALID)
        if total > self.max_object_size:
            raise RangeError(RANGE_TOO_LARGE)
        if self.max_bytes > 0 and len(payload) > self.max_bytes:
            raise RangeError(RANGE_TOO_LARGE)

        end = start + len(payload) - 1
        with self._lock:
            self._expire_locked(time.time())
            existing = self._objects.get(url)
            if (
                existing is not None
                and existing.etag == etag
                and existing.total == total
                and not self._expired_locked(existing, time.time())
            ):
                if existing.body is None:
                    overlap = sum(
                        max(0, min(end, part.end) - max(start, part.start) + 1)
                        for part in existing.parts
                    )
                    projected = existing.cached_size() + len(payload) - overlap
                    if self.max_bytes > 0 and projected > self.max_bytes:
                        raise RangeError(RANGE_TOO_LARGE)
                entry = existing
                if existing.body is None:
                    entry = self._merge_partial_locked(existing, start, end, payload)
            else:
                self._clock += 1
                entry = _Object(
                    url=url,
                    etag=etag,
                    total=total,
                    last_modified="",
                    expires=self._expiry(ttl),
                    last_access=self._clock,
                )
                entry.parts = [_Part(start, end, payload)]
                self._objects[url] = entry

            self._clock += 1
            entry.last_access = self._clock
            self._stats["partial_stored"] += 1
            self._enforce_limits_locked(protected=url)
            return {
                "url": url,
                "total": entry.total,
                "complete": entry.complete(),
                "covered": entry.covered(),
            }

    def _merge_partial_locked(
        self, entry: _Object, start: int, end: int, payload: bytes
    ) -> _Object:
        if entry.body is not None:
            return entry

        pieces: list[_Part] = []
        for part in entry.parts:
            if part.end < start or part.start > end:
                pieces.append(part)
                continue
            if part.start < start:
                cut = start - part.start
                pieces.append(_Part(part.start, start - 1, part.data[:cut]))
            if part.end > end:
                cut = end - part.start + 1
                pieces.append(_Part(end + 1, part.end, part.data[cut:]))
        pieces.append(_Part(start, end, payload))
        pieces.sort(key=lambda part: (part.start, part.end))

        merged: list[_Part] = []
        for part in pieces:
            if merged and part.start <= merged[-1].end + 1:
                prev = merged[-1]
                if part.end <= prev.end:
                    continue
                overlap = prev.end - part.start + 1
                prev.data = prev.data + part.data[overlap:]
                prev.end = part.end
            else:
                merged.append(_Part(part.start, part.end, part.data))
        entry.parts = merged
        return entry

    # ------------------------------------------------------------------
    # Request handling
    def handle(self, request: dict[str, Any]) -> dict[str, Any]:
        url = request.get("url", "")
        headers_in = request.get("headers") or {}
        if not isinstance(headers_in, dict):
            headers_in = {}
        header_map = {str(key).lower(): value for key, value in headers_in.items()}

        def header(name: str) -> str:
            key = name.lower()
            if key in header_map and header_map[key] is not None:
                return str(header_map[key])
            for candidate in (name, key, key.replace("-", "_")):
                if candidate in request and request[candidate] is not None:
                    return str(request[candidate])
            return ""

        now = time.time()
        with self._lock:
            entry = self._objects.get(url)
            expired = False
            if entry is not None and self._expired_locked(entry, now):
                del self._objects[url]
                self._stats["expired"] += 1
                expired = True
                entry = None

            if entry is None:
                self._stats["misses"] += 1
                code = RANGE_EXPIRED if expired else RANGE_MISS
                return {"status": "miss", "headers": {}, "body": b"", "code": code}

            self._clock += 1
            entry.last_access = self._clock

            if self._etag_matches(header("If-None-Match"), entry.etag):
                self._stats["not_modified"] += 1
                return {
                    "status": 304,
                    "headers": {"ETag": entry.etag, "Content-Length": "0"},
                    "body": b"",
                }

            range_header = header("Range")
            if_range = header("If-Range")
            allow_range = self._if_range_allows(if_range, entry.etag)

            if not range_header:
                return self._serve_full_locked(entry)
            if not allow_range:
                return self._serve_full_locked(entry)

            try:
                ranges = self.parse_range(range_header, entry.total)
            except RangeError as exc:
                if exc.code == RANGE_UNSATISFIABLE:
                    self._stats["unsatisfiable"] += 1
                else:
                    self._stats["misses"] += 1
                response_headers = {
                    "Content-Range": f"bytes */{entry.total}",
                    "Content-Length": "0",
                    "ETag": entry.etag,
                }
                return {
                    "status": 416,
                    "headers": response_headers,
                    "body": b"",
                    "code": exc.code,
                }

            merged = self.coalesce(ranges)
            payloads: list[tuple[int, int, bytes]] = []
            for start, end in merged:
                piece = entry.find_part(start, end)
                if piece is None:
                    self._stats["misses"] += 1
                    return {
                        "status": "miss",
                        "headers": {},
                        "body": b"",
                        "code": RANGE_INCOMPLETE,
                    }
                payloads.append((start, end, piece))

            if len(payloads) == 1:
                start, end, piece = payloads[0]
                headers = {
                    "Content-Type": "application/octet-stream",
                    "Content-Length": str(len(piece)),
                    "Content-Range": f"bytes {start}-{end}/{entry.total}",
                    "ETag": entry.etag,
                    "Accept-Ranges": "bytes",
                }
                self._stats["hits"] += 1
                self._stats["partial_206"] += 1
                self._stats["bytes_served"] += len(piece)
                return {"status": 206, "headers": headers, "body": piece}

            return self._serve_multipart_locked(entry, payloads)

    def _serve_full_locked(self, entry: _Object) -> dict[str, Any]:
        body = entry.full_body()
        if body is None:
            self._stats["misses"] += 1
            return {
                "status": "miss",
                "headers": {},
                "body": b"",
                "code": RANGE_MISS,
            }
        headers = {
            "Content-Type": "application/octet-stream",
            "Content-Length": str(len(body)),
            "ETag": entry.etag,
            "Accept-Ranges": "bytes",
        }
        self._stats["hits"] += 1
        self._stats["bytes_served"] += len(body)
        return {"status": 200, "headers": headers, "body": body}

    def _serve_multipart_locked(
        self, entry: _Object, payloads: list[tuple[int, int, bytes]]
    ) -> dict[str, Any]:
        boundary = f"rangecache-{entry.etag.encode('utf-8').hex()[:24]}"
        while boundary in entry.etag:
            boundary += "x"
        chunks: list[bytes] = []
        for start, end, piece in payloads:
            chunks.append(
                (
                    f"--{boundary}\r\n"
                    "Content-Type: application/octet-stream\r\n"
                    f"Content-Range: bytes {start}-{end}/{entry.total}\r\n"
                    "\r\n"
                ).encode("ascii")
            )
            chunks.append(piece)
            chunks.append(b"\r\n")
        chunks.append(f"--{boundary}--\r\n".encode("ascii"))
        body = b"".join(chunks)
        headers = {
            "Content-Type": f"multipart/byteranges; boundary={boundary}",
            "Content-Length": str(len(body)),
            "ETag": entry.etag,
            "Accept-Ranges": "bytes",
        }
        self._stats["hits"] += 1
        self._stats["multipart"] += 1
        self._stats["bytes_served"] += len(body)
        return {"status": 206, "headers": headers, "body": body}

    # ------------------------------------------------------------------
    # Cache maintenance and state
    def invalidate(self, url: str) -> int:
        with self._lock:
            if url not in self._objects:
                return 0
            del self._objects[url]
            return 1

    def entries(self) -> list[str]:
        with self._lock:
            self._expire_locked(time.time())
            return sorted(self._objects)

    def expire(self, now: float | None = None) -> int:
        with self._lock:
            return self._expire_locked(time.time() if now is None else float(now))

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            objects: dict[str, Any] = {}
            for url, entry in self._objects.items():
                objects[url] = {
                    "etag": entry.etag,
                    "total": entry.total,
                    "last_modified": entry.last_modified,
                    "expires": entry.expires,
                    "last_access": entry.last_access,
                    "body": (
                        base64.b64encode(entry.body).decode("ascii")
                        if entry.body is not None
                        else None
                    ),
                    "parts": [
                        {
                            "start": part.start,
                            "end": part.end,
                            "data": base64.b64encode(part.data).decode("ascii"),
                        }
                        for part in entry.parts
                    ],
                }
            return {
                "version": SNAPSHOT_VERSION,
                "clock": self._clock,
                "objects": copy.deepcopy(objects),
                "stats": copy.deepcopy(self._stats),
            }

    def restore(self, state: dict[str, Any]) -> None:
        if not isinstance(state, dict) or state.get("version") != SNAPSHOT_VERSION:
            raise RangeError(RANGE_SNAPSHOT_VERSION)

        try:
            clock = int(state.get("clock", 0))
            raw_objects = state.get("objects", {})
            raw_stats = state.get("stats", {})
            if clock < 0 or not isinstance(raw_objects, dict):
                raise ValueError

            rebuilt: dict[str, _Object] = {}
            for url, raw in raw_objects.items():
                if not isinstance(url, str) or not isinstance(raw, dict):
                    raise ValueError
                etag = raw.get("etag")
                total = int(raw.get("total", -1))
                if not isinstance(etag, str) or not self._strong_etag(etag):
                    raise ValueError
                if total < 0 or total > self.max_object_size:
                    raise ValueError

                body: bytes | None = None
                encoded_body = raw.get("body")
                if encoded_body is not None:
                    body = base64.b64decode(str(encoded_body), validate=True)
                    if len(body) != total:
                        raise ValueError

                parts: list[_Part] = []
                for raw_part in raw.get("parts", []):
                    start = int(raw_part["start"])
                    end = int(raw_part["end"])
                    if start < 0 or end < start or end >= total:
                        raise ValueError
                    data = base64.b64decode(str(raw_part["data"]), validate=True)
                    if len(data) != end - start + 1:
                        raise ValueError
                    if parts and start <= parts[-1].end:
                        raise ValueError
                    parts.append(_Part(start, end, data))
                if body is not None and parts:
                    raise ValueError
                if body is None and not parts:
                    raise ValueError

                expires_raw = raw.get("expires")
                expires = None if expires_raw is None else float(expires_raw)
                rebuilt[url] = _Object(
                    url=url,
                    etag=etag,
                    total=total,
                    last_modified=str(raw.get("last_modified", "")),
                    expires=expires,
                    last_access=int(raw.get("last_access", 0)),
                    body=body,
                    parts=parts,
                )

            stats = dict(self._stats)
            if not isinstance(raw_stats, dict):
                raise ValueError
            for key in stats:
                if key in raw_stats:
                    value = int(raw_stats[key])
                    if value < 0:
                        raise ValueError
                    stats[key] = value

            if self.max_bytes > 0 and sum(o.cached_size() for o in rebuilt.values()) > self.max_bytes:
                raise ValueError
            if self.max_entries > 0 and len(rebuilt) > self.max_entries:
                raise ValueError
        except (KeyError, TypeError, ValueError, RangeError, binascii.Error):
            raise RangeError(RANGE_SNAPSHOT_CORRUPT) from None

        self._objects = rebuilt
        self._clock = clock
        self._stats = stats

    def stats(self) -> dict[str, int]:
        with self._lock:
            result = {"entries": len(self._objects)}
            result.update(self._stats)
            return result

    # ------------------------------------------------------------------
    # Internal helpers
    def _validate_etag(self, etag: str) -> None:
        if not self._strong_etag(etag):
            raise RangeError(RANGE_INVALID)

    @staticmethod
    def _strong_etag(etag: Any) -> bool:
        return isinstance(etag, str) and bool(etag.strip()) and not etag.startswith("W/")

    def _expiry(self, ttl: float | None) -> float | None:
        if ttl is None:
            return None
        return time.time() + float(ttl)

    @staticmethod
    def _expired_locked(entry: _Object, now: float) -> bool:
        return entry.expires is not None and entry.expires <= now

    def _expire_locked(self, now: float) -> int:
        expired = [
            url
            for url, entry in self._objects.items()
            if self._expired_locked(entry, now)
        ]
        for url in expired:
            del self._objects[url]
        self._stats["expired"] += len(expired)
        return len(expired)

    def _enforce_limits_locked(self, protected: str) -> int:
        evicted = 0
        while self.max_bytes > 0:
            total = sum(entry.cached_size() for entry in self._objects.values())
            if total <= self.max_bytes:
                break
            candidates = [
                (entry.last_access, url)
                for url, entry in self._objects.items()
                if url != protected
            ]
            if not candidates:
                break
            _, victim = min(candidates)
            del self._objects[victim]
            evicted += 1

        while self.max_entries > 0 and len(self._objects) > self.max_entries:
            candidates = [
                (entry.last_access, url)
                for url, entry in self._objects.items()
                if url != protected
            ]
            if not candidates:
                break
            _, victim = min(candidates)
            del self._objects[victim]
            evicted += 1

        self._stats["evicted"] += evicted
        return evicted

    @staticmethod
    def _etag_matches(value: str, etag: str) -> bool:
        if not value:
            return False
        if value.strip() == "*":
            return True
        return any(token.strip() == etag for token in value.split(","))

    @staticmethod
    def _if_range_allows(value: str, etag: str) -> bool:
        if not value:
            return True
        if value.startswith("W/"):
            return False
        return value == etag
