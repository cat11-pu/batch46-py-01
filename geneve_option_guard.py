"""Geneve option validation guard."""

from __future__ import annotations

import copy
import ipaddress
import threading
from collections import OrderedDict
from typing import Any, Iterable


_STATE_VERSION = 1
_VALID_ENCODINGS = frozenset({"raw", "utf8", "ipv4"})
_MISSING = object()


class GeneveError(ValueError):
    def __init__(self, code: str, detail: str | None = None):
        super().__init__(code)
        self.code = code
        self.detail = detail


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _bytes_value(value: object) -> bytes | None:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, memoryview):
        return value.tobytes()
    return None


class GeneveGuard:
    """Validates Geneve option TLVs against a registry and caches results."""

    def __init__(self, *, max_options: int = 8, max_option_bytes: int = 128,
                 allowed_classes: Iterable[int] = (0x0108,),
                 cache_capacity: int = 64) -> None:
        if not _is_int(max_options) or max_options < 0:
            raise GeneveError("GENEVE_BAD_REGISTRATION")
        if not _is_int(max_option_bytes) or max_option_bytes < 0:
            raise GeneveError("GENEVE_BAD_REGISTRATION")
        if not _is_int(cache_capacity) or cache_capacity < 0:
            raise GeneveError("GENEVE_BAD_REGISTRATION")

        try:
            classes = tuple(allowed_classes)
        except TypeError:
            raise GeneveError("GENEVE_BAD_REGISTRATION") from None
        if any(not _is_int(opt_class) or not 0 <= opt_class <= 0xFFFF
               for opt_class in classes):
            raise GeneveError("GENEVE_BAD_REGISTRATION")

        self.max_options = max_options
        self.max_option_bytes = max_option_bytes
        self.allowed_classes = classes
        self.cache_capacity = cache_capacity

        self._lock = threading.RLock()
        self._registered: dict[tuple[int, int], dict[str, Any]] = {}
        self._cache: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self._counters: dict[str, Any] = {
            "parsed": 0,
            "accepted": 0,
            "rejected": 0,
            "replayed": 0,
            "skipped_options": 0,
            "codes": {},
        }

    def register_option(self, opt_class: int, opt_type: int, *,
                        critical: bool = False, max_len: int = 16,
                        encoding: str = "raw") -> dict:
        if (not _is_int(opt_class) or not 0 <= opt_class <= 0xFFFF
                or not _is_int(opt_type) or not 0 <= opt_type <= 0xFF
                or not _is_int(max_len) or not 0 <= max_len <= 1024
                or not isinstance(critical, bool)
                or encoding not in _VALID_ENCODINGS):
            raise GeneveError("GENEVE_BAD_REGISTRATION")

        record = {
            "class": opt_class,
            "type": opt_type,
            "critical": critical,
            "max_len": max_len,
            "encoding": encoding,
        }
        with self._lock:
            self._registered[(opt_class, opt_type)] = record
        return copy.deepcopy(record)

    def unregister_option(self, opt_class: int, opt_type: int) -> bool:
        if not _is_int(opt_class) or not _is_int(opt_type):
            return False
        with self._lock:
            return self._registered.pop((opt_class, opt_type), None) is not None

    def list_options(self) -> list[dict]:
        with self._lock:
            return [
                copy.deepcopy(self._registered[key])
                for key in sorted(self._registered)
            ]

    def parse(self, packet: dict, *, request_id: str | None = None) -> dict:
        with self._lock:
            if request_id is not None:
                cached = self._cache.get(request_id)
                if cached is not None:
                    self._cache.move_to_end(request_id)
                    self._counters["replayed"] += 1
                    result = copy.deepcopy(cached)
                    result["cached"] = True
                    return result

            try:
                result = self._parse_packet(packet)
            except GeneveError as exc:
                self._counters["rejected"] += 1
                codes = self._counters["codes"]
                codes[exc.code] = codes.get(exc.code, 0) + 1
                raise

            self._counters["parsed"] += 1
            self._counters["accepted"] += 1
            self._counters["skipped_options"] += len(result["skipped"])

            if request_id is not None and self.cache_capacity > 0:
                self._cache[request_id] = copy.deepcopy(result)
                self._cache.move_to_end(request_id)
                while len(self._cache) > self.cache_capacity:
                    self._cache.popitem(last=False)

            return copy.deepcopy(result)

    def _parse_packet(self, packet: dict) -> dict:
        version, vni, options = self._validate_header(packet)
        option_bytes = self._validate_capacity(options)
        registered = self._registered
        allowed_classes = self.allowed_classes

        seen: set[tuple[int, int]] = set()
        skipped: list[list[int]] = []
        normalized: list[dict[str, Any]] = []

        for raw in options:
            opt_class, opt_type, critical, value = self._read_option(raw)
            key = (opt_class, opt_type)
            if key in seen:
                raise GeneveError("GENEVE_OPT_DUP")
            seen.add(key)

            record = registered.get(key)
            if opt_class not in allowed_classes or record is None:
                if critical:
                    raise GeneveError("GENEVE_CRITICAL_UNKNOWN")
                skipped.append([opt_class, opt_type])
                continue

            if critical != record["critical"]:
                raise GeneveError("GENEVE_CRITICAL_MISMATCH")

            length = len(value)
            if length > record["max_len"]:
                raise GeneveError("GENEVE_OPT_LEN")
            if length == 0:
                raise GeneveError("GENEVE_OPT_EMPTY")
            self._validate_encoding(value, record["encoding"])

            normalized.append({
                "class": opt_class,
                "type": opt_type,
                "critical": critical,
                "value": value,
                "length": length,
            })

        normalized.sort(key=lambda item: (item["class"], item["type"]))
        return {
            "status": "accepted",
            "code": None,
            "version": version,
            "vni": vni,
            "options": normalized,
            "skipped": skipped,
            "option_bytes": option_bytes,
            "cached": False,
        }

    def _validate_header(self, packet: object) -> tuple[int, int, list]:
        if not isinstance(packet, dict):
            raise GeneveError("GENEVE_BAD_PACKET")

        version = packet.get("version", _MISSING)
        if not _is_int(version) or version != 0:
            raise GeneveError("GENEVE_BAD_VERSION")

        vni = packet.get("vni", _MISSING)
        if not _is_int(vni) or not 1 <= vni <= 0xFFFFFF:
            raise GeneveError("GENEVE_BAD_VNI")

        options = packet.get("options", _MISSING)
        if not isinstance(options, list):
            raise GeneveError("GENEVE_BAD_PACKET")

        return version, vni, options

    def _validate_capacity(self, options: list) -> int:
        if len(options) > self.max_options:
            raise GeneveError("GENEVE_OPT_COUNT")

        option_bytes = 0
        for raw in options:
            value_length = 0
            if isinstance(raw, dict):
                value = raw.get("value", b"")
                if isinstance(value, (bytes, bytearray, memoryview)):
                    value_length = len(value)
            option_bytes += 4 + value_length
            if option_bytes > self.max_option_bytes:
                raise GeneveError("GENEVE_OPTS_OVERFLOW")
        return option_bytes

    def _read_option(self, raw: object) -> tuple[int, int, bool, bytes]:
        if not isinstance(raw, dict):
            raise GeneveError("GENEVE_BAD_PACKET")
        if "class" not in raw or "type" not in raw:
            raise GeneveError("GENEVE_BAD_PACKET")

        opt_class = raw["class"]
        opt_type = raw["type"]
        critical = raw.get("critical", False)
        if (not _is_int(opt_class) or not _is_int(opt_type)
                or not isinstance(critical, bool)):
            raise GeneveError("GENEVE_BAD_PACKET")

        value = _bytes_value(raw.get("value", b""))
        if value is None:
            raise GeneveError("GENEVE_BAD_PACKET")
        return opt_class, opt_type, critical, value

    @staticmethod
    def _validate_encoding(value: bytes, encoding: str) -> None:
        if encoding == "utf8":
            try:
                value.decode("utf-8")
            except UnicodeDecodeError:
                raise GeneveError("GENEVE_OPT_ENCODING") from None
        elif encoding == "ipv4":
            if len(value) != 4:
                raise GeneveError("GENEVE_OPT_ENCODING")
            try:
                ipaddress.IPv4Address(value)
            except ipaddress.AddressValueError:
                raise GeneveError("GENEVE_OPT_ENCODING") from None

    def audit(self, packet: dict) -> dict:
        with self._lock:
            if not isinstance(packet, dict):
                return {
                    "ok": False,
                    "issues": ["GENEVE_BAD_PACKET"],
                    "vni": None,
                    "option_bytes": 0,
                }

            issues: list[str] = []
            vni = packet.get("vni")
            options = packet.get("options", _MISSING)
            option_bytes = 0

            version = packet.get("version", _MISSING)
            if not _is_int(version) or version != 0:
                issues.append("GENEVE_BAD_VERSION")

            if not _is_int(vni) or not 1 <= vni <= 0xFFFFFF:
                issues.append("GENEVE_BAD_VNI")

            if not isinstance(options, list):
                issues.append("GENEVE_BAD_PACKET")
                return {
                    "ok": False,
                    "issues": issues,
                    "vni": vni,
                    "option_bytes": option_bytes,
                }

            if len(options) > self.max_options:
                issues.append("GENEVE_OPT_COUNT")

            option_bytes = self._audit_option_bytes(options)
            if option_bytes > self.max_option_bytes:
                issues.append("GENEVE_OPTS_OVERFLOW")

            seen: set[tuple[int, int]] = set()
            for raw in options:
                self._audit_option(raw, seen, issues)

            return {
                "ok": not issues,
                "issues": issues,
                "vni": vni,
                "option_bytes": option_bytes,
            }

    @staticmethod
    def _audit_option_bytes(options: list) -> int:
        total = 0
        for raw in options:
            value_length = 0
            if isinstance(raw, dict):
                value = raw.get("value", b"")
                if isinstance(value, (bytes, bytearray, memoryview)):
                    value_length = len(value)
            total += 4 + value_length
        return total

    def _audit_option(self, raw: object, seen: set[tuple[int, int]],
                      issues: list[str]) -> None:
        if not isinstance(raw, dict):
            issues.append("GENEVE_BAD_PACKET")
            return
        if "class" not in raw or "type" not in raw:
            issues.append("GENEVE_BAD_PACKET")
            return

        opt_class = raw["class"]
        opt_type = raw["type"]
        critical = raw.get("critical", False)
        if (not _is_int(opt_class) or not _is_int(opt_type)
                or not isinstance(critical, bool)):
            issues.append("GENEVE_BAD_PACKET")
            return

        key = (opt_class, opt_type)
        if key in seen:
            issues.append("GENEVE_OPT_DUP")
        else:
            seen.add(key)

        value = _bytes_value(raw.get("value", b""))
        if value is None:
            issues.append("GENEVE_BAD_PACKET")
            return

        record = self._registered.get(key)
        if opt_class not in self.allowed_classes or record is None:
            if critical:
                issues.append("GENEVE_CRITICAL_UNKNOWN")
            return

        if critical != record["critical"]:
            issues.append("GENEVE_CRITICAL_MISMATCH")

        length = len(value)
        if length > record["max_len"]:
            issues.append("GENEVE_OPT_LEN")
        if length == 0:
            issues.append("GENEVE_OPT_EMPTY")

        encoding = record["encoding"]
        if encoding == "utf8":
            try:
                value.decode("utf-8")
            except UnicodeDecodeError:
                issues.append("GENEVE_OPT_ENCODING")
        elif encoding == "ipv4":
            if len(value) != 4:
                issues.append("GENEVE_OPT_ENCODING")
            else:
                try:
                    ipaddress.IPv4Address(value)
                except ipaddress.AddressValueError:
                    issues.append("GENEVE_OPT_ENCODING")

    def cache_size(self) -> int:
        with self._lock:
            return len(self._cache)

    def clear_cache(self) -> int:
        with self._lock:
            count = len(self._cache)
            self._cache.clear()
            return count

    def stats(self) -> dict:
        with self._lock:
            return copy.deepcopy(self._counters)

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": _STATE_VERSION,
                "registered": self.list_options(),
                "allowed_classes": copy.deepcopy(self.allowed_classes),
                "cache": copy.deepcopy(self._cache),
                "counters": copy.deepcopy(self._counters),
            }

    def restore(self, state: dict) -> None:
        if (not isinstance(state, dict)
                or not _is_int(state.get("version"))
                or state.get("version") != _STATE_VERSION):
            raise GeneveError("GENEVE_STATE_VERSION")

        try:
            registered_rows = state["registered"]
            allowed_classes = tuple(state["allowed_classes"])
            cache_rows = state["cache"]
            counters = copy.deepcopy(state["counters"])
        except (KeyError, TypeError):
            raise GeneveError("GENEVE_STATE_VERSION") from None

        if not isinstance(registered_rows, list) or not isinstance(cache_rows, dict):
            raise GeneveError("GENEVE_STATE_VERSION")

        registered: dict[tuple[int, int], dict[str, Any]] = {}
        try:
            for row in copy.deepcopy(registered_rows):
                opt_class = row["class"]
                opt_type = row["type"]
                critical = row["critical"]
                max_len = row["max_len"]
                encoding = row["encoding"]
                if (not _is_int(opt_class) or not 0 <= opt_class <= 0xFFFF
                        or not _is_int(opt_type) or not 0 <= opt_type <= 0xFF
                        or not isinstance(critical, bool)
                        or not _is_int(max_len) or not 0 <= max_len <= 1024
                        or encoding not in _VALID_ENCODINGS):
                    raise GeneveError("GENEVE_STATE_VERSION")
                registered[(opt_class, opt_type)] = {
                    "class": opt_class,
                    "type": opt_type,
                    "critical": critical,
                    "max_len": max_len,
                    "encoding": encoding,
                }
        except (KeyError, TypeError):
            raise GeneveError("GENEVE_STATE_VERSION") from None

        if any(not _is_int(opt_class) or not 0 <= opt_class <= 0xFFFF
               for opt_class in allowed_classes):
            raise GeneveError("GENEVE_STATE_VERSION")

        cache: OrderedDict[str, dict[str, Any]] = OrderedDict()
        try:
            for request_id, result in copy.deepcopy(cache_rows).items():
                if not isinstance(request_id, str) or not isinstance(result, dict):
                    raise GeneveError("GENEVE_STATE_VERSION")
                cache[request_id] = result
        except (AttributeError, TypeError):
            raise GeneveError("GENEVE_STATE_VERSION") from None
        while len(cache) > self.cache_capacity:
            cache.popitem(last=False)

        expected_counters = {
            "parsed", "accepted", "rejected", "replayed",
            "skipped_options", "codes",
        }
        if (not isinstance(counters, dict)
                or set(counters) != expected_counters
                or not isinstance(counters["codes"], dict)
                or any(not _is_int(counters[name]) or counters[name] < 0
                       for name in expected_counters - {"codes"})):
            raise GeneveError("GENEVE_STATE_VERSION")

        with self._lock:
            self._registered = registered
            self.allowed_classes = allowed_classes
            self._cache = cache
            self._counters = counters
