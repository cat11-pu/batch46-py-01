"""gRPC server reflection exposure guard."""

from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
import re
import secrets
import threading
import time

SNAPSHOT_VERSION = 1
VISIBILITIES = ("public", "internal", "private")

_SERVICE_SEGMENT_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")
_METHOD_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_VIOLATION_CODES = frozenset({
    "RFG_DENIED",
    "RFG_NOT_FOUND",
    "RFG_RATE_LIMIT",
    "RFG_BAD_CURSOR",
    "RFG_BAD_PAGE",
    "RFG_BAD_SYMBOL",
})
_AUDIT_OPS = frozenset({
    "list_services",
    "list_methods",
    "resolve_symbol",
    "block",
    "unblock",
    "expire",
})
_STAT_KEYS = (
    "services",
    "callers",
    "requests",
    "denied",
    "not_found",
    "rate_limited",
    "blocked",
    "audit",
)
_COUNTER_KEYS = ("requests", "denied", "not_found", "rate_limited")


class ReflectionError(ValueError):
    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class ReflectionGuard:
    """Service registry, per-caller grants, listing, rate limits and audits."""

    def __init__(self, *, max_services: int = 64,
                 max_methods_per_response: int = 50, rate_limit: int = 10,
                 rate_window: int = 60, enumeration_threshold: int = 5,
                 block_seconds: int = 120, audit_limit: int = 200) -> None:
        self.max_services = max_services
        self.max_methods_per_response = max_methods_per_response
        self.rate_limit = rate_limit
        self.rate_window = rate_window
        self.enumeration_threshold = enumeration_threshold
        self.block_seconds = block_seconds
        self.audit_limit = audit_limit
        self._lock = threading.RLock()
        self._services = {}
        self._grants = {}
        self._blocked = {}
        self._recent = {}
        self._violations = {}
        self._audit = []
        self._stats = {key: 0 for key in _COUNTER_KEYS}
        self._cursor_key = secrets.token_bytes(32)

    # ------------------------------------------------------------------
    # Internal helpers

    @staticmethod
    def _effective_now(now: int | None) -> int:
        return int(time.time()) if now is None else int(now)

    @staticmethod
    def _is_int(value: object) -> bool:
        return isinstance(value, int) and not isinstance(value, bool)

    @classmethod
    def _valid_service_name(cls, name: object) -> bool:
        if not isinstance(name, str):
            return False
        parts = name.split(".")
        return (
            len(parts) >= 2
            and all(_SERVICE_SEGMENT_RE.fullmatch(part) for part in parts)
        )

    @staticmethod
    def _valid_method_name(method: object) -> bool:
        return isinstance(method, str) and bool(_METHOD_RE.fullmatch(method))

    @staticmethod
    def _corrupt(detail: object) -> ReflectionError:
        return ReflectionError("RFG_SNAPSHOT_CORRUPT", detail)

    def _append_audit_locked(self, caller: str, op: str, code: str,
                             ts: int) -> None:
        if self.audit_limit <= 0:
            self._audit.clear()
            return
        self._audit.append({
            "caller": caller,
            "op": op,
            "code": code,
            "ts": ts,
        })
        if len(self._audit) > self.audit_limit:
            del self._audit[:-self.audit_limit]

    def _audit_expiry_locked(self, caller: str, ts: int) -> None:
        self._append_audit_locked(caller, "expire", "RFG_EXPIRED", ts)

    def _purge_caller_block_locked(self, caller: str, now: int) -> None:
        until = self._blocked.get(caller)
        if until is not None and until <= now:
            del self._blocked[caller]
            self._audit_expiry_locked(caller, now)

    def _purge_all_blocks_locked(self, now: int) -> list[str]:
        expired = sorted(
            caller for caller, until in self._blocked.items()
            if until <= now
        )
        for caller in expired:
            del self._blocked[caller]
            self._audit_expiry_locked(caller, now)
        return expired

    def _enter_access_locked(self, caller: str, now: int) -> None:
        self._purge_caller_block_locked(caller, now)
        if caller in self._blocked:
            raise ReflectionError(
                "RFG_BLOCKED", {"caller": caller, "until": self._blocked[caller]}
            )

        self._stats["requests"] += 1
        cutoff = now - self.rate_window
        recent = [
            stamp for stamp in self._recent.get(caller, ())
            if stamp > cutoff
        ]
        recent.append(now)
        bounded_size = max(1, self.rate_limit) + 1
        if len(recent) > bounded_size:
            recent = recent[-bounded_size:]
        self._recent[caller] = recent
        if len(recent) > self.rate_limit:
            raise ReflectionError(
                "RFG_RATE_LIMIT",
                {"caller": caller, "limit": self.rate_limit,
                 "window": self.rate_window},
            )

    def _start_access_locked(self, caller: str, now: int, op: str) -> None:
        try:
            self._enter_access_locked(caller, now)
        except ReflectionError as exc:
            if exc.code != "RFG_BLOCKED":
                self._record_access_failure_locked(
                    caller, op, exc.code, now
                )
            raise

    def _record_access_failure_locked(self, caller: str, op: str,
                                      code: str, now: int) -> None:
        if code == "RFG_DENIED":
            self._stats["denied"] += 1
        elif code == "RFG_NOT_FOUND":
            self._stats["not_found"] += 1
        elif code == "RFG_RATE_LIMIT":
            self._stats["rate_limited"] += 1

        self._append_audit_locked(caller, op, code, now)
        if code not in _VIOLATION_CODES:
            return

        cutoff = now - self.rate_window
        violations = [
            stamp for stamp in self._violations.get(caller, ())
            if stamp > cutoff
        ]
        violations.append(now)
        bounded_size = max(1, self.enumeration_threshold)
        if len(violations) > bounded_size:
            violations = violations[-bounded_size:]
        self._violations[caller] = violations

        if len(violations) >= self.enumeration_threshold:
            until = self._blocked.get(caller)
            if until is None or until <= now:
                self._blocked[caller] = now + self.block_seconds
                self._append_audit_locked(
                    caller, "block", "RFG_BLOCKED", now
                )

    def _page_limit(self, page_size: int | None) -> int:
        if page_size is None:
            page_size = self.max_methods_per_response
        if not self._is_int(page_size) or page_size < 1:
            raise ReflectionError("RFG_BAD_PAGE", page_size)
        if page_size > self.max_methods_per_response:
            page_size = self.max_methods_per_response
        return page_size

    @staticmethod
    def _cursor_part(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")

    @staticmethod
    def _decode_cursor_part(text: str) -> bytes:
        padding = "=" * (-len(text) % 4)
        return base64.b64decode(
            (text + padding).encode("ascii"), altchars=b"-_", validate=True
        )

    def _encode_cursor(self, kind: str, service: str | None,
                       offset: int) -> str:
        payload = json.dumps(
            [kind, service, offset], separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
        signature = hmac.new(
            self._cursor_key, payload, hashlib.sha256
        ).digest()
        return self._cursor_part(payload) + "." + self._cursor_part(signature)

    def _decode_cursor(self, cursor: str, kind: str,
                       service: str | None) -> int:
        try:
            if not isinstance(cursor, str):
                raise ValueError
            pieces = cursor.split(".")
            if len(pieces) != 2:
                raise ValueError
            payload = self._decode_cursor_part(pieces[0])
            signature = self._decode_cursor_part(pieces[1])
            expected = hmac.new(
                self._cursor_key, payload, hashlib.sha256
            ).digest()
            if not hmac.compare_digest(signature, expected):
                raise ValueError
            decoded = json.loads(payload.decode("utf-8"))
            if not isinstance(decoded, list) or len(decoded) != 3:
                raise ValueError
            cursor_kind, cursor_service, offset = decoded
            if cursor_kind != kind or cursor_service != service:
                raise ValueError
            if not self._is_int(offset) or offset < 0:
                raise ValueError
            return offset
        except (ValueError, TypeError, UnicodeError, json.JSONDecodeError):
            raise ReflectionError("RFG_BAD_CURSOR", cursor) from None

    @staticmethod
    def _can_access(service: dict, granted: set[str],
                    name: str) -> bool:
        return service["visibility"] == "public" or name in granted

    def _stats_locked(self) -> dict:
        return {
            "services": len(self._services),
            "callers": len(self._grants),
            "requests": self._stats["requests"],
            "denied": self._stats["denied"],
            "not_found": self._stats["not_found"],
            "rate_limited": self._stats["rate_limited"],
            "blocked": len(self._blocked),
            "audit": len(self._audit),
        }

    # ------------------------------------------------------------------
    # Registration and authorization

    def register_service(self, name: str, *, visibility: str = "public",
                         methods: tuple = (),
                         labels: dict | None = None) -> dict:
        with self._lock:
            if not self._valid_service_name(name):
                raise ReflectionError("RFG_BAD_SERVICE", name)
            if visibility not in VISIBILITIES:
                raise ReflectionError("RFG_BAD_VISIBILITY", visibility)
            if isinstance(methods, (str, bytes)) or methods is None:
                raise ReflectionError("RFG_BAD_METHOD", methods)
            try:
                method_tuple = tuple(methods)
            except TypeError:
                raise ReflectionError("RFG_BAD_METHOD", methods) from None
            if any(
                not self._valid_method_name(method) for method in method_tuple
            ) or len(set(method_tuple)) != len(method_tuple):
                raise ReflectionError("RFG_BAD_METHOD", methods)
            if labels is None:
                label_copy = {}
            elif isinstance(labels, dict):
                label_copy = copy.deepcopy(labels)
            else:
                raise ReflectionError(
                    "RFG_BAD_SERVICE", "labels must be a dict"
                )

            existing = self._services.get(name)
            if existing is not None:
                if (
                    existing["visibility"] == visibility
                    and set(existing["methods"]) == set(method_tuple)
                    and existing["labels"] == label_copy
                ):
                    return {
                        "service": name,
                        "visibility": existing["visibility"],
                        "methods": tuple(existing["methods"]),
                        "status": "unchanged",
                    }
                raise ReflectionError("RFG_SERVICE_CONFLICT", name)

            if len(self._services) >= self.max_services:
                raise ReflectionError("RFG_CAPACITY", self.max_services)
            self._services[name] = {
                "visibility": visibility,
                "methods": method_tuple,
                "labels": label_copy,
            }
            return {
                "service": name,
                "visibility": visibility,
                "methods": method_tuple,
                "status": "registered",
            }

    def revoke_service(self, name: str) -> dict:
        with self._lock:
            if name not in self._services:
                raise ReflectionError("RFG_NOT_FOUND", name)
            del self._services[name]
            for granted in self._grants.values():
                granted.discard(name)
            return {"service": name, "status": "revoked"}

    def grant(self, caller: str, *, services: tuple = ()) -> dict:
        with self._lock:
            if not isinstance(caller, str) or not caller.strip():
                raise ReflectionError("RFG_BAD_CALLER", caller)
            if isinstance(services, (str, bytes)) or services is None:
                raise ReflectionError("RFG_UNKNOWN_SERVICE", services)
            try:
                requested = tuple(services)
            except TypeError:
                raise ReflectionError(
                    "RFG_UNKNOWN_SERVICE", services
                ) from None
            for service in requested:
                if not isinstance(service, str) or service not in self._services:
                    raise ReflectionError("RFG_UNKNOWN_SERVICE", service)

            normalized = tuple(sorted(set(requested)))
            self._grants[caller] = set(normalized)
            return {"caller": caller, "services": normalized}

    # ------------------------------------------------------------------
    # Reflection access

    def list_services(self, caller: str, *, page_size: int | None = None,
                      cursor: str | None = None,
                      now: int | None = None) -> dict:
        with self._lock:
            stamp = self._effective_now(now)
            self._start_access_locked(caller, stamp, "list_services")
            try:
                limit = self._page_limit(page_size)
                offset = (
                    self._decode_cursor(cursor, "services", None)
                    if cursor is not None else 0
                )
                granted = self._grants.get(caller, set())
                visible = sorted(
                    name for name, service in self._services.items()
                    if service["visibility"] == "public"
                    or (
                        service["visibility"] == "internal"
                        and name in granted
                    )
                )
                page = visible[offset:offset + limit]
                has_more = offset + limit < len(visible)
                next_cursor = (
                    self._encode_cursor("services", None, offset + limit)
                    if has_more else None
                )
                return {"services": page, "next_cursor": next_cursor}
            except ReflectionError as exc:
                self._record_access_failure_locked(
                    caller, "list_services", exc.code, stamp
                )
                raise

    def list_methods(self, caller: str, service: str, *,
                     page_size: int | None = None, cursor: str | None = None,
                     now: int | None = None) -> dict:
        with self._lock:
            stamp = self._effective_now(now)
            self._start_access_locked(caller, stamp, "list_methods")
            try:
                limit = self._page_limit(page_size)
                definition = (
                    self._services.get(service)
                    if isinstance(service, str) else None
                )
                if definition is None:
                    raise ReflectionError("RFG_NOT_FOUND", service)
                granted = self._grants.get(caller, set())
                if not self._can_access(definition, granted, service):
                    raise ReflectionError("RFG_DENIED", service)
                offset = (
                    self._decode_cursor(cursor, "methods", service)
                    if cursor is not None else 0
                )
                methods = sorted(definition["methods"])
                page = methods[offset:offset + limit]
                has_more = offset + limit < len(methods)
                next_cursor = (
                    self._encode_cursor("methods", service, offset + limit)
                    if has_more else None
                )
                return {
                    "service": service,
                    "methods": page,
                    "next_cursor": next_cursor,
                }
            except ReflectionError as exc:
                self._record_access_failure_locked(
                    caller, "list_methods", exc.code, stamp
                )
                raise

    def resolve_symbol(self, caller: str, symbol: str, *,
                       now: int | None = None) -> dict:
        with self._lock:
            stamp = self._effective_now(now)
            self._start_access_locked(caller, stamp, "resolve_symbol")
            try:
                if not isinstance(symbol, str) or not symbol:
                    raise ReflectionError("RFG_BAD_SYMBOL", symbol)
                pieces = symbol.split("/")
                if len(pieces) > 2:
                    raise ReflectionError("RFG_BAD_SYMBOL", symbol)
                if len(pieces) == 2:
                    service_name, method_name = pieces
                    if not service_name or not method_name:
                        raise ReflectionError("RFG_BAD_SYMBOL", symbol)
                else:
                    service_name = symbol
                    method_name = None

                definition = self._services.get(service_name)
                if definition is None:
                    raise ReflectionError("RFG_NOT_FOUND", service_name)
                granted = self._grants.get(caller, set())
                if not self._can_access(
                    definition, granted, service_name
                ):
                    raise ReflectionError("RFG_DENIED", service_name)
                if (
                    method_name is not None
                    and method_name not in definition["methods"]
                ):
                    raise ReflectionError(
                        "RFG_NOT_FOUND", f"{service_name}/{method_name}"
                    )
                return {
                    "kind": "service" if method_name is None else "method",
                    "service": service_name,
                    "method": method_name,
                }
            except ReflectionError as exc:
                self._record_access_failure_locked(
                    caller, "resolve_symbol", exc.code, stamp
                )
                raise

    # ------------------------------------------------------------------
    # Audit and blocking

    def audit(self, *, caller: str | None = None,
              limit: int | None = None,
              client: str | None = None) -> list:
        # ``client`` is kept as a compatibility alias for older callers.
        with self._lock:
            selected_caller = caller if caller is not None else client
            rows = (
                self._audit if selected_caller is None
                else [
                    row for row in self._audit
                    if row["caller"] == selected_caller
                ]
            )
            if limit is not None:
                if not self._is_int(limit):
                    raise ReflectionError("RFG_BAD_PAGE", limit)
                if limit <= 0:
                    rows = []
                else:
                    rows = rows[-limit:]
            return [dict(row) for row in rows]

    def block_caller(self, caller: str, seconds: int, *,
                     now: int | None = None) -> dict:
        with self._lock:
            if not self._is_int(seconds) or seconds <= 0:
                raise ReflectionError("RFG_BAD_BLOCK", seconds)
            stamp = self._effective_now(now)
            until = stamp + seconds
            self._blocked[caller] = until
            self._append_audit_locked(
                caller, "block", "RFG_BLOCKED", stamp
            )
            return {"caller": caller, "until": until, "status": "blocked"}

    def unblock_caller(self, caller: str) -> dict:
        with self._lock:
            self._blocked.pop(caller, None)
            self._append_audit_locked(
                caller, "unblock", "RFG_UNBLOCKED",
                self._effective_now(None),
            )
            return {"caller": caller, "status": "unblocked"}

    def blocked(self, *, now: int | None = None) -> list:
        with self._lock:
            stamp = self._effective_now(now)
            self._purge_all_blocks_locked(stamp)
            return sorted(self._blocked)

    def stats(self) -> dict:
        with self._lock:
            return self._stats_locked()

    def expire(self, now: int) -> list:
        with self._lock:
            stamp = self._effective_now(now)
            return self._purge_all_blocks_locked(stamp)

    # ------------------------------------------------------------------
    # Persistence

    def snapshot(self) -> dict:
        with self._lock:
            snapshot = {
                "version": SNAPSHOT_VERSION,
                "services": {
                    name: {
                        "visibility": service["visibility"],
                        "methods": list(service["methods"]),
                        "labels": copy.deepcopy(service["labels"]),
                    }
                    for name, service in self._services.items()
                },
                "grants": {
                    caller: sorted(services)
                    for caller, services in self._grants.items()
                },
                "blocked": dict(self._blocked),
                "rate": {
                    caller: list(stamps)
                    for caller, stamps in self._recent.items()
                },
                "violations": {
                    caller: list(stamps)
                    for caller, stamps in self._violations.items()
                },
                "audit": [dict(row) for row in self._audit],
                "stats": self._stats_locked(),
            }
            return copy.deepcopy(snapshot)

    def restore(self, snapshot: dict) -> None:
        with self._lock:
            try:
                validated = self._validate_snapshot(snapshot)
            except ReflectionError as exc:
                if exc.code == "RFG_SNAPSHOT_CORRUPT":
                    raise
                raise self._corrupt(exc.detail) from None
            except (TypeError, ValueError, KeyError, AttributeError) as exc:
                raise self._corrupt(str(exc)) from None

            self._services = validated["services"]
            self._grants = validated["grants"]
            self._blocked = validated["blocked"]
            self._recent = validated["rate"]
            self._violations = validated["violations"]
            self._audit = validated["audit"]
            self._stats = validated["stats"]

    def _validate_snapshot(self, snapshot: dict) -> dict:
        if not isinstance(snapshot, dict):
            raise self._corrupt("snapshot must be a dict")
        required = (
            "version", "services", "grants", "blocked", "rate",
            "violations", "audit", "stats",
        )
        if any(key not in snapshot for key in required):
            raise self._corrupt("missing snapshot fields")
        if (
            not self._is_int(snapshot["version"])
            or snapshot["version"] != SNAPSHOT_VERSION
        ):
            raise self._corrupt("unsupported snapshot version")

        raw_services = snapshot["services"]
        if not isinstance(raw_services, dict):
            raise self._corrupt("services must be a dict")
        if len(raw_services) > self.max_services:
            raise self._corrupt("service capacity exceeded")

        services = {}
        for name, raw in raw_services.items():
            if not self._valid_service_name(name):
                raise self._corrupt("invalid service name")
            if not isinstance(raw, dict):
                raise self._corrupt("service definition must be a dict")
            if not all(key in raw for key in ("visibility", "methods", "labels")):
                raise self._corrupt("missing service fields")
            visibility = raw["visibility"]
            if visibility not in VISIBILITIES:
                raise self._corrupt("invalid visibility")
            raw_methods = raw["methods"]
            if not isinstance(raw_methods, (list, tuple)):
                raise self._corrupt("methods must be a sequence")
            if any(
                not self._valid_method_name(method)
                for method in raw_methods
            ) or len(set(raw_methods)) != len(raw_methods):
                raise self._corrupt("invalid methods")
            if not isinstance(raw["labels"], dict):
                raise self._corrupt("labels must be a dict")
            services[name] = {
                "visibility": visibility,
                "methods": tuple(raw_methods),
                "labels": copy.deepcopy(raw["labels"]),
            }

        raw_grants = snapshot["grants"]
        if not isinstance(raw_grants, dict):
            raise self._corrupt("grants must be a dict")
        grants = {}
        for caller, raw in raw_grants.items():
            if not isinstance(caller, str) or not caller.strip():
                raise self._corrupt("invalid grant caller")
            if not isinstance(raw, (list, tuple)):
                raise self._corrupt("granted services must be a sequence")
            if any(not isinstance(name, str) for name in raw):
                raise self._corrupt("invalid granted service")
            if any(name not in services for name in raw):
                raise self._corrupt("grant references unknown service")
            grants[caller] = set(raw)

        raw_blocked = snapshot["blocked"]
        if not isinstance(raw_blocked, dict):
            raise self._corrupt("blocked must be a dict")
        blocked = {}
        for caller, until in raw_blocked.items():
            if not isinstance(caller, str) or not self._is_int(until):
                raise self._corrupt("invalid blocked entry")
            blocked[caller] = until

        raw_rate = snapshot["rate"]
        if not isinstance(raw_rate, dict):
            raise self._corrupt("rate must be a dict")
        rate = {}
        rate_bound = max(1, self.rate_limit) + 1
        for caller, raw in raw_rate.items():
            if not isinstance(caller, str) or not isinstance(raw, (list, tuple)):
                raise self._corrupt("invalid rate entry")
            if any(not self._is_int(stamp) for stamp in raw):
                raise self._corrupt("invalid rate timestamp")
            stamps = sorted(raw)
            if len(stamps) > rate_bound:
                stamps = stamps[-rate_bound:]
            rate[caller] = stamps

        raw_violations = snapshot["violations"]
        if not isinstance(raw_violations, dict):
            raise self._corrupt("violations must be a dict")
        violations = {}
        violation_bound = max(1, self.enumeration_threshold)
        for caller, raw in raw_violations.items():
            if not isinstance(caller, str) or not isinstance(raw, (list, tuple)):
                raise self._corrupt("invalid violation entry")
            if any(not self._is_int(stamp) for stamp in raw):
                raise self._corrupt("invalid violation timestamp")
            stamps = sorted(raw)
            if len(stamps) > violation_bound:
                stamps = stamps[-violation_bound:]
            violations[caller] = stamps

        raw_audit = snapshot["audit"]
        if not isinstance(raw_audit, list):
            raise self._corrupt("audit must be a list")
        audit = []
        for raw in raw_audit:
            if not isinstance(raw, dict):
                raise self._corrupt("audit entry must be a dict")
            if not all(key in raw for key in ("caller", "op", "code", "ts")):
                raise self._corrupt("missing audit fields")
            if (
                not isinstance(raw["caller"], str)
                or raw["op"] not in _AUDIT_OPS
                or not isinstance(raw["code"], str)
                or not self._is_int(raw["ts"])
            ):
                raise self._corrupt("invalid audit entry")
            audit.append({
                "caller": raw["caller"],
                "op": raw["op"],
                "code": raw["code"],
                "ts": raw["ts"],
            })
        if self.audit_limit <= 0:
            audit = []
        elif len(audit) > self.audit_limit:
            audit = audit[-self.audit_limit:]

        raw_stats = snapshot["stats"]
        if not isinstance(raw_stats, dict):
            raise self._corrupt("stats must be a dict")
        if any(key not in raw_stats for key in _STAT_KEYS):
            raise self._corrupt("missing stats fields")
        if any(
            not self._is_int(raw_stats[key]) or raw_stats[key] < 0
            for key in _STAT_KEYS
        ):
            raise self._corrupt("invalid statistics")
        stats = {key: raw_stats[key] for key in _COUNTER_KEYS}

        return {
            "services": services,
            "grants": grants,
            "blocked": blocked,
            "rate": rate,
            "violations": violations,
            "audit": audit,
            "stats": stats,
        }
