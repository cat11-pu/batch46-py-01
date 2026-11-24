"""MPLS label-stack validation, session tracking, and snapshot support."""

from __future__ import annotations

import copy
import threading
import time
from collections.abc import Mapping, Sequence
from typing import Any


MAX_LABEL = (1 << 20) - 1
MAX_LABEL_VALUE = MAX_LABEL
DEFAULT_LABEL_MIN = 16
DEFAULT_LABEL_MAX = MAX_LABEL
MAX_AUDIT_ENTRIES = 500
SNAPSHOT_VERSION = 1

NULL_LABELS = frozenset({0, 3})
ENTROPY_LABEL = 7
RESERVED_LABELS = frozenset(range(0, 16))


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


class MplsError(ValueError):
    def __init__(self, code: str, detail: str | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail

    def __str__(self) -> str:
        if self.detail is None:
            return self.code
        return f"{self.code}: {self.detail}"


class MplsGuard:
    MAX_LABEL = MAX_LABEL
    RESERVED_LABELS = RESERVED_LABELS

    def __init__(self, *, max_depth: int = 8, max_sessions: int = 64) -> None:
        if not _is_int(max_depth) or max_depth < 1:
            raise MplsError("MPLS_DEPTH_EXCEEDED", max_depth)
        if not _is_int(max_sessions) or max_sessions < 1:
            raise MplsError("MPLS_SESSION_LIMIT", max_sessions)

        self.max_depth = max_depth
        self.max_sessions = max_sessions

        self._lock = threading.RLock()
        self._tenants: dict[str, dict[str, int]] = {}
        self._sessions: dict[tuple[str, str], dict[str, Any]] = {}
        self._audit: list[dict[str, Any]] = []
        self._audit_seq = 0

        self._pushes = 0
        self._pops = 0
        self._rejects = 0
        self._max_depth_seen = 0

    # ------------------------------------------------------------------
    # Audit and error helpers
    # ------------------------------------------------------------------

    def _append_audit(
        self,
        code: str,
        action: str,
        *,
        tenant: str | None = None,
        session: str | None = None,
        detail: object = None,
        status: str = "rejected",
    ) -> None:
        self._audit_seq += 1
        timestamp = time.time()
        self._audit.append(
            {
                "seq": self._audit_seq,
                "timestamp": timestamp,
                "time": timestamp,
                "tenant": tenant,
                "session": session,
                "action": action,
                "operation": action,
                "code": code,
                "error_code": code,
                "detail": detail,
                "status": status,
            }
        )
        overflow = len(self._audit) - MAX_AUDIT_ENTRIES
        if overflow > 0:
            del self._audit[:overflow]

    def _reject(
        self,
        code: str,
        action: str,
        *,
        tenant: str | None = None,
        session: str | None = None,
        detail: object = None,
        count: bool = True,
        status: str = "rejected",
    ) -> MplsError:
        if count:
            self._rejects += 1
        self._append_audit(
            code,
            action,
            tenant=tenant,
            session=session,
            detail=detail,
            status=status,
        )
        return MplsError(code, detail)

    # ------------------------------------------------------------------
    # Configuration and validation helpers
    # ------------------------------------------------------------------

    def _tenant_config(
        self,
        tenant: object,
        action: str,
        *,
        session: str | None = None,
    ) -> dict[str, int]:
        if not isinstance(tenant, str):
            raise self._reject(
                "MPLS_TENANT_RANGE",
                action,
                session=session,
                detail=tenant,
            )
        config = self._tenants.get(tenant)
        if config is None:
            return {
                "label_min": DEFAULT_LABEL_MIN,
                "label_max": DEFAULT_LABEL_MAX,
                "max_depth": self.max_depth,
            }
        return config

    @staticmethod
    def _stack_error(
        config: Mapping[str, int],
        labels: Sequence[object],
        *,
        allow_empty: bool = False,
    ) -> str | None:
        if len(labels) == 0:
            return None if allow_empty else "MPLS_STACK_EMPTY"
        if len(labels) > config["max_depth"]:
            return "MPLS_DEPTH_EXCEEDED"

        for value in labels:
            if not _is_int(value) or value < 0 or value > MAX_LABEL:
                return "MPLS_LABEL_RANGE"

        last = len(labels) - 1
        for index, value in enumerate(labels):
            if value in NULL_LABELS:
                if index != last:
                    return "MPLS_RESERVED_POSITION"
                continue
            if value == ENTROPY_LABEL:
                if len(labels) < 2 or index != last - 1:
                    return "MPLS_ENTROPY_POSITION"
                continue
            if value in RESERVED_LABELS:
                return "MPLS_RESERVED_LABEL"
            if value < config["label_min"] or value > config["label_max"]:
                return "MPLS_TENANT_RANGE"
        return None

    def _validated_stack(
        self,
        tenant: str,
        config: Mapping[str, int],
        labels: object,
        action: str,
        *,
        session: str | None = None,
        allow_empty: bool = False,
    ) -> list[int]:
        if labels is None:
            raise self._reject(
                "MPLS_STACK_EMPTY",
                action,
                tenant=tenant,
                session=session,
                detail=labels,
            )
        try:
            values = list(labels)  # type: ignore[arg-type]
        except TypeError:
            raise self._reject(
                "MPLS_STACK_EMPTY",
                action,
                tenant=tenant,
                session=session,
                detail=labels,
            ) from None

        self._max_depth_seen = max(self._max_depth_seen, len(values))
        code = self._stack_error(config, values, allow_empty=allow_empty)
        if code is not None:
            raise self._reject(
                code,
                action,
                tenant=tenant,
                session=session,
                detail=values,
            )
        return values

    def _require_session(
        self,
        tenant: str,
        session: object,
        action: str,
    ) -> tuple[tuple[str, str], dict[str, Any]]:
        if not isinstance(session, str):
            raise self._reject(
                "MPLS_SESSION_MISSING",
                action,
                tenant=tenant,
                detail=session,
            )
        key = (tenant, session)
        state = self._sessions.get(key)
        if state is None:
            raise self._reject(
                "MPLS_SESSION_MISSING",
                action,
                tenant=tenant,
                session=session,
            )
        return key, state

    # ------------------------------------------------------------------
    # Tenant registration and stateless validation
    # ------------------------------------------------------------------

    def register_tenant(
        self,
        tenant: str,
        *,
        label_min: int = DEFAULT_LABEL_MIN,
        label_max: int = DEFAULT_LABEL_MAX,
        max_depth: int | None = None,
    ) -> dict:
        with self._lock:
            if not isinstance(tenant, str):
                raise self._reject(
                    "MPLS_TENANT_RANGE",
                    "register_tenant",
                    detail=tenant,
                )
            if tenant in self._tenants:
                raise self._reject(
                    "MPLS_TENANT_EXISTS",
                    "register_tenant",
                    tenant=tenant,
                )
            if (
                not _is_int(label_min)
                or not _is_int(label_max)
                or label_min < DEFAULT_LABEL_MIN
                or label_max > MAX_LABEL
                or label_min > label_max
            ):
                raise self._reject(
                    "MPLS_TENANT_RANGE",
                    "register_tenant",
                    tenant=tenant,
                    detail=(label_min, label_max),
                )

            depth = self.max_depth if max_depth is None else max_depth
            if not _is_int(depth) or depth < 1:
                raise self._reject(
                    "MPLS_DEPTH_EXCEEDED",
                    "register_tenant",
                    tenant=tenant,
                    detail=max_depth,
                )

            config = {
                "label_min": label_min,
                "label_max": label_max,
                "max_depth": depth,
            }
            self._tenants[tenant] = config
            return {
                "tenant": tenant,
                "label_min": label_min,
                "label_max": label_max,
                "label_range": [label_min, label_max],
                "max_depth": depth,
                "status": "registered",
                "ok": True,
            }

    def validate_stack(self, tenant: str, labels: Sequence[int]) -> dict:
        with self._lock:
            config = self._tenant_config(tenant, "validate_stack")
            values = self._validated_stack(
                tenant,
                config,
                labels,
                "validate_stack",
            )
            return {
                "tenant": tenant,
                "valid": True,
                "ok": True,
                "status": "valid",
                "code": "MPLS_OK",
                "depth": len(values),
                "bottom": values[-1],
                "entropy": ENTROPY_LABEL in values,
                "labels": list(values),
                "stack": list(values),
                "max_depth": config["max_depth"],
            }

    # ------------------------------------------------------------------
    # Session operations
    # ------------------------------------------------------------------

    def push(
        self,
        tenant: str,
        session: str,
        label: int,
        *,
        token: str | None = None,
    ) -> dict:
        with self._lock:
            config = self._tenant_config(
                tenant,
                "push",
                session=session if isinstance(session, str) else None,
            )
            if not isinstance(session, str):
                raise self._reject(
                    "MPLS_SESSION_MISSING",
                    "push",
                    tenant=tenant,
                    detail=session,
                )

            key = (tenant, session)
            current = self._sessions.get(key)

            if (
                current is not None
                and token is not None
                and token in current["tokens"]
            ):
                stack = list(current["stack"])
                self._reject(
                    "MPLS_DUP_TOKEN",
                    "push",
                    tenant=tenant,
                    session=session,
                    detail=token,
                    status="duplicate",
                )
                return {
                    "tenant": tenant,
                    "session": session,
                    "label": label,
                    "token": token,
                    "status": "duplicate",
                    "code": "MPLS_DUP_TOKEN",
                    "ok": False,
                    "duplicate": True,
                    "depth": len(stack),
                    "labels": stack,
                    "stack": list(stack),
                }

            if current is None:
                candidate = [label]
            else:
                candidate = list(current["stack"]) + [label]

            values = self._validated_stack(
                tenant,
                config,
                candidate,
                "push",
                session=session,
            )

            if current is None:
                if len(self._sessions) >= self.max_sessions:
                    raise self._reject(
                        "MPLS_SESSION_LIMIT",
                        "push",
                        tenant=tenant,
                        session=session,
                        detail=self.max_sessions,
                    )
                tokens: set[object] = set()
            else:
                tokens = set(current["tokens"])

            if token is not None:
                try:
                    tokens.add(token)
                except TypeError:
                    raise self._reject(
                        "MPLS_DUP_TOKEN",
                        "push",
                        tenant=tenant,
                        session=session,
                        detail=token,
                    ) from None

            self._sessions[key] = {"stack": values, "tokens": tokens}
            self._pushes += 1
            return {
                "tenant": tenant,
                "session": session,
                "label": label,
                "token": token,
                "status": "applied",
                "code": "MPLS_OK",
                "ok": True,
                "duplicate": False,
                "depth": len(values),
                "labels": list(values),
                "stack": list(values),
            }

    def pop(self, tenant: str, session: str, count: int = 1) -> dict:
        with self._lock:
            self._tenant_config(
                tenant,
                "pop",
                session=session if isinstance(session, str) else None,
            )
            if not isinstance(session, str):
                raise self._reject(
                    "MPLS_SESSION_MISSING",
                    "pop",
                    tenant=tenant,
                    detail=session,
                )
            if not _is_int(count) or count < 1:
                raise self._reject(
                    "MPLS_BAD_COUNT",
                    "pop",
                    tenant=tenant,
                    session=session,
                    detail=count,
                )

            key, current = self._require_session(tenant, session, "pop")
            stack = current["stack"]
            if count > len(stack):
                raise self._reject(
                    "MPLS_UNDERFLOW",
                    "pop",
                    tenant=tenant,
                    session=session,
                    detail=count,
                )

            removed = list(reversed(stack[-count:]))
            remaining = list(stack[:-count])
            self._sessions[key] = {
                "stack": remaining,
                "tokens": set(current["tokens"]),
            }
            self._pops += count
            return {
                "tenant": tenant,
                "session": session,
                "count": count,
                "removed": removed,
                "status": "popped",
                "code": "MPLS_OK",
                "ok": True,
                "depth": len(remaining),
                "labels": list(remaining),
                "remaining": list(remaining),
                "stack": list(remaining),
            }

    def swap_top(self, tenant: str, session: str, label: int) -> dict:
        with self._lock:
            config = self._tenant_config(
                tenant,
                "swap_top",
                session=session if isinstance(session, str) else None,
            )
            if not isinstance(session, str):
                raise self._reject(
                    "MPLS_SESSION_MISSING",
                    "swap_top",
                    tenant=tenant,
                    detail=session,
                )

            key, current = self._require_session(tenant, session, "swap_top")
            stack = current["stack"]
            if not stack:
                raise self._reject(
                    "MPLS_UNDERFLOW",
                    "swap_top",
                    tenant=tenant,
                    session=session,
                )

            candidate = list(stack[:-1]) + [label]
            values = self._validated_stack(
                tenant,
                config,
                candidate,
                "swap_top",
                session=session,
            )
            previous = stack[-1]
            self._sessions[key] = {
                "stack": values,
                "tokens": set(current["tokens"]),
            }
            return {
                "tenant": tenant,
                "session": session,
                "label": label,
                "previous": previous,
                "status": "swapped",
                "code": "MPLS_OK",
                "ok": True,
                "depth": len(values),
                "labels": list(values),
                "stack": list(values),
            }

    def read_stack(self, tenant: str, session: str) -> list[int]:
        with self._lock:
            self._tenant_config(
                tenant,
                "read_stack",
                session=session if isinstance(session, str) else None,
            )
            _, current = self._require_session(tenant, session, "read_stack")
            return list(current["stack"])

    def close_session(self, tenant: str, session: str) -> bool:
        with self._lock:
            if not isinstance(tenant, str) or not isinstance(session, str):
                return False
            return self._sessions.pop((tenant, session), None) is not None

    # ------------------------------------------------------------------
    # Audit and metrics
    # ------------------------------------------------------------------

    def audit(self, tenant: str | None = None, limit: int = 100) -> list[dict]:
        with self._lock:
            if not _is_int(limit) or limit < 1 or limit > 1000:
                raise self._reject(
                    "MPLS_BAD_LIMIT",
                    "audit",
                    tenant=tenant if isinstance(tenant, str) else None,
                    detail=limit,
                )

            rows: list[dict] = []
            for record in reversed(self._audit):
                if tenant is not None and record["tenant"] != tenant:
                    continue
                rows.append(copy.deepcopy(record))
                if len(rows) >= limit:
                    break
            return rows

    def metrics(self) -> dict:
        with self._lock:
            return {
                "pushes": self._pushes,
                "pops": self._pops,
                "rejects": self._rejects,
                "sessions": len(self._sessions),
                "max_depth_seen": self._max_depth_seen,
            }

    # ------------------------------------------------------------------
    # Snapshot and restore
    # ------------------------------------------------------------------

    def snapshot(self) -> dict:
        with self._lock:
            tenants = {
                tenant: dict(config)
                for tenant, config in self._tenants.items()
            }

            sessions: dict[str, dict[str, dict[str, Any]]] = {}
            tokens: dict[str, dict[str, list[object]]] = {}
            for (tenant, session), current in self._sessions.items():
                token_values = sorted(current["tokens"], key=repr)
                sessions.setdefault(tenant, {})[session] = {
                    "stack": list(current["stack"]),
                    "tokens": list(token_values),
                }
                tokens.setdefault(tenant, {})[session] = list(token_values)

            return {
                "version": SNAPSHOT_VERSION,
                "tenants": tenants,
                "sessions": sessions,
                "tokens": tokens,
                "counters": {
                    "pushes": self._pushes,
                    "pops": self._pops,
                    "rejects": self._rejects,
                    "max_depth_seen": self._max_depth_seen,
                },
            }

    @staticmethod
    def _snapshot_invalid(detail: object = None) -> MplsError:
        return MplsError("MPLS_SNAPSHOT_INVALID", detail)

    def _parse_snapshot_tenants(
        self,
        raw: object,
    ) -> dict[str, dict[str, int]]:
        if not isinstance(raw, Mapping):
            raise self._snapshot_invalid("tenants")

        tenants: dict[str, dict[str, int]] = {}
        for tenant, config in raw.items():
            if not isinstance(tenant, str) or not isinstance(config, Mapping):
                raise self._snapshot_invalid(tenant)
            label_min = config.get("label_min")
            label_max = config.get("label_max")
            depth = config.get("max_depth")
            if (
                not _is_int(label_min)
                or not _is_int(label_max)
                or not _is_int(depth)
                or label_min < DEFAULT_LABEL_MIN
                or label_max > MAX_LABEL
                or label_min > label_max
                or depth < 1
            ):
                raise self._snapshot_invalid(tenant)
            tenants[tenant] = {
                "label_min": label_min,
                "label_max": label_max,
                "max_depth": depth,
            }
        return tenants

    def _parse_snapshot_sessions(
        self,
        raw_sessions: object,
        raw_tokens: object,
        tenants: Mapping[str, Mapping[str, int]],
    ) -> dict[tuple[str, str], dict[str, Any]]:
        if not isinstance(raw_sessions, Mapping):
            raise self._snapshot_invalid("sessions")
        if not isinstance(raw_tokens, Mapping):
            raise self._snapshot_invalid("tokens")

        parsed: dict[tuple[str, str], dict[str, Any]] = {}
        for tenant, tenant_sessions in raw_sessions.items():
            if not isinstance(tenant, str) or not isinstance(tenant_sessions, Mapping):
                raise self._snapshot_invalid(tenant)
            tenant_tokens = raw_tokens.get(tenant, {})
            if not isinstance(tenant_tokens, Mapping):
                raise self._snapshot_invalid(tenant)

            config = tenants.get(tenant)
            if config is None:
                config = {
                    "label_min": DEFAULT_LABEL_MIN,
                    "label_max": DEFAULT_LABEL_MAX,
                    "max_depth": self.max_depth,
                }

            for session, record in tenant_sessions.items():
                if not isinstance(session, str) or not isinstance(record, Mapping):
                    raise self._snapshot_invalid(session)
                stack = record.get("stack")
                if not isinstance(stack, (list, tuple)):
                    raise self._snapshot_invalid(session)
                code = self._stack_error(config, stack, allow_empty=True)
                if code is not None:
                    raise self._snapshot_invalid(code)

                record_tokens = record.get("tokens", [])
                bucket_tokens = tenant_tokens.get(session, [])
                if (
                    not isinstance(record_tokens, (list, tuple, set, frozenset))
                    or not isinstance(bucket_tokens, (list, tuple, set, frozenset))
                ):
                    raise self._snapshot_invalid(session)

                token_set: set[object] = set()
                for token in list(record_tokens) + list(bucket_tokens):
                    try:
                        hash(token)
                    except TypeError:
                        raise self._snapshot_invalid(session) from None
                    token_set.add(token)

                parsed[(tenant, session)] = {
                    "stack": list(stack),
                    "tokens": token_set,
                }
        return parsed

    @staticmethod
    def _parse_snapshot_counters(
        raw: object,
    ) -> tuple[int, int, int, int]:
        if not isinstance(raw, Mapping):
            raise MplsGuard._snapshot_invalid("counters")
        values: list[int] = []
        for name in ("pushes", "pops", "rejects", "max_depth_seen"):
            value = raw.get(name)
            if not _is_int(value) or value < 0:
                raise MplsGuard._snapshot_invalid(name)
            values.append(value)
        return values[0], values[1], values[2], values[3]

    def restore(self, payload: Mapping[str, object]) -> dict:
        with self._lock:
            try:
                if not isinstance(payload, Mapping):
                    raise self._snapshot_invalid(type(payload).__name__)

                version = payload.get("version")
                if not _is_int(version) or version != SNAPSHOT_VERSION:
                    raise self._snapshot_invalid("version")
                for required in ("tenants", "sessions", "tokens", "counters"):
                    if required not in payload:
                        raise self._snapshot_invalid(required)

                tenants = self._parse_snapshot_tenants(payload["tenants"])
                sessions = self._parse_snapshot_sessions(
                    payload["sessions"],
                    payload["tokens"],
                    tenants,
                )
                pushes, pops, rejects, saved_depth = (
                    self._parse_snapshot_counters(payload["counters"])
                )
            except MplsError as exc:
                self._reject(
                    "MPLS_SNAPSHOT_INVALID",
                    "restore",
                    detail=exc.detail,
                    count=False,
                )
                raise self._snapshot_invalid(exc.detail) from None

            observed_depth = max(
                (len(current["stack"]) for current in sessions.values()),
                default=0,
            )
            max_depth_seen = max(
                self._max_depth_seen,
                saved_depth,
                observed_depth,
            )

            self._tenants = tenants
            self._sessions = sessions
            self._pushes = pushes
            self._pops = pops
            self._rejects = rejects
            self._max_depth_seen = max_depth_seen

            return {
                "status": "restored",
                "code": "MPLS_OK",
                "ok": True,
                "restored": True,
                "version": SNAPSHOT_VERSION,
                "tenants": len(self._tenants),
                "sessions": len(self._sessions),
                "pushes": self._pushes,
                "pops": self._pops,
                "rejects": self._rejects,
                "max_depth_seen": self._max_depth_seen,
            }
