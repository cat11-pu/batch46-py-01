"""Workload identity federation guard for cross-cluster SVIDs.

The guard owns issuers, workload registrations, node attestations, issued
SVIDs and their renewal lineage.  Every state transition and its audit record
is protected by one re-entrant lock so concurrent issuance cannot race past
the per-node outstanding limit or reuse a serial number.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import re
import threading
import time
from collections.abc import Mapping
from datetime import datetime, timezone


SNAPSHOT_VERSION = 1

WI_ISSUER_SECRET_INVALID = "WI_ISSUER_SECRET_INVALID"
WI_ISSUER_DUPLICATE = "WI_ISSUER_DUPLICATE"
WI_ISSUER_UNKNOWN = "WI_ISSUER_UNKNOWN"
WI_SELECTOR_INVALID = "WI_SELECTOR_INVALID"
WI_WORKLOAD_DUPLICATE = "WI_WORKLOAD_DUPLICATE"
WI_FACT_INVALID = "WI_FACT_INVALID"
WI_TTL_INVALID = "WI_TTL_INVALID"
WI_NODE_UNKNOWN = "WI_NODE_UNKNOWN"
WI_NODE_UNATTESTED = "WI_NODE_UNATTESTED"
WI_TENANT_MISMATCH = "WI_TENANT_MISMATCH"
WI_WORKLOAD_UNKNOWN = "WI_WORKLOAD_UNKNOWN"
WI_SELECTOR_MISMATCH = "WI_SELECTOR_MISMATCH"
WI_OUTSTANDING_LIMIT = "WI_OUTSTANDING_LIMIT"
WI_RENEW_TOO_EARLY = "WI_RENEW_TOO_EARLY"
WI_REVOKED = "WI_REVOKED"
WI_SVID_EXPIRED = "WI_SVID_EXPIRED"
WI_RENEW_LIMIT = "WI_RENEW_LIMIT"
WI_SVID_UNKNOWN = "WI_SVID_UNKNOWN"
WI_SVID_INVALID = "WI_SVID_INVALID"
WI_TRUST_DOMAIN_MISMATCH = "WI_TRUST_DOMAIN_MISMATCH"
WI_SIGNATURE_INVALID = "WI_SIGNATURE_INVALID"
WI_FACT_DRIFT = "WI_FACT_DRIFT"
WI_SNAPSHOT_INVALID = "WI_SNAPSHOT_INVALID"
WI_SNAPSHOT_STALE = "WI_SNAPSHOT_STALE"
WI_OK = "WI_OK"

SVID_SIGNATURE_FIELDS = (
    "serial",
    "trust_domain",
    "sa",
    "subject",
    "node",
    "fact_digest",
    "issued_at",
    "expires_at",
    "renewals",
    "parent",
)

_HEX_64 = re.compile(r"^[0-9a-fA-F]{64}$")
_SERIAL_SUFFIX = re.compile(r"/svid-(\d+)$")


class WorkloadIdentityError(ValueError):
    """A rejected workload-identity operation with a stable ``WI_*`` code."""

    def __init__(self, code: str, detail=None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail
        self.message = code


# Friendly aliases for callers that use a different exception name.
WIError = WorkloadIdentityError
SvidError = WorkloadIdentityError
SVIDError = WorkloadIdentityError
WorkloadError = WorkloadIdentityError
WorkloadIdentityGuardError = WorkloadIdentityError
GuardError = WorkloadIdentityError


def _is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _parse_time(value, code: str = WI_SVID_INVALID) -> float:
    """Accept epoch numbers, datetimes and ISO-8601 strings."""

    if value is None:
        return time.time()
    if isinstance(value, bool):
        raise WorkloadIdentityError(code, "boolean timestamp")
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, datetime):
        moment = value
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        return moment.timestamp()
    if isinstance(value, str):
        text = value.strip()
        if not text:
            raise WorkloadIdentityError(code, "empty timestamp")
        try:
            return float(text)
        except ValueError:
            pass
        iso = text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text
        try:
            moment = datetime.fromisoformat(iso)
        except ValueError as exc:
            raise WorkloadIdentityError(code, text) from exc
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        return moment.timestamp()
    raise WorkloadIdentityError(code, repr(value))


def _iso_utc(timestamp: float) -> str:
    return (
        datetime.fromtimestamp(timestamp, timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _format_like(now, timestamp: float) -> str:
    """Format ``timestamp`` using the timezone style of the caller's value."""

    if isinstance(now, str):
        text = now.strip()
        iso = text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text
        try:
            moment = datetime.fromisoformat(iso)
        except ValueError:
            return _iso_utc(timestamp)
        zone = moment.tzinfo or timezone.utc
        rendered = datetime.fromtimestamp(timestamp, zone).isoformat()
        if text.endswith(("Z", "z")):
            rendered = rendered.replace("+00:00", "Z")
        return rendered
    if isinstance(now, datetime):
        zone = now.tzinfo or timezone.utc
        return datetime.fromtimestamp(timestamp, zone).isoformat()
    return _iso_utc(timestamp)


def _display_now(now, timestamp: float) -> str:
    """Keep a caller-provided string's spelling, otherwise use canonical UTC."""

    if isinstance(now, str):
        return now
    if isinstance(now, datetime):
        return now.isoformat()
    return _iso_utc(timestamp)


def svid_signature(secret: str, claims: dict) -> str:
    """Return the canonical signature over the ten signed SVID fields.

    ``chain`` and ``status`` deliberately do not participate.  A missing or
    ``None`` value is rendered the same way as Python's ordinary string
    formatting would render it, which keeps the helper easy to reproduce.
    """

    payload = "|".join(
        "{}={}".format(field, claims.get(field, ""))
        for field in SVID_SIGNATURE_FIELDS
    )
    return hashlib.sha256((payload + "|" + secret).encode("utf-8")).hexdigest()


def _signature_alternates(secret: str, claims: dict):
    """Yield signatures for both common ``None`` encodings.

    The task specifies a signature helper but does not prescribe whether an
    absent root ``parent`` is rendered as ``None`` or as an empty string.
    Accepting both encodings keeps verification interoperable without making
    any unsigned field authoritative.
    """

    yield svid_signature(secret, claims)
    normalised = {
        field: (
            ""
            if claims.get(field) is None
            else claims.get(field)
        )
        for field in SVID_SIGNATURE_FIELDS
    }
    yield svid_signature(secret, normalised)


def fact_digest(facts: Mapping) -> str:
    """Hash node facts in a deterministic, JSON-safe way."""

    payload = json.dumps(
        dict(facts), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


compute_fact_digest = fact_digest


def _normalise_string_map(value, code: str) -> dict:
    if not isinstance(value, Mapping):
        raise WorkloadIdentityError(code, "expected a mapping")
    if not value:
        raise WorkloadIdentityError(code, "mapping is empty")
    result = {}
    for key, item in value.items():
        if not isinstance(key, str) or key == "":
            raise WorkloadIdentityError(code, repr(key))
        if not isinstance(item, str) or item == "":
            raise WorkloadIdentityError(code, repr(item))
        result[key] = item
    return result


def _public_svid(record: Mapping) -> dict:
    return {
        "serial": record["serial"],
        "trust_domain": record["trust_domain"],
        "sa": record["sa"],
        "subject": record["subject"],
        "node": record["node"],
        "fact_digest": record["fact_digest"],
        "issued_at": record["issued_at"],
        "expires_at": record["expires_at"],
        "renewals": record["renewals"],
        "parent": record.get("parent"),
        "chain": list(record.get("chain", [])),
        "status": record.get("status", "valid"),
        "signature": record["signature"],
    }


class WorkloadIdentityGuard:
    """Issue, renew, revoke and verify workload SVIDs."""

    SNAPSHOT_VERSION = SNAPSHOT_VERSION

    def __init__(
        self,
        max_ttl: int = 3600,
        min_ttl: int = 60,
        renew_window_ratio: float = 0.2,
        max_outstanding_per_node: int = 4,
        max_renewals: int = 2,
        audit_capacity: int = 256,
    ) -> None:
        self.max_ttl = int(max_ttl)
        self.min_ttl = int(min_ttl)
        try:
            ratio = float(renew_window_ratio)
        except (TypeError, ValueError):
            ratio = 0.2
        self.renew_window_ratio = min(1.0, max(0.0, ratio))
        self.max_outstanding_per_node = int(max_outstanding_per_node)
        self.max_renewals = int(max_renewals)
        self.audit_capacity = int(audit_capacity)

        self._lock = threading.RLock()
        self._issuers: dict[str, dict] = {}
        self._workloads: dict[tuple[str, str], dict] = {}
        self._nodes: dict[str, dict] = {}
        self._svids: dict[str, dict] = {}
        self._serial_counter = 0
        self._issuer_seq = 0
        self._snapshot_generation = 0
        self._clock_hint = 0.0
        self._audit: list[dict] = []
        self._stats = {
            "issued": 0,
            "renewed": 0,
            "revoked": 0,
            "verified": 0,
            "rejected": 0,
            "attestations": 0,
            "issuer_rotations": 0,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _changed(self) -> None:
        # Only snapshot() advances the snapshot generation.  Mutations are
        # protected by the serial and revocation watermarks merged on restore.
        return None

    def _touch(self, timestamp: float) -> None:
        if timestamp > self._clock_hint:
            self._clock_hint = timestamp

    def _audit_write(self, action: str, code: str = WI_OK, **fields) -> None:
        row = {"action": action, "code": code, "status": "ok"}
        if code != WI_OK:
            row["status"] = "rejected"
        for key, value in fields.items():
            row[key] = copy.deepcopy(value)
        self._audit.insert(0, row)
        if self.audit_capacity >= 0 and len(self._audit) > self.audit_capacity:
            del self._audit[self.audit_capacity :]

    def _issuer_view(self, record: Mapping) -> dict:
        return {
            "trust_domain": record["trust_domain"],
            "issuer_id": record.get("issuer_id"),
            "generation": record["generation"],
        }

    def _workload_view(self, record: Mapping, *, status: str, unchanged: bool):
        return {
            "trust_domain": record["trust_domain"],
            "sa": record["sa"],
            "selectors": dict(record["selectors"]),
            "issued": record.get("issued", 0),
            "status": status,
            "unchanged": unchanged,
        }

    def _node_view(self, record: Mapping) -> dict:
        return {
            "node_id": record["node_id"],
            "node": record["node_id"],
            "trust_domain": record["trust_domain"],
            "facts": dict(record["facts"]),
            "fact_digest": record["fact_digest"],
            "expires_at": record["expires_at"],
            "status": "attested",
        }

    def _effective_ttl(self, ttl_seconds) -> int:
        ttl = self.max_ttl if ttl_seconds is None else ttl_seconds
        if not _is_int(ttl) or ttl < self.min_ttl:
            raise WorkloadIdentityError(WI_TTL_INVALID, repr(ttl))
        if ttl > self.max_ttl:
            ttl = self.max_ttl
        return ttl

    def _outstanding_for_node(self, node_id: str, timestamp: float) -> int:
        return sum(
            1
            for record in self._svids.values()
            if record["node"] == node_id
            and not record.get("revoked", False)
            and not record.get("expired", False)
            and record["_expires_ts"] > timestamp
        )

    def _find_workload(self, trust_domain: str, sa: str):
        record = self._workloads.get((trust_domain, sa))
        if record is not None:
            return record
        for (other_domain, other_sa), other in self._workloads.items():
            if other_sa == sa and other_domain != trust_domain:
                raise WorkloadIdentityError(WI_TENANT_MISMATCH, sa)
        raise WorkloadIdentityError(WI_WORKLOAD_UNKNOWN, sa)

    def _next_serial(self, trust_domain: str) -> str:
        self._serial_counter += 1
        return "{}/svid-{:06d}".format(trust_domain, self._serial_counter)

    def _issue_record(
        self,
        *,
        trust_domain: str,
        sa: str,
        node_id: str,
        fact_digest_value: str,
        issued_at: str,
        issued_ts: float,
        ttl: int,
        renewals: int,
        parent,
        chain: list,
        expires_at: str,
    ) -> dict:
        issuer = (
            self._issuers.get(trust_domain)
            if isinstance(trust_domain, str)
            else None
        )
        if issuer is None:
            raise WorkloadIdentityError(WI_ISSUER_UNKNOWN, trust_domain)

        serial = self._next_serial(trust_domain)
        expires_ts = issued_ts + ttl
        claims = {
            "serial": serial,
            "trust_domain": trust_domain,
            "sa": sa,
            "subject": "spiffe://{}/sa/{}".format(trust_domain, sa),
            "node": node_id,
            "fact_digest": fact_digest_value,
            "issued_at": issued_at,
            "expires_at": expires_at,
            "renewals": renewals,
            "parent": parent,
        }
        record = dict(claims)
        record.update(
            {
                "chain": list(chain),
                "status": "valid",
                "signature": svid_signature(issuer["secret"], claims),
                "revoked": False,
                "revoked_at": None,
                "reason": None,
                "renewed_to": None,
                "_issued_ts": issued_ts,
                "_expires_ts": expires_ts,
            }
        )
        self._svids[serial] = record
        return record

    # ------------------------------------------------------------------
    # Issuers
    # ------------------------------------------------------------------
    def register_issuer(
        self,
        trust_domain: str,
        *,
        secret: str,
        issuer_id: str | None = None,
    ) -> dict:
        with self._lock:
            if not isinstance(secret, str) or _HEX_64.fullmatch(secret) is None:
                raise WorkloadIdentityError(WI_ISSUER_SECRET_INVALID, repr(secret))
            if trust_domain in self._issuers:
                raise WorkloadIdentityError(WI_ISSUER_DUPLICATE, trust_domain)

            record = {
                "trust_domain": trust_domain,
                "secret": secret,
                "secrets": [secret],
                "issuer_id": issuer_id,
                "generation": 1,
            }
            self._issuers[trust_domain] = record
            self._changed()
            self._audit_write(
                "issuer_registered",
                trust_domain=trust_domain,
                issuer_id=issuer_id,
            )
            return self._issuer_view(record)

    def rotate_issuer(self, trust_domain: str, *, secret: str) -> dict:
        with self._lock:
            record = self._issuers.get(trust_domain)
            if record is None:
                raise WorkloadIdentityError(WI_ISSUER_UNKNOWN, trust_domain)
            if not isinstance(secret, str) or _HEX_64.fullmatch(secret) is None:
                raise WorkloadIdentityError(WI_ISSUER_SECRET_INVALID, repr(secret))
            record.setdefault("secrets", [record["secret"]]).append(secret)
            record["secret"] = secret
            record["generation"] += 1
            self._stats["issuer_rotations"] += 1
            self._changed()
            self._audit_write(
                "issuer_rotated",
                trust_domain=trust_domain,
                generation=record["generation"],
            )
            return self._issuer_view(record)

    # ------------------------------------------------------------------
    # Workload registration
    # ------------------------------------------------------------------
    def register_workload(
        self,
        trust_domain: str,
        sa: str,
        *,
        selectors: dict[str, str],
    ) -> dict:
        with self._lock:
            normalised = _normalise_string_map(selectors, WI_SELECTOR_INVALID)
            key = (trust_domain, sa)
            existing = self._workloads.get(key)
            if existing is not None:
                if existing["selectors"] == normalised:
                    return self._workload_view(
                        existing, status="unchanged", unchanged=True
                    )
                raise WorkloadIdentityError(WI_WORKLOAD_DUPLICATE, sa)

            record = {
                "trust_domain": trust_domain,
                "sa": sa,
                "selectors": dict(normalised),
                "issued": 0,
            }
            self._workloads[key] = record
            self._changed()
            self._audit_write(
                "workload_registered",
                trust_domain=trust_domain,
                sa=sa,
                selectors=normalised,
            )
            return self._workload_view(
                record, status="registered", unchanged=False
            )

    # ------------------------------------------------------------------
    # Node attestation
    # ------------------------------------------------------------------
    def attest_node(
        self,
        node_id: str,
        *,
        trust_domain: str,
        facts: dict[str, str],
        ttl_seconds: int = 1800,
        now=None,
    ) -> dict:
        timestamp = _parse_time(now)
        ttl = 1800 if ttl_seconds is None else ttl_seconds
        with self._lock:
            normalised = _normalise_string_map(facts, WI_FACT_INVALID)
            if not _is_int(ttl) or ttl <= 0:
                raise WorkloadIdentityError(WI_TTL_INVALID, repr(ttl))
            if trust_domain not in self._issuers:
                raise WorkloadIdentityError(WI_ISSUER_UNKNOWN, trust_domain)

            self._touch(timestamp)
            digest = fact_digest(normalised)
            record = {
                "node_id": node_id,
                "trust_domain": trust_domain,
                "facts": dict(normalised),
                "fact_digest": digest,
                "issued_at": _display_now(now, timestamp),
                "expires_at": _format_like(now, timestamp + ttl),
                "_expires_ts": timestamp + ttl,
            }
            self._nodes[node_id] = record
            self._stats["attestations"] += 1
            self._changed()
            self._audit_write(
                "node_attested",
                node_id=node_id,
                trust_domain=trust_domain,
                fact_digest=digest,
                expires_at=record["expires_at"],
            )
            return self._node_view(record)

    # ------------------------------------------------------------------
    # SVID issuance and renewal
    # ------------------------------------------------------------------
    def issue_svid(
        self,
        node_id: str,
        *,
        sa: str,
        ttl_seconds: int | None = None,
        now=None,
    ) -> dict:
        timestamp = _parse_time(now)
        with self._lock:
            node = self._nodes.get(node_id)
            if node is None:
                raise WorkloadIdentityError(WI_NODE_UNKNOWN, node_id)
            if timestamp >= node["_expires_ts"]:
                raise WorkloadIdentityError(WI_NODE_UNATTESTED, node_id)

            workload = self._find_workload(node["trust_domain"], sa)
            for key, expected in workload["selectors"].items():
                if node["facts"].get(key) != expected:
                    raise WorkloadIdentityError(WI_SELECTOR_MISMATCH, key)

            if (
                self._outstanding_for_node(node_id, timestamp)
                >= self.max_outstanding_per_node
            ):
                raise WorkloadIdentityError(WI_OUTSTANDING_LIMIT, node_id)

            ttl = self._effective_ttl(ttl_seconds)
            self._touch(timestamp)
            issued_at = _display_now(now, timestamp)
            record = self._issue_record(
                trust_domain=node["trust_domain"],
                sa=sa,
                node_id=node_id,
                fact_digest_value=node["fact_digest"],
                issued_at=issued_at,
                issued_ts=timestamp,
                ttl=ttl,
                renewals=0,
                parent="",
                chain=[],
                expires_at=_format_like(now, timestamp + ttl),
            )
            workload["issued"] = workload.get("issued", 0) + 1
            self._stats["issued"] += 1
            self._changed()
            self._audit_write(
                "svid_issued",
                serial=record["serial"],
                node_id=node_id,
                trust_domain=record["trust_domain"],
                sa=sa,
            )
            return _public_svid(record)

    def renew_svid(
        self,
        serial: str,
        *,
        ttl_seconds: int | None = None,
        now=None,
    ) -> dict:
        timestamp = _parse_time(now)
        with self._lock:
            old = self._svids.get(serial)
            if old is None:
                raise WorkloadIdentityError(WI_SVID_UNKNOWN, serial)
            if old.get("revoked", False):
                raise WorkloadIdentityError(WI_REVOKED, serial)
            if timestamp >= old["_expires_ts"]:
                raise WorkloadIdentityError(WI_SVID_EXPIRED, serial)
            if old.get("renewed_to") is not None:
                raise WorkloadIdentityError(WI_RENEW_LIMIT, serial)
            if old["renewals"] >= self.max_renewals:
                raise WorkloadIdentityError(WI_RENEW_LIMIT, serial)

            lifetime = old["_expires_ts"] - old["_issued_ts"]
            window_start = old["_expires_ts"] - lifetime * self.renew_window_ratio
            if timestamp < window_start:
                raise WorkloadIdentityError(WI_RENEW_TOO_EARLY, serial)

            ttl = self._effective_ttl(ttl_seconds)
            if (
                self._outstanding_for_node(old["node"], timestamp)
                >= self.max_outstanding_per_node
            ):
                raise WorkloadIdentityError(WI_OUTSTANDING_LIMIT, old["node"])

            self._touch(timestamp)
            issued_at = _display_now(now, timestamp)
            record = self._issue_record(
                trust_domain=old["trust_domain"],
                sa=old["sa"],
                node_id=old["node"],
                fact_digest_value=old["fact_digest"],
                issued_at=issued_at,
                issued_ts=timestamp,
                ttl=ttl,
                renewals=old["renewals"] + 1,
                parent=old["serial"],
                chain=list(old.get("chain", [])) + [old["serial"]],
                expires_at=_format_like(now, timestamp + ttl),
            )
            old["renewed_to"] = record["serial"]
            self._stats["renewed"] += 1
            self._changed()
            self._audit_write(
                "svid_renewed",
                serial=record["serial"],
                parent=old["serial"],
                node_id=old["node"],
            )
            return _public_svid(record)

    # ------------------------------------------------------------------
    # Revocation
    # ------------------------------------------------------------------
    def revoke_serial(self, serial: str, *, reason: str = "manual") -> dict:
        with self._lock:
            record = self._svids.get(serial)
            if record is None:
                raise WorkloadIdentityError(WI_SVID_UNKNOWN, serial)

            revoked_at = _iso_utc(time.time())
            newly_revoked = 0
            stack = [serial]
            visited = set()
            while stack:
                current_serial = stack.pop()
                if current_serial in visited:
                    continue
                visited.add(current_serial)
                current = self._svids.get(current_serial)
                if current is None:
                    continue
                if not current.get("revoked", False):
                    current["revoked"] = True
                    current["status"] = "revoked"
                    current["revoked_at"] = revoked_at
                    current["reason"] = reason
                    newly_revoked += 1
                for child_serial, child in self._svids.items():
                    if child.get("parent") == current_serial:
                        stack.append(child_serial)

            if newly_revoked:
                self._stats["revoked"] += newly_revoked
                self._changed()
            self._audit_write(
                "serial_revoked",
                serial=serial,
                reason=reason,
                cascaded=newly_revoked,
            )
            stored_reason = record.get("reason") or reason
            return {
                "serial": serial,
                "status": "revoked",
                "reason": stored_reason,
                "cascaded": newly_revoked,
            }

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------
    def verify_svid(
        self,
        svid: dict,
        *,
        now=None,
        expected_trust_domain: str | None = None,
    ) -> dict:
        timestamp = _parse_time(now)
        with self._lock:
            self._touch(timestamp)
            try:
                return self._verify_locked(
                    svid,
                    timestamp=timestamp,
                    expected_trust_domain=expected_trust_domain,
                )
            except WorkloadIdentityError as exc:
                self._stats["rejected"] += 1
                serial = svid.get("serial") if isinstance(svid, Mapping) else None
                self._audit_write(
                    "svid_verified",
                    code=exc.code,
                    serial=serial,
                )
                raise

    def _verify_locked(
        self,
        svid: dict,
        *,
        timestamp: float,
        expected_trust_domain: str | None,
    ) -> dict:
        if not isinstance(svid, Mapping):
            raise WorkloadIdentityError(WI_SVID_INVALID, "not a mapping")
        required = SVID_SIGNATURE_FIELDS + ("signature",)
        if any(field not in svid for field in required):
            raise WorkloadIdentityError(WI_SVID_INVALID, "missing field")

        trust_domain = svid.get("trust_domain")
        if (
            expected_trust_domain is not None
            and trust_domain != expected_trust_domain
        ):
            raise WorkloadIdentityError(WI_TRUST_DOMAIN_MISMATCH, trust_domain)

        issuer = self._issuers.get(trust_domain)
        if issuer is None:
            raise WorkloadIdentityError(WI_ISSUER_UNKNOWN, trust_domain)

        supplied_signature = svid.get("signature")
        if not isinstance(supplied_signature, str):
            raise WorkloadIdentityError(WI_SIGNATURE_INVALID, "signature")
        secrets = issuer.get("secrets") or [issuer["secret"]]
        supplied_bytes = supplied_signature.encode("utf-8")
        matches = any(
            hmac.compare_digest(candidate.encode("utf-8"), supplied_bytes)
            for secret in reversed(secrets)
            for candidate in _signature_alternates(secret, svid)
        )
        if not matches:
            raise WorkloadIdentityError(WI_SIGNATURE_INVALID, trust_domain)

        serial = svid.get("serial")
        record = self._svids.get(serial) if isinstance(serial, str) else None
        if record is None:
            raise WorkloadIdentityError(WI_SVID_UNKNOWN, serial)
        if record.get("revoked", False):
            raise WorkloadIdentityError(WI_REVOKED, serial)
        if timestamp >= record["_expires_ts"]:
            raise WorkloadIdentityError(WI_SVID_EXPIRED, serial)

        node = self._nodes.get(record["node"])
        if node is None:
            raise WorkloadIdentityError(WI_NODE_UNKNOWN, record["node"])
        if node["fact_digest"] != record["fact_digest"]:
            raise WorkloadIdentityError(WI_FACT_DRIFT, record["node"])

        self._stats["verified"] += 1
        self._audit_write(
            "svid_verified",
            serial=serial,
            node_id=record["node"],
            trust_domain=record["trust_domain"],
        )
        return {
            "status": "valid",
            "serial": record["serial"],
            "trust_domain": record["trust_domain"],
            "sa": record["sa"],
            "subject": record["subject"],
            "node": record["node"],
            "expires_at": record["expires_at"],
            "renewals": record["renewals"],
        }

    # ------------------------------------------------------------------
    # State inspection
    # ------------------------------------------------------------------
    def node_state(self, node_id: str, now=None) -> dict:
        with self._lock:
            timestamp = (
                self._clock_hint if now is None else _parse_time(now)
            )
            record = self._nodes.get(node_id)
            if record is None:
                return {
                    "fact_digest": None,
                    "expires_at": None,
                    "outstanding": 0,
                }
            return {
                "fact_digest": record["fact_digest"],
                "expires_at": record["expires_at"],
                "outstanding": self._outstanding_for_node(node_id, timestamp),
            }

    def workload_state(self, trust_domain: str, sa: str) -> dict:
        with self._lock:
            record = self._workloads.get((trust_domain, sa))
            if record is None:
                return {"selectors": {}, "issued": 0}
            return {
                "selectors": dict(record["selectors"]),
                "issued": record.get("issued", 0),
            }

    # ------------------------------------------------------------------
    # Housekeeping / observability
    # ------------------------------------------------------------------
    def sweep(self, now=None) -> dict:
        timestamp = _parse_time(now)
        with self._lock:
            self._touch(timestamp)
            newly_swept = []
            for serial, record in self._svids.items():
                if (
                    timestamp >= record["_expires_ts"]
                    and not record.get("expired", False)
                ):
                    record["expired"] = True
                    if not record.get("revoked", False):
                        record["status"] = "expired"
                    newly_swept.append(serial)
            expired_nodes = sum(
                1
                for record in self._nodes.values()
                if timestamp >= record["_expires_ts"]
            )
            if expired_nodes or newly_swept:
                self._audit_write(
                    "swept",
                    nodes=expired_nodes,
                    svids=len(newly_swept),
                )
            return {
                "swept": len(newly_swept),
                "serials": list(newly_swept),
                "nodes": expired_nodes,
                "svids": len(newly_swept),
                "expired_nodes": expired_nodes,
                "expired_svids": len(newly_swept),
            }

    def audit(self, limit: int = 20) -> list:
        with self._lock:
            if limit is None:
                return copy.deepcopy(self._audit)
            if not _is_int(limit):
                return []
            if limit <= 0:
                return []
            return copy.deepcopy(self._audit[:limit])

    def stats(self) -> dict:
        with self._lock:
            active_records = [
                record
                for record in self._svids.values()
                if not record.get("revoked", False)
                and not record.get("expired", False)
                and record["_expires_ts"] > self._clock_hint
            ]
            expired_records = [
                record
                for record in self._svids.values()
                if record.get("expired", False)
                or record["_expires_ts"] <= self._clock_hint
            ]
            outstanding = len(active_records)
            active = len(active_records)
            expired = len(expired_records)
            revoked_now = sum(
                1
                for record in self._svids.values()
                if record.get("revoked")
            )
            total_issued = self._stats["issued"] + self._stats["renewed"]
            return {
                "issuers": len(self._issuers),
                "issuer_count": len(self._issuers),
                "workloads": len(self._workloads),
                "workload_count": len(self._workloads),
                "nodes": len(self._nodes),
                "node_count": len(self._nodes),
                "svids": len(self._svids),
                "svid_count": len(self._svids),
                "outstanding": outstanding,
                "active": active,
                "svids_active": active,
                "active_svids": active,
                "expired": expired,
                "svids_expired": expired,
                "expired_svids": expired,
                "issued": self._stats["issued"],
                "issued_svids": self._stats["issued"],
                "renewed": self._stats["renewed"],
                "renewals": self._stats["renewed"],
                "total_issued": total_issued,
                "revoked": self._stats["revoked"],
                "revoked_svids": revoked_now,
                "svids_revoked": revoked_now,
                "verified": self._stats["verified"],
                "verifications": self._stats["verified"],
                "rejected": self._stats["rejected"],
                "attestations": self._stats["attestations"],
                "issuer_rotations": self._stats["issuer_rotations"],
                "serial_counter": self._serial_counter,
                "serial": self._serial_counter,
                "next_serial": self._serial_counter + 1,
                "generation": self._snapshot_generation,
                "snapshot_generation": self._snapshot_generation,
                "audit_entries": len(self._audit),
                "audit": len(self._audit),
            }

    # ------------------------------------------------------------------
    # Snapshots
    # ------------------------------------------------------------------
    def snapshot(self) -> dict:
        with self._lock:
            self._snapshot_generation += 1
            snap = {
                "version": SNAPSHOT_VERSION,
                "generation": self._snapshot_generation,
                "config": {
                    "max_ttl": self.max_ttl,
                    "min_ttl": self.min_ttl,
                    "renew_window_ratio": self.renew_window_ratio,
                    "max_outstanding_per_node": self.max_outstanding_per_node,
                    "max_renewals": self.max_renewals,
                    "audit_capacity": self.audit_capacity,
                },
                "issuers": {
                    domain: copy.deepcopy(record)
                    for domain, record in self._issuers.items()
                },
                "workloads": [
                    copy.deepcopy(record)
                    for record in self._workloads.values()
                ],
                "nodes": {
                    node_id: copy.deepcopy(record)
                    for node_id, record in self._nodes.items()
                },
                "svids": {
                    serial: copy.deepcopy(record)
                    for serial, record in self._svids.items()
                },
                "serial_counter": self._serial_counter,
                "next_serial": self._serial_counter + 1,
                "issuer_seq": self._issuer_seq,
                "clock_hint": self._clock_hint,
                "audit": copy.deepcopy(self._audit),
                "stats": dict(self._stats),
            }
            try:
                json.dumps(snap)
            except (TypeError, ValueError) as exc:
                raise WorkloadIdentityError(WI_SNAPSHOT_INVALID, str(exc)) from exc
            return snap

    def restore(self, snap: dict) -> None:
        if isinstance(snap, str):
            try:
                snap = json.loads(snap)
            except (TypeError, ValueError) as exc:
                raise WorkloadIdentityError(WI_SNAPSHOT_INVALID, "invalid JSON") from exc

        with self._lock:
            try:
                if not isinstance(snap, Mapping):
                    raise ValueError("snapshot must be a mapping")
                version = snap.get("version")
                if isinstance(version, bool) or version not in (
                    SNAPSHOT_VERSION,
                    str(SNAPSHOT_VERSION),
                ):
                    raise ValueError("unknown snapshot version")

                required_top = (
                    "generation",
                    "issuers",
                    "workloads",
                    "nodes",
                    "svids",
                    "serial_counter",
                )
                if any(key not in snap for key in required_top):
                    raise ValueError("snapshot fields missing")
                json.dumps(snap)

                generation = snap["generation"]
                if not _is_int(generation) or generation < 0:
                    raise ValueError("invalid snapshot generation")

                config = snap.get("config", {})
                if not isinstance(config, Mapping):
                    raise ValueError("invalid config")
                max_ttl = int(config.get("max_ttl", self.max_ttl))
                min_ttl = int(config.get("min_ttl", self.min_ttl))
                renew_window_ratio = float(
                    config.get("renew_window_ratio", self.renew_window_ratio)
                )
                max_outstanding_per_node = int(
                    config.get(
                        "max_outstanding_per_node",
                        self.max_outstanding_per_node,
                    )
                )
                max_renewals = int(
                    config.get("max_renewals", self.max_renewals)
                )
                audit_capacity = int(
                    config.get("audit_capacity", self.audit_capacity)
                )

                raw_issuers = snap["issuers"]
                if not isinstance(raw_issuers, Mapping):
                    raise ValueError("invalid issuers")
                issuers = {}
                for domain, raw in raw_issuers.items():
                    if not isinstance(raw, Mapping):
                        raise ValueError("invalid issuer")
                    secret = raw.get("secret")
                    if (
                        not isinstance(secret, str)
                        or _HEX_64.fullmatch(secret) is None
                    ):
                        raise ValueError("invalid issuer secret")
                    issuer_generation = raw.get("generation", 1)
                    if (
                        not _is_int(issuer_generation)
                        or issuer_generation < 1
                    ):
                        raise ValueError("invalid issuer generation")
                    raw_secrets = raw.get("secrets", [secret])
                    if (
                        not isinstance(raw_secrets, (list, tuple))
                        or not raw_secrets
                        or any(
                            not isinstance(item, str)
                            or _HEX_64.fullmatch(item) is None
                            for item in raw_secrets
                        )
                    ):
                        raise ValueError("invalid issuer key history")
                    secrets = list(raw_secrets)
                    if secret not in secrets:
                        secrets.append(secret)
                    issuer_domain = raw.get("trust_domain", domain)
                    issuers[str(issuer_domain)] = {
                        "trust_domain": str(issuer_domain),
                        "secret": secret,
                        "secrets": secrets,
                        "issuer_id": raw.get("issuer_id"),
                        "generation": issuer_generation,
                    }

                workloads = {}
                raw_workloads = snap["workloads"]
                if isinstance(raw_workloads, Mapping):
                    workload_records = list(raw_workloads.values())
                elif isinstance(raw_workloads, (list, tuple)):
                    workload_records = list(raw_workloads)
                else:
                    raise ValueError("invalid workloads")
                for raw in workload_records:
                    if not isinstance(raw, Mapping):
                        raise ValueError("invalid workload")
                    domain = raw.get("trust_domain")
                    sa = raw.get("sa")
                    if not isinstance(domain, str) or not isinstance(sa, str):
                        raise ValueError("invalid workload identity")
                    selectors = _normalise_string_map(
                        raw.get("selectors"), WI_SNAPSHOT_INVALID
                    )
                    issued = raw.get("issued", 0)
                    if not _is_int(issued) or issued < 0:
                        raise ValueError("invalid workload issued count")
                    workloads[(domain, sa)] = {
                        "trust_domain": domain,
                        "sa": sa,
                        "selectors": dict(selectors),
                        "issued": issued,
                    }

                raw_nodes = snap["nodes"]
                if not isinstance(raw_nodes, Mapping):
                    raise ValueError("invalid nodes")
                nodes = {}
                for node_id, raw in raw_nodes.items():
                    if not isinstance(raw, Mapping):
                        raise ValueError("invalid node")
                    domain = raw.get("trust_domain")
                    if not isinstance(domain, str):
                        raise ValueError("invalid node trust domain")
                    facts = _normalise_string_map(
                        raw.get("facts"), WI_SNAPSHOT_INVALID
                    )
                    expires_ts = raw.get("_expires_ts")
                    if expires_ts is None:
                        expires_ts = _parse_time(
                            raw.get("expires_at"), WI_SNAPSHOT_INVALID
                        )
                    if not isinstance(expires_ts, (int, float)):
                        raise ValueError("invalid node expiry")
                    expires_ts = float(expires_ts)
                    digest = raw.get("fact_digest")
                    if not isinstance(digest, str):
                        digest = fact_digest(facts)
                    nodes[str(node_id)] = {
                        "node_id": str(raw.get("node_id", node_id)),
                        "trust_domain": domain,
                        "facts": dict(facts),
                        "fact_digest": digest,
                        "issued_at": raw.get("issued_at"),
                        "expires_at": raw.get(
                            "expires_at", _iso_utc(expires_ts)
                        ),
                        "_expires_ts": expires_ts,
                    }

                raw_svids = snap["svids"]
                if not isinstance(raw_svids, Mapping):
                    raise ValueError("invalid SVIDs")
                svids = {}
                highest_serial = 0
                for serial, raw in raw_svids.items():
                    if not isinstance(raw, Mapping):
                        raise ValueError("invalid SVID")
                    required_svid = SVID_SIGNATURE_FIELDS + ("signature",)
                    if any(field not in raw for field in required_svid):
                        raise ValueError("missing SVID field")
                    if not isinstance(raw.get("signature"), str):
                        raise ValueError("invalid SVID signature")
                    renewals = raw.get("renewals")
                    if not _is_int(renewals) or renewals < 0:
                        raise ValueError("invalid SVID renewal count")
                    chain = raw.get("chain", [])
                    if not isinstance(chain, (list, tuple)) or any(
                        not isinstance(item, str) for item in chain
                    ):
                        raise ValueError("invalid SVID chain")
                    issued_ts = raw.get("_issued_ts")
                    if issued_ts is None:
                        issued_ts = _parse_time(
                            raw.get("issued_at"), WI_SNAPSHOT_INVALID
                        )
                    expires_ts = raw.get("_expires_ts")
                    if expires_ts is None:
                        expires_ts = _parse_time(
                            raw.get("expires_at"), WI_SNAPSHOT_INVALID
                        )
                    if not isinstance(issued_ts, (int, float)) or not isinstance(
                        expires_ts, (int, float)
                    ):
                        raise ValueError("invalid SVID validity")
                    record = {
                        "serial": str(raw.get("serial", serial)),
                        "trust_domain": raw["trust_domain"],
                        "sa": raw["sa"],
                        "subject": raw["subject"],
                        "node": raw["node"],
                        "fact_digest": raw["fact_digest"],
                        "issued_at": raw["issued_at"],
                        "expires_at": raw["expires_at"],
                        "renewals": renewals,
                        "parent": raw.get("parent", ""),
                        "chain": list(chain),
                        "status": raw.get("status", "valid"),
                        "signature": raw["signature"],
                        "revoked": bool(raw.get("revoked", False)),
                        "revoked_at": raw.get("revoked_at"),
                        "reason": raw.get("reason"),
                        "renewed_to": raw.get("renewed_to"),
                        "expired": bool(
                            raw.get(
                                "expired",
                                raw.get("status") == "expired",
                            )
                        ),
                        "_issued_ts": float(issued_ts),
                        "_expires_ts": float(expires_ts),
                    }
                    svids[record["serial"]] = record
                    suffix = _SERIAL_SUFFIX.search(record["serial"])
                    if suffix is not None:
                        highest_serial = max(
                            highest_serial, int(suffix.group(1))
                        )

                serial_counter = snap["serial_counter"]
                if not _is_int(serial_counter) or serial_counter < 0:
                    raise ValueError("invalid serial counter")
                issuer_seq = snap.get("issuer_seq", self._issuer_seq)
                if not _is_int(issuer_seq) or issuer_seq < 0:
                    raise ValueError("invalid issuer sequence")
                clock_hint = snap.get("clock_hint", self._clock_hint)
                if not isinstance(clock_hint, (int, float)):
                    raise ValueError("invalid clock hint")

                raw_audit = snap.get("audit", [])
                if not isinstance(raw_audit, list):
                    raise ValueError("invalid audit")
                audit = copy.deepcopy(raw_audit)
                if audit_capacity >= 0:
                    audit = audit[:audit_capacity]

                stats = dict(self._stats)
                raw_stats = snap.get("stats", {})
                if not isinstance(raw_stats, Mapping):
                    raise ValueError("invalid stats")
                for key, value in raw_stats.items():
                    if _is_int(value) and value >= 0:
                        stats[key] = value
            except WorkloadIdentityError as exc:
                if exc.code == WI_SNAPSHOT_INVALID:
                    raise
                raise WorkloadIdentityError(WI_SNAPSHOT_INVALID, str(exc)) from exc
            except (KeyError, TypeError, ValueError) as exc:
                raise WorkloadIdentityError(
                    WI_SNAPSHOT_INVALID, str(exc)
                ) from exc

            if generation < self._snapshot_generation:
                raise WorkloadIdentityError(WI_SNAPSHOT_STALE, generation)

            # Never lower a watermark established since the snapshot was
            # taken, even when the caller restores the same snapshot twice.
            serial_counter = max(
                serial_counter, self._serial_counter, highest_serial
            )
            clock_hint = max(float(clock_hint), self._clock_hint)
            for serial, current in self._svids.items():
                restored = svids.get(serial)
                if restored is not None and current.get("revoked"):
                    restored["revoked"] = True
                    restored["status"] = "revoked"
                    restored["revoked_at"] = current.get("revoked_at")
                    restored["reason"] = current.get("reason")
            for key, value in self._stats.items():
                if _is_int(value):
                    stats[key] = max(stats.get(key, 0), value)

            self.max_ttl = max_ttl
            self.min_ttl = min_ttl
            self.renew_window_ratio = min(
                1.0, max(0.0, renew_window_ratio)
            )
            self.max_outstanding_per_node = max_outstanding_per_node
            self.max_renewals = max_renewals
            self.audit_capacity = audit_capacity
            self._issuers = issuers
            self._workloads = workloads
            self._nodes = nodes
            self._svids = svids
            self._serial_counter = serial_counter
            self._issuer_seq = max(issuer_seq, self._issuer_seq)
            self._clock_hint = clock_hint
            self._audit = audit
            self._stats = stats
            self._snapshot_generation = max(
                generation, self._snapshot_generation
            )


# Optional module-level facade for callers that do not need multiple guards.
_default_guard = None


def _guard() -> WorkloadIdentityGuard:
    global _default_guard
    if _default_guard is None:
        _default_guard = WorkloadIdentityGuard()
    return _default_guard


def register_issuer(trust_domain, *, secret, issuer_id=None):
    return _guard().register_issuer(
        trust_domain, secret=secret, issuer_id=issuer_id
    )


def rotate_issuer(trust_domain, *, secret):
    return _guard().rotate_issuer(trust_domain, secret=secret)


def register_workload(trust_domain, sa, *, selectors):
    return _guard().register_workload(trust_domain, sa, selectors=selectors)


def attest_node(node_id, *, trust_domain, facts, ttl_seconds=1800, now=None):
    return _guard().attest_node(
        node_id,
        trust_domain=trust_domain,
        facts=facts,
        ttl_seconds=ttl_seconds,
        now=now,
    )


def issue_svid(node_id, *, sa, ttl_seconds=None, now=None):
    return _guard().issue_svid(
        node_id, sa=sa, ttl_seconds=ttl_seconds, now=now
    )


def renew_svid(serial, *, ttl_seconds=None, now=None):
    return _guard().renew_svid(
        serial, ttl_seconds=ttl_seconds, now=now
    )


def revoke_serial(serial, *, reason="manual"):
    return _guard().revoke_serial(serial, reason=reason)


def verify_svid(svid, *, now=None, expected_trust_domain=None):
    return _guard().verify_svid(
        svid, now=now, expected_trust_domain=expected_trust_domain
    )


def node_state(node_id):
    return _guard().node_state(node_id)


def workload_state(trust_domain, sa):
    return _guard().workload_state(trust_domain, sa)


def sweep(now=None):
    return _guard().sweep(now=now)


def snapshot():
    return _guard().snapshot()


def restore(snap):
    return _guard().restore(snap)


def audit(limit=20):
    return _guard().audit(limit)


def stats():
    return _guard().stats()


__all__ = [
    "WorkloadIdentityGuard",
    "WorkloadIdentityError",
    "WIError",
    "SvidError",
    "SVIDError",
    "WorkloadError",
    "WorkloadIdentityGuardError",
    "GuardError",
    "svid_signature",
    "fact_digest",
    "compute_fact_digest",
    "SVID_SIGNATURE_FIELDS",
    "SNAPSHOT_VERSION",
    "WI_ISSUER_SECRET_INVALID",
    "WI_ISSUER_DUPLICATE",
    "WI_ISSUER_UNKNOWN",
    "WI_SELECTOR_INVALID",
    "WI_WORKLOAD_DUPLICATE",
    "WI_FACT_INVALID",
    "WI_TTL_INVALID",
    "WI_NODE_UNKNOWN",
    "WI_NODE_UNATTESTED",
    "WI_TENANT_MISMATCH",
    "WI_WORKLOAD_UNKNOWN",
    "WI_SELECTOR_MISMATCH",
    "WI_OUTSTANDING_LIMIT",
    "WI_RENEW_TOO_EARLY",
    "WI_REVOKED",
    "WI_SVID_EXPIRED",
    "WI_RENEW_LIMIT",
    "WI_SVID_UNKNOWN",
    "WI_SVID_INVALID",
    "WI_TRUST_DOMAIN_MISMATCH",
    "WI_SIGNATURE_INVALID",
    "WI_FACT_DRIFT",
    "WI_SNAPSHOT_INVALID",
    "WI_SNAPSHOT_STALE",
    "WI_OK",
    "register_issuer",
    "rotate_issuer",
    "register_workload",
    "attest_node",
    "issue_svid",
    "renew_svid",
    "revoke_serial",
    "verify_svid",
    "node_state",
    "workload_state",
    "sweep",
    "snapshot",
    "restore",
    "audit",
    "stats",
]
