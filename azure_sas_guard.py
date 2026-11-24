"""Azure shared access signature permission, scope, expiry and key guard."""

from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import ipaddress
import threading
from typing import Any, Mapping


class SasError(ValueError):
    """Raised when a SAS cannot be issued or parsed."""

    def __init__(self, code: str, detail: str | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


_PERMISSION_ORDER = "racwdxltmeop"
_PERMISSION_SET = frozenset(_PERMISSION_ORDER)

_FIELD_ORDER = [
    "sa",
    "skv",
    "sv",
    "ss",
    "srt",
    "sp",
    "st",
    "se",
    "spr",
    "sip",
    "si",
    "sdd",
]

_SAS_VERSION = "2024-11-01"
_SAS_SERVICE = "b"
_PROTOCOLS = ("https", "https,http")


def _canonical_permissions(permissions: str) -> str:
    unknown = sorted(set(permissions) - _PERMISSION_SET)
    if unknown:
        raise SasError(
            "SAS_UNKNOWN_PERMISSION",
            "unknown permission(s): " + ",".join(unknown),
        )
    return "".join(ch for ch in _PERMISSION_ORDER if ch in permissions)


class SasGuard:
    """Issue and verify SAS tokens backed by stored access policies."""

    def __init__(self, *, max_records: int = 100, max_lifetime: int = 604800) -> None:
        self.max_records = max_records
        self.max_lifetime = max_lifetime
        self._lock = threading.RLock()
        self._keys: dict[str, str] = {}
        self._current: str | None = None
        self._retired: dict[str, int] = {}
        self._policies: dict[str, dict[str, Any]] = {}
        self._records: list[dict[str, Any]] = []
        self._built = 0
        self._verified = 0
        self._rejected = 0

    def register_key(self, version: str, secret: str) -> dict[str, Any]:
        with self._lock:
            self._keys[version] = secret
            if self._current is None:
                self._current = version
            return {"version": version, "current": self._current}

    def rotate_key(
        self,
        version: str,
        *,
        now: int,
        overlap: int = 300,
    ) -> dict[str, Any]:
        with self._lock:
            if version not in self._keys:
                raise SasError("SAS_UNKNOWN_KEY", f"unknown key version: {version}")
            previous = self._current
            if previous is not None and previous != version:
                self._retired[previous] = now + overlap
            self._current = version
            return {
                "current": version,
                "previous": previous,
                "retire_at": self._retired.get(previous) if previous else None,
            }

    def define_policy(
        self,
        name: str,
        *,
        permissions: str,
        start: int,
        expiry: int,
    ) -> dict[str, Any]:
        canonical = _canonical_permissions(permissions)
        with self._lock:
            policy = {
                "name": name,
                "permissions": canonical,
                "start": start,
                "expiry": expiry,
                "revoked": False,
                "revoked_at": None,
            }
            self._policies[name] = policy
            return dict(policy)

    def revoke_policy(self, name: str, *, now: int) -> dict[str, Any]:
        with self._lock:
            policy = self._policies.get(name)
            if policy is None:
                raise SasError("SAS_UNKNOWN_POLICY", f"unknown policy: {name}")
            policy["revoked"] = True
            policy["revoked_at"] = now
            return {"name": name, "revoked": True, "revoked_at": now}

    def check_permissions(self, granted: str, required: str) -> dict[str, Any]:
        effective = _canonical_permissions(granted)
        needed = _canonical_permissions(required)
        missing = [ch for ch in needed if ch not in effective]
        return {
            "allowed": not missing,
            "missing": missing,
            "effective": effective,
        }

    def build_sas(
        self,
        account: str,
        *,
        resource: str,
        permissions: str | None = None,
        start: int,
        expiry: int,
        key_version: str | None = None,
        policy: str | None = None,
        ip: str | None = None,
        protocol: str = "https",
    ) -> dict[str, Any]:
        if permissions is not None and policy is not None:
            raise SasError(
                "SAS_POLICY_CONFLICT",
                "permissions and policy are mutually exclusive",
            )
        canonical = (
            _canonical_permissions(permissions) if permissions is not None else ""
        )
        if expiry <= start or expiry - start > self.max_lifetime:
            raise SasError("SAS_INVALID_WINDOW", "invalid SAS validity window")
        if protocol not in _PROTOCOLS:
            raise SasError("SAS_BAD_PROTOCOL", f"unsupported protocol: {protocol}")
        scope = resource.strip("/")
        if not scope:
            raise SasError("SAS_INVALID_SCOPE", "resource scope is empty")
        network = ""
        if ip is not None:
            try:
                network = str(ipaddress.ip_network(ip, strict=False))
            except ValueError:
                raise SasError("SAS_BAD_IP", f"invalid CIDR: {ip}") from None
        with self._lock:
            key_version = key_version if key_version is not None else self._current
            if key_version is None or key_version not in self._keys:
                raise SasError(
                    "SAS_UNKNOWN_KEY", f"unknown key version: {key_version}"
                )
            eff_start, eff_expiry = start, expiry
            if policy is not None:
                stored = self._policies.get(policy)
                if stored is None:
                    raise SasError(
                        "SAS_UNKNOWN_POLICY", f"unknown policy: {policy}"
                    )
                eff_start = max(start, stored["start"])
                eff_expiry = min(expiry, stored["expiry"])
                if eff_expiry <= eff_start:
                    raise SasError(
                        "SAS_INVALID_WINDOW",
                        "policy window does not intersect SAS window",
                    )
            if len(self._records) >= self.max_records:
                raise SasError("SAS_RECORD_LIMIT", "SAS record store is full")
            fields = {
                "sa": account,
                "skv": key_version,
                "sv": _SAS_VERSION,
                "ss": _SAS_SERVICE,
                "srt": "o" if "/" in resource else "c",
                "sp": canonical,
                "st": str(eff_start),
                "se": str(eff_expiry),
                "spr": protocol,
                "sip": network,
                "si": policy or "",
                "sdd": scope,
            }
            signature = self._sign(fields)
            token = "&".join(
                [f"{name}={fields[name]}" for name in _FIELD_ORDER]
                + [f"sig={signature}"]
            )
            self._records.append(
                {
                    "signature": signature,
                    "resource": scope,
                    "policy": policy or "",
                    "key_version": key_version,
                    "start": eff_start,
                    "expiry": eff_expiry,
                }
            )
            self._built += 1
            return {"fields": fields, "token": token, "signature": signature}

    def string_to_sign(self, fields: Mapping[str, str]) -> str:
        return "\n".join(str(fields[name]) for name in _FIELD_ORDER)

    def _sign(self, fields: Mapping[str, str]) -> str:
        secret = self._keys[fields["skv"]]
        digest = hmac.new(
            secret.encode("utf-8"),
            self.string_to_sign(fields).encode("utf-8"),
            hashlib.sha256,
        ).digest()
        return base64.b64encode(digest).decode("ascii")

    @staticmethod
    def _parse_token(token: str) -> tuple[dict[str, str], str]:
        fields: dict[str, str] = {}
        signature = ""
        for part in token.split("&"):
            name, _, value = part.partition("=")
            if name == "sig":
                signature = value
            else:
                fields[name] = value
        return fields, signature

    def _normalize(
        self, sas: Mapping[str, Any] | str
    ) -> tuple[dict[str, str], str]:
        if isinstance(sas, str):
            return self._parse_token(sas)
        if "fields" in sas:
            fields = dict(sas["fields"])
        else:
            fields = dict(sas)
        signature = str(fields.pop("sig", "") or "")
        if not signature:
            token = sas.get("token")
            if token:
                _, signature = self._parse_token(token)
        if not signature:
            signature = str(sas.get("signature", "") or "")
        return fields, signature

    def _deny(self, code: str) -> dict[str, Any]:
        self._rejected += 1
        return {"status": "denied", "code": code}

    def verify(
        self,
        sas: Mapping[str, Any] | str,
        *,
        operation: str,
        now: int,
        target: str,
        client_ip: str | None = None,
        protocol: str = "https",
    ) -> dict[str, Any]:
        required = _canonical_permissions(operation)
        fields, signature = self._normalize(sas)
        with self._lock:
            key_version = fields.get("skv", "")
            secret = self._keys.get(key_version)
            if secret is None:
                return self._deny("SAS_UNKNOWN_KEY")
            expected = base64.b64encode(
                hmac.new(
                    secret.encode("utf-8"),
                    self.string_to_sign(fields).encode("utf-8"),
                    hashlib.sha256,
                ).digest()
            ).decode("ascii")
            if not signature or not hmac.compare_digest(expected, signature):
                return self._deny("SAS_BAD_SIGNATURE")
            retire_at = self._retired.get(key_version)
            if retire_at is not None and now >= retire_at:
                return self._deny("SAS_KEY_RETIRED")
            policy_name = fields.get("si", "")
            granted = fields.get("sp", "")
            if policy_name:
                policy = self._policies.get(policy_name)
                if policy is None:
                    return self._deny("SAS_UNKNOWN_POLICY")
                if policy["revoked"]:
                    return self._deny("SAS_POLICY_REVOKED")
                granted = policy["permissions"]
            if protocol not in fields.get("spr", "").split(","):
                return self._deny("SAS_DENY_PROTOCOL")
            sip = fields.get("sip", "")
            if sip:
                try:
                    network = ipaddress.ip_network(sip, strict=False)
                    source = ipaddress.ip_address(client_ip) if client_ip else None
                except ValueError:
                    source = None
                if source is None or source not in network:
                    return self._deny("SAS_DENY_IP")
            if now < int(fields["st"]):
                return self._deny("SAS_NOT_YET_VALID")
            if now >= int(fields["se"]):
                return self._deny("SAS_EXPIRED")
            if any(ch not in granted for ch in required):
                return self._deny("SAS_DENY_PERMISSION")
            scope = fields.get("sdd", "")
            target_scope = target.strip("/")
            if fields.get("srt") == "c":
                in_scope = target_scope == scope or target_scope.startswith(
                    scope + "/"
                )
            else:
                in_scope = target_scope == scope
            if not in_scope:
                return self._deny("SAS_DENY_SCOPE")
            self._verified += 1
            return {"status": "ok", "code": "SAS_OK"}

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return copy.deepcopy(
                {
                    "keys": self._keys,
                    "current": self._current,
                    "retired": self._retired,
                    "policies": self._policies,
                    "records": self._records,
                    "counters": {
                        "built": self._built,
                        "verified": self._verified,
                        "rejected": self._rejected,
                    },
                }
            )

    def restore(self, state: Mapping[str, Any]) -> None:
        with self._lock:
            restored = copy.deepcopy(dict(state))
            self._keys = dict(restored["keys"])
            self._current = restored["current"]
            self._retired = dict(restored["retired"])
            self._policies = dict(restored["policies"])
            self._records = list(restored["records"])
            counters = restored["counters"]
            self._built = counters["built"]
            self._verified = counters["verified"]
            self._rejected = counters["rejected"]

    def purge_expired(self, *, now: int) -> int:
        with self._lock:
            kept = [rec for rec in self._records if rec["expiry"] > now]
            removed = len(self._records) - len(kept)
            self._records = kept
            return removed

    def stats(self) -> dict[str, int]:
        with self._lock:
            return {
                "built": self._built,
                "verified": self._verified,
                "rejected": self._rejected,
                "records": len(self._records),
            }
