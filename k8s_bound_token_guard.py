"""Bound projected service-account token issuance and validation.

The guard intentionally keeps its own compact JWT-like representation.  It is
not a general purpose JWT library: only HS256 tokens using a key from this
guard's key ring are accepted.
"""

from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import hmac
import json
import re
import secrets
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any


TOK_OK = "TOK_OK"
TOK_MALFORMED = "TOK_MALFORMED"
TOK_BAD_SIGNATURE = "TOK_BAD_SIGNATURE"
TOK_KEY_RETIRED = "TOK_KEY_RETIRED"
TOK_EXPIRED = "TOK_EXPIRED"
TOK_NOT_YET_VALID = "TOK_NOT_YET_VALID"
TOK_INVALID_AUDIENCE = "TOK_INVALID_AUDIENCE"
TOK_AUDIENCE_LIMIT = "TOK_AUDIENCE_LIMIT"
TOK_AUDIENCE_MISMATCH = "TOK_AUDIENCE_MISMATCH"
TOK_INVALID_LIFETIME = "TOK_INVALID_LIFETIME"
TOK_LIFETIME_TOO_LONG = "TOK_LIFETIME_TOO_LONG"
TOK_DUPLICATE_UID = "TOK_DUPLICATE_UID"
TOK_LIMIT = "TOK_LIMIT"
TOK_BOUND_OBJECT_MISMATCH = "TOK_BOUND_OBJECT_MISMATCH"
TOK_NODE_MISMATCH = "TOK_NODE_MISMATCH"
TOK_REVOKED = "TOK_REVOKED"
TOK_REFRESH_NOT_NEEDED = "TOK_REFRESH_NOT_NEEDED"


class BoundTokenError(ValueError):
    """Raised for every rejected token operation.

    ``code`` is the stable, machine-readable reason.  Keeping it on the
    exception (as well as in the message) makes audit logging deterministic.
    """

    def __init__(self, code: str, message: str | None = None):
        self.code = code
        self.message = message or code
        self.detail = self.message
        super().__init__(self.message)


@dataclass
class Config:
    """Issuer policy.

    The aliases accepted by :class:`BoundTokenGuard` are deliberately not
    exposed here; this class is the canonical configuration shape.
    """

    audiences: Sequence[str] = ()
    max_token_lifetime: int = 3600
    max_tokens: int = 4096
    clock_skew: int = 30
    key_grace: int = 300
    max_audiences: int = 8
    refresh_ratio: float = 0.2


_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_DEFAULT_STATS = {
    "issued": 0,
    "validated": 0,
    "refreshed": 0,
    "rejected": 0,
}


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _seconds(value: Any) -> Any:
    """Accept plain seconds and datetime/Go-style durations when present."""

    if hasattr(value, "total_seconds"):
        return value.total_seconds()
    if hasattr(value, "total_nanoseconds"):
        return value.total_nanoseconds() / 1_000_000_000
    return value


class BoundTokenGuard:
    """Issues, refreshes, validates and revokes pod-bound tokens."""

    def __init__(self, config: Any = None, **kwargs: Any):
        values: dict[str, Any] = {}

        if config is not None:
            if isinstance(config, Mapping):
                values.update(dict(config))
            elif isinstance(config, Config):
                values.update(vars(config))
            else:
                # A duck-typed configuration object is convenient for callers
                # that have a small settings class of their own.
                if hasattr(config, "__dict__"):
                    values.update(vars(config))
                else:
                    for name in (
                        "audiences",
                        "max_token_lifetime",
                        "max_ttl",
                        "max_tokens",
                        "max_tokens_per_pod",
                        "clock_skew",
                        "key_grace",
                        "max_audiences",
                        "refresh_ratio",
                    ):
                        if hasattr(config, name):
                            values[name] = getattr(config, name)
        values.update(kwargs)

        aliases = {
            "max_ttl": "max_token_lifetime",
            "max_lifetime": "max_token_lifetime",
            "max_token_ttl": "max_token_lifetime",
            "token_lifetime": "max_token_lifetime",
            "max_tokens_per_pod": "max_tokens",
            "key_retirement_grace": "key_grace",
            "rotation_grace": "key_grace",
            "key_rotation_grace": "key_grace",
            "grace": "key_grace",
            "skew": "clock_skew",
            "clock_skew_seconds": "clock_skew",
            "refresh_fraction": "refresh_ratio",
            "refresh_threshold": "refresh_ratio",
            "refresh_window_ratio": "refresh_ratio",
        }
        for alias, canonical in aliases.items():
            if alias in values and canonical not in values:
                values[canonical] = values[alias]

        self._audiences = tuple(values.get("audiences") or ())
        lifetime = values.get("max_token_lifetime", 3600)
        self._max_token_lifetime = None if lifetime is None else _seconds(lifetime)

        max_tokens = values.get("max_tokens", 4096)
        try:
            self._max_tokens = max(0, int(max_tokens))
        except (TypeError, ValueError):
            self._max_tokens = 4096

        self._clock_skew = _seconds(values.get("clock_skew", 30))
        self._key_grace = _seconds(values.get("key_grace", 300))
        self._max_audiences = int(values.get("max_audiences", 8))
        self._refresh_ratio = float(values.get("refresh_ratio", 0.2))
        if self._clock_skew < 0:
            self._clock_skew = 0
        if self._key_grace < 0:
            self._key_grace = 0
        if self._max_audiences < 1:
            self._max_audiences = 8
        if self._refresh_ratio < 0:
            self._refresh_ratio = 0.0
        if self._refresh_ratio > 1:
            self._refresh_ratio = 1.0

        self._lock = threading.RLock()
        self._stats = dict(_DEFAULT_STATS)

        self._keys: dict[str, bytes] = {}
        self._retired_at: dict[str, Any] = {}
        self._kid_seq = 0
        self._current_kid = self._new_key(self._keys)

        self._revoked: dict[str, Any] = {}
        self._tokens: dict[str, dict[str, Any]] = {}

    # ------------------------------------------------------------------
    # Key and token primitives
    # ------------------------------------------------------------------
    def _new_key(self, keys: dict[str, bytes]) -> str:
        while True:
            self._kid_seq += 1
            kid = f"kid-{self._kid_seq}"
            if kid not in keys:
                keys[kid] = secrets.token_bytes(32)
                return kid

    @staticmethod
    def _b64encode(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    @staticmethod
    def _b64decode(segment: str) -> bytes:
        if (
            not isinstance(segment, str)
            or not segment
            or "=" in segment
            or _B64URL_RE.fullmatch(segment) is None
        ):
            raise BoundTokenError(TOK_MALFORMED)
        padding = "=" * (-len(segment) % 4)
        try:
            return base64.urlsafe_b64decode(segment + padding)
        except (ValueError, TypeError, binascii.Error) as exc:
            raise BoundTokenError(TOK_MALFORMED) from exc

    def _normalise_audiences(self, audiences: Any) -> list[str]:
        if audiences is None:
            raise BoundTokenError(TOK_INVALID_AUDIENCE)
        if isinstance(audiences, str):
            raw = [audiences]
        elif isinstance(audiences, Sequence):
            raw = list(audiences)
        else:
            try:
                raw = list(audiences)
            except TypeError as exc:
                raise BoundTokenError(TOK_INVALID_AUDIENCE) from exc

        if not raw:
            raise BoundTokenError(TOK_INVALID_AUDIENCE)
        if any(not isinstance(item, str) or item == "" for item in raw):
            raise BoundTokenError(TOK_INVALID_AUDIENCE)

        unique = sorted(set(raw))
        if len(unique) > self._max_audiences:
            raise BoundTokenError(TOK_AUDIENCE_LIMIT)
        return unique

    @staticmethod
    def _required_audiences(audiences: Any) -> list[str]:
        if audiences is None:
            return []
        if isinstance(audiences, str):
            return [audiences]
        try:
            raw = list(audiences)
        except TypeError as exc:
            raise BoundTokenError(TOK_INVALID_AUDIENCE) from exc
        if any(not isinstance(item, str) or item == "" for item in raw):
            raise BoundTokenError(TOK_INVALID_AUDIENCE)
        return raw

    def _check_ttl(self, ttl: Any) -> None:
        if not _is_number(ttl) or ttl <= 0:
            raise BoundTokenError(TOK_INVALID_LIFETIME)
        if self._max_token_lifetime is not None and ttl > self._max_token_lifetime:
            raise BoundTokenError(TOK_LIFETIME_TOO_LONG)

    def _sign(
        self,
        *,
        subject: str,
        audiences: list[str],
        jti: str,
        iat: Any,
        nbf: Any,
        exp: Any,
        pod: str | None,
        node: str | None,
        uid: str | None,
    ) -> tuple[str, dict[str, Any]]:
        header = {"alg": "HS256", "typ": "JWT", "kid": self._current_kid}
        payload: dict[str, Any] = {
            "sub": subject,
            "aud": list(audiences),
            "iat": iat,
            "nbf": nbf,
            "exp": exp,
            "jti": jti,
        }
        if pod is not None:
            payload["pod_uid"] = pod
        if node is not None:
            payload["node"] = node

        header_part = self._b64encode(
            json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8")
        )
        payload_part = self._b64encode(
            json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        )
        signing_input = f"{header_part}.{payload_part}".encode("ascii")
        signature = hmac.new(
            self._keys[self._current_kid], signing_input, hashlib.sha256
        ).digest()
        token = f"{header_part}.{payload_part}.{self._b64encode(signature)}"

        record = {
            "token": token,
            "jti": jti,
            "sub": subject,
            "aud": list(audiences),
            "iat": iat,
            "nbf": nbf,
            "exp": exp,
            "pod_uid": pod,
            "node": node,
            "uid": uid,
            "kid": self._current_kid,
        }
        return token, record

    @staticmethod
    def _public_record(record: Mapping[str, Any]) -> dict[str, Any]:
        claims = {
            "sub": record["sub"],
            "aud": list(record["aud"]),
            "iat": record["iat"],
            "nbf": record["nbf"],
            "exp": record["exp"],
            "jti": record["jti"],
        }
        if record.get("pod_uid") is not None:
            claims["pod_uid"] = record["pod_uid"]
        if record.get("node") is not None:
            claims["node"] = record["node"]
        return {
            "code": TOK_OK,
            "token": record["token"],
            "value": record["token"],
            "jti": record["jti"],
            "sub": record["sub"],
            "subject": record["sub"],
            "aud": list(record["aud"]),
            "audiences": list(record["aud"]),
            "iat": record["iat"],
            "issued_at": record["iat"],
            "nbf": record["nbf"],
            "not_before": record["nbf"],
            "exp": record["exp"],
            "expires_at": record["exp"],
            "pod_uid": record.get("pod_uid"),
            "node": record.get("node"),
            "uid": record.get("uid"),
            "kid": record["kid"],
            "header": {"alg": "HS256", "typ": "JWT", "kid": record["kid"]},
            "claims": copy.deepcopy(claims),
            "payload": copy.deepcopy(claims),
        }

    def _parse(self, token: Any) -> tuple[dict[str, Any], dict[str, Any], bytes]:
        if not isinstance(token, str):
            raise BoundTokenError(TOK_MALFORMED)
        parts = token.split(".")
        if len(parts) != 3 or any(part == "" for part in parts):
            raise BoundTokenError(TOK_MALFORMED)

        header_bytes = self._b64decode(parts[0])
        payload_bytes = self._b64decode(parts[1])
        signature = self._b64decode(parts[2])
        try:
            header = json.loads(header_bytes.decode("utf-8"))
            payload = json.loads(payload_bytes.decode("utf-8"))
        except (UnicodeDecodeError, ValueError, TypeError) as exc:
            raise BoundTokenError(TOK_MALFORMED) from exc

        if not isinstance(header, dict) or not isinstance(payload, dict):
            raise BoundTokenError(TOK_MALFORMED)
        if header.get("alg") != "HS256" or header.get("typ") != "JWT":
            raise BoundTokenError(TOK_MALFORMED)
        if not isinstance(header.get("kid"), str) or not header["kid"]:
            raise BoundTokenError(TOK_MALFORMED)

        for name in ("sub", "aud", "iat", "nbf", "exp", "jti"):
            if name not in payload:
                raise BoundTokenError(TOK_MALFORMED)
        if not isinstance(payload["sub"], str) or not payload["sub"]:
            raise BoundTokenError(TOK_MALFORMED)
        if not isinstance(payload["jti"], str) or not payload["jti"]:
            raise BoundTokenError(TOK_MALFORMED)
        if any(
            not _is_number(payload[name]) for name in ("iat", "nbf", "exp")
        ):
            raise BoundTokenError(TOK_MALFORMED)

        aud = payload["aud"]
        if isinstance(aud, str):
            aud = [aud]
        if not isinstance(aud, list) or any(
            not isinstance(item, str) or item == "" for item in aud
        ):
            raise BoundTokenError(TOK_MALFORMED)
        payload["aud"] = aud

        for optional in ("pod_uid", "node"):
            value = payload.get(optional)
            if value is not None and not isinstance(value, str):
                raise BoundTokenError(TOK_MALFORMED)

        return header, payload, signature

    def _verify(
        self, token: str, header: Mapping[str, Any], signature: bytes
    ) -> bool:
        key = self._keys.get(header["kid"])
        if key is None:
            return False
        parts = token.split(".")
        expected = hmac.new(
            key, f"{parts[0]}.{parts[1]}".encode("ascii"), hashlib.sha256
        ).digest()
        return hmac.compare_digest(expected, signature)

    def _parse_and_verify(
        self, token: str
    ) -> tuple[dict[str, Any], dict[str, Any], bytes]:
        header, payload, signature = self._parse(token)
        if not self._verify(token, header, signature):
            raise BoundTokenError(TOK_BAD_SIGNATURE)
        return header, payload, signature

    def _check_retired(self, kid: str, now: Any) -> None:
        retired_at = self._retired_at.get(kid)
        if retired_at is not None and now > retired_at:
            raise BoundTokenError(TOK_KEY_RETIRED)

    def _reject_current(self) -> None:
        self._stats["rejected"] += 1

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def issue(
        self,
        subject: str,
        *,
        audiences: Sequence[str],
        now: int,
        ttl: int = 600,
        pod: str | None = None,
        node: str | None = None,
        uid: str | None = None,
        not_before: int | None = None,
    ) -> dict:
        with self._lock:
            try:
                if not isinstance(subject, str) or subject == "":
                    raise BoundTokenError(TOK_MALFORMED)
                audience_list = self._normalise_audiences(audiences)
                self._check_ttl(ttl)
                nbf = now if not_before is None else not_before

                if uid is not None:
                    for record in self._tokens.values():
                        if record.get("uid") == uid and record.get("exp", 0) > now:
                            raise BoundTokenError(TOK_DUPLICATE_UID)

                if len(self._tokens) >= self._max_tokens:
                    self._purge_locked(now)
                if len(self._tokens) >= self._max_tokens:
                    raise BoundTokenError(TOK_LIMIT)

                while True:
                    jti = secrets.token_hex(32)
                    if jti not in self._tokens:
                        break
                token, record = self._sign(
                    subject=subject,
                    audiences=audience_list,
                    jti=jti,
                    iat=now,
                    nbf=nbf,
                    exp=now + ttl,
                    pod=pod,
                    node=node,
                    uid=uid,
                )
                self._tokens[jti] = record
                self._stats["issued"] += 1
                return self._public_record(record)
            except BoundTokenError:
                self._reject_current()
                raise

    def decode(self, token: str) -> dict:
        with self._lock:
            try:
                header, payload, _ = self._parse_and_verify(token)
                result = copy.deepcopy(payload)
                result.update(
                    {
                        "code": TOK_OK,
                        "token": token,
                        "header": copy.deepcopy(header),
                        "payload": copy.deepcopy(payload),
                        "claims": copy.deepcopy(payload),
                        "kid": header["kid"],
                        "subject": payload["sub"],
                        "audiences": list(payload["aud"]),
                        "issued_at": payload["iat"],
                        "not_before": payload["nbf"],
                        "expires_at": payload["exp"],
                    }
                )
                return result
            except BoundTokenError:
                self._reject_current()
                raise

    def validate(
        self,
        token: str,
        *,
        now: int,
        audiences: Sequence[str] = (),
        pod: str | None = None,
        node: str | None = None,
    ) -> dict:
        with self._lock:
            try:
                header, payload, _ = self._parse_and_verify(token)
                kid = header["kid"]
                self._check_retired(kid, now)

                if now >= payload["exp"]:
                    raise BoundTokenError(TOK_EXPIRED)
                if payload["nbf"] > now + self._clock_skew:
                    raise BoundTokenError(TOK_NOT_YET_VALID)

                required = self._required_audiences(audiences)
                token_audiences = set(payload["aud"])
                if any(audience not in token_audiences for audience in required):
                    raise BoundTokenError(TOK_AUDIENCE_MISMATCH)

                if pod is not None and payload.get("pod_uid") != pod:
                    raise BoundTokenError(TOK_BOUND_OBJECT_MISMATCH)
                if node is not None and payload.get("node") != node:
                    raise BoundTokenError(TOK_NODE_MISMATCH)

                subject = payload["sub"]
                revoked_at = self._revoked.get(subject)
                if revoked_at is not None and payload["iat"] <= revoked_at:
                    raise BoundTokenError(TOK_REVOKED)

                self._stats["validated"] += 1
                return {
                    "code": TOK_OK,
                    "sub": subject,
                    "aud": list(payload["aud"]),
                    "exp": payload["exp"],
                    "pod_uid": payload.get("pod_uid"),
                    "node": payload.get("node"),
                    "kid": kid,
                }
            except BoundTokenError:
                self._reject_current()
                raise

    def refresh(self, token: str, *, now: int, ttl: int = 600) -> dict:
        with self._lock:
            try:
                header, payload, _ = self._parse_and_verify(token)
                kid = header["kid"]
                self._check_retired(kid, now)

                if now >= payload["exp"]:
                    raise BoundTokenError(TOK_EXPIRED)
                if payload["nbf"] > now + self._clock_skew:
                    raise BoundTokenError(TOK_NOT_YET_VALID)

                jti = payload["jti"]
                record = self._tokens.get(jti)
                if record is None or record.get("token") != token:
                    raise BoundTokenError(TOK_REVOKED)

                revoked_at = self._revoked.get(payload["sub"])
                if revoked_at is not None and record["iat"] <= revoked_at:
                    raise BoundTokenError(TOK_REVOKED)

                self._check_ttl(ttl)
                original_lifetime = record["exp"] - record["iat"]
                remaining = record["exp"] - now
                if (
                    original_lifetime <= 0
                    or remaining > original_lifetime * self._refresh_ratio
                ):
                    raise BoundTokenError(TOK_REFRESH_NOT_NEEDED)

                new_token, new_record = self._sign(
                    subject=record["sub"],
                    audiences=list(record["aud"]),
                    jti=jti,
                    iat=now,
                    nbf=now,
                    exp=now + ttl,
                    pod=record.get("pod_uid"),
                    node=record.get("node"),
                    uid=record.get("uid"),
                )
                self._tokens[jti] = new_record
                self._stats["refreshed"] += 1
                return self._public_record(new_record)
            except BoundTokenError:
                self._reject_current()
                raise

    def revoke(self, subject: str, *, now: int) -> dict:
        with self._lock:
            try:
                if not isinstance(subject, str) or subject == "":
                    raise BoundTokenError(TOK_MALFORMED)
                self._revoked[subject] = now
                invalidated = sum(
                    1
                    for record in self._tokens.values()
                    if record.get("sub") == subject and record.get("iat", 0) <= now
                )
                return {
                    "subject": subject,
                    "revoked_at": now,
                    "invalidated": invalidated,
                }
            except BoundTokenError:
                self._reject_current()
                raise

    def rotate_key(self, *, now: int) -> dict:
        with self._lock:
            retired_kid = self._current_kid
            new_kid = self._new_key(self._keys)
            retired_at = now + self._key_grace
            self._retired_at[retired_kid] = retired_at
            self._current_kid = new_kid
            return {
                "new_kid": new_kid,
                "retired_kid": retired_kid,
                "retired_at": retired_at,
            }

    def purge_expired(self, *, now: int) -> int:
        with self._lock:
            return self._purge_locked(now)

    def _purge_locked(self, now: Any) -> int:
        expired = [
            jti
            for jti, record in self._tokens.items()
            if record.get("exp", 0) <= now
        ]
        for jti in expired:
            del self._tokens[jti]
        return len(expired)

    def snapshot(self) -> dict:
        with self._lock:
            keys = {kid: key.hex() for kid, key in self._keys.items()}
            retired_at = copy.deepcopy(self._retired_at)
            revoked = copy.deepcopy(self._revoked)
            tokens = copy.deepcopy(self._tokens)
            stats = copy.deepcopy(self._stats)
            return {
                "version": 1,
                "keys": keys,
                "key_ring": keys,
                "current_kid": self._current_kid,
                "retired_at": retired_at,
                "retired": retired_at,
                "revoked": revoked,
                "revocations": revoked,
                "tokens": tokens,
                "token_table": tokens,
                "stats": stats,
                "kid_seq": self._kid_seq,
            }

    def restore(self, state: Mapping[str, Any]) -> None:
        with self._lock:
            if not isinstance(state, Mapping):
                raise BoundTokenError(TOK_MALFORMED)

            keys = state.get("keys", state.get("key_ring", {}))
            retired = state.get("retired_at", state.get("retired", {}))
            revoked = state.get("revoked", state.get("revocations", {}))
            tokens = state.get("tokens", state.get("token_table", {}))
            stats = state.get("stats", {})

            restored_keys: dict[str, bytes] = {}
            for kid, value in dict(keys or {}).items():
                if isinstance(value, str):
                    try:
                        restored_keys[kid] = bytes.fromhex(value)
                    except ValueError:
                        restored_keys[kid] = value.encode("utf-8")
                elif isinstance(value, (bytes, bytearray, memoryview)):
                    restored_keys[kid] = bytes(value)
                else:
                    raise BoundTokenError(TOK_MALFORMED)
            self._keys = restored_keys
            self._retired_at = copy.deepcopy(dict(retired or {}))
            self._revoked = copy.deepcopy(dict(revoked or {}))

            if isinstance(tokens, list):
                token_map: dict[str, dict[str, Any]] = {}
                for record in tokens:
                    if isinstance(record, Mapping) and record.get("jti"):
                        token_map[str(record["jti"])] = copy.deepcopy(dict(record))
                self._tokens = token_map
            else:
                self._tokens = copy.deepcopy(dict(tokens or {}))

            restored_stats = dict(_DEFAULT_STATS)
            if isinstance(stats, Mapping):
                for name in _DEFAULT_STATS:
                    if _is_number(stats.get(name)):
                        restored_stats[name] = stats[name]
            self._stats = restored_stats

            kid_seq = state.get("kid_seq")
            if not isinstance(kid_seq, int) or isinstance(kid_seq, bool):
                kid_seq = 0
                for kid in self._keys:
                    if isinstance(kid, str) and kid.startswith("kid-"):
                        try:
                            kid_seq = max(kid_seq, int(kid[4:]))
                        except ValueError:
                            pass
            self._kid_seq = kid_seq

            current = state.get("current_kid")
            if current not in self._keys:
                current = None
            if current is None:
                if self._keys:
                    current = next(iter(self._keys))
                else:
                    current = self._new_key(self._keys)
            self._current_kid = current

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    @classmethod
    def from_snapshot(
        cls, state: Mapping[str, Any], config: Any = None, **kwargs: Any
    ) -> "BoundTokenGuard":
        guard = cls(config=config, **kwargs)
        guard.restore(state)
        return guard


__all__ = [
    "BoundTokenError",
    "BoundTokenGuard",
    "Config",
    "TOK_OK",
    "TOK_MALFORMED",
    "TOK_BAD_SIGNATURE",
    "TOK_KEY_RETIRED",
    "TOK_EXPIRED",
    "TOK_NOT_YET_VALID",
    "TOK_INVALID_AUDIENCE",
    "TOK_AUDIENCE_LIMIT",
    "TOK_AUDIENCE_MISMATCH",
    "TOK_INVALID_LIFETIME",
    "TOK_LIFETIME_TOO_LONG",
    "TOK_DUPLICATE_UID",
    "TOK_LIMIT",
    "TOK_BOUND_OBJECT_MISMATCH",
    "TOK_NODE_MISMATCH",
    "TOK_REVOKED",
    "TOK_REFRESH_NOT_NEEDED",
]
