"""PASETO v4.local guard with authenticated footers and replay control."""

import base64
import binascii
import hashlib
import hmac
import json
import math
import os
import secrets
import threading
from collections.abc import Mapping


class PasetoError(ValueError):
    """Raised for malformed, forged or policy-rejected tokens."""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


def _b64encode(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64decode(text):
    if not isinstance(text, str) or "=" in text:
        raise ValueError("non-canonical base64")
    try:
        padding = "=" * (-len(text) % 4)
        raw = base64.b64decode(
            text + padding, altchars=b"-_", validate=True
        )
    except (ValueError, TypeError, UnicodeError, binascii.Error):
        raise ValueError("invalid base64") from None
    if _b64encode(raw) != text:
        raise ValueError("non-canonical base64")
    return raw


def _key_bytes(key):
    if isinstance(key, bytes):
        return key
    if isinstance(key, (bytearray, memoryview)):
        return bytes(key)
    if isinstance(key, str):
        return key.encode("utf-8")
    try:
        return json.dumps(
            key, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    except (TypeError, ValueError):
        return str(key).encode("utf-8")


def _json_bytes(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _derive_keys(key):
    enc_key = hmac.new(
        key, b"paseto-v4-guard/encryption/v1", hashlib.sha256
    ).digest()
    mac_key = hmac.new(
        key, b"paseto-v4-guard/authentication/v1", hashlib.sha256
    ).digest()
    return enc_key, mac_key


def _xor_keystream(data, enc_key, nonce):
    output = bytearray(len(data))
    offset = 0
    counter = 0
    while offset < len(data):
        block = hmac.new(
            enc_key, nonce + counter.to_bytes(8, "big"), hashlib.sha256
        ).digest()
        take = min(len(block), len(data) - offset)
        for index in range(take):
            output[offset + index] = data[offset + index] ^ block[index]
        offset += take
        counter += 1
    return bytes(output)


def _body_tag(mac_key, nonce, ciphertext, footer_raw):
    digest = hmac.new(mac_key, digestmod=hashlib.sha256)
    digest.update(b"v4.local\x00")
    for chunk in (nonce, ciphertext, footer_raw):
        digest.update(len(chunk).to_bytes(8, "big"))
        digest.update(chunk)
    return digest.digest()


def _seal(claims, implicit_digest, key, footer_raw):
    envelope = {"claims": claims, "implicit": implicit_digest}
    plaintext = _json_bytes(envelope)
    enc_key, mac_key = _derive_keys(key)
    nonce = os.urandom(16)
    ciphertext = _xor_keystream(plaintext, enc_key, nonce)
    tag = _body_tag(mac_key, nonce, ciphertext, footer_raw)
    return nonce + ciphertext + tag


def _open(body, key, footer_raw):
    if len(body) < 16 + 32:
        raise ValueError("truncated body")
    nonce = body[:16]
    ciphertext = body[16:-32]
    tag = body[-32:]
    enc_key, mac_key = _derive_keys(key)
    expected = _body_tag(mac_key, nonce, ciphertext, footer_raw)
    if not hmac.compare_digest(tag, expected):
        raise ValueError("authentication failed")
    plaintext = _xor_keystream(ciphertext, enc_key, nonce)
    return plaintext


def _implicit_digest(implicit):
    if implicit is None:
        return None
    if isinstance(implicit, bytes):
        raw = implicit
    elif isinstance(implicit, str):
        raw = implicit.encode("utf-8")
    else:
        raw = _json_bytes(implicit)
    return hashlib.sha256(raw).hexdigest()


def _number(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("not a finite number")
    if not math.isfinite(value):
        raise ValueError("not a finite number")
    return value


class PasetoGuard:
    """Local token issuing, verification, key rotation and replay control."""

    def __init__(self, *, key, key_id="k1", now=0, max_token_bytes=1024):
        self._lock = threading.RLock()
        self.key = key
        self.key_id = key_id
        self.now = now
        self.max_token_bytes = max_token_bytes
        self._keys = {
            key_id: {
                "key": _key_bytes(key),
                "status": "current",
                "expires_at": None,
            }
        }
        self._revoked = {}
        self._consumed = set()
        self._stats = {
            "issued": 0,
            "verified": 0,
            "denied": 0,
            "replays": 0,
        }
        self._audit = []

    def _now(self, now):
        return self.now if now is None else now

    def _current_key(self):
        record = self._keys.get(self.key_id)
        if record is None or record["status"] != "current":
            raise PasetoError("PASETO_UNKNOWN_KEY")
        return record["key"]

    def issue(self, claims, *, footer=None, implicit=None, ttl=600,
              now=None) -> str:
        now_value = self._now(now)
        if not isinstance(claims, Mapping):
            raise PasetoError("PASETO_FORMAT")
        try:
            copied = dict(claims)
        except (TypeError, ValueError):
            raise PasetoError("PASETO_FORMAT") from None

        copied["iat"] = now_value
        if "exp" not in copied:
            copied["exp"] = now_value + ttl
        if copied.get("jti") is None or copied.get("jti") == "":
            copied["jti"] = secrets.token_urlsafe(16)

        with self._lock:
            if footer is None:
                footer_copy = {"kid": self.key_id}
            else:
                try:
                    footer_copy = dict(footer)
                except (TypeError, ValueError):
                    raise PasetoError("PASETO_FORMAT") from None
                if not footer_copy.get("kid"):
                    footer_copy["kid"] = self.key_id
            try:
                footer_raw = _json_bytes(footer_copy)
                if not isinstance(
                    json.loads(footer_raw.decode("utf-8")), dict
                ):
                    raise ValueError("footer is not an object")
            except (TypeError, ValueError, UnicodeError):
                raise PasetoError("PASETO_FORMAT") from None
            key = self._current_key()
            try:
                body = _seal(
                    copied, _implicit_digest(implicit), key, footer_raw
                )
            except Exception:
                raise PasetoError("PASETO_FORMAT") from None
            token = ".".join(
                ("v4", "local", _b64encode(body), _b64encode(footer_raw))
            )
            if len(token) > self.max_token_bytes:
                raise PasetoError("PASETO_SIZE_LIMIT")
            self._stats["issued"] += 1
            return token

    def verify(self, token, *, implicit=None, audience=None, max_age=None,
               single_use=False, require_footer=None, now=None) -> dict:
        now_value = self._now(now)
        context = {"jti": None, "kid": None}
        try:
            return self._verify(
                token,
                implicit=implicit,
                audience=audience,
                max_age=max_age,
                single_use=single_use,
                require_footer=require_footer,
                now=now_value,
                context=context,
            )
        except PasetoError as exc:
            with self._lock:
                self._stats["denied"] += 1
                if exc.code == "PASETO_REPLAY":
                    self._stats["replays"] += 1
                self._audit.append(
                    {
                        "ok": False,
                        "code": exc.code,
                        "jti": context["jti"],
                        "kid": context["kid"],
                        "now": now_value,
                    }
                )
            raise
        except Exception:
            with self._lock:
                self._stats["denied"] += 1
                self._audit.append(
                    {
                        "ok": False,
                        "code": "PASETO_INTEGRITY",
                        "jti": context["jti"],
                        "kid": context["kid"],
                        "now": now_value,
                    }
                )
            raise PasetoError("PASETO_INTEGRITY") from None

    def _verify(self, token, *, implicit, audience, max_age, single_use,
                require_footer, now, context):
        if not isinstance(token, str):
            raise PasetoError("PASETO_FORMAT")
        if len(token) > self.max_token_bytes:
            raise PasetoError("PASETO_SIZE_LIMIT")

        parts = token.split(".")
        if len(parts) != 4 or parts[0] != "v4" or parts[1] != "local":
            raise PasetoError("PASETO_FORMAT")
        try:
            body_raw = _b64decode(parts[2])
            footer_raw = _b64decode(parts[3])
        except ValueError:
            raise PasetoError("PASETO_FORMAT") from None

        try:
            footer = json.loads(footer_raw.decode("utf-8"))
        except (ValueError, UnicodeError):
            raise PasetoError("PASETO_FORMAT") from None
        if not isinstance(footer, dict) or "kid" not in footer:
            raise PasetoError("PASETO_FORMAT")
        kid = footer.get("kid")
        context["kid"] = kid
        try:
            hash(kid)
        except TypeError:
            raise PasetoError("PASETO_UNKNOWN_KEY") from None

        with self._lock:
            record = self._keys.get(kid)
            if record is None:
                raise PasetoError("PASETO_UNKNOWN_KEY")
            if record["status"] == "grace":
                if record["expires_at"] is not None and now >= record["expires_at"]:
                    raise PasetoError("PASETO_UNKNOWN_KEY")
            elif record["status"] != "current":
                raise PasetoError("PASETO_UNKNOWN_KEY")
            verification_key = record["key"]

        try:
            plaintext = _open(body_raw, verification_key, footer_raw)
        except Exception:
            raise PasetoError("PASETO_INTEGRITY") from None

        try:
            envelope = json.loads(plaintext.decode("utf-8"))
        except (ValueError, UnicodeError):
            raise PasetoError("PASETO_INTEGRITY") from None
        if not isinstance(envelope, dict):
            raise PasetoError("PASETO_INTEGRITY")
        claims = envelope.get("claims")
        if not isinstance(claims, dict):
            raise PasetoError("PASETO_INTEGRITY")
        if "implicit" not in envelope:
            raise PasetoError("PASETO_INTEGRITY")

        if any(name not in claims for name in ("exp", "iat", "jti")):
            raise PasetoError("PASETO_FORMAT")
        try:
            expiry = _number(claims["exp"])
            issued_at = _number(claims["iat"])
        except ValueError:
            raise PasetoError("PASETO_FORMAT") from None
        jti = claims["jti"]
        try:
            hash(jti)
        except TypeError:
            raise PasetoError("PASETO_FORMAT") from None
        context["jti"] = jti

        expected_implicit = envelope["implicit"]
        actual_implicit = _implicit_digest(implicit)
        if expected_implicit != actual_implicit:
            raise PasetoError("PASETO_IMPLICIT")

        if now >= expiry:
            raise PasetoError("PASETO_EXPIRED")
        if "nbf" in claims:
            try:
                not_before = _number(claims["nbf"])
            except ValueError:
                raise PasetoError("PASETO_FORMAT") from None
            if now < not_before:
                raise PasetoError("PASETO_NOT_YET_VALID")
        if max_age is not None and now - issued_at > max_age:
            raise PasetoError("PASETO_TOKEN_TOO_OLD")

        if audience is not None:
            if isinstance(audience, str):
                expected_audience = {audience}
            elif isinstance(audience, (list, tuple, set, frozenset)):
                expected_audience = set(audience)
            else:
                expected_audience = {audience}
            token_audience = claims.get("aud")
            if isinstance(token_audience, str):
                actual_audience = {token_audience}
            elif isinstance(token_audience, (list, tuple, set, frozenset)):
                try:
                    actual_audience = set(token_audience)
                except TypeError:
                    actual_audience = set()
            else:
                actual_audience = set()
            if not expected_audience.intersection(actual_audience):
                raise PasetoError("PASETO_AUDIENCE")

        if require_footer is not None:
            if not isinstance(require_footer, Mapping):
                raise PasetoError("PASETO_FOOTER_MISMATCH")
            for name, value in require_footer.items():
                if name not in footer or footer[name] != value:
                    raise PasetoError("PASETO_FOOTER_MISMATCH")

        with self._lock:
            if jti in self._consumed:
                raise PasetoError("PASETO_REPLAY")
            revoked_until = self._revoked.get(jti)
            if revoked_until is not None and now < revoked_until:
                raise PasetoError("PASETO_REVOKED")
            if single_use:
                self._consumed.add(jti)
            self._stats["verified"] += 1
            self._audit.append(
                {
                    "ok": True,
                    "code": None,
                    "jti": jti,
                    "kid": kid,
                    "now": now,
                }
            )

        return dict(claims)

    def peek(self, token) -> dict:
        if not isinstance(token, str):
            raise PasetoError("PASETO_FORMAT")
        if len(token) > self.max_token_bytes:
            raise PasetoError("PASETO_SIZE_LIMIT")
        parts = token.split(".")
        if len(parts) != 4 or parts[0] != "v4" or parts[1] != "local":
            raise PasetoError("PASETO_FORMAT")
        try:
            body_raw = _b64decode(parts[2])
            footer_raw = _b64decode(parts[3])
            footer = json.loads(footer_raw.decode("utf-8"))
        except (ValueError, UnicodeError):
            raise PasetoError("PASETO_FORMAT") from None
        if not isinstance(footer, dict) or "kid" not in footer:
            raise PasetoError("PASETO_FORMAT")
        return {
            "version": parts[0],
            "purpose": parts[1],
            "kid": footer["kid"],
            "footer": {
                name: value for name, value in footer.items() if name != "kid"
            },
            "body_bytes": len(body_raw),
        }

    def revoke(self, jti, *, expires_at=None, now=None) -> dict:
        now_value = self._now(now)
        try:
            hash(jti)
        except TypeError:
            raise PasetoError("PASETO_FORMAT") from None
        expires = now_value + 3600 if expires_at is None else expires_at
        with self._lock:
            self._revoked[jti] = expires
        return {"jti": jti, "expires_at": expires}

    def rotate_key(self, *, key_id, key=None, grace=300, now=None) -> dict:
        now_value = self._now(now)
        if key is None:
            key = secrets.token_bytes(32)
        with self._lock:
            previous = self.key_id
            if previous in self._keys:
                self._keys[previous]["status"] = "grace"
                self._keys[previous]["expires_at"] = now_value + grace
            self._keys[key_id] = {
                "key": _key_bytes(key),
                "status": "current",
                "expires_at": None,
            }
            self.key_id = key_id
            self.key = key
        return {
            "key_id": key_id,
            "previous": previous,
            "expires_at": now_value + grace,
        }

    def retire_key(self, key_id, *, now=None) -> dict:
        with self._lock:
            if key_id not in self._keys:
                raise PasetoError("PASETO_UNKNOWN_KEY")
            del self._keys[key_id]
            if key_id == self.key_id:
                self.key_id = None
                self.key = None
            return {
                "key_id": key_id,
                "status": "retired",
            }

    def keyring(self) -> list:
        with self._lock:
            return [
                {
                    "key_id": key_id,
                    "status": record["status"],
                    "expires_at": record["expires_at"],
                }
                for key_id, record in self._keys.items()
            ]

    def sweep_revocations(self, *, now=None) -> int:
        now_value = self._now(now)
        with self._lock:
            expired = [
                jti
                for jti, expires_at in self._revoked.items()
                if expires_at <= now_value
            ]
            for jti in expired:
                del self._revoked[jti]
            return len(expired)

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    def audit_log(self) -> list:
        with self._lock:
            return [dict(entry) for entry in self._audit]

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": 1,
                "now": self.now,
                "max_token_bytes": self.max_token_bytes,
                "key_id": self.key_id,
                "keys": [
                    {
                        "key_id": key_id,
                        "key": _b64encode(record["key"]),
                        "status": record["status"],
                        "expires_at": record["expires_at"],
                    }
                    for key_id, record in self._keys.items()
                ],
                "revocations": [
                    {"jti": jti, "expires_at": expires_at}
                    for jti, expires_at in self._revoked.items()
                ],
                "consumed": list(self._consumed),
                "stats": dict(self._stats),
                "audit": [dict(entry) for entry in self._audit],
            }

    @classmethod
    def restore(cls, state) -> "PasetoGuard":
        if not isinstance(state, Mapping):
            raise PasetoError("PASETO_FORMAT")
        try:
            key_rows = state["keys"]
            if not key_rows:
                raise ValueError("no keys")
            key_id = state.get("key_id")
            current = next(
                (row for row in key_rows if row.get("key_id") == key_id),
                None,
            )
            if current is None:
                current = next(
                    (row for row in key_rows if row.get("status") == "current"),
                    None,
                )
            seed = current
            if seed is None and key_id is None:
                seed = key_rows[0]
            if seed is None:
                raise ValueError("no current key")
            decoded_key = _b64decode(seed["key"])
            restored = cls(
                key=decoded_key,
                key_id=seed["key_id"],
                now=state.get("now", 0),
                max_token_bytes=state.get("max_token_bytes", 1024),
            )
            restored.key_id = key_id
            restored.key = decoded_key if key_id is not None else None
            restored._keys = {
                row["key_id"]: {
                    "key": _b64decode(row["key"]),
                    "status": row["status"],
                    "expires_at": row.get("expires_at"),
                }
                for row in key_rows
            }
            restored._revoked = {
                row["jti"]: row["expires_at"]
                for row in state.get("revocations", [])
            }
            restored._consumed = set(state.get("consumed", []))
            stats = {
                "issued": 0,
                "verified": 0,
                "denied": 0,
                "replays": 0,
            }
            stats.update(state.get("stats", {}))
            restored._stats = stats
            restored._audit = [dict(entry) for entry in state.get("audit", [])]
            return restored
        except PasetoError:
            raise
        except (KeyError, TypeError, ValueError, AttributeError):
            raise PasetoError("PASETO_FORMAT", "invalid snapshot") from None
