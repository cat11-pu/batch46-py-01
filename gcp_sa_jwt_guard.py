"""GCP service-account JWT assertion exchange and access token guard."""

from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
import secrets
import threading
from typing import Any, Mapping, Sequence


JWT_OK = "JWT_OK"
JWT_MALFORMED = "JWT_MALFORMED"
JWT_ALG_NONE = "JWT_ALG_NONE"
JWT_UNKNOWN_ISSUER = "JWT_UNKNOWN_ISSUER"
JWT_BAD_SIGNATURE = "JWT_BAD_SIGNATURE"
JWT_BAD_AUDIENCE = "JWT_BAD_AUDIENCE"
JWT_LIFETIME_TOO_LONG = "JWT_LIFETIME_TOO_LONG"
JWT_NOT_YET_VALID = "JWT_NOT_YET_VALID"
JWT_EXPIRED = "JWT_EXPIRED"
JWT_DELEGATION_DENIED = "JWT_DELEGATION_DENIED"
JWT_SCOPE_NOT_GRANTED = "JWT_SCOPE_NOT_GRANTED"
JWT_REPLAY = "JWT_REPLAY"
JWT_TOKEN_LIMIT = "JWT_TOKEN_LIMIT"

_HEADER = {"alg": "HS256", "typ": "JWT"}
_TOKEN_PREFIX = "ya29."
_ACCESS_TOKEN_TTL = 3600


class SaJwtError(ValueError):
    """Raised when an assertion cannot be issued or exchanged."""

    def __init__(self, code: str, detail: str | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class SaJwtGuard:
    """Self-signed JWT assertion issuance, exchange and token introspection."""

    def __init__(
        self,
        *,
        clock_skew: int = 60,
        max_lifetime: int = 3600,
        max_tokens: int = 50,
        replay_retention: int = 3600,
    ) -> None:
        self.clock_skew = clock_skew
        self.max_lifetime = max_lifetime
        self.max_tokens = max_tokens
        self.replay_retention = replay_retention
        self._lock = threading.RLock()
        self._accounts: dict[str, dict[str, Any]] = {}
        self._delegation: dict[str, set[str]] = {}
        self._replays: dict[str, int] = {}
        self._tokens: dict[str, dict[str, Any]] = {}
        self._stats = {"asserted": 0, "exchanged": 0, "rejected": 0}

    @staticmethod
    def _canonical(scope: Sequence[str]) -> list[str]:
        return sorted(set(scope))

    @staticmethod
    def _b64encode(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    @staticmethod
    def _b64decode(segment: str) -> bytes:
        padding = "=" * (-len(segment) % 4)
        return base64.urlsafe_b64decode(segment + padding)

    def _encode(self, obj: Any) -> str:
        raw = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode()
        return self._b64encode(raw)

    def _sign(self, signing_input: str, secret: str) -> str:
        digest = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
        return self._b64encode(digest)

    def register_service_account(
        self,
        email: str,
        *,
        secret: str,
        scopes: Sequence[str],
    ) -> dict[str, Any]:
        canonical = self._canonical(scopes)
        with self._lock:
            self._accounts[email] = {"secret": secret, "scopes": canonical}
            self._delegation.setdefault(email, set())
            return {"email": email, "scopes": list(canonical)}

    def allow_delegation(self, email: str, subject: str) -> dict[str, Any]:
        with self._lock:
            if email not in self._accounts:
                raise SaJwtError(JWT_UNKNOWN_ISSUER, f"unknown issuer {email}")
            self._delegation.setdefault(email, set()).add(subject)
            return {"email": email, "subject": subject, "delegated": True}

    def create_assertion(
        self,
        email: str,
        *,
        audience: str,
        scope: Sequence[str] | None = None,
        now: int,
        lifetime: int = 3600,
        subject: str | None = None,
        jwt_id: str | None = None,
    ) -> dict[str, Any]:
        if lifetime <= 0 or lifetime > self.max_lifetime:
            raise SaJwtError(
                JWT_LIFETIME_TOO_LONG,
                f"lifetime {lifetime} exceeds max {self.max_lifetime}",
            )
        with self._lock:
            account = self._accounts.get(email)
            if account is None:
                raise SaJwtError(JWT_UNKNOWN_ISSUER, f"unknown issuer {email}")
            if scope is None:
                canonical_scope = list(account["scopes"])
            else:
                canonical_scope = self._canonical(scope)
            actual_subject = subject if subject is not None else email
            token_id = jwt_id if jwt_id is not None else secrets.token_hex(16)
            issued_at = now
            expires_at = now + lifetime
            payload = {
                "iss": email,
                "sub": actual_subject,
                "aud": audience,
                "iat": issued_at,
                "exp": expires_at,
                "jti": token_id,
                "scope": " ".join(canonical_scope),
            }
            signing_input = self._encode(_HEADER) + "." + self._encode(payload)
            signature = self._sign(signing_input, account["secret"])
            return {
                "assertion": signing_input + "." + signature,
                "jti": token_id,
                "exp": expires_at,
                "iat": issued_at,
                "scope": list(canonical_scope),
            }

    def _parse_and_verify(self, token: str) -> dict[str, Any]:
        parts = token.split(".") if isinstance(token, str) else []
        if len(parts) != 3 or not parts[0] or not parts[1]:
            raise SaJwtError(JWT_MALFORMED, "assertion must have three segments")
        header_segment, payload_segment, signature_segment = parts
        try:
            header = json.loads(self._b64decode(header_segment))
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            raise SaJwtError(JWT_MALFORMED, "header is not valid JSON") from exc
        if not isinstance(header, dict) or header.get("alg") != "HS256":
            raise SaJwtError(JWT_ALG_NONE, "only HS256 assertions are accepted")
        try:
            claims = json.loads(self._b64decode(payload_segment))
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            raise SaJwtError(JWT_MALFORMED, "payload is not valid JSON") from exc
        if not isinstance(claims, dict):
            raise SaJwtError(JWT_MALFORMED, "payload must be a JSON object")
        issuer = claims.get("iss")
        account = self._accounts.get(issuer)
        if account is None:
            raise SaJwtError(JWT_UNKNOWN_ISSUER, f"unknown issuer {issuer}")
        signing_input = header_segment + "." + payload_segment
        expected = self._sign(signing_input, account["secret"])
        try:
            provided = self._b64decode(signature_segment)
        except (ValueError, TypeError) as exc:
            raise SaJwtError(JWT_BAD_SIGNATURE, "signature is not valid base64url") from exc
        if not hmac.compare_digest(provided, self._b64decode(expected)):
            raise SaJwtError(JWT_BAD_SIGNATURE, "signature verification failed")
        return claims

    def decode_assertion(self, token: str) -> dict[str, Any]:
        with self._lock:
            return self._parse_and_verify(token)

    def exchange(
        self,
        assertion: str,
        *,
        audience: str,
        requested_scope: Sequence[str],
        now: int,
    ) -> dict[str, Any]:
        with self._lock:
            self._stats["asserted"] += 1
            try:
                result = self._exchange_locked(assertion, audience, requested_scope, now)
            except SaJwtError:
                self._stats["rejected"] += 1
                raise
            self._stats["exchanged"] += 1
            return result

    def _exchange_locked(
        self,
        assertion: str,
        audience: str,
        requested_scope: Sequence[str],
        now: int,
    ) -> dict[str, Any]:
        claims = self._parse_and_verify(assertion)
        issuer = claims["iss"]
        account = self._accounts[issuer]

        if claims.get("aud") != audience:
            raise SaJwtError(JWT_BAD_AUDIENCE, "assertion audience does not match")

        issued_at = claims.get("iat")
        expires_at = claims.get("exp")
        if not isinstance(issued_at, int) or not isinstance(expires_at, int):
            raise SaJwtError(JWT_MALFORMED, "iat/exp must be integers")
        if expires_at - issued_at > self.max_lifetime:
            raise SaJwtError(JWT_LIFETIME_TOO_LONG, "assertion lifetime exceeds cap")

        if issued_at > now + self.clock_skew:
            raise SaJwtError(JWT_NOT_YET_VALID, "assertion issued in the future")
        if now >= expires_at:
            raise SaJwtError(JWT_EXPIRED, "assertion has expired")

        subject = claims.get("sub", issuer)
        if subject != issuer and subject not in self._delegation.get(issuer, set()):
            raise SaJwtError(JWT_DELEGATION_DENIED, f"delegation to {subject} not allowed")

        granted = set(account["scopes"])
        assertion_scopes = set(str(claims.get("scope", "")).split())
        requested = self._canonical(requested_scope)
        if not assertion_scopes <= granted:
            raise SaJwtError(JWT_SCOPE_NOT_GRANTED, "assertion claims unregistered scopes")
        if any(item not in assertion_scopes or item not in granted for item in requested):
            raise SaJwtError(JWT_SCOPE_NOT_GRANTED, "requested scope was not granted")

        jwt_id = claims.get("jti")
        if jwt_id in self._replays:
            raise SaJwtError(JWT_REPLAY, f"jti {jwt_id} was already consumed")

        if self._active_token_count(now) >= self.max_tokens:
            self._purge_expired_tokens_locked(now)
            if self._active_token_count(now) >= self.max_tokens:
                raise SaJwtError(JWT_TOKEN_LIMIT, "active access token limit reached")

        self._replays[jwt_id] = now

        access_token = _TOKEN_PREFIX + secrets.token_hex(24)
        remaining = expires_at - now
        token_expires_in = min(_ACCESS_TOKEN_TTL, remaining)
        record = {
            "sub": subject,
            "scope": requested,
            "iat": now,
            "exp": now + token_expires_in,
            "assertion_exp": expires_at,
            "revoked": False,
        }
        self._tokens[access_token] = record
        return {
            "status": "ok",
            "code": JWT_OK,
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": token_expires_in,
            "scope": list(requested),
            "sub": subject,
        }

    def _active_token_count(self, now: int) -> int:
        return sum(
            1
            for record in self._tokens.values()
            if not record["revoked"] and record["exp"] > now
        )

    def _purge_expired_tokens_locked(self, now: int) -> int:
        expired = [token for token, record in self._tokens.items() if record["exp"] <= now]
        for token in expired:
            del self._tokens[token]
        return len(expired)

    def introspect(self, access_token: str, *, now: int) -> dict[str, Any]:
        with self._lock:
            record = self._tokens.get(access_token)
            if record is None or record["revoked"] or record["exp"] <= now:
                return {"active": False}
            return {
                "active": True,
                "sub": record["sub"],
                "scope": list(record["scope"]),
                "exp": record["exp"],
                "iat": record["iat"],
            }

    def revoke_token(self, access_token: str) -> dict[str, Any]:
        with self._lock:
            record = self._tokens.get(access_token)
            if record is None or record["revoked"]:
                return {"revoked": False}
            record["revoked"] = True
            return {"revoked": True}

    def purge_replays(self, cutoff: int) -> int:
        with self._lock:
            stale = [jwt_id for jwt_id, used_at in self._replays.items() if used_at <= cutoff]
            for jwt_id in stale:
                del self._replays[jwt_id]
            return len(stale)

    def purge_expired_tokens(self, *, now: int) -> int:
        with self._lock:
            return self._purge_expired_tokens_locked(now)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "accounts": copy.deepcopy(self._accounts),
                "delegation": copy.deepcopy(self._delegation),
                "replays": copy.deepcopy(self._replays),
                "tokens": copy.deepcopy(self._tokens),
                "stats": copy.deepcopy(self._stats),
                "config": {
                    "clock_skew": self.clock_skew,
                    "max_lifetime": self.max_lifetime,
                    "max_tokens": self.max_tokens,
                    "replay_retention": self.replay_retention,
                },
            }

    def restore(self, state: Mapping[str, Any]) -> None:
        with self._lock:
            snapshot = copy.deepcopy(dict(state))
            config = snapshot.get("config", {})
            self.clock_skew = config.get("clock_skew", self.clock_skew)
            self.max_lifetime = config.get("max_lifetime", self.max_lifetime)
            self.max_tokens = config.get("max_tokens", self.max_tokens)
            self.replay_retention = config.get("replay_retention", self.replay_retention)
            self._accounts = snapshot.get("accounts", {})
            self._delegation = {
                email: set(subjects)
                for email, subjects in snapshot.get("delegation", {}).items()
            }
            self._replays = snapshot.get("replays", {})
            self._tokens = snapshot.get("tokens", {})
            self._stats = dict(snapshot.get("stats", {"asserted": 0, "exchanged": 0, "rejected": 0}))

    def stats(self) -> dict[str, int]:
        with self._lock:
            return dict(self._stats)
