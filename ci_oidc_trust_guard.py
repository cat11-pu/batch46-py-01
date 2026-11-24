"""CI OIDC trust policy guard.

The guard keeps policies, consumed token identifiers, counters and the audit
trail in one process-local state.  All state transitions are protected by a
re-entrant lock so replay detection and credential issuance are atomic.
"""

from __future__ import annotations

import copy
import json
import re
import threading
from collections import OrderedDict


OIDC_MALFORMED_TOKEN = "OIDC_MALFORMED_TOKEN"
OIDC_ISSUER_MISMATCH = "OIDC_ISSUER_MISMATCH"
OIDC_TOKEN_EXPIRED = "OIDC_TOKEN_EXPIRED"
OIDC_CLOCK_SKEW = "OIDC_CLOCK_SKEW"
OIDC_REPLAY_DETECTED = "OIDC_REPLAY_DETECTED"
OIDC_AUDIENCE_MISMATCH = "OIDC_AUDIENCE_MISMATCH"
OIDC_SUBJECT_MISMATCH = "OIDC_SUBJECT_MISMATCH"
OIDC_CLAIM_MISMATCH = "OIDC_CLAIM_MISMATCH"
OIDC_DENY_POLICY = "OIDC_DENY_POLICY"
OIDC_NO_MATCHING_POLICY = "OIDC_NO_MATCHING_POLICY"
OIDC_UNKNOWN_POLICY = "OIDC_UNKNOWN_POLICY"
OIDC_INVALID_POLICY = "OIDC_INVALID_POLICY"

_REQUIRED_FIELDS = ("iss", "aud", "sub", "jti", "iat", "exp")
_CLOCK_SKEW = 60


class CiOidcError(ValueError):
    """Raised for malformed tokens and denied trust decisions."""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


def _string_list(value, *, name):
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        result = list(value)
        if not all(isinstance(item, str) for item in result):
            raise CiOidcError(
                OIDC_INVALID_POLICY, f"{name} must contain only strings"
            )
        return result
    raise CiOidcError(OIDC_INVALID_POLICY, f"{name} must be a string or list")


def _normalize_claim_value(value):
    if isinstance(value, tuple):
        return [_normalize_claim_value(item) for item in value]
    if isinstance(value, list):
        return [_normalize_claim_value(item) for item in value]
    return copy.deepcopy(value)


def _normalize_claims(claims):
    if claims is None:
        return {}
    if not isinstance(claims, dict):
        raise CiOidcError(OIDC_INVALID_POLICY, "claims must be a mapping")
    return {
        key: _normalize_claim_value(value)
        for key, value in claims.items()
    }


def _strict_scalar_equal(left, right):
    return type(left) is type(right) and left == right


def _claim_value_matches(expected, actual):
    """Match a policy claim value against the value presented by a token.

    A list on either side is a set of alternatives.  Every value presented by
    the token must exactly equal one of the allowed values.  This makes
    ``{"environment": ["prod", "staging"]}`` accept ``"prod"`` while still
    rejecting ``"Prod"`` and partial/prefix values.
    """

    expected_values = expected if isinstance(expected, list) else [expected]
    actual_values = actual if isinstance(actual, list) else [actual]
    if not actual_values:
        return False
    return all(
        any(_strict_scalar_equal(value, allowed) for allowed in expected_values)
        for value in actual_values
    )


def _claims_match(policy, claims):
    for key, expected in policy["claims"].items():
        if key not in claims:
            return False
        if not _claim_value_matches(expected, claims[key]):
            return False
    return True


def _audience_matches(policy, audience):
    presented = audience if isinstance(audience, list) else [audience]
    return any(value in policy["audiences"] for value in presented)


def _subject_pattern_matches(pattern, subject):
    # '*' matches any run of characters except the colon separator.  Full
    # anchoring prevents a policy for .../main from accepting .../main:pr.
    pieces = pattern.split("*")
    expression = "[^:]*".join(re.escape(piece) for piece in pieces)
    return re.fullmatch(expression, subject) is not None


def _subject_matches(policy, subject):
    patterns = policy["subjects"]
    if not patterns:
        return True
    return any(_subject_pattern_matches(pattern, subject) for pattern in patterns)


def _policy_matches(policy, token, claims):
    return (
        _audience_matches(policy, token["aud"])
        and _subject_matches(policy, token["sub"])
        and _claims_match(policy, claims)
    )


class CiOidcGuard:
    """Issuer trust, policy matching and one-shot token exchange."""

    def __init__(self, *, issuer, now=0):
        self.issuer = issuer
        self.now = now
        self._policies = OrderedDict()
        # (issuer, jti) -> token expiry, used only for replay retention.
        self._used = {}
        self._evaluations = 0
        self._assumed = 0
        self._denied = 0
        self._audit = []
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # Policy lifecycle
    # ------------------------------------------------------------------
    def register_policy(self, name, *, audiences, subjects=(), claims=None,
                        max_session=3600, deny=False, enabled=True) -> dict:
        if not isinstance(name, str) or not name:
            raise CiOidcError(
                OIDC_INVALID_POLICY, "policy name must be a non-empty string"
            )
        if isinstance(max_session, bool) or not isinstance(max_session, int):
            raise CiOidcError(
                OIDC_INVALID_POLICY, "max_session must be an integer"
            )

        policy = {
            "name": name,
            "audiences": _string_list(audiences, name="audiences"),
            "subjects": _string_list(subjects, name="subjects"),
            "claims": _normalize_claims(claims),
            "max_session": max_session,
            "deny": bool(deny),
            "enabled": bool(enabled),
        }

        with self._lock:
            # Re-registering a name updates it in place, preserving the
            # original registration position.
            self._policies[name] = policy
            self._record("register_policy", policy=copy.deepcopy(policy))
        return copy.deepcopy(policy)

    def set_policy_enabled(self, name, enabled) -> dict:
        with self._lock:
            policy = self._policies.get(name)
            if policy is None:
                raise CiOidcError(
                    OIDC_UNKNOWN_POLICY, f"unknown policy {name!r}"
                )
            policy["enabled"] = bool(enabled)
            self._record(
                "set_policy_enabled", policy=name, enabled=policy["enabled"]
            )
            return copy.deepcopy(policy)

    def rotate_issuer(self, issuer) -> dict:
        with self._lock:
            previous = self.issuer
            self.issuer = issuer
            self._record("rotate_issuer", issuer=issuer, previous=previous)
            return {"issuer": issuer, "previous": previous}

    def policies(self) -> list:
        with self._lock:
            return [copy.deepcopy(policy) for policy in self._policies.values()]

    # ------------------------------------------------------------------
    # Evaluation and exchange
    # ------------------------------------------------------------------
    def evaluate(self, token, *, now=None) -> dict:
        with self._lock:
            normalized = self._validate_token(token)
            current = self._resolve_now(now)
            self._evaluations += 1
            result = self._evaluate_locked(normalized, current, consume=False)
            if not result["allowed"]:
                self._denied += 1
            self._record(
                "evaluate",
                code=result["code"],
                policy=result["policy"],
                jti=normalized["jti"],
                subject=normalized["sub"],
            )
            return result

    def assume(self, token, *, now=None) -> dict:
        with self._lock:
            normalized = self._validate_token(token)
            current = self._resolve_now(now)
            self._evaluations += 1
            result = self._evaluate_locked(normalized, current, consume=True)
            if not result["allowed"]:
                self._denied += 1
                detail = result["policy"]
                self._record(
                    "assume_denied",
                    code=result["code"],
                    policy=result["policy"],
                    jti=normalized["jti"],
                    subject=normalized["sub"],
                )
                raise CiOidcError(result["code"], detail)

            session = result["session"]
            expires_at = current + session
            credential = {
                "access_key_id": f"CI-{normalized['jti']}",
                "access_key_secret": f"secret-{normalized['jti']}",
                "session_token": f"session-{normalized['jti']}",
                "expires_at": expires_at,
                "issuer": normalized["iss"],
                "subject": normalized["sub"],
                "policy": result["policy"],
            }
            self._assumed += 1
            self._record(
                "assume",
                code=None,
                policy=result["policy"],
                jti=normalized["jti"],
                subject=normalized["sub"],
                session=session,
            )
            return {
                "policy": result["policy"],
                "session": session,
                "expires_at": expires_at,
                "sub": normalized["sub"],
                "jti": normalized["jti"],
                "credential": credential,
                "credentials": copy.deepcopy(credential),
            }

    def explain(self, token, *, now=None) -> dict:
        with self._lock:
            normalized = self._validate_token(token)
            current = self._resolve_now(now)
            result = self._explain_locked(normalized, current)
            self._record(
                "explain",
                allowed=result["allowed"],
                jti=normalized["jti"],
                subject=normalized["sub"],
                reasons=list(result["reasons"]),
            )
            return result

    def _evaluate_locked(self, token, now, *, consume):
        base_code = self._base_rejection(token, now)
        if base_code is not None:
            return self._denial(base_code)

        enabled = self._enabled_policies()
        if not enabled:
            return self._denial(OIDC_NO_MATCHING_POLICY)

        claims = self._token_claims(token)
        matching = [
            policy for policy in enabled
            if _policy_matches(policy, token, claims)
        ]

        deny_matches = [policy for policy in matching if policy["deny"]]
        if deny_matches:
            return self._denial(
                OIDC_DENY_POLICY, policy=deny_matches[0]["name"]
            )

        allow_matches = [policy for policy in matching if not policy["deny"]]
        if allow_matches:
            policy = allow_matches[0]
            session = max(
                0, min(policy["max_session"], token["exp"] - now)
            )
            if consume:
                self._used[(token["iss"], token["jti"])] = token["exp"]
            return {
                "allowed": True,
                "policy": policy["name"],
                "code": None,
                "session": session,
            }

        # No policy matched every dimension.  Report the first dimension for
        # which no enabled policy passed at all.
        if not any(
            _audience_matches(policy, token["aud"]) for policy in enabled
        ):
            return self._denial(OIDC_AUDIENCE_MISMATCH)
        if not any(
            _subject_matches(policy, token["sub"]) for policy in enabled
        ):
            return self._denial(OIDC_SUBJECT_MISMATCH)
        if not any(_claims_match(policy, claims) for policy in enabled):
            return self._denial(OIDC_CLAIM_MISMATCH)
        return self._denial(OIDC_NO_MATCHING_POLICY)

    def _explain_locked(self, token, now):
        reasons = []
        enabled = self._enabled_policies()
        claims = self._token_claims(token)

        if token["iss"] != self.issuer:
            reasons.append(OIDC_ISSUER_MISMATCH)

        if not any(
            _audience_matches(policy, token["aud"]) for policy in enabled
        ):
            reasons.append(OIDC_AUDIENCE_MISMATCH)

        if now >= token["exp"]:
            reasons.append(OIDC_TOKEN_EXPIRED)

        if token["iat"] > now + _CLOCK_SKEW:
            reasons.append(OIDC_CLOCK_SKEW)

        if (token["iss"], token["jti"]) in self._used:
            reasons.append(OIDC_REPLAY_DETECTED)

        if not any(
            _subject_matches(policy, token["sub"]) for policy in enabled
        ):
            reasons.append(OIDC_SUBJECT_MISMATCH)

        if not any(_claims_match(policy, claims) for policy in enabled):
            reasons.append(OIDC_CLAIM_MISMATCH)

        matching = [
            policy for policy in enabled
            if _policy_matches(policy, token, claims)
        ]
        deny_matches = [policy for policy in matching if policy["deny"]]
        for _policy in deny_matches:
            reasons.append(OIDC_DENY_POLICY)

        allow_matches = [policy for policy in matching if not policy["deny"]]
        if not reasons and not allow_matches:
            reasons.append(OIDC_NO_MATCHING_POLICY)

        return {"allowed": not reasons, "reasons": reasons}

    def _base_rejection(self, token, now):
        if token["iss"] != self.issuer:
            return OIDC_ISSUER_MISMATCH
        if now >= token["exp"]:
            return OIDC_TOKEN_EXPIRED
        if token["iat"] > now + _CLOCK_SKEW:
            return OIDC_CLOCK_SKEW
        if (token["iss"], token["jti"]) in self._used:
            return OIDC_REPLAY_DETECTED
        return None

    @staticmethod
    def _denial(code, *, policy=None):
        return {
            "allowed": False,
            "policy": policy,
            "code": code,
            "session": 0,
        }

    # ------------------------------------------------------------------
    # Replay retention and reporting
    # ------------------------------------------------------------------
    def purge_used_jti(self, *, now=None) -> int:
        with self._lock:
            current = self._resolve_now(now)
            expired = [
                key for key, expiry in self._used.items() if expiry <= current
            ]
            for key in expired:
                del self._used[key]
            self._record("purge_used_jti", removed=len(expired))
            return len(expired)

    def stats(self) -> dict:
        with self._lock:
            return {
                "evaluations": self._evaluations,
                "assumed": self._assumed,
                "denied": self._denied,
                "used_jti": len(self._used),
            }

    def audit_log(self) -> list:
        with self._lock:
            return copy.deepcopy(self._audit)

    def snapshot(self) -> dict:
        with self._lock:
            used_jti = [
                {"issuer": issuer, "jti": jti, "exp": expiry}
                for (issuer, jti), expiry in self._used.items()
            ]
            return {
                "version": 1,
                "issuer": self.issuer,
                "now": self.now,
                "policies": [
                    copy.deepcopy(policy)
                    for policy in self._policies.values()
                ],
                "used_jti": used_jti,
                "stats": {
                    "evaluations": self._evaluations,
                    "assumed": self._assumed,
                    "denied": self._denied,
                    "used_jti": len(self._used),
                },
                "audit": copy.deepcopy(self._audit),
            }

    @classmethod
    def restore(cls, state) -> "CiOidcGuard":
        if isinstance(state, (str, bytes, bytearray)):
            state = json.loads(state)
        if not isinstance(state, dict):
            raise CiOidcError(
                OIDC_MALFORMED_TOKEN, "snapshot must be a mapping"
            )

        guard = cls(
            issuer=state.get("issuer", ""),
            now=state.get("now", 0),
        )

        for raw in state.get("policies", []):
            name = raw["name"]
            guard._policies[name] = {
                "name": name,
                "audiences": _string_list(
                    raw.get("audiences", []), name="audiences"
                ),
                "subjects": _string_list(
                    raw.get("subjects", []), name="subjects"
                ),
                "claims": _normalize_claims(raw.get("claims")),
                "max_session": int(raw.get("max_session", 3600)),
                "deny": bool(raw.get("deny", False)),
                "enabled": bool(raw.get("enabled", True)),
            }

        used = state.get("used_jti", [])
        if isinstance(used, dict):
            used = [
                {
                    "issuer": guard.issuer,
                    "jti": jti,
                    "exp": value.get("exp") if isinstance(value, dict) else value,
                }
                for jti, value in used.items()
            ]
        for entry in used:
            issuer = entry.get("issuer", entry.get("iss", guard.issuer))
            jti = entry.get("jti")
            expiry = entry.get("exp", entry.get("expires_at"))
            if jti is None or expiry is None:
                continue
            guard._used[(issuer, jti)] = int(expiry)

        counters = state.get("stats", {})
        guard._evaluations = int(counters.get("evaluations", 0))
        guard._assumed = int(counters.get("assumed", 0))
        guard._denied = int(counters.get("denied", 0))
        guard._audit = copy.deepcopy(state.get("audit", []))
        return guard

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _resolve_now(self, now):
        return self.now if now is None else now

    def _enabled_policies(self):
        return [
            policy for policy in self._policies.values() if policy["enabled"]
        ]

    @staticmethod
    def _token_claims(token):
        claims = token.get("claims")
        if isinstance(claims, dict):
            return copy.deepcopy(claims)
        return {}

    @staticmethod
    def _validate_token(token):
        if not isinstance(token, dict):
            raise CiOidcError(
                OIDC_MALFORMED_TOKEN, "token must be a mapping"
            )
        for field in _REQUIRED_FIELDS:
            if field not in token:
                raise CiOidcError(
                    OIDC_MALFORMED_TOKEN, f"missing token field {field!r}"
                )

        for field in ("iat", "exp"):
            value = token[field]
            if isinstance(value, bool) or not isinstance(value, int):
                raise CiOidcError(
                    OIDC_MALFORMED_TOKEN,
                    f"token field {field!r} must be an integer",
                )

        for field in ("iss", "sub", "jti"):
            if not isinstance(token[field], str):
                raise CiOidcError(
                    OIDC_MALFORMED_TOKEN,
                    f"token field {field!r} must be a string",
                )

        audience = token["aud"]
        if not (
            isinstance(audience, str)
            or (
                isinstance(audience, list)
                and all(isinstance(item, str) for item in audience)
            )
        ):
            raise CiOidcError(
                OIDC_MALFORMED_TOKEN,
                "token field 'aud' must be a string or list of strings",
            )

        if "claims" in token and token["claims"] is not None:
            if not isinstance(token["claims"], dict):
                raise CiOidcError(
                    OIDC_MALFORMED_TOKEN,
                    "token field 'claims' must be a mapping",
                )
        return token

    def _record(self, action, **fields):
        entry = {"action": action}
        entry.update(fields)
        self._audit.append(entry)


__all__ = ["CiOidcError", "CiOidcGuard"]
