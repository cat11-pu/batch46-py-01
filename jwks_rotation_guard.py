"""JWKS rotation and cache guard.

Publish, rotation, cache refresh and verification all share the same
in-memory state, guarded by a single re-entrant lock.
"""

import copy
import hashlib
import hmac
import json
import threading


class JwksError(ValueError):
    """Raised for cache, key and signature failures, carrying a stable code."""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


_TOKEN_FIELDS = ("iss", "kid", "alg", "payload", "signature")


class _IssuerState:
    __slots__ = ("name", "healthy", "keys", "cache", "cache_at",
                 "last_fetch_at")

    def __init__(self, name):
        self.name = name
        self.healthy = True
        self.keys = {}        # kid -> key record, publish order
        self.cache = {}       # kid -> key record copy, fetch order
        self.cache_at = None
        self.last_fetch_at = None


class JwksGuard:
    """Issuer registry, key cache, rotation overlap and token verification."""

    def __init__(self, *, ttl=300, refresh_cooldown=30, max_stale=900,
                 max_keys=8, now=0):
        self.ttl = ttl
        self.refresh_cooldown = refresh_cooldown
        self.max_stale = max_stale
        self.max_keys = max_keys
        self.now = now
        self._lock = threading.RLock()
        self._issuers = {}
        self._refreshes = 0
        self._failures = 0
        self._audit_log = []

    def _now(self, now):
        return self.now if now is None else now

    def _require(self, issuer):
        state = self._issuers.get(issuer)
        if state is None:
            raise JwksError("JWKS_UNKNOWN_ISSUER")
        return state

    def _audit(self, event, issuer, at, kid=None):
        entry = {"event": event, "issuer": issuer, "at": at}
        if kid is not None:
            entry["kid"] = kid
        self._audit_log.append(entry)

    @staticmethod
    def _active(record, now):
        return record["expires_at"] is None or now < record["expires_at"]

    @staticmethod
    def _sign(material, kid, iss, alg, payload):
        body = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        message = "{0}|{1}|{2}|{3}".format(iss, kid, alg, body).encode("utf-8")
        return hmac.new(material.encode("utf-8"), message,
                        hashlib.sha256).hexdigest()

    def _fetch(self, state, now):
        """Simulate a JWKS pull; updates cache and counters on success."""
        state.last_fetch_at = now
        if not state.healthy:
            self._failures += 1
            self._audit("fetch_failed", state.name, now)
            return False
        state.cache = {kid: dict(rec) for kid, rec in state.keys.items()}
        state.cache_at = now
        self._refreshes += 1
        self._audit("fetch", state.name, now)
        return True

    def _ensure_cache(self, state, now):
        """Load or refresh the cache per TTL; fall back to stale cache."""
        if state.cache_at is None or now - state.cache_at >= self.ttl:
            if self._fetch(state, now):
                return False
            if state.cache_at is not None and \
                    now - state.cache_at <= self.max_stale:
                return True
            raise JwksError("JWKS_CACHE_STALE")
        return False

    def add_issuer(self, issuer) -> dict:
        with self._lock:
            if issuer in self._issuers:
                raise JwksError("JWKS_ISSUER_EXISTS")
            self._issuers[issuer] = _IssuerState(issuer)
            self._audit("add_issuer", issuer, self._now(None))
            return {"issuer": issuer, "added": True}

    def publish_key(self, issuer, kid, *, material, alg="RS256",
                    not_before=None, expires_at=None, now=None) -> dict:
        now = self._now(now)
        with self._lock:
            state = self._require(issuer)
            existing = state.keys.get(kid)
            if existing is not None and self._active(existing, now):
                raise JwksError("JWKS_DUP_KID")
            if existing is None:
                active = sum(1 for rec in state.keys.values()
                             if self._active(rec, now))
                if active >= self.max_keys:
                    raise JwksError("JWKS_KEY_LIMIT")
            else:
                del state.keys[kid]
            state.keys[kid] = {
                "kid": kid,
                "alg": alg,
                "material": material,
                "not_before": not_before,
                "expires_at": expires_at,
                "published_at": now,
            }
            self._audit("publish_key", issuer, now, kid=kid)
            return {"issuer": issuer, "kid": kid, "alg": alg,
                    "not_before": not_before, "expires_at": expires_at}

    def retire_key(self, issuer, kid, *, now=None) -> dict:
        now = self._now(now)
        with self._lock:
            state = self._require(issuer)
            if kid not in state.keys:
                raise JwksError("JWKS_UNKNOWN_KID")
            del state.keys[kid]
            state.cache.pop(kid, None)
            self._audit("retire_key", issuer, now, kid=kid)
            return {"issuer": issuer, "kid": kid, "retired": True}

    def rotate(self, issuer, *, kid, material, overlap=60, alg="RS256",
               now=None) -> dict:
        now = self._now(now)
        with self._lock:
            state = self._require(issuer)
            previous = None
            for key_id, rec in state.keys.items():
                if key_id != kid and self._active(rec, now):
                    previous = rec
            previous_expires_at = None
            if previous is not None:
                previous_expires_at = now + overlap
                previous["expires_at"] = previous_expires_at
            self.publish_key(issuer, kid, material=material, alg=alg, now=now)
            self._fetch(state, now)
            self._audit("rotate", issuer, now, kid=kid)
            return {"kid": kid,
                    "previous": previous["kid"] if previous else None,
                    "previous_expires_at": previous_expires_at}

    def set_endpoint_healthy(self, issuer, healthy) -> dict:
        with self._lock:
            state = self._require(issuer)
            state.healthy = bool(healthy)
            self._audit("endpoint_health", issuer, self._now(None))
            return {"issuer": issuer, "healthy": state.healthy}

    def keys(self, issuer, *, now=None) -> dict:
        now = self._now(now)
        with self._lock:
            state = self._require(issuer)
            stale = self._ensure_cache(state, now)
            out = []
            for rec in state.cache.values():
                if rec["expires_at"] is not None and now >= rec["expires_at"]:
                    continue
                out.append({"kid": rec["kid"], "alg": rec["alg"],
                            "not_before": rec["not_before"],
                            "expires_at": rec["expires_at"]})
            return {"issuer": issuer, "keys": out, "stale": stale}

    def verify(self, token, *, issuer, now=None) -> dict:
        now = self._now(now)
        with self._lock:
            if not isinstance(token, dict) or \
                    any(field not in token for field in _TOKEN_FIELDS):
                raise JwksError("JWKS_MALFORMED_TOKEN")
            if token["iss"] != issuer:
                raise JwksError("JWKS_ISSUER_MISMATCH")
            state = self._require(issuer)
            stale = self._ensure_cache(state, now)
            kid = token["kid"]
            record = state.cache.get(kid)
            if record is None:
                last = state.last_fetch_at
                if last is None or now - last >= self.refresh_cooldown:
                    if self._fetch(state, now):
                        stale = False
                    record = state.cache.get(kid)
                if record is None:
                    raise JwksError("JWKS_UNKNOWN_KID")
            if token["alg"] != record["alg"]:
                raise JwksError("JWKS_ALG_MISMATCH")
            if record["not_before"] is not None and now < record["not_before"]:
                raise JwksError("JWKS_KEY_NOT_YET_VALID")
            if record["expires_at"] is not None and \
                    now >= record["expires_at"]:
                raise JwksError("JWKS_KEY_EXPIRED")
            try:
                expected = self._sign(record["material"], kid, token["iss"],
                                      token["alg"], token["payload"])
            except (TypeError, ValueError):
                raise JwksError("JWKS_MALFORMED_TOKEN")
            signature = token["signature"]
            if not isinstance(signature, str) or \
                    not hmac.compare_digest(expected, signature):
                raise JwksError("JWKS_BAD_SIGNATURE")
            self._audit("verify", issuer, now, kid=kid)
            return {"payload": copy.deepcopy(token["payload"]),
                    "kid": kid, "issuer": issuer, "stale": stale}

    def refresh(self, issuer, *, now=None, force=False) -> dict:
        now = self._now(now)
        with self._lock:
            state = self._require(issuer)
            refreshed = False
            stale = False
            if force or state.cache_at is None or \
                    now - state.cache_at >= self.ttl:
                if self._fetch(state, now):
                    refreshed = True
                elif state.cache_at is not None and \
                        now - state.cache_at <= self.max_stale:
                    stale = True
                else:
                    raise JwksError("JWKS_CACHE_STALE")
            return {"issuer": issuer, "refreshed": refreshed, "stale": stale,
                    "cache_at": state.cache_at, "keys": len(state.cache)}

    def cache_info(self) -> dict:
        with self._lock:
            return {"issuers": {
                name: {
                    "healthy": state.healthy,
                    "cache_at": state.cache_at,
                    "last_fetch_at": state.last_fetch_at,
                    "cached_kids": list(state.cache),
                    "published_kids": list(state.keys),
                } for name, state in self._issuers.items()
            }}

    def stats(self) -> dict:
        with self._lock:
            return {"refreshes": self._refreshes, "failures": self._failures}

    def audit_log(self) -> list:
        with self._lock:
            return [dict(entry) for entry in self._audit_log]

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "ttl": self.ttl,
                "refresh_cooldown": self.refresh_cooldown,
                "max_stale": self.max_stale,
                "max_keys": self.max_keys,
                "now": self.now,
                "stats": {"refreshes": self._refreshes,
                          "failures": self._failures},
                "audit": [dict(entry) for entry in self._audit_log],
                "issuers": {
                    name: {
                        "healthy": state.healthy,
                        "cache_at": state.cache_at,
                        "last_fetch_at": state.last_fetch_at,
                        "keys": [dict(rec) for rec in state.keys.values()],
                        "cache": [dict(rec) for rec in state.cache.values()],
                    } for name, state in self._issuers.items()
                },
            }

    @classmethod
    def restore(cls, state) -> "JwksGuard":
        guard = cls(ttl=state["ttl"],
                    refresh_cooldown=state["refresh_cooldown"],
                    max_stale=state["max_stale"],
                    max_keys=state["max_keys"],
                    now=state.get("now", 0))
        guard._refreshes = state["stats"]["refreshes"]
        guard._failures = state["stats"]["failures"]
        guard._audit_log = [dict(entry) for entry in state.get("audit", [])]
        for name, payload in state["issuers"].items():
            issuer_state = _IssuerState(name)
            issuer_state.healthy = payload["healthy"]
            issuer_state.cache_at = payload["cache_at"]
            issuer_state.last_fetch_at = payload["last_fetch_at"]
            issuer_state.keys = {rec["kid"]: dict(rec)
                                 for rec in payload["keys"]}
            issuer_state.cache = {rec["kid"]: dict(rec)
                                  for rec in payload["cache"]}
            guard._issuers[name] = issuer_state
        return guard
