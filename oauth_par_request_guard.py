"""OAuth pushed authorization request guard."""

from __future__ import annotations

import secrets
import threading
import time


class ParError(ValueError):
    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


_URI_PREFIX = "urn:ietf:params:oauth:request_uri:"
_SNAPSHOT_VERSION = 1
_ENTRY_FIELDS = ("client_id", "redirect_uri", "scopes", "state",
                 "code_challenge", "code_challenge_method",
                 "created_at", "expires_at")


def _is_number(value) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


class ParGuard:
    """Validate pushed authorization requests and redeem request URIs once."""

    def __init__(self, *, request_ttl: float = 60.0, max_pending: int = 100,
                 max_per_client: int = 10, clock=None) -> None:
        self.request_ttl = float(request_ttl)
        self.max_pending = int(max_pending)
        self.max_per_client = int(max_per_client)
        self._clock = clock
        self._lock = threading.RLock()
        self._last_explicit = None
        self._clients = {}
        self._revoked = set()
        self._pending = {}
        self._used = {}
        self._stats = {"pushed": 0, "redeemed": 0}

    def _now(self, now) -> float:
        if now is not None:
            ts = float(now)
            if self._last_explicit is None or ts > self._last_explicit:
                self._last_explicit = ts
            return ts
        if self._clock is not None:
            return float(self._clock())
        if self._last_explicit is not None:
            return self._last_explicit
        return time.monotonic()

    @staticmethod
    def _client_record(client_id, redirect_uris, confidential,
                       allowed_scopes, require_pkce) -> dict:
        return {
            "client_id": client_id,
            "redirect_uris": tuple(redirect_uris),
            "confidential": bool(confidential),
            "allowed_scopes": tuple(allowed_scopes),
            "require_pkce": None if require_pkce is None else bool(require_pkce),
        }

    @staticmethod
    def _client_view(record: dict) -> dict:
        return {
            "client_id": record["client_id"],
            "redirect_uris": list(record["redirect_uris"]),
            "confidential": record["confidential"],
            "allowed_scopes": list(record["allowed_scopes"]),
            "require_pkce": record["require_pkce"],
        }

    def register_client(self, client_id: str, *, redirect_uris,
                        confidential: bool = True, allowed_scopes=(),
                        require_pkce=None) -> dict:
        if not isinstance(client_id, str) or not client_id:
            raise ParError("PAR_UNKNOWN_CLIENT", client_id)
        record = self._client_record(client_id, redirect_uris, confidential,
                                     allowed_scopes, require_pkce)
        with self._lock:
            existing = self._clients.get(client_id)
            if existing is not None and client_id not in self._revoked:
                if existing != record:
                    raise ParError("PAR_CONFLICT", client_id)
                return self._client_view(existing)
            self._clients[client_id] = record
            self._revoked.discard(client_id)
            return self._client_view(record)

    def revoke_client(self, client_id: str) -> None:
        with self._lock:
            if client_id not in self._clients or client_id in self._revoked:
                raise ParError("PAR_UNKNOWN_CLIENT", client_id)
            self._revoked.add(client_id)

    def _new_request_uri(self) -> str:
        while True:
            uri = _URI_PREFIX + secrets.token_urlsafe(24)
            if uri not in self._pending and uri not in self._used:
                return uri

    def _evict_expired(self, ts: float) -> int:
        removed = 0
        for table in (self._pending, self._used):
            for uri in [u for u, e in table.items() if e["expires_at"] <= ts]:
                del table[uri]
                removed += 1
        return removed

    def push(self, request: dict, *, now=None) -> dict:
        if not isinstance(request, dict):
            raise ParError("PAR_INVALID_REQUEST", "request must be a mapping")
        with self._lock:
            ts = self._now(now)
            duplicates = request.get("duplicates")
            if duplicates:
                raise ParError("PAR_DUPLICATE_PARAM", list(duplicates))
            client_id = request.get("client_id")
            client = self._clients.get(client_id)
            if client is None:
                raise ParError("PAR_UNKNOWN_CLIENT", client_id)
            if client_id in self._revoked:
                raise ParError("PAR_CLIENT_REVOKED", client_id)
            if request.get("response_type") != "code":
                raise ParError("PAR_UNSUPPORTED_RESPONSE_TYPE",
                               request.get("response_type"))
            redirect_uri = request.get("redirect_uri")
            if redirect_uri not in client["redirect_uris"]:
                raise ParError("PAR_REDIRECT_MISMATCH", redirect_uri)
            challenge = request.get("code_challenge")
            method = request.get("code_challenge_method")
            pkce_required = client["require_pkce"]
            if pkce_required is None:
                pkce_required = not client["confidential"]
            if challenge is None:
                if pkce_required:
                    raise ParError("PAR_PKCE_REQUIRED", client_id)
            elif method != "S256":
                raise ParError("PAR_PKCE_METHOD_UNSUPPORTED", method)
            scopes = sorted(set(str(request.get("scope") or "").split()))
            allowed = client["allowed_scopes"]
            if allowed:
                extra = [s for s in scopes if s not in allowed]
                if extra:
                    raise ParError("PAR_SCOPE_NOT_ALLOWED", extra)
            self._evict_expired(ts)
            per_client = sum(1 for e in self._pending.values()
                             if e["client_id"] == client_id)
            if per_client >= self.max_per_client:
                raise ParError("PAR_QUOTA_EXCEEDED", client_id)
            if len(self._pending) >= self.max_pending:
                raise ParError("PAR_QUOTA_EXCEEDED", "max_pending")
            uri = self._new_request_uri()
            self._pending[uri] = {
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "scopes": scopes,
                "state": request.get("state"),
                "code_challenge": challenge,
                "code_challenge_method": method if challenge is not None else None,
                "created_at": ts,
                "expires_at": ts + self.request_ttl,
            }
            self._stats["pushed"] += 1
            return {"request_uri": uri, "expires_in": self.request_ttl}

    def redeem(self, request_uri: str, *, client_id: str, now=None) -> dict:
        with self._lock:
            ts = self._now(now)
            used_entry = self._used.get(request_uri)
            if used_entry is not None:
                if used_entry["expires_at"] > ts:
                    raise ParError("PAR_REQUEST_URI_USED", request_uri)
                del self._used[request_uri]
            entry = self._pending.get(request_uri)
            if entry is None:
                raise ParError("PAR_UNKNOWN_REQUEST_URI", request_uri)
            if entry["expires_at"] <= ts:
                raise ParError("PAR_REQUEST_EXPIRED", request_uri)
            if entry["client_id"] != client_id:
                raise ParError("PAR_CLIENT_MISMATCH", request_uri)
            del self._pending[request_uri]
            self._used[request_uri] = entry
            self._stats["redeemed"] += 1
            return {
                "status": "redeemed",
                "client_id": entry["client_id"],
                "redirect_uri": entry["redirect_uri"],
                "scopes": list(entry["scopes"]),
                "state": entry["state"],
                "code_challenge": entry["code_challenge"],
                "code_challenge_method": entry["code_challenge_method"],
            }

    def peek(self, request_uri: str) -> dict:
        with self._lock:
            used = request_uri in self._used
            entry = self._used.get(request_uri) if used else self._pending.get(request_uri)
            if entry is None:
                raise ParError("PAR_UNKNOWN_REQUEST_URI", request_uri)
            return {
                "client_id": entry["client_id"],
                "redirect_uri": entry["redirect_uri"],
                "scopes": list(entry["scopes"]),
                "state": entry["state"],
                "code_challenge": entry["code_challenge"],
                "code_challenge_method": entry["code_challenge_method"],
                "expires_at": entry["expires_at"],
                "used": used,
            }

    def quota(self, client_id: str) -> dict:
        with self._lock:
            ts = self._now(None)
            live = [e for e in self._pending.values() if e["expires_at"] > ts]
            return {
                "pending": sum(1 for e in live if e["client_id"] == client_id),
                "max_per_client": self.max_per_client,
                "global_pending": len(live),
                "max_pending": self.max_pending,
            }

    def purge(self, now=None) -> int:
        with self._lock:
            return self._evict_expired(self._now(now))

    @staticmethod
    def _entry_view(entry: dict) -> dict:
        view = dict(entry)
        view["scopes"] = list(entry["scopes"])
        return view

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": _SNAPSHOT_VERSION,
                "clients": {cid: self._client_view(rec)
                            for cid, rec in self._clients.items()},
                "revoked": sorted(self._revoked),
                "pending": {uri: self._entry_view(e)
                            for uri, e in self._pending.items()},
                "used": {uri: self._entry_view(e)
                         for uri, e in self._used.items()},
                "stats": dict(self._stats),
            }

    @staticmethod
    def _parse_entry(value) -> dict:
        if not isinstance(value, dict):
            raise ParError("PAR_SNAPSHOT_INVALID", "entry must be a mapping")
        entry = {}
        for field in _ENTRY_FIELDS:
            if field not in value:
                raise ParError("PAR_SNAPSHOT_INVALID", field)
            entry[field] = value[field]
        if not isinstance(entry["client_id"], str):
            raise ParError("PAR_SNAPSHOT_INVALID", "client_id")
        if not isinstance(entry["redirect_uri"], str):
            raise ParError("PAR_SNAPSHOT_INVALID", "redirect_uri")
        scopes = entry["scopes"]
        if not isinstance(scopes, (list, tuple)) or \
                not all(isinstance(s, str) for s in scopes):
            raise ParError("PAR_SNAPSHOT_INVALID", "scopes")
        entry["scopes"] = sorted(set(scopes))
        for field in ("created_at", "expires_at"):
            if not _is_number(entry[field]):
                raise ParError("PAR_SNAPSHOT_INVALID", field)
            entry[field] = float(entry[field])
        for field in ("state", "code_challenge", "code_challenge_method"):
            if entry[field] is not None and not isinstance(entry[field], str):
                raise ParError("PAR_SNAPSHOT_INVALID", field)
        return entry

    def restore(self, state: dict) -> None:
        if not isinstance(state, dict):
            raise ParError("PAR_SNAPSHOT_INVALID", "state must be a mapping")
        if state.get("version") != _SNAPSHOT_VERSION:
            raise ParError("PAR_SNAPSHOT_INVALID", "version")
        raw_clients = state.get("clients")
        raw_revoked = state.get("revoked")
        raw_pending = state.get("pending")
        raw_used = state.get("used")
        raw_stats = state.get("stats")
        if not isinstance(raw_clients, dict):
            raise ParError("PAR_SNAPSHOT_INVALID", "clients")
        if not isinstance(raw_revoked, (list, tuple)) or \
                not all(isinstance(c, str) for c in raw_revoked):
            raise ParError("PAR_SNAPSHOT_INVALID", "revoked")
        if not isinstance(raw_pending, dict) or not isinstance(raw_used, dict):
            raise ParError("PAR_SNAPSHOT_INVALID", "pending/used")
        if not isinstance(raw_stats, dict):
            raise ParError("PAR_SNAPSHOT_INVALID", "stats")
        clients = {}
        for cid, rec in raw_clients.items():
            if not isinstance(cid, str) or not cid or not isinstance(rec, dict):
                raise ParError("PAR_SNAPSHOT_INVALID", "clients")
            redirect_uris = rec.get("redirect_uris")
            allowed_scopes = rec.get("allowed_scopes", ())
            confidential = rec.get("confidential")
            require_pkce = rec.get("require_pkce")
            if not isinstance(redirect_uris, (list, tuple)) or \
                    not all(isinstance(u, str) for u in redirect_uris):
                raise ParError("PAR_SNAPSHOT_INVALID", "redirect_uris")
            if not isinstance(allowed_scopes, (list, tuple)) or \
                    not all(isinstance(s, str) for s in allowed_scopes):
                raise ParError("PAR_SNAPSHOT_INVALID", "allowed_scopes")
            if not isinstance(confidential, bool):
                raise ParError("PAR_SNAPSHOT_INVALID", "confidential")
            if require_pkce is not None and not isinstance(require_pkce, bool):
                raise ParError("PAR_SNAPSHOT_INVALID", "require_pkce")
            clients[cid] = self._client_record(cid, redirect_uris, confidential,
                                               allowed_scopes, require_pkce)
        pending = {}
        for uri, value in raw_pending.items():
            if not isinstance(uri, str):
                raise ParError("PAR_SNAPSHOT_INVALID", "pending")
            pending[uri] = self._parse_entry(value)
        used = {}
        for uri, value in raw_used.items():
            if not isinstance(uri, str):
                raise ParError("PAR_SNAPSHOT_INVALID", "used")
            used[uri] = self._parse_entry(value)
        stats = {}
        for key in ("pushed", "redeemed"):
            value = raw_stats.get(key)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ParError("PAR_SNAPSHOT_INVALID", "stats")
            stats[key] = value
        with self._lock:
            self._clients = clients
            self._revoked = set(raw_revoked)
            self._pending = pending
            self._used = used
            self._stats = stats
            seen = [e["created_at"] for e in list(pending.values()) + list(used.values())]
            if seen:
                latest = max(seen)
                if self._last_explicit is None or latest > self._last_explicit:
                    self._last_explicit = latest

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    def reset_stats(self) -> None:
        with self._lock:
            self._stats = {"pushed": 0, "redeemed": 0}
