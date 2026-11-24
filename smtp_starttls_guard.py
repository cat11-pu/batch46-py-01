"""SMTP STARTTLS policy and downgrade guard."""

from __future__ import annotations

import copy
import re
import threading
from collections.abc import Mapping, Sequence

SNAPSHOT_VERSION = 1

STATE_BEGUN = "begun"
STATE_EHLO = "ehlo"
STATE_TLS = "tls"
STATE_ORDER = (STATE_BEGUN, STATE_EHLO, STATE_TLS)

TLS_ORDER = ("TLSv1.3", "TLSv1.2")
MODES = ("require", "opportunistic")

MIN_REPORT_LIMIT = 1
MAX_REPORT_LIMIT = 500

_VERSION_RE = re.compile(r"^\s*(?:TLS)?v?(\d+)(?:\.(\d+))?\s*$", re.IGNORECASE)


class StarttlsError(ValueError):
    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


def _version_tuple(value: object) -> tuple[int, int] | None:
    if not isinstance(value, str):
        return None
    match = _VERSION_RE.match(value)
    if match is None:
        return None
    return (int(match.group(1)), int(match.group(2) or 0))


class StarttlsGuard:
    TLS_VERSIONS = TLS_ORDER
    MODES = MODES

    def __init__(self, *, cache_ttl: int = 600, max_sessions: int = 64) -> None:
        self.cache_ttl = int(cache_ttl)
        self.max_sessions = int(max_sessions)
        self._lock = threading.RLock()
        self._policies: dict[str, dict] = {}
        # Cache entries are keyed by the EHLO domain, never by connection.
        # supported_at is retained after a stripped EHLO so a transient
        # capability loss remains visible for the configured TTL.
        self._cache: dict[str, dict] = {}
        self._sessions: dict[str, dict] = {}
        self._downgrades: list[dict] = []
        self._stats = {
            "sessions_started": 0,
            "ehlo_observed": 0,
            "tls_established": 0,
            "rejections": 0,
            "downgrades": 0,
            "duplicates": 0,
        }

    # ------------------------------------------------------------------
    # Validation and policy helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _domain(value: object) -> str:
        if not isinstance(value, str):
            raise StarttlsError("SMTP_DOMAIN_INVALID")
        normalized = value.strip().lower()
        while normalized.endswith("."):
            normalized = normalized[:-1]
        if not normalized:
            raise StarttlsError("SMTP_DOMAIN_INVALID")
        return normalized

    @staticmethod
    def _validate_policy(mode: object, min_version: object) -> None:
        if mode not in MODES:
            raise StarttlsError("SMTP_POLICY_INVALID")
        if min_version not in TLS_ORDER:
            raise StarttlsError("SMTP_TLS_VERSION")

    def _policy_locked(self, domain: str) -> dict:
        configured = self._policies.get(domain)
        if configured is None:
            return {
                "domain": domain,
                "mode": "require",
                "min_version": "TLSv1.2",
            }
        return {
            "domain": domain,
            "mode": configured["mode"],
            "min_version": configured["min_version"],
        }

    @staticmethod
    def _normalize_capabilities(capabilities: Sequence[str]) -> list[str]:
        if capabilities is None:
            raise StarttlsError("SMTP_EHLO_EMPTY")
        if isinstance(capabilities, (str, bytes)):
            raise StarttlsError("SMTP_EHLO_INVALID")
        try:
            items = list(capabilities)
        except TypeError as exc:
            raise StarttlsError("SMTP_EHLO_INVALID") from exc
        if not items:
            raise StarttlsError("SMTP_EHLO_EMPTY")

        normalized: set[str] = set()
        for item in items:
            if not isinstance(item, str):
                raise StarttlsError("SMTP_EHLO_INVALID")
            line = item.strip().upper()
            if line:
                normalized.add(line)
        if not normalized:
            raise StarttlsError("SMTP_EHLO_EMPTY")
        return sorted(normalized)

    @staticmethod
    def _has_starttls(capabilities: Sequence[str]) -> bool:
        return any(line.split()[0] == "STARTTLS"
                   for line in capabilities if line.split())

    # ------------------------------------------------------------------
    # Policy API
    # ------------------------------------------------------------------
    def set_policy(self, domain: str, *, mode: str = "require",
                   min_version: str = "TLSv1.2") -> dict:
        normalized = self._domain(domain)
        self._validate_policy(mode, min_version)
        with self._lock:
            self._policies[normalized] = {
                "mode": mode,
                "min_version": min_version,
            }
            return {
                "domain": normalized,
                "mode": mode,
                "min_version": min_version,
                "status": "set",
            }

    def policy_for(self, domain: str) -> dict:
        normalized = self._domain(domain)
        with self._lock:
            return self._policy_locked(normalized)

    # ------------------------------------------------------------------
    # Capability cache
    # ------------------------------------------------------------------
    def cache_lookup(self, domain: str, now: int) -> dict:
        normalized = self._domain(domain)
        with self._lock:
            entry = self._cache.get(normalized)
            if entry is None:
                return {
                    "domain": normalized,
                    "hit": False,
                    "starttls": None,
                }
            age = int(now) - int(entry["written_at"])
            if age > self.cache_ttl:
                return {
                    "domain": normalized,
                    "hit": False,
                    "starttls": None,
                }
            return {
                "domain": normalized,
                "hit": True,
                "starttls": bool(entry["starttls"]),
                "age": age,
            }

    # ------------------------------------------------------------------
    # Session helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _session_view(session: Mapping[str, object]) -> dict:
        capabilities = list(session["capabilities"])
        return {
            "session_id": session["session_id"],
            "peer_ip": session["peer_ip"],
            "domain": session["domain"],
            "ehlo_domain": session["domain"],
            "state": session["state"],
            "tls_version": session["tls_version"],
            "cipher": session["cipher"],
            "capabilities": capabilities,
            "normalized": list(capabilities),
            "starttls": session["starttls"],
        }

    def _evaluate_locked(self, session: Mapping[str, object]) -> tuple[str, str, str]:
        if session["state"] == STATE_TLS:
            return "accept_tls", "SMTP_TLS_ESTABLISHED", "accepted"

        policy = self._policy_locked(session["domain"])
        if session["stripped"] and not session["starttls"]:
            return "reject", "SMTP_STARTTLS_STRIPPED", "rejected"
        if not session["starttls"]:
            if policy["mode"] == "require":
                return "reject", "SMTP_STARTTLS_MISSING", "rejected"
            return "allow", "SMTP_STARTTLS_OPTIONAL", "allowed"
        return "starttls", "SMTP_STARTTLS_REQUIRED", "starttls"

    def _record_rejection_locked(self, session: dict) -> None:
        if not session["rejection_counted"]:
            session["rejection_counted"] = True
            self._stats["rejections"] += 1

    def _observe_view(self, session: Mapping[str, object], status: str,
                      decision: str, code: str) -> dict:
        result = self._session_view(session)
        policy = self._policy_locked(session["domain"])
        result.update({
            "status": status,
            "action": decision,
            "decision": decision,
            "code": code,
            "mode": policy["mode"],
            "min_version": policy["min_version"],
            "plaintext": decision == "allow",
        })
        return result

    # ------------------------------------------------------------------
    # Session API
    # ------------------------------------------------------------------
    def begin_session(self, session_id: str, *, peer_ip: str,
                      ehlo_domain: str, now: int = 0) -> dict:
        if not isinstance(session_id, str) or not session_id:
            raise StarttlsError("SMTP_SESSION_INVALID")
        domain = self._domain(ehlo_domain)
        with self._lock:
            if session_id in self._sessions:
                raise StarttlsError("SMTP_SESSION_EXISTS")
            if len(self._sessions) >= self.max_sessions:
                raise StarttlsError("SMTP_SESSION_LIMIT")
            session = {
                "session_id": session_id,
                "peer_ip": peer_ip,
                "domain": domain,
                "state": STATE_BEGUN,
                "tls_version": None,
                "cipher": None,
                "capabilities": [],
                "capabilities_norm": None,
                "starttls": None,
                "stripped": False,
                "rejection_counted": False,
                "last_decision": None,
                "last_code": None,
                "started_at": int(now),
                "observed_at": None,
            }
            self._sessions[session_id] = session
            self._stats["sessions_started"] += 1
            result = self._session_view(session)
            result["status"] = STATE_BEGUN
            return result

    def observe_ehlo(self, session_id: str,
                     capabilities: Sequence[str], *, now: int = 0) -> dict:
        instant = int(now)
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                raise StarttlsError("SMTP_SESSION_MISSING")
            if session["state"] == STATE_TLS:
                raise StarttlsError("SMTP_STATE_ORDER")

            normalized = self._normalize_capabilities(capabilities)
            starttls = self._has_starttls(normalized)

            if (session["state"] == STATE_EHLO
                    and session["capabilities_norm"] == normalized):
                self._stats["duplicates"] += 1
                if (session["last_decision"] is None
                        or session["last_code"] is None):
                    decision, code, _ = self._evaluate_locked(session)
                else:
                    decision = session["last_decision"]
                    code = session["last_code"]
                return self._observe_view(
                    session,
                    "duplicate",
                    decision,
                    code,
                )

            domain = session["domain"]
            entry = self._cache.get(domain)
            stripped = False
            if entry is not None and not starttls:
                supported_at = entry.get("supported_at")
                if (supported_at is not None
                        and instant - int(supported_at) <= self.cache_ttl):
                    stripped = True

            previous_capabilities = list(session["capabilities"])
            previous_starttls = session["starttls"]

            session["state"] = STATE_EHLO
            session["capabilities"] = list(normalized)
            session["capabilities_norm"] = list(normalized)
            session["starttls"] = starttls
            session["observed_at"] = instant
            self._stats["ehlo_observed"] += 1

            if entry is None:
                entry = {
                    "capabilities": [],
                    "starttls": False,
                    "written_at": instant,
                    "supported_at": None,
                }
                self._cache[domain] = entry

            entry["capabilities"] = list(normalized)
            entry["written_at"] = instant
            if starttls:
                entry["starttls"] = True
                entry["supported_at"] = instant
            else:
                entry["starttls"] = False
                supported_at = entry.get("supported_at")
                if (supported_at is not None
                        and instant - int(supported_at) > self.cache_ttl):
                    entry["supported_at"] = None

            if stripped and not session["stripped"]:
                session["stripped"] = True
                self._stats["downgrades"] += 1
                self._downgrades.append({
                    "domain": domain,
                    "session": session_id,
                    "session_id": session_id,
                    "peer_ip": session["peer_ip"],
                    "code": "SMTP_STARTTLS_STRIPPED",
                    "status": "stripped",
                    "ts": instant,
                    "now": instant,
                    "previous_capabilities": previous_capabilities,
                    "capabilities": list(normalized),
                    "previous_starttls": previous_starttls,
                })

            decision, code, _ = self._evaluate_locked(session)
            if decision == "reject":
                self._record_rejection_locked(session)
            session["last_decision"] = decision
            session["last_code"] = code
            return self._observe_view(session, "observed", decision, code)

    def decide(self, session_id: str, now: int = 0) -> dict:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                raise StarttlsError("SMTP_SESSION_MISSING")
            if session["state"] == STATE_BEGUN:
                raise StarttlsError("SMTP_STATE_ORDER")

            decision, code, status = self._evaluate_locked(session)
            if decision == "reject":
                self._record_rejection_locked(session)
            session["last_decision"] = decision
            session["last_code"] = code

            policy = self._policy_locked(session["domain"])
            return {
                "session_id": session_id,
                "domain": session["domain"],
                "state": session["state"],
                "action": decision,
                "decision": decision,
                "status": status,
                "code": code,
                "mode": policy["mode"],
                "min_version": policy["min_version"],
                "starttls": session["starttls"],
                "plaintext": decision == "allow",
            }

    def mark_tls(self, session_id: str, *, version: str,
                 cipher: str) -> dict:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                raise StarttlsError("SMTP_SESSION_MISSING")
            if session["state"] != STATE_EHLO:
                raise StarttlsError("SMTP_STATE_ORDER")

            policy = self._policy_locked(session["domain"])
            actual = _version_tuple(version)
            required = _version_tuple(policy["min_version"])
            if actual is None or required is None or actual < required:
                raise StarttlsError("SMTP_TLS_VERSION")
            if not isinstance(cipher, str) or not cipher.strip():
                raise StarttlsError("SMTP_TLS_CIPHER")

            session["state"] = STATE_TLS
            session["tls_version"] = version.strip()
            session["cipher"] = cipher.strip()
            session["stripped"] = False
            self._stats["tls_established"] += 1
            result = self._session_view(session)
            result.update({
                "status": STATE_TLS,
                "version": session["tls_version"],
                "decision": "accept_tls",
                "action": "accept_tls",
                "code": "SMTP_TLS_ESTABLISHED",
            })
            return result

    def close_session(self, session_id: str) -> bool:
        with self._lock:
            if session_id not in self._sessions:
                return False
            del self._sessions[session_id]
            return True

    # ------------------------------------------------------------------
    # Reports, metrics and snapshots
    # ------------------------------------------------------------------
    def downgrade_report(self, limit: int = 50) -> list[dict]:
        if (not isinstance(limit, int) or isinstance(limit, bool)
                or not MIN_REPORT_LIMIT <= limit <= MAX_REPORT_LIMIT):
            raise StarttlsError("SMTP_BAD_LIMIT")
        with self._lock:
            return copy.deepcopy(list(reversed(self._downgrades))[:limit])

    def metrics(self) -> dict:
        with self._lock:
            result = dict(self._stats)
            result["active_sessions"] = len(self._sessions)
            return result

    def snapshot(self) -> dict:
        with self._lock:
            sessions = {}
            for session_id, session in self._sessions.items():
                item = copy.deepcopy(session)
                item["capabilities"] = list(session["capabilities"])
                item["capabilities_norm"] = (
                    list(session["capabilities_norm"])
                    if session["capabilities_norm"] is not None else None
                )
                sessions[session_id] = item
            cache = {}
            for domain, entry in self._cache.items():
                cache[domain] = {
                    "capabilities": list(entry["capabilities"]),
                    "starttls": bool(entry["starttls"]),
                    "written_at": int(entry["written_at"]),
                    "supported_at": (
                        int(entry["supported_at"])
                        if entry.get("supported_at") is not None else None
                    ),
                }
            return {
                "version": SNAPSHOT_VERSION,
                "cache_ttl": self.cache_ttl,
                "max_sessions": self.max_sessions,
                "policies": copy.deepcopy(self._policies),
                "cache": cache,
                "sessions": sessions,
                "downgrades": copy.deepcopy(self._downgrades),
                "metrics": {
                    **self._stats,
                    "active_sessions": len(self._sessions),
                },
            }

    def restore(self, payload: Mapping[str, object]) -> dict:
        if not isinstance(payload, Mapping):
            raise StarttlsError("SMTP_SNAPSHOT_INVALID")

        try:
            version = payload["version"]
            if (isinstance(version, bool) or not isinstance(version, int)
                    or version != SNAPSHOT_VERSION):
                raise ValueError("snapshot version")

            raw_policies = payload["policies"]
            raw_cache = payload["cache"]
            raw_sessions = payload["sessions"]
            raw_downgrades = payload["downgrades"]
            raw_stats = payload["metrics"]
            cache_ttl = payload.get("cache_ttl", self.cache_ttl)
            max_sessions = payload.get("max_sessions", self.max_sessions)
            if not isinstance(raw_policies, Mapping):
                raise ValueError("policies")
            if not isinstance(raw_cache, Mapping):
                raise ValueError("cache")
            if not isinstance(raw_sessions, Mapping):
                raise ValueError("sessions")
            if not isinstance(raw_downgrades, list):
                raise ValueError("downgrades")
            if not isinstance(raw_stats, Mapping):
                raise ValueError("metrics")
            if isinstance(cache_ttl, bool) or not isinstance(cache_ttl, int):
                raise ValueError("cache ttl")
            if (isinstance(max_sessions, bool)
                    or not isinstance(max_sessions, int)):
                raise ValueError("max sessions")

            policies: dict[str, dict] = {}
            for domain, value in raw_policies.items():
                normalized = self._domain(domain)
                if not isinstance(value, Mapping):
                    raise ValueError("policy")
                mode = value.get("mode")
                min_version = value.get("min_version")
                self._validate_policy(mode, min_version)
                policies[normalized] = {
                    "mode": mode,
                    "min_version": min_version,
                }

            cache: dict[str, dict] = {}
            for domain, value in raw_cache.items():
                normalized = self._domain(domain)
                if not isinstance(value, Mapping):
                    raise ValueError("cache entry")
                capabilities = value.get("capabilities")
                if (not isinstance(capabilities, (list, tuple))
                        or any(not isinstance(item, str)
                               for item in capabilities)):
                    raise ValueError("cache capabilities")
                starttls = value.get("starttls")
                written_at = value.get("written_at")
                supported_at = value.get("supported_at")
                if not isinstance(starttls, bool):
                    raise ValueError("cache starttls")
                if isinstance(written_at, bool) or not isinstance(written_at, int):
                    raise ValueError("cache written_at")
                if supported_at is not None and (
                        isinstance(supported_at, bool)
                        or not isinstance(supported_at, int)):
                    raise ValueError("cache supported_at")
                cache[normalized] = {
                    "capabilities": list(capabilities),
                    "starttls": starttls,
                    "written_at": written_at,
                    "supported_at": supported_at,
                }

            sessions: dict[str, dict] = {}
            for session_id, value in raw_sessions.items():
                if not isinstance(session_id, str) or not session_id:
                    raise ValueError("session id")
                if not isinstance(value, Mapping):
                    raise ValueError("session")
                state = value.get("state")
                if state not in STATE_ORDER:
                    raise ValueError("session state")
                domain = self._domain(value.get("domain"))
                peer_ip = value.get("peer_ip", "")
                if not isinstance(peer_ip, str):
                    raise ValueError("peer ip")
                capabilities = value.get("capabilities", [])
                if (not isinstance(capabilities, (list, tuple))
                        or any(not isinstance(item, str)
                               for item in capabilities)):
                    raise ValueError("session capabilities")
                capabilities_norm = value.get("capabilities_norm")
                if capabilities_norm is not None and (
                        not isinstance(capabilities_norm, (list, tuple))
                        or any(not isinstance(item, str)
                               for item in capabilities_norm)):
                    raise ValueError("session capabilities_norm")
                tls_version = value.get("tls_version")
                cipher = value.get("cipher")
                starttls = value.get("starttls")
                stripped = value.get("stripped", False)
                rejection_counted = value.get("rejection_counted", False)
                last_decision = value.get("last_decision")
                last_code = value.get("last_code")
                started_at = value.get("started_at", 0)
                observed_at = value.get("observed_at")
                if tls_version is not None and not isinstance(tls_version, str):
                    raise ValueError("tls version")
                if cipher is not None and not isinstance(cipher, str):
                    raise ValueError("cipher")
                if starttls is not None and not isinstance(starttls, bool):
                    raise ValueError("starttls")
                if not isinstance(stripped, bool):
                    raise ValueError("stripped")
                if not isinstance(rejection_counted, bool):
                    raise ValueError("rejection")
                if last_decision is not None and not isinstance(last_decision, str):
                    raise ValueError("last decision")
                if last_code is not None and not isinstance(last_code, str):
                    raise ValueError("last code")
                if isinstance(started_at, bool) or not isinstance(started_at, int):
                    raise ValueError("started_at")
                if observed_at is not None and (
                        isinstance(observed_at, bool)
                        or not isinstance(observed_at, int)):
                    raise ValueError("observed_at")
                sessions[session_id] = {
                    "session_id": session_id,
                    "peer_ip": peer_ip,
                    "domain": domain,
                    "state": state,
                    "tls_version": tls_version,
                    "cipher": cipher,
                    "capabilities": list(capabilities),
                    "capabilities_norm": (
                        list(capabilities_norm)
                        if capabilities_norm is not None else None
                    ),
                    "starttls": starttls,
                    "stripped": stripped,
                    "rejection_counted": rejection_counted,
                    "last_decision": last_decision,
                    "last_code": last_code,
                    "started_at": started_at,
                    "observed_at": observed_at,
                }

            downgrades: list[dict] = []
            for row in raw_downgrades:
                if not isinstance(row, Mapping):
                    raise ValueError("downgrade row")
                if not isinstance(row.get("code"), str):
                    raise ValueError("downgrade code")
                downgrades.append(copy.deepcopy(dict(row)))

            required_stats = (
                "sessions_started",
                "ehlo_observed",
                "tls_established",
                "rejections",
                "downgrades",
                "duplicates",
            )
            stats: dict[str, int] = {}
            for key in required_stats:
                value = raw_stats.get(key)
                if isinstance(value, bool) or not isinstance(value, int):
                    raise ValueError("metric")
                stats[key] = value
        except StarttlsError as exc:
            raise StarttlsError("SMTP_SNAPSHOT_INVALID") from exc
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise StarttlsError("SMTP_SNAPSHOT_INVALID") from exc

        with self._lock:
            self.cache_ttl = cache_ttl
            self.max_sessions = max_sessions
            self._policies = policies
            self._cache = cache
            self._sessions = sessions
            self._downgrades = downgrades
            self._stats = stats
            return {
                "status": "restored",
                "restored": len(sessions),
                "sessions": len(sessions),
                "policies": len(policies),
                "cache": len(cache),
                "downgrades": len(downgrades),
            }


__all__ = [
    "StarttlsError",
    "StarttlsGuard",
    "SNAPSHOT_VERSION",
    "STATE_BEGUN",
    "STATE_EHLO",
    "STATE_TLS",
    "TLS_ORDER",
    "MODES",
]
