"""BGP FlowSpec injection guard."""

from __future__ import annotations

import copy
import hashlib
import ipaddress
import threading
import time
from collections import deque

SNAPSHOT_VERSION = 1
PEER_ROLES = ("edge", "customer", "upstream", "untrusted")
RULE_ACTIONS = ("discard", "rate-limit", "redirect")
MATCH_FIELDS = (
    "destination",
    "source",
    "protocol",
    "port",
    "tcp_flags",
    "packet_length",
    "dscp",
    "icmp_type",
)
TCP_FLAGS = ("syn", "ack", "fin", "rst", "psh", "urg")
_CONTROL_FIELDS = {"action", "priority", "ttl", "next_hop", "rule_id"}
_COUNTER_FIELDS = ("accepted", "rejected", "rate_limited", "duplicates")


class FlowspecError(ValueError):
    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


def _empty_stats() -> dict:
    return {field: 0 for field in _COUNTER_FIELDS}


def _parse_network(value: object, code: str):
    if not isinstance(value, str):
        raise FlowspecError(code, "prefix must be a string")
    try:
        return ipaddress.ip_network(value.strip(), strict=False)
    except (ValueError, TypeError):
        raise FlowspecError(code, value) from None


def _prefix_key(network) -> tuple:
    return network.version, int(network.network_address), network.prefixlen


def _normalize_prefixes(prefixes: object) -> tuple:
    if not isinstance(prefixes, (tuple, list)):
        raise FlowspecError("FSP_BAD_PREFIX", "prefixes must be a sequence")
    normalized = {}
    for value in prefixes:
        network = _parse_network(value, "FSP_BAD_PREFIX")
        normalized[network.with_prefixlen] = network
    ordered = sorted(normalized.values(), key=_prefix_key)
    return tuple(network.with_prefixlen for network in ordered)


def _as_int(value: object, code: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise FlowspecError(code, value)
    return value


def _normalize_range(value: object, maximum: int, code: str) -> str:
    if isinstance(value, int) and not isinstance(value, bool):
        start = end = value
    elif isinstance(value, str):
        text = value.strip()
        if text.count("-") == 1:
            first, second = text.split("-", 1)
            if not first.isdigit() or not second.isdigit():
                raise FlowspecError(code, value)
            start, end = int(first), int(second)
        elif text.isdigit():
            start = end = int(text)
        else:
            raise FlowspecError(code, value)
    elif isinstance(value, (tuple, list)) and len(value) == 2:
        start = _as_int(value[0], code)
        end = _as_int(value[1], code)
    else:
        raise FlowspecError(code, value)

    if start < 0 or end < 0 or start > end or end > maximum:
        raise FlowspecError(code, value)
    if start == end:
        return str(start)
    return f"{start}-{end}"


def _normalize_tcp_flags(value: object) -> tuple:
    if isinstance(value, str):
        values = [value]
    elif isinstance(value, (tuple, list, set, frozenset)):
        values = list(value)
    else:
        raise FlowspecError("FSP_BAD_RULE", value)

    normalized = set()
    for flag in values:
        if not isinstance(flag, str):
            raise FlowspecError("FSP_BAD_RULE", value)
        flag = flag.lower()
        if flag not in TCP_FLAGS:
            raise FlowspecError("FSP_BAD_RULE", value)
        normalized.add(flag)
    return tuple(flag for flag in TCP_FLAGS if flag in normalized)


def _canonical_ip(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def _normalize_components(rule: dict, max_components: int) -> dict:
    unknown = set(rule) - set(MATCH_FIELDS) - _CONTROL_FIELDS
    if unknown:
        raise FlowspecError("FSP_BAD_COMPONENT", sorted(unknown, key=str))

    if "destination" not in rule:
        raise FlowspecError("FSP_BAD_RULE", "destination is required")
    if not isinstance(rule["destination"], str):
        raise FlowspecError("FSP_BAD_RULE", "destination must be a string")

    component_count = sum(field in rule for field in MATCH_FIELDS)
    if component_count > max_components:
        raise FlowspecError(
            "FSP_TOO_MANY_COMPONENTS",
            {"count": component_count, "maximum": max_components},
        )

    destination = _parse_network(rule["destination"], "FSP_BAD_PREFIX")
    normalized = {"destination": destination.with_prefixlen}

    if "source" in rule:
        normalized["source"] = _parse_network(
            rule["source"], "FSP_BAD_PREFIX"
        ).with_prefixlen

    if "protocol" in rule:
        protocol = _as_int(rule["protocol"], "FSP_BAD_RULE")
        if not 0 <= protocol <= 255:
            raise FlowspecError("FSP_BAD_RULE", protocol)
        normalized["protocol"] = protocol

    if "port" in rule:
        normalized["port"] = _normalize_range(
            rule["port"], 65535, "FSP_BAD_PORT_RANGE"
        )

    if "tcp_flags" in rule:
        normalized["tcp_flags"] = _normalize_tcp_flags(rule["tcp_flags"])

    if "packet_length" in rule:
        normalized["packet_length"] = _normalize_range(
            rule["packet_length"], 65535, "FSP_BAD_RULE"
        )

    if "dscp" in rule:
        dscp = _as_int(rule["dscp"], "FSP_BAD_RULE")
        if not 0 <= dscp <= 63:
            raise FlowspecError("FSP_BAD_RULE", dscp)
        normalized["dscp"] = dscp

    if "icmp_type" in rule:
        icmp_type = _as_int(rule["icmp_type"], "FSP_BAD_RULE")
        if not 0 <= icmp_type <= 255:
            raise FlowspecError("FSP_BAD_RULE", icmp_type)
        normalized["icmp_type"] = icmp_type

    return {"fields": normalized, "destination_network": destination}


def _match_key(fields: dict) -> tuple:
    return tuple((field, fields[field]) for field in MATCH_FIELDS if field in fields)


class FlowspecGuard:
    """Peer registry, FlowSpec validation, conflict resolution and rate limits."""

    def __init__(self, *, max_rules: int = 256, max_components: int = 8,
                 rate_limit: int = 20, rate_window: int = 60,
                 violation_threshold: int = 3, block_seconds: int = 300,
                 allowed_next_hops: tuple = ()) -> None:
        self.max_rules = max_rules
        self.max_components = max_components
        self.rate_limit = rate_limit
        self.rate_window = rate_window
        self.violation_threshold = violation_threshold
        self.block_seconds = block_seconds
        self.allowed_next_hops = tuple(allowed_next_hops)

        self._allowed_next_hops_raw = {
            hop for hop in self.allowed_next_hops if isinstance(hop, str)
        }
        self._allowed_next_hops = {
            canonical
            for hop in self.allowed_next_hops
            if (canonical := _canonical_ip(hop)) is not None
        }

        self._lock = threading.RLock()
        self._peers = {}
        self._rules = {}
        self._stats = {}
        self._blocked = {}
        self._recent = {}
        self._violations = {}
        self._match_index = {}
        self._last_now = 0

    def _resolve_now(self, now: int | None) -> int:
        resolved = int(time.time()) if now is None else now
        if resolved > self._last_now:
            self._last_now = resolved
        return resolved

    @staticmethod
    def _result(action: str, code: str, peer: str,
                rule_id: str | None = None,
                priority: int | None = None) -> dict:
        return {
            "action": action,
            "code": code,
            "peer": peer,
            "rule_id": rule_id,
            "priority": priority,
        }

    def _peer_stats(self, peer: str) -> dict:
        return self._stats.setdefault(peer, _empty_stats())

    def _count(self, peer: str, field: str) -> None:
        if peer in self._peers:
            self._peer_stats(peer)[field] += 1

    def _reject(self, peer: str, code: str,
                rule_id: str | None = None,
                priority: int | None = None) -> dict:
        self._count(peer, "rejected")
        return self._result(
            "rejected", code, peer, rule_id=rule_id, priority=priority
        )

    def _normalize_rule(self, rule: dict, peer: str) -> dict:
        components = _normalize_components(rule, self.max_components)
        fields = components["fields"]

        if "priority" not in rule:
            raise FlowspecError("FSP_BAD_RULE", "priority is required")
        priority = _as_int(rule["priority"], "FSP_BAD_RULE")

        action = rule.get("action")
        if action not in RULE_ACTIONS:
            raise FlowspecError("FSP_BAD_ACTION", action)

        next_hop = None
        has_next_hop = "next_hop" in rule
        if action == "redirect":
            if not has_next_hop:
                raise FlowspecError("FSP_BAD_ACTION", "next_hop is required")
            value = rule["next_hop"]
            canonical = _canonical_ip(value)
            allowed = isinstance(value, str) and (
                value in self._allowed_next_hops_raw
                or (
                    canonical is not None
                    and canonical in self._allowed_next_hops
                )
            )
            if not allowed:
                raise FlowspecError("FSP_NEXT_HOP_DENIED", value)
            next_hop = canonical if canonical is not None else value
        elif has_next_hop:
            raise FlowspecError("FSP_BAD_ACTION", "unexpected next_hop")

        ttl = None
        if "ttl" in rule:
            ttl = _as_int(rule["ttl"], "FSP_BAD_RULE")
            if ttl < 0:
                raise FlowspecError("FSP_BAD_RULE", ttl)

        requested_id = None
        if "rule_id" in rule:
            requested_id = rule["rule_id"]
            if not isinstance(requested_id, str) or not requested_id:
                raise FlowspecError("FSP_BAD_RULE", "invalid rule_id")

        match_key = _match_key(fields)
        identity_key = (match_key, priority, action, next_hop)
        if requested_id is None:
            digest = hashlib.sha256(
                repr((peer, identity_key)).encode("utf-8")
            ).hexdigest()[:32]
            requested_id = f"fs-{digest}"

        return {
            "rule_id": requested_id,
            "peer": None,
            "priority": priority,
            "action": action,
            "next_hop": next_hop,
            "ttl": ttl,
            "expires_at": None,
            "fields": fields,
            "destination_network": components["destination_network"],
            "match_key": match_key,
            "identity_key": identity_key,
        }

    def _prune_expired_locked(self, now: int) -> list:
        due = [
            rule_id
            for rule_id, row in self._rules.items()
            if row["expires_at"] is not None and row["expires_at"] <= now
        ]
        for rule_id in sorted(due):
            row = self._rules.pop(rule_id)
            key = (row["peer"], row["match_key"])
            if self._match_index.get(key) == rule_id:
                del self._match_index[key]
        return sorted(due)

    def _prune_recent_locked(self, peer: str, now: int) -> None:
        cutoff = now - self.rate_window
        recent = self._recent.get(peer)
        if recent is not None:
            while recent and recent[0] <= cutoff:
                recent.popleft()
        violations = self._violations.get(peer)
        if violations is not None:
            while violations and violations[0] <= cutoff:
                violations.popleft()

    def _allow_accept_locked(self, peer: str, now: int) -> bool:
        self._prune_recent_locked(peer, now)
        recent = self._recent.setdefault(peer, deque())
        if len(recent) < self.rate_limit:
            return True

        violations = self._violations.setdefault(peer, deque())
        violations.append(now)
        while len(violations) > max(1, self.violation_threshold):
            violations.popleft()
        if len(violations) >= self.violation_threshold:
            self._blocked[peer] = now + self.block_seconds
        return False

    def _ingest_locked(self, rule: dict, peer: str, now: int) -> dict:
        if peer not in self._peers:
            return self._result("rejected", "FSP_PEER_UNKNOWN", peer)

        deadline = self._blocked.get(peer)
        if deadline is not None:
            if deadline > now:
                return self._result("blocked", "FSP_PEER_BLOCKED", peer)
            del self._blocked[peer]

        role = self._peers[peer]["role"]
        if role in ("untrusted", "upstream"):
            return self._reject(peer, "FSP_PEER_DENIED")

        if not isinstance(rule, dict):
            return self._reject(peer, "FSP_BAD_RULE")

        try:
            normalized = self._normalize_rule(rule, peer)
        except FlowspecError as exc:
            return self._reject(peer, exc.code)

        destination = normalized["destination_network"]
        if role == "customer":
            owned = self._peers[peer]["networks"]
            if not any(
                destination.version == network.version
                and destination.subnet_of(network)
                for network in owned
            ):
                return self._reject(
                    peer, "FSP_PREFIX_NOT_OWNED",
                    rule_id=normalized["rule_id"],
                    priority=normalized["priority"],
                )

        self._prune_expired_locked(now)

        key = (peer, normalized["match_key"])
        existing_id = self._match_index.get(key)
        existing = self._rules.get(existing_id) if existing_id else None
        proposed_id = normalized["rule_id"]

        if existing is not None:
            if existing["identity_key"] == normalized["identity_key"]:
                self._count(peer, "duplicates")
                return self._result(
                    "duplicate", "FSP_DUPLICATE", peer,
                    rule_id=existing["rule_id"],
                    priority=existing["priority"],
                )
            if normalized["priority"] >= existing["priority"]:
                return self._reject(
                    peer, "FSP_CONFLICT",
                    rule_id=proposed_id,
                    priority=normalized["priority"],
                )
        elif len(self._rules) >= self.max_rules:
            return self._reject(
                peer, "FSP_CAPACITY",
                rule_id=proposed_id,
                priority=normalized["priority"],
            )

        if proposed_id in self._rules and (
            existing is None or proposed_id != existing["rule_id"]
        ):
            return self._reject(
                peer, "FSP_BAD_RULE",
                rule_id=proposed_id,
                priority=normalized["priority"],
            )

        if not self._allow_accept_locked(peer, now):
            self._count(peer, "rate_limited")
            return self._result(
                "rate_limited", "FSP_RATE_LIMIT", peer,
                rule_id=proposed_id,
                priority=normalized["priority"],
            )

        code = "FSP_ACCEPTED"
        if existing is not None:
            del self._rules[existing["rule_id"]]
            code = "FSP_REPLACED"

        normalized["peer"] = peer
        normalized["expires_at"] = (
            None if normalized["ttl"] is None else now + normalized["ttl"]
        )
        self._rules[proposed_id] = normalized
        self._match_index[key] = proposed_id
        self._recent.setdefault(peer, deque()).append(now)
        self._count(peer, "accepted")

        return self._result(
            "accept", code, peer,
            rule_id=proposed_id,
            priority=normalized["priority"],
        )

    def register_peer(self, peer: str, *, role: str, asn: int,
                      prefixes: tuple = ()) -> dict:
        with self._lock:
            if role not in PEER_ROLES:
                raise FlowspecError("FSP_BAD_ROLE", role)
            if (not isinstance(asn, int) or isinstance(asn, bool)
                    or not 1 <= asn <= 4294967295):
                raise FlowspecError("FSP_BAD_ASN", asn)
            normalized_prefixes = _normalize_prefixes(prefixes)
            networks = tuple(
                ipaddress.ip_network(prefix) for prefix in normalized_prefixes
            )

            existing = self._peers.get(peer)
            if existing is not None:
                if (
                    existing["role"] == role
                    and existing["asn"] == asn
                    and existing["prefixes"] == normalized_prefixes
                ):
                    return {
                        "peer": peer,
                        "role": role,
                        "asn": asn,
                        "prefixes": normalized_prefixes,
                        "status": "unchanged",
                    }
                raise FlowspecError("FSP_PEER_CONFLICT", peer)

            self._peers[peer] = {
                "peer": peer,
                "role": role,
                "asn": asn,
                "prefixes": normalized_prefixes,
                "networks": networks,
            }
            self._peer_stats(peer)
            return {
                "peer": peer,
                "role": role,
                "asn": asn,
                "prefixes": normalized_prefixes,
                "status": "registered",
            }

    def ingest(self, rule: dict, *, peer: str, now: int | None = None) -> dict:
        with self._lock:
            return self._ingest_locked(rule, peer, self._resolve_now(now))

    def ingest_batch(self, rules: list, *, peer: str,
                     now: int | None = None) -> list:
        with self._lock:
            if now is None:
                batch_now = int(time.time())
                self._resolve_now(batch_now)
            else:
                batch_now = self._resolve_now(now)
            return [
                self._ingest_locked(rule, peer, batch_now)
                for rule in rules
            ]

    @staticmethod
    def _rule_row(rule: dict) -> dict:
        return {
            "rule_id": rule["rule_id"],
            "destination": rule["fields"]["destination"],
            "priority": rule["priority"],
            "action": rule["action"],
            "expires_at": rule["expires_at"],
        }

    def rules(self, *, peer: str | None = None,
              now: int | None = None) -> list:
        with self._lock:
            rows = []
            for rule in self._rules.values():
                if peer is not None and rule["peer"] != peer:
                    continue
                if (
                    now is not None
                    and rule["expires_at"] is not None
                    and rule["expires_at"] <= now
                ):
                    continue
                rows.append(self._rule_row(rule))
            rows.sort(key=lambda row: (
                row["priority"], row["destination"], row["rule_id"]
            ))
            return rows

    def effective(self, destination: str, *,
                  now: int | None = None) -> list:
        with self._lock:
            if not isinstance(destination, str):
                return []
            try:
                address = ipaddress.ip_address(destination.strip())
            except ValueError:
                return []
            effective_now = self._resolve_now(now)
            rows = []
            for rule in self._rules.values():
                network = rule["destination_network"]
                if network.version != address.version:
                    continue
                if (
                    rule["expires_at"] is not None
                    and rule["expires_at"] <= effective_now
                ):
                    continue
                if address not in network:
                    continue
                rows.append(rule)
            rows.sort(key=lambda rule: (
                -rule["destination_network"].prefixlen,
                rule["priority"],
                rule["rule_id"],
            ))
            return [self._rule_row(rule) for rule in rows]

    def withdraw(self, rule_id: str) -> dict:
        with self._lock:
            rule = self._rules.get(rule_id)
            if rule is None:
                raise FlowspecError("FSP_UNKNOWN_RULE", rule_id)
            del self._rules[rule_id]
            key = (rule["peer"], rule["match_key"])
            if self._match_index.get(key) == rule_id:
                del self._match_index[key]
            return {"status": "withdrawn", "rule_id": rule_id}

    def stats(self, peer: str | None = None) -> dict:
        with self._lock:
            active_blocked = {
                name for name, deadline in self._blocked.items()
                if deadline > self._last_now
            }
            if peer is not None:
                counters = dict(self._stats.get(peer, _empty_stats()))
                counters["active"] = sum(
                    rule["peer"] == peer for rule in self._rules.values()
                )
                counters["blocked"] = peer in active_blocked
                return counters

            aggregate = _empty_stats()
            for counters in self._stats.values():
                for field in _COUNTER_FIELDS:
                    aggregate[field] += counters[field]
            aggregate["active"] = len(self._rules)
            aggregate["blocked"] = len(active_blocked)
            aggregate["peers"] = len(self._peers)
            return aggregate

    def block_peer(self, peer: str, seconds: int, *,
                   now: int | None = None) -> dict:
        with self._lock:
            if peer not in self._peers:
                raise FlowspecError("FSP_PEER_UNKNOWN", peer)
            seconds = _as_int(seconds, "FSP_BAD_RULE")
            deadline = self._resolve_now(now) + seconds
            self._blocked[peer] = deadline
            return {
                "peer": peer,
                "status": "blocked",
                "blocked": True,
                "until": deadline,
            }

    def release_peer(self, peer: str) -> dict:
        with self._lock:
            self._blocked.pop(peer, None)
            self._violations.pop(peer, None)
            return {"peer": peer, "status": "released", "blocked": False}

    def blocked(self, *, now: int | None = None) -> list:
        with self._lock:
            current = self._resolve_now(now)
            for peer, deadline in list(self._blocked.items()):
                if deadline <= current:
                    del self._blocked[peer]
            return sorted(self._blocked)

    def expire(self, now: int) -> list:
        with self._lock:
            return self._prune_expired_locked(now)

    @staticmethod
    def _snapshot_rule(rule: dict) -> dict:
        row = {
            "rule_id": rule["rule_id"],
            "peer": rule["peer"],
            "destination": rule["fields"]["destination"],
            "priority": rule["priority"],
            "action": rule["action"],
            "expires_at": rule["expires_at"],
        }
        for field in MATCH_FIELDS[1:]:
            if field in rule["fields"]:
                row[field] = rule["fields"][field]
        if rule["next_hop"] is not None:
            row["next_hop"] = rule["next_hop"]
        if rule["ttl"] is not None:
            row["ttl"] = rule["ttl"]
        return row

    def snapshot(self) -> dict:
        with self._lock:
            peers = {
                peer: {
                    "peer": record["peer"],
                    "role": record["role"],
                    "asn": record["asn"],
                    "prefixes": tuple(record["prefixes"]),
                }
                for peer, record in self._peers.items()
            }
            rules = [
                self._snapshot_rule(self._rules[rule_id])
                for rule_id in sorted(self._rules)
            ]
            payload = {
                "version": SNAPSHOT_VERSION,
                "peers": peers,
                "rules": rules,
                "stats": copy.deepcopy(self._stats),
                "blocked": dict(self._blocked),
            }
            return copy.deepcopy(payload)

    def restore(self, snapshot: dict) -> None:
        with self._lock:
            try:
                if not isinstance(snapshot, dict):
                    raise FlowspecError("FSP_SNAPSHOT_CORRUPT", "not a mapping")
                if (
                    not isinstance(snapshot.get("version"), int)
                    or isinstance(snapshot.get("version"), bool)
                    or snapshot.get("version") != SNAPSHOT_VERSION
                ):
                    raise FlowspecError("FSP_SNAPSHOT_CORRUPT", "bad version")
                required = {"peers", "rules", "stats", "blocked"}
                if not required.issubset(snapshot):
                    raise FlowspecError("FSP_SNAPSHOT_CORRUPT", "missing field")

                peers_in = snapshot["peers"]
                rules_in = snapshot["rules"]
                stats_in = snapshot["stats"]
                blocked_in = snapshot["blocked"]
                if not isinstance(peers_in, dict):
                    raise FlowspecError("FSP_SNAPSHOT_CORRUPT", "bad peers")
                if not isinstance(rules_in, list):
                    raise FlowspecError("FSP_SNAPSHOT_CORRUPT", "bad rules")
                if not isinstance(stats_in, dict):
                    raise FlowspecError("FSP_SNAPSHOT_CORRUPT", "bad stats")
                if not isinstance(blocked_in, dict):
                    raise FlowspecError("FSP_SNAPSHOT_CORRUPT", "bad blocked")
                if len(rules_in) > self.max_rules:
                    raise FlowspecError("FSP_SNAPSHOT_CORRUPT", "too many rules")

                peers = {}
                for peer, record in peers_in.items():
                    if not isinstance(peer, str) or not isinstance(record, dict):
                        raise FlowspecError("FSP_SNAPSHOT_CORRUPT", "bad peer")
                    role = record.get("role")
                    asn = record.get("asn")
                    if role not in PEER_ROLES:
                        raise FlowspecError("FSP_SNAPSHOT_CORRUPT", "bad role")
                    if (not isinstance(asn, int) or isinstance(asn, bool)
                            or not 1 <= asn <= 4294967295):
                        raise FlowspecError("FSP_SNAPSHOT_CORRUPT", "bad asn")
                    prefixes = _normalize_prefixes(record.get("prefixes", ()))
                    networks = tuple(
                        ipaddress.ip_network(prefix) for prefix in prefixes
                    )
                    peers[peer] = {
                        "peer": peer,
                        "role": role,
                        "asn": asn,
                        "prefixes": prefixes,
                        "networks": networks,
                    }

                stats = {}
                for peer, counters in stats_in.items():
                    if peer not in peers or not isinstance(counters, dict):
                        raise FlowspecError("FSP_SNAPSHOT_CORRUPT", "bad stats")
                    clean = _empty_stats()
                    for field in _COUNTER_FIELDS:
                        value = counters.get(field, 0)
                        if (not isinstance(value, int) or isinstance(value, bool)
                                or value < 0):
                            raise FlowspecError(
                                "FSP_SNAPSHOT_CORRUPT", "bad counter"
                            )
                        clean[field] = value
                    stats[peer] = clean
                for peer in peers:
                    stats.setdefault(peer, _empty_stats())

                blocked = {}
                for peer, deadline in blocked_in.items():
                    if peer not in peers:
                        raise FlowspecError(
                            "FSP_SNAPSHOT_CORRUPT", "unknown blocked peer"
                        )
                    if (not isinstance(deadline, (int, float))
                            or isinstance(deadline, bool)):
                        raise FlowspecError(
                            "FSP_SNAPSHOT_CORRUPT", "bad block deadline"
                        )
                    blocked[peer] = deadline

                rules = {}
                match_index = {}
                for raw in rules_in:
                    if not isinstance(raw, dict):
                        raise FlowspecError("FSP_SNAPSHOT_CORRUPT", "bad rule")
                    rule_id = raw.get("rule_id")
                    if not isinstance(rule_id, str) or not rule_id:
                        raise FlowspecError(
                            "FSP_SNAPSHOT_CORRUPT", "bad rule id"
                        )
                    if rule_id in rules:
                        raise FlowspecError(
                            "FSP_SNAPSHOT_CORRUPT", "duplicate rule id"
                        )
                    peer = raw.get("peer")
                    if peer not in peers:
                        raise FlowspecError(
                            "FSP_SNAPSHOT_CORRUPT", "unknown rule peer"
                        )

                    candidate = {
                        key: raw[key]
                        for key in (
                            "destination", "priority", "action", "next_hop",
                            "source", "protocol", "port", "tcp_flags",
                            "packet_length", "dscp", "icmp_type",
                        )
                        if key in raw
                    }
                    normalized = self._normalize_rule(candidate, peer)
                    normalized["rule_id"] = rule_id
                    normalized["peer"] = peer
                    expires_at = raw.get("expires_at")
                    if expires_at is not None and (
                        not isinstance(expires_at, (int, float))
                        or isinstance(expires_at, bool)
                    ):
                        raise FlowspecError(
                            "FSP_SNAPSHOT_CORRUPT", "bad expiry"
                        )
                    normalized["expires_at"] = expires_at
                    ttl = raw.get("ttl")
                    if ttl is not None and (
                        not isinstance(ttl, int) or isinstance(ttl, bool)
                        or ttl < 0
                    ):
                        raise FlowspecError(
                            "FSP_SNAPSHOT_CORRUPT", "bad ttl"
                        )
                    normalized["ttl"] = ttl

                    match = (peer, normalized["match_key"])
                    if match in match_index:
                        raise FlowspecError(
                            "FSP_SNAPSHOT_CORRUPT", "duplicate match"
                        )
                    rules[rule_id] = normalized
                    match_index[match] = rule_id

                self._peers = peers
                self._rules = rules
                self._stats = stats
                self._blocked = blocked
                self._recent = {}
                self._violations = {}
                self._match_index = match_index
                self._last_now = 0
            except FlowspecError as exc:
                if exc.code == "FSP_SNAPSHOT_CORRUPT":
                    raise
                raise FlowspecError(
                    "FSP_SNAPSHOT_CORRUPT", exc.detail
                ) from None
            except Exception as exc:
                raise FlowspecError("FSP_SNAPSHOT_CORRUPT", str(exc)) from None
