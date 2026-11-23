"""IPv6 Router Advertisement guard.

The guard keeps per-port roles and VLANs, validates Neighbor Discovery
messages, maintains a bounded per-VLAN prefix table, rate limits accepted
Router Advertisements, and quarantines ports that keep violating policy.
"""

from __future__ import annotations

import copy
import ipaddress
import threading
import time
from collections import deque


SNAPSHOT_VERSION = 1
VIOLATION_WINDOW = 60
MAX_PREFIXES_PER_VLAN = 8
MAX_VIOLATION_LOG = 1024

VALID_ROLES = frozenset({"uplink", "host", "untrusted"})

_LINK_LOCAL = ipaddress.IPv6Network("fe80::/10")
_DEFAULT_RA_DESTINATION = ipaddress.IPv6Address("ff02::1")


class RaError(Exception):
    """Configuration/administrative error with a stable error code."""

    def __init__(self, code: str, detail=None):
        self.code = code
        self.detail = detail
        super().__init__(code if detail is None else f"{code}: {detail}")


class _PrefixRecord(dict):
    """Prefix row that also compares equal to its canonical CIDR string."""

    def __eq__(self, other):
        if isinstance(other, str):
            return self.get("prefix") == other
        if isinstance(other, dict):
            return (dict.__eq__(self, other) or
                    (bool(other) and
                     all(self.get(key) == value
                         for key, value in other.items())))
        return NotImplemented

    __hash__ = None


class _ViolationRecord(dict):
    """Violation row that also compares equal to its error code."""

    def __eq__(self, other):
        if isinstance(other, str):
            return self.get("code") == other
        if isinstance(other, dict):
            return (dict.__eq__(self, other) or
                    (bool(other) and
                     all(self.get(key) == value
                         for key, value in other.items())))
        return NotImplemented

    __hash__ = None


def _result(action: str, code: str, port: str) -> dict:
    return {"action": action, "code": code, "port": port}


def _as_now(value) -> float:
    if value is None:
        return float(time.time())
    if hasattr(value, "timestamp"):
        return float(value.timestamp())
    return float(value)


def _packet_now(packet: dict) -> float:
    if "now" in packet:
        return _as_now(packet.get("now"))
    if "timestamp" in packet:
        return _as_now(packet.get("timestamp"))
    return float(time.time())


def _packet_type(packet: dict) -> str | None:
    value = packet.get("type", packet.get("packet_type", packet.get("icmp_type")))
    if value is None:
        if "target" in packet:
            return "na"
        return "ra"
    if isinstance(value, str):
        value = value.strip().lower().replace("-", "_")
    if value in (134, "134", "ra", "router_advertisement", "router_advert"):
        return "ra"
    if value in (135, "135", "ns", "neighbor_solicitation"):
        return "ns"
    if value in (136, "136", "na", "neighbor_advertisement"):
        return "na"
    return None


def _packet_value(packet: dict, *names, default=None):
    for name in names:
        if name in packet:
            return packet[name]
    return default


def _parse_ipv6_address(value):
    if isinstance(value, ipaddress.IPv6Address):
        return value
    try:
        return ipaddress.IPv6Address(str(value))
    except (ipaddress.AddressValueError, ValueError, TypeError):
        return None


def _parse_ipv6_network(value):
    if isinstance(value, ipaddress.IPv6Network):
        return value
    try:
        return ipaddress.IPv6Network(str(value), strict=False)
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError,
            ValueError, TypeError):
        return None


def _is_link_local(value) -> bool:
    address = _parse_ipv6_address(value)
    return address is not None and address.is_link_local


def _is_unspecified(value) -> bool:
    address = _parse_ipv6_address(value)
    return address is not None and address.is_unspecified


def _lifetime(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return value
    return None


def _prefix_value(prefix: dict, *names, default=None):
    if not isinstance(prefix, dict):
        return default
    return _packet_value(prefix, *names, default=default)


class RaGuard:
    """Policy-enforcing IPv6 RA guard."""

    def __init__(self, *, rate_limit: int = 5, rate_window: int = 1,
                 violation_threshold: int = 3, quarantine_seconds: int = 300):
        self.rate_limit = int(rate_limit)
        self.rate_window = int(rate_window)
        self.violation_threshold = int(violation_threshold)
        self.quarantine_seconds = int(quarantine_seconds)

        self._lock = threading.RLock()
        self._ports: dict[str, dict] = {}
        self._prefixes: dict[int, dict[str, dict]] = {}
        self._rate: dict[str, deque] = {}
        self._violation_times: dict[str, deque] = {}
        self._violations: dict[str, list[dict]] = {}
        self._quarantine_until: dict[str, float] = {}
        self._stats: dict[str, dict] = {}
        self._last_now: float | None = None

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------
    def _new_stats(self) -> dict:
        return {
            "received": 0,
            "accepted": 0,
            "dropped": 0,
            "rate_limited": 0,
            "quarantined": 0,
            "violations": 0,
            "ignored": 0,
        }

    @staticmethod
    def _config_view(port: str, cfg: dict) -> dict:
        return {
            "port": port,
            "role": cfg["role"],
            "vlan": cfg["vlan"],
            "allowed_prefixes": list(cfg["allowed_prefixes"]),
            "default_route": cfg["default_route"],
        }

    def configure_port(self, port: str, role: str, *, vlan: int = 1,
                       allowed_prefixes: tuple = (),
                       default_route: bool = False) -> dict:
        if not isinstance(port, str) or not port:
            raise RaError("RA_BAD_PORT", "port must be a non-empty string")
        if not isinstance(role, str) or role not in VALID_ROLES:
            raise RaError("RA_BAD_ROLE", role)
        if isinstance(vlan, bool) or not isinstance(vlan, int) or not 1 <= vlan <= 4094:
            raise RaError("RA_BAD_VLAN", vlan)

        if isinstance(allowed_prefixes, str):
            allowed_prefixes = (allowed_prefixes,)
        networks = []
        for item in allowed_prefixes or ():
            network = _parse_ipv6_network(item)
            if network is None:
                raise RaError("RA_BAD_PREFIX_CONFIG", item)
            networks.append(str(network))
        allowed = tuple(networks)

        config = {
            "role": role,
            "vlan": vlan,
            "allowed_prefixes": allowed,
            "default_route": bool(default_route),
        }

        with self._lock:
            existing = self._ports.get(port)
            if existing is not None:
                if existing == config:
                    return self._config_view(port, existing)
                raise RaError("RA_PORT_CONFLICT", port)

            self._ports[port] = config
            self._prefixes.setdefault(vlan, {})
            self._rate.setdefault(port, deque())
            self._violation_times.setdefault(port, deque())
            self._violations.setdefault(port, [])
            self._stats[port] = self._new_stats()
            return self._config_view(port, config)

    # ------------------------------------------------------------------
    # Ingress
    # ------------------------------------------------------------------
    def ingest(self, packet: dict) -> dict:
        with self._lock:
            return self._ingest_locked(packet)

    def ingest_batch(self, packets: list) -> list:
        with self._lock:
            return [self._ingest_locked(packet) for packet in packets]

    def _ingest_locked(self, packet: dict) -> dict:
        if not isinstance(packet, dict):
            return _result("drop", "RA_INVALID_PACKET", "")

        now = _packet_now(packet)
        self._last_now = now
        port = _packet_value(packet, "port", "ifname", "interface", default="")
        if not isinstance(port, str) or port not in self._ports:
            return _result("drop", "RA_PORT_UNKNOWN", str(port))

        self._prune_violation_window(port, now)
        deadline = self._quarantine_until.get(port)
        if deadline is not None:
            if deadline > now:
                self._stats[port]["received"] += 1
                self._stats[port]["quarantined"] += 1
                return _result("quarantined", "RA_PORT_QUARANTINED", port)
            del self._quarantine_until[port]

        cfg = self._ports[port]
        self._stats[port]["received"] += 1
        role = cfg["role"]
        packet_type = _packet_type(packet)

        if role == "untrusted":
            return self._drop(port, "RA_ROLE_DENIED", now)
        if packet_type is None:
            return self._drop(port, "RA_INVALID_PACKET", now)
        if packet_type == "ra" and role == "host":
            return self._drop(port, "RA_ROLE_DENIED", now)

        hop_limit = _packet_value(packet, "hop_limit", "hlim", "hoplimit")
        if hop_limit != 255:
            return self._drop(port, "RA_HOP_LIMIT", now)

        if packet_type == "ra":
            dst = _packet_value(packet, "dst", "destination", "dst_address",
                                "destination_address", default="ff02::1")
            if _parse_ipv6_address(dst) != _DEFAULT_RA_DESTINATION:
                return self._drop(port, "RA_DST_INVALID", now)

        src = _packet_value(packet, "src", "source", "source_address")
        if packet_type == "ns" and _is_unspecified(src):
            pass
        elif not _is_link_local(src):
            return self._drop(port, "RA_SRC_NOT_LINK_LOCAL", now)

        if packet_type == "ns" or packet_type == "na":
            self._stats[port]["accepted"] += 1
            return _result("accept", "RA_ACCEPTED", port)

        router_lifetime = _lifetime(_packet_value(
            packet, "router_lifetime", "router_lifetime_seconds", default=0
        ))
        if router_lifetime is None or router_lifetime < 0:
            return self._drop(port, "RA_ROUTER_LIFETIME_INVALID", now)
        if router_lifetime > 0 and not cfg["default_route"]:
            return self._drop(port, "RA_DEFAULT_ROUTE_DENIED", now)

        prefixes = packet.get("prefixes") or []
        if not isinstance(prefixes, (list, tuple)):
            return self._drop(port, "RA_PREFIX_INVALID", now)
        if len(prefixes) > MAX_PREFIXES_PER_VLAN:
            return self._drop(port, "RA_TOO_MANY_PREFIXES", now)

        parsed = []
        seen = set()
        for item in prefixes:
            network = _parse_ipv6_network(_prefix_value(
                item, "prefix", "cidr", "network"
            ))
            if network is None or network.prefixlen != 64:
                return self._drop(port, "RA_PREFIX_LEN", now)
            valid = _lifetime(_prefix_value(
                item, "valid_lifetime", "valid", default=None
            ))
            preferred = _lifetime(_prefix_value(
                item, "preferred_lifetime", "preferred", default=None
            ))
            if valid is None or preferred is None:
                return self._drop(port, "RA_PREFIX_LIFETIME_INVALID", now)
            if preferred > valid:
                return self._drop(port, "RA_LIFETIME_ORDER", now)
            if valid < 600:
                return self._drop(port, "RA_LIFETIME_TOO_SHORT", now)
            if not any(
                    network.subnet_of(allowed)
                    for allowed in self._allowed_networks(cfg)):
                return self._drop(port, "RA_PREFIX_NOT_ALLOWED", now)
            if network not in seen:
                seen.add(network)
                parsed.append((network, valid, preferred))

        if self._would_exceed_prefix_capacity(cfg["vlan"], parsed, now):
            return self._drop(port, "RA_TOO_MANY_PREFIXES", now)

        if self._rate_limited(port, now):
            return self._rate_limited_result(port, now)

        self._commit_prefixes(port, cfg["vlan"], parsed, now)
        if self.rate_limit > 0 and self.rate_window > 0:
            self._rate[port].append(now)
        self._stats[port]["accepted"] += 1
        return _result("accept", "RA_ACCEPTED", port)

    @staticmethod
    def _allowed_networks(cfg):
        return tuple(_parse_ipv6_network(item) for item in cfg["allowed_prefixes"])

    def _rate_limited(self, port: str, now: float) -> bool:
        if self.rate_limit <= 0 or self.rate_window <= 0:
            return False
        window = self._rate[port]
        cutoff = now - self.rate_window
        while window and window[0] <= cutoff:
            window.popleft()
        return len(window) >= self.rate_limit

    def _rate_limited_result(self, port: str, now: float) -> dict:
        self._stats[port]["rate_limited"] += 1
        self._record_violation(port, "RA_RATE_LIMIT", now)
        return _result("rate_limited", "RA_RATE_LIMIT", port)

    def _drop(self, port: str, code: str, now: float) -> dict:
        self._stats[port]["dropped"] += 1
        self._record_violation(port, code, now)
        return _result("drop", code, port)

    def _prune_violation_window(self, port: str, now: float) -> None:
        cutoff = now - VIOLATION_WINDOW
        times = self._violation_times[port]
        records = self._violations[port]
        while times and times[0] <= cutoff:
            times.popleft()
            if records:
                records.pop(0)

    def _record_violation(self, port: str, code: str, now: float) -> None:
        self._prune_violation_window(port, now)
        self._violation_times[port].append(now)
        self._violations[port].append(_ViolationRecord({
            "port": port,
            "code": code,
            "reason": code,
            "now": now,
            "time": now,
        }))
        if len(self._violations[port]) > MAX_VIOLATION_LOG:
            self._violations[port].pop(0)
        self._stats[port]["violations"] += 1
        threshold = max(1, self.violation_threshold)
        if (len(self._violation_times[port]) >= threshold and
                port not in self._quarantine_until):
            self._quarantine_until[port] = now + max(0, self.quarantine_seconds)

    # ------------------------------------------------------------------
    # Prefix table
    # ------------------------------------------------------------------
    def _would_exceed_prefix_capacity(self, vlan: int, parsed, now: float) -> bool:
        table = self._prefixes.setdefault(vlan, {})
        live = {
            key for key, entry in table.items()
            if entry["valid_until"] > now
        }
        for network, _valid, _preferred in parsed:
            live.add(str(network))
        return len(live) > MAX_PREFIXES_PER_VLAN

    def _commit_prefixes(self, port: str, vlan: int, parsed, now: float) -> None:
        table = self._prefixes.setdefault(vlan, {})
        for key in [key for key, entry in table.items()
                    if entry["valid_until"] <= now]:
            del table[key]

        for network, valid, preferred in parsed:
            key = str(network)
            valid_until = now + valid
            preferred_until = now + preferred
            existing = table.get(key)
            if existing is not None and valid_until < existing["valid_until"]:
                self._stats[port]["ignored"] += 1
                continue
            table[key] = {
                "prefix": key,
                "vlan": vlan,
                "valid_until": valid_until,
                "preferred_until": preferred_until,
                "port": port,
            }

    def prefix_table(self, vlan: int) -> list:
        with self._lock:
            table = self._prefixes.get(vlan, {})
            entries = [_PrefixRecord(copy.deepcopy(entry))
                       for entry in table.values()]
            entries.sort(key=lambda item: (
                int(ipaddress.IPv6Network(item["prefix"]).network_address),
                ipaddress.IPv6Network(item["prefix"]).prefixlen,
            ))
            return entries

    def effective_prefixes(self, port: str, *, now: int | None = None) -> list:
        with self._lock:
            cfg = self._ports.get(port)
            if cfg is None:
                return []
            if now is None:
                at = self._last_now if self._last_now is not None else time.time()
            else:
                at = _as_now(now)
            table = self._prefixes.get(cfg["vlan"], {})
            entries = [
                entry for entry in table.values()
                if entry["valid_until"] > at
            ]
            entries.sort(key=lambda item: (
                int(ipaddress.IPv6Network(item["prefix"]).network_address),
                ipaddress.IPv6Network(item["prefix"]).prefixlen,
            ))
            return [entry["prefix"] for entry in entries]

    # ------------------------------------------------------------------
    # Counters and quarantine
    # ------------------------------------------------------------------
    def port_stats(self, port: str) -> dict:
        with self._lock:
            cfg = self._ports.get(port)
            if cfg is None:
                stats = self._new_stats()
                stats.update({
                    "port": port,
                    "role": None,
                    "vlan": None,
                    "rejected": 0,
                    "violation_count": 0,
                    "violations_window": 0,
                    "active": 0,
                    "blocked": port in self._quarantine_until,
                    "quarantined": port in self._quarantine_until,
                    "quarantine_until": self._quarantine_until.get(port),
                })
                return stats
            stats = copy.deepcopy(self._stats[port])
            live = sum(
                1 for entry in self._prefixes.get(cfg["vlan"], {}).values()
                if entry["port"] == port and
                (self._last_now is None or entry["valid_until"] > self._last_now)
            )
            stats.update({
                "port": port,
                "role": cfg["role"],
                "vlan": cfg["vlan"],
                "rejected": stats["dropped"],
                "violation_count": stats["violations"],
                "violations_window": len(self._violation_times[port]),
                "active": live,
                "blocked": port in self._quarantine_until,
                "quarantined": port in self._quarantine_until,
                "quarantine_until": self._quarantine_until.get(port),
            })
            return stats

    def violations(self, port: str | None = None) -> list:
        with self._lock:
            if port is not None:
                return [_ViolationRecord(copy.deepcopy(item))
                        for item in self._violations.get(port, [])]
            out = []
            for name in sorted(self._violations):
                out.extend(_ViolationRecord(copy.deepcopy(item))
                           for item in self._violations[name])
            return out

    def quarantine(self, port: str, seconds: int) -> dict:
        if isinstance(seconds, bool) or not isinstance(seconds, int) or seconds < 0:
            raise RaError("RA_BAD_QUARANTINE", seconds)
        with self._lock:
            base = self._last_now if self._last_now is not None else time.time()
            deadline = float(base) + seconds
            self._quarantine_until[port] = deadline
            return {
                "port": port,
                "action": "quarantine",
                "code": "RA_QUARANTINED",
                "status": "quarantined",
                "blocked": True,
                "quarantined": True,
                "until": deadline,
                "quarantine_until": deadline,
            }

    def release_port(self, port: str) -> dict:
        with self._lock:
            self._quarantine_until.pop(port, None)
            if port in self._rate:
                self._rate[port].clear()
                self._violation_times[port].clear()
                self._violations[port].clear()
            return {
                "port": port,
                "action": "release",
                "code": "RA_RELEASED",
                "status": "released",
                "blocked": False,
                "quarantined": False,
                "until": None,
                "quarantine_until": None,
            }

    def expire(self, now: int) -> list:
        at = _as_now(now)
        with self._lock:
            self._last_now = at
            expired = sorted(
                port for port, deadline in self._quarantine_until.items()
                if deadline <= at
            )
            for port in expired:
                del self._quarantine_until[port]
            for port in self._violation_times:
                self._prune_violation_window(port, at)
            return expired

    # ------------------------------------------------------------------
    # Snapshot/restore
    # ------------------------------------------------------------------
    def snapshot(self) -> dict:
        with self._lock:
            ports = {
                port: {
                    "role": cfg["role"],
                    "vlan": cfg["vlan"],
                    "allowed_prefixes": list(cfg["allowed_prefixes"]),
                    "default_route": cfg["default_route"],
                }
                for port, cfg in self._ports.items()
            }
            prefixes = {
                vlan: {
                    key: copy.deepcopy(entry)
                    for key, entry in table.items()
                }
                for vlan, table in self._prefixes.items()
            }
            snapshot = {
                "version": SNAPSHOT_VERSION,
                "policy": {
                    "rate_limit": self.rate_limit,
                    "rate_window": self.rate_window,
                    "violation_threshold": self.violation_threshold,
                    "quarantine_seconds": self.quarantine_seconds,
                },
                "ports": copy.deepcopy(ports),
                "prefixes": copy.deepcopy(prefixes),
                "rate": {
                    port: list(window) for port, window in self._rate.items()
                },
                "violation_times": {
                    port: list(times)
                    for port, times in self._violation_times.items()
                },
                "violations": copy.deepcopy(self._violations),
                "quarantine_until": dict(self._quarantine_until),
                "stats": copy.deepcopy(self._stats),
                "last_now": self._last_now,
            }
            return copy.deepcopy(snapshot)

    def restore(self, snapshot: dict) -> None:
        with self._lock:
            try:
                state = self._validated_snapshot(snapshot)
            except RaError:
                raise
            except Exception as exc:
                raise RaError("RA_SNAPSHOT_CORRUPT", str(exc)) from exc

            self._ports = state["ports"]
            self._prefixes = state["prefixes"]
            self._rate = state["rate"]
            self._violation_times = state["violation_times"]
            self._violations = state["violations"]
            self._quarantine_until = state["quarantine_until"]
            self._stats = state["stats"]
            self._last_now = state["last_now"]
            self.rate_limit = state["policy"]["rate_limit"]
            self.rate_window = state["policy"]["rate_window"]
            self.violation_threshold = state["policy"]["violation_threshold"]
            self.quarantine_seconds = state["policy"]["quarantine_seconds"]

    def _validated_snapshot(self, snapshot: dict) -> dict:
        if not isinstance(snapshot, dict):
            raise RaError("RA_SNAPSHOT_CORRUPT", "snapshot must be a mapping")
        version = snapshot.get("version")
        if (isinstance(version, bool) or not isinstance(version, int)
                or version != SNAPSHOT_VERSION):
            raise RaError("RA_SNAPSHOT_CORRUPT", "unsupported version")

        raw_ports = snapshot.get("ports")
        raw_prefixes = snapshot.get("prefixes")
        if not isinstance(raw_ports, dict) or not isinstance(raw_prefixes, dict):
            raise RaError("RA_SNAPSHOT_CORRUPT", "missing ports or prefixes")

        raw_policy = snapshot.get("policy", {})
        if not isinstance(raw_policy, dict):
            raise RaError("RA_SNAPSHOT_CORRUPT", "bad policy")
        policy = {
            "rate_limit": self.rate_limit,
            "rate_window": self.rate_window,
            "violation_threshold": self.violation_threshold,
            "quarantine_seconds": self.quarantine_seconds,
        }
        for key in policy:
            if key not in raw_policy:
                continue
            value = raw_policy[key]
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise RaError("RA_SNAPSHOT_CORRUPT", "bad policy value")
            policy[key] = value

        ports = {}
        for port, cfg in raw_ports.items():
            if not isinstance(port, str) or not port or not isinstance(cfg, dict):
                raise RaError("RA_SNAPSHOT_CORRUPT", "bad port")
            role = cfg.get("role")
            vlan = cfg.get("vlan")
            allowed = cfg.get("allowed_prefixes", [])
            default_route = cfg.get("default_route", False)
            if role not in VALID_ROLES:
                raise RaError("RA_SNAPSHOT_CORRUPT", "bad role")
            if isinstance(vlan, bool) or not isinstance(vlan, int) or not 1 <= vlan <= 4094:
                raise RaError("RA_SNAPSHOT_CORRUPT", "bad vlan")
            if not isinstance(allowed, (list, tuple)):
                raise RaError("RA_SNAPSHOT_CORRUPT", "bad allowed prefixes")
            networks = []
            for item in allowed:
                network = _parse_ipv6_network(item)
                if network is None:
                    raise RaError("RA_SNAPSHOT_CORRUPT", "bad allowed prefix")
                networks.append(str(network))
            ports[port] = {
                "role": role,
                "vlan": vlan,
                "allowed_prefixes": tuple(networks),
                "default_route": bool(default_route),
            }

        prefixes = {}
        for vlan, table in raw_prefixes.items():
            if isinstance(vlan, str) and vlan.isdigit():
                vlan = int(vlan)
            if isinstance(vlan, bool) or not isinstance(vlan, int) or not 1 <= vlan <= 4094:
                raise RaError("RA_SNAPSHOT_CORRUPT", "bad prefix vlan")
            if not isinstance(table, dict):
                raise RaError("RA_SNAPSHOT_CORRUPT", "bad prefix table")
            if len(table) > MAX_PREFIXES_PER_VLAN:
                raise RaError("RA_SNAPSHOT_CORRUPT", "prefix table overflow")
            entries = {}
            for key, entry in table.items():
                if not isinstance(entry, dict):
                    raise RaError("RA_SNAPSHOT_CORRUPT", "bad prefix entry")
                network = _parse_ipv6_network(entry.get("prefix", key))
                if network is None:
                    raise RaError("RA_SNAPSHOT_CORRUPT", "bad prefix")
                valid_until = entry.get("valid_until")
                preferred_until = entry.get("preferred_until", valid_until)
                if not isinstance(valid_until, (int, float)) or isinstance(valid_until, bool):
                    raise RaError("RA_SNAPSHOT_CORRUPT", "bad prefix lifetime")
                if not isinstance(preferred_until, (int, float)) or isinstance(preferred_until, bool):
                    raise RaError("RA_SNAPSHOT_CORRUPT", "bad preferred lifetime")
                canonical = str(network)
                entries[canonical] = {
                    "prefix": canonical,
                    "vlan": vlan,
                    "valid_until": float(valid_until),
                    "preferred_until": float(preferred_until),
                    "port": entry.get("port", ""),
                }
            prefixes[vlan] = entries

        rate = {}
        raw_rate = snapshot.get("rate", {})
        if not isinstance(raw_rate, dict):
            raise RaError("RA_SNAPSHOT_CORRUPT", "bad rate table")
        for port, window in raw_rate.items():
            if port not in ports or not isinstance(window, (list, tuple)):
                raise RaError("RA_SNAPSHOT_CORRUPT", "bad rate window")
            values = []
            for value in window:
                if isinstance(value, bool) or not isinstance(value, (int, float)):
                    raise RaError("RA_SNAPSHOT_CORRUPT", "bad rate value")
                values.append(float(value))
            rate[port] = deque(values)
        for port in ports:
            rate.setdefault(port, deque())

        raw_times = snapshot.get("violation_times", {})
        raw_logs = snapshot.get("violations", {})
        if not isinstance(raw_times, dict) or not isinstance(raw_logs, dict):
            raise RaError("RA_SNAPSHOT_CORRUPT", "bad violations")
        violation_times = {}
        violations = {}
        for port in ports:
            times = raw_times.get(port, [])
            logs = raw_logs.get(port, [])
            if not isinstance(times, (list, tuple)) or not isinstance(logs, list):
                raise RaError("RA_SNAPSHOT_CORRUPT", "bad violation records")
            normalized_times = []
            for value in times:
                if isinstance(value, bool) or not isinstance(value, (int, float)):
                    raise RaError("RA_SNAPSHOT_CORRUPT", "bad violation time")
                normalized_times.append(float(value))
            normalized_logs = []
            for item in logs:
                if not isinstance(item, dict) or "code" not in item:
                    raise RaError("RA_SNAPSHOT_CORRUPT", "bad violation entry")
                normalized_logs.append(copy.deepcopy(item))
            violation_times[port] = deque(normalized_times)
            violations[port] = normalized_logs

        raw_quarantine = snapshot.get("quarantine_until", {})
        if not isinstance(raw_quarantine, dict):
            raise RaError("RA_SNAPSHOT_CORRUPT", "bad quarantine table")
        quarantine = {}
        for port, deadline in raw_quarantine.items():
            if port not in ports:
                raise RaError("RA_SNAPSHOT_CORRUPT", "quarantine for unknown port")
            if isinstance(deadline, bool) or not isinstance(deadline, (int, float)):
                raise RaError("RA_SNAPSHOT_CORRUPT", "bad quarantine deadline")
            quarantine[port] = float(deadline)

        raw_stats = snapshot.get("stats", {})
        if not isinstance(raw_stats, dict):
            raise RaError("RA_SNAPSHOT_CORRUPT", "bad stats")
        stats = {}
        for port in ports:
            entry = raw_stats.get(port, {})
            if not isinstance(entry, dict):
                raise RaError("RA_SNAPSHOT_CORRUPT", "bad stats entry")
            complete = self._new_stats()
            for key in complete:
                value = entry.get(key, 0)
                if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                    raise RaError("RA_SNAPSHOT_CORRUPT", "bad stats counter")
                complete[key] = value
            stats[port] = complete

        last_now = snapshot.get("last_now")
        if last_now is not None:
            if isinstance(last_now, bool) or not isinstance(last_now, (int, float)):
                raise RaError("RA_SNAPSHOT_CORRUPT", "bad clock")
            last_now = float(last_now)

        return {
            "ports": ports,
            "prefixes": prefixes,
            "rate": rate,
            "violation_times": violation_times,
            "violations": violations,
            "quarantine_until": quarantine,
            "stats": stats,
            "last_now": last_now,
            "policy": policy,
        }
