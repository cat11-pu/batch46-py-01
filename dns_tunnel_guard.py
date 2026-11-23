"""DNS tunnel traffic detector."""

from __future__ import annotations

import copy
import re
import threading
import time

SNAPSHOT_VERSION = 1
SUSPICIOUS_QTYPES = ("TXT", "NULL")
DEFAULT_SUFFIXES = ("com", "net", "org", "io", "co.uk")
REASONS = ("LONG_LABEL", "SUSPICIOUS_QTYPE", "HIGH_UNIQUE", "LARGE_RESPONSE")

_LABEL_RE = re.compile(r"^[a-z0-9_-]+$")


class DnsTunnelError(ValueError):
    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class DnsTunnelGuard:
    """Allowlist, per-client sliding window, scoring, blocking and snapshots."""

    def __init__(self, *, window: int = 60, unique_threshold: int = 20,
                 label_threshold: int = 30, max_events: int = 500,
                 block_seconds: int = 300, max_alerts: int = 200,
                 public_suffixes: tuple = DEFAULT_SUFFIXES) -> None:
        if not isinstance(window, int) or isinstance(window, bool) or window <= 0:
            raise DnsTunnelError("DNS_BAD_CONFIG", "window")
        if (not isinstance(unique_threshold, int)
                or isinstance(unique_threshold, bool)
                or unique_threshold <= 0):
            raise DnsTunnelError("DNS_BAD_CONFIG", "unique_threshold")
        if (not isinstance(label_threshold, int)
                or isinstance(label_threshold, bool)
                or label_threshold < 0):
            raise DnsTunnelError("DNS_BAD_CONFIG", "label_threshold")
        if (not isinstance(max_events, int) or isinstance(max_events, bool)
                or max_events <= 0):
            raise DnsTunnelError("DNS_BAD_CONFIG", "max_events")
        if (not isinstance(block_seconds, int)
                or isinstance(block_seconds, bool)
                or block_seconds <= 0):
            raise DnsTunnelError("DNS_BAD_CONFIG", "block_seconds")
        if (not isinstance(max_alerts, int) or isinstance(max_alerts, bool)
                or max_alerts < 0):
            raise DnsTunnelError("DNS_BAD_CONFIG", "max_alerts")
        if not isinstance(public_suffixes, (tuple, list)):
            raise DnsTunnelError("DNS_BAD_CONFIG", "public_suffixes")

        suffixes = []
        for suffix in public_suffixes:
            if not isinstance(suffix, str):
                raise DnsTunnelError("DNS_BAD_CONFIG", "public_suffixes")
            normalized = suffix.lower().rstrip(".")
            if not normalized:
                raise DnsTunnelError("DNS_BAD_CONFIG", "public_suffixes")
            suffixes.append(normalized)

        self.window = window
        self.unique_threshold = unique_threshold
        self.label_threshold = label_threshold
        self.max_events = max_events
        self.block_seconds = block_seconds
        self.max_alerts = max_alerts
        self.public_suffixes = tuple(suffixes)
        self._lock = threading.RLock()
        self._allowlist = {}
        self._clients = {}
        self._alerts = []
        self._blocked = {}

    @staticmethod
    def _clock() -> float:
        return time.time()

    @staticmethod
    def _normalize(name: str) -> str:
        return name.lower().rstrip(".")

    @classmethod
    def _valid_name(cls, name: str) -> bool:
        if not isinstance(name, str) or not name or len(name) > 253:
            return False
        labels = name.split(".")
        if len(labels) < 2:
            return False
        for label in labels:
            if not (1 <= len(label) <= 63):
                return False
            if _LABEL_RE.fullmatch(label) is None:
                return False
        return True

    def _base_domain(self, qname: str) -> str:
        labels = qname.split(".")
        best = None
        best_labels = 0
        for suffix in self.public_suffixes:
            suffix_labels = suffix.split(".")
            count = len(suffix_labels)
            if count <= best_labels:
                continue
            if qname == suffix or qname.endswith("." + suffix):
                best = suffix
                best_labels = count
        if best is not None and len(labels) > best_labels:
            return ".".join(labels[-(best_labels + 1):])
        if len(labels) >= 2:
            return ".".join(labels[-2:])
        return qname

    def allow_domain(self, domain: str, *, note: str = "") -> dict:
        with self._lock:
            if not isinstance(domain, str):
                raise DnsTunnelError("DNS_BAD_DOMAIN", domain)
            normalized = self._normalize(domain)
            if not self._valid_name(normalized):
                raise DnsTunnelError("DNS_BAD_DOMAIN", domain)
            if normalized in self._allowlist:
                return {
                    "domain": normalized,
                    "note": self._allowlist[normalized],
                    "status": "unchanged",
                }
            self._allowlist[normalized] = note
            return {"domain": normalized, "note": note, "status": "allowed"}

    def revoke_domain(self, domain: str) -> None:
        with self._lock:
            if not isinstance(domain, str):
                raise DnsTunnelError("DNS_UNKNOWN_DOMAIN", domain)
            normalized = self._normalize(domain)
            if normalized not in self._allowlist:
                raise DnsTunnelError("DNS_UNKNOWN_DOMAIN", normalized)
            del self._allowlist[normalized]

    def base_domain(self, qname: str) -> str:
        if not isinstance(qname, str):
            return ""
        normalized = self._normalize(qname)
        if not normalized:
            return ""
        return self._base_domain(normalized)

    def _is_allowlisted(self, qname: str) -> bool:
        for domain in self._allowlist:
            if qname == domain or qname.endswith("." + domain):
                return True
        return False

    def _prune_events(self, events: list, now: float) -> None:
        cutoff = now - self.window
        while events and events[0]["ts"] <= cutoff:
            events.pop(0)

    def _client_record(self, client: str) -> dict:
        record = self._clients.get(client)
        if record is None:
            record = {"events": []}
            self._clients[client] = record
        return record

    def _result(self, client: str, qname: object, action: str, code: str,
                score: int = 0, reasons: list | None = None,
                ts: object = None) -> dict:
        return {
            "client": client,
            "qname": qname,
            "action": action,
            "code": code,
            "score": score,
            "reasons": [] if reasons is None else reasons,
            "ts": ts,
        }

    def _blocked_until(self, client: str, now: float) -> object:
        until = self._blocked.get(client)
        if until is None:
            return 0
        if until <= now:
            del self._blocked[client]
            return 0
        return until

    def _append_alert(self, client: str, qname: str, score: int,
                      reasons: list, ts: object, action: str) -> None:
        self._alerts.append({
            "client": client,
            "qname": qname,
            "score": score,
            "reasons": list(reasons),
            "ts": ts,
            "action": action,
        })
        if len(self._alerts) > self.max_alerts:
            del self._alerts[:len(self._alerts) - self.max_alerts]

    def ingest(self, event: dict, *, now: int | None = None) -> dict:
        with self._lock:
            if not isinstance(event, dict):
                return self._result("", None, "drop", "DNS_BAD_QNAME")

            client = event.get("client")
            if not isinstance(client, str) or not client.strip():
                raise DnsTunnelError("DNS_BAD_CLIENT", client)

            raw_ts = event.get("ts")
            if now is None:
                current_now = raw_ts if isinstance(raw_ts, (int, float)) \
                    and not isinstance(raw_ts, bool) else self._clock()
            else:
                current_now = now

            until = self._blocked_until(client, current_now)
            if until:
                return self._result(
                    client, event.get("qname"), "block", "DNS_CLIENT_BLOCKED",
                    ts=raw_ts,
                )

            qname = event.get("qname")
            if not isinstance(qname, str):
                return self._result(client, qname, "drop", "DNS_BAD_QNAME",
                                    ts=raw_ts)
            normalized = self._normalize(qname)
            if not self._valid_name(normalized):
                return self._result(client, normalized, "drop", "DNS_BAD_QNAME",
                                    ts=raw_ts)

            if self._is_allowlisted(normalized):
                return self._result(
                    client, normalized, "allow", "DNS_ALLOWLISTED", ts=raw_ts,
                )

            if event.get("rcode", 0) != 0:
                return self._result(
                    client, normalized, "allow", "DNS_RCODE_IGNORED",
                    ts=raw_ts,
                )
            if event.get("truncated", False):
                return self._result(
                    client, normalized, "allow", "DNS_TRUNCATED", ts=raw_ts,
                )

            event_ts = current_now

            qtype = event.get("qtype", "")
            if not isinstance(qtype, str):
                qtype = str(qtype)
            qtype = qtype.upper()

            size = event.get("size", 0)
            if not isinstance(size, (int, float)) or isinstance(size, bool):
                size = 0

            base = self._base_domain(normalized)
            record = self._client_record(client)
            events = record["events"]
            events.append({
                "client": client,
                "qname": normalized,
                "base_domain": base,
                "qtype": qtype,
                "size": size,
                "ts": event_ts,
            })
            events.sort(key=lambda item: item["ts"])
            self._prune_events(events, current_now)
            if len(events) > self.max_events:
                del events[:len(events) - self.max_events]

            reasons = []
            score = 0
            labels = normalized.split(".")
            if any(len(label) > self.label_threshold for label in labels):
                reasons.append("LONG_LABEL")
                score += 40
            if qtype in SUSPICIOUS_QTYPES:
                reasons.append("SUSPICIOUS_QTYPE")
                score += 25
            unique_for_base = len({
                item["qname"] for item in events
                if item["base_domain"] == base
            })
            if unique_for_base >= self.unique_threshold:
                reasons.append("HIGH_UNIQUE")
                score += 25
            if size >= 400:
                reasons.append("LARGE_RESPONSE")
                score += 10
            score = min(score, 100)

            if score >= 80:
                action = "block"
                code = "DNS_BLOCKED"
                self._blocked[client] = current_now + self.block_seconds
                self._append_alert(client, normalized, score, reasons,
                                   event_ts, action)
            elif score >= 40:
                action = "alert"
                code = "DNS_ALERT"
                self._append_alert(client, normalized, score, reasons,
                                   event_ts, action)
            else:
                action = "allow"
                code = "DNS_ALLOWED"

            return self._result(
                client, normalized, action, code, score, reasons, event_ts,
            )

    def ingest_batch(self, events: list, *, now: int | None = None) -> list:
        with self._lock:
            if not isinstance(events, list):
                raise DnsTunnelError("DNS_BAD_EVENT", "events")
            ordered = sorted(
                enumerate(events),
                key=lambda item: (
                    item[1].get("ts", 0)
                    if isinstance(item[1], dict)
                    and isinstance(item[1].get("ts", 0), (int, float))
                    and not isinstance(item[1].get("ts", 0), bool)
                    else 0
                ),
            )
            return [self.ingest(event, now=now) for _, event in ordered]

    def client_state(self, client: str, *, now: int | None = None) -> dict:
        with self._lock:
            current_now = self._clock() if now is None else now
            record = self._clients.get(client)
            if record is None:
                events = []
            else:
                events = record["events"]
                self._prune_events(events, current_now)
            unique = len({item["qname"] for item in events})
            base_domains = sorted({item["base_domain"] for item in events})
            recent = [item["qname"] for item in events]
            return {
                "events": len(events),
                "unique": unique,
                "base_domains": base_domains,
                "recent": recent,
                "blocked_until": self._blocked_until(client, current_now),
            }

    def alerts(self, *, client: str | None = None,
               limit: int | None = None) -> list:
        with self._lock:
            rows = [
                row for row in self._alerts
                if client is None or row["client"] == client
            ]
            rows.sort(key=lambda row: row["ts"])
            if limit is not None:
                if limit <= 0:
                    return []
                rows = rows[-limit:]
            return copy.deepcopy(rows)

    def block_client(self, client: str, seconds: int, *,
                     now: int | None = None) -> dict:
        with self._lock:
            if not isinstance(client, str) or not client.strip():
                raise DnsTunnelError("DNS_BAD_CLIENT", client)
            if (not isinstance(seconds, int) or isinstance(seconds, bool)
                    or seconds <= 0):
                raise DnsTunnelError("DNS_BAD_BLOCK", seconds)
            current_now = self._clock() if now is None else now
            until = current_now + seconds
            self._blocked[client] = until
            return {"client": client, "until": until, "status": "blocked"}

    def unblock_client(self, client: str) -> dict:
        with self._lock:
            self._blocked.pop(client, None)
            return {"client": client, "status": "unblocked"}

    def blocked(self, *, now: int | None = None) -> list:
        with self._lock:
            current_now = self._clock() if now is None else now
            expired = [
                client for client, until in self._blocked.items()
                if until <= current_now
            ]
            for client in expired:
                del self._blocked[client]
            return sorted(self._blocked)

    def expire(self, now: int) -> list:
        with self._lock:
            expired = sorted(
                client for client, until in self._blocked.items()
                if until <= now
            )
            for client in expired:
                del self._blocked[client]

            for client in list(self._clients):
                events = self._clients[client]["events"]
                self._prune_events(events, now)
                if not events and client not in self._blocked:
                    del self._clients[client]
            return expired

    def snapshot(self) -> dict:
        with self._lock:
            clients = {}
            for client in sorted(set(self._clients) | set(self._blocked)):
                record = self._clients.get(client)
                events = [] if record is None else record["events"]
                clients[client] = {
                    "events": copy.deepcopy(events),
                    "blocked_until": self._blocked.get(client, 0),
                }
            return {
                "version": SNAPSHOT_VERSION,
                "allowlist": copy.deepcopy(self._allowlist),
                "clients": clients,
                "alerts": copy.deepcopy(self._alerts),
            }

    @staticmethod
    def _corrupt(detail: object = None) -> DnsTunnelError:
        return DnsTunnelError("DNS_SNAPSHOT_CORRUPT", detail)

    def restore(self, snapshot: dict) -> None:
        with self._lock:
            if not isinstance(snapshot, dict):
                raise self._corrupt("snapshot")
            version = snapshot.get("version")
            if (not isinstance(version, int) or isinstance(version, bool)
                    or version != SNAPSHOT_VERSION):
                raise self._corrupt("version")

            allowlist_in = snapshot.get("allowlist")
            clients_in = snapshot.get("clients")
            alerts_in = snapshot.get("alerts")
            if not isinstance(allowlist_in, dict):
                raise self._corrupt("allowlist")
            if not isinstance(clients_in, dict):
                raise self._corrupt("clients")
            if not isinstance(alerts_in, list):
                raise self._corrupt("alerts")

            new_allowlist = {}
            for domain, note in allowlist_in.items():
                if not isinstance(domain, str) or not isinstance(note, str):
                    raise self._corrupt("allowlist")
                normalized = self._normalize(domain)
                if normalized != domain or not self._valid_name(normalized):
                    raise self._corrupt("allowlist")
                new_allowlist[normalized] = note

            new_clients = {}
            new_blocked = {}
            for client, record in clients_in.items():
                if not isinstance(client, str) or not client.strip():
                    raise self._corrupt("client")
                if not isinstance(record, dict):
                    raise self._corrupt("client")
                events_in = record.get("events")
                if not isinstance(events_in, list):
                    raise self._corrupt("events")
                until = record.get("blocked_until", 0)
                if until is None:
                    until = 0
                if (not isinstance(until, (int, float))
                        or isinstance(until, bool) or until < 0):
                    raise self._corrupt("blocked_until")

                events = []
                for item in events_in:
                    if not isinstance(item, dict):
                        raise self._corrupt("event")
                    qname = item.get("qname")
                    ts = item.get("ts")
                    if not isinstance(qname, str):
                        raise self._corrupt("event")
                    qname = self._normalize(qname)
                    if not self._valid_name(qname):
                        raise self._corrupt("event")
                    if (not isinstance(ts, (int, float))
                            or isinstance(ts, bool)):
                        raise self._corrupt("event")
                    qtype = item.get("qtype", "")
                    if not isinstance(qtype, str):
                        raise self._corrupt("event")
                    size = item.get("size", 0)
                    if (not isinstance(size, (int, float))
                            or isinstance(size, bool)):
                        raise self._corrupt("event")
                    base = item.get("base_domain")
                    if base is None:
                        base = self._base_domain(qname)
                    if not isinstance(base, str):
                        raise self._corrupt("event")
                    events.append({
                        "client": client,
                        "qname": qname,
                        "base_domain": base,
                        "qtype": qtype,
                        "size": size,
                        "ts": ts,
                    })
                events.sort(key=lambda item: item["ts"])
                if len(events) > self.max_events:
                    del events[:len(events) - self.max_events]

                if events or until:
                    new_clients[client] = {"events": events}
                if until:
                    new_blocked[client] = until

            new_alerts = []
            for item in alerts_in:
                if not isinstance(item, dict):
                    raise self._corrupt("alert")
                client = item.get("client")
                qname = item.get("qname")
                score = item.get("score")
                reasons = item.get("reasons")
                ts = item.get("ts")
                action = item.get("action")
                if not isinstance(client, str):
                    raise self._corrupt("alert")
                if not isinstance(qname, str):
                    raise self._corrupt("alert")
                if (not isinstance(score, (int, float))
                        or isinstance(score, bool)):
                    raise self._corrupt("alert")
                if not isinstance(reasons, list) or not all(
                        isinstance(reason, str) for reason in reasons):
                    raise self._corrupt("alert")
                if (not isinstance(ts, (int, float))
                        or isinstance(ts, bool)):
                    raise self._corrupt("alert")
                if not isinstance(action, str):
                    raise self._corrupt("alert")
                new_alerts.append({
                    "client": client,
                    "qname": qname,
                    "score": score,
                    "reasons": list(reasons),
                    "ts": ts,
                    "action": action,
                })
            if len(new_alerts) > self.max_alerts:
                del new_alerts[:len(new_alerts) - self.max_alerts]

            self._allowlist = new_allowlist
            self._clients = new_clients
            self._blocked = new_blocked
            self._alerts = new_alerts
