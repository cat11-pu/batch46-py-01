"""Cross-server character transfer guard (batch46-game-b-04)."""

import copy
import json
import threading
from datetime import datetime, timezone


class TransferError(ValueError):
    """Raised when a transfer request violates a hard rule."""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = dict(detail or {})


class CrossServerTransfer:
    """Two-phase transfer ledger with quotas, TTL, snapshots and history."""

    def __init__(self, *, max_pending=20, quota_per_source=5, ttl_seconds=600,
                 payload_limit=65536, history_limit=50):
        self.max_pending = max_pending
        self.quota_per_source = quota_per_source
        self.ttl_seconds = ttl_seconds
        self.payload_limit = payload_limit
        self.history_limit = history_limit
        self._servers = {}
        self._transfers = {}
        self._home = {}
        self._log = []
        self._lock = threading.RLock()

    @staticmethod
    def _public_server(record):
        row = dict(record)
        row["remaining"] = max(0, row["capacity"] - row["used"])
        return row

    def _public_transfer(self, record):
        row = dict(record)
        row.pop("_payload", None)
        return copy.deepcopy(row)

    @staticmethod
    def _parse_timestamp(value):
        if isinstance(value, datetime):
            parsed = value
        else:
            text = str(value).strip()
            if text.endswith(("Z", "z")):
                text = text[:-1] + "+00:00"
            parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    def _payload_size(self, payload):
        try:
            encoded = json.dumps(
                payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                default=str,
            ).encode("utf-8")
        except (TypeError, ValueError):
            encoded = repr(payload).encode("utf-8")
        return len(encoded)

    def _require_server(self, server):
        try:
            return self._servers[server]
        except KeyError:
            raise TransferError(
                "TRF_UNKNOWN_SERVER", {"server": server}
            ) from None

    def _require_transfer(self, transfer_id):
        try:
            return self._transfers[transfer_id]
        except KeyError:
            raise TransferError(
                "TRF_UNKNOWN_TRANSFER", {"transfer_id": transfer_id}
            ) from None

    def _pending_for_source(self, server):
        return sum(
            1
            for record in self._transfers.values()
            if record["status"] == "pending" and record["source"] == server
        )

    def _pending_total(self):
        return sum(
            1
            for record in self._transfers.values()
            if record["status"] == "pending"
        )

    def _record_audit(self, action, record, **extra):
        event = {
            "action": action,
            "transfer_id": record["transfer_id"],
            "account": record["account"],
            "source": record["source"],
            "target": record["target"],
        }
        event.update(extra)
        self._log.append(event)
        if self.history_limit <= 0:
            self._log.clear()
        elif len(self._log) > self.history_limit:
            del self._log[:len(self._log) - self.history_limit]

    def register_server(self, server, *, capacity=1000, used=0):
        if not isinstance(capacity, int) or isinstance(capacity, bool) or capacity < 0:
            raise TransferError(
                "TRF_INVALID_CAPACITY",
                {"server": server, "capacity": capacity},
            )
        if not isinstance(used, int) or isinstance(used, bool) or used < 0:
            raise TransferError(
                "TRF_INVALID_USED", {"server": server, "used": used}
            )
        if used > capacity:
            raise TransferError(
                "TRF_INVALID_CAPACITY",
                {"server": server, "capacity": capacity, "used": used},
            )
        with self._lock:
            self._servers[server] = {"server": server, "capacity": capacity,
                                     "used": used}
            return self._public_server(self._servers[server])

    def servers(self):
        with self._lock:
            return [
                self._public_server(self._servers[name])
                for name in sorted(self._servers)
            ]

    def begin(self, transfer_id, *, account, character=None, source, target,
              payload, created_at):
        with self._lock:
            if transfer_id in self._transfers:
                record = self._public_transfer(self._transfers[transfer_id])
                record["existing_status"] = record["status"]
                record["status"] = "existing"
                return record

            self._require_server(source)
            self._require_server(target)
            if source == target:
                raise TransferError(
                    "TRF_SAME_SERVER",
                    {"server": source, "source": source, "target": target},
                )

            size = self._payload_size(payload)
            if size > self.payload_limit:
                raise TransferError(
                    "TRF_PAYLOAD_TOO_LARGE",
                    {"size": size, "limit": self.payload_limit},
                )

            for record in self._transfers.values():
                if record["status"] == "pending" and record["account"] == account:
                    raise TransferError(
                        "TRF_PENDING_CONFLICT",
                        {"account": account,
                         "transfer_id": record["transfer_id"]},
                    )

            source_pending = self._pending_for_source(source)
            if source_pending >= self.quota_per_source:
                raise TransferError(
                    "TRF_QUOTA_EXCEEDED",
                    {"server": source, "pending": source_pending,
                     "limit": self.quota_per_source},
                )

            total_pending = self._pending_total()
            if total_pending >= self.max_pending:
                raise TransferError(
                    "TRF_QUEUE_FULL",
                    {"pending": total_pending, "limit": self.max_pending},
                )

            self._parse_timestamp(created_at)
            record = {
                "transfer_id": transfer_id,
                "account": account,
                "character": character,
                "source": source,
                "target": target,
                "payload_size": size,
                "created_at": created_at,
                "status": "pending",
                "_payload": copy.deepcopy(payload),
            }
            self._transfers[transfer_id] = record
            self._home[account] = source
            return self._public_transfer(record)

    def commit(self, transfer_id):
        with self._lock:
            record = self._require_transfer(transfer_id)
            if record["status"] == "committed":
                raise TransferError(
                    "TRF_ALREADY_COMMITTED", {"transfer_id": transfer_id}
                )
            if record["status"] != "pending":
                raise TransferError(
                    "TRF_NOT_PENDING",
                    {"transfer_id": transfer_id, "status": record["status"]},
                )

            target = self._servers[record["target"]]
            if target["used"] >= target["capacity"]:
                raise TransferError(
                    "TRF_TARGET_FULL",
                    {"server": record["target"],
                     "capacity": target["capacity"],
                     "used": target["used"]},
                )

            source = self._servers[record["source"]]
            source["used"] = max(0, source["used"] - 1)
            target["used"] += 1
            record["status"] = "committed"
            self._home[record["account"]] = record["target"]
            self._record_audit("commit", record)
            return self._public_transfer(record)

    def rollback(self, transfer_id, *, reason="manual"):
        with self._lock:
            record = self._require_transfer(transfer_id)
            if record["status"] != "pending":
                raise TransferError(
                    "TRF_NOT_PENDING",
                    {"transfer_id": transfer_id, "status": record["status"]},
                )
            record["status"] = "rolled_back"
            self._home[record["account"]] = record["source"]
            self._record_audit("rollback", record, reason=reason)
            return self._public_transfer(record)

    def status(self, transfer_id):
        with self._lock:
            return self._public_transfer(self._require_transfer(transfer_id))

    def pending(self, server=None):
        with self._lock:
            return [
                self._public_transfer(record)
                for record in self._transfers.values()
                if record["status"] == "pending"
                and (server is None or record["source"] == server)
            ]

    def expire(self, now):
        with self._lock:
            now_dt = self._parse_timestamp(now)
            expired = []
            for record in self._transfers.values():
                if record["status"] != "pending":
                    continue
                created = self._parse_timestamp(record["created_at"])
                if (now_dt - created).total_seconds() >= self.ttl_seconds:
                    record["status"] = "expired"
                    self._home[record["account"]] = record["source"]
                    self._record_audit("expire", record, at=now)
                    expired.append(record["transfer_id"])
            return expired

    def snapshot(self):
        with self._lock:
            return {
                "format": 1,
                "servers": copy.deepcopy(self._servers),
                "transfers": copy.deepcopy(self._transfers),
                "home": copy.deepcopy(self._home),
                "log": copy.deepcopy(self._log),
            }

    def restore(self, snapshot):
        with self._lock:
            if isinstance(snapshot, str):
                snapshot = json.loads(snapshot)
            if not isinstance(snapshot, dict):
                raise TransferError(
                    "TRF_INVALID_SNAPSHOT", {"snapshot": type(snapshot).__name__}
                )
            self._servers = copy.deepcopy(snapshot.get("servers", {}))
            self._transfers = copy.deepcopy(snapshot.get("transfers", {}))
            self._home = copy.deepcopy(snapshot.get("home", {}))
            self._log = copy.deepcopy(snapshot.get("log", []))
            return {"status": "restored"}

    def account_home(self, account):
        with self._lock:
            return self._home.get(account)

    def history(self, account, limit=10):
        with self._lock:
            rows = [event for event in self._log if event["account"] == account]
            rows.reverse()
            if limit is None:
                return copy.deepcopy(rows)
            return copy.deepcopy(rows[:max(0, limit)])

    def audit(self, limit=10):
        with self._lock:
            rows = list(reversed(self._log))
            if limit is None:
                return copy.deepcopy(rows)
            return copy.deepcopy(rows[:max(0, limit)])

    def quota(self, server):
        with self._lock:
            self._require_server(server)
            pending = self._pending_for_source(server)
            global_pending = self._pending_total()
            return {
                "server": server,
                "pending": pending,
                "limit": self.quota_per_source,
                "remaining": max(0, self.quota_per_source - pending),
                "global_pending": global_pending,
                "global_remaining": max(0, self.max_pending - global_pending),
            }

    def metrics(self):
        with self._lock:
            counts = {
                "pending": 0,
                "committed": 0,
                "rolled_back": 0,
                "expired": 0,
            }
            for record in self._transfers.values():
                counts[record["status"]] += 1
            counts["servers"] = len(self._servers)
            counts["transfers"] = len(self._transfers)
            return counts
