"""Certificate Transparency SCT policy guard.

Log registration, SCT issuance, policy verification and list codec all share
the same in-memory state guarded by a single re-entrant lock.
"""

import base64
import binascii
import hashlib
import hmac
import json
import threading


DAY_SECONDS = 86400
VALID_STATUSES = ("usable", "readonly", "retired", "disabled")


class SctError(ValueError):
    """Raised for policy rejections and malformed SCT containers."""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class SctGuard:
    """Log registry, SCT issuance accounting and certificate policy checks."""

    def __init__(self, *, now=0, max_scts=16, max_list_bytes=4096):
        self.now = now
        self.max_scts = max_scts
        self.max_list_bytes = max_list_bytes
        self._logs = {}
        self._stats = {
            "logs": 0,
            "usable": 0,
            "issued": 0,
            "verified": 0,
            "passed": 0,
            "failed": 0,
        }
        self._audit = []
        self._lock = threading.RLock()

    def _current_now(self, now):
        return self.now if now is None else now

    def _sign(self, log, cert_fingerprint, timestamp):
        message = "{}|{}|{}".format(
            log["log_id"], cert_fingerprint, timestamp
        ).encode("utf-8")
        return hmac.new(
            log["key"].encode("utf-8"), message, hashlib.sha256
        ).hexdigest()

    def add_log(self, log_id, *, operator, key, not_after=None,
                status="usable", quota=0) -> dict:
        if status not in VALID_STATUSES:
            raise SctError("SCT_BAD_STATUS", {"status": status})
        with self._lock:
            if log_id in self._logs:
                raise SctError("SCT_LOG_EXISTS", {"log_id": log_id})
            record = {
                "log_id": log_id,
                "operator": operator,
                "key": key,
                "not_after": not_after,
                "status": status,
                "quota": quota,
                "issued": 0,
            }
            self._logs[log_id] = record
            self._stats["logs"] = len(self._logs)
            self._stats["usable"] = sum(
                1 for log in self._logs.values()
                if log["status"] == "usable"
            )
            return dict(record)

    def set_log_status(self, log_id, status) -> dict:
        if status not in VALID_STATUSES:
            raise SctError("SCT_BAD_STATUS", {"status": status})
        with self._lock:
            log = self._logs.get(log_id)
            if log is None:
                raise SctError("SCT_UNKNOWN_LOG", {"log_id": log_id})
            log["status"] = status
            self._stats["usable"] = sum(
                1 for entry in self._logs.values()
                if entry["status"] == "usable"
            )
            return {"log_id": log_id, "status": status}

    def submit(self, log_id, cert_fingerprint, *, now=None) -> dict:
        timestamp = self._current_now(now)
        with self._lock:
            log = self._logs.get(log_id)
            if log is None:
                raise SctError("SCT_UNKNOWN_LOG", {"log_id": log_id})
            if log["status"] in ("retired", "disabled"):
                raise SctError(
                    "SCT_LOG_UNAVAILABLE",
                    {"log_id": log_id, "status": log["status"]},
                )
            quota = log["quota"]
            if quota and log["issued"] >= quota:
                raise SctError(
                    "SCT_QUOTA",
                    {"log_id": log_id, "quota": quota, "issued": log["issued"]},
                )
            signature = self._sign(log, cert_fingerprint, timestamp)
            log["issued"] += 1
            self._stats["issued"] += 1
            return {
                "log_id": log_id,
                "operator": log["operator"],
                "timestamp": timestamp,
                "signature": signature,
            }

    def required_count(self, cert) -> int:
        duration = cert["not_after"] - cert["not_before"]
        days = (duration + DAY_SECONDS - 1) // DAY_SECONDS
        if days <= 90:
            return 1
        if days <= 180:
            return 2
        return 3

    def verify(self, cert, scts, *, now=None) -> dict:
        timestamp_now = self._current_now(now)
        required = self.required_count(cert)
        if not scts:
            verdict = {
                "valid": False,
                "code": "SCT_EMPTY_LIST",
                "required": required,
                "accepted": [],
                "rejected": [],
                "operators": [],
            }
        else:
            unique = []
            seen = set()
            for sct in scts:
                identity = (sct["log_id"], sct["timestamp"])
                if identity in seen:
                    continue
                seen.add(identity)
                unique.append(sct)
            if len(unique) > self.max_scts:
                verdict = {
                    "valid": False,
                    "code": "SCT_TOO_MANY",
                    "required": required,
                    "accepted": [],
                    "rejected": [],
                    "operators": [],
                }
            else:
                accepted = []
                rejected = []
                operators = set()
                for sct in unique:
                    log_id = sct["log_id"]
                    timestamp = sct["timestamp"]

                    log = self._logs.get(log_id)
                    if log is None:
                        code = "SCT_UNKNOWN_LOG"
                    elif log["status"] == "retired":
                        code = "SCT_LOG_RETIRED"
                    elif log["status"] == "disabled":
                        code = "SCT_LOG_DISABLED"
                    else:
                        expected = self._sign(
                            log, cert["fingerprint"], timestamp
                        )
                        if not hmac.compare_digest(
                                expected, sct["signature"]):
                            code = "SCT_BAD_SIGNATURE"
                        elif timestamp > timestamp_now:
                            code = "SCT_FUTURE_TIMESTAMP"
                        elif (timestamp < cert["not_before"]
                              or timestamp > cert["not_after"]):
                            code = "SCT_OUTSIDE_VALIDITY"
                        else:
                            code = None

                    if code is None:
                        accepted.append(sct)
                        operators.add(log["operator"])
                    else:
                        rejected.append(dict(sct, code=code))

                operator_names = sorted(operators)
                if len(operator_names) >= required:
                    code = None
                    valid = True
                elif accepted:
                    code = "SCT_INSUFFICIENT"
                    valid = False
                else:
                    code = rejected[0]["code"]
                    valid = False
                verdict = {
                    "valid": valid,
                    "code": code,
                    "required": required,
                    "accepted": accepted,
                    "rejected": rejected,
                    "operators": operator_names,
                }

        with self._lock:
            self._stats["verified"] += 1
            if verdict["valid"]:
                self._stats["passed"] += 1
            else:
                self._stats["failed"] += 1
            self._audit.append({
                "fingerprint": str(cert["fingerprint"])[:8],
                "valid": verdict["valid"],
                "code": verdict["code"],
            })
        return verdict

    def require(self, cert, scts, *, now=None) -> dict:
        verdict = self.verify(cert, scts, now=now)
        if verdict["valid"]:
            return verdict
        raise SctError(verdict["code"], verdict)

    def pack(self, scts) -> str:
        triples = []
        seen = set()
        for sct in scts:
            triple = (sct["log_id"], sct["timestamp"], sct["signature"])
            if triple in seen:
                continue
            seen.add(triple)
            triples.append(list(triple))
        if len(triples) > self.max_scts:
            raise SctError(
                "SCT_TOO_MANY",
                {"count": len(triples), "max_scts": self.max_scts},
            )
        payload = json.dumps(triples, separators=(",", ":")).encode("utf-8")
        blob = base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")
        if len(blob) > self.max_list_bytes:
            raise SctError(
                "SCT_SIZE_LIMIT",
                {"size": len(blob), "max_list_bytes": self.max_list_bytes},
            )
        return blob

    def unpack(self, blob) -> list:
        if len(blob) > self.max_list_bytes:
            raise SctError(
                "SCT_SIZE_LIMIT",
                {"size": len(blob), "max_list_bytes": self.max_list_bytes},
            )
        padding = "=" * (-len(blob) % 4)
        try:
            raw = base64.b64decode(
                (blob + padding).encode("ascii"), altchars=b"-_",
                validate=True,
            )
            payload = json.loads(raw.decode("utf-8"))
        except (binascii.Error, ValueError, UnicodeDecodeError):
            raise SctError("SCT_MALFORMED_LIST", {"blob": blob})
        if not isinstance(payload, list):
            raise SctError("SCT_MALFORMED_LIST", {"reason": "not-a-list"})
        scts = []
        for element in payload:
            if not isinstance(element, (list, tuple)) or len(element) != 3:
                raise SctError(
                    "SCT_MALFORMED_LIST", {"reason": "bad-element-shape"}
                )
            log_id, timestamp, signature = element
            if (not isinstance(log_id, str)
                    or isinstance(timestamp, bool)
                    or not isinstance(timestamp, int)
                    or not isinstance(signature, str)):
                raise SctError(
                    "SCT_MALFORMED_LIST", {"reason": "bad-element-type"}
                )
            scts.append({
                "log_id": log_id,
                "timestamp": timestamp,
                "signature": signature,
            })
        return scts

    def sweep(self, *, now=None) -> int:
        cutoff = self._current_now(now)
        count = 0
        with self._lock:
            for log in self._logs.values():
                if (log["not_after"] is not None
                        and log["not_after"] <= cutoff
                        and log["status"] != "retired"):
                    log["status"] = "retired"
                    count += 1
            self._stats["usable"] = sum(
                1 for entry in self._logs.values()
                if entry["status"] == "usable"
            )
        return count

    def stats(self) -> dict:
        with self._lock:
            stats = dict(self._stats)
            stats["logs"] = len(self._logs)
            stats["usable"] = sum(
                1 for log in self._logs.values()
                if log["status"] == "usable"
            )
            stats["issued"] = sum(log["issued"] for log in self._logs.values())
            return stats

    def audit_log(self) -> list:
        with self._lock:
            return [dict(entry) for entry in self._audit]

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "config": {
                    "now": self.now,
                    "max_scts": self.max_scts,
                    "max_list_bytes": self.max_list_bytes,
                },
                "logs": {
                    log_id: dict(record)
                    for log_id, record in self._logs.items()
                },
                "stats": dict(self._stats),
                "audit": [dict(entry) for entry in self._audit],
            }

    @classmethod
    def restore(cls, state) -> "SctGuard":
        config = state.get("config", {})
        guard = cls(
            now=config.get("now", 0),
            max_scts=config.get("max_scts", 16),
            max_list_bytes=config.get("max_list_bytes", 4096),
        )
        with guard._lock:
            guard._logs = {
                log_id: dict(record)
                for log_id, record in state.get("logs", {}).items()
            }
            guard._stats = dict(guard._stats)
            guard._stats.update(state.get("stats", {}))
            guard._audit = [dict(entry) for entry in state.get("audit", [])]
        return guard
