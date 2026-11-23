"""IMA baseline appraisal guard.

The guard keeps per-host baseline digests, requires quorum-approved baseline
changes, supports short-lived signed exceptions, and quarantines hosts after a
run of failed appraisals.
"""

from __future__ import annotations

import copy
import json
import re
import threading
import time
from datetime import datetime, timezone


SNAPSHOT_VERSION = 1

_ALGO_LENGTHS = {
    "sha1": 40,
    "sha256": 64,
    "sha384": 96,
    "sha512": 128,
}

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


class ImaGuardError(ValueError):
    """Error carrying a stable IMA guard error code."""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


ImaError = ImaGuardError
ImaGuardException = ImaGuardError


class _AliasDict(dict):
    """dict that exposes a few harmless aliases without serialising them."""

    _aliases = {}

    def __missing__(self, key):
        alias = self._aliases.get(key)
        if alias is not None and alias in self:
            return self[alias]
        raise KeyError(key)


class _StateView(_AliasDict):
    _aliases = {
        "baselines": "baseline",
        "baseline_count": "baseline",
        "failures": "consecutive_failures",
        "failure_count": "consecutive_failures",
        "last": "last_appraised",
    }


class _StatsView(_AliasDict):
    _aliases = {
        "baseline": "baselines",
        "host": "hosts",
        "proposal": "proposals",
        "exception": "exceptions",
        "quarantine": "quarantined",
    }


def _iso_utc(timestamp):
    return (
        datetime.fromtimestamp(timestamp, timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _parse_time(value):
    if value is None:
        return time.time()
    if isinstance(value, bool):
        raise ImaGuardError("IMA_TIME_INVALID", "boolean is not a timestamp")
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.timestamp()
    if isinstance(value, str):
        text = value.strip()
        if not text:
            raise ImaGuardError("IMA_TIME_INVALID", "empty timestamp")
        try:
            return float(text)
        except ValueError:
            pass
        iso = text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text
        try:
            parsed = datetime.fromisoformat(iso)
        except ValueError as exc:
            raise ImaGuardError("IMA_TIME_INVALID", text) from exc
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    raise ImaGuardError("IMA_TIME_INVALID", repr(value))


def _time_pair(now):
    timestamp = _parse_time(now)
    if now is None:
        display = _iso_utc(timestamp)
    elif isinstance(now, str):
        display = now
    elif isinstance(now, datetime):
        display = now.isoformat()
    else:
        display = _iso_utc(timestamp)
    return timestamp, display


def _validate_path(path):
    if not isinstance(path, str) or not path.startswith("/"):
        raise ImaGuardError("IMA_PATH_INVALID", repr(path))
    return path


def _validate_algo(algo):
    if not isinstance(algo, str) or algo not in _ALGO_LENGTHS:
        raise ImaGuardError("IMA_ALGO_INVALID", repr(algo))
    return algo


def _validate_digest(digest, algo):
    _validate_algo(algo)
    expected = _ALGO_LENGTHS[algo]
    if (
        not isinstance(digest, str)
        or len(digest) != expected
        or _HEX_RE.fullmatch(digest) is None
    ):
        raise ImaGuardError("IMA_DIGEST_INVALID", repr(digest))
    return digest


def _validate_standalone_digest(digest):
    if (
        not isinstance(digest, str)
        or len(digest) not in set(_ALGO_LENGTHS.values())
        or _HEX_RE.fullmatch(digest) is None
    ):
        raise ImaGuardError("IMA_DIGEST_INVALID", repr(digest))
    return digest


class ImaGuard:
    """Baseline appraisal, proposal, exception and quarantine state."""

    def __init__(
        self,
        max_batch=4096,
        quorum=2,
        proposal_ttl_seconds=3600,
        quarantine_after=3,
        audit_capacity=256,
    ):
        self.max_batch = int(max_batch)
        self.quorum = int(quorum)
        self.proposal_ttl_seconds = int(proposal_ttl_seconds)
        self.quarantine_after = int(quarantine_after)
        self.audit_capacity = int(audit_capacity)
        self._lock = threading.RLock()
        self._baselines = {}
        self._proposals = {}
        self._proposal_seq = {}
        self._exceptions = {}
        self._hosts = {}
        self._audit = []

    def _host(self, host, create=False):
        record = self._hosts.get(host)
        if record is None and create:
            record = {
                "consecutive_failures": 0,
                "quarantined": False,
                "last_appraised": None,
                "status": "unknown",
            }
            self._hosts[host] = record
        return record

    def _append_audit(self, action, host=None, at=None, **fields):
        row = {"action": action, "host": host, "at": at}
        row.update(fields)
        self._audit.append(row)
        if self.audit_capacity >= 0:
            overflow = len(self._audit) - self.audit_capacity
            if overflow > 0:
                del self._audit[:overflow]

    def _proposal_view(self, proposal):
        return {
            "id": proposal["id"],
            "host": proposal["host"],
            "changes": copy.deepcopy(proposal["changes"]),
            "proposer": proposal["proposer"],
            "approvals": list(proposal["approvals"]),
            "status": proposal["status"],
            "created_at": proposal["created_at"],
            "expires_at": proposal["expires_at"],
            "applied_at": proposal.get("applied_at"),
        }

    def _get_proposal(self, proposal_id):
        proposal = self._proposals.get(proposal_id)
        if proposal is None:
            raise ImaGuardError("IMA_PROPOSAL_UNKNOWN", proposal_id)
        return proposal

    def _expire_proposal_if_needed(self, proposal, timestamp):
        if (
            proposal["status"] in ("pending", "ready")
            and timestamp >= proposal["_expires_ts"]
        ):
            proposal["status"] = "expired"

    def _validate_change(self, change):
        if not isinstance(change, dict):
            raise ImaGuardError("IMA_CHANGE_INVALID", "change must be a mapping")
        op = change.get("op")
        if op not in ("add", "remove"):
            raise ImaGuardError("IMA_CHANGE_INVALID", repr(op))
        path = change.get("path")
        if not isinstance(path, str):
            raise ImaGuardError("IMA_CHANGE_INVALID", "path must be a string")
        _validate_path(path)
        algo = change.get("algo", change.get("algorithm", "sha256"))
        _validate_algo(algo)
        digest = change.get("digest")
        if op == "add":
            _validate_digest(digest, algo)
        elif digest is not None:
            _validate_digest(digest, algo)
        result = {"op": op, "path": path, "algo": algo}
        if digest is not None:
            result["digest"] = digest
        if "note" in change:
            result["note"] = change["note"]
        return result

    def add_baseline(
        self,
        host,
        path,
        *,
        digest,
        algo="sha256",
        note=None,
        now=None,
    ):
        _validate_path(path)
        _validate_algo(algo)
        _validate_digest(digest, algo)
        timestamp, display = _time_pair(now)
        with self._lock:
            entries = self._baselines.setdefault(host, {})
            key = (path, algo)
            existing = entries.get(key)
            if existing is not None:
                if existing["digest"] == digest:
                    result = dict(existing)
                    result["status"] = "unchanged"
                    return result
                raise ImaGuardError(
                    "IMA_BASELINE_CONFLICT", "%s (%s)" % (path, algo)
                )
            entry = {
                "host": host,
                "path": path,
                "algo": algo,
                "digest": digest,
                "note": note,
                "added_at": display,
            }
            entries[key] = entry
            self._host(host, create=True)
            self._append_audit(
                "baseline_added",
                host=host,
                at=display,
                path=path,
                algo=algo,
                digest=digest,
            )
            result = dict(entry)
            result["status"] = "added"
            return result

    def remove_baseline(self, host, path, *, algo="sha256", now=None):
        _validate_path(path)
        _validate_algo(algo)
        _timestamp, display = _time_pair(now)
        with self._lock:
            entries = self._baselines.get(host, {})
            key = (path, algo)
            if key not in entries:
                raise ImaGuardError(
                    "IMA_BASELINE_UNKNOWN", "%s (%s)" % (path, algo)
                )
            entry = entries.pop(key)
            if not entries:
                self._baselines.pop(host, None)
            self._append_audit(
                "baseline_removed",
                host=host,
                at=display,
                path=path,
                algo=algo,
            )
            result = dict(entry)
            result["status"] = "removed"
            return result

    def propose_baseline(self, host, *, changes, proposer, now=None):
        if not isinstance(changes, list) or not changes:
            raise ImaGuardError(
                "IMA_CHANGE_INVALID", "changes must be a non-empty list"
            )
        if not isinstance(proposer, str):
            raise ImaGuardError("IMA_CHANGE_INVALID", "proposer must be a string")
        validated = []
        seen = set()
        for change in changes:
            item = self._validate_change(change)
            key = (item["path"], item["algo"])
            if key in seen:
                raise ImaGuardError(
                    "IMA_CHANGE_INVALID", "%s (%s)" % key
                )
            seen.add(key)
            validated.append(item)

        timestamp, display = _time_pair(now)
        with self._lock:
            sequence = self._proposal_seq.get(host, 0) + 1
            self._proposal_seq[host] = sequence
            proposal_id = "%s:%d" % (host, sequence)
            expires_ts = timestamp + self.proposal_ttl_seconds
            status = "ready" if len(validated) == 0 else "pending"
            if self.quorum <= 0:
                status = "ready"
            proposal = {
                "id": proposal_id,
                "host": host,
                "changes": validated,
                "proposer": proposer,
                "approvals": [],
                "status": status,
                "created_at": display,
                "expires_at": _iso_utc(expires_ts),
                "applied_at": None,
                "_created_ts": timestamp,
                "_expires_ts": expires_ts,
            }
            self._proposals[proposal_id] = proposal
            self._host(host, create=True)
            self._append_audit(
                "proposal_created",
                host=host,
                at=display,
                proposal=proposal_id,
                proposer=proposer,
                changes=len(validated),
            )
            return self._proposal_view(proposal)

    def approve_proposal(self, proposal_id, *, approver, now=None):
        if not isinstance(approver, str):
            raise ImaGuardError(
                "IMA_CHANGE_INVALID", "approver must be a string"
            )
        timestamp, display = _time_pair(now)
        with self._lock:
            proposal = self._get_proposal(proposal_id)
            if proposal["status"] == "applied":
                raise ImaGuardError("IMA_PROPOSAL_APPLIED", proposal_id)
            self._expire_proposal_if_needed(proposal, timestamp)
            if proposal["status"] == "expired":
                raise ImaGuardError("IMA_PROPOSAL_EXPIRED", proposal_id)
            if approver == proposal["proposer"]:
                raise ImaGuardError("IMA_SELF_APPROVAL", approver)
            if approver in proposal["approvals"]:
                raise ImaGuardError("IMA_APPROVER_DUPLICATE", approver)
            proposal["approvals"].append(approver)
            if len(proposal["approvals"]) >= self.quorum:
                proposal["status"] = "ready"
            else:
                proposal["status"] = "pending"
            self._append_audit(
                "proposal_approved",
                host=proposal["host"],
                at=display,
                proposal=proposal_id,
                approver=approver,
            )
            return self._proposal_view(proposal)

    def apply_proposal(self, proposal_id, *, now=None):
        timestamp, display = _time_pair(now)
        with self._lock:
            proposal = self._get_proposal(proposal_id)
            if proposal["status"] == "applied":
                raise ImaGuardError("IMA_PROPOSAL_APPLIED", proposal_id)
            self._expire_proposal_if_needed(proposal, timestamp)
            if proposal["status"] == "expired":
                raise ImaGuardError("IMA_PROPOSAL_EXPIRED", proposal_id)
            if len(proposal["approvals"]) < self.quorum:
                raise ImaGuardError("IMA_QUORUM_PENDING", proposal_id)

            host = proposal["host"]
            staged = copy.deepcopy(self._baselines)
            entries = staged.setdefault(host, {})
            for change in proposal["changes"]:
                if change["op"] != "remove":
                    continue
                key = (change["path"], change["algo"])
                if key not in entries:
                    raise ImaGuardError(
                        "IMA_BASELINE_UNKNOWN",
                        "%s (%s)" % (change["path"], change["algo"]),
                    )
            for change in proposal["changes"]:
                key = (change["path"], change["algo"])
                if change["op"] == "remove":
                    entries.pop(key, None)
            for change in proposal["changes"]:
                if change["op"] != "add":
                    continue
                key = (change["path"], change["algo"])
                entries[key] = {
                    "host": host,
                    "path": change["path"],
                    "algo": change["algo"],
                    "digest": change["digest"],
                    "note": change.get("note"),
                    "added_at": display,
                }

            self._baselines = staged
            self._host(host, create=True)
            proposal["status"] = "applied"
            proposal["applied_at"] = display
            self._append_audit(
                "proposal_applied",
                host=host,
                at=display,
                proposal=proposal_id,
                changes=len(proposal["changes"]),
            )
            return self._proposal_view(proposal)

    def appraise(
        self,
        host,
        measurements,
        *,
        require_complete=True,
        now=None,
    ):
        timestamp, display = _time_pair(now)
        with self._lock:
            if not isinstance(measurements, (list, tuple)):
                raise ImaGuardError(
                    "IMA_MEASUREMENT_INVALID", "measurements must be a list"
                )
            if len(measurements) > self.max_batch:
                raise ImaGuardError(
                    "IMA_BATCH_TOO_LARGE",
                    "%d > %d" % (len(measurements), self.max_batch),
                )
            state = self._host(host)
            if state is not None and state["quarantined"]:
                raise ImaGuardError("IMA_HOST_QUARANTINED", host)

            checked_entries = []
            seen = set()
            for measurement in measurements:
                if not isinstance(measurement, dict):
                    raise ImaGuardError(
                        "IMA_MEASUREMENT_INVALID", "measurement must be a mapping"
                    )
                if "path" not in measurement or not isinstance(
                    measurement.get("path"), str
                ):
                    raise ImaGuardError(
                        "IMA_MEASUREMENT_INVALID", "missing or invalid path"
                    )
                algo = measurement.get("algo", measurement.get("algorithm"))
                if not isinstance(algo, str):
                    raise ImaGuardError(
                        "IMA_MEASUREMENT_INVALID", "missing or invalid algo"
                    )
                if "digest" not in measurement or not isinstance(
                    measurement.get("digest"), str
                ):
                    raise ImaGuardError(
                        "IMA_MEASUREMENT_INVALID", "missing or invalid digest"
                    )
                path = measurement["path"]
                digest = measurement["digest"]
                _validate_path(path)
                _validate_algo(algo)
                _validate_digest(digest, algo)
                key = (path, algo)
                if key in seen:
                    raise ImaGuardError(
                        "IMA_DUPLICATE_PATH", "%s (%s)" % key
                    )
                seen.add(key)
                checked_entries.append((path, algo, digest))

            baselines = self._baselines.get(host, {})
            violations = []
            excepted = set()
            for path, algo, actual in checked_entries:
                baseline = baselines.get((path, algo))
                if baseline is None:
                    violations.append(
                        {
                            "path": path,
                            "kind": "unknown_file",
                            "expected": None,
                            "actual": actual,
                        }
                    )
                elif baseline["digest"] != actual:
                    violations.append(
                        {
                            "path": path,
                            "kind": "digest_mismatch",
                            "expected": baseline["digest"],
                            "actual": actual,
                        }
                    )

            if require_complete:
                for (path, algo), baseline in baselines.items():
                    if (path, algo) not in seen:
                        violations.append(
                            {
                                "path": path,
                                "kind": "missing_file",
                                "expected": baseline["digest"],
                                "actual": None,
                            }
                        )

            filtered = []
            for violation in violations:
                kind = violation["kind"]
                if kind in ("unknown_file", "digest_mismatch"):
                    key = (host, violation["path"], violation["actual"])
                    exception = self._exceptions.get(key)
                    if (
                        exception is not None
                        and timestamp < exception["_expires_ts"]
                    ):
                        excepted.add(violation["path"])
                        continue
                filtered.append(violation)

            filtered.sort(key=lambda item: (item["path"], item["kind"]))
            state = self._host(host, create=True)
            status = "pass" if not filtered else "fail"
            if status == "pass":
                state["consecutive_failures"] = 0
            else:
                state["consecutive_failures"] += 1
            if (
                status == "fail"
                and state["consecutive_failures"] >= self.quarantine_after
            ):
                state["quarantined"] = True
            state["status"] = status
            state["last_appraised"] = display
            self._append_audit(
                "appraisal",
                host=host,
                at=display,
                status=status,
                violations=len(filtered),
                checked=len(checked_entries),
                excepted=sorted(excepted),
                consecutive_failures=state["consecutive_failures"],
                quarantined=state["quarantined"],
            )
            return {
                "status": status,
                "violations": filtered,
                "checked": len(checked_entries),
                "excepted": sorted(excepted),
                "consecutive_failures": state["consecutive_failures"],
                "quarantined": state["quarantined"],
            }

    def grant_exception(
        self,
        host,
        path,
        *,
        digest,
        ttl_seconds=600,
        reason="",
        now=None,
    ):
        _validate_path(path)
        _validate_standalone_digest(digest)
        if (
            isinstance(ttl_seconds, bool)
            or not isinstance(ttl_seconds, int)
            or ttl_seconds <= 0
        ):
            raise ImaGuardError("IMA_TTL_INVALID", repr(ttl_seconds))
        timestamp, display = _time_pair(now)
        expires_ts = timestamp + ttl_seconds
        with self._lock:
            key = (host, path, digest)
            exception = {
                "host": host,
                "path": path,
                "digest": digest,
                "reason": reason,
                "granted_at": display,
                "expires_at": _iso_utc(expires_ts),
                "_granted_ts": timestamp,
                "_expires_ts": expires_ts,
            }
            self._exceptions[key] = exception
            self._host(host, create=True)
            self._append_audit(
                "exception_granted",
                host=host,
                at=display,
                path=path,
                digest=digest,
                ttl_seconds=ttl_seconds,
            )
            result = {
                "host": host,
                "path": path,
                "digest": digest,
                "reason": reason,
                "expires_at": exception["expires_at"],
                "ttl_seconds": ttl_seconds,
                "status": "granted",
            }
            return result

    def host_state(self, host):
        with self._lock:
            state = self._host(host)
            baseline = len(self._baselines.get(host, {}))
            if state is None:
                return _StateView(
                    baseline=baseline,
                    status="unknown",
                    consecutive_failures=0,
                    quarantined=False,
                    last_appraised=None,
                )
            return _StateView(
                baseline=baseline,
                status=state["status"],
                consecutive_failures=state["consecutive_failures"],
                quarantined=state["quarantined"],
                last_appraised=state["last_appraised"],
            )

    def expire(self, now=None):
        timestamp, display = _time_pair(now)
        with self._lock:
            expired = [
                key
                for key, exception in self._exceptions.items()
                if timestamp >= exception["_expires_ts"]
            ]
            for key in expired:
                del self._exceptions[key]
            for proposal in self._proposals.values():
                self._expire_proposal_if_needed(proposal, timestamp)
            if expired:
                self._append_audit(
                    "exceptions_expired",
                    at=display,
                    count=len(expired),
                )
            return {"exceptions": len(expired)}

    def release_quarantine(self, host):
        with self._lock:
            state = self._host(host, create=True)
            was_quarantined = state["quarantined"]
            state["quarantined"] = False
            state["consecutive_failures"] = 0
            if was_quarantined:
                self._append_audit(
                    "quarantine_released",
                    host=host,
                    at=_iso_utc(time.time()),
                )
            return self.host_state(host)

    def snapshot(self):
        with self._lock:
            baselines = {}
            for host, entries in self._baselines.items():
                baselines[host] = [copy.deepcopy(entry) for entry in entries.values()]
            proposals = {
                proposal_id: copy.deepcopy(proposal)
                for proposal_id, proposal in self._proposals.items()
            }
            exceptions = [
                copy.deepcopy(exception)
                for exception in self._exceptions.values()
            ]
            hosts = copy.deepcopy(self._hosts)
            return {
                "version": SNAPSHOT_VERSION,
                "config": {
                    "max_batch": self.max_batch,
                    "quorum": self.quorum,
                    "proposal_ttl_seconds": self.proposal_ttl_seconds,
                    "quarantine_after": self.quarantine_after,
                    "audit_capacity": self.audit_capacity,
                },
                "baselines": baselines,
                "proposals": proposals,
                "proposal_seq": dict(self._proposal_seq),
                "exceptions": exceptions,
                "hosts": hosts,
                "audit": copy.deepcopy(self._audit),
            }

    def restore(self, snap):
        try:
            if isinstance(snap, str):
                snap = json.loads(snap)
            if not isinstance(snap, dict):
                raise ValueError("snapshot must be a mapping")
            if snap.get("version") not in (SNAPSHOT_VERSION, str(SNAPSHOT_VERSION)):
                raise ValueError("unknown snapshot version")
            json.dumps(snap)

            config = snap.get("config", {})
            if not isinstance(config, dict):
                raise ValueError("invalid config")
            max_batch = int(config.get("max_batch", self.max_batch))
            quorum = int(config.get("quorum", self.quorum))
            proposal_ttl_seconds = int(
                config.get("proposal_ttl_seconds", self.proposal_ttl_seconds)
            )
            quarantine_after = int(
                config.get("quarantine_after", self.quarantine_after)
            )
            audit_capacity = int(
                config.get("audit_capacity", self.audit_capacity)
            )

            baselines = {}
            raw_baselines = snap.get("baselines", {})
            if not isinstance(raw_baselines, dict):
                raise ValueError("invalid baselines")
            for host, entries in raw_baselines.items():
                if not isinstance(entries, list):
                    raise ValueError("invalid baseline entries")
                host_entries = {}
                for entry in entries:
                    if not isinstance(entry, dict):
                        raise ValueError("invalid baseline entry")
                    path = entry["path"]
                    algo = entry["algo"]
                    digest = entry["digest"]
                    _validate_path(path)
                    _validate_digest(digest, algo)
                    host_entries[(path, algo)] = {
                        "host": host,
                        "path": path,
                        "algo": algo,
                        "digest": digest,
                        "note": entry.get("note"),
                        "added_at": entry.get("added_at"),
                    }
                baselines[host] = host_entries

            raw_proposals = snap.get("proposals", {})
            if not isinstance(raw_proposals, dict):
                raise ValueError("invalid proposals")
            proposals = {}
            for proposal_id, proposal in raw_proposals.items():
                if not isinstance(proposal, dict):
                    raise ValueError("invalid proposal")
                if proposal.get("id") != proposal_id:
                    raise ValueError("proposal id mismatch")
                if not isinstance(proposal.get("changes"), list):
                    raise ValueError("invalid proposal changes")
                if not isinstance(proposal.get("approvals"), list):
                    raise ValueError("invalid proposal approvals")
                if "_expires_ts" not in proposal or "_created_ts" not in proposal:
                    raise ValueError("proposal timestamps missing")
                proposals[proposal_id] = copy.deepcopy(proposal)

            raw_seq = snap.get("proposal_seq", {})
            if not isinstance(raw_seq, dict):
                raise ValueError("invalid proposal sequence")
            proposal_seq = {str(key): int(value) for key, value in raw_seq.items()}

            raw_exceptions = snap.get("exceptions", [])
            if not isinstance(raw_exceptions, list):
                raise ValueError("invalid exceptions")
            exceptions = {}
            for exception in raw_exceptions:
                if not isinstance(exception, dict):
                    raise ValueError("invalid exception")
                host = exception["host"]
                path = exception["path"]
                digest = exception["digest"]
                _validate_path(path)
                _validate_standalone_digest(digest)
                if "_expires_ts" not in exception:
                    raise ValueError("exception expiry missing")
                exceptions[(host, path, digest)] = copy.deepcopy(exception)

            raw_hosts = snap.get("hosts", {})
            if not isinstance(raw_hosts, dict):
                raise ValueError("invalid hosts")
            hosts = {}
            for host, state in raw_hosts.items():
                if not isinstance(state, dict):
                    raise ValueError("invalid host state")
                hosts[host] = {
                    "consecutive_failures": int(
                        state.get("consecutive_failures", 0)
                    ),
                    "quarantined": bool(state.get("quarantined", False)),
                    "last_appraised": state.get("last_appraised"),
                    "status": state.get("status", "unknown"),
                }

            raw_audit = snap.get("audit", [])
            if not isinstance(raw_audit, list):
                raise ValueError("invalid audit")
            audit = copy.deepcopy(raw_audit[-audit_capacity:]) if audit_capacity >= 0 else []
        except ImaGuardError as exc:
            raise ImaGuardError("IMA_SNAPSHOT_INVALID", str(exc)) from exc
        except (KeyError, TypeError, ValueError) as exc:
            raise ImaGuardError("IMA_SNAPSHOT_INVALID", str(exc)) from exc

        with self._lock:
            self.max_batch = max_batch
            self.quorum = quorum
            self.proposal_ttl_seconds = proposal_ttl_seconds
            self.quarantine_after = quarantine_after
            self.audit_capacity = audit_capacity
            self._baselines = baselines
            self._proposals = proposals
            self._proposal_seq = proposal_seq
            self._exceptions = exceptions
            self._hosts = hosts
            self._audit = audit

    def audit(self, limit=20):
        with self._lock:
            rows = list(reversed(self._audit))
            if limit is None:
                return copy.deepcopy(rows)
            if not isinstance(limit, int) or isinstance(limit, bool):
                raise ImaGuardError("IMA_AUDIT_LIMIT_INVALID", repr(limit))
            if limit <= 0:
                return []
            return copy.deepcopy(rows[:limit])

    def stats(self):
        with self._lock:
            proposal_status = {
                "pending": 0,
                "ready": 0,
                "applied": 0,
                "expired": 0,
            }
            for proposal in self._proposals.values():
                status = proposal["status"]
                proposal_status[status] = proposal_status.get(status, 0) + 1
            hosts = set(self._baselines) | set(self._hosts)
            return _StatsView(
                hosts=len(hosts),
                baselines=sum(
                    len(entries) for entries in self._baselines.values()
                ),
                proposals=len(self._proposals),
                pending=proposal_status["pending"],
                ready=proposal_status["ready"],
                applied=proposal_status["applied"],
                expired=proposal_status["expired"],
                exceptions=len(self._exceptions),
                quarantined=sum(
                    1
                    for state in self._hosts.values()
                    if state.get("quarantined")
                ),
                audit=len(self._audit),
            )
