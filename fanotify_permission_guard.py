"""In-memory fanotify permission-event state machine.

The implementation deliberately does not talk to a real fanotify file
descriptor.  It models the userspace side of permission events: mark merging,
bounded queueing, verdict de-duplication, timeouts, cookie coalescing,
allowlisting and restartable snapshots.
"""

from __future__ import annotations

import copy
import posixpath
import threading
from typing import Any, Iterable, Mapping, Sequence

SNAPSHOT_VERSION = 1

FAN_MASK_INVALID = "FAN_MASK_INVALID"
FAN_PATH_INVALID = "FAN_PATH_INVALID"
FAN_LIMIT = "FAN_LIMIT"
FAN_MARK_UNKNOWN = "FAN_MARK_UNKNOWN"
FAN_MASK_UNWATCHED = "FAN_MASK_UNWATCHED"
FAN_NO_MARK = "FAN_NO_MARK"
FAN_EVENT_DUP = "FAN_EVENT_DUP"
FAN_QUEUE_FULL = "FAN_QUEUE_FULL"
FAN_DECISION_DUP = "FAN_DECISION_DUP"
FAN_EVENT_UNKNOWN = "FAN_EVENT_UNKNOWN"
FAN_DECISION_INVALID = "FAN_DECISION_INVALID"
FAN_PID_MISMATCH = "FAN_PID_MISMATCH"
FAN_TIMEOUT = "FAN_TIMEOUT"
FAN_EVENT_EXPIRED = "FAN_EVENT_EXPIRED"
FAN_COOKIE_COALESCED = "FAN_COOKIE_COALESCED"
FAN_ALLOWLISTED = "FAN_ALLOWLISTED"
FAN_ALLOWLIST_UNKNOWN = "FAN_ALLOWLIST_UNKNOWN"
FAN_CLOSED = "FAN_CLOSED"
FAN_SNAPSHOT_INVALID = "FAN_SNAPSHOT_INVALID"

_MASK_ALIASES = {
    "open_perm": "open_perm",
    "fan_open_perm": "open_perm",
    "open": "open_perm",
    "access_perm": "access_perm",
    "fan_access_perm": "access_perm",
    "access": "access_perm",
}

_METRIC_KEYS = (
    "submitted",
    "allowed",
    "denied",
    "coalesced",
    "ignored",
    "expired",
    "queue_full",
    "suppressed",
)


class FanotifyError(ValueError):
    """Compatibility exception for callers that prefer exceptions."""

    def __init__(self, code: str, detail: Any = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


def _valid_path(path: Any) -> bool:
    if not isinstance(path, str) or not path or "\x00" in path:
        return False
    if not path.startswith("/") or path.startswith("//"):
        return False
    if posixpath.normpath(path) != path:
        return False
    return True


def _canonical_masks(mask: Any) -> list[str] | None:
    if isinstance(mask, str):
        values: Iterable[Any] = (mask,)
    else:
        try:
            values = list(mask)
        except TypeError:
            return None
    result: set[str] = set()
    for value in values:
        if not isinstance(value, str):
            return None
        canonical = _MASK_ALIASES.get(value.strip().lower())
        if canonical is None:
            return None
        result.add(canonical)
    if not result:
        return None
    return sorted(result)


def _canonical_mask(mask: Any) -> str | None:
    masks = _canonical_masks(mask)
    if masks is None or len(masks) != 1:
        return None
    return masks[0]


def _covers(prefix: str, path: str) -> bool:
    if prefix == path:
        return True
    if prefix == "/":
        return path.startswith("/")
    return path.startswith(prefix + "/")


def _error(status: str, code: str, **fields: Any) -> dict:
    out = {"status": status, "code": code}
    out.update(fields)
    return out


class FanotifyGuard:
    """Bounded, thread-safe fanotify permission-event state machine."""

    def __init__(
        self,
        config: Mapping[str, Any] | Any | None = None,
        *args: Any,
        max_marks: int = 64,
        max_pending: int = 256,
        default_timeout: float = 5.0,
        max_allowlist: int = 1024,
        **kwargs: Any,
    ) -> None:
        values: dict[str, Any] = {}
        if "cfg" in kwargs:
            config = kwargs.pop("cfg")
        if args or isinstance(config, (int, float)) and not isinstance(config, bool):
            positional = [config, *args]
            names = ("max_marks", "max_pending", "default_timeout")
            if len(positional) > len(names):
                raise TypeError("too many positional arguments")
            config = None
            values.update(zip(names, positional))
        if config is not None:
            if isinstance(config, Mapping):
                values.update(config)
            elif all(hasattr(config, name) for name in ("max_marks", "max_pending")):
                values.update(
                    {
                        "max_marks": getattr(config, "max_marks"),
                        "max_pending": getattr(config, "max_pending"),
                        "default_timeout": getattr(
                            config, "default_timeout", default_timeout
                        ),
                    }
                )
            else:
                raise TypeError("config must be a mapping or configuration object")
        values.update(kwargs)
        if "max_marks" in values:
            max_marks = values["max_marks"]
        if "max_pending" in values:
            max_pending = values["max_pending"]
        if "default_timeout" in values:
            default_timeout = values["default_timeout"]
        elif "timeout" in values:
            default_timeout = values["timeout"]
        if "max_allowlist" in values:
            max_allowlist = values["max_allowlist"]

        self.max_marks = max(0, int(max_marks))
        self.max_pending = max(0, int(max_pending))
        self.max_allowlist = max(0, int(max_allowlist))
        self.default_timeout = float(default_timeout)

        self._lock = threading.RLock()
        self._marks: dict[str, dict[str, Any]] = {}
        self._allowlist: set[str] = set()
        self._pending: dict[str, dict[str, Any]] = {}
        self._decisions: dict[str, dict[str, Any]] = {}
        self._seen_events: set[str] = set()
        self._cookies: dict[str, str] = {}
        self._metrics = {key: 0 for key in _METRIC_KEYS}
        self._next_wd = 1
        self._seq = 0
        self._closed = False

    # -- marks ---------------------------------------------------------

    def add_mark(self, path: str, mask: Sequence[str]) -> dict:
        with self._lock:
            if not _valid_path(path):
                return _error("rejected", FAN_PATH_INVALID, path=path)
            masks = _canonical_masks(mask)
            if masks is None:
                return _error("rejected", FAN_MASK_INVALID, path=path)

            current = self._marks.get(path)
            if current is not None:
                missing = set(masks) - set(current["mask"])
                if not missing:
                    return {
                        "status": "unchanged",
                        "path": path,
                        "mask": list(current["mask"]),
                        "wd": current["wd"],
                    }
                current["mask"] = sorted(set(current["mask"]) | set(masks))
                return {
                    "status": "updated",
                    "path": path,
                    "mask": list(current["mask"]),
                    "wd": current["wd"],
                }

            if len(self._marks) >= self.max_marks:
                return _error("rejected", FAN_LIMIT, path=path)

            wd = self._next_wd
            self._next_wd += 1
            self._marks[path] = {"wd": wd, "mask": masks}
            return {"status": "added", "path": path, "mask": list(masks), "wd": wd}

    def remove_mark(self, path: str) -> dict:
        with self._lock:
            if path not in self._marks:
                return _error("rejected", FAN_MARK_UNKNOWN, path=path)
            mark = self._marks.pop(path)
            return {
                "status": "removed",
                "path": path,
                "mask": list(mark["mask"]),
                "wd": mark["wd"],
            }

    # -- allowlist -----------------------------------------------------

    def allowlist_add(self, path: str) -> dict:
        with self._lock:
            if not _valid_path(path):
                return _error("rejected", FAN_PATH_INVALID, path=path)
            if path in self._allowlist:
                return {"status": "unchanged", "path": path}
            if len(self._allowlist) >= self.max_allowlist:
                return _error("rejected", FAN_LIMIT, path=path)
            self._allowlist.add(path)
            return {"status": "added", "path": path}

    def allowlist_remove(self, path: str) -> dict:
        with self._lock:
            if path not in self._allowlist:
                return _error("rejected", FAN_ALLOWLIST_UNKNOWN, path=path)
            self._allowlist.remove(path)
            return {"status": "removed", "path": path}

    def _allowlisted(self, path: str) -> bool:
        return any(_covers(entry, path) for entry in self._allowlist)

    # -- events --------------------------------------------------------

    def _match_mark(self, path: str) -> str | None:
        best: str | None = None
        for mark_path in self._marks:
            if not _covers(mark_path, path):
                continue
            if best is None or len(mark_path) > len(best):
                best = mark_path
        return best

    @staticmethod
    def _public_event(event: Mapping[str, Any]) -> dict:
        return {key: copy.deepcopy(value) for key, value in event.items()
                if not key.startswith("_")}

    def submit_event(
        self,
        event_id: str,
        path: str,
        mask: str,
        *,
        pid: int | None = None,
        cookie: str | None = None,
        timeout: float | None = None,
        now: float = 0,
    ) -> dict:
        with self._lock:
            if self._closed:
                return _error("rejected", FAN_CLOSED, event_id=event_id, path=path)
            if not _valid_path(path):
                return _error("rejected", FAN_PATH_INVALID, event_id=event_id, path=path)
            canonical = _canonical_mask(mask)
            if canonical is None:
                return _error("rejected", FAN_MASK_INVALID, event_id=event_id, path=path)

            self._metrics["submitted"] += 1

            if self._allowlisted(path):
                self._seen_events.add(event_id)
                self._metrics["allowed"] += 1
                self._metrics["suppressed"] += 1
                record = {
                    "event_id": event_id,
                    "path": path,
                    "mask": canonical,
                    "pid": pid,
                    "reason": "allowlist",
                    "decision": "allow",
                    "status": "allowed",
                    "code": FAN_ALLOWLISTED,
                    "decided_at": now,
                }
                self._decisions.setdefault(event_id, record)
                return {
                    "status": "allowed",
                    "decision": "allow",
                    "code": FAN_ALLOWLISTED,
                    "event_id": event_id,
                    "path": path,
                    "mask": canonical,
                    "pid": pid,
                }

            if cookie is not None:
                original_id = self._cookies.get(cookie)
                if original_id is not None and original_id in self._pending:
                    self._seen_events.add(event_id)
                    self._metrics["coalesced"] += 1
                    original = self._pending[original_id]
                    return {
                        "status": "coalesced",
                        "code": FAN_COOKIE_COALESCED,
                        "event_id": original_id,
                        "original_event_id": original_id,
                        "path": original["path"],
                        "mask": original["mask"],
                        "pid": original.get("pid"),
                        "cookie": cookie,
                        "deadline": original["deadline"],
                        "seq": original["seq"],
                    }

            if event_id in self._seen_events:
                self._metrics["ignored"] += 1
                existing = self._pending.get(event_id)
                if existing is not None:
                    extra = {"deadline": existing["deadline"], "seq": existing["seq"]}
                else:
                    previous = self._decisions.get(event_id, {})
                    extra = {}
                    for key in ("decision", "reason"):
                        if key in previous:
                            extra[key] = previous[key]
                return _error(
                    "duplicate", FAN_EVENT_DUP, event_id=event_id, path=path, **extra
                )

            mark_path = self._match_mark(path)
            if mark_path is None:
                self._metrics["ignored"] += 1
                self._seen_events.add(event_id)
                return _error("rejected", FAN_NO_MARK, event_id=event_id, path=path)
            if canonical not in self._marks[mark_path]["mask"]:
                self._metrics["ignored"] += 1
                self._seen_events.add(event_id)
                return _error(
                    "rejected",
                    FAN_MASK_UNWATCHED,
                    event_id=event_id,
                    path=path,
                    mask=canonical,
                )

            if len(self._pending) >= self.max_pending:
                self._metrics["denied"] += 1
                self._metrics["queue_full"] += 1
                self._seen_events.add(event_id)
                record = {
                    "event_id": event_id,
                    "path": path,
                    "mask": canonical,
                    "pid": pid,
                    "cookie": cookie,
                    "reason": "queue full",
                    "decision": "deny",
                    "status": "denied",
                    "code": FAN_QUEUE_FULL,
                    "decided_at": now,
                }
                self._decisions.setdefault(event_id, record)
                return {
                    "status": "denied",
                    "decision": "deny",
                    "code": FAN_QUEUE_FULL,
                    "event_id": event_id,
                    "path": path,
                    "mask": canonical,
                    "pid": pid,
                }

            wait = self.default_timeout if timeout is None else float(timeout)
            self._seq += 1
            event = {
                "event_id": event_id,
                "path": path,
                "mask": canonical,
                "pid": pid,
                "cookie": cookie,
                "deadline": float(now) + wait,
                "seq": self._seq,
                "status": "pending",
                "_mark_path": mark_path,
            }
            self._pending[event_id] = event
            self._seen_events.add(event_id)
            if cookie is not None:
                self._cookies[cookie] = event_id
            return self._public_event(event)

    def _expire_record(self, event: Mapping[str, Any], now: float) -> dict:
        event_id = event["event_id"]
        out = self._public_event(event)
        out.update(
            {
                "status": "denied",
                "decision": "deny",
                "reason": "timeout",
                "code": FAN_TIMEOUT,
                "decided_at": now,
            }
        )
        self._pending.pop(event_id, None)
        cookie = event.get("cookie")
        if cookie is not None and self._cookies.get(cookie) == event_id:
            self._cookies.pop(cookie, None)
        self._decisions[event_id] = {
            "event_id": event_id,
            "path": event["path"],
            "mask": event["mask"],
            "pid": event.get("pid"),
            "cookie": cookie,
            "reason": "timeout",
            "decision": "deny",
            "status": "denied",
            "code": FAN_TIMEOUT,
            "decided_at": now,
        }
        self._metrics["denied"] += 1
        self._metrics["expired"] += 1
        return out

    def decide(
        self,
        event_id: str,
        decision: str,
        *,
        pid: int | None = None,
        reason: str | None = None,
        now: float | None = None,
    ) -> dict:
        with self._lock:
            if self._closed:
                return _error("rejected", FAN_CLOSED, event_id=event_id)
            if decision not in ("allow", "deny"):
                return _error(
                    "rejected", FAN_DECISION_INVALID, event_id=event_id,
                    decision=decision,
                )

            event = self._pending.get(event_id)
            if event is None:
                previous = self._decisions.get(event_id)
                if previous is None:
                    return _error("rejected", FAN_EVENT_UNKNOWN, event_id=event_id)
                if previous.get("code") == FAN_TIMEOUT or previous.get("status") == "expired":
                    return {
                        "status": "expired",
                        "code": FAN_EVENT_EXPIRED,
                        "event_id": event_id,
                        "decision": previous.get("decision", "deny"),
                        "reason": previous.get("reason", "timeout"),
                    }
                return {
                    "status": "duplicate",
                    "code": FAN_DECISION_DUP,
                    "event_id": event_id,
                    "decision": previous.get("decision"),
                    "reason": previous.get("reason"),
                }

            if pid is not None and event.get("pid") != pid:
                return _error(
                    "rejected", FAN_PID_MISMATCH, event_id=event_id,
                    pid=pid, expected_pid=event.get("pid"),
                )

            if now is not None and float(now) >= event["deadline"]:
                self._expire_record(event, float(now))
                return {
                    "status": "expired",
                    "code": FAN_EVENT_EXPIRED,
                    "event_id": event_id,
                    "decision": "deny",
                    "reason": "timeout",
                }

            self._pending.pop(event_id, None)
            cookie = event.get("cookie")
            if cookie is not None and self._cookies.get(cookie) == event_id:
                self._cookies.pop(cookie, None)

            status = "allowed" if decision == "allow" else "denied"
            self._decisions[event_id] = {
                "event_id": event_id,
                "path": event["path"],
                "mask": event["mask"],
                "pid": event.get("pid"),
                "cookie": cookie,
                "decision": decision,
                "reason": reason,
                "status": status,
                "decided_at": now,
            }
            if decision == "allow":
                self._metrics["allowed"] += 1
            else:
                self._metrics["denied"] += 1
            return {
                "status": status,
                "event_id": event_id,
                "path": event["path"],
                "mask": event["mask"],
                "pid": event.get("pid"),
                "decision": decision,
                "reason": reason,
            }

    def expire(self, now: float) -> list[dict]:
        with self._lock:
            expired = [
                event for event in self._pending.values()
                if float(now) >= event["deadline"]
            ]
            expired.sort(key=lambda event: (event["deadline"], event["seq"]))
            return [self._expire_record(event, float(now)) for event in expired]

    def pending(self) -> list[dict]:
        with self._lock:
            events = sorted(self._pending.values(), key=lambda event: event["seq"])
            return [self._public_event(event) for event in events]

    # -- reporting / lifecycle ----------------------------------------

    def status(self) -> dict:
        with self._lock:
            return {
                "closed": self._closed,
                "marks": len(self._marks),
                "allowlist": len(self._allowlist),
                "pending": len(self._pending),
                "seq": self._seq,
                "metrics": dict(self._metrics),
            }

    def metrics(self) -> dict:
        with self._lock:
            return dict(self._metrics)

    def close(self) -> dict:
        with self._lock:
            self._closed = True
            return {
                "status": "closed",
                "closed": True,
                "pending": len(self._pending),
            }

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": SNAPSHOT_VERSION,
                "marks": copy.deepcopy(self._marks),
                "allowlist": sorted(self._allowlist),
                "pending": copy.deepcopy(self._pending),
                "decisions": copy.deepcopy(self._decisions),
                "metrics": dict(self._metrics),
                "seq": self._seq,
                "closed": self._closed,
                "next_wd": self._next_wd,
                "seen_events": sorted(self._seen_events),
            }

    def restore(self, snapshot: dict) -> dict:
        with self._lock:
            parsed = self._parse_snapshot(snapshot)
            if parsed is None:
                return _error("rejected", FAN_SNAPSHOT_INVALID)

            marks, allowlist, pending, decisions, metrics, seq, closed, next_wd, seen = parsed
            self._marks = marks
            self._allowlist = allowlist
            self._pending = pending
            self._decisions = decisions
            self._metrics = metrics
            self._seq = seq
            self._closed = closed
            self._next_wd = next_wd
            self._seen_events = seen
            self._cookies = {}
            for event_id, event in self._pending.items():
                cookie = event.get("cookie")
                if cookie is not None:
                    self._cookies[cookie] = event_id
            return {
                "status": "restored",
                "marks": len(self._marks),
                "allowlist": len(self._allowlist),
                "pending": len(self._pending),
                "seq": self._seq,
                "closed": self._closed,
            }

    def _parse_snapshot(self, snapshot: Any) -> tuple | None:
        if not isinstance(snapshot, Mapping):
            return None
        if snapshot.get("version") != SNAPSHOT_VERSION:
            return None
        required = (
            "marks", "allowlist", "pending", "decisions", "metrics", "seq", "closed",
        )
        if any(key not in snapshot for key in required):
            return None

        raw_marks = snapshot["marks"]
        marks: dict[str, dict[str, Any]] = {}
        mark_wds: set[int] = set()
        if isinstance(raw_marks, Mapping):
            items = raw_marks.items()
        elif isinstance(raw_marks, list):
            items = []
            for entry in raw_marks:
                if not isinstance(entry, Mapping) or "path" not in entry:
                    return None
                items.append((entry["path"], entry))
        else:
            return None
        for path, entry in items:
            if not _valid_path(path) or not isinstance(entry, Mapping):
                return None
            wd = entry.get("wd")
            masks = _canonical_masks(entry.get("mask"))
            if not isinstance(wd, int) or isinstance(wd, bool) or wd <= 0:
                return None
            if masks is None:
                return None
            if wd in mark_wds:
                return None
            mark_wds.add(wd)
            marks[path] = {"wd": wd, "mask": masks}
        if len(marks) > self.max_marks:
            return None

        raw_allowlist = snapshot["allowlist"]
        if not isinstance(raw_allowlist, (list, tuple, set)):
            return None
        allowlist = set()
        for path in raw_allowlist:
            if not _valid_path(path):
                return None
            allowlist.add(path)
        if len(allowlist) > self.max_allowlist:
            return None

        raw_pending = snapshot["pending"]
        if not isinstance(raw_pending, Mapping):
            return None
        pending: dict[str, dict[str, Any]] = {}
        pending_cookies: set[str] = set()
        for event_id, raw in raw_pending.items():
            if not isinstance(event_id, str) or not isinstance(raw, Mapping):
                return None
            path = raw.get("path")
            mask = _canonical_mask(raw.get("mask"))
            deadline = raw.get("deadline")
            seq = raw.get("seq")
            if not _valid_path(path) or mask is None:
                return None
            if not isinstance(deadline, (int, float)) or isinstance(deadline, bool):
                return None
            if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
                return None
            cookie = raw.get("cookie")
            if cookie is not None:
                if not isinstance(cookie, str) or cookie in pending_cookies:
                    return None
                pending_cookies.add(cookie)
            event = {
                "event_id": event_id,
                "path": path,
                "mask": mask,
                "pid": raw.get("pid"),
                "cookie": cookie,
                "deadline": float(deadline),
                "seq": seq,
                "status": "pending",
                "_mark_path": raw.get("_mark_path"),
            }
            pending[event_id] = event
        if len(pending) > self.max_pending:
            return None

        raw_decisions = snapshot["decisions"]
        if not isinstance(raw_decisions, Mapping):
            return None
        decisions: dict[str, dict[str, Any]] = {}
        for event_id, raw in raw_decisions.items():
            if not isinstance(event_id, str) or not isinstance(raw, Mapping):
                return None
            if raw.get("decision") not in ("allow", "deny"):
                return None
            if not isinstance(raw.get("status"), str):
                return None
            decisions[event_id] = copy.deepcopy(dict(raw))

        raw_metrics = snapshot["metrics"]
        if not isinstance(raw_metrics, Mapping):
            return None
        metrics: dict[str, int] = {}
        for key in _METRIC_KEYS:
            value = raw_metrics.get(key, 0)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                return None
            metrics[key] = value

        seq = snapshot["seq"]
        if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
            return None
        closed = snapshot["closed"]
        if not isinstance(closed, bool):
            return None
        next_wd = snapshot.get("next_wd", max(mark_wds, default=0) + 1)
        if not isinstance(next_wd, int) or isinstance(next_wd, bool):
            return None
        if next_wd <= max(mark_wds, default=0):
            return None

        raw_seen = snapshot.get("seen_events")
        if raw_seen is None:
            seen = set(pending) | set(decisions)
        else:
            if not isinstance(raw_seen, (list, tuple, set)):
                return None
            seen = set()
            for event_id in raw_seen:
                if not isinstance(event_id, str):
                    return None
                seen.add(event_id)
            seen.update(pending)
            seen.update(decisions)

        return marks, allowlist, pending, decisions, metrics, seq, closed, next_wd, seen


__all__ = [
    "FanotifyGuard",
    "FanotifyError",
    "SNAPSHOT_VERSION",
    "FAN_MASK_INVALID",
    "FAN_PATH_INVALID",
    "FAN_LIMIT",
    "FAN_MARK_UNKNOWN",
    "FAN_MASK_UNWATCHED",
    "FAN_NO_MARK",
    "FAN_EVENT_DUP",
    "FAN_QUEUE_FULL",
    "FAN_DECISION_DUP",
    "FAN_EVENT_UNKNOWN",
    "FAN_DECISION_INVALID",
    "FAN_PID_MISMATCH",
    "FAN_TIMEOUT",
    "FAN_EVENT_EXPIRED",
    "FAN_COOKIE_COALESCED",
    "FAN_ALLOWLISTED",
    "FAN_ALLOWLIST_UNKNOWN",
    "FAN_CLOSED",
    "FAN_SNAPSHOT_INVALID",
]
