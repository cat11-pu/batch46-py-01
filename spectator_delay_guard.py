"""Spectator delay and delivery guard (batch46-game-b-03, Bugfix)."""

from __future__ import annotations

import copy
import json
import threading
from datetime import datetime, timezone


class SpectatorError(ValueError):
    """Raised when a spectator stream operation is rejected."""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = dict(detail or {})


def _parse_timestamp(value):
    """Return a POSIX timestamp, interpreting timezone-less values as UTC."""
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, (int, float)):
        return float(value)
    else:
        text = str(value).strip()
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        parsed = datetime.fromisoformat(text)

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


class SpectatorDelay:
    """Delayed frame queue, per-viewer cursors, pause and snapshots."""

    def __init__(self, *, delay_seconds=30, queue_cap=100, viewer_cap=1000):
        self.delay_seconds = delay_seconds
        self.queue_cap = queue_cap
        self.viewer_cap = viewer_cap
        self._matches = {}
        self._viewers = {}
        self._cursors = {}
        self._delivered = 0
        self._lock = threading.RLock()

    def _require_match(self, match):
        state = self._matches.get(match)
        if state is None:
            raise SpectatorError("SPECT_UNKNOWN_MATCH", {"match": match})
        return state

    def _require_viewer(self, viewer):
        try:
            return self._viewers[viewer]
        except KeyError:
            raise SpectatorError("SPECT_UNKNOWN_VIEWER", {"viewer": viewer}) from None

    def _cursor_for(self, viewer, match):
        return self._cursors.get(viewer, {}).get(match, 0)

    def _set_cursor(self, viewer, match, cursor):
        self._cursors.setdefault(viewer, {})[match] = cursor

    def _prune_delivered(self, match, state):
        """Drop frames that every known viewer for this match has consumed."""
        cursors = [
            per_match[match]
            for per_match in self._cursors.values()
            if match in per_match
        ]
        if not cursors:
            return
        floor = min(cursors)
        for seq in [seq for seq in state["frames"] if seq <= floor]:
            del state["frames"][seq]

    def _take(self, viewer, match, state, now_ts, limit, force):
        cursor = self._cursor_for(viewer, match)
        ready = []
        for seq in sorted(state["frames"]):
            if seq <= cursor:
                continue
            entry = state["frames"][seq]
            if not force and entry["deadline_ts"] > now_ts:
                break
            ready.append(entry)
            if len(ready) >= limit:
                break

        if not ready:
            return []

        last_seq = ready[-1]["seq"]
        self._set_cursor(viewer, match, last_seq)
        self._delivered += len(ready)
        self._prune_delivered(match, state)
        return [copy.deepcopy(entry) for entry in ready]

    def subscribe(self, viewer, *, match):
        with self._lock:
            active_match = self._viewers.get(viewer)
            if active_match == match:
                return {
                    "status": "existing",
                    "viewer": viewer,
                    "match": match,
                    "cursor": self._cursor_for(viewer, match),
                }

            if active_match is None and len(self._viewers) >= self.viewer_cap:
                raise SpectatorError("SPECT_FULL", {"viewer_cap": self.viewer_cap})

            if match not in self._matches:
                self._matches[match] = {
                    "delay_seconds": self.delay_seconds,
                    "paused": False,
                    "frames": {},
                    "timeline": [],
                    "seen": set(),
                    "dropped": 0,
                }

            self._viewers[viewer] = match
            self._cursors.setdefault(viewer, {})
            cursor = self._cursors[viewer].setdefault(match, 0)
            self._prune_delivered(match, self._matches[match])
            return {
                "status": "applied",
                "viewer": viewer,
                "match": match,
                "cursor": cursor,
            }

    def unsubscribe(self, viewer):
        with self._lock:
            match = self._require_viewer(viewer)
            del self._viewers[viewer]
            return {
                "status": "applied",
                "viewer": viewer,
                "match": match,
                "cursor": self._cursor_for(viewer, match),
            }

    def ingest(self, match, frame):
        with self._lock:
            state = self._require_match(match)
            entry = copy.deepcopy(frame)
            seq = entry["seq"]

            if seq in state["seen"]:
                return {
                    "status": "ignored",
                    "code": "SPECT_DUP_SEQ",
                    "match": match,
                    "seq": seq,
                }

            deadline_ts = (
                _parse_timestamp(entry["occurred_at"]) + state["delay_seconds"]
            )
            entry["deadline_ts"] = deadline_ts
            state["seen"].add(seq)
            state["timeline"].append(entry)
            state["frames"][seq] = entry

            while len(state["frames"]) > self.queue_cap:
                oldest = min(state["frames"])
                del state["frames"][oldest]
                state["dropped"] += 1

            return {
                "status": "applied",
                "match": match,
                "seq": seq,
                "deadline_ts": deadline_ts,
            }

    def poll(self, viewer, *, now, max_items=10):
        with self._lock:
            match = self._require_viewer(viewer)
            state = self._require_match(match)
            if state["paused"]:
                return []

            limit = max(0, int(max_items))
            if limit == 0:
                return []

            now_ts = _parse_timestamp(now)
            return self._take(viewer, match, state, now_ts, limit, force=False)

    def drain(self, viewer):
        """Force-deliver every pending frame for a viewer in sequence order."""
        with self._lock:
            match = self._require_viewer(viewer)
            state = self._require_match(match)
            cursor = self._cursor_for(viewer, match)
            pending = sum(1 for seq in state["frames"] if seq > cursor)
            if pending == 0:
                return []
            return self._take(
                viewer, match, state, float("inf"), pending, force=True
            )

    def set_delay(self, match, seconds):
        with self._lock:
            state = self._require_match(match)
            state["delay_seconds"] = int(seconds)
            return {
                "status": "applied",
                "match": match,
                "delay_seconds": state["delay_seconds"],
            }

    def pause(self, match):
        with self._lock:
            state = self._require_match(match)
            state["paused"] = True
            return {"status": "applied", "match": match, "paused": True}

    def resume(self, match):
        with self._lock:
            state = self._require_match(match)
            state["paused"] = False
            return {"status": "applied", "match": match, "paused": False}

    def queue_depth(self, match):
        with self._lock:
            state = self._require_match(match)
            return {
                "buffered": len(state["frames"]),
                "dropped": state["dropped"],
            }

    def backlog(self, viewer):
        with self._lock:
            match = self._require_viewer(viewer)
            state = self._require_match(match)
            cursor = self._cursor_for(viewer, match)
            return sum(1 for seq in state["frames"] if seq > cursor)

    def timeline(self, match):
        with self._lock:
            state = self._require_match(match)
            return copy.deepcopy(state["timeline"])

    def stats(self):
        with self._lock:
            return {
                "viewers": len(self._viewers),
                "matches": len(self._matches),
                "delivered": self._delivered,
            }

    def snapshot(self):
        with self._lock:
            matches = {}
            for name, state in self._matches.items():
                matches[name] = {
                    "delay_seconds": state["delay_seconds"],
                    "paused": state["paused"],
                    "frames": [
                        copy.deepcopy(state["frames"][seq])
                        for seq in sorted(state["frames"])
                    ],
                    "timeline": copy.deepcopy(state["timeline"]),
                    "seen": sorted(state["seen"]),
                    "dropped": state["dropped"],
                }
            return {
                "version": 1,
                "config": {
                    "delay_seconds": self.delay_seconds,
                    "queue_cap": self.queue_cap,
                    "viewer_cap": self.viewer_cap,
                },
                "viewers": dict(self._viewers),
                "cursors": {
                    viewer: dict(per_match)
                    for viewer, per_match in self._cursors.items()
                },
                "delivered": self._delivered,
                "matches": matches,
            }

    def restore(self, snapshot):
        with self._lock:
            if isinstance(snapshot, str):
                snapshot = json.loads(snapshot)
            snap = copy.deepcopy(snapshot)

            config = snap.get("config", {})
            self.delay_seconds = config.get("delay_seconds", self.delay_seconds)
            self.queue_cap = config.get("queue_cap", self.queue_cap)
            self.viewer_cap = config.get("viewer_cap", self.viewer_cap)

            matches = {}
            for name, raw in snap.get("matches", {}).items():
                frames = {}
                for entry in raw.get("frames", []):
                    frames[entry["seq"]] = entry
                matches[name] = {
                    "delay_seconds": raw.get("delay_seconds", self.delay_seconds),
                    "paused": bool(raw.get("paused", False)),
                    "frames": frames,
                    "timeline": copy.deepcopy(raw.get("timeline", [])),
                    "seen": set(raw.get("seen", [])),
                    "dropped": raw.get("dropped", 0),
                }

            cursors = {}
            for viewer, per_match in snap.get("cursors", {}).items():
                cursors[viewer] = {
                    match: int(cursor)
                    for match, cursor in per_match.items()
                }

            self._matches = matches
            self._viewers = dict(snap.get("viewers", {}))
            self._cursors = cursors
            self._delivered = snap.get("delivered", 0)
            return {"status": "restored"}
