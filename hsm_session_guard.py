"""HSM session pool with monotonic object handles and rotation."""

import copy
import re
import threading
from datetime import datetime, timedelta, timezone


_HEX64 = re.compile(r"[0-9a-fA-F]{64}\Z")
_OBJECT_KINDS = ("session", "token")
_SNAPSHOT_VERSION = 1


class HsmError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


def _parse_time(value):
    if isinstance(value, datetime):
        parsed = value
    else:
        text = str(value)
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _format_time(value):
    return value.astimezone(timezone.utc).isoformat()


def _valid_digest(value):
    return isinstance(value, str) and _HEX64.fullmatch(value) is not None


class HsmSessionGuard:
    """Session pool and object-handle lifecycle for a shared HSM slot."""

    def __init__(self, *, max_sessions_per_app=4, max_objects=64,
                 idle_timeout=900, max_failed_logins=3, handle_floor=1000,
                 audit_capacity=256):
        self.max_sessions_per_app = int(max_sessions_per_app)
        self.max_objects = int(max_objects)
        self.idle_timeout = int(idle_timeout)
        self.max_failed_logins = int(max_failed_logins)
        self.handle_floor = int(handle_floor)
        self.audit_capacity = int(audit_capacity)
        self._lock = threading.RLock()
        self._sessions = {}
        self._objects = {}
        self._handle_map = {}
        self._stale = set()
        self._retired = set()
        self._app_seq = {}
        self._app_pins = {}
        self._failures = {}
        self._locked = set()
        self._next_handle = int(handle_floor)
        self._next_object_id = 1
        self._generation = 0
        self._audit = []
        self._seq = 0

    # ------------------------------------------------------------------
    # Internal helpers.  Every call below is made while holding _lock.
    # ------------------------------------------------------------------
    def _audit_event(self, action, *, session=None, app=None, now=None,
                     **detail):
        self._seq += 1
        entry = {
            "seq": self._seq,
            "action": action,
            "session": session,
            "app": app,
            "at": _format_time(now) if isinstance(now, datetime) else now,
        }
        if detail:
            entry["detail"] = detail
        self._audit.append(entry)
        if self.audit_capacity <= 0:
            self._audit.clear()
        else:
            while len(self._audit) > self.audit_capacity:
                self._audit.pop(0)
        return entry

    def _allocate_handle(self):
        handle = self._next_handle
        self._next_handle += 1
        self._retired.add(handle)
        self._generation += 1
        return handle

    def _destroy_object(self, obj):
        object_id = obj["id"]
        for handle in obj.get("history", ()):
            self._handle_map.pop(handle, None)
            self._stale.discard(handle)
        self._objects.pop(object_id, None)
        obj["alive"] = False

    def _expire_session(self, session, now):
        """Close an idle session and remove only its private objects."""
        destroyed = 0
        if session["status"] != "open":
            return destroyed
        session["status"] = "closed"
        session["reason"] = "expired"
        session["closed_at"] = _format_time(now)
        for obj in list(self._objects.values()):
            if obj["kind"] == "session" and obj["owner"] == session["id"]:
                self._destroy_object(obj)
                destroyed += 1
        return destroyed

    def _prepare_session(self, session_id, now, *, touch=True):
        session = self._sessions.get(session_id)
        if session is None:
            raise HsmError("HSM_SESSION_UNKNOWN", {"session": session_id})
        if session["status"] == "open":
            idle = timedelta(seconds=self.idle_timeout)
            if now - session["last_active"] >= idle:
                self._expire_session(session, now)
                raise HsmError("HSM_SESSION_EXPIRED", {"session": session_id})
            if touch:
                session["last_active"] = now
        else:
            raise HsmError("HSM_SESSION_CLOSED", {"session": session_id})
        return session

    def _visible_objects(self, session):
        visible = []
        for obj in self._objects.values():
            if obj["kind"] == "session":
                if obj["owner"] == session["id"]:
                    visible.append(obj)
            elif obj["kind"] == "token" and obj["app"] == session["app"]:
                visible.append(obj)
        visible.sort(key=lambda item: item["handle"])
        return visible

    def _resolve_handle(self, handle):
        if isinstance(handle, bool) or not isinstance(handle, int):
            raise HsmError("HSM_HANDLE_UNKNOWN", {"handle": handle})
        object_id = self._handle_map.get(handle)
        if object_id is None:
            raise HsmError("HSM_HANDLE_UNKNOWN", {"handle": handle})
        obj = self._objects.get(object_id)
        if obj is None:
            raise HsmError("HSM_HANDLE_UNKNOWN", {"handle": handle})
        if handle in self._stale or obj["handle"] != handle:
            raise HsmError("HSM_HANDLE_STALE", {"handle": handle})
        return obj

    def _owned_objects(self, session_id):
        return [obj for obj in self._objects.values()
                if obj["owner"] == session_id]

    # ------------------------------------------------------------------
    # Authentication and session lifecycle.
    # ------------------------------------------------------------------
    def login(self, app_id, *, pin_digest, slot="slot-0",
              now="2026-11-23T09:00:00+00:00"):
        if not _valid_digest(pin_digest):
            raise HsmError("HSM_PIN_INVALID")
        now_dt = _parse_time(now)
        with self._lock:
            if app_id in self._locked:
                raise HsmError("HSM_PIN_LOCKED", {"app": app_id})

            known_pin = self._app_pins.get(app_id)
            if known_pin is not None and pin_digest != known_pin:
                failures = self._failures.get(app_id, 0) + 1
                self._failures[app_id] = failures
                if failures >= self.max_failed_logins:
                    self._locked.add(app_id)
                raise HsmError("HSM_AUTH_FAILED", {"app": app_id})

            self._app_pins.setdefault(app_id, pin_digest)

            # An idle session is no longer an active consumer of the app's
            # session quota.  Expiring it here also releases its objects.
            for session in list(self._sessions.values()):
                if session["app"] != app_id or session["status"] != "open":
                    continue
                if now_dt - session["last_active"] >= timedelta(
                        seconds=self.idle_timeout):
                    self._expire_session(session, now_dt)

            for session in self._sessions.values():
                if (session["app"] == app_id
                        and session["slot"] == slot
                        and session["status"] == "open"):
                    session["last_active"] = now_dt
                    self._failures[app_id] = 0
                    self._audit_event(
                        "session.reuse", session=session["id"], app=app_id,
                        now=now_dt, slot=slot)
                    return {
                        "session": session["id"],
                        "app": app_id,
                        "slot": slot,
                        "status": "reused",
                    }

            active = sum(
                1 for session in self._sessions.values()
                if session["app"] == app_id and session["status"] == "open")
            if active >= self.max_sessions_per_app:
                raise HsmError("HSM_SESSION_LIMIT", {"app": app_id})

            sequence = self._app_seq.get(app_id, 0) + 1
            self._app_seq[app_id] = sequence
            session_id = "%s-%d" % (app_id, sequence)
            session = {
                "id": session_id,
                "app": app_id,
                "slot": slot,
                "status": "open",
                "created": _format_time(now_dt),
                "last_active": now_dt,
                "reason": None,
                "closed_at": None,
            }
            self._sessions[session_id] = session
            self._failures[app_id] = 0
            self._audit_event(
                "session.login", session=session_id, app=app_id,
                now=now_dt, slot=slot)
            return {
                "session": session_id,
                "app": app_id,
                "slot": slot,
                "status": "created",
            }

    def unlock_app(self, app_id):
        with self._lock:
            self._locked.discard(app_id)
            self._failures[app_id] = 0
            self._audit_event("app.unlock", app=app_id)
            return {"app": app_id, "locked": False, "failures": 0}

    def logout(self, session_id, *, reason="closed",
               now="2026-11-23T09:00:00+00:00"):
        now_dt = _parse_time(now)
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                raise HsmError("HSM_SESSION_UNKNOWN", {"session": session_id})
            if session["status"] == "open":
                if now_dt - session["last_active"] >= timedelta(
                        seconds=self.idle_timeout):
                    self._expire_session(session, now_dt)
                    raise HsmError("HSM_SESSION_EXPIRED",
                                   {"session": session_id})
            else:
                return {
                    "session": session_id,
                    "status": "closed",
                    "destroyed": 0,
                    "reason": session.get("reason") or reason,
                }

            destroyed = 0
            for obj in list(self._objects.values()):
                if (obj["kind"] == "session"
                        and obj["owner"] == session_id):
                    self._destroy_object(obj)
                    destroyed += 1
            session["status"] = "closed"
            session["reason"] = reason
            session["closed_at"] = _format_time(now_dt)
            self._audit_event(
                "session.logout", session=session_id, app=session["app"],
                now=now_dt, reason=reason, destroyed=destroyed)
            return {
                "session": session_id,
                "status": "closed",
                "destroyed": destroyed,
                "reason": reason,
            }

    def heartbeat(self, session_id, *, now="2026-11-23T09:00:00+00:00"):
        now_dt = _parse_time(now)
        with self._lock:
            session = self._prepare_session(session_id, now_dt)
            self._audit_event(
                "session.heartbeat", session=session_id,
                app=session["app"], now=now_dt)
            return {"session": session_id, "status": "open"}

    # ------------------------------------------------------------------
    # Objects and handles.
    # ------------------------------------------------------------------
    def open_object(self, session_id, *, label, value_digest, kind="session",
                    max_uses=None, now="2026-11-23T09:00:00+00:00"):
        now_dt = _parse_time(now)
        with self._lock:
            session = self._prepare_session(session_id, now_dt)
            if kind not in _OBJECT_KINDS:
                raise HsmError("HSM_OBJECT_KIND_INVALID", {"kind": kind})
            if not isinstance(label, str) or not label.strip():
                raise HsmError("HSM_LABEL_INVALID", {"label": label})
            if not _valid_digest(value_digest):
                raise HsmError("HSM_DIGEST_INVALID")
            if (max_uses is not None
                    and (isinstance(max_uses, bool)
                         or not isinstance(max_uses, int)
                         or max_uses < 1)):
                raise HsmError("HSM_USE_LIMIT_INVALID",
                               {"max_uses": max_uses})
            if len(self._objects) >= self.max_objects:
                raise HsmError("HSM_OBJECT_LIMIT")

            handle = self._allocate_handle()
            object_id = self._next_object_id
            self._next_object_id += 1
            obj = {
                "id": object_id,
                "app": session["app"],
                "owner": session_id,
                "kind": kind,
                "label": label,
                "digest": value_digest,
                "max_uses": max_uses,
                "uses": 0,
                "handle": handle,
                "history": [handle],
                "created": _format_time(now_dt),
            }
            self._objects[object_id] = obj
            self._handle_map[handle] = object_id
            self._audit_event(
                "object.open", session=session_id, app=session["app"],
                now=now_dt, handle=handle, label=label, kind=kind,
                max_uses=max_uses)
            return {
                "handle": handle,
                "label": label,
                "kind": kind,
                "uses": 0,
                "max_uses": max_uses,
            }

    def find_objects(self, session_id, *, label=None, kind=None,
                     now="2026-11-23T09:00:00+00:00"):
        now_dt = _parse_time(now)
        with self._lock:
            session = self._prepare_session(session_id, now_dt)
            rows = []
            for obj in self._visible_objects(session):
                if label is not None and obj["label"] != label:
                    continue
                if kind is not None and obj["kind"] != kind:
                    continue
                rows.append({
                    "handle": obj["handle"],
                    "label": obj["label"],
                    "kind": obj["kind"],
                    "uses": obj["uses"],
                })
            return rows

    def use_object(self, session_id, handle, *,
                   now="2026-11-23T09:00:00+00:00"):
        now_dt = _parse_time(now)
        with self._lock:
            session = self._prepare_session(session_id, now_dt)
            obj = self._resolve_handle(handle)
            if obj["kind"] == "session":
                if obj["owner"] != session_id:
                    raise HsmError("HSM_HANDLE_FOREIGN", {"handle": handle})
            elif obj["app"] != session["app"]:
                raise HsmError("HSM_HANDLE_FOREIGN", {"handle": handle})

            if (obj["max_uses"] is not None
                    and obj["uses"] >= obj["max_uses"]):
                raise HsmError("HSM_USE_LIMIT", {"handle": handle})

            obj["uses"] += 1
            self._audit_event(
                "object.use", session=session_id, app=session["app"],
                now=now_dt, handle=handle, label=obj["label"],
                uses=obj["uses"])
            return {
                "handle": handle,
                "label": obj["label"],
                "kind": obj["kind"],
                "uses": obj["uses"],
                "max_uses": obj["max_uses"],
            }

    def destroy_object(self, session_id, handle, *,
                       now="2026-11-23T09:00:00+00:00"):
        now_dt = _parse_time(now)
        with self._lock:
            session = self._prepare_session(session_id, now_dt)
            obj = self._resolve_handle(handle)
            if obj["owner"] != session_id:
                raise HsmError("HSM_HANDLE_FOREIGN", {"handle": handle})
            label = obj["label"]
            self._destroy_object(obj)
            self._audit_event(
                "object.destroy", session=session_id, app=session["app"],
                now=now_dt, handle=handle, label=label)
            return {"handle": handle, "destroyed": 1}

    def rotate_handles(self, session_id, *,
                       now="2026-11-23T09:00:00+00:00"):
        now_dt = _parse_time(now)
        with self._lock:
            session = self._prepare_session(session_id, now_dt)
            visible = self._visible_objects(session)

            # Allocate every replacement first, then publish the complete
            # mapping.  The lock makes the remap indivisible to other
            # callers: a handle is either old/stale or new/usable.
            replacements = [self._allocate_handle() for _ in visible]
            mappings = []
            for obj, new_handle in zip(visible, replacements):
                old_handle = obj["handle"]
                self._stale.add(old_handle)
                obj["history"].append(new_handle)
                obj["handle"] = new_handle
                self._handle_map[new_handle] = obj["id"]
                mappings.append({"from": old_handle, "to": new_handle})

            mappings.sort(key=lambda item: item["from"])
            self._audit_event(
                "object.rotate", session=session_id, app=session["app"],
                now=now_dt, rotated=len(mappings))
            return {"rotated": len(mappings), "handles": mappings}

    # ------------------------------------------------------------------
    # Idle sweeping, inspection, audit and persistence.
    # ------------------------------------------------------------------
    def sweep(self, now="2026-11-23T10:00:00+00:00"):
        now_dt = _parse_time(now)
        with self._lock:
            closed = 0
            destroyed = 0
            idle = timedelta(seconds=self.idle_timeout)
            for session in list(self._sessions.values()):
                if (session["status"] == "open"
                        and now_dt - session["last_active"] >= idle):
                    destroyed += self._expire_session(session, now_dt)
                    closed += 1
            if closed:
                self._audit_event(
                    "session.sweep", now=now_dt, sessions=closed,
                    objects=destroyed)
            return {"sessions": closed, "objects": destroyed}

    def session_state(self, session_id):
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                raise HsmError("HSM_SESSION_UNKNOWN",
                               {"session": session_id})
            owned = len(self._owned_objects(session_id))
            visible = len(self._visible_objects(session))
            return {
                "session": session_id,
                "app": session["app"],
                "slot": session["slot"],
                "status": session["status"],
                "created": session["created"],
                "last_active": _format_time(session["last_active"]),
                "reason": session.get("reason"),
                "closed_at": session.get("closed_at"),
                "objects": owned,
                "visible_objects": visible,
            }

    def stats(self):
        with self._lock:
            active = sum(
                1 for session in self._sessions.values()
                if session["status"] == "open")
            apps = {session["app"] for session in self._sessions.values()}
            return {
                "sessions": active,
                "objects": len(self._objects),
                "handles": self._generation,
                "generation": self._generation,
                "next_handle": self._next_handle,
                "apps": len(apps),
                "audit": len(self._audit),
                "locked": len(self._locked),
            }

    def audit(self, limit=20):
        with self._lock:
            try:
                count = int(limit)
            except (TypeError, ValueError):
                count = 20
            if count <= 0:
                return []
            entries = list(reversed(self._audit))[:count]
            return copy.deepcopy(entries)

    def snapshot(self):
        with self._lock:
            sessions = {}
            for session_id, session in self._sessions.items():
                sessions[session_id] = {
                    "id": session["id"],
                    "app": session["app"],
                    "slot": session["slot"],
                    "status": session["status"],
                    "created": session["created"],
                    "last_active": _format_time(session["last_active"]),
                    "reason": session.get("reason"),
                    "closed_at": session.get("closed_at"),
                }
            objects = []
            for obj in self._objects.values():
                objects.append({
                    "id": obj["id"],
                    "app": obj["app"],
                    "owner": obj["owner"],
                    "kind": obj["kind"],
                    "label": obj["label"],
                    "digest": obj["digest"],
                    "max_uses": obj["max_uses"],
                    "uses": obj["uses"],
                    "handle": obj["handle"],
                    "history": sorted(set(obj["history"])),
                    "created": obj["created"],
                })
            return {
                "version": _SNAPSHOT_VERSION,
                "generation": self._generation,
                "next_handle": self._next_handle,
                "next_object_id": self._next_object_id,
                "seq": self._seq,
                "app_seq": dict(self._app_seq),
                "app_pins": dict(self._app_pins),
                "failures": dict(self._failures),
                "locked": sorted(self._locked),
                "sessions": sessions,
                "objects": objects,
                "used_handles": sorted(self._retired),
                "audit": copy.deepcopy(self._audit),
            }

    def restore(self, snap):
        with self._lock:
            if not isinstance(snap, dict):
                raise HsmError("HSM_SNAPSHOT_INVALID")
            if snap.get("version") != _SNAPSHOT_VERSION:
                raise HsmError("HSM_SNAPSHOT_INVALID")

            try:
                generation = int(snap["generation"])
                next_handle = int(snap["next_handle"])
                next_object_id = int(snap.get("next_object_id", 1))
                seq = int(snap.get("seq", 0))
                if next_handle < self.handle_floor:
                    raise ValueError("bad handle floor")
                if generation < 0 or next_object_id < 1:
                    raise ValueError("bad counters")

                sessions = {}
                for session_id, raw in snap.get("sessions", {}).items():
                    if not isinstance(raw, dict):
                        raise ValueError("bad session")
                    status = raw["status"]
                    if status not in ("open", "closed"):
                        raise ValueError("bad session status")
                    last_active = _parse_time(raw["last_active"])
                    sessions[str(session_id)] = {
                        "id": str(raw.get("id", session_id)),
                        "app": raw["app"],
                        "slot": raw["slot"],
                        "status": status,
                        "created": raw["created"],
                        "last_active": last_active,
                        "reason": raw.get("reason"),
                        "closed_at": raw.get("closed_at"),
                    }

                objects = {}
                handle_map = {}
                stale = set()
                for raw in snap.get("objects", []):
                    if not isinstance(raw, dict):
                        raise ValueError("bad object")
                    object_id = int(raw["id"])
                    kind = raw["kind"]
                    if kind not in _OBJECT_KINDS:
                        raise ValueError("bad object kind")
                    label = raw["label"]
                    if not isinstance(label, str) or not label.strip():
                        raise ValueError("bad object label")
                    if not _valid_digest(raw["digest"]):
                        raise ValueError("bad object digest")
                    max_uses = raw.get("max_uses")
                    uses = int(raw.get("uses", 0))
                    if (max_uses is not None
                            and (isinstance(max_uses, bool)
                                 or not isinstance(max_uses, int)
                                 or max_uses < 1)):
                        raise ValueError("bad use limit")
                    if uses < 0:
                        raise ValueError("bad use count")
                    current_handle = int(raw["handle"])
                    history = [int(item) for item in raw.get(
                        "history", [current_handle])]
                    if current_handle not in history:
                        history.append(current_handle)
                    history = sorted(set(history))
                    if object_id in objects:
                        raise ValueError("duplicate object")
                    for handle in history:
                        if handle in handle_map:
                            raise ValueError("duplicate handle")
                        handle_map[handle] = object_id
                    stale.update(
                        handle for handle in history
                        if handle != current_handle)
                    objects[object_id] = {
                        "id": object_id,
                        "app": raw["app"],
                        "owner": raw["owner"],
                        "kind": kind,
                        "label": label,
                        "digest": raw["digest"],
                        "max_uses": max_uses,
                        "uses": uses,
                        "handle": current_handle,
                        "history": history,
                        "created": raw.get("created"),
                        "alive": True,
                    }
                if any(handle >= next_handle for handle in handle_map):
                    raise ValueError("handle beyond counter")

                app_seq = {str(key): int(value)
                           for key, value in snap.get("app_seq", {}).items()}
                app_pins = {str(key): value
                            for key, value in snap.get("app_pins", {}).items()}
                failures = {str(key): int(value)
                            for key, value in snap.get("failures", {}).items()}
                locked = {str(item) for item in snap.get("locked", [])}
                used = {int(item) for item in snap.get("used_handles", [])}
                used.update(handle_map)
                audit = copy.deepcopy(snap.get("audit", []))
                if not isinstance(audit, list):
                    raise ValueError("bad audit")
            except (KeyError, TypeError, ValueError, AttributeError):
                raise HsmError("HSM_SNAPSHOT_INVALID")

            if generation < self._generation:
                raise HsmError("HSM_SNAPSHOT_STALE")
            if next_handle < self._next_handle:
                raise HsmError("HSM_SNAPSHOT_STALE")

            # Keep monotonic counters monotonic even when restoring a
            # snapshot that predates a non-handle-allocating operation.
            seq = max(seq, self._seq)
            next_object_id = max(next_object_id, self._next_object_id)

            if self.audit_capacity <= 0:
                audit = []
            elif len(audit) > self.audit_capacity:
                audit = audit[-self.audit_capacity:]

            self._sessions = sessions
            self._objects = objects
            self._handle_map = handle_map
            self._stale = stale
            self._retired = used
            self._app_seq = app_seq
            self._app_pins = app_pins
            self._failures = failures
            self._locked = locked
            self._next_handle = next_handle
            self._next_object_id = next_object_id
            self._generation = generation
            self._seq = seq
            self._audit = audit
