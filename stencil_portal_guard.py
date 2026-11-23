"""模板传送门：房间/传送门图、递归层级、每帧预算与快照骨架。"""

import threading
from collections import deque

SNAPSHOT_VERSION = 1


class PortalError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class StencilPortal:
    """房间与传送门图、逐层模板标记、每帧可见性规划与快照恢复。"""

    def __init__(self, stencil_bits=8, max_depth=4, frame_budget=32):
        self._lock = threading.RLock()
        self._stencil_bits, self._max_depth, self._frame_budget = (
            self._validate_config(stencil_bits, max_depth, frame_budget))
        self._rooms = {}
        self._portals = {}
        self._next_room_seq = 1
        self._next_portal_seq = 1
        self._frame_active = False
        self._epoch = 0
        self._frame_passes = 0
        self._frame_plans = 0
        self._total_passes = 0
        self._total_plans = 0
        self._budget_rejected = 0

    @staticmethod
    def _is_int(value):
        return type(value) is int

    @staticmethod
    def _is_number(value):
        return (isinstance(value, (int, float))
                and not isinstance(value, bool))

    @classmethod
    def _validate_config(cls, stencil_bits, max_depth, frame_budget):
        if (not cls._is_int(stencil_bits) or not 1 <= stencil_bits <= 32
                or not cls._is_int(max_depth) or max_depth < 1
                or max_depth + 1 > stencil_bits
                or not cls._is_int(frame_budget) or frame_budget < 1):
            raise PortalError("PORTAL_BAD_CONFIG")
        return stencil_bits, max_depth, frame_budget

    @classmethod
    def _validate_bounds(cls, bounds):
        if not isinstance(bounds, (tuple, list)) or len(bounds) != 4:
            raise PortalError("PORTAL_BAD_ROOM")
        if any(not cls._is_int(value) for value in bounds):
            raise PortalError("PORTAL_BAD_ROOM")
        x0, y0, x1, y1 = bounds
        if x1 <= x0 or y1 <= y0:
            raise PortalError("PORTAL_BAD_ROOM")
        return (x0, y0, x1, y1)

    @classmethod
    def _validate_transform(cls, transform):
        if (not isinstance(transform, (tuple, list))
                or len(transform) != 16
                or any(not cls._is_number(value) for value in transform)):
            raise PortalError("PORTAL_BAD_TRANSFORM")
        return tuple(transform)

    @staticmethod
    def _require_id(value):
        return isinstance(value, str)

    def _plan_rows(self, start, max_depth):
        if not self._require_id(start) or start not in self._rooms:
            raise PortalError("PORTAL_UNKNOWN_ROOM")

        best = {start: (0, None)}
        portal_ids = sorted(self._portals)
        queue = deque([start])
        while queue:
            room_id = queue.popleft()
            depth = best[room_id][0]
            if depth >= max_depth:
                continue
            for portal_id in portal_ids:
                portal = self._portals[portal_id]
                if portal["source"] != room_id or not portal["enabled"]:
                    continue
                target = portal["target"]
                if target in best:
                    continue
                best[target] = (depth + 1, portal_id)
                queue.append(target)

        rows = []
        for room_id, (depth, via) in best.items():
            rows.append({
                "room": room_id,
                "depth": depth,
                "via": via,
                "ref": self.stencil_tag(depth),
                "clip_count": depth,
            })
        rows.sort(key=lambda row: (
            row["depth"],
            "" if row["via"] is None else row["via"],
            row["room"],
        ))
        return rows

    def register_room(self, room_id, *, bounds=(0, 0, 1, 1)):
        with self._lock:
            if not self._require_id(room_id):
                raise PortalError("PORTAL_BAD_ROOM")
            normalized = self._validate_bounds(bounds)
            existing = self._rooms.get(room_id)
            if existing is not None:
                if existing["bounds"] == normalized:
                    return {
                        "status": "unchanged",
                        "room": room_id,
                        "id": room_id,
                        "bounds": list(normalized),
                        "seq": existing["seq"],
                    }
                raise PortalError("PORTAL_DUP_ROOM")
            seq = self._next_room_seq
            self._next_room_seq += 1
            self._rooms[room_id] = {"bounds": normalized, "seq": seq}
            return {
                "status": "registered",
                "room": room_id,
                "id": room_id,
                "bounds": list(normalized),
                "seq": seq,
            }

    def unregister_room(self, room_id):
        with self._lock:
            if not self._require_id(room_id) or room_id not in self._rooms:
                raise PortalError("PORTAL_UNKNOWN_ROOM")
            removed = sorted(
                portal_id for portal_id, portal in self._portals.items()
                if portal["source"] == room_id or portal["target"] == room_id)
            del self._rooms[room_id]
            for portal_id in removed:
                del self._portals[portal_id]
            return {
                "status": "unregistered",
                "room": room_id,
                "id": room_id,
                "removed_portals": removed,
            }

    def register_portal(self, portal_id, *, source, target, transform,
                        enabled=True):
        with self._lock:
            if (not self._require_id(portal_id)
                    or not self._require_id(source)
                    or not self._require_id(target)
                    or source == target
                    or not isinstance(enabled, bool)):
                raise PortalError("PORTAL_BAD_PORTAL")
            if source not in self._rooms or target not in self._rooms:
                raise PortalError("PORTAL_UNKNOWN_ROOM")
            normalized = self._validate_transform(transform)

            existing = self._portals.get(portal_id)
            if existing is not None:
                if (existing["source"] == source
                        and existing["target"] == target
                        and existing["transform"] == normalized
                        and existing["enabled"] is enabled):
                    return {
                        "status": "unchanged",
                        "portal": portal_id,
                        "id": portal_id,
                        "source": source,
                        "target": target,
                        "enabled": enabled,
                        "seq": existing["seq"],
                    }
                raise PortalError("PORTAL_DUP_ID")

            seq = self._next_portal_seq
            self._next_portal_seq += 1
            self._portals[portal_id] = {
                "source": source,
                "target": target,
                "transform": normalized,
                "enabled": enabled,
                "seq": seq,
            }
            return {
                "status": "registered",
                "portal": portal_id,
                "id": portal_id,
                "source": source,
                "target": target,
                "enabled": enabled,
                "seq": seq,
            }

    def set_portal_enabled(self, portal_id, enabled):
        with self._lock:
            if not self._require_id(portal_id):
                raise PortalError("PORTAL_UNKNOWN_PORTAL")
            if not isinstance(enabled, bool):
                raise PortalError("PORTAL_BAD_PORTAL")
            portal = self._portals.get(portal_id)
            if portal is None:
                raise PortalError("PORTAL_UNKNOWN_PORTAL")
            changed = portal["enabled"] is not enabled
            if changed:
                portal["enabled"] = enabled
            return {
                "status": "updated" if changed else "unchanged",
                "portal": portal_id,
                "id": portal_id,
                "enabled": enabled,
                "changed": changed,
            }

    def describe_portal(self, portal_id):
        with self._lock:
            if not self._require_id(portal_id):
                raise PortalError("PORTAL_UNKNOWN_PORTAL")
            portal = self._portals.get(portal_id)
            if portal is None:
                raise PortalError("PORTAL_UNKNOWN_PORTAL")
            return {
                "id": portal_id,
                "portal": portal_id,
                "source": portal["source"],
                "target": portal["target"],
                "transform": list(portal["transform"]),
                "enabled": portal["enabled"],
                "seq": portal["seq"],
            }

    def stencil_tag(self, depth):
        with self._lock:
            if (not self._is_int(depth) or depth < 0
                    or depth > self._max_depth):
                raise PortalError("PORTAL_BAD_DEPTH")
            mask = (1 << self._stencil_bits) - 1
            return ((1 << (depth + 1)) - 1) & mask

    def reachable_rooms(self, start, max_depth=None):
        with self._lock:
            if not self._require_id(start) or start not in self._rooms:
                raise PortalError("PORTAL_UNKNOWN_ROOM")
            if max_depth is None:
                limit = self._max_depth
            else:
                if not self._is_int(max_depth) or max_depth < 0:
                    raise PortalError("PORTAL_BAD_DEPTH")
                limit = min(max_depth, self._max_depth)
            return sorted(row["room"]
                          for row in self._plan_rows(start, limit))

    def begin_frame(self):
        with self._lock:
            if self._frame_active:
                raise PortalError("PORTAL_FRAME_STATE")
            self._frame_active = True
            self._epoch += 1
            self._frame_passes = 0
            self._frame_plans = 0
            return self._epoch

    def end_frame(self):
        with self._lock:
            if not self._frame_active:
                raise PortalError("PORTAL_FRAME_STATE")
            result = {
                "frame": self._epoch,
                "passes": self._frame_passes,
                "budget_left": self._frame_budget - self._frame_passes,
            }
            self._frame_active = False
            return result

    def render_plan(self, camera_room):
        with self._lock:
            if not self._frame_active:
                raise PortalError("PORTAL_FRAME_STATE")
            plan = self._plan_rows(camera_room, self._max_depth)
            if self._frame_passes + len(plan) > self._frame_budget:
                self._budget_rejected += 1
                raise PortalError("PORTAL_FRAME_BUDGET")
            self._frame_passes += len(plan)
            self._frame_plans += 1
            self._total_passes += len(plan)
            self._total_plans += 1
            return plan

    def validate(self):
        with self._lock:
            connected = set()
            disabled = []
            ok = True
            for portal_id, portal in self._portals.items():
                if not portal["enabled"]:
                    disabled.append(portal_id)
                    continue
                if (portal["source"] not in self._rooms
                        or portal["target"] not in self._rooms
                        or portal["source"] == portal["target"]):
                    ok = False
                    continue
                connected.add(portal["source"])
                connected.add(portal["target"])
            isolated = sorted(room_id for room_id in self._rooms
                              if room_id not in connected)
            return {
                "ok": ok,
                "rooms": len(self._rooms),
                "portals": len(self._portals),
                "disabled": sorted(disabled),
                "isolated": isolated,
            }

    def stats(self):
        with self._lock:
            enabled = sum(1 for portal in self._portals.values()
                          if portal["enabled"])
            return {
                "rooms": len(self._rooms),
                "portals": len(self._portals),
                "enabled_portals": enabled,
                "disabled_portals": len(self._portals) - enabled,
                "passes": self._total_passes,
                "plans": self._total_plans,
                "total_passes": self._total_passes,
                "total_plans": self._total_plans,
                "frame_passes": self._frame_passes,
                "frame_plans": self._frame_plans,
                "budget_rejected": self._budget_rejected,
                "frame": self._epoch,
                "epoch": self._epoch,
                "frame_active": self._frame_active,
                "active": self._frame_active,
                "budget_left": self._frame_budget - self._frame_passes,
            }

    def snapshot(self):
        with self._lock:
            rooms = [
                {
                    "id": room_id,
                    "room_id": room_id,
                    "bounds": list(self._rooms[room_id]["bounds"]),
                    "seq": self._rooms[room_id]["seq"],
                }
                for room_id in sorted(self._rooms)
            ]
            portals = [
                {
                    "id": portal_id,
                    "portal_id": portal_id,
                    "source": self._portals[portal_id]["source"],
                    "target": self._portals[portal_id]["target"],
                    "transform": list(self._portals[portal_id]["transform"]),
                    "enabled": self._portals[portal_id]["enabled"],
                    "seq": self._portals[portal_id]["seq"],
                }
                for portal_id in sorted(self._portals)
            ]
            counters = {
                "passes": self._total_passes,
                "plans": self._total_plans,
                "budget_rejected": self._budget_rejected,
                "total_passes": self._total_passes,
                "total_plans": self._total_plans,
            }
            return {
                "version": SNAPSHOT_VERSION,
                "config": {
                    "stencil_bits": self._stencil_bits,
                    "max_depth": self._max_depth,
                    "frame_budget": self._frame_budget,
                },
                "stencil_bits": self._stencil_bits,
                "max_depth": self._max_depth,
                "frame_budget": self._frame_budget,
                "rooms": rooms,
                "portals": portals,
                "frame": {
                    "active": self._frame_active,
                    "number": self._epoch,
                    "frame": self._epoch,
                    "passes": self._frame_passes,
                    "plans": self._frame_plans,
                },
                "frame_active": self._frame_active,
                "frame_number": self._epoch,
                "frame_passes": self._frame_passes,
                "frame_plans": self._frame_plans,
                "counters": counters,
                "next_seq": {
                    "room": self._next_room_seq,
                    "portal": self._next_portal_seq,
                },
            }

    def restore(self, snap):
        with self._lock:
            if not isinstance(snap, dict):
                raise PortalError("PORTAL_SNAPSHOT_INVALID")
            if snap.get("version") != SNAPSHOT_VERSION:
                raise PortalError("PORTAL_SNAPSHOT_INVALID")

            config = snap.get("config")
            if config is None:
                config = {key: snap.get(key) for key in (
                    "stencil_bits", "max_depth", "frame_budget")}
            if not isinstance(config, dict):
                raise PortalError("PORTAL_SNAPSHOT_INVALID")
            try:
                stencil_bits, max_depth, frame_budget = self._validate_config(
                    config.get("stencil_bits"),
                    config.get("max_depth"),
                    config.get("frame_budget"))
            except PortalError:
                raise PortalError("PORTAL_SNAPSHOT_INVALID") from None
            for key, value in (
                    ("stencil_bits", stencil_bits),
                    ("max_depth", max_depth),
                    ("frame_budget", frame_budget)):
                if key in snap and snap[key] != value:
                    raise PortalError("PORTAL_SNAPSHOT_INVALID")

            rooms = {}
            next_room_seq = 1
            raw_rooms = snap.get("rooms")
            if isinstance(raw_rooms, dict):
                room_items = list(raw_rooms.items())
            elif isinstance(raw_rooms, list):
                room_items = []
                for item in raw_rooms:
                    if not isinstance(item, dict):
                        raise PortalError("PORTAL_SNAPSHOT_INVALID")
                    room_id = item.get(
                        "id", item.get("room_id", item.get("room")))
                    room_items.append((
                        room_id,
                        {"bounds": item.get("bounds"),
                         "seq": item.get("seq")},
                    ))
            else:
                raise PortalError("PORTAL_SNAPSHOT_INVALID")
            for room_id, raw in room_items:
                if not self._require_id(room_id) or room_id in rooms:
                    raise PortalError("PORTAL_SNAPSHOT_INVALID")
                if isinstance(raw, dict):
                    raw_bounds = raw.get("bounds")
                    seq = raw.get("seq")
                else:
                    raw_bounds = raw
                    seq = None
                try:
                    bounds = self._validate_bounds(raw_bounds)
                except PortalError:
                    raise PortalError("PORTAL_SNAPSHOT_INVALID") from None
                if seq is None:
                    seq = next_room_seq
                if not self._is_int(seq) or seq < 1:
                    raise PortalError("PORTAL_SNAPSHOT_INVALID")
                next_room_seq = max(next_room_seq, seq + 1)
                rooms[room_id] = {"bounds": bounds, "seq": seq}

            portals = {}
            next_portal_seq = 1
            raw_portals = snap.get("portals")
            if isinstance(raw_portals, dict):
                portal_items = list(raw_portals.items())
            elif isinstance(raw_portals, list):
                portal_items = []
                for item in raw_portals:
                    if not isinstance(item, dict):
                        raise PortalError("PORTAL_SNAPSHOT_INVALID")
                    portal_id = item.get(
                        "id", item.get("portal_id", item.get("portal")))
                    portal_items.append((portal_id, item))
            else:
                raise PortalError("PORTAL_SNAPSHOT_INVALID")
            for portal_id, raw in portal_items:
                if not self._require_id(portal_id) or portal_id in portals:
                    raise PortalError("PORTAL_SNAPSHOT_INVALID")
                if not isinstance(raw, dict):
                    raise PortalError("PORTAL_SNAPSHOT_INVALID")
                source = raw.get("source")
                target = raw.get("target")
                if (not self._require_id(source)
                        or not self._require_id(target)
                        or source == target
                        or source not in rooms or target not in rooms):
                    raise PortalError("PORTAL_SNAPSHOT_INVALID")
                try:
                    transform = self._validate_transform(
                        raw.get("transform"))
                except PortalError:
                    raise PortalError("PORTAL_SNAPSHOT_INVALID") from None
                enabled = raw.get("enabled")
                if not isinstance(enabled, bool):
                    raise PortalError("PORTAL_SNAPSHOT_INVALID")
                seq = raw.get("seq")
                if seq is None:
                    seq = next_portal_seq
                if not self._is_int(seq) or seq < 1:
                    raise PortalError("PORTAL_SNAPSHOT_INVALID")
                next_portal_seq = max(next_portal_seq, seq + 1)
                portals[portal_id] = {
                    "source": source,
                    "target": target,
                    "transform": transform,
                    "enabled": enabled,
                    "seq": seq,
                }

            raw_frame = snap.get("frame")
            if isinstance(raw_frame, dict):
                frame_active = raw_frame.get("active")
                frame_number = raw_frame.get(
                    "number", raw_frame.get("frame"))
                frame_passes = raw_frame.get("passes")
                frame_plans = raw_frame.get("plans", 0)
            else:
                frame_active = snap.get("frame_active")
                frame_number = snap.get("frame_number", raw_frame)
                frame_passes = snap.get("frame_passes")
                frame_plans = snap.get("frame_plans", 0)
            if (not isinstance(frame_active, bool)
                    or not self._is_int(frame_number) or frame_number < 0
                    or not self._is_int(frame_passes) or frame_passes < 0
                    or frame_passes > frame_budget
                    or not self._is_int(frame_plans) or frame_plans < 0
                    or (frame_active and frame_number < 1)):
                raise PortalError("PORTAL_SNAPSHOT_INVALID")
            for key, value in (
                    ("frame_active", frame_active),
                    ("frame_number", frame_number),
                    ("frame_passes", frame_passes),
                    ("frame_plans", frame_plans)):
                if key in snap and snap[key] != value:
                    raise PortalError("PORTAL_SNAPSHOT_INVALID")

            counters = snap.get("counters")
            if not isinstance(counters, dict):
                raise PortalError("PORTAL_SNAPSHOT_INVALID")
            total_passes = counters.get(
                "passes", counters.get("total_passes"))
            total_plans = counters.get("plans", counters.get("total_plans"))
            budget_rejected = counters.get("budget_rejected")
            if (not self._is_int(total_passes) or total_passes < 0
                    or not self._is_int(total_plans) or total_plans < 0
                    or not self._is_int(budget_rejected)
                    or budget_rejected < 0):
                raise PortalError("PORTAL_SNAPSHOT_INVALID")

            next_seq = snap.get("next_seq")
            if next_seq is not None:
                if not isinstance(next_seq, dict):
                    raise PortalError("PORTAL_SNAPSHOT_INVALID")
                room_next = next_seq.get("room", next_room_seq)
                portal_next = next_seq.get("portal", next_portal_seq)
                if (not self._is_int(room_next) or room_next < 1
                        or not self._is_int(portal_next) or portal_next < 1):
                    raise PortalError("PORTAL_SNAPSHOT_INVALID")
                next_room_seq = max(next_room_seq, room_next)
                next_portal_seq = max(next_portal_seq, portal_next)

            self._stencil_bits = stencil_bits
            self._max_depth = max_depth
            self._frame_budget = frame_budget
            self._rooms = rooms
            self._portals = portals
            self._next_room_seq = next_room_seq
            self._next_portal_seq = next_portal_seq
            self._frame_active = frame_active
            self._epoch = frame_number
            self._frame_passes = frame_passes
            self._frame_plans = frame_plans
            self._total_passes = total_passes
            self._total_plans = total_plans
            self._budget_rejected = budget_rejected
            return {
                "rooms": len(rooms),
                "portals": len(portals),
                "enabled_portals": sum(
                    1 for portal in portals.values() if portal["enabled"]),
                "frame": self._epoch,
                "frame_active": self._frame_active,
            }

    def reset(self):
        with self._lock:
            removed = len(self._rooms) + len(self._portals)
            self._rooms = {}
            self._portals = {}
            self._next_room_seq = 1
            self._next_portal_seq = 1
            self._frame_active = False
            self._epoch = 0
            self._frame_passes = 0
            self._frame_plans = 0
            self._total_passes = 0
            self._total_plans = 0
            self._budget_rejected = 0
            return removed
