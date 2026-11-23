"""Reflection probe capture queue: cubemap faces, mip chain and priorities."""

import math
import threading

SNAPSHOT_VERSION = 1
FACES = ("px", "nx", "py", "ny", "pz", "nz")
_FACE_SET = frozenset(FACES)


class ReflectionProbeError(ValueError):
    """Domain error carrying a stable machine-readable code."""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class ReflectionProbe:
    """Probe registry, prioritized capture queue and time-sliced dispatch."""

    def __init__(self, *, max_probes: int = 64, face_size: int = 128,
                 mip_levels: int = 6, frame_budget: int = 4):
        if (not isinstance(max_probes, int) or isinstance(max_probes, bool)
                or max_probes < 0):
            raise ReflectionProbeError("RP_INVALID_CONFIG")
        if (not isinstance(face_size, int) or isinstance(face_size, bool)
                or face_size < 4 or face_size > 1024
                or face_size & (face_size - 1)):
            raise ReflectionProbeError("RP_INVALID_CONFIG")
        max_mip_levels = face_size.bit_length()
        if (not isinstance(mip_levels, int) or isinstance(mip_levels, bool)
                or mip_levels < 1 or mip_levels > max_mip_levels):
            raise ReflectionProbeError("RP_INVALID_CONFIG")
        if (not isinstance(frame_budget, int)
                or isinstance(frame_budget, bool) or frame_budget < 0):
            raise ReflectionProbeError("RP_INVALID_CONFIG")

        self.max_probes = max_probes
        self.face_size = face_size
        self.mip_levels = mip_levels
        self.frame_budget = frame_budget
        self._lock = threading.RLock()
        self._probes = {}
        self._queue = []
        self._requests = 0
        self._captures = 0
        self._next_seq = 1
        self._dispatches = {}

    @staticmethod
    def _valid_position(position):
        try:
            if len(position) != 3:
                return None
            values = tuple(float(value) for value in position)
        except (TypeError, ValueError):
            return None
        if not all(math.isfinite(value) for value in values):
            return None
        return values

    @staticmethod
    def _valid_priority(priority):
        return (isinstance(priority, int)
                and not isinstance(priority, bool) and priority >= 0)

    @staticmethod
    def _capture_for(probe_id, queue):
        for capture in queue:
            if capture["probe_id"] == probe_id:
                return capture
        return None

    @staticmethod
    def _sorted_queue(queue):
        return sorted(queue, key=lambda item: (-item["priority"], item["seq"]))

    def register_probe(self, probe_id: str, *,
                       position: tuple[float, float, float], radius: float,
                       priority: int = 0, static: bool = False) -> dict:
        if not isinstance(probe_id, str) or not probe_id:
            raise ReflectionProbeError(
                "RP_INVALID_PROBE", {"field": "probe_id"})
        values = self._valid_position(position)
        if values is None:
            raise ReflectionProbeError(
                "RP_INVALID_PROBE", {"field": "position"})
        try:
            radius_value = float(radius)
        except (TypeError, ValueError):
            raise ReflectionProbeError(
                "RP_INVALID_PROBE", {"field": "radius"})
        if isinstance(radius, bool) or not math.isfinite(radius_value) \
                or radius_value <= 0:
            raise ReflectionProbeError(
                "RP_INVALID_PROBE", {"field": "radius"})
        if not self._valid_priority(priority):
            raise ReflectionProbeError(
                "RP_INVALID_PROBE", {"field": "priority"})
        if not isinstance(static, bool):
            raise ReflectionProbeError(
                "RP_INVALID_PROBE", {"field": "static"})

        with self._lock:
            if probe_id in self._probes:
                raise ReflectionProbeError(
                    "RP_DUPLICATE_PROBE", {"probe_id": probe_id})
            if len(self._probes) >= self.max_probes:
                raise ReflectionProbeError(
                    "RP_PROBE_LIMIT", {"max_probes": self.max_probes})
            self._probes[probe_id] = {
                "position": values,
                "radius": radius_value,
                "priority": priority,
                "static": static,
                "checksum": None,
            }
        return {
            "status": "registered",
            "probe_id": probe_id,
            "position": values,
            "radius": radius_value,
            "priority": priority,
            "static": static,
        }

    def unregister_probe(self, probe_id: str) -> dict:
        with self._lock:
            if probe_id not in self._probes:
                raise ReflectionProbeError(
                    "RP_UNKNOWN_PROBE", {"probe_id": probe_id})
            del self._probes[probe_id]
            self._queue = [
                item for item in self._queue
                if item["probe_id"] != probe_id
            ]
            self._dispatches = {
                frame: result for frame, result in self._dispatches.items()
                if probe_id not in result["started"]
            }
        return {"status": "unregistered", "probe_id": probe_id}

    def request_capture(self, probe_id: str, *, frame: int,
                        reason: str = "manual") -> dict:
        with self._lock:
            probe = self._probes.get(probe_id)
            if probe is None:
                raise ReflectionProbeError(
                    "RP_UNKNOWN_PROBE", {"probe_id": probe_id})
            if reason == "auto" and probe["static"]:
                return {
                    "status": "ignored",
                    "code": "RP_STATIC_PROBE",
                    "probe_id": probe_id,
                }
            if self._capture_for(probe_id, self._queue) is not None:
                return {
                    "status": "ignored",
                    "code": "RP_ALREADY_PENDING",
                    "probe_id": probe_id,
                }

            seq = self._next_seq
            capture = {
                "probe_id": probe_id,
                "priority": probe["priority"],
                "seq": seq,
                "status": "pending",
                "reason": reason,
                "request_frame": frame,
                "dispatch_frame": None,
                "previous_checksum": probe["checksum"],
                "faces": {},
            }
            self._next_seq += 1
            self._requests += 1
            self._queue.append(capture)
        return {
            "status": "queued",
            "probe_id": probe_id,
            "priority": capture["priority"],
            "seq": seq,
            "frame": frame,
            "reason": reason,
        }

    def dispatch(self, frame: int) -> dict:
        with self._lock:
            cached = self._dispatches.get(frame)
            if cached is not None:
                return {
                    "status": "cached",
                    "frame": frame,
                    "started": list(cached["started"]),
                    "deferred": cached["deferred"],
                }

            queued = self._sorted_queue(self._queue)
            pending = [item for item in queued if item["status"] == "pending"]
            started = []
            for capture in pending[:self.frame_budget]:
                capture["status"] = "started"
                capture["dispatch_frame"] = frame
                capture["faces"] = {}
                started.append(capture["probe_id"])

            deferred = sum(
                1 for item in self._queue
                if item["status"] == "pending"
                and item["request_frame"] == frame)
            result = {
                "frame": frame,
                "started": started,
                "deferred": deferred,
            }
            self._dispatches[frame] = {
                "started": list(started),
                "deferred": deferred,
            }
        return {
            "status": "dispatched",
            "frame": frame,
            "started": list(started),
            "deferred": deferred,
        }

    def capture_face(self, probe_id: str, face: str, frame: int, *,
                     checksum: str) -> dict:
        with self._lock:
            if probe_id not in self._probes:
                raise ReflectionProbeError(
                    "RP_UNKNOWN_PROBE", {"probe_id": probe_id})
            if face not in _FACE_SET:
                raise ReflectionProbeError(
                    "RP_INVALID_FACE", {"face": face})
            capture = self._capture_for(probe_id, self._queue)
            if capture is None:
                raise ReflectionProbeError(
                    "RP_NO_ACTIVE_CAPTURE", {"probe_id": probe_id})
            if capture["status"] != "started":
                raise ReflectionProbeError(
                    "RP_NOT_DISPATCHED", {"probe_id": probe_id})
            if capture["dispatch_frame"] != frame:
                raise ReflectionProbeError(
                    "RP_STALE_FRAME",
                    {"frame": frame,
                     "dispatch_frame": capture["dispatch_frame"]})
            if face in capture["faces"]:
                raise ReflectionProbeError(
                    "RP_DUP_FACE", {"probe_id": probe_id, "face": face})
            capture["faces"][face] = checksum
        return {
            "status": "applied",
            "probe_id": probe_id,
            "face": face,
            "frame": frame,
            "checksum": checksum,
        }

    def complete_capture(self, probe_id: str, *, frame: int,
                         checksum: str) -> dict:
        with self._lock:
            if probe_id not in self._probes:
                raise ReflectionProbeError(
                    "RP_UNKNOWN_PROBE", {"probe_id": probe_id})
            capture = self._capture_for(probe_id, self._queue)
            if capture is None:
                raise ReflectionProbeError(
                    "RP_NO_ACTIVE_CAPTURE", {"probe_id": probe_id})
            if capture["status"] != "started":
                raise ReflectionProbeError(
                    "RP_NOT_DISPATCHED", {"probe_id": probe_id})
            if capture["dispatch_frame"] != frame:
                raise ReflectionProbeError(
                    "RP_STALE_FRAME",
                    {"frame": frame,
                     "dispatch_frame": capture["dispatch_frame"]})
            if set(capture["faces"]) != _FACE_SET:
                raise ReflectionProbeError(
                    "RP_INCOMPLETE_FACES",
                    {"missing": sorted(_FACE_SET.difference(capture["faces"]))})

            self._probes[probe_id]["checksum"] = checksum
            self._queue.remove(capture)
            self._captures += 1
        return {
            "status": "complete",
            "probe_id": probe_id,
            "frame": frame,
            "checksum": checksum,
        }

    def abort_capture(self, probe_id: str, *, frame: int) -> dict:
        with self._lock:
            if probe_id not in self._probes:
                raise ReflectionProbeError(
                    "RP_UNKNOWN_PROBE", {"probe_id": probe_id})
            capture = self._capture_for(probe_id, self._queue)
            if capture is None:
                raise ReflectionProbeError(
                    "RP_NO_ACTIVE_CAPTURE", {"probe_id": probe_id})
            if (capture["status"] == "started"
                    and capture["dispatch_frame"] != frame):
                raise ReflectionProbeError(
                    "RP_STALE_FRAME",
                    {"frame": frame,
                     "dispatch_frame": capture["dispatch_frame"]})

            previous = capture["previous_checksum"]
            self._probes[probe_id]["checksum"] = previous
            self._queue.remove(capture)
        return {
            "status": "aborted",
            "probe_id": probe_id,
            "frame": frame,
            "checksum": previous,
        }

    def pending_captures(self) -> list[dict]:
        with self._lock:
            queued = self._sorted_queue(self._queue)
            return [
                {
                    "probe_id": item["probe_id"],
                    "priority": item["priority"],
                    "seq": item["seq"],
                    "status": item["status"],
                }
                for item in queued
            ]

    def probe_state(self, probe_id: str) -> dict:
        with self._lock:
            probe = self._probes.get(probe_id)
            if probe is None:
                raise ReflectionProbeError(
                    "RP_UNKNOWN_PROBE", {"probe_id": probe_id})
            capture = self._capture_for(probe_id, self._queue)
            if capture is None:
                faces = []
                status = "idle"
                seq = None
                frame = None
            else:
                faces = [face for face in FACES if face in capture["faces"]]
                status = capture["status"]
                seq = capture["seq"]
                frame = (capture["dispatch_frame"]
                         if capture["status"] == "started"
                         else capture["request_frame"])
            return {
                "probe_id": probe_id,
                "position": probe["position"],
                "radius": probe["radius"],
                "priority": probe["priority"],
                "static": probe["static"],
                "checksum": probe["checksum"],
                "faces": faces,
                "status": status,
                "seq": seq,
                "frame": frame,
            }

    def resolve(self, position: tuple[float, float, float]) -> dict:
        values = self._valid_position(position)
        if values is None:
            raise ReflectionProbeError(
                "RP_INVALID_PROBE", {"field": "position"})

        with self._lock:
            best = None
            for probe_id, probe in self._probes.items():
                if probe["checksum"] is None:
                    continue
                if self._capture_for(probe_id, self._queue) is not None:
                    continue
                distance = math.dist(values, probe["position"])
                if distance > probe["radius"]:
                    continue
                candidate = (distance, probe_id)
                if best is None or candidate < best[0]:
                    best = (candidate, probe)
            if best is None:
                raise ReflectionProbeError("RP_NO_PROBE")
            (distance, probe_id), probe = best
            return {
                "probe_id": probe_id,
                "position": probe["position"],
                "checksum": probe["checksum"],
                "distance": distance,
            }

    def mip_sizes(self) -> list[int]:
        return [
            max(1, self.face_size >> level)
            for level in range(self.mip_levels)
        ]

    def snapshot(self) -> dict:
        with self._lock:
            probes = {}
            for probe_id, probe in self._probes.items():
                probes[probe_id] = {
                    "position": list(probe["position"]),
                    "radius": probe["radius"],
                    "priority": probe["priority"],
                    "static": probe["static"],
                    "checksum": probe["checksum"],
                }
            queue = []
            for capture in self._sorted_queue(self._queue):
                queue.append({
                    "probe_id": capture["probe_id"],
                    "priority": capture["priority"],
                    "seq": capture["seq"],
                    "status": capture["status"],
                    "reason": capture["reason"],
                    "request_frame": capture["request_frame"],
                    "dispatch_frame": capture["dispatch_frame"],
                    "previous_checksum": capture["previous_checksum"],
                    "faces": dict(capture["faces"]),
                })
            dispatches = []
            for frame in sorted(self._dispatches):
                result = self._dispatches[frame]
                dispatches.append({
                    "frame": frame,
                    "started": list(result["started"]),
                    "deferred": result["deferred"],
                })
            return {
                "version": SNAPSHOT_VERSION,
                "probes": probes,
                "queue": queue,
                "dispatches": dispatches,
                "requests": self._requests,
                "captures": self._captures,
                "next_seq": self._next_seq,
            }

    def restore(self, snapshot: dict) -> dict:
        with self._lock:
            if not isinstance(snapshot, dict):
                raise ReflectionProbeError("RP_SNAPSHOT_INVALID")
            if "version" not in snapshot:
                raise ReflectionProbeError("RP_SNAPSHOT_INVALID")
            if snapshot["version"] != SNAPSHOT_VERSION:
                raise ReflectionProbeError(
                    "RP_SNAPSHOT_VERSION",
                    {"expected": SNAPSHOT_VERSION,
                     "actual": snapshot["version"]})

            try:
                probes, queue, dispatches, requests, captures, next_seq = \
                    self._parse_snapshot(snapshot)
            except (KeyError, TypeError, ValueError, ReflectionProbeError):
                raise ReflectionProbeError("RP_SNAPSHOT_INVALID")

            self._probes = probes
            self._queue = queue
            self._dispatches = dispatches
            self._requests = requests
            self._captures = captures
            self._next_seq = next_seq
        return {
            "status": "restored",
            "version": SNAPSHOT_VERSION,
            "probes": len(probes),
            "pending": len(queue),
        }

    def _parse_snapshot(self, snapshot):
        raw_probes = snapshot["probes"]
        raw_queue = snapshot["queue"]
        raw_dispatches = snapshot.get("dispatches", [])
        requests = snapshot["requests"]
        captures = snapshot["captures"]
        next_seq = snapshot["next_seq"]

        if not isinstance(raw_probes, dict):
            raise ValueError("probes")
        if not isinstance(raw_queue, list):
            raise ValueError("queue")
        if not isinstance(raw_dispatches, list):
            raise ValueError("dispatches")
        if (not isinstance(requests, int) or isinstance(requests, bool)
                or requests < 0):
            raise ValueError("requests")
        if (not isinstance(captures, int) or isinstance(captures, bool)
                or captures < 0):
            raise ValueError("captures")
        if (not isinstance(next_seq, int) or isinstance(next_seq, bool)
                or next_seq < 1):
            raise ValueError("next_seq")

        probes = {}
        for probe_id, raw in raw_probes.items():
            if not isinstance(probe_id, str) or not probe_id:
                raise ValueError("probe_id")
            if not isinstance(raw, dict):
                raise ValueError("probe")
            position = self._valid_position(raw["position"])
            if position is None:
                raise ValueError("position")
            try:
                radius = float(raw["radius"])
            except (TypeError, ValueError):
                raise ValueError("radius")
            if not math.isfinite(radius) or radius <= 0:
                raise ValueError("radius")
            priority = raw["priority"]
            if not self._valid_priority(priority):
                raise ValueError("priority")
            static = raw["static"]
            if not isinstance(static, bool):
                raise ValueError("static")
            checksum = raw["checksum"]
            if checksum is not None and not isinstance(checksum, str):
                raise ValueError("checksum")
            probes[probe_id] = {
                "position": position,
                "radius": radius,
                "priority": priority,
                "static": static,
                "checksum": checksum,
            }

        queue = []
        seen_probes = set()
        seen_seq = set()
        for raw in raw_queue:
            if not isinstance(raw, dict):
                raise ValueError("capture")
            probe_id = raw["probe_id"]
            if probe_id not in probes or probe_id in seen_probes:
                raise ValueError("capture probe")
            priority = raw["priority"]
            if not self._valid_priority(priority):
                raise ValueError("capture priority")
            seq = raw["seq"]
            if (not isinstance(seq, int) or isinstance(seq, bool) or seq < 1
                    or seq in seen_seq):
                raise ValueError("capture seq")
            status = raw["status"]
            if status not in ("pending", "started"):
                raise ValueError("capture status")
            reason = raw.get("reason", "manual")
            if not isinstance(reason, str):
                raise ValueError("capture reason")
            request_frame = raw.get("request_frame")
            if (not isinstance(request_frame, int)
                    or isinstance(request_frame, bool)):
                raise ValueError("capture request frame")
            dispatch_frame = raw.get("dispatch_frame")
            if status == "started":
                if (not isinstance(dispatch_frame, int)
                        or isinstance(dispatch_frame, bool)):
                    raise ValueError("capture dispatch frame")
            elif dispatch_frame is not None:
                if (not isinstance(dispatch_frame, int)
                        or isinstance(dispatch_frame, bool)):
                    raise ValueError("capture dispatch frame")
            previous = raw.get("previous_checksum")
            if previous is not None and not isinstance(previous, str):
                raise ValueError("capture checksum")
            raw_faces = raw.get("faces", {})
            if not isinstance(raw_faces, dict):
                raise ValueError("capture faces")
            faces = {}
            for face, checksum in raw_faces.items():
                if face not in _FACE_SET or not isinstance(checksum, str):
                    raise ValueError("capture face")
                faces[face] = checksum
            queue.append({
                "probe_id": probe_id,
                "priority": priority,
                "seq": seq,
                "status": status,
                "reason": reason,
                "request_frame": request_frame,
                "dispatch_frame": dispatch_frame,
                "previous_checksum": previous,
                "faces": faces,
            })
            seen_probes.add(probe_id)
            seen_seq.add(seq)

        if next_seq <= max(seen_seq, default=0):
            raise ValueError("next_seq")

        dispatches = {}
        for raw in raw_dispatches:
            if not isinstance(raw, dict):
                raise ValueError("dispatch")
            frame = raw["frame"]
            if not isinstance(frame, int) or isinstance(frame, bool):
                raise ValueError("dispatch frame")
            started = raw["started"]
            deferred = raw["deferred"]
            if not isinstance(started, list) or not all(
                    isinstance(probe_id, str) for probe_id in started):
                raise ValueError("dispatch started")
            if (not isinstance(deferred, int) or isinstance(deferred, bool)
                    or deferred < 0):
                raise ValueError("dispatch deferred")
            dispatches[frame] = {
                "started": list(started),
                "deferred": deferred,
            }
        return probes, queue, dispatches, requests, captures, next_seq

    def stats(self) -> dict:
        with self._lock:
            return {
                "probes": len(self._probes),
                "requests": self._requests,
                "captures": self._captures,
                "pending": len(self._queue),
                "next_seq": self._next_seq,
            }
