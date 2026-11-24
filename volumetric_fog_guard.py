"""Volumetric fog froxel pipeline: depth reconstruction, scattering and history."""

import copy
import hashlib
import json
import math
import threading


SNAPSHOT_VERSION = 1
MAX_SAMPLES_PER_FROXEL = 64
MAX_MOTION_PIXELS = 64.0
DEFAULT_SAMPLE_BUDGET = 250_000


class FogError(ValueError):
    """Domain error carrying a stable machine-readable code."""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


def _is_number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _is_finite_number(value):
    if not _is_number(value):
        return False
    try:
        return math.isfinite(float(value))
    except (TypeError, ValueError, OverflowError):
        return False


def _invalid(code, detail=None):
    raise FogError(code, detail)


class VolumetricFog:
    """Camera, froxel grid, lights, participating media and temporal history."""

    def __init__(self, *, grid=(16, 9, 64), max_froxels=1_000_000,
                 history_frames=4, max_sample_units=DEFAULT_SAMPLE_BUDGET):
        try:
            normalized_grid = tuple(grid)
        except TypeError:
            _invalid("FOG_INVALID_GRID")
        if (len(normalized_grid) != 3 or
                any(not _is_number(v) or isinstance(v, float) or v <= 0
                    for v in normalized_grid)):
            _invalid("FOG_INVALID_GRID")
        if not _is_number(max_froxels) or max_froxels < 0:
            _invalid("FOG_INVALID_CONFIG")
        if not _is_number(history_frames) or history_frames < 0:
            _invalid("FOG_INVALID_CONFIG")
        if not _is_number(max_sample_units) or max_sample_units <= 0:
            _invalid("FOG_INVALID_CONFIG")

        froxels = normalized_grid[0] * normalized_grid[1] * normalized_grid[2]
        if froxels > max_froxels:
            _invalid("FOG_BUDGET_EXCEEDED")

        self.grid = tuple(int(v) for v in normalized_grid)
        self.max_froxels = max_froxels
        self.history_frames = history_frames
        self.max_sample_units = max_sample_units
        self._lock = threading.RLock()

        self._camera = None
        self._lights = {}
        self._media = {}

        self._last_depth_frame = None
        self._last_linear = None
        self._last_invalid = 0
        self._last_min = None
        self._last_max = None
        self._last_width = None
        self._last_height = None

        self._last_scatter_frame = None
        self._last_scatter_checksum = None
        self._last_scatter_samples = None

        self._history_frames = 0
        self._history_last_frame = None
        self._history_motion = []

    # ------------------------------------------------------------------
    # Internal helpers. Callers hold ``self._lock`` unless stated.
    # ------------------------------------------------------------------

    @property
    def _froxel_count(self):
        return self.grid[0] * self.grid[1] * self.grid[2]

    @staticmethod
    def _check_frame(frame_id):
        if (not isinstance(frame_id, int) or isinstance(frame_id, bool) or
                frame_id < 0):
            _invalid("FOG_INVALID_FRAME")

    def _jitter_locked(self, frame_id):
        jx, jy = self._camera["jitter"]
        if frame_id % 2 == 1:
            return (jx, jy)
        return (-jx, -jy)

    def _reset_temporal_locked(self):
        self._last_depth_frame = None
        self._last_linear = None
        self._last_invalid = 0
        self._last_min = None
        self._last_max = None
        self._last_width = None
        self._last_height = None
        self._last_scatter_frame = None
        self._last_scatter_checksum = None
        self._last_scatter_samples = None
        self._history_frames = 0
        self._history_last_frame = None
        self._history_motion = []

    def _depth_result_locked(self, frame_id, status):
        return {
            "status": status,
            "frame": frame_id,
            "linear": copy.copy(self._last_linear),
            "invalid": self._last_invalid,
            "valid": len(self._last_linear) - self._last_invalid,
            "min_depth": self._last_min,
            "max_depth": self._last_max,
            "min": self._last_min,
            "max": self._last_max,
            "width": self._last_width,
            "height": self._last_height,
            "jitter": self._jitter_locked(frame_id),
        }

    def _stats_locked(self):
        return {
            "camera": self._camera["camera_id"] if self._camera else None,
            "lights": len(self._lights),
            "media": len(self._media),
            "frames": self._history_frames,
            "history_frames": self._history_frames,
            "last_frame": self._history_last_frame,
            "depth_frame": self._last_depth_frame,
            "scatter_frame": self._last_scatter_frame,
            "invalid_depth": self._last_invalid,
            "linear_samples": (
                len(self._last_linear) if self._last_linear is not None else 0
            ),
        }

    @staticmethod
    def _validate_light(light):
        intensity = light["intensity"]
        position = light["position"]
        radius = light["radius"]
        color = light["color"]
        if not _is_finite_number(intensity):
            _invalid("FOG_INVALID_LIGHT")
        if not isinstance(position, (tuple, list)) or len(position) != 3:
            _invalid("FOG_INVALID_LIGHT")
        if any(not _is_finite_number(v) for v in position):
            _invalid("FOG_INVALID_LIGHT")
        if not _is_finite_number(radius) or float(radius) <= 0.0:
            _invalid("FOG_INVALID_LIGHT")
        if not isinstance(color, (tuple, list)) or len(color) != 3:
            _invalid("FOG_INVALID_LIGHT")
        if any(not _is_finite_number(v) for v in color):
            _invalid("FOG_INVALID_LIGHT")

    @staticmethod
    def _validate_media(media):
        density = media["density"]
        height_falloff = media["height_falloff"]
        extinction = media["extinction"]
        if not _is_finite_number(density) or not 0.0 <= float(density) <= 1.0:
            _invalid("FOG_INVALID_MEDIA")
        if not _is_finite_number(height_falloff):
            _invalid("FOG_INVALID_MEDIA")
        if not _is_finite_number(extinction) or float(extinction) < 0.0:
            _invalid("FOG_INVALID_MEDIA")

    def _checksum_locked(self, frame_id, samples_per_froxel):
        lights = [
            {
                "id": light_id,
                "intensity": self._lights[light_id]["intensity"],
                "position": list(self._lights[light_id]["position"]),
                "radius": self._lights[light_id]["radius"],
                "color": list(self._lights[light_id]["color"]),
            }
            for light_id in sorted(self._lights)
        ]
        media = [
            {
                "id": media_id,
                "density": self._media[media_id]["density"],
                "height_falloff": self._media[media_id]["height_falloff"],
                "extinction": self._media[media_id]["extinction"],
            }
            for media_id in sorted(self._media)
        ]
        payload = {
            "grid": list(self.grid),
            "samples_per_froxel": samples_per_froxel,
            "lights": lights,
            "media": media,
            "depth": {
                "min": self._last_min,
                "max": self._last_max,
                "invalid": self._last_invalid,
            },
        }
        encoded = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    # ------------------------------------------------------------------
    # Public API.
    # ------------------------------------------------------------------

    def set_camera(self, camera_id: str, *, near: float, far: float,
                   reversed_z: bool = False,
                   jitter: tuple[float, float] = (0.0, 0.0)) -> dict:
        with self._lock:
            if not isinstance(camera_id, str):
                _invalid("FOG_INVALID_CAMERA")
            if not _is_finite_number(near) or float(near) <= 0.0:
                _invalid("FOG_INVALID_CAMERA")
            if not _is_finite_number(far) or float(far) <= float(near):
                _invalid("FOG_INVALID_CAMERA")
            if (not isinstance(jitter, (tuple, list)) or len(jitter) != 2 or
                    any(not _is_finite_number(v) for v in jitter)):
                _invalid("FOG_INVALID_CAMERA")

            self._camera = {
                "camera_id": camera_id,
                "near": float(near),
                "far": float(far),
                "reversed_z": bool(reversed_z),
                "jitter": (float(jitter[0]), float(jitter[1])),
            }
            self._reset_temporal_locked()
            return {
                "status": "applied",
                "camera": camera_id,
                "near": float(near),
                "far": float(far),
                "reversed_z": bool(reversed_z),
                "jitter": self._camera["jitter"],
            }

    def add_light(self, light_id: str, *, intensity: float,
                  position: tuple[float, float, float], radius: float,
                  color: tuple[float, float, float] = (1.0, 1.0, 1.0)) -> dict:
        with self._lock:
            if not isinstance(light_id, str):
                _invalid("FOG_INVALID_LIGHT")
            light = {
                "intensity": intensity,
                "position": (
                    tuple(position)
                    if isinstance(position, (tuple, list))
                    else position
                ),
                "radius": radius,
                "color": (
                    tuple(color) if isinstance(color, (tuple, list)) else color
                ),
            }
            self._validate_light(light)
            status = "updated" if light_id in self._lights else "added"
            self._lights[light_id] = light
            return {"status": status, "light_id": light_id}

    def remove_light(self, light_id: str) -> dict:
        with self._lock:
            if light_id in self._lights:
                del self._lights[light_id]
                return {"status": "removed", "light_id": light_id}
            return {"status": "missing", "light_id": light_id}

    def inject_media(self, media_id: str, *, density: float,
                     height_falloff: float, extinction: float) -> dict:
        with self._lock:
            if not isinstance(media_id, str):
                _invalid("FOG_INVALID_MEDIA")
            media = {
                "density": density,
                "height_falloff": height_falloff,
                "extinction": extinction,
            }
            self._validate_media(media)
            status = "updated" if media_id in self._media else "added"
            self._media[media_id] = media
            return {"status": status, "media_id": media_id}

    def reconstruct_depth(self, frame_id: int, depth: list[float], *,
                          width: int, height: int) -> dict:
        with self._lock:
            if self._camera is None:
                _invalid("FOG_NO_CAMERA")
            self._check_frame(frame_id)

            if self._last_depth_frame is not None:
                if frame_id == self._last_depth_frame:
                    return self._depth_result_locked(frame_id, "cached")
                if frame_id < self._last_depth_frame:
                    _invalid("FOG_STALE_FRAME")

            if (not isinstance(width, int) or isinstance(width, bool) or
                    width <= 0 or not isinstance(height, int) or
                    isinstance(height, bool) or height <= 0):
                _invalid("FOG_INVALID_DEPTH")
            try:
                depth_count = len(depth)
            except TypeError:
                _invalid("FOG_INVALID_DEPTH")
            if depth_count != width * height:
                _invalid("FOG_INVALID_DEPTH")

            camera = self._camera
            near = camera["near"]
            far = camera["far"]
            reversed_z = camera["reversed_z"]
            linear = []
            valid = []
            invalid_count = 0

            for value in depth:
                if not _is_number(value):
                    _invalid("FOG_INVALID_DEPTH")
                try:
                    raw = float(value)
                except (TypeError, ValueError, OverflowError):
                    _invalid("FOG_INVALID_DEPTH")
                if not math.isfinite(raw):
                    linear.append(far)
                    invalid_count += 1
                    continue

                z = 1.0 - raw if reversed_z else raw
                if z <= 0.0:
                    distance = near
                elif z >= 1.0:
                    distance = far
                else:
                    distance = (near * far) / (far - z * (far - near))
                linear.append(distance)
                valid.append(distance)

            self._last_depth_frame = frame_id
            self._last_linear = linear
            self._last_invalid = invalid_count
            self._last_min = min(valid) if valid else None
            self._last_max = max(valid) if valid else None
            self._last_width = width
            self._last_height = height
            self._last_scatter_frame = None
            self._last_scatter_checksum = None
            self._last_scatter_samples = None
            return self._depth_result_locked(frame_id, "applied")

    def scatter(self, frame_id: int, *, samples_per_froxel: int = 8) -> dict:
        with self._lock:
            if self._camera is None:
                _invalid("FOG_NO_CAMERA")
            self._check_frame(frame_id)
            if (not isinstance(samples_per_froxel, int) or
                    isinstance(samples_per_froxel, bool) or
                    not 1 <= samples_per_froxel <= MAX_SAMPLES_PER_FROXEL):
                _invalid("FOG_INVALID_SAMPLES")
            if self._last_depth_frame is None:
                _invalid("FOG_NO_DEPTH")
            if frame_id < self._last_depth_frame:
                _invalid("FOG_STALE_FRAME")
            if frame_id > self._last_depth_frame:
                _invalid("FOG_STALE_FRAME")

            froxels = self._froxel_count
            sample_units = froxels * samples_per_froxel
            if sample_units > self.max_sample_units:
                _invalid("FOG_SAMPLE_BUDGET")

            checksum = self._checksum_locked(frame_id, samples_per_froxel)

            self._last_scatter_frame = frame_id
            self._last_scatter_checksum = checksum
            self._last_scatter_samples = sample_units
            return {
                "status": "applied",
                "frame": frame_id,
                "samples": sample_units,
                "samples_per_froxel": samples_per_froxel,
                "froxels": froxels,
                "checksum": checksum,
                "lights": len(self._lights),
                "media": len(self._media),
                "jitter": self._jitter_locked(frame_id),
            }

    def resolve(self, frame_id: int) -> dict:
        with self._lock:
            if self._camera is None:
                _invalid("FOG_NO_CAMERA")
            self._check_frame(frame_id)
            result = {
                "status": "applied",
                "frame": frame_id,
                "jitter": self._jitter_locked(frame_id),
            }
            if frame_id == self._last_scatter_frame:
                result["checksum"] = self._last_scatter_checksum
                result["samples"] = self._last_scatter_samples
            return result

    def reproject(self, frame_id: int,
                  motion: list[tuple[float, float]]) -> dict:
        with self._lock:
            if self._camera is None:
                _invalid("FOG_NO_CAMERA")
            self._check_frame(frame_id)
            try:
                motion_count = len(motion)
            except TypeError:
                _invalid("FOG_INVALID_MOTION")
            allowed_motion_lengths = {self.grid[0] * self.grid[1]}
            if self._last_width is not None and self._last_height is not None:
                allowed_motion_lengths.add(self._last_width * self._last_height)
            if motion_count not in allowed_motion_lengths:
                _invalid("FOG_INVALID_MOTION")

            accepted = 0
            rejected = 0
            valid_motion = []
            for offset in motion:
                if not isinstance(offset, (tuple, list)) or len(offset) != 2:
                    rejected += 1
                    continue
                dx, dy = offset
                if not _is_finite_number(dx) or not _is_finite_number(dy):
                    rejected += 1
                    continue
                dx = float(dx)
                dy = float(dy)
                if (abs(dx) > MAX_MOTION_PIXELS or
                        abs(dy) > MAX_MOTION_PIXELS):
                    rejected += 1
                    continue
                accepted += 1
                valid_motion.append((dx, dy))

            if rejected:
                self._history_frames = 0
                self._history_last_frame = None
                self._history_motion = []
                return {
                    "status": "reset",
                    "frame": frame_id,
                    "accepted": accepted,
                    "rejected": rejected,
                    "frames": 0,
                    "last_frame": None,
                }

            if self._history_last_frame != frame_id:
                self._history_frames = min(
                    self._history_frames + 1, self.history_frames
                )
                self._history_last_frame = frame_id
                self._history_motion.extend(valid_motion)
                keep = max(1, self.history_frames) if self.history_frames else 0
                if keep:
                    self._history_motion = (
                        self._history_motion[-keep * motion_count:]
                    )
                else:
                    self._history_motion = []
            return {
                "status": "applied",
                "frame": frame_id,
                "accepted": accepted,
                "rejected": 0,
                "frames": self._history_frames,
                "last_frame": self._history_last_frame,
            }

    def history_state(self) -> dict:
        with self._lock:
            return {
                "camera": self._camera["camera_id"] if self._camera else None,
                "frames": self._history_frames,
                "last_frame": self._history_last_frame,
                "motion": copy.deepcopy(self._history_motion),
                "capacity": self.history_frames,
            }

    def snapshot(self) -> dict:
        with self._lock:
            frame_state = {
                "last_reconstructed": self._last_depth_frame,
                "last_scatter": self._last_scatter_frame,
                "invalid_depth": self._last_invalid,
                "linear": self._last_linear,
                "min_depth": self._last_min,
                "max_depth": self._last_max,
                "width": self._last_width,
                "height": self._last_height,
                "scatter_checksum": self._last_scatter_checksum,
                "scatter_samples": self._last_scatter_samples,
            }
            return copy.deepcopy({
                "version": SNAPSHOT_VERSION,
                "camera": self._camera,
                "lights": self._lights,
                "media": self._media,
                "frame_id": self._last_depth_frame,
                "frame": frame_state,
                "frames": frame_state,
                "history": {
                    "frames": self._history_frames,
                    "last_frame": self._history_last_frame,
                    "motion": self._history_motion,
                },
                "stats": self._stats_locked(),
            })

    def restore(self, snapshot: dict) -> dict:
        with self._lock:
            if not isinstance(snapshot, dict):
                _invalid("FOG_SNAPSHOT_INVALID")
            if "version" not in snapshot:
                _invalid("FOG_SNAPSHOT_INVALID")
            version = snapshot["version"]
            if (not isinstance(version, int) or isinstance(version, bool) or
                    version != SNAPSHOT_VERSION):
                _invalid("FOG_SNAPSHOT_VERSION")

            required = (
                "camera", "lights", "media", "frame_id", "frame", "frames",
                "history", "stats"
            )
            if any(key not in snapshot for key in required):
                _invalid("FOG_SNAPSHOT_INVALID")

            try:
                parsed = self._parse_snapshot(snapshot)
            except FogError as exc:
                if exc.code == "FOG_SNAPSHOT_INVALID":
                    raise
                _invalid("FOG_SNAPSHOT_INVALID")
            except (KeyError, TypeError, ValueError, OverflowError):
                _invalid("FOG_SNAPSHOT_INVALID")

            (camera, lights, media, frame_state, history_state,
             _stats) = parsed

            self._camera = camera
            self._lights = lights
            self._media = media
            (self._last_depth_frame, self._last_scatter_frame,
             self._last_invalid, self._last_linear, self._last_min,
             self._last_max, self._last_width, self._last_height,
             self._last_scatter_checksum,
             self._last_scatter_samples) = frame_state
            (self._history_frames, self._history_last_frame,
             self._history_motion) = history_state
            return {"status": "restored", "version": SNAPSHOT_VERSION}

    def _parse_snapshot(self, snapshot):
        camera_snapshot = copy.deepcopy(snapshot["camera"])
        if camera_snapshot is not None:
            if not isinstance(camera_snapshot, dict):
                _invalid("FOG_SNAPSHOT_INVALID")
            camera_required = (
                "camera_id", "near", "far", "reversed_z", "jitter"
            )
            if any(key not in camera_snapshot for key in camera_required):
                _invalid("FOG_SNAPSHOT_INVALID")
            if not isinstance(camera_snapshot["camera_id"], str):
                _invalid("FOG_SNAPSHOT_INVALID")
            if (not _is_finite_number(camera_snapshot["near"]) or
                    not _is_finite_number(camera_snapshot["far"]) or
                    float(camera_snapshot["near"]) <= 0.0 or
                    float(camera_snapshot["far"]) <=
                    float(camera_snapshot["near"])):
                _invalid("FOG_SNAPSHOT_INVALID")
            jitter = camera_snapshot["jitter"]
            if (not isinstance(jitter, (tuple, list)) or len(jitter) != 2 or
                    any(not _is_finite_number(v) for v in jitter)):
                _invalid("FOG_SNAPSHOT_INVALID")
            camera_snapshot = {
                "camera_id": camera_snapshot["camera_id"],
                "near": float(camera_snapshot["near"]),
                "far": float(camera_snapshot["far"]),
                "reversed_z": bool(camera_snapshot["reversed_z"]),
                "jitter": (float(jitter[0]), float(jitter[1])),
            }

        lights_snapshot = copy.deepcopy(snapshot["lights"])
        if not isinstance(lights_snapshot, dict):
            _invalid("FOG_SNAPSHOT_INVALID")
        lights = {}
        for light_id, light in lights_snapshot.items():
            if not isinstance(light_id, str) or not isinstance(light, dict):
                _invalid("FOG_SNAPSHOT_INVALID")
            if any(key not in light for key in
                   ("intensity", "position", "radius", "color")):
                _invalid("FOG_SNAPSHOT_INVALID")
            normalized = {
                "intensity": light["intensity"],
                "position": tuple(light["position"]),
                "radius": light["radius"],
                "color": tuple(light["color"]),
            }
            self._validate_light(normalized)
            lights[light_id] = normalized

        media_snapshot = copy.deepcopy(snapshot["media"])
        if not isinstance(media_snapshot, dict):
            _invalid("FOG_SNAPSHOT_INVALID")
        media = {}
        for media_id, entry in media_snapshot.items():
            if not isinstance(media_id, str) or not isinstance(entry, dict):
                _invalid("FOG_SNAPSHOT_INVALID")
            if any(key not in entry for key in
                   ("density", "height_falloff", "extinction")):
                _invalid("FOG_SNAPSHOT_INVALID")
            normalized = {
                "density": entry["density"],
                "height_falloff": entry["height_falloff"],
                "extinction": entry["extinction"],
            }
            self._validate_media(normalized)
            media[media_id] = normalized

        frame_snapshot = copy.deepcopy(snapshot["frames"])
        if not isinstance(frame_snapshot, dict):
            _invalid("FOG_SNAPSHOT_INVALID")
        frame_required = (
            "last_reconstructed", "last_scatter", "invalid_depth", "linear",
            "min_depth", "max_depth", "width", "height", "scatter_checksum",
            "scatter_samples",
        )
        if any(key not in frame_snapshot for key in frame_required):
            _invalid("FOG_SNAPSHOT_INVALID")
        if (snapshot["frame"] != frame_snapshot or
                snapshot["frame_id"] != frame_snapshot["last_reconstructed"]):
            _invalid("FOG_SNAPSHOT_INVALID")
        if frame_snapshot["linear"] is not None:
            if not isinstance(frame_snapshot["linear"], list):
                _invalid("FOG_SNAPSHOT_INVALID")
            if any(not _is_finite_number(v)
                   for v in frame_snapshot["linear"]):
                _invalid("FOG_SNAPSHOT_INVALID")
        if (frame_snapshot["invalid_depth"] is None or
                not isinstance(frame_snapshot["invalid_depth"], int) or
                isinstance(frame_snapshot["invalid_depth"], bool)):
            _invalid("FOG_SNAPSHOT_INVALID")
        for key in ("last_reconstructed", "last_scatter", "width", "height",
                    "scatter_samples"):
            if frame_snapshot[key] is not None and (
                    not isinstance(frame_snapshot[key], int) or
                    isinstance(frame_snapshot[key], bool)):
                _invalid("FOG_SNAPSHOT_INVALID")
        for key in ("min_depth", "max_depth"):
            if (frame_snapshot[key] is not None and
                    not _is_finite_number(frame_snapshot[key])):
                _invalid("FOG_SNAPSHOT_INVALID")
        if (frame_snapshot["scatter_checksum"] is not None and
                not isinstance(frame_snapshot["scatter_checksum"], str)):
            _invalid("FOG_SNAPSHOT_INVALID")
        frame_state = (
            frame_snapshot["last_reconstructed"],
            frame_snapshot["last_scatter"],
            frame_snapshot["invalid_depth"],
            frame_snapshot["linear"],
            frame_snapshot["min_depth"],
            frame_snapshot["max_depth"],
            frame_snapshot["width"],
            frame_snapshot["height"],
            frame_snapshot["scatter_checksum"],
            frame_snapshot["scatter_samples"],
        )

        history_snapshot = copy.deepcopy(snapshot["history"])
        if not isinstance(history_snapshot, dict):
            _invalid("FOG_SNAPSHOT_INVALID")
        if any(key not in history_snapshot for key in
               ("frames", "last_frame", "motion")):
            _invalid("FOG_SNAPSHOT_INVALID")
        if (not isinstance(history_snapshot["frames"], int) or
                isinstance(history_snapshot["frames"], bool) or
                history_snapshot["frames"] < 0):
            _invalid("FOG_SNAPSHOT_INVALID")
        if history_snapshot["last_frame"] is not None and (
                not isinstance(history_snapshot["last_frame"], int) or
                isinstance(history_snapshot["last_frame"], bool)):
            _invalid("FOG_SNAPSHOT_INVALID")
        motion = history_snapshot["motion"]
        if not isinstance(motion, list):
            _invalid("FOG_SNAPSHOT_INVALID")
        normalized_motion = []
        for offset in motion:
            if (not isinstance(offset, (tuple, list)) or len(offset) != 2 or
                    any(not _is_finite_number(v) for v in offset)):
                _invalid("FOG_SNAPSHOT_INVALID")
            normalized_motion.append((float(offset[0]), float(offset[1])))
        history_state = (
            history_snapshot["frames"],
            history_snapshot["last_frame"],
            normalized_motion,
        )

        stats_snapshot = snapshot["stats"]
        if not isinstance(stats_snapshot, dict):
            _invalid("FOG_SNAPSHOT_INVALID")

        return (
            camera_snapshot, lights, media, frame_state, history_state,
            stats_snapshot,
        )

    def stats(self) -> dict:
        with self._lock:
            return self._stats_locked()
