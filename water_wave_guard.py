"""Ocean surface: Gerstner waves, mesh LOD rings and foam accumulation."""

import hashlib
import math
import struct
import threading
from typing import NamedTuple


SNAPSHOT_VERSION = 1
MAX_RINGS = 4
MIN_RING_RESOLUTION = 2
FOAM_DECAY_PER_SECOND = 0.5


class WaterWaveError(ValueError):
    """Domain error carrying a stable machine-readable code."""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class _Wave(NamedTuple):
    wave_id: str
    amplitude: float
    wavelength: float
    steepness: float
    direction_x: float
    direction_z: float
    speed: float
    k: float


def _finite_number(value, code, detail):
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        raise WaterWaveError(code, detail) from None
    if not math.isfinite(number):
        raise WaterWaveError(code, detail)
    return number


def _normalised_direction(direction, code, detail):
    try:
        if len(direction) != 2:
            raise TypeError
        dx = float(direction[0])
        dz = float(direction[1])
    except (TypeError, ValueError, IndexError, OverflowError):
        raise WaterWaveError(code, detail) from None
    if not (math.isfinite(dx) and math.isfinite(dz)):
        raise WaterWaveError(code, detail)
    length = math.hypot(dx, dz)
    if length == 0.0 or not math.isfinite(length):
        raise WaterWaveError(code, detail)
    return dx / length, dz / length


class WaterWaves:
    """Wave set, water level, foam layer and radial mesh builder."""

    def __init__(self, *, resolution: int = 64, max_vertices: int = 200_000,
                 max_waves: int = 8):
        self.resolution = resolution
        self.max_vertices = max_vertices
        self.max_waves = max_waves

        self._lock = threading.RLock()
        self._water_level = 0.0
        self._waves = {}
        self._time = 0.0
        self._foam = {}
        self._frame = 0
        self._last_step_frame = -1
        self._samples = 0
        self._builds = 0
        self._steps = 0
        self._generation = 0
        self._mesh_cache = {}

    def set_water_level(self, level: float) -> dict:
        value = _finite_number(level, "WW_INVALID_LEVEL", "water level")
        with self._lock:
            if value != self._water_level:
                self._water_level = value
                self._invalidate_mesh_locked()
            return {
                "status": "applied",
                "water_level": self._water_level,
                "level": self._water_level,
            }

    def add_wave(self, wave_id: str, *, amplitude: float, wavelength: float,
                 steepness: float, direction: tuple[float, float],
                 speed: float) -> dict:
        if not isinstance(wave_id, str):
            raise WaterWaveError("WW_INVALID_WAVE", "wave_id")
        amplitude = _finite_number(
            amplitude, "WW_INVALID_WAVE", "amplitude")
        wavelength = _finite_number(
            wavelength, "WW_INVALID_WAVE", "wavelength")
        steepness = _finite_number(
            steepness, "WW_INVALID_WAVE", "steepness")
        speed = _finite_number(speed, "WW_INVALID_WAVE", "speed")
        direction_x, direction_z = _normalised_direction(
            direction, "WW_INVALID_WAVE", "direction")

        if amplitude <= 0.0:
            raise WaterWaveError("WW_INVALID_WAVE", "amplitude")
        if wavelength <= 0.0:
            raise WaterWaveError("WW_INVALID_WAVE", "wavelength")
        if steepness < 0.0 or steepness > 1.0:
            raise WaterWaveError("WW_INVALID_WAVE", "steepness")
        if speed < 0.0:
            raise WaterWaveError("WW_INVALID_WAVE", "speed")

        k = (2.0 * math.pi) / wavelength
        if not math.isfinite(k):
            raise WaterWaveError("WW_INVALID_WAVE", "wavelength")

        with self._lock:
            replaced = wave_id in self._waves
            if not replaced and len(self._waves) >= self.max_waves:
                raise WaterWaveError("WW_WAVE_LIMIT", wave_id)
            self._waves[wave_id] = _Wave(
                wave_id=wave_id,
                amplitude=amplitude,
                wavelength=wavelength,
                steepness=steepness,
                direction_x=direction_x,
                direction_z=direction_z,
                speed=speed,
                k=k,
            )
            self._invalidate_mesh_locked()
            count = len(self._waves)

        return {
            "status": "replaced" if replaced else "applied",
            "wave_id": wave_id,
            "waves": count,
            "count": count,
        }

    def remove_wave(self, wave_id: str) -> dict:
        with self._lock:
            removed = wave_id in self._waves
            if removed:
                del self._waves[wave_id]
                self._invalidate_mesh_locked()
            count = len(self._waves)
        return {
            "status": "applied" if removed else "missing",
            "wave_id": wave_id,
            "removed": removed,
            "waves": count,
            "count": count,
        }

    def sample_height(self, x: float, z: float, t: float | None = None) -> float:
        with self._lock:
            self._samples += 1
            time = self._time if t is None else t
            water_level = self._water_level
            waves = self._ordered_waves_locked()
        return self._height_at(waves, water_level, x, z, time)

    def sample_normal(self, x: float, z: float,
                      t: float | None = None) -> tuple[float, float, float]:
        with self._lock:
            time = self._time if t is None else t
            waves = self._ordered_waves_locked()

        gradient_x = 0.0
        gradient_z = 0.0
        for wave in waves:
            phase = (
                wave.k * (wave.direction_x * x + wave.direction_z * z)
                - wave.speed * wave.k * time
            )
            factor = wave.amplitude * wave.k * math.cos(phase)
            gradient_x += factor * wave.direction_x
            gradient_z += factor * wave.direction_z

        length = math.sqrt(
            gradient_x * gradient_x + 1.0 + gradient_z * gradient_z)
        if length == 0.0 or not math.isfinite(length):
            return (0.0, 1.0, 0.0)
        return (-gradient_x / length, 1.0 / length, -gradient_z / length)

    def splash(self, x: float, z: float, amount: float) -> dict:
        amount = _finite_number(amount, "WW_INVALID_FOAM", "amount")
        if amount < 0.0:
            raise WaterWaveError("WW_INVALID_FOAM", "amount")
        cell_x, cell_z = self._cell(x, z)

        with self._lock:
            current = self._foam.get((cell_x, cell_z), 0.0)
            if amount > 0.0:
                current = min(1.0, current + amount)
                if current > 0.0:
                    self._foam[(cell_x, cell_z)] = current
            return {
                "status": "applied",
                "cell": (cell_x, cell_z),
                "x": cell_x,
                "z": cell_z,
                "foam": current,
                "amount": current,
            }

    def foam_at(self, x: float, z: float) -> float:
        cell_x, cell_z = self._cell(x, z)
        with self._lock:
            return self._foam.get((cell_x, cell_z), 0.0)

    def step(self, dt: float, *, frame: int) -> dict:
        dt = _finite_number(dt, "WW_INVALID_STEP", "dt")
        if dt <= 0.0 or dt > 2.0:
            raise WaterWaveError("WW_INVALID_STEP", "dt")
        if not isinstance(frame, int) or isinstance(frame, bool):
            raise WaterWaveError("WW_INVALID_FRAME", "frame")

        with self._lock:
            if frame == self._last_step_frame:
                return {
                    "status": "ignored",
                    "code": "WW_DUP_FRAME",
                    "frame": frame,
                    "time": self._time,
                }
            if frame < self._last_step_frame:
                raise WaterWaveError("WW_STALE_FRAME", "frame")

            self._time += dt
            self._frame = frame
            self._last_step_frame = frame
            self._steps += 1
            self._decay_foam_locked(dt)
            self._mesh_cache.clear()
            return {
                "status": "applied",
                "frame": frame,
                "time": self._time,
                "dt": dt,
                "foam_cells": len(self._foam),
            }

    def build_mesh(self, frame: int, *, rings: int = 3,
                   center: tuple[float, float] = (0.0, 0.0)) -> dict:
        if (not isinstance(rings, int) or isinstance(rings, bool)
                or rings < 1 or rings > MAX_RINGS):
            raise WaterWaveError("WW_INVALID_RINGS", rings)
        if not isinstance(frame, int) or isinstance(frame, bool):
            raise WaterWaveError("WW_INVALID_FRAME", "frame")
        if not isinstance(center, (tuple, list)) or len(center) != 2:
            raise WaterWaveError("WW_INVALID_CENTER", "center")
        try:
            center_x = float(center[0])
            center_z = float(center[1])
        except (TypeError, ValueError, OverflowError):
            raise WaterWaveError("WW_INVALID_CENTER", "center") from None
        if not (math.isfinite(center_x) and math.isfinite(center_z)):
            raise WaterWaveError("WW_INVALID_CENTER", "center")

        with self._lock:
            if frame != self._frame:
                raise WaterWaveError("WW_STALE_FRAME", "frame")

            resolution = int(self.resolution)
            resolutions = []
            vertex_count = 0
            for ring in range(rings):
                ring_resolution = max(
                    MIN_RING_RESOLUTION, resolution >> ring)
                resolutions.append(ring_resolution)
                vertex_count += ring_resolution * ring_resolution

            if vertex_count > self.max_vertices:
                raise WaterWaveError(
                    "WW_BUDGET_EXCEEDED", vertex_count)

            key = (
                frame,
                rings,
                center_x,
                center_z,
                resolution,
                self._generation,
            )
            cached = self._mesh_cache.get(key)
            if cached is not None:
                result = dict(cached)
                result["vertices"] = list(cached["vertices"])
                result["status"] = "cached"
                return result

            water_level = self._water_level
            time = self._time
            waves = self._ordered_waves_locked()
            vertices = []
            for ring, ring_resolution in enumerate(resolutions):
                offset = (ring_resolution - 1) / 2.0
                for z_index in range(ring_resolution):
                    z = center_z + (z_index - offset)
                    for x_index in range(ring_resolution):
                        x = center_x + (x_index - offset)
                        height = self._height_at(
                            waves, water_level, x, z, time)
                        vertices.append((x, z, height))

            checksum = self._checksum(
                waves, water_level, time, center_x, center_z,
                rings, vertices)
            stored = {
                "frame": frame,
                "rings": rings,
                "center": (center_x, center_z),
                "vertex_count": vertex_count,
                "vertices": tuple(vertices),
                "checksum": checksum,
            }
            self._mesh_cache[key] = stored
            self._builds += 1
            result = dict(stored)
            result["vertices"] = list(vertices)
            result["status"] = "applied"
            return result

    def lod_for(self, distance: float) -> int:
        try:
            distance = float(distance)
        except (TypeError, ValueError, OverflowError):
            raise WaterWaveError("WW_INVALID_DISTANCE", distance) from None
        if math.isnan(distance) or distance < 0.0:
            raise WaterWaveError("WW_INVALID_DISTANCE", distance)
        if distance < 16.0:
            return 0
        if distance < 48.0:
            return 1
        if distance < 128.0:
            return 2
        return 3

    def snapshot(self) -> dict:
        with self._lock:
            waves = [
                {
                    "wave_id": wave.wave_id,
                    "amplitude": wave.amplitude,
                    "wavelength": wave.wavelength,
                    "steepness": wave.steepness,
                    "direction": [wave.direction_x, wave.direction_z],
                    "speed": wave.speed,
                }
                for wave in self._ordered_waves_locked()
            ]
            foam = [
                [cell_x, cell_z, amount]
                for (cell_x, cell_z), amount in sorted(self._foam.items())
            ]
            return {
                "version": SNAPSHOT_VERSION,
                "water_level": self._water_level,
                "waves": waves,
                "time": self._time,
                "foam": foam,
                "frame": self._frame,
                "stats": {
                    "samples": self._samples,
                    "builds": self._builds,
                    "steps": self._steps,
                },
            }

    def restore(self, snapshot: dict) -> dict:
        if not isinstance(snapshot, dict):
            raise WaterWaveError("WW_SNAPSHOT_INVALID", "snapshot")
        if snapshot.get("version") != SNAPSHOT_VERSION:
            raise WaterWaveError("WW_SNAPSHOT_VERSION", "version")

        try:
            water_level = _finite_number(
                snapshot["water_level"], "WW_SNAPSHOT_INVALID",
                "water_level")
            time = _finite_number(
                snapshot["time"], "WW_SNAPSHOT_INVALID", "time")
            if time < 0.0:
                raise ValueError
            raw_frame = snapshot["frame"]
            if (not isinstance(raw_frame, int)
                    or isinstance(raw_frame, bool) or raw_frame < 0):
                raise ValueError
            raw_waves = snapshot["waves"]
            raw_foam = snapshot["foam"]
            raw_stats = snapshot["stats"]
            if not isinstance(raw_stats, dict):
                raise ValueError
            samples = self._snapshot_counter(raw_stats, "samples")
            builds = self._snapshot_counter(raw_stats, "builds")
            steps = self._snapshot_counter(raw_stats, "steps", default=0)
            waves = self._parse_snapshot_waves(raw_waves)
            foam = self._parse_snapshot_foam(raw_foam)
        except WaterWaveError as exc:
            if exc.code == "WW_SNAPSHOT_INVALID":
                raise
            raise WaterWaveError(
                "WW_SNAPSHOT_INVALID", exc.detail) from None
        except (KeyError, TypeError, ValueError, OverflowError,
                ArithmeticError):
            raise WaterWaveError("WW_SNAPSHOT_INVALID", "snapshot") from None

        with self._lock:
            self._water_level = water_level
            self._waves = waves
            self._time = time
            self._foam = foam
            self._frame = raw_frame
            self._last_step_frame = raw_frame
            self._samples = samples
            self._builds = builds
            self._steps = steps
            self._generation += 1
            self._mesh_cache.clear()

        return {
            "status": "restored",
            "frame": raw_frame,
            "time": time,
            "waves": len(waves),
        }

    def stats(self) -> dict:
        with self._lock:
            return {
                "waves": len(self._waves),
                "samples": self._samples,
                "builds": self._builds,
                "steps": self._steps,
                "time": self._time,
                "frame": self._frame,
                "foam_cells": len(self._foam),
            }

    def _ordered_waves_locked(self):
        return tuple(sorted(self._waves.values(), key=lambda wave: wave.wave_id))

    @staticmethod
    def _height_at(waves, water_level, x, z, time):
        height = water_level
        for wave in waves:
            phase = (
                wave.k * (wave.direction_x * x + wave.direction_z * z)
                - wave.speed * wave.k * time
            )
            height += wave.amplitude * math.sin(phase)
        return height

    @staticmethod
    def _cell(x, z):
        try:
            x = float(x)
            z = float(z)
        except (TypeError, ValueError, OverflowError):
            raise WaterWaveError("WW_INVALID_FOAM", "cell") from None
        if not (math.isfinite(x) and math.isfinite(z)):
            raise WaterWaveError("WW_INVALID_FOAM", "cell")
        return math.floor(x), math.floor(z)

    def _decay_foam_locked(self, dt):
        decay = FOAM_DECAY_PER_SECOND * dt
        if not self._foam:
            return
        remaining = {}
        for cell, amount in self._foam.items():
            value = amount - decay
            if value > 0.0:
                remaining[cell] = value
        self._foam = remaining

    def _invalidate_mesh_locked(self):
        self._generation += 1
        self._mesh_cache.clear()

    @staticmethod
    def _checksum(waves, water_level, time, center_x, center_z,
                  rings, vertices):
        digest = hashlib.sha256()
        digest.update(b"WaterWavesMesh\0")
        digest.update(struct.pack("<I", len(waves)))
        for wave in waves:
            wave_id = wave.wave_id.encode("utf-8")
            digest.update(struct.pack("<I", len(wave_id)))
            digest.update(wave_id)
            digest.update(struct.pack(
                "<6d",
                wave.amplitude,
                wave.wavelength,
                wave.steepness,
                wave.direction_x,
                wave.direction_z,
                wave.speed,
            ))
        digest.update(struct.pack(
            "<4dI", water_level, time, center_x, center_z, rings))
        digest.update(struct.pack("<I", len(vertices)))
        for x, z, height in vertices:
            digest.update(struct.pack("<3d", x, z, height))
        return digest.hexdigest()

    @staticmethod
    def _snapshot_counter(stats, key, default=None):
        if key not in stats:
            if default is not None:
                return default
            raise ValueError
        value = stats[key]
        if (not isinstance(value, int) or isinstance(value, bool)
                or value < 0):
            raise ValueError
        return value

    def _parse_snapshot_waves(self, raw_waves):
        if isinstance(raw_waves, dict):
            entries = []
            for wave_id, config in raw_waves.items():
                if not isinstance(config, dict):
                    raise ValueError
                entry = dict(config)
                entry.setdefault("wave_id", wave_id)
                entries.append(entry)
        elif isinstance(raw_waves, (list, tuple)):
            entries = raw_waves
        else:
            raise ValueError

        waves = {}
        for entry in entries:
            if not isinstance(entry, dict):
                raise ValueError
            wave_id = entry.get("wave_id", entry.get("id"))
            if not isinstance(wave_id, str) or wave_id in waves:
                raise ValueError
            amplitude = _finite_number(
                entry.get("amplitude"), "WW_SNAPSHOT_INVALID", "amplitude")
            wavelength = _finite_number(
                entry.get("wavelength"), "WW_SNAPSHOT_INVALID", "wavelength")
            steepness = _finite_number(
                entry.get("steepness"), "WW_SNAPSHOT_INVALID", "steepness")
            speed = _finite_number(
                entry.get("speed"), "WW_SNAPSHOT_INVALID", "speed")
            direction_x, direction_z = _normalised_direction(
                entry.get("direction"), "WW_SNAPSHOT_INVALID", "direction")
            if amplitude <= 0.0 or wavelength <= 0.0:
                raise ValueError
            if steepness < 0.0 or steepness > 1.0 or speed < 0.0:
                raise ValueError
            k = (2.0 * math.pi) / wavelength
            if not math.isfinite(k):
                raise ValueError
            waves[wave_id] = _Wave(
                wave_id=wave_id,
                amplitude=amplitude,
                wavelength=wavelength,
                steepness=steepness,
                direction_x=direction_x,
                direction_z=direction_z,
                speed=speed,
                k=k,
            )
        return waves

    @staticmethod
    def _parse_snapshot_foam(raw_foam):
        foam = {}
        if isinstance(raw_foam, dict):
            entries = []
            for cell, amount in raw_foam.items():
                if not isinstance(cell, (list, tuple)) or len(cell) != 2:
                    raise ValueError
                entries.append((cell[0], cell[1], amount))
        elif isinstance(raw_foam, (list, tuple)):
            entries = []
            for item in raw_foam:
                if isinstance(item, dict):
                    entries.append((
                        item.get("x"),
                        item.get("z"),
                        item.get("amount", item.get("foam")),
                    ))
                elif isinstance(item, (list, tuple)) and len(item) == 3:
                    entries.append(tuple(item))
                else:
                    raise ValueError
        else:
            raise ValueError

        for cell_x, cell_z, amount in entries:
            if (not isinstance(cell_x, int) or isinstance(cell_x, bool)
                    or not isinstance(cell_z, int) or isinstance(cell_z, bool)):
                raise ValueError
            amount = _finite_number(
                amount, "WW_SNAPSHOT_INVALID", "foam")
            if amount < 0.0 or amount > 1.0:
                raise ValueError
            if amount > 0.0:
                foam[(cell_x, cell_z)] = amount
        return foam
