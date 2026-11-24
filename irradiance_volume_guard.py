"""Irradiance volume: voxel SH storage, dirty boxes and bounded incremental updates."""

import math
import threading
from numbers import Integral

SNAPSHOT_VERSION = 1
SH_COEFFICIENTS = 9


class IrradianceVolumeError(ValueError):
    """Domain error carrying a stable machine-readable code."""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


def _config_error(detail=None):
    return IrradianceVolumeError("IR_INVALID_CONFIG", detail)


def _is_integer(value):
    return isinstance(value, Integral) and not isinstance(value, bool)


class IrradianceVolume:
    """Sparse irradiance voxel grid with dirty tracking and frame budgets."""

    def __init__(self, *, dims=(8, 4, 8), voxel_size: float = 1.0,
                 max_updates_per_frame: int = 1024,
                 max_voxels: int = 65536):
        try:
            dimensions = tuple(dims)
        except (TypeError, ValueError) as exc:
            raise _config_error("dims") from exc
        if len(dimensions) != 3:
            raise _config_error("dims")
        for axis in dimensions:
            if not _is_integer(axis) or axis < 1:
                raise _config_error("dims")

        if not _is_integer(max_voxels) or max_voxels < 1:
            raise _config_error("max_voxels")
        if dimensions[0] * dimensions[1] * dimensions[2] > max_voxels:
            raise _config_error("max_voxels")

        if not _is_integer(max_updates_per_frame) or \
                max_updates_per_frame < 1:
            raise _config_error("max_updates_per_frame")

        if isinstance(voxel_size, bool):
            raise _config_error("voxel_size")
        try:
            size = float(voxel_size)
        except (TypeError, ValueError, OverflowError) as exc:
            raise _config_error("voxel_size") from exc
        if not math.isfinite(size) or size <= 0.0:
            raise _config_error("voxel_size")

        self.dims = tuple(int(axis) for axis in dimensions)
        self.voxel_size = size
        self.max_updates_per_frame = int(max_updates_per_frame)
        self.max_voxels = int(max_voxels)
        self._voxels = {}
        self._dirty = set()
        self._generation = 0
        self._frame = None
        self._frozen = False
        self._lock = threading.RLock()

    def _checked_index(self, index):
        try:
            coordinates = tuple(index)
        except (TypeError, ValueError) as exc:
            raise IrradianceVolumeError("IR_INDEX_RANGE", index) from exc
        if len(coordinates) != 3:
            raise IrradianceVolumeError("IR_INDEX_RANGE", index)
        for value, axis in zip(coordinates, self.dims):
            if not _is_integer(value) or value < 0 or value >= axis:
                raise IrradianceVolumeError("IR_INDEX_RANGE", index)
        return tuple(int(value) for value in coordinates)

    @staticmethod
    def _checked_sh(sh):
        if isinstance(sh, (str, bytes)):
            raise IrradianceVolumeError("IR_INVALID_VOXEL", "sh")
        try:
            coefficients = tuple(sh)
        except (TypeError, ValueError) as exc:
            raise IrradianceVolumeError("IR_INVALID_VOXEL", "sh") from exc
        if len(coefficients) != SH_COEFFICIENTS:
            raise IrradianceVolumeError("IR_INVALID_VOXEL", "sh")
        result = []
        for coefficient in coefficients:
            if isinstance(coefficient, bool):
                raise IrradianceVolumeError("IR_INVALID_VOXEL", "sh")
            try:
                value = float(coefficient)
            except (TypeError, ValueError, OverflowError) as exc:
                raise IrradianceVolumeError(
                    "IR_INVALID_VOXEL", "sh"
                ) from exc
            if not math.isfinite(value):
                raise IrradianceVolumeError("IR_INVALID_VOXEL", "sh")
            result.append(value)
        return tuple(result)

    @staticmethod
    def _checked_position(position):
        try:
            coordinates = tuple(position)
        except (TypeError, ValueError) as exc:
            raise IrradianceVolumeError(
                "IR_INVALID_POSITION", position
            ) from exc
        if len(coordinates) != 3:
            raise IrradianceVolumeError("IR_INVALID_POSITION", position)
        result = []
        for coordinate in coordinates:
            if isinstance(coordinate, bool):
                raise IrradianceVolumeError(
                    "IR_INVALID_POSITION", position
                )
            try:
                value = float(coordinate)
            except (TypeError, ValueError, OverflowError) as exc:
                raise IrradianceVolumeError(
                    "IR_INVALID_POSITION", position
                ) from exc
            if not math.isfinite(value):
                raise IrradianceVolumeError(
                    "IR_INVALID_POSITION", position
                )
            result.append(value)
        return tuple(result)

    @staticmethod
    def _checked_box(box):
        try:
            coordinates = tuple(box)
        except (TypeError, ValueError) as exc:
            raise IrradianceVolumeError("IR_INVALID_BOX", box) from exc
        if len(coordinates) != 6:
            raise IrradianceVolumeError("IR_INVALID_BOX", box)
        for coordinate in coordinates:
            if not _is_integer(coordinate):
                raise IrradianceVolumeError("IR_INVALID_BOX", box)
        coordinates = tuple(int(coordinate) for coordinate in coordinates)
        if any(coordinates[axis] > coordinates[axis + 3]
               for axis in range(3)):
            raise IrradianceVolumeError("IR_INVALID_BOX", box)
        return coordinates

    @staticmethod
    def _checked_frame(frame):
        if not _is_integer(frame):
            raise IrradianceVolumeError("IR_INVALID_FRAME", frame)
        return int(frame)

    def set_voxel(self, index: tuple[int, int, int], *,
                  sh: tuple[float, ...]) -> dict:
        with self._lock:
            if self._frozen:
                raise IrradianceVolumeError("IR_FROZEN")
            coordinate = self._checked_index(index)
            coefficients = self._checked_sh(sh)
            self._voxels[coordinate] = coefficients
            self._dirty.add(coordinate)
            return {
                "status": "applied",
                "index": coordinate,
                "dirty": len(self._dirty),
                "voxels": len(self._voxels),
                "generation": self._generation,
            }

    def mark_dirty(self, box: tuple[int, int, int, int, int, int]) -> dict:
        with self._lock:
            if self._frozen:
                raise IrradianceVolumeError("IR_FROZEN")
            coordinates = self._checked_box(box)
            clamped = any(
                coordinates[axis] < 0 or
                coordinates[axis + 3] >= self.dims[axis]
                for axis in range(3)
            )
            low = [
                max(coordinates[axis], 0)
                for axis in range(3)
            ]
            high = [
                min(coordinates[axis + 3], self.dims[axis] - 1)
                for axis in range(3)
            ]
            added = 0
            if all(low[axis] <= high[axis] for axis in range(3)):
                for x_index in range(low[0], high[0] + 1):
                    for y_index in range(low[1], high[1] + 1):
                        for z_index in range(low[2], high[2] + 1):
                            coordinate = (x_index, y_index, z_index)
                            if coordinate not in self._dirty:
                                self._dirty.add(coordinate)
                                added += 1
            return {
                "status": "applied",
                "added": added,
                "clamped": clamped,
                "dirty": len(self._dirty),
            }

    def update(self, frame: int) -> dict:
        with self._lock:
            frame = self._checked_frame(frame)
            if self._frame is not None and frame < self._frame:
                raise IrradianceVolumeError("IR_STALE_FRAME", frame)
            if self._frame is not None and frame == self._frame:
                return {
                    "status": "ignored",
                    "code": "IR_DUP_FRAME",
                    "processed": 0,
                    "remaining": len(self._dirty),
                    "generation": self._generation,
                    "frame": frame,
                }

            self._frame = frame
            if not self._dirty:
                return {
                    "status": "noop",
                    "processed": 0,
                    "remaining": 0,
                    "generation": self._generation,
                    "frame": frame,
                }

            before = len(self._dirty)
            selected = sorted(self._dirty)[:self.max_updates_per_frame]
            for coordinate in selected:
                self._dirty.remove(coordinate)
            processed = len(selected)
            self._generation += 1
            return {
                "status": "applied",
                "processed": processed,
                "remaining": before - processed,
                "generation": self._generation,
                "frame": frame,
            }

    def sample(self, position: tuple[float, float, float]) -> dict:
        with self._lock:
            coordinates = self._checked_position(position)
            maximums = tuple(
                axis * self.voxel_size for axis in self.dims
            )
            clamped = any(
                coordinates[axis] < 0.0 or
                coordinates[axis] > maximums[axis]
                for axis in range(3)
            )
            lower = []
            upper = []
            fractions = []
            for axis in range(3):
                value = min(max(coordinates[axis], 0.0), maximums[axis])
                if self.dims[axis] <= 1:
                    lower.append(0)
                    upper.append(0)
                    fractions.append(0.0)
                    continue
                unclamped = value / self.voxel_size - 0.5
                first = math.floor(unclamped)
                first = min(max(first, 0), self.dims[axis] - 2)
                fraction = unclamped - first
                fraction = min(max(fraction, 0.0), 1.0)
                lower.append(first)
                upper.append(first + 1)
                fractions.append(fraction)

            corners = []
            weights = []
            for z_corner in (0, 1):
                for y_corner in (0, 1):
                    for x_corner in (0, 1):
                        corners.append((
                            upper[0] if x_corner else lower[0],
                            upper[1] if y_corner else lower[1],
                            upper[2] if z_corner else lower[2],
                        ))
                        weights.append(
                            (fractions[0] if x_corner else 1.0 - fractions[0])
                            * (fractions[1] if y_corner
                               else 1.0 - fractions[1])
                            * (fractions[2] if z_corner
                               else 1.0 - fractions[2])
                        )

            total_weight = sum(weights)
            if total_weight != 1.0 and total_weight > 0.0:
                weights = [
                    weight / total_weight for weight in weights
                ]
            correction = 1.0 - sum(weights)
            if correction:
                weights[-1] += correction

            coefficients = [0.0] * SH_COEFFICIENTS
            for corner, weight in zip(corners, weights):
                voxel = self._voxels.get(corner)
                if voxel is None:
                    continue
                for channel in range(SH_COEFFICIENTS):
                    coefficients[channel] += weight * voxel[channel]

            return {
                "sh": tuple(coefficients),
                "cell": tuple(lower),
                "weights": tuple(weights),
                "clamped": clamped,
            }

    def freeze(self) -> dict:
        with self._lock:
            self._frozen = True
            return {"status": "frozen", "frozen": True}

    def unfreeze(self) -> dict:
        with self._lock:
            self._frozen = False
            return {"status": "unfrozen", "frozen": False}

    def generation(self) -> int:
        with self._lock:
            return self._generation

    def clear(self) -> dict:
        with self._lock:
            if self._frozen:
                raise IrradianceVolumeError("IR_FROZEN")
            cleared_voxels = len(self._voxels)
            cleared_dirty = len(self._dirty)
            self._voxels.clear()
            self._dirty.clear()
            self._generation += 1
            return {
                "status": "applied",
                "cleared_voxels": cleared_voxels,
                "cleared_dirty": cleared_dirty,
                "generation": self._generation,
            }

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": SNAPSHOT_VERSION,
                "values": [
                    (coordinate, self._voxels[coordinate])
                    for coordinate in sorted(self._voxels)
                ],
                "dirty": sorted(self._dirty),
                "generation": self._generation,
                "frozen": self._frozen,
                "frame": self._frame,
            }

    def _parse_snapshot_values(self, raw_values):
        if isinstance(raw_values, dict):
            entries = list(raw_values.items())
        elif isinstance(raw_values, (list, tuple)):
            entries = list(raw_values)
        else:
            raise IrradianceVolumeError("IR_SNAPSHOT_INVALID", "values")

        values = {}
        for entry in entries:
            if isinstance(entry, dict):
                index = entry.get("index", entry.get("coord"))
                sh = entry.get("sh", entry.get("value"))
            elif isinstance(entry, (list, tuple)) and len(entry) == 2:
                index, sh = entry
            else:
                raise IrradianceVolumeError(
                    "IR_SNAPSHOT_INVALID", "values"
                )
            try:
                coordinate = self._checked_index(index)
                coefficients = self._checked_sh(sh)
            except IrradianceVolumeError as exc:
                raise IrradianceVolumeError(
                    "IR_SNAPSHOT_INVALID", "values"
                ) from exc
            if coordinate in values:
                raise IrradianceVolumeError(
                    "IR_SNAPSHOT_INVALID", "values"
                )
            values[coordinate] = coefficients
        return values

    def _parse_snapshot_dirty(self, raw_dirty):
        if isinstance(raw_dirty, dict):
            entries = list(raw_dirty.keys())
        elif isinstance(raw_dirty, (list, tuple, set, frozenset)):
            entries = list(raw_dirty)
        else:
            raise IrradianceVolumeError("IR_SNAPSHOT_INVALID", "dirty")

        dirty = set()
        for entry in entries:
            if isinstance(entry, dict):
                entry = entry.get("index", entry.get("coord"))
            try:
                coordinate = self._checked_index(entry)
            except IrradianceVolumeError as exc:
                raise IrradianceVolumeError(
                    "IR_SNAPSHOT_INVALID", "dirty"
                ) from exc
            dirty.add(coordinate)
        return dirty

    def restore(self, snapshot: dict) -> dict:
        with self._lock:
            if not isinstance(snapshot, dict):
                raise IrradianceVolumeError("IR_SNAPSHOT_INVALID")
            if "version" not in snapshot:
                raise IrradianceVolumeError("IR_SNAPSHOT_INVALID", "version")
            version = snapshot["version"]
            if not _is_integer(version) or version != SNAPSHOT_VERSION:
                raise IrradianceVolumeError(
                    "IR_SNAPSHOT_VERSION", version
                )
            for key in ("values", "dirty", "generation", "frozen"):
                if key not in snapshot:
                    raise IrradianceVolumeError(
                        "IR_SNAPSHOT_INVALID", key
                    )

            if "frame" in snapshot:
                raw_frame = snapshot["frame"]
            elif "frames" in snapshot:
                raw_frame = snapshot["frames"]
            elif "last_frame" in snapshot:
                raw_frame = snapshot["last_frame"]
            else:
                raise IrradianceVolumeError(
                    "IR_SNAPSHOT_INVALID", "frame"
                )

            generation = snapshot["generation"]
            if not _is_integer(generation) or generation < 0:
                raise IrradianceVolumeError(
                    "IR_SNAPSHOT_INVALID", "generation"
                )
            frozen = snapshot["frozen"]
            if not isinstance(frozen, bool):
                raise IrradianceVolumeError(
                    "IR_SNAPSHOT_INVALID", "frozen"
                )
            if raw_frame is not None and not _is_integer(raw_frame):
                raise IrradianceVolumeError(
                    "IR_SNAPSHOT_INVALID", "frame"
                )
            frame = None if raw_frame is None else int(raw_frame)

            values = self._parse_snapshot_values(snapshot["values"])
            dirty = self._parse_snapshot_dirty(snapshot["dirty"])

            self._voxels = values
            self._dirty = dirty
            self._generation = int(generation)
            self._frozen = frozen
            self._frame = frame
            return {
                "status": "restored",
                "voxels": len(self._voxels),
                "dirty": len(self._dirty),
                "generation": self._generation,
                "frozen": self._frozen,
                "frame": self._frame,
            }

    def stats(self) -> dict:
        with self._lock:
            return {
                "voxels": len(self._voxels),
                "dirty": len(self._dirty),
                "generation": self._generation,
                "frames": 0 if self._frame is None else self._frame,
                "frame": self._frame,
                "frozen": self._frozen,
            }
