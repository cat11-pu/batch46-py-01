"""Light probe volume: tetrahedral interpolation, validity and bake transactions."""

import math
import threading


SNAPSHOT_VERSION = 1
MAX_COLOR_CHANNEL = 64.0
_WEIGHT_EPSILON = 1e-12

# Fixed corner order: c000, c100, c010, c110, c001, c101, c011, c111.
_CORNER_OFFSETS = (
    (0, 0, 0), (1, 0, 0), (0, 1, 0), (1, 1, 0),
    (0, 0, 1), (1, 0, 1), (0, 1, 1), (1, 1, 1),
)


class LightProbeError(ValueError):
    """Domain error carrying a stable machine-readable code."""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class LightProbe:
    """Irradiance probe grid with tetrahedral sampling and exposure control."""

    def __init__(self, *, bounds=((0.0, 0.0, 0.0), (8.0, 8.0, 8.0)),
                 spacing: float = 1.0, max_probes: int = 4096):
        normalized_bounds = self._normalize_bounds(bounds)
        normalized_spacing = self._normalize_spacing(spacing)
        shape = self._derive_shape(normalized_bounds, normalized_spacing)
        if (isinstance(max_probes, bool)
                or not isinstance(max_probes, int) or max_probes < 0):
            raise LightProbeError("LP_INVALID_CONFIG", "max_probes")

        self._lock = threading.RLock()
        self.bounds = normalized_bounds
        self.spacing = normalized_spacing
        self.max_probes = max_probes
        self._shape = shape
        self._probes = {}
        self._exposure = 1.0
        self._generation = 0
        self._frame = None
        self._samples = 0

    @staticmethod
    def _is_number(value):
        return (isinstance(value, (int, float))
                and not isinstance(value, bool))

    @classmethod
    def _normalize_bounds(cls, bounds):
        try:
            if len(bounds) != 2:
                raise ValueError
            lower = tuple(float(value) for value in bounds[0])
            upper = tuple(float(value) for value in bounds[1])
        except (TypeError, ValueError, IndexError):
            raise LightProbeError("LP_INVALID_CONFIG", "bounds") from None
        if len(lower) != 3 or len(upper) != 3:
            raise LightProbeError("LP_INVALID_CONFIG", "bounds")
        for low, high in zip(lower, upper):
            if not math.isfinite(low) or not math.isfinite(high):
                raise LightProbeError("LP_INVALID_CONFIG", "bounds")
            if low >= high:
                raise LightProbeError("LP_INVALID_CONFIG", "bounds")
        return (lower, upper)

    @classmethod
    def _normalize_spacing(cls, spacing):
        if not cls._is_number(spacing):
            raise LightProbeError("LP_INVALID_CONFIG", "spacing")
        value = float(spacing)
        if not math.isfinite(value) or value <= 0.0:
            raise LightProbeError("LP_INVALID_CONFIG", "spacing")
        return value

    @staticmethod
    def _derive_shape(bounds, spacing):
        shape = []
        for low, high in zip(bounds[0], bounds[1]):
            count = int(round((high - low) / spacing)) + 1
            if count < 2:
                raise LightProbeError("LP_INVALID_CONFIG", "grid")
            shape.append(count)
        return tuple(shape)

    @staticmethod
    def _normalize_color(color, code):
        try:
            values = tuple(color)
        except TypeError:
            raise LightProbeError(code, "color") from None
        if len(values) != 3:
            raise LightProbeError(code, "color")
        normalized = []
        for value in values:
            if (isinstance(value, bool)
                    or not isinstance(value, (int, float))):
                raise LightProbeError(code, "color")
            value = float(value)
            if not math.isfinite(value):
                raise LightProbeError(code, "color")
            normalized.append(value)
        return tuple(normalized)

    @staticmethod
    def _normalize_exposure(exposure):
        if (isinstance(exposure, bool)
                or not isinstance(exposure, (int, float))):
            raise LightProbeError("LP_INVALID_EXPOSURE")
        value = float(exposure)
        if not math.isfinite(value) or not 0.0 < value <= 16.0:
            raise LightProbeError("LP_INVALID_EXPOSURE")
        return value

    def _validate_coord(self, coord):
        if not isinstance(coord, tuple) or len(coord) != 3:
            raise LightProbeError("LP_INDEX_RANGE", coord)
        for value in coord:
            if (isinstance(value, bool)
                    or not isinstance(value, int)):
                raise LightProbeError("LP_INDEX_RANGE", coord)
        for value, size in zip(coord, self._shape):
            if value < 0 or value >= size:
                raise LightProbeError("LP_INDEX_RANGE", coord)
        return coord

    @staticmethod
    def _coord_is_valid(coord, shape):
        if not isinstance(coord, tuple) or len(coord) != 3:
            return False
        for value in coord:
            if (isinstance(value, bool)
                    or not isinstance(value, int)):
                return False
        return all(0 <= value < size
                   for value, size in zip(coord, shape))

    @staticmethod
    def _clamp_position(position, bounds, spacing, shape):
        try:
            values = tuple(position)
        except TypeError:
            raise LightProbeError("LP_INVALID_POSITION") from None
        if len(values) != 3:
            raise LightProbeError("LP_INVALID_POSITION")

        lower, upper = bounds
        clamped = False
        fractions = []
        cells = []
        for index, value in enumerate(values):
            if (isinstance(value, bool)
                    or not isinstance(value, (int, float))):
                raise LightProbeError("LP_INVALID_POSITION")
            value = float(value)
            if not math.isfinite(value):
                raise LightProbeError("LP_INVALID_POSITION")

            low = lower[index]
            high = upper[index]
            if value < low:
                value = low
                clamped = True
            elif value > high:
                value = high
                clamped = True

            local = (value - low) / spacing
            last_cell = shape[index] - 2
            if local >= last_cell + 1:
                cell = last_cell
                fraction = 1.0
            else:
                cell = int(math.floor(local))
                if cell < 0:
                    cell = 0
                elif cell > last_cell:
                    cell = last_cell
                fraction = local - cell
                fraction = min(1.0, max(0.0, fraction))
            cells.append(cell)
            fractions.append(fraction)

        return tuple(cells), tuple(fractions), clamped

    @staticmethod
    def _tetrahedral_weights(fx, fy, fz):
        """Return deterministic barycentric weights for the eight corners."""

        x, y, z = fx, fy, fz
        # Five tetrahedra: one central tetrahedron plus the four corner
        # tetrahedra at c000, c110, c101 and c011.  The central tetrahedron
        # is tested first so symmetric points such as the cube centre have
        # four positive, stable weights.
        candidates = (
            ((1, 2, 4, 7), (
                (1.0 + x - y - z) / 2.0,
                (1.0 - x + y - z) / 2.0,
                (1.0 - x - y + z) / 2.0,
                (x + y + z - 1.0) / 2.0,
            )),
            ((0, 1, 2, 4), (
                1.0 - x - y - z,
                x,
                y,
                z,
            )),
            ((3, 1, 2, 7), (
                x + y - z - 1.0,
                1.0 - y,
                1.0 - x,
                z,
            )),
            ((5, 1, 4, 7), (
                x + z - y - 1.0,
                1.0 - z,
                1.0 - x,
                y,
            )),
            ((6, 2, 4, 7), (
                y + z - x - 1.0,
                1.0 - z,
                1.0 - y,
                x,
            )),
        )

        chosen = None
        fallback = None
        fallback_score = None
        for indices, values in candidates:
            smallest = min(values)
            if fallback_score is None or smallest > fallback_score:
                fallback = (indices, values)
                fallback_score = smallest
            if smallest >= -_WEIGHT_EPSILON:
                chosen = (indices, values)
                break
        if chosen is None:
            chosen = fallback

        weights = [0.0] * 8
        indices, values = chosen
        for index, value in zip(indices, values):
            weights[index] = max(0.0, value)

        total = sum(weights)
        if total <= 0.0 or not math.isfinite(total):
            weights = [0.0] * 8
            weights[0] = 1.0
        else:
            weights = [value / total for value in weights]

        # Remove the last few rounding bits so repeated calls are not only
        # equal numerically but add up to exactly one.
        residual = 1.0 - sum(weights)
        if residual:
            largest = max(range(8), key=weights.__getitem__)
            weights[largest] += residual
        return tuple(weights)

    @staticmethod
    def _normalize_weights(weights, available):
        if not available:
            raise LightProbeError("LP_NO_VALID_PROBE")

        total = sum(weights[index] for index in available)
        normalized = [0.0] * 8
        if total > 0.0 and math.isfinite(total):
            for index in available:
                normalized[index] = weights[index] / total
        else:
            share = 1.0 / len(available)
            for index in available:
                normalized[index] = share

        residual = 1.0 - sum(normalized)
        if residual:
            largest = max(range(8), key=normalized.__getitem__)
            normalized[largest] += residual
        return tuple(normalized)

    def set_probe(self, coord: tuple[int, int, int], *,
                  color: tuple[float, float, float],
                  valid: bool = True) -> dict:
        with self._lock:
            coord = self._validate_coord(coord)
            normalized_color = self._normalize_color(
                color, "LP_INVALID_UPDATE")
            existed = coord in self._probes
            if not existed and len(self._probes) >= self.max_probes:
                raise LightProbeError("LP_BUDGET_EXCEEDED")
            self._probes[coord] = {
                "color": normalized_color,
                "valid": bool(valid),
            }
            return {
                "status": "updated" if existed else "created",
                "coord": coord,
                "color": normalized_color,
                "valid": bool(valid),
                "probes": len(self._probes),
                "generation": self._generation,
            }

    def remove_probe(self, coord: tuple[int, int, int]) -> dict:
        with self._lock:
            coord = self._validate_coord(coord)
            removed = self._probes.pop(coord, None) is not None
            return {
                "status": "removed" if removed else "missing",
                "removed": removed,
                "coord": coord,
                "probes": len(self._probes),
                "generation": self._generation,
            }

    def invalidate(self, coords: list[tuple[int, int, int]]) -> dict:
        with self._lock:
            invalidated = 0
            missing = 0
            seen = set()
            try:
                iterator = iter(coords)
            except TypeError:
                raise LightProbeError("LP_INVALID_UPDATE") from None

            for coord in iterator:
                if isinstance(coord, tuple) and len(coord) == 3:
                    try:
                        if coord in seen:
                            continue
                        seen.add(coord)
                    except TypeError:
                        pass
                if not self._coord_is_valid(coord, self._shape):
                    missing += 1
                    continue
                entry = self._probes.get(coord)
                if entry is None:
                    missing += 1
                elif entry["valid"]:
                    entry["valid"] = False
                    invalidated += 1
            return {
                "invalidated": invalidated,
                "missing": missing,
                "probes": len(self._probes),
            }

    def probe_at(self, position: tuple[float, float, float]) -> dict:
        with self._lock:
            cell, fractions, clamped = self._clamp_position(
                position, self.bounds, self.spacing, self._shape)
            raw_weights = self._tetrahedral_weights(*fractions)

            entries = []
            available = []
            for index, offset in enumerate(_CORNER_OFFSETS):
                coord = (
                    cell[0] + offset[0],
                    cell[1] + offset[1],
                    cell[2] + offset[2],
                )
                entry = self._probes.get(coord)
                entries.append(entry)
                if entry is not None and entry["valid"]:
                    available.append(index)

            weights = self._normalize_weights(raw_weights, available)

            color = [0.0, 0.0, 0.0]
            for index, weight in enumerate(weights):
                if weight == 0.0:
                    continue
                probe_color = entries[index]["color"]
                for channel in range(3):
                    color[channel] += weight * probe_color[channel]
            color = tuple(
                min(value * self._exposure, MAX_COLOR_CHANNEL)
                for value in color
            )

            self._samples += 1
            return {
                "cell": cell,
                "weights": weights,
                "color": color,
                "clamped": clamped,
            }

    def sample_many(self,
                    positions: list[tuple[float, float, float]]) -> list[dict]:
        results = []
        try:
            iterator = enumerate(positions)
        except TypeError:
            raise LightProbeError("LP_INVALID_POSITION") from None
        for index, position in iterator:
            try:
                results.append(self.probe_at(position))
            except LightProbeError as error:
                detail = {
                    "index": index,
                    "results": results,
                    "partial": results,
                    "completed": len(results),
                }
                if error.detail is not None:
                    detail["cause"] = error.detail
                error.detail = detail
                raise
        return results

    def bake(self, frame: int, updates: list[dict]) -> dict:
        with self._lock:
            if (isinstance(frame, bool)
                    or not isinstance(frame, int)):
                raise LightProbeError("LP_INVALID_UPDATE", "frame")

            if self._frame is not None:
                if frame == self._frame:
                    return {
                        "status": "ignored",
                        "code": "LP_DUP_FRAME",
                        "updated": 0,
                        "generation": self._generation,
                        "frame": frame,
                    }
                if frame < self._frame:
                    raise LightProbeError("LP_STALE_FRAME")

            if updates is None:
                raise LightProbeError("LP_INVALID_UPDATE", "updates")

            try:
                iterator = iter(updates)
            except TypeError:
                raise LightProbeError(
                    "LP_INVALID_UPDATE", "updates") from None

            if not updates:
                self._frame = frame
                return {
                    "status": "noop",
                    "updated": 0,
                    "generation": self._generation,
                    "frame": frame,
                }

            normalized_updates = []
            new_coords = set()
            for update in iterator:
                if not isinstance(update, dict):
                    raise LightProbeError("LP_INVALID_UPDATE", "entry")
                if "coord" not in update or "color" not in update:
                    raise LightProbeError("LP_INVALID_UPDATE", "entry")
                coord = update["coord"]
                if not self._coord_is_valid(coord, self._shape):
                    raise LightProbeError("LP_INVALID_UPDATE", "coord")
                color = self._normalize_color(
                    update["color"], "LP_INVALID_UPDATE")
                valid = bool(update.get("valid", True))
                normalized_updates.append((coord, color, valid))
                if coord not in self._probes:
                    new_coords.add(coord)

            if len(self._probes) + len(new_coords) > self.max_probes:
                raise LightProbeError("LP_BUDGET_EXCEEDED")

            for coord, color, valid in normalized_updates:
                self._probes[coord] = {
                    "color": color,
                    "valid": valid,
                }
            self._generation += 1
            self._frame = frame
            return {
                "status": "applied",
                "updated": len(normalized_updates),
                "generation": self._generation,
                "frame": frame,
            }

    def set_exposure(self, exposure: float) -> dict:
        normalized = self._normalize_exposure(exposure)
        with self._lock:
            self._exposure = normalized
            return {
                "status": "applied",
                "exposure": normalized,
                "generation": self._generation,
            }

    def grid_shape(self) -> tuple[int, int, int]:
        with self._lock:
            return self._shape

    def snapshot(self) -> dict:
        with self._lock:
            probes = []
            for coord in sorted(self._probes):
                entry = self._probes[coord]
                probes.append({
                    "coord": coord,
                    "color": entry["color"],
                    "valid": entry["valid"],
                })
            return {
                "version": SNAPSHOT_VERSION,
                "bounds": self.bounds,
                "spacing": self.spacing,
                "max_probes": self.max_probes,
                "exposure": self._exposure,
                "probes": probes,
                "frame": self._frame,
                "generation": self._generation,
            }

    def restore(self, snapshot: dict) -> dict:
        with self._lock:
            if not isinstance(snapshot, dict):
                raise LightProbeError("LP_SNAPSHOT_INVALID")
            if "version" not in snapshot:
                raise LightProbeError("LP_SNAPSHOT_INVALID")
            if snapshot["version"] != SNAPSHOT_VERSION:
                raise LightProbeError("LP_SNAPSHOT_VERSION")

            required = (
                "bounds", "spacing", "exposure", "probes",
                "frame", "generation",
            )
            if any(key not in snapshot for key in required):
                raise LightProbeError("LP_SNAPSHOT_INVALID")

            try:
                bounds = self._normalize_bounds(snapshot["bounds"])
                spacing = self._normalize_spacing(snapshot["spacing"])
                shape = self._derive_shape(bounds, spacing)
                exposure = self._normalize_exposure(
                    snapshot["exposure"])

                if "max_probes" in snapshot:
                    max_probes = snapshot["max_probes"]
                    if (isinstance(max_probes, bool)
                            or not isinstance(max_probes, int)
                            or max_probes < 0):
                        raise ValueError
                else:
                    max_probes = self.max_probes

                raw_probes = snapshot["probes"]
                if not isinstance(raw_probes, (list, tuple)):
                    raise ValueError
                probes = {}
                for row in raw_probes:
                    if not isinstance(row, dict):
                        raise ValueError
                    if ("coord" not in row or "color" not in row
                            or "valid" not in row):
                        raise ValueError
                    coord = row["coord"]
                    if not self._coord_is_valid(coord, shape):
                        raise ValueError
                    if coord in probes:
                        raise ValueError
                    color = self._normalize_color(
                        row["color"], "LP_SNAPSHOT_INVALID")
                    valid = row["valid"]
                    if not isinstance(valid, bool):
                        raise ValueError
                    probes[coord] = {
                        "color": color,
                        "valid": valid,
                    }
                if len(probes) > max_probes:
                    raise ValueError

                frame = snapshot["frame"]
                if frame is not None:
                    if (isinstance(frame, bool)
                            or not isinstance(frame, int)):
                        raise ValueError

                generation = snapshot["generation"]
                if (isinstance(generation, bool)
                        or not isinstance(generation, int)
                        or generation < 0):
                    raise ValueError
            except LightProbeError as error:
                raise LightProbeError(
                    "LP_SNAPSHOT_INVALID", error.detail) from None
            except (TypeError, ValueError, IndexError):
                raise LightProbeError("LP_SNAPSHOT_INVALID") from None

            self.bounds = bounds
            self.spacing = spacing
            self.max_probes = max_probes
            self._shape = shape
            self._exposure = exposure
            self._probes = probes
            self._frame = frame
            self._generation = generation
            return {
                "status": "restored",
                "probes": len(self._probes),
                "frame": self._frame,
                "generation": self._generation,
            }

    def stats(self) -> dict:
        with self._lock:
            valid_probes = sum(
                1 for entry in self._probes.values() if entry["valid"])
            return {
                "probes": len(self._probes),
                "valid_probes": valid_probes,
                "generation": self._generation,
                "samples": self._samples,
                "frame": self._frame,
                "exposure": self._exposure,
                "max_probes": self.max_probes,
                "grid_shape": self._shape,
            }
