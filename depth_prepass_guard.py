"""深度预通道：深度缓冲、层级剔除、绘制排序与快照。"""

import copy
import math
import threading

SNAPSHOT_VERSION = 1

_DEPTH_ENTRY_BYTES = 8
_DRAW_ENTRY_BYTES = 96
_PYRAMID_ENTRY_BYTES = 8


class DepthPrepassError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _is_number(value):
    return (isinstance(value, (int, float))
            and not isinstance(value, bool)
            and math.isfinite(value))


def _validated_viewport(width, height, near, far):
    if not _is_int(width) or not _is_int(height) or width <= 0 or height <= 0:
        raise DepthPrepassError("DP_BAD_VIEWPORT")
    if not _is_number(near) or not _is_number(far):
        raise DepthPrepassError("DP_BAD_VIEWPORT")
    if near < 0 or far <= near:
        raise DepthPrepassError("DP_BAD_VIEWPORT")
    return width, height, near, far


def _validated_bounds(bounds, width, height):
    if not isinstance(bounds, (tuple, list)) or len(bounds) != 4:
        raise DepthPrepassError("DP_BAD_DRAW")
    if any(not _is_int(value) for value in bounds):
        raise DepthPrepassError("DP_BAD_DRAW")
    x0, y0, x1, y1 = bounds
    if x0 >= x1 or y0 >= y1:
        raise DepthPrepassError("DP_BAD_DRAW")
    if x0 < 0 or y0 < 0 or x1 > width or y1 > height:
        raise DepthPrepassError("DP_DRAW_OOB")
    return x0, y0, x1, y1


def _validated_draw(draw, width, height):
    if not isinstance(draw, dict):
        raise DepthPrepassError("DP_BAD_DRAW")
    for field in ("id", "depth_min", "depth_max", "bounds"):
        if field not in draw:
            raise DepthPrepassError("DP_BAD_DRAW")

    draw_id = draw["id"]
    try:
        hash(draw_id)
    except TypeError:
        raise DepthPrepassError("DP_BAD_DRAW") from None

    depth_min = draw["depth_min"]
    depth_max = draw["depth_max"]
    if (not _is_number(depth_min) or not _is_number(depth_max)
            or depth_min < 0 or depth_max < 0 or depth_min > depth_max):
        raise DepthPrepassError("DP_BAD_DRAW")

    bounds = _validated_bounds(draw["bounds"], width, height)

    normalized = dict(draw)
    normalized["depth_min"] = float(depth_min)
    normalized["depth_max"] = float(depth_max)
    normalized["bounds"] = bounds
    normalized["alpha_test"] = bool(draw.get("alpha_test", False))
    normalized.setdefault("material", None)
    return normalized


def _sort_draws(draws):
    try:
        return sorted(draws, key=lambda row: (row["depth_min"], row["id"]))
    except TypeError:
        return sorted(draws,
                      key=lambda row: (row["depth_min"], repr(row["id"])))


class DepthPrepass:
    """深度预通道的深度缓冲、保守遮挡查询、排序与快照恢复。"""

    def __init__(self, tile_size=8, depth_bits=24, max_draws=256):
        self._lock = threading.RLock()
        self._tile_size = tile_size
        self._depth_bits = depth_bits
        self._max_draws = max_draws
        self._viewport = None
        self._near = 0.1
        self._far = 1000.0
        self._depth = {}
        self._pass_active = False
        self._draws = {}
        self._seen_ids = set()
        self._epoch = 0

        self._pass_occluded = 0
        self._depth_writes = 0
        self._drawn = 0
        self._occluded_total = 0
        self._duplicate_draws = 0

        self._pyramid_values = None
        self._pyramid_dims = []
        self._tile_geometry = None
        self._pyramid_builds = 0

    # ------------------------------------------------------------------
    # Viewport and pass lifecycle
    # ------------------------------------------------------------------
    def set_viewport(self, width, height, near=0.1, far=1000.0):
        with self._lock:
            width, height, near, far = _validated_viewport(
                width, height, near, far)

            self._viewport = (width, height)
            self._near = near
            self._far = far

            self._depth.clear()
            self._draws.clear()
            self._seen_ids.clear()
            self._pass_active = False
            self._pass_occluded = 0
            self._invalidate_pyramid()

            return {
                "width": width,
                "height": height,
                "near": near,
                "far": far,
            }

    def begin_pass(self):
        with self._lock:
            if self._viewport is None:
                raise DepthPrepassError("DP_NOT_READY")
            if self._pass_active:
                raise DepthPrepassError("DP_PASS_STATE")

            self._epoch += 1
            self._depth.clear()
            self._draws.clear()
            self._seen_ids.clear()
            self._pass_active = True
            self._pass_occluded = 0
            self._invalidate_pyramid()
            return self._epoch

    def end_pass(self):
        with self._lock:
            if not self._pass_active:
                raise DepthPrepassError("DP_PASS_STATE")

            opaque = [draw for draw in self._draws.values()
                      if not draw["alpha_test"]]
            transparent = [draw for draw in self._draws.values()
                           if draw["alpha_test"]]
            ordered = _sort_draws(opaque) + _sort_draws(transparent)

            state_switches = 0
            previous_material = None
            first = True
            for draw in ordered:
                material = draw.get("material")
                if not first and material != previous_material:
                    state_switches += 1
                previous_material = material
                first = False

            self._drawn += len(ordered)
            self._pass_active = False

            return {
                "order": [draw["id"] for draw in ordered],
                "draws": len(ordered),
                "occluded": self._pass_occluded,
                "state_switches": state_switches,
            }

    # ------------------------------------------------------------------
    # Depth buffer
    # ------------------------------------------------------------------
    def write_depth(self, pixel, depth):
        with self._lock:
            if not _is_number(depth) or depth < 0 or depth > 1:
                raise DepthPrepassError("DP_DEPTH_RANGE")
            if self._viewport is None:
                raise DepthPrepassError("DP_PIXEL_OOB")

            x, y = self._validated_pixel(pixel)
            key = (x, y)
            previous = self._depth.get(key)
            if previous is not None and depth >= previous:
                return {
                    "pixel": (x, y),
                    "depth": previous,
                    "written": False,
                }

            self._depth[key] = float(depth)
            self._depth_writes += 1
            self._invalidate_pyramid()
            return {
                "pixel": (x, y),
                "depth": float(depth),
                "written": True,
            }

    def depth_at(self, pixel):
        with self._lock:
            if self._viewport is None:
                return None
            try:
                key = self._validated_pixel(pixel)
            except DepthPrepassError:
                return None
            return self._depth.get(key)

    def _validated_pixel(self, pixel):
        if not isinstance(pixel, (tuple, list)) or len(pixel) != 2:
            raise DepthPrepassError("DP_PIXEL_OOB")
        x, y = pixel
        if not _is_int(x) or not _is_int(y):
            raise DepthPrepassError("DP_PIXEL_OOB")
        width, height = self._viewport
        if x < 0 or y < 0 or x >= width or y >= height:
            raise DepthPrepassError("DP_PIXEL_OOB")
        return x, y

    # ------------------------------------------------------------------
    # Tile pyramid and conservative occlusion
    # ------------------------------------------------------------------
    def build_pyramid(self):
        with self._lock:
            if self._viewport is None:
                return []
            self._ensure_pyramid()
            return [
                {"level": level, "width": width, "height": height}
                for level, (width, height) in enumerate(self._pyramid_dims)
            ]

    def hiz_query(self, rect, depth):
        with self._lock:
            if self._viewport is None:
                raise DepthPrepassError("DP_NOT_READY")
            if not _is_number(depth) or depth < 0 or depth > 1:
                raise DepthPrepassError("DP_DEPTH_RANGE")

            x0, y0, x1, y1 = self._validated_rect(rect)
            self._ensure_pyramid()

            tile_size = self._tile_size
            tx0 = x0 // tile_size
            ty0 = y0 // tile_size
            tx1 = (x1 - 1) // tile_size
            ty1 = (y1 - 1) // tile_size

            has_geometry = False
            level0 = self._pyramid_values[0]
            for ty in range(ty0, ty1 + 1):
                for tx in range(tx0, tx1 + 1):
                    if self._tile_geometry[ty][tx]:
                        has_geometry = True
                    if level0[ty][tx] > depth:
                        return False
            return has_geometry

    def _validated_rect(self, rect):
        if not isinstance(rect, (tuple, list)) or len(rect) != 4:
            raise DepthPrepassError("DP_RECT_OOB")
        if any(not _is_int(value) for value in rect):
            raise DepthPrepassError("DP_RECT_OOB")
        x0, y0, x1, y1 = rect
        width, height = self._viewport
        if (x0 < 0 or y0 < 0 or x1 > width or y1 > height
                or x0 >= x1 or y0 >= y1):
            raise DepthPrepassError("DP_RECT_OOB")
        return x0, y0, x1, y1

    def _invalidate_pyramid(self):
        self._pyramid_values = None
        self._pyramid_dims = []
        self._tile_geometry = None

    def _ensure_pyramid(self):
        if self._pyramid_values is not None:
            return

        width, height = self._viewport
        tile_size = self._tile_size
        grid_width = (width + tile_size - 1) // tile_size
        grid_height = (height + tile_size - 1) // tile_size

        counts = [[0] * grid_width for _ in range(grid_height)]
        maxima = [[0.0] * grid_width for _ in range(grid_height)]
        geometry = [[False] * grid_width for _ in range(grid_height)]

        for (x, y), value in self._depth.items():
            tx = x // tile_size
            ty = y // tile_size
            counts[ty][tx] += 1
            geometry[ty][tx] = True
            if value > maxima[ty][tx]:
                maxima[ty][tx] = value

        level0 = [[1.0] * grid_width for _ in range(grid_height)]
        for ty in range(grid_height):
            covered_height = min(tile_size, height - ty * tile_size)
            for tx in range(grid_width):
                covered_width = min(tile_size, width - tx * tile_size)
                total_pixels = covered_width * covered_height
                if counts[ty][tx] == total_pixels:
                    level0[ty][tx] = maxima[ty][tx]

        values = [level0]
        dims = [(grid_width, grid_height)]
        current_width, current_height = grid_width, grid_height
        while current_width > 1 or current_height > 1:
            next_width = (current_width + 1) // 2
            next_height = (current_height + 1) // 2
            previous = values[-1]
            parent = [[0.0] * next_width for _ in range(next_height)]
            for py in range(next_height):
                for px in range(next_width):
                    best = 0.0
                    for cy in (py * 2, py * 2 + 1):
                        if cy >= current_height:
                            continue
                        for cx in (px * 2, px * 2 + 1):
                            if cx >= current_width:
                                continue
                            if previous[cy][cx] > best:
                                best = previous[cy][cx]
                    parent[py][px] = best
            values.append(parent)
            dims.append((next_width, next_height))
            current_width, current_height = next_width, next_height

        self._pyramid_values = values
        self._pyramid_dims = dims
        self._tile_geometry = geometry
        self._pyramid_builds += 1

    def _draw_is_occluded(self, draw):
        self._ensure_pyramid()
        x0, y0, x1, y1 = draw["bounds"]
        tile_size = self._tile_size
        tx0 = x0 // tile_size
        ty0 = y0 // tile_size
        tx1 = (x1 - 1) // tile_size
        ty1 = (y1 - 1) // tile_size

        has_geometry = False
        level0 = self._pyramid_values[0]
        for ty in range(ty0, ty1 + 1):
            for tx in range(tx0, tx1 + 1):
                if self._tile_geometry[ty][tx]:
                    has_geometry = True
                if level0[ty][tx] > draw["depth_min"]:
                    return False
        return has_geometry

    # ------------------------------------------------------------------
    # Draw submission and ordering
    # ------------------------------------------------------------------
    def submit_draw(self, draw):
        with self._lock:
            if not self._pass_active:
                raise DepthPrepassError("DP_PASS_STATE")

            width, height = self._viewport
            normalized = _validated_draw(draw, width, height)
            draw_id = normalized["id"]

            if draw_id in self._seen_ids:
                self._duplicate_draws += 1
                return {
                    "id": draw_id,
                    "status": "ignored",
                    "code": "DP_DUP_DRAW",
                }

            if len(self._draws) >= self._max_draws:
                raise DepthPrepassError("DP_TOO_MANY_DRAWS")

            self._seen_ids.add(draw_id)
            transparent = normalized["alpha_test"]
            if not transparent and self._draw_is_occluded(normalized):
                self._pass_occluded += 1
                self._occluded_total += 1
                return {
                    "id": draw_id,
                    "status": "occluded",
                    "code": "DP_OCCLUDED",
                    "transparent": False,
                }

            self._draws[draw_id] = normalized
            return {
                "id": draw_id,
                "status": "scheduled",
                "transparent": transparent,
            }

    def sorted_draws(self):
        with self._lock:
            return self._sorted_draw_rows()

    def _sorted_draw_rows(self):
        opaque = [draw for draw in self._draws.values()
                  if not draw["alpha_test"]]
        transparent = [draw for draw in self._draws.values()
                       if draw["alpha_test"]]
        rows = _sort_draws(opaque) + _sort_draws(transparent)
        result = []
        for draw in rows:
            row = copy.deepcopy(draw)
            row["bounds"] = list(row["bounds"])
            row["transparent"] = row["alpha_test"]
            result.append(row)
        return result

    def filter_opaque(self, draws):
        with self._lock:
            if not isinstance(draws, (tuple, list)):
                raise DepthPrepassError("DP_BAD_DRAW")

            opaque = []
            for draw in draws:
                if not isinstance(draw, dict):
                    raise DepthPrepassError("DP_BAD_DRAW")
                if "id" not in draw or "depth_min" not in draw:
                    raise DepthPrepassError("DP_BAD_DRAW")
                depth_min = draw["depth_min"]
                if not _is_number(depth_min) or depth_min < 0:
                    raise DepthPrepassError("DP_BAD_DRAW")
                try:
                    hash(draw["id"])
                except TypeError:
                    raise DepthPrepassError("DP_BAD_DRAW") from None
                if not draw.get("alpha_test", False):
                    opaque.append({
                        "id": draw["id"],
                        "depth_min": float(depth_min),
                    })
            return [draw["id"] for draw in _sort_draws(opaque)]

    # ------------------------------------------------------------------
    # Accounting and diagnostics
    # ------------------------------------------------------------------
    def memory_usage(self):
        with self._lock:
            depth_bytes = len(self._depth) * _DEPTH_ENTRY_BYTES
            draw_bytes = len(self._draws) * _DRAW_ENTRY_BYTES
            pyramid_entries = sum(
                width * height for width, height in self._pyramid_dims)
            pyramid_bytes = pyramid_entries * _PYRAMID_ENTRY_BYTES
            return int(depth_bytes + draw_bytes + pyramid_bytes)

    def stats(self):
        with self._lock:
            return {
                "passes": self._epoch,
                "active": self._pass_active,
                "depth_pixels": len(self._depth),
                "depth_writes": self._depth_writes,
                "draws": len(self._draws),
                "drawn": self._drawn,
                "occluded": self._occluded_total,
                "pass_occluded": self._pass_occluded,
                "duplicate_draws": self._duplicate_draws,
                "pyramid_builds": self._pyramid_builds,
            }

    # ------------------------------------------------------------------
    # Snapshot / restore
    # ------------------------------------------------------------------
    def snapshot(self):
        with self._lock:
            viewport = None
            if self._viewport is not None:
                viewport = {
                    "width": self._viewport[0],
                    "height": self._viewport[1],
                    "near": self._near,
                    "far": self._far,
                }

            draws = []
            for draw in self._draws.values():
                row = copy.deepcopy(draw)
                row["bounds"] = list(row["bounds"])
                draws.append(row)

            return {
                "version": SNAPSHOT_VERSION,
                "config": {
                    "tile_size": self._tile_size,
                    "depth_bits": self._depth_bits,
                    "max_draws": self._max_draws,
                },
                "viewport": viewport,
                "depth": {
                    f"{x},{y}": value
                    for (x, y), value in self._depth.items()
                },
                "active": self._pass_active,
                "pass_active": self._pass_active,
                "epoch": self._epoch,
                "pass": self._epoch,
                "draws": draws,
                "seen_ids": sorted(self._seen_ids, key=repr),
                "occluded": self._pass_occluded,
                "counters": {
                    "depth_writes": self._depth_writes,
                    "drawn": self._drawn,
                    "occluded": self._occluded_total,
                    "duplicate_draws": self._duplicate_draws,
                    "pyramid_builds": self._pyramid_builds,
                },
            }

    def restore(self, snap):
        with self._lock:
            try:
                restored = self._parse_snapshot(snap)
            except (DepthPrepassError, KeyError, TypeError, ValueError,
                    IndexError):
                raise DepthPrepassError("DP_SNAPSHOT_INVALID") from None

            (tile_size, depth_bits, max_draws, viewport, near, far,
             depth, active, epoch, draws, seen_ids, pass_occluded,
             counters) = restored

            self._tile_size = tile_size
            self._depth_bits = depth_bits
            self._max_draws = max_draws
            self._viewport = viewport
            self._near = near
            self._far = far
            self._depth = depth
            self._pass_active = active
            self._epoch = epoch
            self._draws = {draw["id"]: draw for draw in draws}
            self._seen_ids = seen_ids
            self._pass_occluded = pass_occluded
            self._depth_writes = counters["depth_writes"]
            self._drawn = counters["drawn"]
            self._occluded_total = counters["occluded"]
            self._duplicate_draws = counters["duplicate_draws"]
            self._pyramid_builds = counters["pyramid_builds"]
            self._invalidate_pyramid()
            return self.stats()

    def _parse_snapshot(self, snap):
        if not isinstance(snap, dict):
            raise DepthPrepassError("DP_SNAPSHOT_INVALID")
        version = snap.get("version")
        if not _is_int(version) or version != SNAPSHOT_VERSION:
            raise DepthPrepassError("DP_SNAPSHOT_INVALID")

        config = snap.get("config", {})
        if not isinstance(config, dict):
            raise DepthPrepassError("DP_SNAPSHOT_INVALID")
        tile_size = config.get("tile_size", self._tile_size)
        depth_bits = config.get("depth_bits", self._depth_bits)
        max_draws = config.get("max_draws", self._max_draws)
        if (not _is_int(tile_size) or tile_size <= 0
                or not _is_int(depth_bits) or depth_bits <= 0
                or not _is_int(max_draws) or max_draws < 0):
            raise DepthPrepassError("DP_SNAPSHOT_INVALID")

        if "viewport" not in snap:
            raise DepthPrepassError("DP_SNAPSHOT_INVALID")
        raw_viewport = snap.get("viewport")
        if raw_viewport is None:
            viewport = None
            near, far = 0.1, 1000.0
        elif isinstance(raw_viewport, dict):
            try:
                width = raw_viewport["width"]
                height = raw_viewport["height"]
                near = raw_viewport.get("near", 0.1)
                far = raw_viewport.get("far", 1000.0)
            except KeyError:
                raise DepthPrepassError("DP_SNAPSHOT_INVALID") from None
            width, height, near, far = _validated_viewport(
                width, height, near, far)
            viewport = (width, height)
        else:
            raise DepthPrepassError("DP_SNAPSHOT_INVALID")

        raw_depth = snap.get("depth")
        if not isinstance(raw_depth, dict):
            raise DepthPrepassError("DP_SNAPSHOT_INVALID")
        depth = {}
        for key, value in raw_depth.items():
            if not isinstance(key, str) or key.count(",") != 1:
                raise DepthPrepassError("DP_SNAPSHOT_INVALID")
            left, right = key.split(",")
            try:
                x = int(left)
                y = int(right)
            except ValueError:
                raise DepthPrepassError("DP_SNAPSHOT_INVALID") from None
            if not _is_number(value) or value < 0 or value > 1:
                raise DepthPrepassError("DP_SNAPSHOT_INVALID")
            if viewport is None:
                raise DepthPrepassError("DP_SNAPSHOT_INVALID")
            width, height = viewport
            if x < 0 or y < 0 or x >= width or y >= height:
                raise DepthPrepassError("DP_SNAPSHOT_INVALID")
            depth[(x, y)] = float(value)

        if "pass_active" not in snap and "active" not in snap:
            raise DepthPrepassError("DP_SNAPSHOT_INVALID")
        active = snap.get("pass_active", snap.get("active"))
        if not isinstance(active, bool):
            raise DepthPrepassError("DP_SNAPSHOT_INVALID")
        if "active" in snap:
            if (not isinstance(snap["active"], bool)
                    or snap["active"] != active):
                raise DepthPrepassError("DP_SNAPSHOT_INVALID")

        if "pass" not in snap and "epoch" not in snap:
            raise DepthPrepassError("DP_SNAPSHOT_INVALID")
        epoch = snap.get("pass", snap.get("epoch"))
        if not _is_int(epoch) or epoch < 0:
            raise DepthPrepassError("DP_SNAPSHOT_INVALID")
        if "epoch" in snap:
            if not _is_int(snap["epoch"]) or snap["epoch"] != epoch:
                raise DepthPrepassError("DP_SNAPSHOT_INVALID")

        raw_draws = snap.get("draws")
        if not isinstance(raw_draws, list):
            raise DepthPrepassError("DP_SNAPSHOT_INVALID")
        draws = []
        draw_ids = set()
        for raw_draw in raw_draws:
            if viewport is None:
                raise DepthPrepassError("DP_SNAPSHOT_INVALID")
            draw = _validated_draw(raw_draw, viewport[0], viewport[1])
            if draw["id"] in draw_ids:
                raise DepthPrepassError("DP_SNAPSHOT_INVALID")
            draw_ids.add(draw["id"])
            draws.append(draw)
        if len(draws) > max_draws:
            raise DepthPrepassError("DP_SNAPSHOT_INVALID")

        raw_seen = snap.get("seen_ids", list(draw_ids))
        if not isinstance(raw_seen, list):
            raise DepthPrepassError("DP_SNAPSHOT_INVALID")
        seen_ids = set()
        for draw_id in raw_seen:
            try:
                hash(draw_id)
            except TypeError:
                raise DepthPrepassError("DP_SNAPSHOT_INVALID") from None
            seen_ids.add(draw_id)
        if not draw_ids.issubset(seen_ids):
            raise DepthPrepassError("DP_SNAPSHOT_INVALID")

        if "occluded" not in snap:
            raise DepthPrepassError("DP_SNAPSHOT_INVALID")
        pass_occluded = snap.get("occluded")
        if not _is_int(pass_occluded) or pass_occluded < 0:
            raise DepthPrepassError("DP_SNAPSHOT_INVALID")

        if "counters" not in snap:
            raise DepthPrepassError("DP_SNAPSHOT_INVALID")
        raw_counters = snap.get("counters")
        if not isinstance(raw_counters, dict):
            raise DepthPrepassError("DP_SNAPSHOT_INVALID")
        counters = {}
        for name in ("depth_writes", "drawn", "occluded", "duplicate_draws",
                     "pyramid_builds"):
            if name not in raw_counters:
                raise DepthPrepassError("DP_SNAPSHOT_INVALID")
            value = raw_counters[name]
            if not _is_int(value) or value < 0:
                raise DepthPrepassError("DP_SNAPSHOT_INVALID")
            counters[name] = value

        return (tile_size, depth_bits, max_draws, viewport, near, far,
                depth, active, epoch, draws, seen_ids, pass_occluded,
                counters)

    # ------------------------------------------------------------------
    # Reset
    # ------------------------------------------------------------------
    def reset(self):
        with self._lock:
            self._epoch += 1
            self._depth.clear()
            self._draws.clear()
            self._seen_ids.clear()
            self._pass_active = False
            self._pass_occluded = 0
            self._depth_writes = 0
            self._drawn = 0
            self._occluded_total = 0
            self._duplicate_draws = 0
            self._pyramid_builds = 0
            self._invalidate_pyramid()
            return self._epoch
