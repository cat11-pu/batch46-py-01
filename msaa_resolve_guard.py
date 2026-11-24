"""MSAA 样本存储、深度测试、tile 解析与显存预算管理。"""

import math
import threading


class MsaaError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class MsaaResolve:
    """多采样样本写入、深度测试、tile 解析、显存预算与快照恢复。"""

    _SUPPORTED_SAMPLE_COUNTS = (1, 2, 4, 8, 16)
    _RESOLVE_MODES = ("average", "min", "max")
    _BYTES_PER_SAMPLE = 24
    _SNAPSHOT_VERSION = 1

    def __init__(self, sample_count=4, tile_size=8, memory_budget=65536,
                 resolve_mode="average"):
        self._validate_sample_count(sample_count)
        self._validate_tile_size(tile_size)
        self._validate_memory_budget(memory_budget)
        self._validate_mode(resolve_mode)
        self._lock = threading.RLock()
        self._sample_count = sample_count
        self._tile_size = tile_size
        self._memory_budget = memory_budget
        self._resolve_mode = resolve_mode
        self._bounds = None
        self._samples = {}
        self._tile_pixels = {}
        self._dirty = set()
        self._epoch = 0
        self._tick = 0
        self._tile_last_write = {}
        self._eviction_order = []
        self._alpha_to_coverage = False
        self._counters = {
            "samples_written": 0,
            "duplicate_writes": 0,
            "rejected_depth": 0,
            "evictions": 0,
            "tiles_resolved": 0,
        }

    @staticmethod
    def _is_int(value):
        return isinstance(value, int) and not isinstance(value, bool)

    @classmethod
    def _validate_sample_count(cls, value, code="MSAA_BAD_SAMPLE_COUNT"):
        if not cls._is_int(value) or value not in cls._SUPPORTED_SAMPLE_COUNTS:
            raise MsaaError(code, value)

    @classmethod
    def _validate_tile_size(cls, value):
        if not cls._is_int(value) or value < 1:
            raise MsaaError("MSAA_BAD_TILE_SIZE", value)

    @classmethod
    def _validate_memory_budget(cls, value):
        if not cls._is_int(value) or value < 0:
            raise MsaaError("MSAA_BAD_MEMORY_BUDGET", value)

    @classmethod
    def _validate_mode(cls, value):
        if value not in cls._RESOLVE_MODES:
            raise MsaaError("MSAA_BAD_RESOLVE_MODE", value)

    @staticmethod
    def _normalize_color(color):
        if not isinstance(color, (tuple, list)) or len(color) != 4:
            raise MsaaError("MSAA_BAD_COLOR", color)
        result = []
        for channel in color:
            if isinstance(channel, bool) or not isinstance(channel, (int, float)):
                raise MsaaError("MSAA_BAD_COLOR", color)
            value = float(channel)
            if not math.isfinite(value) or value < 0.0 or value > 1.0:
                raise MsaaError("MSAA_BAD_COLOR", color)
            result.append(value)
        return tuple(result)

    @staticmethod
    def _normalize_coverage(coverage):
        if isinstance(coverage, bool) or not isinstance(coverage, (int, float)):
            raise MsaaError("MSAA_BAD_COVERAGE", coverage)
        value = float(coverage)
        if not math.isfinite(value) or value < 0.0 or value > 1.0:
            raise MsaaError("MSAA_BAD_COVERAGE", coverage)
        return value

    @staticmethod
    def _normalize_depth(depth):
        if depth is None:
            return None
        if isinstance(depth, bool) or not isinstance(depth, (int, float)):
            raise MsaaError("MSAA_BAD_DEPTH", depth)
        value = float(depth)
        if not math.isfinite(value):
            raise MsaaError("MSAA_BAD_DEPTH", depth)
        return value

    @classmethod
    def _normalize_stencil(cls, stencil):
        if not cls._is_int(stencil):
            raise MsaaError("MSAA_BAD_STENCIL", stencil)
        return stencil

    @classmethod
    def _normalize_pixel(cls, pixel):
        if (not isinstance(pixel, (tuple, list)) or len(pixel) != 2
                or not cls._is_int(pixel[0]) or not cls._is_int(pixel[1])):
            raise MsaaError("MSAA_PIXEL_OOB", pixel)
        x, y = pixel
        if x < 0 or y < 0:
            raise MsaaError("MSAA_PIXEL_OOB", pixel)
        return (x, y)

    @staticmethod
    def _parse_pair(value):
        if (not isinstance(value, (tuple, list)) or len(value) != 2
                or not all(isinstance(v, int) and not isinstance(v, bool)
                           for v in value)):
            raise ValueError("pair")
        result = (value[0], value[1])
        if result[0] < 0 or result[1] < 0:
            raise ValueError("pair")
        return result

    @classmethod
    def _parse_pair_key(cls, key):
        if isinstance(key, tuple):
            return cls._parse_pair(key)
        if not isinstance(key, str):
            raise ValueError("key")
        parts = key.split(",")
        if len(parts) != 2:
            raise ValueError("key")
        try:
            value = (int(parts[0]), int(parts[1]))
        except ValueError as exc:
            raise ValueError("key") from exc
        return cls._parse_pair(value)

    def _tile_for_pixel(self, pixel):
        return (pixel[0] // self._tile_size, pixel[1] // self._tile_size)

    def _empty_pixel_result(self, pixel):
        return {
            "pixel": pixel,
            "color": (0.0, 0.0, 0.0, 0.0),
            "coverage": 0.0,
            "samples": 0,
            "resolved": False,
            "depth": None,
            "stencil": 0,
        }

    def _resolve_pixel_locked(self, pixel):
        records = self._samples.get(pixel)
        if not records:
            return self._empty_pixel_result(pixel)

        covered = [
            (index, record)
            for index, record in sorted(records.items())
            if record["coverage"] > 0.0
        ]
        if not covered:
            return self._empty_pixel_result(pixel)

        if self._resolve_mode == "average":
            total_coverage = sum(record["coverage"] for _, record in covered)
            color = tuple(
                sum(record["color"][channel] * record["coverage"]
                    for _, record in covered) / total_coverage
                for channel in range(4)
            )
        elif self._resolve_mode == "min":
            color = tuple(
                min(record["color"][channel] for _, record in covered)
                for channel in range(4)
            )
        else:
            color = tuple(
                max(record["color"][channel] for _, record in covered)
                for channel in range(4)
            )

        nearest_index = None
        nearest_depth = None
        for index, record in covered:
            depth = record["depth"]
            if depth is None:
                continue
            if nearest_depth is None or depth < nearest_depth:
                nearest_depth = depth
                nearest_index = index

        stencil = (records[nearest_index]["stencil"]
                   if nearest_index is not None else 0)
        coverage = (sum(record["coverage"] for _, record in covered)
                    / self._sample_count)
        return {
            "pixel": pixel,
            "color": color,
            "coverage": coverage,
            "samples": len(covered),
            "resolved": True,
            "depth": nearest_depth,
            "stencil": stencil,
        }

    def _tile_resolution_locked(self, tile):
        pixels = 0
        samples = 0
        for pixel in self._tile_pixels.get(tile, ()):
            result = self._resolve_pixel_locked(pixel)
            if result["resolved"]:
                pixels += 1
                samples += result["samples"]
        return pixels, samples

    def _clear_samples_locked(self):
        self._samples.clear()
        self._tile_pixels.clear()
        self._dirty.clear()
        self._tile_last_write.clear()

    def configure(self, *, sample_count=None, tile_size=None, resolve_mode=None,
                  memory_budget=None):
        with self._lock:
            new_sample_count = self._sample_count
            new_tile_size = self._tile_size
            new_memory_budget = self._memory_budget
            new_resolve_mode = self._resolve_mode

            if sample_count is not None:
                self._validate_sample_count(sample_count)
                new_sample_count = sample_count
            if tile_size is not None:
                self._validate_tile_size(tile_size)
                new_tile_size = tile_size
            if memory_budget is not None:
                self._validate_memory_budget(memory_budget)
                new_memory_budget = memory_budget
            if resolve_mode is not None:
                self._validate_mode(resolve_mode)
                new_resolve_mode = resolve_mode

            sample_changed = new_sample_count != self._sample_count
            tile_changed = new_tile_size != self._tile_size

            self._sample_count = new_sample_count
            self._tile_size = new_tile_size
            self._memory_budget = new_memory_budget
            self._resolve_mode = new_resolve_mode

            if sample_changed or tile_changed:
                self._clear_samples_locked()
            if sample_changed:
                self._epoch += 1

            return {
                "sample_count": self._sample_count,
                "tile_size": self._tile_size,
                "resolve_mode": self._resolve_mode,
                "memory_budget": self._memory_budget,
                "alpha_to_coverage": self._alpha_to_coverage,
                "epoch": self._epoch,
                "cleared": sample_changed or tile_changed,
            }

    def resize(self, width, height):
        if not self._is_int(width) or not self._is_int(height):
            raise MsaaError("MSAA_BAD_BOUNDS", (width, height))
        if width < 0 or height < 0:
            raise MsaaError("MSAA_BAD_BOUNDS", (width, height))

        with self._lock:
            dropped = 0
            samples = {}
            tile_pixels = {}
            for pixel, records in self._samples.items():
                if pixel[0] < width and pixel[1] < height:
                    samples[pixel] = records
                    tile = self._tile_for_pixel(pixel)
                    tile_pixels.setdefault(tile, set()).add(pixel)
                else:
                    dropped += len(records)

            self._bounds = (width, height)
            self._samples = samples
            self._tile_pixels = tile_pixels
            self._dirty = {tile for tile in self._dirty if tile in tile_pixels}
            self._tile_last_write = {
                tile: tick for tile, tick in self._tile_last_write.items()
                if tile in tile_pixels
            }
            for tile in tile_pixels:
                self._tile_last_write.setdefault(tile, 0)

            return {
                "width": width,
                "height": height,
                "dropped": dropped,
                "samples": sum(len(records) for records in samples.values()),
            }

    def add_sample(self, pixel, sample_index, color, coverage=1.0, depth=None,
                   stencil=0):
        with self._lock:
            self._validate_sample_count(self._sample_count)
            pixel = self._normalize_pixel(pixel)
            if not self._is_int(sample_index) or not (
                    0 <= sample_index < self._sample_count):
                raise MsaaError("MSAA_SAMPLE_INDEX", sample_index)
            if (self._bounds is not None
                    and (pixel[0] >= self._bounds[0]
                         or pixel[1] >= self._bounds[1])):
                raise MsaaError("MSAA_PIXEL_OOB", pixel)

            color = self._normalize_color(color)
            depth = self._normalize_depth(depth)
            stencil = self._normalize_stencil(stencil)

            if self._alpha_to_coverage:
                steps = math.floor(color[3] * self._sample_count + 0.5)
                coverage = steps / self._sample_count
            else:
                coverage = self._normalize_coverage(coverage)

            records = self._samples.get(pixel)
            existing = records.get(sample_index) if records else None
            if existing is not None:
                unchanged = (
                    existing["color"] == color
                    and existing["coverage"] == coverage
                    and existing["depth"] == depth
                    and existing["stencil"] == stencil
                )
                if unchanged:
                    self._counters["duplicate_writes"] += 1
                    return {
                        "status": "unchanged",
                        "code": "MSAA_DUP_WRITE",
                        "pixel": pixel,
                        "sample_index": sample_index,
                        "tile": self._tile_for_pixel(pixel),
                    }

                if (depth is not None and existing["depth"] is not None
                        and depth >= existing["depth"]):
                    self._counters["rejected_depth"] += 1
                    return {
                        "status": "rejected",
                        "code": "MSAA_DEPTH_REJECT",
                        "pixel": pixel,
                        "sample_index": sample_index,
                        "tile": self._tile_for_pixel(pixel),
                    }
            else:
                total_samples = sum(len(item) for item in self._samples.values())
                if (total_samples + 1) * self._BYTES_PER_SAMPLE > self._memory_budget:
                    tile = self._tile_for_pixel(pixel)
                    need = ((total_samples + 1) * self._BYTES_PER_SAMPLE
                            - self._memory_budget)
                    candidates = [
                        (
                            self._tile_last_write.get(other_tile, 0),
                            other_tile,
                            sum(len(self._samples[item])
                                for item in self._tile_pixels[other_tile]),
                        )
                        for other_tile in self._tile_pixels
                        if other_tile != tile
                    ]
                    candidates.sort()

                    evicted = []
                    freed = 0
                    for _tick, other_tile, other_samples in candidates:
                        if freed >= need:
                            break
                        evicted.append(other_tile)
                        freed += other_samples * self._BYTES_PER_SAMPLE
                    if freed < need:
                        raise MsaaError(
                            "MSAA_MEMORY_BUDGET",
                            {
                                "needed": need,
                                "budget": self._memory_budget,
                                "tile": tile,
                            },
                        )

                    for other_tile in evicted:
                        for evicted_pixel in self._tile_pixels.pop(other_tile):
                            self._samples.pop(evicted_pixel, None)
                        self._dirty.discard(other_tile)
                        self._tile_last_write.pop(other_tile, None)
                        self._eviction_order.append(other_tile)
                        self._counters["evictions"] += 1

            tile = self._tile_for_pixel(pixel)
            if records is None:
                records = {}
                self._samples[pixel] = records
            records[sample_index] = {
                "color": color,
                "coverage": coverage,
                "depth": depth,
                "stencil": stencil,
            }
            self._tile_pixels.setdefault(tile, set()).add(pixel)
            self._tick += 1
            self._tile_last_write[tile] = self._tick
            self._dirty.add(tile)
            self._counters["samples_written"] += 1

            return {
                "status": "replaced" if existing is not None else "written",
                "pixel": pixel,
                "sample_index": sample_index,
                "tile": tile,
            }

    def resolve_pixel(self, pixel):
        with self._lock:
            pixel = self._normalize_pixel(pixel)
            if (self._bounds is not None
                    and (pixel[0] >= self._bounds[0]
                         or pixel[1] >= self._bounds[1])):
                raise MsaaError("MSAA_PIXEL_OOB", pixel)
            return self._resolve_pixel_locked(pixel)

    def resolve_depth(self, pixel):
        with self._lock:
            pixel = self._normalize_pixel(pixel)
            if (self._bounds is not None
                    and (pixel[0] >= self._bounds[0]
                         or pixel[1] >= self._bounds[1])):
                raise MsaaError("MSAA_PIXEL_OOB", pixel)

            records = self._samples.get(pixel)
            covered = [
                (index, record)
                for index, record in sorted((records or {}).items())
                if record["coverage"] > 0.0
            ]
            nearest_index = None
            nearest_depth = None
            for index, record in covered:
                depth = record["depth"]
                if depth is None:
                    continue
                if nearest_depth is None or depth < nearest_depth:
                    nearest_depth = depth
                    nearest_index = index

            stencil = (records[nearest_index]["stencil"]
                       if nearest_index is not None else 0)
            return {
                "pixel": pixel,
                "depth": nearest_depth,
                "stencil": stencil,
                "samples": len(covered),
                "resolved": bool(covered),
            }

    def resolve_tile(self, tile):
        with self._lock:
            try:
                tile = self._parse_pair(tile)
            except ValueError as exc:
                raise MsaaError("MSAA_BAD_TILE", tile) from exc
            was_dirty = tile in self._dirty
            pixels, samples = self._tile_resolution_locked(tile)
            if was_dirty:
                self._dirty.discard(tile)
                self._counters["tiles_resolved"] += 1
            return {
                "tile": tile,
                "pixels": pixels,
                "samples": samples,
                "tiles": 1 if was_dirty else 0,
            }

    def resolve_all(self):
        with self._lock:
            dirty = sorted(self._dirty, key=lambda item: (item[1], item[0]))
            pixels = 0
            samples = 0
            for tile in dirty:
                tile_pixels, tile_samples = self._tile_resolution_locked(tile)
                pixels += tile_pixels
                samples += tile_samples
            self._dirty.clear()
            self._counters["tiles_resolved"] += len(dirty)
            return {
                "pixels": pixels,
                "tiles": len(dirty),
                "samples": samples,
            }

    def flush_dirty(self):
        with self._lock:
            dirty = sorted(self._dirty, key=lambda item: (item[1], item[0]))
            self._dirty.clear()
            self._counters["tiles_resolved"] += len(dirty)
            return dirty

    def set_alpha_to_coverage(self, enabled):
        with self._lock:
            self._alpha_to_coverage = bool(enabled)
            return self._alpha_to_coverage

    def memory_usage(self):
        with self._lock:
            return (sum(len(records) for records in self._samples.values())
                    * self._BYTES_PER_SAMPLE)

    def stats(self):
        with self._lock:
            samples = sum(len(records) for records in self._samples.values())
            result = {
                "sample_count": self._sample_count,
                "tile_size": self._tile_size,
                "resolve_mode": self._resolve_mode,
                "memory_budget": self._memory_budget,
                "alpha_to_coverage": self._alpha_to_coverage,
                "bounds": self._bounds,
                "epoch": self._epoch,
                "samples": samples,
                "pixels": len(self._samples),
                "dirty_tiles": len(self._dirty),
                "memory_usage": samples * self._BYTES_PER_SAMPLE,
            }
            result.update(self._counters)
            return result

    def snapshot(self):
        with self._lock:
            samples = {}
            for pixel in sorted(self._samples, key=lambda item: (item[1], item[0])):
                records = self._samples[pixel]
                encoded_records = {}
                for index in sorted(records):
                    record = records[index]
                    encoded_records[str(index)] = {
                        "color": list(record["color"]),
                        "coverage": record["coverage"],
                        "depth": record["depth"],
                        "stencil": record["stencil"],
                    }
                samples["{},{}".format(*pixel)] = encoded_records

            return {
                "version": self._SNAPSHOT_VERSION,
                "config": {
                    "sample_count": self._sample_count,
                    "tile_size": self._tile_size,
                    "resolve_mode": self._resolve_mode,
                    "memory_budget": self._memory_budget,
                    "alpha_to_coverage": self._alpha_to_coverage,
                },
                "bounds": list(self._bounds) if self._bounds is not None else None,
                "samples": samples,
                "dirty": [
                    list(tile)
                    for tile in sorted(self._dirty,
                                       key=lambda item: (item[1], item[0]))
                ],
                "tile_last_write": {
                    "{},{}".format(*tile): tick
                    for tile, tick in sorted(
                        self._tile_last_write.items(),
                        key=lambda item: (item[0][1], item[0][0]),
                    )
                },
                "eviction_order": [list(tile) for tile in self._eviction_order],
                "counters": dict(self._counters),
                "tick": self._tick,
                "epoch": self._epoch,
            }

    def restore(self, snap):
        with self._lock:
            state = self._validate_snapshot(snap)
            self._sample_count = state["sample_count"]
            self._tile_size = state["tile_size"]
            self._memory_budget = state["memory_budget"]
            self._resolve_mode = state["resolve_mode"]
            self._alpha_to_coverage = state["alpha_to_coverage"]
            self._bounds = state["bounds"]
            self._samples = state["samples"]
            self._tile_pixels = state["tile_pixels"]
            self._dirty = state["dirty"]
            self._tile_last_write = state["tile_last_write"]
            self._eviction_order = state["eviction_order"]
            self._counters = state["counters"]
            self._tick = state["tick"]
            self._epoch = state["epoch"]

            return {
                "version": self._SNAPSHOT_VERSION,
                "samples": sum(len(records)
                               for records in self._samples.values()),
                "pixels": len(self._samples),
                "dirty": len(self._dirty),
                "epoch": self._epoch,
                "config": {
                    "sample_count": self._sample_count,
                    "tile_size": self._tile_size,
                    "resolve_mode": self._resolve_mode,
                    "memory_budget": self._memory_budget,
                    "alpha_to_coverage": self._alpha_to_coverage,
                },
            }

    def _validate_snapshot(self, snap):
        try:
            return self._validate_snapshot_inner(snap)
        except MsaaError as exc:
            if exc.code == "MSAA_SNAPSHOT_INVALID":
                raise
            raise MsaaError("MSAA_SNAPSHOT_INVALID", exc.detail) from exc
        except Exception as exc:  # noqa: BLE001
            raise MsaaError("MSAA_SNAPSHOT_INVALID", str(exc)) from exc

    def _validate_snapshot_inner(self, snap):
        if not isinstance(snap, dict):
            raise MsaaError("MSAA_SNAPSHOT_INVALID", "snapshot")
        version = snap.get("version")
        if (not self._is_int(version)
                or version != self._SNAPSHOT_VERSION):
            raise MsaaError("MSAA_SNAPSHOT_INVALID", "version")

        config = snap.get("config")
        if not isinstance(config, dict):
            raise MsaaError("MSAA_SNAPSHOT_INVALID", "config")
        try:
            sample_count = config["sample_count"]
            tile_size = config["tile_size"]
            resolve_mode = config["resolve_mode"]
            memory_budget = config["memory_budget"]
        except KeyError as exc:
            raise MsaaError("MSAA_SNAPSHOT_INVALID", "config") from exc

        self._validate_sample_count(sample_count)
        self._validate_tile_size(tile_size)
        self._validate_mode(resolve_mode)
        self._validate_memory_budget(memory_budget)
        alpha_to_coverage = config.get("alpha_to_coverage", False)
        if not isinstance(alpha_to_coverage, bool):
            raise MsaaError("MSAA_SNAPSHOT_INVALID", "alpha_to_coverage")

        bounds_value = snap.get("bounds")
        if bounds_value is None:
            bounds = None
        else:
            bounds = self._parse_pair(bounds_value)

        raw_samples = snap.get("samples")
        if not isinstance(raw_samples, dict):
            raise MsaaError("MSAA_SNAPSHOT_INVALID", "samples")
        samples = {}
        tile_pixels = {}
        for raw_pixel, raw_records in raw_samples.items():
            pixel = self._parse_pair_key(raw_pixel)
            if (bounds is not None
                    and (pixel[0] >= bounds[0] or pixel[1] >= bounds[1])):
                raise MsaaError("MSAA_SNAPSHOT_INVALID", "pixel")
            if not isinstance(raw_records, dict):
                raise MsaaError("MSAA_SNAPSHOT_INVALID", "records")
            records = {}
            for raw_index, raw_record in raw_records.items():
                try:
                    index = int(raw_index)
                except (TypeError, ValueError) as exc:
                    raise MsaaError("MSAA_SNAPSHOT_INVALID", "index") from exc
                if (str(index) != str(raw_index).strip()
                        or not 0 <= index < sample_count):
                    raise MsaaError("MSAA_SNAPSHOT_INVALID", "index")
                if not isinstance(raw_record, dict):
                    raise MsaaError("MSAA_SNAPSHOT_INVALID", "record")
                if "color" not in raw_record or "coverage" not in raw_record:
                    raise MsaaError("MSAA_SNAPSHOT_INVALID", "record")
                records[index] = {
                    "color": self._normalize_color(raw_record["color"]),
                    "coverage": self._normalize_coverage(
                        raw_record["coverage"]),
                    "depth": self._normalize_depth(
                        raw_record.get("depth")),
                    "stencil": self._normalize_stencil(
                        raw_record.get("stencil", 0)),
                }
            if not records:
                raise MsaaError("MSAA_SNAPSHOT_INVALID", "records")
            samples[pixel] = records
            tile = (pixel[0] // tile_size, pixel[1] // tile_size)
            tile_pixels.setdefault(tile, set()).add(pixel)

        raw_dirty = snap.get("dirty", [])
        if not isinstance(raw_dirty, (list, tuple)):
            raise MsaaError("MSAA_SNAPSHOT_INVALID", "dirty")
        dirty = {self._parse_pair(item) for item in raw_dirty}

        raw_last_write = snap.get("tile_last_write", {})
        if not isinstance(raw_last_write, dict):
            raise MsaaError("MSAA_SNAPSHOT_INVALID", "tile_last_write")
        tile_last_write = {}
        for raw_tile, tick in raw_last_write.items():
            tile = self._parse_pair_key(raw_tile)
            if not self._is_int(tick) or tick < 0:
                raise MsaaError("MSAA_SNAPSHOT_INVALID", "tick")
            tile_last_write[tile] = tick
        for tile in tile_pixels:
            tile_last_write.setdefault(tile, 0)

        raw_evictions = snap.get("eviction_order", [])
        if not isinstance(raw_evictions, (list, tuple)):
            raise MsaaError("MSAA_SNAPSHOT_INVALID", "eviction_order")
        eviction_order = [self._parse_pair(item) for item in raw_evictions]

        raw_counters = snap.get("counters", {})
        if not isinstance(raw_counters, dict):
            raise MsaaError("MSAA_SNAPSHOT_INVALID", "counters")
        counters = {}
        for name, default in {
            "samples_written": 0,
            "duplicate_writes": 0,
            "rejected_depth": 0,
            "evictions": 0,
            "tiles_resolved": 0,
        }.items():
            value = raw_counters.get(name, default)
            if not self._is_int(value) or value < 0:
                raise MsaaError("MSAA_SNAPSHOT_INVALID", "counters")
            counters[name] = value

        tick = snap.get("tick")
        minimum_tick = max(tile_last_write.values(), default=0)
        if tick is None:
            tick = minimum_tick
        elif not self._is_int(tick) or tick < minimum_tick:
            raise MsaaError("MSAA_SNAPSHOT_INVALID", "tick")

        epoch = snap.get("epoch", 0)
        if not self._is_int(epoch) or epoch < 0:
            raise MsaaError("MSAA_SNAPSHOT_INVALID", "epoch")

        return {
            "sample_count": sample_count,
            "tile_size": tile_size,
            "memory_budget": memory_budget,
            "resolve_mode": resolve_mode,
            "alpha_to_coverage": alpha_to_coverage,
            "bounds": bounds,
            "samples": samples,
            "tile_pixels": tile_pixels,
            "dirty": dirty,
            "tile_last_write": tile_last_write,
            "eviction_order": eviction_order,
            "counters": counters,
            "tick": tick,
            "epoch": epoch,
        }

    def reset(self):
        with self._lock:
            self._clear_samples_locked()
            self._epoch += 1
            self._tick = 0
            self._eviction_order = []
            self._counters = {
                "samples_written": 0,
                "duplicate_writes": 0,
                "rejected_depth": 0,
                "evictions": 0,
                "tiles_resolved": 0,
            }
            return self._epoch
