"""可变速率着色率图、内容自适应推导与预算守卫。"""

import math
import re
import threading

ENTRY_BYTES = 32
DEFAULT_SUPPORTED = ("1x1", "1x2", "2x1", "2x2")
SNAPSHOT_VERSION = 1

_RATE_RE = re.compile(r"^([124])x([124])$", re.IGNORECASE)


class VrsError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _rate_area(rate):
    left, right = rate.split("x")
    return int(left) * int(right)


def _as_tile(tile, code="VRS_BAD_TILE"):
    if (not isinstance(tile, (tuple, list)) or len(tile) != 2
            or not all(_is_int(value) for value in tile)):
        raise VrsError(code, "tile must be a pair of integers")
    x, y = tile
    if x < 0 or y < 0:
        raise VrsError(code, "tile coordinates must be non-negative")
    return int(x), int(y)


class VrsGuard:
    """率图维护、内容自适应推导、附件合并、脏 tile 失效与快照恢复。"""

    def __init__(self, base_rate="1x1", supported_rates=None, tile_size=16,
                 memory_budget=1 << 20):
        self._lock = threading.RLock()

        if supported_rates is None:
            raw_supported = list(DEFAULT_SUPPORTED)
        else:
            if not isinstance(supported_rates, (list, tuple)):
                raise VrsError("VRS_BAD_RATE", "supported_rates must be a sequence")
            raw_supported = list(supported_rates)

        supported = []
        seen = set()
        for rate in raw_supported:
            normalized = self.normalize_rate(rate)
            if normalized not in seen:
                supported.append(normalized)
                seen.add(normalized)
        if "1x1" not in seen:
            raise VrsError("VRS_BAD_RATE", "1x1 must be supported")

        normalized_base = self.normalize_rate(base_rate)
        if normalized_base not in seen:
            raise VrsError("VRS_BAD_RATE", "base_rate must be supported")

        if not _is_int(tile_size) or tile_size <= 0:
            raise VrsError("VRS_BAD_CONFIG", "tile_size must be a positive integer")
        if not _is_int(memory_budget) or memory_budget < 0:
            raise VrsError("VRS_MEMORY_BUDGET", "memory_budget must be non-negative")

        self._base_rate = normalized_base
        self._supported = supported
        self._tile_size = tile_size
        self._memory_budget = memory_budget
        self._entries = {}
        self._dirty = set()
        self._epoch = 0
        self._changes = 0
        self._fallback_count = 0
        self._flushes = 0

    def normalize_rate(self, rate):
        if not isinstance(rate, str):
            raise VrsError("VRS_BAD_RATE", "rate must be a string")
        match = _RATE_RE.fullmatch(rate.strip())
        if match is None:
            raise VrsError("VRS_BAD_RATE", "rate must use sides from {1, 2, 4}")
        return "{}x{}".format(match.group(1), match.group(2)).lower()

    def _resolve_rate(self, rate):
        normalized = self.normalize_rate(rate)
        if normalized in self._supported:
            return normalized, False

        requested_area = _rate_area(normalized)
        candidates = [
            candidate for candidate in self._supported
            if _rate_area(candidate) <= requested_area
        ]
        if not candidates:
            raise VrsError("VRS_BAD_RATE", "no supported rate fits")
        best_area = max(_rate_area(candidate) for candidate in candidates)
        for candidate in candidates:
            if _rate_area(candidate) == best_area:
                return candidate, True
        raise VrsError("VRS_BAD_RATE", "no supported rate fits")

    def _coarsest_rate(self):
        best = self._supported[0]
        best_area = _rate_area(best)
        for candidate in self._supported[1:]:
            area = _rate_area(candidate)
            if area > best_area:
                best = candidate
                best_area = area
        return best

    def supported_rates(self):
        with self._lock:
            return list(self._supported)

    def set_base_rate(self, rate):
        with self._lock:
            resolved, fallback = self._resolve_rate(rate)
            if fallback:
                self._fallback_count += 1

            changed = resolved != self._base_rate
            dirty_marked = 0
            if changed:
                self._base_rate = resolved
                self._epoch += 1
                self._changes += 1
                for tile in self._entries:
                    if tile not in self._dirty:
                        self._dirty.add(tile)
                        dirty_marked += 1

            return {
                "rate": resolved,
                "fallback": fallback,
                "changed": changed,
                "epoch": self._epoch,
                "dirty_marked": dirty_marked,
            }

    def _write_entry(self, tile, rate, priority, source):
        old = self._entries.get(tile)
        rate_changed = old is None or old["rate"] != rate
        metadata_changed = old is not None and (
            old.get("priority", 0) != priority or old.get("source") != source
        )

        if old is None:
            self._entries[tile] = {
                "rate": rate,
                "priority": priority,
                "source": source,
            }
        else:
            old["rate"] = rate
            old["priority"] = priority
            old["source"] = source

        if rate_changed:
            self._changes += 1
            self._dirty.add(tile)

        return rate_changed, metadata_changed

    def set_tile_rate(self, tile, rate, *, source="api"):
        tile = _as_tile(tile)
        with self._lock:
            resolved, fallback = self._resolve_rate(rate)

            is_new = tile not in self._entries
            if is_new and (len(self._entries) + 1) * ENTRY_BYTES > self._memory_budget:
                raise VrsError("VRS_MEMORY_BUDGET", "rate map memory budget exceeded")

            changed, _ = self._write_entry(tile, resolved, 0, source)
            if fallback:
                self._fallback_count += 1

            return {
                "tile": tile,
                "rate": resolved,
                "fallback": fallback,
                "changed": changed,
                "source": source,
                "tiles": len(self._entries),
                "memory_usage": len(self._entries) * ENTRY_BYTES,
            }

    def set_rate_map(self, mapping):
        if not isinstance(mapping, dict):
            raise VrsError("VRS_BAD_TILE", "rate map must be a dict")

        with self._lock:
            validated = []
            fallback_count = 0
            new_tiles = set()
            for raw_tile, rate in mapping.items():
                tile = _as_tile(raw_tile)
                resolved, fallback = self._resolve_rate(rate)
                if fallback:
                    fallback_count += 1
                validated.append((tile, resolved))
                if tile not in self._entries:
                    new_tiles.add(tile)

            if (len(self._entries) + len(new_tiles)) * ENTRY_BYTES > self._memory_budget:
                raise VrsError("VRS_MEMORY_BUDGET", "rate map memory budget exceeded")

            changed_tiles = 0
            for tile, resolved in validated:
                changed, _ = self._write_entry(tile, resolved, 0, "rate_map")
                if changed:
                    changed_tiles += 1
            self._fallback_count += fallback_count

            return {
                "applied": len(validated),
                "changed": changed_tiles,
                "fallback_count": fallback_count,
                "tiles": len(self._entries),
            }

    def rate_at(self, pixel):
        with self._lock:
            if (not isinstance(pixel, (tuple, list)) or len(pixel) != 2
                    or not all(_is_int(value) for value in pixel)):
                raise VrsError("VRS_BAD_PIXEL", "pixel must be a pair of integers")
            x, y = pixel
            if x < 0 or y < 0:
                raise VrsError("VRS_BAD_PIXEL", "pixel coordinates must be non-negative")
            tile = (x // self._tile_size, y // self._tile_size)
            entry = self._entries.get(tile)
            return self._base_rate if entry is None else entry["rate"]

    @staticmethod
    def _valid_number(value):
        return (isinstance(value, (int, float)) and not isinstance(value, bool)
                and math.isfinite(value))

    def derive_rates(self, tile_stats):
        if not isinstance(tile_stats, (list, tuple)):
            raise VrsError("VRS_BAD_STATS", "tile_stats must be a sequence")

        with self._lock:
            coarsest = self._coarsest_rate()
            validated = []
            new_tiles = set()

            for stat in tile_stats:
                if not isinstance(stat, dict):
                    raise VrsError("VRS_BAD_STATS", "each stat must be a dict")
                try:
                    tile = _as_tile(stat.get("tile"), "VRS_BAD_STATS")
                except VrsError as exc:
                    raise VrsError("VRS_BAD_STATS", exc.detail) from None

                variance = stat.get("variance")
                motion = stat.get("motion", 0)
                if (not self._valid_number(variance) or variance < 0
                        or not self._valid_number(motion) or motion < 0):
                    raise VrsError("VRS_BAD_STATS", "variance and motion must be finite and non-negative")

                if motion > 32:
                    rate = "1x1"
                elif variance < 1:
                    rate = coarsest
                elif variance < 8:
                    rate = "1x2" if "1x2" in self._supported else coarsest
                else:
                    rate = "1x1"

                validated.append((tile, rate, stat))
                if tile not in self._entries:
                    new_tiles.add(tile)

            if (len(self._entries) + len(new_tiles)) * ENTRY_BYTES > self._memory_budget:
                raise VrsError("VRS_MEMORY_BUDGET", "rate map memory budget exceeded")

            changed_tiles = 0
            rates = []
            for tile, rate, _ in validated:
                changed, _ = self._write_entry(tile, rate, 0, "derive")
                if changed:
                    changed_tiles += 1
                rates.append({"tile": tile, "rate": rate})

            rates.sort(key=lambda item: item["tile"])
            return {
                "rates": rates,
                "applied": len(validated),
                "changed": changed_tiles,
            }

    def mark_dirty(self, tile):
        tile = _as_tile(tile)
        with self._lock:
            if tile in self._dirty:
                return False
            self._dirty.add(tile)
            return True

    def flush(self):
        with self._lock:
            if not self._dirty:
                return []
            tiles = sorted(self._dirty, key=lambda tile: (tile[1], tile[0]))
            self._dirty.clear()
            self._flushes += 1
            return tiles

    def _attachment_wins(self, candidate, current):
        if current is None:
            return True
        candidate_priority = candidate["priority"]
        current_priority = current["priority"]
        if candidate_priority != current_priority:
            return candidate_priority > current_priority
        return _rate_area(candidate["rate"]) < _rate_area(current["rate"])

    def apply_attachment(self, attachment):
        if not isinstance(attachment, (list, tuple)):
            raise VrsError("VRS_BAD_STATS", "attachment must be a sequence")

        with self._lock:
            groups = {}
            order = []
            for item in attachment:
                if not isinstance(item, dict):
                    raise VrsError("VRS_BAD_STATS", "each attachment entry must be a dict")
                tile = _as_tile(item.get("tile"))

                resolved, fallback = self._resolve_rate(item.get("rate"))
                priority = item.get("priority", 0)
                if not self._valid_number(priority):
                    raise VrsError("VRS_BAD_STATS", "priority must be a finite number")

                candidate = {
                    "tile": tile,
                    "rate": resolved,
                    "priority": priority,
                    "fallback": fallback,
                }
                if tile not in groups:
                    groups[tile] = []
                    order.append(tile)
                groups[tile].append(candidate)

            winners = {}
            new_tiles = set()
            for tile in order:
                current = self._entries.get(tile)
                winner = None
                for candidate in groups[tile]:
                    if self._attachment_wins(candidate, current):
                        current = candidate
                        winner = candidate
                if winner is not None:
                    winners[tile] = winner
                    if tile not in self._entries:
                        new_tiles.add(tile)

            if (len(self._entries) + len(new_tiles)) * ENTRY_BYTES > self._memory_budget:
                raise VrsError("VRS_MEMORY_BUDGET", "rate map memory budget exceeded")

            applied = 0
            skipped = 0
            changed_tiles = 0
            for tile in order:
                winner = winners.get(tile)
                candidates = groups[tile]
                if winner is None:
                    skipped += len(candidates)
                    continue

                applied += 1
                skipped += len(candidates) - 1
                changed, _ = self._write_entry(
                    tile, winner["rate"], winner["priority"], "attachment"
                )
                if changed:
                    changed_tiles += 1
                if winner["fallback"]:
                    self._fallback_count += 1

            return {
                "applied": applied,
                "skipped": skipped,
                "changed": changed_tiles,
                "tiles": len(self._entries),
            }

    def coverage_image_size(self, width, height):
        if (not _is_int(width) or not _is_int(height)
                or width < 0 or height < 0):
            raise VrsError("VRS_BAD_PIXEL", "image dimensions must be non-negative integers")

        with self._lock:
            if width == 0 or height == 0:
                return {
                    "invocations": 0,
                    "max_invocations": 0,
                    "ratio": 0.0,
                }

            invocations = 0
            tiles_x = (width + self._tile_size - 1) // self._tile_size
            tiles_y = (height + self._tile_size - 1) // self._tile_size
            for tile_y in range(tiles_y):
                tile_height = min(self._tile_size, height - tile_y * self._tile_size)
                for tile_x in range(tiles_x):
                    tile_width = min(self._tile_size, width - tile_x * self._tile_size)
                    entry = self._entries.get((tile_x, tile_y))
                    rate = self._base_rate if entry is None else entry["rate"]
                    rate_x, rate_y = (int(part) for part in rate.split("x"))
                    calls_x = (tile_width + rate_x - 1) // rate_x
                    calls_y = (tile_height + rate_y - 1) // rate_y
                    invocations += calls_x * calls_y

            max_invocations = width * height
            ratio = round(invocations / max_invocations, 6)
            return {
                "invocations": invocations,
                "max_invocations": max_invocations,
                "ratio": ratio,
            }

    def memory_usage(self):
        with self._lock:
            return len(self._entries) * ENTRY_BYTES

    def stats(self):
        with self._lock:
            return {
                "tiles": len(self._entries),
                "changes": self._changes,
                "fallback_count": self._fallback_count,
                "flushes": self._flushes,
                "epoch": self._epoch,
                "dirty": len(self._dirty),
                "memory_usage": len(self._entries) * ENTRY_BYTES,
                "base_rate": self._base_rate,
            }

    def snapshot(self):
        with self._lock:
            entries = []
            for tile in sorted(self._entries):
                meta = self._entries[tile]
                entries.append({
                    "tile": [tile[0], tile[1]],
                    "rate": meta["rate"],
                    "priority": meta.get("priority", 0),
                    "source": meta.get("source", "api"),
                })
            dirty = [[tile[0], tile[1]] for tile in sorted(self._dirty)]
            return {
                "version": SNAPSHOT_VERSION,
                "base_rate": self._base_rate,
                "supported_rates": list(self._supported),
                "tile_size": self._tile_size,
                "memory_budget": self._memory_budget,
                "entries": entries,
                "dirty": dirty,
                "changes": self._changes,
                "fallback_count": self._fallback_count,
                "flushes": self._flushes,
                "epoch": self._epoch,
            }

    def restore(self, snap):
        with self._lock:
            try:
                if not isinstance(snap, dict):
                    raise ValueError("snapshot must be a dict")
                version = snap.get("version")
                if not _is_int(version) or version != SNAPSHOT_VERSION:
                    raise ValueError("unsupported snapshot version")

                raw_supported = snap.get("supported_rates")
                if not isinstance(raw_supported, (list, tuple)):
                    raise ValueError("supported_rates must be a sequence")
                supported = []
                seen = set()
                for rate in raw_supported:
                    normalized = self.normalize_rate(rate)
                    if normalized not in seen:
                        supported.append(normalized)
                        seen.add(normalized)
                if "1x1" not in seen:
                    raise ValueError("1x1 must be supported")

                base_rate = self.normalize_rate(snap.get("base_rate"))
                if base_rate not in seen:
                    raise ValueError("base_rate must be supported")

                tile_size = snap.get("tile_size")
                if not _is_int(tile_size) or tile_size <= 0:
                    raise ValueError("invalid tile_size")

                memory_budget = snap.get("memory_budget")
                if not _is_int(memory_budget) or memory_budget < 0:
                    raise ValueError("invalid memory_budget")

                raw_entries = snap.get("entries")
                if not isinstance(raw_entries, list):
                    raise ValueError("entries must be a list")
                entries = {}
                for raw in raw_entries:
                    if not isinstance(raw, dict):
                        raise ValueError("invalid entry")
                    tile = _as_tile(raw.get("tile"))
                    rate = self.normalize_rate(raw.get("rate"))
                    if rate not in seen:
                        raise ValueError("entry rate must be supported")
                    priority = raw.get("priority", 0)
                    if not self._valid_number(priority):
                        raise ValueError("invalid entry priority")
                    source = raw.get("source", "api")
                    if not isinstance(source, str):
                        raise ValueError("invalid entry source")
                    if tile in entries:
                        raise ValueError("duplicate entry tile")
                    entries[tile] = {
                        "rate": rate,
                        "priority": priority,
                        "source": source,
                    }

                if len(entries) * ENTRY_BYTES > memory_budget:
                    raise ValueError("entries exceed memory budget")

                raw_dirty = snap.get("dirty", [])
                if not isinstance(raw_dirty, list):
                    raise ValueError("dirty must be a list")
                dirty = set()
                for raw in raw_dirty:
                    dirty.add(_as_tile(raw))

                counters = {}
                for name in ("changes", "fallback_count", "flushes", "epoch"):
                    value = snap.get(name, 0)
                    if not _is_int(value) or value < 0:
                        raise ValueError("invalid counter {}".format(name))
                    counters[name] = value
            except (VrsError, TypeError, ValueError) as exc:
                raise VrsError("VRS_SNAPSHOT_INVALID", str(exc)) from None

            self._supported = supported
            self._base_rate = base_rate
            self._tile_size = tile_size
            self._memory_budget = memory_budget
            self._entries = entries
            self._dirty = dirty
            self._changes = counters["changes"]
            self._fallback_count = counters["fallback_count"]
            self._flushes = counters["flushes"]
            self._epoch = counters["epoch"]

            return {
                "tiles": len(entries),
                "dirty": len(dirty),
                "changes": self._changes,
                "epoch": self._epoch,
            }

    def reset(self):
        with self._lock:
            self._entries.clear()
            self._dirty.clear()
            self._epoch += 1
            return self._epoch
