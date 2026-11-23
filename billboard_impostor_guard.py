"""公告板替身：图集烘焙、视角选择、LOD 滞回与预算守卫骨架。"""

import math
import numbers
import threading

SNAPSHOT_VERSION = 1
LOD_BOUNDARIES = (10.0, 30.0, 80.0)


class ImpostorError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class ImpostorGuard:
    """替身网格登记、图集格分配、视角量化、LOD 切换与快照恢复。"""

    def __init__(self, view_count=8, atlas_size=1024, cell_size=128,
                 memory_budget=64 * 1024 * 1024, hysteresis_ratio=0.1):
        self._view_count, self._atlas_size, self._cell_size, \
            self._memory_budget, self._hysteresis = self._validated_config(
                view_count, atlas_size, cell_size, memory_budget,
                hysteresis_ratio)
        self._lock = threading.RLock()
        self._meshes = {}
        self._cells = {}
        self._current_views = {}
        self._current_lods = {}
        self._epoch = 0
        self._bakes = 0
        self._rebakes = 0
        self._evictions = 0
        self._view_switches = 0
        self._lod_switches = 0

    def register_mesh(self, mesh_id, *, bounds, vertex_count, material=None):
        with self._lock:
            if not self._valid_mesh_id(mesh_id):
                raise ImpostorError("IMP_BAD_MESH", mesh_id)
            clean_bounds = self._validated_bounds(bounds)
            if not self._is_int(vertex_count) or vertex_count < 1:
                raise ImpostorError("IMP_BAD_MESH", "vertex_count")
            if material is not None and not isinstance(material, str):
                raise ImpostorError("IMP_BAD_MESH", "material")

            existing = self._meshes.get(mesh_id)
            if existing is not None:
                if (existing["bounds"] == clean_bounds and
                        existing["vertex_count"] == vertex_count and
                        existing["material"] == material):
                    status = "unchanged"
                else:
                    raise ImpostorError("IMP_DUP_MESH", mesh_id)
            else:
                self._meshes[mesh_id] = {
                    "bounds": clean_bounds,
                    "vertex_count": vertex_count,
                    "material": material,
                }
                status = "registered"

            return {
                "mesh": mesh_id,
                "status": status,
                "bounds": list(clean_bounds),
                "vertex_count": vertex_count,
                "material": material,
            }

    def bake(self, mesh_id, view_index, *, samples, alpha_cutoff=0.5):
        with self._lock:
            self._require_mesh(mesh_id)
            self._check_view_index(view_index)
            silhouette = self._build_silhouette(samples, alpha_cutoff)
            key = (mesh_id, view_index)
            cell = self._cells.get(key)

            if cell is not None:
                cell["silhouette"] = silhouette
                self._bakes += 1
                self._rebakes += 1
                self._touch(cell)
                return {
                    "mesh": mesh_id,
                    "view": view_index,
                    "status": "rebaked",
                    "cell": cell["index"],
                    "bytes": self._cell_bytes(),
                    "silhouette": dict(silhouette),
                }

            if len(self._cells) >= self._capacity():
                raise ImpostorError("IMP_ATLAS_FULL")
            if (len(self._cells) + 1) * self._cell_bytes() > self._memory_budget:
                raise ImpostorError("IMP_MEMORY_BUDGET")

            index = self._next_free_index()
            cell = {
                "index": index,
                "x": (index % self._cells_per_row()) * self._cell_size,
                "y": (index // self._cells_per_row()) * self._cell_size,
                "size": self._cell_size,
                "last_used": 0,
                "silhouette": silhouette,
            }
            self._touch(cell)
            self._cells[key] = cell
            self._bakes += 1
            return {
                "mesh": mesh_id,
                "view": view_index,
                "status": "baked",
                "cell": index,
                "bytes": self._cell_bytes(),
                "silhouette": dict(silhouette),
            }

    def atlas_cell(self, mesh_id, view_index):
        with self._lock:
            self._require_mesh(mesh_id)
            self._check_view_index(view_index)
            cell = self._cells.get((mesh_id, view_index))
            if cell is None:
                raise ImpostorError("IMP_NOT_BAKED", (mesh_id, view_index))
            self._touch(cell)
            return {
                "index": cell["index"],
                "x": cell["x"],
                "y": cell["y"],
                "size": cell["size"],
            }

    def silhouette(self, mesh_id, view_index):
        with self._lock:
            self._require_mesh(mesh_id)
            self._check_view_index(view_index)
            cell = self._cells.get((mesh_id, view_index))
            if cell is None:
                raise ImpostorError("IMP_NOT_BAKED", (mesh_id, view_index))
            self._touch(cell)
            return dict(cell["silhouette"])

    def view_index(self, yaw):
        with self._lock:
            if not self._is_real(yaw) or not math.isfinite(float(yaw)):
                raise ImpostorError("IMP_BAD_VIEW", yaw)
            bucket = 360.0 / self._view_count
            normalized = float(yaw) % 360.0
            return int(math.floor((normalized + bucket / 2.0) / bucket)) \
                % self._view_count

    def best_view(self, mesh_id, yaw):
        with self._lock:
            self._require_mesh(mesh_id)
            return self.view_index(yaw)

    def select_view(self, mesh_id, yaw):
        with self._lock:
            self._require_mesh(mesh_id)
            candidate = self.view_index(yaw)
            current = self._current_views.get(mesh_id)
            if current is None:
                self._current_views[mesh_id] = candidate
                return {"view": candidate, "switched": True,
                        "reason": "initial"}

            bucket = 360.0 / self._view_count
            normalized = float(yaw) % 360.0
            delta = self._angle_delta(normalized, current * bucket)
            threshold = bucket * (0.5 + 2.0 * self._hysteresis)
            if delta <= threshold:
                return {"view": current, "switched": False, "reason": "kept"}

            self._current_views[mesh_id] = candidate
            self._view_switches += 1
            return {"view": candidate, "switched": True,
                    "reason": "switched"}

    def lod_for(self, mesh_id, distance):
        with self._lock:
            self._require_mesh(mesh_id)
            if (not self._is_real(distance) or
                    not math.isfinite(float(distance)) or distance < 0):
                raise ImpostorError("IMP_BAD_DISTANCE", distance)

            current = self._current_lods.get(mesh_id)
            if current is None:
                lod = sum(1 for boundary in LOD_BOUNDARIES
                          if distance >= boundary)
                self._current_lods[mesh_id] = lod
                return {"lod": lod, "changed": True}

            lod = current
            while (lod < len(LOD_BOUNDARIES) and
                   distance >= LOD_BOUNDARIES[lod] * (1.0 + self._hysteresis)):
                lod += 1
            while (lod > 0 and
                   distance <= LOD_BOUNDARIES[lod - 1] *
                   (1.0 - self._hysteresis)):
                lod -= 1

            changed = lod != current
            if changed:
                self._current_lods[mesh_id] = lod
                self._lod_switches += 1
            return {"lod": lod, "changed": changed}

    def evict(self, count):
        with self._lock:
            if not self._is_int(count) or count < 0:
                raise ImpostorError("IMP_BAD_EVICT", count)
            if count == 0 or not self._cells:
                return []

            ordered = sorted(
                self._cells.items(),
                key=lambda item: (item[1]["last_used"], item[1]["index"],
                                  item[0][0], item[0][1]))
            removed = []
            for key, _cell in ordered[:count]:
                del self._cells[key]
                removed.append({"mesh": key[0], "view": key[1]})
            self._evictions += len(removed)
            return removed

    def memory_usage(self):
        with self._lock:
            return len(self._cells) * self._cell_bytes()

    def stats(self):
        with self._lock:
            return {
                "meshes": len(self._meshes),
                "cells": len(self._cells),
                "bakes": self._bakes,
                "rebakes": self._rebakes,
                "evictions": self._evictions,
                "view_switches": self._view_switches,
                "lod_switches": self._lod_switches,
                "epoch": self._epoch,
                "memory_bytes": len(self._cells) * self._cell_bytes(),
            }

    def snapshot(self):
        with self._lock:
            cells = []
            for (mesh_id, view_index), cell in sorted(
                    self._cells.items(), key=lambda item: item[1]["index"]):
                cells.append({
                    "mesh": mesh_id,
                    "view": view_index,
                    "index": cell["index"],
                    "x": cell["x"],
                    "y": cell["y"],
                    "size": cell["size"],
                    "last_used": cell["last_used"],
                    "silhouette": dict(cell["silhouette"]),
                })
            return {
                "version": SNAPSHOT_VERSION,
                "config": {
                    "view_count": self._view_count,
                    "atlas_size": self._atlas_size,
                    "cell_size": self._cell_size,
                    "memory_budget": self._memory_budget,
                    "hysteresis_ratio": self._hysteresis,
                },
                "meshes": {
                    mesh_id: {
                        "bounds": list(mesh["bounds"]),
                        "vertex_count": mesh["vertex_count"],
                        "material": mesh["material"],
                    }
                    for mesh_id, mesh in sorted(self._meshes.items())
                },
                "cells": cells,
                "views": dict(self._current_views),
                "lods": dict(self._current_lods),
                "epoch": self._epoch,
                "counters": {
                    "bakes": self._bakes,
                    "rebakes": self._rebakes,
                    "evictions": self._evictions,
                    "view_switches": self._view_switches,
                    "lod_switches": self._lod_switches,
                },
            }

    def restore(self, snap):
        with self._lock:
            try:
                state = self._decode_snapshot(snap)
            except Exception as exc:
                if isinstance(exc, ImpostorError) and \
                        exc.code == "IMP_SNAPSHOT_INVALID":
                    raise
                raise ImpostorError("IMP_SNAPSHOT_INVALID", exc) from exc

            (self._view_count, self._atlas_size, self._cell_size,
             self._memory_budget, self._hysteresis) = state["config"]
            self._meshes = state["meshes"]
            self._cells = state["cells"]
            self._current_views = state["views"]
            self._current_lods = state["lods"]
            self._epoch = state["epoch"]
            (self._bakes, self._rebakes, self._evictions,
             self._view_switches, self._lod_switches) = state["counters"]
            return {"meshes": len(self._meshes), "cells": len(self._cells)}

    def reset(self):
        with self._lock:
            count = len(self._meshes)
            self._meshes.clear()
            self._cells.clear()
            self._current_views.clear()
            self._current_lods.clear()
            self._epoch = 0
            self._bakes = 0
            self._rebakes = 0
            self._evictions = 0
            self._view_switches = 0
            self._lod_switches = 0
            return count

    @staticmethod
    def _is_int(value):
        return isinstance(value, int) and not isinstance(value, bool)

    @staticmethod
    def _is_real(value):
        return (isinstance(value, numbers.Real) and
                not isinstance(value, bool))

    @staticmethod
    def _valid_mesh_id(mesh_id):
        return isinstance(mesh_id, str) and bool(mesh_id)

    @classmethod
    def _validated_config(cls, view_count, atlas_size, cell_size,
                          memory_budget, hysteresis_ratio):
        if not cls._is_int(view_count) or not 4 <= view_count <= 64:
            raise ImpostorError("IMP_BAD_CONFIG", "view_count")
        if not cls._is_int(cell_size) or cell_size < 1:
            raise ImpostorError("IMP_BAD_CONFIG", "cell_size")
        if (not cls._is_int(atlas_size) or atlas_size < cell_size or
                atlas_size % cell_size != 0):
            raise ImpostorError("IMP_BAD_CONFIG", "atlas_size")
        if (not cls._is_real(memory_budget) or
                not math.isfinite(float(memory_budget)) or
                memory_budget < cell_size * cell_size * 4):
            raise ImpostorError("IMP_BAD_CONFIG", "memory_budget")
        if (not cls._is_real(hysteresis_ratio) or
                not math.isfinite(float(hysteresis_ratio)) or
                not 0.0 <= hysteresis_ratio <= 1.0):
            raise ImpostorError("IMP_BAD_CONFIG", "hysteresis_ratio")
        return (view_count, atlas_size, cell_size, memory_budget,
                hysteresis_ratio)

    @classmethod
    def _validated_bounds(cls, bounds):
        if isinstance(bounds, (str, bytes)) or bounds is None:
            raise ImpostorError("IMP_BAD_MESH", "bounds")
        try:
            values = tuple(bounds)
        except TypeError as exc:
            raise ImpostorError("IMP_BAD_MESH", "bounds") from exc
        if len(values) != 6:
            raise ImpostorError("IMP_BAD_MESH", "bounds")
        for value in values:
            if not cls._is_real(value) or not math.isfinite(float(value)):
                raise ImpostorError("IMP_BAD_MESH", "bounds")
        if not all(values[index + 3] > values[index] for index in range(3)):
            raise ImpostorError("IMP_BAD_MESH", "bounds")
        return values

    @classmethod
    def _validated_silhouette(cls, samples, alpha_cutoff):
        if (not cls._is_real(alpha_cutoff) or
                not math.isfinite(float(alpha_cutoff)) or
                not 0.0 <= alpha_cutoff <= 1.0):
            raise ImpostorError("IMP_BAD_SAMPLES", "alpha_cutoff")
        if isinstance(samples, (str, bytes)) or samples is None:
            raise ImpostorError("IMP_BAD_SAMPLES", "samples")
        try:
            rows = list(samples)
        except TypeError as exc:
            raise ImpostorError("IMP_BAD_SAMPLES", "samples") from exc
        if not rows:
            raise ImpostorError("IMP_BAD_SAMPLES", "samples")

        parsed = []
        for sample in rows:
            if isinstance(sample, (str, bytes)):
                raise ImpostorError("IMP_BAD_SAMPLES", sample)
            try:
                values = tuple(sample)
            except TypeError as exc:
                raise ImpostorError("IMP_BAD_SAMPLES", sample) from exc
            if len(values) != 3:
                raise ImpostorError("IMP_BAD_SAMPLES", sample)
            for value in values:
                if (not cls._is_real(value) or
                        not math.isfinite(float(value)) or
                        not 0.0 <= value <= 1.0):
                    raise ImpostorError("IMP_BAD_SAMPLES", sample)
            parsed.append((float(values[0]), float(values[1]),
                           float(values[2])))

        covered = [(u, v) for u, v, alpha in parsed
                   if alpha >= alpha_cutoff]
        if not covered:
            return {"u0": 0.0, "v0": 0.0, "u1": 0.0, "v1": 0.0,
                    "coverage": 0.0}
        return {
            "u0": min(u for u, _v in covered),
            "v0": min(v for _u, v in covered),
            "u1": max(u for u, _v in covered),
            "v1": max(v for _u, v in covered),
            "coverage": len(covered) / len(parsed),
        }

    @classmethod
    def _decode_silhouette(cls, value):
        if not isinstance(value, dict):
            raise ImpostorError("IMP_SNAPSHOT_INVALID", "silhouette")
        keys = ("u0", "v0", "u1", "v1", "coverage")
        numbers = {}
        for key in keys:
            item = value.get(key)
            if (not cls._is_real(item) or
                    not math.isfinite(float(item)) or
                    not 0.0 <= item <= 1.0):
                raise ImpostorError("IMP_SNAPSHOT_INVALID", key)
            numbers[key] = float(item)
        if numbers["u0"] > numbers["u1"] or \
                numbers["v0"] > numbers["v1"]:
            raise ImpostorError("IMP_SNAPSHOT_INVALID", "silhouette")
        return numbers

    @staticmethod
    def _angle_delta(first, second):
        delta = (first - second) % 360.0
        return min(delta, 360.0 - delta)

    def _cell_bytes(self):
        return self._cell_size * self._cell_size * 4

    def _capacity(self):
        return (self._atlas_size // self._cell_size) ** 2

    def _cells_per_row(self):
        return self._atlas_size // self._cell_size

    def _next_free_index(self):
        used = {cell["index"] for cell in self._cells.values()}
        for index in range(self._capacity()):
            if index not in used:
                return index
        raise ImpostorError("IMP_ATLAS_FULL")

    def _touch(self, cell):
        self._epoch += 1
        cell["last_used"] = self._epoch

    def _require_mesh(self, mesh_id):
        if not isinstance(mesh_id, str) or mesh_id not in self._meshes:
            raise ImpostorError("IMP_UNKNOWN_MESH", mesh_id)

    def _check_view_index(self, view_index):
        if (not self._is_int(view_index) or view_index < 0 or
                view_index >= self._view_count):
            raise ImpostorError("IMP_BAD_VIEW", view_index)

    def _build_silhouette(self, samples, alpha_cutoff):
        return self._validated_silhouette(samples, alpha_cutoff)

    def _decode_snapshot(self, snap):
        if not isinstance(snap, dict):
            raise ImpostorError("IMP_SNAPSHOT_INVALID", "snapshot")
        version = snap.get("version")
        if not self._is_int(version) or version != SNAPSHOT_VERSION:
            raise ImpostorError("IMP_SNAPSHOT_INVALID", "version")

        config = snap.get("config")
        if not isinstance(config, dict):
            raise ImpostorError("IMP_SNAPSHOT_INVALID", "config")
        try:
            config_values = self._validated_config(
                config.get("view_count"),
                config.get("atlas_size"),
                config.get("cell_size"),
                config.get("memory_budget"),
                config.get("hysteresis_ratio"))
        except ImpostorError as exc:
            raise ImpostorError("IMP_SNAPSHOT_INVALID", exc) from exc
        view_count, atlas_size, cell_size, memory_budget, _hysteresis = \
            config_values
        cell_bytes = cell_size * cell_size * 4
        capacity = (atlas_size // cell_size) ** 2
        cells_per_row = atlas_size // cell_size

        meshes = {}
        raw_meshes = snap.get("meshes")
        if not isinstance(raw_meshes, dict):
            raise ImpostorError("IMP_SNAPSHOT_INVALID", "meshes")
        for mesh_id, raw_mesh in raw_meshes.items():
            if not self._valid_mesh_id(mesh_id) or \
                    not isinstance(raw_mesh, dict):
                raise ImpostorError("IMP_SNAPSHOT_INVALID", "mesh")
            try:
                bounds = self._validated_bounds(raw_mesh.get("bounds"))
            except ImpostorError as exc:
                raise ImpostorError("IMP_SNAPSHOT_INVALID", exc) from exc
            vertex_count = raw_mesh.get("vertex_count")
            if not self._is_int(vertex_count) or vertex_count < 1:
                raise ImpostorError("IMP_SNAPSHOT_INVALID", "vertex_count")
            material = raw_mesh.get("material")
            if material is not None and not isinstance(material, str):
                raise ImpostorError("IMP_SNAPSHOT_INVALID", "material")
            meshes[mesh_id] = {
                "bounds": bounds,
                "vertex_count": vertex_count,
                "material": material,
            }

        raw_cells = snap.get("cells")
        if not isinstance(raw_cells, list):
            raise ImpostorError("IMP_SNAPSHOT_INVALID", "cells")
        cells = {}
        used_indices = set()
        max_last_used = 0
        for raw_cell in raw_cells:
            if not isinstance(raw_cell, dict):
                raise ImpostorError("IMP_SNAPSHOT_INVALID", "cell")
            mesh_id = raw_cell.get("mesh")
            if mesh_id not in meshes:
                raise ImpostorError("IMP_SNAPSHOT_INVALID", "cell mesh")
            view_index = raw_cell.get("view")
            if (not self._is_int(view_index) or view_index < 0 or
                    view_index >= view_count):
                raise ImpostorError("IMP_SNAPSHOT_INVALID", "cell view")
            index = raw_cell.get("index")
            if (not self._is_int(index) or index < 0 or
                    index >= capacity):
                raise ImpostorError("IMP_SNAPSHOT_INVALID", "cell index")
            key = (mesh_id, view_index)
            if key in cells or index in used_indices:
                raise ImpostorError("IMP_SNAPSHOT_INVALID", "cell duplicate")
            last_used = raw_cell.get("last_used")
            if not self._is_int(last_used) or last_used < 0:
                raise ImpostorError("IMP_SNAPSHOT_INVALID", "last_used")
            silhouette = self._decode_silhouette(
                raw_cell.get("silhouette"))

            expected_x = (index % cells_per_row) * cell_size
            expected_y = (index // cells_per_row) * cell_size
            size = raw_cell.get("size", cell_size)
            x = raw_cell.get("x", expected_x)
            y = raw_cell.get("y", expected_y)
            if (not self._is_int(size) or size != cell_size or
                    not self._is_int(x) or x != expected_x or
                    not self._is_int(y) or y != expected_y):
                raise ImpostorError("IMP_SNAPSHOT_INVALID", "cell layout")

            cells[key] = {
                "index": index,
                "x": expected_x,
                "y": expected_y,
                "size": cell_size,
                "last_used": last_used,
                "silhouette": silhouette,
            }
            used_indices.add(index)
            max_last_used = max(max_last_used, last_used)

        if len(cells) > capacity or len(cells) * cell_bytes > memory_budget:
            raise ImpostorError("IMP_SNAPSHOT_INVALID", "cell budget")

        raw_views = snap.get("views")
        if not isinstance(raw_views, dict):
            raise ImpostorError("IMP_SNAPSHOT_INVALID", "views")
        views = {}
        for mesh_id, view_index in raw_views.items():
            if mesh_id not in meshes:
                raise ImpostorError("IMP_SNAPSHOT_INVALID", "view mesh")
            if (not self._is_int(view_index) or view_index < 0 or
                    view_index >= view_count):
                raise ImpostorError("IMP_SNAPSHOT_INVALID", "view")
            views[mesh_id] = view_index

        raw_lods = snap.get("lods")
        if not isinstance(raw_lods, dict):
            raise ImpostorError("IMP_SNAPSHOT_INVALID", "lods")
        lods = {}
        for mesh_id, lod in raw_lods.items():
            if mesh_id not in meshes:
                raise ImpostorError("IMP_SNAPSHOT_INVALID", "lod mesh")
            if (not self._is_int(lod) or lod < 0 or
                    lod > len(LOD_BOUNDARIES)):
                raise ImpostorError("IMP_SNAPSHOT_INVALID", "lod")
            lods[mesh_id] = lod

        epoch = snap.get("epoch")
        if (not self._is_int(epoch) or epoch < 0 or
                epoch < max_last_used):
            raise ImpostorError("IMP_SNAPSHOT_INVALID", "epoch")

        raw_counters = snap.get("counters")
        if not isinstance(raw_counters, dict):
            raise ImpostorError("IMP_SNAPSHOT_INVALID", "counters")
        counter_names = ("bakes", "rebakes", "evictions", "view_switches",
                         "lod_switches")
        counters = []
        for name in counter_names:
            value = raw_counters.get(name)
            if not self._is_int(value) or value < 0:
                raise ImpostorError("IMP_SNAPSHOT_INVALID", name)
            counters.append(value)

        return {
            "config": config_values,
            "meshes": meshes,
            "cells": cells,
            "views": views,
            "lods": lods,
            "epoch": epoch,
            "counters": tuple(counters),
        }
