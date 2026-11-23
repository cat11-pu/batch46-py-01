"""公告板替身：图集烘焙、视角选择、LOD 滞回与预算守卫骨架。"""

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
        self._lock = threading.RLock()
        self._view_count = view_count
        self._atlas_size = atlas_size
        self._cell_size = cell_size
        self._memory_budget = memory_budget
        self._hysteresis = hysteresis_ratio
        self._meshes = {}
        self._cells = {}
        self._epoch = 0

    def register_mesh(self, mesh_id, *, bounds, vertex_count, material=None):
        raise NotImplementedError

    def bake(self, mesh_id, view_index, *, samples, alpha_cutoff=0.5):
        raise NotImplementedError

    def atlas_cell(self, mesh_id, view_index):
        raise NotImplementedError

    def silhouette(self, mesh_id, view_index):
        raise NotImplementedError

    def view_index(self, yaw):
        raise NotImplementedError

    def best_view(self, mesh_id, yaw):
        raise NotImplementedError

    def select_view(self, mesh_id, yaw):
        raise NotImplementedError

    def lod_for(self, mesh_id, distance):
        raise NotImplementedError

    def evict(self, count):
        raise NotImplementedError

    def memory_usage(self):
        raise NotImplementedError

    def stats(self):
        raise NotImplementedError

    def snapshot(self):
        raise NotImplementedError

    def restore(self, snap):
        raise NotImplementedError

    def reset(self):
        raise NotImplementedError
