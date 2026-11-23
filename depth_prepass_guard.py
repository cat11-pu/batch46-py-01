"""深度预通道：深度缓冲、层级剔除、绘制排序与快照骨架。"""

import threading

SNAPSHOT_VERSION = 1


class DepthPrepassError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


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
        self._epoch = 0

    def set_viewport(self, width, height, near=0.1, far=1000.0):
        raise NotImplementedError

    def begin_pass(self):
        raise NotImplementedError

    def end_pass(self):
        raise NotImplementedError

    def submit_draw(self, draw):
        raise NotImplementedError

    def write_depth(self, pixel, depth):
        raise NotImplementedError

    def depth_at(self, pixel):
        raise NotImplementedError

    def build_pyramid(self):
        raise NotImplementedError

    def hiz_query(self, rect, depth):
        raise NotImplementedError

    def sorted_draws(self):
        raise NotImplementedError

    def filter_opaque(self, draws):
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
