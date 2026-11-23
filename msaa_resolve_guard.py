"""MSAA 样本存储、深度测试、tile 解析与显存预算骨架。"""

import threading


class MsaaError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class MsaaResolve:
    """多采样样本写入、深度测试、tile 解析、显存预算与快照恢复。"""

    def __init__(self, sample_count=4, tile_size=8, memory_budget=65536,
                 resolve_mode="average"):
        self._lock = threading.RLock()
        self._sample_count = sample_count
        self._tile_size = tile_size
        self._memory_budget = memory_budget
        self._resolve_mode = resolve_mode
        self._bounds = None
        self._samples = {}
        self._dirty = set()
        self._epoch = 0

    def configure(self, *, sample_count=None, tile_size=None, resolve_mode=None,
                  memory_budget=None):
        raise NotImplementedError

    def resize(self, width, height):
        raise NotImplementedError

    def add_sample(self, pixel, sample_index, color, coverage=1.0, depth=None,
                   stencil=0):
        raise NotImplementedError

    def resolve_pixel(self, pixel):
        raise NotImplementedError

    def resolve_depth(self, pixel):
        raise NotImplementedError

    def resolve_tile(self, tile):
        raise NotImplementedError

    def resolve_all(self):
        raise NotImplementedError

    def flush_dirty(self):
        raise NotImplementedError

    def set_alpha_to_coverage(self, enabled):
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
