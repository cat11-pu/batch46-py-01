"""可变速率着色率图、内容自适应推导与预算守卫骨架。"""

import threading

ENTRY_BYTES = 32
DEFAULT_SUPPORTED = ("1x1", "1x2", "2x1", "2x2")


class VrsError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class VrsGuard:
    """率图维护、内容自适应推导、附件合并、脏 tile 失效与快照恢复。"""

    def __init__(self, base_rate="1x1", supported_rates=None, tile_size=16,
                 memory_budget=1 << 20):
        self._lock = threading.RLock()
        self._base_rate = base_rate
        self._supported = list(supported_rates) if supported_rates else list(DEFAULT_SUPPORTED)
        self._tile_size = tile_size
        self._memory_budget = memory_budget
        self._entries = {}
        self._dirty = set()
        self._epoch = 0

    def normalize_rate(self, rate):
        raise NotImplementedError

    def supported_rates(self):
        raise NotImplementedError

    def set_base_rate(self, rate):
        raise NotImplementedError

    def set_tile_rate(self, tile, rate, *, source="api"):
        raise NotImplementedError

    def set_rate_map(self, mapping):
        raise NotImplementedError

    def rate_at(self, pixel):
        raise NotImplementedError

    def derive_rates(self, tile_stats):
        raise NotImplementedError

    def mark_dirty(self, tile):
        raise NotImplementedError

    def flush(self):
        raise NotImplementedError

    def apply_attachment(self, attachment):
        raise NotImplementedError

    def coverage_image_size(self, width, height):
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
