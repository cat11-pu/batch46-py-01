class ShaderCacheError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class ShaderCache:
    """Driver-scoped shader cache with variant limits, LRU trim and compile dedupe."""

    def __init__(self, *, byte_budget=1 << 20, entry_budget=64, variant_limit=4):
        self.byte_budget = byte_budget
        self.entry_budget = entry_budget
        self.variant_limit = variant_limit

    def compose_key(self, source_hash, driver, defines=()):
        raise NotImplementedError

    def put(self, source_hash, driver, defines, byte_size, *, pinned=False):
        raise NotImplementedError

    def get(self, key):
        raise NotImplementedError

    def begin_compile(self, source_hash, driver, defines=()):
        raise NotImplementedError

    def finish_compile(self, key, byte_size):
        raise NotImplementedError

    def fail_compile(self, key):
        raise NotImplementedError

    def pin(self, key):
        raise NotImplementedError

    def unpin(self, key):
        raise NotImplementedError

    def trim(self):
        raise NotImplementedError

    def invalidate_driver(self, driver):
        raise NotImplementedError

    def variants(self, source_hash):
        raise NotImplementedError

    def keys(self):
        raise NotImplementedError

    def stats(self):
        raise NotImplementedError

    def snapshot(self):
        raise NotImplementedError

    def restore(self, state):
        raise NotImplementedError
