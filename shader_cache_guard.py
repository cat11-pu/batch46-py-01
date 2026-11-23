import threading


class ShaderCacheError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


def _normalize_defines(defines):
    table = {}
    for item in defines or ():
        if not isinstance(item, str) or "=" not in item:
            raise ShaderCacheError("SHC_DEFINE_FORMAT", repr(item))
        name, _, value = item.partition("=")
        if not name or not value:
            raise ShaderCacheError("SHC_DEFINE_FORMAT", repr(item))
        if name in table and table[name] != value:
            raise ShaderCacheError("SHC_DEFINE_CONFLICT", name)
        table[name] = value
    return ["{}={}".format(name, table[name]) for name in sorted(table)]


def _validate_size(byte_size):
    if isinstance(byte_size, bool) or not isinstance(byte_size, int) or byte_size <= 0:
        raise ShaderCacheError("SHC_SIZE_INVALID", repr(byte_size))


class ShaderCache:
    """Driver-scoped shader cache with variant limits, LRU trim and compile dedupe."""

    SNAPSHOT_VERSION = 2

    def __init__(self, *, byte_budget=1 << 20, entry_budget=64, variant_limit=4):
        self.byte_budget = byte_budget
        self.entry_budget = entry_budget
        self.variant_limit = variant_limit
        self._lock = threading.RLock()
        self._entries = {}
        self._compiling = {}
        self._seq = 0
        self._clock = 0
        self._bytes = 0
        self._hits = 0
        self._misses = 0
        self._evictions = 0
        self._compiles = 0

    def compose_key(self, source_hash, driver, defines=()):
        if not isinstance(source_hash, str) or not source_hash:
            raise ShaderCacheError("SHC_KEY_INVALID", repr(source_hash))
        if not isinstance(driver, str) or not driver:
            raise ShaderCacheError("SHC_KEY_INVALID", repr(driver))
        normalized = _normalize_defines(defines)
        return "{}|{}|{}".format(source_hash, driver, ",".join(normalized))

    def put(self, source_hash, driver, defines, byte_size, *, pinned=False):
        key = self.compose_key(source_hash, driver, defines)
        _validate_size(byte_size)
        normalized = _normalize_defines(defines)
        with self._lock:
            existing = self._entries.get(key)
            if existing is not None:
                if existing["byte_size"] != byte_size:
                    raise ShaderCacheError("SHC_SIZE_CONFLICT", key)
                return {
                    "status": "duplicate",
                    "key": key,
                    "entries": len(self._entries),
                    "bytes": self._bytes,
                }
            self._enforce_variant_limit(source_hash, driver)
            self._seq += 1
            self._clock += 1
            self._entries[key] = {
                "key": key,
                "source_hash": source_hash,
                "driver": driver,
                "defines": normalized,
                "byte_size": byte_size,
                "pinned": bool(pinned),
                "last_used": self._clock,
                "seq": self._seq,
            }
            self._bytes += byte_size
            return {
                "status": "stored",
                "key": key,
                "entries": len(self._entries),
                "bytes": self._bytes,
            }

    def _enforce_variant_limit(self, source_hash, driver):
        variants = [
            entry
            for entry in self._entries.values()
            if entry["source_hash"] == source_hash and entry["driver"] == driver
        ]
        if len(variants) < self.variant_limit:
            return
        evictable = [entry for entry in variants if not entry["pinned"]]
        if not evictable:
            raise ShaderCacheError("SHC_VARIANT_LIMIT", source_hash)
        victim = min(evictable, key=lambda entry: (entry["last_used"], entry["seq"]))
        self._evict(victim["key"])

    def _evict(self, key):
        entry = self._entries.pop(key)
        self._bytes -= entry["byte_size"]
        self._evictions += 1
        return entry

    def get(self, key):
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                self._misses += 1
                return {"hit": False}
            self._hits += 1
            self._clock += 1
            entry["last_used"] = self._clock
            return {
                "hit": True,
                "byte_size": entry["byte_size"],
                "defines": list(entry["defines"]),
            }

    def begin_compile(self, source_hash, driver, defines=()):
        key = self.compose_key(source_hash, driver, defines)
        normalized = _normalize_defines(defines)
        with self._lock:
            if key in self._entries:
                return {"status": "hit", "key": key}
            if key in self._compiling:
                return {"status": "joined", "key": key}
            self._compiling[key] = {
                "source_hash": source_hash,
                "driver": driver,
                "defines": normalized,
            }
            self._compiles += 1
            return {"status": "compile", "key": key}

    def finish_compile(self, key, byte_size):
        _validate_size(byte_size)
        with self._lock:
            meta = self._compiling.pop(key, None)
            if meta is None:
                raise ShaderCacheError("SHC_NOT_COMPILING", key)
            existing = self._entries.get(key)
            if existing is not None:
                if existing["byte_size"] != byte_size:
                    raise ShaderCacheError("SHC_SIZE_CONFLICT", key)
                return {
                    "status": "stored",
                    "key": key,
                    "byte_size": byte_size,
                    "entries": len(self._entries),
                    "bytes": self._bytes,
                }
            self._seq += 1
            self._clock += 1
            self._entries[key] = {
                "key": key,
                "source_hash": meta["source_hash"],
                "driver": meta["driver"],
                "defines": list(meta["defines"]),
                "byte_size": byte_size,
                "pinned": False,
                "last_used": self._clock,
                "seq": self._seq,
            }
            self._bytes += byte_size
            return {
                "status": "stored",
                "key": key,
                "byte_size": byte_size,
                "entries": len(self._entries),
                "bytes": self._bytes,
            }

    def fail_compile(self, key):
        with self._lock:
            if self._compiling.pop(key, None) is None:
                raise ShaderCacheError("SHC_NOT_COMPILING", key)
            return {"status": "failed", "key": key}

    def _set_pinned(self, key, pinned):
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                raise ShaderCacheError("SHC_KEY_INVALID", key)
            entry["pinned"] = pinned
            return {"key": key, "pinned": pinned}

    def pin(self, key):
        return self._set_pinned(key, True)

    def unpin(self, key):
        return self._set_pinned(key, False)

    def trim(self):
        with self._lock:
            evicted = []
            while self._bytes > self.byte_budget or len(self._entries) > self.entry_budget:
                evictable = [entry for entry in self._entries.values() if not entry["pinned"]]
                if not evictable:
                    raise ShaderCacheError("SHC_BUDGET_STUCK")
                victim = min(evictable, key=lambda entry: (entry["last_used"], entry["seq"]))
                self._evict(victim["key"])
                evicted.append(victim["key"])
            return {
                "evicted": evicted,
                "bytes": self._bytes,
                "entries": len(self._entries),
            }

    def invalidate_driver(self, driver):
        if not isinstance(driver, str) or not driver:
            raise ShaderCacheError("SHC_KEY_INVALID", repr(driver))
        with self._lock:
            removed = [
                entry["key"]
                for entry in sorted(self._entries.values(), key=lambda entry: entry["seq"])
                if entry["driver"] != driver
            ]
            for key in removed:
                entry = self._entries.pop(key)
                self._bytes -= entry["byte_size"]
            return {"removed": removed, "bytes": self._bytes}

    def variants(self, source_hash):
        with self._lock:
            return [
                entry["key"]
                for entry in sorted(self._entries.values(), key=lambda entry: entry["seq"])
                if entry["source_hash"] == source_hash
            ]

    def keys(self):
        with self._lock:
            return [
                entry["key"]
                for entry in sorted(self._entries.values(), key=lambda entry: entry["seq"])
            ]

    def stats(self):
        with self._lock:
            queries = self._hits + self._misses
            hit_rate = round(self._hits / queries, 4) if queries else 0.0
            return {
                "hits": self._hits,
                "misses": self._misses,
                "evictions": self._evictions,
                "compiles": self._compiles,
                "bytes": self._bytes,
                "entries": len(self._entries),
                "hit_rate": hit_rate,
            }

    def snapshot(self):
        with self._lock:
            entries = [
                {
                    "key": entry["key"],
                    "source_hash": entry["source_hash"],
                    "driver": entry["driver"],
                    "defines": list(entry["defines"]),
                    "byte_size": entry["byte_size"],
                    "pinned": entry["pinned"],
                    "last_used": entry["last_used"],
                    "seq": entry["seq"],
                }
                for entry in sorted(self._entries.values(), key=lambda entry: entry["seq"])
            ]
            return {
                "version": self.SNAPSHOT_VERSION,
                "entries": entries,
                "stats": {
                    "hits": self._hits,
                    "misses": self._misses,
                    "evictions": self._evictions,
                    "compiles": self._compiles,
                },
            }

    def restore(self, state):
        if not isinstance(state, dict) or state.get("version") != self.SNAPSHOT_VERSION:
            raise ShaderCacheError("SHC_SNAPSHOT_INVALID", "version")
        raw_entries = state.get("entries")
        if not isinstance(raw_entries, list):
            raise ShaderCacheError("SHC_SNAPSHOT_INVALID", "entries")
        prepared = []
        seen = set()
        for raw in raw_entries:
            if not isinstance(raw, dict):
                raise ShaderCacheError("SHC_SNAPSHOT_INVALID", "entry")
            try:
                source_hash = raw["source_hash"]
                driver = raw["driver"]
                defines = raw["defines"]
                byte_size = raw["byte_size"]
                key = raw["key"]
                pinned = bool(raw["pinned"])
                last_used = raw["last_used"]
                seq = raw["seq"]
            except (KeyError, TypeError):
                raise ShaderCacheError("SHC_SNAPSHOT_INVALID", "entry")
            if isinstance(byte_size, bool) or not isinstance(byte_size, int) or byte_size <= 0:
                raise ShaderCacheError("SHC_SNAPSHOT_INVALID", "byte_size")
            if isinstance(seq, bool) or not isinstance(seq, int):
                raise ShaderCacheError("SHC_SNAPSHOT_INVALID", "seq")
            if isinstance(last_used, bool) or not isinstance(last_used, int):
                raise ShaderCacheError("SHC_SNAPSHOT_INVALID", "last_used")
            if not isinstance(key, str) or key in seen:
                raise ShaderCacheError("SHC_SNAPSHOT_INVALID", "key")
            try:
                recomputed = self.compose_key(source_hash, driver, defines)
            except ShaderCacheError:
                raise ShaderCacheError("SHC_SNAPSHOT_INVALID", "defines")
            if recomputed != key:
                raise ShaderCacheError("SHC_SNAPSHOT_INVALID", "key")
            seen.add(key)
            prepared.append(
                {
                    "key": key,
                    "source_hash": source_hash,
                    "driver": driver,
                    "defines": list(defines),
                    "byte_size": byte_size,
                    "pinned": pinned,
                    "last_used": last_used,
                    "seq": seq,
                }
            )
        stats = state.get("stats") or {}
        with self._lock:
            self._entries = {entry["key"]: dict(entry) for entry in prepared}
            self._compiling = {}
            self._bytes = sum(entry["byte_size"] for entry in prepared)
            self._seq = max([entry["seq"] for entry in prepared], default=0)
            self._clock = max([entry["last_used"] for entry in prepared], default=0)
            self._hits = int(stats.get("hits", 0))
            self._misses = int(stats.get("misses", 0))
            self._evictions = int(stats.get("evictions", 0))
            self._compiles = int(stats.get("compiles", 0))
            return {"restored": len(prepared), "bytes": self._bytes}
