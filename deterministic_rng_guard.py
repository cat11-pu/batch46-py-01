import hashlib
import threading
from typing import List, Optional, Sequence

_MASK64 = (1 << 64) - 1
_GOLDEN = 0x9E3779B97F4A7C15


def _mix64(value: int) -> int:
    value = (value + _GOLDEN) & _MASK64
    value = ((value ^ (value >> 30)) * 0xBF58476D1CE4E5B9) & _MASK64
    value = ((value ^ (value >> 27)) * 0x94D049BB133111EB) & _MASK64
    return value ^ (value >> 31)


def _label_hash(label: str) -> int:
    digest = hashlib.blake2b(str(label).encode("utf-8"), digest_size=8).digest()
    return int.from_bytes(digest, "big")


class _Stream:
    __slots__ = ("label", "seed", "position")

    def __init__(self, label: str, seed: int) -> None:
        self.label = label
        self.seed = seed & _MASK64
        self.position = 0

    def to_dict(self) -> dict:
        return {"label": self.label, "seed": self.seed, "position": self.position}


class RngError(ValueError):
    def __init__(self, code: str, detail: Optional[str] = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class DeterministicRng:
    """Named deterministic streams, draw primitives, fork, snapshots and draw budget."""

    def __init__(self, seed: int = 0, *, max_draws: int = 4096,
                 version: int = 1) -> None:
        self.seed = seed
        self.max_draws = max_draws
        self.version = version
        self._lock = threading.RLock()
        self._streams = {}
        self._draws_used = 0
        self._streams["default"] = _Stream("default", _mix64(self.seed))

    def _get_stream(self, label: str) -> _Stream:
        stream = self._streams.get(label)
        if stream is None:
            raise RngError("RNG_UNKNOWN_STREAM", label)
        return stream

    def _draw_u32(self, stream: _Stream) -> int:
        if self._draws_used >= self.max_draws:
            raise RngError("RNG_BUDGET_EXCEEDED",
                           "budget exhausted (%d)" % self.max_draws)
        value = _mix64((stream.seed + stream.position) & _MASK64) >> 32
        stream.position += 1
        self._draws_used += 1
        return value

    def create_stream(self, label: str, seed: Optional[int] = None, *,
                      parent: Optional[str] = None) -> dict:
        with self._lock:
            if parent is not None:
                self._get_stream(parent)
            if label in self._streams:
                raise RngError("RNG_STREAM_DUP", label)
            if seed is not None:
                stream_seed = _mix64(seed)
            elif parent is not None:
                stream_seed = _mix64(self._streams[parent].seed ^ _label_hash(label))
            else:
                stream_seed = _mix64(self.seed ^ _label_hash(label))
            stream = _Stream(label, stream_seed)
            self._streams[label] = stream
            return {"label": label, "seed": stream.seed, "parent": parent,
                    "position": 0}

    def has_stream(self, label: str) -> bool:
        with self._lock:
            return label in self._streams

    def streams(self) -> List[str]:
        with self._lock:
            return list(self._streams.keys())

    def next_u32(self, label: str = "default") -> int:
        with self._lock:
            return self._draw_u32(self._get_stream(label))

    def next_float(self, label: str = "default") -> float:
        with self._lock:
            return self._draw_u32(self._get_stream(label)) / float(1 << 32)

    def next_below(self, label: str, bound: int) -> int:
        with self._lock:
            stream = self._get_stream(label)
            if not isinstance(bound, int) or isinstance(bound, bool) or bound <= 0:
                raise RngError("RNG_INVALID_RANGE",
                               "bound must be a positive int, got %r" % (bound,))
            if bound == 1:
                return 0
            return self._draw_u32(stream) % bound

    def next_int(self, label: str, low: int, high: int) -> int:
        with self._lock:
            stream = self._get_stream(label)
            if low > high:
                raise RngError("RNG_INVALID_RANGE",
                               "low %r exceeds high %r" % (low, high))
            if low == high:
                return low
            return low + self._draw_u32(stream) % (high - low + 1)

    def chance(self, label: str, probability: float) -> bool:
        with self._lock:
            stream = self._get_stream(label)
            if (not isinstance(probability, (int, float))
                    or isinstance(probability, bool)
                    or not 0.0 <= probability <= 1.0):
                raise RngError("RNG_INVALID_PROBABILITY",
                               "probability out of range: %r" % (probability,))
            if probability <= 0.0:
                return False
            if probability >= 1.0:
                return True
            return self._draw_u32(stream) < probability * (1 << 32)

    def shuffle(self, label: str, items: Sequence) -> List:
        with self._lock:
            stream = self._get_stream(label)
            if isinstance(items, (str, bytes)) or not hasattr(items, "__len__"):
                raise RngError("RNG_INVALID_RANGE",
                               "items must be a sequence, got %r" % (items,))
            result = list(items)
            needed = max(0, len(result) - 1)
            if self._draws_used + needed > self.max_draws:
                raise RngError("RNG_BUDGET_EXCEEDED",
                               "budget exhausted (%d)" % self.max_draws)
            for index in range(len(result) - 1, 0, -1):
                swap = self._draw_u32(stream) % (index + 1)
                result[index], result[swap] = result[swap], result[index]
            return result

    def pick(self, label: str, items: Sequence):
        with self._lock:
            stream = self._get_stream(label)
            if items is None or len(items) == 0:
                raise RngError("RNG_EMPTY_POOL", "cannot pick from an empty pool")
            if len(items) == 1:
                return items[0]
            return items[self._draw_u32(stream) % len(items)]

    def fork(self, label: str, child_label: str) -> dict:
        with self._lock:
            parent = self._get_stream(label)
            if child_label in self._streams:
                raise RngError("RNG_STREAM_DUP", child_label)
            child = _Stream(child_label,
                            _mix64(parent.seed ^ _label_hash(child_label)))
            self._streams[child_label] = child
            return {"label": child_label, "seed": child.seed,
                    "parent": label, "position": 0}

    def position(self, label: str = "default") -> int:
        with self._lock:
            return self._get_stream(label).position

    def remaining(self) -> int:
        with self._lock:
            return self.max_draws - self._draws_used

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": self.version,
                "seed": self.seed,
                "max_draws": self.max_draws,
                "draws_used": self._draws_used,
                "streams": {label: stream.to_dict()
                            for label, stream in self._streams.items()},
            }

    def restore(self, snapshot: dict) -> None:
        with self._lock:
            if not isinstance(snapshot, dict) \
                    or snapshot.get("version") != self.version:
                raise RngError("RNG_SNAPSHOT_VERSION",
                               "expected version %r" % (self.version,))
            streams = {}
            for label, state in snapshot["streams"].items():
                stream = _Stream(label, int(state["seed"]))
                stream.position = int(state["position"])
                streams[label] = stream
            self._streams = streams
            self._draws_used = int(snapshot["draws_used"])
