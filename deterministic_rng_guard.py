from typing import List, Optional, Sequence


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

    def create_stream(self, label: str, seed: Optional[int] = None, *,
                      parent: Optional[str] = None) -> dict:
        raise NotImplementedError

    def has_stream(self, label: str) -> bool:
        raise NotImplementedError

    def streams(self) -> List[str]:
        raise NotImplementedError

    def next_u32(self, label: str = "default") -> int:
        raise NotImplementedError

    def next_float(self, label: str = "default") -> float:
        raise NotImplementedError

    def next_below(self, label: str, bound: int) -> int:
        raise NotImplementedError

    def next_int(self, label: str, low: int, high: int) -> int:
        raise NotImplementedError

    def chance(self, label: str, probability: float) -> bool:
        raise NotImplementedError

    def shuffle(self, label: str, items: Sequence) -> List:
        raise NotImplementedError

    def pick(self, label: str, items: Sequence):
        raise NotImplementedError

    def fork(self, label: str, child_label: str) -> dict:
        raise NotImplementedError

    def position(self, label: str = "default") -> int:
        raise NotImplementedError

    def remaining(self) -> int:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, snapshot: dict) -> None:
        raise NotImplementedError
