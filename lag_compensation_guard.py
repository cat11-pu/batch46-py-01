from typing import List, Mapping, Optional, Tuple


class LagError(ValueError):
    def __init__(self, code: str, detail: Optional[str] = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class LagCompensation:
    """Bounded position history, interpolation and rewind-based hit checks."""

    def __init__(self, *, history: int = 64, max_rewind: int = 16) -> None:
        self.history = history
        self.max_rewind = max_rewind

    def record(self, tick: int, entities: Mapping[str, Tuple[float, float]]) -> int:
        raise NotImplementedError

    def ticks(self) -> List[int]:
        raise NotImplementedError

    def latest(self) -> int:
        raise NotImplementedError

    def pose(self, tick: int, entity: str) -> Tuple[float, float]:
        raise NotImplementedError

    def begin_rewind(self, tick: int) -> int:
        raise NotImplementedError

    def rewinding(self) -> bool:
        raise NotImplementedError

    def rewound_pose(self, entity: str) -> Tuple[float, float]:
        raise NotImplementedError

    def rewound_hit(self, entity: str, point: Tuple[float, float],
                    radius: float = 0.0) -> bool:
        raise NotImplementedError

    def end_rewind(self) -> bool:
        raise NotImplementedError

    def fire(self, shooter: str, target: str, tick: int,
             point: Tuple[float, float], *, radius: float = 0.0) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, snapshot: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
