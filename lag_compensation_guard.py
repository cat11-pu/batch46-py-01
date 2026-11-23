import math
import threading
from bisect import bisect_left
from typing import List, Mapping, Optional, Tuple


SNAPSHOT_VERSION = 1


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
        self._ticks: List[int] = []
        self._frames: List[dict] = []
        self._lock = threading.RLock()
        self._rewind_tick: Optional[int] = None
        self._rewind_shooter: Optional[str] = None
        self._stats = {"rewinds": 0}

    def record(self, tick: int, entities: Mapping[str, Tuple[float, float]]) -> int:
        with self._lock:
            if self._ticks:
                current_latest = self._ticks[-1]
                if tick == current_latest:
                    raise LagError(
                        "LAG_TICK_DUP",
                        f"tick {tick} is already recorded",
                    )
                if tick < current_latest:
                    raise LagError(
                        "LAG_TICK_ORDER",
                        f"tick {tick} is older than latest {current_latest}",
                    )
            frame = {
                name: (float(position[0]), float(position[1]))
                for name, position in entities.items()
            }
            self._ticks.append(tick)
            self._frames.append(frame)
            while len(self._ticks) > self.history:
                self._ticks.pop(0)
                self._frames.pop(0)
            return tick

    def ticks(self) -> List[int]:
        with self._lock:
            return list(self._ticks)

    def latest(self) -> int:
        with self._lock:
            if not self._ticks:
                raise LagError("LAG_EMPTY_HISTORY", "no frames recorded yet")
            return self._ticks[-1]

    def pose(self, tick: int, entity: str) -> Tuple[float, float]:
        with self._lock:
            return self._resolve_pose(tick, entity)

    def _resolve_pose(self, tick: int, entity: str) -> Tuple[float, float]:
        """Resolve a pose by exact frame or linear interpolation.

        The caller must hold ``self._lock``.  Historical state is never
        mutated, so calls stay correct while a rewind session is open.
        """
        if not self._ticks:
            raise LagError("LAG_EMPTY_HISTORY", "no frames recorded yet")
        oldest = self._ticks[0]
        newest = self._ticks[-1]
        if tick < oldest:
            raise LagError(
                "LAG_TICK_EXPIRED",
                f"tick {tick} is older than oldest retained tick {oldest}",
            )
        if tick > newest:
            raise LagError(
                "LAG_TICK_FUTURE",
                f"tick {tick} is newer than latest tick {newest}",
            )
        index = bisect_left(self._ticks, tick)
        if index < len(self._ticks) and self._ticks[index] == tick:
            frame = self._frames[index]
            if entity not in frame:
                raise LagError(
                    "LAG_UNKNOWN_ENTITY",
                    f"entity {entity!r} missing from tick {tick}",
                )
            return frame[entity]
        left_tick = self._ticks[index - 1]
        right_tick = self._ticks[index]
        left_frame = self._frames[index - 1]
        right_frame = self._frames[index]
        if entity not in left_frame or entity not in right_frame:
            raise LagError(
                "LAG_UNKNOWN_ENTITY",
                f"entity {entity!r} missing between ticks {left_tick} and {right_tick}",
            )
        ratio = (tick - left_tick) / (right_tick - left_tick)
        left_pose = left_frame[entity]
        right_pose = right_frame[entity]
        return (
            left_pose[0] + (right_pose[0] - left_pose[0]) * ratio,
            left_pose[1] + (right_pose[1] - left_pose[1]) * ratio,
        )

    def begin_rewind(self, tick: int) -> int:
        with self._lock:
            if self._rewind_tick is not None:
                raise LagError(
                    "LAG_REWIND_ACTIVE",
                    f"rewind to {self._rewind_tick} is still open",
                )
            if not self._ticks:
                raise LagError("LAG_EMPTY_HISTORY", "no frames recorded yet")
            oldest = self._ticks[0]
            newest = self._ticks[-1]
            if tick < oldest:
                raise LagError(
                    "LAG_TICK_EXPIRED",
                    f"tick {tick} is older than oldest retained tick {oldest}",
                )
            if tick > newest:
                raise LagError(
                    "LAG_TICK_FUTURE",
                    f"tick {tick} is newer than latest tick {newest}",
                )
            window_floor = newest - self.max_rewind
            if tick < window_floor:
                raise LagError(
                    "LAG_REWIND_TOO_OLD",
                    f"tick {tick} precedes rewind floor {window_floor}",
                )
            self._rewind_tick = tick
            self._stats["rewinds"] += 1
            return tick

    def rewinding(self) -> bool:
        with self._lock:
            return self._rewind_tick is not None

    def rewound_pose(self, entity: str) -> Tuple[float, float]:
        with self._lock:
            if self._rewind_tick is None:
                raise LagError("LAG_NO_REWIND", "no active rewind session")
            return self._resolve_pose(self._rewind_tick, entity)

    def rewound_hit(self, entity: str, point: Tuple[float, float],
                    radius: float = 0.0) -> bool:
        with self._lock:
            if self._rewind_tick is None:
                raise LagError("LAG_NO_REWIND", "no active rewind session")
            pose_x, pose_y = self._resolve_pose(self._rewind_tick, entity)
            distance = math.hypot(pose_x - point[0], pose_y - point[1])
            return distance <= radius

    def end_rewind(self) -> bool:
        with self._lock:
            if self._rewind_tick is None:
                raise LagError("LAG_NO_REWIND", "no active rewind session")
            self._rewind_tick = None
            self._rewind_shooter = None
            return True

    def fire(self, shooter: str, target: str, tick: int,
             point: Tuple[float, float], *, radius: float = 0.0) -> dict:
        with self._lock:
            newest = self.latest()
            self.begin_rewind(tick)
            try:
                pose_x, pose_y = self.rewound_pose(target)
                hit = math.hypot(pose_x - point[0], pose_y - point[1]) <= radius
            finally:
                self.end_rewind()
            return {
                "hit": hit,
                "tick": tick,
                "delta": newest - tick,
            }

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": SNAPSHOT_VERSION,
                "history": self.history,
                "max_rewind": self.max_rewind,
                "frames": [
                    {
                        "tick": tick,
                        "entities": {
                            entity: (position[0], position[1])
                            for entity, position in frame.items()
                        },
                    }
                    for tick, frame in zip(self._ticks, self._frames)
                ],
                "stats": dict(self._stats),
            }

    def restore(self, snapshot: dict) -> None:
        if not isinstance(snapshot, dict) or \
                snapshot.get("version") != SNAPSHOT_VERSION:
            raise LagError(
                "LAG_SNAPSHOT_VERSION",
                f"expected snapshot version {SNAPSHOT_VERSION}",
            )
        with self._lock:
            self._rewind_tick = None
            self._rewind_shooter = None
            self.history = snapshot.get("history", self.history)
            self.max_rewind = snapshot.get("max_rewind", self.max_rewind)
            restored_ticks: List[int] = []
            restored_frames: List[dict] = []
            for entry in snapshot.get("frames", []):
                restored_ticks.append(entry["tick"])
                restored_frames.append({
                    entity: (float(position[0]), float(position[1]))
                    for entity, position in entry["entities"].items()
                })
            if len(restored_ticks) > self.history:
                drop = len(restored_ticks) - self.history
                del restored_ticks[:drop]
                del restored_frames[:drop]
            self._ticks = restored_ticks
            self._frames = restored_frames
            saved_stats = snapshot.get("stats", {})
            self._stats = {"rewinds": int(saved_stats.get("rewinds", 0))}

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)
