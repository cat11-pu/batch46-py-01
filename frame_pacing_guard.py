"""Video frame pacing guard (GSB Bugfix task).

FramePacer aligns frames to vsync boundaries, enforces a monotonic clock,
discards excessively late frames, adapts the target fps and keeps a capped
history of presented frame durations.  All mutable state is guarded by a
reentrant lock so the render loop, cutscene and capture paths can share one
instance from multiple threads.
"""

import math
import threading


class FramePacerError(ValueError):
    """Domain error carrying a stable error code and optional detail."""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class FramePacer:
    """Vsync aligned frame scheduler with adaptive target fps and snapshots."""

    def __init__(self, *, target_fps: float = 60.0, vsync_hz: float = 60.0,
                 max_late_ms: float = 8.0, max_in_flight: int = 4,
                 history: int = 240, min_fps: float = 30.0) -> None:
        self._config = {
            "target_fps": target_fps,
            "vsync_hz": vsync_hz,
            "max_late_ms": max_late_ms,
            "max_in_flight": max_in_flight,
            "history": history,
            "min_fps": min_fps,
        }
        self._lock = threading.RLock()
        self._clock_us = 0
        self._configured_fps = float(target_fps)
        self._target_fps = float(target_fps)
        self._in_flight = {}
        self._known = set()
        self._durations = []
        self._presented = 0
        self._dropped = 0
        self._missed = 0
        self._miss_streak = 0
        self._stable_streak = 0

    def configure(self, **kwargs) -> dict:
        """Update construction-time options and return the new config."""
        with self._lock:
            for key in kwargs:
                if key not in self._config:
                    raise FramePacerError("PAC_CONFIG_UNKNOWN", key)
            self._config.update(kwargs)
            if "target_fps" in kwargs:
                fps = float(kwargs["target_fps"])
                self._configured_fps = fps
                self._target_fps = fps
                self._miss_streak = 0
                self._stable_streak = 0
            if "history" in kwargs:
                cap = int(kwargs["history"])
                self._durations = self._durations[-cap:] if cap > 0 else []
            return dict(self._config)

    def start(self, start_us: int = 0) -> dict:
        """Arm the monotonic clock at an absolute microsecond timestamp."""
        with self._lock:
            self._clock_us = int(start_us)
            return {"start_us": self._clock_us, "now_us": self._clock_us}

    def now_us(self) -> int:
        """Return the current absolute clock value in microseconds."""
        with self._lock:
            return self._clock_us

    def advance(self, now_us: int) -> int:
        """Move the clock to an absolute timestamp; return the increment."""
        with self._lock:
            now_us = int(now_us)
            if now_us < self._clock_us:
                raise FramePacerError(
                    "PAC_CLOCK_REGRESS",
                    {"now_us": now_us, "current_us": self._clock_us})
            delta = now_us - self._clock_us
            self._clock_us = now_us
            return delta

    def _deadline_for(self, start_us: int) -> int:
        period = 1_000_000.0 / float(self._config["vsync_hz"])
        boundary = math.floor(start_us / period) + 1
        return int(boundary * period)

    def begin_frame(self, frame_id: str) -> dict:
        """Register a frame starting at the current clock value."""
        with self._lock:
            if frame_id in self._known:
                raise FramePacerError("PAC_FRAME_EXISTS", frame_id)
            if len(self._in_flight) >= int(self._config["max_in_flight"]):
                raise FramePacerError("PAC_INFLIGHT_LIMIT", frame_id)
            start_us = self._clock_us
            deadline_us = self._deadline_for(start_us)
            self._in_flight[frame_id] = {
                "start_us": start_us,
                "deadline_us": deadline_us,
            }
            self._known.add(frame_id)
            return {
                "frame_id": frame_id,
                "start_us": start_us,
                "deadline_us": deadline_us,
                "target_fps": self._target_fps,
            }

    def _register_miss(self) -> None:
        self._stable_streak = 0
        self._miss_streak += 1
        if self._miss_streak >= 3:
            self._miss_streak = 0
            floor_fps = float(self._config["min_fps"])
            self._target_fps = max(floor_fps, self._target_fps - 10.0)

    def _register_present(self) -> None:
        self._miss_streak = 0
        self._stable_streak += 1
        if self._stable_streak >= 120:
            self._stable_streak = 0
            self._target_fps = min(self._configured_fps,
                                   self._target_fps + 5.0)

    def _record_duration(self, duration_us: int) -> None:
        self._durations.append(duration_us)
        cap = int(self._config["history"])
        if len(self._durations) > cap:
            del self._durations[:-cap]

    def end_frame(self, frame_id: str) -> dict:
        """Finish a frame, classifying it as present or dropped."""
        with self._lock:
            frame = self._in_flight.get(frame_id)
            if frame is None:
                raise FramePacerError("PAC_FRAME_UNKNOWN", frame_id)
            del self._in_flight[frame_id]

            now_us = self._clock_us
            duration_us = now_us - frame["start_us"]
            late_us = now_us - frame["deadline_us"]
            max_late_us = float(self._config["max_late_ms"]) * 1000.0
            missed = late_us > 0

            if missed and late_us > max_late_us:
                action = "drop"
                self._dropped += 1
                self._missed += 1
                self._register_miss()
            else:
                action = "present"
                self._presented += 1
                self._record_duration(duration_us)
                if missed:
                    self._missed += 1
                    self._register_miss()
                else:
                    self._register_present()

            return {
                "frame_id": frame_id,
                "action": action,
                "missed": missed,
                "start_us": frame["start_us"],
                "deadline_us": frame["deadline_us"],
                "duration_us": duration_us,
                "late_us": late_us,
                "target_fps": self._target_fps,
            }

    def drop_frame(self, frame_id: str) -> bool:
        """Explicitly discard an in-flight frame; unknown ids return False."""
        with self._lock:
            if frame_id not in self._in_flight:
                return False
            del self._in_flight[frame_id]
            self._dropped += 1
            self._missed += 1
            self._register_miss()
            return True

    def in_flight(self) -> list:
        """Return in-flight frame ids in begin order."""
        with self._lock:
            return list(self._in_flight.keys())

    def set_target_fps(self, fps: float) -> dict:
        """Pin both the configured cap and current target fps."""
        with self._lock:
            value = float(fps)
            floor_fps = float(self._config["min_fps"])
            if value < floor_fps or value > 240.0:
                raise FramePacerError("PAC_FPS_RANGE", value)
            self._configured_fps = value
            self._target_fps = value
            self._miss_streak = 0
            self._stable_streak = 0
            return {
                "target_fps": value,
                "configured_fps": value,
            }

    def adaptive_fps(self) -> float:
        """Return the current adaptive target fps."""
        with self._lock:
            return self._target_fps

    def percentile(self, p: float) -> float:
        """Nearest-rank percentile over the latest presented durations."""
        with self._lock:
            if not self._durations:
                return 0.0
            ordered = sorted(self._durations)
            rank = math.ceil(float(p) / 100.0 * len(ordered))
            index = max(rank - 1, 0)
            return float(ordered[index])

    def stats(self) -> dict:
        """Return cumulative counters plus the current pacing state."""
        with self._lock:
            frames = self._presented + self._dropped
            return {
                "frames": frames,
                "presented": self._presented,
                "dropped": self._dropped,
                "missed": self._missed,
                "miss_rate": (self._missed / frames) if frames else 0.0,
                "p95_us": self.percentile(95.0),
                "target_fps": self._target_fps,
                "configured_fps": self._configured_fps,
                "in_flight": len(self._in_flight),
                "now_us": self._clock_us,
            }

    def snapshot(self) -> dict:
        """Capture a json-serialisable snapshot of every mutable state."""
        with self._lock:
            return {
                "config": dict(self._config),
                "clock_us": self._clock_us,
                "configured_fps": self._configured_fps,
                "target_fps": self._target_fps,
                "presented": self._presented,
                "dropped": self._dropped,
                "missed": self._missed,
                "miss_streak": self._miss_streak,
                "stable_streak": self._stable_streak,
                "in_flight": [
                    {
                        "frame_id": frame_id,
                        "start_us": info["start_us"],
                        "deadline_us": info["deadline_us"],
                    }
                    for frame_id, info in self._in_flight.items()
                ],
                "durations": list(self._durations),
                "known": list(self._known),
            }

    def restore(self, snapshot: dict) -> None:
        """Replace all mutable state with a previous snapshot."""
        with self._lock:
            self._config = dict(snapshot["config"])
            self._clock_us = int(snapshot["clock_us"])
            self._configured_fps = float(snapshot["configured_fps"])
            self._target_fps = float(snapshot["target_fps"])
            self._presented = int(snapshot["presented"])
            self._dropped = int(snapshot["dropped"])
            self._missed = int(snapshot["missed"])
            self._miss_streak = int(snapshot["miss_streak"])
            self._stable_streak = int(snapshot["stable_streak"])
            self._durations = list(snapshot["durations"])
            self._known = set(snapshot["known"])
            self._in_flight = {}
            for entry in snapshot["in_flight"]:
                self._in_flight[entry["frame_id"]] = {
                    "start_us": int(entry["start_us"]),
                    "deadline_us": int(entry["deadline_us"]),
                }
