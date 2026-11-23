"""Video frame pacing guard scaffold (GSB Bugfix task)."""


class FramePacerError(ValueError):
    """Domain error carrying a stable error code and optional detail."""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class FramePacer:
    """Vsync aligned frame scheduler with adaptive target fps and snapshots."""

    def __init__(self, *, target_fps=60.0, vsync_hz=60.0, max_late_ms=8.0,
                 max_in_flight=4, history=240, min_fps=30.0):
        self._config = {
            "target_fps": target_fps,
            "vsync_hz": vsync_hz,
            "max_late_ms": max_late_ms,
            "max_in_flight": max_in_flight,
            "history": history,
            "min_fps": min_fps,
        }
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

    def configure(self, **kwargs):
        raise NotImplementedError

    def start(self, start_us=0):
        raise NotImplementedError

    def now_us(self):
        raise NotImplementedError

    def advance(self, now_us):
        raise NotImplementedError

    def begin_frame(self, frame_id):
        raise NotImplementedError

    def end_frame(self, frame_id):
        raise NotImplementedError

    def drop_frame(self, frame_id):
        raise NotImplementedError

    def in_flight(self):
        raise NotImplementedError

    def set_target_fps(self, fps):
        raise NotImplementedError

    def adaptive_fps(self):
        raise NotImplementedError

    def percentile(self, p):
        raise NotImplementedError

    def stats(self):
        raise NotImplementedError

    def snapshot(self):
        raise NotImplementedError

    def restore(self, snapshot):
        raise NotImplementedError
