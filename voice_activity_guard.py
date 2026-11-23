"""Voice activity detection guard scaffold (GSB Bugfix task)."""


class VoiceActivityError(ValueError):
    """Domain error carrying a stable error code and optional detail."""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class VoiceActivity:
    """Energy based VAD with hangover, calibration, segments and snapshots."""

    def __init__(self, *, max_streams=32, frame_ms=20, threshold_db=-35.0,
                 hangover_ms=200, min_speech_ms=60, margin_db=9.0):
        self._config = {
            "max_streams": max_streams,
            "frame_ms": frame_ms,
            "threshold_db": threshold_db,
            "hangover_ms": hangover_ms,
            "min_speech_ms": min_speech_ms,
            "margin_db": margin_db,
        }
        self._streams = {}
        self._stats = {
            "frames": 0,
            "speech_frames": 0,
            "segments": 0,
            "discarded": 0,
        }

    def create_stream(self, stream_id, *, sample_rate=16000):
        raise NotImplementedError

    def drop_stream(self, stream_id):
        raise NotImplementedError

    def streams(self):
        raise NotImplementedError

    def frame_size(self, stream_id):
        raise NotImplementedError

    def feed(self, stream_id, frame):
        raise NotImplementedError

    def feed_batch(self, stream_id, frames):
        raise NotImplementedError

    def set_threshold(self, stream_id, threshold_db):
        raise NotImplementedError

    def calibrate(self, stream_id, frames):
        raise NotImplementedError

    def state(self, stream_id):
        raise NotImplementedError

    def segments(self, stream_id):
        raise NotImplementedError

    def close_segment(self, stream_id):
        raise NotImplementedError

    def stats(self):
        raise NotImplementedError

    def snapshot(self):
        raise NotImplementedError

    def restore(self, snapshot):
        raise NotImplementedError
