"""DSP limiter guard scaffold (GSB Bugfix task)."""


class DspLimiterError(ValueError):
    """Domain error carrying a stable error code and optional detail."""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class DspLimiter:
    """Lookahead peak limiter with linked stereo gain and snapshot support."""

    def __init__(self, *, sample_rate=48000, ceiling_db=-1.0, attack_ms=5.0,
                 release_ms=50.0, lookahead_ms=2.0, max_block_size=4096):
        self._config = {
            "sample_rate": sample_rate,
            "ceiling_db": ceiling_db,
            "attack_ms": attack_ms,
            "release_ms": release_ms,
            "lookahead_ms": lookahead_ms,
            "max_block_size": max_block_size,
        }
        self._gains = {}
        self._delay = {}
        self._linked_gain = 1.0
        self._stats = {
            "blocks": 0,
            "frames": 0,
            "limited_samples": 0,
        }

    def configure(self, **kwargs):
        raise NotImplementedError

    def ceiling(self):
        raise NotImplementedError

    def latency_samples(self):
        raise NotImplementedError

    def process_block(self, channel, samples):
        raise NotImplementedError

    def process_linked(self, channels):
        raise NotImplementedError

    def gain_reduction_db(self):
        raise NotImplementedError

    def channel_gain(self, channel):
        raise NotImplementedError

    def stats(self):
        raise NotImplementedError

    def reset(self):
        raise NotImplementedError

    def snapshot(self):
        raise NotImplementedError

    def restore(self, snapshot):
        raise NotImplementedError
