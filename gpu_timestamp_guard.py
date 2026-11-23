class GpuTimestampError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class GpuTimestamp:
    """Frame-scoped GPU timestamp queries with unrolling of 48-bit tick wraps."""

    def __init__(self, *, query_pool_size=64, max_frames_in_flight=3, wrap_bits=48):
        self.query_pool_size = query_pool_size
        self.max_frames_in_flight = max_frames_in_flight
        self.wrap_bits = wrap_bits

    def begin_frame(self, frame_id, *, queue="graphics"):
        raise NotImplementedError

    def write_timestamp(self, frame_id, stage, ticks):
        raise NotImplementedError

    def end_frame(self, frame_id, *, completed=True):
        raise NotImplementedError

    def frame_stats(self, frame_id):
        raise NotImplementedError

    def frames(self):
        raise NotImplementedError

    def percentiles(self):
        raise NotImplementedError

    def calibrate(self, gpu_ticks, cpu_ns):
        raise NotImplementedError

    def tick_rate(self):
        raise NotImplementedError

    def pool_usage(self):
        raise NotImplementedError

    def snapshot(self):
        raise NotImplementedError

    def restore(self, state):
        raise NotImplementedError
