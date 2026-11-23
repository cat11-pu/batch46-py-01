"""Spatial audio panning guard scaffold (GSB Bugfix task)."""


class SpatialAudioError(ValueError):
    """Domain error carrying a stable error code and optional detail."""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class SpatialAudio:
    """Listener/source registry, pan law and distance attenuation for 3D audio."""

    def __init__(self, *, max_sources=64, max_listeners=4):
        self.max_sources = max_sources
        self.max_listeners = max_listeners
        self._listeners = {}
        self._sources = {}
        self._sequence = 0
        self._stats = {
            "mix_calls": 0,
            "moves": 0,
            "evictions": 0,
            "listener_updates": 0,
        }

    def add_listener(self, listener_id, *, position=(0.0, 0.0, 0.0), yaw=0.0,
                     master_gain=1.0):
        raise NotImplementedError

    def remove_listener(self, listener_id):
        raise NotImplementedError

    def update_listener(self, listener_id, *, position=None, yaw=None,
                        master_gain=None):
        raise NotImplementedError

    def add_source(self, source_id, *, position=(0.0, 0.0, 0.0), gain=1.0,
                   priority=0, category="sfx"):
        raise NotImplementedError

    def remove_source(self, source_id):
        raise NotImplementedError

    def move_source(self, source_id, position, *, velocity=None,
                    sequence=None):
        raise NotImplementedError

    def move_batch(self, updates):
        raise NotImplementedError

    def pan_gains(self, listener_id, source_id):
        raise NotImplementedError

    def mix(self, listener_id):
        raise NotImplementedError

    def set_environment(self, *, ref_distance=1.0, max_distance=100.0):
        raise NotImplementedError

    def sources(self):
        raise NotImplementedError

    def listeners(self):
        raise NotImplementedError

    def stats(self):
        raise NotImplementedError

    def snapshot(self):
        raise NotImplementedError

    def restore(self, snapshot):
        raise NotImplementedError
