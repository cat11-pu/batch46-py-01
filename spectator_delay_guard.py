"""Spectator delay and delivery guard (batch46-game-b-03, Bugfix skeleton)."""


class SpectatorError(ValueError):
    """Raised when a spectator stream operation is rejected."""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = dict(detail or {})


class SpectatorDelay:
    """Delayed frame queue, per-viewer cursors, pause and snapshots."""

    def __init__(self, *, delay_seconds=30, queue_cap=100, viewer_cap=1000):
        self.delay_seconds = delay_seconds
        self.queue_cap = queue_cap
        self.viewer_cap = viewer_cap
        self._matches = {}
        self._viewers = {}

    def subscribe(self, viewer, *, match):
        raise NotImplementedError

    def unsubscribe(self, viewer):
        raise NotImplementedError

    def ingest(self, match, frame):
        raise NotImplementedError

    def poll(self, viewer, *, now, max_items=10):
        raise NotImplementedError

    def set_delay(self, match, seconds):
        raise NotImplementedError

    def pause(self, match):
        raise NotImplementedError

    def resume(self, match):
        raise NotImplementedError

    def queue_depth(self, match):
        raise NotImplementedError

    def backlog(self, viewer):
        raise NotImplementedError

    def timeline(self, match):
        raise NotImplementedError

    def drain(self, viewer):
        raise NotImplementedError

    def stats(self):
        raise NotImplementedError

    def snapshot(self):
        raise NotImplementedError

    def restore(self, snapshot):
        raise NotImplementedError
