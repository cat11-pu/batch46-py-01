"""Echo cancellation reference guard scaffold (GSB Bugfix task)."""


class EchoCancelError(ValueError):
    """Domain error carrying a stable error code and optional detail."""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class EchoCancel:
    """Reference ring buffer, delay alignment and double-talk detection."""

    def __init__(self, *, max_sessions=8, max_push_samples=4096,
                 filter_len=512, max_delay_ms=50.0):
        self._config = {
            "max_sessions": max_sessions,
            "max_push_samples": max_push_samples,
            "filter_len": filter_len,
            "max_delay_ms": max_delay_ms,
        }
        self._sessions = {}

    def create_session(self, session_id, *, sample_rate=16000,
                       delay_hint_ms=0.0):
        raise NotImplementedError

    def close_session(self, session_id):
        raise NotImplementedError

    def sessions(self):
        raise NotImplementedError

    def push_reference(self, session_id, samples):
        raise NotImplementedError

    def reference(self, session_id, length=None):
        raise NotImplementedError

    def push_capture(self, session_id, samples):
        raise NotImplementedError

    def align(self, session_id):
        raise NotImplementedError

    def set_delay(self, session_id, delay_samples):
        raise NotImplementedError

    def delay_samples(self, session_id):
        raise NotImplementedError

    def double_talk(self, session_id):
        raise NotImplementedError

    def reference_level_db(self, session_id):
        raise NotImplementedError

    def flush(self, session_id):
        raise NotImplementedError

    def stats(self, session_id):
        raise NotImplementedError

    def snapshot(self):
        raise NotImplementedError

    def restore(self, snapshot):
        raise NotImplementedError
