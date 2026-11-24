"""fanotify permission event guard.

Bugfix target: the module is a skeleton. Mark merging, the pending permission
queue, deadline expiry, cookie coalescing, allowlist suppression, metrics and
the snapshot/restore path must be implemented behind the signatures below.
"""

import threading

MASKS = ("open_perm", "access_perm", "exec_perm")
DECISIONS = ("allow", "deny")


class FanotifyError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class FanotifyGuard:
    """Marks, pending permission events, decisions and timeout expiry."""

    def __init__(self, max_marks=32, max_pending=8, default_timeout=5):
        self.max_marks = max_marks
        self.max_pending = max_pending
        self.default_timeout = default_timeout
        self._lock = threading.RLock()

    def add_mark(self, path, mask):
        raise NotImplementedError

    def remove_mark(self, path):
        raise NotImplementedError

    def allowlist_add(self, path):
        raise NotImplementedError

    def allowlist_remove(self, path):
        raise NotImplementedError

    def submit_event(self, event_id, path, mask, *, pid=None, cookie=None,
                     timeout=None, now=0):
        raise NotImplementedError

    def decide(self, event_id, decision, *, pid=None, reason=None, now=None):
        raise NotImplementedError

    def expire(self, now):
        raise NotImplementedError

    def pending(self):
        raise NotImplementedError

    def status(self):
        raise NotImplementedError

    def metrics(self):
        raise NotImplementedError

    def close(self):
        raise NotImplementedError

    def snapshot(self):
        raise NotImplementedError

    def restore(self, snapshot):
        raise NotImplementedError
