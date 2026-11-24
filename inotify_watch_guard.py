"""inotify watch guard.

Bugfix target: the module is a skeleton. Watch allocation, duplicate merge,
per-owner and global quota accounting, batch atomicity, IN_IGNORED handling,
moves and the snapshot/restore path must be implemented behind these
signatures.
"""

import threading

WATCH_MASKS = ("create", "delete", "modify", "move", "attrib")


class InotifyError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class InotifyGuard:
    """Watch descriptors, per-owner quota accounting and IN_IGNORED handling."""

    def __init__(self, max_watches=128, max_per_owner=64, max_ignored=64):
        self.max_watches = max_watches
        self.max_per_owner = max_per_owner
        self.max_ignored = max_ignored
        self._lock = threading.RLock()

    def add_watch(self, path, mask, *, owner="root", is_dir=False):
        raise NotImplementedError

    def add_watch_batch(self, entries, *, owner="root", is_dir=False):
        raise NotImplementedError

    def remove_watch(self, target, *, owner="root"):
        raise NotImplementedError

    def move_watch(self, old_path, new_path, *, owner="root"):
        raise NotImplementedError

    def watch_for(self, path, *, owner="root"):
        raise NotImplementedError

    def path_for(self, wd):
        raise NotImplementedError

    def event(self, wd, mask, *, name=None, cookie=None):
        raise NotImplementedError

    def ignored(self, limit=None):
        raise NotImplementedError

    def stats(self):
        raise NotImplementedError

    def set_limit(self, *, max_watches=None, max_per_owner=None):
        raise NotImplementedError

    def snapshot(self):
        raise NotImplementedError

    def restore(self, snapshot):
        raise NotImplementedError
