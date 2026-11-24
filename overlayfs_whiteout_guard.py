"""overlayfs whiteout guard.

Bugfix target: the module is a skeleton. Lower/upper layer tables, merged
resolution, whiteout and opaque directory creation, rename semantics, orphan
cleanup, compaction and the snapshot/restore path must be implemented behind
the signatures below.
"""

import threading

KINDS = ("file", "dir", "whiteout", "opaque")
LOWER_KINDS = ("file", "dir")


class OverlayError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class OverlayGuard:
    """Lower layer table, upper entries, merged resolution and cleanup."""

    def __init__(self, max_entries=512, max_journal=256):
        self.max_entries = max_entries
        self.max_journal = max_journal
        self._lock = threading.RLock()

    def add_lower(self, layer, entries):
        raise NotImplementedError

    def add_upper(self, path, kind, *, content=None, origin=None):
        raise NotImplementedError

    def resolve(self, path):
        raise NotImplementedError

    def list_merged(self, path, *, recursive=False):
        raise NotImplementedError

    def remove(self, path, *, recursive=False):
        raise NotImplementedError

    def rename(self, src, dst):
        raise NotImplementedError

    def cleanup(self, *, dry_run=False):
        raise NotImplementedError

    def compact(self):
        raise NotImplementedError

    def stats(self):
        raise NotImplementedError

    def journal(self, limit=None):
        raise NotImplementedError

    def snapshot(self):
        raise NotImplementedError

    def restore(self, snapshot):
        raise NotImplementedError
