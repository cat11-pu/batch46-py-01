"""SELinux boolean and context guard.

Bugfix target: the module is a skeleton. Boolean declaration, staged changes,
dependency validation, atomic commits, context precedence, relabeling and the
snapshot/restore path must be implemented behind the signatures below.
"""

import threading

MODES = ("enforcing", "permissive", "disabled")


class SelinuxError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class SelinuxGuard:
    """Boolean store, staged changes, context rule table and policy version."""

    def __init__(self, max_booleans=64, max_context_rules=64,
                 max_audit=256):
        self.max_booleans = max_booleans
        self.max_context_rules = max_context_rules
        self.max_audit = max_audit
        self._lock = threading.RLock()

    def define_boolean(self, name, *, default=False, persistent=False,
                       requires=None, description=None):
        raise NotImplementedError

    def set_boolean(self, name, value, *, persistent=False):
        raise NotImplementedError

    def get_boolean(self, name, *, persistent=False):
        raise NotImplementedError

    def pending_changes(self):
        raise NotImplementedError

    def commit(self, *, policy_version=None):
        raise NotImplementedError

    def abort(self):
        raise NotImplementedError

    def mode(self):
        raise NotImplementedError

    def set_mode(self, mode):
        raise NotImplementedError

    def add_context_rule(self, path, context, *, priority=100):
        raise NotImplementedError

    def resolve_context(self, path):
        raise NotImplementedError

    def relabel(self, path, context):
        raise NotImplementedError

    def label_of(self, path):
        raise NotImplementedError

    def snapshot(self):
        raise NotImplementedError

    def restore(self, snapshot):
        raise NotImplementedError

    def audit(self, limit=None):
        raise NotImplementedError
