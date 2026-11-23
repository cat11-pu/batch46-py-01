"""ptrace scope boundary enforcement guard (skeleton).

Implement the process-tree policy described in README.md.  Every public
method below is imported by the tests and must keep its signature.
"""

SCOPE_CLASSIC = 0
SCOPE_ANCESTOR = 1
SCOPE_ADMIN_ONLY = 2
SCOPE_DENY_ALL = 3


class PtraceError(ValueError):
    """Raised for every rejected ptrace operation."""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class PtraceGuard:
    def __init__(self, *, scope=SCOPE_ANCESTOR, audit_capacity=16):
        pass

    def register_process(self, pid, *, uid=0, ppid=1, comm="proc",
                         privileged=False):
        raise NotImplementedError

    def process_info(self, pid):
        raise NotImplementedError

    def unregister_process(self, pid):
        raise NotImplementedError

    def reparent(self, pid, new_ppid):
        raise NotImplementedError

    def children(self, pid):
        raise NotImplementedError

    def ancestors(self, pid):
        raise NotImplementedError

    def set_scope(self, level):
        raise NotImplementedError

    def scope(self):
        raise NotImplementedError

    def check_attach(self, pid, tracer_pid):
        raise NotImplementedError

    def attach(self, pid, tracer_pid):
        raise NotImplementedError

    def detach(self, pid, tracer_pid):
        raise NotImplementedError

    def detach_all(self, tracer_pid):
        raise NotImplementedError

    def attachments(self):
        raise NotImplementedError

    def stats(self):
        raise NotImplementedError

    def audit(self, limit=None):
        raise NotImplementedError

    def snapshot(self):
        raise NotImplementedError

    @classmethod
    def restore(cls, data):
        raise NotImplementedError
