"""Account merge conflict guard (batch46-game-b-05, Bugfix skeleton)."""


class MergeError(ValueError):
    """Raised when an account merge request is rejected."""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = dict(detail or {})


class AccountMerge:
    """Field strategies, merge planning, conflict resolution and snapshots."""

    def __init__(self, *, field_limit=50, max_conflicts=100, history_limit=50):
        self.field_limit = field_limit
        self.max_conflicts = max_conflicts
        self.history_limit = history_limit
        self._fields = {}
        self._accounts = {}
        self._merges = {}
        self._log = []

    def register_field(self, field, *, strategy="max", cap=None):
        raise NotImplementedError

    def create_account(self, account, *, fields=None):
        raise NotImplementedError

    def plan(self, merge_id, primary, secondary):
        raise NotImplementedError

    def conflicts(self, merge_id):
        raise NotImplementedError

    def resolve(self, merge_id, field, *, value):
        raise NotImplementedError

    def apply(self, merge_id):
        raise NotImplementedError

    def cancel(self, merge_id):
        raise NotImplementedError

    def account(self, account):
        raise NotImplementedError

    def snapshot(self):
        raise NotImplementedError

    def restore(self, snapshot):
        raise NotImplementedError

    def history(self, account, limit=10):
        raise NotImplementedError

    def audit(self, limit=10):
        raise NotImplementedError

    def stats(self):
        raise NotImplementedError
