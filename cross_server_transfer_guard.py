"""Cross-server character transfer guard (batch46-game-b-04, Bugfix skeleton)."""


class TransferError(ValueError):
    """Raised when a transfer request violates a hard rule."""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = dict(detail or {})


class CrossServerTransfer:
    """Two-phase transfer ledger with quotas, TTL, snapshots and history."""

    def __init__(self, *, max_pending=20, quota_per_source=5, ttl_seconds=600,
                 payload_limit=65536, history_limit=50):
        self.max_pending = max_pending
        self.quota_per_source = quota_per_source
        self.ttl_seconds = ttl_seconds
        self.payload_limit = payload_limit
        self.history_limit = history_limit
        self._servers = {}
        self._transfers = {}
        self._home = {}
        self._log = []

    def register_server(self, server, *, capacity=1000, used=0):
        raise NotImplementedError

    def servers(self):
        raise NotImplementedError

    def begin(self, transfer_id, *, account, character, source, target, payload,
              created_at):
        raise NotImplementedError

    def commit(self, transfer_id):
        raise NotImplementedError

    def rollback(self, transfer_id, *, reason="manual"):
        raise NotImplementedError

    def status(self, transfer_id):
        raise NotImplementedError

    def pending(self, server=None):
        raise NotImplementedError

    def expire(self, now):
        raise NotImplementedError

    def snapshot(self):
        raise NotImplementedError

    def restore(self, snapshot):
        raise NotImplementedError

    def account_home(self, account):
        raise NotImplementedError

    def history(self, account, limit=10):
        raise NotImplementedError

    def audit(self, limit=10):
        raise NotImplementedError

    def quota(self, server):
        raise NotImplementedError

    def metrics(self):
        raise NotImplementedError
