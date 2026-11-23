"""Tournament bracket guard (batch46-game-b-02, Bugfix skeleton)."""


class BracketError(ValueError):
    """Raised when a bracket operation cannot be completed."""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = dict(detail or {})


class BracketGuard:
    """Registration, seeding, pairing, results, standings and snapshots."""

    def __init__(self, *, size=8, max_rounds=3, audit_limit=200):
        self.size = size
        self.max_rounds = max_rounds
        self.audit_limit = audit_limit
        self._players = {}
        self._rounds = {}
        self._results = {}

    def register(self, player, *, rating=1000, region="cn", event_id=None):
        raise NotImplementedError

    def withdraw(self, player):
        raise NotImplementedError

    def seed_order(self):
        raise NotImplementedError

    def build_round(self, round_no):
        raise NotImplementedError

    def record_result(self, match_id, winner, *, score="2-0", event_id=None):
        raise NotImplementedError

    def current_round(self):
        raise NotImplementedError

    def matches(self, round_no=None):
        raise NotImplementedError

    def byes(self, round_no):
        raise NotImplementedError

    def standings(self):
        raise NotImplementedError

    def champion(self):
        raise NotImplementedError

    def audit(self, limit=None):
        raise NotImplementedError

    def snapshot(self):
        raise NotImplementedError

    def restore(self, snapshot):
        raise NotImplementedError
