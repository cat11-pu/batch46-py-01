"""Team roster and composition guard (batch46-game-b-01, Bugfix skeleton)."""


class TeamError(ValueError):
    """Raised when a roster operation violates a hard team rule."""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = dict(detail or {})


class TeamBuilder:
    """Roster storage, composition rules, validation, snapshots and tickets."""

    def __init__(self, *, capacity=5, power_cap=10000, audit_limit=50):
        self.capacity = capacity
        self.power_cap = power_cap
        self.audit_limit = audit_limit
        self._teams = {}
        self._rules = {}

    def define_rule(self, rule_id, *, kind, limit=1, value=None, severity="block"):
        raise NotImplementedError

    def list_rules(self):
        raise NotImplementedError

    def create_team(self, team_id, owner, *, server="s1", capacity=None):
        raise NotImplementedError

    def join(self, team_id, member, *, role, power=0, server="s1", relic=None,
             event_id=None):
        raise NotImplementedError

    def leave(self, team_id, member, *, event_id=None):
        raise NotImplementedError

    def change_role(self, team_id, member, role):
        raise NotImplementedError

    def validate(self, team_id):
        raise NotImplementedError

    def members(self, team_id):
        raise NotImplementedError

    def stats(self, team_id):
        raise NotImplementedError

    def snapshot(self, team_id):
        raise NotImplementedError

    def restore(self, team_id, snapshot):
        raise NotImplementedError

    def matchmaking_ticket(self, team_id):
        raise NotImplementedError

    def audit(self, team_id, limit=None):
        raise NotImplementedError
