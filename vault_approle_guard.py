"""AppRole SecretID guard skeleton.

The public surface below is fixed; the behaviour each method must provide is
described in README.md.
"""


class AppRoleError(ValueError):
    """Raised for every rejected AppRole operation, carrying a stable code."""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class AppRoleGuard:
    """Role registry, SecretID lifecycle and login accounting."""

    def __init__(self, *, now=0):
        self.now = now

    def create_role(self, role, *, policies, secret_id_ttl=3600,
                    secret_id_num_uses=0, bind_cidrs=(),
                    require_metadata=None, max_logins_per_minute=0) -> dict:
        raise NotImplementedError

    def generate_secret_id(self, role, *, cidr=None, metadata=None,
                           ttl=None, num_uses=None, now=None) -> dict:
        raise NotImplementedError

    def login(self, role_id, secret_id, *, cidr, metadata=None,
              now=None) -> dict:
        raise NotImplementedError

    def revoke_secret_id(self, accessor, *, now=None) -> dict:
        raise NotImplementedError

    def rotate_role_id(self, role, *, now=None) -> dict:
        raise NotImplementedError

    def role_info(self, role) -> dict:
        raise NotImplementedError

    def sweep_expired(self, *, now=None) -> int:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def audit_log(self) -> list:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    @classmethod
    def restore(cls, state, *, now=0) -> "AppRoleGuard":
        raise NotImplementedError
