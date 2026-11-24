"""CI OIDC trust policy guard skeleton.

The public surface below is fixed; the behaviour each method must provide is
described in README.md.
"""


class CiOidcError(ValueError):
    """Raised for malformed tokens and denied trust decisions."""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class CiOidcGuard:
    """Issuer trust, policy matching and one-shot token exchange."""

    def __init__(self, *, issuer, now=0):
        self.issuer = issuer
        self.now = now

    def register_policy(self, name, *, audiences, subjects=(), claims=None,
                        max_session=3600, deny=False, enabled=True) -> dict:
        raise NotImplementedError

    def set_policy_enabled(self, name, enabled) -> dict:
        raise NotImplementedError

    def rotate_issuer(self, issuer) -> dict:
        raise NotImplementedError

    def evaluate(self, token, *, now=None) -> dict:
        raise NotImplementedError

    def assume(self, token, *, now=None) -> dict:
        raise NotImplementedError

    def explain(self, token, *, now=None) -> dict:
        raise NotImplementedError

    def purge_used_jti(self, *, now=None) -> int:
        raise NotImplementedError

    def policies(self) -> list:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def audit_log(self) -> list:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    @classmethod
    def restore(cls, state) -> "CiOidcGuard":
        raise NotImplementedError
