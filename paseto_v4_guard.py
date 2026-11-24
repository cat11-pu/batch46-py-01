"""PASETO v4.local guard skeleton.

The public surface below is fixed; the behaviour each method must provide is
described in README.md.
"""


class PasetoError(ValueError):
    """Raised for malformed, forged or policy-rejected tokens."""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class PasetoGuard:
    """Local token issuing, verification, key rotation and replay control."""

    def __init__(self, *, key, key_id="k1", now=0, max_token_bytes=1024):
        self.key = key
        self.key_id = key_id
        self.now = now
        self.max_token_bytes = max_token_bytes

    def issue(self, claims, *, footer=None, implicit=None, ttl=600,
              now=None) -> str:
        raise NotImplementedError

    def verify(self, token, *, implicit=None, audience=None, max_age=None,
               single_use=False, require_footer=None, now=None) -> dict:
        raise NotImplementedError

    def peek(self, token) -> dict:
        raise NotImplementedError

    def revoke(self, jti, *, expires_at=None, now=None) -> dict:
        raise NotImplementedError

    def rotate_key(self, *, key_id, key=None, grace=300, now=None) -> dict:
        raise NotImplementedError

    def retire_key(self, key_id, *, now=None) -> dict:
        raise NotImplementedError

    def keyring(self) -> list:
        raise NotImplementedError

    def sweep_revocations(self, *, now=None) -> int:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def audit_log(self) -> list:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    @classmethod
    def restore(cls, state) -> "PasetoGuard":
        raise NotImplementedError
