"""JWKS rotation and cache guard skeleton.

The public surface below is fixed; the behaviour each method must provide is
described in README.md.
"""


class JwksError(ValueError):
    """Raised for cache, key and signature failures, carrying a stable code."""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class JwksGuard:
    """Issuer registry, key cache, rotation overlap and token verification."""

    def __init__(self, *, ttl=300, refresh_cooldown=30, max_stale=900,
                 max_keys=8, now=0):
        self.ttl = ttl
        self.refresh_cooldown = refresh_cooldown
        self.max_stale = max_stale
        self.max_keys = max_keys
        self.now = now

    def add_issuer(self, issuer) -> dict:
        raise NotImplementedError

    def publish_key(self, issuer, kid, *, material, alg="RS256",
                    not_before=None, expires_at=None, now=None) -> dict:
        raise NotImplementedError

    def retire_key(self, issuer, kid, *, now=None) -> dict:
        raise NotImplementedError

    def rotate(self, issuer, *, kid, material, overlap=60, alg="RS256",
               now=None) -> dict:
        raise NotImplementedError

    def set_endpoint_healthy(self, issuer, healthy) -> dict:
        raise NotImplementedError

    def keys(self, issuer, *, now=None) -> dict:
        raise NotImplementedError

    def verify(self, token, *, issuer, now=None) -> dict:
        raise NotImplementedError

    def refresh(self, issuer, *, now=None, force=False) -> dict:
        raise NotImplementedError

    def cache_info(self) -> dict:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def audit_log(self) -> list:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    @classmethod
    def restore(cls, state) -> "JwksGuard":
        raise NotImplementedError
