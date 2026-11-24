"""Certificate Transparency SCT policy guard skeleton.

The public surface below is fixed; the behaviour each method must provide is
described in README.md.
"""


class SctError(ValueError):
    """Raised for policy rejections and malformed SCT containers."""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class SctGuard:
    """Log registry, SCT issuance accounting and certificate policy checks."""

    def __init__(self, *, now=0, max_scts=16, max_list_bytes=4096):
        self.now = now
        self.max_scts = max_scts
        self.max_list_bytes = max_list_bytes

    def add_log(self, log_id, *, operator, key, not_after=None,
                status="usable", quota=0) -> dict:
        raise NotImplementedError

    def set_log_status(self, log_id, status) -> dict:
        raise NotImplementedError

    def submit(self, log_id, cert_fingerprint, *, now=None) -> dict:
        raise NotImplementedError

    def required_count(self, cert) -> int:
        raise NotImplementedError

    def verify(self, cert, scts, *, now=None) -> dict:
        raise NotImplementedError

    def require(self, cert, scts, *, now=None) -> dict:
        raise NotImplementedError

    def pack(self, scts) -> str:
        raise NotImplementedError

    def unpack(self, blob) -> list:
        raise NotImplementedError

    def sweep(self, *, now=None) -> int:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def audit_log(self) -> list:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    @classmethod
    def restore(cls, state) -> "SctGuard":
        raise NotImplementedError
