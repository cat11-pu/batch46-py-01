"""Core dump sensitive-field redaction guard (skeleton).

Implement the rule engine described in README.md.  Every public method
below is imported by the tests and must keep its signature.
"""

REDACT_MASK = "mask"
REDACT_HASH = "hash"
REDACT_DROP = "drop"
REDACT_ACTIONS = (REDACT_MASK, REDACT_HASH, REDACT_DROP)

RECORD_KINDS = ("env", "arg", "mem", "reg", "file")


class CoreDumpError(ValueError):
    """Raised for every rejected core dump operation."""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class CoreDumpGuard:
    def __init__(self, *, max_rules=16, max_records=8,
                 max_dumps_per_tenant=4, max_value_bytes=64,
                 audit_capacity=8):
        pass

    def register_rule(self, pattern, *, kind=None, action=REDACT_MASK,
                      replacement="***"):
        raise NotImplementedError

    def rules(self):
        raise NotImplementedError

    def process(self, dump_id, records, *, tenant="default"):
        raise NotImplementedError

    def get(self, dump_id, name, *, tenant="default"):
        raise NotImplementedError

    def list_names(self, dump_id, *, tenant="default"):
        raise NotImplementedError

    def purge(self, dump_id, *, tenant="default"):
        raise NotImplementedError

    def usage(self, tenant="default"):
        raise NotImplementedError

    def set_tenant_quota(self, tenant, limit):
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
