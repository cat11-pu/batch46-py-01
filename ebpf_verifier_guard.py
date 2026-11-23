"""eBPF verifier and map quota guard (skeleton).

Implement the verifier and quota engine described in README.md.  Every
public method below is imported by the tests and must keep its signature.
"""

PROGRAM_TYPES = ("xdp", "kprobe", "tracepoint")

HELPER_TABLE = {
    "xdp": ("map_lookup", "map_update", "xdp_pass"),
    "kprobe": ("map_lookup", "map_update", "probe_read"),
    "tracepoint": ("map_lookup", "map_update", "trace_printk"),
}

MAP_HELPERS = ("map_lookup", "map_update")


class EbpfError(ValueError):
    """Raised for every rejected eBPF operation."""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class EbpfGuard:
    def __init__(self, *, max_instructions=64, max_programs=4, max_maps=4,
                 max_map_bytes=4096, audit_capacity=8):
        pass

    def verify(self, spec, *, tenant="default"):
        raise NotImplementedError

    def load_program(self, spec, *, tenant="default"):
        raise NotImplementedError

    def program_info(self, program_id, *, tenant="default"):
        raise NotImplementedError

    def programs(self, tenant="default"):
        raise NotImplementedError

    def maps(self, tenant="default"):
        raise NotImplementedError

    def map_update(self, name, key, value, *, tenant="default"):
        raise NotImplementedError

    def map_lookup(self, name, key, *, tenant="default"):
        raise NotImplementedError

    def attach(self, program_id, hook, *, tenant="default"):
        raise NotImplementedError

    def detach(self, program_id, hook, *, tenant="default"):
        raise NotImplementedError

    def close_program(self, program_id, *, tenant="default"):
        raise NotImplementedError

    def set_quota(self, tenant, *, max_programs=None, max_maps=None,
                  max_map_bytes=None):
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
