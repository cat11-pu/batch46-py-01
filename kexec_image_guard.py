"""kexec image signature verification guard (skeleton).

Implement the trust-store and staging engine described in README.md.
Every public function and method below is imported by the tests and must
keep its signature.
"""

KEY_KINDS = ("rsa", "ecdsa")


def expected_signature(key_id, image_name, digest):
    """Return the deterministic signature value for an image."""
    raise NotImplementedError


class KexecError(ValueError):
    """Raised for every rejected kexec operation."""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class KexecGuard:
    def __init__(self, *, slot_count=2, max_total_bytes=1024,
                 max_image_bytes=512, allow_unsigned=False,
                 audit_capacity=8):
        pass

    def add_key(self, key_id, *, kind="rsa"):
        raise NotImplementedError

    def revoke_key(self, key_id):
        raise NotImplementedError

    def key_info(self, key_id):
        raise NotImplementedError

    def load_image(self, slot, image, *, tenant="default"):
        raise NotImplementedError

    def staged(self, slot, *, tenant="default"):
        raise NotImplementedError

    def unload(self, slot, *, tenant="default"):
        raise NotImplementedError

    def boot(self, slot, *, tenant="default"):
        raise NotImplementedError

    def blacklist(self, digest):
        raise NotImplementedError

    def usage(self):
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
