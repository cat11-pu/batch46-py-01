"""KVM vCPU MSR access filtering guard (skeleton).

Implement the policy engine described in README.md.  Every public method
below is imported by the tests and must keep its signature.
"""

MSR_ALLOW = "allow"
MSR_DENY = "deny"
MSR_MASK = "mask"

MSR_ACTIONS = (MSR_ALLOW, MSR_DENY, MSR_MASK)


class MsrGuardError(ValueError):
    """Raised for every rejected MSR operation."""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class KvmMsrGuard:
    def __init__(self, *, max_vcpus=16, max_rules=32, cache_capacity=8,
                 audit_capacity=8):
        pass

    def define_policy(self, vm_id, rules, *, default=MSR_DENY):
        raise NotImplementedError

    def policy_of(self, vm_id):
        raise NotImplementedError

    def create_vcpu(self, vm_id, vcpu_id):
        raise NotImplementedError

    def remove_vcpu(self, vm_id, vcpu_id):
        raise NotImplementedError

    def check(self, vm_id, vcpu_id, index, value=0, *, write=True):
        raise NotImplementedError

    def set_msr(self, vm_id, vcpu_id, index, value):
        raise NotImplementedError

    def read_msr(self, vm_id, vcpu_id, index):
        raise NotImplementedError

    def apply_batch(self, vm_id, vcpu_id, accesses, *, batch_id=None):
        raise NotImplementedError

    def close_vm(self, vm_id):
        raise NotImplementedError

    def cache_size(self, vm_id):
        raise NotImplementedError

    def stats(self, vm_id=None):
        raise NotImplementedError

    def audit(self, limit=None):
        raise NotImplementedError

    def snapshot(self):
        raise NotImplementedError

    @classmethod
    def restore(cls, data):
        raise NotImplementedError
