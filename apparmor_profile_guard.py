"""AppArmor profile switching guard.

Bugfix target: the module is a skeleton. The profile registry, revision
history, executable attachment index, pid confinement accounting and the
snapshot/restore path all need to be implemented behind the signatures below.
"""

import threading

MODES = ("enforce", "complain")


class AppArmorError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class AppArmorGuard:
    """Owns the profile table, generation history and pid confinement state."""

    def __init__(self, max_profiles=64, max_attachments=128, max_audit=256,
                 max_hat_depth=3):
        self.max_profiles = max_profiles
        self.max_attachments = max_attachments
        self.max_audit = max_audit
        self.max_hat_depth = max_hat_depth
        self._lock = threading.RLock()

    def register_profile(self, name, *, mode="enforce", attachments=(),
                         body="", flags=None):
        raise NotImplementedError

    def load_profile(self, name, body, *, generation=None):
        raise NotImplementedError

    def replace_profile(self, name, body, *, expect_generation=None,
                        mode=None):
        raise NotImplementedError

    def switch_mode(self, name, mode):
        raise NotImplementedError

    def rollback(self, name, generation):
        raise NotImplementedError

    def attach(self, name, executable):
        raise NotImplementedError

    def detach(self, name, executable):
        raise NotImplementedError

    def confine(self, pid, profile_name):
        raise NotImplementedError

    def release(self, pid):
        raise NotImplementedError

    def enter_hat(self, pid, hat):
        raise NotImplementedError

    def exit_hat(self, pid):
        raise NotImplementedError

    def state(self, name):
        raise NotImplementedError

    def snapshot(self):
        raise NotImplementedError

    def restore(self, snapshot):
        raise NotImplementedError

    def audit(self, limit=None):
        raise NotImplementedError
