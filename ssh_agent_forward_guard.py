"""SSH agent forwarding boundary guard."""

import copy
import threading
from datetime import datetime, timedelta, timezone

LOOPBACK_HOSTS = ('localhost', '127.0.0.1', '::1', '0.0.0.0')

class AgentError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail

class AgentForwardGuard:
    """Boundary guard for forwarded ssh-agent sockets on a bastion."""
    def __init__(self, *, audit_capacity=256):
        self.audit_capacity = int(audit_capacity)
        self._lock = threading.RLock()
        self._keys = {}
        self._sessions = {}
        self._bindings = {}
        self._used_signs = {}
        self._sign_results = {}
        self._nonces = set()
        self._audit = []
        self._seq = 0

    def register_key(self, key_id, *, fingerprint, owner_account, principals=(), max_signs=32, ttl_seconds=3600, now='2026-11-23T09:00:00+00:00'):
        raise NotImplementedError

    def revoke_key(self, key_id, *, reason='manual'):
        raise NotImplementedError

    def open_session(self, session_id, *, account, host, target_user, keys, ttl_seconds=600, purposes=('git', 'scp'), targets=(), now='2026-11-23T09:00:00+00:00'):
        raise NotImplementedError

    def close_session(self, session_id, *, reason='closed'):
        raise NotImplementedError

    def request_forward(self, session_id, *, remote_host, nonce, remote_port=22, now='2026-11-23T09:00:00+00:00'):
        raise NotImplementedError

    def approve_forward(self, session_id, request_id, *, approved_by, now='2026-11-23T09:00:00+00:00'):
        raise NotImplementedError

    def sign(self, session_id, key_id, *, digest, purpose='git', request_id=None, now='2026-11-23T09:00:00+00:00'):
        raise NotImplementedError

    def usage(self, session_id):
        raise NotImplementedError

    def stats(self):
        raise NotImplementedError

    def audit(self, limit=20):
        raise NotImplementedError

    def sweep(self, now='2026-11-23T10:00:00+00:00'):
        raise NotImplementedError

    def snapshot(self):
        raise NotImplementedError

    def restore(self, snap):
        raise NotImplementedError
