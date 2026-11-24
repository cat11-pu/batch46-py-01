"""In-memory AppRole guard with shared, lock-protected state.

All four paths (issue, login, revoke, sweep) operate on the same role,
SecretID and accounting registries, and every read/write of that shared
state is serialized through a single re-entrant lock.
"""

import copy
import ipaddress
import secrets as _secrets
import threading


class AppRoleError(ValueError):
    """Raised for every rejected AppRole operation, carrying a stable code."""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class AppRoleGuard:
    """Role registry, SecretID lifecycle and login accounting."""

    def __init__(self, *, now=0):
        self.now = now
        self._lock = threading.RLock()
        # role name -> role configuration dict
        self._roles = {}
        # current role_id -> role name (rotated ids are removed)
        self._role_ids = {}
        # secret_id -> secret record
        self._secrets = {}
        # accessor -> secret_id
        self._accessors = {}
        # role name -> timestamps of successful logins (rolling window)
        self._login_times = {}
        # every token ever issued, to guarantee uniqueness
        self._tokens = set()
        self._audit = []
        self._tokens_issued = 0
        self._logins_failed = 0

    def _now(self, now):
        return self.now if now is None else now

    def _unique_id(self, prefix, registry):
        while True:
            candidate = prefix + _secrets.token_hex(16)
            if candidate not in registry:
                return candidate

    def _audit_event(self, event, now, **fields):
        entry = {"event": event, "time": now}
        entry.update(fields)
        self._audit.append(entry)

    def _deny(self, now, code, role_id, role=None, accessor=None, cidr=None):
        self._logins_failed += 1
        self._audit_event(
            "login", now, role=role, role_id=role_id, accessor=accessor,
            cidr=cidr, result="denied", error=code,
        )
        raise AppRoleError(code)

    @staticmethod
    def _cidr_allows(record, bind_cidrs, raw_cidr):
        try:
            address = ipaddress.ip_address(raw_cidr)
        except (ValueError, TypeError):
            return False
        networks = (record["cidr"],) if record["cidr"] else bind_cidrs
        if not networks:
            return True
        for network_text in networks:
            try:
                network = ipaddress.ip_network(network_text, strict=False)
            except (ValueError, TypeError):
                continue
            if address in network:
                return True
        return False

    @staticmethod
    def _metadata_satisfied(required, metadata):
        if not required:
            return True
        provided = metadata or {}
        return all(provided.get(key) == value for key, value in required.items())

    def create_role(self, role, *, policies, secret_id_ttl=3600,
                    secret_id_num_uses=0, bind_cidrs=(),
                    require_metadata=None, max_logins_per_minute=0) -> dict:
        with self._lock:
            if role in self._roles:
                raise AppRoleError("APPROLE_ROLE_EXISTS")
            role_id = self._unique_id("r.", self._role_ids)
            self._roles[role] = {
                "role": role,
                "role_id": role_id,
                "policies": list(policies),
                "secret_id_ttl": secret_id_ttl,
                "secret_id_num_uses": secret_id_num_uses,
                "bind_cidrs": list(bind_cidrs),
                "require_metadata": dict(require_metadata or {}),
                "max_logins_per_minute": max_logins_per_minute,
            }
            self._role_ids[role_id] = role
            self._login_times[role] = []
            return {"role": role, "role_id": role_id}

    def generate_secret_id(self, role, *, cidr=None, metadata=None,
                           ttl=None, num_uses=None, now=None) -> dict:
        with self._lock:
            config = self._roles.get(role)
            if config is None:
                raise AppRoleError("APPROLE_UNKNOWN_ROLE")
            moment = self._now(now)
            effective_ttl = config["secret_id_ttl"] if ttl is None else ttl
            effective_uses = (
                config["secret_id_num_uses"] if num_uses is None else num_uses
            )
            secret_id = self._unique_id("s.", self._secrets)
            accessor = self._unique_id("a.", self._accessors)
            record = {
                "secret_id": secret_id,
                "accessor": accessor,
                "role": role,
                "cidr": cidr,
                "metadata": dict(metadata or {}),
                "ttl": effective_ttl,
                "num_uses": effective_uses,
                "uses": 0,
                "expires_at": moment + effective_ttl,
                "revoked": False,
                "created_at": moment,
            }
            self._secrets[secret_id] = record
            self._accessors[accessor] = secret_id
            return {
                "secret_id": secret_id,
                "accessor": accessor,
                "expires_at": record["expires_at"],
            }

    def login(self, role_id, secret_id, *, cidr, metadata=None,
              now=None) -> dict:
        with self._lock:
            moment = self._now(now)
            role = self._role_ids.get(role_id)
            if role is None:
                self._deny(moment, "APPROLE_ROLE_ID_MISMATCH", role_id,
                           cidr=cidr)
            config = self._roles[role]
            record = self._secrets.get(secret_id)
            if record is None or record["role"] != role:
                self._deny(moment, "APPROLE_SECRET_UNKNOWN", role_id,
                           role=role, cidr=cidr)
            accessor = record["accessor"]
            if record["revoked"]:
                self._deny(moment, "APPROLE_SECRET_REVOKED", role_id,
                           role=role, accessor=accessor, cidr=cidr)
            if moment >= record["expires_at"]:
                self._deny(moment, "APPROLE_SECRET_EXPIRED", role_id,
                           role=role, accessor=accessor, cidr=cidr)
            if not self._cidr_allows(record, config["bind_cidrs"], cidr):
                self._deny(moment, "APPROLE_CIDR_DENIED", role_id,
                           role=role, accessor=accessor, cidr=cidr)
            if not self._metadata_satisfied(config["require_metadata"],
                                            metadata):
                self._deny(moment, "APPROLE_METADATA_MISMATCH", role_id,
                           role=role, accessor=accessor, cidr=cidr)

            window = self._prune_window(role, moment)
            limit = config["max_logins_per_minute"]
            if limit and len(window) >= limit:
                self._deny(moment, "APPROLE_LIMIT_EXCEEDED", role_id,
                           role=role, accessor=accessor, cidr=cidr)
            if record["num_uses"] and record["uses"] >= record["num_uses"]:
                self._deny(moment, "APPROLE_SECRET_CONSUMED", role_id,
                           role=role, accessor=accessor, cidr=cidr)

            record["uses"] += 1
            window.append(moment)
            self._tokens_issued += 1
            token = self._unique_id("hvs.", self._tokens)
            self._tokens.add(token)
            self._audit_event(
                "login", moment, role=role, role_id=role_id,
                accessor=accessor, cidr=cidr, result="ok", error=None,
            )
            return {
                "token": token,
                "role": role,
                "policies": sorted(config["policies"]),
                "accessor": accessor,
            }

    def _prune_window(self, role, moment):
        window = self._login_times.setdefault(role, [])
        cutoff = moment - 60
        alive = [timestamp for timestamp in window if timestamp > cutoff]
        self._login_times[role] = alive
        return alive

    def revoke_secret_id(self, accessor, *, now=None) -> dict:
        with self._lock:
            moment = self._now(now)
            secret_id = self._accessors.get(accessor)
            if secret_id is None:
                raise AppRoleError("APPROLE_SECRET_UNKNOWN")
            record = self._secrets[secret_id]
            record["revoked"] = True
            self._audit_event(
                "revoke", moment, role=record["role"], accessor=accessor,
                result="ok", error=None,
            )
            return {"revoked": True}

    def rotate_role_id(self, role, *, now=None) -> dict:
        with self._lock:
            config = self._roles.get(role)
            if config is None:
                raise AppRoleError("APPROLE_UNKNOWN_ROLE")
            moment = self._now(now)
            old_role_id = config["role_id"]
            self._role_ids.pop(old_role_id, None)
            new_role_id = self._unique_id("r.", self._role_ids)
            config["role_id"] = new_role_id
            self._role_ids[new_role_id] = role
            self._audit_event(
                "rotate_role_id", moment, role=role,
                role_id=new_role_id, result="ok", error=None,
            )
            return {"role": role, "role_id": new_role_id}

    def role_info(self, role) -> dict:
        with self._lock:
            config = self._roles.get(role)
            if config is None:
                raise AppRoleError("APPROLE_UNKNOWN_ROLE")
            active = revoked = 0
            for record in self._secrets.values():
                if record["role"] != role:
                    continue
                if record["revoked"]:
                    revoked += 1
                else:
                    active += 1
            return {
                "role": role,
                "role_id": config["role_id"],
                "policies": list(config["policies"]),
                "secret_id_ttl": config["secret_id_ttl"],
                "secret_id_num_uses": config["secret_id_num_uses"],
                "bind_cidrs": list(config["bind_cidrs"]),
                "require_metadata": dict(config["require_metadata"]),
                "max_logins_per_minute": config["max_logins_per_minute"],
                "active_secret_ids": active,
                "revoked_secret_ids": revoked,
            }

    def sweep_expired(self, *, now=None) -> int:
        with self._lock:
            moment = self._now(now)
            expired = [
                secret_id
                for secret_id, record in self._secrets.items()
                if record["expires_at"] <= moment
            ]
            for secret_id in expired:
                record = self._secrets.pop(secret_id)
                self._accessors.pop(record["accessor"], None)
                self._audit_event(
                    "sweep", moment, role=record["role"],
                    accessor=record["accessor"], result="ok", error=None,
                )
            return len(expired)

    def stats(self) -> dict:
        with self._lock:
            active = sum(
                1 for record in self._secrets.values()
                if not record["revoked"]
            )
            revoked = sum(
                1 for record in self._secrets.values() if record["revoked"]
            )
            return {
                "tokens_issued": self._tokens_issued,
                "logins_failed": self._logins_failed,
                "roles": len(self._roles),
                "active_secret_ids": active,
                "revoked_secret_ids": revoked,
            }

    def audit_log(self) -> list:
        with self._lock:
            return copy.deepcopy(self._audit)

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": 1,
                "now": self.now,
                "roles": copy.deepcopy(self._roles),
                "role_ids": dict(self._role_ids),
                "secrets": copy.deepcopy(self._secrets),
                "accessors": dict(self._accessors),
                "login_times": {
                    role: list(times)
                    for role, times in self._login_times.items()
                },
                "tokens": list(self._tokens),
                "audit": copy.deepcopy(self._audit),
                "tokens_issued": self._tokens_issued,
                "logins_failed": self._logins_failed,
            }

    @classmethod
    def restore(cls, state, *, now=0) -> "AppRoleGuard":
        guard = cls(now=now)
        guard._roles = copy.deepcopy(state.get("roles", {}))
        guard._role_ids = dict(state.get("role_ids", {}))
        guard._secrets = copy.deepcopy(state.get("secrets", {}))
        guard._accessors = dict(state.get("accessors", {}))
        guard._login_times = {
            role: list(times)
            for role, times in state.get("login_times", {}).items()
        }
        guard._tokens = set(state.get("tokens", ()))
        guard._audit = copy.deepcopy(state.get("audit", []))
        guard._tokens_issued = state.get("tokens_issued", 0)
        guard._logins_failed = state.get("logins_failed", 0)
        return guard
