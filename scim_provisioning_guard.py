"""SCIM user provisioning guard (implementation skeleton)."""

from __future__ import annotations

import copy
import threading


class ScimError(ValueError):
    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


_PATCH_OPS = frozenset({"add", "replace", "remove"})
_PATCH_PATHS = frozenset({"userName", "displayName", "active", "externalId"})
_REQUIRED_PATHS = frozenset({"userName", "active"})
_RECORD_FIELDS = ("id", "userName", "displayName", "active", "version",
                  "deleted", "externalId")
_SNAPSHOT_VERSION = 1


class ScimGuard:
    """Apply SCIM upserts, patches, deactivations and batches per tenant."""

    def __init__(self, *, max_users_per_tenant: int = 1000,
                 max_batch: int = 200) -> None:
        self.max_users_per_tenant = max_users_per_tenant
        self.max_batch = max_batch
        self._lock = threading.RLock()
        # tenant -> {"source", "allowed_domains", "users": {id: record},
        #            "events": set(event_id)}
        self._tenants: dict = {}

    # ------------------------------------------------------------------
    # internal helpers
    # ------------------------------------------------------------------
    def _tenant_entry(self, tenant: str) -> dict:
        try:
            return self._tenants[tenant]
        except KeyError:
            raise ScimError("SCIM_UNKNOWN_TENANT",
                            {"tenant": tenant}) from None

    @staticmethod
    def _validate_resource(resource: object) -> None:
        if not isinstance(resource, dict):
            raise ScimError("SCIM_INVALID_RESOURCE",
                            {"reason": "resource must be an object"})
        user_id = resource.get("id")
        if not isinstance(user_id, str) or not user_id:
            raise ScimError("SCIM_INVALID_RESOURCE",
                            {"reason": "id must be a non-empty string"})
        user_name = resource.get("userName")
        if not isinstance(user_name, str) or not user_name:
            raise ScimError("SCIM_INVALID_RESOURCE",
                            {"reason": "userName must be a non-empty string"})
        version = resource.get("version")
        if (not isinstance(version, int) or isinstance(version, bool)
                or version < 1):
            raise ScimError("SCIM_INVALID_RESOURCE",
                            {"reason": "version must be an integer >= 1"})
        if "active" in resource and not isinstance(resource["active"], bool):
            raise ScimError("SCIM_INVALID_RESOURCE",
                            {"reason": "active must be a boolean"})

    @staticmethod
    def _validate_operations(operations: object) -> list:
        if not isinstance(operations, (list, tuple)) or not operations:
            raise ScimError("SCIM_INVALID_OPERATION",
                            {"reason": "operations must be a non-empty list"})
        parsed = []
        for operation in operations:
            if not isinstance(operation, dict):
                raise ScimError("SCIM_INVALID_OPERATION",
                                {"reason": "operation must be an object"})
            op = operation.get("op")
            if op not in _PATCH_OPS:
                raise ScimError("SCIM_UNSUPPORTED_OPERATION",
                                {"op": op})
            path = operation.get("path")
            if path not in _PATCH_PATHS:
                raise ScimError("SCIM_UNSUPPORTED_PATH",
                                {"path": path})
            if op == "remove" and path in _REQUIRED_PATHS:
                raise ScimError("SCIM_REQUIRED_ATTRIBUTE",
                                {"path": path})
            parsed.append((op, path, operation.get("value")))
        return parsed

    def _apply_resource(self, entry: dict, resource: dict) -> dict:
        """Version/dedupe guarded write. Caller holds the lock and has
        already validated the resource shape and tenant capacity."""
        users = entry["users"]
        user_id = resource["id"]
        version = resource["version"]
        event_id = resource.get("event_id")
        if event_id is not None and event_id in entry["events"]:
            return {"status": "duplicate", "code": "SCIM_DUPLICATE_EVENT",
                    "id": user_id, "version": version}
        stored = users.get(user_id)
        if stored is not None and version <= stored["version"]:
            return {"status": "stale", "code": "SCIM_VERSION_STALE",
                    "id": user_id, "version": stored["version"]}
        record = {
            "id": user_id,
            "userName": resource["userName"],
            "displayName": resource.get("displayName"),
            "active": resource.get("active", True),
            "version": version,
            "deleted": False,
            "externalId": resource.get("externalId"),
        }
        users[user_id] = record
        if event_id is not None:
            entry["events"].add(event_id)
        return {"status": "applied", "id": user_id, "version": version,
                "active": record["active"]}

    # ------------------------------------------------------------------
    # tenant registry
    # ------------------------------------------------------------------
    def register_tenant(self, tenant: str, *, source: str,
                        allowed_domains=()) -> dict:
        with self._lock:
            domains = tuple(allowed_domains)
            existing = self._tenants.get(tenant)
            if existing is not None:
                if (existing["source"] != source
                        or existing["allowed_domains"] != domains):
                    raise ScimError("SCIM_CONFLICT", {"tenant": tenant})
                return {"tenant": tenant, "source": existing["source"],
                        "allowed_domains": list(existing["allowed_domains"])}
            self._tenants[tenant] = {
                "source": source,
                "allowed_domains": domains,
                "users": {},
                "events": set(),
            }
            return {"tenant": tenant, "source": source,
                    "allowed_domains": list(domains)}

    # ------------------------------------------------------------------
    # single-resource writes
    # ------------------------------------------------------------------
    def upsert(self, tenant: str, resource: dict) -> dict:
        with self._lock:
            entry = self._tenant_entry(tenant)
            self._validate_resource(resource)
            users = entry["users"]
            if (resource["id"] not in users
                    and len(users) >= self.max_users_per_tenant):
                raise ScimError("SCIM_TENANT_CAPACITY",
                                {"tenant": tenant,
                                 "max_users_per_tenant":
                                     self.max_users_per_tenant})
            return self._apply_resource(entry, resource)

    def patch(self, tenant: str, user_id: str, operations,
              *, expected_version=None) -> dict:
        with self._lock:
            entry = self._tenant_entry(tenant)
            stored = entry["users"].get(user_id)
            if stored is None:
                raise ScimError("SCIM_NOT_FOUND", {"id": user_id})
            if stored["deleted"]:
                raise ScimError("SCIM_DELETED", {"id": user_id})
            if (expected_version is not None
                    and expected_version != stored["version"]):
                raise ScimError("SCIM_VERSION_CONFLICT",
                                {"id": user_id,
                                 "expected": expected_version,
                                 "current": stored["version"]})
            parsed = self._validate_operations(operations)
            record = dict(stored)
            for op, path, value in parsed:
                if op == "remove":
                    record[path] = None
                else:
                    record[path] = value
            record["version"] = stored["version"] + 1
            entry["users"][user_id] = record
            return {"status": "patched", "id": user_id,
                    "version": record["version"], "active": record["active"]}

    def deactivate(self, tenant: str, user_id: str,
                   *, expected_version=None) -> dict:
        with self._lock:
            entry = self._tenant_entry(tenant)
            stored = entry["users"].get(user_id)
            if stored is None:
                raise ScimError("SCIM_NOT_FOUND", {"id": user_id})
            if stored["deleted"]:
                raise ScimError("SCIM_ALREADY_DELETED", {"id": user_id})
            if (expected_version is not None
                    and expected_version != stored["version"]):
                raise ScimError("SCIM_VERSION_CONFLICT",
                                {"id": user_id,
                                 "expected": expected_version,
                                 "current": stored["version"]})
            record = dict(stored)
            record["active"] = False
            record["deleted"] = True
            record["version"] = stored["version"] + 1
            entry["users"][user_id] = record
            return {"status": "deactivated", "id": user_id,
                    "version": record["version"], "deleted": True}

    # ------------------------------------------------------------------
    # reads
    # ------------------------------------------------------------------
    def get(self, tenant: str, user_id: str) -> dict:
        with self._lock:
            entry = self._tenant_entry(tenant)
            stored = entry["users"].get(user_id)
            if stored is None:
                raise ScimError("SCIM_NOT_FOUND", {"id": user_id})
            return dict(stored)

    def list_users(self, tenant: str, *, include_deleted: bool = False) -> list:
        with self._lock:
            entry = self._tenant_entry(tenant)
            return [dict(record) for record in entry["users"].values()
                    if include_deleted or not record["deleted"]]

    def is_applied(self, tenant: str, event_id: str) -> bool:
        with self._lock:
            entry = self._tenant_entry(tenant)
            return event_id in entry["events"]

    # ------------------------------------------------------------------
    # batch
    # ------------------------------------------------------------------
    def apply_batch(self, tenant: str, events) -> dict:
        with self._lock:
            entry = self._tenant_entry(tenant)
            if not isinstance(events, (list, tuple)):
                raise ScimError("SCIM_INVALID_RESOURCE",
                                {"reason": "events must be a list"})
            if len(events) > self.max_batch:
                raise ScimError("SCIM_BATCH_TOO_LARGE",
                                {"max_batch": self.max_batch,
                                 "size": len(events)})
            # Atomic pre-validation: nothing is written before every
            # event passes tenant ownership and shape checks.
            for event in events:
                if not isinstance(event, dict):
                    raise ScimError("SCIM_INVALID_RESOURCE",
                                    {"reason": "event must be an object"})
                event_tenant = event.get("tenant")
                if event_tenant is not None and event_tenant != tenant:
                    raise ScimError("SCIM_TENANT_MISMATCH",
                                    {"tenant": event_tenant,
                                     "expected": tenant})
                self._validate_resource(event)
            new_ids = {event["id"] for event in events
                       if event["id"] not in entry["users"]}
            if len(entry["users"]) + len(new_ids) > self.max_users_per_tenant:
                raise ScimError("SCIM_TENANT_CAPACITY",
                                {"tenant": tenant,
                                 "max_users_per_tenant":
                                     self.max_users_per_tenant})
            counts = {"applied": 0, "stale": 0, "duplicate": 0, "noop": 0}
            results = []
            for event in sorted(events, key=lambda item: item["version"]):
                outcome = self._apply_resource(entry, event)
                counts[outcome["status"]] += 1
                results.append(outcome)
            return {"applied": counts["applied"], "stale": counts["stale"],
                    "duplicate": counts["duplicate"], "noop": counts["noop"],
                    "results": results}

    # ------------------------------------------------------------------
    # tenant purge
    # ------------------------------------------------------------------
    def purge_tenant(self, tenant: str) -> int:
        with self._lock:
            entry = self._tenant_entry(tenant)
            count = len(entry["users"])
            del self._tenants[tenant]
            return count

    # ------------------------------------------------------------------
    # snapshot / restore
    # ------------------------------------------------------------------
    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": _SNAPSHOT_VERSION,
                "tenants": {
                    name: {
                        "source": entry["source"],
                        "allowed_domains": list(entry["allowed_domains"]),
                        "users": {user_id: dict(record) for user_id, record
                                  in entry["users"].items()},
                        "events": sorted(entry["events"]),
                    }
                    for name, entry in self._tenants.items()
                },
            }

    @staticmethod
    def _parse_snapshot(state: object) -> dict:
        def invalid(reason: str) -> ScimError:
            return ScimError("SCIM_SNAPSHOT_INVALID", {"reason": reason})

        if not isinstance(state, dict):
            raise invalid("snapshot must be an object")
        version = state.get("version")
        if not isinstance(version, int) or isinstance(version, bool) \
                or version != _SNAPSHOT_VERSION:
            raise invalid("unsupported snapshot version")
        tenants = state.get("tenants")
        if not isinstance(tenants, dict):
            raise invalid("tenants must be an object")
        parsed = {}
        for name, entry in tenants.items():
            if not isinstance(name, str) or not name:
                raise invalid("tenant name must be a non-empty string")
            if not isinstance(entry, dict):
                raise invalid("tenant entry must be an object")
            source = entry.get("source")
            if not isinstance(source, str):
                raise invalid("tenant source must be a string")
            domains = entry.get("allowed_domains")
            if not isinstance(domains, (list, tuple)) or not all(
                    isinstance(domain, str) for domain in domains):
                raise invalid("allowed_domains must be a list of strings")
            users = entry.get("users")
            if not isinstance(users, dict):
                raise invalid("users must be an object")
            events = entry.get("events")
            if not isinstance(events, (list, tuple)) or not all(
                    isinstance(event_id, str) for event_id in events):
                raise invalid("events must be a list of strings")
            parsed_users = {}
            for user_id, record in users.items():
                if not isinstance(record, dict) or any(
                        field not in record for field in _RECORD_FIELDS):
                    raise invalid("user record has invalid shape")
                if record["id"] != user_id:
                    raise invalid("user id mismatch")
                if not isinstance(record["userName"], str) \
                        or not record["userName"]:
                    raise invalid("userName must be a non-empty string")
                record_version = record["version"]
                if not isinstance(record_version, int) \
                        or isinstance(record_version, bool) \
                        or record_version < 1:
                    raise invalid("version must be an integer >= 1")
                if not isinstance(record["active"], bool) \
                        or not isinstance(record["deleted"], bool):
                    raise invalid("active/deleted must be booleans")
                for optional in ("displayName", "externalId"):
                    if record[optional] is not None and not isinstance(
                            record[optional], str):
                        raise invalid(f"{optional} must be a string or null")
                parsed_users[user_id] = {field: record[field]
                                         for field in _RECORD_FIELDS}
            parsed[name] = {
                "source": source,
                "allowed_domains": tuple(domains),
                "users": parsed_users,
                "events": set(events),
            }
        return parsed

    def restore(self, state: dict) -> None:
        # Fully validate and build the replacement state before touching
        # the live one, so a bad snapshot leaves the guard unchanged.
        parsed = self._parse_snapshot(state)
        with self._lock:
            self._tenants = copy.deepcopy(parsed)
