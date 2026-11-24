"""SCIM user provisioning guard (implementation skeleton)."""

from __future__ import annotations

import threading


class ScimError(ValueError):
    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class ScimGuard:
    """Apply SCIM upserts, patches, deactivations and batches per tenant."""

    def __init__(self, *, max_users_per_tenant: int = 1000,
                 max_batch: int = 200) -> None:
        self.max_users_per_tenant = max_users_per_tenant
        self.max_batch = max_batch
        self._lock = threading.RLock()

    def register_tenant(self, tenant: str, *, source: str,
                        allowed_domains=()) -> dict:
        raise NotImplementedError

    def upsert(self, tenant: str, resource: dict) -> dict:
        raise NotImplementedError

    def patch(self, tenant: str, user_id: str, operations,
              *, expected_version=None) -> dict:
        raise NotImplementedError

    def deactivate(self, tenant: str, user_id: str,
                   *, expected_version=None) -> dict:
        raise NotImplementedError

    def get(self, tenant: str, user_id: str) -> dict:
        raise NotImplementedError

    def list_users(self, tenant: str, *, include_deleted: bool = False) -> list:
        raise NotImplementedError

    def apply_batch(self, tenant: str, events) -> dict:
        raise NotImplementedError

    def is_applied(self, tenant: str, event_id: str) -> bool:
        raise NotImplementedError

    def purge_tenant(self, tenant: str) -> int:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError
