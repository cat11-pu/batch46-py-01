"""kexec image signature verification guard.

The guard owns a small trust store, a fixed number of staging slots and the
one-shot boot state for images that have already been booted.  All mutating
operations are serialised with a re-entrant lock so callers can safely share
one guard between threads.
"""

import hashlib
import hmac
import json
import threading
from collections import deque


KEY_KINDS = ("rsa", "ecdsa")

_DIGEST_CHARS = frozenset("0123456789abcdef")
_AUDIT_EVENTS = frozenset(
    ("load", "duplicate", "reject", "boot", "boot_denied", "unload")
)
_SUCCESS_EVENTS = frozenset(("load", "duplicate", "boot", "unload"))
_SNAPSHOT_VERSION = 1


def expected_signature(key_id, image_name, digest):
    """Return the deterministic signature value for an image."""
    payload = "%s:%s:%s" % (key_id, image_name, digest)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class KexecError(ValueError):
    """Raised for every rejected kexec operation."""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _valid_digest(value):
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in _DIGEST_CHARS for char in value)
    )


class KexecGuard:
    def __init__(self, *, slot_count=2, max_total_bytes=1024,
                 max_image_bytes=512, allow_unsigned=False,
                 audit_capacity=8):
        if not _is_int(slot_count) or slot_count < 0:
            raise KexecError("KEXEC_BAD_CONFIG",
                             "slot_count must be a non-negative integer")
        if not _is_int(max_total_bytes) or max_total_bytes < 0:
            raise KexecError("KEXEC_BAD_CONFIG",
                             "max_total_bytes must be a non-negative integer")
        if not _is_int(max_image_bytes) or max_image_bytes < 0:
            raise KexecError("KEXEC_BAD_CONFIG",
                             "max_image_bytes must be a non-negative integer")
        if not _is_int(audit_capacity) or audit_capacity < 0:
            raise KexecError("KEXEC_BAD_CONFIG",
                             "audit_capacity must be a non-negative integer")
        self.slot_count = slot_count
        self.max_total_bytes = max_total_bytes
        self.max_image_bytes = max_image_bytes
        self.allow_unsigned = bool(allow_unsigned)
        self.audit_capacity = audit_capacity

        self._lock = threading.RLock()
        self._keys = {}
        self._slots = [None] * slot_count
        self._booted = set()
        self._blacklist = set()
        self._stats = {
            "loads": 0,
            "rejected": 0,
            "boots": 0,
            "denied_boots": 0,
            "unloads": 0,
            "duplicates": 0,
        }
        self._audit = deque(maxlen=audit_capacity)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _record(self, event, code=None):
        self._audit.append({"event": event, "code": code})

    def _check_slot(self, slot):
        if not _is_int(slot) or slot < 0 or slot >= self.slot_count:
            raise KexecError(
                "KEXEC_BAD_SLOT",
                "slot %r is outside 0..%d" % (slot, self.slot_count - 1),
            )
        return slot

    def _check_digest(self, digest):
        if not _valid_digest(digest):
            raise KexecError(
                "KEXEC_BAD_DIGEST",
                "digest must be 64 lowercase hexadecimal characters",
            )
        return digest

    def _check_tenant(self, tenant):
        if not isinstance(tenant, str):
            raise KexecError("KEXEC_TENANT_MISMATCH",
                             "tenant must be a string")
        return tenant

    def _validate_image(self, image):
        if not isinstance(image, dict):
            raise KexecError("KEXEC_BAD_IMAGE", "image must be a dictionary")

        digest = image.get("digest")
        self._check_digest(digest)

        name = image.get("name")
        if not isinstance(name, str) or name == "":
            raise KexecError("KEXEC_BAD_IMAGE",
                             "image name must be a non-empty string")

        size = image.get("size")
        if not _is_int(size) or size <= 0:
            raise KexecError("KEXEC_BAD_IMAGE",
                             "image size must be a positive integer")

        return {
            "name": name,
            "digest": digest,
            "size": size,
            "key_id": image.get("key_id"),
            "signature": image.get("signature"),
        }

    def _authenticate(self, record):
        key_id = record["key_id"]
        signature = record["signature"]

        if key_id is None:
            if signature is not None:
                if not self.allow_unsigned:
                    raise KexecError(
                        "KEXEC_UNSIGNED",
                        "a signature without a key cannot be verified",
                    )
                if not isinstance(signature, str):
                    raise KexecError(
                        "KEXEC_BAD_SIGNATURE",
                        "signature must be a string",
                    )
            elif not self.allow_unsigned:
                raise KexecError("KEXEC_UNSIGNED",
                                 "unsigned images are not allowed")
            return False

        if signature is None:
            raise KexecError("KEXEC_UNSIGNED",
                             "image key_id is present but signature is missing")

        if not isinstance(key_id, str):
            raise KexecError("KEXEC_KEY_UNKNOWN",
                             "key %r is not registered" % (key_id,))

        key = self._keys.get(key_id)
        if key is None:
            raise KexecError("KEXEC_KEY_UNKNOWN",
                             "key %r is not registered" % (key_id,))
        if key["revoked"]:
            raise KexecError("KEXEC_KEY_REVOKED",
                             "key %r has been revoked" % (key_id,))

        expected = expected_signature(key_id, record["name"], record["digest"])
        if not isinstance(signature, str):
            raise KexecError("KEXEC_BAD_SIGNATURE",
                             "signature does not match the image")
        try:
            matches = hmac.compare_digest(
                signature.encode("utf-8"), expected.encode("ascii")
            )
        except UnicodeError:
            matches = False
        if not matches:
            raise KexecError("KEXEC_BAD_SIGNATURE",
                             "signature does not match the image")
        return True

    def _bytes_used(self):
        return sum(record["size"] for record in self._slots
                   if record is not None)

    def _usage_locked(self):
        return {
            "bytes": self._bytes_used(),
            "slots": sum(1 for record in self._slots if record is not None),
            "slot_count": self.slot_count,
            "limit_bytes": self.max_total_bytes,
            "max_image_bytes": self.max_image_bytes,
        }

    def _load_locked(self, slot, image, tenant):
        self._check_slot(slot)
        self._check_tenant(tenant)
        candidate = self._validate_image(image)

        digest = candidate["digest"]
        if digest in self._blacklist:
            raise KexecError("KEXEC_BLACKLISTED",
                             "digest %s is blacklisted" % digest)
        if digest in self._booted:
            raise KexecError("KEXEC_ALREADY_BOOTED",
                             "digest %s has already been booted" % digest)

        verified = self._authenticate(candidate)

        current = self._slots[slot]
        if current is not None:
            if (current["name"] == candidate["name"]
                    and current["digest"] == candidate["digest"]
                    and current["size"] == candidate["size"]):
                usage = self._usage_locked()
                return {
                    "status": "already",
                    "slot": slot,
                    "name": current["name"],
                    "digest": current["digest"],
                    "size": current["size"],
                    "verified": current["verified"],
                    "usage": usage,
                }, True
            raise KexecError(
                "KEXEC_SLOT_BUSY",
                "slot %d already holds a different image" % slot,
            )

        size = candidate["size"]
        if size > self.max_image_bytes:
            raise KexecError(
                "KEXEC_IMAGE_TOO_LARGE",
                "image is %d bytes; per-image limit is %d"
                % (size, self.max_image_bytes),
            )
        if self._bytes_used() + size > self.max_total_bytes:
            raise KexecError(
                "KEXEC_IMAGE_TOO_LARGE",
                "staging image would exceed the %d byte total limit"
                % self.max_total_bytes,
            )

        record = {
            "slot": slot,
            "name": candidate["name"],
            "digest": digest,
            "size": size,
            "key_id": candidate["key_id"],
            "signature": candidate["signature"],
            "verified": verified,
            "tenant": tenant,
        }
        self._slots[slot] = record

        return {
            "status": "staged",
            "slot": slot,
            "name": record["name"],
            "digest": record["digest"],
            "size": record["size"],
            "verified": record["verified"],
            "usage": self._usage_locked(),
        }, False

    def _boot_locked(self, slot, tenant):
        self._check_slot(slot)
        record = self._slots[slot]
        if record is None:
            raise KexecError("KEXEC_SLOT_EMPTY",
                             "slot %d is empty" % slot)

        self._check_tenant(tenant)
        if tenant != record["tenant"]:
            raise KexecError(
                "KEXEC_TENANT_MISMATCH",
                "slot %d belongs to tenant %r" % (slot, record["tenant"]),
            )

        if record["digest"] in self._blacklist:
            raise KexecError("KEXEC_BLACKLISTED",
                             "digest %s is blacklisted" % record["digest"])
        if record["digest"] in self._booted:
            raise KexecError(
                "KEXEC_ALREADY_BOOTED",
                "digest %s has already been booted" % record["digest"],
            )

        key_id = record["key_id"]
        if key_id is not None:
            key = self._keys.get(key_id)
            if key is None:
                raise KexecError("KEXEC_KEY_UNKNOWN",
                                 "key %r is not registered" % (key_id,))
            if key["revoked"]:
                raise KexecError("KEXEC_KEY_REVOKED",
                                 "key %r has been revoked" % (key_id,))

        self._slots[slot] = None
        self._booted.add(record["digest"])
        return {
            "slot": slot,
            "name": record["name"],
            "digest": record["digest"],
            "verified": record["verified"],
        }

    # ------------------------------------------------------------------
    # Trust store
    # ------------------------------------------------------------------
    def add_key(self, key_id, *, kind="rsa"):
        if not isinstance(key_id, str) or key_id == "":
            raise KexecError("KEXEC_BAD_KEY",
                             "key_id must be a non-empty string")
        if kind not in KEY_KINDS:
            raise KexecError("KEXEC_BAD_KEY",
                             "key kind must be one of %s" % (KEY_KINDS,))

        with self._lock:
            if key_id in self._keys:
                raise KexecError("KEXEC_KEY_EXISTS",
                                 "key %r already exists" % (key_id,))
            self._keys[key_id] = {"kind": kind, "revoked": False}
            return {"key_id": key_id, "kind": kind, "revoked": False}

    def revoke_key(self, key_id):
        with self._lock:
            key = self._keys.get(key_id) if isinstance(key_id, str) else None
            if key is None:
                raise KexecError("KEXEC_KEY_UNKNOWN",
                                 "key %r is not registered" % (key_id,))
            if key["revoked"]:
                return False
            key["revoked"] = True
            return True

    def key_info(self, key_id):
        with self._lock:
            key = self._keys.get(key_id) if isinstance(key_id, str) else None
            if key is None:
                raise KexecError("KEXEC_KEY_UNKNOWN",
                                 "key %r is not registered" % (key_id,))
            return {"key_id": key_id, "kind": key["kind"],
                    "revoked": key["revoked"]}

    # ------------------------------------------------------------------
    # Staging and boot
    # ------------------------------------------------------------------
    def load_image(self, slot, image, *, tenant="default"):
        with self._lock:
            try:
                result, duplicate = self._load_locked(slot, image, tenant)
            except KexecError as exc:
                self._stats["rejected"] += 1
                self._record("reject", exc.code)
                raise
            except Exception as exc:
                error = KexecError("KEXEC_BAD_IMAGE", str(exc))
                self._stats["rejected"] += 1
                self._record("reject", error.code)
                raise error from exc

            if duplicate:
                self._stats["duplicates"] += 1
                self._record("duplicate")
            else:
                self._stats["loads"] += 1
                self._record("load")
            return result

    def staged(self, slot, *, tenant="default"):
        with self._lock:
            self._check_slot(slot)
            record = self._slots[slot]
            if record is None:
                return None
            if tenant != record["tenant"]:
                raise KexecError(
                    "KEXEC_TENANT_MISMATCH",
                    "slot %d belongs to tenant %r"
                    % (slot, record["tenant"]),
                )
            return {
                "slot": slot,
                "name": record["name"],
                "digest": record["digest"],
                "size": record["size"],
                "key_id": record["key_id"],
                "verified": record["verified"],
                "tenant": record["tenant"],
            }

    def unload(self, slot, *, tenant="default"):
        with self._lock:
            self._check_slot(slot)
            record = self._slots[slot]
            if record is None:
                return False
            if tenant != record["tenant"]:
                raise KexecError(
                    "KEXEC_TENANT_MISMATCH",
                    "slot %d belongs to tenant %r"
                    % (slot, record["tenant"]),
                )
            self._slots[slot] = None
            self._stats["unloads"] += 1
            self._record("unload")
            return True

    def boot(self, slot, *, tenant="default"):
        with self._lock:
            try:
                result = self._boot_locked(slot, tenant)
            except KexecError as exc:
                self._stats["denied_boots"] += 1
                self._record("boot_denied", exc.code)
                raise
            except Exception as exc:
                error = KexecError("KEXEC_SLOT_EMPTY", str(exc))
                self._stats["denied_boots"] += 1
                self._record("boot_denied", error.code)
                raise error from exc

            self._stats["boots"] += 1
            self._record("boot")
            return result

    def blacklist(self, digest):
        with self._lock:
            self._check_digest(digest)
            if digest in self._blacklist:
                return False
            self._blacklist.add(digest)
            return True

    # ------------------------------------------------------------------
    # Introspection and persistence
    # ------------------------------------------------------------------
    def usage(self):
        with self._lock:
            return self._usage_locked()

    def stats(self):
        with self._lock:
            return dict(self._stats)

    def audit(self, limit=None):
        with self._lock:
            rows = [dict(row) for row in self._audit]
            if limit is None:
                return rows
            if not _is_int(limit):
                raise KexecError("KEXEC_BAD_AUDIT_LIMIT",
                                 "audit limit must be an integer or None")
            if limit <= 0:
                return []
            return rows[-limit:]

    def snapshot(self):
        with self._lock:
            payload = {
                "version": _SNAPSHOT_VERSION,
                "config": {
                    "slot_count": self.slot_count,
                    "max_total_bytes": self.max_total_bytes,
                    "max_image_bytes": self.max_image_bytes,
                    "allow_unsigned": self.allow_unsigned,
                    "audit_capacity": self.audit_capacity,
                },
                "keys": [
                    {
                        "key_id": key_id,
                        "kind": self._keys[key_id]["kind"],
                        "revoked": self._keys[key_id]["revoked"],
                    }
                    for key_id in sorted(self._keys)
                ],
                "slots": [
                    None if record is None else {
                        "name": record["name"],
                        "digest": record["digest"],
                        "size": record["size"],
                        "key_id": record["key_id"],
                        "signature": record["signature"],
                        "verified": record["verified"],
                        "tenant": record["tenant"],
                    }
                    for record in self._slots
                ],
                "booted": sorted(self._booted),
                "blacklist": sorted(self._blacklist),
                "stats": dict(self._stats),
                "audit": [dict(row) for row in self._audit],
            }
            canonical = json.dumps(
                payload, sort_keys=True, separators=(",", ":")
            )
            payload["checksum"] = hashlib.sha256(
                canonical.encode("utf-8")
            ).hexdigest()
            return json.dumps(payload, sort_keys=True, separators=(",", ":"))

    @classmethod
    def restore(cls, data):
        try:
            if not isinstance(data, str):
                raise ValueError("snapshot must be a string")
            payload = json.loads(data)
            if not isinstance(payload, dict):
                raise ValueError("snapshot must be a JSON object")

            checksum = payload.pop("checksum", None)
            if not isinstance(checksum, str):
                raise ValueError("snapshot checksum is missing")
            canonical = json.dumps(
                payload, sort_keys=True, separators=(",", ":")
            )
            actual = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            if not hmac.compare_digest(checksum, actual):
                raise ValueError("snapshot checksum does not match")

            if payload.get("version") != _SNAPSHOT_VERSION:
                raise ValueError("unsupported snapshot version")
            config = payload.get("config")
            if not isinstance(config, dict):
                raise ValueError("snapshot config is invalid")

            guard = cls(
                slot_count=config.get("slot_count"),
                max_total_bytes=config.get("max_total_bytes"),
                max_image_bytes=config.get("max_image_bytes"),
                allow_unsigned=config.get("allow_unsigned"),
                audit_capacity=config.get("audit_capacity"),
            )

            raw_keys = payload.get("keys")
            if not isinstance(raw_keys, list):
                raise ValueError("snapshot keys are invalid")
            keys = {}
            for item in raw_keys:
                if not isinstance(item, dict):
                    raise ValueError("snapshot key entry is invalid")
                key_id = item.get("key_id")
                kind = item.get("kind")
                revoked = item.get("revoked")
                if (not isinstance(key_id, str) or key_id == ""
                        or kind not in KEY_KINDS
                        or not isinstance(revoked, bool)
                        or key_id in keys):
                    raise ValueError("snapshot key entry is invalid")
                keys[key_id] = {"kind": kind, "revoked": revoked}

            raw_slots = payload.get("slots")
            if not isinstance(raw_slots, list) or len(raw_slots) != guard.slot_count:
                raise ValueError("snapshot slots are invalid")
            slots = []
            total_bytes = 0
            for index, item in enumerate(raw_slots):
                if item is None:
                    slots.append(None)
                    continue
                if not isinstance(item, dict):
                    raise ValueError("snapshot slot entry is invalid")

                name = item.get("name")
                digest = item.get("digest")
                size = item.get("size")
                key_id = item.get("key_id")
                signature = item.get("signature")
                verified = item.get("verified")
                tenant = item.get("tenant")

                if not isinstance(name, str) or name == "":
                    raise ValueError("snapshot slot name is invalid")
                if not _valid_digest(digest):
                    raise ValueError("snapshot slot digest is invalid")
                if not _is_int(size) or size <= 0:
                    raise ValueError("snapshot slot size is invalid")
                if not isinstance(verified, bool):
                    raise ValueError("snapshot slot verification is invalid")
                if not isinstance(tenant, str):
                    raise ValueError("snapshot slot tenant is invalid")

                if key_id is None:
                    if verified or not guard.allow_unsigned:
                        raise ValueError(
                            "snapshot contains an invalid unsigned image"
                        )
                    if signature is not None and not isinstance(signature, str):
                        raise ValueError("snapshot slot signature is invalid")
                else:
                    if not isinstance(key_id, str) or key_id not in keys:
                        raise ValueError("snapshot slot key is unknown")
                    if not isinstance(signature, str) or not hmac.compare_digest(
                            signature,
                            expected_signature(key_id, name, digest)):
                        raise ValueError("snapshot slot signature is invalid")
                    if not verified:
                        raise ValueError(
                            "snapshot signed image is not verified"
                        )

                if size > guard.max_image_bytes:
                    raise ValueError("snapshot slot exceeds image limit")
                total_bytes += size

                slots.append({
                    "slot": index,
                    "name": name,
                    "digest": digest,
                    "size": size,
                    "key_id": key_id,
                    "signature": signature,
                    "verified": verified,
                    "tenant": tenant,
                })

            if total_bytes > guard.max_total_bytes:
                raise ValueError("snapshot slots exceed total limit")

            raw_booted = payload.get("booted")
            if not isinstance(raw_booted, list):
                raise ValueError("snapshot booted tombstones are invalid")
            booted = set()
            for digest in raw_booted:
                if not _valid_digest(digest) or digest in booted:
                    raise ValueError("snapshot booted digest is invalid")
                booted.add(digest)

            raw_blacklist = payload.get("blacklist")
            if not isinstance(raw_blacklist, list):
                raise ValueError("snapshot blacklist is invalid")
            blacklist = set()
            for digest in raw_blacklist:
                if not _valid_digest(digest) or digest in blacklist:
                    raise ValueError("snapshot blacklist digest is invalid")
                blacklist.add(digest)

            raw_stats = payload.get("stats")
            if not isinstance(raw_stats, dict):
                raise ValueError("snapshot stats are invalid")
            expected_stat_keys = {
                "loads", "rejected", "boots", "denied_boots",
                "unloads", "duplicates",
            }
            if set(raw_stats) != expected_stat_keys:
                raise ValueError("snapshot stats are invalid")
            stats = {}
            for name, value in raw_stats.items():
                if not _is_int(value) or value < 0:
                    raise ValueError("snapshot stats are invalid")
                stats[name] = value

            raw_audit = payload.get("audit")
            if not isinstance(raw_audit, list):
                raise ValueError("snapshot audit is invalid")
            if len(raw_audit) > guard.audit_capacity:
                raise ValueError("snapshot audit exceeds capacity")
            audit = []
            for row in raw_audit:
                if not isinstance(row, dict):
                    raise ValueError("snapshot audit row is invalid")
                event = row.get("event")
                code = row.get("code")
                if event not in _AUDIT_EVENTS:
                    raise ValueError("snapshot audit event is invalid")
                if event in _SUCCESS_EVENTS:
                    if code is not None:
                        raise ValueError("snapshot audit code is invalid")
                elif not isinstance(code, str) or code == "":
                    raise ValueError("snapshot audit code is invalid")
                audit.append({"event": event, "code": code})

            with guard._lock:
                guard._keys = keys
                guard._slots = slots
                guard._booted = booted
                guard._blacklist = blacklist
                guard._stats = stats
                guard._audit = deque(audit, maxlen=guard.audit_capacity)
            return guard
        except KexecError as exc:
            raise KexecError("KEXEC_SNAPSHOT_INVALID", str(exc)) from exc
        except Exception as exc:
            raise KexecError("KEXEC_SNAPSHOT_INVALID", str(exc)) from exc
