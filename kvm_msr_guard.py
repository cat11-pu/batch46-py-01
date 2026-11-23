"""KVM vCPU MSR access filtering guard.

The guard keeps a per-VM policy, vCPU value store, decision cache, batch
ledger and audit trail.  All public operations are serialized so writes and
their accounting stay consistent under concurrent callers.
"""

from __future__ import annotations

import json
import threading
from collections import OrderedDict, deque
from dataclasses import dataclass, field


MSR_ALLOW = "allow"
MSR_DENY = "deny"
MSR_MASK = "mask"

MSR_ACTIONS = (MSR_ALLOW, MSR_DENY, MSR_MASK)

MSR_OK = "MSR_OK"
MSR_DENIED = "MSR_DENIED"
MSR_VM_UNKNOWN = "MSR_VM_UNKNOWN"
MSR_VM_CLOSED = "MSR_VM_CLOSED"
MSR_NO_POLICY = "MSR_NO_POLICY"
MSR_VCPU_EXISTS = "MSR_VCPU_EXISTS"
MSR_VCPU_LIMIT = "MSR_VCPU_LIMIT"
MSR_VCPU_UNKNOWN = "MSR_VCPU_UNKNOWN"
MSR_BAD_INDEX = "MSR_BAD_INDEX"
MSR_BAD_RULE = "MSR_BAD_RULE"
MSR_RULE_LIMIT = "MSR_RULE_LIMIT"
MSR_BATCH_REJECTED = "MSR_BATCH_REJECTED"
MSR_BATCH_CONFLICT = "MSR_BATCH_CONFLICT"
MSR_SNAPSHOT_INVALID = "MSR_SNAPSHOT_INVALID"

_MAX_MSR_INDEX = 0xFFFFFFFF
_STAT_KEYS = (
    "checks",
    "allowed",
    "denied",
    "batches",
    "denied_batches",
    "duplicates",
)


class MsrGuardError(ValueError):
    """Raised for every rejected MSR operation."""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


def _zero_stats():
    return {key: 0 for key in _STAT_KEYS}


@dataclass
class _VmState:
    rules: list
    default: str
    closed: bool = False
    vcpus: dict = field(default_factory=dict)
    cache: OrderedDict = field(default_factory=OrderedDict)
    batches: dict = field(default_factory=dict)
    stats: dict = field(default_factory=_zero_stats)


class KvmMsrGuard:
    def __init__(self, *, max_vcpus=16, max_rules=32, cache_capacity=8,
                 audit_capacity=8):
        self._max_vcpus = max(0, int(max_vcpus))
        self._max_rules = max(0, int(max_rules))
        self._cache_capacity = max(0, int(cache_capacity))
        self._audit_capacity = max(0, int(audit_capacity))
        self._vms = {}
        self._stats = _zero_stats()
        self._audit = deque(maxlen=self._audit_capacity)
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # validation helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _require_vm_id(vm_id):
        if not isinstance(vm_id, str):
            raise MsrGuardError(MSR_VM_UNKNOWN, vm_id)

    @staticmethod
    def _require_vcpu_id(vcpu_id):
        if (not isinstance(vcpu_id, int) or isinstance(vcpu_id, bool)
                or vcpu_id < 0):
            raise MsrGuardError(MSR_VCPU_UNKNOWN, vcpu_id)

    @staticmethod
    def _require_index(index):
        if (not isinstance(index, int) or isinstance(index, bool)
                or index < 0 or index > _MAX_MSR_INDEX):
            raise MsrGuardError(MSR_BAD_INDEX, index)

    @staticmethod
    def _normalize_default(default):
        if default not in (MSR_ALLOW, MSR_DENY):
            raise MsrGuardError(MSR_BAD_RULE, default)
        return default

    def _normalize_rules(self, rules):
        if not isinstance(rules, (list, tuple)):
            raise MsrGuardError(MSR_BAD_RULE, "rules")
        if len(rules) > self._max_rules:
            raise MsrGuardError(MSR_RULE_LIMIT, len(rules))

        normalized = []
        for rule in rules:
            if not isinstance(rule, (list, tuple)) or len(rule) not in (3, 4):
                raise MsrGuardError(MSR_BAD_RULE, rule)
            if len(rule) == 4:
                start, end, action, mask = rule
            else:
                start, end, action = rule
                mask = None
            if (not isinstance(start, int) or isinstance(start, bool)
                    or not isinstance(end, int) or isinstance(end, bool)
                    or start < 0 or end < start or end > _MAX_MSR_INDEX):
                raise MsrGuardError(MSR_BAD_RULE, rule)
            if action not in MSR_ACTIONS:
                raise MsrGuardError(MSR_BAD_RULE, rule)
            if action == MSR_MASK:
                if (not isinstance(mask, int) or isinstance(mask, bool)
                        or mask < 0):
                    raise MsrGuardError(MSR_BAD_RULE, rule)
            elif mask is not None:
                if (not isinstance(mask, int) or isinstance(mask, bool)
                        or mask < 0):
                    raise MsrGuardError(MSR_BAD_RULE, rule)
            if len(rule) == 4:
                normalized.append((start, end, action, mask))
            else:
                normalized.append((start, end, action))
        return normalized

    def _get_vm(self, vm_id):
        self._require_vm_id(vm_id)
        state = self._vms.get(vm_id)
        if state is None:
            raise MsrGuardError(MSR_VM_UNKNOWN, vm_id)
        return state

    def _get_open_vm(self, vm_id):
        state = self._get_vm(vm_id)
        if state.closed:
            raise MsrGuardError(MSR_VM_CLOSED, vm_id)
        return state

    @staticmethod
    def _get_vcpu(state, vm_id, vcpu_id):
        KvmMsrGuard._require_vcpu_id(vcpu_id)
        if vcpu_id not in state.vcpus:
            raise MsrGuardError(MSR_VCPU_UNKNOWN, vcpu_id)
        return state.vcpus[vcpu_id]

    # ------------------------------------------------------------------
    # policy and vCPU lifecycle
    # ------------------------------------------------------------------
    def define_policy(self, vm_id, rules, *, default=MSR_DENY):
        with self._lock:
            self._require_vm_id(vm_id)
            existing = self._vms.get(vm_id)
            if existing is not None and existing.closed:
                raise MsrGuardError(MSR_VM_CLOSED, vm_id)

            normalized = self._normalize_rules(rules)
            normalized_default = self._normalize_default(default)

            if existing is None:
                state = _VmState(rules=normalized, default=normalized_default)
                self._vms[vm_id] = state
            else:
                existing.rules = normalized
                existing.default = normalized_default
                existing.cache.clear()
            return len(normalized)

    def policy_of(self, vm_id):
        with self._lock:
            state = self._get_vm(vm_id)
            return {
                "configured": True,
                "default": state.default,
                "rules": list(state.rules),
            }

    def create_vcpu(self, vm_id, vcpu_id):
        with self._lock:
            state = self._get_open_vm(vm_id)
            self._require_vcpu_id(vcpu_id)
            if vcpu_id in state.vcpus:
                raise MsrGuardError(MSR_VCPU_EXISTS, vcpu_id)
            if len(state.vcpus) >= self._max_vcpus:
                raise MsrGuardError(MSR_VCPU_LIMIT, vcpu_id)
            state.vcpus[vcpu_id] = {}
            return {"vm": vm_id, "vcpu": vcpu_id}

    def remove_vcpu(self, vm_id, vcpu_id):
        with self._lock:
            state = self._get_open_vm(vm_id)
            self._get_vcpu(state, vm_id, vcpu_id)
            del state.vcpus[vcpu_id]
            state.cache.clear()
            return True

    # ------------------------------------------------------------------
    # decision and access paths
    # ------------------------------------------------------------------
    @staticmethod
    def _rule_parts(rule):
        start, end, action = rule[0], rule[1], rule[2]
        mask = rule[3] if len(rule) == 4 else None
        return start, end, action, mask

    def _decide(self, state, vcpu_id, index):
        key = (vcpu_id, index)
        cached = state.cache.get(key)
        if cached is not None:
            state.cache.move_to_end(key)
            return cached

        action = None
        mask = None

        # Exact single-index rules take precedence over every range rule.
        for rule in state.rules:
            start, end, rule_action, rule_mask = self._rule_parts(rule)
            if start == end == index:
                action, mask = rule_action, rule_mask
                break

        if action is None:
            for rule in state.rules:
                start, end, rule_action, rule_mask = self._rule_parts(rule)
                if start != end and start <= index <= end:
                    action, mask = rule_action, rule_mask
                    break

        if action is None:
            action = state.default
            mask = None

        decision = (action, mask)
        if self._cache_capacity > 0:
            state.cache[key] = decision
            state.cache.move_to_end(key)
            if len(state.cache) > self._cache_capacity:
                state.cache.popitem(last=False)
        return decision

    def _bump(self, state, **increments):
        for key, amount in increments.items():
            state.stats[key] += amount
            self._stats[key] += amount

    def _record(self, vm_id, vcpu_id, index, action, allowed, value, write,
                code):
        self._audit.append({
            "vm": vm_id,
            "vcpu": vcpu_id,
            "index": index,
            "action": action,
            "allowed": allowed,
            "value": value,
            "write": write,
            "code": code,
        })

    def check(self, vm_id, vcpu_id, index, value=0, *, write=True):
        with self._lock:
            state = self._get_open_vm(vm_id)
            self._get_vcpu(state, vm_id, vcpu_id)
            self._require_index(index)

            action, mask = self._decide(state, vcpu_id, index)
            if action == MSR_DENY:
                self._bump(state, checks=1, denied=1)
                self._record(vm_id, vcpu_id, index, action, False, value,
                             write, MSR_DENIED)
                raise MsrGuardError(MSR_DENIED, index)

            result_value = value if action == MSR_ALLOW else value & mask
            self._bump(state, checks=1, allowed=1)
            self._record(vm_id, vcpu_id, index, action, True, result_value,
                         write, MSR_OK)
            return {
                "allowed": True,
                "action": action,
                "value": result_value,
            }

    def set_msr(self, vm_id, vcpu_id, index, value):
        with self._lock:
            state = self._get_open_vm(vm_id)
            values = self._get_vcpu(state, vm_id, vcpu_id)
            self._require_index(index)

            action, mask = self._decide(state, vcpu_id, index)
            if action == MSR_DENY:
                self._bump(state, checks=1, denied=1)
                self._record(vm_id, vcpu_id, index, action, False, value,
                             True, MSR_DENIED)
                raise MsrGuardError(MSR_DENIED, index)

            result_value = value if action == MSR_ALLOW else value & mask
            values[index] = result_value
            self._bump(state, checks=1, allowed=1)
            self._record(vm_id, vcpu_id, index, action, True, result_value,
                         True, MSR_OK)
            return {
                "allowed": True,
                "action": action,
                "value": result_value,
            }

    def read_msr(self, vm_id, vcpu_id, index):
        with self._lock:
            state = self._get_open_vm(vm_id)
            values = self._get_vcpu(state, vm_id, vcpu_id)
            self._require_index(index)

            action, mask = self._decide(state, vcpu_id, index)
            if action == MSR_DENY:
                self._bump(state, checks=1, denied=1)
                self._record(vm_id, vcpu_id, index, action, False,
                             values.get(index, 0), False, MSR_DENIED)
                raise MsrGuardError(MSR_DENIED, index)

            current = values.get(index, 0)
            result_value = current if action == MSR_ALLOW else current & mask
            self._bump(state, checks=1, allowed=1)
            self._record(vm_id, vcpu_id, index, action, True, result_value,
                         False, MSR_OK)
            return result_value

    # ------------------------------------------------------------------
    # batch application
    # ------------------------------------------------------------------
    @staticmethod
    def _normalize_access(access):
        if not isinstance(access, dict):
            raise MsrGuardError(MSR_BAD_INDEX, None)
        if "index" not in access:
            raise MsrGuardError(MSR_BAD_INDEX, None)
        index = access["index"]
        KvmMsrGuard._require_index(index)
        write = bool(access.get("write", True))
        value = access.get("value", 0)
        if write and (not isinstance(value, int) or isinstance(value, bool)):
            raise MsrGuardError(MSR_BATCH_REJECTED, index)
        if not write:
            value = 0
        return index, write, value

    @staticmethod
    def _batch_signature(accesses):
        canonical = [
            [index, write, value if write else None]
            for index, write, value in accesses
        ]
        return json.dumps(canonical, separators=(",", ":"))

    def apply_batch(self, vm_id, vcpu_id, accesses, *, batch_id=None):
        with self._lock:
            state = self._get_open_vm(vm_id)
            self._get_vcpu(state, vm_id, vcpu_id)
            if batch_id is not None and not isinstance(batch_id, str):
                raise MsrGuardError(MSR_BAD_RULE, batch_id)
            if not isinstance(accesses, (list, tuple)):
                raise MsrGuardError(MSR_BATCH_REJECTED, 0)

            normalized = [self._normalize_access(item) for item in accesses]

            if batch_id is not None:
                signature = self._batch_signature(normalized)
                previous = state.batches.get(batch_id)
                if previous is not None:
                    if (previous["vcpu"] == vcpu_id
                            and previous["signature"] == signature):
                        self._bump(state, duplicates=1)
                        return {
                            "status": "duplicate",
                            "results": [],
                        }
                    raise MsrGuardError(MSR_BATCH_CONFLICT, batch_id)
            else:
                signature = None

            staged = dict(state.vcpus[vcpu_id])
            results = []
            for position, (index, write, value) in enumerate(normalized):
                action, mask = self._decide(state, vcpu_id, index)
                if action == MSR_DENY:
                    self._bump(state, denied_batches=1)
                    raise MsrGuardError(MSR_BATCH_REJECTED, position)

                if write:
                    result_value = (value if action == MSR_ALLOW
                                    else value & mask)
                    staged[index] = result_value
                else:
                    current = staged.get(index, 0)
                    result_value = (current if action == MSR_ALLOW
                                    else current & mask)
                results.append({
                    "index": index,
                    "allowed": True,
                    "action": action,
                    "value": result_value,
                })

            state.vcpus[vcpu_id] = staged
            count = len(normalized)
            self._bump(state, checks=count, allowed=count, batches=1)
            for (index, write, _value), row in zip(normalized, results):
                self._record(vm_id, vcpu_id, index, row["action"], True,
                             row["value"], write, MSR_OK)
            if batch_id is not None:
                state.batches[batch_id] = {
                    "vcpu": vcpu_id,
                    "signature": signature,
                }
            return {
                "status": "applied",
                "results": results,
            }

    # ------------------------------------------------------------------
    # VM lifecycle and introspection
    # ------------------------------------------------------------------
    def close_vm(self, vm_id):
        with self._lock:
            state = self._get_vm(vm_id)
            if state.closed:
                return False
            state.closed = True
            state.cache.clear()
            return True

    def cache_size(self, vm_id):
        with self._lock:
            state = self._get_vm(vm_id)
            return len(state.cache)

    def stats(self, vm_id=None):
        with self._lock:
            if vm_id is None:
                return dict(self._stats)
            state = self._get_vm(vm_id)
            return dict(state.stats)

    def audit(self, limit=None):
        with self._lock:
            if limit is None:
                rows = list(self._audit)
            else:
                count = max(0, int(limit))
                rows = list(self._audit)[-count:] if count else []
            return [dict(row) for row in rows]

    # ------------------------------------------------------------------
    # persistence
    # ------------------------------------------------------------------
    def snapshot(self):
        with self._lock:
            vms = {}
            for vm_id, state in self._vms.items():
                vms[vm_id] = {
                    "rules": [list(rule) for rule in state.rules],
                    "default": state.default,
                    "closed": state.closed,
                    "vcpus": {
                        str(vcpu_id): [[index, value]
                                       for index, value
                                       in sorted(values.items())]
                        for vcpu_id, values in state.vcpus.items()
                    },
                    "batches": {
                        batch_id: dict(record)
                        for batch_id, record in state.batches.items()
                    },
                    "stats": dict(state.stats),
                }
            payload = {
                "version": 1,
                "config": {
                    "max_vcpus": self._max_vcpus,
                    "max_rules": self._max_rules,
                    "cache_capacity": self._cache_capacity,
                    "audit_capacity": self._audit_capacity,
                },
                "vms": vms,
                "stats": dict(self._stats),
                "audit": [dict(row) for row in self._audit],
            }
            return json.dumps(payload, sort_keys=True, separators=(",", ":"))

    @staticmethod
    def _restore_stats(raw):
        if not isinstance(raw, dict):
            raise ValueError("stats")
        result = {}
        for key in _STAT_KEYS:
            value = raw.get(key)
            if (not isinstance(value, int) or isinstance(value, bool)
                    or value < 0):
                raise ValueError("stats")
            result[key] = value
        return result

    @classmethod
    def restore(cls, data):
        try:
            if not isinstance(data, (str, bytes, bytearray)):
                raise ValueError("snapshot")
            payload = json.loads(data)
            if not isinstance(payload, dict) or payload.get("version") != 1:
                raise ValueError("snapshot")

            config = payload["config"]
            if not isinstance(config, dict):
                raise ValueError("config")
            config_values = {}
            for key in ("max_vcpus", "max_rules", "cache_capacity",
                        "audit_capacity"):
                value = config.get(key)
                if (not isinstance(value, int) or isinstance(value, bool)
                        or value < 0):
                    raise ValueError("config")
                config_values[key] = value

            guard = cls(**config_values)

            raw_vms = payload["vms"]
            if not isinstance(raw_vms, dict):
                raise ValueError("vms")
            for vm_id, raw_state in raw_vms.items():
                if not isinstance(vm_id, str) or not isinstance(raw_state, dict):
                    raise ValueError("vm")
                rules = guard._normalize_rules(raw_state["rules"])
                default = guard._normalize_default(raw_state["default"])
                closed = raw_state["closed"]
                if not isinstance(closed, bool):
                    raise ValueError("closed")

                raw_vcpus = raw_state["vcpus"]
                if not isinstance(raw_vcpus, dict):
                    raise ValueError("vcpus")
                if len(raw_vcpus) > guard._max_vcpus:
                    raise ValueError("vcpus")
                vcpus = {}
                for raw_vcpu_id, raw_values in raw_vcpus.items():
                    vcpu_id = int(raw_vcpu_id)
                    guard._require_vcpu_id(vcpu_id)
                    if vcpu_id in vcpus or not isinstance(raw_values, list):
                        raise ValueError("vcpus")
                    values = {}
                    for pair in raw_values:
                        if not isinstance(pair, (list, tuple)) or len(pair) != 2:
                            raise ValueError("values")
                        index, value = pair
                        guard._require_index(index)
                        if (not isinstance(value, int)
                                or isinstance(value, bool)):
                            raise ValueError("values")
                        if index in values:
                            raise ValueError("values")
                        values[index] = value
                    vcpus[vcpu_id] = values

                raw_batches = raw_state["batches"]
                if not isinstance(raw_batches, dict):
                    raise ValueError("batches")
                batches = {}
                for batch_id, record in raw_batches.items():
                    if not isinstance(batch_id, str):
                        raise ValueError("batches")
                    if not isinstance(record, dict):
                        raise ValueError("batches")
                    record_vcpu = record.get("vcpu")
                    signature = record.get("signature")
                    guard._require_vcpu_id(record_vcpu)
                    if not isinstance(signature, str):
                        raise ValueError("batches")
                    batches[batch_id] = {
                        "vcpu": record_vcpu,
                        "signature": signature,
                    }

                stats = guard._restore_stats(raw_state["stats"])
                guard._vms[vm_id] = _VmState(
                    rules=rules,
                    default=default,
                    closed=closed,
                    vcpus=vcpus,
                    batches=batches,
                    stats=stats,
                )

            guard._stats = guard._restore_stats(payload["stats"])
            raw_audit = payload["audit"]
            if not isinstance(raw_audit, list):
                raise ValueError("audit")
            audit_rows = []
            for row in raw_audit:
                if not isinstance(row, dict):
                    raise ValueError("audit")
                audit_rows.append(dict(row))
            if guard._audit_capacity == 0:
                audit_rows = []
            else:
                audit_rows = audit_rows[-guard._audit_capacity:]
            guard._audit = deque(audit_rows,
                                 maxlen=guard._audit_capacity)
            return guard
        except MsrGuardError as exc:
            raise MsrGuardError(MSR_SNAPSHOT_INVALID, exc.code) from None
        except Exception as exc:
            raise MsrGuardError(MSR_SNAPSHOT_INVALID, str(exc)) from None
