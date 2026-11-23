"""eBPF verifier and resource quota guard."""

import json
import threading


PROGRAM_TYPES = ("xdp", "kprobe", "tracepoint")

HELPER_TABLE = {
    "xdp": ("map_lookup", "map_update", "xdp_pass"),
    "kprobe": ("map_lookup", "map_update", "probe_read"),
    "tracepoint": ("map_lookup", "map_update", "trace_printk"),
}

MAP_HELPERS = ("map_lookup", "map_update")

STATS_FIELDS = (
    "loads",
    "rejected",
    "attaches",
    "detaches",
    "closed",
    "map_updates",
    "map_rejects",
    "hook_busy",
)

QUOTA_FIELDS = ("max_programs", "max_maps", "max_map_bytes")


class EbpfError(ValueError):
    """Raised for every rejected eBPF operation."""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class EbpfGuard:
    def __init__(self, *, max_instructions=64, max_programs=4, max_maps=4,
                 max_map_bytes=4096, audit_capacity=8):
        self._lock = threading.RLock()
        self.max_instructions = self._limit(
            max_instructions, "max_instructions", minimum=1
        )
        self.max_programs = self._limit(
            max_programs, "max_programs", minimum=0
        )
        self.max_maps = self._limit(max_maps, "max_maps", minimum=0)
        self.max_map_bytes = self._limit(
            max_map_bytes, "max_map_bytes", minimum=0
        )
        self.audit_capacity = self._limit(
            audit_capacity, "audit_capacity", minimum=0
        )
        self._next_id = 1
        self._programs = {}
        self._maps = {}
        self._hooks = {}
        self._tenant_quotas = {}
        self._stats = {name: 0 for name in STATS_FIELDS}
        self._audit = []

    @staticmethod
    def _limit(value, name, *, minimum):
        if not isinstance(value, int) or isinstance(value, bool):
            raise EbpfError("EBPF_BAD_QUOTA", "%s must be an integer" % name)
        if value < minimum:
            raise EbpfError(
                "EBPF_BAD_QUOTA", "%s must be >= %d" % (name, minimum)
            )
        return value

    @staticmethod
    def _is_int(value):
        return isinstance(value, int) and not isinstance(value, bool)

    @staticmethod
    def _sequence(value):
        return isinstance(value, (list, tuple))

    def _base_quotas(self):
        return {
            "max_programs": self.max_programs,
            "max_maps": self.max_maps,
            "max_map_bytes": self.max_map_bytes,
        }

    def _quota_for(self, tenant):
        return dict(self._tenant_quotas.get(tenant) or self._base_quotas())

    def _record(self, action, **fields):
        if self.audit_capacity == 0:
            return
        entry = {"action": action}
        entry.update(fields)
        self._audit.append(entry)
        if len(self._audit) > self.audit_capacity:
            del self._audit[:-self.audit_capacity]

    @staticmethod
    def _tenant_name(tenant):
        if not isinstance(tenant, str):
            raise EbpfError("EBPF_TENANT_MISMATCH", "tenant must be a string")
        return tenant

    def _verify_spec(self, spec):
        if not isinstance(spec, dict):
            raise EbpfError("EBPF_BAD_PROGRAM", "spec must be a dict")

        name = spec.get("name")
        if not isinstance(name, str) or not name:
            raise EbpfError("EBPF_BAD_PROGRAM", "name must be a non-empty string")

        program_type = spec.get("type")
        if program_type not in PROGRAM_TYPES:
            raise EbpfError(
                "EBPF_BAD_TYPE",
                "type must be one of %s" % ", ".join(PROGRAM_TYPES),
            )

        map_specs = self._verify_maps(spec.get("maps", []))
        map_names = {item["name"] for item in map_specs}

        instructions = spec.get("instructions")
        if not self._sequence(instructions):
            raise EbpfError("EBPF_BAD_INSN", "instructions must be a sequence")
        if len(instructions) > self.max_instructions:
            raise EbpfError(
                "EBPF_TOO_MANY_INSNS",
                "%d instructions exceed limit %d"
                % (len(instructions), self.max_instructions),
            )
        if not instructions or not self._is_exit(instructions[-1]):
            raise EbpfError("EBPF_NO_EXIT", "last instruction must be exit")

        for index, instruction in enumerate(instructions):
            self._verify_instruction(
                instruction, index, len(instructions), program_type, map_names
            )

        return {
            "name": name,
            "type": program_type,
            "instruction_count": len(instructions),
            "maps": map_specs,
            "map_names": [item["name"] for item in map_specs],
        }

    def _verify_maps(self, raw_maps):
        if not self._sequence(raw_maps):
            raise EbpfError("EBPF_BAD_MAP", "maps must be a sequence")

        result = []
        seen = set()
        for raw_map in raw_maps:
            if not isinstance(raw_map, dict):
                raise EbpfError("EBPF_BAD_MAP", "map declaration must be a dict")

            name = raw_map.get("name")
            max_entries = raw_map.get("max_entries")
            value_size = raw_map.get("value_size")
            if not isinstance(name, str) or not name:
                raise EbpfError(
                    "EBPF_BAD_MAP", "map name must be a non-empty string"
                )
            if not self._is_int(max_entries) or max_entries <= 0:
                raise EbpfError(
                    "EBPF_BAD_MAP", "max_entries must be a positive integer"
                )
            if not self._is_int(value_size) or value_size <= 0:
                raise EbpfError(
                    "EBPF_BAD_MAP", "value_size must be a positive integer"
                )
            if name in seen:
                raise EbpfError(
                    "EBPF_DUPLICATE_MAP",
                    "map %r is declared more than once" % name,
                )

            seen.add(name)
            result.append({
                "name": name,
                "max_entries": max_entries,
                "value_size": value_size,
            })
        return result

    @staticmethod
    def _is_exit(instruction):
        return (
            isinstance(instruction, (list, tuple))
            and len(instruction) == 1
            and instruction[0] == "exit"
        )

    def _verify_instruction(self, instruction, index, count, program_type,
                            map_names):
        if not self._sequence(instruction) or not instruction:
            raise EbpfError("EBPF_BAD_INSN", "instruction %d is malformed" % index)
        if not isinstance(instruction[0], str):
            raise EbpfError("EBPF_BAD_INSN", "instruction %d has no opcode" % index)

        opcode = instruction[0]
        if opcode == "exit":
            if len(instruction) != 1:
                raise EbpfError(
                    "EBPF_BAD_INSN", "exit at %d must not have operands" % index
                )
            return

        if opcode == "jump":
            self._verify_jump(instruction, index, count)
            return

        if opcode == "call":
            self._verify_call(instruction, index, program_type, map_names)
            return

        raise EbpfError(
            "EBPF_BAD_INSN", "unknown opcode %r at %d" % (opcode, index)
        )

    def _verify_jump(self, instruction, index, count):
        if len(instruction) not in (2, 3):
            raise EbpfError(
                "EBPF_BAD_INSN", "jump at %d has the wrong shape" % index
            )

        offset = instruction[1]
        if not self._is_int(offset) or offset == 0:
            raise EbpfError(
                "EBPF_BAD_JUMP", "jump at %d has an invalid offset" % index
            )

        target = index + offset
        if target < 0 or target >= count:
            raise EbpfError(
                "EBPF_BAD_JUMP",
                "jump at %d targets instruction %d outside [0, %d)"
                % (index, target, count),
            )

        if len(instruction) == 3:
            bound = instruction[2]
            if not self._is_int(bound) or bound < 1 or bound > 1000:
                raise EbpfError(
                    "EBPF_BAD_BOUND",
                    "jump at %d bound must be between 1 and 1000" % index,
                )
        elif offset < 0:
            raise EbpfError(
                "EBPF_UNBOUNDED_LOOP",
                "backward jump at %d has no loop bound" % index,
            )

    def _verify_call(self, instruction, index, program_type, map_names):
        if len(instruction) not in (2, 3):
            raise EbpfError(
                "EBPF_BAD_INSN", "call at %d has the wrong shape" % index
            )

        helper = instruction[1]
        if not isinstance(helper, str) or not helper:
            raise EbpfError(
                "EBPF_BAD_INSN", "call at %d has no helper name" % index
            )

        known = {
            helper_name
            for helper_names in HELPER_TABLE.values()
            for helper_name in helper_names
        }
        if helper not in known:
            raise EbpfError(
                "EBPF_HELPER_UNKNOWN", "unknown helper %r" % helper
            )
        if helper not in HELPER_TABLE[program_type]:
            raise EbpfError(
                "EBPF_HELPER_DENIED",
                "helper %r is not allowed for %s" % (helper, program_type),
            )

        if helper in MAP_HELPERS:
            if len(instruction) != 3:
                raise EbpfError(
                    "EBPF_BAD_INSN",
                    "%s call at %d requires a map name" % (helper, index),
                )
            map_name = instruction[2]
            if not isinstance(map_name, str) or not map_name:
                raise EbpfError(
                    "EBPF_BAD_INSN",
                    "%s call at %d requires a map name" % (helper, index),
                )
            if map_name not in map_names:
                raise EbpfError(
                    "EBPF_MAP_UNKNOWN",
                    "map %r is not declared by the program" % map_name,
                )
        elif len(instruction) != 2:
            raise EbpfError(
                "EBPF_BAD_INSN",
                "helper %r at %d does not take a map name" % (helper, index),
            )

    def verify(self, spec, *, tenant="default"):
        self._tenant_name(tenant)
        verified = self._verify_spec(spec)
        return {
            "name": verified["name"],
            "type": verified["type"],
            "instructions": verified["instruction_count"],
            "maps": list(verified["map_names"]),
        }

    def load_program(self, spec, *, tenant="default"):
        with self._lock:
            tenant = self._tenant_name(tenant)
            try:
                verified = self._verify_spec(spec)
                quota = self._quota_for(tenant)

                program_count = sum(
                    1
                    for program in self._programs.values()
                    if program["tenant"] == tenant
                )
                if program_count + 1 > quota["max_programs"]:
                    raise EbpfError(
                        "EBPF_PROG_QUOTA",
                        "tenant %r is at its program quota" % tenant,
                    )

                tenant_maps = self._maps.get(tenant, {})
                new_maps = []
                for declaration in verified["maps"]:
                    existing = tenant_maps.get(declaration["name"])
                    if existing is None:
                        new_maps.append(declaration)
                        continue
                    if (
                        existing["max_entries"] != declaration["max_entries"]
                        or existing["value_size"] != declaration["value_size"]
                    ):
                        raise EbpfError(
                            "EBPF_MAP_CONFLICT",
                            "map %r already exists with different dimensions"
                            % declaration["name"],
                        )

                if len(tenant_maps) + len(new_maps) > quota["max_maps"]:
                    raise EbpfError(
                        "EBPF_MAP_QUOTA",
                        "tenant %r is at its map quota" % tenant,
                    )

                current_bytes = sum(
                    item["max_entries"] * item["value_size"]
                    for item in tenant_maps.values()
                )
                additional_bytes = sum(
                    item["max_entries"] * item["value_size"]
                    for item in new_maps
                )
                if current_bytes + additional_bytes > quota["max_map_bytes"]:
                    raise EbpfError(
                        "EBPF_MAP_MEMORY",
                        "tenant %r exceeds its map byte budget" % tenant,
                    )

                namespace = self._maps.setdefault(tenant, {})
                for declaration in new_maps:
                    namespace[declaration["name"]] = {
                        "name": declaration["name"],
                        "max_entries": declaration["max_entries"],
                        "value_size": declaration["value_size"],
                        "refs": 0,
                        "data": {},
                    }
                for declaration in verified["maps"]:
                    namespace[declaration["name"]]["refs"] += 1

                program_id = self._next_id
                self._next_id += 1
                program = {
                    "id": program_id,
                    "name": verified["name"],
                    "type": verified["type"],
                    "tenant": tenant,
                    "instruction_count": verified["instruction_count"],
                    "maps": list(verified["map_names"]),
                    "attached": [],
                }
                self._programs[program_id] = program
                self._stats["loads"] += 1
                self._record(
                    "load",
                    tenant=tenant,
                    id=program_id,
                    name=program["name"],
                )
                return {
                    "id": program_id,
                    "name": program["name"],
                    "type": program["type"],
                    "instructions": program["instruction_count"],
                    "maps": list(program["maps"]),
                }
            except EbpfError as exc:
                self._stats["rejected"] += 1
                self._record(
                    "reject",
                    tenant=tenant,
                    code=exc.code,
                    detail=str(exc.detail) if exc.detail is not None else None,
                )
                raise

    def _get_program(self, program_id, tenant):
        if not self._is_int(program_id) or program_id not in self._programs:
            raise EbpfError(
                "EBPF_PROG_UNKNOWN", "program %r does not exist" % program_id
            )
        program = self._programs[program_id]
        if program["tenant"] != tenant:
            raise EbpfError(
                "EBPF_TENANT_MISMATCH",
                "program %d is not owned by tenant %r"
                % (program_id, tenant),
            )
        return program

    @staticmethod
    def _program_view(program):
        return {
            "id": program["id"],
            "name": program["name"],
            "type": program["type"],
            "tenant": program["tenant"],
            "instructions": program["instruction_count"],
            "maps": list(program["maps"]),
            "attached": list(program["attached"]),
        }

    def program_info(self, program_id, *, tenant="default"):
        with self._lock:
            tenant = self._tenant_name(tenant)
            return self._program_view(self._get_program(program_id, tenant))

    def programs(self, tenant="default"):
        with self._lock:
            tenant = self._tenant_name(tenant)
            return [
                self._program_view(program)
                for program in self._programs.values()
                if program["tenant"] == tenant
            ]

    def _get_map(self, name, tenant):
        if not isinstance(name, str):
            raise EbpfError("EBPF_MAP_UNKNOWN", "map name must be a string")
        namespace = self._maps.get(tenant, {})
        record = namespace.get(name)
        if record is None:
            raise EbpfError(
                "EBPF_MAP_UNKNOWN",
                "map %r does not exist for tenant %r" % (name, tenant),
            )
        return record

    @staticmethod
    def _map_view(record):
        return {
            "name": record["name"],
            "max_entries": record["max_entries"],
            "value_size": record["value_size"],
            "used": len(record["data"]),
            "refs": record["refs"],
            "bytes": record["max_entries"] * record["value_size"],
        }

    def maps(self, tenant="default"):
        with self._lock:
            tenant = self._tenant_name(tenant)
            return [
                self._map_view(record)
                for record in self._maps.get(tenant, {}).values()
            ]

    @staticmethod
    def _validate_key(key):
        if not isinstance(key, str) or not 1 <= len(key) <= 32:
            raise EbpfError(
                "EBPF_BAD_KEY", "key must contain between 1 and 32 characters"
            )

    def map_update(self, name, key, value, *, tenant="default"):
        with self._lock:
            tenant = self._tenant_name(tenant)
            try:
                record = self._get_map(name, tenant)
                self._validate_key(key)
                if not isinstance(value, str):
                    raise EbpfError("EBPF_BAD_VALUE", "value must be a string")
                try:
                    value_bytes = len(value.encode("utf-8"))
                except UnicodeEncodeError as exc:
                    raise EbpfError(
                        "EBPF_BAD_VALUE", "value is not valid UTF-8 text"
                    ) from exc
                if value_bytes > record["value_size"]:
                    raise EbpfError(
                        "EBPF_VALUE_TOO_LARGE",
                        "%d bytes exceed value_size %d"
                        % (value_bytes, record["value_size"]),
                    )

                created = key not in record["data"]
                if created and len(record["data"]) >= record["max_entries"]:
                    raise EbpfError(
                        "EBPF_MAP_FULL",
                        "map %r already contains %d entries"
                        % (record["name"], record["max_entries"]),
                    )

                record["data"][key] = value
                self._stats["map_updates"] += 1
                self._record(
                    "map_update",
                    tenant=tenant,
                    name=record["name"],
                    key=key,
                    used=len(record["data"]),
                    created=created,
                )
                return {
                    "name": record["name"],
                    "key": key,
                    "used": len(record["data"]),
                    "created": created,
                }
            except EbpfError as exc:
                self._stats["map_rejects"] += 1
                self._record(
                    "map_reject",
                    tenant=tenant,
                    name=name if isinstance(name, str) else repr(name),
                    code=exc.code,
                )
                raise

    def map_lookup(self, name, key, *, tenant="default"):
        with self._lock:
            tenant = self._tenant_name(tenant)
            record = self._get_map(name, tenant)
            self._validate_key(key)
            return record["data"].get(key)

    def attach(self, program_id, hook, *, tenant="default"):
        with self._lock:
            tenant = self._tenant_name(tenant)
            program = self._get_program(program_id, tenant)
            if not isinstance(hook, str) or not hook:
                raise EbpfError("EBPF_BAD_HOOK", "hook must be a non-empty string")
            if hook in self._hooks:
                self._stats["hook_busy"] += 1
                self._record(
                    "hook_busy",
                    tenant=tenant,
                    id=program_id,
                    hook=hook,
                )
                raise EbpfError(
                    "EBPF_HOOK_BUSY", "hook %r is already attached" % hook
                )

            self._hooks[hook] = program_id
            program["attached"].append(hook)
            self._stats["attaches"] += 1
            self._record(
                "attach", tenant=tenant, id=program_id, hook=hook
            )
            return {
                "id": program_id,
                "hook": hook,
                "attached": len(program["attached"]),
            }

    def detach(self, program_id, hook, *, tenant="default"):
        with self._lock:
            tenant = self._tenant_name(tenant)
            program = self._get_program(program_id, tenant)
            if not isinstance(hook, str) or not hook:
                raise EbpfError("EBPF_BAD_HOOK", "hook must be a non-empty string")
            if self._hooks.get(hook) != program_id:
                return False

            del self._hooks[hook]
            program["attached"].remove(hook)
            self._stats["detaches"] += 1
            self._record(
                "detach", tenant=tenant, id=program_id, hook=hook
            )
            return True

    def close_program(self, program_id, *, tenant="default"):
        with self._lock:
            tenant = self._tenant_name(tenant)
            program = self._get_program(program_id, tenant)

            detached = 0
            for hook in list(program["attached"]):
                if self._hooks.get(hook) == program_id:
                    del self._hooks[hook]
                detached += 1

            freed_maps = []
            namespace = self._maps.get(tenant, {})
            for map_name in program["maps"]:
                record = namespace.get(map_name)
                if record is None:
                    continue
                record["refs"] -= 1
                if record["refs"] <= 0:
                    del namespace[map_name]
                    freed_maps.append(map_name)

            del self._programs[program_id]
            self._stats["closed"] += 1
            self._record(
                "close",
                tenant=tenant,
                id=program_id,
                detached=detached,
                freed_maps=list(freed_maps),
            )
            return {"detached": detached, "freed_maps": freed_maps}

    def set_quota(self, tenant, *, max_programs=None, max_maps=None,
                  max_map_bytes=None):
        with self._lock:
            tenant = self._tenant_name(tenant)
            updates = {}
            for field, value in (
                ("max_programs", max_programs),
                ("max_maps", max_maps),
                ("max_map_bytes", max_map_bytes),
            ):
                if value is None:
                    continue
                if not self._is_int(value) or value < 0:
                    raise EbpfError(
                        "EBPF_BAD_QUOTA",
                        "%s must be a non-negative integer" % field,
                    )
                updates[field] = value

            quota = self._quota_for(tenant)
            quota.update(updates)
            self._tenant_quotas[tenant] = quota
            self._record("set_quota", tenant=tenant, **updates)
            return {"tenant": tenant, **quota}

    def stats(self):
        with self._lock:
            return dict(self._stats)

    def audit(self, limit=None):
        with self._lock:
            if limit is None:
                selected = self._audit
            else:
                if not self._is_int(limit) or limit < 0:
                    raise EbpfError("EBPF_BAD_INSN", "limit must be >= 0")
                selected = self._audit[-limit:] if limit else []
            return [dict(entry) for entry in selected]

    def snapshot(self):
        with self._lock:
            programs = []
            for program in self._programs.values():
                programs.append({
                    "id": program["id"],
                    "name": program["name"],
                    "type": program["type"],
                    "tenant": program["tenant"],
                    "instructions": program["instruction_count"],
                    "maps": list(program["maps"]),
                    "attached": list(program["attached"]),
                })

            maps = {}
            for tenant, namespace in self._maps.items():
                maps[tenant] = {}
                for name, record in namespace.items():
                    maps[tenant][name] = {
                        "max_entries": record["max_entries"],
                        "value_size": record["value_size"],
                        "refs": record["refs"],
                        "data": dict(record["data"]),
                    }

            payload = {
                "version": 1,
                "config": {
                    "max_instructions": self.max_instructions,
                    "max_programs": self.max_programs,
                    "max_maps": self.max_maps,
                    "max_map_bytes": self.max_map_bytes,
                    "audit_capacity": self.audit_capacity,
                },
                "next_id": self._next_id,
                "tenant_quotas": {
                    tenant: dict(quota)
                    for tenant, quota in self._tenant_quotas.items()
                },
                "programs": programs,
                "maps": maps,
                "hooks": dict(self._hooks),
                "stats": dict(self._stats),
                "audit": [dict(entry) for entry in self._audit],
            }
            return json.dumps(payload, ensure_ascii=False)

    @classmethod
    def restore(cls, data):
        try:
            if not isinstance(data, (str, bytes, bytearray)):
                raise ValueError("snapshot must be text")
            payload = json.loads(data)
            return cls._restore_payload(payload)
        except EbpfError as exc:
            if exc.code == "EBPF_SNAPSHOT_INVALID":
                raise
            raise EbpfError("EBPF_SNAPSHOT_INVALID", str(exc)) from exc
        except Exception as exc:
            raise EbpfError("EBPF_SNAPSHOT_INVALID", str(exc)) from exc

    @classmethod
    def _restore_payload(cls, payload):
        if not isinstance(payload, dict) or payload.get("version") != 1:
            raise EbpfError("EBPF_SNAPSHOT_INVALID", "unsupported snapshot")

        config = payload.get("config")
        if not isinstance(config, dict):
            raise EbpfError("EBPF_SNAPSHOT_INVALID", "missing config")
        instance = cls(
            max_instructions=config.get("max_instructions"),
            max_programs=config.get("max_programs"),
            max_maps=config.get("max_maps"),
            max_map_bytes=config.get("max_map_bytes"),
            audit_capacity=config.get("audit_capacity"),
        )

        raw_quotas = payload.get("tenant_quotas")
        if not isinstance(raw_quotas, dict):
            raise EbpfError("EBPF_SNAPSHOT_INVALID", "invalid tenant quotas")
        for tenant, quota in raw_quotas.items():
            if not isinstance(tenant, str) or not isinstance(quota, dict):
                raise EbpfError(
                    "EBPF_SNAPSHOT_INVALID", "invalid tenant quota entry"
                )
            normalized = {}
            for field in QUOTA_FIELDS:
                value = quota.get(field)
                if not instance._is_int(value) or value < 0:
                    raise EbpfError(
                        "EBPF_SNAPSHOT_INVALID",
                        "invalid quota %s for tenant %r" % (field, tenant),
                    )
                normalized[field] = value
            instance._tenant_quotas[tenant] = normalized

        raw_maps = payload.get("maps")
        if not isinstance(raw_maps, dict):
            raise EbpfError("EBPF_SNAPSHOT_INVALID", "invalid map table")
        for tenant, namespace in raw_maps.items():
            if not isinstance(tenant, str) or not isinstance(namespace, dict):
                raise EbpfError(
                    "EBPF_SNAPSHOT_INVALID", "invalid map namespace"
                )
            for name, record in namespace.items():
                if not isinstance(name, str) or not name or not isinstance(record, dict):
                    raise EbpfError(
                        "EBPF_SNAPSHOT_INVALID", "invalid map record"
                    )
                max_entries = record.get("max_entries")
                value_size = record.get("value_size")
                refs = record.get("refs")
                data = record.get("data")
                if (
                    not instance._is_int(max_entries)
                    or max_entries <= 0
                    or not instance._is_int(value_size)
                    or value_size <= 0
                    or not instance._is_int(refs)
                    or refs <= 0
                    or not isinstance(data, dict)
                ):
                    raise EbpfError(
                        "EBPF_SNAPSHOT_INVALID", "invalid map fields"
                    )
                if len(data) > max_entries:
                    raise EbpfError(
                        "EBPF_SNAPSHOT_INVALID", "map data exceeds max_entries"
                    )
                clean_data = {}
                for key, value in data.items():
                    if (
                        not isinstance(key, str)
                        or not 1 <= len(key) <= 32
                        or not isinstance(value, str)
                    ):
                        raise EbpfError(
                            "EBPF_SNAPSHOT_INVALID", "invalid map entry"
                        )
                    try:
                        value_bytes = len(value.encode("utf-8"))
                    except UnicodeEncodeError as exc:
                        raise EbpfError(
                            "EBPF_SNAPSHOT_INVALID", "invalid map value"
                        ) from exc
                    if value_bytes > value_size:
                        raise EbpfError(
                            "EBPF_SNAPSHOT_INVALID", "map value is too large"
                        )
                    clean_data[key] = value
                instance._maps.setdefault(tenant, {})[name] = {
                    "name": name,
                    "max_entries": max_entries,
                    "value_size": value_size,
                    "refs": refs,
                    "data": clean_data,
                }

        raw_programs = payload.get("programs")
        if not isinstance(raw_programs, list):
            raise EbpfError("EBPF_SNAPSHOT_INVALID", "invalid program table")
        for record in raw_programs:
            if not isinstance(record, dict):
                raise EbpfError(
                    "EBPF_SNAPSHOT_INVALID", "invalid program record"
                )
            program_id = record.get("id")
            name = record.get("name")
            program_type = record.get("type")
            tenant = record.get("tenant")
            instructions = record.get("instructions")
            map_names = record.get("maps")
            attached = record.get("attached")
            if (
                not instance._is_int(program_id)
                or program_id <= 0
                or program_id in instance._programs
                or not isinstance(name, str)
                or not name
                or program_type not in PROGRAM_TYPES
                or not isinstance(tenant, str)
                or not instance._is_int(instructions)
                or not 1 <= instructions <= instance.max_instructions
                or not isinstance(map_names, list)
                or len(set(map_names)) != len(map_names)
                or not all(isinstance(item, str) for item in map_names)
                or not isinstance(attached, list)
                or len(set(attached)) != len(attached)
                or not all(isinstance(item, str) and item for item in attached)
            ):
                raise EbpfError(
                    "EBPF_SNAPSHOT_INVALID", "invalid program fields"
                )
            namespace = instance._maps.get(tenant, {})
            if any(map_name not in namespace for map_name in map_names):
                raise EbpfError(
                    "EBPF_SNAPSHOT_INVALID", "program references a missing map"
                )
            instance._programs[program_id] = {
                "id": program_id,
                "name": name,
                "type": program_type,
                "tenant": tenant,
                "instruction_count": instructions,
                "maps": list(map_names),
                "attached": list(attached),
            }

        expected_refs = {
            (tenant, name): 0
            for tenant, namespace in instance._maps.items()
            for name in namespace
        }
        for program in instance._programs.values():
            for map_name in program["maps"]:
                expected_refs[(program["tenant"], map_name)] += 1
        for (tenant, name), refs in expected_refs.items():
            record = instance._maps[tenant][name]
            if record["refs"] != refs:
                raise EbpfError(
                    "EBPF_SNAPSHOT_INVALID", "map refcount does not match"
                )

        raw_hooks = payload.get("hooks")
        if not isinstance(raw_hooks, dict):
            raise EbpfError("EBPF_SNAPSHOT_INVALID", "invalid hook table")
        for hook, program_id in raw_hooks.items():
            if (
                not isinstance(hook, str)
                or not hook
                or not instance._is_int(program_id)
                or program_id not in instance._programs
                or hook not in instance._programs[program_id]["attached"]
            ):
                raise EbpfError(
                    "EBPF_SNAPSHOT_INVALID", "invalid hook record"
                )
            instance._hooks[hook] = program_id
        for program in instance._programs.values():
            for hook in program["attached"]:
                if instance._hooks.get(hook) != program["id"]:
                    raise EbpfError(
                        "EBPF_SNAPSHOT_INVALID", "program hook is not registered"
                    )

        raw_stats = payload.get("stats")
        if not isinstance(raw_stats, dict):
            raise EbpfError("EBPF_SNAPSHOT_INVALID", "invalid stats")
        for field in STATS_FIELDS:
            value = raw_stats.get(field)
            if not instance._is_int(value) or value < 0:
                raise EbpfError(
                    "EBPF_SNAPSHOT_INVALID", "invalid statistic %s" % field
                )
            instance._stats[field] = value

        raw_audit = payload.get("audit")
        if not isinstance(raw_audit, list) or not all(
            isinstance(entry, dict) for entry in raw_audit
        ):
            raise EbpfError("EBPF_SNAPSHOT_INVALID", "invalid audit log")
        if instance.audit_capacity:
            instance._audit = [
                dict(entry)
                for entry in raw_audit[-instance.audit_capacity:]
            ]
        else:
            instance._audit = []

        next_id = payload.get("next_id")
        if not instance._is_int(next_id) or next_id <= 0:
            raise EbpfError("EBPF_SNAPSHOT_INVALID", "invalid next id")
        maximum_id = max(instance._programs, default=0)
        instance._next_id = max(next_id, maximum_id + 1)
        return instance
