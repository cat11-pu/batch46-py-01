import hashlib
import json
import threading
from collections.abc import Sequence


class PipelineCacheError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class PipelineCache:
    """Content-addressed pipeline cache with compatibility groups and budgets."""

    _SNAPSHOT_VERSION = 3

    def __init__(self, *, entry_budget=64, byte_budget=None, generation=1):
        self.entry_budget = entry_budget
        self.byte_budget = byte_budget
        self.generation = generation

        self._lock = threading.RLock()
        self._definitions = {}
        self._group_map = {}
        self._next_group = 1
        self._entries = {}
        self._registered = {}
        self._hits = 0
        self._misses = 0
        self._evictions = 0
        self._sequence = 0

    @staticmethod
    def _raise(code, detail=None):
        raise PipelineCacheError(code, detail)

    @staticmethod
    def _copy_descriptor(descriptor):
        return {
            "vs": descriptor["vs"],
            "fs": descriptor["fs"],
            "blend": descriptor["blend"],
            "depth_test": descriptor["depth_test"],
            "depth_write": descriptor["depth_write"],
            "cull": descriptor["cull"],
            "topology": descriptor["topology"],
            "vertex_layout": [
                [name, value] for name, value in descriptor["vertex_layout"]
            ],
            "render_pass": descriptor["render_pass"],
            "layout": descriptor["layout"],
            "tags": list(descriptor["tags"]),
        }

    @classmethod
    def _normalize_descriptor(
        cls,
        *,
        vs,
        fs,
        blend,
        depth_test,
        depth_write,
        cull,
        topology,
        vertex_layout,
        render_pass,
        layout,
        tags,
    ):
        string_fields = {
            "vs": vs,
            "fs": fs,
            "blend": blend,
            "cull": cull,
            "topology": topology,
            "render_pass": render_pass,
            "layout": layout,
        }
        for field, value in string_fields.items():
            if not isinstance(value, str) or not value:
                cls._raise(
                    "PLC_DESCRIPTOR_INVALID",
                    f"{field} must be a non-empty string",
                )

        if not isinstance(depth_test, bool):
            cls._raise(
                "PLC_DESCRIPTOR_INVALID", "depth_test must be a boolean"
            )
        if not isinstance(depth_write, bool):
            cls._raise(
                "PLC_DESCRIPTOR_INVALID", "depth_write must be a boolean"
            )

        if isinstance(vertex_layout, (str, bytes)) or not isinstance(
            vertex_layout, Sequence
        ):
            cls._raise(
                "PLC_LAYOUT_INVALID", "vertex_layout must be a sequence"
            )

        attributes = []
        seen_names = set()
        for attribute in vertex_layout:
            if isinstance(attribute, (str, bytes)) or not isinstance(
                attribute, Sequence
            ):
                cls._raise(
                    "PLC_LAYOUT_INVALID",
                    "each vertex attribute must be a pair",
                )
            values = tuple(attribute)
            if len(values) != 2:
                cls._raise(
                    "PLC_LAYOUT_INVALID",
                    "each vertex attribute must have a name and type",
                )
            name, value = values
            if (
                not isinstance(name, str)
                or not name
                or not isinstance(value, str)
                or not value
            ):
                cls._raise(
                    "PLC_LAYOUT_INVALID",
                    "vertex attribute fields must be non-empty strings",
                )
            if name in seen_names:
                cls._raise(
                    "PLC_LAYOUT_INVALID",
                    f"duplicate vertex attribute {name!r}",
                )
            seen_names.add(name)
            attributes.append((name, value))
        attributes.sort()

        if isinstance(tags, (str, bytes)) or not isinstance(tags, Sequence):
            cls._raise(
                "PLC_DESCRIPTOR_INVALID", "tags must be a sequence"
            )
        normalized_tags = []
        for tag in tags:
            if not isinstance(tag, str):
                cls._raise(
                    "PLC_DESCRIPTOR_INVALID", "tags must contain only strings"
                )
            normalized_tags.append(tag)
        normalized_tags.sort()

        return {
            "vs": vs,
            "fs": fs,
            "blend": blend,
            "depth_test": depth_test,
            "depth_write": depth_write,
            "cull": cull,
            "topology": topology,
            "vertex_layout": attributes,
            "render_pass": render_pass,
            "layout": layout,
            "tags": normalized_tags,
        }

    @staticmethod
    def _hash_descriptor(descriptor):
        payload = json.dumps(
            descriptor,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]

    def _next_use(self):
        self._sequence += 1
        return self._sequence

    def _group_for(self, layout, render_pass):
        key = (layout, render_pass)
        group = self._group_map.get(key)
        if group is None:
            group = self._next_group
            self._next_group += 1
            self._group_map[key] = group
        return group

    def _total_bytes(self):
        return sum(
            len(entry["blob"])
            for entry in self._entries.values()
            if entry["blob"] is not None
        )

    def _registered_entry(self, pipeline_id):
        definition = self._definitions.get(pipeline_id)
        if definition is None:
            self._raise("PLC_UNKNOWN", f"unknown pipeline {pipeline_id!r}")

        pipeline_hash = self._registered.get(pipeline_id)
        if pipeline_hash is None:
            return definition, None

        entry = self._entries.get(pipeline_hash)
        if entry is None:
            self._registered.pop(pipeline_id, None)
            return definition, None
        return definition, entry

    def _remove_entry(self, pipeline_hash):
        entry = self._entries.pop(pipeline_hash, None)
        if entry is None:
            return None
        stale_ids = [
            pipeline_id
            for pipeline_id, registered_hash in self._registered.items()
            if registered_hash == pipeline_hash
        ]
        for pipeline_id in stale_ids:
            del self._registered[pipeline_id]
        return entry

    def define_pipeline(
        self,
        pipeline_id: str,
        *,
        vs: str,
        fs: str,
        blend: str = "opaque",
        depth_test: bool = True,
        depth_write: bool = True,
        cull: str = "back",
        topology: str = "tri",
        vertex_layout: Sequence[tuple[str, str]] = (),
        render_pass: str = "main",
        layout: str = "default",
        tags: Sequence[str] = (),
    ) -> dict:
        if not isinstance(pipeline_id, str) or not pipeline_id:
            self._raise("PLC_ID_INVALID", "pipeline_id must be a non-empty string")

        with self._lock:
            descriptor = self._normalize_descriptor(
                vs=vs,
                fs=fs,
                blend=blend,
                depth_test=depth_test,
                depth_write=depth_write,
                cull=cull,
                topology=topology,
                vertex_layout=vertex_layout,
                render_pass=render_pass,
                layout=layout,
                tags=tags,
            )
            pipeline_hash = self._hash_descriptor(descriptor)

            existing = self._definitions.get(pipeline_id)
            if existing is not None:
                if existing["descriptor"] != descriptor:
                    self._raise(
                        "PLC_ID_CONFLICT",
                        f"pipeline {pipeline_id!r} was already defined differently",
                    )
                return {
                    "id": pipeline_id,
                    "hash": existing["hash"],
                    "group": existing["group"],
                }

            group = self._group_for(
                descriptor["layout"], descriptor["render_pass"]
            )
            self._definitions[pipeline_id] = {
                "descriptor": descriptor,
                "hash": pipeline_hash,
                "group": group,
            }
            return {
                "id": pipeline_id,
                "hash": pipeline_hash,
                "group": group,
            }

    def register(self, pipeline_id: str) -> dict:
        with self._lock:
            definition = self._definitions.get(pipeline_id)
            if definition is None:
                self._raise("PLC_UNKNOWN", f"unknown pipeline {pipeline_id!r}")

            pipeline_hash = definition["hash"]
            current_hash = self._registered.get(pipeline_id)
            if current_hash is not None:
                entry = self._entries.get(current_hash)
                if entry is not None:
                    return {
                        "status": "duplicate",
                        "id": pipeline_id,
                        "hash": entry["hash"],
                        "group": entry["group"],
                        "generation": entry["generation"],
                    }
                self._registered.pop(pipeline_id, None)

            entry = self._entries.get(pipeline_hash)
            if entry is None:
                entry = {
                    "id": pipeline_id,
                    "descriptor": definition["descriptor"],
                    "hash": pipeline_hash,
                    "group": definition["group"],
                    "generation": self.generation,
                    "blob": None,
                    "last_used": self._next_use(),
                }
                self._entries[pipeline_hash] = entry
                status = "stored"
            else:
                status = "duplicate"

            self._registered[pipeline_id] = pipeline_hash
            return {
                "status": status,
                "id": pipeline_id,
                "hash": entry["hash"],
                "group": entry["group"],
                "generation": entry["generation"],
            }

    def get(self, pipeline_id: str) -> dict:
        with self._lock:
            definition = self._definitions.get(pipeline_id)
            if definition is None:
                self._raise("PLC_UNKNOWN", f"unknown pipeline {pipeline_id!r}")

            pipeline_hash = self._registered.get(pipeline_id)
            entry = (
                self._entries.get(pipeline_hash)
                if pipeline_hash is not None
                else None
            )
            if entry is None:
                if pipeline_hash is not None:
                    self._registered.pop(pipeline_id, None)
                self._misses += 1
                return {
                    "hit": False,
                    "bytes": 0,
                    "group": definition["group"],
                    "generation": self.generation,
                }

            entry["last_used"] = self._next_use()
            self._hits += 1
            return {
                "hit": True,
                "bytes": len(entry["blob"]) if entry["blob"] is not None else 0,
                "group": entry["group"],
                "generation": entry["generation"],
            }

    def store_blob(self, pipeline_id: str, blob: bytes) -> dict:
        with self._lock:
            _, entry = self._registered_entry(pipeline_id)
            if entry is None:
                self._raise(
                    "PLC_UNKNOWN", f"pipeline {pipeline_id!r} is not registered"
                )
            if not isinstance(blob, bytes) or not blob:
                self._raise(
                    "PLC_BLOB_INVALID", "blob must be a non-empty bytes value"
                )
            if self.byte_budget is not None and len(blob) > self.byte_budget:
                self._raise(
                    "PLC_BLOB_TOO_LARGE",
                    "blob exceeds the cache byte budget",
                )

            entry["blob"] = blob
            entry["last_used"] = self._next_use()
            return {
                "id": pipeline_id,
                "bytes": len(blob),
                "total_bytes": self._total_bytes(),
            }

    def blob(self, pipeline_id: str) -> bytes:
        with self._lock:
            _, entry = self._registered_entry(pipeline_id)
            if entry is None:
                self._raise(
                    "PLC_UNKNOWN", f"pipeline {pipeline_id!r} is not registered"
                )
            if entry["blob"] is None:
                self._raise(
                    "PLC_NO_BLOB", f"pipeline {pipeline_id!r} has no blob"
                )
            entry["last_used"] = self._next_use()
            return entry["blob"]

    def trim(self) -> dict:
        with self._lock:
            evicted = []
            while self._entries:
                over_entries = (
                    self.entry_budget is not None
                    and len(self._entries) > self.entry_budget
                )
                over_bytes = (
                    self.byte_budget is not None
                    and self._total_bytes() > self.byte_budget
                )
                if not over_entries and not over_bytes:
                    break

                oldest_hash = min(
                    self._entries,
                    key=lambda pipeline_hash: self._entries[pipeline_hash][
                        "last_used"
                    ],
                )
                entry = self._remove_entry(oldest_hash)
                evicted.append(entry["id"])
                self._evictions += 1

            return {
                "evicted": evicted,
                "entries": len(self._entries),
                "bytes": self._total_bytes(),
            }

    def compat_group(self, pipeline_id: str) -> int:
        with self._lock:
            definition = self._definitions.get(pipeline_id)
            if definition is None:
                self._raise("PLC_UNKNOWN", f"unknown pipeline {pipeline_id!r}")
            return definition["group"]

    def validate_bindings(self, pipeline_id: str, set_layout: str) -> dict:
        with self._lock:
            definition = self._definitions.get(pipeline_id)
            if definition is None:
                self._raise("PLC_UNKNOWN", f"unknown pipeline {pipeline_id!r}")
            descriptor = definition["descriptor"]
            if set_layout != descriptor["layout"]:
                self._raise(
                    "PLC_LAYOUT_MISMATCH",
                    f"set layout {set_layout!r} does not match "
                    f"{descriptor['layout']!r}",
                )
            return {
                "compatible": True,
                "layout": descriptor["layout"],
            }

    def invalidate_generation(self, new_generation: int) -> dict:
        with self._lock:
            if (
                not isinstance(new_generation, int)
                or isinstance(new_generation, bool)
                or new_generation <= self.generation
            ):
                self._raise(
                    "PLC_GENERATION_REGRESS",
                    "generation must strictly increase",
                )

            old_hashes = [
                pipeline_hash
                for pipeline_hash, entry in self._entries.items()
                if entry["generation"] < new_generation
            ]
            removed = [
                self._entries[pipeline_hash]["id"] for pipeline_hash in old_hashes
            ]
            for pipeline_hash in old_hashes:
                self._remove_entry(pipeline_hash)

            self.generation = new_generation
            return {
                "removed": removed,
                "entries": len(self._entries),
                "generation": self.generation,
            }

    def keys(self) -> list[str]:
        with self._lock:
            return [entry["id"] for entry in self._entries.values()]

    def stats(self) -> dict:
        with self._lock:
            return {
                "entries": len(self._entries),
                "bytes": self._total_bytes(),
                "hits": self._hits,
                "misses": self._misses,
                "evictions": self._evictions,
                "generation": self.generation,
            }

    def snapshot(self) -> dict:
        with self._lock:
            definitions = []
            for pipeline_id in sorted(self._definitions):
                definition = self._definitions[pipeline_id]
                definitions.append(
                    {
                        "id": pipeline_id,
                        "descriptor": self._copy_descriptor(
                            definition["descriptor"]
                        ),
                        "hash": definition["hash"],
                        "group": definition["group"],
                    }
                )

            groups = [
                {
                    "layout": layout,
                    "render_pass": render_pass,
                    "group": group,
                }
                for (layout, render_pass), group in sorted(
                    self._group_map.items(), key=lambda item: item[1]
                )
            ]

            entries = []
            for entry in self._entries.values():
                blob = entry["blob"]
                entries.append(
                    {
                        "id": entry["id"],
                        "descriptor": self._copy_descriptor(
                            entry["descriptor"]
                        ),
                        "hash": entry["hash"],
                        "group": entry["group"],
                        "generation": entry["generation"],
                        "bytes": len(blob) if blob is not None else 0,
                        "blob": blob.hex() if blob is not None else None,
                        "last_used": entry["last_used"],
                    }
                )

            registrations = [
                {"id": pipeline_id, "hash": pipeline_hash}
                for pipeline_id, pipeline_hash in self._registered.items()
            ]

            return {
                "version": self._SNAPSHOT_VERSION,
                "generation": self.generation,
                "definitions": definitions,
                "groups": groups,
                "entries": entries,
                "registrations": registrations,
                "stats": {
                    "hits": self._hits,
                    "misses": self._misses,
                    "evictions": self._evictions,
                },
            }

    def restore(self, state: dict) -> dict:
        def invalid(detail):
            return PipelineCacheError("PLC_SNAPSHOT_INVALID", detail)

        with self._lock:
            try:
                if not isinstance(state, dict):
                    raise invalid("snapshot must be a dictionary")
                version = state.get("version")
                if (
                    not isinstance(version, int)
                    or isinstance(version, bool)
                    or version != self._SNAPSHOT_VERSION
                ):
                    raise invalid("unsupported snapshot version")

                generation = state.get("generation")
                if (
                    not isinstance(generation, int)
                    or isinstance(generation, bool)
                    or generation < 1
                ):
                    raise invalid("invalid snapshot generation")

                raw_definitions = state.get("definitions")
                raw_groups = state.get("groups")
                raw_entries = state.get("entries")
                raw_registrations = state.get("registrations")
                raw_stats = state.get("stats")
                if (
                    not isinstance(raw_definitions, list)
                    or not isinstance(raw_groups, list)
                    or not isinstance(raw_entries, list)
                    or not isinstance(raw_registrations, list)
                    or not isinstance(raw_stats, dict)
                ):
                    raise invalid("invalid snapshot structure")

                new_definitions = {}
                for item in raw_definitions:
                    if not isinstance(item, dict):
                        raise invalid("invalid definition record")
                    pipeline_id = item.get("id")
                    descriptor = item.get("descriptor")
                    stored_hash = item.get("hash")
                    group = item.get("group")
                    if (
                        not isinstance(pipeline_id, str)
                        or not pipeline_id
                        or not isinstance(descriptor, dict)
                        or not isinstance(stored_hash, str)
                        or not isinstance(group, int)
                        or isinstance(group, bool)
                        or group < 1
                    ):
                        raise invalid("invalid definition record")
                    if pipeline_id in new_definitions:
                        raise invalid("duplicate definition id")
                    try:
                        normalized = self._normalize_descriptor(
                            vs=descriptor.get("vs"),
                            fs=descriptor.get("fs"),
                            blend=descriptor.get("blend"),
                            depth_test=descriptor.get("depth_test"),
                            depth_write=descriptor.get("depth_write"),
                            cull=descriptor.get("cull"),
                            topology=descriptor.get("topology"),
                            vertex_layout=descriptor.get("vertex_layout"),
                            render_pass=descriptor.get("render_pass"),
                            layout=descriptor.get("layout"),
                            tags=descriptor.get("tags"),
                        )
                    except PipelineCacheError as exc:
                        raise invalid(
                            f"invalid definition descriptor: {exc.code}"
                        )
                    recomputed = self._hash_descriptor(normalized)
                    if stored_hash != recomputed:
                        raise PipelineCacheError(
                            "PLC_HASH_MISMATCH",
                            f"definition hash mismatch for {pipeline_id!r}",
                        )
                    new_definitions[pipeline_id] = {
                        "descriptor": normalized,
                        "hash": recomputed,
                        "group": group,
                    }

                new_group_map = {}
                used_groups = set()
                for item in raw_groups:
                    if not isinstance(item, dict):
                        raise invalid("invalid group record")
                    layout = item.get("layout")
                    render_pass = item.get("render_pass")
                    group = item.get("group")
                    if (
                        not isinstance(layout, str)
                        or not layout
                        or not isinstance(render_pass, str)
                        or not render_pass
                        or not isinstance(group, int)
                        or isinstance(group, bool)
                        or group < 1
                    ):
                        raise invalid("invalid group record")
                    key = (layout, render_pass)
                    if key in new_group_map or group in used_groups:
                        raise invalid("duplicate compatibility group")
                    new_group_map[key] = group
                    used_groups.add(group)

                for definition in new_definitions.values():
                    key = (
                        definition["descriptor"]["layout"],
                        definition["descriptor"]["render_pass"],
                    )
                    if new_group_map.get(key) != definition["group"]:
                        raise invalid("definition group mapping is inconsistent")

                new_entries = {}
                for item in raw_entries:
                    if not isinstance(item, dict):
                        raise invalid("invalid entry record")
                    pipeline_id = item.get("id")
                    descriptor = item.get("descriptor")
                    stored_hash = item.get("hash")
                    group = item.get("group")
                    entry_generation = item.get("generation")
                    declared_bytes = item.get("bytes")
                    blob_hex = item.get("blob")
                    last_used = item.get("last_used")
                    if (
                        not isinstance(pipeline_id, str)
                        or not pipeline_id
                        or not isinstance(descriptor, dict)
                        or not isinstance(stored_hash, str)
                        or not isinstance(group, int)
                        or isinstance(group, bool)
                        or group < 1
                        or not isinstance(entry_generation, int)
                        or isinstance(entry_generation, bool)
                        or entry_generation < 1
                        or not isinstance(declared_bytes, int)
                        or isinstance(declared_bytes, bool)
                        or declared_bytes < 0
                        or not isinstance(last_used, int)
                        or isinstance(last_used, bool)
                        or last_used < 0
                    ):
                        raise invalid("invalid entry record")
                    try:
                        normalized = self._normalize_descriptor(
                            vs=descriptor.get("vs"),
                            fs=descriptor.get("fs"),
                            blend=descriptor.get("blend"),
                            depth_test=descriptor.get("depth_test"),
                            depth_write=descriptor.get("depth_write"),
                            cull=descriptor.get("cull"),
                            topology=descriptor.get("topology"),
                            vertex_layout=descriptor.get("vertex_layout"),
                            render_pass=descriptor.get("render_pass"),
                            layout=descriptor.get("layout"),
                            tags=descriptor.get("tags"),
                        )
                    except PipelineCacheError as exc:
                        raise invalid(f"invalid entry descriptor: {exc.code}")
                    recomputed = self._hash_descriptor(normalized)
                    if stored_hash != recomputed:
                        raise PipelineCacheError(
                            "PLC_HASH_MISMATCH",
                            f"entry hash mismatch for {pipeline_id!r}",
                        )
                    if recomputed in new_entries:
                        raise invalid("duplicate entry hash")

                    if blob_hex is None:
                        blob = None
                    elif isinstance(blob_hex, str):
                        try:
                            blob = bytes.fromhex(blob_hex)
                        except ValueError:
                            raise invalid("invalid hexadecimal blob")
                        if not blob:
                            raise invalid("empty snapshot blob")
                    else:
                        raise invalid("invalid snapshot blob")

                    actual_bytes = len(blob) if blob is not None else 0
                    if declared_bytes != actual_bytes:
                        raise invalid("entry byte count is inconsistent")

                    definition = new_definitions.get(pipeline_id)
                    if (
                        definition is None
                        or definition["hash"] != recomputed
                        or definition["group"] != group
                    ):
                        raise invalid("entry does not match its definition")

                    new_entries[recomputed] = {
                        "id": pipeline_id,
                        "descriptor": normalized,
                        "hash": recomputed,
                        "group": group,
                        "generation": entry_generation,
                        "blob": blob,
                        "last_used": last_used,
                    }

                new_registered = {}
                for item in raw_registrations:
                    if not isinstance(item, dict):
                        raise invalid("invalid registration record")
                    pipeline_id = item.get("id")
                    pipeline_hash = item.get("hash")
                    if (
                        not isinstance(pipeline_id, str)
                        or not isinstance(pipeline_hash, str)
                        or pipeline_id in new_registered
                    ):
                        raise invalid("invalid registration record")
                    definition = new_definitions.get(pipeline_id)
                    if (
                        definition is None
                        or definition["hash"] != pipeline_hash
                        or pipeline_hash not in new_entries
                    ):
                        raise invalid("registration does not match an entry")
                    new_registered[pipeline_id] = pipeline_hash

                for entry in new_entries.values():
                    if new_registered.get(entry["id"]) != entry["hash"]:
                        raise invalid("entry is missing its canonical registration")

                stats = {}
                for key in ("hits", "misses", "evictions"):
                    value = raw_stats.get(key)
                    if (
                        not isinstance(value, int)
                        or isinstance(value, bool)
                        or value < 0
                    ):
                        raise invalid("invalid snapshot statistics")
                    stats[key] = value

            except PipelineCacheError as exc:
                if exc.code == "PLC_HASH_MISMATCH":
                    raise
                if exc.code == "PLC_SNAPSHOT_INVALID":
                    raise
                raise invalid(str(exc))
            except (KeyError, TypeError, ValueError, AttributeError) as exc:
                raise invalid(str(exc))

            self._definitions = new_definitions
            self._group_map = new_group_map
            self._next_group = max(
                self._next_group, max(used_groups, default=0) + 1
            )
            self._entries = new_entries
            self._registered = new_registered
            self._hits = stats["hits"]
            self._misses = stats["misses"]
            self._evictions = stats["evictions"]
            self._sequence = max(
                self._sequence,
                max(
                    (entry["last_used"] for entry in new_entries.values()),
                    default=0,
                ),
            )
            self.generation = max(self.generation, generation)

            return {
                "restored": len(new_entries),
                "generation": self.generation,
            }
