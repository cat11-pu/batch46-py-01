"""Transactional SELinux boolean, context and relabel guard.

The guard keeps committed policy state separate from the staged state.  All
operations are serialised by a re-entrant lock so a commit is atomic with
respect to readers and other writers.
"""

from __future__ import annotations

import copy
import posixpath
import threading


class SelinuxError(ValueError):
    """Structured error carrying a machine-readable SELinux error code."""

    def __init__(self, code: str, detail=None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


# Common aliases make the error easy to import from small test harnesses.
SelinuxGuardError = SelinuxError
GuardError = SelinuxError
Error = SelinuxError

VALID_MODES = ("enforcing", "permissive", "disabled")


class _Provenance(str):
    """A string that also compares equal to useful provenance aliases."""

    def __new__(cls, value, *aliases):
        obj = super().__new__(cls, value)
        obj._aliases = aliases
        return obj

    def __eq__(self, other):
        return str.__eq__(self, other) or other in self._aliases

    def __hash__(self):
        return str.__hash__(self)


class SelinuxGuard:
    """Manage booleans, context rules and labels with atomic commits."""

    def __init__(
        self,
        max_booleans: int = 128,
        max_context_rules: int = 128,
        max_audit: int = 100,
        mode: str = "enforcing",
        **kwargs,
    ) -> None:
        if "max_bools" in kwargs:
            max_booleans = kwargs["max_bools"]
        if "max_rules" in kwargs:
            max_context_rules = kwargs["max_rules"]
        if "audit_limit" in kwargs:
            max_audit = kwargs["audit_limit"]
        if "max_audit_entries" in kwargs:
            max_audit = kwargs["max_audit_entries"]

        if type(max_booleans) is not int or max_booleans < 0:
            raise SelinuxError("SELINUX_VALUE_INVALID", "max_booleans")
        if type(max_context_rules) is not int or max_context_rules < 0:
            raise SelinuxError("SELINUX_VALUE_INVALID", "max_context_rules")
        if type(max_audit) is not int or max_audit < 0:
            raise SelinuxError("SELINUX_VALUE_INVALID", "max_audit")
        if mode not in VALID_MODES:
            raise SelinuxError("SELINUX_MODE_INVALID", mode)

        self._lock = threading.RLock()
        self.max_booleans = max_booleans
        self.max_context_rules = max_context_rules
        self.max_audit = max_audit

        self._booleans: dict[str, dict] = {}
        self._pending: dict[str, dict] = {}
        self._context_rules: list[dict] = []
        self._labels: dict[str, dict] = {}
        self._mode = mode
        self._policy_version = 0
        self._audit: list[dict] = []
        self._seq = 0
        self._audit_seq = 0

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _clean_path(value) -> str:
        if not isinstance(value, str) or not value.startswith("/"):
            raise SelinuxError("SELINUX_CONTEXT_UNKNOWN", value)
        cleaned = posixpath.normpath(value)
        if cleaned != value:
            raise SelinuxError("SELINUX_CONTEXT_UNKNOWN", value)
        return cleaned

    @staticmethod
    def _normalise_requires(name: str, requires):
        if requires is None:
            return None
        if isinstance(requires, str):
            requires = (requires, True)
        elif isinstance(requires, (list, tuple)):
            if len(requires) == 1:
                requires = (requires[0], True)
            elif len(requires) != 2:
                raise SelinuxError("SELINUX_VALUE_INVALID", "requires")
        else:
            raise SelinuxError("SELINUX_VALUE_INVALID", "requires")

        dep, expected = requires
        if not isinstance(dep, str) or not dep:
            raise SelinuxError("SELINUX_VALUE_INVALID", "requires")
        if type(expected) is not bool:
            raise SelinuxError("SELINUX_VALUE_INVALID", "requires")
        if dep == name:
            raise SelinuxError("SELINUX_DEPENDENCY_CYCLE", name)
        return (dep, expected)

    def _record(self, action: str, **fields) -> None:
        entry = {"seq": self._seq, "action": action, "event": action}
        self._seq += 1
        entry.update(fields)
        self._audit.append(entry)
        if self.max_audit == 0:
            self._audit.clear()
        elif len(self._audit) > self.max_audit:
            del self._audit[: len(self._audit) - self.max_audit]

    def _pending_names(self) -> list[str]:
        return sorted(self._pending)

    @staticmethod
    def _copy_rule(rule: dict) -> dict:
        return copy.deepcopy(rule)

    def _bool_view(self, name: str, persistent: bool = False) -> dict:
        record = self._booleans[name]
        pending = self._pending.get(name)
        runtime_value = record["value"]
        persistent_value = record.get("persistent_value")
        value = persistent_value if persistent else runtime_value
        return {
            "status": "ok",
            "ok": True,
            "name": name,
            "value": value,
            "runtime_value": runtime_value,
            "persistent_value": persistent_value,
            "persistent": record["persistent"],
            "persistent_allowed": record["persistent"],
            "pending": pending["value"] if pending is not None else None,
            "pending_persistent": (
                pending["persistent"] if pending is not None else None
            ),
            "policy_version": self._policy_version,
            "revision": record.get("revision", 0),
        }

    @staticmethod
    def _is_prefix(rule_path: str, target: str) -> bool:
        if rule_path == "/":
            return target.startswith("/")
        base = rule_path.rstrip("/")
        return target == base or target.startswith(base + "/")

    def _resolve(self, target: str) -> dict:
        matches = [
            rule for rule in self._context_rules
            if self._is_prefix(rule["path"], target)
        ]
        if not matches:
            raise SelinuxError("SELINUX_CONTEXT_UNKNOWN", target)

        best_priority = max(rule["priority"] for rule in matches)
        matches = [r for r in matches if r["priority"] == best_priority]
        best_length = max(len(r["path"].rstrip("/")) for r in matches)
        finalists = [
            r for r in matches
            if len(r["path"].rstrip("/")) == best_length
        ]
        contexts = {r["context"] for r in finalists}
        if len(contexts) > 1:
            raise SelinuxError("SELINUX_CONTEXT_CONFLICT", target)

        rule = finalists[0]
        matched = _Provenance("rule", rule["path"], "context_rule")
        return {
            "status": "ok",
            "ok": True,
            "path": target,
            "context": rule["context"],
            "priority": rule["priority"],
            "rule_path": rule["path"],
            "matched": matched,
            "matched_path": rule["path"],
            "source": "rule",
            "rule": self._copy_rule(rule),
        }

    # ------------------------------------------------------------------
    # Boolean lifecycle
    # ------------------------------------------------------------------
    def define_boolean(
        self,
        name: str,
        *,
        default: bool = False,
        persistent: bool = False,
        requires: tuple[str, bool] | None = None,
        description: str | None = None,
    ) -> dict:
        with self._lock:
            if not isinstance(name, str) or not name:
                raise SelinuxError("SELINUX_VALUE_INVALID", "name")
            if type(default) is not bool:
                raise SelinuxError("SELINUX_VALUE_INVALID", "default")
            if type(persistent) is not bool:
                raise SelinuxError("SELINUX_VALUE_INVALID", "persistent")
            if description is not None and not isinstance(description, str):
                raise SelinuxError("SELINUX_VALUE_INVALID", "description")
            if name in self._booleans:
                raise SelinuxError("SELINUX_DUP_BOOLEAN", name)

            normalized_requires = self._normalise_requires(name, requires)
            if normalized_requires is not None:
                dep = normalized_requires[0]
                if dep not in self._booleans:
                    raise SelinuxError("SELINUX_UNKNOWN_BOOLEAN", dep)
                seen = set()
                cursor = dep
                while cursor is not None:
                    if cursor == name or cursor in seen:
                        raise SelinuxError("SELINUX_DEPENDENCY_CYCLE", name)
                    seen.add(cursor)
                    parent = self._booleans[cursor].get("requires")
                    if not parent:
                        break
                    cursor = parent[0]

            if len(self._booleans) >= self.max_booleans:
                raise SelinuxError("SELINUX_LIMIT", "max_booleans")

            record = {
                "name": name,
                "default": default,
                "persistent": persistent,
                "requires": normalized_requires,
                "description": description,
                "value": default,
                "runtime_value": default,
                "persistent_value": default if persistent else None,
                "revision": 0,
            }
            self._booleans[name] = record
            self._record(
                "define_boolean",
                name=name,
                value=default,
                default=default,
                persistent=persistent,
                requires=normalized_requires,
                description=description,
            )
            return {
                "status": "defined",
                "ok": True,
                "name": name,
                "value": default,
                "default": default,
                "persistent": persistent,
                "persistent_value": record["persistent_value"],
                "requires": normalized_requires,
                "description": description,
            }

    def set_boolean(
        self, name: str, value: bool, *, persistent: bool = False
    ) -> dict:
        with self._lock:
            if self._mode == "disabled":
                raise SelinuxError("SELINUX_DISABLED", name)
            if name not in self._booleans:
                raise SelinuxError("SELINUX_UNKNOWN_BOOLEAN", name)
            if type(value) is not bool:
                raise SelinuxError("SELINUX_VALUE_INVALID", name)
            if type(persistent) is not bool:
                raise SelinuxError("SELINUX_VALUE_INVALID", "persistent")

            record = self._booleans[name]
            if persistent and not record["persistent"]:
                raise SelinuxError("SELINUX_NOT_PERSISTENT", name)

            current_persisted = record.get("persistent_value")
            changed = value != record["value"] or (
                persistent and current_persisted != value
            )
            if not changed:
                cancelled = name in self._pending
                self._pending.pop(name, None)
                if cancelled:
                    self._record(
                        "cancel_boolean",
                        name=name,
                        value=value,
                        persistent=persistent,
                    )
                return {
                    "status": "cancelled",
                    "ok": True,
                    "name": name,
                    "value": record["value"],
                    "persistent": record["persistent"],
                    "pending": None,
                    "pending_changes": self.pending_changes(),
                    "policy_version": self._policy_version,
                }

            self._pending[name] = {
                "name": name,
                "value": value,
                "persistent": persistent,
                "old_value": record["value"],
                "old_persistent_value": current_persisted,
            }
            self._record(
                "stage_boolean",
                name=name,
                value=value,
                persistent=persistent,
                old_value=record["value"],
            )
            return {
                "status": "pending",
                "ok": True,
                "name": name,
                "value": value,
                "persistent": persistent,
                "pending": value,
                "pending_changes": self.pending_changes(),
                "policy_version": self._policy_version,
            }

    def get_boolean(self, name: str, *, persistent: bool = False) -> dict:
        with self._lock:
            if name not in self._booleans:
                raise SelinuxError("SELINUX_UNKNOWN_BOOLEAN", name)
            return self._bool_view(name, persistent=persistent)

    def pending_changes(self) -> list[dict]:
        with self._lock:
            return [
                {
                    **copy.deepcopy(self._pending[name]),
                    "expected_policy_version": self._policy_version,
                }
                for name in self._pending_names()
            ]

    def commit(self, *, policy_version: int | None = None) -> dict:
        with self._lock:
            if self._mode == "disabled":
                raise SelinuxError("SELINUX_DISABLED", "commit")

            # An empty staging area wins over a stale expected version: two
            # callers racing on the same batch must report one applied and one
            # empty, even when both supplied the same expected version.
            if not self._pending:
                return {
                    "status": "empty",
                    "ok": True,
                    "applied": [],
                    "changes": [],
                    "pending": [],
                    "policy_version": self._policy_version,
                    "version": self._policy_version,
                }

            if policy_version is not None:
                if type(policy_version) is not int:
                    raise SelinuxError("SELINUX_POLICY_MISMATCH", policy_version)
                if policy_version != self._policy_version:
                    raise SelinuxError("SELINUX_POLICY_MISMATCH", policy_version)

            # Validate the complete post-commit dependency graph before any
            # state is touched.  This keeps a failed batch fully staged.
            final_values = {
                name: record["value"]
                for name, record in self._booleans.items()
            }
            for name, change in self._pending.items():
                final_values[name] = change["value"]

            for name, record in self._booleans.items():
                requires = record.get("requires")
                if requires is None or not final_values.get(name, False):
                    continue
                dep, expected = requires
                if final_values.get(dep, False) != expected:
                    raise SelinuxError(
                        "SELINUX_DEPENDENCY_UNMET",
                        {"name": name, "requires": dep, "expected": expected},
                    )

            names = self._pending_names()
            changes = []
            for name in names:
                staged = self._pending[name]
                record = self._booleans[name]
                old_value = record["value"]
                old_persisted = record.get("persistent_value")
                record["value"] = staged["value"]
                record["runtime_value"] = staged["value"]
                if staged["persistent"]:
                    record["persistent_value"] = staged["value"]
                record["revision"] = record.get("revision", 0) + 1
                changes.append(
                    {
                        "name": name,
                        "value": staged["value"],
                        "new_value": staged["value"],
                        "old_value": old_value,
                        "persistent": staged["persistent"],
                        "persistent_value": record.get("persistent_value"),
                        "old_persistent_value": old_persisted,
                    }
                )

            self._pending.clear()
            self._policy_version += 1
            self._record(
                "commit",
                policy_version=self._policy_version,
                changes=copy.deepcopy(changes),
                names=list(names),
            )
            return {
                "status": "applied",
                "ok": True,
                "applied": list(names),
                "bools": copy.deepcopy(changes),
                "changes": changes,
                "pending": [],
                "policy_version": self._policy_version,
                "version": self._policy_version,
            }

    def abort(self) -> dict:
        with self._lock:
            dropped = len(self._pending)
            names = self._pending_names()
            self._pending.clear()
            if dropped:
                self._record("abort", dropped=dropped, names=names)
            return {
                "status": "aborted",
                "ok": True,
                "dropped": dropped,
                "names": names,
                "pending": [],
                "pending_changes": [],
                "policy_version": self._policy_version,
            }

    # ------------------------------------------------------------------
    # SELinux mode
    # ------------------------------------------------------------------
    def mode(self) -> str:
        with self._lock:
            return self._mode

    def set_mode(self, mode: str) -> dict:
        with self._lock:
            if mode not in VALID_MODES:
                raise SelinuxError("SELINUX_MODE_INVALID", mode)
            if mode == self._mode:
                return {
                    "status": "unchanged",
                    "ok": True,
                    "mode": self._mode,
                    "previous_mode": self._mode,
                }
            if mode == "disabled" and self._pending:
                raise SelinuxError("SELINUX_BUSY", mode)

            previous = self._mode
            self._mode = mode
            self._record("set_mode", mode=mode, previous_mode=previous)
            return {
                "status": "changed",
                "ok": True,
                "mode": self._mode,
                "previous_mode": previous,
            }

    # ------------------------------------------------------------------
    # Context rules and labels
    # ------------------------------------------------------------------
    def add_context_rule(
        self, path: str, context: str, *, priority: int = 100
    ) -> dict:
        with self._lock:
            cleaned = self._clean_path(path)
            if not isinstance(context, str) or not context:
                raise SelinuxError("SELINUX_VALUE_INVALID", "context")
            if type(priority) is not int:
                raise SelinuxError("SELINUX_VALUE_INVALID", "priority")

            for rule in self._context_rules:
                if (
                    rule["path"] == cleaned
                    and rule["priority"] == priority
                    and rule["context"] == context
                ):
                    return {
                        "status": "unchanged",
                        "ok": True,
                        "path": cleaned,
                        "context": context,
                        "priority": priority,
                        "rule_path": cleaned,
                        "source": "rule",
                    }

            if len(self._context_rules) >= self.max_context_rules:
                raise SelinuxError("SELINUX_LIMIT", "max_context_rules")

            rule = {
                "path": cleaned,
                "context": context,
                "priority": priority,
            }
            self._context_rules.append(rule)
            self._record(
                "add_context_rule",
                path=cleaned,
                context=context,
                priority=priority,
            )
            return {
                "status": "added",
                "ok": True,
                "path": cleaned,
                "context": context,
                "priority": priority,
                "rule_path": cleaned,
                "source": "rule",
                "rule": self._copy_rule(rule),
            }

    def resolve_context(self, path: str) -> dict:
        with self._lock:
            if not isinstance(path, str) or not path:
                raise SelinuxError("SELINUX_CONTEXT_UNKNOWN", path)
            target = posixpath.normpath(path) if path.startswith("/") else path
            return self._resolve(target)

    def relabel(self, path: str, context: str) -> dict:
        with self._lock:
            if not isinstance(context, str) or not context:
                raise SelinuxError("SELINUX_VALUE_INVALID", "context")
            target = self._clean_path(path)
            resolved = self._resolve(target)
            self._labels[target] = {
                "path": target,
                "context": context,
                "source": "relabel",
                "rule_path": resolved["rule_path"],
                "priority": resolved["priority"],
            }
            self._record(
                "relabel",
                path=target,
                context=context,
                rule_path=resolved["rule_path"],
            )
            return {
                "status": "relabeled",
                "ok": True,
                "path": target,
                "context": context,
                "priority": resolved["priority"],
                "rule_path": resolved["rule_path"],
                "matched": _Provenance("relabel", target, "label"),
                "source": "relabel",
            }

    def label_of(self, path: str) -> dict:
        with self._lock:
            if not isinstance(path, str) or not path:
                raise SelinuxError("SELINUX_CONTEXT_UNKNOWN", path)
            target = posixpath.normpath(path) if path.startswith("/") else path
            label = self._labels.get(target)
            if label is not None:
                return {
                    "status": "ok",
                    "ok": True,
                    "path": target,
                    "context": label["context"],
                    "priority": label.get("priority"),
                    "rule_path": label.get("rule_path"),
                    "matched": _Provenance("relabel", target, "label"),
                    "source": "relabel",
                }
            resolved = self._resolve(target)
            resolved["status"] = "ok"
            resolved["ok"] = True
            return resolved

    # ------------------------------------------------------------------
    # Snapshot / restore
    # ------------------------------------------------------------------
    def snapshot(self) -> dict:
        with self._lock:
            booleans = copy.deepcopy(self._booleans)
            pending = copy.deepcopy(self._pending)
            rules = copy.deepcopy(self._context_rules)
            labels = copy.deepcopy(self._labels)
            audit = copy.deepcopy(self._audit)
            return {
                "version": 1,
                "booleans": booleans,
                "boolean": booleans,
                "bools": booleans,
                "pending": pending,
                "pending_changes": pending,
                "context_rules": rules,
                "rules": rules,
                "labels": labels,
                "relabels": labels,
                "mode": self._mode,
                "policy_version": self._policy_version,
                "audit": audit,
                "seq": self._seq,
                "audit_seq": self._audit_seq,
            }

    def restore(self, snapshot: dict) -> dict:
        with self._lock:
            try:
                new_state = self._parse_snapshot(snapshot)
            except SelinuxError as exc:
                if exc.code == "SELINUX_SNAPSHOT_INVALID":
                    raise
                raise SelinuxError("SELINUX_SNAPSHOT_INVALID", exc.detail) from exc
            except Exception as exc:  # pragma: no cover - defensive conversion
                raise SelinuxError("SELINUX_SNAPSHOT_INVALID", str(exc)) from exc

            (
                booleans,
                pending,
                rules,
                labels,
                mode,
                policy_version,
                audit,
                seq,
            ) = new_state
            self._booleans = booleans
            self._pending = pending
            self._context_rules = rules
            self._labels = labels
            self._mode = mode
            self._policy_version = policy_version
            self._audit = audit
            self._seq = seq
            self._audit_seq = audit[-1]["seq"] + 1 if audit else 0
            return {
                "status": "restored",
                "ok": True,
                "mode": mode,
                "policy_version": policy_version,
                "pending": self._pending_names(),
                "booleans": len(booleans),
                "context_rules": len(rules),
            }

    def _parse_snapshot(self, snapshot):
        if not isinstance(snapshot, dict):
            raise SelinuxError("SELINUX_SNAPSHOT_INVALID", "not a dict")
        if snapshot.get("version", 1) != 1:
            raise SelinuxError("SELINUX_SNAPSHOT_INVALID", "version")

        source = snapshot.get(
            "booleans", snapshot.get("boolean", snapshot.get("bools"))
        )
        if source is None or not isinstance(source, dict):
            raise SelinuxError("SELINUX_SNAPSHOT_INVALID", "booleans")
        if len(source) > self.max_booleans:
            raise SelinuxError("SELINUX_SNAPSHOT_INVALID", "too many booleans")

        booleans: dict[str, dict] = {}
        for raw_name, raw in source.items():
            if not isinstance(raw_name, str) or not raw_name:
                raise SelinuxError("SELINUX_SNAPSHOT_INVALID", "name")
            if isinstance(raw, bool):
                raw = {"value": raw, "default": raw}
            if not isinstance(raw, dict):
                raise SelinuxError("SELINUX_SNAPSHOT_INVALID", raw_name)

            default = raw.get("default", raw.get("default_value", raw.get("value", False)))
            if type(default) is not bool:
                raise SelinuxError("SELINUX_SNAPSHOT_INVALID", raw_name)
            persistent = raw.get("persistent", raw.get("persistent_allowed", False))
            if type(persistent) is not bool:
                raise SelinuxError("SELINUX_SNAPSHOT_INVALID", raw_name)
            value = raw.get("value", raw.get("runtime_value", default))
            if type(value) is not bool:
                raise SelinuxError("SELINUX_SNAPSHOT_INVALID", raw_name)
            persistent_value = raw.get("persistent_value")
            if persistent_value is None and persistent:
                persistent_value = default
            if persistent_value is not None and type(persistent_value) is not bool:
                raise SelinuxError("SELINUX_SNAPSHOT_INVALID", raw_name)
            if not persistent:
                persistent_value = None

            requires = raw.get("requires")
            if requires is not None:
                if isinstance(requires, str):
                    requires = (requires, True)
                elif isinstance(requires, (list, tuple)):
                    if len(requires) == 1:
                        requires = (requires[0], True)
                    elif len(requires) != 2:
                        raise SelinuxError("SELINUX_SNAPSHOT_INVALID", raw_name)
                else:
                    raise SelinuxError("SELINUX_SNAPSHOT_INVALID", raw_name)
                if (
                    not isinstance(requires[0], str)
                    or not requires[0]
                    or type(requires[1]) is not bool
                ):
                    raise SelinuxError("SELINUX_SNAPSHOT_INVALID", raw_name)
                requires = (requires[0], requires[1])

            revision = raw.get("revision", 0)
            if type(revision) is not int or revision < 0:
                raise SelinuxError("SELINUX_SNAPSHOT_INVALID", raw_name)
            description = raw.get("description")
            if description is not None and not isinstance(description, str):
                raise SelinuxError("SELINUX_SNAPSHOT_INVALID", raw_name)

            booleans[raw_name] = {
                "name": raw_name,
                "default": default,
                "persistent": persistent,
                "requires": requires,
                "description": description,
                "value": value,
                "runtime_value": value,
                "persistent_value": persistent_value,
                "revision": revision,
            }

        for name, record in booleans.items():
            requires = record.get("requires")
            if requires is None:
                continue
            dep = requires[0]
            if dep == name or dep not in booleans:
                raise SelinuxError("SELINUX_SNAPSHOT_INVALID", name)
        for name in booleans:
            seen = set()
            cursor = name
            while cursor in booleans:
                if cursor in seen:
                    raise SelinuxError("SELINUX_SNAPSHOT_INVALID", "cycle")
                seen.add(cursor)
                requires = booleans[cursor].get("requires")
                if requires is None:
                    break
                cursor = requires[0]

        pending_source = snapshot.get("pending", snapshot.get("pending_changes", {}))
        pending: dict[str, dict] = {}
        if isinstance(pending_source, dict):
            pending_items = list(pending_source.items())
        elif isinstance(pending_source, list):
            pending_items = []
            for item in pending_source:
                if not isinstance(item, dict) or "name" not in item:
                    raise SelinuxError("SELINUX_SNAPSHOT_INVALID", "pending")
                pending_items.append((item["name"], item))
        else:
            raise SelinuxError("SELINUX_SNAPSHOT_INVALID", "pending")

        for raw_name, raw in pending_items:
            if not isinstance(raw_name, str) or raw_name not in booleans:
                raise SelinuxError("SELINUX_SNAPSHOT_INVALID", "pending name")
            if isinstance(raw, bool):
                raw = {"value": raw}
            if not isinstance(raw, dict):
                raise SelinuxError("SELINUX_SNAPSHOT_INVALID", raw_name)
            value = raw.get("value", raw.get("new_value", raw.get("new")))
            if type(value) is not bool:
                raise SelinuxError("SELINUX_SNAPSHOT_INVALID", raw_name)
            persistent = raw.get("persistent", False)
            if type(persistent) is not bool:
                raise SelinuxError("SELINUX_SNAPSHOT_INVALID", raw_name)
            if persistent and not booleans[raw_name]["persistent"]:
                raise SelinuxError("SELINUX_SNAPSHOT_INVALID", raw_name)
            pending[raw_name] = {
                "name": raw_name,
                "value": value,
                "persistent": persistent,
                "old_value": raw.get("old_value", booleans[raw_name]["value"]),
                "old_persistent_value": raw.get(
                    "old_persistent_value",
                    booleans[raw_name].get("persistent_value"),
                ),
            }

        rules_source = snapshot.get(
            "context_rules", snapshot.get("rules", [])
        )
        if not isinstance(rules_source, list):
            raise SelinuxError("SELINUX_SNAPSHOT_INVALID", "rules")
        if len(rules_source) > self.max_context_rules:
            raise SelinuxError("SELINUX_SNAPSHOT_INVALID", "too many rules")
        rules: list[dict] = []
        seen_rules = set()
        for item in rules_source:
            if not isinstance(item, dict):
                raise SelinuxError("SELINUX_SNAPSHOT_INVALID", "rule")
            path = item.get("path")
            context = item.get("context")
            priority = item.get("priority", 100)
            if (
                not isinstance(path, str)
                or not path.startswith("/")
                or not isinstance(context, str)
                or not context
                or type(priority) is not int
            ):
                raise SelinuxError("SELINUX_SNAPSHOT_INVALID", "rule")
            path = posixpath.normpath(path)
            key = (path, priority, context)
            if key in seen_rules:
                continue
            seen_rules.add(key)
            rules.append(
                {"path": path, "context": context, "priority": priority}
            )

        labels_source = snapshot.get("labels", snapshot.get("relabels", {}))
        if not isinstance(labels_source, dict):
            raise SelinuxError("SELINUX_SNAPSHOT_INVALID", "labels")
        labels: dict[str, dict] = {}
        for raw_path, raw in labels_source.items():
            if not isinstance(raw_path, str) or not raw_path.startswith("/"):
                raise SelinuxError("SELINUX_SNAPSHOT_INVALID", "label path")
            if isinstance(raw, str):
                context = raw
                extra = {}
            elif isinstance(raw, dict):
                context = raw.get("context")
                extra = raw
            else:
                raise SelinuxError("SELINUX_SNAPSHOT_INVALID", raw_path)
            if not isinstance(context, str) or not context:
                raise SelinuxError("SELINUX_SNAPSHOT_INVALID", raw_path)
            path = posixpath.normpath(raw_path)
            labels[path] = {
                "path": path,
                "context": context,
                "source": "relabel",
                "rule_path": extra.get("rule_path"),
                "priority": extra.get("priority"),
            }

        mode = snapshot.get("mode", "enforcing")
        if mode not in VALID_MODES:
            raise SelinuxError("SELINUX_SNAPSHOT_INVALID", "mode")

        policy_version = snapshot.get("policy_version", 0)
        if type(policy_version) is not int or policy_version < 0:
            raise SelinuxError("SELINUX_SNAPSHOT_INVALID", "policy_version")

        audit_source = snapshot.get("audit", [])
        if not isinstance(audit_source, list):
            raise SelinuxError("SELINUX_SNAPSHOT_INVALID", "audit")
        audit: list[dict] = []
        for entry in audit_source:
            if not isinstance(entry, dict):
                raise SelinuxError("SELINUX_SNAPSHOT_INVALID", "audit entry")
            entry = copy.deepcopy(entry)
            seq = entry.get("seq")
            if type(seq) is not int or seq < 0:
                raise SelinuxError("SELINUX_SNAPSHOT_INVALID", "audit seq")
            audit.append(entry)
        audit.sort(key=lambda item: item["seq"])
        if len(audit) > self.max_audit:
            audit = audit[-self.max_audit :] if self.max_audit else []

        raw_seq = snapshot.get("seq", 0)
        if type(raw_seq) is not int or raw_seq < 0:
            raise SelinuxError("SELINUX_SNAPSHOT_INVALID", "seq")
        if audit:
            seq = max(raw_seq, audit[-1]["seq"] + 1)
        else:
            seq = raw_seq

        return (
            booleans,
            pending,
            rules,
            labels,
            mode,
            policy_version,
            audit,
            seq,
        )

    # ------------------------------------------------------------------
    # Audit
    # ------------------------------------------------------------------
    def audit(self, limit: int | None = None) -> list[dict]:
        with self._lock:
            if limit is None:
                selected = self._audit
            else:
                if type(limit) is not int:
                    raise SelinuxError("SELINUX_VALUE_INVALID", "limit")
                if limit <= 0:
                    return []
                selected = self._audit[-limit:]
            return copy.deepcopy(selected)
