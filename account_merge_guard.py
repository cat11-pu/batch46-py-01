"""Account merge conflict guard (batch46-game-b-05).

The guard keeps account data in memory, plans a merge without mutating any
account, and only commits the merge when :meth:`AccountMerge.apply` is called.
All state changes are protected by a re-entrant lock so concurrent applies of
the same merge cannot commit twice.
"""

import copy
import threading


_MISSING = object()
_STRATEGIES = {"max", "sum", "primary", "union", "manual"}


class MergeError(ValueError):
    """Raised when an account merge request is rejected."""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = dict(detail or {})


class AccountMerge:
    """Field strategies, merge planning, conflict resolution and snapshots."""

    def __init__(self, *, field_limit=50, max_conflicts=100, history_limit=50):
        self.field_limit = field_limit
        self.max_conflicts = max_conflicts
        self.history_limit = history_limit
        self._lock = threading.RLock()
        self._fields = {}
        self._accounts = {}
        self._merges = {}
        self._log = []

    def register_field(self, field, *, strategy="max", cap=None):
        with self._lock:
            if field in self._fields:
                raise MergeError("MERGE_DUP_FIELD", {"field": field})
            if strategy not in _STRATEGIES:
                raise MergeError(
                    "MERGE_UNKNOWN_STRATEGY",
                    {"field": field, "strategy": strategy},
                )
            self._fields[field] = {
                "strategy": strategy,
                "cap": copy.deepcopy(cap),
            }
            return {
                "field": field,
                "strategy": strategy,
                "cap": copy.deepcopy(cap),
            }

    def create_account(self, account, *, fields=None):
        with self._lock:
            if account in self._accounts:
                raise MergeError("MERGE_DUP_ACCOUNT", {"account": account})
            values = {} if fields is None else dict(fields)
            self._check_field_limit(values)
            self._accounts[account] = {
                "status": "active",
                "merged_into": None,
                "fields": copy.deepcopy(values),
            }
            return self._account_view(account)

    def plan(self, merge_id, primary, secondary):
        with self._lock:
            if merge_id in self._merges:
                raise MergeError("MERGE_DUP_MERGE", {"merge_id": merge_id})
            if primary == secondary:
                raise MergeError("MERGE_SELF", {"account": primary})

            primary_account = self._accounts.get(primary)
            if primary_account is None:
                raise MergeError("MERGE_UNKNOWN_ACCOUNT", {"account": primary})
            secondary_account = self._accounts.get(secondary)
            if secondary_account is None:
                raise MergeError("MERGE_UNKNOWN_ACCOUNT", {"account": secondary})
            if secondary_account["status"] == "merged":
                raise MergeError(
                    "MERGE_SECONDARY_MERGED", {"account": secondary}
                )

            primary_fields = primary_account["fields"]
            secondary_fields = secondary_account["fields"]
            field_names = list(primary_fields)
            field_names.extend(
                name for name in secondary_fields if name not in primary_fields
            )
            self._check_field_limit(field_names)

            preview = {}
            conflicts = []
            for field in field_names:
                primary_value = self._value(primary_fields, field)
                secondary_value = self._value(secondary_fields, field)
                definition = self._fields.get(field)
                strategy = "primary" if definition is None else definition["strategy"]
                cap = None if definition is None else definition["cap"]

                preview[field] = copy.deepcopy(
                    self._merge_value(
                        strategy, primary_value, secondary_value, cap
                    )
                )
                if (
                    strategy == "manual"
                    and primary_value is not _MISSING
                    and secondary_value is not _MISSING
                    and primary_value != secondary_value
                ):
                    conflicts.append(
                        {
                            "field": field,
                            "primary": copy.deepcopy(primary_value),
                            "secondary": copy.deepcopy(secondary_value),
                        }
                    )

            conflicts.sort(key=lambda conflict: conflict["field"])
            conflict_total = len(conflicts)
            conflict_truncated = self._is_truncated(conflict_total)
            self._merges[merge_id] = {
                "merge_id": merge_id,
                "primary": primary,
                "secondary": secondary,
                "state": "planned",
                "preview": preview,
                "conflicts": conflicts,
                "resolved": {},
                "conflict_total": conflict_total,
                "conflict_truncated": conflict_truncated,
            }
            self._append_log(
                {
                    "action": "plan",
                    "merge_id": merge_id,
                    "primary": primary,
                    "secondary": secondary,
                }
            )
            return {
                "status": "planned",
                "merge_id": merge_id,
                "primary": primary,
                "secondary": secondary,
                "preview": copy.deepcopy(preview),
                "conflicts": self._visible_conflicts(merge_id),
                "conflict_total": conflict_total,
                "conflict_truncated": conflict_truncated,
            }

    def conflicts(self, merge_id):
        with self._lock:
            self._require_merge(merge_id)
            return self._visible_conflicts(merge_id)

    def resolve(self, merge_id, field, *, value):
        with self._lock:
            merge = self._require_planned(merge_id)
            conflict_fields = {
                conflict["field"] for conflict in merge["conflicts"]
            }
            if field not in conflict_fields:
                raise MergeError(
                    "MERGE_UNKNOWN_FIELD",
                    {"merge_id": merge_id, "field": field},
                )
            merge["resolved"][field] = copy.deepcopy(value)
            merge["preview"][field] = copy.deepcopy(value)
            self._append_log(
                {
                    "action": "resolve",
                    "merge_id": merge_id,
                    "primary": merge["primary"],
                    "secondary": merge["secondary"],
                    "field": field,
                    "value": copy.deepcopy(value),
                }
            )
            return {
                "status": "resolved",
                "merge_id": merge_id,
                "field": field,
                "value": copy.deepcopy(value),
            }

    def apply(self, merge_id):
        with self._lock:
            merge = self._merges.get(merge_id)
            if merge is None:
                raise MergeError("MERGE_NOT_PLANNED", {"merge_id": merge_id})
            if merge["state"] == "applied":
                return {
                    "status": "already_applied",
                    "merge_id": merge_id,
                    "primary": merge["primary"],
                    "secondary": merge["secondary"],
                }
            if merge["state"] != "planned":
                raise MergeError("MERGE_NOT_PLANNED", {"merge_id": merge_id})

            unresolved = [
                conflict["field"]
                for conflict in merge["conflicts"]
                if conflict["field"] not in merge["resolved"]
            ]
            if unresolved:
                raise MergeError(
                    "MERGE_UNRESOLVED",
                    {"merge_id": merge_id, "fields": unresolved},
                )

            primary = self._accounts.get(merge["primary"])
            secondary = self._accounts.get(merge["secondary"])
            if primary is None:
                raise MergeError(
                    "MERGE_UNKNOWN_ACCOUNT", {"account": merge["primary"]}
                )
            if secondary is None:
                raise MergeError(
                    "MERGE_UNKNOWN_ACCOUNT", {"account": merge["secondary"]}
                )
            if secondary["status"] == "merged":
                raise MergeError(
                    "MERGE_SECONDARY_MERGED", {"account": merge["secondary"]}
                )

            primary["fields"] = copy.deepcopy(merge["preview"])
            secondary["status"] = "merged"
            secondary["merged_into"] = merge["primary"]
            merge["state"] = "applied"
            self._append_log(
                {
                    "action": "apply",
                    "merge_id": merge_id,
                    "primary": merge["primary"],
                    "secondary": merge["secondary"],
                }
            )
            return {
                "status": "applied",
                "merge_id": merge_id,
                "primary": merge["primary"],
                "secondary": merge["secondary"],
            }

    def cancel(self, merge_id):
        with self._lock:
            merge = self._merges.get(merge_id)
            if merge is None or merge["state"] != "planned":
                raise MergeError("MERGE_NOT_PLANNED", {"merge_id": merge_id})
            merge["state"] = "cancelled"
            self._append_log(
                {
                    "action": "cancel",
                    "merge_id": merge_id,
                    "primary": merge["primary"],
                    "secondary": merge["secondary"],
                }
            )
            return {
                "status": "cancelled",
                "merge_id": merge_id,
                "primary": merge["primary"],
                "secondary": merge["secondary"],
            }

    def account(self, account):
        with self._lock:
            return self._account_view(account)

    def snapshot(self):
        with self._lock:
            return {
                "fields": copy.deepcopy(self._fields),
                "accounts": copy.deepcopy(self._accounts),
                "merges": copy.deepcopy(self._merges),
                "log": copy.deepcopy(self._log),
            }

    def restore(self, snapshot):
        with self._lock:
            if not isinstance(snapshot, dict):
                raise MergeError("MERGE_BAD_SNAPSHOT")
            required = ("fields", "accounts", "merges", "log")
            if any(key not in snapshot for key in required):
                raise MergeError("MERGE_BAD_SNAPSHOT")
            self._fields = copy.deepcopy(snapshot["fields"])
            self._accounts = copy.deepcopy(snapshot["accounts"])
            self._merges = copy.deepcopy(snapshot["merges"])
            self._log = copy.deepcopy(snapshot["log"])
            return {"status": "restored"}

    def history(self, account, limit=10):
        with self._lock:
            if account not in self._accounts:
                raise MergeError("MERGE_UNKNOWN_ACCOUNT", {"account": account})
            rows = [
                row
                for row in reversed(self._log)
                if row.get("primary") == account or row.get("secondary") == account
            ]
            return copy.deepcopy(self._bounded(rows, limit))

    def audit(self, limit=10):
        with self._lock:
            rows = list(reversed(self._log))
            return copy.deepcopy(self._bounded(rows, limit))

    def stats(self):
        with self._lock:
            statuses = [account["status"] for account in self._accounts.values()]
            states = [merge["state"] for merge in self._merges.values()]
            conflict_count = sum(
                len(merge["conflicts"]) for merge in self._merges.values()
            )
            return {
                "fields": len(self._fields),
                "accounts": len(self._accounts),
                "active_accounts": statuses.count("active"),
                "merged_accounts": statuses.count("merged"),
                "merges": len(self._merges),
                "planned_merges": states.count("planned"),
                "applied_merges": states.count("applied"),
                "cancelled_merges": states.count("cancelled"),
                "conflicts": conflict_count,
                "history": len(self._log),
            }

    @staticmethod
    def _value(fields, field):
        return fields[field] if field in fields else _MISSING

    @staticmethod
    def _merge_value(strategy, primary_value, secondary_value, cap):
        primary_present = primary_value is not _MISSING
        secondary_present = secondary_value is not _MISSING

        if strategy == "max":
            if not primary_present:
                return secondary_value
            if not secondary_present:
                return primary_value
            if primary_value is None:
                return secondary_value
            if secondary_value is None:
                return primary_value
            try:
                return max(primary_value, secondary_value)
            except TypeError:
                return primary_value

        if strategy == "sum":
            left = 0 if not primary_present or primary_value is None else primary_value
            right = (
                0 if not secondary_present or secondary_value is None else secondary_value
            )
            total = left + right
            if cap is not None and total > cap:
                total = cap
            return total

        if strategy == "union":
            result = []
            for value in (
                AccountMerge._as_list(primary_value)
                + AccountMerge._as_list(secondary_value)
            ):
                if not any(value == existing for existing in result):
                    result.append(value)
            return result

        if not primary_present:
            return secondary_value
        return primary_value

    @staticmethod
    def _as_list(value):
        if value is _MISSING or value is None:
            return []
        if isinstance(value, (list, tuple)):
            return list(value)
        return [value]

    def _check_field_limit(self, fields):
        if self.field_limit is None:
            return
        count = len(fields)
        if count > self.field_limit:
            raise MergeError(
                "MERGE_FIELD_LIMIT",
                {"field_count": count, "field_limit": self.field_limit},
            )

    def _account_view(self, account):
        data = self._accounts.get(account)
        if data is None:
            raise MergeError("MERGE_UNKNOWN_ACCOUNT", {"account": account})
        return {
            "status": data["status"],
            "merged_into": data["merged_into"],
            "fields": copy.deepcopy(data["fields"]),
        }

    def _require_merge(self, merge_id):
        merge = self._merges.get(merge_id)
        if merge is None:
            raise MergeError("MERGE_NOT_PLANNED", {"merge_id": merge_id})
        return merge

    def _require_planned(self, merge_id):
        merge = self._require_merge(merge_id)
        if merge["state"] != "planned":
            raise MergeError("MERGE_NOT_PLANNED", {"merge_id": merge_id})
        return merge

    def _visible_conflicts(self, merge_id):
        conflicts = self._merges[merge_id]["conflicts"]
        if self.max_conflicts is None:
            visible = conflicts
        else:
            visible = conflicts[: max(0, self.max_conflicts)]
        return copy.deepcopy(visible)

    def _is_truncated(self, total):
        if self.max_conflicts is None:
            return False
        return total > max(0, self.max_conflicts)

    def _bounded(self, rows, limit):
        if limit is None:
            return rows
        return rows[: max(0, limit)]

    def _append_log(self, row):
        self._log.append(copy.deepcopy(row))
        if self.history_limit is not None:
            limit = max(0, self.history_limit)
            if len(self._log) > limit:
                del self._log[: len(self._log) - limit]
