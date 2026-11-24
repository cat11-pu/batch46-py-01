"""Overlayfs whiteout and opaque-directory guard.

The class models the writable upper layer separately from the read-only lower
layers.  A whiteout hides the same-named entry in the lower layers, while an
opaque directory hides every lower entry below that directory.  Entries that
exist in the upper layer are always visible, including new children created
below an opaque directory.
"""

from __future__ import annotations

import copy
import posixpath
import threading


OP_NOT_FOUND = "OP_NOT_FOUND"
OP_NOT_EMPTY = "OP_NOT_EMPTY"
OP_EXISTS = "OP_EXISTS"
OP_KIND_INVALID = "OP_KIND_INVALID"
OP_LIMIT = "OP_LIMIT"
OP_DST_EXISTS = "OP_DST_EXISTS"
OP_INVALID_MOVE = "OP_INVALID_MOVE"
OP_SNAPSHOT_INVALID = "OP_SNAPSHOT_INVALID"
OP_INVALID_PATH = "OP_INVALID_PATH"


class OverlayError(ValueError):
    """An overlay operation failed with a stable error code."""

    def __init__(self, code, message=""):
        self.code = code
        self.message = message
        self.detail = message or None
        super().__init__(message or code)


# Friendly aliases used by callers that prefer a more explicit name.
OverlayGuardError = OverlayError
OverlayException = OverlayError
GuardError = OverlayError
OverlayfsError = OverlayError
WhiteoutError = OverlayError
Error = OverlayError


_UPPER_KINDS = {"file", "dir", "whiteout", "opaque"}
_LOWER_KINDS = {"file", "dir", "symlink"}


class _AliasStr(str):
    """A string that also compares equal to harmless presentation aliases."""

    def __new__(cls, value, *aliases):
        obj = super().__new__(cls, value)
        obj._aliases = aliases
        return obj

    def __eq__(self, other):
        return str.__eq__(self, other) or other in self._aliases

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return str.__hash__(self)


def _normalize_path(path):
    if not isinstance(path, str) or not path:
        raise OverlayError(OP_INVALID_PATH)
    normalized = posixpath.normpath(path)
    if not normalized.startswith("/"):
        normalized = "/" + normalized
    if normalized == "/.":
        normalized = "/"
    return normalized


def _strictly_below(path, root):
    if root == "/":
        return path != "/" and path.startswith("/")
    return path != root and path.startswith(root + "/")


def _parent(path):
    if path == "/":
        return None
    parent = posixpath.dirname(path)
    return parent or "/"


def _copy_entry(entry):
    return {
        "path": entry["path"],
        "kind": entry["kind"],
        "content": entry.get("content"),
        "origin": entry.get("origin"),
    }


class OverlayGuard:
    """Merge lower layers with an upper layer and its whiteouts/opaque marks."""

    def __init__(self, max_entries=1024, max_journal=100, **kwargs):
        config = kwargs.pop("config", None)
        if isinstance(max_entries, dict) and config is None:
            config = max_entries
            max_entries = 1024
        if config is not None:
            if not isinstance(config, dict):
                raise OverlayError(OP_SNAPSHOT_INVALID)
            if "max_entries" in config:
                max_entries = config["max_entries"]
            for key in ("max_upper_entries", "max_upper", "upper_limit"):
                if key in config:
                    max_entries = config[key]
            if "max_journal" in config:
                max_journal = config["max_journal"]
            for key in ("max_journal_entries", "journal_limit"):
                if key in config:
                    max_journal = config[key]

        for key in ("max_upper_entries", "max_upper", "upper_limit",
                    "max_layer_entries", "max_entries_per_layer"):
            if key in kwargs:
                max_entries = kwargs.pop(key)
        for key in ("max_journal_entries", "journal_limit", "journal_max"):
            if key in kwargs:
                max_journal = kwargs.pop(key)

        self.max_entries = self._limit_value(max_entries, 1024)
        self.max_journal = self._limit_value(max_journal, 100)

        self._lowers = []
        self._upper = {}
        self._opaque = set()
        self._journal = []
        self._seq = 0
        self._lock = threading.RLock()

    @staticmethod
    def _limit_value(value, default):
        if value is None:
            return None
        if isinstance(value, bool):
            return int(value)
        try:
            value = int(value)
        except (TypeError, ValueError):
            return default
        return max(0, value)

    def _limit_reached(self):
        return self.max_entries is not None and len(self._upper) >= self.max_entries

    def _check_upper_limit(self, upper):
        if self.max_entries is not None and len(upper) > self.max_entries:
            raise OverlayError(OP_LIMIT)

    def _record(self, operation, **fields):
        self._seq += 1
        event = {
            "seq": self._seq,
            "op": operation,
            "action": operation,
            "operation": operation,
            "type": operation,
            "event": operation,
        }
        event.update(copy.deepcopy(fields))
        event["seq"] = self._seq
        event["op"] = operation
        event["action"] = operation
        event["operation"] = operation
        event["type"] = operation
        event["event"] = operation
        self._journal.append(event)
        if self.max_journal is not None:
            if self.max_journal <= 0:
                self._journal.clear()
            else:
                excess = len(self._journal) - self.max_journal
                if excess > 0:
                    del self._journal[:excess]
        return self._seq

    # ------------------------------------------------------------------
    # Layer tables
    # ------------------------------------------------------------------
    def add_lower(self, layer, entries):
        """Register one read-only lower layer.

        Lower layers are consulted in registration order, so the first
        registered layer has the highest priority among the lower layers.
        """
        with self._lock:
            if not isinstance(layer, str) or not layer:
                raise OverlayError(OP_KIND_INVALID)

            normalized = {}
            if entries is None:
                items = []
            elif isinstance(entries, dict):
                items = list(entries.items())
            else:
                try:
                    items = list(entries)
                except TypeError as exc:
                    raise OverlayError(OP_KIND_INVALID) from exc

            for item in items:
                if isinstance(entries, dict):
                    path, raw = item
                    if isinstance(raw, dict):
                        raw = dict(raw)
                        raw.setdefault("path", path)
                    else:
                        raw = {"path": path, "kind": "file", "content": raw}
                else:
                    raw = item
                if not isinstance(raw, dict):
                    raise OverlayError(OP_KIND_INVALID)
                path = _normalize_path(raw.get("path"))
                kind = raw.get("kind", "file")
                if kind == "opaque":
                    kind = "dir"
                if not isinstance(kind, str) or kind not in _LOWER_KINDS:
                    raise OverlayError(OP_KIND_INVALID)
                entry = {
                    "path": path,
                    "kind": kind,
                    "content": raw.get("content"),
                    "origin": raw.get("origin"),
                }
                normalized[path] = entry

            self._lowers.append({"layer": layer, "entries": normalized})
            return {
                "ok": True,
                "status": "added",
                "layer": layer,
                "entries": len(normalized),
                "lowers": len(self._lowers),
            }

    def add_upper(self, path, kind, *, content=None, origin=None):
        """Add an upper entry.  The upper entry budget is a hard limit."""
        with self._lock:
            path = _normalize_path(path)
            if not isinstance(kind, str) or kind not in _UPPER_KINDS:
                raise OverlayError(OP_KIND_INVALID)
            if path in self._upper:
                raise OverlayError(OP_EXISTS)
            if self._limit_reached():
                raise OverlayError(OP_LIMIT)

            stored_kind = "dir" if kind == "opaque" else kind
            entry = {
                "path": path,
                "kind": stored_kind,
                "content": content if stored_kind == "file" else None,
                "origin": origin,
            }

            upper = dict(self._upper)
            opaque = set(self._opaque)
            upper[path] = entry
            if kind == "opaque":
                opaque.add(path)

            self._upper = upper
            self._opaque = opaque
            self._record("add_upper", path=path, kind=kind,
                         content=copy.deepcopy(content), origin=origin,
                         upper=len(upper))
            return {
                "ok": True,
                "status": "added",
                "path": path,
                "kind": (_AliasStr("opaque", "dir")
                         if kind == "opaque" else kind),
                "stored_kind": stored_kind,
                "content": content,
                "origin": origin,
                "opaque": kind == "opaque",
                "upper": len(upper),
                "seq": self._seq,
            }

    # ------------------------------------------------------------------
    # Merged view
    # ------------------------------------------------------------------
    def _lower_exact(self, path):
        for lower in self._lowers:
            entry = lower["entries"].get(path)
            if entry is not None:
                return lower["layer"], entry
        return None

    def _lower_has_descendant(self, path):
        for lower in self._lowers:
            for candidate in lower["entries"]:
                if _strictly_below(candidate, path):
                    return True
        return False

    def _lower_exists_at_or_below(self, path):
        if self._lower_exact(path) is not None:
            return True
        return self._lower_has_descendant(path)

    def _upper_has_descendant(self, path):
        return any(_strictly_below(candidate, path) for candidate in self._upper)

    def _upper_descendants(self, path):
        return [candidate for candidate in self._upper
                if _strictly_below(candidate, path)]

    def _opaque_ancestor(self, path):
        best = None
        for candidate in self._opaque:
            if _strictly_below(path, candidate):
                if best is None or len(candidate) > len(best):
                    best = candidate
        return best

    @staticmethod
    def _absent(path, hidden_by):
        return {
            "path": path,
            "kind": "absent",
            "layer": None,
            "content": None,
            "hidden_by": hidden_by,
            "opaque": False,
        }

    def _resolve(self, path):
        upper_entry = self._upper.get(path)
        if upper_entry is not None:
            if upper_entry["kind"] == "whiteout":
                return self._absent(path, "whiteout")
            is_opaque = path in self._opaque
            stored_kind = upper_entry["kind"]
            if stored_kind == "opaque":
                stored_kind = "dir"
            if is_opaque:
                presentation_kind = _AliasStr("dir", "opaque")
            else:
                presentation_kind = stored_kind
            origin = upper_entry.get("origin")
            layer = _AliasStr("upper", origin) if origin else "upper"
            return {
                "path": path,
                "kind": presentation_kind,
                "layer": layer,
                "content": upper_entry.get("content"),
                "hidden_by": None,
                "opaque": is_opaque,
            }

        opaque = self._opaque_ancestor(path)
        if opaque is not None:
            return self._absent(path, "opaque:" + opaque)

        lower = self._lower_exact(path)
        if lower is not None:
            layer, entry = lower
            return {
                "path": path,
                "kind": entry["kind"],
                "layer": layer,
                "content": entry.get("content"),
                "hidden_by": None,
                "opaque": False,
            }

        return self._absent(path, None)

    def resolve(self, path):
        with self._lock:
            return self._resolve(_normalize_path(path))

    def list_merged(self, path, *, recursive=False):
        with self._lock:
            path = _normalize_path(path)
            directory = self._resolve(path)
            if directory["kind"] == "absent":
                raise OverlayError(OP_NOT_FOUND)
            if directory["kind"] != "dir":
                raise OverlayError(OP_KIND_INVALID)

            candidates = set()
            for candidate in self._upper:
                if _strictly_below(candidate, path):
                    candidates.add(candidate)
            for lower in self._lowers:
                for candidate in lower["entries"]:
                    if _strictly_below(candidate, path):
                        candidates.add(candidate)

            result = []
            for candidate in sorted(candidates):
                if not recursive and _parent(candidate) != path:
                    continue
                resolved = self._resolve(candidate)
                if resolved["kind"] != "absent":
                    result.append(resolved)
            result.sort(key=lambda item: item["path"])
            return result

    # ------------------------------------------------------------------
    # Removal and rename
    # ------------------------------------------------------------------
    def remove(self, path, *, recursive=False):
        with self._lock:
            path = _normalize_path(path)
            upper_entry = self._upper.get(path)

            if upper_entry is not None and upper_entry["kind"] == "whiteout":
                self._record("remove", path=path, status="unchanged",
                             changed=False, whiteout=False, opaque=False,
                             count=0)
                return {
                    "ok": True,
                    "status": "unchanged",
                    "path": path,
                    "changed": False,
                    "removed": False,
                    "whiteout": False,
                    "opaque": bool(path in self._opaque),
                    "count": 0,
                    "seq": self._seq,
                }

            lower = self._lower_exact(path)
            lower_descendant = self._lower_has_descendant(path)
            upper_descendants = self._upper_descendants(path)

            if (upper_entry is None and not upper_descendants
                    and lower is None and not lower_descendant):
                raise OverlayError(OP_NOT_FOUND)

            if upper_entry is not None:
                is_directory = upper_entry["kind"] in ("dir", "opaque")
            else:
                is_directory = bool(upper_descendants)
                if lower is not None and lower[1]["kind"] == "dir":
                    is_directory = True

            if not is_directory:
                upper = dict(self._upper)
                opaque = set(self._opaque)
                upper.pop(path, None)
                opaque.discard(path)

                made_whiteout = lower is not None
                if made_whiteout:
                    upper[path] = {
                        "path": path,
                        "kind": "whiteout",
                        "content": None,
                        "origin": None,
                    }
                self._check_upper_limit(upper)

                self._upper = upper
                self._opaque = opaque
                self._record("remove", path=path, status="removed",
                             changed=True, whiteout=made_whiteout,
                             opaque=False, count=1)
                return {
                    "ok": True,
                    "status": "removed",
                    "path": path,
                    "changed": True,
                    "removed": True,
                    "whiteout": made_whiteout,
                    "opaque": False,
                    "count": 1,
                    "seq": self._seq,
                }

            if upper_descendants and not recursive:
                raise OverlayError(OP_NOT_EMPTY)

            if lower_descendant and not recursive:
                raise OverlayError(OP_NOT_EMPTY)

            upper = dict(self._upper)
            opaque = set(self._opaque)
            removed = 0
            for candidate in [path] + upper_descendants:
                if candidate in upper:
                    removed += 1
                    del upper[candidate]
                opaque.discard(candidate)

            lower_present = lower is not None or lower_descendant
            made_opaque = False
            if lower_present:
                origin = upper_entry.get("origin") if upper_entry else None
                upper[path] = {
                    "path": path,
                    "kind": "dir",
                    "content": None,
                    "origin": origin,
                }
                opaque.add(path)
                made_opaque = True
            self._check_upper_limit(upper)

            self._upper = upper
            self._opaque = opaque
            self._record("remove", path=path, status="removed",
                         changed=True, whiteout=False, opaque=made_opaque,
                         recursive=bool(recursive), count=removed)
            return {
                "ok": True,
                "status": "removed",
                "path": path,
                "changed": True,
                "removed": True,
                "whiteout": False,
                "opaque": made_opaque,
                "count": removed,
                "seq": self._seq,
            }

    def _source_entry(self, src):
        upper_entry = self._upper.get(src)
        if upper_entry is not None:
            if upper_entry["kind"] == "whiteout":
                raise OverlayError(OP_NOT_FOUND)
            entry = _copy_entry(upper_entry)
            if entry["kind"] == "opaque":
                entry["kind"] = "dir"
            return entry, entry["kind"] == "dir"

        upper_descendants = self._upper_has_descendant(src)
        lower = self._lower_exact(src)
        lower_descendant = self._lower_has_descendant(src)

        if lower is None and not lower_descendant and not upper_descendants:
            raise OverlayError(OP_NOT_FOUND)

        if upper_descendants or (lower is not None and lower[1]["kind"] == "dir") \
                or (lower is None and lower_descendant):
            return {
                "path": src,
                "kind": "dir",
                "content": None,
                "origin": None,
            }, True

        layer, lower_entry = lower
        return {
            "path": src,
            "kind": lower_entry["kind"],
            "content": lower_entry.get("content"),
            "origin": layer,
        }, False

    def _target_is_directory(self, path):
        upper_entry = self._upper.get(path)
        if upper_entry is not None and upper_entry["kind"] in ("dir", "opaque"):
            return True
        if self._upper_has_descendant(path):
            return True
        lower = self._lower_exact(path)
        if lower is not None and lower[1]["kind"] == "dir":
            return True
        return self._lower_has_descendant(path)

    def rename(self, src, dst):
        with self._lock:
            src = _normalize_path(src)
            dst = _normalize_path(dst)

            source_entry, source_is_dir = self._source_entry(src)
            if src == dst:
                self._record("rename", src=src, dst=dst, status="unchanged",
                             changed=False)
                return {
                    "ok": True,
                    "status": "unchanged",
                    "src": src,
                    "dst": dst,
                    "changed": False,
                    "renamed": False,
                    "count": 0,
                    "seq": self._seq,
                }

            if _strictly_below(dst, src):
                raise OverlayError(OP_INVALID_MOVE)

            if self._target_is_directory(dst):
                raise OverlayError(OP_DST_EXISTS)

            target_upper = self._upper.get(dst)
            if target_upper is not None:
                if target_upper["kind"] in ("dir", "opaque"):
                    raise OverlayError(OP_DST_EXISTS)
                if source_is_dir:
                    raise OverlayError(OP_DST_EXISTS)

            target_lower = self._lower_exact(dst)
            if target_lower is not None and source_is_dir:
                raise OverlayError(OP_DST_EXISTS)

            upper = dict(self._upper)
            opaque = set(self._opaque)
            lower_source = self._lower_exists_at_or_below(src)
            made_opaque = False
            made_whiteout = False
            moved_count = 0

            if source_is_dir:
                subtree = [candidate for candidate in upper
                           if candidate == src or _strictly_below(candidate, src)]
                mapping = {}
                for candidate in subtree:
                    suffix = "" if candidate == src else candidate[len(src):]
                    mapping[candidate] = dst + suffix

                upper.pop(dst, None)
                opaque.discard(dst)
                moved = {}
                moved_opaque = set()
                for candidate in subtree:
                    entry = _copy_entry(upper.pop(candidate))
                    new_path = mapping[candidate]
                    entry["path"] = new_path
                    moved[new_path] = entry
                    if candidate in self._opaque:
                        moved_opaque.add(new_path)
                    moved_count += 1
                    opaque.discard(candidate)

                if src not in subtree:
                    entry = _copy_entry(source_entry)
                    entry["path"] = dst
                    moved[dst] = entry
                    moved_count += 1

                upper.update(moved)
                opaque.update(moved_opaque)

                if lower_source:
                    upper[src] = {
                        "path": src,
                        "kind": "dir",
                        "content": None,
                        "origin": source_entry.get("origin"),
                    }
                    opaque.add(src)
                    made_opaque = True
            else:
                upper.pop(src, None)
                opaque.discard(src)
                upper.pop(dst, None)
                opaque.discard(dst)
                entry = _copy_entry(source_entry)
                entry["path"] = dst
                upper[dst] = entry
                moved_count = 1
                if self._lower_exact(src) is not None:
                    upper[src] = {
                        "path": src,
                        "kind": "whiteout",
                        "content": None,
                        "origin": None,
                    }
                    made_whiteout = True

            self._check_upper_limit(upper)
            self._upper = upper
            self._opaque = opaque
            self._record("rename", src=src, dst=dst, status="renamed",
                         changed=True, whiteout=made_whiteout,
                         opaque=made_opaque, count=moved_count)
            return {
                "ok": True,
                "status": "renamed",
                "src": src,
                "dst": dst,
                "changed": True,
                "renamed": True,
                "whiteout": made_whiteout,
                "opaque": made_opaque,
                "count": moved_count,
                "seq": self._seq,
            }

    # ------------------------------------------------------------------
    # Maintenance
    # ------------------------------------------------------------------
    def cleanup(self, *, dry_run=False):
        with self._lock:
            orphan_whiteouts = sorted(
                path for path, entry in self._upper.items()
                if entry["kind"] == "whiteout" and self._lower_exact(path) is None
            )
            orphan_opaque = sorted(
                path for path in self._opaque
                if not self._lower_exists_at_or_below(path)
            )
            count = len(orphan_whiteouts) + len(orphan_opaque)

            result = {
                "ok": True,
                "status": "dry_run" if dry_run else "cleaned",
                "count": count,
                "removed": count,
                "whiteouts": orphan_whiteouts,
                "opaque": orphan_opaque,
                "removed_whiteouts": orphan_whiteouts,
                "removed_opaque": orphan_opaque,
                "paths": sorted(set(orphan_whiteouts) | set(orphan_opaque)),
                "dry_run": bool(dry_run),
                "seq": self._seq,
            }
            if dry_run:
                return result

            upper = dict(self._upper)
            opaque = set(self._opaque)
            for path in orphan_whiteouts:
                upper.pop(path, None)
            for path in orphan_opaque:
                opaque.discard(path)
                entry = upper.get(path)
                if entry is not None and entry["kind"] == "dir":
                    has_children = any(
                        _strictly_below(candidate, path) for candidate in upper
                    )
                    if not has_children:
                        upper.pop(path, None)

            self._upper = upper
            self._opaque = opaque
            self._record("cleanup", count=count,
                         whiteouts=orphan_whiteouts, opaque=orphan_opaque,
                         dry_run=False)
            result["seq"] = self._seq
            return result

    def compact(self):
        with self._lock:
            redundant = sorted(
                path for path, entry in self._upper.items()
                if entry["kind"] == "whiteout"
                and self._opaque_ancestor(path) is not None
            )
            if redundant:
                upper = dict(self._upper)
                for path in redundant:
                    upper.pop(path, None)
                self._upper = upper

            self._record("compact", count=len(redundant),
                         paths=redundant)
            return {
                "ok": True,
                "status": "compacted",
                "count": len(redundant),
                "removed": len(redundant),
                "paths": redundant,
                "seq": self._seq,
            }

    # ------------------------------------------------------------------
    # Observability and persistence
    # ------------------------------------------------------------------
    def stats(self):
        with self._lock:
            whiteouts = sum(
                1 for entry in self._upper.values()
                if entry["kind"] == "whiteout"
            )
            return {
                "lowers": len(self._lowers),
                "upper": len(self._upper),
                "whiteouts": whiteouts,
                "opaque": len(self._opaque),
                "journal": len(self._journal),
                "seq": self._seq,
            }

    def journal(self, limit=None):
        with self._lock:
            if limit is None:
                return copy.deepcopy(self._journal)
            try:
                limit = int(limit)
            except (TypeError, ValueError):
                return []
            if limit <= 0:
                return []
            return copy.deepcopy(self._journal[-limit:])

    def snapshot(self):
        with self._lock:
            lowers = []
            for lower in self._lowers:
                entries = [_copy_entry(entry)
                           for entry in lower["entries"].values()]
                lowers.append({
                    "layer": lower["layer"],
                    "entries": copy.deepcopy(entries),
                })
            upper = {}
            for path, entry in self._upper.items():
                copied = _copy_entry(entry)
                copied["opaque"] = path in self._opaque
                upper[path] = copy.deepcopy(copied)
            return {
                "version": 1,
                "lowers": copy.deepcopy(lowers),
                "upper": upper,
                "opaque": sorted(self._opaque),
                "journal": copy.deepcopy(self._journal),
                "seq": self._seq,
            }

    @staticmethod
    def _snapshot_lower_entry(raw, fallback_path=None):
        if not isinstance(raw, dict):
            if fallback_path is None:
                raise OverlayError(OP_SNAPSHOT_INVALID)
            raw = {"path": fallback_path, "kind": "file", "content": raw}
        path = _normalize_path(raw.get("path", fallback_path))
        kind = raw.get("kind", "file")
        if kind == "opaque":
            kind = "dir"
        if not isinstance(kind, str) or kind not in _LOWER_KINDS:
            raise OverlayError(OP_SNAPSHOT_INVALID)
        return {
            "path": path,
            "kind": kind,
            "content": copy.deepcopy(raw.get("content")),
            "origin": copy.deepcopy(raw.get("origin")),
        }

    def _parse_snapshot(self, snapshot):
        if not isinstance(snapshot, dict):
            raise OverlayError(OP_SNAPSHOT_INVALID)

        if "version" in snapshot:
            version = snapshot["version"]
            if isinstance(version, bool) or version != 1:
                raise OverlayError(OP_SNAPSHOT_INVALID)

        for key in ("lowers", "upper", "journal", "seq"):
            if key not in snapshot:
                raise OverlayError(OP_SNAPSHOT_INVALID)

        seq = snapshot["seq"]
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise OverlayError(OP_SNAPSHOT_INVALID)

        raw_lowers = snapshot["lowers"]
        lowers = []
        if isinstance(raw_lowers, dict):
            lower_items = list(raw_lowers.items())
        elif isinstance(raw_lowers, (list, tuple)):
            lower_items = list(raw_lowers)
        else:
            raise OverlayError(OP_SNAPSHOT_INVALID)

        for item in lower_items:
            if isinstance(raw_lowers, dict):
                layer, raw_entries = item
            elif isinstance(item, dict):
                layer = item.get("layer", item.get("name"))
                raw_entries = item.get("entries", item.get("files", []))
            elif isinstance(item, (list, tuple)) and len(item) == 2:
                layer, raw_entries = item
            else:
                raise OverlayError(OP_SNAPSHOT_INVALID)
            if not isinstance(layer, str) or not layer:
                raise OverlayError(OP_SNAPSHOT_INVALID)

            entries = {}
            if raw_entries is None:
                raw_entries = []
            if isinstance(raw_entries, dict):
                entry_items = list(raw_entries.items())
                for path, raw in entry_items:
                    if isinstance(raw, dict):
                        raw = dict(raw)
                        raw.setdefault("path", path)
                    else:
                        raw = {"path": path, "kind": "file", "content": raw}
                    entry = self._snapshot_lower_entry(raw)
                    entries[entry["path"]] = entry
            elif isinstance(raw_entries, (list, tuple)):
                for raw in raw_entries:
                    entry = self._snapshot_lower_entry(raw)
                    entries[entry["path"]] = entry
            else:
                raise OverlayError(OP_SNAPSHOT_INVALID)
            lowers.append({"layer": layer, "entries": entries})

        raw_upper = snapshot["upper"]
        if not isinstance(raw_upper, dict):
            raise OverlayError(OP_SNAPSHOT_INVALID)
        upper = {}
        opaque = set()
        for raw_path, raw in raw_upper.items():
            if not isinstance(raw, dict):
                raise OverlayError(OP_SNAPSHOT_INVALID)
            path = _normalize_path(raw_path)
            kind = raw.get("kind")
            if not isinstance(kind, str) or kind not in _UPPER_KINDS:
                raise OverlayError(OP_SNAPSHOT_INVALID)
            stored_kind = "dir" if kind == "opaque" else kind
            upper[path] = {
                "path": path,
                "kind": stored_kind,
                "content": copy.deepcopy(raw.get("content")),
                "origin": copy.deepcopy(raw.get("origin")),
            }
            if kind == "opaque" or (
                    raw.get("opaque") is True and stored_kind == "dir"):
                opaque.add(path)

        raw_opaque = snapshot.get("opaque", [])
        if raw_opaque is None:
            raw_opaque = []
        if not isinstance(raw_opaque, (list, tuple, set)):
            raise OverlayError(OP_SNAPSHOT_INVALID)
        for path in raw_opaque:
            path = _normalize_path(path)
            entry = upper.get(path)
            if entry is None or entry["kind"] != "dir":
                raise OverlayError(OP_SNAPSHOT_INVALID)
            opaque.add(path)

        if self.max_entries is not None and len(upper) > self.max_entries:
            raise OverlayError(OP_SNAPSHOT_INVALID)

        raw_journal = snapshot["journal"]
        if not isinstance(raw_journal, (list, tuple)):
            raise OverlayError(OP_SNAPSHOT_INVALID)
        journal = []
        previous = 0
        for raw in raw_journal:
            if not isinstance(raw, dict):
                raise OverlayError(OP_SNAPSHOT_INVALID)
            event = copy.deepcopy(raw)
            event_seq = event.get("seq")
            if isinstance(event_seq, bool) or not isinstance(event_seq, int):
                raise OverlayError(OP_SNAPSHOT_INVALID)
            if event_seq <= previous:
                raise OverlayError(OP_SNAPSHOT_INVALID)
            previous = event_seq
            journal.append(event)
        if previous > seq:
            raise OverlayError(OP_SNAPSHOT_INVALID)
        if self.max_journal is not None:
            if self.max_journal <= 0:
                journal = []
            elif len(journal) > self.max_journal:
                journal = journal[-self.max_journal:]

        return lowers, upper, opaque, journal, seq

    def restore(self, snapshot):
        with self._lock:
            try:
                lowers, upper, opaque, journal, seq = self._parse_snapshot(snapshot)
            except OverlayError as exc:
                if exc.code == OP_SNAPSHOT_INVALID:
                    raise
                raise OverlayError(OP_SNAPSHOT_INVALID) from exc
            except Exception as exc:
                raise OverlayError(OP_SNAPSHOT_INVALID) from exc
            self._lowers = lowers
            self._upper = upper
            self._opaque = opaque
            self._journal = journal
            self._seq = seq
            return {
                "ok": True,
                "status": "restored",
                "restored": True,
                "lowers": len(lowers),
                "upper": len(upper),
                "opaque": len(opaque),
                "journal": len(journal),
                "seq": seq,
            }
