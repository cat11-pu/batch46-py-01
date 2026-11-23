"""ptrace scope boundary enforcement guard (skeleton).

Implement the process-tree policy described in README.md.  Every public
method below is imported by the tests and must keep its signature.
"""

import json
import threading

SCOPE_CLASSIC = 0
SCOPE_ANCESTOR = 1
SCOPE_ADMIN_ONLY = 2
SCOPE_DENY_ALL = 3

_VALID_SCOPES = (SCOPE_CLASSIC, SCOPE_ANCESTOR, SCOPE_ADMIN_ONLY,
                 SCOPE_DENY_ALL)


class PtraceError(ValueError):
    """Raised for every rejected ptrace operation."""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class PtraceGuard:
    def __init__(self, *, scope=SCOPE_ANCESTOR, audit_capacity=16):
        if scope not in _VALID_SCOPES:
            raise PtraceError("PT_BAD_SCOPE",
                              "scope must be one of 0, 1, 2, 3")
        if not isinstance(audit_capacity, int) or audit_capacity < 1:
            raise PtraceError("PT_BAD_AUDIT_CAPACITY",
                              "audit_capacity must be a positive int")
        self._lock = threading.RLock()
        self._scope = scope
        self._audit_capacity = audit_capacity
        self._processes = {}
        self._attachments = {}
        self._audit = []
        self._stats = {
            "registered": 0,
            "attaches": 0,
            "already": 0,
            "denied": 0,
            "detaches": 0,
            "exits": 0,
            "reparents": 0,
        }

    # -- internal helpers -------------------------------------------------

    def _record_audit(self, event, code=None, target=None, tracer=None,
                      detail=None):
        row = {"event": event, "code": code}
        if target is not None:
            row["target"] = target
        if tracer is not None:
            row["tracer"] = tracer
        if detail is not None:
            row["detail"] = detail
        self._audit.append(row)
        overflow = len(self._audit) - self._audit_capacity
        if overflow > 0:
            del self._audit[:overflow]

    def _get_process(self, pid):
        proc = self._processes.get(pid)
        if proc is None:
            raise PtraceError("PT_UNKNOWN", "unknown pid %r" % (pid,))
        return proc

    def _ancestor_pids(self, pid):
        chain = []
        seen = {pid}
        current = self._processes[pid]["ppid"]
        while current is not None and current not in seen:
            chain.append(current)
            seen.add(current)
            parent = self._processes.get(current)
            if parent is None:
                break
            current = parent["ppid"]
        return chain

    def _decide(self, pid, tracer_pid):
        """Return (allowed, code, already). Caller must hold the lock."""
        target = self._processes.get(pid)
        if target is None:
            raise PtraceError("PT_UNKNOWN", "unknown target pid %r" % (pid,))
        tracer = self._processes.get(tracer_pid)
        if tracer is None:
            raise PtraceError("PT_UNKNOWN", "unknown tracer pid %r"
                              % (tracer_pid,))
        if pid == tracer_pid:
            return False, "PT_SELF", False
        if self._scope == SCOPE_DENY_ALL:
            return False, "PT_SCOPE_DENY", False
        if target["uid"] != tracer["uid"] and not tracer["privileged"]:
            return False, "PT_DAC_DENY", False
        if self._scope == SCOPE_ADMIN_ONLY and not tracer["privileged"]:
            return False, "PT_SCOPE_DENY", False
        if (self._scope == SCOPE_ANCESTOR and not tracer["privileged"]
                and tracer_pid not in self._ancestor_pids(pid)):
            return False, "PT_NOT_ANCESTOR", False
        holder = self._attachments.get(pid)
        if holder is not None:
            if holder == tracer_pid:
                return True, None, True
            return False, "PT_BUSY", False
        return True, None, False

    # -- process tree -----------------------------------------------------

    def register_process(self, pid, *, uid=0, ppid=1, comm="proc",
                         privileged=False):
        with self._lock:
            if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
                raise PtraceError("PT_BAD_PID", "pid must be a positive int")
            if not isinstance(uid, int) or isinstance(uid, bool) or uid < 0:
                raise PtraceError("PT_BAD_UID", "uid must be a non-negative int")
            if not isinstance(comm, str) or not comm:
                raise PtraceError("PT_BAD_COMM", "comm must be a non-empty str")
            if pid in self._processes:
                raise PtraceError("PT_EXISTS", "pid %d already registered"
                                  % pid)
            if ppid != 1 and ppid not in self._processes:
                raise PtraceError("PT_UNKNOWN_PPID",
                                  "unknown parent pid %r" % (ppid,))
            self._processes[pid] = {
                "uid": uid,
                "ppid": ppid,
                "comm": comm,
                "privileged": bool(privileged),
            }
            self._stats["registered"] += 1
            return {
                "pid": pid,
                "uid": uid,
                "ppid": ppid,
                "comm": comm,
                "privileged": bool(privileged),
            }

    def process_info(self, pid):
        with self._lock:
            proc = self._get_process(pid)
            return {
                "pid": pid,
                "uid": proc["uid"],
                "ppid": proc["ppid"],
                "comm": proc["comm"],
                "privileged": proc["privileged"],
                "attached_by": self._attachments.get(pid),
                "children": self.children(pid),
            }

    def unregister_process(self, pid):
        with self._lock:
            self._get_process(pid)
            reparented = 0
            for other_pid, proc in self._processes.items():
                if other_pid != pid and proc["ppid"] == pid:
                    proc["ppid"] = 1
                    reparented += 1
            detached = 0
            for target, tracer in list(self._attachments.items()):
                if target == pid or tracer == pid:
                    del self._attachments[target]
                    detached += 1
            del self._processes[pid]
            self._stats["exits"] += 1
            self._record_audit("exit", target=pid,
                               detail={"reparented": reparented,
                                       "detached": detached})
            return {"reparented": reparented, "detached": detached}

    def reparent(self, pid, new_ppid):
        with self._lock:
            proc = self._get_process(pid)
            if new_ppid != 1 and new_ppid not in self._processes:
                raise PtraceError("PT_UNKNOWN_PPID",
                                  "unknown parent pid %r" % (new_ppid,))
            if new_ppid == pid or (new_ppid in self._processes
                                   and pid in self._ancestor_pids(new_ppid)):
                raise PtraceError("PT_CYCLE",
                                  "reparenting %d under %d would cycle"
                                  % (pid, new_ppid))
            if proc["ppid"] == new_ppid:
                return False
            proc["ppid"] = new_ppid
            self._stats["reparents"] += 1
            self._record_audit("reparent", target=pid,
                               detail={"new_ppid": new_ppid})
            return True

    def children(self, pid):
        with self._lock:
            if pid != 1 and pid not in self._processes:
                raise PtraceError("PT_UNKNOWN", "unknown pid %r" % (pid,))
            return sorted(child_pid
                          for child_pid, proc in self._processes.items()
                          if proc["ppid"] == pid and child_pid != pid)

    def ancestors(self, pid):
        with self._lock:
            self._get_process(pid)
            return self._ancestor_pids(pid)

    def set_scope(self, level):
        with self._lock:
            if level not in _VALID_SCOPES:
                raise PtraceError("PT_BAD_SCOPE",
                                  "scope must be one of 0, 1, 2, 3")
            old = self._scope
            self._scope = level
            return old

    def scope(self):
        with self._lock:
            return self._scope

    # -- attach / detach --------------------------------------------------

    def check_attach(self, pid, tracer_pid):
        with self._lock:
            allowed, code, already = self._decide(pid, tracer_pid)
            return {
                "allowed": allowed,
                "code": code,
                "already": already,
                "target": pid,
                "tracer": tracer_pid,
            }

    def attach(self, pid, tracer_pid):
        with self._lock:
            allowed, code, already = self._decide(pid, tracer_pid)
            if not allowed:
                self._stats["denied"] += 1
                self._record_audit("attach_denied", code=code, target=pid,
                                   tracer=tracer_pid)
                raise PtraceError(code, "attach of %d by %d denied: %s"
                                  % (pid, tracer_pid, code))
            if already:
                self._stats["already"] += 1
                self._record_audit("attach_already", target=pid,
                                   tracer=tracer_pid)
            else:
                self._attachments[pid] = tracer_pid
                self._stats["attaches"] += 1
                self._record_audit("attach", target=pid, tracer=tracer_pid)
            return {
                "allowed": True,
                "already": already,
                "target": pid,
                "tracer": tracer_pid,
            }

    def detach(self, pid, tracer_pid):
        with self._lock:
            if self._attachments.get(pid) != tracer_pid:
                return False
            del self._attachments[pid]
            self._stats["detaches"] += 1
            self._record_audit("detach", target=pid, tracer=tracer_pid)
            return True

    def detach_all(self, tracer_pid):
        with self._lock:
            self._get_process(tracer_pid)
            targets = [target for target, tracer
                       in self._attachments.items() if tracer == tracer_pid]
            for target in targets:
                del self._attachments[target]
            if targets:
                self._stats["detaches"] += len(targets)
                self._record_audit("detach_all", tracer=tracer_pid,
                                   detail={"count": len(targets)})
            return len(targets)

    def attachments(self):
        with self._lock:
            return dict(self._attachments)

    def stats(self):
        with self._lock:
            return dict(self._stats)

    def audit(self, limit=None):
        with self._lock:
            rows = self._audit if limit is None else self._audit[-limit:]
            return [dict(row) for row in rows]

    # -- snapshot ---------------------------------------------------------

    def snapshot(self):
        with self._lock:
            payload = {
                "version": 1,
                "scope": self._scope,
                "audit_capacity": self._audit_capacity,
                "processes": [
                    {"pid": pid, **proc}
                    for pid, proc in sorted(self._processes.items())
                ],
                "attachments": {str(target): tracer
                                for target, tracer
                                in self._attachments.items()},
                "stats": dict(self._stats),
                "audit": [dict(row) for row in self._audit],
            }
            return json.dumps(payload, sort_keys=True)

    @classmethod
    def restore(cls, data):
        try:
            payload = json.loads(data)
            if not isinstance(payload, dict):
                raise ValueError("snapshot must be an object")
            scope = payload["scope"]
            audit_capacity = payload["audit_capacity"]
            processes = payload["processes"]
            attachments = payload["attachments"]
            stats = payload["stats"]
            audit = payload["audit"]
            if not isinstance(processes, list) \
                    or not isinstance(attachments, dict) \
                    or not isinstance(stats, dict) \
                    or not isinstance(audit, list):
                raise ValueError("snapshot fields have wrong types")
            try:
                guard = cls(scope=scope, audit_capacity=audit_capacity)
            except PtraceError as exc:
                raise ValueError("bad guard settings: %s" % exc.code)
            for entry in processes:
                pid = entry["pid"]
                proc = {
                    "uid": entry["uid"],
                    "ppid": entry["ppid"],
                    "comm": entry["comm"],
                    "privileged": bool(entry["privileged"]),
                }
                if not isinstance(pid, int) or pid <= 0 \
                        or not isinstance(proc["uid"], int) \
                        or proc["uid"] < 0 \
                        or not isinstance(proc["ppid"], int) \
                        or not isinstance(proc["comm"], str) \
                        or not proc["comm"]:
                    raise ValueError("bad process entry")
                guard._processes[pid] = proc
            for target, tracer in attachments.items():
                target_pid = int(target)
                if target_pid not in guard._processes \
                        or tracer not in guard._processes:
                    raise ValueError("attachment references unknown pid")
                guard._attachments[target_pid] = tracer
            for key in guard._stats:
                value = stats.get(key, 0)
                if not isinstance(value, int) or value < 0:
                    raise ValueError("bad stats counter")
                guard._stats[key] = value
            for row in audit:
                if not isinstance(row, dict) or "event" not in row:
                    raise ValueError("bad audit row")
                guard._audit.append(dict(row))
            overflow = len(guard._audit) - guard._audit_capacity
            if overflow > 0:
                del guard._audit[:overflow]
            return guard
        except PtraceError:
            raise
        except Exception as exc:
            raise PtraceError("PT_SNAPSHOT_INVALID",
                              "invalid snapshot: %s" % (exc,)) from exc
