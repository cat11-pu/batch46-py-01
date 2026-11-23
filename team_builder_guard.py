"""Team roster and composition guard (batch46-game-b-01, Bugfix skeleton)."""

import copy
import threading


class TeamError(ValueError):
    """Raised when a roster operation violates a hard team rule."""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = dict(detail or {})


class TeamBuilder:
    """Roster storage, composition rules, validation, snapshots and tickets."""

    def __init__(self, *, capacity=5, power_cap=10000, audit_limit=50):
        self.capacity = capacity
        self.power_cap = power_cap
        self.audit_limit = audit_limit
        self._teams = {}
        self._rules = {}
        self._audits = {}
        self._lock = threading.RLock()

    def define_rule(self, rule_id, *, kind, limit=1, value=None, severity="block"):
        with self._lock:
            self._rules[rule_id] = {
                "rule_id": rule_id,
                "kind": kind,
                "limit": limit,
                "value": value,
                "severity": severity,
            }
            return copy.deepcopy(self._rules[rule_id])

    def list_rules(self):
        with self._lock:
            return [copy.deepcopy(rule) for rule in self._rules.values()]

    def _rules_of_kind(self, kind):
        return [rule for rule in self._rules.values() if rule["kind"] == kind]

    def _get_team(self, team_id):
        team = self._teams.get(team_id)
        if team is None:
            raise TeamError("TEAM_NOT_FOUND", {"team_id": team_id})
        return team

    def _record_audit(self, team_id, row):
        log = self._audits.setdefault(team_id, [])
        log.insert(0, copy.deepcopy(row))
        if len(log) > self.audit_limit:
            del log[self.audit_limit:]

    def create_team(self, team_id, owner, *, server="s1", capacity=None):
        with self._lock:
            if team_id in self._teams:
                raise TeamError("TEAM_EXISTS", {"team_id": team_id})
            team_capacity = self.capacity if capacity is None else capacity
            self._teams[team_id] = {
                "team_id": team_id,
                "owner": owner,
                "server": server,
                "capacity": team_capacity,
                "version": 0,
                "members": [{
                    "member": owner,
                    "role": "leader",
                    "power": 0,
                    "server": server,
                    "relic": None,
                }],
            }
            self._audits[team_id] = []
            return {
                "status": "created",
                "team_id": team_id,
                "owner": owner,
                "capacity": team_capacity,
                "version": 0,
            }

    def join(self, team_id, member, *, role, power=0, server="s1", relic=None,
             event_id=None):
        with self._lock:
            team = self._get_team(team_id)
            members = team["members"]

            if any(entry["member"] == member for entry in members):
                return {
                    "status": "ignored",
                    "code": "TEAM_DUP_MEMBER",
                    "team_id": team_id,
                    "member": member,
                }

            if len(members) >= team["capacity"]:
                raise TeamError("TEAM_FULL", {
                    "team_id": team_id,
                    "capacity": team["capacity"],
                    "member_count": len(members),
                })

            if server != team["server"] and not any(
                rule.get("value") == "allow"
                for rule in self._rules_of_kind("cross_server")
            ):
                raise TeamError("TEAM_CROSS_SERVER", {
                    "team_id": team_id,
                    "team_server": team["server"],
                    "server": server,
                })

            if (
                relic is not None
                and self._rules_of_kind("relic_unique")
                and any(entry["relic"] == relic for entry in members)
            ):
                raise TeamError("TEAM_DUP_RELIC", {
                    "team_id": team_id,
                    "relic": relic,
                })

            total_power = sum(entry["power"] for entry in members)
            if total_power + power > self.power_cap:
                raise TeamError("TEAM_POWER_CAP", {
                    "team_id": team_id,
                    "power_cap": self.power_cap,
                    "total_power": total_power,
                    "power": power,
                })

            record = {
                "member": member,
                "role": role,
                "power": power,
                "server": server,
                "relic": relic,
            }
            members.append(record)
            team["version"] += 1
            self._record_audit(team_id, {
                "action": "join",
                "member": member,
                "role": role,
                "power": power,
                "server": server,
                "relic": relic,
                "event_id": event_id,
                "version": team["version"],
            })
            return {
                "status": "applied",
                "team_id": team_id,
                "member": member,
                "role": role,
                "version": team["version"],
            }

    def leave(self, team_id, member, *, event_id=None):
        with self._lock:
            team = self._get_team(team_id)
            members = team["members"]
            index = next(
                (idx for idx, entry in enumerate(members)
                 if entry["member"] == member),
                None,
            )
            if index is None:
                raise TeamError("TEAM_NOT_MEMBER", {
                    "team_id": team_id,
                    "member": member,
                })

            removed = members.pop(index)
            promoted = None
            if team["owner"] == member and members:
                successor = members[0]
                promoted = successor["member"]
                team["owner"] = promoted
                successor["role"] = "leader"

            team["version"] += 1
            self._record_audit(team_id, {
                "action": "leave",
                "member": member,
                "role": removed["role"],
                "event_id": event_id,
                "promoted": promoted,
                "version": team["version"],
            })
            return {
                "status": "applied",
                "team_id": team_id,
                "member": member,
                "promoted": promoted,
                "version": team["version"],
            }

    def change_role(self, team_id, member, role):
        with self._lock:
            team = self._get_team(team_id)
            target = next(
                (entry for entry in team["members"]
                 if entry["member"] == member),
                None,
            )
            if target is None:
                raise TeamError("TEAM_NOT_MEMBER", {
                    "team_id": team_id,
                    "member": member,
                })

            for rule in self._rules_of_kind("role_limit"):
                if rule.get("value") != role:
                    continue
                current = sum(
                    1 for entry in team["members"]
                    if entry["member"] != member and entry["role"] == role
                )
                if current >= rule["limit"]:
                    raise TeamError("TEAM_ROLE_LIMIT", {
                        "team_id": team_id,
                        "rule": rule["rule_id"],
                        "role": role,
                        "limit": rule["limit"],
                        "members": [
                            entry["member"] for entry in team["members"]
                            if entry["role"] == role
                        ],
                    })

            old_role = target["role"]
            target["role"] = role
            team["version"] += 1
            self._record_audit(team_id, {
                "action": "change_role",
                "member": member,
                "from_role": old_role,
                "role": role,
                "version": team["version"],
            })
            return {
                "status": "applied",
                "team_id": team_id,
                "member": member,
                "role": role,
                "version": team["version"],
            }

    def validate(self, team_id):
        with self._lock:
            team = self._get_team(team_id)
            violations = []
            for rule in self._rules.values():
                kind = rule["kind"]
                if kind == "role_limit":
                    names = [
                        entry["member"] for entry in team["members"]
                        if entry["role"] == rule.get("value")
                    ]
                    if len(names) > rule["limit"]:
                        violations.append({
                            "rule": rule["rule_id"],
                            "code": "TEAM_ROLE_LIMIT",
                            "role": rule.get("value"),
                            "limit": rule["limit"],
                            "members": names,
                        })
                elif kind == "power_min":
                    for entry in team["members"]:
                        if entry["role"] == "leader":
                            continue
                        if entry["power"] < rule.get("value", 0):
                            violations.append({
                                "rule": rule["rule_id"],
                                "code": "TEAM_POWER_MIN",
                                "member": entry["member"],
                                "power": entry["power"],
                                "min_power": rule.get("value"),
                            })
            return {
                "team_id": team_id,
                "ok": not violations,
                "violations": violations,
            }

    def members(self, team_id):
        with self._lock:
            team = self._get_team(team_id)
            return copy.deepcopy(team["members"])

    def stats(self, team_id):
        with self._lock:
            team = self._get_team(team_id)
            roles = {}
            total_power = 0
            for entry in team["members"]:
                roles[entry["role"]] = roles.get(entry["role"], 0) + 1
                total_power += entry["power"]
            return {
                "team_id": team_id,
                "owner": team["owner"],
                "member_count": len(team["members"]),
                "total_power": total_power,
                "roles": roles,
                "version": team["version"],
            }

    def snapshot(self, team_id):
        with self._lock:
            team = self._get_team(team_id)
            return {
                "team_id": team_id,
                "owner": team["owner"],
                "server": team["server"],
                "capacity": team["capacity"],
                "version": team["version"],
                "members": copy.deepcopy(team["members"]),
            }

    def restore(self, team_id, snapshot):
        with self._lock:
            team = self._get_team(team_id)
            if not isinstance(snapshot, dict) or \
                    snapshot.get("team_id") != team_id:
                raise TeamError("TEAM_SNAPSHOT_MISMATCH", {
                    "team_id": team_id,
                    "snapshot_team": snapshot.get("team_id")
                    if isinstance(snapshot, dict) else None,
                })

            snapshot_version = snapshot.get("version")
            if snapshot_version != team["version"] - 1:
                raise TeamError("TEAM_SNAPSHOT_STALE", {
                    "team_id": team_id,
                    "snapshot_version": snapshot_version,
                    "current_version": team["version"],
                })

            team["members"] = copy.deepcopy(snapshot["members"])
            team["owner"] = snapshot["owner"]
            team["server"] = snapshot["server"]
            team["capacity"] = snapshot["capacity"]
            team["version"] = snapshot_version
            self._record_audit(team_id, {
                "action": "restore",
                "snapshot_version": snapshot_version,
                "version": snapshot_version,
            })
            return {
                "status": "restored",
                "team_id": team_id,
                "version": snapshot_version,
            }

    def matchmaking_ticket(self, team_id):
        with self._lock:
            team = self._get_team(team_id)
            summary = self.stats(team_id)
            return {
                "team_id": team_id,
                "member_count": summary["member_count"],
                "total_power": summary["total_power"],
                "roles": copy.deepcopy(summary["roles"]),
                "version": team["version"],
            }

    def audit(self, team_id, limit=None):
        with self._lock:
            log = self._audits.get(team_id, [])
            if limit is not None:
                log = log[:limit]
            return copy.deepcopy(log)
