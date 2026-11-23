import copy
import threading
from typing import Dict, List, Optional


class HitError(ValueError):
    def __init__(self, code: str, detail: Optional[str] = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


SNAPSHOT_VERSION = 1


class HitRegistration:
    """Target registry, pending shots, damage resolution and LIFO rollback."""

    def __init__(self, *, max_pending: int = 8) -> None:
        self.max_pending = max_pending
        self._lock = threading.RLock()
        self._players: Dict[str, str] = {}
        self._targets: Dict[str, dict] = {}
        self._shots: Dict[str, dict] = {}
        self._pending: List[str] = []
        self._damage_logs: Dict[str, List[str]] = {}
        self._rollback_stack: List[str] = []
        self._kills: Dict[str, int] = {}
        self._stats = {
            "applied": 0,
            "ignored": 0,
            "friendly_kills": 0,
            "rolled_back": 0,
        }

    def join(self, player_id: str, team: str) -> None:
        with self._lock:
            self._players[player_id] = team

    def spawn(self, target_id: str, *, hp: int = 100, armor: int = 0,
              team: str = "red", tick: int = 0) -> dict:
        with self._lock:
            if target_id in self._targets:
                raise HitError("HIT_TARGET_DUP", target_id)
            if hp <= 0 or armor < 0:
                raise HitError("HIT_INVALID_STAT",
                               "hp=%r armor=%r" % (hp, armor))
            self._targets[target_id] = {
                "hp": hp,
                "armor": armor,
                "team": team,
                "alive": True,
                "spawn_tick": tick,
                "despawn_tick": None,
            }
            self._damage_logs[target_id] = []
            return self.state(target_id)

    def despawn(self, target_id: str, *, tick: int) -> dict:
        with self._lock:
            target = self._targets.get(target_id)
            if target is None:
                raise HitError("HIT_UNKNOWN_TARGET", target_id)
            target["despawn_tick"] = tick
            return self.state(target_id)

    def submit(self, shot_id: str, *, shooter: str, target: str, damage: int,
               tick: int, headshot: bool = False) -> dict:
        with self._lock:
            if shot_id in self._shots:
                return {"shot_id": shot_id, "status": "ignored",
                        "code": "HIT_DUP_SHOT"}
            if target not in self._targets:
                raise HitError("HIT_UNKNOWN_TARGET", target)
            if damage <= 0:
                raise HitError("HIT_INVALID_DAMAGE", repr(damage))
            if len(self._pending) >= self.max_pending:
                raise HitError("HIT_QUEUE_FULL",
                               "max_pending=%d" % self.max_pending)
            self._shots[shot_id] = {
                "shot_id": shot_id,
                "shooter": shooter,
                "target": target,
                "damage": damage,
                "tick": tick,
                "headshot": bool(headshot),
                "status": "pending",
                "before": None,
            }
            self._pending.append(shot_id)
            return {"shot_id": shot_id, "status": "pending"}

    def resolve(self, shot_id: str) -> dict:
        with self._lock:
            shot = self._shots.get(shot_id)
            if shot is None:
                raise HitError("HIT_UNKNOWN_SHOT", shot_id)
            status = shot["status"]
            if status == "cancelled":
                return {"shot_id": shot_id, "status": "ignored",
                        "code": "HIT_SHOT_CANCELLED"}
            if status != "pending":
                return {"shot_id": shot_id, "status": "ignored",
                        "code": "HIT_ALREADY_RESOLVED"}
            target = self._targets[shot["target"]]
            if not target["alive"]:
                return self._ignore(shot, "HIT_TARGET_DEAD")
            spawn_tick = target["spawn_tick"]
            despawn_tick = target["despawn_tick"]
            if (shot["tick"] < spawn_tick or
                    (despawn_tick is not None and
                     shot["tick"] > despawn_tick)):
                return self._ignore(shot, "HIT_STALE_TARGET")

            before = {
                "hp": target["hp"],
                "armor": target["armor"],
                "alive": target["alive"],
            }
            effective = shot["damage"] * (2 if shot["headshot"] else 1)
            absorbed = min(target["armor"], effective // 2)
            hp_loss = min(before["hp"], effective - absorbed)
            target["armor"] -= absorbed
            target["hp"] -= hp_loss
            killed = before["alive"] and target["hp"] == 0
            if killed:
                target["alive"] = False

            shooter = shot["shooter"]
            friendly = self._players.get(shooter) == target["team"]
            kill_credited = False
            if friendly:
                self._stats["friendly_kills"] += 1
            elif killed:
                self._kills[shooter] = self._kills.get(shooter, 0) + 1
                kill_credited = True

            shot["before"] = {
                "target": shot["target"],
                "shooter": shooter,
                "hp": before["hp"],
                "armor": before["armor"],
                "alive": before["alive"],
                "kill_credited": kill_credited,
                "friendly": friendly,
            }
            shot["status"] = "applied"
            self._pending.remove(shot_id)
            self._damage_logs[shot["target"]].append(shot_id)
            self._rollback_stack.append(shot_id)
            self._stats["applied"] += 1
            return {
                "shot_id": shot_id,
                "status": "applied",
                "damage": hp_loss,
                "absorbed": absorbed,
                "remaining_hp": target["hp"],
                "remaining_armor": target["armor"],
                "killed": killed,
            }

    def _ignore(self, shot: dict, code: str) -> dict:
        shot["status"] = "ignored"
        self._pending.remove(shot["shot_id"])
        self._stats["ignored"] += 1
        return {"shot_id": shot["shot_id"], "status": "ignored",
                "code": code}

    def resolve_pending(self) -> List[dict]:
        with self._lock:
            results = []
            for shot_id in self._sorted_pending():
                results.append(self.resolve(shot_id))
            return results

    def _sorted_pending(self) -> List[str]:
        return sorted(self._pending,
                      key=lambda sid: (self._shots[sid]["tick"], sid))

    def cancel(self, shot_id: str) -> bool:
        with self._lock:
            shot = self._shots.get(shot_id)
            if shot is None:
                raise HitError("HIT_UNKNOWN_SHOT", shot_id)
            if shot["status"] != "pending":
                raise HitError("HIT_CANCEL_STATE", shot["status"])
            shot["status"] = "cancelled"
            self._pending.remove(shot_id)
            return True

    def rollback(self, shot_id: str, *, reason: str = "cheat") -> dict:
        with self._lock:
            if not self._rollback_stack or self._rollback_stack[-1] != shot_id:
                raise HitError("HIT_ROLLBACK_ORDER", shot_id)
            self._rollback_stack.pop()
            shot = self._shots[shot_id]
            before = shot["before"]
            target = self._targets[before["target"]]
            target["hp"] = before["hp"]
            target["armor"] = before["armor"]
            target["alive"] = before["alive"]
            kills_reverted = 0
            if before["kill_credited"]:
                shooter = before["shooter"]
                self._kills[shooter] = self._kills.get(shooter, 1) - 1
                kills_reverted = 1
            if before["friendly"]:
                self._stats["friendly_kills"] -= 1
            self._damage_logs[before["target"]].remove(shot_id)
            shot["status"] = "rolled_back"
            shot["before"] = None
            self._stats["rolled_back"] += 1
            return {
                "shot_id": shot_id,
                "status": "rolled_back",
                "reason": reason,
                "health": target["hp"],
                "armor": target["armor"],
                "alive": target["alive"],
                "kills_reverted": kills_reverted,
            }

    def health(self, target_id: str) -> int:
        with self._lock:
            return self._target(target_id)["hp"]

    def armor(self, target_id: str) -> int:
        with self._lock:
            return self._target(target_id)["armor"]

    def kills(self, shooter: str) -> int:
        with self._lock:
            return self._kills.get(shooter, 0)

    def damage_log(self, target_id: str) -> List[str]:
        with self._lock:
            self._target(target_id)
            return list(self._damage_logs[target_id])

    def pending(self) -> List[str]:
        with self._lock:
            return self._sorted_pending()

    def state(self, target_id: str) -> dict:
        with self._lock:
            target = self._target(target_id)
            return {
                "target_id": target_id,
                "hp": target["hp"],
                "armor": target["armor"],
                "team": target["team"],
                "alive": target["alive"],
                "spawn_tick": target["spawn_tick"],
                "despawn_tick": target["despawn_tick"],
            }

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    def snapshot(self) -> dict:
        with self._lock:
            return copy.deepcopy({
                "version": SNAPSHOT_VERSION,
                "max_pending": self.max_pending,
                "players": self._players,
                "targets": self._targets,
                "shots": self._shots,
                "pending": self._pending,
                "damage_logs": self._damage_logs,
                "rollback_stack": self._rollback_stack,
                "kills": self._kills,
                "stats": self._stats,
            })

    def restore(self, snapshot: dict) -> None:
        with self._lock:
            if snapshot.get("version") != SNAPSHOT_VERSION:
                raise HitError("HIT_SNAPSHOT_VERSION",
                               repr(snapshot.get("version")))
            state = copy.deepcopy(snapshot)
            self.max_pending = state["max_pending"]
            self._players = state["players"]
            self._targets = state["targets"]
            self._shots = state["shots"]
            self._pending = state["pending"]
            self._damage_logs = state["damage_logs"]
            self._rollback_stack = state["rollback_stack"]
            self._kills = state["kills"]
            self._stats = state["stats"]

    def _target(self, target_id: str) -> dict:
        target = self._targets.get(target_id)
        if target is None:
            raise HitError("HIT_UNKNOWN_TARGET", target_id)
        return target
