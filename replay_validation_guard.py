import copy
import hashlib
import json
import threading
from typing import List, Optional, Sequence


class ReplayError(ValueError):
    def __init__(self, code: str, detail: Optional[str] = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


def _canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, default=str)


def _hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _sorted_players(players: Sequence[str]) -> List[str]:
    return sorted(set(players))


def _header_seed(match_id: str, players: Sequence[str], ruleset: str) -> str:
    return _hash("replay-header:" + _canonical({
        "match_id": match_id,
        "players": _sorted_players(players),
        "ruleset": ruleset,
    }))


def _frame_checksum(prev: str, seq: int, tick: int, input_payload) -> str:
    return _hash("replay-frame:" + prev + ":" + _canonical({
        "seq": seq,
        "tick": tick,
        "input": input_payload,
    }))


def _checkpoint_checksum(payload: dict) -> str:
    return _hash("replay-checkpoint:" + _canonical(payload))


def _frame_field_error(frame) -> Optional[str]:
    if not isinstance(frame, dict):
        return "frame must be a dict"
    for key in ("seq", "tick"):
        if key not in frame:
            return "missing %s" % key
        value = frame[key]
        if isinstance(value, bool) or not isinstance(value, int):
            return "%s must be an int" % key
    return None


class ReplayValidator:
    """Hash-chained replay recording, streaming verification and checkpoints."""

    def __init__(self, *, max_frames: int = 4096) -> None:
        self.max_frames = max_frames
        self._lock = threading.Lock()
        self._active = False
        self._match_id: Optional[str] = None
        self._players: List[str] = []
        self._ruleset: str = "v1"
        self._seed: Optional[str] = None
        self._digest: Optional[str] = None
        self._frames: List[dict] = []
        self._count = 0
        self._last_tick: Optional[int] = None

    def _require_session(self) -> None:
        if not self._active:
            raise ReplayError("REPLAY_NO_SESSION")

    def _header_locked(self) -> dict:
        return {
            "match_id": self._match_id,
            "players": list(self._players),
            "ruleset": self._ruleset,
            "digest": self._seed,
        }

    def begin(self, match_id: str, *, players: Sequence[str] = (),
              ruleset: str = "v1") -> dict:
        with self._lock:
            if self._active:
                raise ReplayError("REPLAY_ACTIVE")
            self._active = True
            self._match_id = match_id
            self._players = _sorted_players(players)
            self._ruleset = ruleset
            self._seed = _header_seed(match_id, self._players, ruleset)
            self._digest = self._seed
            self._frames = []
            self._count = 0
            self._last_tick = None
            return self._header_locked()

    def append(self, frame: dict) -> dict:
        with self._lock:
            self._require_session()
            problem = _frame_field_error(frame)
            if problem is not None:
                raise ReplayError("REPLAY_FRAME_INVALID", problem)
            if self._count >= self.max_frames:
                raise ReplayError("REPLAY_FRAME_LIMIT",
                                  "max_frames=%d reached" % self.max_frames)
            seq = frame["seq"]
            tick = frame["tick"]
            if seq != self._count:
                raise ReplayError("REPLAY_SEQ_GAP",
                                  "expected seq %d, got %d" % (self._count, seq))
            if self._last_tick is not None and tick < self._last_tick:
                raise ReplayError("REPLAY_TICK_REGRESS",
                                  "tick %d < %d" % (tick, self._last_tick))
            checksum = _frame_checksum(self._digest, seq, tick,
                                       frame.get("input"))
            stored = copy.deepcopy(frame)
            stored["prev"] = self._digest
            stored["checksum"] = checksum
            self._frames.append(stored)
            self._digest = checksum
            self._count += 1
            self._last_tick = tick
            return {"seq": seq, "frames": self._count, "digest": checksum}

    def finish(self) -> dict:
        with self._lock:
            self._require_session()
            summary = {
                "match_id": self._match_id,
                "players": list(self._players),
                "ruleset": self._ruleset,
                "frames": self._count,
                "final_digest": self._digest,
            }
            self._active = False
            return summary

    def abort(self) -> bool:
        with self._lock:
            self._require_session()
            self._active = False
            self._frames = []
            self._count = 0
            self._last_tick = None
            self._digest = None
            self._seed = None
            self._match_id = None
            self._players = []
            self._ruleset = "v1"
            return True

    def digest(self) -> str:
        with self._lock:
            self._require_session()
            return self._digest

    def header(self) -> dict:
        with self._lock:
            if self._seed is None:
                return {}
            return self._header_locked()

    def frames(self) -> List[dict]:
        with self._lock:
            return copy.deepcopy(self._frames)

    def checkpoint(self) -> dict:
        with self._lock:
            self._require_session()
            payload = {
                "match_id": self._match_id,
                "players": list(self._players),
                "ruleset": self._ruleset,
                "frames": self._count,
                "digest": self._digest,
                "last_tick": self._last_tick,
            }
            payload["checksum"] = _checkpoint_checksum(payload)
            return payload

    def resume(self, checkpoint: dict) -> dict:
        with self._lock:
            if self._active:
                raise ReplayError("REPLAY_ACTIVE")
            keys = ("match_id", "players", "ruleset", "frames", "digest",
                    "last_tick")
            if not isinstance(checkpoint, dict) or \
                    any(key not in checkpoint for key in keys) or \
                    "checksum" not in checkpoint:
                raise ReplayError("REPLAY_CHECKPOINT_INVALID",
                                  "missing checkpoint fields")
            payload = {key: checkpoint[key] for key in keys}
            if _checkpoint_checksum(payload) != checkpoint["checksum"]:
                raise ReplayError("REPLAY_CHECKPOINT_INVALID",
                                  "checksum mismatch")
            if isinstance(payload["frames"], bool) or \
                    not isinstance(payload["frames"], int) or \
                    payload["frames"] < 0:
                raise ReplayError("REPLAY_CHECKPOINT_INVALID",
                                  "bad frame count")
            self._active = True
            self._match_id = payload["match_id"]
            self._players = _sorted_players(payload["players"])
            self._ruleset = payload["ruleset"]
            self._seed = _header_seed(self._match_id, self._players,
                                      self._ruleset)
            self._digest = payload["digest"]
            self._frames = []
            self._count = payload["frames"]
            self._last_tick = payload["last_tick"]
            return self._header_locked()

    def verify(self, frames: List[dict], *, header: Optional[dict] = None) -> dict:
        if not frames:
            return {"ok": False, "code": "REPLAY_EMPTY"}
        if header is not None:
            if not isinstance(header, dict):
                return {"ok": False, "code": "REPLAY_HEADER_MISMATCH",
                        "index": 0}
            seed = _header_seed(header.get("match_id"),
                                header.get("players", ()),
                                header.get("ruleset"))
            if "digest" in header and header["digest"] != seed:
                return {"ok": False, "code": "REPLAY_HEADER_MISMATCH",
                        "index": 0}
            prev = seed
        else:
            prev = None
        last_tick = None
        for index, frame in enumerate(frames):
            if _frame_field_error(frame) is not None:
                return {"ok": False, "code": "REPLAY_FRAME_INVALID",
                        "index": index}
            seq = frame["seq"]
            tick = frame["tick"]
            if seq != index:
                return {"ok": False, "code": "REPLAY_SEQ_GAP",
                        "index": index}
            if last_tick is not None and tick < last_tick:
                return {"ok": False, "code": "REPLAY_TICK_REGRESS",
                        "index": index}
            stored_prev = frame.get("prev")
            if prev is None:
                prev = stored_prev
            elif stored_prev is not None and stored_prev != prev:
                code = "REPLAY_HEADER_MISMATCH" \
                    if index == 0 and header is not None \
                    else "REPLAY_CHECKSUM_MISMATCH"
                return {"ok": False, "code": code, "index": index}
            checksum = _frame_checksum(prev, seq, tick, frame.get("input"))
            if frame.get("checksum") != checksum:
                code = "REPLAY_HEADER_MISMATCH" \
                    if index == 0 and header is not None \
                    and stored_prev is None \
                    else "REPLAY_CHECKSUM_MISMATCH"
                return {"ok": False, "code": code, "index": index}
            prev = checksum
            last_tick = tick
        return {"ok": True, "frames": len(frames), "digest": prev}

    def outcome(self) -> dict:
        with self._lock:
            scores = {}
            for frame in self._frames:
                input_payload = frame.get("input")
                if not isinstance(input_payload, dict):
                    continue
                score = input_payload.get("score")
                if not isinstance(score, dict):
                    continue
                for team, points in score.items():
                    if isinstance(points, bool) or \
                            not isinstance(points, (int, float)):
                        continue
                    scores[team] = scores.get(team, 0) + points
            if not scores:
                winner = "draw"
            else:
                best = max(scores.values())
                leaders = [team for team, value in scores.items()
                           if value == best]
                winner = leaders[0] if len(leaders) == 1 else "draw"
            return {"scores": scores, "winner": winner}

    def stats(self) -> dict:
        with self._lock:
            return {
                "match_id": self._match_id,
                "players": list(self._players),
                "ruleset": self._ruleset,
                "active": self._active,
                "frames": self._count,
                "digest": self._digest,
                "max_frames": self.max_frames,
            }
