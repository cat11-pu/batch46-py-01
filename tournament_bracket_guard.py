"""Tournament bracket guard (batch46-game-b-02, Bugfix skeleton)."""

import copy
import threading


class BracketError(ValueError):
    """Raised when a bracket operation cannot be completed."""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = dict(detail or {})


def _bracket_order(size):
    """Standard seed layout: size 8 -> [1,8,4,5,2,7,3,6]."""
    order = [1]
    n = 1
    while n < size:
        n *= 2
        order = [seed for s in order for seed in (s, n + 1 - s)]
    return order


class BracketGuard:
    """Registration, seeding, pairing, results, standings and snapshots."""

    def __init__(self, *, size=8, max_rounds=3, audit_limit=200):
        self.size = size
        self.max_rounds = max_rounds
        self.audit_limit = audit_limit
        self._lock = threading.RLock()
        self._players = {}  # name -> {"rating": int, "seq": int}
        self._seq = 0
        self._rounds = {}  # round_no -> [match dict]
        self._champion = None
        self._locked = False
        self._audit = []

    def register(self, player, *, rating=1000, region="cn", event_id=None):
        with self._lock:
            if self._locked:
                raise BracketError("BKT_LOCKED", {"player": player})
            if player in self._players:
                return {
                    "status": "ignored",
                    "code": "BKT_DUP_PLAYER",
                    "player": player,
                    "count": len(self._players),
                }
            self._seq += 1
            self._players[player] = {"rating": rating, "seq": self._seq}
            self._log("register", player)
            return {
                "status": "applied",
                "player": player,
                "count": len(self._players),
            }

    def withdraw(self, player):
        with self._lock:
            if self._locked:
                raise BracketError("BKT_LOCKED", {"player": player})
            if player not in self._players:
                raise BracketError("BKT_UNKNOWN_PLAYER", {"player": player})
            del self._players[player]
            self._log("withdraw", player)
            return {"status": "applied", "player": player,
                    "count": len(self._players)}

    def seed_order(self):
        with self._lock:
            ranked = sorted(
                self._players.items(),
                key=lambda item: (-item[1]["rating"], item[1]["seq"]),
            )
            return [name for name, _ in ranked]

    def build_round(self, round_no):
        with self._lock:
            if round_no < 1 or round_no > self.max_rounds:
                raise BracketError("BKT_ROUND_LIMIT", {"round": round_no})
            if round_no in self._rounds:
                return copy.deepcopy(self._rounds[round_no])
            if self._champion is not None:
                raise BracketError("BKT_SEASON_CLOSED", {"round": round_no})
            if round_no == 1:
                matches = self._pair_first_round()
            else:
                prev = self._rounds.get(round_no - 1)
                if prev is None or any(m["winner"] is None for m in prev):
                    raise BracketError("BKT_ROUND_PENDING",
                                       {"round": round_no - 1})
                matches = self._pair_next_round(prev)
            self._rounds[round_no] = matches
            self._locked = True
            return copy.deepcopy(matches)

    def _pair_first_round(self):
        seeds = self.seed_order()
        slots = {index + 1: name for index, name in enumerate(seeds)}
        ordered = [slots.get(seed) for seed in _bracket_order(self.size)]
        return self._make_matches(1, ordered)

    def _pair_next_round(self, prev_matches):
        advancers = [m["winner"] for m in prev_matches]
        return self._make_matches(self._round_no_of(prev_matches) + 1,
                                  advancers)

    @staticmethod
    def _round_no_of(matches):
        return matches[0]["round"] if matches else 0

    def _make_matches(self, round_no, players):
        matches = []
        for index in range(0, len(players), 2):
            player_a = players[index]
            player_b = players[index + 1] if index + 1 < len(players) else None
            if player_a is None and player_b is None:
                continue
            bye = player_a is None or player_b is None
            matches.append({
                "match_id": "r%d-m%d" % (round_no, len(matches) + 1),
                "round": round_no,
                "player_a": player_a,
                "player_b": player_b,
                "bye": bye,
                "winner": player_a if player_b is None else player_b
                if player_a is None else None,
                "score": None,
            })
        return matches

    def record_result(self, match_id, winner, *, score="2-0", event_id=None):
        with self._lock:
            if self._champion is not None:
                raise BracketError("BKT_SEASON_CLOSED",
                                   {"match_id": match_id})
            match = self._find_match(match_id)
            if match is None:
                raise BracketError("BKT_UNKNOWN_MATCH",
                                   {"match_id": match_id})
            if match["winner"] is not None:
                raise BracketError("BKT_MATCH_DONE", {"match_id": match_id})
            if winner not in (match["player_a"], match["player_b"]):
                raise BracketError("BKT_UNKNOWN_WINNER",
                                   {"match_id": match_id, "winner": winner})
            match["winner"] = winner
            match["score"] = score
            round_matches = self._rounds[match["round"]]
            if (len(round_matches) == 1
                    and all(m["winner"] is not None for m in round_matches)):
                self._champion = winner
            return {"status": "applied", "match_id": match_id,
                    "winner": winner, "score": score}

    def _find_match(self, match_id):
        for matches in self._rounds.values():
            for match in matches:
                if match["match_id"] == match_id:
                    return match
        return None

    def current_round(self):
        with self._lock:
            return max(self._rounds) if self._rounds else 0

    def matches(self, round_no=None):
        with self._lock:
            if round_no is not None:
                return copy.deepcopy(self._rounds.get(round_no, []))
            out = []
            for key in sorted(self._rounds):
                out.extend(copy.deepcopy(self._rounds[key]))
            return out

    def byes(self, round_no):
        with self._lock:
            return [m["winner"] for m in self._rounds.get(round_no, [])
                    if m["bye"]]

    def standings(self):
        with self._lock:
            wins = {name: 0 for name in self._players}
            losses = {name: 0 for name in self._players}
            for key in sorted(self._rounds):
                for match in self._rounds[key]:
                    winner = match["winner"]
                    if winner is None:
                        continue
                    wins[winner] = wins.get(winner, 0) + 1
                    if not match["bye"]:
                        loser = (match["player_b"] if winner == match["player_a"]
                                 else match["player_a"])
                        if loser is not None:
                            losses[loser] = losses.get(loser, 0) + 1
            seeds = {name: index + 1
                     for index, name in enumerate(self.seed_order())}
            rows = [{
                "player": name,
                "wins": wins[name],
                "losses": losses[name],
                "seed": seeds[name],
            } for name in self._players]
            rows.sort(key=lambda row: (-row["wins"], row["seed"]))
            return rows

    def champion(self):
        with self._lock:
            return self._champion

    def audit(self, limit=None):
        with self._lock:
            cap = self.audit_limit if limit is None else limit
            return copy.deepcopy(self._audit[-cap:][::-1])

    def _log(self, action, player):
        self._audit.append({"action": action, "player": player})
        if len(self._audit) > self.audit_limit:
            del self._audit[: len(self._audit) - self.audit_limit]

    def snapshot(self):
        with self._lock:
            return {
                "players": copy.deepcopy(self._players),
                "seq": self._seq,
                "rounds": copy.deepcopy(self._rounds),
                "champion": self._champion,
                "locked": self._locked,
                "audit": copy.deepcopy(self._audit),
            }

    def restore(self, snapshot):
        with self._lock:
            self._players = copy.deepcopy(snapshot["players"])
            self._seq = snapshot["seq"]
            self._rounds = copy.deepcopy(snapshot["rounds"])
            self._champion = snapshot["champion"]
            self._locked = snapshot["locked"]
            self._audit = copy.deepcopy(snapshot["audit"])
            return {"status": "restored"}
