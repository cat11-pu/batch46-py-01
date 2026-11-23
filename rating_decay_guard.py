"""PvP rating bookkeeping: zero-sum Elo, inactivity decay and comeback refunds."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import math
import threading


class RatingError(ValueError):
    """Structured error carrying a machine readable code."""

    def __init__(self, code: str, detail=None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class RatingDecay:
    FLOOR = 100
    CEILING = 3000
    BASE_K = 32
    PROVISIONAL_K = 64
    PROVISIONAL_MATCHES = 5
    DECAY_GRACE_DAYS = 14
    DECAY_PER_WEEK = 25
    DECAY_CAP = 100
    DECAY_PROTECT_BELOW = 1000
    COMEBACK_MATCHES = 3
    COMEBACK_RATE = 0.5
    COMEBACK_CAP = 60
    SNAPSHOT_VERSION = 1

    _SNAPSHOT_FIELDS = ("players", "matches", "history", "decay", "seq")

    def __init__(self, policy: dict | None = None) -> None:
        self._players: dict = {}
        self._matches: dict = {}
        self._history: list = []
        self._decay: dict = {}
        self._comeback: dict = {}
        self._seq = 0
        self._lock = threading.RLock()
        self._policy = dict(policy or {})

    # ------------------------------------------------------------------
    # Time helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _parse_time(value) -> datetime:
        if value is None:
            return datetime.now(timezone.utc)
        if isinstance(value, datetime):
            parsed = value
        elif isinstance(value, (int, float)) and not isinstance(value, bool):
            parsed = datetime.fromtimestamp(value, timezone.utc)
        elif isinstance(value, str):
            text = value.strip()
            if text.endswith(("Z", "z")):
                text = text[:-1] + "+00:00"
            parsed = datetime.fromisoformat(text)
        else:
            raise TypeError(f"unsupported timestamp: {value!r}")

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        else:
            parsed = parsed.astimezone(timezone.utc)
        return parsed

    @classmethod
    def _iso_time(cls, value) -> str:
        return cls._parse_time(value).isoformat()

    @staticmethod
    def _round_half_up(value: float) -> int:
        return int(math.floor(value + 0.5 + 1e-12))

    @classmethod
    def _clamp(cls, value: int) -> int:
        return max(cls.FLOOR, min(cls.CEILING, int(value)))

    def _require_player(self, player_id: str) -> dict:
        try:
            return self._players[player_id]
        except (KeyError, TypeError):
            raise RatingError("RATING_UNKNOWN_PLAYER", player_id) from None

    @staticmethod
    def _touch(player: dict, occurred: datetime) -> None:
        old = RatingDecay._parse_time(player.get("last_active"))
        if occurred > old:
            player["last_active"] = occurred.isoformat()

    def _count_comeback_match(self, player_id: str) -> None:
        state = self._comeback.get(player_id)
        if state and not state.get("claimed") and state.get("decay_total", 0) > 0:
            state["matches"] = int(state.get("matches", 0)) + 1

    # ------------------------------------------------------------------
    # Registration and ratings
    # ------------------------------------------------------------------
    def register(self, player_id: str, rating: int = 1500, region: str = "global",
                 *, now=None) -> dict:
        with self._lock:
            if player_id in self._players:
                raise RatingError("RATING_DUPLICATE_PLAYER", player_id)

            registered_at = self._iso_time(now)
            player = {
                "rating": self._clamp(rating),
                "region": region,
                "provisional_left": self.PROVISIONAL_MATCHES,
                "retired": False,
                "matches_played": 0,
                "created_at": registered_at,
                "last_active": registered_at,
            }
            self._players[player_id] = player
            return {
                "player": player_id,
                "status": "registered",
                "rating": player["rating"],
                "region": player["region"],
                "provisional_left": player["provisional_left"],
            }

    def rating(self, player_id: str) -> int:
        with self._lock:
            return int(self._require_player(player_id)["rating"])

    # ------------------------------------------------------------------
    # Match settlement
    # ------------------------------------------------------------------
    def record_match(self, match_id: str, winner: str, loser: str, *,
                     occurred_at=None, season: str = "s1") -> dict:
        with self._lock:
            if match_id in self._matches:
                original = self._matches[match_id]
                return {
                    "match_id": match_id,
                    "status": "ignored",
                    "code": "RATING_DUP_MATCH",
                    "winner": original.get("winner"),
                    "loser": original.get("loser"),
                    "k": original.get("k"),
                }

            winner_state = self._require_player(winner)
            loser_state = self._require_player(loser)
            if winner == loser:
                raise RatingError("RATING_SELF_MATCH", winner)

            occurred = self._parse_time(occurred_at)
            winner_before = int(winner_state["rating"])
            loser_before = int(loser_state["rating"])

            k = (self.PROVISIONAL_K
                 if int(winner_state.get("provisional_left", 0)) > 0
                 else self.BASE_K)
            expected = 1.0 / (
                1.0 + 10.0 ** ((loser_before - winner_before) / 400.0)
            )
            raw_delta = self._round_half_up(k * (1.0 - expected))

            winner_after = self._clamp(winner_before + raw_delta)
            loser_after = self._clamp(loser_before - raw_delta)
            winner_delta = winner_after - winner_before
            loser_delta = loser_after - loser_before

            winner_state["rating"] = winner_after
            loser_state["rating"] = loser_after
            winner_state["provisional_left"] = max(
                0, int(winner_state.get("provisional_left", 0)) - 1
            )
            loser_state["provisional_left"] = max(
                0, int(loser_state.get("provisional_left", 0)) - 1
            )
            winner_state["matches_played"] = int(winner_state.get("matches_played", 0)) + 1
            loser_state["matches_played"] = int(loser_state.get("matches_played", 0)) + 1
            self._touch(winner_state, occurred)
            self._touch(loser_state, occurred)
            self._count_comeback_match(winner)
            self._count_comeback_match(loser)

            self._seq += 1
            entry = {
                "match_id": match_id,
                "winner": winner,
                "loser": loser,
                "k": k,
                "season": season,
                "occurred_at": occurred.isoformat(),
                "expected_winner_probability": expected,
                "winner_delta": winner_delta,
                "loser_delta": loser_delta,
                "winner_rating": winner_after,
                "loser_rating": loser_after,
                "seq": self._seq,
            }
            self._history.append(entry)
            self._matches[match_id] = {
                "match_id": match_id,
                "winner": winner,
                "loser": loser,
                "k": k,
                "season": season,
                "occurred_at": occurred.isoformat(),
                "seq": self._seq,
            }

            result = dict(entry)
            result["status"] = "applied"
            result["code"] = None
            return result

    def record_matches(self, matches) -> list:
        rows = list(matches)

        def sort_key(row):
            occurred = row.get("occurred_at")
            if occurred is None:
                return (datetime.max.replace(tzinfo=timezone.utc),)
            return (self._parse_time(occurred),)

        ordered = sorted(rows, key=sort_key)
        results = []
        with self._lock:
            for row in ordered:
                results.append(self.record_match(
                    row["match_id"],
                    row["winner"],
                    row["loser"],
                    occurred_at=row.get("occurred_at"),
                    season=row.get("season", "s1"),
                ))
        return results

    def history(self, player_id: str, limit: int = 10) -> list:
        with self._lock:
            self._require_player(player_id)
            rows = [
                row for row in self._history
                if row.get("winner") == player_id or row.get("loser") == player_id
            ]
            rows.sort(
                key=lambda row: (
                    self._parse_time(row.get("occurred_at")),
                    int(row.get("seq", 0)),
                ),
                reverse=True,
            )
            if limit is not None:
                rows = rows[:max(0, int(limit))]
            return deepcopy(rows)

    # ------------------------------------------------------------------
    # Decay and comeback compensation
    # ------------------------------------------------------------------
    def apply_decay(self, season: str, now) -> list:
        now_dt = self._parse_time(now)
        reports = []
        with self._lock:
            applied_this_season = self._decay.setdefault(season, {})
            for player_id in sorted(self._players):
                player = self._players[player_id]
                current = int(player["rating"])

                if player_id in applied_this_season:
                    reports.append({
                        "player": player_id,
                        "season": season,
                        "status": "skipped",
                        "code": "RATING_DECAY_APPLIED",
                        "delta": 0,
                        "rating": current,
                    })
                    continue

                last_active = self._parse_time(player.get("last_active"))
                idle_seconds = (now_dt - last_active).total_seconds()
                if idle_seconds < self.DECAY_GRACE_DAYS * 86400:
                    reports.append({
                        "player": player_id,
                        "season": season,
                        "status": "skipped",
                        "code": "RATING_DECAY_GRACE",
                        "delta": 0,
                        "rating": current,
                    })
                    continue

                periods = 1 + int(
                    (idle_seconds - self.DECAY_GRACE_DAYS * 86400) // (7 * 86400)
                )
                nominal = min(periods * self.DECAY_PER_WEEK, self.DECAY_CAP)
                deductible = max(0, current - self.DECAY_PROTECT_BELOW)
                delta = min(nominal, deductible)
                player["rating"] = current - delta

                applied_this_season[player_id] = {
                    "amount": delta,
                    "periods": periods,
                    "at": now_dt.isoformat(),
                }
                if delta > 0:
                    state = self._comeback.setdefault(player_id, {
                        "decay_total": 0,
                        "matches": 0,
                        "claimed": False,
                        "refund": 0,
                        "claimed_at": None,
                    })
                    state["decay_total"] = int(state.get("decay_total", 0)) + delta
                    state["matches"] = 0

                reports.append({
                    "player": player_id,
                    "season": season,
                    "status": "applied",
                    "code": None,
                    "delta": -delta,
                    "rating": player["rating"],
                })
        return reports

    def claim_comeback(self, player_id: str, *, now=None) -> dict:
        claimed_at = self._iso_time(now)
        with self._lock:
            player = self._require_player(player_id)
            state = self._comeback.get(player_id)

            if (not state or state.get("claimed")
                    or int(state.get("decay_total", 0)) <= 0):
                return {
                    "player": player_id,
                    "status": "empty",
                    "code": "RATING_NO_COMEBACK",
                    "refund": 0,
                    "rating": int(player["rating"]),
                }

            if int(state.get("matches", 0)) < self.COMEBACK_MATCHES:
                raise RatingError("RATING_COMEBACK_NOT_READY", {
                    "player": player_id,
                    "matches": int(state.get("matches", 0)),
                    "required": self.COMEBACK_MATCHES,
                })

            nominal_refund = min(
                self.COMEBACK_CAP,
                int(state["decay_total"] * self.COMEBACK_RATE),
            )
            before = int(player["rating"])
            player["rating"] = self._clamp(before + nominal_refund)
            refund = int(player["rating"]) - before

            state["claimed"] = True
            state["refund"] = refund
            state["claimed_at"] = claimed_at

            return {
                "player": player_id,
                "status": "applied",
                "code": None,
                "refund": refund,
                "rating": int(player["rating"]),
            }

    # ------------------------------------------------------------------
    # Presentation and lifecycle
    # ------------------------------------------------------------------
    def leaderboard(self, region: str | None = None, limit: int = 10) -> list:
        with self._lock:
            rows = []
            for player_id, player in self._players.items():
                if player.get("retired", False):
                    continue
                if region is not None and player.get("region", "global") != region:
                    continue
                rows.append({
                    "player": player_id,
                    "rating": int(player["rating"]),
                    "region": player.get("region", "global"),
                })
            rows.sort(key=lambda row: (-row["rating"], row["player"]))
            if limit is not None:
                rows = rows[:max(0, int(limit))]
            return rows

    def retire(self, player_id: str) -> dict:
        with self._lock:
            player = self._require_player(player_id)
            player["retired"] = True
            return {
                "player": player_id,
                "status": "retired",
                "rating": int(player["rating"]),
            }

    def stats(self) -> dict:
        with self._lock:
            return {
                "players": len(self._players),
                "matches": len(self._matches),
                "history": len(self._history),
                "decay_seasons": len(self._decay),
                "comeback_claims": sum(
                    1 for state in self._comeback.values() if state.get("claimed")
                ),
            }

    # ------------------------------------------------------------------
    # Snapshot / restore
    # ------------------------------------------------------------------
    def snapshot(self) -> dict:
        with self._lock:
            return deepcopy({
                "version": self.SNAPSHOT_VERSION,
                "players": self._players,
                "matches": self._matches,
                "history": self._history,
                "decay": self._decay,
                "comeback": self._comeback,
                "seq": self._seq,
            })

    @classmethod
    def _bad_snapshot(cls, detail=None):
        raise RatingError("RATING_BAD_SNAPSHOT", detail)

    @classmethod
    def _validate_snapshot(cls, state: dict) -> dict:
        if not isinstance(state, dict):
            cls._bad_snapshot("snapshot must be an object")
        if state.get("version") != cls.SNAPSHOT_VERSION:
            cls._bad_snapshot("unsupported version")
        for field in cls._SNAPSHOT_FIELDS:
            if field not in state:
                cls._bad_snapshot(f"missing field: {field}")

        try:
            snapshot = deepcopy(state)
        except Exception as exc:  # pragma: no cover - defensive
            cls._bad_snapshot(exc)

        players = snapshot["players"]
        matches = snapshot["matches"]
        history = snapshot["history"]
        decay = snapshot["decay"]
        seq = snapshot["seq"]
        if not isinstance(players, dict):
            cls._bad_snapshot("players must be an object")
        if not isinstance(matches, dict):
            cls._bad_snapshot("matches must be an object")
        if not isinstance(history, list):
            cls._bad_snapshot("history must be a list")
        if not isinstance(decay, dict):
            cls._bad_snapshot("decay must be an object")
        if not isinstance(seq, int) or isinstance(seq, bool):
            cls._bad_snapshot("seq must be an integer")

        for player_id, player in players.items():
            if not isinstance(player_id, str) or not isinstance(player, dict):
                cls._bad_snapshot("invalid player entry")
            rating = player.get("rating")
            if (not isinstance(rating, int) or isinstance(rating, bool)
                    or not cls.FLOOR <= rating <= cls.CEILING):
                cls._bad_snapshot("invalid player rating")
            region = player.setdefault("region", "global")
            if not isinstance(region, str):
                cls._bad_snapshot("invalid player region")
            provisional = player.setdefault(
                "provisional_left", cls.PROVISIONAL_MATCHES
            )
            if not isinstance(provisional, int) or isinstance(provisional, bool):
                cls._bad_snapshot("invalid provisional_left")
            retired = player.setdefault("retired", False)
            if not isinstance(retired, bool):
                cls._bad_snapshot("invalid retired flag")
            played = player.setdefault("matches_played", 0)
            if not isinstance(played, int) or isinstance(played, bool):
                cls._bad_snapshot("invalid matches_played")
            player.setdefault("created_at", player.get("last_active"))
            player.setdefault("last_active", player.get("created_at"))

        for match in matches.values():
            if not isinstance(match, dict):
                cls._bad_snapshot("invalid match entry")
        for row in history:
            if not isinstance(row, dict):
                cls._bad_snapshot("invalid history entry")
        for ledger in decay.values():
            if not isinstance(ledger, dict):
                cls._bad_snapshot("invalid decay ledger")

        comeback = snapshot.setdefault("comeback", {})
        if not isinstance(comeback, dict):
            cls._bad_snapshot("comeback must be an object")
        return snapshot

    def restore(self, state: dict) -> None:
        with self._lock:
            snapshot = self._validate_snapshot(state)
            self._players = snapshot["players"]
            self._matches = snapshot["matches"]
            self._history = snapshot["history"]
            self._decay = snapshot["decay"]
            self._comeback = snapshot["comeback"]
            self._seq = snapshot["seq"]
