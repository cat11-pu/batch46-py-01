"""Stamina regeneration: timed accrual, caps, daily resets and refills."""

from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone


class EnergyError(ValueError):
    """Structured error carrying a machine readable code."""

    def __init__(self, code: str, detail=None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


def _parse_now(now) -> datetime:
    if now is None:
        return datetime.now(timezone.utc)
    if isinstance(now, str):
        text = now.strip()
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError as exc:
            raise EnergyError("ENERGY_BAD_TIMESTAMP", now) from exc
    elif isinstance(now, datetime):
        parsed = now
    else:
        raise EnergyError("ENERGY_BAD_TIMESTAMP", now)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).isoformat()


def _valid_amount(amount) -> bool:
    return isinstance(amount, int) and not isinstance(amount, bool) and amount > 0


def _effective_now(account: dict, now) -> datetime:
    if now is None:
        return account["last_at"]
    return _parse_now(now)


class EnergyRegen:
    SECONDS_PER_POINT = 300
    MAX_OFFLINE_SECONDS = 43200
    OVERFLOW_MARGIN = 60
    REFILLS_PER_DAY = 3
    SNAPSHOT_VERSION = 1

    def __init__(self, *, default_cap: int = 120) -> None:
        self._default_cap = default_cap
        self._accounts: dict = {}
        self._refs: dict = {}
        self._history: list = []
        self._lock = threading.RLock()

    def _get_account(self, account_id: str) -> dict:
        try:
            return self._accounts[account_id]
        except KeyError:
            raise EnergyError("ENERGY_UNKNOWN_ACCOUNT", account_id) from None

    def _log(self, account_id: str, event: str, moment: datetime, **fields) -> None:
        entry = {"account": account_id, "event": event, "at": _iso(moment)}
        entry.update(fields)
        self._history.append(entry)

    def _apply_regen(self, account: dict, now: datetime) -> None:
        last_at = account["last_at"]
        if now < last_at:
            raise EnergyError("ENERGY_CLOCK_REGRESSION",
                              {"last_at": _iso(last_at), "now": _iso(now)})
        if now == last_at:
            return
        if account["energy"] >= account["cap"]:
            account["remainder"] = 0
            account["last_at"] = now
            return
        elapsed = int((now - last_at).total_seconds())
        elapsed = min(elapsed, self.MAX_OFFLINE_SECONDS)
        total = account["remainder"] + elapsed
        ticks, remainder = divmod(total, self.SECONDS_PER_POINT)
        new_energy = account["energy"] + ticks
        if new_energy >= account["cap"]:
            account["energy"] = account["cap"]
            account["remainder"] = 0
        else:
            account["energy"] = new_energy
            account["remainder"] = remainder
        account["last_at"] = now

    def _state_dict(self, account: dict) -> dict:
        return {
            "energy": account["energy"],
            "cap": account["cap"],
            "remainder": account["remainder"],
            "last_at": _iso(account["last_at"]),
            "next_full_at": self._next_full_at(account),
        }

    def _next_full_at(self, account: dict):
        if account["energy"] >= account["cap"]:
            return None
        missing = account["cap"] - account["energy"]
        seconds = missing * self.SECONDS_PER_POINT - account["remainder"]
        return _iso(account["last_at"] + timedelta(seconds=seconds))

    def create_account(self, account_id: str, *, energy: int | None = None,
                       cap: int | None = None, now=None) -> dict:
        with self._lock:
            if account_id in self._accounts:
                raise EnergyError("ENERGY_ACCOUNT_EXISTS", account_id)
            cap_value = self._default_cap if cap is None else cap
            if not _valid_amount(cap_value):
                raise EnergyError("ENERGY_INVALID_AMOUNT", cap)
            energy_value = 0 if energy is None else energy
            if isinstance(energy_value, bool) or not isinstance(energy_value, int) \
                    or energy_value < 0:
                raise EnergyError("ENERGY_INVALID_AMOUNT", energy)
            moment = _parse_now(now)
            account = {
                "energy": energy_value,
                "cap": cap_value,
                "remainder": 0,
                "last_at": moment,
                "reset_day": None,
                "refill_day": None,
                "refills": 0,
            }
            self._accounts[account_id] = account
            self._log(account_id, "create", moment,
                      energy=energy_value, cap=cap_value)
            return self._state_dict(account)

    def regen(self, account_id: str, now) -> dict:
        with self._lock:
            account = self._get_account(account_id)
            moment = _effective_now(account, now)
            self._apply_regen(account, moment)
            return self._state_dict(account)

    def state(self, account_id: str, now=None) -> dict:
        with self._lock:
            account = self._get_account(account_id)
            moment = _effective_now(account, now)
            self._apply_regen(account, moment)
            return self._state_dict(account)

    def next_full_at(self, account_id: str, now=None):
        with self._lock:
            account = self._get_account(account_id)
            moment = _effective_now(account, now)
            self._apply_regen(account, moment)
            return self._next_full_at(account)

    def spend(self, account_id: str, amount: int, *, now=None,
              ref: str | None = None) -> dict:
        if not _valid_amount(amount):
            raise EnergyError("ENERGY_INVALID_AMOUNT", amount)
        with self._lock:
            account = self._get_account(account_id)
            if ref is not None:
                stored = self._refs.get(account_id, {}).get(ref)
                if stored is not None:
                    replay = dict(stored)
                    replay["status"] = "replayed"
                    return replay
            moment = _effective_now(account, now)
            self._apply_regen(account, moment)
            if account["energy"] < amount:
                raise EnergyError("ENERGY_INSUFFICIENT",
                                  {"energy": account["energy"], "amount": amount})
            account["energy"] -= amount
            result = {
                "status": "applied",
                "spent": amount,
                "energy": account["energy"],
                "ref": ref,
            }
            if ref is not None:
                self._refs.setdefault(account_id, {})[ref] = dict(result)
            self._log(account_id, "spend", moment,
                      amount=amount, energy=account["energy"])
            return result

    def grant(self, account_id: str, amount: int, *, now=None,
              allow_overflow: bool = False) -> dict:
        if not _valid_amount(amount):
            raise EnergyError("ENERGY_INVALID_AMOUNT", amount)
        with self._lock:
            account = self._get_account(account_id)
            moment = _effective_now(account, now)
            self._apply_regen(account, moment)
            limit = account["cap"]
            if allow_overflow:
                limit += self.OVERFLOW_MARGIN
            room = max(0, limit - account["energy"])
            granted = min(amount, room)
            wasted = amount - granted
            account["energy"] += granted
            if account["energy"] >= account["cap"]:
                account["remainder"] = 0
            self._log(account_id, "grant", moment,
                      granted=granted, wasted=wasted, energy=account["energy"])
            return {
                "status": "applied",
                "granted": granted,
                "wasted": wasted,
                "energy": account["energy"],
            }

    def daily_reset(self, account_id: str, now) -> dict:
        with self._lock:
            account = self._get_account(account_id)
            moment = _effective_now(account, now)
            self._apply_regen(account, moment)
            day = moment.date().isoformat()
            if account["reset_day"] == day:
                return {
                    "status": "skipped",
                    "code": "ENERGY_RESET_DONE",
                    "energy": account["energy"],
                }
            account["reset_day"] = day
            account["energy"] = account["cap"]
            account["remainder"] = 0
            account["last_at"] = moment
            self._log(account_id, "daily_reset", moment, energy=account["energy"])
            return {"status": "applied", "energy": account["energy"]}

    def buy_refill(self, account_id: str, *, now=None) -> dict:
        with self._lock:
            account = self._get_account(account_id)
            moment = _effective_now(account, now)
            self._apply_regen(account, moment)
            if account["energy"] >= account["cap"]:
                raise EnergyError("ENERGY_ALREADY_FULL", account_id)
            day = moment.date().isoformat()
            if account["refill_day"] != day:
                account["refill_day"] = day
                account["refills"] = 0
            if account["refills"] >= self.REFILLS_PER_DAY:
                raise EnergyError("ENERGY_REFILL_LIMIT",
                                  {"refills_today": account["refills"]})
            account["refills"] += 1
            account["energy"] = account["cap"]
            account["remainder"] = 0
            account["last_at"] = moment
            self._log(account_id, "buy_refill", moment,
                      energy=account["energy"], refills_today=account["refills"])
            return {
                "status": "applied",
                "energy": account["energy"],
                "refills_today": account["refills"],
            }

    def history(self, account_id: str, limit: int = 10) -> list:
        with self._lock:
            self._get_account(account_id)
            entries = [dict(entry) for entry in self._history
                       if entry["account"] == account_id]
            entries.reverse()
            return entries[:limit]

    def stats(self) -> dict:
        with self._lock:
            return {
                "accounts": len(self._accounts),
                "refs": sum(len(refs) for refs in self._refs.values()),
                "history": len(self._history),
            }

    def snapshot(self) -> dict:
        with self._lock:
            accounts = {}
            for account_id, account in self._accounts.items():
                accounts[account_id] = {
                    "energy": account["energy"],
                    "cap": account["cap"],
                    "remainder": account["remainder"],
                    "last_at": _iso(account["last_at"]),
                    "reset_day": account["reset_day"],
                    "refill_day": account["refill_day"],
                    "refills": account["refills"],
                }
            refs = {account_id: {ref: dict(result) for ref, result in refs.items()}
                    for account_id, refs in self._refs.items()}
            return {
                "version": self.SNAPSHOT_VERSION,
                "default_cap": self._default_cap,
                "accounts": accounts,
                "refs": refs,
                "history": [dict(entry) for entry in self._history],
            }

    def restore(self, state: dict) -> None:
        bad = EnergyError("ENERGY_BAD_SNAPSHOT")
        if not isinstance(state, dict) or state.get("version") != self.SNAPSHOT_VERSION:
            raise bad
        try:
            raw_accounts = state["accounts"]
            raw_refs = state["refs"]
            raw_history = state["history"]
            default_cap = state["default_cap"]
        except KeyError as exc:
            raise bad from exc
        if not isinstance(raw_accounts, dict) or not isinstance(raw_refs, dict) \
                or not isinstance(raw_history, list) \
                or not isinstance(default_cap, int):
            raise bad
        accounts = {}
        try:
            for account_id, raw in raw_accounts.items():
                if not isinstance(account_id, str) or not isinstance(raw, dict):
                    raise bad
                energy = raw["energy"]
                cap = raw["cap"]
                remainder = raw["remainder"]
                refills = raw["refills"]
                last_at = raw["last_at"]
                reset_day = raw["reset_day"]
                refill_day = raw["refill_day"]
                if any(isinstance(value, bool) for value in
                       (energy, cap, remainder, refills)) \
                        or not all(isinstance(value, int) for value in
                                   (energy, cap, remainder, refills)) \
                        or not isinstance(last_at, str) \
                        or not (reset_day is None or isinstance(reset_day, str)) \
                        or not (refill_day is None or isinstance(refill_day, str)):
                    raise bad
                try:
                    parsed_last_at = _parse_now(last_at)
                except EnergyError as exc:
                    raise bad from exc
                accounts[account_id] = {
                    "energy": energy,
                    "cap": cap,
                    "remainder": remainder,
                    "last_at": parsed_last_at,
                    "reset_day": reset_day,
                    "refill_day": refill_day,
                    "refills": refills,
                }
            refs = {}
            for account_id, per_account in raw_refs.items():
                if not isinstance(account_id, str) or not isinstance(per_account, dict):
                    raise bad
                refs[account_id] = {}
                for ref, result in per_account.items():
                    if not isinstance(ref, str) or not isinstance(result, dict):
                        raise bad
                    refs[account_id][ref] = dict(result)
            history = []
            for entry in raw_history:
                if not isinstance(entry, dict) \
                        or not isinstance(entry.get("account"), str) \
                        or not isinstance(entry.get("event"), str) \
                        or not isinstance(entry.get("at"), str):
                    raise bad
                history.append(dict(entry))
        except EnergyError:
            raise
        except (KeyError, TypeError, ValueError) as exc:
            raise bad from exc
        with self._lock:
            self._default_cap = default_cap
            self._accounts = accounts
            self._refs = refs
            self._history = history
