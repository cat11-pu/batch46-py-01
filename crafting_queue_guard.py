"""Crafting stations: queueing, material reservations and timed completion."""

from __future__ import annotations

import copy
import threading
from datetime import datetime, timedelta, timezone


class CraftError(ValueError):
    """Structured error carrying a machine readable code."""

    def __init__(self, code: str, detail=None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


_ACTIVE_STATUSES = frozenset(("pending", "running"))
_CLOSED_STATUSES = frozenset(("completed", "cancelled", "failed"))


def _is_positive_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _is_non_negative_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _parse_time(value) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        text = value.strip()
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError as exc:
            raise CraftError("CRAFT_BAD_TIME", value) from exc
    else:
        raise CraftError("CRAFT_BAD_TIME", value)

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _format_time(value) -> str:
    return _parse_time(value).isoformat()


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class CraftingQueue:
    SNAPSHOT_VERSION = 1

    def __init__(self, *, max_jobs_per_account: int = 20) -> None:
        if not _is_positive_int(max_jobs_per_account):
            raise CraftError("CRAFT_BAD_CONFIG", max_jobs_per_account)

        self._lock = threading.RLock()
        self._max_jobs_per_account = max_jobs_per_account
        self._stations: dict = {}
        self._recipes: dict = {}
        self._inventory: dict = {}
        self._reserved: dict = {}
        self._jobs: dict = {}
        self._requests: dict = {}
        self._history: list = []
        self._seq = 0

    # ------------------------------------------------------------------
    # Configuration and account inventory
    # ------------------------------------------------------------------
    def add_station(self, name: str, capacity: int = 3, parallel: int = 1) -> dict:
        if not isinstance(name, str) or not name:
            raise CraftError("CRAFT_BAD_STATION", name)
        if not _is_positive_int(capacity) or not _is_positive_int(parallel):
            raise CraftError("CRAFT_BAD_STATION", name)

        with self._lock:
            if name in self._stations:
                raise CraftError("CRAFT_STATION_EXISTS", name)
            station = {
                "name": name,
                "capacity": capacity,
                "parallel": parallel,
            }
            self._stations[name] = station
            return copy.deepcopy(station)

    def register_recipe(self, recipe_id: str, inputs: dict, output: dict,
                        duration: int, station: str) -> dict:
        if not isinstance(recipe_id, str) or not recipe_id:
            raise CraftError("CRAFT_BAD_RECIPE", recipe_id)
        if not isinstance(station, str) or not station:
            raise CraftError("CRAFT_BAD_RECIPE", recipe_id)
        if not _is_positive_int(duration):
            raise CraftError("CRAFT_BAD_RECIPE", recipe_id)

        def clean_items(items):
            if not isinstance(items, dict):
                raise CraftError("CRAFT_BAD_RECIPE", recipe_id)
            cleaned = {}
            for item, qty in items.items():
                if not isinstance(item, str) or not item or not _is_positive_int(qty):
                    raise CraftError("CRAFT_BAD_RECIPE", recipe_id)
                cleaned[item] = qty
            return cleaned

        recipe = {
            "recipe_id": recipe_id,
            "inputs": clean_items(inputs),
            "output": clean_items(output),
            "duration": duration,
            "station": station,
        }

        with self._lock:
            if recipe_id in self._recipes:
                raise CraftError("CRAFT_RECIPE_EXISTS", recipe_id)
            self._recipes[recipe_id] = recipe
            return copy.deepcopy(recipe)

    def deposit(self, account: str, item: str, qty: int) -> dict:
        if not isinstance(account, str) or not account:
            raise CraftError("CRAFT_BAD_ACCOUNT", account)
        if not isinstance(item, str) or not item:
            raise CraftError("CRAFT_BAD_ITEM", item)
        if not _is_positive_int(qty):
            raise CraftError("CRAFT_BAD_COUNT", qty)

        with self._lock:
            inventory = self._inventory.setdefault(account, {})
            inventory[item] = inventory.get(item, 0) + qty
            return {
                "account": account,
                "item": item,
                "qty": qty,
                "inventory": copy.deepcopy(inventory),
                "available": self._available_locked(account),
            }

    def inventory(self, account: str) -> dict:
        with self._lock:
            return copy.deepcopy(self._inventory.get(account, {}))

    def available(self, account: str) -> dict:
        with self._lock:
            return self._available_locked(account)

    def _available_locked(self, account: str) -> dict:
        inventory = self._inventory.get(account, {})
        reserved = self._reserved.get(account, {})
        items = list(inventory)
        items.extend(item for item in reserved if item not in inventory)
        return {
            item: inventory.get(item, 0) - reserved.get(item, 0)
            for item in items
        }

    # ------------------------------------------------------------------
    # Queueing
    # ------------------------------------------------------------------
    def enqueue(self, account: str, recipe_id: str, count: int = 1, *,
                priority: int = 0, request_id: str | None = None,
                now=None) -> dict:
        with self._lock:
            if request_id is not None:
                existing = self._requests.get((account, request_id))
                if existing is not None:
                    view = self._job_view(self._jobs[existing])
                    view["replayed"] = True
                    return view

            recipe = self._recipes.get(recipe_id)
            if recipe is None:
                raise CraftError("CRAFT_UNKNOWN_RECIPE", recipe_id)
            if not _is_positive_int(count):
                raise CraftError("CRAFT_BAD_COUNT", count)

            station_name = recipe["station"]
            station = self._stations.get(station_name)
            if station is None:
                raise CraftError("CRAFT_UNKNOWN_STATION", station_name)

            account_active = sum(
                1 for row in self._jobs.values()
                if row["account"] == account and row["status"] in _ACTIVE_STATUSES
            )
            if account_active >= self._max_jobs_per_account:
                raise CraftError("CRAFT_ACCOUNT_LIMIT", account)

            station_active = sum(
                1 for row in self._jobs.values()
                if row["station"] == station_name and row["status"] in _ACTIVE_STATUSES
            )
            if station_active >= station["capacity"]:
                raise CraftError("CRAFT_QUEUE_FULL", station_name)

            needed = {
                item: qty * count
                for item, qty in recipe["inputs"].items()
            }
            available = self._available_locked(account)
            for item, qty in needed.items():
                if available.get(item, 0) < qty:
                    raise CraftError(
                        "CRAFT_INSUFFICIENT_MATERIALS",
                        {"item": item, "required": qty,
                         "available": available.get(item, 0)},
                    )

            if request_id is not None and not isinstance(request_id, str):
                raise CraftError("CRAFT_BAD_REQUEST_ID", request_id)

            now_dt = _parse_time(now) if now is not None else _utc_now()
            self._seq += 1
            job_id = f"job-{self._seq:04d}"

            account_reserved = self._reserved.setdefault(account, {})
            for item, qty in needed.items():
                account_reserved[item] = account_reserved.get(item, 0) + qty

            job = {
                "job_id": job_id,
                "account": account,
                "recipe_id": recipe_id,
                "station": station_name,
                "count": count,
                "priority": priority,
                "seq": self._seq,
                "status": "pending",
                "reserved": copy.deepcopy(needed),
                "output": {
                    item: qty * count
                    for item, qty in recipe["output"].items()
                },
                "duration": recipe["duration"],
                "created_at": _format_time(now_dt),
                "started_at": None,
                "ready_at": None,
                "finished_at": None,
                "reason": "",
            }
            self._jobs[job_id] = job
            if request_id is not None:
                self._requests[(account, request_id)] = job_id

            self._history.append({
                "event": "enqueued",
                "job_id": job_id,
                "account": account,
                "at": _format_time(now_dt),
            })
            self._promote_station(station_name, now_dt)

            view = self._job_view(job)
            view["replayed"] = False
            return view

    def withdraw(self, account: str, item: str, qty: int) -> dict:
        if not _is_positive_int(qty):
            raise CraftError("CRAFT_BAD_COUNT", qty)

        with self._lock:
            inventory = self._inventory.get(account, {})
            reserved = self._reserved.get(account, {})
            free = inventory.get(item, 0) - reserved.get(item, 0)
            if qty > free:
                raise CraftError(
                    "CRAFT_INSUFFICIENT_AVAILABLE",
                    {"item": item, "required": qty, "available": max(free, 0)},
                )

            target = self._inventory.setdefault(account, {})
            target[item] = target.get(item, 0) - qty
            return {
                "account": account,
                "item": item,
                "qty": qty,
                "withdrawn": qty,
                "inventory": copy.deepcopy(target),
                "available": self._available_locked(account),
            }

    def job(self, job_id: str) -> dict:
        with self._lock:
            return self._job_view(self._get_job_locked(job_id))

    def queue_view(self, account: str, station: str | None = None) -> list:
        with self._lock:
            rows = [
                row for row in self._jobs.values()
                if row["account"] == account
                and row["status"] in _ACTIVE_STATUSES
                and (station is None or row["station"] == station)
            ]
            rows.sort(key=lambda row: (-row["priority"], row["seq"]))
            return [self._job_view(row) for row in rows]

    # ------------------------------------------------------------------
    # Timed progression
    # ------------------------------------------------------------------
    def tick(self, now) -> dict:
        with self._lock:
            now_dt = _parse_time(now)

            due = [
                row for row in self._jobs.values()
                if row["status"] == "running"
                and row["ready_at"] is not None
                and _parse_time(row["ready_at"]) <= now_dt
            ]
            due.sort(key=lambda row: (_parse_time(row["ready_at"]), row["seq"]))

            completed = []
            for row in due:
                self._complete_locked(row, now_dt)
                completed.append(row["job_id"])

            started = []
            for station_name in self._stations:
                started.extend(self._promote_station(station_name, now_dt))

            return {"completed": completed, "started": started}

    def cancel(self, account: str, job_id: str, *, now=None) -> dict:
        with self._lock:
            row = self._get_job_locked(job_id)
            if row["account"] != account:
                raise CraftError("CRAFT_UNKNOWN_JOB", job_id)

            status = row["status"]
            if status == "completed":
                raise CraftError("CRAFT_JOB_DONE", job_id)
            if status in ("cancelled", "failed"):
                raise CraftError("CRAFT_JOB_CLOSED", job_id)

            now_dt = _parse_time(now) if now is not None else _utc_now()
            if status == "pending":
                refund = copy.deepcopy(row["reserved"])
                self._release_reservation_locked(row)
            else:
                refund = self._settle_partial_locked(row)

            row["status"] = "cancelled"
            row["finished_at"] = _format_time(now_dt)
            row["refund"] = copy.deepcopy(refund)
            self._history.append({
                "event": "cancelled",
                "job_id": job_id,
                "account": account,
                "at": _format_time(now_dt),
                "refund": copy.deepcopy(refund),
            })

            view = self._job_view(row)
            view["refund"] = copy.deepcopy(refund)
            return view

    def fail(self, job_id: str, *, reason: str = "", now=None) -> dict:
        with self._lock:
            row = self._get_job_locked(job_id)
            status = row["status"]
            if status == "completed":
                raise CraftError("CRAFT_JOB_DONE", job_id)
            if status in ("cancelled", "failed"):
                raise CraftError("CRAFT_JOB_CLOSED", job_id)
            if status != "running":
                raise CraftError("CRAFT_JOB_NOT_RUNNING", job_id)

            now_dt = _parse_time(now) if now is not None else _utc_now()
            refund = self._settle_partial_locked(row)
            row["status"] = "failed"
            row["reason"] = str(reason)
            row["finished_at"] = _format_time(now_dt)
            row["refund"] = copy.deepcopy(refund)
            self._history.append({
                "event": "failed",
                "job_id": job_id,
                "account": row["account"],
                "at": _format_time(now_dt),
                "reason": row["reason"],
                "refund": copy.deepcopy(refund),
            })

            view = self._job_view(row)
            view["refund"] = copy.deepcopy(refund)
            return view

    # ------------------------------------------------------------------
    # Internal queue operations
    # ------------------------------------------------------------------
    def _get_job_locked(self, job_id: str) -> dict:
        row = self._jobs.get(job_id)
        if row is None:
            raise CraftError("CRAFT_UNKNOWN_JOB", job_id)
        return row

    def _promote_station(self, station_name: str, now_dt: datetime) -> list:
        station = self._stations[station_name]
        running = sum(
            1 for row in self._jobs.values()
            if row["station"] == station_name and row["status"] == "running"
        )
        slots = station["parallel"] - running
        if slots <= 0:
            return []

        pending = [
            row for row in self._jobs.values()
            if row["station"] == station_name and row["status"] == "pending"
        ]
        pending.sort(key=lambda row: (-row["priority"], row["seq"]))

        started = []
        for row in pending[:slots]:
            row["status"] = "running"
            row["started_at"] = _format_time(now_dt)
            row["ready_at"] = _format_time(
                now_dt + timedelta(seconds=row["duration"] * row["count"])
            )
            started.append(row["job_id"])
            self._history.append({
                "event": "started",
                "job_id": row["job_id"],
                "account": row["account"],
                "at": _format_time(now_dt),
            })
        return started

    def _complete_locked(self, row: dict, now_dt: datetime) -> None:
        account = row["account"]
        inventory = self._inventory.setdefault(account, {})
        reserved = self._reserved.setdefault(account, {})

        for item, qty in row["reserved"].items():
            inventory[item] = inventory.get(item, 0) - qty
            reserved[item] = reserved.get(item, 0) - qty

        for item, qty in row["output"].items():
            inventory[item] = inventory.get(item, 0) + qty

        row["status"] = "completed"
        row["finished_at"] = _format_time(now_dt)
        self._history.append({
            "event": "completed",
            "job_id": row["job_id"],
            "account": account,
            "at": _format_time(now_dt),
            "output": copy.deepcopy(row["output"]),
        })

    def _release_reservation_locked(self, row: dict) -> None:
        account = row["account"]
        reserved = self._reserved.setdefault(account, {})
        for item, qty in row["reserved"].items():
            reserved[item] = reserved.get(item, 0) - qty

    def _settle_partial_locked(self, row: dict) -> dict:
        account = row["account"]
        inventory = self._inventory.setdefault(account, {})
        reserved = self._reserved.setdefault(account, {})
        refund = {}

        for item, qty in row["reserved"].items():
            returned = qty // 2
            consumed = qty - returned
            inventory[item] = inventory.get(item, 0) - consumed
            reserved[item] = reserved.get(item, 0) - qty
            if returned:
                refund[item] = returned

        return refund

    def _job_view(self, row: dict) -> dict:
        return copy.deepcopy(row)

    # ------------------------------------------------------------------
    # Reporting and persistence
    # ------------------------------------------------------------------
    def stats(self) -> dict:
        with self._lock:
            counts = {
                status: 0 for status in
                ("pending", "running", "completed", "cancelled", "failed")
            }
            for row in self._jobs.values():
                counts[row["status"]] = counts.get(row["status"], 0) + 1
            return {
                "jobs": len(self._jobs),
                "seq": self._seq,
                "stations": len(self._stations),
                "recipes": len(self._recipes),
                "pending": counts["pending"],
                "running": counts["running"],
                "completed": counts["completed"],
                "cancelled": counts["cancelled"],
                "failed": counts["failed"],
            }

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": self.SNAPSHOT_VERSION,
                "seq": self._seq,
                "max_jobs_per_account": self._max_jobs_per_account,
                "stations": copy.deepcopy(self._stations),
                "recipes": copy.deepcopy(self._recipes),
                "inventory": copy.deepcopy(self._inventory),
                "reserved": copy.deepcopy(self._reserved),
                "jobs": copy.deepcopy(self._jobs),
                "requests": [
                    {
                        "account": account,
                        "request_id": request_id,
                        "job_id": job_id,
                    }
                    for (account, request_id), job_id in self._requests.items()
                ],
                "history": copy.deepcopy(self._history),
            }

    def restore(self, state: dict) -> None:
        try:
            normalized = self._normalize_snapshot(state)
        except CraftError:
            raise
        except Exception as exc:
            raise CraftError("CRAFT_BAD_SNAPSHOT", str(exc)) from exc

        with self._lock:
            self._max_jobs_per_account = normalized["max_jobs_per_account"]
            self._stations = normalized["stations"]
            self._recipes = normalized["recipes"]
            self._inventory = normalized["inventory"]
            self._reserved = normalized["reserved"]
            self._jobs = normalized["jobs"]
            self._requests = normalized["requests"]
            self._history = normalized["history"]
            self._seq = normalized["seq"]

    def _normalize_snapshot(self, state) -> dict:
        def bad(detail):
            return CraftError("CRAFT_BAD_SNAPSHOT", detail)

        if not isinstance(state, dict):
            raise bad("snapshot must be a mapping")
        if state.get("version") != self.SNAPSHOT_VERSION:
            raise bad("unsupported version")

        required = {
            "seq", "max_jobs_per_account", "stations", "recipes",
            "inventory", "reserved", "jobs", "requests", "history",
        }
        if not required.issubset(state):
            raise bad("missing fields")

        seq = state["seq"]
        if not _is_non_negative_int(seq):
            raise bad("invalid seq")
        max_jobs = state["max_jobs_per_account"]
        if not _is_positive_int(max_jobs):
            raise bad("invalid max_jobs_per_account")

        stations = self._validate_stations(state["stations"])
        recipes = self._validate_recipes(state["recipes"])
        inventory = self._validate_quantities(state["inventory"])
        reserved = self._validate_quantities(state["reserved"])
        jobs = self._validate_jobs(state["jobs"], seq)
        requests = self._validate_requests(state["requests"], jobs)

        history = state["history"]
        if not isinstance(history, list):
            raise bad("invalid history")

        return {
            "seq": seq,
            "max_jobs_per_account": max_jobs,
            "stations": copy.deepcopy(stations),
            "recipes": copy.deepcopy(recipes),
            "inventory": copy.deepcopy(inventory),
            "reserved": copy.deepcopy(reserved),
            "jobs": copy.deepcopy(jobs),
            "requests": copy.deepcopy(requests),
            "history": copy.deepcopy(history),
        }

    def _validate_stations(self, value) -> dict:
        if not isinstance(value, dict):
            raise CraftError("CRAFT_BAD_SNAPSHOT", "invalid stations")
        stations = {}
        for name, row in value.items():
            if not isinstance(name, str) or not isinstance(row, dict):
                raise CraftError("CRAFT_BAD_SNAPSHOT", "invalid station")
            capacity = row.get("capacity")
            parallel = row.get("parallel")
            if not _is_positive_int(capacity) or not _is_positive_int(parallel):
                raise CraftError("CRAFT_BAD_SNAPSHOT", "invalid station limits")
            stations[name] = {
                "name": row.get("name", name),
                "capacity": capacity,
                "parallel": parallel,
            }
        return stations

    def _validate_recipes(self, value) -> dict:
        if not isinstance(value, dict):
            raise CraftError("CRAFT_BAD_SNAPSHOT", "invalid recipes")
        recipes = {}
        for recipe_id, row in value.items():
            if not isinstance(recipe_id, str) or not isinstance(row, dict):
                raise CraftError("CRAFT_BAD_SNAPSHOT", "invalid recipe")
            inputs = row.get("inputs")
            output = row.get("output")
            duration = row.get("duration")
            station = row.get("station")
            if (not isinstance(inputs, dict) or not isinstance(output, dict)
                    or not _is_positive_int(duration)
                    or not isinstance(station, str) or not station):
                raise CraftError("CRAFT_BAD_SNAPSHOT", "invalid recipe fields")
            recipes[recipe_id] = {
                "recipe_id": row.get("recipe_id", recipe_id),
                "inputs": self._validate_item_map(inputs),
                "output": self._validate_item_map(output),
                "duration": duration,
                "station": station,
            }
        return recipes

    def _validate_quantities(self, value) -> dict:
        if not isinstance(value, dict):
            raise CraftError("CRAFT_BAD_SNAPSHOT", "invalid account quantities")
        result = {}
        for account, items in value.items():
            if not isinstance(account, str) or not isinstance(items, dict):
                raise CraftError("CRAFT_BAD_SNAPSHOT", "invalid account")
            result[account] = self._validate_item_map(items, non_negative=True)
        return result

    def _validate_item_map(self, value, *, non_negative=False) -> dict:
        result = {}
        for item, qty in value.items():
            valid = (
                _is_non_negative_int(qty) if non_negative
                else _is_positive_int(qty)
            )
            if not isinstance(item, str) or not item or not valid:
                raise CraftError("CRAFT_BAD_SNAPSHOT", "invalid item quantity")
            result[item] = qty
        return result

    def _validate_jobs(self, value, seq: int) -> dict:
        if not isinstance(value, dict):
            raise CraftError("CRAFT_BAD_SNAPSHOT", "invalid jobs")
        jobs = {}
        max_job_seq = 0
        for job_id, row in value.items():
            if not isinstance(job_id, str) or not isinstance(row, dict):
                raise CraftError("CRAFT_BAD_SNAPSHOT", "invalid job")
            if row.get("job_id") != job_id:
                raise CraftError("CRAFT_BAD_SNAPSHOT", "job id mismatch")
            if row.get("status") not in _ACTIVE_STATUSES | _CLOSED_STATUSES:
                raise CraftError("CRAFT_BAD_SNAPSHOT", "invalid job status")
            required = {
                "account", "recipe_id", "station", "count", "priority",
                "seq", "reserved", "output", "duration",
            }
            if not required.issubset(row):
                raise CraftError("CRAFT_BAD_SNAPSHOT", "missing job fields")
            if not _is_positive_int(row["count"]):
                raise CraftError("CRAFT_BAD_SNAPSHOT", "invalid job count")
            if not _is_positive_int(row["duration"]):
                raise CraftError("CRAFT_BAD_SNAPSHOT", "invalid job duration")
            if not _is_positive_int(row["seq"]):
                raise CraftError("CRAFT_BAD_SNAPSHOT", "invalid job sequence")
            if not isinstance(row.get("reserved"), dict) or not isinstance(row.get("output"), dict):
                raise CraftError("CRAFT_BAD_SNAPSHOT", "invalid job materials")
            normalized = copy.deepcopy(row)
            normalized["reserved"] = self._validate_item_map(
                row["reserved"], non_negative=True
            )
            normalized["output"] = self._validate_item_map(
                row["output"], non_negative=True
            )
            max_job_seq = max(max_job_seq, row["seq"])
            jobs[job_id] = normalized
        if max_job_seq > seq:
            raise CraftError("CRAFT_BAD_SNAPSHOT", "sequence regression")
        return jobs

    def _validate_requests(self, value, jobs: dict) -> dict:
        requests = {}
        if isinstance(value, list):
            rows = value
        elif isinstance(value, dict):
            rows = [
                {"account": account, "request_id": request_id, "job_id": job_id}
                for (account, request_id), job_id in value.items()
                if isinstance(account, str) and isinstance(request_id, str)
            ]
            if len(rows) != len(value):
                raise CraftError("CRAFT_BAD_SNAPSHOT", "invalid requests")
        else:
            raise CraftError("CRAFT_BAD_SNAPSHOT", "invalid requests")

        for row in rows:
            if not isinstance(row, dict):
                raise CraftError("CRAFT_BAD_SNAPSHOT", "invalid request")
            account = row.get("account")
            request_id = row.get("request_id")
            job_id = row.get("job_id")
            if (not isinstance(account, str) or not isinstance(request_id, str)
                    or not isinstance(job_id, str) or job_id not in jobs):
                raise CraftError("CRAFT_BAD_SNAPSHOT", "invalid request fields")
            requests[(account, request_id)] = job_id
        return requests
