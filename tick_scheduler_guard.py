import threading
from typing import Callable, Dict, List, Optional


class TickError(ValueError):
    def __init__(self, code: str, detail: Optional[str] = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


_STAT_KEYS = ("ticks", "dropped", "failures", "overruns", "deferred", "tasks_run")


class _Task:
    __slots__ = ("task_id", "handler", "every", "delay", "priority", "cost",
                 "next_due", "carried")

    def __init__(self, task_id: str, handler: Callable[[], None], every: int,
                 delay: int, priority: int, cost: int, next_due: int,
                 carried: bool = False) -> None:
        self.task_id = task_id
        self.handler = handler
        self.every = every
        self.delay = delay
        self.priority = priority
        self.cost = cost
        self.next_due = next_due
        self.carried = carried

    def describe(self) -> dict:
        return {
            "task_id": self.task_id,
            "handler": self.handler,
            "every": self.every,
            "delay": self.delay,
            "priority": self.priority,
            "cost": self.cost,
            "next_due": self.next_due,
            "carried": self.carried,
        }


class TickScheduler:
    """Fixed-step tick loop with recurring tasks, catch-up budget and snapshots."""

    SNAPSHOT_VERSION = 1

    def __init__(self, *, tick_ms: int = 50, max_catchup: int = 5,
                 max_tasks: int = 64, budget_ms: int = 1000) -> None:
        if tick_ms <= 0:
            raise TickError("TICK_INVALID_CONFIG", "tick_ms must be positive")
        self.tick_ms = tick_ms
        self.max_catchup = max_catchup
        self.max_tasks = max_tasks
        self.budget_ms = budget_ms
        self._lock = threading.RLock()
        self._tasks: Dict[str, _Task] = {}
        self._now = 0
        self._tick = 0
        self._stats = {key: 0 for key in _STAT_KEYS}

    def schedule(self, task_id: str, handler: Callable[[], None], *,
                 every: int = 1, delay: int = 0, priority: int = 0,
                 cost: int = 0) -> dict:
        with self._lock:
            if (not isinstance(task_id, str) or not task_id
                    or not callable(handler)
                    or not isinstance(every, int) or every < 1
                    or not isinstance(delay, int) or delay < 0
                    or not isinstance(cost, int) or cost < 0):
                raise TickError("TICK_INVALID_TASK", repr(task_id))
            if task_id in self._tasks:
                raise TickError("TICK_TASK_DUP", task_id)
            if len(self._tasks) >= self.max_tasks:
                raise TickError("TICK_TASK_LIMIT", task_id)
            task = _Task(task_id, handler, every, delay, priority, cost,
                         next_due=self._tick + delay + 1)
            self._tasks[task_id] = task
            return {
                "task_id": task_id,
                "next_due": task.next_due,
                "every": every,
                "priority": priority,
                "cost": cost,
            }

    def cancel(self, task_id: str) -> bool:
        with self._lock:
            if task_id not in self._tasks:
                raise TickError("TICK_UNKNOWN_TASK", task_id)
            del self._tasks[task_id]
            return True

    def advance(self, elapsed_ms: int) -> List[dict]:
        with self._lock:
            if not isinstance(elapsed_ms, int) or elapsed_ms < 0:
                raise TickError("TICK_INVALID_ELAPSED", repr(elapsed_ms))
            self._now += elapsed_ms
            target = self._now // self.tick_ms
            owed = target - self._tick
            if owed <= 0:
                return []
            if owed > self.max_catchup:
                dropped = owed - self.max_catchup
                self._stats["dropped"] += dropped
                start = target - self.max_catchup + 1
                self._fast_forward_phases(start)
                self._tick = start - 1
            reports = []
            while self._tick < target:
                reports.append(self._run_tick())
            return reports

    def tick(self) -> dict:
        with self._lock:
            self._now += self.tick_ms
            return self._run_tick()

    def now(self) -> int:
        with self._lock:
            return self._now

    def current_tick(self) -> int:
        with self._lock:
            return self._tick

    def pending(self) -> List[str]:
        with self._lock:
            return sorted(self._tasks)

    def due(self, tick: int) -> List[str]:
        with self._lock:
            return [task.task_id for task in self._due_tasks(tick)]

    def drift(self) -> int:
        with self._lock:
            return self._now - self._tick * self.tick_ms

    def stats(self) -> dict:
        with self._lock:
            snapshot = dict(self._stats)
            snapshot["tasks"] = len(self._tasks)
            return snapshot

    def reset(self) -> None:
        with self._lock:
            self._tasks.clear()
            self._now = 0
            self._tick = 0
            self._stats = {key: 0 for key in _STAT_KEYS}

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": self.SNAPSHOT_VERSION,
                "now": self._now,
                "tick": self._tick,
                "tick_ms": self.tick_ms,
                "stats": dict(self._stats),
                "tasks": [task.describe() for task in self._tasks.values()],
            }

    def restore(self, snapshot: dict) -> None:
        with self._lock:
            if (not isinstance(snapshot, dict)
                    or snapshot.get("version") != self.SNAPSHOT_VERSION):
                raise TickError("TICK_SNAPSHOT_VERSION")
            tasks = {}
            for entry in snapshot.get("tasks", []):
                existing = self._tasks.get(entry["task_id"])
                handler = existing.handler if existing is not None else entry["handler"]
                task = _Task(entry["task_id"], handler,
                             entry["every"], entry["delay"], entry["priority"],
                             entry["cost"], entry["next_due"],
                             entry.get("carried", False))
                tasks[task.task_id] = task
            self._tasks = tasks
            self._now = snapshot["now"]
            self._tick = snapshot["tick"]
            stats = {key: 0 for key in _STAT_KEYS}
            stats.update(snapshot.get("stats", {}))
            self._stats = stats

    def _run_tick(self) -> dict:
        self._tick += 1
        return self._execute_tick(self._tick)

    def _due_tasks(self, tick: int) -> List[_Task]:
        due = [task for task in self._tasks.values() if task.next_due <= tick]
        due.sort(key=lambda task: (not task.carried, -task.priority, task.task_id))
        return due

    def _execute_tick(self, tick: int) -> dict:
        ran: List[str] = []
        deferred: List[str] = []
        failed: List[str] = []
        spent = 0
        overrun = False
        for task in self._due_tasks(tick):
            if self._tasks.get(task.task_id) is not task:
                continue
            if not overrun and spent > 0 and spent + task.cost > self.budget_ms:
                overrun = True
                self._stats["overruns"] += 1
            if overrun:
                task.next_due = tick + 1
                task.carried = True
                self._stats["deferred"] += 1
                deferred.append(task.task_id)
                continue
            try:
                task.handler()
            except Exception:
                self._stats["failures"] += 1
                self._tasks.pop(task.task_id, None)
                failed.append(task.task_id)
                continue
            self._stats["tasks_run"] += 1
            spent += task.cost
            task.carried = False
            task.next_due += task.every
            ran.append(task.task_id)
        self._stats["ticks"] += 1
        return {"tick": tick, "ran": ran, "deferred": deferred,
                "failed": failed}

    def _fast_forward_phases(self, start: int) -> None:
        for task in self._tasks.values():
            while task.next_due < start:
                task.next_due += task.every
