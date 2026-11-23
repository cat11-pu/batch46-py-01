from typing import Callable, List, Optional


class TickError(ValueError):
    def __init__(self, code: str, detail: Optional[str] = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class TickScheduler:
    """Fixed-step tick loop with recurring tasks, catch-up budget and snapshots."""

    def __init__(self, *, tick_ms: int = 50, max_catchup: int = 5,
                 max_tasks: int = 64, budget_ms: int = 1000) -> None:
        self.tick_ms = tick_ms
        self.max_catchup = max_catchup
        self.max_tasks = max_tasks
        self.budget_ms = budget_ms

    def schedule(self, task_id: str, handler: Callable[[], None], *,
                 every: int = 1, delay: int = 0, priority: int = 0,
                 cost: int = 0) -> dict:
        raise NotImplementedError

    def cancel(self, task_id: str) -> bool:
        raise NotImplementedError

    def advance(self, elapsed_ms: int) -> List[dict]:
        raise NotImplementedError

    def tick(self) -> dict:
        raise NotImplementedError

    def now(self) -> int:
        raise NotImplementedError

    def current_tick(self) -> int:
        raise NotImplementedError

    def pending(self) -> List[str]:
        raise NotImplementedError

    def due(self, tick: int) -> List[str]:
        raise NotImplementedError

    def drift(self) -> int:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def reset(self) -> None:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, snapshot: dict) -> None:
        raise NotImplementedError
