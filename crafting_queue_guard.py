"""Crafting stations: queueing, material reservations and timed completion."""

from __future__ import annotations


class CraftError(ValueError):
    """Structured error carrying a machine readable code."""

    def __init__(self, code: str, detail=None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class CraftingQueue:
    SNAPSHOT_VERSION = 1

    def __init__(self, *, max_jobs_per_account: int = 20) -> None:
        self._stations: dict = {}
        self._recipes: dict = {}
        self._inventory: dict = {}
        self._reserved: dict = {}
        self._jobs: dict = {}
        self._requests: dict = {}
        self._history: list = []
        self._seq = 0

    def add_station(self, name: str, capacity: int = 3, parallel: int = 1) -> dict:
        raise NotImplementedError

    def register_recipe(self, recipe_id: str, inputs: dict, output: dict,
                        duration: int, station: str) -> dict:
        raise NotImplementedError

    def deposit(self, account: str, item: str, qty: int) -> dict:
        raise NotImplementedError

    def inventory(self, account: str) -> dict:
        raise NotImplementedError

    def available(self, account: str) -> dict:
        raise NotImplementedError

    def enqueue(self, account: str, recipe_id: str, count: int = 1, *,
                priority: int = 0, request_id: str | None = None,
                now=None) -> dict:
        raise NotImplementedError

    def withdraw(self, account: str, item: str, qty: int) -> dict:
        raise NotImplementedError

    def job(self, job_id: str) -> dict:
        raise NotImplementedError

    def queue_view(self, account: str, station: str | None = None) -> list:
        raise NotImplementedError

    def tick(self, now) -> dict:
        raise NotImplementedError

    def cancel(self, account: str, job_id: str, *, now=None) -> dict:
        raise NotImplementedError

    def fail(self, job_id: str, *, reason: str = "", now=None) -> dict:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError
