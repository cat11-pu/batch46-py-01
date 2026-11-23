from typing import List, Optional


class HitError(ValueError):
    def __init__(self, code: str, detail: Optional[str] = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class HitRegistration:
    """Target registry, pending shots, damage resolution and LIFO rollback."""

    def __init__(self, *, max_pending: int = 8) -> None:
        self.max_pending = max_pending

    def join(self, player_id: str, team: str) -> None:
        raise NotImplementedError

    def spawn(self, target_id: str, *, hp: int = 100, armor: int = 0,
              team: str = "red", tick: int = 0) -> dict:
        raise NotImplementedError

    def despawn(self, target_id: str, *, tick: int) -> dict:
        raise NotImplementedError

    def submit(self, shot_id: str, *, shooter: str, target: str, damage: int,
               tick: int, headshot: bool = False) -> dict:
        raise NotImplementedError

    def resolve(self, shot_id: str) -> dict:
        raise NotImplementedError

    def resolve_pending(self) -> List[dict]:
        raise NotImplementedError

    def cancel(self, shot_id: str) -> bool:
        raise NotImplementedError

    def rollback(self, shot_id: str, *, reason: str = "cheat") -> dict:
        raise NotImplementedError

    def health(self, target_id: str) -> int:
        raise NotImplementedError

    def armor(self, target_id: str) -> int:
        raise NotImplementedError

    def kills(self, shooter: str) -> int:
        raise NotImplementedError

    def damage_log(self, target_id: str) -> List[str]:
        raise NotImplementedError

    def pending(self) -> List[str]:
        raise NotImplementedError

    def state(self, target_id: str) -> dict:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, snapshot: dict) -> None:
        raise NotImplementedError
