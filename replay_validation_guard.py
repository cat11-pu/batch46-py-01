from typing import List, Optional, Sequence


class ReplayError(ValueError):
    def __init__(self, code: str, detail: Optional[str] = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class ReplayValidator:
    """Hash-chained replay recording, streaming verification and checkpoints."""

    def __init__(self, *, max_frames: int = 4096) -> None:
        self.max_frames = max_frames

    def begin(self, match_id: str, *, players: Sequence[str] = (),
              ruleset: str = "v1") -> dict:
        raise NotImplementedError

    def append(self, frame: dict) -> dict:
        raise NotImplementedError

    def finish(self) -> dict:
        raise NotImplementedError

    def abort(self) -> bool:
        raise NotImplementedError

    def digest(self) -> str:
        raise NotImplementedError

    def header(self) -> dict:
        raise NotImplementedError

    def frames(self) -> List[dict]:
        raise NotImplementedError

    def checkpoint(self) -> dict:
        raise NotImplementedError

    def resume(self, checkpoint: dict) -> dict:
        raise NotImplementedError

    def verify(self, frames: List[dict], *, header: Optional[dict] = None) -> dict:
        raise NotImplementedError

    def outcome(self) -> dict:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
