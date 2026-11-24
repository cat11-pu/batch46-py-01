"""SCTP chunk parsing and AUTH verification guard."""


class SctpError(ValueError):
    def __init__(self, code: str, detail: str | None = None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class SctpGuard:
    """Parses SCTP bundles, verifies AUTH chunks and bounds the replay cache."""

    def __init__(self, *, max_chunks: int = 16, max_bundle_bytes: int = 1200,
                 replay_window: int = 256, key_grace: float = 300.0) -> None:
        self.max_chunks = max_chunks
        self.max_bundle_bytes = max_bundle_bytes
        self.replay_window = replay_window
        self.key_grace = key_grace

    def add_key(self, key_id: int, key: bytes, *, active: bool = False,
                now: float = 0.0) -> dict:
        raise NotImplementedError

    def rotate_key(self, key_id: int, *, now: float = 0.0) -> dict:
        raise NotImplementedError

    def remove_key(self, key_id: int, *, now: float = 0.0) -> bool:
        raise NotImplementedError

    def active_key_id(self) -> int | None:
        raise NotImplementedError

    def keys(self) -> list[dict]:
        raise NotImplementedError

    def parse_bundle(self, raw: bytes) -> list[dict]:
        raise NotImplementedError

    def verify(self, chunks: list[dict], *, assoc: str,
               now: float = 0.0) -> dict:
        raise NotImplementedError

    def replay_count(self, assoc: str) -> int:
        raise NotImplementedError

    def clear_replay(self, assoc: str) -> int:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError
