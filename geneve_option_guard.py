"""Geneve option validation guard."""

from typing import Iterable


class GeneveError(ValueError):
    def __init__(self, code: str, detail: str | None = None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class GeneveGuard:
    """Validates Geneve option TLVs against a registry and caches results."""

    def __init__(self, *, max_options: int = 8, max_option_bytes: int = 128,
                 allowed_classes: Iterable[int] = (0x0108,),
                 cache_capacity: int = 64) -> None:
        self.max_options = max_options
        self.max_option_bytes = max_option_bytes
        self.allowed_classes = tuple(allowed_classes)
        self.cache_capacity = cache_capacity

    def register_option(self, opt_class: int, opt_type: int, *,
                        critical: bool = False, max_len: int = 16,
                        encoding: str = "raw") -> dict:
        raise NotImplementedError

    def unregister_option(self, opt_class: int, opt_type: int) -> bool:
        raise NotImplementedError

    def list_options(self) -> list[dict]:
        raise NotImplementedError

    def parse(self, packet: dict, *, request_id: str | None = None) -> dict:
        raise NotImplementedError

    def audit(self, packet: dict) -> dict:
        raise NotImplementedError

    def cache_size(self) -> int:
        raise NotImplementedError

    def clear_cache(self) -> int:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError
