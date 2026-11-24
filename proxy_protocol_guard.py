"""PROXY protocol v1/v2 trust boundary guard."""

from typing import Iterable


class ProxyProtocolError(ValueError):
    def __init__(self, code: str, detail: str | None = None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class ProxyProtocolGuard:
    """Parses PROXY headers only from trusted peers and keeps auditable state."""

    def __init__(self, *, trusted_peers: Iterable[str] = (),
                 max_header_bytes: int = 536, max_tlv_bytes: int = 256,
                 max_connections: int = 1024, source_ttl: float = 5.0) -> None:
        self.trusted_peers = tuple(trusted_peers)
        self.max_header_bytes = max_header_bytes
        self.max_tlv_bytes = max_tlv_bytes
        self.max_connections = max_connections
        self.source_ttl = source_ttl

    def allow_peer(self, peer: str) -> None:
        raise NotImplementedError

    def revoke_peer(self, peer: str) -> None:
        raise NotImplementedError

    def is_trusted(self, peer: str) -> bool:
        raise NotImplementedError

    def parse(self, raw: bytes, *, peer: str, connection: str | None = None,
              now: float = 0.0) -> dict:
        raise NotImplementedError

    def trust_source(self, source_ip: str, *, now: float,
                     ttl: float | None = None) -> dict:
        raise NotImplementedError

    def check_source(self, source_ip: str, *, now: float) -> bool:
        raise NotImplementedError

    def purge_sources(self, *, now: float) -> int:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def recent(self, limit: int = 10) -> list[dict]:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError
