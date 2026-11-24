"""GTP-U TEID isolation guard."""


class GtpError(ValueError):
    def __init__(self, code: str, detail: str | None = None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class GtpGuard:
    """Owns TEID-to-tenant tunnels and validates GTP-U messages."""

    def __init__(self, *, max_tunnels: int = 1024, max_ext_headers: int = 4,
                 idle_ttl: float = 300.0, seq_window: int = 64) -> None:
        self.max_tunnels = max_tunnels
        self.max_ext_headers = max_ext_headers
        self.idle_ttl = idle_ttl
        self.seq_window = seq_window

    def open_tunnel(self, tenant: str, *, local_teid: int, peer_teid: int,
                    peer_ip: str, slice_id: int = 0,
                    now: float = 0.0) -> dict:
        raise NotImplementedError

    def close_tunnel(self, local_teid: int, *,
                     now: float = 0.0) -> dict | None:
        raise NotImplementedError

    def tunnel(self, local_teid: int) -> dict | None:
        raise NotImplementedError

    def tunnels_for(self, tenant: str) -> list[dict]:
        raise NotImplementedError

    def classify(self, message: dict, *, peer_ip: str,
                 tenant: str | None = None, now: float = 0.0) -> dict:
        raise NotImplementedError

    def echo(self, message: dict, *, peer_ip: str,
             now: float = 0.0) -> dict:
        raise NotImplementedError

    def expire_idle(self, *, now: float) -> list[int]:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError
