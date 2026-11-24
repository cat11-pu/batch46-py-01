"""VXLAN tenant isolation guard."""


class VxlanError(ValueError):
    def __init__(self, code: str, detail: str | None = None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class VxlanGuard:
    """Keeps VNI-to-tenant bindings, port bindings, FDB and rate limits."""

    def __init__(self, *, max_vnis: int = 4096, max_ports: int = 512,
                 rate_limit_pps: int = 1000, rate_window: float = 1.0,
                 max_frame_bytes: int = 1500) -> None:
        self.max_vnis = max_vnis
        self.max_ports = max_ports
        self.rate_limit_pps = rate_limit_pps
        self.rate_window = rate_window
        self.max_frame_bytes = max_frame_bytes

    def register_tenant(self, tenant: str, vni: int, *,
                        mc_group: str | None = None) -> dict:
        raise NotImplementedError

    def release_tenant(self, tenant: str) -> dict | None:
        raise NotImplementedError

    def tenant_for_vni(self, vni: int) -> str | None:
        raise NotImplementedError

    def vni_for_tenant(self, tenant: str) -> int | None:
        raise NotImplementedError

    def bind_port(self, port: str, tenant: str, mac: str) -> dict:
        raise NotImplementedError

    def unbind_port(self, port: str) -> dict | None:
        raise NotImplementedError

    def learn(self, vni: int, mac: str, port: str) -> dict:
        raise NotImplementedError

    def lookup(self, vni: int, mac: str) -> str | None:
        raise NotImplementedError

    def ingress(self, frame: dict, *, port: str, now: float) -> dict:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError
