"""Reflection probe capture queue: cubemap faces, mip chain and priorities."""

SNAPSHOT_VERSION = 1
FACES = ("px", "nx", "py", "ny", "pz", "nz")


class ReflectionProbeError(ValueError):
    """Domain error carrying a stable machine-readable code."""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class ReflectionProbe:
    """Probe registry, prioritized capture queue and time-sliced dispatch."""

    def __init__(self, *, max_probes: int = 64, face_size: int = 128,
                 mip_levels: int = 6, frame_budget: int = 4):
        self.max_probes = max_probes
        self.face_size = face_size
        self.mip_levels = mip_levels
        self.frame_budget = frame_budget

    def register_probe(self, probe_id: str, *,
                       position: tuple[float, float, float], radius: float,
                       priority: int = 0, static: bool = False) -> dict:
        raise NotImplementedError

    def unregister_probe(self, probe_id: str) -> dict:
        raise NotImplementedError

    def request_capture(self, probe_id: str, *, frame: int,
                        reason: str = "manual") -> dict:
        raise NotImplementedError

    def dispatch(self, frame: int) -> dict:
        raise NotImplementedError

    def capture_face(self, probe_id: str, face: str, frame: int, *,
                     checksum: str) -> dict:
        raise NotImplementedError

    def complete_capture(self, probe_id: str, *, frame: int,
                         checksum: str) -> dict:
        raise NotImplementedError

    def abort_capture(self, probe_id: str, *, frame: int) -> dict:
        raise NotImplementedError

    def pending_captures(self) -> list[dict]:
        raise NotImplementedError

    def probe_state(self, probe_id: str) -> dict:
        raise NotImplementedError

    def resolve(self, position: tuple[float, float, float]) -> dict:
        raise NotImplementedError

    def mip_sizes(self) -> list[int]:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, snapshot: dict) -> dict:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
