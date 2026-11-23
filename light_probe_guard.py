"""Light probe volume: tetrahedral interpolation, validity and bake transactions."""

SNAPSHOT_VERSION = 1
MAX_COLOR_CHANNEL = 64.0


class LightProbeError(ValueError):
    """Domain error carrying a stable machine-readable code."""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class LightProbe:
    """Irradiance probe grid with tetrahedral sampling and exposure control."""

    def __init__(self, *, bounds=((0.0, 0.0, 0.0), (8.0, 8.0, 8.0)),
                 spacing: float = 1.0, max_probes: int = 4096):
        self.bounds = bounds
        self.spacing = spacing
        self.max_probes = max_probes

    def set_probe(self, coord: tuple[int, int, int], *,
                  color: tuple[float, float, float],
                  valid: bool = True) -> dict:
        raise NotImplementedError

    def remove_probe(self, coord: tuple[int, int, int]) -> dict:
        raise NotImplementedError

    def invalidate(self, coords: list[tuple[int, int, int]]) -> dict:
        raise NotImplementedError

    def probe_at(self, position: tuple[float, float, float]) -> dict:
        raise NotImplementedError

    def sample_many(self,
                    positions: list[tuple[float, float, float]]) -> list[dict]:
        raise NotImplementedError

    def bake(self, frame: int, updates: list[dict]) -> dict:
        raise NotImplementedError

    def set_exposure(self, exposure: float) -> dict:
        raise NotImplementedError

    def grid_shape(self) -> tuple[int, int, int]:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, snapshot: dict) -> dict:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
