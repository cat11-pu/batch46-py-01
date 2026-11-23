"""Ocean surface: Gerstner waves, mesh LOD rings and foam accumulation."""

SNAPSHOT_VERSION = 1
MAX_RINGS = 4
MIN_RING_RESOLUTION = 2
FOAM_DECAY_PER_SECOND = 0.5


class WaterWaveError(ValueError):
    """Domain error carrying a stable machine-readable code."""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class WaterWaves:
    """Wave set, water level, foam layer and radial mesh builder."""

    def __init__(self, *, resolution: int = 64, max_vertices: int = 200_000,
                 max_waves: int = 8):
        self.resolution = resolution
        self.max_vertices = max_vertices
        self.max_waves = max_waves

    def set_water_level(self, level: float) -> dict:
        raise NotImplementedError

    def add_wave(self, wave_id: str, *, amplitude: float, wavelength: float,
                 steepness: float, direction: tuple[float, float],
                 speed: float) -> dict:
        raise NotImplementedError

    def remove_wave(self, wave_id: str) -> dict:
        raise NotImplementedError

    def sample_height(self, x: float, z: float, t: float | None = None) -> float:
        raise NotImplementedError

    def sample_normal(self, x: float, z: float,
                      t: float | None = None) -> tuple[float, float, float]:
        raise NotImplementedError

    def splash(self, x: float, z: float, amount: float) -> dict:
        raise NotImplementedError

    def foam_at(self, x: float, z: float) -> float:
        raise NotImplementedError

    def step(self, dt: float, *, frame: int) -> dict:
        raise NotImplementedError

    def build_mesh(self, frame: int, *, rings: int = 3,
                   center: tuple[float, float] = (0.0, 0.0)) -> dict:
        raise NotImplementedError

    def lod_for(self, distance: float) -> int:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, snapshot: dict) -> dict:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
