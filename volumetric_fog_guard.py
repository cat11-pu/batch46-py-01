"""Volumetric fog froxel pipeline: depth reconstruction, scattering and history."""

SNAPSHOT_VERSION = 1
MAX_SAMPLES_PER_FROXEL = 64
MAX_MOTION_PIXELS = 64.0
DEFAULT_SAMPLE_BUDGET = 250_000


class FogError(ValueError):
    """Domain error carrying a stable machine-readable code."""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class VolumetricFog:
    """Camera, froxel grid, lights, participating media and temporal history."""

    def __init__(self, *, grid=(16, 9, 64), max_froxels=1_000_000,
                 history_frames=4, max_sample_units=DEFAULT_SAMPLE_BUDGET):
        self.grid = tuple(grid)
        self.max_froxels = max_froxels
        self.history_frames = history_frames
        self.max_sample_units = max_sample_units

    def set_camera(self, camera_id: str, *, near: float, far: float,
                   reversed_z: bool = False,
                   jitter: tuple[float, float] = (0.0, 0.0)) -> dict:
        raise NotImplementedError

    def add_light(self, light_id: str, *, intensity: float,
                  position: tuple[float, float, float], radius: float,
                  color: tuple[float, float, float] = (1.0, 1.0, 1.0)) -> dict:
        raise NotImplementedError

    def remove_light(self, light_id: str) -> dict:
        raise NotImplementedError

    def inject_media(self, media_id: str, *, density: float,
                     height_falloff: float, extinction: float) -> dict:
        raise NotImplementedError

    def reconstruct_depth(self, frame_id: int, depth: list[float], *,
                          width: int, height: int) -> dict:
        raise NotImplementedError

    def scatter(self, frame_id: int, *, samples_per_froxel: int = 8) -> dict:
        raise NotImplementedError

    def resolve(self, frame_id: int) -> dict:
        raise NotImplementedError

    def reproject(self, frame_id: int,
                  motion: list[tuple[float, float]]) -> dict:
        raise NotImplementedError

    def history_state(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, snapshot: dict) -> dict:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
