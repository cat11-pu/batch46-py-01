"""Irradiance volume: voxel SH storage, dirty boxes and bounded incremental updates."""

SNAPSHOT_VERSION = 1
SH_COEFFICIENTS = 9


class IrradianceVolumeError(ValueError):
    """Domain error carrying a stable machine-readable code."""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class IrradianceVolume:
    """Sparse irradiance voxel grid with dirty tracking and frame budgets."""

    def __init__(self, *, dims=(8, 4, 8), voxel_size: float = 1.0,
                 max_updates_per_frame: int = 1024,
                 max_voxels: int = 65536):
        self.dims = tuple(dims)
        self.voxel_size = voxel_size
        self.max_updates_per_frame = max_updates_per_frame
        self.max_voxels = max_voxels

    def set_voxel(self, index: tuple[int, int, int], *,
                  sh: tuple[float, ...]) -> dict:
        raise NotImplementedError

    def mark_dirty(self, box: tuple[int, int, int, int, int, int]) -> dict:
        raise NotImplementedError

    def update(self, frame: int) -> dict:
        raise NotImplementedError

    def sample(self, position: tuple[float, float, float]) -> dict:
        raise NotImplementedError

    def freeze(self) -> dict:
        raise NotImplementedError

    def unfreeze(self) -> dict:
        raise NotImplementedError

    def generation(self) -> int:
        raise NotImplementedError

    def clear(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, snapshot: dict) -> dict:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
