class SwapchainResizeError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class SwapchainResize:
    """Debounced swapchain rebuild with generation, retire and budget control."""

    def __init__(
        self,
        *,
        width=1280,
        height=720,
        format="bgra8",
        present="fifo",
        min_images=2,
        max_images=3,
        max_retained=2,
        debounce_frames=2,
        max_bytes=None,
    ):
        self.width = width
        self.height = height
        self.format = format
        self.present = present
        self.min_images = min_images
        self.max_images = max_images
        self.max_retained = max_retained
        self.debounce_frames = debounce_frames
        self.max_bytes = max_bytes

    def observe(self, width, height, *, format=None, present=None, frame=0):
        raise NotImplementedError

    def poll(self, frame=0):
        raise NotImplementedError

    def rebuild(self, frame=0):
        raise NotImplementedError

    def acquire(self, generation):
        raise NotImplementedError

    def present(self, generation, frame=0):
        raise NotImplementedError

    def suspend(self, frame=0):
        raise NotImplementedError

    def resume(self, width, height, *, format=None, present=None, frame=0):
        raise NotImplementedError

    def retire(self, generation):
        raise NotImplementedError

    def config(self):
        raise NotImplementedError

    def history(self):
        raise NotImplementedError

    def estimate_bytes(self, width=None, height=None, *, generation=None):
        raise NotImplementedError

    def stats(self):
        raise NotImplementedError

    def snapshot(self):
        raise NotImplementedError

    def restore(self, state):
        raise NotImplementedError
