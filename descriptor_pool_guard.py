class DescriptorPoolError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class DescriptorPool:
    """Per-frame descriptor arenas with per-type budgets and generation handles."""

    def __init__(self, *, max_sets=1024, budgets=None, max_frames_in_flight=2):
        self.max_sets = max_sets
        self.budgets = dict(budgets or {})
        self.max_frames_in_flight = max_frames_in_flight

    def define_layout(self, layout_id, *, counts):
        raise NotImplementedError

    def begin_frame(self, frame_id):
        raise NotImplementedError

    def allocate(self, frame, set_id, layout):
        raise NotImplementedError

    def free(self, set_id):
        raise NotImplementedError

    def retire_frame(self, frame):
        raise NotImplementedError

    def reset_frame(self, frame):
        raise NotImplementedError

    def set_of(self, set_id):
        raise NotImplementedError

    def generation_of(self, set_id):
        raise NotImplementedError

    def usage(self):
        raise NotImplementedError

    def stats(self):
        raise NotImplementedError

    def snapshot(self):
        raise NotImplementedError

    def restore(self, state):
        raise NotImplementedError
