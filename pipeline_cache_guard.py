class PipelineCacheError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class PipelineCache:
    """Content-addressed pipeline cache with compatibility groups and budgets."""

    def __init__(self, *, entry_budget=64, byte_budget=None, generation=1):
        self.entry_budget = entry_budget
        self.byte_budget = byte_budget
        self.generation = generation

    def define_pipeline(
        self,
        pipeline_id,
        *,
        vs,
        fs,
        blend="opaque",
        depth_test=True,
        depth_write=True,
        cull="back",
        topology="tri",
        vertex_layout=(),
        render_pass="main",
        layout="default",
        tags=(),
    ):
        raise NotImplementedError

    def register(self, pipeline_id):
        raise NotImplementedError

    def get(self, pipeline_id):
        raise NotImplementedError

    def store_blob(self, pipeline_id, blob):
        raise NotImplementedError

    def blob(self, pipeline_id):
        raise NotImplementedError

    def trim(self):
        raise NotImplementedError

    def compat_group(self, pipeline_id):
        raise NotImplementedError

    def validate_bindings(self, pipeline_id, set_layout):
        raise NotImplementedError

    def invalidate_generation(self, new_generation):
        raise NotImplementedError

    def keys(self):
        raise NotImplementedError

    def stats(self):
        raise NotImplementedError

    def snapshot(self):
        raise NotImplementedError

    def restore(self, state):
        raise NotImplementedError
