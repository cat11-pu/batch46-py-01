"""模板传送门：房间/传送门图、递归层级、每帧预算与快照骨架。"""

import threading

SNAPSHOT_VERSION = 1


class PortalError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class StencilPortal:
    """房间与传送门图、逐层模板标记、每帧可见性规划与快照恢复。"""

    def __init__(self, stencil_bits=8, max_depth=4, frame_budget=32):
        self._lock = threading.RLock()
        self._stencil_bits = stencil_bits
        self._max_depth = max_depth
        self._frame_budget = frame_budget
        self._rooms = {}
        self._portals = {}
        self._frame_active = False
        self._epoch = 0

    def register_room(self, room_id, *, bounds=(0, 0, 1, 1)):
        raise NotImplementedError

    def unregister_room(self, room_id):
        raise NotImplementedError

    def register_portal(self, portal_id, *, source, target, transform,
                        enabled=True):
        raise NotImplementedError

    def set_portal_enabled(self, portal_id, enabled):
        raise NotImplementedError

    def describe_portal(self, portal_id):
        raise NotImplementedError

    def stencil_tag(self, depth):
        raise NotImplementedError

    def reachable_rooms(self, start, max_depth=None):
        raise NotImplementedError

    def begin_frame(self):
        raise NotImplementedError

    def end_frame(self):
        raise NotImplementedError

    def render_plan(self, camera_room):
        raise NotImplementedError

    def validate(self):
        raise NotImplementedError

    def stats(self):
        raise NotImplementedError

    def snapshot(self):
        raise NotImplementedError

    def restore(self, snap):
        raise NotImplementedError

    def reset(self):
        raise NotImplementedError
