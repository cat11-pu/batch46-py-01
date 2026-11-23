"""字幕时间轴同步守卫。

本题为 Bugfix 骨架：所有公开方法都只抛 NotImplementedError，
需要按 README 中的题面补全校验、平移、帧率换算、合并切分与快照逻辑。
"""

import threading


class SubtitleError(ValueError):
    """带稳定错误码的异常，code 供调用方分支，detail 携带上下文。"""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class SubtitleSync:
    SNAPSHOT_VERSION = 1

    def __init__(self, *, max_cues=500, min_duration_ms=200, max_shift_ms=600000):
        self.max_cues = int(max_cues)
        self.min_duration_ms = int(min_duration_ms)
        self.max_shift_ms = int(max_shift_ms)
        self._lock = threading.RLock()
        self._cues = []
        self._offset_ms = 0
        self._applied_retimes = set()
        self._stats = {
            "loads": 0,
            "shifts": 0,
            "retimes": 0,
            "merges": 0,
            "splits": 0,
            "ignored": 0,
            "restores": 0,
        }

    def load_cues(self, cues):
        """整批校验并装载字幕，成功后返回条数。"""
        raise NotImplementedError("load_cues")

    def shift(self, delta_ms):
        """整体平移时间轴，返回累计偏移毫秒。"""
        raise NotImplementedError("shift")

    def retime_fps(self, source_fps, target_fps):
        """按帧率比例换算全部字幕时间戳。"""
        raise NotImplementedError("retime_fps")

    def cue_at(self, time_ms):
        """返回覆盖该毫秒时刻的字幕，无命中返回 None。"""
        raise NotImplementedError("cue_at")

    def merge_overlaps(self, gap_ms=0):
        """合并间距不超过 gap_ms 的相邻字幕，返回减少条数。"""
        raise NotImplementedError("merge_overlaps")

    def split_cue(self, index, at_ms):
        """在指定时刻把一条字幕切成两条，返回新索引信息。"""
        raise NotImplementedError("split_cue")

    def window(self, start_ms, end_ms):
        """返回与给定区间有交集的所有字幕。"""
        raise NotImplementedError("window")

    def validate(self):
        """返回时间轴上的问题列表，正常状态为空列表。"""
        raise NotImplementedError("validate")

    def snapshot(self):
        """导出可序列化的完整状态快照。"""
        raise NotImplementedError("snapshot")

    def restore(self, snapshot):
        """从快照还原字幕、累计偏移、帧率记录与统计。"""
        raise NotImplementedError("restore")

    def stats(self):
        """返回内部计数器的副本。"""
        raise NotImplementedError("stats")

    def close(self):
        """关闭实例，重复调用不报错。"""
        raise NotImplementedError("close")
