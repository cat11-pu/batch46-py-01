"""字幕时间轴同步守卫。

本题为 Bugfix 骨架：所有公开方法都只抛 NotImplementedError，
需要按 README 中的题面补全校验、平移、帧率换算、合并切分与快照逻辑。
"""

import math
import threading


class SubtitleError(ValueError):
    """带稳定错误码的异常，code 供调用方分支，detail 携带上下文。"""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class SubtitleSync:
    SNAPSHOT_VERSION = 1

    _STAT_KEYS = (
        "loads",
        "shifts",
        "retimes",
        "merges",
        "splits",
        "ignored",
        "restores",
    )

    def __init__(self, *, max_cues=500, min_duration_ms=200, max_shift_ms=600000):
        self.max_cues = int(max_cues)
        self.min_duration_ms = int(min_duration_ms)
        self.max_shift_ms = int(max_shift_ms)
        self._lock = threading.RLock()
        self._cues = []
        self._offset_ms = 0
        self._applied_retimes = set()
        self._closed = False
        self._stats = {
            "loads": 0,
            "shifts": 0,
            "retimes": 0,
            "merges": 0,
            "splits": 0,
            "ignored": 0,
            "restores": 0,
        }

    @staticmethod
    def _copy_cue(cue):
        return {
            "start_ms": cue["start_ms"],
            "end_ms": cue["end_ms"],
            "text": cue["text"],
            "index": cue["index"],
        }

    def _snapshot_cues(self):
        return [self._copy_cue(cue) for cue in self._cues]

    @staticmethod
    def _round_half_up(value):
        return int(math.floor(value + 0.5))

    def _validate_batch(self, cues):
        """整批校验，任何问题都抛 SubtitleError，不改动调用方状态。"""
        if len(cues) > self.max_cues:
            raise SubtitleError(
                "SUB_LIMIT",
                "cue count %d exceeds max_cues %d" % (len(cues), self.max_cues),
            )
        previous = None
        for position, cue in enumerate(cues):
            start = cue["start_ms"]
            end = cue["end_ms"]
            if start < 0 or end - start < self.min_duration_ms:
                raise SubtitleError(
                    "SUB_BAD_CUE",
                    "cue at %d has negative start or duration below %d"
                    % (position, self.min_duration_ms),
                )
            if previous is not None:
                if start < previous["start_ms"]:
                    raise SubtitleError(
                        "SUB_ORDER",
                        "cue at %d starts before the previous cue" % position,
                    )
                if start < previous["end_ms"]:
                    raise SubtitleError(
                        "SUB_OVERLAP",
                        "cue at %d overlaps the previous cue" % position,
                    )
            previous = cue

    @staticmethod
    def _renumber(cues):
        for index, cue in enumerate(cues):
            cue["index"] = index

    def load_cues(self, cues):
        """整批校验并装载字幕，成功后返回条数。"""
        with self._lock:
            batch = list(cues)
            self._validate_batch(batch)
            new_cues = [
                {
                    "start_ms": cue["start_ms"],
                    "end_ms": cue["end_ms"],
                    "text": cue["text"],
                    "index": index,
                }
                for index, cue in enumerate(batch)
            ]
            self._cues = new_cues
            self._offset_ms = 0
            self._applied_retimes = set()
            self._stats["loads"] += 1
            return len(new_cues)

    def shift(self, delta_ms):
        """整体平移时间轴，返回累计偏移毫秒。"""
        with self._lock:
            delta_ms = int(delta_ms)
            new_offset = self._offset_ms + delta_ms
            if abs(delta_ms) > self.max_shift_ms or abs(new_offset) > self.max_shift_ms:
                raise SubtitleError(
                    "SUB_SHIFT_LIMIT",
                    "offset %d exceeds max_shift_ms %d"
                    % (new_offset, self.max_shift_ms),
                )
            if any(cue["start_ms"] + delta_ms < 0 for cue in self._cues):
                raise SubtitleError(
                    "SUB_NEGATIVE_TIME",
                    "shift by %d moves a cue before zero" % delta_ms,
                )
            new_cues = []
            for cue in self._cues:
                moved = self._copy_cue(cue)
                moved["start_ms"] += delta_ms
                moved["end_ms"] += delta_ms
                new_cues.append(moved)
            self._cues = new_cues
            self._offset_ms = new_offset
            self._stats["shifts"] += 1
            return self._offset_ms

    def retime_fps(self, source_fps, target_fps):
        """按帧率比例换算全部字幕时间戳。"""
        with self._lock:
            if source_fps <= 0 or target_fps <= 0:
                raise SubtitleError(
                    "SUB_BAD_ARG",
                    "fps values must be positive, got %r -> %r"
                    % (source_fps, target_fps),
                )
            pair = (source_fps, target_fps)
            scale = source_fps / target_fps
            if pair in self._applied_retimes:
                self._stats["ignored"] += 1
                return {
                    "status": "ignored",
                    "code": "SUB_RETIME_DUP",
                    "scale": scale,
                }
            new_cues = []
            for cue in self._cues:
                scaled = self._copy_cue(cue)
                scaled["start_ms"] = self._round_half_up(cue["start_ms"] * scale)
                scaled["end_ms"] = self._round_half_up(cue["end_ms"] * scale)
                new_cues.append(scaled)
            for position, cue in enumerate(new_cues):
                if cue["end_ms"] - cue["start_ms"] < self.min_duration_ms:
                    raise SubtitleError(
                        "SUB_BAD_CUE",
                        "scaled cue at %d has duration below %d"
                        % (position, self.min_duration_ms),
                    )
            for position in range(1, len(new_cues)):
                if new_cues[position]["start_ms"] < new_cues[position - 1]["end_ms"]:
                    raise SubtitleError(
                        "SUB_OVERLAP",
                        "scaled cues overlap at %d" % position,
                    )
            self._cues = new_cues
            self._stats["retimes"] += 1
            self._applied_retimes.add(pair)
            return {"status": "applied", "scale": scale}

    def cue_at(self, time_ms):
        """返回覆盖该毫秒时刻的字幕，无命中返回 None。"""
        with self._lock:
            for cue in self._cues:
                if cue["start_ms"] <= time_ms < cue["end_ms"]:
                    return self._copy_cue(cue)
            return None

    def merge_overlaps(self, gap_ms=0):
        """合并间距不超过 gap_ms 的相邻字幕，返回减少条数。"""
        with self._lock:
            if gap_ms < 0:
                raise SubtitleError(
                    "SUB_BAD_ARG", "gap_ms must be non-negative, got %r" % gap_ms
                )
            merged = []
            for cue in self._cues:
                if merged and cue["start_ms"] - merged[-1]["end_ms"] <= gap_ms:
                    merged[-1]["end_ms"] = cue["end_ms"]
                    merged[-1]["text"] += "\n" + cue["text"]
                else:
                    merged.append(self._copy_cue(cue))
            reduced = len(self._cues) - len(merged)
            self._renumber(merged)
            self._cues = merged
            self._stats["merges"] += 1
            return reduced

    def split_cue(self, index, at_ms):
        """在指定时刻把一条字幕切成两条，返回新索引信息。"""
        with self._lock:
            if index < 0 or index >= len(self._cues):
                raise SubtitleError(
                    "SUB_INDEX_UNKNOWN", "cue index %d is out of range" % index
                )
            target = self._cues[index]
            first_duration = at_ms - target["start_ms"]
            second_duration = target["end_ms"] - at_ms
            if first_duration < self.min_duration_ms or second_duration < self.min_duration_ms:
                raise SubtitleError(
                    "SUB_BAD_CUE",
                    "split at %d leaves a half shorter than %d"
                    % (at_ms, self.min_duration_ms),
                )
            first = self._copy_cue(target)
            first["end_ms"] = at_ms
            second = self._copy_cue(target)
            second["start_ms"] = at_ms
            new_cues = self._cues[:index] + [first, second] + self._cues[index + 1:]
            self._renumber(new_cues)
            self._cues = new_cues
            self._stats["splits"] += 1
            return {"first": index, "second": index + 1, "count": len(new_cues)}

    def window(self, start_ms, end_ms):
        """返回与给定区间有交集的所有字幕。"""
        with self._lock:
            if start_ms >= end_ms:
                raise SubtitleError(
                    "SUB_BAD_ARG",
                    "window start %d must be before end %d" % (start_ms, end_ms),
                )
            return [
                self._copy_cue(cue)
                for cue in self._cues
                if cue["start_ms"] < end_ms and cue["end_ms"] > start_ms
            ]

    def validate(self):
        """返回时间轴上的问题列表，正常状态为空列表。"""
        with self._lock:
            problems = []
            previous = None
            for index, cue in enumerate(self._cues):
                start = cue["start_ms"]
                end = cue["end_ms"]
                if start < 0 or end - start < self.min_duration_ms:
                    problems.append({"index": index, "code": "SUB_BAD_CUE"})
                elif previous is not None:
                    if start < previous["start_ms"]:
                        problems.append({"index": index, "code": "SUB_ORDER"})
                    elif start < previous["end_ms"]:
                        problems.append({"index": index, "code": "SUB_OVERLAP"})
                previous = cue
            return problems

    def snapshot(self):
        """导出可序列化的完整状态快照。"""
        with self._lock:
            return {
                "version": self.SNAPSHOT_VERSION,
                "cues": self._snapshot_cues(),
                "offset_ms": self._offset_ms,
                "retimes": [[source, target] for source, target in self._applied_retimes],
                "stats": dict(self._stats),
            }

    def restore(self, snapshot):
        """从快照还原字幕、累计偏移、帧率记录与统计。"""
        with self._lock:
            self._validate_snapshot(snapshot)
            new_cues = [self._copy_cue(cue) for cue in snapshot["cues"]]
            new_retimes = {tuple(pair) for pair in snapshot["retimes"]}
            new_stats = dict(snapshot["stats"])
            new_offset = snapshot["offset_ms"]
            self._cues = new_cues
            self._applied_retimes = new_retimes
            self._offset_ms = new_offset
            self._stats = new_stats
            self._stats["restores"] += 1

    def _validate_snapshot(self, snapshot):
        invalid = SubtitleError("SUB_SNAPSHOT_INVALID", "snapshot structure is damaged")
        if not isinstance(snapshot, dict):
            raise invalid
        if snapshot.get("version") != self.SNAPSHOT_VERSION:
            raise invalid
        cues = snapshot.get("cues")
        if not isinstance(cues, list):
            raise invalid
        for cue in cues:
            if not isinstance(cue, dict):
                raise invalid
            if not isinstance(cue.get("start_ms"), int) or isinstance(cue.get("start_ms"), bool):
                raise invalid
            if not isinstance(cue.get("end_ms"), int) or isinstance(cue.get("end_ms"), bool):
                raise invalid
            if not isinstance(cue.get("text"), str):
                raise invalid
            if not isinstance(cue.get("index"), int) or isinstance(cue.get("index"), bool):
                raise invalid
        offset = snapshot.get("offset_ms")
        if not isinstance(offset, int) or isinstance(offset, bool):
            raise invalid
        retimes = snapshot.get("retimes")
        if not isinstance(retimes, list):
            raise invalid
        for pair in retimes:
            if not isinstance(pair, (list, tuple)) or len(pair) != 2:
                raise invalid
        stats = snapshot.get("stats")
        if not isinstance(stats, dict):
            raise invalid
        for key in self._STAT_KEYS:
            if not isinstance(stats.get(key), int) or isinstance(stats.get(key), bool):
                raise invalid

    def stats(self):
        """返回内部计数器的副本。"""
        with self._lock:
            return dict(self._stats)

    def close(self):
        """关闭实例，重复调用不报错。"""
        with self._lock:
            self._closed = True
