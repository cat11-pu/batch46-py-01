"""DASH 分片对齐守卫。

维护各 Representation 的毫秒时间轴、跨档切换点以及可恢复的窗口快照。
所有公开读写操作共用一把可重入锁；写操作先完成校验和构造，再整体替换状态。
"""

import threading


class DashError(ValueError):
    """带稳定错误码的异常，code 供调用方分支，detail 携带上下文。"""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class DashSegment:
    SNAPSHOT_VERSION = 1
    _STAT_KEYS = (
        "representations",
        "alignments",
        "switches",
        "expired",
        "ignored",
        "restores",
    )

    def __init__(self, *, timescale=1000, max_segments=64, max_representations=6):
        self.timescale = int(timescale)
        self.max_segments = int(max_segments)
        self.max_representations = int(max_representations)
        self._lock = threading.RLock()
        self._reps = {}
        self._order = []
        self._current = None
        self._stats = {key: 0 for key in self._STAT_KEYS}
        self._closed = False

    @staticmethod
    def _is_int(value):
        return isinstance(value, int) and not isinstance(value, bool)

    @staticmethod
    def _round_ms(ticks, timescale):
        """把 tick 时长按半入规则换算成整数毫秒。"""
        return (int(ticks) * 2000 + int(timescale)) // (2 * int(timescale))

    @classmethod
    def _build_segments(cls, rep_id, start_number, durations, timescale, base_ms):
        segments = []
        cursor = int(base_ms)
        for offset, ticks in enumerate(durations):
            duration_ms = cls._round_ms(ticks, timescale)
            end_ms = cursor + duration_ms
            number = int(start_number) + offset
            segments.append({
                "number": number,
                "start_ms": cursor,
                "end_ms": end_ms,
                "duration_ms": duration_ms,
                "uri": "%s/seg-%d.m4s" % (rep_id, number),
            })
            cursor = end_ms
        return segments

    @staticmethod
    def _copy_segment(segment):
        return {
            "number": segment["number"],
            "start_ms": segment["start_ms"],
            "end_ms": segment["end_ms"],
            "duration_ms": segment["duration_ms"],
            "uri": segment["uri"],
        }

    @staticmethod
    def _copy_current(current):
        if current is None:
            return None
        return {
            "representation": current["representation"],
            "number": current["number"],
            "start_ms": current["start_ms"],
        }

    @staticmethod
    def _descriptor(rep):
        return {
            "representation": rep["representation"],
            "bandwidth": rep["bandwidth"],
            "codecs": rep["codecs"],
            "width": rep["width"],
            "height": rep["height"],
        }

    def _ensure_open(self):
        if self._closed:
            raise DashError("DASH_CLOSED", "instance is closed")

    def _require_rep(self, rep_id):
        rep = self._reps.get(rep_id)
        if rep is None:
            raise DashError("DASH_REP_UNKNOWN", rep_id)
        return rep

    def _require_aligned(self, rep):
        if not rep["aligned"]:
            raise DashError("DASH_REP_UNAVAILABLE", rep["representation"])
        return rep

    def _find_segment(self, rep, number):
        self._require_aligned(rep)
        if not self._is_int(number):
            raise DashError("DASH_SEGMENT_UNKNOWN", number)
        start = rep["start_number"]
        if number < start:
            raise DashError("DASH_SEGMENT_EXPIRED", number)
        offset = number - start
        if offset >= len(rep["segments"]):
            raise DashError("DASH_SEGMENT_UNKNOWN", number)
        return rep["segments"][offset]

    @staticmethod
    def _snapshot_invalid(detail):
        return DashError("DASH_SNAPSHOT_INVALID", detail)

    def _parse_snapshot(self, snapshot):
        """完整校验并构造新状态；校验失败前绝不改动实例。"""
        if not isinstance(snapshot, dict):
            raise self._snapshot_invalid("snapshot must be a dict")

        version = snapshot.get("version")
        if not self._is_int(version) or version != self.SNAPSHOT_VERSION:
            raise self._snapshot_invalid("unsupported snapshot version")

        if "config" in snapshot:
            raw_config = snapshot["config"]
            if not isinstance(raw_config, dict):
                raise self._snapshot_invalid("config must be a dict")
            for key in ("timescale", "max_segments", "max_representations"):
                if key in raw_config and (
                        not self._is_int(raw_config[key]) or raw_config[key] <= 0):
                    raise self._snapshot_invalid("invalid config %s" % key)

        raw_reps = snapshot.get("representations")
        if not isinstance(raw_reps, dict):
            raise self._snapshot_invalid("representations must be a dict")
        if len(raw_reps) > self.max_representations:
            raise self._snapshot_invalid("too many representations")

        reps = {}
        for rep_id, raw in raw_reps.items():
            if not isinstance(rep_id, str) or not rep_id:
                raise self._snapshot_invalid("invalid representation id")
            if not isinstance(raw, dict):
                raise self._snapshot_invalid("invalid representation row")

            if raw.get("representation", rep_id) != rep_id:
                raise self._snapshot_invalid("representation id mismatch")
            bandwidth = raw.get("bandwidth")
            codecs = raw.get("codecs")
            width = raw.get("width")
            height = raw.get("height")
            if (not self._is_int(bandwidth) or bandwidth <= 0
                    or not isinstance(codecs, str) or not codecs
                    or not self._is_int(width) or width <= 0
                    or not self._is_int(height) or height <= 0):
                raise self._snapshot_invalid("invalid representation metadata")

            aligned = raw.get("aligned")
            if not isinstance(aligned, bool):
                raise self._snapshot_invalid("aligned must be a bool")
            durations = raw.get("durations")
            if not isinstance(durations, list):
                raise self._snapshot_invalid("durations must be a list")
            if any(not self._is_int(value) or value <= 0 for value in durations):
                raise self._snapshot_invalid("invalid segment duration")
            if len(durations) > self.max_segments:
                raise self._snapshot_invalid("segment limit exceeded")

            if not aligned:
                if (durations or raw.get("start_number") is not None
                        or raw.get("timescale") is not None
                        or raw.get("base_ms", 0) != 0):
                    raise self._snapshot_invalid("incomplete unaligned row")
                rep = {
                    "representation": rep_id,
                    "bandwidth": bandwidth,
                    "codecs": codecs,
                    "width": width,
                    "height": height,
                    "aligned": False,
                    "timescale": None,
                    "start_number": None,
                    "durations": [],
                    "base_ms": 0,
                    "segments": [],
                }
            else:
                timescale = raw.get("timescale")
                start_number = raw.get("start_number")
                base_ms = raw.get("base_ms")
                if (not self._is_int(timescale) or timescale <= 0
                        or not self._is_int(start_number)
                        or not self._is_int(base_ms) or base_ms < 0):
                    raise self._snapshot_invalid("invalid alignment window")

                segments = self._build_segments(
                    rep_id, start_number, durations, timescale, base_ms)
                if "segments" not in raw:
                    raise self._snapshot_invalid("missing segment window")
                supplied_segments = raw["segments"]
                if not isinstance(supplied_segments, list) or supplied_segments != segments:
                    raise self._snapshot_invalid("inconsistent segment window")

                rep = {
                    "representation": rep_id,
                    "bandwidth": bandwidth,
                    "codecs": codecs,
                    "width": width,
                    "height": height,
                    "aligned": True,
                    "timescale": timescale,
                    "start_number": start_number,
                    "durations": list(durations),
                    "base_ms": base_ms,
                    "segments": segments,
                }
            reps[rep_id] = rep

        raw_order = snapshot.get("order")
        if raw_order is None:
            order = list(reps)
        else:
            if (not isinstance(raw_order, list)
                    or len(raw_order) != len(reps)
                    or len(set(raw_order)) != len(raw_order)
                    or any(rep_id not in reps for rep_id in raw_order)
                    or set(raw_order) != set(reps)):
                raise self._snapshot_invalid("invalid representation order")
            order = list(raw_order)

        raw_current = snapshot.get("current")
        if raw_current is None:
            current = None
        else:
            if not isinstance(raw_current, dict):
                raise self._snapshot_invalid("invalid current")
            rep_id = raw_current.get("representation")
            number = raw_current.get("number")
            start_ms = raw_current.get("start_ms")
            if (rep_id not in reps or not reps[rep_id]["aligned"]
                    or not self._is_int(number) or not self._is_int(start_ms)
                    or start_ms < 0):
                raise self._snapshot_invalid("invalid current position")
            current = {
                "representation": rep_id,
                "number": number,
                "start_ms": start_ms,
            }

        raw_stats = snapshot.get("stats")
        if not isinstance(raw_stats, dict):
            raise self._snapshot_invalid("stats must be a dict")
        stats = {}
        for key in self._STAT_KEYS:
            value = raw_stats.get(key)
            if not self._is_int(value) or value < 0:
                raise self._snapshot_invalid("invalid stat %s" % key)
            stats[key] = value
        if stats["representations"] != len(reps):
            raise self._snapshot_invalid("representation count mismatch")

        return reps, order, current, stats

    def add_representation(self, rep_id, *, bandwidth, codecs="avc1.4d401f",
                           width=1920, height=1080):
        """登记一个 Representation，重复、非法参数或超出上限时抛 DashError。"""
        with self._lock:
            self._ensure_open()
            if not isinstance(rep_id, str) or not rep_id:
                raise DashError("DASH_BAD_REP", rep_id)
            if rep_id in self._reps:
                raise DashError("DASH_REP_DUP", rep_id)
            if (not self._is_int(bandwidth) or bandwidth <= 0
                    or not isinstance(codecs, str) or not codecs
                    or not self._is_int(width) or width <= 0
                    or not self._is_int(height) or height <= 0):
                raise DashError("DASH_BAD_REP", rep_id)
            if len(self._reps) >= self.max_representations:
                raise DashError("DASH_REP_LIMIT", rep_id)

            rep = {
                "representation": rep_id,
                "bandwidth": bandwidth,
                "codecs": codecs,
                "width": width,
                "height": height,
                "aligned": False,
                "timescale": None,
                "start_number": None,
                "durations": [],
                "base_ms": 0,
                "segments": [],
            }
            self._reps[rep_id] = rep
            self._order.append(rep_id)
            self._stats["representations"] += 1
            return self._descriptor(rep)

    def align_representation(self, rep_id, *, start_number, durations, timescale=None):
        """用起始编号与每分片 tick 时长对齐一个 Representation。"""
        with self._lock:
            self._ensure_open()
            rep = self._require_rep(rep_id)

            if not isinstance(durations, (list, tuple)) or not durations:
                raise DashError("DASH_BAD_SEGMENT", "durations must be non-empty")
            if any(not self._is_int(value) or value <= 0 for value in durations):
                raise DashError("DASH_BAD_SEGMENT", "durations must be positive ticks")
            if not self._is_int(start_number):
                raise DashError("DASH_BAD_SEGMENT", "start_number must be an int")
            if len(durations) > self.max_segments:
                raise DashError("DASH_SEGMENT_LIMIT", len(durations))

            if rep["aligned"]:
                locked_timescale = rep["timescale"]
                if timescale is not None:
                    if not self._is_int(timescale) or timescale <= 0:
                        raise DashError("DASH_BAD_SEGMENT", "invalid timescale")
                    if timescale != locked_timescale:
                        raise DashError(
                            "DASH_TIMESCALE_LOCK",
                            {"locked": locked_timescale, "requested": timescale},
                        )
                chosen_timescale = locked_timescale
            else:
                chosen_timescale = self.timescale if timescale is None else timescale
                if not self._is_int(chosen_timescale) or chosen_timescale <= 0:
                    raise DashError("DASH_BAD_SEGMENT", "invalid timescale")

            if rep["aligned"] and start_number < rep["start_number"]:
                self._stats["ignored"] += 1
                return {
                    "status": "ignored",
                    "code": "DASH_SEQ_REGRESS",
                    "start_number": rep["start_number"],
                    "timescale": rep["timescale"],
                    "segment_count": len(rep["durations"]),
                    "duration_ms": sum(
                        segment["duration_ms"] for segment in rep["segments"]),
                }

            new_durations = list(durations)
            segments = self._build_segments(
                rep_id, start_number, new_durations, chosen_timescale, 0)
            new_rep = {
                "representation": rep_id,
                "bandwidth": rep["bandwidth"],
                "codecs": rep["codecs"],
                "width": rep["width"],
                "height": rep["height"],
                "aligned": True,
                "timescale": chosen_timescale,
                "start_number": start_number,
                "durations": new_durations,
                "base_ms": 0,
                "segments": segments,
            }
            self._reps[rep_id] = new_rep
            self._stats["alignments"] += 1
            return {
                "status": "applied",
                "start_number": start_number,
                "timescale": chosen_timescale,
                "segment_count": len(new_durations),
                "duration_ms": sum(segment["duration_ms"] for segment in segments),
            }

    def segment_at(self, rep_id, number):
        """按分片编号返回起止毫秒、时长与固定格式的 uri。"""
        with self._lock:
            rep = self._require_rep(rep_id)
            segment = self._find_segment(rep, number)
            return self._copy_segment(segment)

    def segment_for_time(self, rep_id, time_ms):
        """返回覆盖指定毫秒时刻的分片，使用左闭右开区间。"""
        with self._lock:
            rep = self._require_aligned(self._require_rep(rep_id))
            if not self._is_int(time_ms) or time_ms < 0:
                raise DashError("DASH_BAD_TIME", time_ms)
            for segment in rep["segments"]:
                if segment["start_ms"] <= time_ms < segment["end_ms"]:
                    return self._copy_segment(segment)
            return None

    def gap_report(self, rep_id, numbers):
        """返回给定编号中不存在于当前窗口的那些编号。"""
        with self._lock:
            rep = self._require_aligned(self._require_rep(rep_id))
            if isinstance(numbers, (str, bytes)):
                raise DashError("DASH_BAD_SEGMENT", "numbers must be iterable")
            try:
                values = list(numbers)
            except TypeError:
                raise DashError("DASH_BAD_SEGMENT", "numbers must be iterable")
            if any(not self._is_int(number) for number in values):
                raise DashError("DASH_BAD_SEGMENT", "numbers must be ints")
            start = rep["start_number"]
            end = start + len(rep["segments"])
            return sorted(
                number for number in values
                if number < start or number >= end
            )

    def alignment_report(self, rep_a, rep_b):
        """比较两个 Representation 的分片边界是否一致。"""
        with self._lock:
            a = self._require_aligned(self._require_rep(rep_a))
            b = self._require_aligned(self._require_rep(rep_b))
            a_starts = [segment["start_ms"] for segment in a["segments"]]
            b_starts = [segment["start_ms"] for segment in b["segments"]]
            a_boundaries = set(a_starts)
            mismatch_ms = next(
                (start for start in b_starts if start not in a_boundaries), None)
            return {
                "aligned": a_starts == b_starts,
                "mismatch_ms": mismatch_ms,
                "a_segments": len(a_starts),
                "b_segments": len(b_starts),
            }

    def switch_representation(self, from_rep, to_rep, *, at_number):
        """在共享边界处切换 Representation，并记录当前播放位置。"""
        with self._lock:
            self._ensure_open()
            source = self._require_rep(from_rep)
            target = self._require_rep(to_rep)
            self._require_aligned(target)

            source_segment = self._find_segment(source, at_number)
            start_ms = source_segment["start_ms"]
            target_segment = next(
                (segment for segment in target["segments"]
                 if segment["start_ms"] == start_ms),
                None,
            )
            if target_segment is None:
                raise DashError(
                    "DASH_SWITCH_MISALIGN",
                    {"at_number": at_number, "start_ms": start_ms},
                )

            self._current = {
                "representation": to_rep,
                "number": target_segment["number"],
                "start_ms": start_ms,
            }
            self._stats["switches"] += 1
            return {
                "status": "switched",
                "variant": to_rep,
                "number": target_segment["number"],
                "start_ms": start_ms,
            }

    def current(self):
        """返回当前 Representation、分片编号与起始毫秒。"""
        with self._lock:
            return self._copy_current(self._current)

    def expire_before(self, number):
        """裁掉编号早于参数的分片，保持时间轴连续。"""
        with self._lock:
            self._ensure_open()
            if not self._is_int(number):
                raise DashError("DASH_BAD_SEGMENT", "number must be an int")

            removed_total = 0
            for rep in self._reps.values():
                if not rep["aligned"]:
                    continue
                start = rep["start_number"]
                count = len(rep["segments"])
                if number <= start:
                    continue
                if count == 0:
                    rep["start_number"] = number
                    continue

                cut = min(number - start, count)
                if cut <= 0:
                    continue
                removed_duration = sum(
                    segment["duration_ms"]
                    for segment in rep["segments"][:cut])
                del rep["segments"][:cut]
                del rep["durations"][:cut]
                rep["base_ms"] += removed_duration
                rep["start_number"] = max(start, number)
                removed_total += cut

            self._stats["expired"] += removed_total
            return removed_total

    def snapshot(self):
        """导出可序列化的完整状态快照。"""
        with self._lock:
            representations = {}
            for rep_id, rep in self._reps.items():
                representations[rep_id] = {
                    "representation": rep["representation"],
                    "bandwidth": rep["bandwidth"],
                    "codecs": rep["codecs"],
                    "width": rep["width"],
                    "height": rep["height"],
                    "aligned": rep["aligned"],
                    "timescale": rep["timescale"],
                    "start_number": rep["start_number"],
                    "durations": list(rep["durations"]),
                    "base_ms": rep["base_ms"],
                    "segments": [
                        self._copy_segment(segment)
                        for segment in rep["segments"]
                    ],
                }
            return {
                "version": self.SNAPSHOT_VERSION,
                "config": {
                    "timescale": self.timescale,
                    "max_segments": self.max_segments,
                    "max_representations": self.max_representations,
                },
                "order": list(self._order),
                "representations": representations,
                "current": self._copy_current(self._current),
                "stats": dict(self._stats),
            }

    def restore(self, snapshot):
        """从快照还原档位、对齐窗口、播放位置与统计。"""
        with self._lock:
            self._ensure_open()
            try:
                reps, order, current, stats = self._parse_snapshot(snapshot)
            except DashError:
                raise
            except Exception as exc:
                raise self._snapshot_invalid(str(exc)) from exc

            stats["restores"] += 1
            self._reps = reps
            self._order = order
            self._current = current
            self._stats = stats

    def stats(self):
        """返回内部计数器的副本。"""
        with self._lock:
            return dict(self._stats)

    def close(self):
        """关闭实例，重复调用不报错。"""
        with self._lock:
            self._closed = True
