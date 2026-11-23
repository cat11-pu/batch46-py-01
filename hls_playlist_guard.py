"""HLS 播放列表切换守卫。

维护每个码率档独立的媒体播放列表窗口，并在同一把锁内完成提交、切档、
过期与快照，避免播放器、录制回源和运维看板看到互相矛盾的状态。
"""

import copy
import math
import threading
from collections import OrderedDict, deque
from collections.abc import Mapping
from numbers import Real


class HlsError(ValueError):
    """带稳定错误码的异常，code 供调用方分支，detail 携带上下文。"""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class HlsPlaylist:
    SNAPSHOT_VERSION = 1
    MAX_SWITCH_SEQUENCES = 64

    def __init__(self, *, target_duration=6.0, window_size=6, max_variants=8,
                 switch_budget=2):
        try:
            self.target_duration = float(target_duration)
            self.window_size = int(window_size)
            self.max_variants = int(max_variants)
            self.switch_budget = int(switch_budget)
        except (TypeError, ValueError, OverflowError):
            raise HlsError("HLS_BAD_CONFIG", {
                "target_duration": target_duration,
                "window_size": window_size,
                "max_variants": max_variants,
                "switch_budget": switch_budget,
            })
        if (not math.isfinite(self.target_duration) or self.target_duration <= 0
                or self.window_size <= 0 or self.max_variants <= 0
                or self.switch_budget < 0):
            raise HlsError("HLS_BAD_CONFIG", {
                "target_duration": self.target_duration,
                "window_size": self.window_size,
                "max_variants": self.max_variants,
                "switch_budget": self.switch_budget,
            })
        self._lock = threading.RLock()
        self._variants = {}
        self._state = {}
        self._current = None
        self._pending = {}
        self._switch_counts = OrderedDict()
        self._stats = {
            "updates_applied": 0,
            "updates_ignored": 0,
            "switches": 0,
            "expired": 0,
            "restores": 0,
        }
        self._closed = False

    def _ensure_open(self, operation):
        if self._closed:
            raise HlsError("HLS_CLOSED", {"operation": operation})

    def _variant(self, variant_id):
        try:
            return self._variants[variant_id]
        except (KeyError, TypeError):
            raise HlsError("HLS_VARIANT_UNKNOWN", {"variant": variant_id})

    @staticmethod
    def _copy_variant(info):
        result = dict(info)
        result["resolution"] = copy.deepcopy(info.get("resolution"))
        return result

    @staticmethod
    def _valid_variant_id(variant_id):
        return isinstance(variant_id, str) and bool(variant_id)

    @staticmethod
    def _duration_value(value):
        if isinstance(value, bool) or not isinstance(value, Real):
            return None
        try:
            value = float(value)
        except (TypeError, ValueError, OverflowError):
            return None
        if not math.isfinite(value):
            return None
        return value

    def register_variant(self, variant_id, *, bandwidth, codecs="avc1.4d401f,mp4a.40.2",
                         resolution=None):
        """登记一个码率档，重复、非法带宽或超出档位上限时抛 HlsError。"""
        with self._lock:
            self._ensure_open("register_variant")
            if not self._valid_variant_id(variant_id):
                raise HlsError("HLS_BAD_VARIANT", {"variant": variant_id})
            if variant_id in self._variants:
                raise HlsError("HLS_VARIANT_DUP", {"variant": variant_id})
            parsed_bandwidth = self._duration_value(bandwidth)
            if parsed_bandwidth is None or parsed_bandwidth <= 0:
                raise HlsError("HLS_BAD_VARIANT", {
                    "variant": variant_id,
                    "bandwidth": bandwidth,
                })
            if not isinstance(codecs, str):
                raise HlsError("HLS_BAD_VARIANT", {
                    "variant": variant_id,
                    "codecs": codecs,
                })
            if len(self._variants) >= self.max_variants:
                raise HlsError("HLS_VARIANT_LIMIT", {
                    "variant": variant_id,
                    "max_variants": self.max_variants,
                })

            info = {
                "variant": variant_id,
                "bandwidth": bandwidth,
                "codecs": codecs,
                "resolution": copy.deepcopy(resolution),
            }
            self._variants[variant_id] = info
            self._state[variant_id] = {
                "media_sequence": 0,
                "segments": deque(),
            }
            self._pending[variant_id] = False
            return self._copy_variant(info)

    def variant_info(self, variant_id):
        """返回档位的带宽、codecs 与分辨率。"""
        with self._lock:
            return self._copy_variant(self._variant(variant_id))

    def update_media_playlist(self, variant_id, *, media_sequence, segments,
                              target_duration=None):
        """以 media_sequence 为起点整体提交一批分片，滑动窗口与序号在这里推进。"""
        with self._lock:
            self._ensure_open("update_media_playlist")
            state = self._state[self._variant(variant_id)["variant"]]

            try:
                if isinstance(segments, (str, bytes, bytearray)):
                    raise TypeError
                raw_segments = list(segments)
            except TypeError:
                raise HlsError("HLS_BAD_SEGMENT", {
                    "variant": variant_id,
                    "segments": segments,
                })

            if len(raw_segments) > self.window_size:
                raise HlsError("HLS_WINDOW_OVERSIZE", {
                    "variant": variant_id,
                    "segment_count": len(raw_segments),
                    "window_size": self.window_size,
                })
            if isinstance(media_sequence, bool) or not isinstance(media_sequence, int):
                raise HlsError("HLS_BAD_SEQUENCE", {
                    "variant": variant_id,
                    "media_sequence": media_sequence,
                })

            effective_target = self.target_duration
            if target_duration is not None:
                parsed_target = self._duration_value(target_duration)
                if parsed_target is None or parsed_target <= 0:
                    raise HlsError("HLS_BAD_SEGMENT", {
                        "variant": variant_id,
                        "target_duration": target_duration,
                    })
                effective_target = parsed_target

            normalized = []
            for index, raw in enumerate(raw_segments):
                if not isinstance(raw, Mapping):
                    raise HlsError("HLS_BAD_SEGMENT", {
                        "variant": variant_id,
                        "index": index,
                    })
                if "uri" not in raw or "duration" not in raw:
                    raise HlsError("HLS_BAD_SEGMENT", {
                        "variant": variant_id,
                        "index": index,
                    })
                duration = self._duration_value(raw["duration"])
                if duration is None or duration < 0:
                    raise HlsError("HLS_BAD_SEGMENT", {
                        "variant": variant_id,
                        "index": index,
                        "duration": raw.get("duration"),
                    })
                if duration > effective_target:
                    raise HlsError("HLS_DURATION_DRIFT", {
                        "variant": variant_id,
                        "index": index,
                        "uri": raw.get("uri"),
                        "duration": duration,
                        "target_duration": effective_target,
                    })
                normalized.append((raw, duration))

            expected = state["media_sequence"]
            if media_sequence < expected:
                self._stats["updates_ignored"] += 1
                return {
                    "status": "ignored",
                    "code": "HLS_SEQ_REGRESS",
                    "variant": variant_id,
                    "media_sequence": expected,
                }
            if media_sequence > expected:
                self._stats["updates_ignored"] += 1
                return {
                    "status": "ignored",
                    "code": "HLS_SEQ_GAP",
                    "variant": variant_id,
                    "media_sequence": expected,
                }

            pending = self._pending.get(variant_id, False)
            rows = []
            for index, (raw, duration) in enumerate(normalized):
                row = dict(raw)
                row["media_sequence"] = expected + index
                row["uri"] = raw["uri"]
                row["duration"] = duration
                row["discontinuity"] = bool(raw.get("discontinuity", False))
                if index == 0 and pending:
                    row["discontinuity"] = True
                rows.append(row)

            window = state["segments"]
            old_length = len(window)
            for row in rows:
                window.append(row)

            trim_count = old_length + len(rows) - self.window_size
            trimmed_uris = []
            for _ in range(max(0, trim_count)):
                trimmed_uris.append(window.popleft().get("uri"))

            if rows and pending:
                self._pending[variant_id] = False
            state["media_sequence"] = expected + len(rows)
            if target_duration is not None:
                self.target_duration = effective_target
            self._stats["updates_applied"] += 1

            return {
                "status": "applied",
                "variant": variant_id,
                "media_sequence": state["media_sequence"],
                "segment_count": len(rows),
                "trimmed": len(trimmed_uris),
                "trimmed_uris": trimmed_uris,
                "window_size": len(window),
            }

    def switch_variant(self, from_variant, to_variant, *, at_sequence=None):
        """在指定序号切换码率档，按 codecs 差异决定是否需要断点标记。"""
        with self._lock:
            self._ensure_open("switch_variant")
            source = self._variant(from_variant)
            target = self._variant(to_variant)
            if from_variant == to_variant:
                raise HlsError("HLS_SWITCH_SAME", {
                    "variant": from_variant,
                })

            if at_sequence is None:
                sequence = self._state[source["variant"]]["media_sequence"]
            else:
                if isinstance(at_sequence, bool) or not isinstance(at_sequence, int):
                    raise HlsError("HLS_BAD_SEQUENCE", {
                        "at_sequence": at_sequence,
                    })
                sequence = at_sequence

            count = self._switch_counts.get(sequence, 0)
            if count >= self.switch_budget:
                raise HlsError("HLS_SWITCH_THRASH", {
                    "at_sequence": sequence,
                    "count": count,
                    "switch_budget": self.switch_budget,
                })

            discontinuity = source["codecs"] != target["codecs"]
            if discontinuity:
                self._pending[target["variant"]] = True

            self._switch_counts[sequence] = count + 1
            self._switch_counts.move_to_end(sequence)
            while len(self._switch_counts) > self.MAX_SWITCH_SEQUENCES:
                self._switch_counts.popitem(last=False)

            self._current = target["variant"]
            self._stats["switches"] += 1
            return {
                "status": "switched",
                "from_variant": source["variant"],
                "to_variant": target["variant"],
                "variant": target["variant"],
                "at_sequence": sequence,
                "discontinuity": discontinuity,
                "media_sequence": self._state[target["variant"]]["media_sequence"],
            }

    def current(self):
        """返回当前档位、媒体序号与窗口长度。"""
        with self._lock:
            if self._current is None:
                return {
                    "variant": None,
                    "media_sequence": 0,
                    "window_size": 0,
                }
            state = self._state[self._current]
            return {
                "variant": self._current,
                "media_sequence": state["media_sequence"],
                "window_size": len(state["segments"]),
            }

    def segments(self, variant_id=None):
        """返回指定档位（缺省为当前档）的窗口分片副本。"""
        with self._lock:
            if variant_id is None:
                variant_id = self._current
                if variant_id is None:
                    return []
            state = self._state[self._variant(variant_id)["variant"]]
            return [dict(row) for row in state["segments"]]

    def pending_discontinuity(self, variant_id):
        """查询某档位是否还有待消费的断点标记。"""
        with self._lock:
            self._variant(variant_id)
            return bool(self._pending.get(variant_id, False))

    def expire_before(self, media_sequence):
        """裁掉序号早于参数的全部分片，返回删除条数。"""
        with self._lock:
            self._ensure_open("expire_before")
            if isinstance(media_sequence, bool) or not isinstance(media_sequence, int):
                raise HlsError("HLS_BAD_SEQUENCE", {
                    "media_sequence": media_sequence,
                })

            removed = 0
            for state in self._state.values():
                window = state["segments"]
                while window and window[0]["media_sequence"] < media_sequence:
                    window.popleft()
                    removed += 1
            self._stats["expired"] += removed
            return removed

    def snapshot(self):
        """导出可序列化的完整状态快照。"""
        with self._lock:
            return {
                "version": self.SNAPSHOT_VERSION,
                "config": {
                    "target_duration": self.target_duration,
                    "window_size": self.window_size,
                    "max_variants": self.max_variants,
                    "switch_budget": self.switch_budget,
                },
                "variants": {
                    variant_id: self._copy_variant(info)
                    for variant_id, info in self._variants.items()
                },
                "state": {
                    variant_id: {
                        "media_sequence": state["media_sequence"],
                        "segments": [dict(row) for row in state["segments"]],
                    }
                    for variant_id, state in self._state.items()
                },
                "current": self._current,
                "pending": {
                    variant_id: True
                    for variant_id, pending in self._pending.items()
                    if pending
                },
                "switch_counts": dict(self._switch_counts),
                "stats": dict(self._stats),
            }

    def restore(self, snapshot):
        """从快照还原配置、窗口、待处理标记与统计。"""
        with self._lock:
            self._ensure_open("restore")
            try:
                if not isinstance(snapshot, dict):
                    raise ValueError("snapshot must be a dict")
                if snapshot.get("version") != self.SNAPSHOT_VERSION:
                    raise ValueError("unsupported snapshot version")

                config = snapshot["config"]
                if not isinstance(config, dict):
                    raise ValueError("config must be a dict")
                target_duration = float(config["target_duration"])
                window_size = int(config["window_size"])
                max_variants = int(config["max_variants"])
                switch_budget = int(config["switch_budget"])
                if (not math.isfinite(target_duration) or target_duration <= 0
                        or window_size <= 0 or max_variants <= 0
                        or switch_budget < 0):
                    raise ValueError("invalid config values")

                raw_variants = snapshot["variants"]
                if not isinstance(raw_variants, dict):
                    raise ValueError("variants must be a dict")
                if len(raw_variants) > max_variants:
                    raise ValueError("too many variants")
                variants = {}
                for variant_id, raw_info in raw_variants.items():
                    if not self._valid_variant_id(variant_id):
                        raise ValueError("invalid variant id")
                    if not isinstance(raw_info, dict):
                        raise ValueError("variant info must be a dict")
                    if raw_info.get("variant", variant_id) != variant_id:
                        raise ValueError("variant id mismatch")
                    bandwidth = raw_info["bandwidth"]
                    if (isinstance(bandwidth, bool) or not isinstance(bandwidth, Real)
                            or not math.isfinite(float(bandwidth)) or bandwidth <= 0):
                        raise ValueError("invalid bandwidth")
                    codecs = raw_info["codecs"]
                    if not isinstance(codecs, str):
                        raise ValueError("invalid codecs")
                    variants[variant_id] = {
                        "variant": variant_id,
                        "bandwidth": bandwidth,
                        "codecs": codecs,
                        "resolution": copy.deepcopy(raw_info.get("resolution")),
                    }

                raw_state = snapshot["state"]
                if not isinstance(raw_state, dict):
                    raise ValueError("state must be a dict")
                if set(raw_state) != set(variants):
                    raise ValueError("state does not match variants")
                states = {}
                for variant_id, raw_entry in raw_state.items():
                    if not isinstance(raw_entry, dict):
                        raise ValueError("state entry must be a dict")
                    media_sequence = raw_entry["media_sequence"]
                    if (isinstance(media_sequence, bool)
                            or not isinstance(media_sequence, int)
                            or media_sequence < 0):
                        raise ValueError("invalid media_sequence")
                    raw_rows = raw_entry["segments"]
                    if not isinstance(raw_rows, list):
                        raise ValueError("segments must be a list")
                    if len(raw_rows) > window_size:
                        raise ValueError("window exceeds configured size")
                    rows = []
                    start_sequence = media_sequence - len(raw_rows)
                    if start_sequence < 0:
                        raise ValueError("invalid window sequence")
                    for index, raw_row in enumerate(raw_rows):
                        if not isinstance(raw_row, dict):
                            raise ValueError("segment must be a dict")
                        if "uri" not in raw_row or "duration" not in raw_row:
                            raise ValueError("segment missing fields")
                        if (raw_row.get("media_sequence") != start_sequence + index
                                or not isinstance(raw_row.get("discontinuity"), bool)):
                            raise ValueError("inconsistent segment")
                        duration = self._duration_value(raw_row["duration"])
                        if duration is None or duration < 0:
                            raise ValueError("invalid segment duration")
                        row = dict(raw_row)
                        row["duration"] = duration
                        rows.append(row)
                    states[variant_id] = {
                        "media_sequence": media_sequence,
                        "segments": deque(rows),
                    }

                current = snapshot.get("current")
                if current is not None and current not in variants:
                    raise ValueError("invalid current variant")

                raw_pending = snapshot.get("pending", {})
                if not isinstance(raw_pending, dict):
                    raise ValueError("pending must be a dict")
                pending = {}
                for variant_id, value in raw_pending.items():
                    if variant_id not in variants or not isinstance(value, bool):
                        raise ValueError("invalid pending state")
                    pending[variant_id] = value
                for variant_id in variants:
                    pending.setdefault(variant_id, False)

                raw_counts = snapshot.get("switch_counts", {})
                if not isinstance(raw_counts, dict):
                    raise ValueError("switch_counts must be a dict")
                if len(raw_counts) > self.MAX_SWITCH_SEQUENCES:
                    raise ValueError("too many switch sequences")
                switch_counts = OrderedDict()
                for sequence, count in raw_counts.items():
                    if isinstance(sequence, str):
                        sequence = int(sequence)
                    if (isinstance(sequence, bool) or not isinstance(sequence, int)
                            or isinstance(count, bool) or not isinstance(count, int)
                            or count < 0):
                        raise ValueError("invalid switch count")
                    switch_counts[sequence] = count

                raw_stats = snapshot["stats"]
                if not isinstance(raw_stats, dict):
                    raise ValueError("stats must be a dict")
                stats = {}
                for name in ("updates_applied", "updates_ignored", "switches",
                             "expired", "restores"):
                    value = raw_stats[name]
                    if (isinstance(value, bool) or not isinstance(value, int)
                            or value < 0):
                        raise ValueError("invalid stat")
                    stats[name] = value
            except (KeyError, TypeError, ValueError, OverflowError):
                raise HlsError("HLS_SNAPSHOT_INVALID", {
                    "reason": "malformed snapshot",
                })

            self.target_duration = target_duration
            self.window_size = window_size
            self.max_variants = max_variants
            self.switch_budget = switch_budget
            self._variants = variants
            self._state = states
            self._current = current
            self._pending = pending
            self._switch_counts = switch_counts
            stats["restores"] += 1
            self._stats = stats

    def stats(self):
        """返回内部计数器的副本。"""
        with self._lock:
            return dict(self._stats)

    def close(self):
        """关闭实例，重复调用不报错。"""
        with self._lock:
            self._closed = True
