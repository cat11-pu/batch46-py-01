"""ABR 码率阶梯守卫。

负责码率阶梯登记校验、按吞吐和缓冲选档、升档滞回、切换频率限制、
吞吐平滑估计以及会话快照。
"""

import math
import threading

BPP_MIN = 0.02
BPP_MAX = 0.15
FPS_BASIS = 30.0


class AbrError(ValueError):
    """带稳定错误码的异常，code 供调用方分支，detail 携带上下文。"""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class AbrLadder:
    SNAPSHOT_VERSION = 1

    _STAT_KEYS = (
        "rungs_added",
        "rungs_removed",
        "selections",
        "up_switches",
        "down_switches",
        "resets",
        "restores",
    )

    def __init__(self, *, max_rungs=8, min_bitrate_kbps=100, max_bitrate_kbps=20000,
                 safety_factor=0.8, upscale_margin=1.25, ewma_alpha=0.3,
                 max_switches_per_window=3, window_size=5, low_buffer_s=2.0):
        self.max_rungs = int(max_rungs)
        self.min_bitrate_kbps = int(min_bitrate_kbps)
        self.max_bitrate_kbps = int(max_bitrate_kbps)
        self.safety_factor = float(safety_factor)
        self.upscale_margin = float(upscale_margin)
        self.ewma_alpha = float(ewma_alpha)
        self.max_switches_per_window = int(max_switches_per_window)
        self.window_size = int(window_size)
        self.low_buffer_s = float(low_buffer_s)
        self._lock = threading.RLock()
        self._rungs = {}
        self._current = None
        self._ewma = None
        self._obs = 0
        self._switch_events = []
        self._stats = {key: 0 for key in self._STAT_KEYS}
        self._closed = False

    @staticmethod
    def _as_int(value):
        if isinstance(value, bool):
            return None
        try:
            number = float(value)
        except (TypeError, ValueError, OverflowError):
            return None
        if not math.isfinite(number) or number != int(number):
            return None
        return int(number)

    @staticmethod
    def _copy_rung(rung):
        if rung is None:
            return None
        return {
            "name": rung["name"],
            "width": rung["width"],
            "height": rung["height"],
            "bitrate_kbps": rung["bitrate_kbps"],
            "codec": rung["codec"],
            "density": rung["density"],
        }

    @staticmethod
    def _density(bitrate_kbps, width, height):
        return bitrate_kbps * 1000 / (width * height * FPS_BASIS)

    @staticmethod
    def _validate_ladder(rows):
        ordered = sorted(rows, key=lambda row: row["bitrate_kbps"])
        previous = None
        for row in ordered:
            if previous is not None:
                if row["bitrate_kbps"] <= previous["bitrate_kbps"]:
                    raise AbrError(
                        "ABR_ORDER",
                        "bitrate must increase strictly with resolution",
                    )
                previous_pixels = previous["width"] * previous["height"]
                pixels = row["width"] * row["height"]
                if pixels <= previous_pixels:
                    raise AbrError(
                        "ABR_ORDER",
                        "pixel count must increase strictly with bitrate",
                    )
            previous = row

    def _sorted_rungs_locked(self):
        return sorted(self._rungs.values(), key=lambda row: row["bitrate_kbps"])

    def _prune_switch_events_locked(self):
        cutoff = self._obs - self.window_size
        self._switch_events = [
            event for event in self._switch_events if event[0] > cutoff
        ]

    def _switch_allowed_locked(self):
        self._prune_switch_events_locked()
        return len(self._switch_events) < self.max_switches_per_window

    def _record_switch_locked(self, rung):
        self._switch_events.append((self._obs, rung["name"]))
        self._prune_switch_events_locked()

    @staticmethod
    def _result(rung, changed, code):
        return {
            "rung": rung["name"] if rung is not None else None,
            "bitrate_kbps": rung["bitrate_kbps"] if rung is not None else None,
            "changed": bool(changed),
            "code": code,
        }

    def add_rung(self, name, *, width, height, bitrate_kbps, codec="h264"):
        """登记一个码率档，并校验分辨率、码率与码率密度。"""
        with self._lock:
            if not isinstance(name, str) or not name:
                raise AbrError("ABR_BAD_RUNG", "name must be a non-empty string")
            if name in self._rungs:
                raise AbrError("ABR_DUP", {"name": name})

            width_i = self._as_int(width)
            height_i = self._as_int(height)
            bitrate_i = self._as_int(bitrate_kbps)
            if width_i is None or height_i is None or bitrate_i is None:
                raise AbrError("ABR_BAD_RUNG", "width, height and bitrate must be integers")
            if width_i <= 0 or height_i <= 0 or bitrate_i <= 0:
                raise AbrError("ABR_BAD_RUNG", "width, height and bitrate must be positive")

            if not (self.min_bitrate_kbps <= bitrate_i <= self.max_bitrate_kbps):
                raise AbrError(
                    "ABR_BITRATE_RANGE",
                    {
                        "bitrate_kbps": bitrate_i,
                        "min": self.min_bitrate_kbps,
                        "max": self.max_bitrate_kbps,
                    },
                )
            if len(self._rungs) >= self.max_rungs:
                raise AbrError(
                    "ABR_RUNG_LIMIT",
                    {"max_rungs": self.max_rungs},
                )

            density = self._density(bitrate_i, width_i, height_i)
            if density < BPP_MIN or density > BPP_MAX:
                raise AbrError(
                    "ABR_RATIO",
                    {
                        "density": density,
                        "min": BPP_MIN,
                        "max": BPP_MAX,
                    },
                )

            rung = {
                "name": name,
                "width": width_i,
                "height": height_i,
                "bitrate_kbps": bitrate_i,
                "codec": codec,
                "density": density,
            }
            self._validate_ladder(list(self._rungs.values()) + [rung])
            self._rungs[name] = rung
            self._stats["rungs_added"] += 1
            return self._copy_rung(rung)

    def rungs(self):
        """返回按码率升序排列的档位列表。"""
        with self._lock:
            return [self._copy_rung(row) for row in self._sorted_rungs_locked()]

    def remove_rung(self, name):
        """删除一个档位，若删除的是当前档则清空当前选择。"""
        with self._lock:
            if name not in self._rungs:
                raise AbrError("ABR_UNKNOWN", {"name": name})
            del self._rungs[name]
            if self._current is not None and self._current["name"] == name:
                self._current = None
            self._stats["rungs_removed"] += 1

    def current(self):
        """返回当前选中的档位。"""
        with self._lock:
            return self._copy_rung(self._current)

    def observe(self, throughput_kbps):
        """写入一次吞吐样本并返回平滑后的估计值。"""
        with self._lock:
            try:
                sample = float(throughput_kbps)
            except (TypeError, ValueError, OverflowError):
                raise AbrError("ABR_BAD_SAMPLE", {"throughput_kbps": throughput_kbps})
            if not math.isfinite(sample) or sample <= 0:
                raise AbrError("ABR_BAD_SAMPLE", {"throughput_kbps": throughput_kbps})

            if self._ewma is None:
                self._ewma = sample
            else:
                self._ewma = (
                    self.ewma_alpha * sample
                    + (1.0 - self.ewma_alpha) * self._ewma
                )
            self._obs += 1
            self._prune_switch_events_locked()
            return self._ewma

    def select(self, throughput_kbps, *, device_cap_kbps=None, buffer_s=None):
        """根据吞吐、设备上限和缓冲选择档位。"""
        with self._lock:
            try:
                throughput = float(throughput_kbps)
            except (TypeError, ValueError, OverflowError):
                raise AbrError("ABR_BAD_SAMPLE", {"throughput_kbps": throughput_kbps})
            if not math.isfinite(throughput):
                raise AbrError("ABR_BAD_SAMPLE", {"throughput_kbps": throughput_kbps})

            cap = None
            if device_cap_kbps is not None:
                try:
                    cap = float(device_cap_kbps)
                except (TypeError, ValueError, OverflowError):
                    raise AbrError(
                        "ABR_BAD_SAMPLE",
                        {"device_cap_kbps": device_cap_kbps},
                    )
                if not math.isfinite(cap):
                    cap = 0.0

            buffer_value = None
            if buffer_s is not None:
                try:
                    buffer_value = float(buffer_s)
                except (TypeError, ValueError, OverflowError):
                    raise AbrError("ABR_BAD_SAMPLE", {"buffer_s": buffer_s})
                if not math.isfinite(buffer_value):
                    buffer_value = 0.0

            self._stats["selections"] += 1
            self._prune_switch_events_locked()

            budget = throughput * self.safety_factor
            limit = budget
            if cap is not None:
                limit = min(limit, cap)

            target = None
            for rung in self._rungs.values():
                bitrate = rung["bitrate_kbps"]
                if bitrate > limit:
                    continue
                if target is None or bitrate > target["bitrate_kbps"]:
                    target = rung

            if target is None:
                return self._result(self._current, False, "ABR_UNDERFLOW")

            if self._current is None:
                self._current = target
                return self._result(target, True, "ABR_INIT")

            if target["bitrate_kbps"] == self._current["bitrate_kbps"]:
                return self._result(target, False, "ABR_STABLE")

            if target["bitrate_kbps"] < self._current["bitrate_kbps"]:
                code = "ABR_DOWN"
            else:
                required = target["bitrate_kbps"] * self.upscale_margin
                if budget < required:
                    return self._result(self._current, False, "ABR_HOLD")
                if buffer_value is not None and buffer_value < self.low_buffer_s:
                    return self._result(self._current, False, "ABR_HOLD")
                code = "ABR_UP"

            if not self._switch_allowed_locked():
                return self._result(self._current, False, "ABR_SWITCH_LIMIT")

            self._current = target
            self._record_switch_locked(target)
            if code == "ABR_UP":
                self._stats["up_switches"] += 1
            else:
                self._stats["down_switches"] += 1
            return self._result(target, True, code)

    def select_auto(self, *, device_cap_kbps=None, buffer_s=None):
        """用当前平滑吞吐调用选档。"""
        with self._lock:
            throughput = 0.0 if self._ewma is None else self._ewma
            return self.select(
                throughput,
                device_cap_kbps=device_cap_kbps,
                buffer_s=buffer_s,
            )

    def reset_session(self):
        """清空当前档、平滑值、观测序号和切换窗口，保留档位。"""
        with self._lock:
            self._current = None
            self._ewma = None
            self._obs = 0
            self._switch_events = []
            self._stats["resets"] += 1

    def snapshot(self):
        """导出可序列化的完整状态快照。"""
        with self._lock:
            self._prune_switch_events_locked()
            return {
                "version": self.SNAPSHOT_VERSION,
                "rungs": [self._copy_rung(row) for row in self._sorted_rungs_locked()],
                "current": self._copy_rung(self._current),
                "ewma": self._ewma,
                "obs": self._obs,
                "switch_events": [
                    {"obs": obs, "rung": name}
                    for obs, name in self._switch_events
                ],
                "stats": dict(self._stats),
            }

    @staticmethod
    def _snapshot_error(detail):
        raise AbrError("ABR_SNAPSHOT_INVALID", detail)

    def restore(self, snapshot):
        """从快照还原档位、当前选择、平滑值与统计。"""
        with self._lock:
            if not isinstance(snapshot, dict):
                self._snapshot_error("snapshot must be a dict")
            version = snapshot.get("version")
            if (
                isinstance(version, bool)
                or not isinstance(version, int)
                or version != self.SNAPSHOT_VERSION
            ):
                self._snapshot_error({"version": version})

            required = ("rungs", "current", "ewma", "obs", "switch_events", "stats")
            if any(key not in snapshot for key in required):
                self._snapshot_error("snapshot is missing required fields")

            raw_rungs = snapshot["rungs"]
            if not isinstance(raw_rungs, list):
                self._snapshot_error("rungs must be a list")

            rungs = {}
            for raw in raw_rungs:
                if not isinstance(raw, dict):
                    self._snapshot_error("rung must be a dict")
                name = raw.get("name")
                width = self._as_int(raw.get("width"))
                height = self._as_int(raw.get("height"))
                bitrate = self._as_int(raw.get("bitrate_kbps"))
                codec = raw.get("codec", "h264")
                if (
                    not isinstance(name, str)
                    or not name
                    or width is None
                    or height is None
                    or bitrate is None
                    or width <= 0
                    or height <= 0
                    or bitrate <= 0
                    or not isinstance(codec, str)
                    or name in rungs
                ):
                    self._snapshot_error("invalid rung")
                density = self._density(bitrate, width, height)
                if density < BPP_MIN or density > BPP_MAX:
                    self._snapshot_error("rung density out of range")
                rungs[name] = {
                    "name": name,
                    "width": width,
                    "height": height,
                    "bitrate_kbps": bitrate,
                    "codec": codec,
                    "density": density,
                }
            try:
                self._validate_ladder(list(rungs.values()))
            except AbrError:
                self._snapshot_error("invalid ladder ordering")

            raw_current = snapshot["current"]
            current = None
            if raw_current is not None:
                if isinstance(raw_current, str):
                    current_name = raw_current
                elif isinstance(raw_current, dict):
                    current_name = raw_current.get("name")
                else:
                    self._snapshot_error("current must be a rung or null")
                if not isinstance(current_name, str) or current_name not in rungs:
                    self._snapshot_error("current rung is unknown")
                current = rungs[current_name]

            ewma = snapshot["ewma"]
            if ewma is not None:
                if isinstance(ewma, bool):
                    self._snapshot_error("invalid ewma")
                try:
                    ewma = float(ewma)
                except (TypeError, ValueError, OverflowError):
                    self._snapshot_error("invalid ewma")
                if not math.isfinite(ewma) or ewma <= 0:
                    self._snapshot_error("invalid ewma")

            obs = snapshot["obs"]
            if isinstance(obs, bool) or not isinstance(obs, int) or obs < 0:
                self._snapshot_error("invalid observation index")

            raw_events = snapshot["switch_events"]
            if not isinstance(raw_events, list):
                self._snapshot_error("switch_events must be a list")
            events = []
            for raw in raw_events:
                if isinstance(raw, dict):
                    event_obs = raw.get("obs")
                    event_rung = raw.get("rung")
                elif isinstance(raw, (list, tuple)) and len(raw) == 2:
                    event_obs, event_rung = raw
                else:
                    self._snapshot_error("invalid switch event")
                if (
                    isinstance(event_obs, bool)
                    or not isinstance(event_obs, int)
                    or event_obs < 0
                    or event_obs > obs
                    or not isinstance(event_rung, str)
                ):
                    self._snapshot_error("invalid switch event")
                events.append((event_obs, event_rung))

            raw_stats = snapshot["stats"]
            if not isinstance(raw_stats, dict):
                self._snapshot_error("stats must be a dict")
            stats = {}
            for key in self._STAT_KEYS:
                value = raw_stats.get(key)
                if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                    self._snapshot_error({"stats": key})
                stats[key] = value

            self._rungs = rungs
            self._current = current
            self._ewma = ewma
            self._obs = obs
            self._switch_events = events
            self._prune_switch_events_locked()
            self._stats = stats
            self._stats["restores"] += 1

    def stats(self):
        """返回内部计数器与当前档位数的副本。"""
        with self._lock:
            result = dict(self._stats)
            result["active_rungs"] = len(self._rungs)
            return result

    def close(self):
        """关闭实例，重复调用不报错。"""
        with self._lock:
            self._closed = True
