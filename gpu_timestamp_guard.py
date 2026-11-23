import copy
import math
import threading


STAGE_ORDER = ("begin", "shadow", "main", "post", "end")
_STAGE_INDEX = {stage: index for index, stage in enumerate(STAGE_ORDER)}


class GpuTimestampError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _is_number(value):
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return False
    try:
        return math.isfinite(value)
    except (OverflowError, TypeError):
        return False


class GpuTimestamp:
    """Frame-scoped GPU timestamp queries with unrolling of 48-bit tick wraps."""

    def __init__(self, *, query_pool_size=64, max_frames_in_flight=3, wrap_bits=48):
        self.query_pool_size = query_pool_size
        self.max_frames_in_flight = max_frames_in_flight
        self.wrap_bits = wrap_bits

        self._lock = threading.RLock()
        self._ticks_per_ns = 1.0
        self._active = {}
        self._ended = {}
        self._used_slots = set()

    def _require_frame_id(self, frame_id):
        if not _is_int(frame_id):
            raise GpuTimestampError("GTS_UNKNOWN_FRAME")

    def _require_live_frame(self, frame_id):
        self._require_frame_id(frame_id)
        frame = self._active.get(frame_id)
        if frame is not None:
            return frame
        if frame_id in self._ended:
            raise GpuTimestampError("GTS_FRAME_CLOSED")
        raise GpuTimestampError("GTS_UNKNOWN_FRAME")

    @staticmethod
    def _clone(value):
        return copy.deepcopy(value)

    def _ticks_to_ns(self, ticks):
        if ticks == 0:
            return 0
        if self._ticks_per_ns == 1.0:
            return int(ticks)
        value = ticks / self._ticks_per_ns
        if value >= 0:
            return int(math.floor(value + 0.5))
        return int(math.ceil(value - 0.5))

    def _build_stats(self, frame, completed):
        stages = list(frame["stages"])
        durations_ns = {}
        gpu_ns = 0

        if completed and stages:
            ticks = frame["logical_ticks"]
            durations_ns[stages[0]] = 0
            for index in range(1, len(stages)):
                delta = ticks[index] - ticks[index - 1]
                durations_ns[stages[index]] = self._ticks_to_ns(delta)
            gpu_ns = self._ticks_to_ns(ticks[-1] - ticks[0])

        return {
            "frame": frame["frame"],
            "queue": frame["queue"],
            "slot": frame["slot"],
            "completed": bool(completed),
            "stages": stages,
            "durations_ns": durations_ns,
            "gpu_ns": gpu_ns,
            "wrap_count": frame["wrap_count"],
        }

    def begin_frame(self, frame_id, *, queue="graphics"):
        with self._lock:
            self._require_frame_id(frame_id)
            if frame_id in self._active:
                raise GpuTimestampError("GTS_DUP_FRAME")
            if frame_id in self._ended:
                raise GpuTimestampError("GTS_FRAME_CLOSED")
            if len(self._active) >= self.max_frames_in_flight:
                raise GpuTimestampError("GTS_FRAME_BUSY")

            slot = None
            for candidate in range(self.query_pool_size):
                if candidate not in self._used_slots:
                    slot = candidate
                    break
            if slot is None:
                raise GpuTimestampError("GTS_POOL_EXHAUSTED")

            self._used_slots.add(slot)
            self._active[frame_id] = {
                "frame": frame_id,
                "queue": queue,
                "slot": slot,
                "stages": [],
                "raw_ticks": [],
                "logical_ticks": [],
                "wrap_count": 0,
                "wrap_offset": 0,
            }
            return {"frame": frame_id, "slot": slot, "queue": queue}

    def write_timestamp(self, frame_id, stage, ticks):
        with self._lock:
            frame = self._require_live_frame(frame_id)
            if not isinstance(stage, str) or stage not in _STAGE_INDEX:
                raise GpuTimestampError("GTS_UNKNOWN_STAGE")
            if not _is_int(ticks):
                raise GpuTimestampError("GTS_INVALID_TICKS")

            stages = frame["stages"]
            if stage in stages:
                raise GpuTimestampError("GTS_DUP_STAGE")

            stage_index = _STAGE_INDEX[stage]
            if not stages:
                if stage != "begin":
                    raise GpuTimestampError("GTS_STAGE_ORDER")
            elif stage_index <= _STAGE_INDEX[stages[-1]]:
                raise GpuTimestampError("GTS_STAGE_ORDER")

            offset = frame["wrap_offset"]
            wrap_count = frame["wrap_count"]
            if frame["raw_ticks"]:
                previous = frame["raw_ticks"][-1]
                if ticks < previous:
                    half_cycle = 1 << (self.wrap_bits - 1)
                    if previous >= half_cycle:
                        offset += 1 << self.wrap_bits
                        wrap_count += 1
                    else:
                        raise GpuTimestampError("GTS_TIME_REWIND")

            logical_ticks = ticks + offset
            frame["stages"].append(stage)
            frame["raw_ticks"].append(ticks)
            frame["logical_ticks"].append(logical_ticks)
            frame["wrap_offset"] = offset
            frame["wrap_count"] = wrap_count

            return {
                "frame": frame_id,
                "queue": frame["queue"],
                "stage": stage,
                "ticks": logical_ticks,
                "raw_ticks": ticks,
                "wrap_count": wrap_count,
            }

    def end_frame(self, frame_id, *, completed=True):
        with self._lock:
            self._require_frame_id(frame_id)
            frame = self._active.get(frame_id)
            if frame is None:
                if frame_id in self._ended:
                    raise GpuTimestampError("GTS_FRAME_CLOSED")
                raise GpuTimestampError("GTS_UNKNOWN_FRAME")

            stats = self._build_stats(frame, bool(completed))
            self._ended[frame_id] = stats
            del self._active[frame_id]
            self._used_slots.discard(frame["slot"])
            return self._clone(stats)

    def frame_stats(self, frame_id):
        with self._lock:
            self._require_frame_id(frame_id)
            frame = self._active.get(frame_id)
            if frame is not None:
                return self._build_stats(frame, False)
            stats = self._ended.get(frame_id)
            if stats is None:
                raise GpuTimestampError("GTS_UNKNOWN_FRAME")
            return self._clone(stats)

    def frames(self):
        with self._lock:
            return sorted(
                frame_id
                for frame_id, stats in self._ended.items()
                if stats["completed"]
            )

    def percentiles(self):
        with self._lock:
            samples = sorted(
                (
                    (stats["gpu_ns"], frame_id)
                    for frame_id, stats in self._ended.items()
                    if stats["completed"]
                ),
                key=lambda item: (item[0], item[1]),
            )
            values = [sample[0] for sample in samples]
            frame_ids = [sample[1] for sample in samples]
            count = len(values)

            def nearest_rank(percent):
                if count == 0:
                    return 0
                rank = int(math.ceil(percent / 100.0 * count))
                rank = max(1, min(count, rank))
                return values[rank - 1]

            return {
                "count": count,
                "p50": nearest_rank(50),
                "p95": nearest_rank(95),
                "p99": nearest_rank(99),
                "frames": frame_ids,
            }

    def calibrate(self, gpu_ticks, cpu_ns):
        with self._lock:
            if (
                not _is_number(gpu_ticks)
                or not _is_number(cpu_ns)
                or gpu_ticks <= 0
                or cpu_ns <= 0
            ):
                raise GpuTimestampError("GTS_CALIBRATION_INVALID")
            ticks_per_ns = float(gpu_ticks) / float(cpu_ns)
            if not math.isfinite(ticks_per_ns) or ticks_per_ns <= 0:
                raise GpuTimestampError("GTS_CALIBRATION_INVALID")
            self._ticks_per_ns = ticks_per_ns
            return {"ticks_per_ns": ticks_per_ns}

    def tick_rate(self):
        with self._lock:
            return self._ticks_per_ns

    def pool_usage(self):
        with self._lock:
            in_flight = len(self._active)
            return {
                "slots": self.query_pool_size,
                "in_flight": in_flight,
                "free": self.query_pool_size - in_flight,
            }

    def snapshot(self):
        with self._lock:
            return {
                "version": 1,
                "calibration": {"ticks_per_ns": self._ticks_per_ns},
                "frames": [
                    self._clone(self._ended[frame_id])
                    for frame_id in sorted(self._ended)
                    if self._ended[frame_id]["completed"]
                ],
            }

    def _parse_snapshot(self, state):
        if not isinstance(state, dict):
            raise GpuTimestampError("GTS_SNAPSHOT_INVALID")
        version = state.get("version")
        if not _is_int(version) or version != 1:
            raise GpuTimestampError("GTS_SNAPSHOT_INVALID")

        calibration = state.get("calibration")
        if not isinstance(calibration, dict):
            raise GpuTimestampError("GTS_SNAPSHOT_INVALID")
        ticks_per_ns = calibration.get("ticks_per_ns")
        if (
            not _is_number(ticks_per_ns)
            or ticks_per_ns <= 0
            or not math.isfinite(ticks_per_ns)
        ):
            raise GpuTimestampError("GTS_SNAPSHOT_INVALID")

        frames = state.get("frames")
        if not isinstance(frames, list):
            raise GpuTimestampError("GTS_SNAPSHOT_INVALID")

        restored = {}
        for item in frames:
            if not isinstance(item, dict):
                raise GpuTimestampError("GTS_SNAPSHOT_INVALID")
            if not {
                "frame",
                "queue",
                "slot",
                "completed",
                "stages",
                "durations_ns",
                "gpu_ns",
                "wrap_count",
            }.issubset(item):
                raise GpuTimestampError("GTS_SNAPSHOT_INVALID")
            frame_id = item.get("frame")
            if not _is_int(frame_id) or frame_id in restored:
                raise GpuTimestampError("GTS_SNAPSHOT_INVALID")

            slot = item.get("slot")
            completed = item.get("completed")
            stages = item.get("stages")
            durations_ns = item.get("durations_ns")
            gpu_ns = item.get("gpu_ns")
            wrap_count = item.get("wrap_count")

            if not _is_int(slot) or slot < 0:
                raise GpuTimestampError("GTS_SNAPSHOT_INVALID")
            if not isinstance(completed, bool):
                raise GpuTimestampError("GTS_SNAPSHOT_INVALID")
            if not isinstance(stages, list) or any(
                not isinstance(stage, str) or stage not in _STAGE_INDEX
                for stage in stages
            ):
                raise GpuTimestampError("GTS_SNAPSHOT_INVALID")
            if len(set(stages)) != len(stages):
                raise GpuTimestampError("GTS_SNAPSHOT_INVALID")
            if stages and stages[0] != "begin":
                raise GpuTimestampError("GTS_SNAPSHOT_INVALID")
            indices = [_STAGE_INDEX[stage] for stage in stages]
            if indices != sorted(set(indices)):
                raise GpuTimestampError("GTS_SNAPSHOT_INVALID")
            if not isinstance(durations_ns, dict) or any(
                not isinstance(stage, str)
                or stage not in _STAGE_INDEX
                or not _is_int(value)
                or value < 0
                for stage, value in durations_ns.items()
            ):
                raise GpuTimestampError("GTS_SNAPSHOT_INVALID")
            if not _is_int(gpu_ns) or gpu_ns < 0:
                raise GpuTimestampError("GTS_SNAPSHOT_INVALID")
            if not _is_int(wrap_count) or wrap_count < 0:
                raise GpuTimestampError("GTS_SNAPSHOT_INVALID")

            if completed:
                if set(durations_ns) != set(stages):
                    raise GpuTimestampError("GTS_SNAPSHOT_INVALID")
                if stages and durations_ns.get(stages[0]) != 0:
                    raise GpuTimestampError("GTS_SNAPSHOT_INVALID")
            elif durations_ns or gpu_ns != 0:
                raise GpuTimestampError("GTS_SNAPSHOT_INVALID")

            restored[frame_id] = self._clone(item)

        return restored, float(ticks_per_ns)

    def restore(self, state):
        with self._lock:
            restored, ticks_per_ns = self._parse_snapshot(state)
            restored = {
                frame_id: stats
                for frame_id, stats in restored.items()
                if stats["completed"]
            }
            self._ended = restored
            self._ticks_per_ns = ticks_per_ns
            self._active.clear()
            self._used_slots.clear()
            return {"restored": len(restored)}
