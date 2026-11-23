"""Lookahead peak limiter with linked stereo gain and snapshot support."""

import copy
import math
import threading
from collections import deque


_CONFIG_RANGES = {
    "sample_rate": (8000, 192000),
    "attack_ms": (0.1, 1000.0),
    "release_ms": (1.0, 5000.0),
    "lookahead_ms": (0.0, 50.0),
    "max_block_size": (1, 65536),
}
_CONFIG_KEYS = (
    "sample_rate",
    "ceiling_db",
    "attack_ms",
    "release_ms",
    "lookahead_ms",
    "max_block_size",
)
_CHANNELS = (0, 1)
_SAMPLE_LIMIT = 8.0
_MIN_DENOMINATOR = 1e-12


class DspLimiterError(ValueError):
    """Domain error carrying a stable error code and optional detail."""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class DspLimiter:
    """Lookahead peak limiter with linked stereo gain and snapshot support."""

    def __init__(self, *, sample_rate: int = 48000,
                 ceiling_db: float = -1.0, attack_ms: float = 5.0,
                 release_ms: float = 50.0, lookahead_ms: float = 2.0,
                 max_block_size: int = 4096) -> None:
        self._lock = threading.RLock()
        self._config = self._validate_full_config(
            {
                "sample_rate": sample_rate,
                "ceiling_db": ceiling_db,
                "attack_ms": attack_ms,
                "release_ms": release_ms,
                "lookahead_ms": lookahead_ms,
                "max_block_size": max_block_size,
            }
        )
        self._latency = self._latency_for(self._config)
        self._gains = {}
        self._delay = {}
        self._linked_gain = 1.0
        self._stats = {
            "blocks": 0,
            "frames": 0,
            "limited_samples": 0,
        }
        self._refresh_derived()

    def configure(self, **kwargs) -> dict:
        with self._lock:
            unknown = set(kwargs) - set(_CONFIG_KEYS)
            if unknown:
                raise DspLimiterError(
                    "DSP_CONFIG_RANGE", "unknown config: %s" % sorted(unknown)
                )

            updated = dict(self._config)
            for key in _CONFIG_KEYS:
                if key in kwargs:
                    updated[key] = self._validate_value(key, kwargs[key])

            old_latency = self._latency
            new_latency = self._latency_for(updated)
            self._config = updated
            self._latency = new_latency
            self._refresh_derived()
            if new_latency != old_latency:
                self._delay.clear()
            return copy.deepcopy(self._config)

    def ceiling(self) -> float:
        with self._lock:
            return float(10.0 ** (self._config["ceiling_db"] / 20.0))

    def latency_samples(self) -> int:
        with self._lock:
            return int(self._latency)

    def process_block(self, channel: int, samples: list[float]) -> dict:
        with self._lock:
            self._require_channel(channel)
            values = self._validated_samples(samples)

            gain = float(self._gains.get(channel, 1.0))
            line = self._delay.get(channel)
            if line is None:
                line = deque()
                self._delay[channel] = line

            output, peak_in, peak_out, limited, gain = (
                self._render_channel(values, line, gain)
            )
            self._gains[channel] = gain
            self._stats["blocks"] += 1
            self._stats["frames"] += len(values)
            self._stats["limited_samples"] += limited
            return {
                "channel": channel,
                "samples": len(values),
                "samples_out": output,
                "peak_in": peak_in,
                "peak_out": peak_out,
                "gain": gain,
                "gain_reduction_db": self._gain_reduction(gain),
                "limited_samples": limited,
            }

    def process_linked(self, channels: dict[int, list[float]]) -> dict:
        with self._lock:
            values, keys, frames = self._validated_linked(channels)

            lines = {}
            for channel in keys:
                line = self._delay.get(channel)
                if line is None:
                    line = deque()
                    self._delay[channel] = line
                lines[channel] = line

            gain = min(
                float(self._gains.get(channel, 1.0)) for channel in keys
            )

            output = {channel: [] for channel in keys}
            peak_in = 0.0
            peak_out = 0.0
            limited = 0
            latency = self._latency
            ceiling = self._ceiling_linear

            for index in range(frames):
                frame_peak = 0.0
                for channel in keys:
                    magnitude = abs(values[channel][index])
                    if magnitude > frame_peak:
                        frame_peak = magnitude
                if frame_peak > ceiling:
                    limited += 1
                if frame_peak > peak_in:
                    peak_in = frame_peak

                gain = self._advance_gain(gain, frame_peak)
                for channel in keys:
                    delayed = self._delay_sample(
                        lines[channel], values[channel][index], latency
                    )
                    rendered = delayed * gain
                    output[channel].append(rendered)
                    magnitude = abs(rendered)
                    if magnitude > peak_out:
                        peak_out = magnitude

            for channel in keys:
                self._gains[channel] = gain
            self._linked_gain = gain

            self._stats["blocks"] += 1
            self._stats["frames"] += frames
            self._stats["limited_samples"] += limited
            return {
                "channels": list(keys),
                "frames": frames,
                "samples_out": output,
                "peak_in": peak_in,
                "peak_out": peak_out,
                "gain": gain,
                "gain_reduction_db": self._gain_reduction(gain),
                "limited_samples": limited,
            }

    def gain_reduction_db(self) -> float:
        with self._lock:
            return self._gain_reduction(self._current_gain())

    def channel_gain(self, channel: int) -> float:
        with self._lock:
            self._require_channel(channel)
            return float(self._gains.get(channel, 1.0))

    def stats(self) -> dict:
        with self._lock:
            return {
                "blocks": int(self._stats["blocks"]),
                "frames": int(self._stats["frames"]),
                "limited_samples": int(self._stats["limited_samples"]),
                "gain_reduction_db": self._gain_reduction(
                    self._current_gain()
                ),
                "latency_samples": int(self._latency),
                "channels": len(self._gains),
            }

    def reset(self) -> None:
        with self._lock:
            self._gains.clear()
            self._delay.clear()
            self._linked_gain = 1.0
            self._stats = {
                "blocks": 0,
                "frames": 0,
                "limited_samples": 0,
            }

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "config": copy.deepcopy(self._config),
                "gains": {
                    channel: float(gain)
                    for channel, gain in sorted(self._gains.items())
                },
                "delay": {
                    channel: list(line)
                    for channel, line in sorted(self._delay.items())
                },
                "linked_gain": float(self._linked_gain),
                "stats": copy.deepcopy(self._stats),
            }

    def restore(self, snapshot: dict) -> None:
        with self._lock:
            if not isinstance(snapshot, dict):
                raise DspLimiterError(
                    "DSP_SNAPSHOT_INVALID", "snapshot must be a dict"
                )
            try:
                state = copy.deepcopy(snapshot)
                config_data = state["config"]
                gains_data = state.get("gains", {})
                delay_data = state.get("delay", {})
                linked_gain = float(state.get("linked_gain", 1.0))
                stats_data = state.get("stats", {})
                if not isinstance(config_data, dict):
                    raise TypeError("config must be a dict")
                if not isinstance(gains_data, dict):
                    raise TypeError("gains must be a dict")
                if not isinstance(delay_data, dict):
                    raise TypeError("delay must be a dict")
                if not isinstance(stats_data, dict):
                    raise TypeError("stats must be a dict")

                restored_config = self._validate_full_config(config_data)
                restored_gains = {}
                for raw_channel, raw_gain in gains_data.items():
                    channel = self._channel_from_snapshot(raw_channel)
                    gain = self._snapshot_number(raw_gain, "gain")
                    if gain < 0.0 or gain > 1.0:
                        raise DspLimiterError(
                            "DSP_SNAPSHOT_INVALID", "gain out of range"
                        )
                    restored_gains[channel] = gain

                restored_delay = {}
                for raw_channel, raw_line in delay_data.items():
                    channel = self._channel_from_snapshot(raw_channel)
                    if not isinstance(raw_line, (list, tuple)):
                        raise TypeError("delay line must be a list")
                    restored_delay[channel] = deque(
                        self._snapshot_number(value, "delay sample")
                        for value in raw_line
                    )

                if not math.isfinite(linked_gain) or not 0.0 <= linked_gain <= 1.0:
                    raise DspLimiterError(
                        "DSP_SNAPSHOT_INVALID", "linked gain out of range"
                    )

                restored_stats = {}
                for key in ("blocks", "frames", "limited_samples"):
                    value = stats_data.get(key, 0)
                    if isinstance(value, bool) or not isinstance(value, int):
                        raise TypeError("stats must be integers")
                    if value < 0:
                        raise DspLimiterError(
                            "DSP_SNAPSHOT_INVALID", "stats must be non-negative"
                        )
                    restored_stats[key] = value
            except DspLimiterError as exc:
                if exc.code == "DSP_SNAPSHOT_INVALID":
                    raise
                raise DspLimiterError(
                    "DSP_SNAPSHOT_INVALID", str(exc)
                ) from exc
            except (KeyError, TypeError, ValueError, OverflowError) as exc:
                raise DspLimiterError("DSP_SNAPSHOT_INVALID", str(exc)) from exc

            self._config = restored_config
            self._latency = self._latency_for(restored_config)
            self._refresh_derived()
            self._gains = restored_gains
            self._delay = restored_delay
            self._linked_gain = linked_gain
            self._stats = restored_stats

    def _refresh_derived(self):
        sample_rate = self._config["sample_rate"]
        self._ceiling_linear = 10.0 ** (self._config["ceiling_db"] / 20.0)
        self._attack_coefficient = math.exp(
            -1000.0 / (self._config["attack_ms"] * sample_rate)
        )
        self._release_coefficient = math.exp(
            -1000.0 / (self._config["release_ms"] * sample_rate)
        )

    def _current_gain(self):
        if self._gains:
            return min(float(value) for value in self._gains.values())
        return float(self._linked_gain)

    def _render_channel(self, values, line, gain):
        output = []
        peak_in = 0.0
        peak_out = 0.0
        limited = 0
        latency = self._latency
        ceiling = self._ceiling_linear

        for sample in values:
            magnitude = abs(sample)
            if magnitude > peak_in:
                peak_in = magnitude
            if magnitude > ceiling:
                limited += 1

            gain = self._advance_gain(gain, magnitude)
            delayed = self._delay_sample(line, sample, latency)
            rendered = delayed * gain
            output.append(rendered)
            rendered_magnitude = abs(rendered)
            if rendered_magnitude > peak_out:
                peak_out = rendered_magnitude

        return output, peak_in, peak_out, limited, gain

    def _advance_gain(self, gain, peak):
        target = min(
            1.0, self._ceiling_linear / max(peak, _MIN_DENOMINATOR)
        )
        if target < gain:
            coefficient = self._attack_coefficient
        else:
            coefficient = self._release_coefficient
        gain = target + (gain - target) * coefficient
        if gain < 0.0:
            return 0.0
        if gain > 1.0:
            return 1.0
        return gain

    @staticmethod
    def _delay_sample(line, sample, latency):
        if latency <= 0:
            return sample
        line.append(sample)
        if len(line) > latency:
            return line.popleft()
        return 0.0

    @staticmethod
    def _gain_reduction(gain):
        if gain >= 1.0:
            return 0.0
        if gain <= 0.0:
            return float("inf")
        return max(0.0, -20.0 * math.log10(gain))

    @staticmethod
    def _latency_for(config):
        return int(
            round(
                config["sample_rate"] * config["lookahead_ms"] / 1000.0
            )
        )

    def _validate_full_config(self, config):
        if not isinstance(config, dict):
            raise DspLimiterError("DSP_CONFIG_RANGE", "config must be a dict")
        missing = [key for key in _CONFIG_KEYS if key not in config]
        if missing:
            raise DspLimiterError(
                "DSP_CONFIG_RANGE", "missing config: %s" % missing
            )
        return {
            key: self._validate_value(key, config[key]) for key in _CONFIG_KEYS
        }

    @staticmethod
    def _validate_value(key, value):
        if key == "ceiling_db":
            number = DspLimiter._finite_number(value, "DSP_CEILING_RANGE")
            if number < -60.0 or number > 0.0:
                raise DspLimiterError(
                    "DSP_CEILING_RANGE", "ceiling_db out of range"
                )
            return float(number)

        number = DspLimiter._finite_number(value, "DSP_CONFIG_RANGE")
        low, high = _CONFIG_RANGES[key]
        if key in ("sample_rate", "max_block_size"):
            if not float(number).is_integer():
                raise DspLimiterError(
                    "DSP_CONFIG_RANGE", "%s must be an integer" % key
                )
            number = int(number)
        if number < low or number > high:
            raise DspLimiterError(
                "DSP_CONFIG_RANGE", "%s out of range" % key
            )
        if key in ("sample_rate", "max_block_size"):
            return int(number)
        return float(number)

    @staticmethod
    def _finite_number(value, code="DSP_CONFIG_RANGE"):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise DspLimiterError(code, "value must be numeric")
        try:
            number = float(value)
        except (TypeError, ValueError, OverflowError) as exc:
            raise DspLimiterError(code, "value must be finite") from exc
        if not math.isfinite(number):
            raise DspLimiterError(code, "value must be finite")
        return number

    @staticmethod
    def _require_channel(channel):
        if isinstance(channel, bool) or not isinstance(channel, int):
            raise DspLimiterError("DSP_CHANNEL_UNKNOWN", repr(channel))
        if channel not in _CHANNELS:
            raise DspLimiterError("DSP_CHANNEL_UNKNOWN", repr(channel))

    def _validated_samples(self, samples):
        try:
            length = len(samples)
        except (TypeError, AttributeError) as exc:
            raise DspLimiterError(
                "DSP_BLOCK_INVALID", "samples must be a sequence"
            ) from exc
        if length == 0:
            raise DspLimiterError("DSP_BLOCK_INVALID", "empty block")
        if length > self._config["max_block_size"]:
            raise DspLimiterError(
                "DSP_BUDGET_EXCEEDED", "block exceeds max_block_size"
            )
        values = [self._validated_sample(value) for value in samples]
        if len(values) != length:
            raise DspLimiterError("DSP_BLOCK_INVALID", "sample count changed")
        return values

    def _validated_linked(self, channels):
        if not isinstance(channels, dict):
            raise DspLimiterError("DSP_BLOCK_INVALID", "channels must be a dict")
        if not channels:
            raise DspLimiterError("DSP_BLOCK_INVALID", "empty linked block")

        keys = []
        for channel in channels:
            self._require_channel(channel)
            keys.append(channel)
        keys.sort()

        frames = None
        for channel in keys:
            try:
                length = len(channels[channel])
            except (TypeError, AttributeError) as exc:
                raise DspLimiterError(
                    "DSP_BLOCK_INVALID", "samples must be a sequence"
                ) from exc
            if length == 0:
                raise DspLimiterError("DSP_BLOCK_INVALID", "empty block")
            if frames is None:
                frames = length
            elif length != frames:
                raise DspLimiterError(
                    "DSP_BLOCK_INVALID", "channel lengths differ"
                )

        if frames > self._config["max_block_size"]:
            raise DspLimiterError(
                "DSP_BUDGET_EXCEEDED", "block exceeds max_block_size"
            )

        values = {
            channel: self._validated_samples(channels[channel])
            for channel in keys
        }
        return values, keys, frames

    @staticmethod
    def _validated_sample(value):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise DspLimiterError("DSP_BLOCK_INVALID", "sample is not numeric")
        try:
            number = float(value)
        except (TypeError, ValueError, OverflowError) as exc:
            raise DspLimiterError(
                "DSP_BLOCK_INVALID", "sample is invalid"
            ) from exc
        if not math.isfinite(number) or abs(number) > _SAMPLE_LIMIT:
            raise DspLimiterError("DSP_BLOCK_INVALID", "sample is invalid")
        return number

    @staticmethod
    def _channel_from_snapshot(value):
        if isinstance(value, str):
            try:
                value = int(value)
            except ValueError as exc:
                raise DspLimiterError(
                    "DSP_SNAPSHOT_INVALID", "bad channel key"
                ) from exc
        if isinstance(value, bool) or not isinstance(value, int):
            raise DspLimiterError("DSP_SNAPSHOT_INVALID", "bad channel key")
        if value not in _CHANNELS:
            raise DspLimiterError("DSP_SNAPSHOT_INVALID", "bad channel key")
        return value

    @staticmethod
    def _snapshot_number(value, label):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise DspLimiterError(
                "DSP_SNAPSHOT_INVALID", "%s is invalid" % label
            )
        number = float(value)
        if not math.isfinite(number):
            raise DspLimiterError(
                "DSP_SNAPSHOT_INVALID", "%s is invalid" % label
            )
        if label == "delay sample" and abs(number) > _SAMPLE_LIMIT:
            raise DspLimiterError(
                "DSP_SNAPSHOT_INVALID", "%s is invalid" % label
            )
        return number
