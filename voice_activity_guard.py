"""Energy based voice activity detection guard.

The :class:`VoiceActivity` state machine drives realtime calls, meeting
transcription and live clipping pipelines.  Every public operation is guarded
by a re-entrant lock so multi thread callers see atomic state transitions.
"""

import copy
import math
import threading


SILENCE_ENERGY_DB = -180.0


class VoiceActivityError(ValueError):
    """Domain error carrying a stable error code and optional detail."""

    def __init__(self, code: str, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class VoiceActivity:
    """Energy based VAD with hangover, calibration, segments and snapshots."""

    def __init__(self, *, max_streams: int = 32, frame_ms: int = 20,
                 threshold_db: float = -35.0, hangover_ms: int = 200,
                 min_speech_ms: int = 60, margin_db: float = 9.0):
        self._config = {
            "max_streams": max_streams,
            "frame_ms": frame_ms,
            "threshold_db": threshold_db,
            "hangover_ms": hangover_ms,
            "min_speech_ms": min_speech_ms,
            "margin_db": margin_db,
        }
        self._streams: dict[str, dict] = {}
        self._stats = {
            "frames": 0,
            "speech_frames": 0,
            "segments": 0,
            "discarded": 0,
        }
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # stream lifecycle
    # ------------------------------------------------------------------
    def create_stream(self, stream_id: str, *, sample_rate: int = 16000) -> dict:
        with self._lock:
            if stream_id in self._streams:
                raise VoiceActivityError("VAD_STREAM_EXISTS", stream_id)
            if len(self._streams) >= self._config["max_streams"]:
                raise VoiceActivityError("VAD_STREAM_LIMIT", stream_id)
            frame_size = sample_rate * self._config["frame_ms"] // 1000
            self._streams[stream_id] = {
                "sample_rate": sample_rate,
                "frame_size": frame_size,
                "threshold_db": float(self._config["threshold_db"]),
                "noise_floor_db": None,
                "index": -1,
                "state": "silence",
                "hangover_left": 0,
                "candidate": None,
                "active": None,
                "segments": [],
                "next_segment_id": 1,
            }
            return {
                "stream_id": stream_id,
                "sample_rate": sample_rate,
                "frame_size": frame_size,
            }

    def drop_stream(self, stream_id: str) -> bool:
        with self._lock:
            if stream_id not in self._streams:
                return False
            del self._streams[stream_id]
            return True

    def streams(self) -> list[str]:
        with self._lock:
            return list(self._streams.keys())

    def frame_size(self, stream_id: str) -> int:
        with self._lock:
            return self._stream(stream_id)["frame_size"]

    # ------------------------------------------------------------------
    # frame processing
    # ------------------------------------------------------------------
    def feed(self, stream_id: str, frame: list[float]) -> dict:
        with self._lock:
            stream = self._stream(stream_id)
            energy = self._validate_and_energy(stream, frame)
            return self._process_frame(stream, energy)

    def feed_batch(self, stream_id: str,
                   frames: list[list[float]]) -> list[dict]:
        with self._lock:
            stream = self._stream(stream_id)
            # Validate the whole batch first: a single bad frame must leave
            # every counter and the stream index untouched.
            energies = [
                self._validate_and_energy(stream, frame) for frame in frames
            ]
            return [self._process_frame(stream, energy) for energy in energies]

    def set_threshold(self, stream_id: str, threshold_db: float) -> dict:
        with self._lock:
            stream = self._stream(stream_id)
            if not (-90.0 <= float(threshold_db) <= 0.0):
                raise VoiceActivityError(
                    "VAD_THRESHOLD_RANGE", threshold_db)
            stream["threshold_db"] = float(threshold_db)
            stream["noise_floor_db"] = None
            return {
                "stream_id": stream_id,
                "threshold_db": stream["threshold_db"],
            }

    def calibrate(self, stream_id: str,
                  frames: list[list[float]]) -> dict:
        with self._lock:
            stream = self._stream(stream_id)
            energies = [
                self._validate_and_energy(stream, frame) for frame in frames
            ]
            noise_floor = sum(energies) / len(energies)
            threshold = min(0.0, noise_floor + self._config["margin_db"])
            stream["noise_floor_db"] = noise_floor
            stream["threshold_db"] = threshold
            return {
                "stream_id": stream_id,
                "noise_floor_db": noise_floor,
                "threshold_db": threshold,
            }

    # ------------------------------------------------------------------
    # inspection and segment control
    # ------------------------------------------------------------------
    def state(self, stream_id: str) -> dict:
        with self._lock:
            stream = self._stream(stream_id)
            return self._state_view(stream)

    def segments(self, stream_id: str) -> list[dict]:
        with self._lock:
            stream = self._stream(stream_id)
            return copy.deepcopy(stream["segments"])

    def close_segment(self, stream_id: str) -> dict:
        with self._lock:
            stream = self._stream(stream_id)
            active = stream["active"]
            candidate = stream["candidate"]
            if active is not None:
                segment = self._finalize_active(stream)
            elif candidate is not None:
                self._discard_candidate(stream)
                segment = None
            else:
                segment = None
            stream["state"] = "silence"
            stream["hangover_left"] = 0
            return {
                "stream_id": stream_id,
                "closed": segment is not None,
                "segment": segment,
            }

    def stats(self) -> dict:
        with self._lock:
            stats = dict(self._stats)
            stats["streams"] = len(self._streams)
            stats["max_streams"] = self._config["max_streams"]
            return stats

    # ------------------------------------------------------------------
    # snapshot / restore
    # ------------------------------------------------------------------
    def snapshot(self) -> dict:
        with self._lock:
            return {
                "config": copy.deepcopy(self._config),
                "stats": copy.deepcopy(self._stats),
                "streams": copy.deepcopy(self._streams),
            }

    def restore(self, snapshot: dict) -> None:
        with self._lock:
            self._config = copy.deepcopy(snapshot["config"])
            self._stats = copy.deepcopy(snapshot["stats"])
            self._streams = copy.deepcopy(snapshot["streams"])

    # ------------------------------------------------------------------
    # internal helpers
    # ------------------------------------------------------------------
    def _stream(self, stream_id: str) -> dict:
        stream = self._streams.get(stream_id)
        if stream is None:
            raise VoiceActivityError("VAD_STREAM_UNKNOWN", stream_id)
        return stream

    def _hangover_frames(self) -> int:
        return math.ceil(self._config["hangover_ms"]
                         / self._config["frame_ms"])

    def _min_speech_frames(self) -> int:
        return math.ceil(self._config["min_speech_ms"]
                         / self._config["frame_ms"])

    @staticmethod
    def _energy(frame: list[float]) -> float:
        total = 0.0
        for sample in frame:
            total += sample * sample
        rms = math.sqrt(total / len(frame))
        if rms <= 0.0:
            return SILENCE_ENERGY_DB
        return 20.0 * math.log10(rms)

    def _validate_and_energy(self, stream: dict,
                             frame: list[float]) -> float:
        if len(frame) != stream["frame_size"]:
            raise VoiceActivityError(
                "VAD_FRAME_SIZE",
                {"expected": stream["frame_size"], "actual": len(frame)})
        for sample in frame:
            if isinstance(sample, bool) or not isinstance(sample, float) \
                    or not math.isfinite(sample) or abs(sample) > 1.0:
                raise VoiceActivityError("VAD_FRAME_INVALID", sample)
        return self._energy(frame)

    def _process_frame(self, stream: dict, energy: float) -> dict:
        stream["index"] += 1
        index = stream["index"]
        is_speech = energy > stream["threshold_db"]

        self._stats["frames"] += 1
        if is_speech:
            self._stats["speech_frames"] += 1

        if is_speech:
            if stream["state"] == "silence":
                stream["candidate"] = {
                    "start": index,
                    "end": index,
                    "frames": 1,
                    "speech_frames": 1,
                }
                stream["state"] = "speech"
                stream["hangover_left"] = 0
                self._maybe_confirm(stream)
            else:
                target = stream["active"] or stream["candidate"]
                target["end"] = index
                target["frames"] += 1
                target["speech_frames"] += 1
                if stream["state"] == "hangover":
                    stream["state"] = "speech"
                    stream["hangover_left"] = 0
                if stream["active"] is None:
                    self._maybe_confirm(stream)
        else:
            if stream["active"] is not None:
                active = stream["active"]
                if stream["state"] == "speech":
                    stream["state"] = "hangover"
                    stream["hangover_left"] = self._hangover_frames()
                    active["end"] = index
                    active["frames"] += 1
                else:
                    stream["hangover_left"] -= 1
                    if stream["hangover_left"] > 0:
                        active["end"] = index
                        active["frames"] += 1
                if stream["hangover_left"] <= 0:
                    self._finalize_active(stream)
                    stream["state"] = "silence"
                    stream["hangover_left"] = 0
            elif stream["candidate"] is not None:
                # A burst shorter than the minimum speech gate never
                # becomes a segment; count it as discarded right away.
                self._discard_candidate(stream)
                stream["state"] = "silence"
                stream["hangover_left"] = 0

        return {
            "index": index,
            "state": stream["state"],
            "speech": stream["state"] in ("speech", "hangover"),
            "energy_db": energy,
            "threshold_db": stream["threshold_db"],
            "noise_floor_db": stream["noise_floor_db"],
            "hangover_left": stream["hangover_left"],
            "segment": stream["active"]["id"] if stream["active"] else None,
        }

    def _maybe_confirm(self, stream: dict) -> None:
        candidate = stream["candidate"]
        if candidate is None or stream["active"] is not None:
            return
        if candidate["speech_frames"] < self._min_speech_frames():
            return
        candidate["id"] = stream["next_segment_id"]
        stream["next_segment_id"] += 1
        stream["active"] = candidate
        stream["candidate"] = None

    def _finalize_active(self, stream: dict) -> dict:
        active = stream["active"]
        segment = {
            "id": active["id"],
            "start": active["start"],
            "end": active["end"],
            "frames": active["frames"],
            "speech_frames": active["speech_frames"],
        }
        stream["segments"].append(segment)
        stream["active"] = None
        self._stats["segments"] += 1
        return copy.deepcopy(segment)

    def _discard_candidate(self, stream: dict) -> None:
        stream["candidate"] = None
        self._stats["discarded"] += 1

    def _state_view(self, stream: dict) -> dict:
        return {
            "index": stream["index"],
            "state": stream["state"],
            "speech": stream["state"] in ("speech", "hangover"),
            "threshold_db": stream["threshold_db"],
            "noise_floor_db": stream["noise_floor_db"],
            "hangover_left": stream["hangover_left"],
        }
