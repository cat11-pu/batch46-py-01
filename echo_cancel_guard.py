"""Echo cancellation reference guard (GSB Bugfix task)."""

from __future__ import annotations

import math
import threading
from collections import deque


class EchoCancelError(ValueError):
    """Domain error carrying a stable error code and optional detail."""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class _Session:
    """Per-session ring buffer, capture block, delay and counters."""

    def __init__(self, session_id, sample_rate, filter_len,
                 max_delay_samples, delay_samples):
        self.session_id = session_id
        self.sample_rate = sample_rate
        self.max_delay_samples = max_delay_samples
        self.delay = delay_samples
        self.reference = deque(maxlen=filter_len)
        self.capture = []
        self.pushed_samples = 0
        self.dropped_samples = 0
        self.underruns = 0
        self.captures = 0
        self.alignments = 0


class EchoCancel:
    """Reference ring buffer, delay alignment and double-talk detection."""

    def __init__(self, *, max_sessions: int = 8,
                 max_push_samples: int = 4096, filter_len: int = 512,
                 max_delay_ms: float = 50.0):
        self._config = {
            "max_sessions": max_sessions,
            "max_push_samples": max_push_samples,
            "filter_len": filter_len,
            "max_delay_ms": max_delay_ms,
        }
        self._sessions = {}
        self._lock = threading.RLock()

    def _get_session(self, session_id):
        session = self._sessions.get(session_id)
        if session is None:
            raise EchoCancelError("ECH_SESSION_UNKNOWN", session_id)
        return session

    def _validate_samples(self, samples):
        if not isinstance(samples, list) or not samples:
            raise EchoCancelError("ECH_SAMPLES_INVALID")
        for sample in samples:
            if not isinstance(sample, (int, float)) or math.isnan(sample):
                raise EchoCancelError("ECH_SAMPLES_INVALID")
        if len(samples) > self._config["max_push_samples"]:
            raise EchoCancelError("ECH_BUDGET_EXCEEDED", len(samples))

    def create_session(self, session_id: str, *, sample_rate: int = 16000,
                       delay_hint_ms: float = 0.0) -> dict:
        if not isinstance(sample_rate, int) or isinstance(sample_rate, bool):
            raise EchoCancelError("ECH_SAMPLE_RATE_INVALID", sample_rate)
        if sample_rate < 8000 or sample_rate > 192000:
            raise EchoCancelError("ECH_SAMPLE_RATE_INVALID", sample_rate)
        max_delay_samples = round(
            sample_rate * self._config["max_delay_ms"] / 1000.0)
        delay_samples = round(sample_rate * delay_hint_ms / 1000.0)
        with self._lock:
            if session_id in self._sessions:
                raise EchoCancelError("ECH_SESSION_EXISTS", session_id)
            if len(self._sessions) >= self._config["max_sessions"]:
                raise EchoCancelError("ECH_SESSION_LIMIT")
            session = _Session(
                session_id, sample_rate, self._config["filter_len"],
                max_delay_samples, delay_samples)
            self._sessions[session_id] = session
            return {
                "session_id": session_id,
                "sample_rate": sample_rate,
                "delay_samples": delay_samples,
                "max_delay_samples": max_delay_samples,
            }

    def close_session(self, session_id: str) -> bool:
        with self._lock:
            if session_id not in self._sessions:
                return False
            del self._sessions[session_id]
            return True

    def sessions(self) -> list:
        with self._lock:
            return list(self._sessions.keys())

    def push_reference(self, session_id: str, samples: list) -> dict:
        self._validate_samples(samples)
        with self._lock:
            session = self._get_session(session_id)
            incoming = len(samples)
            buffered_before = len(session.reference)
            session.reference.extend(samples)
            dropped = max(
                0, buffered_before + incoming - self._config["filter_len"])
            session.dropped_samples += dropped
            session.pushed_samples += incoming
            return {
                "buffered": len(session.reference),
                "dropped": dropped,
                "total_dropped": session.dropped_samples,
                "pushed": session.pushed_samples,
            }

    def reference(self, session_id: str, length: int | None = None) -> list:
        with self._lock:
            session = self._get_session(session_id)
            values = list(session.reference)
            if length is None:
                return values
            return values[-length:]

    def push_capture(self, session_id: str, samples: list) -> dict:
        self._validate_samples(samples)
        with self._lock:
            session = self._get_session(session_id)
            buffered_ref = len(session.reference)
            underrun = buffered_ref == 0
            if underrun:
                session.underruns += 1
            session.capture = list(samples)
            session.captures += 1
            return {
                "underrun": underrun,
                "buffered_ref": buffered_ref,
                "captured": len(samples),
            }

    @staticmethod
    def _normalized_score(capture, window):
        size = len(capture)
        capture_mean = sum(capture) / size
        centered_capture = [value - capture_mean for value in capture]
        capture_norm = math.sqrt(
            sum(value * value for value in centered_capture))
        if capture_norm == 0.0:
            return 0.0
        window_mean = sum(window) / size
        centered_window = [value - window_mean for value in window]
        window_norm = math.sqrt(
            sum(value * value for value in centered_window))
        if window_norm == 0.0:
            return 0.0
        numerator = sum(
            left * right
            for left, right in zip(centered_capture, centered_window))
        return numerator / (capture_norm * window_norm)

    def align(self, session_id: str) -> dict:
        with self._lock:
            session = self._get_session(session_id)
            reference = list(session.reference)
            capture = session.capture
            if (not reference or len(capture) < 4
                    or len(reference) < len(capture)):
                return {
                    "aligned": False,
                    "delay": session.delay,
                    "score": 0.0,
                    "candidates": 0,
                }
            upper = min(
                session.max_delay_samples, len(reference) - len(capture))
            size = len(capture)
            tail = len(reference)
            best_delay = 0
            best_score = -math.inf
            for delay in range(upper + 1):
                start = tail - size - delay
                score = self._normalized_score(
                    capture, reference[start:start + size])
                if score > best_score:
                    best_score = score
                    best_delay = delay
            candidates = upper + 1
            if best_score >= 0.5:
                session.delay = best_delay
                session.alignments += 1
                return {
                    "aligned": True,
                    "delay": best_delay,
                    "score": best_score,
                    "candidates": candidates,
                }
            return {
                "aligned": False,
                "delay": session.delay,
                "score": best_score,
                "candidates": candidates,
            }

    def set_delay(self, session_id: str, delay_samples: int) -> dict:
        if (not isinstance(delay_samples, int)
                or isinstance(delay_samples, bool)):
            raise EchoCancelError("ECH_DELAY_RANGE", delay_samples)
        with self._lock:
            session = self._get_session(session_id)
            if delay_samples < 0 or delay_samples > session.max_delay_samples:
                raise EchoCancelError("ECH_DELAY_RANGE", delay_samples)
            session.delay = delay_samples
            return {
                "delay_samples": session.delay,
                "max_delay_samples": session.max_delay_samples,
            }

    def delay_samples(self, session_id: str) -> int:
        with self._lock:
            return self._get_session(session_id).delay

    @staticmethod
    def _rms(values):
        return math.sqrt(sum(value * value for value in values) / len(values))

    def double_talk(self, session_id: str) -> bool:
        with self._lock:
            session = self._get_session(session_id)
            if not session.capture or not session.reference:
                return False
            capture_rms = self._rms(session.capture)
            reference_rms = self._rms(session.reference)
            return capture_rms > 2.0 * reference_rms

    def reference_level_db(self, session_id: str) -> float:
        with self._lock:
            session = self._get_session(session_id)
            if not session.reference:
                return -180.0
            rms = self._rms(session.reference)
            if rms <= 0.0:
                return -180.0
            return 20.0 * math.log10(rms)

    def flush(self, session_id: str) -> dict:
        with self._lock:
            session = self._get_session(session_id)
            flushed = len(session.reference)
            session.reference.clear()
            session.capture = []
            return {"flushed": flushed, "buffered": 0}

    def stats(self, session_id: str) -> dict:
        with self._lock:
            session = self._get_session(session_id)
            return {
                "sample_rate": session.sample_rate,
                "buffered": len(session.reference),
                "captures": session.captures,
                "pushed_samples": session.pushed_samples,
                "dropped_samples": session.dropped_samples,
                "underruns": session.underruns,
                "alignments": session.alignments,
                "delay_samples": session.delay,
                "max_delay_samples": session.max_delay_samples,
            }

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "config": dict(self._config),
                "sessions": {
                    session_id: {
                        "sample_rate": session.sample_rate,
                        "max_delay_samples": session.max_delay_samples,
                        "delay_samples": session.delay,
                        "reference": list(session.reference),
                        "capture": list(session.capture),
                        "pushed_samples": session.pushed_samples,
                        "dropped_samples": session.dropped_samples,
                        "underruns": session.underruns,
                        "captures": session.captures,
                        "alignments": session.alignments,
                    }
                    for session_id, session in self._sessions.items()
                },
            }

    def restore(self, snapshot: dict) -> None:
        with self._lock:
            config = dict(snapshot["config"])
            self._config = config
            restored = {}
            for session_id, state in snapshot["sessions"].items():
                session = _Session(
                    session_id,
                    state["sample_rate"],
                    config["filter_len"],
                    state["max_delay_samples"],
                    state["delay_samples"])
                session.reference.extend(state["reference"])
                session.capture = list(state["capture"])
                session.pushed_samples = state["pushed_samples"]
                session.dropped_samples = state["dropped_samples"]
                session.underruns = state["underruns"]
                session.captures = state["captures"]
                session.alignments = state["alignments"]
                restored[session_id] = session
            self._sessions = restored
