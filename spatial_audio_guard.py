"""Spatial audio panning guard (GSB Bugfix task)."""

import copy
import math
import threading


class SpatialAudioError(ValueError):
    """Domain error carrying a stable error code and optional detail."""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


def _as_position(position):
    x, y, z = position
    return [float(x), float(y), float(z)]


class SpatialAudio:
    """Listener/source registry, pan law and distance attenuation for 3D audio."""

    def __init__(self, *, max_sources: int = 64,
                 max_listeners: int = 4) -> None:
        self.max_sources = int(max_sources)
        self.max_listeners = int(max_listeners)
        self._listeners = {}
        self._sources = {}
        self._sequence = 0
        self._ref_distance = 1.0
        self._max_distance = 100.0
        self._stats = {
            "mix_calls": 0,
            "moves": 0,
            "evictions": 0,
            "listener_updates": 0,
        }
        self._lock = threading.RLock()

    @staticmethod
    def _listener_view(listener):
        return {
            "id": listener["id"],
            "position": list(listener["position"]),
            "yaw": listener["yaw"],
            "master_gain": listener["master_gain"],
        }

    @staticmethod
    def _source_view(source):
        velocity = source["velocity"]
        return {
            "id": source["id"],
            "position": list(source["position"]),
            "gain": source["gain"],
            "priority": source["priority"],
            "category": source["category"],
            "sequence": source["sequence"],
            "velocity": None if velocity is None else list(velocity),
        }

    def _pan_gains_locked(self, listener, source):
        dx = source["position"][0] - listener["position"][0]
        dy = source["position"][1] - listener["position"][1]
        dz = source["position"][2] - listener["position"][2]

        horizontal_distance = math.hypot(dx, dy)
        distance = math.sqrt(dx * dx + dy * dy + dz * dz)
        yaw = math.radians(listener["yaw"])
        cos_yaw = math.cos(yaw)
        sin_yaw = math.sin(yaw)

        right = -dx * sin_yaw - dy * cos_yaw
        denominator = max(horizontal_distance, 0.5)
        pan = max(-1.0, min(1.0, right / denominator))

        if distance >= self._max_distance:
            attenuation = 0.0
        else:
            attenuation = self._ref_distance / max(
                distance, self._ref_distance
            )

        if pan <= -1.0:
            left_factor, right_factor = 1.0, 0.0
        elif pan >= 1.0:
            left_factor, right_factor = 0.0, 1.0
        else:
            angle = (pan + 1.0) * math.pi / 4.0
            left_factor = math.cos(angle)
            right_factor = math.sin(angle)

        level = (
            attenuation
            * source["gain"]
            * listener["master_gain"]
        )
        gain_l = max(0.0, min(1.0, level * left_factor))
        gain_r = max(0.0, min(1.0, level * right_factor))
        return {
            "gain_l": gain_l,
            "gain_r": gain_r,
            "pan": pan,
            "distance": distance,
            "attenuation": attenuation,
        }

    def _get_listener_locked(self, listener_id):
        try:
            return self._listeners[listener_id]
        except KeyError:
            raise SpatialAudioError(
                "SPA_LISTENER_UNKNOWN", listener_id
            ) from None

    def _get_source_locked(self, source_id):
        try:
            return self._sources[source_id]
        except KeyError:
            raise SpatialAudioError(
                "SPA_SOURCE_UNKNOWN", source_id
            ) from None

    def _apply_move_locked(self, source_id, position, velocity, sequence):
        source = self._get_source_locked(source_id)
        if sequence is None:
            new_sequence = source["sequence"] + 1
        elif sequence <= source["sequence"]:
            return {
                "id": source_id,
                "status": "ignored",
                "code": "SPA_SEQUENCE_STALE",
                "sequence": source["sequence"],
                "position": list(source["position"]),
            }
        else:
            new_sequence = sequence

        source["position"] = list(position)
        if velocity is not None:
            source["velocity"] = list(velocity)
        source["sequence"] = new_sequence
        self._sequence = max(self._sequence, new_sequence)
        self._stats["moves"] += 1
        return {
            "id": source_id,
            "status": "applied",
            "sequence": new_sequence,
            "position": list(source["position"]),
            "velocity": (
                None if source["velocity"] is None
                else list(source["velocity"])
            ),
        }

    def add_listener(self, listener_id: str, *, position: tuple[
            float, float, float] = (0.0, 0.0, 0.0), yaw: float = 0.0,
            master_gain: float = 1.0) -> dict:
        with self._lock:
            if listener_id in self._listeners:
                raise SpatialAudioError(
                    "SPA_LISTENER_EXISTS", listener_id
                )
            if len(self._listeners) >= self.max_listeners:
                raise SpatialAudioError(
                    "SPA_LISTENER_LIMIT", listener_id
                )
            listener = {
                "id": listener_id,
                "position": _as_position(position),
                "yaw": float(yaw),
                "master_gain": float(master_gain),
            }
            self._listeners[listener_id] = listener
            return self._listener_view(listener)

    def remove_listener(self, listener_id: str) -> bool:
        with self._lock:
            return self._listeners.pop(listener_id, None) is not None

    def update_listener(self, listener_id: str, *, position=None, yaw=None,
                        master_gain=None) -> dict:
        with self._lock:
            listener = self._get_listener_locked(listener_id)
            if position is not None:
                listener["position"] = _as_position(position)
            if yaw is not None:
                listener["yaw"] = float(yaw)
            if master_gain is not None:
                listener["master_gain"] = float(master_gain)
            self._stats["listener_updates"] += 1
            return self._listener_view(listener)

    def add_source(self, source_id: str, *, position=(
            0.0, 0.0, 0.0), gain: float = 1.0, priority: int = 0,
            category: str = "sfx") -> dict:
        with self._lock:
            if source_id in self._sources:
                raise SpatialAudioError(
                    "SPA_SOURCE_EXISTS", source_id
                )

            if len(self._sources) >= self.max_sources:
                if not self._sources:
                    raise SpatialAudioError(
                        "SPA_SOURCE_LIMIT", source_id
                    )
                lowest_priority = min(
                    source["priority"]
                    for source in self._sources.values()
                )
                if priority <= lowest_priority:
                    raise SpatialAudioError(
                        "SPA_SOURCE_LIMIT", source_id
                    )
                evicted = next(
                    existing_id
                    for existing_id, source in self._sources.items()
                    if source["priority"] == lowest_priority
                )
                del self._sources[evicted]
                self._stats["evictions"] += 1
            else:
                evicted = None

            source = {
                "id": source_id,
                "position": _as_position(position),
                "gain": float(gain),
                "priority": priority,
                "category": category,
                "sequence": 0,
                "velocity": None,
            }
            self._sources[source_id] = source
            result = self._source_view(source)
            result["evicted"] = evicted
            return result

    def remove_source(self, source_id: str) -> bool:
        with self._lock:
            return self._sources.pop(source_id, None) is not None

    def move_source(self, source_id: str, position, *, velocity=None,
                    sequence: int | None = None) -> dict:
        with self._lock:
            return self._apply_move_locked(
                source_id,
                _as_position(position),
                None if velocity is None else _as_position(velocity),
                sequence,
            )

    def move_batch(self, updates: list[dict]) -> list[dict]:
        with self._lock:
            normalized = []
            for update in updates:
                source_id = update.get(
                    "source", update.get("source_id", update.get("id"))
                )
                if source_id not in self._sources:
                    raise SpatialAudioError(
                        "SPA_SOURCE_UNKNOWN", source_id
                    )
                normalized.append((
                    source_id,
                    _as_position(update["position"]),
                    (
                        None if update.get("velocity") is None
                        else _as_position(update["velocity"])
                    ),
                    update.get("sequence"),
                ))

            return [
                self._apply_move_locked(*update)
                for update in normalized
            ]

    def pan_gains(self, listener_id: str, source_id: str) -> dict:
        with self._lock:
            listener = self._get_listener_locked(listener_id)
            source = self._get_source_locked(source_id)
            return self._pan_gains_locked(listener, source)

    def mix(self, listener_id: str) -> dict:
        with self._lock:
            self._stats["mix_calls"] += 1
            listener = self._get_listener_locked(listener_id)
            rows = []
            total_left = 0.0
            total_right = 0.0
            for source_id, source in self._sources.items():
                gains = self._pan_gains_locked(listener, source)
                row = {"id": source_id}
                row.update(gains)
                rows.append(row)
                total_left += gains["gain_l"]
                total_right += gains["gain_r"]
            return {
                "count": len(rows),
                "gain_l": total_left,
                "gain_r": total_right,
                "sources": rows,
            }

    def set_environment(self, *, ref_distance: float = 1.0,
                        max_distance: float = 100.0) -> dict:
        with self._lock:
            self._ref_distance = float(ref_distance)
            self._max_distance = float(max_distance)
            return {
                "ref_distance": self._ref_distance,
                "max_distance": self._max_distance,
            }

    def sources(self) -> list[dict]:
        with self._lock:
            return [
                self._source_view(source)
                for source in self._sources.values()
            ]

    def listeners(self) -> list[dict]:
        with self._lock:
            return [
                self._listener_view(listener)
                for listener in self._listeners.values()
            ]

    def stats(self) -> dict:
        with self._lock:
            return {
                "sources": len(self._sources),
                "listeners": len(self._listeners),
                "max_sources": self.max_sources,
                "max_listeners": self.max_listeners,
                "mix_calls": self._stats["mix_calls"],
                "moves": self._stats["moves"],
                "evictions": self._stats["evictions"],
                "listener_updates": self._stats["listener_updates"],
            }

    def snapshot(self) -> dict:
        with self._lock:
            snapshot = {
                "version": 1,
                "max_sources": self.max_sources,
                "max_listeners": self.max_listeners,
                "sequence": self._sequence,
                "environment": {
                    "ref_distance": self._ref_distance,
                    "max_distance": self._max_distance,
                },
                "listeners": [
                    self._listener_view(listener)
                    for listener in self._listeners.values()
                ],
                "sources": [
                    self._source_view(source)
                    for source in self._sources.values()
                ],
                "stats": dict(self._stats),
            }
            return copy.deepcopy(snapshot)

    def restore(self, snapshot: dict) -> None:
        with self._lock:
            data = copy.deepcopy(snapshot)
            listeners = {}
            for item in data.get("listeners", []):
                listener_id = item["id"]
                listeners[listener_id] = {
                    "id": listener_id,
                    "position": _as_position(
                        item.get("position", (0.0, 0.0, 0.0))
                    ),
                    "yaw": float(item.get("yaw", 0.0)),
                    "master_gain": float(item.get("master_gain", 1.0)),
                }

            sources = {}
            maximum_sequence = int(data.get("sequence", 0))
            for item in data.get("sources", []):
                source_id = item["id"]
                velocity = item.get("velocity")
                source_sequence = int(item.get("sequence", 0))
                sources[source_id] = {
                    "id": source_id,
                    "position": _as_position(
                        item.get("position", (0.0, 0.0, 0.0))
                    ),
                    "gain": float(item.get("gain", 1.0)),
                    "priority": item.get("priority", 0),
                    "category": item.get("category", "sfx"),
                    "sequence": source_sequence,
                    "velocity": (
                        None if velocity is None
                        else _as_position(velocity)
                    ),
                }
                maximum_sequence = max(maximum_sequence, source_sequence)

            environment = data.get("environment", {})
            ref_distance = float(environment.get("ref_distance", 1.0))
            max_distance = float(environment.get("max_distance", 100.0))
            stats = data.get("stats", {})
            restored_stats = {
                "mix_calls": int(stats.get("mix_calls", 0)),
                "moves": int(stats.get("moves", 0)),
                "evictions": int(stats.get("evictions", 0)),
                "listener_updates": int(
                    stats.get("listener_updates", 0)
                ),
            }

            if "max_sources" in data:
                self.max_sources = int(data["max_sources"])
            if "max_listeners" in data:
                self.max_listeners = int(data["max_listeners"])
            self._listeners = listeners
            self._sources = sources
            self._sequence = maximum_sequence
            self._ref_distance = ref_distance
            self._max_distance = max_distance
            self._stats = restored_stats
