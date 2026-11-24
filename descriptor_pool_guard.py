import threading


class DescriptorPoolError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class DescriptorPool:
    """Per-frame descriptor arenas with per-type budgets and generation handles."""

    SNAPSHOT_VERSION = 4

    def __init__(self, *, max_sets=1024, budgets=None, max_frames_in_flight=2):
        self.max_sets = max_sets
        self.budgets = dict(budgets or {})
        self.max_frames_in_flight = max_frames_in_flight

        self._lock = threading.RLock()
        self._layouts = {}
        self._frames = {}
        self._sets = {}
        self._used = {descriptor_type: 0 for descriptor_type in self.budgets}
        self._stats = {
            "allocations": 0,
            "frees": 0,
            "retires": 0,
            "failures": 0,
            "high_water_sets": 0,
            "high_water_types": {
                descriptor_type: 0 for descriptor_type in self.budgets
            },
        }

    @staticmethod
    def _is_int(value):
        return isinstance(value, int) and not isinstance(value, bool)

    def _fail(self, code, detail=None):
        self._stats["failures"] += 1
        raise DescriptorPoolError(code, detail)

    def _active_frames(self):
        return sum(
            1
            for frame in self._frames.values()
            if frame["status"] == "recording"
        )

    def _copy_counts(self, counts):
        return {descriptor_type: count for descriptor_type, count in counts.items()}

    def _reclaim_frame(self, frame_id):
        frame = self._frames[frame_id]
        reclaimed = []
        for set_id in list(frame["sets"]):
            record = self._sets.pop(set_id, None)
            if record is None:
                continue
            reclaimed.append(set_id)
            for descriptor_type, count in record["counts"].items():
                self._used[descriptor_type] -= count
        frame["sets"].clear()
        return reclaimed

    def _usage(self):
        sets = len(self._sets)
        return {
            "sets": sets,
            "free_sets": self.max_sets - sets,
            "types": {
                descriptor_type: self._used.get(descriptor_type, 0)
                for descriptor_type in self.budgets
            },
            "frames": self._active_frames(),
        }

    def define_layout(self, layout_id, *, counts):
        with self._lock:
            if not isinstance(layout_id, str) or not layout_id:
                self._fail("DSC_LAYOUT_INVALID", {"layout": layout_id})
            if layout_id in self._layouts:
                self._fail("DSC_DUP_LAYOUT", {"layout": layout_id})
            if not isinstance(counts, dict) or not counts:
                self._fail("DSC_LAYOUT_INVALID", {"layout": layout_id})

            normalized = {}
            for descriptor_type, count in counts.items():
                if not isinstance(descriptor_type, str) or descriptor_type not in self.budgets:
                    self._fail("DSC_UNKNOWN_TYPE", {"type": descriptor_type})
                if not self._is_int(count) or count <= 0:
                    self._fail(
                        "DSC_LAYOUT_INVALID",
                        {"layout": layout_id, "type": descriptor_type},
                    )
                normalized[descriptor_type] = count

            self._layouts[layout_id] = normalized
            return {"layout": layout_id, "counts": self._copy_counts(normalized)}

    def begin_frame(self, frame_id):
        with self._lock:
            frame = self._frames.get(frame_id)
            if frame is not None and frame["status"] == "recording":
                self._fail("DSC_DUP_FRAME", {"frame": frame_id})

            active = self._active_frames()
            if active >= self.max_frames_in_flight:
                self._fail(
                    "DSC_FRAME_IN_FLIGHT",
                    {"frame": frame_id, "active": active},
                )

            if frame is None:
                frame = {"generation": 1, "status": "recording", "sets": {}}
                self._frames[frame_id] = frame
            else:
                frame["generation"] += 1
                frame["status"] = "recording"
                frame["sets"].clear()

            return {
                "frame": frame_id,
                "generation": frame["generation"],
                "active": active + 1,
            }

    def allocate(self, frame, set_id, layout):
        with self._lock:
            frame_record = self._frames.get(frame)
            if frame_record is None:
                self._fail("DSC_FRAME_UNKNOWN", {"frame": frame})
            if frame_record["status"] != "recording":
                self._fail("DSC_NO_ARENA", {"frame": frame})

            layout_counts = self._layouts.get(layout)
            if layout_counts is None:
                self._fail("DSC_UNKNOWN_LAYOUT", {"layout": layout})

            if set_id in self._sets:
                self._fail("DSC_DUP_SET", {"set_id": set_id})

            if len(self._sets) >= self.max_sets:
                self._fail(
                    "DSC_POOL_EXHAUSTED",
                    {
                        "kind": "sets",
                        "limit": self.max_sets,
                        "used": len(self._sets),
                    },
                )

            for descriptor_type, count in layout_counts.items():
                used = self._used.get(descriptor_type, 0)
                budget = self.budgets[descriptor_type]
                if used + count > budget:
                    self._fail(
                        "DSC_POOL_EXHAUSTED",
                        {
                            "kind": "type",
                            "type": descriptor_type,
                            "limit": budget,
                            "used": used,
                            "requested": count,
                        },
                    )

            counts = self._copy_counts(layout_counts)
            generation = frame_record["generation"]
            for descriptor_type, count in counts.items():
                self._used[descriptor_type] = (
                    self._used.get(descriptor_type, 0) + count
                )
            self._sets[set_id] = {
                "frame": frame,
                "layout": layout,
                "generation": generation,
                "counts": counts,
            }
            frame_record["sets"][set_id] = None

            self._stats["allocations"] += 1
            self._stats["high_water_sets"] = max(
                self._stats["high_water_sets"], len(self._sets)
            )
            for descriptor_type in self.budgets:
                self._stats["high_water_types"][descriptor_type] = max(
                    self._stats["high_water_types"].get(descriptor_type, 0),
                    self._used.get(descriptor_type, 0),
                )

            return {
                "set_id": set_id,
                "frame": frame,
                "layout": layout,
                "counts": self._copy_counts(counts),
                "generation": generation,
                "sets": len(self._sets),
            }

    def free(self, set_id):
        with self._lock:
            record = self._sets.get(set_id)
            if record is None:
                self._fail("DSC_SET_INVALID", {"set_id": set_id})

            frame_id = record["frame"]
            frame = self._frames[frame_id]
            del self._sets[set_id]
            frame["sets"].pop(set_id, None)
            for descriptor_type, count in record["counts"].items():
                self._used[descriptor_type] -= count
            self._stats["frees"] += 1

            return {
                "set_id": set_id,
                "frame": frame_id,
                "layout": record["layout"],
                "generation": record["generation"],
                "counts": self._copy_counts(record["counts"]),
                "freed": self._copy_counts(record["counts"]),
                "sets": len(self._sets),
            }

    def retire_frame(self, frame):
        with self._lock:
            frame_record = self._frames.get(frame)
            if frame_record is None:
                self._fail("DSC_FRAME_UNKNOWN", {"frame": frame})
            if frame_record["status"] != "recording":
                self._fail("DSC_FRAME_RETIRED", {"frame": frame})

            reclaimed = self._reclaim_frame(frame)
            frame_record["status"] = "retired"
            self._stats["retires"] += 1
            return {
                "frame": frame,
                "generation": frame_record["generation"],
                "reclaimed": reclaimed,
            }

    def reset_frame(self, frame):
        with self._lock:
            frame_record = self._frames.get(frame)
            if frame_record is None:
                self._fail("DSC_FRAME_UNKNOWN", {"frame": frame})
            if frame_record["status"] == "recording":
                self._fail("DSC_FRAME_IN_FLIGHT", {"frame": frame})

            reclaimed = self._reclaim_frame(frame)
            return {
                "frame": frame,
                "generation": frame_record["generation"],
                "reclaimed": reclaimed,
            }

    def set_of(self, set_id):
        with self._lock:
            record = self._sets.get(set_id)
            if record is None:
                self._fail("DSC_SET_INVALID", {"set_id": set_id})
            return {
                "set_id": set_id,
                "frame": record["frame"],
                "layout": record["layout"],
                "generation": record["generation"],
                "counts": self._copy_counts(record["counts"]),
            }

    def generation_of(self, set_id):
        with self._lock:
            record = self._sets.get(set_id)
            if record is None:
                self._fail("DSC_SET_INVALID", {"set_id": set_id})
            return record["generation"]

    def usage(self):
        with self._lock:
            return self._usage()

    def stats(self):
        with self._lock:
            return {
                "allocations": self._stats["allocations"],
                "frees": self._stats["frees"],
                "retires": self._stats["retires"],
                "failures": self._stats["failures"],
                "high_water_sets": self._stats["high_water_sets"],
                "high_water_types": dict(self._stats["high_water_types"]),
            }

    def snapshot(self):
        with self._lock:
            return {
                "version": self.SNAPSHOT_VERSION,
                "config": {
                    "max_sets": self.max_sets,
                    "budgets": dict(self.budgets),
                    "max_frames_in_flight": self.max_frames_in_flight,
                },
                "layouts": {
                    layout_id: self._copy_counts(counts)
                    for layout_id, counts in self._layouts.items()
                },
                "frames": {
                    frame_id: {
                        "frame": frame_id,
                        "generation": frame["generation"],
                        "status": frame["status"],
                    }
                    for frame_id, frame in self._frames.items()
                },
                "sets": {
                    set_id: {
                        "frame": record["frame"],
                        "layout": record["layout"],
                        "generation": record["generation"],
                        "counts": self._copy_counts(record["counts"]),
                    }
                    for set_id, record in self._sets.items()
                },
                "used": dict(self._used),
                "usage": self._usage(),
                "stats": {
                    "allocations": self._stats["allocations"],
                    "frees": self._stats["frees"],
                    "retires": self._stats["retires"],
                    "failures": self._stats["failures"],
                    "high_water_sets": self._stats["high_water_sets"],
                    "high_water_types": dict(
                        self._stats["high_water_types"]
                    ),
                },
            }

    def _restore_invalid(self, detail=None):
        self._fail("DSC_SNAPSHOT_INVALID", detail)

    def _coerce_frame_key(self, key):
        if isinstance(key, str):
            try:
                converted = int(key)
            except ValueError:
                return key
            if str(converted) == key:
                return converted
        return key

    def restore(self, state):
        with self._lock:
            if not isinstance(state, dict):
                self._restore_invalid({"reason": "state"})
            if state.get("version") != self.SNAPSHOT_VERSION:
                self._restore_invalid({"reason": "version"})

            config = state.get("config")
            if not isinstance(config, dict):
                self._restore_invalid({"reason": "config"})

            max_sets = config.get("max_sets")
            budgets = config.get("budgets")
            max_frames_in_flight = config.get("max_frames_in_flight")
            if (
                not self._is_int(max_sets)
                or max_sets < 0
                or not self._is_int(max_frames_in_flight)
                or max_frames_in_flight < 0
                or not isinstance(budgets, dict)
            ):
                self._restore_invalid({"reason": "config"})

            restored_budgets = {}
            for descriptor_type, budget in budgets.items():
                if (
                    not isinstance(descriptor_type, str)
                    or not descriptor_type
                    or not self._is_int(budget)
                    or budget < 0
                ):
                    self._restore_invalid({"reason": "budgets"})
                restored_budgets[descriptor_type] = budget

            layouts = state.get("layouts")
            if not isinstance(layouts, dict):
                self._restore_invalid({"reason": "layouts"})
            restored_layouts = {}
            for layout_id, counts in layouts.items():
                if not isinstance(layout_id, str) or not layout_id:
                    self._restore_invalid({"reason": "layout"})
                if not isinstance(counts, dict) or not counts:
                    self._restore_invalid({"reason": "layout"})
                restored_counts = {}
                for descriptor_type, count in counts.items():
                    if (
                        not isinstance(descriptor_type, str)
                        or descriptor_type not in restored_budgets
                        or not self._is_int(count)
                        or count <= 0
                    ):
                        self._restore_invalid({"reason": "layout"})
                    restored_counts[descriptor_type] = count
                restored_layouts[layout_id] = restored_counts

            raw_frames = state.get("frames")
            if not isinstance(raw_frames, dict):
                self._restore_invalid({"reason": "frames"})
            restored_frames = {}
            active_frames = 0
            for key, raw_frame in raw_frames.items():
                if not isinstance(raw_frame, dict):
                    self._restore_invalid({"reason": "frame"})
                frame_id = raw_frame.get("frame", self._coerce_frame_key(key))
                generation = raw_frame.get("generation")
                status = raw_frame.get("status")
                if (
                    not isinstance(frame_id, (int, str))
                    or isinstance(frame_id, bool)
                    or frame_id in restored_frames
                    or not self._is_int(generation)
                    or generation <= 0
                    or status not in ("recording", "retired")
                ):
                    self._restore_invalid({"reason": "frame"})
                restored_frames[frame_id] = {
                    "generation": generation,
                    "status": status,
                    "sets": {},
                }
                if status == "recording":
                    active_frames += 1

            if active_frames > max_frames_in_flight:
                self._restore_invalid({"reason": "frames"})

            raw_sets = state.get("sets")
            if not isinstance(raw_sets, dict):
                self._restore_invalid({"reason": "sets"})
            restored_sets = {}
            restored_used = {descriptor_type: 0 for descriptor_type in restored_budgets}
            for set_id, raw_set in raw_sets.items():
                if (
                    not isinstance(set_id, str)
                    or not set_id
                    or not isinstance(raw_set, dict)
                ):
                    self._restore_invalid({"reason": "set"})
                frame_id = raw_set.get("frame")
                layout_id = raw_set.get("layout")
                generation = raw_set.get("generation")
                counts = raw_set.get("counts")
                if (
                    not isinstance(frame_id, (int, str))
                    or isinstance(frame_id, bool)
                    or not isinstance(layout_id, str)
                    or frame_id not in restored_frames
                    or layout_id not in restored_layouts
                ):
                    self._restore_invalid({"reason": "set"})
                frame = restored_frames[frame_id]
                if frame["status"] != "recording":
                    self._restore_invalid({"reason": "set"})
                if not self._is_int(generation) or generation != frame["generation"]:
                    self._restore_invalid({"reason": "generation"})
                if not isinstance(counts, dict) or not counts:
                    self._restore_invalid({"reason": "counts"})
                for descriptor_type, count in counts.items():
                    if (
                        not isinstance(descriptor_type, str)
                        or not self._is_int(count)
                        or count <= 0
                    ):
                        self._restore_invalid({"reason": "counts"})
                if counts != restored_layouts[layout_id]:
                    self._restore_invalid({"reason": "counts"})
                if set_id in restored_sets or set_id in frame["sets"]:
                    self._restore_invalid({"reason": "set"})

                restored_set_counts = dict(counts)
                restored_sets[set_id] = {
                    "frame": frame_id,
                    "layout": layout_id,
                    "generation": generation,
                    "counts": restored_set_counts,
                }
                frame["sets"][set_id] = None
                for descriptor_type, count in restored_set_counts.items():
                    restored_used[descriptor_type] += count

            if len(restored_sets) > max_sets:
                self._restore_invalid({"reason": "sets"})
            for descriptor_type, count in restored_used.items():
                if count > restored_budgets[descriptor_type]:
                    self._restore_invalid({"reason": "types"})

            recorded_used = state.get("used")
            if not isinstance(recorded_used, dict):
                self._restore_invalid({"reason": "used"})
            if set(recorded_used) != set(restored_used):
                self._restore_invalid({"reason": "used"})
            for descriptor_type, count in recorded_used.items():
                if not self._is_int(count) or count < 0:
                    self._restore_invalid({"reason": "used"})
            if recorded_used != restored_used:
                self._restore_invalid({"reason": "used"})

            expected_usage = {
                "sets": len(restored_sets),
                "free_sets": max_sets - len(restored_sets),
                "types": dict(restored_used),
                "frames": active_frames,
            }
            if state.get("usage") != expected_usage:
                self._restore_invalid({"reason": "usage"})

            raw_stats = state.get("stats")
            if not isinstance(raw_stats, dict):
                self._restore_invalid({"reason": "stats"})
            stat_names = (
                "allocations",
                "frees",
                "retires",
                "failures",
                "high_water_sets",
            )
            if set(raw_stats) != set(stat_names) | {"high_water_types"}:
                self._restore_invalid({"reason": "stats"})
            restored_stats = {}
            for name in stat_names:
                value = raw_stats.get(name)
                if not self._is_int(value) or value < 0:
                    self._restore_invalid({"reason": "stats"})
                restored_stats[name] = value
            raw_high_water_types = raw_stats.get("high_water_types")
            if not isinstance(raw_high_water_types, dict):
                self._restore_invalid({"reason": "stats"})
            if set(raw_high_water_types) != set(restored_budgets):
                self._restore_invalid({"reason": "stats"})
            high_water_types = {}
            for descriptor_type in restored_budgets:
                value = raw_high_water_types[descriptor_type]
                if not self._is_int(value) or value < 0:
                    self._restore_invalid({"reason": "stats"})
                high_water_types[descriptor_type] = value
            restored_stats["high_water_types"] = high_water_types
            if restored_stats["high_water_sets"] < len(restored_sets):
                self._restore_invalid({"reason": "stats"})
            for descriptor_type, count in restored_used.items():
                if high_water_types[descriptor_type] < count:
                    self._restore_invalid({"reason": "stats"})

            self.max_sets = max_sets
            self.budgets = restored_budgets
            self.max_frames_in_flight = max_frames_in_flight
            self._layouts = restored_layouts
            self._frames = restored_frames
            self._sets = restored_sets
            self._used = restored_used
            self._stats = restored_stats

            return {
                "restored": len(restored_sets),
                "frames": active_frames,
            }
