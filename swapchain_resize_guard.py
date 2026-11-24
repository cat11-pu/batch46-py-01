import copy
import threading


PRESENT_MODES = ("fifo", "immediate", "mailbox")
CAUSES = ("resize", "format", "present", "resume")


class SwapchainResizeError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class SwapchainResize:
    """Debounced swapchain rebuild with generation, retire and budget control."""

    def __init__(
        self,
        *,
        width=1280,
        height=720,
        format="bgra8",
        present="fifo",
        min_images=2,
        max_images=3,
        max_retained=2,
        debounce_frames=2,
        max_bytes=None,
    ):
        self._lock = threading.RLock()

        if not isinstance(min_images, int) or min_images < 1:
            raise ValueError("min_images must be a positive integer")
        if not isinstance(max_images, int) or max_images < min_images:
            raise ValueError("max_images must be at least min_images")
        if not isinstance(max_retained, int) or max_retained < 0:
            raise ValueError("max_retained must be a non-negative integer")
        if not isinstance(debounce_frames, int) or debounce_frames < 0:
            raise ValueError("debounce_frames must be a non-negative integer")
        if max_bytes is not None and (
            not isinstance(max_bytes, int) or max_bytes < 0
        ):
            raise ValueError("max_bytes must be a non-negative integer or None")

        self.min_images = min_images
        self.max_images = max_images
        self.max_retained = max_retained
        self.debounce_frames = debounce_frames
        self.max_bytes = max_bytes

        self._validate_size(width, height)
        if width == 0 and height == 0:
            raise ValueError("initial surface cannot be minimized")
        self._validate_present(present)

        self._width = width
        self._height = height
        self._format = format
        self._present = present
        self._images = self._image_count(present)
        self._generation = 1
        self._suspended = False
        self._in_flight = 0
        self._next_image = 0

        self._pending = None
        self._pending_frames = set()
        self._pending_polls = 0
        self._pending_last_frame = None
        self._resume_pending = False
        self._minimized = False

        self._retained = []
        self._retired_all = []
        self._retired_set = set()
        self._destroyed_history = []

        self._history = []
        self._generation_data = {
            1: self._generation_info_locked(
                self._generation,
                self._width,
                self._height,
                self._format,
                self._present,
                self._images,
            )
        }
        self._stats = {
            "rebuilds": 0,
            "presents": 0,
            "stale_presents": 0,
            "retired": 0,
            "destroyed": 0,
            "suspends": 0,
            "resumes": 0,
            "budget_rejections": 0,
        }

    # ------------------------------------------------------------------
    # Validation and small helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _validate_size(width, height):
        if (
            not isinstance(width, int)
            or isinstance(width, bool)
            or not isinstance(height, int)
            or isinstance(height, bool)
            or width < 0
            or height < 0
            or (width == 0) != (height == 0)
        ):
            raise SwapchainResizeError(
                "SWR_SIZE_INVALID", {"width": width, "height": height}
            )

    @staticmethod
    def _validate_present(present):
        if present not in PRESENT_MODES:
            raise SwapchainResizeError(
                "SWR_PRESENT_INVALID", {"present": present}
            )

    def _image_count(self, present):
        self._validate_present(present)
        if present == "mailbox":
            return min(self.min_images + 1, self.max_images)
        return self.min_images

    def _desired_locked(self, width, height, format, present):
        # An omitted field describes the currently committed surface.
        if format is None:
            format = self._format
        if present is None:
            present = self._present
        self._validate_present(present)
        return {
            "width": width,
            "height": height,
            "format": format,
            "present": present,
        }

    def _current_locked(self):
        return {
            "width": self._width,
            "height": self._height,
            "format": self._format,
            "present": self._present,
        }

    def _reset_debounce_locked(self, frame):
        self._pending_frames = {frame}
        self._pending_polls = 0
        self._pending_last_frame = frame

    def _set_pending_locked(self, desired, frame):
        self._pending = dict(desired)
        self._reset_debounce_locked(frame)

    def _clear_pending_locked(self):
        self._pending = None
        self._pending_frames = set()
        self._pending_polls = 0
        self._pending_last_frame = None

    def _stable_locked(self):
        required = max(0, self.debounce_frames)
        if required == 0:
            return True
        # A frame value is a timestamp. Counting distinct frames makes a
        # burst of resize notifications debounce correctly, while the poll
        # counter still supports callers which leave frame at its default.
        return (
            len(self._pending_frames) >= required
            or self._pending_polls >= required
        )

    @staticmethod
    def _generation_info_locked(
        generation, width, height, format, present, images
    ):
        return {
            "generation": generation,
            "width": width,
            "height": height,
            "format": format,
            "present": present,
            "images": images,
            "required_bytes": width * height * images * 4,
        }

    def _suspend_locked(self, minimized=None):
        if minimized is None:
            minimized = self._minimized or (
                self._pending is not None
                and self._pending["width"] == 0
                and self._pending["height"] == 0
            )
        if not self._suspended:
            self._suspended = True
            self._stats["suspends"] += 1
        self._clear_pending_locked()
        self._resume_pending = False
        self._in_flight = 0
        self._next_image = 0
        self._minimized = bool(minimized)

    def _config_locked(self):
        return {
            "width": self._width,
            "height": self._height,
            "format": self._format,
            "present": self._present,
            "images": self._images,
            "generation": self._generation,
            "suspended": self._suspended,
            "in_flight": self._in_flight,
        }

    def _history_locked(self):
        return [dict(row) for row in self._history]

    # ------------------------------------------------------------------
    # Surface observation and debounced polling
    # ------------------------------------------------------------------
    def observe(self, width, height, *, format=None, present=None, frame=0):
        with self._lock:
            self._validate_size(width, height)
            desired = self._desired_locked(width, height, format, present)

            if width == 0 and height == 0:
                self._minimized = True
                if self._suspended:
                    # Remaining minimized is idempotent: no extra suspend is
                    # counted and the surface is not resumed by observation.
                    if self._pending != desired:
                        self._set_pending_locked(desired, frame)
                    return {"action": "pending"}
                if self._pending != desired:
                    self._set_pending_locked(desired, frame)
                return {"action": "pending"}

            self._minimized = False

            if self._suspended:
                if self._pending != desired:
                    self._set_pending_locked(desired, frame)
                return {"action": "pending"}

            if self._pending is not None and desired == self._pending:
                return {"action": "pending"}

            if desired == self._current_locked() and not self._resume_pending:
                self._clear_pending_locked()
                return {"action": "none"}

            if desired == self._current_locked() and self._resume_pending:
                # Resume must always create a fresh chain, even if the
                # reported surface happens to equal the old one.
                if self._pending != desired:
                    self._set_pending_locked(desired, frame)
                return {"action": "pending"}

            self._set_pending_locked(desired, frame)
            return {"action": "pending"}

    def poll(self, frame=0):
        with self._lock:
            if self._suspended:
                if self._minimized:
                    return {"action": "suspend"}
                return {"action": "none"}

            if self._pending is None:
                return {"action": "none"}

            if (
                self._pending["width"] == 0
                and self._pending["height"] == 0
            ):
                # Minimization is not debounced; there is nothing to create.
                self._suspend_locked(minimized=True)
                return {"action": "suspend"}

            self._pending_polls += 1
            self._pending_frames.add(frame)
            self._pending_last_frame = frame

            if self._stable_locked():
                return {"action": "rebuild"}
            return {"action": "none"}

    def rebuild(self, frame=0):
        with self._lock:
            if self._suspended:
                raise SwapchainResizeError("SWR_SUSPENDED")

            if self._in_flight > 0:
                raise SwapchainResizeError(
                    "SWR_IN_FLIGHT", {"in_flight": self._in_flight}
                )

            if self._pending is None:
                raise SwapchainResizeError("SWR_NO_PENDING")

            if (
                self._pending["width"] == 0
                and self._pending["height"] == 0
            ):
                self._suspend_locked(minimized=True)
                raise SwapchainResizeError("SWR_SUSPENDED")

            if not self._stable_locked():
                raise SwapchainResizeError(
                    "SWR_DEBOUNCE_PENDING",
                    {
                        "polls": self._pending_polls,
                        "frames": len(self._pending_frames),
                        "required": max(0, self.debounce_frames),
                    },
                )

            pending = self._pending
            images = self._image_count(pending["present"])
            required = (
                pending["width"]
                * pending["height"]
                * images
                * 4
            )

            # Budget is checked before any observable state is changed.
            if self.max_bytes is not None and required > self.max_bytes:
                self._stats["budget_rejections"] += 1
                raise SwapchainResizeError(
                    "SWR_BUDGET_EXCEEDED",
                    {"required": required, "budget": self.max_bytes},
                )

            if self._resume_pending:
                cause = "resume"
            elif (
                pending["width"] != self._width
                or pending["height"] != self._height
            ):
                cause = "resize"
            elif pending["format"] != self._format:
                cause = "format"
            elif pending["present"] != self._present:
                cause = "present"
            else:
                cause = "resize"

            generation = self._generation + 1
            self._generation = generation
            self._width = pending["width"]
            self._height = pending["height"]
            self._format = pending["format"]
            self._present = pending["present"]
            self._images = images
            self._in_flight = 0
            self._next_image = 0
            self._minimized = False
            self._resume_pending = False
            self._clear_pending_locked()

            info = self._generation_info_locked(
                generation,
                self._width,
                self._height,
                self._format,
                self._present,
                self._images,
            )
            self._generation_data[generation] = info
            self._history.append(
                {
                    "generation": generation,
                    "cause": cause,
                    "required_bytes": required,
                    "frame": frame,
                }
            )
            self._stats["rebuilds"] += 1

            return {
                "action": "rebuild",
                "generation": generation,
                "width": self._width,
                "height": self._height,
                "format": self._format,
                "present": self._present,
                "images": self._images,
                "required_bytes": required,
                "cause": cause,
            }

    # ------------------------------------------------------------------
    # Image acquisition and presentation
    # ------------------------------------------------------------------
    def acquire(self, generation):
        with self._lock:
            if self._suspended:
                raise SwapchainResizeError("SWR_SUSPENDED")
            if self._resume_pending or generation != self._generation:
                raise SwapchainResizeError(
                    "SWR_STALE_SWAPCHAIN",
                    {
                        "generation": generation,
                        "current": self._generation,
                    },
                )

            image = self._next_image
            self._next_image = (self._next_image + 1) % self._images
            self._in_flight += 1
            return {
                "action": "acquire",
                "generation": self._generation,
                "image": image,
                "in_flight": self._in_flight,
            }

    def present(self, generation, frame=0):
        with self._lock:
            if self._suspended:
                raise SwapchainResizeError("SWR_SUSPENDED")
            if self._resume_pending or generation != self._generation:
                self._stats["stale_presents"] += 1
                raise SwapchainResizeError(
                    "SWR_STALE_SWAPCHAIN",
                    {
                        "generation": generation,
                        "current": self._generation,
                    },
                )
            if self._in_flight <= 0:
                raise SwapchainResizeError("SWR_NOT_ACQUIRED")

            self._in_flight -= 1
            self._stats["presents"] += 1
            return {
                "action": "present",
                "generation": self._generation,
                "presents": self._stats["presents"],
                "in_flight": self._in_flight,
            }

    # ------------------------------------------------------------------
    # Minimize / restore the swapchain itself
    # ------------------------------------------------------------------
    def suspend(self, frame=0):
        with self._lock:
            self._suspend_locked()
            return {"action": "suspend", "suspended": True}

    def resume(self, width, height, *, format=None, present=None, frame=0):
        with self._lock:
            if not self._suspended:
                raise SwapchainResizeError("SWR_NOT_SUSPENDED")
            self._validate_size(width, height)

            if format is None:
                format = self._format
            if present is None:
                present = self._present
            self._validate_present(present)

            desired = {
                "width": width,
                "height": height,
                "format": format,
                "present": present,
            }

            self._suspended = False
            self._minimized = width == 0 and height == 0
            self._resume_pending = True
            self._stats["resumes"] += 1
            self._in_flight = 0
            self._next_image = 0
            self._set_pending_locked(desired, frame)
            return {"action": "pending"}

    # ------------------------------------------------------------------
    # Generation retirement
    # ------------------------------------------------------------------
    def retire(self, generation):
        with self._lock:
            if generation == self._generation:
                raise SwapchainResizeError(
                    "SWR_CURRENT_GENERATION",
                    {"generation": generation},
                )
            if generation in self._retired_set:
                raise SwapchainResizeError(
                    "SWR_GENERATION_RETIRED",
                    {"generation": generation},
                )
            if (
                not isinstance(generation, int)
                or isinstance(generation, bool)
                or generation < 1
                or generation > self._generation
                or generation not in self._generation_data
            ):
                raise SwapchainResizeError(
                    "SWR_GENERATION_UNKNOWN",
                    {"generation": generation},
                )

            self._retired_set.add(generation)
            self._retired_all.append(generation)
            self._retained.append(generation)
            self._stats["retired"] += 1

            destroyed = []
            while len(self._retained) > self.max_retained:
                destroyed.append(self._retained.pop(0))
            if destroyed:
                self._destroyed_history.extend(destroyed)
                self._stats["destroyed"] += len(destroyed)

            return {
                "action": "retire",
                "generation": generation,
                "retained": list(self._retained),
                "destroyed": destroyed,
            }

    # ------------------------------------------------------------------
    # Read-only views
    # ------------------------------------------------------------------
    def config(self):
        with self._lock:
            return self._config_locked()

    def history(self):
        with self._lock:
            return self._history_locked()

    def stats(self):
        with self._lock:
            return dict(self._stats)

    def estimate_bytes(
        self, width=None, height=None, *, generation=None
    ):
        with self._lock:
            if generation is not None:
                if generation == self._generation:
                    info = self._generation_data[self._generation]
                else:
                    info = self._generation_data.get(generation)
                    if info is None:
                        row = next(
                            (
                                item
                                for item in self._history
                                if item["generation"] == generation
                            ),
                            None,
                        )
                        if row is None:
                            raise SwapchainResizeError(
                                "SWR_GENERATION_UNKNOWN",
                                {"generation": generation},
                            )
                        info = {
                            "width": None,
                            "height": None,
                            "images": self._images,
                            "required_bytes": row["required_bytes"],
                        }
                base_width = info["width"]
                base_height = info["height"]
                images = info["images"]
                if (
                    width is None
                    and height is None
                    and base_width is not None
                    and base_height is not None
                ):
                    return int(info["required_bytes"])
            else:
                base_width = self._width
                base_height = self._height
                images = self._images

            if width is None:
                width = base_width if base_width is not None else self._width
            if height is None:
                height = (
                    base_height if base_height is not None else self._height
                )
            if (
                not isinstance(width, int)
                or isinstance(width, bool)
                or not isinstance(height, int)
                or isinstance(height, bool)
                or width < 0
                or height < 0
            ):
                raise SwapchainResizeError(
                    "SWR_SIZE_INVALID", {"width": width, "height": height}
                )
            return int(width) * int(height) * int(images) * 4

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------
    def snapshot(self):
        with self._lock:
            config = self._config_locked()
            return {
                "version": 5,
                "settings": {
                    "min_images": self.min_images,
                    "max_images": self.max_images,
                    "max_retained": self.max_retained,
                    "debounce_frames": self.debounce_frames,
                    "max_bytes": self.max_bytes,
                },
                "config": config,
                "generation": config["generation"],
                "width": config["width"],
                "height": config["height"],
                "format": config["format"],
                "present": config["present"],
                "images": config["images"],
                "pending": copy.deepcopy(self._pending),
                "pending_frames": sorted(self._pending_frames),
                "pending_polls": self._pending_polls,
                "pending_last_frame": self._pending_last_frame,
                "resume_pending": self._resume_pending,
                "minimized": self._minimized,
                "next_image": self._next_image,
                "retained": list(self._retained),
                "retired": list(self._retired_all),
                "destroyed": list(self._destroyed_history),
                "history": self._history_locked(),
                "stats": dict(self._stats),
                "generation_data": copy.deepcopy(self._generation_data),
            }

    def restore(self, state):
        with self._lock:
            if not isinstance(state, dict) or state.get("version") != 5:
                raise SwapchainResizeError(
                    "SWR_SNAPSHOT_INVALID", {"reason": "version"}
                )

            try:
                result = self._validated_restore_state(state)
            except SwapchainResizeError:
                raise
            except (KeyError, TypeError, ValueError, AttributeError) as exc:
                raise SwapchainResizeError(
                    "SWR_SNAPSHOT_INVALID", {"reason": str(exc)}
                ) from exc

            # Commit only after the whole snapshot has been validated.
            self.min_images = result["settings"]["min_images"]
            self.max_images = result["settings"]["max_images"]
            self.max_retained = result["settings"]["max_retained"]
            self.debounce_frames = result["settings"]["debounce_frames"]
            self.max_bytes = result["settings"]["max_bytes"]

            config = result["config"]
            self._width = config["width"]
            self._height = config["height"]
            self._format = config["format"]
            self._present = config["present"]
            self._images = config["images"]
            self._generation = config["generation"]
            self._suspended = config["suspended"]
            self._in_flight = config["in_flight"]

            self._pending = result["pending"]
            self._pending_frames = result["pending_frames"]
            self._pending_polls = result["pending_polls"]
            self._pending_last_frame = result["pending_last_frame"]
            self._resume_pending = result["resume_pending"]
            self._minimized = result["minimized"]
            self._next_image = result["next_image"]

            self._retained = result["retained"]
            self._retired_all = result["retired"]
            self._retired_set = set(result["retired"])
            self._destroyed_history = result["destroyed"]

            self._history = result["history"]
            self._stats = result["stats"]
            self._generation_data = result["generation_data"]

            return {
                "restored": True,
                "generation": self._generation,
            }

    def _validated_restore_state(self, state):
        settings_state = state.get("settings")
        if settings_state is None:
            settings_state = {}
        if not isinstance(settings_state, dict):
            raise SwapchainResizeError(
                "SWR_SNAPSHOT_INVALID", {"reason": "settings"}
            )

        settings = {
            "min_images": settings_state.get(
                "min_images", state.get("min_images", self.min_images)
            ),
            "max_images": settings_state.get(
                "max_images", state.get("max_images", self.max_images)
            ),
            "max_retained": settings_state.get(
                "max_retained", state.get("max_retained", self.max_retained)
            ),
            "debounce_frames": settings_state.get(
                "debounce_frames",
                state.get("debounce_frames", self.debounce_frames),
            ),
            "max_bytes": settings_state.get(
                "max_bytes", state.get("max_bytes", self.max_bytes)
            ),
        }
        if (
            not isinstance(settings["min_images"], int)
            or isinstance(settings["min_images"], bool)
            or settings["min_images"] < 1
            or not isinstance(settings["max_images"], int)
            or isinstance(settings["max_images"], bool)
            or settings["max_images"] < settings["min_images"]
            or not isinstance(settings["max_retained"], int)
            or isinstance(settings["max_retained"], bool)
            or settings["max_retained"] < 0
            or not isinstance(settings["debounce_frames"], int)
            or isinstance(settings["debounce_frames"], bool)
            or settings["debounce_frames"] < 0
            or (
                settings["max_bytes"] is not None
                and (
                    not isinstance(settings["max_bytes"], int)
                    or isinstance(settings["max_bytes"], bool)
                    or settings["max_bytes"] < 0
                )
            )
        ):
            raise SwapchainResizeError(
                "SWR_SNAPSHOT_INVALID", {"reason": "settings"}
            )

        config = state.get("config")
        has_embedded_config = config is not None
        if config is None:
            config = state
        if not isinstance(config, dict):
            raise SwapchainResizeError(
                "SWR_SNAPSHOT_INVALID", {"reason": "config"}
            )

        width = config.get("width")
        height = config.get("height")
        format = config.get("format")
        present = config.get("present")
        images = config.get("images")
        generation = config.get("generation")
        suspended = config.get("suspended")
        in_flight = config.get("in_flight", 0)

        if has_embedded_config:
            for key in (
                "width",
                "height",
                "format",
                "present",
                "images",
                "generation",
            ):
                if key in state and state[key] != config.get(key):
                    raise SwapchainResizeError(
                        "SWR_SNAPSHOT_INVALID", {"reason": "config"}
                    )

        if (
            not isinstance(width, int)
            or isinstance(width, bool)
            or not isinstance(height, int)
            or isinstance(height, bool)
            or width <= 0
            or height <= 0
            or not isinstance(format, str)
            or present not in PRESENT_MODES
            or not isinstance(images, int)
            or isinstance(images, bool)
            or not isinstance(generation, int)
            or isinstance(generation, bool)
            or generation < 1
            or not isinstance(suspended, bool)
            or not isinstance(in_flight, int)
            or isinstance(in_flight, bool)
            or in_flight < 0
        ):
            raise SwapchainResizeError(
                "SWR_SNAPSHOT_INVALID", {"reason": "config"}
            )

        expected_images = (
            min(settings["min_images"] + 1, settings["max_images"])
            if present == "mailbox"
            else settings["min_images"]
        )
        if images != expected_images:
            raise SwapchainResizeError(
                "SWR_SNAPSHOT_INVALID", {"reason": "images"}
            )
        if suspended and in_flight != 0:
            raise SwapchainResizeError(
                "SWR_SNAPSHOT_INVALID", {"reason": "in_flight"}
            )

        history_state = state.get("history", [])
        if not isinstance(history_state, list):
            raise SwapchainResizeError(
                "SWR_SNAPSHOT_INVALID", {"reason": "history"}
            )
        history = []
        previous_generation = 0
        for row in history_state:
            if not isinstance(row, dict):
                raise SwapchainResizeError(
                    "SWR_SNAPSHOT_INVALID", {"reason": "history"}
                )
            row_generation = row.get("generation")
            cause = row.get("cause")
            row_required = row.get("required_bytes")
            row_frame = row.get("frame", 0)
            if (
                not isinstance(row_generation, int)
                or isinstance(row_generation, bool)
                or row_generation <= previous_generation
                or not isinstance(cause, str)
                or cause not in CAUSES
                or not isinstance(row_required, int)
                or isinstance(row_required, bool)
                or row_required < 0
                or not isinstance(row_frame, int)
                or isinstance(row_frame, bool)
            ):
                raise SwapchainResizeError(
                    "SWR_SNAPSHOT_INVALID", {"reason": "history"}
                )
            previous_generation = row_generation
            history.append(
                {
                    "generation": row_generation,
                    "cause": cause,
                    "required_bytes": row_required,
                    "frame": row_frame,
                }
            )

        if generation == 1:
            if history:
                raise SwapchainResizeError(
                    "SWR_SNAPSHOT_INVALID", {"reason": "generation"}
                )
        elif not history or history[-1]["generation"] != generation:
            raise SwapchainResizeError(
                "SWR_SNAPSHOT_INVALID", {"reason": "generation"}
            )

        default_stats = {
            "rebuilds": len(history),
            "presents": 0,
            "stale_presents": 0,
            "retired": 0,
            "destroyed": 0,
            "suspends": 0,
            "resumes": 0,
            "budget_rejections": 0,
        }
        stats_state = state.get("stats", {})
        if not isinstance(stats_state, dict):
            raise SwapchainResizeError(
                "SWR_SNAPSHOT_INVALID", {"reason": "stats"}
            )
        stats = dict(default_stats)
        for key, value in stats_state.items():
            if not isinstance(key, str):
                raise SwapchainResizeError(
                    "SWR_SNAPSHOT_INVALID", {"reason": "stats"}
                )
            if isinstance(value, int) and not isinstance(value, bool):
                if value < 0:
                    raise SwapchainResizeError(
                        "SWR_SNAPSHOT_INVALID", {"reason": "stats"}
                    )
            stats[key] = value
        for key, value in stats.items():
            if not isinstance(value, int) or isinstance(value, bool):
                raise SwapchainResizeError(
                    "SWR_SNAPSHOT_INVALID", {"reason": "stats"}
                )
        if stats["rebuilds"] != len(history):
            raise SwapchainResizeError(
                "SWR_SNAPSHOT_INVALID", {"reason": "rebuilds"}
            )

        pending = copy.deepcopy(state.get("pending"))
        if pending is not None:
            if not isinstance(pending, dict):
                raise SwapchainResizeError(
                    "SWR_SNAPSHOT_INVALID", {"reason": "pending"}
                )
            pending_width = pending.get("width")
            pending_height = pending.get("height")
            pending_format = pending.get("format")
            pending_present = pending.get("present")
            if (
                not isinstance(pending_width, int)
                or isinstance(pending_width, bool)
                or not isinstance(pending_height, int)
                or isinstance(pending_height, bool)
                or pending_width < 0
                or pending_height < 0
                or (pending_width == 0) != (pending_height == 0)
                or not isinstance(pending_format, str)
                or pending_present not in PRESENT_MODES
            ):
                raise SwapchainResizeError(
                    "SWR_SNAPSHOT_INVALID", {"reason": "pending"}
                )
            pending = {
                "width": pending_width,
                "height": pending_height,
                "format": pending_format,
                "present": pending_present,
            }

        pending_frames_state = state.get("pending_frames", [])
        if not isinstance(pending_frames_state, (list, tuple, set)):
            raise SwapchainResizeError(
                "SWR_SNAPSHOT_INVALID", {"reason": "pending_frames"}
            )
        pending_frames = set()
        for frame in pending_frames_state:
            if not isinstance(frame, int) or isinstance(frame, bool):
                raise SwapchainResizeError(
                    "SWR_SNAPSHOT_INVALID", {"reason": "pending_frames"}
                )
            pending_frames.add(frame)

        pending_polls = state.get("pending_polls", 0)
        pending_last_frame = state.get("pending_last_frame")
        next_image = state.get("next_image", 0)
        if (
            not isinstance(pending_polls, int)
            or isinstance(pending_polls, bool)
            or pending_polls < 0
            or (
                pending_last_frame is not None
                and (
                    not isinstance(pending_last_frame, int)
                    or isinstance(pending_last_frame, bool)
                )
            )
            or not isinstance(next_image, int)
            or isinstance(next_image, bool)
            or next_image < 0
            or next_image >= images
        ):
            raise SwapchainResizeError(
                "SWR_SNAPSHOT_INVALID", {"reason": "pending"}
            )
        if pending is not None and not pending_frames:
            pending_frames = {0}
            if pending_last_frame is None:
                pending_last_frame = 0

        resume_pending = state.get("resume_pending", False)
        minimized = state.get("minimized", False)
        if not isinstance(resume_pending, bool) or not isinstance(
            minimized, bool
        ):
            raise SwapchainResizeError(
                "SWR_SNAPSHOT_INVALID", {"reason": "flags"}
            )

        retired = state.get("retired", state.get("retired_all", []))
        retained = state.get("retained", [])
        destroyed = state.get("destroyed", [])
        if (
            not isinstance(retired, list)
            or not isinstance(retained, list)
            or not isinstance(destroyed, list)
        ):
            raise SwapchainResizeError(
                "SWR_SNAPSHOT_INVALID", {"reason": "retired"}
            )
        retired = list(retired)
        retained = list(retained)
        destroyed = list(destroyed)
        for values in (retired, retained, destroyed):
            for item in values:
                if not isinstance(item, int) or isinstance(item, bool):
                    raise SwapchainResizeError(
                        "SWR_SNAPSHOT_INVALID", {"reason": "retired"}
                    )
        if len(set(retired)) != len(retired):
            raise SwapchainResizeError(
                "SWR_SNAPSHOT_INVALID", {"reason": "retired"}
            )
        if len(set(retained)) != len(retained):
            raise SwapchainResizeError(
                "SWR_SNAPSHOT_INVALID", {"reason": "retained"}
            )
        retired_set = set(retired)
        for item in retained:
            if item not in retired_set:
                raise SwapchainResizeError(
                    "SWR_SNAPSHOT_INVALID", {"reason": "retained"}
                )
        if not retired and (retained or destroyed):
            retired = [
                item
                for item in retained
                if item not in destroyed
            ] + list(destroyed)
            retired_set = set(retired)
        for item in retired:
            if item < 1 or item >= generation:
                raise SwapchainResizeError(
                    "SWR_SNAPSHOT_INVALID", {"reason": "retired"}
                )
        positions = {item: index for index, item in enumerate(retired)}
        if [positions[item] for item in retained] != sorted(
            positions[item] for item in retained
        ):
            raise SwapchainResizeError(
                "SWR_SNAPSHOT_INVALID", {"reason": "retained"}
            )
        if len(retained) > settings["max_retained"]:
            raise SwapchainResizeError(
                "SWR_SNAPSHOT_INVALID", {"reason": "retained"}
            )
        if stats["retired"] != len(retired):
            raise SwapchainResizeError(
                "SWR_SNAPSHOT_INVALID", {"reason": "retired_stats"}
            )
        if stats["destroyed"] != len(destroyed):
            raise SwapchainResizeError(
                "SWR_SNAPSHOT_INVALID", {"reason": "destroyed_stats"}
            )

        generation_data = {}
        data_state = state.get("generation_data", {})
        if not isinstance(data_state, dict):
            raise SwapchainResizeError(
                "SWR_SNAPSHOT_INVALID", {"reason": "generation_data"}
            )
        for key, info in data_state.items():
            try:
                key = int(key)
            except (TypeError, ValueError) as exc:
                raise SwapchainResizeError(
                    "SWR_SNAPSHOT_INVALID",
                    {"reason": "generation_data"},
                ) from exc
            if key < 1 or key > generation or not isinstance(info, dict):
                raise SwapchainResizeError(
                    "SWR_SNAPSHOT_INVALID",
                    {"reason": "generation_data"},
                )
            generation_data[key] = copy.deepcopy(info)

        for index in range(1, generation + 1):
            generation_data.setdefault(index, {})

        generation_data[generation] = self._generation_info_locked(
            generation, width, height, format, present, images
        )
        for row in history:
            info = generation_data[row["generation"]]
            info.setdefault("generation", row["generation"])
            info.setdefault("required_bytes", row["required_bytes"])
            info.setdefault("images", images)
            info.setdefault("width", None)
            info.setdefault("height", None)
            if isinstance(info.get("width"), int) and isinstance(
                info.get("height"), int
            ) and isinstance(info.get("images"), int):
                expected = (
                    info["width"] * info["height"] * info["images"] * 4
                )
                if expected != info.get("required_bytes"):
                    raise SwapchainResizeError(
                        "SWR_SNAPSHOT_INVALID",
                        {"reason": "generation_data"},
                    )

        return {
            "settings": settings,
            "config": {
                "width": width,
                "height": height,
                "format": format,
                "present": present,
                "images": images,
                "generation": generation,
                "suspended": suspended,
                "in_flight": in_flight,
            },
            "pending": pending,
            "pending_frames": pending_frames,
            "pending_polls": pending_polls,
            "pending_last_frame": pending_last_frame,
            "resume_pending": resume_pending,
            "minimized": minimized,
            "next_image": next_image,
            "retained": retained,
            "retired": retired,
            "destroyed": destroyed,
            "history": history,
            "stats": stats,
            "generation_data": generation_data,
        }
