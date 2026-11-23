import copy
import threading

import pytest

import lag_compensation_guard as lag


def make(**kwargs):
    return lag.LagCompensation(**kwargs)


def move(**positions):
    return dict(positions)


def test_exact_ticks_return_recorded_poses():
    h = make()
    h.record(10, {"ghost": (0.0, 0.0)})
    h.record(20, {"ghost": (100.0, 40.0)})
    assert h.pose(10, "ghost") == (0.0, 0.0)
    assert h.pose(20, "ghost") == (100.0, 40.0)
    assert h.ticks() == [10, 20]
    assert h.latest() == 20


def test_between_ticks_interpolates_linearly():
    h = make()
    h.record(10, {"ghost": (0.0, 0.0)})
    h.record(20, {"ghost": (100.0, 40.0)})
    assert h.pose(15, "ghost") == (50.0, 20.0)
    assert h.pose(12, "ghost") == pytest.approx((20.0, 8.0))
    assert h.pose(18, "ghost") == pytest.approx((80.0, 32.0))


def test_future_ticks_are_rejected():
    h = make()
    h.record(5, {"guard": (1.0, 1.0)})
    with pytest.raises(lag.LagError) as exc:
        h.pose(6, "guard")
    assert exc.value.code == "LAG_TICK_FUTURE"
    with pytest.raises(lag.LagError) as exc:
        h.begin_rewind(8)
    assert exc.value.code == "LAG_TICK_FUTURE"
    assert h.rewinding() is False


def test_duplicate_tick_is_rejected_without_changing_history():
    h = make()
    h.record(5, {"guard": (1.0, 1.0)})
    with pytest.raises(lag.LagError) as exc:
        h.record(5, {"guard": (9.0, 9.0)})
    assert exc.value.code == "LAG_TICK_DUP"
    assert h.latest() == 5
    assert h.pose(5, "guard") == (1.0, 1.0)


def test_tick_regression_is_rejected():
    h = make()
    h.record(5, {"guard": (1.0, 1.0)})
    with pytest.raises(lag.LagError) as exc:
        h.record(4, {"guard": (0.0, 0.0)})
    assert exc.value.code == "LAG_TICK_ORDER"
    assert h.latest() == 5
    assert h.ticks() == [5]


def test_history_capacity_prunes_the_oldest_frame():
    h = make(history=3)
    for tick in (3, 4, 5):
        h.record(tick, {"guard": (float(tick), 0.0)})
    h.record(6, {"guard": (6.0, 0.0)})
    assert h.ticks() == [4, 5, 6]
    with pytest.raises(lag.LagError) as exc:
        h.pose(3, "guard")
    assert exc.value.code == "LAG_TICK_EXPIRED"
    with pytest.raises(lag.LagError) as exc:
        h.begin_rewind(3)
    assert exc.value.code == "LAG_TICK_EXPIRED"
    assert h.rewinding() is False
    assert h.pose(6, "guard") == (6.0, 0.0)


def test_rewind_exposes_history_without_disturbing_present_queries():
    h = make()
    h.record(10, {"ghost": (0.0, 0.0)})
    h.record(20, {"ghost": (100.0, 0.0)})
    assert h.begin_rewind(10) == 10
    assert h.rewinding() is True
    assert h.rewound_pose("ghost") == (0.0, 0.0)
    assert h.pose(20, "ghost") == (100.0, 0.0)
    assert h.end_rewind() is True
    assert h.rewinding() is False
    assert h.pose(20, "ghost") == (100.0, 0.0)


def test_nested_rewind_is_rejected_and_outer_one_survives():
    h = make()
    h.record(10, {"ghost": (0.0, 0.0)})
    h.record(20, {"ghost": (100.0, 0.0)})
    h.begin_rewind(15)
    with pytest.raises(lag.LagError) as exc:
        h.begin_rewind(16)
    assert exc.value.code == "LAG_REWIND_ACTIVE"
    assert h.rewinding() is True
    assert h.rewound_pose("ghost") == pytest.approx((50.0, 0.0))
    h.end_rewind()


def test_fire_uses_the_historical_pose_then_restores_present():
    h = make()
    h.record(10, {"ghost": (0.0, 0.0)})
    h.record(20, {"ghost": (100.0, 0.0)})
    hit = h.fire("p1", "ghost", 10, (0.0, 0.0), radius=1.0)
    assert hit["hit"] is True
    assert hit["tick"] == 10
    assert hit["delta"] == 10
    miss = h.fire("p1", "ghost", 20, (0.0, 0.0), radius=1.0)
    assert miss["hit"] is False
    assert miss["delta"] == 0
    assert h.rewinding() is False
    assert h.stats()["rewinds"] == 2


def test_rewind_older_than_the_window_is_rejected():
    h = make(max_rewind=5)
    h.record(10, {"ghost": (0.0, 0.0)})
    h.record(20, {"ghost": (100.0, 0.0)})
    with pytest.raises(lag.LagError) as exc:
        h.begin_rewind(14)
    assert exc.value.code == "LAG_REWIND_TOO_OLD"
    assert h.rewinding() is False
    with pytest.raises(lag.LagError) as exc:
        h.end_rewind()
    assert exc.value.code == "LAG_NO_REWIND"


def test_rewind_helpers_require_an_active_session():
    h = make()
    with pytest.raises(lag.LagError) as exc:
        h.pose(0, "ghost")
    assert exc.value.code == "LAG_EMPTY_HISTORY"
    with pytest.raises(lag.LagError) as exc:
        h.begin_rewind(0)
    assert exc.value.code == "LAG_EMPTY_HISTORY"
    with pytest.raises(lag.LagError) as exc:
        h.end_rewind()
    assert exc.value.code == "LAG_NO_REWIND"
    with pytest.raises(lag.LagError) as exc:
        h.rewound_pose("ghost")
    assert exc.value.code == "LAG_NO_REWIND"
    with pytest.raises(lag.LagError) as exc:
        h.rewound_hit("ghost", (0.0, 0.0))
    assert exc.value.code == "LAG_NO_REWIND"


def test_snapshot_restores_history_and_survives_bad_versions():
    h = make()
    h.record(10, {"ghost": (0.0, 0.0)})
    h.record(20, {"ghost": (100.0, 0.0)})
    h.fire("p1", "ghost", 10, (0.0, 0.0), radius=1.0)
    snap = h.snapshot()
    assert snap["version"] == 1
    h.record(30, {"ghost": (200.0, 0.0)})
    assert h.pose(30, "ghost") == (200.0, 0.0)
    h.restore(snap)
    assert h.ticks() == [10, 20]
    assert h.pose(20, "ghost") == (100.0, 0.0)
    assert h.stats()["rewinds"] == 1
    bad = copy.deepcopy(snap)
    bad["version"] = 99
    with pytest.raises(lag.LagError) as exc:
        h.restore(bad)
    assert exc.value.code == "LAG_SNAPSHOT_VERSION"
    assert h.ticks() == [10, 20]


def test_rewind_hit_checks_use_the_historical_position():
    h = make()
    h.record(10, {"ghost": (0.0, 0.0)})
    h.record(20, {"ghost": (100.0, 0.0)})
    h.begin_rewind(10)
    assert h.rewound_hit("ghost", (0.0, 0.0), radius=0.0) is True
    assert h.rewound_hit("ghost", (100.0, 0.0), radius=0.0) is False
    h.end_rewind()
    h.begin_rewind(20)
    assert h.rewound_hit("ghost", (100.0, 0.0), radius=0.0) is True
    h.end_rewind()


def test_unknown_entities_in_the_bracketing_frames_are_reported():
    h = make()
    h.record(10, {"a": (0.0, 0.0)})
    h.record(20, {"a": (10.0, 0.0)})
    h.record(30, {"a": (20.0, 0.0), "b": (5.0, 5.0)})
    assert h.pose(25, "a") == (15.0, 0.0)
    with pytest.raises(lag.LagError) as exc:
        h.pose(25, "b")
    assert exc.value.code == "LAG_UNKNOWN_ENTITY"
    with pytest.raises(lag.LagError) as exc:
        h.pose(15, "ghost")
    assert exc.value.code == "LAG_UNKNOWN_ENTITY"
    h.begin_rewind(25)
    with pytest.raises(lag.LagError) as exc:
        h.rewound_pose("b")
    assert exc.value.code == "LAG_UNKNOWN_ENTITY"
    h.end_rewind()


def test_concurrent_fire_calls_do_not_corrupt_rewind_state():
    h = make(max_rewind=32)
    for tick in range(1, 41):
        h.record(tick, {"ghost": (5.0, 5.0)})
    hits = []
    errors = []
    lock = threading.Lock()

    def worker():
        for _ in range(25):
            try:
                out = h.fire("p1", "ghost", 30, (5.0, 5.0), radius=0.5)
                with lock:
                    hits.append(out["hit"])
            except Exception as exc:  # pragma: no cover - diagnostic path
                with lock:
                    errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    assert len(hits) == 200
    assert all(hits) is True
    assert h.rewinding() is False
    assert h.stats()["rewinds"] == 200
    assert h.latest() == 40
