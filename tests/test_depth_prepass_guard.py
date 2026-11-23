import json
import threading

import pytest

import depth_prepass_guard as dp


def make(viewport=(32, 32), **kwargs):
    a = dp.DepthPrepass(**kwargs)
    a.set_viewport(*viewport)
    return a


def draw(draw_id, depth_min=0.1, depth_max=None, bounds=(0, 0, 8, 8),
         alpha_test=False, material="stone"):
    if depth_max is None:
        depth_max = depth_min + 0.1
    return {"id": draw_id, "depth_min": depth_min, "depth_max": depth_max,
            "bounds": bounds, "alpha_test": alpha_test, "material": material}


def fill_depth(a, x0, y0, x1, y1, value):
    for x in range(x0, x1):
        for y in range(y0, y1):
            a.write_depth((x, y), value)


def test_viewport_validation_and_pass_requires_viewport():
    a = dp.DepthPrepass()
    with pytest.raises(dp.DepthPrepassError) as exc:
        a.begin_pass()
    assert exc.value.code == "DP_NOT_READY"
    with pytest.raises(dp.DepthPrepassError) as exc:
        a.set_viewport(0, 10)
    assert exc.value.code == "DP_BAD_VIEWPORT"
    out = a.set_viewport(16, 16, near=0.5, far=100.0)
    assert out == {"width": 16, "height": 16, "near": 0.5, "far": 100.0}
    with pytest.raises(dp.DepthPrepassError) as exc:
        a.set_viewport(16, 16, near=10.0, far=1.0)
    assert exc.value.code == "DP_BAD_VIEWPORT"


def test_write_depth_validates_range_and_keeps_nearest():
    a = make(viewport=(8, 8))
    with pytest.raises(dp.DepthPrepassError) as exc:
        a.write_depth((0, 0), 1.5)
    assert exc.value.code == "DP_DEPTH_RANGE"
    with pytest.raises(dp.DepthPrepassError) as exc:
        a.write_depth((8, 0), 0.5)
    assert exc.value.code == "DP_PIXEL_OOB"
    assert a.write_depth((1, 1), 0.8)["depth"] == 0.8
    assert a.write_depth((1, 1), 0.2)["depth"] == 0.2
    assert a.write_depth((1, 1), 0.6)["depth"] == 0.2
    assert a.depth_at((1, 1)) == 0.2
    assert a.stats()["depth_writes"] == 2


def test_submit_draw_requires_active_pass_and_valid_bounds():
    a = make(viewport=(32, 32))
    with pytest.raises(dp.DepthPrepassError) as exc:
        a.submit_draw(draw("early"))
    assert exc.value.code == "DP_PASS_STATE"
    a.begin_pass()
    with pytest.raises(dp.DepthPrepassError) as exc:
        a.submit_draw(draw("wide", bounds=(30, 0, 40, 4)))
    assert exc.value.code == "DP_DRAW_OOB"
    with pytest.raises(dp.DepthPrepassError) as exc:
        a.submit_draw(draw("inverted", depth_min=0.9, depth_max=0.1))
    assert exc.value.code == "DP_BAD_DRAW"
    assert a.end_pass()["draws"] == 0


def test_hiz_occludes_only_fully_behind_geometry():
    a = make(viewport=(16, 16), tile_size=8)
    a.begin_pass()
    fill_depth(a, 0, 0, 8, 8, 0.2)
    front = a.submit_draw(draw("near", depth_min=0.5, depth_max=0.6,
                               bounds=(0, 0, 8, 8)))
    assert front["status"] == "occluded"
    assert front["code"] == "DP_OCCLUDED"
    partial = a.submit_draw(draw("edge", depth_min=0.5, depth_max=0.6,
                                 bounds=(4, 0, 12, 8)))
    assert partial["status"] == "scheduled"
    assert a.stats()["occluded"] == 1


def test_alpha_test_draws_are_never_occluded_and_ordered_last():
    a = make(viewport=(16, 16), tile_size=8)
    a.begin_pass()
    fill_depth(a, 0, 0, 8, 8, 0.2)
    leaf = a.submit_draw(draw("leaf", depth_min=0.8, depth_max=0.9,
                              bounds=(0, 0, 8, 8), alpha_test=True,
                              material="leaf"))
    assert leaf["status"] == "scheduled"
    assert leaf["transparent"] is True
    a.submit_draw(draw("wall", depth_min=0.5, depth_max=0.6,
                       bounds=(8, 8, 16, 16), material="wall"))
    end = a.end_pass()
    assert end["order"] == ["wall", "leaf"]
    assert end["occluded"] == 0


def test_end_pass_orders_front_to_back_and_counts_state_switches():
    a = make(viewport=(32, 32))
    a.begin_pass()
    a.submit_draw(draw("c", depth_min=0.5, depth_max=0.6, material="cloth"))
    a.submit_draw(draw("a", depth_min=0.1, depth_max=0.2, material="wood"))
    a.submit_draw(draw("b", depth_min=0.5, depth_max=0.7, material="stone"))
    end = a.end_pass()
    assert end["order"] == ["a", "b", "c"]
    assert end["draws"] == 3
    assert end["state_switches"] == 2
    assert a.stats()["drawn"] == 3


def test_duplicate_draw_id_is_ignored():
    a = make(viewport=(16, 16))
    a.begin_pass()
    first = a.submit_draw(draw("x", bounds=(0, 0, 4, 4)))
    assert first["status"] == "scheduled"
    again = a.submit_draw(draw("x", depth_min=0.4, bounds=(4, 4, 8, 8)))
    assert again["status"] == "ignored"
    assert again["code"] == "DP_DUP_DRAW"
    assert a.stats()["duplicate_draws"] == 1
    assert a.end_pass()["draws"] == 1


def test_max_draws_is_enforced_without_partial_state():
    a = make(viewport=(32, 32), max_draws=2)
    a.begin_pass()
    a.submit_draw(draw("a", bounds=(0, 0, 4, 4)))
    a.submit_draw(draw("b", bounds=(8, 8, 12, 12)))
    with pytest.raises(dp.DepthPrepassError) as exc:
        a.submit_draw(draw("c", bounds=(16, 16, 20, 20)))
    assert exc.value.code == "DP_TOO_MANY_DRAWS"
    end = a.end_pass()
    assert end["draws"] == 2
    assert a.stats()["drawn"] == 2


def test_pass_state_machine():
    a = make(viewport=(8, 8))
    a.begin_pass()
    with pytest.raises(dp.DepthPrepassError) as exc:
        a.begin_pass()
    assert exc.value.code == "DP_PASS_STATE"
    a.end_pass()
    with pytest.raises(dp.DepthPrepassError) as exc:
        a.end_pass()
    assert exc.value.code == "DP_PASS_STATE"
    with pytest.raises(dp.DepthPrepassError) as exc:
        a.submit_draw(draw("late", bounds=(0, 0, 4, 4)))
    assert exc.value.code == "DP_PASS_STATE"
    assert a.stats()["passes"] == 1


def test_pyramid_levels_and_dimensions():
    a = make(viewport=(64, 32), tile_size=8)
    a.write_depth((0, 0), 0.1)
    levels = a.build_pyramid()
    assert levels == [
        {"level": 0, "width": 8, "height": 4},
        {"level": 1, "width": 4, "height": 2},
        {"level": 2, "width": 2, "height": 1},
        {"level": 3, "width": 1, "height": 1},
    ]


def test_hiz_query_validates_rect_and_depth():
    a = make(viewport=(16, 16), tile_size=8)
    with pytest.raises(dp.DepthPrepassError) as exc:
        a.hiz_query((0, 0, 0, 4), 0.5)
    assert exc.value.code == "DP_RECT_OOB"
    with pytest.raises(dp.DepthPrepassError) as exc:
        a.hiz_query((0, 0, 4, 4), 2.0)
    assert exc.value.code == "DP_DEPTH_RANGE"
    assert a.hiz_query((0, 0, 4, 4), 0.5) is False
    fill_depth(a, 0, 0, 8, 8, 0.3)
    assert a.hiz_query((0, 0, 4, 4), 0.5) is True


def test_filter_opaque_and_sorted_draws():
    a = make(viewport=(32, 32))
    candidates = [
        {"id": "t1", "depth_min": 0.1, "alpha_test": True},
        {"id": "o2", "depth_min": 0.6, "alpha_test": False},
        {"id": "o1", "depth_min": 0.2, "alpha_test": False},
    ]
    assert a.filter_opaque(candidates) == ["o1", "o2"]
    with pytest.raises(dp.DepthPrepassError) as exc:
        a.filter_opaque([{"id": "bad"}])
    assert exc.value.code == "DP_BAD_DRAW"
    a.begin_pass()
    a.submit_draw(draw("t1", depth_min=0.1, bounds=(0, 0, 4, 4), alpha_test=True))
    a.submit_draw(draw("o2", depth_min=0.6, bounds=(4, 0, 8, 4)))
    a.submit_draw(draw("o1", depth_min=0.2, bounds=(8, 0, 12, 4)))
    rows = a.sorted_draws()
    assert [row["id"] for row in rows] == ["o1", "o2", "t1"]
    assert rows[-1]["transparent"] is True


def test_snapshot_restore_round_trips_through_json():
    a = make(viewport=(16, 16), tile_size=8)
    a.begin_pass()
    a.write_depth((1, 1), 0.25)
    a.submit_draw(draw("k", depth_min=0.5, depth_max=0.6, bounds=(0, 0, 4, 4)))
    snap = json.loads(json.dumps(a.snapshot()))
    b = dp.DepthPrepass()
    out = b.restore(snap)
    assert out["depth_pixels"] == 1
    assert b.depth_at((1, 1)) == 0.25
    assert b.stats() == a.stats()
    assert b.build_pyramid() == a.build_pyramid()
    assert b.end_pass()["order"] == ["k"]


def test_invalid_snapshot_is_rejected_without_mutating():
    a = make(viewport=(8, 8))
    a.write_depth((0, 0), 0.5)
    before = a.stats()
    with pytest.raises(dp.DepthPrepassError) as exc:
        a.restore({"version": 2})
    assert exc.value.code == "DP_SNAPSHOT_INVALID"
    broken = a.snapshot()
    broken["depth"]["0,0"] = 1.5
    with pytest.raises(dp.DepthPrepassError) as exc:
        a.restore(broken)
    assert exc.value.code == "DP_SNAPSHOT_INVALID"
    assert a.stats() == before
    assert a.depth_at((0, 0)) == 0.5


def test_concurrent_depth_writes_are_not_lost():
    a = make(viewport=(200, 8))

    def worker(base):
        for offset in range(25):
            a.write_depth((base + offset, 0), 0.5)

    threads = [threading.Thread(target=worker, args=(index * 25,))
               for index in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert a.stats()["depth_pixels"] == 200
    assert a.stats()["depth_writes"] == 200
