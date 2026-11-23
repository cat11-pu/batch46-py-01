from concurrent.futures import ThreadPoolExecutor

import pytest

import light_probe_guard as lp


CORNER_COORDS = (
    (0, 0, 0), (1, 0, 0), (0, 1, 0), (1, 1, 0),
    (0, 0, 1), (1, 0, 1), (0, 1, 1), (1, 1, 1),
)
CORNER_COLORS = (
    (0.0, 0.0, 0.0), (1.0, 0.0, 0.0), (0.0, 1.0, 0.0), (1.0, 1.0, 0.0),
    (0.0, 0.0, 1.0), (1.0, 0.0, 1.0), (0.0, 1.0, 1.0), (1.0, 1.0, 1.0),
)


def unit_volume(**kwargs):
    return lp.LightProbe(bounds=((0.0, 0.0, 0.0), (1.0, 1.0, 1.0)),
                         spacing=1.0, **kwargs)


def fill_unit_volume(probes):
    for coord, color in zip(CORNER_COORDS, CORNER_COLORS):
        probes.set_probe(coord, color=color)


def test_exact_probe_position_returns_its_color():
    probes = lp.LightProbe()
    probes.set_probe((0, 0, 0), color=(1.0, 2.0, 3.0))
    out = probes.probe_at((0.0, 0.0, 0.0))
    assert out["color"] == pytest.approx((1.0, 2.0, 3.0))
    assert out["clamped"] is False
    assert sum(out["weights"]) == pytest.approx(1.0)


def test_tetrahedral_interpolation_weights_are_deterministic():
    first = unit_volume()
    fill_unit_volume(first)
    out = first.probe_at((0.5, 0.5, 0.5))
    weights = out["weights"]
    assert len(weights) == 8
    assert sum(weights) == pytest.approx(1.0)
    assert sum(1 for weight in weights if weight > 0.0) == 4
    expected = tuple(
        sum(weights[index] * CORNER_COLORS[index][channel]
            for index in range(8))
        for channel in range(3)
    )
    assert out["color"] == pytest.approx(expected)
    second = unit_volume()
    fill_unit_volume(second)
    assert second.probe_at((0.5, 0.5, 0.5)) == out


def test_out_of_bounds_position_is_clamped_to_edge_cell():
    probes = lp.LightProbe(bounds=((0.0, 0.0, 0.0), (4.0, 4.0, 4.0)),
                           spacing=1.0)
    probes.set_probe((0, 4, 3), color=(0.5, 0.5, 0.5))
    out = probes.probe_at((-2.0, 99.0, 3.4))
    assert out["clamped"] is True
    assert out["cell"] == (0, 3, 3)
    assert out["color"] == pytest.approx((0.5, 0.5, 0.5))


def test_empty_volume_raises_no_valid_probe():
    probes = lp.LightProbe()
    with pytest.raises(lp.LightProbeError) as exc:
        probes.probe_at((0.5, 0.5, 0.5))
    assert exc.value.code == "LP_NO_VALID_PROBE"


def test_invalid_corner_weights_are_redistributed():
    probes = unit_volume()
    for coord in CORNER_COORDS:
        probes.set_probe(coord, color=(1.0, 1.0, 1.0))
    probes.set_probe((1, 0, 0), color=(0.0, 0.0, 0.0), valid=False)
    out = probes.probe_at((0.5, 0.5, 0.5))
    assert out["weights"][1] == 0.0
    assert sum(out["weights"]) == pytest.approx(1.0)
    assert out["color"] == pytest.approx((1.0, 1.0, 1.0))


def test_invalidate_hides_probe_and_set_valid_restores_it():
    probes = unit_volume()
    for coord in CORNER_COORDS:
        probes.set_probe(coord, color=(1.0, 1.0, 1.0))
    result = probes.invalidate([(0, 0, 0), (9, 9, 9)])
    assert result["invalidated"] == 1
    assert result["missing"] == 1
    assert probes.probe_at((0.5, 0.5, 0.5))["weights"][0] == 0.0
    probes.set_probe((0, 0, 0), color=(0.0, 0.0, 0.0), valid=True)
    assert probes.probe_at((0.0, 0.0, 0.0))["color"] == \
        pytest.approx((0.0, 0.0, 0.0))
    assert probes.stats()["probes"] == 8


def test_probe_budget_blocks_new_coordinates_only():
    probes = lp.LightProbe(bounds=((0.0, 0.0, 0.0), (2.0, 2.0, 2.0)),
                           spacing=1.0, max_probes=2)
    probes.set_probe((0, 0, 0), color=(0.0, 0.0, 0.0))
    probes.set_probe((1, 0, 0), color=(0.0, 0.0, 0.0))
    with pytest.raises(lp.LightProbeError) as exc:
        probes.set_probe((2, 0, 0), color=(0.0, 0.0, 0.0))
    assert exc.value.code == "LP_BUDGET_EXCEEDED"
    probes.set_probe((1, 0, 0), color=(1.0, 1.0, 1.0))
    assert probes.stats()["probes"] == 2


def test_probe_index_outside_grid_is_rejected():
    probes = lp.LightProbe(bounds=((0.0, 0.0, 0.0), (4.0, 4.0, 4.0)),
                           spacing=1.0)
    for coord in ((5, 0, 0), (-1, 0, 0)):
        with pytest.raises(lp.LightProbeError) as exc:
            probes.set_probe(coord, color=(0.0, 0.0, 0.0))
        assert exc.value.code == "LP_INDEX_RANGE"


def test_bake_is_atomic_and_bumps_generation_once():
    probes = lp.LightProbe(bounds=((0.0, 0.0, 0.0), (4.0, 4.0, 4.0)),
                           spacing=1.0)
    updates = [
        {"coord": (0, 0, 0), "color": (1.0, 0.0, 0.0)},
        {"coord": (1, 0, 0), "color": (0.0, 1.0, 0.0)},
        {"coord": (0, 1, 0), "color": (0.0, 0.0, 1.0)},
    ]
    out = probes.bake(1, updates)
    assert out["updated"] == 3
    assert out["generation"] == 1
    with pytest.raises(lp.LightProbeError) as exc:
        probes.bake(2, [{"coord": (9, 0, 0), "color": (0.0, 0.0, 0.0)}])
    assert exc.value.code == "LP_INVALID_UPDATE"
    assert probes.stats()["generation"] == 1
    assert probes.probe_at((0, 0, 0))["color"] == pytest.approx((1.0, 0.0,
                                                                 0.0))


def test_duplicate_bake_frame_is_ignored():
    probes = lp.LightProbe()
    probes.bake(1, [{"coord": (0, 0, 0), "color": (1.0, 1.0, 1.0)}])
    duplicate = probes.bake(
        1, [{"coord": (1, 0, 0), "color": (0.0, 0.0, 0.0)}]
    )
    assert duplicate["status"] == "ignored"
    assert duplicate["code"] == "LP_DUP_FRAME"
    assert probes.stats()["generation"] == 1
    assert probes.stats()["probes"] == 1


def test_stale_bake_frame_rejected():
    probes = lp.LightProbe()
    probes.bake(2, [{"coord": (0, 0, 0), "color": (1.0, 1.0, 1.0)}])
    with pytest.raises(lp.LightProbeError) as exc:
        probes.bake(1, [{"coord": (1, 0, 0), "color": (0.0, 0.0, 0.0)}])
    assert exc.value.code == "LP_STALE_FRAME"


def test_exposure_scales_and_clamps_color():
    probes = unit_volume()
    probes.set_probe((0, 0, 0), color=(10.0, 20.0, 30.0))
    probes.set_exposure(2.0)
    assert probes.probe_at((0.0, 0.0, 0.0))["color"] == \
        pytest.approx((20.0, 40.0, 60.0))
    probes.set_exposure(16.0)
    assert probes.probe_at((0.0, 0.0, 0.0))["color"] == \
        pytest.approx((64.0, 64.0, 64.0))
    with pytest.raises(lp.LightProbeError) as exc:
        probes.set_exposure(0.0)
    assert exc.value.code == "LP_INVALID_EXPOSURE"


def test_sample_many_preserves_input_order():
    probes = unit_volume()
    probes.set_probe((0, 0, 0), color=(1.0, 1.0, 1.0))
    positions = [(-1.0, 0.0, 0.0), (0.5, 0.5, 0.5), (0.0, 0.0, 0.0)]
    rows = probes.sample_many(positions)
    assert len(rows) == 3
    assert [row["clamped"] for row in rows] == [True, False, False]
    assert all(row["color"] == pytest.approx((1.0, 1.0, 1.0))
               for row in rows)


def test_snapshot_restore_roundtrip_and_validation():
    probes = lp.LightProbe(bounds=((0.0, 0.0, 0.0), (2.0, 2.0, 2.0)),
                           spacing=1.0)
    probes.set_probe((0, 0, 0), color=(1.0, 0.0, 0.0))
    probes.set_probe((1, 1, 1), color=(0.0, 1.0, 0.0))
    probes.bake(1, [{"coord": (2, 2, 2), "color": (0.0, 0.0, 1.0)}])
    probes.set_exposure(2.0)
    snap = probes.snapshot()
    probes.set_probe((1, 0, 0), color=(9.0, 9.0, 9.0))
    probes.set_exposure(4.0)
    probes.restore(snap)
    assert probes.snapshot() == snap
    bad = dict(snap)
    bad["version"] = 42
    with pytest.raises(lp.LightProbeError) as exc:
        probes.restore(bad)
    assert exc.value.code == "LP_SNAPSHOT_VERSION"
    before = probes.stats()
    broken = dict(snap)
    del broken["probes"]
    with pytest.raises(lp.LightProbeError) as exc:
        probes.restore(broken)
    assert exc.value.code == "LP_SNAPSHOT_INVALID"
    assert probes.stats() == before


def test_concurrent_probe_sampling_is_counted():
    probes = unit_volume()
    probes.set_probe((0, 0, 0), color=(0.5, 0.5, 0.5))
    positions = [(0.0, 0.0, 0.0)] * 300
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(probes.probe_at, positions))
    assert probes.stats()["samples"] == 300
