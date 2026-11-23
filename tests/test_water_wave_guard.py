import math
from concurrent.futures import ThreadPoolExecutor

import pytest

import water_wave_guard as ww


TAU = 2.0 * math.pi


def make(**kwargs):
    return ww.WaterWaves(**kwargs)


def add_default_wave(waves, wave_id="swell"):
    waves.add_wave(wave_id, amplitude=0.5, wavelength=TAU, steepness=0.0,
                   direction=(1.0, 0.0), speed=0.0)


def test_add_wave_validates_parameters_and_enforces_limit():
    waves = make(max_waves=2)
    with pytest.raises(ww.WaterWaveError) as exc:
        waves.add_wave("bad", amplitude=0.0, wavelength=TAU, steepness=0.2,
                       direction=(1.0, 0.0), speed=1.0)
    assert exc.value.code == "WW_INVALID_WAVE"
    add_default_wave(waves, "a")
    add_default_wave(waves, "b")
    with pytest.raises(ww.WaterWaveError) as exc:
        add_default_wave(waves, "c")
    assert exc.value.code == "WW_WAVE_LIMIT"
    assert waves.stats()["waves"] == 2


def test_sample_height_follows_gerstner_phase():
    waves = make(resolution=8)
    waves.set_water_level(1.0)
    add_default_wave(waves)
    assert waves.sample_height(0.0, 0.0, 0.0) == pytest.approx(1.0)
    assert waves.sample_height(math.pi / 2.0, 0.0, 0.0) == pytest.approx(1.5)
    assert waves.sample_height(3.0 * math.pi / 2.0, 0.0, 0.0) == \
        pytest.approx(0.5)


def test_sample_normal_is_unit_length_and_matches_slope():
    waves = make(resolution=8)
    add_default_wave(waves)
    nx, ny, nz = waves.sample_normal(0.0, 0.0, 0.0)
    scale = 1.0 / math.sqrt(1.25)
    assert nx == pytest.approx(-0.5 * scale)
    assert ny == pytest.approx(scale)
    assert nz == pytest.approx(0.0, abs=1e-9)
    assert math.sqrt(nx * nx + ny * ny + nz * nz) == pytest.approx(1.0)


def test_step_advances_time_and_suppresses_duplicate_frame():
    waves = make()
    out = waves.step(0.25, frame=1)
    assert out["status"] == "applied"
    assert out["time"] == pytest.approx(0.25)
    duplicate = waves.step(0.25, frame=1)
    assert duplicate["status"] == "ignored"
    assert duplicate["code"] == "WW_DUP_FRAME"
    assert waves.stats()["time"] == pytest.approx(0.25)
    with pytest.raises(ww.WaterWaveError) as exc:
        waves.step(0.1, frame=0)
    assert exc.value.code == "WW_STALE_FRAME"


def test_step_rejects_out_of_range_dt():
    waves = make()
    for dt in (0.0, -0.1, 2.5):
        with pytest.raises(ww.WaterWaveError) as exc:
            waves.step(dt, frame=1)
        assert exc.value.code == "WW_INVALID_STEP"


def test_splash_accumulates_and_foam_decays():
    waves = make(resolution=8)
    waves.splash(0.2, 0.1, 1.0)
    assert waves.foam_at(0.8, 0.9) == pytest.approx(1.0)
    assert waves.foam_at(1.2, 0.1) == pytest.approx(0.0)
    waves.step(0.5, frame=1)
    assert waves.foam_at(0.2, 0.1) == pytest.approx(0.75)
    waves.splash(0.2, 0.1, 5.0)
    assert waves.foam_at(0.2, 0.1) == pytest.approx(1.0)
    waves.step(2.0, frame=2)
    assert waves.foam_at(0.2, 0.1) == pytest.approx(0.0)


def test_splash_rejects_negative_amount():
    waves = make()
    with pytest.raises(ww.WaterWaveError) as exc:
        waves.splash(0.0, 0.0, -0.5)
    assert exc.value.code == "WW_INVALID_FOAM"


def test_build_mesh_ring_counts_and_vertex_order():
    waves = make(resolution=8)
    out = waves.build_mesh(0, rings=2)
    assert out["status"] == "applied"
    assert out["vertex_count"] == 64 + 16
    vertices = out["vertices"]
    assert len(vertices) == 80
    assert vertices[0][0] == pytest.approx(-3.5)
    assert vertices[0][1] == pytest.approx(-3.5)
    assert vertices[63][0] == pytest.approx(3.5)
    assert vertices[63][1] == pytest.approx(3.5)
    assert vertices[64][0] == pytest.approx(-1.5)
    assert vertices[64][1] == pytest.approx(-1.5)
    assert vertices[-1][0] == pytest.approx(1.5)
    assert vertices[-1][1] == pytest.approx(1.5)


def test_build_mesh_budget_and_ring_validation():
    heavy = make(resolution=64, max_vertices=1000)
    with pytest.raises(ww.WaterWaveError) as exc:
        heavy.build_mesh(0, rings=4)
    assert exc.value.code == "WW_BUDGET_EXCEEDED"
    assert heavy.stats()["builds"] == 0
    light = make(resolution=8)
    for rings in (0, 5):
        with pytest.raises(ww.WaterWaveError) as exc:
            light.build_mesh(0, rings=rings)
        assert exc.value.code == "WW_INVALID_RINGS"
    assert light.stats()["builds"] == 0


def test_build_mesh_only_accepts_current_frame():
    waves = make(resolution=8)
    assert waves.build_mesh(0, rings=1)["status"] == "applied"
    with pytest.raises(ww.WaterWaveError) as exc:
        waves.build_mesh(1, rings=1)
    assert exc.value.code == "WW_STALE_FRAME"
    waves.step(0.1, frame=1)
    assert waves.build_mesh(1, rings=1)["status"] == "applied"
    with pytest.raises(ww.WaterWaveError) as exc:
        waves.build_mesh(0, rings=1)
    assert exc.value.code == "WW_STALE_FRAME"


def test_mesh_checksum_independent_of_wave_insertion_order():
    configs = (
        (0.5, TAU, 0.2, (1.0, 0.0), 1.0),
        (0.3, 6.0, 0.4, (0.0, 1.0), 0.8),
        (0.2, 4.0, 0.6, (0.6, 0.8), 1.2),
    )

    def build(order):
        waves = make(resolution=16)
        for index in order:
            amplitude, wavelength, steepness, direction, speed = \
                configs[index]
            waves.add_wave("w%d" % index, amplitude=amplitude,
                           wavelength=wavelength, steepness=steepness,
                           direction=direction, speed=speed)
        return waves.build_mesh(0, rings=2)

    first = build((0, 1, 2))
    second = build((2, 0, 1))
    assert first["checksum"] == second["checksum"]
    assert first["vertex_count"] == second["vertex_count"]


def test_repeated_build_for_same_frame_is_cached():
    waves = make(resolution=8)
    first = waves.build_mesh(0, rings=2)
    second = waves.build_mesh(0, rings=2)
    assert second["status"] == "cached"
    assert second["checksum"] == first["checksum"]
    assert waves.stats()["builds"] == 1


def test_lod_thresholds():
    waves = make()
    distances = (0.0, 15.9, 16.0, 47.9, 48.0, 127.9, 128.0, 1000.0)
    assert [waves.lod_for(distance) for distance in distances] == \
        [0, 0, 1, 1, 2, 2, 3, 3]
    with pytest.raises(ww.WaterWaveError) as exc:
        waves.lod_for(-1.0)
    assert exc.value.code == "WW_INVALID_DISTANCE"


def test_snapshot_restore_roundtrip_and_atomic_validation():
    waves = make(resolution=8)
    waves.set_water_level(0.5)
    add_default_wave(waves)
    waves.splash(0.2, 0.1, 0.4)
    waves.step(0.25, frame=1)
    waves.build_mesh(1, rings=2)
    snap = waves.snapshot()
    waves.add_wave("later", amplitude=0.1, wavelength=4.0, steepness=0.1,
                   direction=(0.0, 1.0), speed=0.5)
    waves.splash(1.2, 0.1, 0.3)
    waves.step(0.25, frame=2)
    waves.restore(snap)
    assert waves.snapshot() == snap
    bad = dict(snap)
    bad["version"] = 99
    with pytest.raises(ww.WaterWaveError) as exc:
        waves.restore(bad)
    assert exc.value.code == "WW_SNAPSHOT_VERSION"
    before = waves.stats()
    broken = dict(snap)
    del broken["waves"]
    with pytest.raises(ww.WaterWaveError) as exc:
        waves.restore(broken)
    assert exc.value.code == "WW_SNAPSHOT_INVALID"
    assert waves.stats() == before


def test_concurrent_height_samples_are_counted_exactly():
    waves = make(resolution=8)
    add_default_wave(waves)
    xs = [index * 0.01 for index in range(200)]
    with ThreadPoolExecutor(max_workers=8) as pool:
        heights = list(pool.map(
            lambda x: waves.sample_height(x, 0.0, 0.0), xs
        ))
    assert len(heights) == 200
    assert waves.stats()["samples"] == 200
