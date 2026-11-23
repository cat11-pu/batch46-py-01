from concurrent.futures import ThreadPoolExecutor

import pytest

import volumetric_fog_guard as vf


def make(**kwargs):
    return vf.VolumetricFog(**kwargs)


def prepare(fog, frame=1, width=2, height=2):
    fog.set_camera("main", near=0.5, far=100.0)
    fog.reconstruct_depth(frame, [0.5] * (width * height),
                          width=width, height=height)
    return fog.scatter(frame)


def test_reversed_z_depth_linearization_maps_near_and_far():
    fog = make(grid=(4, 1, 1), max_froxels=100)
    fog.set_camera("main", near=0.1, far=200.0, reversed_z=True)
    out = fog.reconstruct_depth(1, [1.0, 0.0, 0.5], width=3, height=1)
    assert out["status"] == "applied"
    assert out["linear"][0] == pytest.approx(0.1, rel=1e-6)
    assert out["linear"][1] == pytest.approx(200.0, rel=1e-6)
    assert 0.1 < out["linear"][2] < 200.0
    assert out["invalid"] == 0


def test_reconstruct_depth_without_camera_is_rejected():
    fog = make(grid=(4, 1, 1), max_froxels=100)
    with pytest.raises(vf.FogError) as exc:
        fog.reconstruct_depth(1, [0.5], width=1, height=1)
    assert exc.value.code == "FOG_NO_CAMERA"


def test_non_finite_depth_samples_fall_back_to_far_plane():
    fog = make(grid=(4, 1, 1), max_froxels=100)
    fog.set_camera("main", near=0.5, far=100.0)
    out = fog.reconstruct_depth(
        1, [float("nan"), float("inf"), 0.0, 1.0], width=2, height=2
    )
    assert out["linear"][0] == pytest.approx(100.0)
    assert out["linear"][1] == pytest.approx(100.0)
    assert out["linear"][2] == pytest.approx(0.5)
    assert out["linear"][3] == pytest.approx(100.0)
    assert out["invalid"] == 2


def test_camera_cut_resets_history_and_frame_counter():
    fog = make(grid=(4, 1, 1), max_froxels=100)
    fog.set_camera("main", near=0.5, far=100.0)
    fog.reconstruct_depth(3, [0.5], width=1, height=1)
    fog.reproject(4, [(0.0, 0.0)])
    assert fog.history_state()["frames"] == 1
    fog.set_camera("cut", near=1.0, far=500.0)
    state = fog.history_state()
    assert state["camera"] == "cut"
    assert state["frames"] == 0
    assert state["last_frame"] is None
    out = fog.reconstruct_depth(1, [0.5], width=1, height=1)
    assert out["status"] == "applied"


def test_duplicate_frame_returns_cached_depth():
    fog = make(grid=(4, 1, 1), max_froxels=100)
    fog.set_camera("main", near=0.5, far=100.0)
    first = fog.reconstruct_depth(5, [0.5], width=1, height=1)
    second = fog.reconstruct_depth(5, [0.9], width=1, height=1)
    assert first["status"] == "applied"
    assert second["status"] == "cached"
    assert second["linear"] == first["linear"]


def test_stale_frame_rejected_on_reconstruct_and_scatter():
    fog = make(grid=(4, 1, 1), max_froxels=100)
    prepare(fog, frame=5)
    with pytest.raises(vf.FogError) as exc:
        fog.reconstruct_depth(4, [0.5] * 4, width=2, height=2)
    assert exc.value.code == "FOG_STALE_FRAME"
    with pytest.raises(vf.FogError) as exc:
        fog.scatter(4)
    assert exc.value.code == "FOG_STALE_FRAME"


def test_jitter_alternates_by_frame_parity():
    fog = make(grid=(4, 1, 1), max_froxels=100)
    fog.set_camera("main", near=0.5, far=100.0, jitter=(0.25, -0.125))
    for frame in (1, 2):
        fog.reconstruct_depth(frame, [0.5] * 4, width=2, height=2)
        fog.scatter(frame)
    assert fog.resolve(1)["jitter"] == pytest.approx((0.25, -0.125))
    assert fog.resolve(2)["jitter"] == pytest.approx((-0.25, 0.125))
    assert fog.resolve(2)["status"] == "applied"


def test_scatter_sample_budget_rejects_oversized_request():
    fog = make(grid=(8, 2, 2), max_froxels=100, max_sample_units=1000)
    fog.set_camera("main", near=0.5, far=100.0)
    fog.reconstruct_depth(1, [0.5] * 4, width=2, height=2)
    with pytest.raises(vf.FogError) as exc:
        fog.scatter(1, samples_per_froxel=64)
    assert exc.value.code == "FOG_SAMPLE_BUDGET"
    with pytest.raises(vf.FogError) as exc:
        fog.scatter(1, samples_per_froxel=0)
    assert exc.value.code == "FOG_INVALID_SAMPLES"
    out = fog.scatter(1, samples_per_froxel=8)
    assert out["samples"] == 32 * 8


def test_light_validation_and_insertion_order_do_not_affect_checksum():
    def build(order):
        fog = make(grid=(4, 1, 1), max_froxels=100)
        fog.set_camera("main", near=0.5, far=100.0)
        for light_id in order:
            fog.add_light(light_id, intensity=2.0,
                          position=(0.0, 0.0, 1.0), radius=5.0)
        fog.reconstruct_depth(1, [0.5] * 4, width=2, height=2)
        return fog.scatter(1)

    first = build(("key", "fill", "rim"))
    second = build(("rim", "key", "fill"))
    assert first["checksum"] == second["checksum"]

    bad = make(grid=(4, 1, 1), max_froxels=100)
    with pytest.raises(vf.FogError) as exc:
        bad.add_light("x", intensity=1.0, position=(0.0, 0.0, 0.0),
                      radius=0.0)
    assert exc.value.code == "FOG_INVALID_LIGHT"


def test_media_validation_and_update():
    fog = make(grid=(4, 1, 1), max_froxels=100)
    with pytest.raises(vf.FogError) as exc:
        fog.inject_media("haze", density=1.5, height_falloff=0.0,
                         extinction=1.0)
    assert exc.value.code == "FOG_INVALID_MEDIA"
    first = fog.inject_media("haze", density=0.2, height_falloff=0.5,
                             extinction=1.0)
    assert first["status"] == "added"
    second = fog.inject_media("haze", density=0.1, height_falloff=0.5,
                              extinction=2.0)
    assert second["status"] == "updated"
    assert fog.stats()["media"] == 1


def test_froxel_budget_enforced_at_construction():
    with pytest.raises(vf.FogError) as exc:
        make(grid=(64, 64, 64), max_froxels=1000)
    assert exc.value.code == "FOG_BUDGET_EXCEEDED"


def test_reproject_rejects_motion_beyond_limit_and_resets_history():
    fog = make(grid=(4, 1, 1), max_froxels=100)
    fog.set_camera("main", near=0.5, far=100.0)
    fog.reconstruct_depth(1, [0.5] * 4, width=2, height=2)
    out = fog.reproject(2, [(0.0, 0.0), (200.0, 0.0),
                            (-65.0, 0.0), (64.0, 0.0)])
    assert out["status"] == "reset"
    assert out["rejected"] == 2
    assert out["accepted"] == 2
    assert fog.history_state()["frames"] == 0


def test_snapshot_restore_roundtrip_and_version_guard():
    fog = make(grid=(4, 1, 1), max_froxels=100)
    prepare(fog)
    fog.add_light("key", intensity=2.0, position=(0.0, 0.0, 1.0),
                  radius=5.0)
    fog.inject_media("haze", density=0.2, height_falloff=0.5, extinction=1.0)
    fog.reproject(2, [(0.0, 0.0)] * 4)
    snap = fog.snapshot()
    fog.add_light("extra", intensity=1.0, position=(1.0, 0.0, 0.0),
                  radius=2.0)
    fog.restore(snap)
    assert fog.snapshot() == snap
    bad = dict(snap)
    bad["version"] = 999
    with pytest.raises(vf.FogError) as exc:
        fog.restore(bad)
    assert exc.value.code == "FOG_SNAPSHOT_VERSION"


def test_invalid_snapshot_restore_is_atomic():
    fog = make(grid=(4, 1, 1), max_froxels=100)
    fog.add_light("key", intensity=2.0, position=(0.0, 0.0, 1.0),
                  radius=5.0)
    fog.add_light("fill", intensity=1.0, position=(1.0, 0.0, 0.0),
                  radius=2.0)
    before = fog.stats()
    bad = fog.snapshot()
    del bad["lights"]
    with pytest.raises(vf.FogError) as exc:
        fog.restore(bad)
    assert exc.value.code == "FOG_SNAPSHOT_INVALID"
    assert fog.stats() == before


def test_concurrent_media_injection_is_thread_safe():
    fog = make(grid=(4, 1, 1), max_froxels=100)
    ids = ["media-%d" % index for index in range(16)]

    def inject(media_id):
        return fog.inject_media(media_id, density=0.1, height_falloff=0.0,
                                extinction=1.0)

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(inject, ids))
    assert fog.stats()["media"] == 16
