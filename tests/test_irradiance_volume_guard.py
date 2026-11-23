from concurrent.futures import ThreadPoolExecutor

import pytest

import irradiance_volume_guard as ivg


SH9 = tuple(float(index) for index in range(9))


def filled_volume(**kwargs):
    return ivg.IrradianceVolume(dims=(4, 4, 4), **kwargs)


def test_constructor_validates_dims_and_volume_budget():
    with pytest.raises(ivg.IrradianceVolumeError) as exc:
        ivg.IrradianceVolume(dims=(0, 4, 4))
    assert exc.value.code == "IR_INVALID_CONFIG"
    with pytest.raises(ivg.IrradianceVolumeError) as exc:
        ivg.IrradianceVolume(dims=(256, 256, 16))
    assert exc.value.code == "IR_INVALID_CONFIG"


def test_voxel_size_and_update_budget_validation():
    with pytest.raises(ivg.IrradianceVolumeError) as exc:
        ivg.IrradianceVolume(voxel_size=0.0)
    assert exc.value.code == "IR_INVALID_CONFIG"
    with pytest.raises(ivg.IrradianceVolumeError) as exc:
        ivg.IrradianceVolume(max_updates_per_frame=0)
    assert exc.value.code == "IR_INVALID_CONFIG"


def test_set_voxel_index_range_and_sh_length():
    volume = filled_volume()
    with pytest.raises(ivg.IrradianceVolumeError) as exc:
        volume.set_voxel((4, 0, 0), sh=SH9)
    assert exc.value.code == "IR_INDEX_RANGE"
    with pytest.raises(ivg.IrradianceVolumeError) as exc:
        volume.set_voxel((0, 0, 0), sh=(0.0, 1.0, 2.0))
    assert exc.value.code == "IR_INVALID_VOXEL"


def test_set_voxel_marks_dirty_once_per_coordinate():
    volume = filled_volume()
    volume.set_voxel((1, 1, 1), sh=SH9)
    first = volume.stats()
    assert first["dirty"] == 1
    assert first["voxels"] == 1
    volume.set_voxel((1, 1, 1), sh=(0.5,) * 9)
    second = volume.stats()
    assert second["dirty"] == 1
    assert second["voxels"] == 1
    assert second["generation"] == 0


def test_mark_dirty_clamps_box_to_volume_bounds():
    volume = filled_volume()
    out = volume.mark_dirty((-5, -5, -5, 1, 1, 1))
    assert out["added"] == 8
    assert out["clamped"] is True
    assert volume.stats()["dirty"] == 8


def test_mark_dirty_rejects_inverted_box():
    volume = filled_volume()
    with pytest.raises(ivg.IrradianceVolumeError) as exc:
        volume.mark_dirty((2, 0, 0, 1, 0, 0))
    assert exc.value.code == "IR_INVALID_BOX"


def test_update_processes_budget_in_lexicographic_order():
    volume = filled_volume(max_updates_per_frame=4)
    coords = [
        (0, 0, 0), (0, 0, 1), (0, 0, 2), (0, 0, 3),
        (0, 1, 0), (0, 1, 1), (0, 1, 2), (0, 1, 3),
        (1, 0, 0), (1, 0, 1),
    ]
    for coord in coords:
        volume.set_voxel(coord, sh=SH9)
    first = volume.update(1)
    assert first["processed"] == 4
    assert first["remaining"] == 6
    assert first["generation"] == 1
    second = volume.update(2)
    assert second["processed"] == 4
    assert second["remaining"] == 2
    assert second["generation"] == 2
    third = volume.update(3)
    assert third["processed"] == 2
    assert third["remaining"] == 0
    assert third["generation"] == 3
    fourth = volume.update(4)
    assert fourth["status"] == "noop"
    assert fourth["processed"] == 0
    assert volume.generation() == 3
    assert volume.stats()["dirty"] == 0


def test_update_duplicate_frame_is_ignored_and_stale_frame_raises():
    volume = filled_volume()
    volume.set_voxel((0, 0, 0), sh=SH9)
    assert volume.update(1)["status"] == "applied"
    duplicate = volume.update(1)
    assert duplicate["status"] == "ignored"
    assert duplicate["code"] == "IR_DUP_FRAME"
    assert volume.generation() == 1
    with pytest.raises(ivg.IrradianceVolumeError) as exc:
        volume.update(0)
    assert exc.value.code == "IR_STALE_FRAME"


def test_freeze_blocks_content_edits_until_unfreeze():
    volume = filled_volume()
    volume.freeze()
    for action in (
        lambda: volume.set_voxel((0, 0, 0), sh=SH9),
        lambda: volume.mark_dirty((0, 0, 0, 1, 1, 1)),
        lambda: volume.clear(),
    ):
        with pytest.raises(ivg.IrradianceVolumeError) as exc:
            action()
        assert exc.value.code == "IR_FROZEN"
    volume.unfreeze()
    volume.set_voxel((0, 0, 0), sh=SH9)
    assert volume.stats()["voxels"] == 1


def test_sample_uses_trilinear_weights():
    volume = ivg.IrradianceVolume(dims=(2, 2, 2), voxel_size=1.0)
    volume.set_voxel((0, 0, 0), sh=(8.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
                                    0.0))
    out = volume.sample((1.0, 1.0, 1.0))
    assert out["clamped"] is False
    assert out["cell"] == (0, 0, 0)
    assert len(out["weights"]) == 8
    assert all(weight == pytest.approx(0.125) for weight in out["weights"])
    assert sum(out["weights"]) == pytest.approx(1.0)
    assert out["sh"][0] == pytest.approx(1.0)
    assert out["sh"][1] == pytest.approx(0.0)


def test_sample_clamps_positions_outside_bounds():
    volume = filled_volume(voxel_size=2.0)
    out = volume.sample((-10.0, 100.0, 1.0))
    assert out["clamped"] is True
    assert out["cell"] == (0, 2, 0)
    assert sum(out["weights"]) == pytest.approx(1.0)


def test_sample_of_empty_volume_returns_zero_coefficients():
    volume = filled_volume()
    out = volume.sample((0.5, 0.5, 0.5))
    assert out["clamped"] is False
    assert out["sh"] == (0.0,) * 9
    assert sum(out["weights"]) == pytest.approx(1.0)


def test_clear_resets_content_and_bumps_generation():
    volume = filled_volume()
    volume.set_voxel((0, 0, 0), sh=SH9)
    volume.update(1)
    assert volume.generation() == 1
    out = volume.clear()
    assert out["status"] == "applied"
    assert out["generation"] == 2
    stats = volume.stats()
    assert stats["voxels"] == 0
    assert stats["dirty"] == 0
    assert stats["generation"] == 2


def test_snapshot_restore_roundtrip_and_validation():
    volume = filled_volume()
    volume.set_voxel((0, 0, 0), sh=SH9)
    volume.set_voxel((1, 1, 1), sh=(1.0,) * 9)
    volume.mark_dirty((0, 0, 0, 2, 2, 2))
    volume.update(1)
    snap = volume.snapshot()
    volume.set_voxel((3, 3, 3), sh=(9.0,) * 9)
    volume.update(2)
    volume.restore(snap)
    assert volume.snapshot() == snap
    bad = dict(snap)
    bad["version"] = 5
    with pytest.raises(ivg.IrradianceVolumeError) as exc:
        volume.restore(bad)
    assert exc.value.code == "IR_SNAPSHOT_VERSION"
    before = volume.stats()
    broken = dict(snap)
    del broken["values"]
    with pytest.raises(ivg.IrradianceVolumeError) as exc:
        volume.restore(broken)
    assert exc.value.code == "IR_SNAPSHOT_INVALID"
    assert volume.stats() == before


def test_concurrent_voxel_writes_are_counted_exactly():
    volume = ivg.IrradianceVolume(dims=(16, 16, 4), max_updates_per_frame=64)
    coords = [(index % 16, index // 16, index % 4) for index in range(64)]
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(
            lambda coord: volume.set_voxel(coord, sh=SH9), coords
        ))
    stats = volume.stats()
    assert stats["voxels"] == 64
    assert stats["dirty"] == 64
