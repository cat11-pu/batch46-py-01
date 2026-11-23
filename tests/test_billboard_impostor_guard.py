import json
import threading

import pytest

import billboard_impostor_guard as imp


BOUNDS = (0.0, 0.0, 0.0, 1.0, 2.0, 1.0)


def make(**kwargs):
    return imp.ImpostorGuard(**kwargs)


def mesh(a, mesh_id="tree"):
    return a.register_mesh(mesh_id, bounds=BOUNDS, vertex_count=120,
                           material="foliage")


def bake(a, mesh_id="tree", view=0, samples=None):
    if samples is None:
        samples = [(0.5, 0.5, 1.0)]
    return a.bake(mesh_id, view, samples=samples)


def test_register_mesh_validation_and_duplicate():
    a = make()
    out = a.register_mesh("rock", bounds=(0, 0, 0, 1, 1, 1), vertex_count=12)
    assert out["status"] == "registered"
    again = a.register_mesh("rock", bounds=(0, 0, 0, 1, 1, 1), vertex_count=12)
    assert again["status"] == "unchanged"
    with pytest.raises(imp.ImpostorError) as exc:
        a.register_mesh("rock", bounds=(0, 0, 0, 2, 2, 2), vertex_count=12)
    assert exc.value.code == "IMP_DUP_MESH"
    with pytest.raises(imp.ImpostorError) as exc:
        a.register_mesh("flat", bounds=(0, 0, 0, 0, 0, 0), vertex_count=12)
    assert exc.value.code == "IMP_BAD_MESH"
    with pytest.raises(imp.ImpostorError) as exc:
        a.register_mesh("rock", bounds=(0, 0, 0, 1, 1, 1), vertex_count=0)
    assert exc.value.code == "IMP_BAD_MESH"
    assert a.stats()["meshes"] == 1


def test_bake_computes_alpha_silhouette():
    a = make()
    mesh(a)
    out = bake(a, samples=[
        (0.1, 0.2, 0.9),
        (0.5, 0.6, 0.5),
        (0.8, 0.9, 0.1),
        (0.4, 0.4, 0.4),
    ])
    assert out["status"] == "baked"
    assert out["silhouette"] == {"u0": 0.1, "v0": 0.2, "u1": 0.5,
                                 "v1": 0.6, "coverage": 0.5}
    assert a.silhouette("tree", 0) == out["silhouette"]


def test_bake_validates_view_samples_and_mesh():
    a = make(view_count=8)
    with pytest.raises(imp.ImpostorError) as exc:
        bake(a, mesh_id="ghost")
    assert exc.value.code == "IMP_UNKNOWN_MESH"
    mesh(a)
    with pytest.raises(imp.ImpostorError) as exc:
        bake(a, view=8)
    assert exc.value.code == "IMP_BAD_VIEW"
    with pytest.raises(imp.ImpostorError) as exc:
        a.bake("tree", 0, samples=[])
    assert exc.value.code == "IMP_BAD_SAMPLES"
    with pytest.raises(imp.ImpostorError) as exc:
        a.bake("tree", 0, samples=[(1.2, 0.0, 0.5)])
    assert exc.value.code == "IMP_BAD_SAMPLES"
    with pytest.raises(imp.ImpostorError) as exc:
        a.bake("tree", 0, samples=[(0.5, 0.5, 0.5)], alpha_cutoff=1.5)
    assert exc.value.code == "IMP_BAD_SAMPLES"


def test_view_index_quantizes_yaw():
    a = make(view_count=8)
    assert [a.view_index(yaw) for yaw in (0, 22.5, 44.9, 200, -10, 360)] == [
        0, 1, 1, 4, 0, 0]
    with pytest.raises(imp.ImpostorError) as exc:
        a.view_index("north")
    assert exc.value.code == "IMP_BAD_VIEW"


def test_best_view_and_select_view_hysteresis():
    a = make(view_count=8, hysteresis_ratio=0.1)
    mesh(a)
    assert a.best_view("tree", 30) == 1
    first = a.select_view("tree", 0)
    assert first["view"] == 0
    assert first["switched"] is True
    assert first["reason"] == "initial"
    kept = a.select_view("tree", 30)
    assert kept["view"] == 0
    assert kept["switched"] is False
    assert kept["reason"] == "kept"
    moved = a.select_view("tree", 60)
    assert moved["view"] == 1
    assert moved["switched"] is True
    hold = a.select_view("tree", 30)
    assert hold["view"] == 1
    assert hold["switched"] is False
    back = a.select_view("tree", 10)
    assert back["view"] == 0
    assert back["switched"] is True
    assert a.stats()["view_switches"] == 2


def test_lod_uses_distance_thresholds_with_hysteresis():
    a = make(hysteresis_ratio=0.2)
    mesh(a)
    assert a.lod_for("tree", 5.0) == {"lod": 0, "changed": True}
    assert a.lod_for("tree", 10.5) == {"lod": 0, "changed": False}
    assert a.lod_for("tree", 13.0) == {"lod": 1, "changed": True}
    assert a.lod_for("tree", 9.5) == {"lod": 1, "changed": False}
    assert a.lod_for("tree", 7.5) == {"lod": 0, "changed": True}
    assert a.lod_for("tree", 7.5) == {"lod": 0, "changed": False}
    assert a.stats()["lod_switches"] == 2
    with pytest.raises(imp.ImpostorError) as exc:
        a.lod_for("tree", -1)
    assert exc.value.code == "IMP_BAD_DISTANCE"
    with pytest.raises(imp.ImpostorError) as exc:
        a.lod_for("ghost", 1)
    assert exc.value.code == "IMP_UNKNOWN_MESH"


def test_atlas_cell_layout_and_unbaked_errors():
    a = make(view_count=4, atlas_size=256, cell_size=128)
    mesh(a)
    with pytest.raises(imp.ImpostorError) as exc:
        a.atlas_cell("tree", 0)
    assert exc.value.code == "IMP_NOT_BAKED"
    for view in range(4):
        bake(a, view=view)
    assert a.atlas_cell("tree", 0) == {"index": 0, "x": 0, "y": 0, "size": 128}
    assert a.atlas_cell("tree", 1) == {"index": 1, "x": 128, "y": 0, "size": 128}
    assert a.atlas_cell("tree", 2) == {"index": 2, "x": 0, "y": 128, "size": 128}
    assert a.stats()["cells"] == 4


def test_rebake_replaces_cell_without_growing_atlas():
    a = make()
    mesh(a)
    first = bake(a, samples=[(0.2, 0.2, 1.0)])
    index = first["cell"]
    again = bake(a, samples=[(0.4, 0.4, 0.9), (0.6, 0.6, 0.8)])
    assert again["status"] == "rebaked"
    assert again["cell"] == index
    assert a.stats()["cells"] == 1
    assert a.stats()["bakes"] == 2
    assert a.silhouette("tree", 0)["u0"] == 0.4
    assert a.silhouette("tree", 0)["coverage"] == 1.0


def test_atlas_full_rejects_new_cell():
    a = make(view_count=4, atlas_size=128, cell_size=128)
    mesh(a)
    bake(a, view=0)
    with pytest.raises(imp.ImpostorError) as exc:
        bake(a, view=1)
    assert exc.value.code == "IMP_ATLAS_FULL"
    assert a.stats()["cells"] == 1
    assert a.stats()["evictions"] == 0


def test_evict_releases_least_recently_used_cells():
    a = make(view_count=4, atlas_size=256, cell_size=128)
    mesh(a)
    bake(a, view=0)
    bake(a, view=1)
    bake(a, view=2)
    a.silhouette("tree", 0)
    removed = a.evict(2)
    assert removed == [{"mesh": "tree", "view": 1},
                       {"mesh": "tree", "view": 2}]
    assert a.stats()["cells"] == 1
    assert a.stats()["evictions"] == 2
    with pytest.raises(imp.ImpostorError) as exc:
        a.silhouette("tree", 1)
    assert exc.value.code == "IMP_NOT_BAKED"


def test_memory_budget_rejects_cell_allocation():
    a = make(atlas_size=256, cell_size=128, memory_budget=65536)
    mesh(a)
    out = bake(a)
    assert out["bytes"] == 65536
    assert a.memory_usage() == 65536
    with pytest.raises(imp.ImpostorError) as exc:
        bake(a, view=1)
    assert exc.value.code == "IMP_MEMORY_BUDGET"
    assert a.stats()["cells"] == 1
    rebaked = bake(a, view=0, samples=[(0.3, 0.3, 1.0)])
    assert rebaked["status"] == "rebaked"
    assert a.memory_usage() == 65536


def test_snapshot_restore_round_trips_through_json():
    a = make()
    mesh(a)
    bake(a, view=0)
    bake(a, view=1, samples=[(0.2, 0.2, 1.0), (0.9, 0.9, 0.8)])
    a.select_view("tree", 0)
    a.lod_for("tree", 5.0)
    snap = json.loads(json.dumps(a.snapshot()))
    b = make()
    out = b.restore(snap)
    assert out["meshes"] == 1
    assert out["cells"] == 2
    assert b.stats() == a.stats()
    assert b.silhouette("tree", 1) == a.silhouette("tree", 1)
    assert b.select_view("tree", 60) == a.select_view("tree", 60)
    assert b.lod_for("tree", 40) == a.lod_for("tree", 40)
    assert b.stats() == a.stats()


def test_invalid_snapshot_is_rejected_without_mutating():
    a = make()
    mesh(a)
    bake(a)
    before = a.stats()
    with pytest.raises(imp.ImpostorError) as exc:
        a.restore({"version": 5})
    assert exc.value.code == "IMP_SNAPSHOT_INVALID"
    broken = a.snapshot()
    broken["cells"][0]["index"] = broken["config"]["atlas_size"]
    with pytest.raises(imp.ImpostorError) as exc:
        a.restore(broken)
    assert exc.value.code == "IMP_SNAPSHOT_INVALID"
    assert a.stats() == before
    assert a.silhouette("tree", 0)["coverage"] == 1.0


def test_concurrent_bakes_allocate_unique_cells():
    a = make(view_count=8, atlas_size=1024, cell_size=128)
    for index in range(8):
        a.register_mesh(f"m{index}", bounds=BOUNDS, vertex_count=10)

    def worker(index):
        for view in range(8):
            a.bake(f"m{index}", view, samples=[(0.5, 0.5, 1.0)])

    threads = [threading.Thread(target=worker, args=(index,)) for index in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert a.stats()["cells"] == 64
    assert a.stats()["bakes"] == 64
    indices = {a.atlas_cell(f"m{index}", view)["index"]
               for index in range(8) for view in range(8)}
    assert len(indices) == 64


def test_reset_clears_meshes_cells_and_state():
    a = make()
    mesh(a)
    bake(a)
    a.select_view("tree", 10)
    a.lod_for("tree", 5.0)
    assert a.reset() == 1
    assert a.stats()["meshes"] == 0
    assert a.stats()["cells"] == 0
    assert a.memory_usage() == 0
    with pytest.raises(imp.ImpostorError) as exc:
        a.atlas_cell("tree", 0)
    assert exc.value.code == "IMP_UNKNOWN_MESH"
