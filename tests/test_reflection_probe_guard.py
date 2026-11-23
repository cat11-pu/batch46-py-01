from concurrent.futures import ThreadPoolExecutor

import pytest

import reflection_probe_guard as rpg


def capture_full(probes, probe_id, frame, checksum="final"):
    probes.request_capture(probe_id, frame=frame)
    probes.dispatch(frame)
    for face in rpg.FACES:
        probes.capture_face(probe_id, face, frame,
                            checksum="%s-%s" % (checksum, face))
    return probes.complete_capture(probe_id, frame=frame,
                                   checksum=checksum)


def test_register_validates_radius_and_duplicate_id():
    probes = rpg.ReflectionProbe()
    with pytest.raises(rpg.ReflectionProbeError) as exc:
        probes.register_probe("a", position=(0.0, 0.0, 0.0), radius=0.0)
    assert exc.value.code == "RP_INVALID_PROBE"
    probes.register_probe("a", position=(0.0, 0.0, 0.0), radius=5.0)
    with pytest.raises(rpg.ReflectionProbeError) as exc:
        probes.register_probe("a", position=(1.0, 0.0, 0.0), radius=5.0)
    assert exc.value.code == "RP_DUPLICATE_PROBE"


def test_probe_limit_enforced():
    probes = rpg.ReflectionProbe(max_probes=2)
    probes.register_probe("a", position=(0.0, 0.0, 0.0), radius=5.0)
    probes.register_probe("b", position=(1.0, 0.0, 0.0), radius=5.0)
    with pytest.raises(rpg.ReflectionProbeError) as exc:
        probes.register_probe("c", position=(2.0, 0.0, 0.0), radius=5.0)
    assert exc.value.code == "RP_PROBE_LIMIT"
    assert probes.stats()["probes"] == 2


def test_mip_chain_sizes_and_config_validation():
    probes = rpg.ReflectionProbe(face_size=128, mip_levels=6)
    assert probes.mip_sizes() == [128, 64, 32, 16, 8, 4]
    small = rpg.ReflectionProbe(face_size=4, mip_levels=3)
    assert small.mip_sizes() == [4, 2, 1]
    with pytest.raises(rpg.ReflectionProbeError) as exc:
        rpg.ReflectionProbe(face_size=100)
    assert exc.value.code == "RP_INVALID_CONFIG"
    with pytest.raises(rpg.ReflectionProbeError) as exc:
        rpg.ReflectionProbe(face_size=128, mip_levels=9)
    assert exc.value.code == "RP_INVALID_CONFIG"


def test_request_capture_validates_probe_and_dedupes():
    probes = rpg.ReflectionProbe()
    probes.register_probe("p", position=(0.0, 0.0, 0.0), radius=5.0)
    first = probes.request_capture("p", frame=1)
    assert first["status"] == "queued"
    with pytest.raises(rpg.ReflectionProbeError) as exc:
        probes.request_capture("missing", frame=1)
    assert exc.value.code == "RP_UNKNOWN_PROBE"
    duplicate = probes.request_capture("p", frame=1)
    assert duplicate["status"] == "ignored"
    assert duplicate["code"] == "RP_ALREADY_PENDING"
    assert len(probes.pending_captures()) == 1


def test_static_probe_skips_automatic_capture():
    probes = rpg.ReflectionProbe()
    probes.register_probe("s", position=(0.0, 0.0, 0.0), radius=5.0,
                          static=True)
    automatic = probes.request_capture("s", frame=1, reason="auto")
    assert automatic["status"] == "ignored"
    assert automatic["code"] == "RP_STATIC_PROBE"
    assert probes.pending_captures() == []
    manual = probes.request_capture("s", frame=1, reason="manual")
    assert manual["status"] == "queued"


def test_pending_order_priority_then_sequence():
    probes = rpg.ReflectionProbe()
    probes.register_probe("p1", position=(0.0, 0.0, 0.0), radius=5.0,
                          priority=1)
    probes.register_probe("p2", position=(1.0, 0.0, 0.0), radius=5.0,
                          priority=5)
    probes.register_probe("p3", position=(2.0, 0.0, 0.0), radius=5.0,
                          priority=5)
    for probe_id in ("p1", "p2", "p3"):
        probes.request_capture(probe_id, frame=1)
    ids = [row["probe_id"] for row in probes.pending_captures()]
    assert ids == ["p2", "p3", "p1"]


def test_dispatch_respects_frame_budget():
    probes = rpg.ReflectionProbe(frame_budget=2)
    priorities = {"p1": 0, "p2": 9, "p3": 8, "p4": 7, "p5": 6}
    for probe_id, priority in priorities.items():
        probes.register_probe(probe_id, position=(0.0, 0.0, 0.0),
                              radius=5.0, priority=priority)
    for probe_id in priorities:
        probes.request_capture(probe_id, frame=1)
    out = probes.dispatch(1)
    assert out["started"] == ["p2", "p3"]
    assert out["deferred"] == 3
    cached = probes.dispatch(1)
    assert cached["status"] == "cached"
    assert cached["started"] == ["p2", "p3"]
    second = probes.dispatch(2)
    assert second["started"] == ["p4", "p5"]
    assert second["deferred"] == 0
    assert probes.stats()["requests"] == 5


def test_capture_faces_reject_duplicates_and_unknown_faces():
    probes = rpg.ReflectionProbe()
    probes.register_probe("p", position=(0.0, 0.0, 0.0), radius=5.0)
    probes.request_capture("p", frame=1)
    probes.dispatch(1)
    assert probes.capture_face("p", "px", 1, checksum="a")["status"] == \
        "applied"
    with pytest.raises(rpg.ReflectionProbeError) as exc:
        probes.capture_face("p", "px", 1, checksum="b")
    assert exc.value.code == "RP_DUP_FACE"
    with pytest.raises(rpg.ReflectionProbeError) as exc:
        probes.capture_face("p", "zz", 1, checksum="c")
    assert exc.value.code == "RP_INVALID_FACE"


def test_complete_requires_all_six_faces():
    probes = rpg.ReflectionProbe()
    probes.register_probe("p", position=(0.0, 0.0, 0.0), radius=5.0)
    probes.request_capture("p", frame=1)
    probes.dispatch(1)
    for face in rpg.FACES[:5]:
        probes.capture_face("p", face, 1, checksum="part-" + face)
    with pytest.raises(rpg.ReflectionProbeError) as exc:
        probes.complete_capture("p", frame=1, checksum="done")
    assert exc.value.code == "RP_INCOMPLETE_FACES"
    probes.capture_face("p", rpg.FACES[5], 1, checksum="part-nz")
    out = probes.complete_capture("p", frame=1, checksum="done")
    assert out["status"] == "complete"
    assert probes.probe_state("p")["checksum"] == "done"
    assert probes.stats()["captures"] == 1


def test_complete_rejects_frame_mismatch():
    probes = rpg.ReflectionProbe()
    probes.register_probe("p", position=(0.0, 0.0, 0.0), radius=5.0)
    probes.request_capture("p", frame=1)
    probes.dispatch(1)
    for face in rpg.FACES:
        probes.capture_face("p", face, 1, checksum="part-" + face)
    with pytest.raises(rpg.ReflectionProbeError) as exc:
        probes.complete_capture("p", frame=2, checksum="done")
    assert exc.value.code == "RP_STALE_FRAME"
    assert probes.complete_capture("p", frame=1,
                                   checksum="done")["status"] == "complete"


def test_abort_capture_rolls_back_to_previous_checksum():
    probes = rpg.ReflectionProbe()
    probes.register_probe("p", position=(0.0, 0.0, 0.0), radius=5.0)
    capture_full(probes, "p", 1, checksum="old-final")
    probes.request_capture("p", frame=2)
    probes.dispatch(2)
    probes.capture_face("p", "px", 2, checksum="new-px")
    out = probes.abort_capture("p", frame=2)
    assert out["status"] == "aborted"
    state = probes.probe_state("p")
    assert state["checksum"] == "old-final"
    assert state["faces"] == []
    assert probes.stats()["captures"] == 1


def test_resolve_picks_nearest_valid_probe():
    probes = rpg.ReflectionProbe()
    probes.register_probe("near", position=(0.0, 0.0, 0.0), radius=5.0)
    probes.register_probe("far", position=(0.0, 0.0, 10.0), radius=5.0)
    capture_full(probes, "near", 1, checksum="near-checksum")
    capture_full(probes, "far", 2, checksum="far-checksum")
    assert probes.resolve((0.0, 0.0, 1.0))["probe_id"] == "near"
    assert probes.resolve((0.0, 0.0, 8.0))["probe_id"] == "far"


def test_resolve_outside_every_radius_raises():
    probes = rpg.ReflectionProbe()
    probes.register_probe("p", position=(0.0, 0.0, 0.0), radius=5.0)
    capture_full(probes, "p", 1, checksum="p-checksum")
    with pytest.raises(rpg.ReflectionProbeError) as exc:
        probes.resolve((100.0, 0.0, 0.0))
    assert exc.value.code == "RP_NO_PROBE"


def test_snapshot_restore_preserves_partial_capture_state():
    probes = rpg.ReflectionProbe()
    probes.register_probe("p1", position=(0.0, 0.0, 0.0), radius=5.0)
    probes.register_probe("p2", position=(1.0, 0.0, 0.0), radius=5.0)
    probes.request_capture("p1", frame=1)
    probes.request_capture("p2", frame=1)
    probes.dispatch(1)
    probes.capture_face("p1", "px", 1, checksum="one")
    probes.capture_face("p1", "nx", 1, checksum="two")
    snap = probes.snapshot()
    probes.capture_face("p1", "py", 1, checksum="three")
    probes.restore(snap)
    assert probes.snapshot() == snap
    bad = dict(snap)
    bad["version"] = 77
    with pytest.raises(rpg.ReflectionProbeError) as exc:
        probes.restore(bad)
    assert exc.value.code == "RP_SNAPSHOT_VERSION"
    before = probes.stats()
    broken = dict(snap)
    del broken["probes"]
    with pytest.raises(rpg.ReflectionProbeError) as exc:
        probes.restore(broken)
    assert exc.value.code == "RP_SNAPSHOT_INVALID"
    assert probes.stats() == before


def test_concurrent_requests_get_unique_sequence():
    probes = rpg.ReflectionProbe(max_probes=64)
    ids = ["probe-%02d" % index for index in range(50)]
    for probe_id in ids:
        probes.register_probe(probe_id, position=(0.0, 0.0, 0.0),
                              radius=5.0)
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(
            lambda probe_id: probes.request_capture(probe_id, frame=1), ids
        ))
    assert probes.stats()["requests"] == 50
    sequence = sorted(row["seq"] for row in probes.pending_captures())
    assert sequence == list(range(1, 51))
