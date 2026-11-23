import json
import math
import threading

import pytest

import spatial_audio_guard as sag

EQ = math.cos(math.pi / 4)


def make(**kwargs):
    eng = sag.SpatialAudio(**kwargs)
    eng.add_listener("main")
    return eng


def test_source_directly_right_pans_hard_right():
    eng = make()
    eng.add_source("fx", position=(0.0, -2.0, 0.0))
    g = eng.pan_gains("main", "fx")
    assert g["pan"] == pytest.approx(1.0)
    assert g["distance"] == pytest.approx(2.0)
    assert g["attenuation"] == pytest.approx(0.5)
    assert g["gain_l"] == pytest.approx(0.0, abs=1e-6)
    assert g["gain_r"] == pytest.approx(0.5, abs=1e-6)


def test_front_source_uses_equal_power_split():
    eng = make()
    eng.add_source("fx", position=(1.0, 0.0, 0.0))
    g = eng.pan_gains("main", "fx")
    assert g["pan"] == pytest.approx(0.0, abs=1e-6)
    assert g["gain_l"] == pytest.approx(EQ, abs=1e-6)
    assert g["gain_r"] == pytest.approx(EQ, abs=1e-6)


def test_left_source_is_mirrored():
    eng = make()
    eng.add_source("fx", position=(0.0, 2.0, 0.0))
    g = eng.pan_gains("main", "fx")
    assert g["pan"] == pytest.approx(-1.0)
    assert g["attenuation"] == pytest.approx(0.5)
    assert g["gain_l"] == pytest.approx(0.5, abs=1e-6)
    assert g["gain_r"] == pytest.approx(0.0, abs=1e-6)


def test_listener_yaw_rotates_the_pan_frame():
    eng = make()
    eng.add_source("fx", position=(0.0, -2.0, 0.0))
    eng.update_listener("main", yaw=90.0)
    turned = eng.pan_gains("main", "fx")
    assert turned["pan"] == pytest.approx(0.0, abs=1e-6)
    assert turned["gain_l"] == pytest.approx(EQ * 0.5, abs=1e-6)
    assert turned["gain_r"] == pytest.approx(EQ * 0.5, abs=1e-6)
    eng.update_listener("main", yaw=180.0)
    behind = eng.pan_gains("main", "fx")
    assert behind["pan"] == pytest.approx(-1.0)
    assert behind["gain_l"] == pytest.approx(0.5, abs=1e-6)


def test_near_field_clamps_pan_to_half():
    eng = make()
    eng.add_source("fx", position=(0.0, -0.25, 0.0))
    g = eng.pan_gains("main", "fx")
    assert g["pan"] == pytest.approx(0.5)
    assert g["attenuation"] == pytest.approx(1.0)
    assert g["gain_l"] == pytest.approx(math.cos(0.375 * math.pi), abs=1e-6)
    assert g["gain_r"] == pytest.approx(math.sin(0.375 * math.pi), abs=1e-6)


def test_inverse_distance_attenuation_and_max_distance_cutoff():
    eng = make()
    eng.add_source("fx", position=(4.0, 0.0, 0.0))
    g = eng.pan_gains("main", "fx")
    assert g["attenuation"] == pytest.approx(0.25)
    assert g["gain_l"] == pytest.approx(EQ * 0.25, abs=1e-6)
    env = eng.set_environment(max_distance=3.0)
    assert env["max_distance"] == pytest.approx(3.0)
    silent = eng.pan_gains("main", "fx")
    assert silent["attenuation"] == pytest.approx(0.0)
    assert silent["gain_l"] == pytest.approx(0.0)
    eng.set_environment(ref_distance=2.0)
    assert eng.pan_gains("main", "fx")["attenuation"] == pytest.approx(0.5)


def test_source_capacity_evicts_lowest_priority():
    eng = make(max_sources=2)
    eng.add_source("a", priority=0)
    eng.add_source("b", priority=0)
    added = eng.add_source("c", priority=5)
    assert added["evicted"] == "a"
    assert [row["id"] for row in eng.sources()] == ["b", "c"]
    assert eng.stats()["evictions"] == 1
    with pytest.raises(sag.SpatialAudioError) as exc:
        eng.add_source("d", priority=0)
    assert exc.value.code == "SPA_SOURCE_LIMIT"


def test_duplicate_and_missing_source_errors():
    eng = make()
    eng.add_source("fx")
    with pytest.raises(sag.SpatialAudioError) as exc:
        eng.add_source("fx")
    assert exc.value.code == "SPA_SOURCE_EXISTS"
    assert eng.remove_source("ghost") is False
    with pytest.raises(sag.SpatialAudioError) as exc:
        eng.move_source("ghost", (0.0, 0.0, 0.0))
    assert exc.value.code == "SPA_SOURCE_UNKNOWN"


def test_batch_move_is_rejected_atomically_on_unknown_source():
    eng = make()
    eng.add_source("a", position=(1.0, 0.0, 0.0))
    eng.add_source("b", position=(2.0, 0.0, 0.0))
    with pytest.raises(sag.SpatialAudioError) as exc:
        eng.move_batch([
            {"source": "a", "position": (0.0, -1.0, 0.0), "sequence": 2},
            {"source": "ghost", "position": (0.0, 0.0, 0.0)},
        ])
    assert exc.value.code == "SPA_SOURCE_UNKNOWN"
    positions = {row["id"]: row["position"] for row in eng.sources()}
    assert positions["a"] == [1.0, 0.0, 0.0]
    assert positions["b"] == [2.0, 0.0, 0.0]
    assert eng.stats()["moves"] == 0


def test_stale_sequence_move_is_ignored_and_batch_continues():
    eng = make()
    eng.add_source("a", position=(1.0, 0.0, 0.0))
    applied = eng.move_source("a", (0.0, -1.0, 0.0), sequence=5)
    assert applied["status"] == "applied"
    stale = eng.move_source("a", (0.0, 1.0, 0.0), sequence=4)
    assert stale["status"] == "ignored"
    assert stale["code"] == "SPA_SEQUENCE_STALE"
    assert eng.pan_gains("main", "a")["pan"] == pytest.approx(1.0)
    results = eng.move_batch([
        {"source": "a", "position": (0.0, 1.0, 0.0), "sequence": 3},
        {"source": "a", "position": (0.0, 1.0, 0.0), "sequence": 6},
    ])
    assert [row["status"] for row in results] == ["ignored", "applied"]
    assert eng.pan_gains("main", "a")["pan"] == pytest.approx(-1.0)


def test_snapshot_restore_roundtrip_through_json():
    eng = make()
    eng.add_source("a", position=(1.0, 0.0, 0.0))
    eng.add_source("b", position=(0.0, -2.0, 0.0), gain=0.5)
    baseline = eng.pan_gains("main", "b")
    snap = json.loads(json.dumps(eng.snapshot()))
    eng.move_source("a", (0.0, 3.0, 0.0), sequence=1)
    eng.remove_source("b")
    eng.add_source("c", position=(2.0, 0.0, 0.0))
    eng.restore(snap)
    assert [row["id"] for row in eng.sources()] == ["a", "b"]
    restored = eng.pan_gains("main", "b")
    for key in ("gain_l", "gain_r", "pan", "distance", "attenuation"):
        assert restored[key] == pytest.approx(baseline[key])
    assert eng.stats()["moves"] == 0


def test_mix_reports_totals_and_counts_sources():
    eng = make()
    eng.add_source("a", position=(1.0, 0.0, 0.0))
    eng.add_source("b", position=(0.0, -1.0, 0.0), gain=0.5)
    mixed = eng.mix("main")
    assert mixed["count"] == 2
    assert [row["id"] for row in mixed["sources"]] == ["a", "b"]
    assert mixed["gain_l"] == pytest.approx(EQ, abs=1e-6)
    assert mixed["gain_r"] == pytest.approx(EQ + 0.5, abs=1e-6)
    first = eng.stats()["mix_calls"]
    eng.mix("main")
    assert eng.stats()["mix_calls"] == first + 1


def test_listener_capacity_and_unknown_listener():
    eng = sag.SpatialAudio(max_listeners=2)
    eng.add_listener("one")
    eng.add_listener("two")
    with pytest.raises(sag.SpatialAudioError) as exc:
        eng.add_listener("three")
    assert exc.value.code == "SPA_LISTENER_LIMIT"
    with pytest.raises(sag.SpatialAudioError) as exc:
        eng.mix("ghost")
    assert exc.value.code == "SPA_LISTENER_UNKNOWN"
    assert eng.remove_listener("two") is True
    eng.add_listener("three")
    assert [row["id"] for row in eng.listeners()] == ["one", "three"]


def test_concurrent_moves_keep_state_consistent():
    eng = make(max_sources=8)
    for i in range(8):
        eng.add_source("s%d" % i, position=(1.0, 0.0, 0.0))
    errors = []

    def worker(index):
        try:
            for step in range(50):
                x = float((step + index) % 3) + 1.0
                eng.move_source("s%d" % index, (x, 0.0, 0.0))
        except BaseException as exc:  # pragma: no cover - failure path
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for thread in threads:
        thread.start()
    for _ in range(20):
        mixed = eng.mix("main")
        assert mixed["count"] == 8
        for row in mixed["sources"]:
            assert 0.0 <= row["gain_l"] <= 1.0
            assert 0.0 <= row["gain_r"] <= 1.0
    for thread in threads:
        thread.join()
    assert errors == []
    stats = eng.stats()
    assert stats["moves"] == 400
    assert stats["mix_calls"] == 20
    assert stats["sources"] == 8


def test_concurrent_adds_never_exceed_source_capacity():
    eng = make(max_sources=8)
    added = []
    rejected = []
    lock = threading.Lock()

    def worker(index):
        try:
            result = eng.add_source("c%02d" % index)
        except sag.SpatialAudioError as exc:
            with lock:
                rejected.append(exc.code)
        else:
            with lock:
                added.append(result["id"])

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(added) == 8
    assert len(set(added)) == 8
    assert rejected == ["SPA_SOURCE_LIMIT"] * 12
    assert eng.stats()["sources"] == 8
