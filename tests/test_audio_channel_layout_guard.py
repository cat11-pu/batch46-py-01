import math
import threading

import pytest

import audio_channel_layout_guard as acl


def make(**kwargs):
    return acl.ChannelLayout(**kwargs)


def test_builtin_layouts_and_unknown_lookup():
    p = make()
    assert p.channels("mono") == ("C",)
    assert p.channels("stereo") == ("L", "R")
    assert p.channels("5.1") == ("L", "R", "C", "LFE", "Ls", "Rs")
    assert p.channels("7.1") == ("L", "R", "C", "LFE", "Ls", "Rs", "Lb", "Rb")
    assert set(p.layouts()) >= {"mono", "stereo", "quad", "5.1", "7.1"}
    with pytest.raises(acl.LayoutError) as exc:
        p.channels("ghost")
    assert exc.value.code == "LAYOUT_UNKNOWN"


def test_define_validates_name_and_channels():
    p = make()
    with pytest.raises(acl.LayoutError) as exc:
        p.define("stereo", ["L", "R"])
    assert exc.value.code == "LAYOUT_DUP"
    with pytest.raises(acl.LayoutError) as exc:
        p.define("bad", ["L", "X"])
    assert exc.value.code == "LAYOUT_UNKNOWN_CHANNEL"
    with pytest.raises(acl.LayoutError) as exc:
        p.define("dupchan", ["L", "L"])
    assert exc.value.code == "LAYOUT_DUP_CHANNEL"
    with pytest.raises(acl.LayoutError) as exc:
        p.define("empty", [])
    assert exc.value.code == "LAYOUT_BAD"
    with pytest.raises(acl.LayoutError) as exc:
        p.define("", ["L"])
    assert exc.value.code == "LAYOUT_BAD"


def test_define_enforces_channel_limit_and_keeps_order():
    p = make(max_channels=3)
    with pytest.raises(acl.LayoutError) as exc:
        p.define("wide", ["L", "R", "C", "LFE"])
    assert exc.value.code == "LAYOUT_LIMIT"
    assert p.define("odd", ["C", "L", "R"]) == ("C", "L", "R")
    assert p.channels("odd") == ("C", "L", "R")
    assert "odd" in p.layouts()


def test_downmix_51_to_stereo_raw_gains():
    p = make()
    matrix = p.build_matrix("5.1", "stereo", normalize=False)
    assert matrix["source_channels"] == ["L", "R", "C", "LFE", "Ls", "Rs"]
    assert matrix["target_channels"] == ["L", "R"]
    assert matrix["rows"][0] == [[0, 0.0], [2, -3.0], [4, -3.0]]
    assert matrix["rows"][1] == [[1, 0.0], [2, -3.0], [5, -3.0]]
    assert matrix["normalized"] is False
    assert matrix["attenuation_db"] == [0.0, 0.0]


def test_downmix_normalizes_headroom_per_target():
    p = make()
    matrix = p.build_matrix("5.1", "stereo")
    assert matrix["normalized"] is True
    expected_attenuation = 20.0 * math.log10(1.0 + 2.0 * 10.0 ** (-3.0 / 20.0))
    assert matrix["attenuation_db"][0] == pytest.approx(expected_attenuation, abs=1e-9)
    assert matrix["attenuation_db"][1] == pytest.approx(expected_attenuation, abs=1e-9)
    for row in matrix["rows"]:
        total = sum(10.0 ** (gain / 20.0) for _, gain in row)
        assert total == pytest.approx(1.0, abs=1e-9)
    gains = {index: gain for index, gain in matrix["rows"][0]}
    assert gains[2] - gains[0] == pytest.approx(-3.0, abs=1e-9)


def test_mono_and_stereo_center_folding_raw():
    p = make()
    up = p.build_matrix("mono", "stereo", normalize=False)
    assert up["rows"] == [[[0, -3.0]], [[0, -3.0]]]
    assert up["normalized"] is False
    assert up["attenuation_db"] == [0.0, 0.0]
    down = p.build_matrix("stereo", "mono", normalize=False)
    assert down["target_channels"] == ["C"]
    assert down["rows"] == [[[0, -3.0], [1, -3.0]]]


def test_matrix_cache_hits_and_eviction():
    p = make()
    first = p.build_matrix("5.1", "stereo")
    second = p.build_matrix("5.1", "stereo")
    assert first == second
    assert p.stats()["builds"] == 1
    assert p.stats()["cache_hits"] == 1
    small = make(cache_size=1)
    small.build_matrix("stereo", "stereo")
    small.build_matrix("mono", "stereo")
    small.build_matrix("5.1", "stereo")
    assert small.stats()["cached_matrices"] == 1
    assert small.stats()["cache_evictions"] == 2
    assert small.stats()["builds"] == 3


def test_activate_process_identity_and_clipping():
    p = make()
    out = p.activate("mono", "mono")
    assert out == {"source": "mono", "target": "mono", "normalized": False}
    mixed = p.process([[1.5], [-0.25]])
    assert mixed["frames"] == [[1.0], [-0.25]]
    assert mixed["clipped"] == 1
    assert p.stats()["frames_processed"] == 2
    assert p.stats()["clipped_samples"] == 1


def test_process_limits_width_and_requires_active_matrix():
    p = make(max_frames=2)
    with pytest.raises(acl.LayoutError) as exc:
        p.process([[0.1]])
    assert exc.value.code == "LAYOUT_NO_ACTIVE"
    p.activate("mono", "stereo")
    with pytest.raises(acl.LayoutError) as exc:
        p.process([[0.1], [0.2], [0.3]])
    assert exc.value.code == "LAYOUT_FRAME_LIMIT"
    with pytest.raises(acl.LayoutError) as exc:
        p.process([[0.1, 0.2]])
    assert exc.value.code == "LAYOUT_FRAME_MISMATCH"
    assert p.stats()["frames_processed"] == 0


def test_downmix_one_shot_matches_active_path():
    p = make()
    direct = p.downmix("mono", "stereo", [[0.5]])
    p.activate("mono", "stereo")
    streamed = p.process([[0.5]])
    assert direct["frames"] == streamed["frames"]
    expected = 0.5 * 10.0 ** (-3.0 / 20.0)
    assert direct["frames"][0][0] == pytest.approx(expected, abs=1e-12)
    assert direct["frames"][0][1] == pytest.approx(expected, abs=1e-12)
    assert direct["clipped"] == 0


def test_remap_permutation_and_count_mismatch():
    p = make()
    p.define("swapped", ["R", "L"])
    out = p.remap("stereo", "swapped", [[0.1, 0.2], [-0.3, 0.4]])
    assert out["frames"] == [[0.2, 0.1], [0.4, -0.3]]
    assert out["clipped"] == 0
    with pytest.raises(acl.LayoutError) as exc:
        p.remap("5.1", "stereo", [[0.0, 0.0, 0.0, 0.0, 0.0, 0.0]])
    assert exc.value.code == "LAYOUT_COUNT_MISMATCH"


def test_peak_reports_per_channel_maxima():
    p = make()
    assert p.peak([[0.5, -0.2], [-0.9, 0.1]]) == [0.9, 0.2]
    assert p.peak([]) == []
    with pytest.raises(acl.LayoutError) as exc:
        p.peak([[0.1, 0.2], [0.3]])
    assert exc.value.code == "LAYOUT_FRAME_MISMATCH"


def test_reset_stats_clears_counters_but_keeps_layouts():
    p = make()
    p.define("alt", ["L", "R", "C"])
    p.downmix("mono", "stereo", [[0.1]])
    assert p.stats()["builds"] == 1
    p.reset_stats()
    assert p.stats()["builds"] == 0
    assert p.stats()["frames_processed"] == 0
    assert p.channels("alt") == ("L", "R", "C")


def test_snapshot_restore_roundtrip_and_bad_version():
    p = make()
    p.define("alt", ["L", "R", "C"])
    p.activate("mono", "stereo")
    first = p.process([[0.5]])
    snap = p.snapshot()
    fresh = make()
    fresh.restore(snap)
    assert fresh.channels("alt") == ("L", "R", "C")
    assert fresh.stats()["restores"] == 1
    assert fresh.process([[0.5]]) == first
    bad = p.snapshot()
    bad["version"] = 5
    with pytest.raises(acl.LayoutError) as exc:
        fresh.restore(bad)
    assert exc.value.code == "LAYOUT_SNAPSHOT_INVALID"
    broken = p.snapshot()
    broken["layouts"] = "nope"
    with pytest.raises(acl.LayoutError) as exc:
        fresh.restore(broken)
    assert exc.value.code == "LAYOUT_SNAPSHOT_INVALID"
    assert fresh.channels("alt") == ("L", "R", "C")


def test_concurrent_activation_swaps_are_atomic():
    p = make()
    p.define("swapped", ["R", "L"])
    p.activate("stereo", "stereo")
    errors = []
    reads = [0]
    guard = threading.Lock()

    def writer():
        for index in range(300):
            target = "swapped" if index % 2 else "stereo"
            p.activate("stereo", target)

    def reader():
        for _ in range(300):
            result = p.process([[0.25, -0.5]])
            if result["frames"] not in ([[0.25, -0.5]], [[-0.5, 0.25]]):
                errors.append(result["frames"])
            if result["clipped"] != 0:
                errors.append("clipped")
            with guard:
                reads[0] += 1

    threads = [threading.Thread(target=writer)]
    threads += [threading.Thread(target=reader) for _ in range(3)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert reads[0] == 900
    assert p.stats()["frames_processed"] == 900
    assert p.stats()["activations"] == 301
