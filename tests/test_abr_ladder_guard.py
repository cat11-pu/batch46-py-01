import pytest

import abr_ladder_guard as alg

RUNGS = [
    ("360p", 640, 360, 300),
    ("480p", 854, 480, 600),
    ("720p", 1280, 720, 1500),
    ("1080p", 1920, 1080, 3000),
]


def make(**kwargs):
    return alg.AbrLadder(**kwargs)


def ladder(**kwargs):
    p = make(**kwargs)
    for name, width, height, bitrate in RUNGS:
        p.add_rung(name, width=width, height=height, bitrate_kbps=bitrate)
    return p


def test_add_rung_validates_duplicates_and_bitrate_range():
    p = make()
    row = p.add_rung("360p", width=640, height=360, bitrate_kbps=300)
    assert row["bitrate_kbps"] == 300
    assert row["density"] == pytest.approx(300000 / (640 * 360 * 30.0), abs=1e-9)
    with pytest.raises(alg.AbrError) as exc:
        p.add_rung("360p", width=854, height=480, bitrate_kbps=600)
    assert exc.value.code == "ABR_DUP"
    with pytest.raises(alg.AbrError) as exc:
        p.add_rung("zero", width=0, height=480, bitrate_kbps=600)
    assert exc.value.code == "ABR_BAD_RUNG"
    with pytest.raises(alg.AbrError) as exc:
        p.add_rung("low", width=640, height=360, bitrate_kbps=50)
    assert exc.value.code == "ABR_BITRATE_RANGE"
    with pytest.raises(alg.AbrError) as exc:
        p.add_rung("huge", width=640, height=360, bitrate_kbps=30000)
    assert exc.value.code == "ABR_BITRATE_RANGE"


def test_rung_ordering_must_follow_resolution():
    p = make()
    p.add_rung("1080p", width=1920, height=1080, bitrate_kbps=3000)
    p.add_rung("720p", width=1280, height=720, bitrate_kbps=1500)
    with pytest.raises(alg.AbrError) as exc:
        p.add_rung("720p-hi", width=1280, height=720, bitrate_kbps=4000)
    assert exc.value.code == "ABR_ORDER"
    with pytest.raises(alg.AbrError) as exc:
        p.add_rung("1080p-eq", width=1920, height=1080, bitrate_kbps=3000)
    assert exc.value.code == "ABR_ORDER"
    assert [row["name"] for row in p.rungs()] == ["720p", "1080p"]


def test_bitrate_density_bounds_are_enforced():
    p = make()
    with pytest.raises(alg.AbrError) as exc:
        p.add_rung("4k-starved", width=3840, height=2160, bitrate_kbps=100)
    assert exc.value.code == "ABR_RATIO"
    with pytest.raises(alg.AbrError) as exc:
        p.add_rung("1080p-fat", width=1920, height=1080, bitrate_kbps=20000)
    assert exc.value.code == "ABR_RATIO"
    assert p.rungs() == []


def test_rung_limit_is_enforced():
    p = make(max_rungs=2)
    p.add_rung("360p", width=640, height=360, bitrate_kbps=300)
    p.add_rung("480p", width=854, height=480, bitrate_kbps=600)
    with pytest.raises(alg.AbrError) as exc:
        p.add_rung("720p", width=1280, height=720, bitrate_kbps=1500)
    assert exc.value.code == "ABR_RUNG_LIMIT"
    assert p.stats()["active_rungs"] == 2


def test_rungs_are_sorted_and_removal_updates_current():
    p = make()
    for name, width, height, bitrate in (RUNGS[2], RUNGS[0], RUNGS[3], RUNGS[1]):
        p.add_rung(name, width=width, height=height, bitrate_kbps=bitrate)
    assert [row["name"] for row in p.rungs()] == ["360p", "480p", "720p", "1080p"]
    assert p.select(1000)["rung"] == "480p"
    p.remove_rung("480p")
    assert p.current() is None
    assert p.stats()["active_rungs"] == 3
    with pytest.raises(alg.AbrError) as exc:
        p.remove_rung("ghost")
    assert exc.value.code == "ABR_UNKNOWN"


def test_select_adopts_highest_affordable_rung():
    p = ladder()
    out = p.select(1000)
    assert out["rung"] == "480p"
    assert out["changed"] is True
    assert out["code"] == "ABR_INIT"
    assert p.current()["name"] == "480p"
    assert p.stats()["selections"] == 1
    stable = p.select(1000)
    assert stable["rung"] == "480p"
    assert stable["changed"] is False
    assert stable["code"] == "ABR_STABLE"


def test_upscale_requires_margin_beyond_affordability():
    p = ladder()
    p.select(1000)
    held = p.select(2000)
    assert held["rung"] == "480p"
    assert held["changed"] is False
    assert held["code"] == "ABR_HOLD"
    up = p.select(2400)
    assert up["rung"] == "720p"
    assert up["changed"] is True
    assert up["code"] == "ABR_UP"
    assert p.stats()["up_switches"] == 1


def test_downgrade_is_immediate():
    p = ladder()
    p.select(2000)
    assert p.current()["name"] == "720p"
    down = p.select(700)
    assert down["rung"] == "360p"
    assert down["changed"] is True
    assert down["code"] == "ABR_DOWN"
    assert p.stats()["down_switches"] == 1


def test_underflow_keeps_current_rung():
    p = ladder()
    empty = p.select(100)
    assert empty["rung"] is None
    assert empty["changed"] is False
    assert empty["code"] == "ABR_UNDERFLOW"
    p.select(1000)
    kept = p.select(100)
    assert kept["rung"] == "480p"
    assert kept["changed"] is False
    assert kept["code"] == "ABR_UNDERFLOW"
    capped = p.select(9000, device_cap_kbps=50)
    assert capped["rung"] == "480p"
    assert capped["code"] == "ABR_UNDERFLOW"


def test_device_cap_limits_the_ladder():
    p = ladder()
    p.select(1000)
    stable = p.select(9000, device_cap_kbps=700)
    assert stable["rung"] == "480p"
    assert stable["changed"] is False
    assert stable["code"] == "ABR_STABLE"
    capped = p.select(9000, device_cap_kbps=2000)
    assert capped["rung"] == "720p"
    assert capped["code"] == "ABR_UP"


def test_low_buffer_blocks_upscale_only():
    p = ladder()
    p.select(1000)
    held = p.select(5000, buffer_s=1.0)
    assert held["rung"] == "480p"
    assert held["code"] == "ABR_HOLD"
    up = p.select(5000, buffer_s=3.0)
    assert up["rung"] == "1080p"
    assert up["code"] == "ABR_UP"


def test_switch_rate_limit_freezes_ladder_until_window_advances():
    p = ladder(max_switches_per_window=2, window_size=4)
    p.observe(5000)
    assert p.select(5000)["code"] == "ABR_INIT"
    assert p.select(2000)["code"] == "ABR_DOWN"
    assert p.select(5000)["code"] == "ABR_UP"
    blocked = p.select(2000)
    assert blocked["rung"] == "1080p"
    assert blocked["changed"] is False
    assert blocked["code"] == "ABR_SWITCH_LIMIT"
    for _ in range(4):
        p.observe(5000)
    allowed = p.select(2000)
    assert allowed["rung"] == "720p"
    assert allowed["code"] == "ABR_DOWN"
    assert allowed["changed"] is True


def test_observe_uses_ewma_and_rejects_bad_samples():
    p = ladder()
    assert p.observe(1000) == pytest.approx(1000.0)
    assert p.observe(2000) == pytest.approx(1300.0)
    with pytest.raises(alg.AbrError) as exc:
        p.observe(0)
    assert exc.value.code == "ABR_BAD_SAMPLE"
    with pytest.raises(alg.AbrError) as exc:
        p.observe(-5)
    assert exc.value.code == "ABR_BAD_SAMPLE"
    auto = p.select_auto()
    assert auto["rung"] == "480p"
    assert auto["code"] == "ABR_INIT"


def test_reset_session_clears_state_but_keeps_rungs():
    p = ladder()
    p.select(1000)
    p.observe(1500)
    p.reset_session()
    assert p.current() is None
    assert p.stats()["resets"] == 1
    assert p.stats()["active_rungs"] == 4
    again = p.select(1000)
    assert again["code"] == "ABR_INIT"
    assert again["rung"] == "480p"


def test_snapshot_restore_roundtrip_and_bad_version():
    p = ladder()
    p.observe(1200)
    p.select(1000)
    p.select(2400)
    assert p.current()["name"] == "720p"
    snap = p.snapshot()
    fresh = make()
    fresh.restore(snap)
    assert fresh.current()["name"] == "720p"
    assert [row["name"] for row in fresh.rungs()] == ["360p", "480p", "720p", "1080p"]
    assert fresh.stats()["restores"] == 1
    assert fresh.stats()["up_switches"] == 1
    continued = fresh.select(700)
    assert continued["rung"] == "360p"
    assert continued["code"] == "ABR_DOWN"
    bad = p.snapshot()
    bad["version"] = 3
    with pytest.raises(alg.AbrError) as exc:
        fresh.restore(bad)
    assert exc.value.code == "ABR_SNAPSHOT_INVALID"
    broken = p.snapshot()
    broken["rungs"] = ["nope"]
    with pytest.raises(alg.AbrError) as exc:
        fresh.restore(broken)
    assert exc.value.code == "ABR_SNAPSHOT_INVALID"
    assert fresh.current()["name"] == "360p"
