import json
import threading

import pytest

import dsp_limiter_guard as dlg

CEILING_6DB = 10.0 ** (-6.0 / 20.0)


def make(**kwargs):
    options = {"sample_rate": 48000, "ceiling_db": -6.0, "attack_ms": 1.0,
               "release_ms": 50.0, "lookahead_ms": 2.0,
               "max_block_size": 65536}
    options.update(kwargs)
    return dlg.DspLimiter(**options)


def test_configure_rejects_out_of_range_values():
    eng = make()
    for bad in ({"attack_ms": 0.0}, {"release_ms": 0.0},
                {"sample_rate": 1000}, {"lookahead_ms": -1.0},
                {"max_block_size": 0}):
        with pytest.raises(dlg.DspLimiterError) as exc:
            eng.configure(**bad)
        assert exc.value.code == "DSP_CONFIG_RANGE"
    assert eng.latency_samples() == 96


def test_ceiling_range_is_enforced():
    eng = make()
    with pytest.raises(dlg.DspLimiterError) as exc:
        eng.configure(ceiling_db=3.0)
    assert exc.value.code == "DSP_CEILING_RANGE"
    with pytest.raises(dlg.DspLimiterError) as exc:
        eng.configure(ceiling_db=-61.0)
    assert exc.value.code == "DSP_CEILING_RANGE"
    eng.configure(ceiling_db=-6.0)
    assert eng.ceiling() == pytest.approx(CEILING_6DB, abs=1e-6)


def test_latency_samples_follow_lookahead():
    eng = make()
    assert eng.latency_samples() == 96
    eng.configure(lookahead_ms=1.5)
    assert eng.latency_samples() == 72
    eng.configure(lookahead_ms=0.0)
    assert eng.latency_samples() == 0


def test_lookahead_delays_impulse_output():
    eng = make(ceiling_db=0.0, attack_ms=1.0, lookahead_ms=2.0,
               max_block_size=1024)
    samples = [0.0] * 200
    samples[10] = 1.0
    out = eng.process_block(0, samples)["samples_out"]
    assert len(out) == 200
    assert all(value == 0.0 for value in out[:106])
    assert out[106] == pytest.approx(1.0, abs=1e-6)
    assert all(value == 0.0 for value in out[107:])


def test_steady_state_is_limited_to_ceiling():
    eng = make()
    eng.process_block(0, [1.0] * 3000)
    result = eng.process_block(0, [1.0] * 1000)
    assert result["peak_in"] == pytest.approx(1.0)
    assert result["peak_out"] <= CEILING_6DB + 1e-3
    assert result["peak_out"] >= CEILING_6DB - 1e-2
    assert result["gain_reduction_db"] == pytest.approx(6.0206, abs=0.05)


def test_signal_below_ceiling_passes_with_unity_gain():
    eng = make(ceiling_db=-1.0, attack_ms=1.0)
    result = eng.process_block(0, [0.1] * 500)
    assert result["peak_out"] == pytest.approx(0.1)
    assert result["gain"] == pytest.approx(1.0)
    assert result["gain_reduction_db"] == pytest.approx(0.0)
    assert result["limited_samples"] == 0


def test_release_envelope_recovers_after_silence():
    eng = make()
    eng.process_block(0, [1.0] * 3000)
    assert eng.gain_reduction_db() > 5.0
    eng.process_block(0, [0.0] * 20000)
    assert eng.gain_reduction_db() < 0.1
    assert eng.channel_gain(0) > 0.99


def test_oversized_block_is_rejected_without_state_change():
    eng = make(max_block_size=512)
    with pytest.raises(dlg.DspLimiterError) as exc:
        eng.process_block(0, [0.1] * 513)
    assert exc.value.code == "DSP_BUDGET_EXCEEDED"
    assert eng.stats()["blocks"] == 0
    assert eng.stats()["frames"] == 0
    eng.process_block(0, [0.1] * 512)
    assert eng.stats()["blocks"] == 1


def test_unknown_channel_is_rejected():
    eng = make()
    with pytest.raises(dlg.DspLimiterError) as exc:
        eng.process_block(3, [0.1])
    assert exc.value.code == "DSP_CHANNEL_UNKNOWN"
    with pytest.raises(dlg.DspLimiterError) as exc:
        eng.process_linked({0: [0.1], 2: [0.1]})
    assert exc.value.code == "DSP_CHANNEL_UNKNOWN"


def test_invalid_sample_values_are_rejected():
    eng = make()
    with pytest.raises(dlg.DspLimiterError) as exc:
        eng.process_block(0, [])
    assert exc.value.code == "DSP_BLOCK_INVALID"
    with pytest.raises(dlg.DspLimiterError) as exc:
        eng.process_block(0, [0.1, "loud"])
    assert exc.value.code == "DSP_BLOCK_INVALID"
    with pytest.raises(dlg.DspLimiterError) as exc:
        eng.process_block(0, [0.1, float("nan")])
    assert exc.value.code == "DSP_BLOCK_INVALID"
    assert eng.stats()["frames"] == 0


def test_stats_count_blocks_frames_and_limited_samples():
    eng = make()
    first = eng.process_block(0, [1.0] * 100)
    assert first["limited_samples"] >= 1
    eng.process_block(1, [0.0] * 200)
    stats = eng.stats()
    assert stats["blocks"] == 2
    assert stats["frames"] == 300
    assert stats["limited_samples"] >= first["limited_samples"]


def test_reset_restores_unity_gain_and_clears_stats():
    eng = make()
    eng.process_block(0, [1.0] * 3000)
    assert eng.channel_gain(0) < 0.9
    eng.reset()
    assert eng.channel_gain(0) == pytest.approx(1.0)
    assert eng.gain_reduction_db() == pytest.approx(0.0)
    assert eng.stats()["blocks"] == 0
    assert eng.stats()["frames"] == 0
    assert eng.latency_samples() == 96


def test_snapshot_restore_preserves_envelope():
    eng = make()
    eng.process_block(0, [1.0] * 3000)
    before_gain = eng.channel_gain(0)
    before_gr = eng.gain_reduction_db()
    snap = json.loads(json.dumps(eng.snapshot()))
    eng.process_block(0, [0.0] * 5000)
    eng.restore(snap)
    assert eng.channel_gain(0) == pytest.approx(before_gain, abs=1e-6)
    assert eng.gain_reduction_db() == pytest.approx(before_gr, abs=1e-4)
    assert eng.stats()["frames"] == 3000


def test_linked_processing_shares_one_gain():
    eng = make(lookahead_ms=0.0)
    result = eng.process_linked({0: [1.0] * 3000, 1: [0.1] * 3000})
    assert result["frames"] == 3000
    assert result["gain"] == pytest.approx(CEILING_6DB, abs=1e-3)
    assert eng.channel_gain(0) == pytest.approx(eng.channel_gain(1))
    assert eng.channel_gain(1) < 0.51
    assert eng.stats()["frames"] == 3000


def test_concurrent_blocks_are_serialized():
    eng = make(max_block_size=64, lookahead_ms=0.0)
    errors = []

    def worker():
        try:
            for _ in range(20):
                result = eng.process_block(0, [0.2] * 32)
                assert result["samples"] == 32
                assert len(result["samples_out"]) == 32
        except BaseException as exc:  # pragma: no cover - failure path
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    stats = eng.stats()
    assert stats["blocks"] == 120
    assert stats["frames"] == 3840
