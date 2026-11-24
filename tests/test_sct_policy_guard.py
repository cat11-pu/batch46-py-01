import json
import threading

import pytest

import sct_policy_guard as sct

DAY = 86400


def make(**kwargs):
    return sct.SctGuard(**kwargs)


def certificate(days=30, fingerprint="fp-1", start=1000):
    return {
        "fingerprint": fingerprint,
        "not_before": start,
        "not_after": start + days * DAY,
    }


def test_single_usable_sct_satisfies_short_lived_certificate():
    g = make()
    g.add_log("log-a", operator="op-a", key="key-a", quota=10)
    cert = certificate(days=30)
    stamp = g.submit("log-a", cert["fingerprint"], now=1100)
    verdict = g.verify(cert, [stamp], now=1200)
    assert verdict["valid"] is True
    assert verdict["code"] is None
    assert verdict["required"] == 1
    assert len(verdict["accepted"]) == 1
    assert verdict["operators"] == ["op-a"]
    assert g.require(cert, [stamp], now=1200)["valid"] is True


def test_long_lived_certificate_needs_three_distinct_operators():
    g = make()
    for index, operator in enumerate(["op-a", "op-b", "op-c"]):
        g.add_log(f"log-{index}", operator=operator, key=f"key-{index}")
    cert = certificate(days=365)
    stamps = [g.submit(f"log-{index}", cert["fingerprint"], now=1100)
              for index in range(3)]
    partial = g.verify(cert, stamps[:2], now=1200)
    assert partial["valid"] is False
    assert partial["code"] == "SCT_INSUFFICIENT"
    assert partial["required"] == 3
    with pytest.raises(sct.SctError) as exc:
        g.require(cert, stamps[:2], now=1200)
    assert exc.value.code == "SCT_INSUFFICIENT"
    assert g.verify(cert, stamps, now=1200)["valid"] is True


def test_required_count_uses_ceil_days_with_90_and_180_boundaries():
    g = make()
    assert g.required_count(certificate(days=90)) == 1
    assert g.required_count(certificate(days=91)) == 2
    assert g.required_count(certificate(days=180)) == 2
    assert g.required_count(certificate(days=181)) == 3


def test_duplicate_scts_are_counted_once():
    g = make()
    g.add_log("log-a", operator="op-a", key="key-a")
    cert = certificate(days=120)
    stamp = g.submit("log-a", cert["fingerprint"], now=1100)
    verdict = g.verify(cert, [stamp, dict(stamp), dict(stamp)], now=1200)
    assert len(verdict["accepted"]) == 1
    assert verdict["operators"] == ["op-a"]
    assert verdict["code"] == "SCT_INSUFFICIENT"


def test_two_timestamps_from_one_log_still_count_as_one_operator():
    g = make()
    g.add_log("log-a", operator="op-a", key="key-a")
    cert = certificate(days=120)
    early = g.submit("log-a", cert["fingerprint"], now=1100)
    late = g.submit("log-a", cert["fingerprint"], now=1150)
    verdict = g.verify(cert, [early, late], now=1200)
    assert len(verdict["accepted"]) == 2
    assert verdict["operators"] == ["op-a"]
    assert verdict["code"] == "SCT_INSUFFICIENT"


def test_one_operator_with_two_logs_counts_as_one():
    g = make()
    g.add_log("log-a", operator="shared-op", key="key-a")
    g.add_log("log-b", operator="shared-op", key="key-b")
    cert = certificate(days=120)
    first = g.submit("log-a", cert["fingerprint"], now=1100)
    second = g.submit("log-b", cert["fingerprint"], now=1110)
    verdict = g.verify(cert, [first, second], now=1200)
    assert len(verdict["accepted"]) == 2
    assert verdict["operators"] == ["shared-op"]
    assert verdict["code"] == "SCT_INSUFFICIENT"


def test_signature_mismatch_rejects_a_copied_sct():
    g = make()
    g.add_log("log-a", operator="op-a", key="key-a")
    cert = certificate(days=30)
    stamp = dict(g.submit("log-a", cert["fingerprint"], now=1100))
    stamp["signature"] = "0" * 64
    verdict = g.verify(cert, [stamp], now=1200)
    assert verdict["valid"] is False
    assert verdict["code"] == "SCT_BAD_SIGNATURE"
    assert verdict["accepted"] == []
    assert verdict["rejected"][0]["code"] == "SCT_BAD_SIGNATURE"
    with pytest.raises(sct.SctError) as exc:
        g.require(cert, [stamp], now=1200)
    assert exc.value.code == "SCT_BAD_SIGNATURE"


def test_unknown_log_is_rejected():
    g = make()
    g.add_log("log-a", operator="op-a", key="key-a")
    cert = certificate(days=30)
    rogue = {"log_id": "log-z", "timestamp": 1100, "signature": "00" * 32}
    verdict = g.verify(cert, [rogue], now=1200)
    assert verdict["valid"] is False
    assert verdict["code"] == "SCT_UNKNOWN_LOG"
    assert verdict["accepted"] == []


def test_disabled_and_retired_logs_are_not_counted():
    g = make()
    g.add_log("log-a", operator="op-a", key="key-a")
    g.add_log("log-b", operator="op-b", key="key-b")
    cert = certificate(days=30)
    first = g.submit("log-a", cert["fingerprint"], now=1100)
    second = g.submit("log-b", cert["fingerprint"], now=1100)
    g.set_log_status("log-a", "disabled")
    g.set_log_status("log-b", "retired")
    verdict = g.verify(cert, [first, second], now=1200)
    assert verdict["accepted"] == []
    assert [row["code"] for row in verdict["rejected"]] == [
        "SCT_LOG_DISABLED",
        "SCT_LOG_RETIRED",
    ]
    assert verdict["code"] == "SCT_LOG_DISABLED"
    assert verdict["valid"] is False


def test_future_and_out_of_validity_timestamps_are_rejected():
    g = make()
    g.add_log("log-a", operator="op-a", key="key-a")
    g.add_log("log-b", operator="op-b", key="key-b")
    cert = certificate(days=30)
    future = g.submit("log-a", cert["fingerprint"], now=1300)
    too_early = g.submit("log-b", cert["fingerprint"], now=900)
    verdict = g.verify(cert, [future, too_early], now=1200)
    assert [row["code"] for row in verdict["rejected"]] == [
        "SCT_FUTURE_TIMESTAMP",
        "SCT_OUTSIDE_VALIDITY",
    ]
    assert verdict["code"] == "SCT_FUTURE_TIMESTAMP"


def test_sct_signed_for_another_certificate_is_rejected():
    g = make()
    g.add_log("log-a", operator="op-a", key="key-a")
    cert_a = certificate(days=30, fingerprint="fp-a")
    cert_b = certificate(days=30, fingerprint="fp-b")
    stolen = g.submit("log-a", cert_a["fingerprint"], now=1100)
    verdict = g.verify(cert_b, [stolen], now=1200)
    assert verdict["valid"] is False
    assert verdict["code"] == "SCT_BAD_SIGNATURE"
    assert verdict["accepted"] == []


def test_pack_roundtrip_preserves_order_and_collapses_duplicates():
    g = make()
    g.add_log("log-a", operator="op-a", key="key-a")
    g.add_log("log-b", operator="op-b", key="key-b")
    cert = certificate(days=30)
    first = g.submit("log-a", cert["fingerprint"], now=1100)
    second = g.submit("log-b", cert["fingerprint"], now=1110)
    blob = g.pack([first, second, first])
    loaded = g.unpack(blob)
    assert [row["log_id"] for row in loaded] == ["log-a", "log-b"]
    assert [row["timestamp"] for row in loaded] == [1100, 1110]
    assert "=" not in blob
    with pytest.raises(sct.SctError) as exc:
        g.unpack("!!!not-base64!!!")
    assert exc.value.code == "SCT_MALFORMED_LIST"


def test_list_limits_reject_oversized_batches_and_blobs():
    g = make(max_scts=16)
    filler = [{"log_id": "log-a", "timestamp": index, "signature": "s"}
              for index in range(17)]
    with pytest.raises(sct.SctError) as exc:
        g.pack(filler)
    assert exc.value.code == "SCT_TOO_MANY"
    tiny = make(max_list_bytes=64)
    tiny.add_log("log-a", operator="op-a", key="key-a")
    cert = certificate(days=30)
    stamp = tiny.submit("log-a", cert["fingerprint"], now=1100)
    with pytest.raises(sct.SctError) as exc2:
        tiny.pack([stamp])
    assert exc2.value.code == "SCT_SIZE_LIMIT"
    with pytest.raises(sct.SctError) as exc3:
        tiny.unpack("a" * 65)
    assert exc3.value.code == "SCT_SIZE_LIMIT"


def test_concurrent_submit_respects_per_log_quota():
    g = make()
    g.add_log("log-a", operator="op-a", key="key-a", quota=3)
    barrier = threading.Barrier(8)
    wins = []
    codes = []
    lock = threading.Lock()

    def worker():
        barrier.wait()
        try:
            out = g.submit("log-a", "fp-race", now=1000)
        except sct.SctError as exc:
            with lock:
                codes.append(exc.code)
            return
        with lock:
            wins.append(out)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(wins) == 3
    assert sorted(codes) == ["SCT_QUOTA"] * 5
    assert g.stats()["issued"] == 3


def test_snapshot_restore_keeps_log_statuses_quotas_and_counters():
    g = make()
    g.add_log("log-a", operator="op-a", key="key-a", quota=1)
    g.add_log("log-b", operator="op-b", key="key-b", not_after=1500)
    cert = certificate(days=30)
    stamp = g.submit("log-a", cert["fingerprint"], now=1100)
    g.submit("log-b", cert["fingerprint"], now=1100)
    g.set_log_status("log-b", "disabled")
    state = json.loads(json.dumps(g.snapshot()))
    restored = sct.SctGuard.restore(state)
    verdict = restored.verify(cert, [stamp], now=1200)
    assert verdict["valid"] is True
    assert restored.stats()["issued"] == 2
    with pytest.raises(sct.SctError) as exc:
        restored.submit("log-a", cert["fingerprint"], now=1200)
    assert exc.value.code == "SCT_QUOTA"
    with pytest.raises(sct.SctError) as exc2:
        restored.submit("log-b", cert["fingerprint"], now=1200)
    assert exc2.value.code == "SCT_LOG_UNAVAILABLE"
    assert restored.sweep(now=1600) == 1
