import threading

import pytest

import geneve_option_guard as gog

CLS = 0x0108
ALT = 0x0109


def guard(**kwargs):
    return gog.GeneveGuard(**kwargs)


def opt(opt_class, opt_type, value=b"", critical=False):
    return {
        "class": opt_class,
        "type": opt_type,
        "critical": critical,
        "value": value,
    }


def packet(options, vni=500, version=0):
    return {"version": version, "vni": vni, "options": options}


def test_valid_packet_with_registered_text_option_is_normalized():
    g = guard()
    g.register_option(CLS, 1, encoding="utf8", max_len=16)
    out = g.parse(packet([opt(CLS, 1, b"edge")]))
    assert out["status"] == "accepted"
    assert out["code"] is None
    assert out["vni"] == 500
    assert out["options"] == [{
        "class": CLS, "type": 1, "critical": False,
        "value": b"edge", "length": 4,
    }]
    assert out["skipped"] == []
    assert out["option_bytes"] == 8
    assert out["cached"] is False
    assert g.stats()["accepted"] == 1


def test_version_and_vni_are_validated_first():
    g = guard()
    with pytest.raises(gog.GeneveError) as exc:
        g.parse(packet([], version=1))
    assert exc.value.code == "GENEVE_BAD_VERSION"
    for bad in (0, 1 << 24, -5):
        with pytest.raises(gog.GeneveError) as exc:
            g.parse(packet([], vni=bad))
        assert exc.value.code == "GENEVE_BAD_VNI"
    assert g.stats()["rejected"] == 4


def test_option_count_capacity_is_enforced():
    g = guard(max_options=2)
    g.register_option(CLS, 1, max_len=4)
    with pytest.raises(gog.GeneveError) as exc:
        g.parse(packet([opt(CLS, 1, b"a")] * 3))
    assert exc.value.code == "GENEVE_OPT_COUNT"
    assert g.stats()["rejected"] == 1


def test_total_option_bytes_are_capped_before_field_validation():
    g = guard(max_option_bytes=12)
    g.register_option(CLS, 1, max_len=8)
    g.register_option(CLS, 2, max_len=8)
    out = g.parse(packet([opt(CLS, 1, b"12345678")]))
    assert out["option_bytes"] == 12
    with pytest.raises(gog.GeneveError) as exc:
        g.parse(packet([opt(CLS, 1, b"12345678"), opt(CLS, 2, b"x")]))
    assert exc.value.code == "GENEVE_OPTS_OVERFLOW"


def test_duplicate_class_and_type_is_rejected():
    g = guard()
    g.register_option(CLS, 1, max_len=4)
    with pytest.raises(gog.GeneveError) as exc:
        g.parse(packet([opt(CLS, 1, b"a"), opt(CLS, 1, b"b")]))
    assert exc.value.code == "GENEVE_OPT_DUP"


def test_unknown_noncritical_options_are_skipped_and_critical_ones_rejected():
    g = guard()
    out = g.parse(packet([opt(CLS, 9, b"\x01", critical=False)]))
    assert out["status"] == "accepted"
    assert out["options"] == []
    assert out["skipped"] == [[CLS, 9]]
    assert out["option_bytes"] == 5
    with pytest.raises(gog.GeneveError) as exc:
        g.parse(packet([opt(CLS, 9, b"\x01", critical=True)]))
    assert exc.value.code == "GENEVE_CRITICAL_UNKNOWN"
    with pytest.raises(gog.GeneveError) as exc:
        g.parse(packet([opt(0x0999, 1, b"\x01", critical=True)]))
    assert exc.value.code == "GENEVE_CRITICAL_UNKNOWN"
    out = g.parse(packet([opt(0x0999, 1, b"\x01", critical=False)]))
    assert out["skipped"] == [[0x0999, 1]]
    assert g.stats()["skipped_options"] == 2


def test_critical_bit_must_match_the_registry():
    g = guard()
    g.register_option(CLS, 1, critical=True, max_len=4)
    with pytest.raises(gog.GeneveError) as exc:
        g.parse(packet([opt(CLS, 1, b"a", critical=False)]))
    assert exc.value.code == "GENEVE_CRITICAL_MISMATCH"
    g.register_option(CLS, 2, critical=False, max_len=4)
    with pytest.raises(gog.GeneveError) as exc:
        g.parse(packet([opt(CLS, 2, b"a", critical=True)]))
    assert exc.value.code == "GENEVE_CRITICAL_MISMATCH"


def test_option_max_length_and_empty_value_are_rejected():
    g = guard()
    g.register_option(CLS, 1, max_len=4)
    with pytest.raises(gog.GeneveError) as exc:
        g.parse(packet([opt(CLS, 1, b"12345")]))
    assert exc.value.code == "GENEVE_OPT_LEN"
    with pytest.raises(gog.GeneveError) as exc:
        g.parse(packet([opt(CLS, 1, b"")]))
    assert exc.value.code == "GENEVE_OPT_EMPTY"


def test_utf8_and_ipv4_encodings_are_enforced():
    g = guard()
    g.register_option(CLS, 1, encoding="utf8", max_len=4)
    with pytest.raises(gog.GeneveError) as exc:
        g.parse(packet([opt(CLS, 1, b"\xff")]))
    assert exc.value.code == "GENEVE_OPT_ENCODING"

    g.register_option(CLS, 2, encoding="ipv4", max_len=16)
    for raw in (b"1.2.3", b"999.1.1.1"):
        with pytest.raises(gog.GeneveError) as exc:
            g.parse(packet([opt(CLS, 2, raw)]))
        assert exc.value.code == "GENEVE_OPT_ENCODING"
    out = g.parse(packet([opt(CLS, 2, b"\x0a\x00\x00\x01")]))
    assert out["options"][0]["value"] == b"\x0a\x00\x00\x01"


def test_output_options_are_sorted_by_class_then_type():
    g = guard(allowed_classes=(CLS, ALT))
    g.register_option(CLS, 3, max_len=4)
    g.register_option(CLS, 1, max_len=4)
    g.register_option(ALT, 2, max_len=4)
    out = g.parse(packet([
        opt(CLS, 3, b"x"),
        opt(ALT, 2, b"x"),
        opt(CLS, 1, b"x"),
    ]))
    order = [(row["class"], row["type"]) for row in out["options"]]
    assert order == [(CLS, 1), (CLS, 3), (ALT, 2)]
    assert out["option_bytes"] == 15


def test_audit_reports_all_issues_without_mutating_stats():
    g = guard()
    g.register_option(CLS, 1, max_len=4)
    report = g.audit(packet([
        opt(CLS, 1, b"a"),
        opt(CLS, 1, b"b"),
        opt(CLS, 9, b"c", critical=True),
    ], vni=7))
    assert report["ok"] is False
    assert report["issues"] == ["GENEVE_OPT_DUP", "GENEVE_CRITICAL_UNKNOWN"]
    assert report["vni"] == 7
    assert report["option_bytes"] == 15
    stats = g.stats()
    assert stats["parsed"] == 0
    assert stats["rejected"] == 0


def test_request_id_cache_replays_without_recounting_and_is_copy_safe():
    g = guard(cache_capacity=2)
    g.register_option(CLS, 1, encoding="utf8", max_len=16)
    pkt = packet([opt(CLS, 1, b"edge")])
    first = g.parse(pkt, request_id="r1")
    assert first["cached"] is False
    second = g.parse(pkt, request_id="r1")
    assert second["cached"] is True
    assert second["options"] == first["options"]
    second["options"][0]["value"] = b"HACK"
    third = g.parse(pkt, request_id="r1")
    assert third["options"][0]["value"] == b"edge"

    assert g.parse(pkt, request_id="r2")["cached"] is False
    assert g.parse(pkt, request_id="r3")["cached"] is False
    assert g.cache_size() == 2
    assert g.parse(pkt, request_id="r1")["cached"] is False
    stats = g.stats()
    assert stats["parsed"] == 4
    assert stats["replayed"] == 2
    assert g.clear_cache() == 2
    assert g.cache_size() == 0


def test_snapshot_restore_preserves_registry_cache_and_counters():
    g = guard()
    g.register_option(CLS, 1, encoding="utf8", max_len=16)
    pkt = packet([opt(CLS, 1, b"edge")])
    g.parse(pkt, request_id="r1")
    snap = g.snapshot()
    pristine = g.snapshot()
    snap["registered"][0]["max_len"] = 99
    snap["cache"]["r1"]["vni"] = 999
    snap["counters"]["parsed"] = 99
    assert g.list_options()[0]["max_len"] == 16
    assert g.stats()["parsed"] == 1
    assert g.parse(pkt, request_id="r1")["vni"] == 500

    restored = guard()
    restored.restore(pristine)
    assert restored.stats()["parsed"] == 1
    replay = restored.parse(pkt, request_id="r1")
    assert replay["cached"] is True
    assert replay["vni"] == 500
    fresh = restored.parse(pkt, request_id="r2")
    assert fresh["cached"] is False
    assert fresh["options"][0]["value"] == b"edge"
    with pytest.raises(gog.GeneveError) as exc:
        restored.restore({"version": 2})
    assert exc.value.code == "GENEVE_STATE_VERSION"


def test_concurrent_parses_count_once_per_request():
    g = guard(cache_capacity=256)
    g.register_option(CLS, 1, encoding="utf8", max_len=16)
    pkt = packet([opt(CLS, 1, b"edge")])
    errors = []

    def work(worker):
        try:
            for index in range(5):
                g.parse(pkt, request_id=f"t{worker}-{index}")
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=work, args=(n,)) for n in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    stats = g.stats()
    assert stats["parsed"] == 40
    assert stats["accepted"] == 40
    assert stats["replayed"] == 0
    assert g.cache_size() == 40


def test_unregister_and_reregister_change_validation_outcome():
    g = guard()
    g.register_option(CLS, 1, encoding="utf8", max_len=4)
    pkt = packet([opt(CLS, 1, b"edge")])
    assert g.unregister_option(CLS, 1) is True
    skipped = g.parse(pkt)
    assert skipped["status"] == "accepted"
    assert skipped["options"] == []
    assert skipped["skipped"] == [[CLS, 1]]
    g.register_option(CLS, 1, max_len=2)
    with pytest.raises(gog.GeneveError) as exc:
        g.parse(pkt)
    assert exc.value.code == "GENEVE_OPT_LEN"
    assert g.unregister_option(CLS, 1) is True
    assert g.unregister_option(CLS, 1) is False
    stats = g.stats()
    assert stats["parsed"] == 1
    assert stats["accepted"] == 1
    assert stats["rejected"] == 1
