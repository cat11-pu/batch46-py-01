import threading

import pytest

import dns_tunnel_guard as dtg


def make(**kwargs):
    return dtg.DnsTunnelGuard(**kwargs)


def ev(qname, client="c1", qtype="A", size=60, rcode=0, truncated=False,
       ts=1000):
    return {
        "client": client,
        "qname": qname,
        "qtype": qtype,
        "size": size,
        "rcode": rcode,
        "truncated": truncated,
        "ts": ts,
    }


def test_allowlist_uses_suffix_boundaries_and_normalizes_names():
    g = make()
    out = g.allow_domain("Good.COM")
    assert out["domain"] == "good.com"
    assert out["status"] == "allowed"
    allowed = g.ingest(ev("X.GOOD.COM."), now=1000)
    assert allowed["action"] == "allow"
    assert allowed["code"] == "DNS_ALLOWLISTED"
    assert allowed["score"] == 0
    assert g.client_state("c1", now=1000)["events"] == 0
    for index, name in enumerate(("notgood.com", "good.com.evil.net")):
        out = g.ingest(ev(name, client=f"c{index + 2}", qtype="TXT", size=500),
                       now=1000)
        assert out["code"] != "DNS_ALLOWLISTED"
    with pytest.raises(dtg.DnsTunnelError) as exc:
        g.allow_domain("bad..com")
    assert exc.value.code == "DNS_BAD_DOMAIN"
    with pytest.raises(dtg.DnsTunnelError) as exc:
        g.revoke_domain("missing.com")
    assert exc.value.code == "DNS_UNKNOWN_DOMAIN"
    g.revoke_domain("good.com")
    after = g.ingest(ev("x.good.com"), now=1001)
    assert after["code"] != "DNS_ALLOWLISTED"


def test_invalid_qnames_are_dropped_without_touching_state():
    g = make()
    names = [
        "",
        "localhost",
        ("a" * 64) + ".example.com",
        "bad name.com",
        ("a." * 130) + "com",
    ]
    for index, name in enumerate(names):
        client = f"bad{index}"
        out = g.ingest(ev(name, client=client), now=1000)
        assert out["action"] == "drop"
        assert out["code"] == "DNS_BAD_QNAME"
        assert out["score"] == 0
        assert g.client_state(client, now=1000)["events"] == 0
    with pytest.raises(dtg.DnsTunnelError) as exc:
        g.ingest({"qname": "a.example.com", "client": ""}, now=1000)
    assert exc.value.code == "DNS_BAD_CLIENT"


def test_qname_normalization_and_public_suffix_handling():
    g = make()
    assert g.base_domain("A.Example.CO.UK.") == "example.co.uk"
    assert g.base_domain("x.y.good.io") == "good.io"
    assert g.base_domain("host.unknownzone") == "host.unknownzone"
    assert g.base_domain("a.b.internalzone") == "b.internalzone"
    out = g.ingest(ev("A.Example.CO.UK.", client="c9"), now=1000)
    assert out["action"] == "allow"
    state = g.client_state("c9", now=1000)
    assert state["unique"] == 1
    assert state["recent"] == ["a.example.co.uk"]
    assert state["base_domains"] == ["example.co.uk"]


def test_single_long_label_raises_an_alert():
    g = make()
    label = "x" * 31
    alert = g.ingest(ev(f"{label}.example.com"), now=1000)
    assert alert["action"] == "alert"
    assert alert["code"] == "DNS_ALERT"
    assert alert["score"] == 40
    assert alert["reasons"] == ["LONG_LABEL"]
    ok = g.ingest(ev(("y" * 30) + ".example.com", client="c2"), now=1000)
    assert ok["action"] == "allow"
    assert ok["score"] == 0
    assert ok["reasons"] == []


def test_suspicious_qtype_is_scored_together_with_payload_size():
    g = make()
    txt = g.ingest(ev("short.example.com", qtype="TXT", size=100), now=1000)
    assert txt["action"] == "allow"
    assert txt["score"] == 25
    assert txt["reasons"] == ["SUSPICIOUS_QTYPE"]
    combo = g.ingest(
        ev(("z" * 40) + ".example.com", client="c2", qtype="TXT", size=500),
        now=1000,
    )
    assert combo["score"] == 75
    assert combo["reasons"] == [
        "LONG_LABEL",
        "SUSPICIOUS_QTYPE",
        "LARGE_RESPONSE",
    ]
    assert combo["action"] == "alert"


def test_high_unique_count_is_per_client_and_base_domain():
    g = make(unique_threshold=3)
    first = g.ingest(ev("a.t.example.com", qtype="TXT"), now=1000)
    assert first["score"] == 25
    second = g.ingest(ev("b.t.example.com", qtype="TXT"), now=1001)
    assert second["score"] == 25
    third = g.ingest(ev("c.t.example.com", qtype="TXT"), now=1002)
    assert third["score"] == 50
    assert third["reasons"] == ["SUSPICIOUS_QTYPE", "HIGH_UNIQUE"]
    other_base = g.ingest(ev("a.t.other.com", qtype="TXT", client="c2"),
                          now=1003)
    assert other_base["score"] == 25
    state = g.client_state("c1", now=1003)
    assert state["unique"] == 3
    assert state["base_domains"] == ["example.com"]


def test_repeating_one_qname_does_not_count_as_unique():
    g = make(unique_threshold=2)
    for index in range(4):
        out = g.ingest(ev("same.example.com", qtype="TXT"), now=1000 + index)
        assert out["score"] == 25
        assert "HIGH_UNIQUE" not in out["reasons"]
    state = g.client_state("c1", now=1010)
    assert state["unique"] == 1
    assert state["events"] == 4


def test_window_expiry_drops_old_events_before_scoring():
    g = make(unique_threshold=2, window=60)
    g.ingest(ev("a.example.com"), now=1000)
    second = g.ingest(ev("b.example.com"), now=1030)
    assert second["score"] == 25
    assert second["reasons"] == ["HIGH_UNIQUE"]
    third = g.ingest(ev("c.example.com"), now=1100)
    assert third["score"] == 0
    assert third["reasons"] == []
    state = g.client_state("c1", now=1100)
    assert state["events"] == 1
    assert state["recent"] == ["c.example.com"]


def test_high_score_blocks_client_until_deadline():
    g = make(unique_threshold=2, block_seconds=300)
    label = "q" * 40
    first = g.ingest(
        ev(f"{label}.a.example.com", qtype="TXT", size=500), now=1000)
    assert first["action"] == "alert"
    assert first["score"] == 75
    second = g.ingest(
        ev(f"{label}.b.example.com", qtype="TXT", size=500), now=1001)
    assert second["action"] == "block"
    assert second["code"] == "DNS_BLOCKED"
    assert second["score"] == 100
    assert g.blocked(now=1001) == ["c1"]
    while_blocked = g.ingest(ev("calm.example.com"), now=1050)
    assert while_blocked["action"] == "block"
    assert while_blocked["code"] == "DNS_CLIENT_BLOCKED"
    assert while_blocked["score"] == 0
    assert g.blocked(now=1301) == []
    after = g.ingest(ev("calm.example.com"), now=1301)
    assert after["action"] == "allow"
    assert after["code"] == "DNS_ALLOWED"


def test_manual_block_unblock_and_expire():
    g = make(block_seconds=300)
    out = g.block_client("c7", 60, now=2000)
    assert out == {"client": "c7", "until": 2060, "status": "blocked"}
    assert g.blocked(now=2010) == ["c7"]
    assert g.ingest(ev("a.example.com", client="c7"),
                    now=2010)["code"] == "DNS_CLIENT_BLOCKED"
    unblocked = g.unblock_client("c7")
    assert unblocked["status"] == "unblocked"
    assert g.blocked(now=2010) == []
    assert g.ingest(ev("a.example.com", client="c7"),
                    now=2010)["action"] == "allow"
    g.block_client("c7", 120, now=3000)
    g.block_client("c8", 30, now=3000)
    assert g.expire(3029) == []
    assert g.expire(3030) == ["c8"]
    assert g.expire(3120) == ["c7"]
    with pytest.raises(dtg.DnsTunnelError) as exc:
        g.block_client("c9", 0, now=3000)
    assert exc.value.code == "DNS_BAD_BLOCK"


def test_failed_and_truncated_events_are_ignored():
    g = make()
    failed = g.ingest(ev("a.example.com", rcode=2), now=1000)
    assert failed["action"] == "allow"
    assert failed["code"] == "DNS_RCODE_IGNORED"
    assert failed["score"] == 0
    trunc = g.ingest(ev("b.example.com", truncated=True), now=1000)
    assert trunc["action"] == "allow"
    assert trunc["code"] == "DNS_TRUNCATED"
    assert g.client_state("c1", now=1000)["events"] == 0
    normal = g.ingest(ev("c.example.com"), now=1000)
    assert normal["action"] == "allow"
    assert normal["code"] == "DNS_ALLOWED"
    assert g.client_state("c1", now=1000)["events"] == 1


def test_batch_is_applied_in_timestamp_order_and_event_buffer_is_bounded():
    g = make(max_events=3)
    events = [
        ev("q4.example.com", ts=1004),
        ev("q1.example.com", ts=1001),
        ev("q5.example.com", ts=1005),
        ev("q2.example.com", ts=1002),
        ev("q3.example.com", ts=1003),
    ]
    results = g.ingest_batch(events, now=1005)
    assert len(results) == 5
    assert all(row["action"] == "allow" for row in results)
    state = g.client_state("c1", now=1005)
    assert state["events"] == 3
    assert state["recent"] == [
        "q3.example.com", "q4.example.com", "q5.example.com"
    ]
    assert state["unique"] == 3


def test_alert_history_is_bounded_ordered_and_filterable():
    g = make(max_alerts=3, unique_threshold=100, label_threshold=30)
    for index in range(3):
        g.ingest(ev(("a" * 31) + f".{index}.example.com", client="c1"),
                 now=1000 + index)
    for index in range(2):
        g.ingest(ev(("b" * 31) + f".{index}.other.com", client="c2"),
                 now=1100 + index)
    rows = g.alerts()
    assert len(rows) == 3
    assert [row["client"] for row in rows] == ["c1", "c2", "c2"]
    assert rows[-1]["ts"] == 1101
    assert [row["client"] for row in g.alerts(client="c1")] == ["c1"]
    newest = g.alerts(limit=1)
    assert len(newest) == 1
    assert newest[0]["client"] == "c2"
    assert newest[0]["ts"] == 1101
    assert g.alerts(client="missing") == []


def test_snapshot_restore_round_trip_and_corruption_guard():
    g = make()
    g.allow_domain("good.com", note="cdn")
    g.ingest(ev(("a" * 31) + ".t.example.com", qtype="TXT"), now=1000)
    g.ingest(ev(("b" * 31) + ".t.example.com", qtype="TXT"), now=1001)
    assert len(g.alerts()) == 2
    g.block_client("c2", 120, now=1001)
    snap = g.snapshot()
    assert snap["version"] == 1
    snap["alerts"].clear()
    assert len(g.alerts()) == 2
    snap = g.snapshot()
    clone = make()
    clone.restore(snap)
    assert clone.client_state("c1", now=1001)["events"] == 2
    assert clone.client_state("c1", now=1001)["unique"] == 2
    assert clone.blocked(now=1050) == ["c2"]
    assert clone.ingest(ev("x.good.com"),
                        now=1050)["code"] == "DNS_ALLOWLISTED"
    with pytest.raises(dtg.DnsTunnelError) as exc:
        clone.restore({"version": 2, "allowlist": {}, "clients": {},
                       "alerts": []})
    assert exc.value.code == "DNS_SNAPSHOT_CORRUPT"
    assert clone.client_state("c1", now=1001)["events"] == 2
    bad = dict(snap)
    bad["clients"] = {"c1": {"events": "nope"}}
    with pytest.raises(dtg.DnsTunnelError) as exc:
        clone.restore(bad)
    assert exc.value.code == "DNS_SNAPSHOT_CORRUPT"
    assert clone.blocked(now=1050) == ["c2"]


def test_concurrent_ingest_keeps_buffer_and_alert_log_bounded():
    g = make(max_events=20, unique_threshold=1000, block_seconds=1,
             max_alerts=10)
    errors = []

    def worker(index):
        try:
            for step in range(8):
                g.ingest(ev(f"u{index}-{step}.example.com", client="busy"),
                         now=1000)
        except Exception as exc:  # noqa: BLE001
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    state = g.client_state("busy", now=1000)
    assert state["events"] == 20
    assert state["unique"] == 20
    assert len(g.alerts()) == 0
