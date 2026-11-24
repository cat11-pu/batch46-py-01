import threading

import pytest

import gtp_teid_guard as gtg

PEER = "10.0.0.9"


def guard(**kwargs):
    return gtg.GtpGuard(**kwargs)


def msg(**overrides):
    value = {
        "version": 1,
        "pt": 1,
        "s": False,
        "pn": False,
        "e": False,
        "msg_type": 255,
        "teid": 100,
        "seq": 1,
        "payload_bytes": 10,
        "extensions": [],
    }
    value.update(overrides)
    return value


def echo_resp(seq):
    return {"version": 1, "pt": 1, "msg_type": 2, "s": True, "seq": seq}


def open_default(g, tenant="a", teid=100, now=0.0):
    return g.open_tunnel(
        tenant, local_teid=teid, peer_teid=200, peer_ip=PEER,
        slice_id=7, now=now,
    )


def test_open_tunnel_validates_teid_and_stores_the_record():
    g = guard()
    out = open_default(g, now=1.0)
    assert out["tenant"] == "a"
    assert out["local_teid"] == 100
    assert out["peer_teid"] == 200
    assert out["peer_ip"] == PEER
    assert out["slice_id"] == 7
    assert out["created"] is True
    assert out["created_at"] == 1.0
    assert out["last_seen"] == 1.0
    assert g.tunnel(100)["tenant"] == "a"
    assert g.tunnel(101) is None
    with pytest.raises(gtg.GtpError) as exc:
        open_default(g, teid=0)
    assert exc.value.code == "GTP_TEID_RESERVED"
    with pytest.raises(gtg.GtpError) as exc:
        open_default(g, teid=1 << 32)
    assert exc.value.code == "GTP_BAD_TEID"


def test_duplicate_open_is_idempotent_but_conflicting_claims_fail():
    g = guard()
    open_default(g)
    again = open_default(g)
    assert again["created"] is False
    assert again["created_at"] == 0.0
    with pytest.raises(gtg.GtpError) as exc:
        g.open_tunnel("a", local_teid=100, peer_teid=201, peer_ip=PEER)
    assert exc.value.code == "GTP_TEID_CONFLICT"
    with pytest.raises(gtg.GtpError) as exc:
        g.open_tunnel("b", local_teid=100, peer_teid=200, peer_ip=PEER)
    assert exc.value.code == "GTP_TEID_CONFLICT"
    assert g.stats()["tunnels"] == 1


def test_tunnel_capacity_is_enforced():
    g = guard(max_tunnels=2)
    open_default(g, teid=100)
    open_default(g, teid=101)
    with pytest.raises(gtg.GtpError) as exc:
        open_default(g, teid=102)
    assert exc.value.code == "GTP_TUNNEL_LIMIT"
    assert g.stats()["tunnels"] == 2


def test_classify_rejects_bad_version_pt_and_message_type():
    g = guard()
    open_default(g)
    with pytest.raises(gtg.GtpError) as exc:
        g.classify(msg(version=2), peer_ip=PEER)
    assert exc.value.code == "GTP_BAD_VERSION"
    with pytest.raises(gtg.GtpError) as exc:
        g.classify(msg(pt=0), peer_ip=PEER)
    assert exc.value.code == "GTP_BAD_PT"
    with pytest.raises(gtg.GtpError) as exc:
        g.classify(msg(msg_type=7), peer_ip=PEER)
    assert exc.value.code == "GTP_BAD_TYPE"


def test_unknown_teid_tenant_mismatch_and_peer_mismatch():
    g = guard()
    open_default(g)
    with pytest.raises(gtg.GtpError) as exc:
        g.classify(msg(), peer_ip=PEER, tenant="b")
    assert exc.value.code == "GTP_TENANT_MISMATCH"
    with pytest.raises(gtg.GtpError) as exc:
        g.classify(msg(), peer_ip="10.0.0.10")
    assert exc.value.code == "GTP_PEER_MISMATCH"
    with pytest.raises(gtg.GtpError) as exc:
        g.classify(msg(teid=999), peer_ip=PEER)
    assert exc.value.code == "GTP_UNKNOWN_TEID"


def test_g_pdu_payload_length_is_bounded_and_required():
    g = guard()
    open_default(g)
    with pytest.raises(gtg.GtpError) as exc:
        g.classify(msg(payload_bytes=0), peer_ip=PEER)
    assert exc.value.code == "GTP_BAD_LENGTH"
    with pytest.raises(gtg.GtpError) as exc:
        g.classify(msg(payload_bytes=65536), peer_ip=PEER)
    assert exc.value.code == "GTP_BAD_LENGTH"
    out = g.classify(msg(payload_bytes=10), peer_ip=PEER)
    assert out == {
        "status": "accepted",
        "code": None,
        "tenant": "a",
        "local_teid": 100,
        "peer_teid": 200,
        "msg_type": 255,
        "payload_bytes": 10,
        "slice_id": 7,
        "last_seen": 0.0,
        "extensions": 0,
    }


def test_extension_header_chain_limits_and_duplicates():
    g = guard(max_ext_headers=4)
    open_default(g)
    with pytest.raises(gtg.GtpError) as exc:
        g.classify(msg(e=True, extensions=[]), peer_ip=PEER)
    assert exc.value.code == "GTP_EXT_EMPTY"
    with pytest.raises(gtg.GtpError) as exc:
        g.classify(msg(e=True, extensions=[1, 2, 3, 4, 5]), peer_ip=PEER)
    assert exc.value.code == "GTP_EXT_LIMIT"
    with pytest.raises(gtg.GtpError) as exc:
        g.classify(msg(e=True, extensions=[0x85, 0x85]), peer_ip=PEER)
    assert exc.value.code == "GTP_EXT_LOOP"
    with pytest.raises(gtg.GtpError) as exc:
        g.classify(msg(e=False, extensions=[1]), peer_ip=PEER)
    assert exc.value.code == "GTP_EXT_UNEXPECTED"


def test_echo_requests_are_answered_and_not_deduplicated():
    g = guard()
    open_default(g)
    request = {"version": 1, "pt": 1, "msg_type": 1, "s": True, "seq": 5}
    first = g.echo(request, peer_ip=PEER)
    assert first == {
        "status": "accepted", "code": None, "response": True,
        "peer_ip": PEER, "seq": 5, "msg_type": 1,
    }
    second = g.echo(request, peer_ip=PEER)
    assert second["response"] is True
    assert g.stats()["echo_requests"] == 2


def test_echo_response_dedup_and_stale_sequence_window():
    g = guard(seq_window=64)
    open_default(g)
    first = g.echo(echo_resp(100), peer_ip=PEER)
    assert first["response"] is False
    assert first["highest"] == 100
    with pytest.raises(gtg.GtpError) as exc:
        g.echo(echo_resp(100), peer_ip=PEER)
    assert exc.value.code == "GTP_DUP_SEQ"
    with pytest.raises(gtg.GtpError) as exc:
        g.echo(echo_resp(30), peer_ip=PEER)
    assert exc.value.code == "GTP_STALE_SEQ"
    later = g.echo(echo_resp(90), peer_ip=PEER)
    assert later["highest"] == 100
    with pytest.raises(gtg.GtpError) as exc:
        g.echo(echo_resp(90), peer_ip=PEER)
    assert exc.value.code == "GTP_DUP_SEQ"
    edge = g.echo(echo_resp(36), peer_ip=PEER)
    assert edge["seq"] == 36


def test_idle_expiry_closes_tunnel_and_frees_the_teid():
    g = guard(idle_ttl=10.0)
    open_default(g, now=0.0)
    assert g.expire_idle(now=10.0) == []
    assert g.expire_idle(now=10.1) == [100]
    assert g.tunnel(100) is None
    with pytest.raises(gtg.GtpError) as exc:
        g.classify(msg(), peer_ip=PEER)
    assert exc.value.code == "GTP_UNKNOWN_TEID"
    reopened = open_default(g, now=10.2)
    assert reopened["created"] is True
    assert reopened["last_seen"] == 10.2


def test_close_tunnel_allows_teid_reuse_and_counts_closures():
    g = guard()
    open_default(g)
    closed = g.close_tunnel(100)
    assert closed["local_teid"] == 100
    assert closed["tenant"] == "a"
    assert g.close_tunnel(100) is None
    assert g.tunnels_for("a") == []
    reopened = open_default(g)
    assert reopened["created"] is True
    assert g.stats()["closed"] == 1


def test_tunnels_for_is_sorted_and_returns_copies():
    g = guard()
    open_default(g, tenant="a", teid=300)
    open_default(g, tenant="a", teid=100)
    open_default(g, tenant="b", teid=200)
    rows = g.tunnels_for("a")
    assert [row["local_teid"] for row in rows] == [100, 300]
    rows[0]["tenant"] = "hacked"
    assert g.tunnel(100)["tenant"] == "a"
    assert [row["local_teid"] for row in g.tunnels_for("b")] == [200]
    assert g.tunnels_for("z") == []


def test_snapshot_restore_preserves_tunnels_echo_state_and_counters():
    g = guard()
    open_default(g, now=1.0)
    g.classify(msg(), peer_ip=PEER, now=2.0)
    g.echo(echo_resp(100), peer_ip=PEER, now=2.0)
    snap = g.snapshot()
    pristine = g.snapshot()
    snap["tunnels"][100]["tenant"] = "hacked"
    snap["counters"]["accepted"] = 99
    snap["echo"][PEER]["highest"] = 1
    assert g.tunnel(100)["tenant"] == "a"
    assert g.stats()["accepted"] == 1

    restored = guard()
    restored.restore(pristine)
    assert restored.tunnel(100)["tenant"] == "a"
    assert restored.stats()["accepted"] == 1
    assert restored.stats()["echo_responses"] == 1
    with pytest.raises(gtg.GtpError) as exc:
        restored.echo(echo_resp(100), peer_ip=PEER)
    assert exc.value.code == "GTP_DUP_SEQ"
    out = restored.classify(msg(), peer_ip=PEER, now=5.0)
    assert out["status"] == "accepted"
    assert out["last_seen"] == 5.0
    with pytest.raises(gtg.GtpError) as exc:
        restored.restore({"version": 2})
    assert exc.value.code == "GTP_STATE_VERSION"


def test_concurrent_open_and_classify_are_atomic():
    g = guard(max_tunnels=128)
    errors = []

    def work(worker):
        try:
            teid = 500 + worker
            peer = f"10.0.0.{worker + 1}"
            g.open_tunnel(
                f"tenant{worker % 4}", local_teid=teid, peer_teid=900 + worker,
                peer_ip=peer, now=0.0,
            )
            g.classify(msg(teid=teid), peer_ip=peer, now=1.0)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=work, args=(n,)) for n in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    stats = g.stats()
    assert stats["tunnels"] == 8
    assert stats["accepted"] == 8
    assert stats["tenants"] == 4
    assert len(g.tunnels_for("tenant0")) == 2


def test_rejection_codes_are_counted_per_failure():
    g = guard()
    open_default(g)
    attempts = [
        (msg(version=2), PEER, None, "GTP_BAD_VERSION"),
        (msg(teid=999), PEER, None, "GTP_UNKNOWN_TEID"),
        (msg(), PEER, "b", "GTP_TENANT_MISMATCH"),
    ]
    for message, peer, tenant, code in attempts:
        with pytest.raises(gtg.GtpError) as exc:
            g.classify(message, peer_ip=peer, tenant=tenant)
        assert exc.value.code == code
    stats = g.stats()
    assert stats["rejected"] == 3
    assert stats["codes"] == {
        "GTP_BAD_VERSION": 1,
        "GTP_UNKNOWN_TEID": 1,
        "GTP_TENANT_MISMATCH": 1,
    }
    out = g.classify(msg(), peer_ip=PEER)
    assert out["status"] == "accepted"
    assert g.stats()["accepted"] == 1
    assert g.stats()["g_pdu"] == 1
