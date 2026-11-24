import socket
import struct
import threading

import pytest

import proxy_protocol_guard as ppg

V2_SIG = b"\r\n\r\n\x00\r\nQUIT\n"
V1 = b"PROXY TCP4 192.0.2.9 10.0.0.2 51000 443\r\n"


def guard(**kwargs):
    return ppg.ProxyProtocolGuard(**kwargs)


def tlv(kind, value):
    return struct.pack("!BH", kind, len(value)) + value


def v2(command=1, family=0x11, src="192.0.2.9", dst="10.0.0.2",
       sport=51000, dport=443, tlvs=b"", length_delta=0, sig=V2_SIG):
    if family == 0x11:
        addr = (socket.inet_aton(src) + socket.inet_aton(dst)
                + struct.pack("!HH", sport, dport))
    elif family == 0x21:
        addr = (socket.inet_pton(socket.AF_INET6, src)
                + socket.inet_pton(socket.AF_INET6, dst)
                + struct.pack("!HH", sport, dport))
    else:
        addr = b""
    body = addr + tlvs
    return (sig + bytes([0x20 | command, family])
            + struct.pack("!H", len(body) + length_delta) + body)


def test_untrusted_peer_is_rejected_before_header_parsing():
    g = guard()
    with pytest.raises(ppg.ProxyProtocolError) as exc:
        g.parse(V1, peer="203.0.113.7")
    assert exc.value.code == "PPX_UNTRUSTED_PEER"
    stats = g.stats()
    assert stats["accepted"] == 0
    assert stats["rejected"] == 1
    assert stats["codes"] == {"PPX_UNTRUSTED_PEER": 1}
    assert g.recent(1)[0]["status"] == "rejected"


def test_trusted_peer_v1_tcp4_is_parsed_exactly():
    g = guard(trusted_peers=["10.0.0.0/24", "10.1.1.1"])
    assert g.is_trusted("10.0.0.7") is True
    assert g.is_trusted("10.1.1.1") is True
    assert g.is_trusted("10.1.1.2") is False
    out = g.parse(V1, peer="10.0.0.7")
    assert out == {
        "status": "accepted",
        "code": None,
        "version": 1,
        "command": "PROXY",
        "source": ("192.0.2.9", 51000),
        "destination": ("10.0.0.2", 443),
        "tlvs": {},
        "header_bytes": len(V1),
    }


def test_v1_unknown_command_has_no_addresses_and_bad_protocol_is_rejected():
    g = guard(trusted_peers=["10.0.0.7"])
    out = g.parse(b"PROXY UNKNOWN\r\n", peer="10.0.0.7")
    assert out["command"] == "UNKNOWN"
    assert out["source"] is None
    assert out["destination"] is None
    assert out["tlvs"] == {}
    with pytest.raises(ppg.ProxyProtocolError) as exc:
        g.parse(b"PROXY UDP4 192.0.2.9 10.0.0.2 51000 443\r\n",
                peer="10.0.0.7", connection="c2")
    assert exc.value.code == "PPX_BAD_PROTOCOL"
    assert g.stats()["accepted"] == 1
    assert g.stats()["rejected"] == 1


def test_v1_oversized_line_and_missing_crlf_are_rejected():
    g = guard(trusted_peers=["10.0.0.7"], max_header_bytes=64)
    with pytest.raises(ppg.ProxyProtocolError) as exc:
        g.parse(b"PROXY TCP4 " + b"1" * 80, peer="10.0.0.7")
    assert exc.value.code == "PPX_TOO_LARGE"
    with pytest.raises(ppg.ProxyProtocolError) as exc:
        g.parse(b"PROXY TCP4 192.0.2.9 10.0.0.2 51000 443", peer="10.0.0.7")
    assert exc.value.code == "PPX_TRUNCATED"


def test_v2_tcp4_with_tlvs_and_local_command_are_parsed():
    g = guard(trusted_peers=["10.0.0.0/8"])
    raw = v2(tlvs=tlv(0x01, b"h2") + tlv(0x02, b"api.example.com"))
    out = g.parse(raw, peer="10.0.0.7", connection="c1")
    assert out["version"] == 2
    assert out["command"] == "PROXY"
    assert out["source"] == ("192.0.2.9", 51000)
    assert out["destination"] == ("10.0.0.2", 443)
    assert out["tlvs"] == {"alpn": "h2", "authority": "api.example.com"}
    assert out["header_bytes"] == len(raw)

    local = g.parse(v2(command=0, family=0x00), peer="10.0.0.7", connection="c2")
    assert local["command"] == "LOCAL"
    assert local["source"] is None
    assert local["destination"] is None
    assert local["tlvs"] == {}


def test_v2_bad_signature_is_rejected():
    g = guard(trusted_peers=["10.0.0.7"])
    bad = v2(sig=V2_SIG[:11] + b"X")
    with pytest.raises(ppg.ProxyProtocolError) as exc:
        g.parse(bad, peer="10.0.0.7")
    assert exc.value.code == "PPX_BAD_SIGNATURE"
    assert g.stats()["codes"] == {"PPX_BAD_SIGNATURE": 1}


def test_v2_declared_length_must_match_body():
    g = guard(trusted_peers=["10.0.0.7"])
    with pytest.raises(ppg.ProxyProtocolError) as exc:
        g.parse(v2(length_delta=4), peer="10.0.0.7")
    assert exc.value.code == "PPX_LENGTH_MISMATCH"


def test_v2_tlv_duplicate_unknown_and_oversized_values_are_rejected():
    g = guard(trusted_peers=["10.0.0.7"])
    with pytest.raises(ppg.ProxyProtocolError) as exc:
        g.parse(v2(tlvs=tlv(0x01, b"h2") + tlv(0x01, b"h3")),
                peer="10.0.0.7", connection="d1")
    assert exc.value.code == "PPX_TLV_DUP"
    with pytest.raises(ppg.ProxyProtocolError) as exc:
        g.parse(v2(tlvs=tlv(0xEE, b"x")), peer="10.0.0.7", connection="d2")
    assert exc.value.code == "PPX_TLV_TYPE"
    with pytest.raises(ppg.ProxyProtocolError) as exc:
        g.parse(v2(tlvs=tlv(0x01, b"h" * 40)),
                peer="10.0.0.7", connection="d3")
    assert exc.value.code == "PPX_TLV_LEN"


def test_v2_total_tlv_bytes_are_capped():
    g = guard(trusted_peers=["10.0.0.7"], max_tlv_bytes=8)
    with pytest.raises(ppg.ProxyProtocolError) as exc:
        g.parse(v2(tlvs=tlv(0x01, b"h2") + tlv(0x02, b"abcdefg")),
                peer="10.0.0.7")
    assert exc.value.code == "PPX_TLV_TOO_LARGE"


def test_duplicate_connection_is_suppressed_and_lru_eviction_frees_it():
    g = guard(trusted_peers=["10.0.0.7"], max_connections=2)
    g.parse(V1, peer="10.0.0.7", connection="c1")
    g.parse(V1, peer="10.0.0.7", connection="c2")
    with pytest.raises(ppg.ProxyProtocolError) as exc:
        g.parse(V1, peer="10.0.0.7", connection="c1")
    assert exc.value.code == "PPX_DUPLICATE"
    g.parse(V1, peer="10.0.0.7", connection="c3")
    with pytest.raises(ppg.ProxyProtocolError) as exc:
        g.parse(V1, peer="10.0.0.7", connection="c2")
    assert exc.value.code == "PPX_DUPLICATE"
    g.parse(V1, peer="10.0.0.7", connection="c1")
    stats = g.stats()
    assert stats["connections"] == 2
    assert stats["evicted"] == 2


def test_snapshot_restore_is_deep_copy_and_preserves_connection_state():
    g = guard(trusted_peers=["10.0.0.0/24"], max_connections=4)
    g.parse(V1, peer="10.0.0.7", connection="c1")
    g.trust_source("198.51.100.5", now=100.0, ttl=30.0)
    snap = g.snapshot()
    pristine = g.snapshot()
    snap["counters"]["accepted"] = 999
    snap["trusted_peers"].append("203.0.113.0/24")
    snap["sources"]["198.51.100.5"] = 0.0
    assert g.stats()["accepted"] == 1
    assert g.is_trusted("10.0.0.7") is True
    assert g.is_trusted("203.0.113.9") is False
    assert g.check_source("198.51.100.5", now=110.0) is True

    restored = guard()
    restored.restore(pristine)
    assert restored.is_trusted("10.0.0.7") is True
    assert restored.check_source("198.51.100.5", now=129.0) is True
    assert restored.check_source("198.51.100.5", now=130.0) is False
    assert restored.stats()["accepted"] == 1
    with pytest.raises(ppg.ProxyProtocolError) as exc:
        restored.parse(V1, peer="10.0.0.7", connection="c1")
    assert exc.value.code == "PPX_DUPLICATE"
    with pytest.raises(ppg.ProxyProtocolError) as exc:
        restored.restore({"version": 2})
    assert exc.value.code == "PPX_STATE_VERSION"


def test_source_trust_expires_and_purge_counts_entries():
    g = guard()
    out = g.trust_source("198.51.100.5", now=100.0, ttl=10.0)
    assert out == {"source_ip": "198.51.100.5", "expires_at": 110.0}
    assert g.check_source("198.51.100.5", now=109.999) is True
    assert g.check_source("198.51.100.5", now=110.0) is False
    assert g.purge_sources(now=110.0) == 1
    assert g.check_source("198.51.100.5", now=111.0) is False
    assert g.purge_sources(now=111.0) == 0


def test_recent_log_is_chronological_and_capped_at_one_hundred():
    g = guard(trusted_peers=["10.0.0.7"], max_connections=200)
    for index in range(105):
        g.parse(b"PROXY UNKNOWN\r\n", peer="10.0.0.7", connection=f"c{index}")
    rows = g.recent(1000)
    assert len(rows) == 100
    assert rows[0]["connection"] == "c5"
    assert rows[-1]["connection"] == "c104"
    assert all(row["status"] == "accepted" for row in rows)
    assert [row["connection"] for row in g.recent(2)] == ["c103", "c104"]
    assert g.stats()["accepted"] == 105


def test_concurrent_parses_keep_counters_and_connections_atomic():
    g = guard(trusted_peers=["10.0.0.7"], max_connections=512)
    errors = []

    def work(worker):
        try:
            for index in range(10):
                g.parse(V1, peer="10.0.0.7", connection=f"t{worker}-{index}")
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=work, args=(n,)) for n in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    stats = g.stats()
    assert stats["accepted"] == 80
    assert stats["connections"] == 80
    assert stats["rejected"] == 0


def test_rejection_codes_are_counted_and_recent_keeps_order():
    g = guard(trusted_peers=["10.0.0.7"])
    attempts = [
        (V1, "203.0.113.1", "PPX_UNTRUSTED_PEER"),
        (b"PROXY UDP4 192.0.2.9 10.0.0.2 51000 443\r\n",
         "10.0.0.7", "PPX_BAD_PROTOCOL"),
        (v2(sig=V2_SIG[:11] + b"Y"), "10.0.0.7", "PPX_BAD_SIGNATURE"),
    ]
    for raw, peer, code in attempts:
        with pytest.raises(ppg.ProxyProtocolError) as exc:
            g.parse(raw, peer=peer)
        assert exc.value.code == code
    stats = g.stats()
    assert stats["accepted"] == 0
    assert stats["rejected"] == 3
    assert stats["codes"] == {
        "PPX_UNTRUSTED_PEER": 1,
        "PPX_BAD_PROTOCOL": 1,
        "PPX_BAD_SIGNATURE": 1,
    }
    assert [row["code"] for row in g.recent(3)] == [
        "PPX_UNTRUSTED_PEER", "PPX_BAD_PROTOCOL", "PPX_BAD_SIGNATURE",
    ]
