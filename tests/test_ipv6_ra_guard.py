import json

import pytest

import ipv6_ra_guard as ra


def pfx(prefix="2001:db8:10::/64", valid=3600, preferred=1800):
    return {
        "prefix": prefix,
        "valid": valid,
        "preferred": preferred,
        "on_link": True,
        "autonomous": True,
    }


def packet(port="ge-0/0/1", *, prefixes=None, at=1000, **overrides):
    row = {
        "port": port,
        "type": "RA",
        "src": "fe80::1",
        "dst": "ff02::1",
        "hop_limit": 255,
        "router_lifetime": 1800,
        "flags": {"M": 0, "O": 0},
        "prefixes": [pfx()] if prefixes is None else list(prefixes),
        "at": at,
    }
    row.update(overrides)
    return row


def guard():
    return ra.RaGuard()


def uplink(g, port="ge-0/0/1", vlan=10, allowed=("2001:db8::/48",), default_route=True):
    g.configure_port(port, "uplink", vlan=vlan, allowed_prefixes=allowed,
                     default_route=default_route)
    return g


def configured():
    g = guard()
    uplink(g)
    return g


def test_untrusted_port_drops_every_neighbor_message():
    g = guard()
    g.configure_port("ge-0/0/9", "untrusted", vlan=10)
    out = g.ingest({"port": "ge-0/0/9", "type": "NS", "src": "fe80::9",
                    "dst": "ff02::1", "hop_limit": 255, "at": 1000})
    assert out["action"] == "drop"
    assert out["code"] == "RA_ROLE_DENIED"
    stats = g.port_stats("ge-0/0/9")
    assert stats["dropped"] == 1
    assert stats["accepted"] == 0


def test_host_port_cannot_advertise_a_router():
    g = guard()
    g.configure_port("ge-0/0/2", "host", vlan=10, allowed_prefixes=("2001:db8::/48",))
    out = g.ingest(packet("ge-0/0/2"))
    assert out["code"] == "RA_ROLE_DENIED"
    assert g.prefix_table(10) == []


def test_hop_limit_must_be_255():
    g = configured()
    out = g.ingest(packet(hop_limit=64))
    assert out["action"] == "drop"
    assert out["code"] == "RA_HOP_LIMIT"
    assert g.port_stats("ge-0/0/1")["dropped"] == 1


def test_source_must_be_link_local():
    g = configured()
    out = g.ingest(packet(src="2001:db8::1"))
    assert out["code"] == "RA_SRC_NOT_LINK_LOCAL"
    assert g.prefix_table(10) == []


def test_destination_must_be_all_nodes_multicast():
    g = configured()
    out = g.ingest(packet(dst="ff02::2"))
    assert out["code"] == "RA_DST_INVALID"
    assert g.port_stats("ge-0/0/1")["accepted"] == 0


def test_prefix_count_is_capped():
    g = configured()
    many = [pfx("2001:db8:%x::/64" % index, 3600, 1800) for index in range(9)]
    out = g.ingest(packet(prefixes=many))
    assert out["code"] == "RA_TOO_MANY_PREFIXES"
    assert g.prefix_table(10) == []


def test_prefix_length_must_be_64():
    g = configured()
    out = g.ingest(packet(prefixes=[pfx("2001:db8:10::/48")]))
    assert out["code"] == "RA_PREFIX_LEN"
    assert g.prefix_table(10) == []


def test_preferred_lifetime_cannot_exceed_valid():
    g = configured()
    out = g.ingest(packet(prefixes=[pfx(valid=3600, preferred=3600)]))
    assert out["action"] == "accept"
    bad = g.ingest(packet(prefixes=[pfx("2001:db8:20::/64", valid=3600,
                                        preferred=7200)], at=1010))
    assert bad["code"] == "RA_LIFETIME_ORDER"
    assert [row["prefix"] for row in g.prefix_table(10)] == ["2001:db8:10::/64"]


def test_minimum_valid_lifetime_is_enforced():
    g = configured()
    out = g.ingest(packet(prefixes=[pfx(valid=300, preferred=150)]))
    assert out["code"] == "RA_LIFETIME_TOO_SHORT"
    assert g.port_stats("ge-0/0/1")["accepted"] == 0


def test_default_route_requires_port_opt_in():
    g = guard()
    uplink(g, default_route=False)
    denied = g.ingest(packet())
    assert denied["action"] == "drop"
    assert denied["code"] == "RA_DEFAULT_ROUTE_DENIED"
    allowed = g.ingest(packet(router_lifetime=0, at=1010))
    assert allowed["action"] == "accept"
    assert allowed["code"] == "RA_ACCEPTED"


def test_prefix_outside_allowed_list_is_dropped():
    g = guard()
    uplink(g, allowed=("2001:db8:10::/48",))
    out = g.ingest(packet(prefixes=[pfx("2001:db8:99::/64")]))
    assert out["code"] == "RA_PREFIX_NOT_ALLOWED"
    assert g.prefix_table(10) == []
    ok = g.ingest(packet(prefixes=[pfx("2001:db8:10::/64")], at=1010))
    assert ok["action"] == "accept"


def test_rate_limit_drops_excess_ra_per_port():
    g = configured()
    g.configure_port("ge-0/0/5", "uplink", vlan=10,
                     allowed_prefixes=("2001:db8::/48",), default_route=True)
    outcomes = [g.ingest(packet(at=1000))["action"] for _ in range(6)]
    assert outcomes == ["accept", "accept", "accept", "accept", "accept",
                        "rate_limited"]
    stats = g.port_stats("ge-0/0/1")
    assert stats["accepted"] == 5
    assert stats["rate_limited"] == 1
    other = g.ingest(packet(port="ge-0/0/5", at=1000))
    assert other["action"] == "accept"


def test_violation_threshold_quarantines_port_until_expiry():
    g = configured()
    for _ in range(3):
        out = g.ingest(packet(hop_limit=64, at=1000))
        assert out["code"] == "RA_HOP_LIMIT"
    stats = g.port_stats("ge-0/0/1")
    assert stats["violations"] == 3
    assert stats["quarantined_until"] == 1300
    assert [row["code"] for row in g.violations("ge-0/0/1")] == [
        "RA_HOP_LIMIT", "RA_HOP_LIMIT", "RA_HOP_LIMIT",
    ]
    blocked = g.ingest(packet(at=1001))
    assert blocked["action"] == "quarantined"
    assert blocked["code"] == "RA_PORT_QUARANTINED"
    assert g.expire(1300) == ["ge-0/0/1"]
    recovered = g.ingest(packet(at=1300))
    assert recovered["action"] == "accept"


def test_prefix_table_is_monotonic_and_scoped_to_vlan():
    g = guard()
    uplink(g, allowed=("2001:db8::/32",))
    g.configure_port("ge-0/0/3", "host", vlan=10)
    g.configure_port("ge-0/0/4", "host", vlan=20)
    out = g.ingest(packet(prefixes=[pfx("2001:db8:10::/64"),
                                    pfx("2001:db8:9::/64")], at=1000))
    assert out["action"] == "accept"
    assert [row["prefix"] for row in g.prefix_table(10)] == [
        "2001:db8:9::/64", "2001:db8:10::/64",
    ]
    assert g.prefix_table(20) == []
    assert g.effective_prefixes("ge-0/0/3", now=4500) == [
        "2001:db8:9::/64", "2001:db8:10::/64",
    ]
    assert g.effective_prefixes("ge-0/0/4", now=4500) == []
    assert g.effective_prefixes("ge-0/0/3", now=4700) == []
    short = g.ingest(packet(prefixes=[pfx("2001:db8:10::/64", valid=300,
                                          preferred=150)], at=1100))
    assert short["action"] == "accept"
    rows = {row["prefix"]: row for row in g.prefix_table(10)}
    assert rows["2001:db8:10::/64"]["valid"] == 3600
    assert rows["2001:db8:10::/64"]["expires_at"] == 4600
    assert g.port_stats("ge-0/0/1")["ignored"] == 1


def test_snapshot_restore_keeps_prefixes_quarantine_and_counters():
    g = configured()
    g.configure_port("ge-0/0/7", "uplink", vlan=10,
                     allowed_prefixes=("2001:db8::/48",), default_route=True)
    g.ingest(packet(prefixes=[pfx("2001:db8:10::/64", valid=7200,
                                  preferred=3600)], at=1000))
    for _ in range(3):
        g.ingest(packet(port="ge-0/0/7", hop_limit=1, at=1000))
    snap = json.loads(json.dumps(g.snapshot()))
    assert snap["version"] == ra.SNAPSHOT_VERSION
    restored = guard()
    restored.restore(snap)
    assert [row["prefix"] for row in restored.prefix_table(10)] == [
        "2001:db8:10::/64",
    ]
    assert restored.port_stats("ge-0/0/1")["accepted"] == 1
    blocked = restored.ingest(packet(port="ge-0/0/7", at=1001))
    assert blocked["code"] == "RA_PORT_QUARANTINED"
    assert restored.port_stats("ge-0/0/7")["quarantined_until"] == 1300
    with pytest.raises(ra.RaError) as exc:
        restored.restore(dict(snap, version=99))
    assert exc.value.code == "RA_SNAPSHOT_CORRUPT"
    assert restored.port_stats("ge-0/0/1")["accepted"] == 1
