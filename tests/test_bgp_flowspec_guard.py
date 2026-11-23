import threading

import pytest

import bgp_flowspec_guard as fsg


def make(**kwargs):
    return fsg.FlowspecGuard(**kwargs)


def add_peer(guard, name="edge-a", role="edge", asn=65001, prefixes=()):
    return guard.register_peer(name, role=role, asn=asn, prefixes=prefixes)


def rule(destination="10.0.0.0/8", **extra):
    out = {"destination": destination, "action": "discard", "priority": 100}
    out.update(extra)
    return out


def test_peer_registration_validates_role_asn_and_prefixes():
    g = make()
    with pytest.raises(fsg.FlowspecError) as exc:
        g.register_peer("edge-x", role="router", asn=65001)
    assert exc.value.code == "FSP_BAD_ROLE"
    with pytest.raises(fsg.FlowspecError) as exc:
        g.register_peer("edge-x", role="edge", asn=0)
    assert exc.value.code == "FSP_BAD_ASN"
    with pytest.raises(fsg.FlowspecError) as exc:
        g.register_peer("edge-x", role="edge", asn=4294967296)
    assert exc.value.code == "FSP_BAD_ASN"
    with pytest.raises(fsg.FlowspecError) as exc:
        g.register_peer("edge-x", role="edge", asn=65001,
                        prefixes=("10.0.0.0/33",))
    assert exc.value.code == "FSP_BAD_PREFIX"
    first = g.register_peer("edge-x", role="edge", asn=65001,
                            prefixes=("10.0.0.0/8",))
    assert first["status"] == "registered"
    assert first["prefixes"] == ("10.0.0.0/8",)
    again = g.register_peer("edge-x", role="edge", asn=65001,
                            prefixes=("10.0.0.0/8",))
    assert again["status"] == "unchanged"
    with pytest.raises(fsg.FlowspecError) as exc:
        g.register_peer("edge-x", role="customer", asn=65001, prefixes=())
    assert exc.value.code == "FSP_PEER_CONFLICT"


def test_unknown_and_untrusted_peers_cannot_inject():
    g = make()
    unknown = g.ingest(rule(), peer="ghost", now=1000)
    assert unknown["action"] == "rejected"
    assert unknown["code"] == "FSP_PEER_UNKNOWN"
    add_peer(g, "untrusted-1", role="untrusted", asn=65100)
    denied = g.ingest(rule(), peer="untrusted-1", now=1000)
    assert denied["action"] == "rejected"
    assert denied["code"] == "FSP_PEER_DENIED"
    add_peer(g, "up-1", role="upstream", asn=65101)
    denied = g.ingest(rule(), peer="up-1", now=1000)
    assert denied["code"] == "FSP_PEER_DENIED"
    assert g.rules() == []
    assert g.stats("untrusted-1")["accepted"] == 0


def test_customer_may_only_inject_inside_owned_prefixes():
    g = make()
    add_peer(g, "cust-1", role="customer", asn=65200,
             prefixes=("10.20.0.0/16",))
    exact = g.ingest(rule("10.20.0.0/16"), peer="cust-1", now=1000)
    assert exact["action"] == "accept"
    narrower = g.ingest(rule("10.20.5.0/24"), peer="cust-1", now=1001)
    assert narrower["action"] == "accept"
    wider = g.ingest(rule("10.0.0.0/8"), peer="cust-1", now=1002)
    assert wider["action"] == "rejected"
    assert wider["code"] == "FSP_PREFIX_NOT_OWNED"
    outside = g.ingest(rule("10.21.0.0/24"), peer="cust-1", now=1003)
    assert outside["code"] == "FSP_PREFIX_NOT_OWNED"
    assert len(g.rules()) == 2


def test_destination_is_required_and_must_parse():
    g = make()
    add_peer(g)
    missing = g.ingest({"action": "discard", "priority": 100},
                       peer="edge-a", now=1000)
    assert missing["action"] == "rejected"
    assert missing["code"] == "FSP_BAD_RULE"
    bad = g.ingest(rule("10.0.0.0/33"), peer="edge-a", now=1000)
    assert bad["action"] == "rejected"
    assert bad["code"] == "FSP_BAD_PREFIX"
    v6 = g.ingest(rule("2001:db8::/32"), peer="edge-a", now=1000)
    assert v6["action"] == "accept"
    assert g.rules()[0]["destination"] == "2001:db8::/32"


def test_match_components_are_validated():
    g = make(max_components=3)
    add_peer(g)
    unknown = g.ingest(rule(payload=b"x"), peer="edge-a", now=1000)
    assert unknown["code"] == "FSP_BAD_COMPONENT"
    too_many = g.ingest(
        rule(source="192.0.2.0/24", protocol=6, port="80-90",
             tcp_flags=["syn"]),
        peer="edge-a", now=1000,
    )
    assert too_many["code"] == "FSP_TOO_MANY_COMPONENTS"
    reversed_range = g.ingest(rule(port="90-80"), peer="edge-a", now=1000)
    assert reversed_range["code"] == "FSP_BAD_PORT_RANGE"
    bad_protocol = g.ingest(rule(protocol=256), peer="edge-a", now=1000)
    assert bad_protocol["code"] == "FSP_BAD_RULE"
    assert g.rules() == []


def test_redirect_action_requires_allowed_next_hop():
    g = make(allowed_next_hops=("192.0.2.9",))
    add_peer(g)
    missing = g.ingest(rule(action="redirect"), peer="edge-a", now=1000)
    assert missing["code"] == "FSP_BAD_ACTION"
    denied = g.ingest(rule(action="redirect", next_hop="198.51.100.7"),
                      peer="edge-a", now=1000)
    assert denied["code"] == "FSP_NEXT_HOP_DENIED"
    stray = g.ingest(rule(action="discard", next_hop="192.0.2.9"),
                     peer="edge-a", now=1000)
    assert stray["code"] == "FSP_BAD_ACTION"
    bad_action = g.ingest(rule(action="mirror"), peer="edge-a", now=1000)
    assert bad_action["code"] == "FSP_BAD_ACTION"
    ok = g.ingest(rule(action="redirect", next_hop="192.0.2.9"),
                  peer="edge-a", now=1000)
    assert ok["action"] == "accept"
    assert ok["code"] == "FSP_ACCEPTED"


def test_identical_rule_is_idempotent_per_peer():
    g = make()
    add_peer(g)
    add_peer(g, "edge-b", asn=65002)
    first = g.ingest(rule(), peer="edge-a", now=1000)
    assert first["action"] == "accept"
    second = g.ingest(rule(), peer="edge-a", now=1001)
    assert second["action"] == "duplicate"
    assert second["code"] == "FSP_DUPLICATE"
    assert second["rule_id"] == first["rule_id"]
    assert len(g.rules()) == 1
    stats = g.stats("edge-a")
    assert stats["accepted"] == 1
    assert stats["duplicates"] == 1
    assert stats["active"] == 1
    other = g.ingest(rule(), peer="edge-b", now=1002)
    assert other["action"] == "accept"
    assert other["rule_id"] != first["rule_id"]
    assert len(g.rules()) == 2


def test_priority_conflict_keeps_only_the_winner():
    g = make()
    add_peer(g)
    base = g.ingest(rule(priority=100), peer="edge-a", now=1000)
    assert base["action"] == "accept"
    weaker = g.ingest(rule(priority=200), peer="edge-a", now=1001)
    assert weaker["action"] == "rejected"
    assert weaker["code"] == "FSP_CONFLICT"
    same = g.ingest(rule(priority=100, action="rate-limit"),
                    peer="edge-a", now=1002)
    assert same["code"] == "FSP_CONFLICT"
    stronger = g.ingest(rule(priority=50, action="rate-limit"),
                        peer="edge-a", now=1003)
    assert stronger["action"] == "accept"
    assert stronger["code"] == "FSP_REPLACED"
    rows = g.rules()
    assert len(rows) == 1
    assert rows[0]["priority"] == 50
    assert rows[0]["action"] == "rate-limit"
    assert rows[0]["rule_id"] == stronger["rule_id"]


def test_rule_capacity_is_bounded_but_replacement_is_allowed():
    g = make(max_rules=2)
    add_peer(g)
    batch = g.ingest_batch(
        [
            rule("10.0.0.0/8", priority=100),
            rule("172.16.0.0/12", priority=100),
            rule("192.168.0.0/16", priority=100),
        ],
        peer="edge-a", now=1000,
    )
    assert [row["action"] for row in batch] == ["accept", "accept", "rejected"]
    assert batch[2]["code"] == "FSP_CAPACITY"
    assert len(g.rules()) == 2
    replaced = g.ingest(rule("10.0.0.0/8", priority=10),
                        peer="edge-a", now=1001)
    assert replaced["action"] == "accept"
    assert replaced["code"] == "FSP_REPLACED"
    assert len(g.rules()) == 2
    assert g.stats("edge-a")["rejected"] == 1


def test_rate_limit_blocks_abusive_peer_until_deadline():
    g = make(rate_limit=2, rate_window=60, violation_threshold=2,
             block_seconds=300)
    add_peer(g, "edge-a")
    add_peer(g, "edge-b", asn=65002)
    assert g.ingest(rule("10.1.0.0/16"), peer="edge-a",
                    now=1000)["action"] == "accept"
    assert g.ingest(rule("10.2.0.0/16"), peer="edge-a",
                    now=1000)["action"] == "accept"
    limited = g.ingest(rule("10.3.0.0/16"), peer="edge-a", now=1000)
    assert limited["action"] == "rate_limited"
    assert limited["code"] == "FSP_RATE_LIMIT"
    trigger = g.ingest(rule("10.4.0.0/16"), peer="edge-a", now=1005)
    assert trigger["action"] == "rate_limited"
    assert g.blocked(now=1005) == ["edge-a"]
    blocked = g.ingest(rule("10.5.0.0/16"), peer="edge-a", now=1010)
    assert blocked["action"] == "blocked"
    assert blocked["code"] == "FSP_PEER_BLOCKED"
    assert g.stats("edge-a")["rate_limited"] == 2
    assert g.ingest(rule("10.6.0.0/16"), peer="edge-b",
                    now=1010)["action"] == "accept"
    after = g.ingest(rule("10.7.0.0/16"), peer="edge-a", now=1305)
    assert after["action"] == "accept"
    assert g.blocked(now=1305) == []


def test_effective_lookup_orders_by_prefix_length_then_priority():
    g = make()
    add_peer(g)
    a = g.ingest(rule("10.0.0.0/8", priority=100), peer="edge-a", now=1000)
    b = g.ingest(rule("10.1.0.0/16", priority=200), peer="edge-a", now=1000)
    c = g.ingest(rule("10.1.2.0/24", priority=50), peer="edge-a", now=1000)
    d = g.ingest(rule("192.168.0.0/16", priority=10, ttl=10),
                 peer="edge-a", now=1000)
    ids = [row["rule_id"] for row in g.effective("10.1.2.3", now=1000)]
    assert ids == [c["rule_id"], b["rule_id"], a["rule_id"]]
    assert [row["rule_id"] for row in g.effective("10.2.0.1", now=1000)] == [
        a["rule_id"]
    ]
    assert g.effective("2001:db8::1", now=1000) == []
    assert [row["rule_id"] for row in g.effective("192.168.1.1", now=1000)] == [
        d["rule_id"]
    ]
    assert g.effective("192.168.1.1", now=1010) == []
    assert len(g.rules()) == 4


def test_expire_removes_only_due_rules_in_stable_order():
    g = make()
    add_peer(g)
    long_rule = g.ingest(rule("10.0.0.0/8", ttl=60),
                         peer="edge-a", now=1000)
    short_rule = g.ingest(rule("10.1.0.0/16", ttl=30),
                          peer="edge-a", now=1000)
    assert g.expire(1029) == []
    assert g.expire(1030) == [short_rule["rule_id"]]
    assert [row["rule_id"] for row in g.rules()] == [long_rule["rule_id"]]
    assert g.expire(1060) == [long_rule["rule_id"]]
    assert g.rules() == []
    assert g.stats("edge-a")["active"] == 0
    assert g.expire(2000) == []


def test_withdraw_removes_rule_and_frees_the_match():
    g = make()
    add_peer(g)
    accepted = g.ingest(rule(), peer="edge-a", now=1000)
    out = g.withdraw(accepted["rule_id"])
    assert out["status"] == "withdrawn"
    assert out["rule_id"] == accepted["rule_id"]
    assert g.rules() == []
    assert g.stats("edge-a")["active"] == 0
    with pytest.raises(fsg.FlowspecError) as exc:
        g.withdraw(accepted["rule_id"])
    assert exc.value.code == "FSP_UNKNOWN_RULE"
    again = g.ingest(rule(), peer="edge-a", now=1001)
    assert again["action"] == "accept"
    assert again["rule_id"] == accepted["rule_id"]


def test_snapshot_restore_round_trip_and_corruption_guard():
    g = make()
    add_peer(g, "edge-a")
    add_peer(g, "edge-b", asn=65002)
    a = g.ingest(rule("10.0.0.0/8"), peer="edge-a", now=1000)
    b = g.ingest(rule("172.16.0.0/12"), peer="edge-b", now=1000)
    g.block_peer("edge-b", 120, now=1000)
    snap = g.snapshot()
    assert snap["version"] == 1
    snap["rules"].clear()
    assert len(g.rules()) == 2
    snap = g.snapshot()
    clone = make()
    clone.restore(snap)
    assert [row["rule_id"] for row in clone.rules()] == [
        a["rule_id"], b["rule_id"]
    ]
    assert clone.stats()["accepted"] == 2
    assert clone.blocked(now=1050) == ["edge-b"]
    assert clone.stats("edge-b")["blocked"] is True
    with pytest.raises(fsg.FlowspecError) as exc:
        clone.restore({"version": 99, "peers": {}, "rules": [],
                       "stats": {}, "blocked": {}})
    assert exc.value.code == "FSP_SNAPSHOT_CORRUPT"
    assert len(clone.rules()) == 2
    bad = dict(snap)
    bad["rules"] = [{"rule_id": "x"}]
    with pytest.raises(fsg.FlowspecError) as exc:
        clone.restore(bad)
    assert exc.value.code == "FSP_SNAPSHOT_CORRUPT"
    assert len(clone.rules()) == 2


def test_concurrent_ingest_respects_capacity_and_counts():
    g = make(max_rules=10, rate_limit=1000)
    add_peer(g)
    errors = []
    accepted = []
    lock = threading.Lock()

    def worker(index):
        try:
            for step in range(6):
                out = g.ingest(rule(f"10.{index}.{step}.0/24"),
                               peer="edge-a", now=1000)
                if out["action"] == "accept":
                    with lock:
                        accepted.append(out["rule_id"])
        except Exception as exc:  # noqa: BLE001
            with lock:
                errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    assert len(accepted) == 10
    assert len(set(accepted)) == 10
    stats = g.stats("edge-a")
    assert stats["accepted"] == 10
    assert stats["rejected"] == 38
    assert stats["active"] == 10
    assert len(g.rules()) == 10
