import threading

import pytest

import vxlan_tenant_guard as vtg

MAC1 = "aa:bb:cc:dd:ee:01"
MAC2 = "aa:bb:cc:dd:ee:02"
MAC3 = "aa:bb:cc:dd:ee:03"
BCAST = "ff:ff:ff:ff:ff:ff"


def guard(**kwargs):
    return vtg.VxlanGuard(**kwargs)


def frame(src, dst, size=100, **extra):
    value = {"src_mac": src, "dst_mac": dst, "size": size}
    value.update(extra)
    return value


def test_reserved_vni_values_are_rejected_before_registration():
    g = guard()
    for bad in (0, 16777215, -1, 1 << 24):
        with pytest.raises(vtg.VxlanError) as exc:
            g.register_tenant("t1", bad)
        assert exc.value.code == "VX_VNI_RESERVED"
    out = g.register_tenant("t1", 100)
    assert out == {"tenant": "t1", "vni": 100, "mc_group": None, "created": True}
    assert g.tenant_for_vni(100) == "t1"
    assert g.vni_for_tenant("t1") == 100
    assert g.tenant_for_vni(101) is None


def test_duplicate_vni_and_tenant_rebinding_are_rejected_but_same_claim_is_idempotent():
    g = guard()
    g.register_tenant("a", 100)
    with pytest.raises(vtg.VxlanError) as exc:
        g.register_tenant("b", 100)
    assert exc.value.code == "VX_VNI_CONFLICT"
    with pytest.raises(vtg.VxlanError) as exc:
        g.register_tenant("a", 200)
    assert exc.value.code == "VX_TENANT_CONFLICT"
    again = g.register_tenant("a", 100)
    assert again["created"] is False
    assert again["vni"] == 100
    assert g.tenant_for_vni(200) is None


def test_multicast_group_is_exclusive_across_tenants():
    g = guard()
    g.register_tenant("a", 100, mc_group="239.1.1.1")
    with pytest.raises(vtg.VxlanError) as exc:
        g.register_tenant("b", 200, mc_group="239.1.1.1")
    assert exc.value.code == "VX_MC_CONFLICT"
    out = g.register_tenant("b", 200, mc_group="239.1.1.2")
    assert out["created"] is True
    assert out["mc_group"] == "239.1.1.2"


def test_vni_registry_capacity_is_enforced():
    g = guard(max_vnis=2)
    g.register_tenant("a", 100)
    g.register_tenant("b", 200)
    with pytest.raises(vtg.VxlanError) as exc:
        g.register_tenant("c", 300)
    assert exc.value.code == "VX_VNI_LIMIT"
    assert g.stats()["tenants"] == 2


def test_port_binding_conflicts_invalid_macs_and_idempotent_rebind():
    g = guard()
    g.register_tenant("a", 100)
    first = g.bind_port("p1", "a", "AA:BB:CC:DD:EE:01")
    assert first == {"port": "p1", "tenant": "a", "vni": 100, "mac": MAC1}
    assert g.bind_port("p1", "a", MAC1) == first
    g.register_tenant("b", 200)
    with pytest.raises(vtg.VxlanError) as exc:
        g.bind_port("p1", "b", MAC2)
    assert exc.value.code == "VX_PORT_CONFLICT"
    with pytest.raises(vtg.VxlanError) as exc:
        g.bind_port("p2", "a", "zz:bb:cc:dd:ee:02")
    assert exc.value.code == "VX_MAC_INVALID"
    out = g.bind_port("p2", "a", MAC2)
    assert out["vni"] == 100
    assert out["mac"] == MAC2


def test_source_mac_spoof_is_dropped_and_not_learned():
    g = guard()
    g.register_tenant("a", 100)
    g.bind_port("p1", "a", MAC1)
    out = g.ingress(frame(MAC2, BCAST), port="p1", now=0.0)
    assert out == {
        "action": "drop", "code": "VX_MAC_SPOOF",
        "tenant": "a", "vni": 100, "egress": [],
    }
    assert g.lookup(100, MAC2) is None
    out = g.ingress(frame(MAC1, BCAST), port="p1", now=0.0)
    assert out["action"] == "flood"
    assert out["egress"] == []
    assert g.stats()["drop"] == 1
    assert g.stats()["codes"] == {"VX_MAC_SPOOF": 1}


def test_unknown_unicast_floods_only_ports_of_the_same_tenant():
    g = guard()
    g.register_tenant("a", 100)
    g.register_tenant("b", 200)
    g.bind_port("p1", "a", MAC1)
    g.bind_port("p2", "a", MAC2)
    g.bind_port("p3", "b", MAC3)
    out = g.ingress(frame(MAC1, "02:00:00:00:00:99"),
                    port="p1", now=0.0)
    assert out == {
        "action": "flood", "code": None,
        "tenant": "a", "vni": 100, "egress": ["p2"],
    }
    assert g.stats()["flood"] == 1


def test_known_unicast_forwards_and_same_port_hairpin_is_dropped():
    g = guard()
    g.register_tenant("a", 100)
    g.bind_port("p1", "a", MAC1)
    g.bind_port("p2", "a", MAC2)
    g.ingress(frame(MAC2, BCAST), port="p2", now=0.0)
    out = g.ingress(frame(MAC1, MAC2), port="p1", now=0.1)
    assert out == {
        "action": "forward", "code": None,
        "tenant": "a", "vni": 100, "egress": ["p2"],
    }
    hairpin = g.ingress(frame(MAC2, MAC2), port="p2", now=0.2)
    assert hairpin["action"] == "drop"
    assert hairpin["code"] == "VX_HAIRPIN"
    assert g.lookup(100, MAC2) == "p2"
    assert g.stats()["forward"] == 1
    assert g.stats()["drop"] == 1


def test_double_tagged_frames_are_rejected_before_mac_learning():
    g = guard()
    g.register_tenant("a", 100)
    g.bind_port("p1", "a", MAC1)
    for ethertype in (0x8100, 0x88A8):
        out = g.ingress(frame(MAC1, BCAST, ethertype=ethertype),
                        port="p1", now=0.0)
        assert out["code"] == "VX_DOUBLE_TAG"
    assert g.lookup(100, MAC1) is None
    assert g.stats()["codes"] == {"VX_DOUBLE_TAG": 2}
    assert g.stats()["drop"] == 2


def test_mtu_and_vni_mismatch_drop_before_learning():
    g = guard()
    g.register_tenant("a", 100)
    g.bind_port("p1", "a", MAC1)
    out = g.ingress(frame(MAC1, BCAST, size=1601), port="p1", now=0.0)
    assert out["code"] == "VX_MTU_EXCEEDED"
    out = g.ingress(frame(MAC1, BCAST, vni=999), port="p1", now=0.0)
    assert out["code"] == "VX_VNI_MISMATCH"
    assert g.lookup(100, MAC1) is None
    assert g.stats()["drop"] == 2


def test_per_port_rate_limit_uses_sliding_window():
    g = guard(rate_limit_pps=2, rate_window=1.0)
    g.register_tenant("a", 100)
    g.bind_port("p1", "a", MAC1)
    g.bind_port("p2", "a", MAC2)
    packet = frame(MAC1, BCAST)
    assert g.ingress(packet, port="p1", now=0.0)["action"] == "flood"
    assert g.ingress(packet, port="p1", now=0.1)["action"] == "flood"
    limited = g.ingress(packet, port="p1", now=0.2)
    assert limited["code"] == "VX_RATE_LIMIT"
    limited = g.ingress(packet, port="p1", now=0.95)
    assert limited["code"] == "VX_RATE_LIMIT"
    assert g.ingress(packet, port="p1", now=1.2)["action"] == "flood"
    assert g.stats()["rate_dropped"] == 2
    assert g.stats()["codes"] == {"VX_RATE_LIMIT": 2}


def test_release_tenant_removes_ports_and_forwarding_entries():
    g = guard()
    g.register_tenant("a", 100)
    g.bind_port("p1", "a", MAC1)
    g.bind_port("p2", "a", MAC2)
    g.ingress(frame(MAC1, BCAST), port="p1", now=0.0)
    out = g.release_tenant("a")
    assert out == {"tenant": "a", "vni": 100, "ports": 2}
    assert g.tenant_for_vni(100) is None
    assert g.vni_for_tenant("a") is None
    assert g.lookup(100, MAC1) is None
    dropped = g.ingress(frame(MAC1, BCAST), port="p1", now=0.0)
    assert dropped == {
        "action": "drop", "code": "VX_UNKNOWN_PORT",
        "tenant": None, "vni": None, "egress": [],
    }
    assert g.release_tenant("a") is None


def test_snapshot_restore_preserves_mappings_and_is_deep_copy():
    g = guard()
    g.register_tenant("a", 100)
    g.bind_port("p1", "a", MAC1)
    g.ingress(frame(MAC1, BCAST), port="p1", now=0.0)
    snap = g.snapshot()
    pristine = g.snapshot()
    snap["tenants"]["a"]["vni"] = 999
    snap["fdb"][100][MAC1] = "p9"
    snap["counters"]["flood"] = 99
    assert g.tenant_for_vni(100) == "a"
    assert g.lookup(100, MAC1) == "p1"
    assert g.stats()["flood"] == 1

    restored = guard()
    restored.restore(pristine)
    assert restored.tenant_for_vni(100) == "a"
    assert restored.vni_for_tenant("a") == 100
    assert restored.lookup(100, MAC1) == "p1"
    assert restored.stats()["flood"] == 1
    assert restored.bind_port("p1", "a", MAC1)["vni"] == 100
    with pytest.raises(vtg.VxlanError) as exc:
        restored.restore({"version": 2})
    assert exc.value.code == "VX_STATE_VERSION"


def test_concurrent_port_binding_and_flooding_are_atomic():
    g = guard(max_ports=64)
    g.register_tenant("a", 100)
    errors = []

    def work(worker):
        mac = f"02:00:00:00:00:{worker:02x}"
        port = f"p{worker}"
        try:
            g.bind_port(port, "a", mac)
            g.ingress(frame(mac, BCAST), port=port, now=0.0)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=work, args=(n,)) for n in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    stats = g.stats()
    assert stats["ports"] == 8
    assert stats["flood"] == 8
    assert stats["fdb_entries"] == 8


def test_fdb_move_tracking_and_cross_tenant_learn_rejection():
    g = guard()
    g.register_tenant("a", 100)
    g.register_tenant("b", 200)
    g.bind_port("p1", "a", MAC1)
    g.bind_port("p2", "a", MAC2)
    g.bind_port("p3", "b", MAC3)
    assert g.learn(100, MAC1, "p1")["moved"] is False
    assert g.learn(100, MAC1, "p2")["moved"] is True
    assert g.lookup(100, MAC1) == "p2"
    assert g.stats()["moves"] == 1
    with pytest.raises(vtg.VxlanError) as exc:
        g.learn(200, MAC1, "p1")
    assert exc.value.code == "VX_PORT_TENANT_MISMATCH"
    with pytest.raises(vtg.VxlanError) as exc:
        g.learn(300, MAC1, "p1")
    assert exc.value.code == "VX_UNKNOWN_VNI"
    assert g.stats()["fdb_entries"] == 1
