import concurrent.futures
import json

import pytest

import ndp_cache_guard as ndp


def guard(**overrides):
    g = ndp.NdpGuard(clock=lambda: 1000, **overrides)
    g.configure_iface("eth0")
    return g


def na(target="2001:db8::2", mac="aa:bb:cc:dd:ee:02", *, at=1000,
       iface="eth0", **overrides):
    row = {
        "iface": iface,
        "type": "NA",
        "src": "fe80::2",
        "src_mac": mac,
        "target": target,
        "target_mac": mac,
        "solicited": True,
        "override": False,
        "at": at,
    }
    row.update(overrides)
    return row


def ns(src="fe80::3", mac="aa:bb:cc:dd:ee:03", target="2001:db8::2", *,
       at=1000, iface="eth0", **overrides):
    row = {
        "iface": iface,
        "type": "NS",
        "src": src,
        "src_mac": mac,
        "target": target,
        "at": at,
    }
    row.update(overrides)
    return row


def test_solicited_na_creates_reachable_binding():
    g = guard()
    assert g.solicit("eth0", "2001:db8::2")["status"] == "pending"
    out = g.learn(na())
    assert out["action"] == "accept"
    assert out["code"] == "NDP_NA_ACCEPTED"
    row = g.lookup("eth0", "2001:db8::2")
    assert row["mac"] == "aa:bb:cc:dd:ee:02"
    assert row["state"] == "reachable"
    assert row["age"] == 0
    assert [entry["address"] for entry in g.entries("eth0")] == ["2001:db8::2"]


def test_unsolicited_na_is_dropped_and_recorded():
    g = guard()
    out = g.learn(na(solicited=False))
    assert out["action"] == "drop"
    assert out["code"] == "NDP_UNSOLICITED_NA"
    assert g.entries("eth0") == []
    assert g.stats()["by_code"]["NDP_UNSOLICITED_NA"] == 1
    assert [row["code"] for row in g.violations("eth0")] == ["NDP_UNSOLICITED_NA"]


def test_na_without_pending_solicitation_is_dropped():
    g = guard()
    out = g.learn(na(target="2001:db8::7"))
    assert out["code"] == "NDP_NO_PENDING"
    assert g.entries("eth0") == []


def test_pending_solicitation_expires_before_answer():
    g = guard()
    g.solicit("eth0", "2001:db8::2")
    out = g.learn(na(at=1004))
    assert out["code"] == "NDP_PENDING_EXPIRED"
    assert g.entries("eth0") == []
    assert g.learn(na(at=1002))["action"] == "accept"


def test_dynamic_mac_change_requires_override():
    g = guard()
    g.solicit("eth0", "2001:db8::2")
    g.learn(na())
    g.solicit("eth0", "2001:db8::2")
    clash = g.learn(na(mac="aa:bb:cc:dd:ee:99", at=1010))
    assert clash["action"] == "drop"
    assert clash["code"] == "NDP_BINDING_CONFLICT"
    assert g.lookup("eth0", "2001:db8::2")["mac"] == "aa:bb:cc:dd:ee:02"
    g.solicit("eth0", "2001:db8::2")
    taken = g.learn(na(mac="aa:bb:cc:dd:ee:99", at=1020, override=True))
    assert taken["action"] == "accept"
    assert g.lookup("eth0", "2001:db8::2")["mac"] == "aa:bb:cc:dd:ee:99"


def test_static_binding_cannot_be_overridden():
    g = guard()
    g.bind_static("eth0", "2001:db8::5", "aa:bb:cc:dd:ee:05")
    g.solicit("eth0", "2001:db8::5")
    out = g.learn(na(target="2001:db8::5", mac="aa:bb:cc:dd:ee:55",
                     override=True))
    assert out["code"] == "NDP_STATIC_CONFLICT"
    row = g.lookup("eth0", "2001:db8::5")
    assert row["mac"] == "aa:bb:cc:dd:ee:05"
    assert row["state"] == "static"


def test_malformed_mac_is_rejected():
    g = guard()
    out = g.learn(na(mac="aa:bb:cc:dd:ee"))
    assert out["action"] == "drop"
    assert out["code"] == "NDP_BAD_MAC"
    assert g.entries("eth0") == []


def test_dad_solicitation_does_not_create_a_binding():
    g = guard()
    out = g.learn(ns(src="::", mac="aa:bb:cc:dd:ee:66"))
    assert out["action"] == "accept"
    assert out["code"] == "NDP_DAD"
    assert g.entries("eth0") == []


def test_mac_cannot_claim_unlimited_addresses():
    g = guard(max_per_mac=2)
    mac = "aa:bb:cc:dd:ee:77"
    for index in range(2):
        target = "2001:db8::%d" % (index + 2)
        g.solicit("eth0", target)
        assert g.learn(na(target=target, mac=mac))["action"] == "accept"
    g.solicit("eth0", "2001:db8::4")
    out = g.learn(na(target="2001:db8::4", mac=mac))
    assert out["action"] == "drop"
    assert out["code"] == "NDP_MAC_FLOOD"
    assert len(g.entries("eth0")) == 2


def test_cache_evicts_the_oldest_dynamic_entry():
    g = guard(max_entries=2)
    for index, at in ((9, 1000), (10, 1001), (11, 1002)):
        target = "2001:db8::%d" % index
        g.solicit("eth0", target)
        assert g.learn(na(target=target, mac="aa:bb:cc:dd:ee:%02x" % index,
                          at=at))["action"] == "accept"
    addresses = [entry["address"] for entry in g.entries("eth0")]
    assert addresses == ["2001:db8::10", "2001:db8::11"]
    assert g.stats("eth0")["evicted"] == 1


def test_cache_full_of_static_entries_rejects_new_binding():
    g = guard(max_entries=1)
    g.bind_static("eth0", "2001:db8::5", "aa:bb:cc:dd:ee:05")
    g.solicit("eth0", "2001:db8::6")
    out = g.learn(na(target="2001:db8::6", mac="aa:bb:cc:dd:ee:06"))
    assert out["action"] == "drop"
    assert out["code"] == "NDP_CACHE_FULL"
    assert [entry["address"] for entry in g.entries("eth0")] == ["2001:db8::5"]


def test_stale_entries_are_reported_and_purged():
    g = guard()
    g.solicit("eth0", "2001:db8::2")
    g.learn(na())
    row = g.lookup("eth0", "2001:db8::2", now=1301)
    assert row["state"] == "stale"
    assert row["age"] == 301
    assert g.purge(1301) == ["eth0/2001:db8::2"]
    with pytest.raises(ndp.NdpError) as exc:
        g.lookup("eth0", "2001:db8::2", now=1301)
    assert exc.value.code == "NDP_NOT_FOUND"


def test_link_change_flushes_only_dynamic_entries():
    g = guard()
    g.configure_iface("eth1")
    g.bind_static("eth0", "2001:db8::5", "aa:bb:cc:dd:ee:05")
    g.solicit("eth0", "2001:db8::2")
    g.learn(na())
    g.solicit("eth1", "2001:db8::3")
    g.learn(na(target="2001:db8::3", mac="aa:bb:cc:dd:ee:03", iface="eth1"))
    assert g.link_change("eth0") == ["2001:db8::2"]
    assert [entry["address"] for entry in g.entries("eth0")] == ["2001:db8::5"]
    assert [entry["address"] for entry in g.entries("eth1")] == ["2001:db8::3"]


def test_snapshot_round_trip_and_corrupt_restore_is_atomic():
    g = guard()
    g.bind_static("eth0", "2001:db8::5", "aa:bb:cc:dd:ee:05")
    g.solicit("eth0", "2001:db8::2")
    g.learn(na())
    g.learn(na(target="2001:db8::9", solicited=False))
    snap = json.loads(json.dumps(g.snapshot()))
    assert snap["version"] == ndp.SNAPSHOT_VERSION
    restored = guard()
    restored.restore(snap)
    assert [(row["address"], row["mac"], row["state"])
            for row in restored.entries("eth0")] == [
        ("2001:db8::2", "aa:bb:cc:dd:ee:02", "reachable"),
        ("2001:db8::5", "aa:bb:cc:dd:ee:05", "static"),
    ]
    assert restored.stats()["by_code"]["NDP_UNSOLICITED_NA"] == 1
    bad = json.loads(json.dumps(snap))
    bad["entries"].append(dict(bad["entries"][0], mac="aa:bb:cc:dd:ee:88"))
    with pytest.raises(ndp.NdpError) as exc:
        restored.restore(bad)
    assert exc.value.code == "NDP_SNAPSHOT_CORRUPT"
    assert len(restored.entries("eth0")) == 2


def test_concurrent_conflicting_na_binds_exactly_one_mac():
    g = guard()

    def worker(index):
        target = "2001:db8::2"
        g.solicit("eth0", target)
        return g.learn(na(target=target, mac="aa:bb:cc:dd:ee:%02x" % index))

    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        results = [future.result()
                   for future in [pool.submit(worker, index) for index in range(16)]]
    accepted = [row for row in results if row["action"] == "accept"]
    conflicts = [row for row in results if row["code"] == "NDP_BINDING_CONFLICT"]
    assert len(accepted) == 1
    assert len(conflicts) == 15
    assert len(g.entries("eth0")) == 1
