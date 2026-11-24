import threading
from datetime import datetime, timezone

import pytest

import azure_sas_guard as sg


T0 = int(datetime(2026, 11, 23, 10, 0, 0, tzinfo=timezone.utc).timestamp())
FIELD_ORDER = [
    "sa",
    "skv",
    "sv",
    "ss",
    "srt",
    "sp",
    "st",
    "se",
    "spr",
    "sip",
    "si",
    "sdd",
]


def make(**kwargs):
    g = sg.SasGuard(**kwargs)
    g.register_key("v1", "secret-one")
    return g


def issue(g, **overrides):
    params = {
        "account": "acct",
        "resource": "cont",
        "permissions": "rl",
        "start": T0,
        "expiry": T0 + 600,
        "key_version": "v1",
    }
    params.update(overrides)
    return g.build_sas(**params)


def test_permission_canonical_order_and_containment():
    g = make()
    res = issue(g, permissions="wlr")
    assert res["fields"]["sp"] == "rwl"
    assert g.check_permissions("wlr", "lr") == {
        "allowed": True,
        "missing": [],
        "effective": "rwl",
    }
    assert g.check_permissions("rwl", "d") == {
        "allowed": False,
        "missing": ["d"],
        "effective": "rwl",
    }
    with pytest.raises(sg.SasError) as exc:
        g.check_permissions("rwl", "q")
    assert exc.value.code == "SAS_UNKNOWN_PERMISSION"
    assert g.verify(res, operation="r", now=T0 + 1, target="cont/blob")["code"] == "SAS_OK"
    assert g.verify(res, operation="w", now=T0 + 1, target="cont/blob")["code"] == "SAS_OK"
    assert g.verify(res, operation="l", now=T0 + 1, target="cont/blob")["code"] == "SAS_OK"
    denied = g.verify(res, operation="d", now=T0 + 1, target="cont/blob")
    assert denied["status"] == "denied"
    assert denied["code"] == "SAS_DENY_PERMISSION"


def test_start_and_expiry_boundaries():
    g = make()
    res = issue(g, start=T0 + 100, expiry=T0 + 600)
    assert g.verify(res, operation="r", now=T0 + 99, target="cont/blob")["code"] == "SAS_NOT_YET_VALID"
    assert g.verify(res, operation="r", now=T0 + 100, target="cont/blob")["code"] == "SAS_OK"
    assert g.verify(res, operation="r", now=T0 + 599, target="cont/blob")["code"] == "SAS_OK"
    assert g.verify(res, operation="r", now=T0 + 600, target="cont/blob")["code"] == "SAS_EXPIRED"


def test_protocol_restriction():
    g = make()
    https_only = issue(g)
    assert g.verify(https_only, operation="r", now=T0 + 1, target="cont/blob", protocol="http")["code"] == "SAS_DENY_PROTOCOL"
    assert g.verify(https_only, operation="r", now=T0 + 1, target="cont/blob", protocol="https")["code"] == "SAS_OK"
    both = issue(g, protocol="https,http")
    assert g.verify(both, operation="r", now=T0 + 1, target="cont/blob", protocol="http")["code"] == "SAS_OK"


def test_ip_restriction_and_invalid_cidr():
    g = make()
    restricted = issue(g, ip="10.0.0.0/24")
    assert g.verify(restricted, operation="r", now=T0 + 1, target="cont/blob", client_ip="10.0.0.5")["code"] == "SAS_OK"
    assert g.verify(restricted, operation="r", now=T0 + 1, target="cont/blob", client_ip="10.0.1.5")["code"] == "SAS_DENY_IP"
    assert g.verify(restricted, operation="r", now=T0 + 1, target="cont/blob", client_ip=None)["code"] == "SAS_DENY_IP"
    with pytest.raises(sg.SasError) as exc:
        issue(g, ip="not-a-cidr")
    assert exc.value.code == "SAS_BAD_IP"


def test_scope_enforcement_for_container_and_blob_sas():
    g = make()
    container = issue(g, resource="cont")
    assert g.verify(container, operation="r", now=T0 + 1, target="cont/blob1")["code"] == "SAS_OK"
    assert g.verify(container, operation="r", now=T0 + 1, target="other/blob1")["code"] == "SAS_DENY_SCOPE"
    blob = issue(g, resource="cont/blob1")
    assert g.verify(blob, operation="r", now=T0 + 1, target="cont/blob1")["code"] == "SAS_OK"
    assert g.verify(blob, operation="r", now=T0 + 1, target="cont/blob2")["code"] == "SAS_DENY_SCOPE"
    assert g.verify(blob, operation="r", now=T0 + 1, target="cont/blob1/extra")["code"] == "SAS_DENY_SCOPE"


def test_tampered_permission_breaks_signature():
    g = make()
    res = issue(g)
    bad = {"fields": dict(res["fields"]), "token": res["token"]}
    bad["fields"]["sp"] = "rw"
    out = g.verify(bad, operation="r", now=T0 + 1, target="cont/blob")
    assert out["code"] == "SAS_BAD_SIGNATURE"
    tampered = res["token"].replace("sp=rl", "sp=rw")
    assert g.verify(tampered, operation="r", now=T0 + 1, target="cont/blob")["code"] == "SAS_BAD_SIGNATURE"


def test_stored_policy_narrows_permissions_and_revocation_blocks():
    g = make()
    g.define_policy("readonly", permissions="rl", start=T0, expiry=T0 + 600)
    res = g.build_sas(
        "acct",
        resource="cont",
        permissions=None,
        start=T0,
        expiry=T0 + 600,
        key_version="v1",
        policy="readonly",
    )
    assert res["fields"]["si"] == "readonly"
    assert res["fields"]["sp"] == ""
    assert g.verify(res, operation="r", now=T0 + 1, target="cont/blob")["code"] == "SAS_OK"
    assert g.verify(res, operation="w", now=T0 + 1, target="cont/blob")["code"] == "SAS_DENY_PERMISSION"
    g.revoke_policy("readonly", now=T0 + 100)
    out = g.verify(res, operation="r", now=T0 + 101, target="cont/blob")
    assert out["status"] == "denied"
    assert out["code"] == "SAS_POLICY_REVOKED"


def test_policy_window_overrides_sas_window():
    g = make()
    g.define_policy("narrow", permissions="r", start=T0 + 200, expiry=T0 + 300)
    res = g.build_sas(
        "acct",
        resource="cont",
        permissions=None,
        start=T0,
        expiry=T0 + 600,
        key_version="v1",
        policy="narrow",
    )
    assert g.verify(res, operation="r", now=T0 + 199, target="cont/blob")["code"] == "SAS_NOT_YET_VALID"
    assert g.verify(res, operation="r", now=T0 + 200, target="cont/blob")["code"] == "SAS_OK"
    assert g.verify(res, operation="r", now=T0 + 299, target="cont/blob")["code"] == "SAS_OK"
    assert g.verify(res, operation="r", now=T0 + 300, target="cont/blob")["code"] == "SAS_EXPIRED"


def test_policy_conflict_and_unknown_references():
    g = make()
    g.define_policy("p", permissions="r", start=T0, expiry=T0 + 600)
    with pytest.raises(sg.SasError) as exc:
        issue(g, policy="p", permissions="r")
    assert exc.value.code == "SAS_POLICY_CONFLICT"
    with pytest.raises(sg.SasError) as exc:
        issue(g, policy="ghost", permissions=None)
    assert exc.value.code == "SAS_UNKNOWN_POLICY"
    with pytest.raises(sg.SasError) as exc:
        issue(g, key_version="v9")
    assert exc.value.code == "SAS_UNKNOWN_KEY"


def test_key_rotation_grace_then_retirement():
    g = make()
    g.register_key("v2", "secret-two")
    old = issue(g, key_version="v1")
    assert g.verify(old, operation="r", now=T0 + 1, target="cont/blob")["code"] == "SAS_OK"
    rotation = g.rotate_key("v2", now=T0, overlap=300)
    assert rotation["current"] == "v2"
    assert g.verify(old, operation="r", now=T0 + 60, target="cont/blob")["code"] == "SAS_OK"
    retired = g.verify(old, operation="r", now=T0 + 300, target="cont/blob")
    assert retired["status"] == "denied"
    assert retired["code"] == "SAS_KEY_RETIRED"
    fresh = issue(g, key_version="v2")
    assert fresh["fields"]["skv"] == "v2"
    assert g.verify(fresh, operation="r", now=T0 + 301, target="cont/blob")["code"] == "SAS_OK"


def test_token_roundtrip_uses_fixed_field_order():
    g = make()
    res = issue(g)
    assert res["fields"]["sv"] == "2024-11-01"
    assert res["fields"]["ss"] == "b"
    assert res["fields"]["srt"] == "c"
    assert res["fields"]["sip"] == ""
    assert res["fields"]["si"] == ""
    assert res["fields"]["sdd"] == "cont"
    names = [part.split("=", 1)[0] for part in res["token"].split("&")]
    assert names == FIELD_ORDER + ["sig"]
    expected = "\n".join(str(res["fields"][name]) for name in FIELD_ORDER)
    assert g.string_to_sign(res["fields"]) == expected
    assert g.verify(res["token"], operation="r", now=T0 + 1, target="cont/blob")["code"] == "SAS_OK"


def test_snapshot_restore_keeps_policy_state_and_counters():
    g = make()
    g.define_policy("p", permissions="r", start=T0, expiry=T0 + 600)
    res = g.build_sas(
        "acct",
        resource="cont",
        permissions=None,
        start=T0,
        expiry=T0 + 600,
        key_version="v1",
        policy="p",
    )
    stats_before = g.stats()
    snap = g.snapshot()
    g.revoke_policy("p", now=T0 + 10)
    restored = sg.SasGuard()
    restored.restore(snap)
    assert restored.stats() == stats_before
    assert restored.verify(res, operation="r", now=T0 + 11, target="cont/blob")["code"] == "SAS_OK"
    restored.revoke_policy("p", now=T0 + 20)
    assert restored.verify(res, operation="r", now=T0 + 21, target="cont/blob")["code"] == "SAS_POLICY_REVOKED"


def test_record_limit_and_expired_purge():
    g = sg.SasGuard(max_records=2)
    g.register_key("v1", "secret-one")
    issue(g)
    issue(g)
    with pytest.raises(sg.SasError) as exc:
        issue(g)
    assert exc.value.code == "SAS_RECORD_LIMIT"
    assert g.purge_expired(now=T0 + 600) == 2
    fresh = issue(g)
    assert g.verify(fresh, operation="r", now=T0 + 1, target="cont/blob")["code"] == "SAS_OK"
    assert g.stats()["built"] == 3


def test_concurrent_verify_then_policy_revocation():
    g = make()
    g.define_policy("p", permissions="r", start=T0, expiry=T0 + 600)
    res = g.build_sas(
        "acct",
        resource="cont",
        permissions=None,
        start=T0,
        expiry=T0 + 600,
        key_version="v1",
        policy="p",
    )
    codes = []
    errors = []
    lock = threading.Lock()
    barrier = threading.Barrier(8)

    def worker():
        try:
            barrier.wait()
            local = [
                g.verify(res, operation="r", now=T0 + 1, target="cont/blob")["code"]
                for _ in range(50)
            ]
        except Exception as exc:  # pragma: no cover - only on failure
            with lock:
                errors.append(repr(exc))
            return
        with lock:
            codes.extend(local)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    assert len(codes) == 400
    assert codes.count("SAS_OK") == 400
    assert g.stats()["verified"] == 400
    g.revoke_policy("p", now=T0 + 5)
    denied = g.verify(res, operation="r", now=T0 + 6, target="cont/blob")
    assert denied["code"] == "SAS_POLICY_REVOKED"
    assert g.stats()["rejected"] == 1


def test_issue_window_and_protocol_validation():
    g = make()
    with pytest.raises(sg.SasError) as exc:
        issue(g, expiry=T0)
    assert exc.value.code == "SAS_INVALID_WINDOW"
    with pytest.raises(sg.SasError) as exc:
        issue(g, expiry=T0 + 604801)
    assert exc.value.code == "SAS_INVALID_WINDOW"
    with pytest.raises(sg.SasError) as exc:
        issue(g, resource="")
    assert exc.value.code == "SAS_INVALID_SCOPE"
    with pytest.raises(sg.SasError) as exc:
        issue(g, protocol="http")
    assert exc.value.code == "SAS_BAD_PROTOCOL"
