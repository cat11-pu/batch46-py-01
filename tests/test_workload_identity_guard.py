import json
import threading

import pytest

import workload_identity_guard as wi

T0 = "2026-11-23T09:00:00+00:00"
TD = "td-a"
SECRET = "a" * 64
SECRET2 = "b" * 64


def make(**kwargs):
    return wi.WorkloadIdentityGuard(**kwargs)


def setup(**kwargs):
    g = make(**kwargs)
    g.register_issuer(TD, secret=SECRET)
    g.register_workload(TD, "worker", selectors={"node-type": "worker"})
    g.attest_node("node-1", trust_domain=TD,
                  facts={"node-type": "worker", "instance": "a"}, now=T0)
    return g


def issued(g, sa="worker", **kwargs):
    kwargs.setdefault("now", T0)
    return g.issue_svid("node-1", sa=sa, **kwargs)


def test_register_issuer_and_workload_validation():
    g = make()
    with pytest.raises(wi.IdentityError) as secret:
        g.register_issuer(TD, secret="zz")
    assert secret.value.code == "WI_ISSUER_SECRET_INVALID"
    assert g.register_issuer(TD, secret=SECRET)["status"] == "active"
    with pytest.raises(wi.IdentityError) as duplicate:
        g.register_issuer(TD, secret=SECRET2)
    assert duplicate.value.code == "WI_ISSUER_DUPLICATE"
    with pytest.raises(wi.IdentityError) as unknown:
        g.register_workload("td-ghost", "worker", selectors={"a": "b"})
    assert unknown.value.code == "WI_ISSUER_UNKNOWN"
    with pytest.raises(wi.IdentityError) as empty:
        g.register_workload(TD, "worker", selectors={})
    assert empty.value.code == "WI_SELECTOR_INVALID"
    with pytest.raises(wi.IdentityError) as bad_selector:
        g.register_workload(TD, "worker", selectors={"a": 1})
    assert bad_selector.value.code == "WI_SELECTOR_INVALID"
    assert g.register_workload(TD, "worker", selectors={"node-type": "worker"})["status"] == "registered"
    assert g.register_workload(TD, "worker", selectors={"node-type": "worker"})["status"] == "unchanged"
    with pytest.raises(wi.IdentityError) as duplicate_workload:
        g.register_workload(TD, "worker", selectors={"node-type": "db"})
    assert duplicate_workload.value.code == "WI_WORKLOAD_DUPLICATE"
    assert g.workload_state(TD, "worker")["selectors"] == {"node-type": "worker"}


def test_issuer_rotation_invalidates_outstanding_svids():
    g = setup()
    svid = issued(g)
    assert g.verify_svid(svid, now=T0)["status"] == "valid"
    rotated = g.rotate_issuer(TD, secret=SECRET2)
    assert rotated["status"] == "rotated"
    assert rotated["rotated"] == 1
    with pytest.raises(wi.IdentityError) as invalid:
        g.verify_svid(svid, now=T0)
    assert invalid.value.code == "WI_SIGNATURE_INVALID"
    with pytest.raises(wi.IdentityError) as unknown:
        g.rotate_issuer("td-ghost", secret=SECRET2)
    assert unknown.value.code == "WI_ISSUER_UNKNOWN"


def test_issue_requires_attested_node_and_known_workload():
    g = setup()
    with pytest.raises(wi.IdentityError) as node:
        g.issue_svid("ghost", sa="worker", now=T0)
    assert node.value.code == "WI_NODE_UNKNOWN"
    with pytest.raises(wi.IdentityError) as domain:
        g.attest_node("node-2", trust_domain="td-ghost",
                      facts={"node-type": "worker"}, now=T0)
    assert domain.value.code == "WI_ISSUER_UNKNOWN"
    with pytest.raises(wi.IdentityError) as facts:
        g.attest_node("node-2", trust_domain=TD, facts={}, now=T0)
    assert facts.value.code == "WI_FACT_INVALID"
    with pytest.raises(wi.IdentityError) as ttl:
        g.attest_node("node-2", trust_domain=TD, facts={"a": "b"},
                      ttl_seconds=0, now=T0)
    assert ttl.value.code == "WI_TTL_INVALID"
    g.attest_node("node-2", trust_domain=TD,
                  facts={"node-type": "worker", "instance": "b"}, now=T0)
    with pytest.raises(wi.IdentityError) as workload:
        g.issue_svid("node-2", sa="ghost", now=T0)
    assert workload.value.code == "WI_WORKLOAD_UNKNOWN"
    with pytest.raises(wi.IdentityError) as unattested:
        g.issue_svid("node-1", sa="worker", now="2026-11-23T09:30:00+00:00")
    assert unattested.value.code == "WI_NODE_UNATTESTED"


def test_selector_mismatch_blocks_issue():
    g = setup()
    g.register_workload(TD, "strict", selectors={"node-type": "worker",
                                                 "region": "cn-north"})
    with pytest.raises(wi.IdentityError) as missing:
        g.issue_svid("node-1", sa="strict", now=T0)
    assert missing.value.code == "WI_SELECTOR_MISMATCH"
    g.attest_node("node-1", trust_domain=TD,
                  facts={"node-type": "worker", "region": "cn-south"}, now=T0)
    with pytest.raises(wi.IdentityError) as wrong:
        g.issue_svid("node-1", sa="strict", now=T0)
    assert wrong.value.code == "WI_SELECTOR_MISMATCH"
    g.attest_node("node-1", trust_domain=TD,
                  facts={"node-type": "worker", "region": "cn-north"}, now=T0)
    out = g.issue_svid("node-1", sa="strict", now=T0)
    assert out["sa"] == "strict"


def test_cross_tenant_issue_and_verify_are_rejected():
    g = setup()
    g.register_issuer("td-b", secret=SECRET2)
    g.register_workload("td-b", "payments", selectors={"node-type": "worker"})
    with pytest.raises(wi.IdentityError) as tenant:
        g.issue_svid("node-1", sa="payments", now=T0)
    assert tenant.value.code == "WI_TENANT_MISMATCH"
    svid = issued(g)
    assert g.verify_svid(svid, now=T0, expected_trust_domain=TD)["status"] == "valid"
    with pytest.raises(wi.IdentityError) as mismatch:
        g.verify_svid(svid, now=T0, expected_trust_domain="td-b")
    assert mismatch.value.code == "WI_TRUST_DOMAIN_MISMATCH"
    assert svid["subject"] == "spiffe://td-a/sa/worker"


def test_ttl_is_clamped_and_validated():
    g = setup()
    clamped = issued(g, ttl_seconds=7200)
    assert clamped["expires_at"] == "2026-11-23T10:00:00+00:00"
    with pytest.raises(wi.IdentityError) as short:
        issued(g, ttl_seconds=59)
    assert short.value.code == "WI_TTL_INVALID"
    exact = issued(g, ttl_seconds=60)
    assert exact["expires_at"] == "2026-11-23T09:01:00+00:00"


def test_verify_returns_claims_and_rejects_tampering():
    g = setup()
    svid = issued(g)
    out = g.verify_svid(svid, now=T0)
    assert out["status"] == "valid"
    assert out["serial"] == svid["serial"]
    assert out["sa"] == "worker"
    assert out["node"] == "node-1"
    assert out["renewals"] == 0
    tampered = dict(svid)
    tampered["sa"] = "admin"
    with pytest.raises(wi.IdentityError) as signature:
        g.verify_svid(tampered, now=T0)
    assert signature.value.code == "WI_SIGNATURE_INVALID"
    broken = dict(svid)
    del broken["node"]
    with pytest.raises(wi.IdentityError) as invalid:
        g.verify_svid(broken, now=T0)
    assert invalid.value.code == "WI_SVID_INVALID"


def test_expired_svid_is_rejected():
    g = setup()
    svid = issued(g, ttl_seconds=60)
    assert g.verify_svid(svid, now="2026-11-23T09:00:59+00:00")["status"] == "valid"
    with pytest.raises(wi.IdentityError) as expired:
        g.verify_svid(svid, now="2026-11-23T09:01:00+00:00")
    assert expired.value.code == "WI_SVID_EXPIRED"


def test_fact_drift_invalidates_outstanding_svid():
    g = setup()
    svid = issued(g)
    original = g.node_state("node-1")["fact_digest"]
    assert g.verify_svid(svid, now=T0)["status"] == "valid"
    g.attest_node("node-1", trust_domain=TD,
                  facts={"node-type": "worker", "instance": "b"},
                  now="2026-11-23T09:05:00+00:00")
    assert g.node_state("node-1")["fact_digest"] != original
    with pytest.raises(wi.IdentityError) as drift:
        g.verify_svid(svid, now="2026-11-23T09:05:00+00:00")
    assert drift.value.code == "WI_FACT_DRIFT"
    fresh = g.issue_svid("node-1", sa="worker",
                         now="2026-11-23T09:05:00+00:00")
    assert g.verify_svid(fresh, now="2026-11-23T09:05:00+00:00")["status"] == "valid"


def test_renewal_window_and_limit():
    g = setup()
    parent = issued(g, ttl_seconds=100)
    with pytest.raises(wi.IdentityError) as early:
        g.renew_svid(parent["serial"], now="2026-11-23T09:00:10+00:00")
    assert early.value.code == "WI_RENEW_TOO_EARLY"
    child = g.renew_svid(parent["serial"], ttl_seconds=100,
                         now="2026-11-23T09:01:30+00:00")
    assert child["renewals"] == 1
    assert child["chain"] == [parent["serial"]]
    assert g.verify_svid(parent, now="2026-11-23T09:01:30+00:00")["status"] == "valid"
    grandchild = g.renew_svid(child["serial"], ttl_seconds=100,
                              now="2026-11-23T09:03:00+00:00")
    assert grandchild["renewals"] == 2
    with pytest.raises(wi.IdentityError) as limit:
        g.renew_svid(grandchild["serial"], now="2026-11-23T09:04:35+00:00")
    assert limit.value.code == "WI_RENEW_LIMIT"


def test_revocation_cascades_to_renewed_child():
    g = setup()
    parent = issued(g, ttl_seconds=100)
    child = g.renew_svid(parent["serial"], ttl_seconds=100,
                         now="2026-11-23T09:01:30+00:00")
    revoked = g.revoke_serial(parent["serial"], reason="leaked")
    assert revoked["status"] == "revoked"
    assert revoked["cascaded"] == 2
    for svid in (parent, child):
        with pytest.raises(wi.IdentityError) as blocked:
            g.verify_svid(svid, now="2026-11-23T09:01:40+00:00")
        assert blocked.value.code == "WI_REVOKED"
    assert g.revoke_serial(parent["serial"])["cascaded"] == 0
    with pytest.raises(wi.IdentityError) as unknown:
        g.revoke_serial("td-a/svid-999999")
    assert unknown.value.code == "WI_SVID_UNKNOWN"


def test_outstanding_cap_and_serial_format():
    g = setup()
    serials = [issued(g)["serial"] for _ in range(4)]
    assert serials == ["td-a/svid-%06d" % index for index in range(1, 5)]
    with pytest.raises(wi.IdentityError) as limit:
        issued(g)
    assert limit.value.code == "WI_OUTSTANDING_LIMIT"
    assert g.stats()["serials"] == 4
    assert g.node_state("node-1")["outstanding"] == 4
    g.revoke_serial(serials[0])
    fifth = issued(g)
    assert fifth["serial"] == "td-a/svid-000005"


def test_snapshot_restore_preserves_serial_sequence_and_state():
    g = setup()
    svid = issued(g)
    snap = json.loads(json.dumps(g.snapshot()))
    g.restore(snap)
    assert g.verify_svid(svid, now=T0)["status"] == "valid"
    second = issued(g)
    assert second["serial"] == "td-a/svid-000002"
    with pytest.raises(wi.IdentityError) as invalid:
        g.restore({"version": 8})
    assert invalid.value.code == "WI_SNAPSHOT_INVALID"


def test_stale_snapshot_cannot_reuse_serials():
    g = setup()
    issued(g)
    snap = g.snapshot()
    issued(g)
    third = issued(g)
    assert third["serial"] == "td-a/svid-000003"
    with pytest.raises(wi.IdentityError) as stale:
        g.restore(snap)
    assert stale.value.code == "WI_SNAPSHOT_STALE"
    fourth = issued(g)
    assert fourth["serial"] == "td-a/svid-000004"


def test_concurrent_issue_never_exceeds_outstanding_cap():
    g = setup()
    barrier = threading.Barrier(30)
    granted = []
    denied = []
    errors = []

    def worker():
        try:
            barrier.wait(timeout=10)
            granted.append(g.issue_svid("node-1", sa="worker", now=T0)["serial"])
        except wi.IdentityError as exc:
            denied.append(exc.code)
        except Exception as exc:  # pragma: no cover - defensive
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker) for _ in range(30)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=20)
    assert errors == []
    assert len(granted) == 4
    assert len(set(granted)) == 4
    assert len(denied) == 26
    assert set(denied) == {"WI_OUTSTANDING_LIMIT"}
    assert g.stats()["serials"] == 4
