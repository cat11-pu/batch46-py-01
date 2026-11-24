import threading

import pytest

import ssh_agent_forward_guard as afg

T0 = "2026-11-23T09:00:00+00:00"


def make(**kwargs):
    return afg.AgentForwardGuard(**kwargs)


def guard_with_session(**session_kwargs):
    g = make()
    g.register_key("k1", fingerprint="a" * 64, owner_account="alice",
                   max_signs=8, ttl_seconds=3600, now=T0)
    options = {
        "account": "alice",
        "host": "bastion-1",
        "target_user": "deploy",
        "keys": ("k1",),
        "ttl_seconds": 600,
        "purposes": ("git", "scp"),
        "targets": ("build.internal",),
        "now": T0,
    }
    options.update(session_kwargs)
    g.open_session("s1", **options)
    return g


def approved_forward(g, session="s1", nonce="0011223344556677", reviewer="auditor"):
    reply = g.request_forward(session, remote_host="build.internal", nonce=nonce, now=T0)
    g.approve_forward(session, reply["request_id"], approved_by=reviewer, now=T0)
    return reply["request_id"]


def test_register_key_rejects_duplicate_id_and_fingerprint():
    g = make()
    first = g.register_key("k1", fingerprint="a" * 64, owner_account="alice",
                           max_signs=4, ttl_seconds=600, now=T0)
    assert first["key"] == "k1"
    assert first["expires_at"] == "2026-11-23T09:10:00+00:00"
    assert first["max_signs"] == 4
    with pytest.raises(afg.AgentError) as dup_id:
        g.register_key("k1", fingerprint="b" * 64, owner_account="alice", now=T0)
    assert dup_id.value.code == "AF_KEY_DUPLICATE"
    with pytest.raises(afg.AgentError) as dup_fp:
        g.register_key("k2", fingerprint="a" * 64, owner_account="bob", now=T0)
    assert dup_fp.value.code == "AF_KEY_FINGERPRINT_DUP"
    with pytest.raises(afg.AgentError) as bad_fp:
        g.register_key("k3", fingerprint="xyz", owner_account="bob", now=T0)
    assert bad_fp.value.code == "AF_FINGERPRINT_INVALID"
    assert g.stats()["keys"] == 1
    assert g.stats()["signs"] == 0


def test_key_expiry_and_owner_binding_at_open_session():
    g = make()
    g.register_key("k1", fingerprint="c" * 64, owner_account="alice",
                   ttl_seconds=600, now=T0)
    options = {"host": "bastion-1", "target_user": "deploy", "keys": ("k1",)}
    with pytest.raises(afg.AgentError) as wrong_owner:
        g.open_session("s1", account="bob", now=T0, **options)
    assert wrong_owner.value.code == "AF_KEY_OWNER_MISMATCH"
    with pytest.raises(afg.AgentError) as unknown:
        g.open_session("s1", account="alice", keys=("ghost",), now=T0,
                       host="bastion-1", target_user="deploy")
    assert unknown.value.code == "AF_KEY_UNKNOWN"
    with pytest.raises(afg.AgentError) as expired:
        g.open_session("s1", account="alice", now="2026-11-23T09:10:00+00:00", **options)
    assert expired.value.code == "AF_KEY_EXPIRED"
    opened = g.open_session("s1", account="alice", now="2026-11-23T09:09:59+00:00", **options)
    assert opened["status"] == "open"
    assert opened["expires_at"] == "2026-11-23T09:19:59+00:00"


def test_key_bound_to_live_session_cannot_be_forwarded_twice():
    g = guard_with_session()
    options = {"account": "alice", "host": "bastion-2", "target_user": "deploy",
               "keys": ("k1",), "now": T0}
    with pytest.raises(afg.AgentError) as busy:
        g.open_session("s2", **options)
    assert busy.value.code == "AF_KEY_BUSY"
    with pytest.raises(afg.AgentError) as duplicate:
        g.open_session("s1", **options)
    assert duplicate.value.code == "AF_SESSION_DUPLICATE"
    g.close_session("s1")
    assert g.open_session("s2", **options)["status"] == "open"
    assert g.close_session("s1")["status"] == "closed"


def test_forward_request_host_allowlist_loopback_and_port_validation():
    g = guard_with_session()
    with pytest.raises(afg.AgentError) as denied:
        g.request_forward("s1", remote_host="evil.example", nonce="aa" * 8, now=T0)
    assert denied.value.code == "AF_FORWARD_HOST_DENIED"
    with pytest.raises(afg.AgentError) as loopback:
        g.request_forward("s1", remote_host="127.0.0.1", nonce="bb" * 8, now=T0)
    assert loopback.value.code == "AF_FORWARD_LOOPBACK"
    with pytest.raises(afg.AgentError) as port_zero:
        g.request_forward("s1", remote_host="build.internal", nonce="cc" * 8,
                          remote_port=0, now=T0)
    assert port_zero.value.code == "AF_PORT_INVALID"
    with pytest.raises(afg.AgentError) as port_big:
        g.request_forward("s1", remote_host="build.internal", nonce="dd" * 8,
                          remote_port=70000, now=T0)
    assert port_big.value.code == "AF_PORT_INVALID"
    with pytest.raises(afg.AgentError) as short_nonce:
        g.request_forward("s1", remote_host="build.internal", nonce="zz", now=T0)
    assert short_nonce.value.code == "AF_NONCE_INVALID"
    ok = g.request_forward("s1", remote_host="build.internal", nonce="ee" * 8,
                           remote_port=2202, now=T0)
    assert ok["status"] == "pending"
    assert ok["request_id"] == "s1:" + "ee" * 8
    assert ok["port"] == 2202


def test_forward_nonce_replay_is_rejected_across_sessions():
    g = guard_with_session()
    nonce = "ab" * 8
    g.request_forward("s1", remote_host="build.internal", nonce=nonce, now=T0)
    with pytest.raises(afg.AgentError) as replay:
        g.request_forward("s1", remote_host="build.internal", nonce=nonce, now=T0)
    assert replay.value.code == "AF_NONCE_REPLAY"
    g.register_key("k2", fingerprint="f" * 64, owner_account="bob", ttl_seconds=600, now=T0)
    g.open_session("s2", account="bob", host="bastion-2", target_user="deploy",
                   keys=("k2",), now=T0)
    with pytest.raises(afg.AgentError) as cross:
        g.request_forward("s2", remote_host="build.internal", nonce=nonce, now=T0)
    assert cross.value.code == "AF_NONCE_REPLAY"


def test_forward_approval_requires_second_party_and_is_idempotent():
    g = guard_with_session()
    reply = g.request_forward("s1", remote_host="build.internal",
                              nonce="12" * 8, now=T0)
    rid = reply["request_id"]
    with pytest.raises(afg.AgentError) as self_approval:
        g.approve_forward("s1", rid, approved_by="alice", now=T0)
    assert self_approval.value.code == "AF_SELF_APPROVAL"
    with pytest.raises(afg.AgentError) as unknown:
        g.approve_forward("s1", "s1:deadbeef", approved_by="auditor", now=T0)
    assert unknown.value.code == "AF_FORWARD_UNKNOWN"
    first = g.approve_forward("s1", rid, approved_by="auditor", now=T0)
    assert first["status"] == "approved"
    again = g.approve_forward("s1", rid, approved_by="someone-else", now=T0)
    assert again["status"] == "approved"
    assert again["approver"] == "auditor"
    assert g.usage("s1")["forwards"] == 1


def test_sign_requires_approved_forward():
    g = guard_with_session()
    with pytest.raises(afg.AgentError) as required:
        g.sign("s1", "k1", digest="1" * 64, now=T0)
    assert required.value.code == "AF_FORWARD_REQUIRED"
    reply = g.request_forward("s1", remote_host="build.internal", nonce="34" * 8, now=T0)
    with pytest.raises(afg.AgentError) as pending:
        g.sign("s1", "k1", digest="1" * 64, now=T0)
    assert pending.value.code == "AF_FORWARD_REQUIRED"
    g.approve_forward("s1", reply["request_id"], approved_by="auditor", now=T0)
    out = g.sign("s1", "k1", digest="2" * 64, now=T0)
    assert out["status"] == "applied"
    assert out["sign_index"] == 1


def test_sign_purpose_and_digest_validation():
    g = guard_with_session()
    approved_forward(g)
    with pytest.raises(afg.AgentError) as purpose:
        g.sign("s1", "k1", digest="3" * 64, purpose="shell", now=T0)
    assert purpose.value.code == "AF_PURPOSE_DENIED"
    with pytest.raises(afg.AgentError) as digest:
        g.sign("s1", "k1", digest="not-a-digest", now=T0)
    assert digest.value.code == "AF_DIGEST_INVALID"
    g.register_key("k2", fingerprint="9" * 64, owner_account="alice", now=T0)
    with pytest.raises(afg.AgentError) as not_allowed:
        g.sign("s1", "k2", digest="4" * 64, now=T0)
    assert not_allowed.value.code == "AF_KEY_NOT_ALLOWED"
    out = g.sign("s1", "k1", digest="5" * 64, purpose="scp", now=T0)
    assert out["purpose"] == "scp"
    assert out["digest"] == "5" * 64
    assert g.usage("s1")["signs"] == 1


def test_sign_budget_is_enforced_exactly():
    g = make()
    g.register_key("k1", fingerprint="a" * 64, owner_account="alice",
                   max_signs=3, ttl_seconds=3600, now=T0)
    g.open_session("s1", account="alice", host="bastion-1", target_user="deploy",
                   keys=("k1",), targets=("build.internal",), now=T0)
    approved_forward(g)
    for index in range(3):
        out = g.sign("s1", "k1", digest=("%d" % (index + 1)) * 64,
                     request_id="r%d" % index, now=T0)
        assert out["sign_index"] == index + 1
    with pytest.raises(afg.AgentError) as budget:
        g.sign("s1", "k1", digest="9" * 64, request_id="r9", now=T0)
    assert budget.value.code == "AF_SIGN_BUDGET"
    assert g.usage("s1")["signs"] == 3
    assert g.stats()["signs"] == 3


def test_request_id_replay_is_idempotent_and_digest_conflict_denied():
    g = make()
    g.register_key("k1", fingerprint="a" * 64, owner_account="alice",
                   max_signs=2, ttl_seconds=3600, now=T0)
    g.open_session("s1", account="alice", host="bastion-1", target_user="deploy",
                   keys=("k1",), targets=("build.internal",), now=T0)
    approved_forward(g)
    first = g.sign("s1", "k1", digest="6" * 64, request_id="req-1", now=T0)
    assert first["status"] == "applied"
    replay = g.sign("s1", "k1", digest="6" * 64, request_id="req-1", now=T0)
    assert replay["status"] == "replayed"
    assert replay["sign_index"] == 1
    assert g.usage("s1")["signs"] == 1
    with pytest.raises(afg.AgentError) as conflict:
        g.sign("s1", "k1", digest="7" * 64, request_id="req-1", now=T0)
    assert conflict.value.code == "AF_REQUEST_CONFLICT"
    second = g.sign("s1", "k1", digest="8" * 64, request_id="req-2", now=T0)
    assert second["sign_index"] == 2


def test_session_expiry_blocks_sign_and_releases_key():
    g = make()
    g.register_key("k1", fingerprint="a" * 64, owner_account="alice",
                   max_signs=4, ttl_seconds=3600, now=T0)
    g.open_session("s1", account="alice", host="bastion-1", target_user="deploy",
                   keys=("k1",), ttl_seconds=60, targets=("build.internal",), now=T0)
    approved_forward(g)
    with pytest.raises(afg.AgentError) as expired:
        g.sign("s1", "k1", digest="1" * 64, now="2026-11-23T09:01:00+00:00")
    assert expired.value.code == "AF_SESSION_EXPIRED"
    assert g.usage("s1")["status"] == "expired"
    reopened = g.open_session("s2", account="alice", host="bastion-1",
                              target_user="deploy", keys=("k1",), now=T0)
    assert reopened["status"] == "open"
    report = g.sweep(now="2026-11-23T09:11:00+00:00")
    assert report["sessions"] == 1
    with pytest.raises(afg.AgentError) as closed:
        g.sign("s1", "k1", digest="2" * 64, now="2026-11-23T09:11:00+00:00")
    assert closed.value.code == "AF_SESSION_EXPIRED"


def test_revoked_key_blocks_new_signs():
    g = guard_with_session()
    approved_forward(g)
    assert g.sign("s1", "k1", digest="1" * 64, now=T0)["status"] == "applied"
    revoked = g.revoke_key("k1", reason="laptop-stolen")
    assert revoked["status"] == "revoked"
    with pytest.raises(afg.AgentError) as blocked:
        g.sign("s1", "k1", digest="2" * 64, now=T0)
    assert blocked.value.code == "AF_KEY_REVOKED"
    assert g.revoke_key("k1")["status"] == "revoked"
    with pytest.raises(afg.AgentError) as unknown:
        g.revoke_key("ghost")
    assert unknown.value.code == "AF_KEY_UNKNOWN"


def test_snapshot_restore_preserves_budget_and_audit_sequence():
    import json

    g = make()
    g.register_key("k1", fingerprint="a" * 64, owner_account="alice",
                   max_signs=4, ttl_seconds=3600, now=T0)
    g.open_session("s1", account="alice", host="bastion-1", target_user="deploy",
                   keys=("k1",), targets=("build.internal",), now=T0)
    approved_forward(g)
    g.sign("s1", "k1", digest="1" * 64, request_id="r1", now=T0)
    g.sign("s1", "k1", digest="2" * 64, request_id="r2", now=T0)
    snap = g.snapshot()
    assert json.loads(json.dumps(snap))["version"] == 1
    snapshot_seq = g.audit(1)[0]["seq"]
    third = g.sign("s1", "k1", digest="3" * 64, request_id="r3", now=T0)
    assert third["sign_index"] == 3
    g.restore(snap)
    assert g.usage("s1")["signs"] == 2
    assert g.audit(1)[0]["seq"] == snapshot_seq
    after = g.sign("s1", "k1", digest="4" * 64, request_id="r4", now=T0)
    assert after["sign_index"] == 3
    assert g.audit(1)[0]["seq"] > snapshot_seq
    with pytest.raises(afg.AgentError) as invalid:
        g.restore({"version": 99})
    assert invalid.value.code == "AF_SNAPSHOT_INVALID"


def test_audit_is_newest_first_and_capped():
    g = make(audit_capacity=4)
    g.register_key("k1", fingerprint="a" * 64, owner_account="alice", now=T0)
    g.open_session("s1", account="alice", host="bastion-1", target_user="deploy",
                   keys=("k1",), targets=("build.internal",), now=T0)
    rid = approved_forward(g)
    g.sign("s1", "k1", digest="1" * 64, now=T0)
    entries = g.audit(10)
    assert len(entries) == 4
    assert [row["action"] for row in entries] == [
        "sign", "forward.approve", "forward.request", "session.open",
    ]
    seqs = [row["seq"] for row in entries]
    assert seqs == sorted(seqs, reverse=True)
    assert entries[0]["session"] == "s1"
    assert g.stats()["audit"] == 4
    assert any(row.get("request") == rid for row in entries)


def test_concurrent_signs_never_exceed_budget():
    g = make()
    g.register_key("k1", fingerprint="a" * 64, owner_account="alice",
                   max_signs=5, ttl_seconds=3600, now=T0)
    g.open_session("s1", account="alice", host="bastion-1", target_user="deploy",
                   keys=("k1",), targets=("build.internal",), now=T0)
    approved_forward(g)
    barrier = threading.Barrier(18)
    applied = []
    denied = []
    errors = []

    def worker(index):
        try:
            barrier.wait(timeout=10)
            out = g.sign("s1", "k1", digest=("%064d" % index), request_id="c%d" % index, now=T0)
            applied.append(out["sign_index"])
        except afg.AgentError as exc:
            denied.append(exc.code)
        except Exception as exc:  # pragma: no cover - defensive
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(18)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=20)
    assert errors == []
    assert len(applied) == 5
    assert sorted(applied) == [1, 2, 3, 4, 5]
    assert len(denied) == 13
    assert set(denied) == {"AF_SIGN_BUDGET"}
    assert g.usage("s1")["signs"] == 5
