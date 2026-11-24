import json
import threading

import pytest

import ima_appraisal_guard as ima

T0 = "2026-11-23T09:00:00+00:00"
D1 = "1" * 64
D2 = "2" * 64
D3 = "3" * 64
EVIL = "e" * 64


def make(**kwargs):
    return ima.ImaGuard(**kwargs)


def m(path, digest, algo="sha256"):
    return {"path": path, "digest": digest, "algo": algo}


def test_add_baseline_validates_digest_algo_and_path():
    g = make()
    with pytest.raises(ima.ImaError) as algo:
        g.add_baseline("h1", "/usr/bin/app", digest=D1, algo="md5")
    assert algo.value.code == "IMA_ALGO_INVALID"
    with pytest.raises(ima.ImaError) as short:
        g.add_baseline("h1", "/usr/bin/app", digest="1" * 40)
    assert short.value.code == "IMA_DIGEST_INVALID"
    with pytest.raises(ima.ImaError) as path:
        g.add_baseline("h1", "usr/bin/app", digest=D1)
    assert path.value.code == "IMA_PATH_INVALID"
    added = g.add_baseline("h1", "/usr/bin/app", digest=D1, note="pkg")
    assert added["status"] == "added"
    assert g.host_state("h1")["baseline"] == 1
    assert g.stats()["hosts"] == 1


def test_add_baseline_is_idempotent_and_conflicts_on_new_digest():
    g = make()
    g.add_baseline("h1", "/usr/bin/app", digest=D1)
    unchanged = g.add_baseline("h1", "/usr/bin/app", digest=D1)
    assert unchanged["status"] == "unchanged"
    with pytest.raises(ima.ImaError) as conflict:
        g.add_baseline("h1", "/usr/bin/app", digest=D2)
    assert conflict.value.code == "IMA_BASELINE_CONFLICT"
    removed = g.remove_baseline("h1", "/usr/bin/app")
    assert removed["status"] == "removed"
    assert g.host_state("h1")["baseline"] == 0
    with pytest.raises(ima.ImaError) as unknown:
        g.remove_baseline("h1", "/usr/bin/app")
    assert unknown.value.code == "IMA_BASELINE_UNKNOWN"


def test_appraisal_passes_on_clean_baseline():
    g = make()
    g.add_baseline("h1", "/usr/bin/app", digest=D1)
    g.add_baseline("h1", "/etc/app.conf", digest=D2)
    out = g.appraise("h1", [m("/usr/bin/app", D1), m("/etc/app.conf", D2)], now=T0)
    assert out["status"] == "pass"
    assert out["violations"] == []
    assert out["checked"] == 2
    assert out["consecutive_failures"] == 0
    state = g.host_state("h1")
    assert state["status"] == "pass"
    assert state["last_appraised"] == T0
    assert g.stats()["appraisals"] == 1


def test_unknown_file_is_reported_as_violation():
    g = make()
    g.add_baseline("h1", "/usr/bin/app", digest=D1)
    out = g.appraise("h1", [m("/usr/bin/app", D1), m("/tmp/evil", EVIL)], now=T0)
    assert out["status"] == "fail"
    assert out["violations"] == [
        {"path": "/tmp/evil", "algo": "sha256", "kind": "unknown_file",
         "expected": None, "actual": EVIL},
    ]
    assert g.host_state("h1")["consecutive_failures"] == 1


def test_digest_mismatch_violations_are_sorted_and_fail():
    g = make()
    g.add_baseline("h1", "/b", digest=D1)
    g.add_baseline("h1", "/a", digest=D1)
    out = g.appraise("h1", [m("/b", D3), m("/a", D3)], now=T0)
    assert out["status"] == "fail"
    assert [row["path"] for row in out["violations"]] == ["/a", "/b"]
    assert {row["kind"] for row in out["violations"]} == {"digest_mismatch"}
    assert out["violations"][0]["expected"] == D1
    assert out["violations"][0]["actual"] == D3


def test_missing_baseline_file_is_reported_when_required():
    g = make()
    g.add_baseline("h1", "/a", digest=D1)
    g.add_baseline("h1", "/b", digest=D2)
    strict = g.appraise("h1", [m("/a", D1)], now=T0)
    assert strict["status"] == "fail"
    assert strict["violations"] == [
        {"path": "/b", "algo": "sha256", "kind": "missing_file",
         "expected": D2, "actual": None},
    ]
    relaxed = g.appraise("h1", [m("/a", D1)], require_complete=False, now=T0)
    assert relaxed["status"] == "pass"
    assert relaxed["violations"] == []
    assert relaxed["checked"] == 1


def test_duplicate_path_in_batch_rejects_batch_atomically():
    g = make()
    g.add_baseline("h1", "/a", digest=D1)
    with pytest.raises(ima.ImaError) as duplicate:
        g.appraise("h1", [m("/a", D1), m("/a", D2)], now=T0)
    assert duplicate.value.code == "IMA_DUPLICATE_PATH"
    state = g.host_state("h1")
    assert state["consecutive_failures"] == 0
    assert state["status"] == "unknown"
    assert g.stats()["appraisals"] == 0


def test_batch_size_limit_is_enforced_before_state_change():
    g = make(max_batch=3)
    g.add_baseline("h1", "/a", digest=D1)
    rows = [m("/a", D1), m("/b", D1), m("/c", D1), m("/d", D1)]
    with pytest.raises(ima.ImaError) as too_big:
        g.appraise("h1", rows, require_complete=False, now=T0)
    assert too_big.value.code == "IMA_BATCH_TOO_LARGE"
    assert g.host_state("h1")["last_appraised"] is None


def test_exception_suppresses_only_matching_digest():
    g = make()
    g.add_baseline("h1", "/a", digest=D1)
    g.grant_exception("h1", "/a", digest=EVIL, ttl_seconds=600,
                      reason="hotfix", now=T0)
    out = g.appraise("h1", [m("/a", EVIL)], now=T0)
    assert out["status"] == "pass"
    assert out["excepted"] == ["/a"]
    assert out["violations"] == []
    other = g.appraise("h1", [m("/a", D3)], now=T0)
    assert other["status"] == "fail"
    assert other["violations"][0]["kind"] == "digest_mismatch"
    assert other["excepted"] == []


def test_expired_exception_stops_suppressing():
    g = make()
    g.add_baseline("h1", "/a", digest=D1)
    g.grant_exception("h1", "/a", digest=EVIL, ttl_seconds=60,
                      reason="hotfix", now=T0)
    assert g.appraise("h1", [m("/a", EVIL)], now=T0)["status"] == "pass"
    late = "2026-11-23T09:02:00+00:00"
    assert g.appraise("h1", [m("/a", EVIL)], now=late)["status"] == "fail"
    report = g.expire(now=late)
    assert report["exceptions"] == 1
    assert g.stats()["exceptions"] == 0
    again = g.appraise("h1", [m("/a", EVIL)], now=late)
    assert again["status"] == "fail"
    assert g.host_state("h1")["consecutive_failures"] == 2


def test_proposal_requires_quorum_and_rejects_self_approval():
    g = make()
    proposal = g.propose_baseline("h1", changes=[
        {"op": "add", "path": "/opt/b", "digest": D2},
    ], proposer="alice", now=T0)
    pid = proposal["proposal"]
    assert pid == "h1:1"
    with pytest.raises(ima.ImaError) as self_approval:
        g.approve_proposal(pid, approver="alice", now=T0)
    assert self_approval.value.code == "IMA_SELF_APPROVAL"
    first = g.approve_proposal(pid, approver="bob", now=T0)
    assert first["status"] == "pending"
    with pytest.raises(ima.ImaError) as quorum:
        g.apply_proposal(pid, now=T0)
    assert quorum.value.code == "IMA_QUORUM_PENDING"
    with pytest.raises(ima.ImaError) as duplicate:
        g.approve_proposal(pid, approver="bob", now=T0)
    assert duplicate.value.code == "IMA_APPROVER_DUPLICATE"
    second = g.approve_proposal(pid, approver="carol", now=T0)
    assert second["status"] == "ready"
    applied = g.apply_proposal(pid, now=T0)
    assert applied["status"] == "applied"
    assert applied["approvers"] == ["bob", "carol"]
    assert g.host_state("h1")["baseline"] == 1
    with pytest.raises(ima.ImaError) as twice:
        g.apply_proposal(pid, now=T0)
    assert twice.value.code == "IMA_PROPOSAL_APPLIED"


def test_proposal_expiry_and_change_validation():
    g = make(proposal_ttl_seconds=3600)
    pid = g.propose_baseline("h1", changes=[
        {"op": "add", "path": "/opt/b", "digest": D2},
    ], proposer="alice", now=T0)["proposal"]
    g.approve_proposal(pid, approver="bob", now=T0)
    g.approve_proposal(pid, approver="carol", now=T0)
    with pytest.raises(ima.ImaError) as expired:
        g.apply_proposal(pid, now="2026-11-23T10:00:00+00:00")
    assert expired.value.code == "IMA_PROPOSAL_EXPIRED"
    with pytest.raises(ima.ImaError) as unknown:
        g.apply_proposal("h1:99", now=T0)
    assert unknown.value.code == "IMA_PROPOSAL_UNKNOWN"
    with pytest.raises(ima.ImaError) as empty:
        g.propose_baseline("h1", changes=[], proposer="alice", now=T0)
    assert empty.value.code == "IMA_CHANGE_INVALID"
    with pytest.raises(ima.ImaError) as op:
        g.propose_baseline("h1", changes=[{"op": "patch", "path": "/a"}],
                           proposer="alice", now=T0)
    assert op.value.code == "IMA_CHANGE_INVALID"
    with pytest.raises(ima.ImaError) as repeated:
        g.propose_baseline("h1", changes=[
            {"op": "add", "path": "/a", "digest": D1},
            {"op": "remove", "path": "/a"},
        ], proposer="alice", now=T0)
    assert repeated.value.code == "IMA_CHANGE_INVALID"


def test_quarantine_after_three_failures_and_release():
    g = make()
    g.add_baseline("h1", "/a", digest=D1)
    for index in range(3):
        out = g.appraise("h1", [m("/a", EVIL)], now=T0)
        assert out["status"] == "fail"
    assert out["consecutive_failures"] == 3
    assert out["quarantined"] is True
    with pytest.raises(ima.ImaError) as blocked:
        g.appraise("h1", [m("/a", D1)], now=T0)
    assert blocked.value.code == "IMA_HOST_QUARANTINED"
    released = g.release_quarantine("h1")
    assert released["quarantined"] is False
    clean = g.appraise("h1", [m("/a", D1)], now=T0)
    assert clean["status"] == "pass"
    assert clean["consecutive_failures"] == 0


def test_snapshot_restore_preserves_proposals_exceptions_and_streak():
    g = make()
    g.add_baseline("h1", "/a", digest=D1)
    pid = g.propose_baseline("h1", changes=[
        {"op": "add", "path": "/b", "digest": D2},
    ], proposer="alice", now=T0)["proposal"]
    g.approve_proposal(pid, approver="bob", now=T0)
    g.grant_exception("h1", "/a", digest=EVIL, ttl_seconds=3600, now=T0)
    g.appraise("h1", [m("/a", EVIL), m("/b", D2)], now=T0)
    assert g.host_state("h1")["consecutive_failures"] == 1
    snap = json.loads(json.dumps(g.snapshot()))
    g.approve_proposal(pid, approver="carol", now=T0)
    g.apply_proposal(pid, now=T0)
    g.appraise("h1", [m("/a", EVIL)], now=T0)
    g.appraise("h1", [m("/a", EVIL)], now=T0)
    assert g.host_state("h1")["quarantined"] is True
    g.restore(snap)
    state = g.host_state("h1")
    assert state["consecutive_failures"] == 1
    assert state["quarantined"] is False
    assert state["baseline"] == 1
    assert g.stats()["exceptions"] == 1
    g.approve_proposal(pid, approver="carol", now=T0)
    assert g.apply_proposal(pid, now=T0)["status"] == "applied"
    out = g.appraise("h1", [m("/a", EVIL), m("/b", D2)], now=T0)
    assert out["status"] == "pass"
    assert out["excepted"] == ["/a"]
    with pytest.raises(ima.ImaError) as invalid:
        g.restore({"version": 7})
    assert invalid.value.code == "IMA_SNAPSHOT_INVALID"


def test_concurrent_apply_of_proposal_happens_exactly_once():
    g = make()
    pid = g.propose_baseline("h1", changes=[
        {"op": "add", "path": "/x", "digest": D3},
    ], proposer="alice", now=T0)["proposal"]
    g.approve_proposal(pid, approver="bob", now=T0)
    g.approve_proposal(pid, approver="carol", now=T0)
    barrier = threading.Barrier(12)
    applied = []
    denied = []
    errors = []

    def worker():
        try:
            barrier.wait(timeout=10)
            out = g.apply_proposal(pid, now=T0)
            applied.append(out["status"])
        except ima.ImaError as exc:
            denied.append(exc.code)
        except Exception as exc:  # pragma: no cover - defensive
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker) for _ in range(12)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=20)
    assert errors == []
    assert applied == ["applied"]
    assert len(denied) == 11
    assert set(denied) == {"IMA_PROPOSAL_APPLIED"}
    assert g.host_state("h1")["baseline"] == 1
    assert g.stats()["proposals"] == 1
