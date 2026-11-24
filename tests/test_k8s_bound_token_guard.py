import base64
import json
import threading
from datetime import datetime, timezone

import pytest

import k8s_bound_token_guard as kt


T0 = int(datetime(2026, 11, 23, 10, 0, 0, tzinfo=timezone.utc).timestamp())
SUBJECT = "system:serviceaccount:ns:app"


def make(**kwargs):
    return kt.BoundTokenGuard(**kwargs)


def issue(g, **overrides):
    params = {
        "subject": SUBJECT,
        "audiences": ["api", "metrics"],
        "now": T0,
        "ttl": 600,
        "pod": "uid-1",
        "node": "node-a",
    }
    params.update(overrides)
    return g.issue(**params)


def encode(obj) -> str:
    raw = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def test_issue_and_validate_roundtrip():
    g = make()
    out = issue(
        g,
        audiences=["metrics", "api", "api"],
        pod="uid-a",
        node="node-a",
        uid="u1",
    )
    claims = out["claims"]
    assert claims["sub"] == SUBJECT
    assert claims["aud"] == ["api", "metrics"]
    assert claims["iat"] == T0
    assert claims["nbf"] == T0
    assert claims["exp"] == T0 + 600
    assert claims["pod_uid"] == "uid-a"
    assert claims["node"] == "node-a"
    assert claims["jti"] == "u1"
    info = g.validate(
        out["token"],
        now=T0 + 1,
        audiences=["metrics"],
        pod="uid-a",
        node="node-a",
    )
    assert info["status"] == "ok"
    assert info["code"] == "TOK_OK"
    assert info["sub"] == SUBJECT
    assert info["aud"] == ["api", "metrics"]
    assert g.stats()["issued"] == 1
    assert g.stats()["validated"] == 1


def test_required_audiences_must_all_be_present():
    g = make()
    out = issue(g)
    assert g.validate(out["token"], now=T0 + 1, audiences=["api", "metrics"])["code"] == "TOK_OK"
    with pytest.raises(kt.BoundTokenError) as exc:
        g.validate(out["token"], now=T0 + 1, audiences=["api", "other"])
    assert exc.value.code == "TOK_AUDIENCE_MISMATCH"
    assert g.validate(out["token"], now=T0 + 1, audiences=[])["code"] == "TOK_OK"


def test_audience_validation_and_cap():
    g = make()
    with pytest.raises(kt.BoundTokenError) as exc:
        issue(g, audiences=[])
    assert exc.value.code == "TOK_INVALID_AUDIENCE"
    with pytest.raises(kt.BoundTokenError) as exc:
        issue(g, audiences=[f"api{i}" for i in range(9)])
    assert exc.value.code == "TOK_AUDIENCE_LIMIT"
    out = issue(g, audiences=[f"api{i}" for i in range(8)], uid="eight")
    assert len(out["claims"]["aud"]) == 8


def test_expiry_boundary():
    g = make()
    out = issue(g)
    assert g.validate(out["token"], now=T0 + 599)["code"] == "TOK_OK"
    with pytest.raises(kt.BoundTokenError) as exc:
        g.validate(out["token"], now=T0 + 600)
    assert exc.value.code == "TOK_EXPIRED"


def test_not_before_skew_boundary():
    g = make()
    out = issue(g, not_before=T0 + 120, uid="nbf-1")
    with pytest.raises(kt.BoundTokenError) as exc:
        g.validate(out["token"], now=T0 + 59)
    assert exc.value.code == "TOK_NOT_YET_VALID"
    assert g.validate(out["token"], now=T0 + 60)["code"] == "TOK_OK"


def test_lifetime_bounds():
    g = make()
    with pytest.raises(kt.BoundTokenError) as exc:
        issue(g, ttl=3601)
    assert exc.value.code == "TOK_LIFETIME_TOO_LONG"
    with pytest.raises(kt.BoundTokenError) as exc:
        issue(g, ttl=0)
    assert exc.value.code == "TOK_INVALID_LIFETIME"
    with pytest.raises(kt.BoundTokenError) as exc:
        issue(g, ttl=-5)
    assert exc.value.code == "TOK_INVALID_LIFETIME"


def test_pod_binding_mismatch():
    g = make()
    bound = issue(g, pod="uid-a", uid="p1")
    assert g.validate(bound["token"], now=T0 + 1, pod="uid-a")["code"] == "TOK_OK"
    with pytest.raises(kt.BoundTokenError) as exc:
        g.validate(bound["token"], now=T0 + 1, pod="uid-b")
    assert exc.value.code == "TOK_BOUND_OBJECT_MISMATCH"
    unbound = issue(g, pod=None, node=None, uid="p2")
    with pytest.raises(kt.BoundTokenError) as exc:
        g.validate(unbound["token"], now=T0 + 1, pod="uid-a")
    assert exc.value.code == "TOK_BOUND_OBJECT_MISMATCH"
    assert g.validate(unbound["token"], now=T0 + 1)["code"] == "TOK_OK"


def test_node_binding_mismatch():
    g = make()
    bound = issue(g, node="node-a", uid="n1")
    assert g.validate(bound["token"], now=T0 + 1, node="node-a")["code"] == "TOK_OK"
    with pytest.raises(kt.BoundTokenError) as exc:
        g.validate(bound["token"], now=T0 + 1, node="node-b")
    assert exc.value.code == "TOK_NODE_MISMATCH"
    unbound = issue(g, pod=None, node=None, uid="n2")
    with pytest.raises(kt.BoundTokenError) as exc:
        g.validate(unbound["token"], now=T0 + 1, node="node-a")
    assert exc.value.code == "TOK_NODE_MISMATCH"
    assert g.validate(unbound["token"], now=T0 + 1)["code"] == "TOK_OK"


def test_tampered_and_malformed_tokens_are_rejected():
    g = make()
    out = issue(g, uid="tamper-1")
    header, payload, signature = out["token"].split(".")
    padded = payload + "=" * (-len(payload) % 4)
    claims = json.loads(base64.urlsafe_b64decode(padded.encode()).decode())
    claims["sub"] = "system:serviceaccount:ns:evil"
    tampered = header + "." + encode(claims) + "." + signature
    with pytest.raises(kt.BoundTokenError) as exc:
        g.validate(tampered, now=T0 + 1)
    assert exc.value.code == "TOK_BAD_SIGNATURE"
    with pytest.raises(kt.BoundTokenError) as exc:
        g.validate("garbage", now=T0 + 1)
    assert exc.value.code == "TOK_MALFORMED"
    with pytest.raises(kt.BoundTokenError) as exc:
        g.validate(header + "." + payload, now=T0 + 1)
    assert exc.value.code == "TOK_MALFORMED"


def test_revoke_invalidates_earlier_tokens_only():
    g = make()
    old = issue(g, uid="rev-1")
    assert g.validate(old["token"], now=T0 + 1)["code"] == "TOK_OK"
    result = g.revoke(SUBJECT, now=T0 + 10)
    assert result["subject"] == SUBJECT
    assert result["revoked_at"] == T0 + 10
    assert result["invalidated"] == 1
    with pytest.raises(kt.BoundTokenError) as exc:
        g.validate(old["token"], now=T0 + 11)
    assert exc.value.code == "TOK_REVOKED"
    fresh = issue(g, now=T0 + 11, uid="rev-2")
    assert g.validate(fresh["token"], now=T0 + 12)["code"] == "TOK_OK"


def test_key_rotation_grace_then_retirement():
    g = make()
    old = issue(g, uid="key-1")
    rotation = g.rotate_key(now=T0)
    assert rotation["new_kid"] == "k2"
    assert rotation["retired_kid"] == "k1"
    assert rotation["retired_at"] == T0 + 300
    assert g.validate(old["token"], now=T0 + 299)["code"] == "TOK_OK"
    with pytest.raises(kt.BoundTokenError) as exc:
        g.validate(old["token"], now=T0 + 300)
    assert exc.value.code == "TOK_KEY_RETIRED"
    fresh = issue(g, now=T0 + 300, uid="key-2")
    assert fresh["kid"] == "k2"
    assert g.decode(fresh["token"])["header"]["kid"] == "k2"
    assert g.validate(fresh["token"], now=T0 + 301)["code"] == "TOK_OK"


def test_refresh_only_after_eighty_percent_elapsed():
    g = make()
    out = issue(g, ttl=600, uid="ref-1")
    with pytest.raises(kt.BoundTokenError) as exc:
        g.refresh(out["token"], now=T0 + 479)
    assert exc.value.code == "TOK_REFRESH_NOT_NEEDED"
    fresh = g.refresh(out["token"], now=T0 + 480)
    assert fresh["jti"] == out["jti"]
    assert fresh["token"] != out["token"]
    assert fresh["claims"]["iat"] == T0 + 480
    assert fresh["claims"]["exp"] == T0 + 1080
    assert fresh["claims"]["pod_uid"] == "uid-1"
    assert g.validate(fresh["token"], now=T0 + 481, pod="uid-1")["code"] == "TOK_OK"
    with pytest.raises(kt.BoundTokenError) as exc:
        g.refresh(out["token"], now=T0 + 481, ttl=7200)
    assert exc.value.code == "TOK_LIFETIME_TOO_LONG"


def test_snapshot_restore_keeps_revocations_and_tokens():
    g = make()
    kept = issue(g, uid="s1")
    doomed = issue(g, subject="system:serviceaccount:ns:other", uid="s2")
    g.revoke("system:serviceaccount:ns:other", now=T0 + 5)
    stats_before = g.stats()
    snap = g.snapshot()
    g.revoke(SUBJECT, now=T0 + 6)
    restored = kt.BoundTokenGuard()
    restored.restore(snap)
    assert restored.stats() == stats_before
    assert restored.validate(kept["token"], now=T0 + 1)["code"] == "TOK_OK"
    with pytest.raises(kt.BoundTokenError) as exc:
        restored.validate(doomed["token"], now=T0 + 6)
    assert exc.value.code == "TOK_REVOKED"
    assert restored.validate(kept["token"], now=T0 + 7)["code"] == "TOK_OK"


def test_token_limit_and_expired_purge():
    g = make(max_tokens=2)
    issue(g, uid="l1")
    issue(g, uid="l2")
    with pytest.raises(kt.BoundTokenError) as exc:
        issue(g, uid="l3")
    assert exc.value.code == "TOK_LIMIT"
    assert g.purge_expired(now=T0 + 600) == 2
    issue(g, uid="l3")
    assert g.stats()["issued"] == 3


def test_concurrent_issue_with_same_uid_is_atomic():
    g = make()
    codes = []
    errors = []
    lock = threading.Lock()
    barrier = threading.Barrier(8)

    def worker():
        try:
            barrier.wait()
            g.issue(
                SUBJECT,
                audiences=["api"],
                now=T0,
                ttl=600,
                pod="uid-1",
                uid="same",
            )
        except kt.BoundTokenError as exc:
            with lock:
                codes.append(exc.code)
        except Exception as exc:  # pragma: no cover - only on failure
            with lock:
                errors.append(repr(exc))
        else:
            with lock:
                codes.append("TOK_OK")

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    assert codes.count("TOK_OK") == 1
    assert codes.count("TOK_DUPLICATE_UID") == 7
    assert g.stats()["issued"] == 1
