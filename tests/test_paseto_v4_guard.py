import base64
import json
import threading

import pytest

import paseto_v4_guard as paseto


def make(**kwargs):
    return paseto.PasetoGuard(**kwargs)


def b64decode(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def b64encode(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def test_issue_and_verify_roundtrip_uses_four_segments():
    g = make(key="k1-material")
    tok = g.issue({"sub": "alice", "aud": "billing"}, now=1000)
    parts = tok.split(".")
    assert parts[:2] == ["v4", "local"]
    assert len(parts) == 4
    assert "=" not in tok
    out = g.verify(tok, now=1000)
    assert out["sub"] == "alice"
    assert out["aud"] == "billing"
    assert out["iat"] == 1000
    assert out["exp"] == 1600
    assert isinstance(out["jti"], str) and out["jti"]


def test_default_expiry_uses_ttl_and_iat_uses_now():
    g = make(key="k1-material")
    tok = g.issue({"sub": "alice"}, ttl=120, now=2000)
    out = g.verify(tok, now=2000)
    assert out["iat"] == 2000
    assert out["exp"] == 2120
    assert g.stats()["issued"] == 1


def test_expiry_boundary_rejects_at_exp():
    g = make(key="k1-material")
    tok = g.issue({"sub": "alice"}, ttl=60, now=1000)
    assert g.verify(tok, now=1059)["sub"] == "alice"
    with pytest.raises(paseto.PasetoError) as exc:
        g.verify(tok, now=1060)
    assert exc.value.code == "PASETO_EXPIRED"


def test_not_before_is_enforced():
    g = make(key="k1-material")
    tok = g.issue({"sub": "alice", "nbf": 1100}, now=1000)
    with pytest.raises(paseto.PasetoError) as exc:
        g.verify(tok, now=1099)
    assert exc.value.code == "PASETO_NOT_YET_VALID"
    assert g.verify(tok, now=1100)["sub"] == "alice"


def test_body_and_footer_tampering_are_rejected_by_integrity_check():
    g = make(key="k1-material")
    tok = g.issue({"sub": "alice", "jti": "t1"}, footer={"tenant": "a"},
                  now=1000)
    parts = tok.split(".")
    body = bytearray(b64decode(parts[2]))
    body[-1] ^= 0x01
    tampered_body = ".".join(parts[:2] + [b64encode(bytes(body)), parts[3]])
    with pytest.raises(paseto.PasetoError) as exc:
        g.verify(tampered_body, now=1000)
    assert exc.value.code == "PASETO_INTEGRITY"
    footer = json.loads(b64decode(parts[3]).decode("utf-8"))
    footer["tenant"] = "evil"
    tampered_footer = ".".join(
        parts[:3] + [b64encode(json.dumps(footer).encode("utf-8"))]
    )
    with pytest.raises(paseto.PasetoError) as exc2:
        g.verify(tampered_footer, now=1000)
    assert exc2.value.code == "PASETO_INTEGRITY"


def test_implicit_assertion_must_match():
    g = make(key="k1-material")
    tok = g.issue({"sub": "alice"}, implicit="ctx-a", now=1000)
    assert g.verify(tok, implicit="ctx-a", now=1000)["sub"] == "alice"
    with pytest.raises(paseto.PasetoError) as exc:
        g.verify(tok, implicit="ctx-b", now=1000)
    assert exc.value.code == "PASETO_IMPLICIT"
    with pytest.raises(paseto.PasetoError) as exc2:
        g.verify(tok, now=1000)
    assert exc2.value.code == "PASETO_IMPLICIT"
    plain = g.issue({"sub": "bob", "jti": "i2"}, now=1000)
    with pytest.raises(paseto.PasetoError) as exc3:
        g.verify(plain, implicit="ctx", now=1000)
    assert exc3.value.code == "PASETO_IMPLICIT"


def test_audience_must_intersect_when_requested():
    g = make(key="k1-material")
    tok = g.issue({"sub": "alice", "aud": ["billing", "ops"]}, now=1000)
    assert g.verify(tok, audience="ops", now=1000)["sub"] == "alice"
    with pytest.raises(paseto.PasetoError) as exc:
        g.verify(tok, audience="admin", now=1000)
    assert exc.value.code == "PASETO_AUDIENCE"
    single = g.issue({"sub": "bob", "aud": "billing", "jti": "au2"}, now=1000)
    assert g.verify(single, audience="billing", now=1000)["sub"] == "bob"
    with pytest.raises(paseto.PasetoError) as exc2:
        g.verify(single, audience=["ops"], now=1000)
    assert exc2.value.code == "PASETO_AUDIENCE"


def test_revoked_jti_is_rejected_and_sweep_removes_expired_entries():
    g = make(key="k1-material")
    first = g.issue({"sub": "alice", "jti": "r-1"}, now=1000)
    second = g.issue({"sub": "bob", "jti": "r-2"}, now=1000)
    assert g.verify(second, now=1000)["sub"] == "bob"
    g.revoke("r-1", expires_at=1500, now=1000)
    g.revoke("r-2", expires_at=1200, now=1000)
    with pytest.raises(paseto.PasetoError) as exc:
        g.verify(first, now=1001)
    assert exc.value.code == "PASETO_REVOKED"
    assert g.sweep_revocations(now=1200) == 1
    assert g.verify(second, now=1200)["sub"] == "bob"


def test_single_use_verification_rejects_replay():
    g = make(key="k1-material")
    tok = g.issue({"sub": "alice", "jti": "once"}, now=1000)
    assert g.verify(tok, single_use=True, now=1000)["jti"] == "once"
    with pytest.raises(paseto.PasetoError) as exc:
        g.verify(tok, single_use=True, now=1001)
    assert exc.value.code == "PASETO_REPLAY"
    with pytest.raises(paseto.PasetoError) as exc2:
        g.verify(tok, now=1002)
    assert exc2.value.code == "PASETO_REPLAY"


def test_key_rotation_keeps_old_key_during_grace():
    g = make(key="material-one", key_id="k1")
    old = g.issue({"sub": "alice", "jti": "pre-rotation"}, now=1000)
    out = g.rotate_key(key_id="k2", key="material-two", grace=300, now=1000)
    assert out["key_id"] == "k2"
    assert out["previous"] == "k1"
    assert out["expires_at"] == 1300
    assert g.verify(old, now=1299)["sub"] == "alice"
    with pytest.raises(paseto.PasetoError) as exc:
        g.verify(old, now=1300)
    assert exc.value.code == "PASETO_UNKNOWN_KEY"
    fresh = g.issue({"sub": "bob"}, now=1000)
    assert g.verify(fresh, now=1000)["sub"] == "bob"
    statuses = {row["key_id"]: row["status"] for row in g.keyring()}
    assert statuses == {"k1": "grace", "k2": "current"}
    assert "material-one" not in json.dumps(g.keyring())


def test_max_age_rejects_tokens_issued_too_long_ago():
    g = make(key="k1-material")
    tok = g.issue({"sub": "alice"}, ttl=600, now=1000)
    with pytest.raises(paseto.PasetoError) as exc:
        g.verify(tok, max_age=60, now=1120)
    assert exc.value.code == "PASETO_TOKEN_TOO_OLD"
    assert g.verify(tok, max_age=200, now=1120)["sub"] == "alice"


def test_peek_exposes_header_and_footer_but_not_claims():
    g = make(key="k1-material", key_id="k1")
    tok = g.issue({"sub": "alice", "secret": "s3cr3t-value"},
                  footer={"tenant": "a"}, now=1000)
    info = g.peek(tok)
    assert info["version"] == "v4"
    assert info["purpose"] == "local"
    assert info["kid"] == "k1"
    assert info["footer"] == {"tenant": "a"}
    assert isinstance(info["body_bytes"], int) and info["body_bytes"] > 0
    assert "s3cr3t-value" not in str(info)
    assert "alice" not in str(info)


def test_token_size_limit_applies_to_issue_and_verify():
    g = make(key="k1-material", max_token_bytes=512)
    with pytest.raises(paseto.PasetoError) as exc:
        g.issue({"sub": "x" * 800}, now=1000)
    assert exc.value.code == "PASETO_SIZE_LIMIT"
    with pytest.raises(paseto.PasetoError) as exc2:
        g.verify("v4.local." + "a" * 600, now=1000)
    assert exc2.value.code == "PASETO_SIZE_LIMIT"


def test_concurrent_single_use_verify_allows_one_winner():
    g = make(key="k1-material")
    tok = g.issue({"sub": "alice", "jti": "race"}, now=1000)
    barrier = threading.Barrier(8)
    wins = []
    codes = []
    lock = threading.Lock()

    def worker():
        barrier.wait()
        try:
            out = g.verify(tok, single_use=True, now=1000)
        except paseto.PasetoError as exc:
            with lock:
                codes.append(exc.code)
            return
        with lock:
            wins.append(out)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(wins) == 1
    assert sorted(codes) == ["PASETO_REPLAY"] * 7
    assert g.stats()["verified"] == 1


def test_snapshot_restore_keeps_keyring_revocations_and_replay_set():
    g = make(key="material-one", key_id="k1")
    pre = g.issue({"sub": "pre", "jti": "pre-1"}, now=1000)
    g.rotate_key(key_id="k2", key="material-two", grace=300, now=1000)
    revoked = g.issue({"sub": "alice", "jti": "o1"}, now=1000)
    g.revoke("o1", expires_at=3000, now=1000)
    used = g.issue({"sub": "bob", "jti": "u1"}, now=1000)
    assert g.verify(used, single_use=True, now=1000)["jti"] == "u1"
    state = json.loads(json.dumps(g.snapshot()))
    restored = paseto.PasetoGuard.restore(state)
    with pytest.raises(paseto.PasetoError) as exc:
        restored.verify(revoked, now=1001)
    assert exc.value.code == "PASETO_REVOKED"
    with pytest.raises(paseto.PasetoError) as exc2:
        restored.verify(used, now=1001)
    assert exc2.value.code == "PASETO_REPLAY"
    assert restored.verify(pre, now=1200)["sub"] == "pre"
    fresh = restored.issue({"sub": "carol"}, now=1001)
    assert restored.verify(fresh, now=1001)["sub"] == "carol"
