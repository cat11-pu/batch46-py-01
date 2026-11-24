import base64
import hashlib
import hmac
import json
import threading
from datetime import datetime, timezone

import pytest

import gcp_sa_jwt_guard as sj


T0 = int(datetime(2026, 11, 23, 10, 0, 0, tzinfo=timezone.utc).timestamp())
SA = "svc@proj.iam.gserviceaccount.com"
SECRET = "dummy-secret"
AUD = "https://oauth2.googleapis.com/token"


def make(**kwargs):
    g = sj.SaJwtGuard(**kwargs)
    g.register_service_account(SA, secret=SECRET, scopes=["a", "b", "c"])
    return g


def mint(g, **overrides):
    params = {
        "email": SA,
        "audience": AUD,
        "scope": ["a", "b"],
        "now": T0,
        "lifetime": 900,
    }
    params.update(overrides)
    return g.create_assertion(**params)


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def encode(obj) -> str:
    return b64(json.dumps(obj, separators=(",", ":"), sort_keys=True).encode())


def sign_jwt(claims, secret=SECRET, header=None):
    header = header or {"alg": "HS256", "typ": "JWT"}
    signing_input = encode(header) + "." + encode(claims)
    digest = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    return signing_input + "." + b64(digest)


def test_exchange_returns_bearer_token_with_canonical_scope():
    g = make()
    assertion = mint(g, scope=["b", "a", "b"])["assertion"]
    out = g.exchange(assertion, audience=AUD, requested_scope=["b", "a", "a"], now=T0)
    assert out["status"] == "ok"
    assert out["code"] == "JWT_OK"
    assert out["token_type"] == "Bearer"
    assert out["access_token"].startswith("ya29.")
    assert out["expires_in"] == 900
    assert out["scope"] == ["a", "b"]
    assert out["sub"] == SA


def test_replay_is_rejected_until_purged():
    g = make()
    assertion = mint(g)["assertion"]
    assert g.exchange(assertion, audience=AUD, requested_scope=["a"], now=T0)["code"] == "JWT_OK"
    with pytest.raises(sj.SaJwtError) as exc:
        g.exchange(assertion, audience=AUD, requested_scope=["a"], now=T0)
    assert exc.value.code == "JWT_REPLAY"
    assert g.purge_replays(T0) == 1
    again = g.exchange(assertion, audience=AUD, requested_scope=["a"], now=T0)
    assert again["code"] == "JWT_OK"


def test_alg_none_and_malformed_tokens_are_rejected():
    g = make()
    claims = {"iss": SA, "sub": SA, "aud": AUD, "iat": T0, "exp": T0 + 600, "jti": "none-1"}
    none_token = encode({"alg": "none", "typ": "JWT"}) + "." + encode(claims) + "."
    with pytest.raises(sj.SaJwtError) as exc:
        g.exchange(none_token, audience=AUD, requested_scope=["a"], now=T0)
    assert exc.value.code == "JWT_ALG_NONE"
    with pytest.raises(sj.SaJwtError) as exc:
        g.exchange("not-a-jwt", audience=AUD, requested_scope=["a"], now=T0)
    assert exc.value.code == "JWT_MALFORMED"


def test_tampered_payload_breaks_signature():
    g = make()
    assertion = mint(g)["assertion"]
    header, payload, signature = assertion.split(".")
    padded = payload + "=" * (-len(payload) % 4)
    claims = json.loads(base64.urlsafe_b64decode(padded.encode()).decode())
    claims["scope"] = "a b c"
    tampered = header + "." + encode(claims) + "." + signature
    with pytest.raises(sj.SaJwtError) as exc:
        g.exchange(tampered, audience=AUD, requested_scope=["a"], now=T0)
    assert exc.value.code == "JWT_BAD_SIGNATURE"


def test_expiry_boundary():
    g = make()
    expired = mint(g, now=T0 - 600, lifetime=600, jwt_id="expired-1")["assertion"]
    with pytest.raises(sj.SaJwtError) as exc:
        g.exchange(expired, audience=AUD, requested_scope=["a"], now=T0)
    assert exc.value.code == "JWT_EXPIRED"
    fresh = mint(g, now=T0, lifetime=600, jwt_id="fresh-1")["assertion"]
    assert g.exchange(fresh, audience=AUD, requested_scope=["a"], now=T0 + 599)["code"] == "JWT_OK"


def test_issued_at_skew_boundary():
    g = make()
    future = mint(g, now=T0 + 61, jwt_id="future-1")["assertion"]
    with pytest.raises(sj.SaJwtError) as exc:
        g.exchange(future, audience=AUD, requested_scope=["a"], now=T0)
    assert exc.value.code == "JWT_NOT_YET_VALID"
    edge = mint(g, now=T0 + 60, jwt_id="edge-1")["assertion"]
    assert g.exchange(edge, audience=AUD, requested_scope=["a"], now=T0)["code"] == "JWT_OK"


def test_audience_mismatch():
    g = make()
    assertion = mint(g, audience="https://example.test/token")["assertion"]
    with pytest.raises(sj.SaJwtError) as exc:
        g.exchange(assertion, audience=AUD, requested_scope=["a"], now=T0)
    assert exc.value.code == "JWT_BAD_AUDIENCE"


def test_scope_must_be_granted_and_is_canonicalized():
    g = make()
    assertion = mint(g, scope=["c", "a", "a"], jwt_id="scope-1")["assertion"]
    out = g.exchange(assertion, audience=AUD, requested_scope=["c", "a", "a"], now=T0)
    assert out["scope"] == ["a", "c"]
    ungranted = mint(g, scope=["a", "z"], jwt_id="scope-2")["assertion"]
    with pytest.raises(sj.SaJwtError) as exc:
        g.exchange(ungranted, audience=AUD, requested_scope=["a"], now=T0)
    assert exc.value.code == "JWT_SCOPE_NOT_GRANTED"
    too_wide = mint(g, jwt_id="scope-3")["assertion"]
    with pytest.raises(sj.SaJwtError) as exc:
        g.exchange(too_wide, audience=AUD, requested_scope=["a", "z"], now=T0)
    assert exc.value.code == "JWT_SCOPE_NOT_GRANTED"


def test_lifetime_cap_on_issue_and_on_exchange():
    g = make()
    with pytest.raises(sj.SaJwtError) as exc:
        mint(g, lifetime=7201)
    assert exc.value.code == "JWT_LIFETIME_TOO_LONG"
    claims = {
        "iss": SA,
        "sub": SA,
        "aud": AUD,
        "iat": T0,
        "exp": T0 + 7201,
        "jti": "long-1",
        "scope": "a",
    }
    token = sign_jwt(claims)
    with pytest.raises(sj.SaJwtError) as exc:
        g.exchange(token, audience=AUD, requested_scope=["a"], now=T0)
    assert exc.value.code == "JWT_LIFETIME_TOO_LONG"


def test_delegation_requires_allowlist_entry():
    g = make()
    denied = mint(g, subject="alice@example.com", jwt_id="deleg-1")["assertion"]
    with pytest.raises(sj.SaJwtError) as exc:
        g.exchange(denied, audience=AUD, requested_scope=["a"], now=T0)
    assert exc.value.code == "JWT_DELEGATION_DENIED"
    g.allow_delegation(SA, "alice@example.com")
    allowed = mint(g, subject="alice@example.com", jwt_id="deleg-2")["assertion"]
    out = g.exchange(allowed, audience=AUD, requested_scope=["a"], now=T0)
    assert out["code"] == "JWT_OK"
    assert out["sub"] == "alice@example.com"
    other = mint(g, subject="bob@example.com", jwt_id="deleg-3")["assertion"]
    with pytest.raises(sj.SaJwtError) as exc:
        g.exchange(other, audience=AUD, requested_scope=["a"], now=T0)
    assert exc.value.code == "JWT_DELEGATION_DENIED"


def test_introspect_and_revoke():
    g = make()
    out = g.exchange(mint(g)["assertion"], audience=AUD, requested_scope=["a"], now=T0)
    token = out["access_token"]
    info = g.introspect(token, now=T0 + 1)
    assert info["active"] is True
    assert info["sub"] == SA
    assert info["scope"] == ["a"]
    assert info["exp"] == T0 + 900
    revoked = g.revoke_token(token)
    assert revoked["revoked"] is True
    assert g.introspect(token, now=T0 + 2)["active"] is False
    assert g.introspect("ya29.unknown", now=T0)["active"] is False


def test_access_token_expires_with_assertion():
    g = make()
    out = g.exchange(
        mint(g, lifetime=120)["assertion"],
        audience=AUD,
        requested_scope=["a"],
        now=T0,
    )
    token = out["access_token"]
    assert g.introspect(token, now=T0 + 119)["active"] is True
    assert g.introspect(token, now=T0 + 120)["active"] is False


def test_snapshot_restore_keeps_replay_cache_and_tokens():
    g = make()
    assertion = mint(g)["assertion"]
    out = g.exchange(assertion, audience=AUD, requested_scope=["a"], now=T0)
    stats_before = g.stats()
    snap = g.snapshot()
    g.revoke_token(out["access_token"])
    restored = sj.SaJwtGuard()
    restored.restore(snap)
    assert restored.stats() == stats_before
    assert restored.introspect(out["access_token"], now=T0 + 1)["active"] is True
    with pytest.raises(sj.SaJwtError) as exc:
        restored.exchange(assertion, audience=AUD, requested_scope=["a"], now=T0)
    assert exc.value.code == "JWT_REPLAY"


def test_token_limit_and_purge():
    g = make(max_tokens=2)
    assert g.exchange(mint(g, jwt_id="t1")["assertion"], audience=AUD, requested_scope=["a"], now=T0)["code"] == "JWT_OK"
    assert g.exchange(mint(g, jwt_id="t2")["assertion"], audience=AUD, requested_scope=["a"], now=T0)["code"] == "JWT_OK"
    with pytest.raises(sj.SaJwtError) as exc:
        g.exchange(mint(g, jwt_id="t3")["assertion"], audience=AUD, requested_scope=["a"], now=T0)
    assert exc.value.code == "JWT_TOKEN_LIMIT"
    assert g.purge_expired_tokens(now=T0 + 900) == 2
    assert g.exchange(mint(g, jwt_id="t4")["assertion"], audience=AUD, requested_scope=["a"], now=T0)["code"] == "JWT_OK"


def test_concurrent_exchange_consumes_jti_once():
    g = make()
    assertion = mint(g)["assertion"]
    codes = []
    errors = []
    lock = threading.Lock()
    barrier = threading.Barrier(8)

    def worker():
        try:
            barrier.wait()
            g.exchange(assertion, audience=AUD, requested_scope=["a"], now=T0)
        except sj.SaJwtError as exc:
            with lock:
                codes.append(exc.code)
        except Exception as exc:  # pragma: no cover - only on failure
            with lock:
                errors.append(repr(exc))
        else:
            with lock:
                codes.append("JWT_OK")

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    assert codes.count("JWT_OK") == 1
    assert codes.count("JWT_REPLAY") == 7
    assert g.stats()["exchanged"] == 1
    assert g.stats()["rejected"] == 7
