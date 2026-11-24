import hashlib
import hmac
import json
import threading

import pytest

import jwks_rotation_guard as jw

ISSUER = "https://idp.example"
ISSUER_B = "https://idp-b.example"


def make(**kwargs):
    return jw.JwksGuard(**kwargs)


def compact(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def signature(material, kid, iss, alg, payload):
    message = f"{iss}|{kid}|{alg}|{compact(payload)}".encode("utf-8")
    return hmac.new(material.encode("utf-8"), message,
                    hashlib.sha256).hexdigest()


def token(material, kid="k1", iss=ISSUER, alg="RS256", payload=None):
    body = {"sub": "deploy-bot", "scope": "read"} if payload is None else payload
    return {
        "iss": iss,
        "kid": kid,
        "alg": alg,
        "payload": body,
        "signature": signature(material, kid, iss, alg, body),
    }


def test_valid_token_is_verified_and_returns_payload():
    g = make()
    g.add_issuer(ISSUER)
    g.publish_key(ISSUER, "k1", material="secret-one", now=1000)
    out = g.verify(token("secret-one"), issuer=ISSUER, now=1000)
    assert out["payload"] == {"scope": "read", "sub": "deploy-bot"}
    assert out["kid"] == "k1"
    assert out["issuer"] == ISSUER
    assert out["stale"] is False
    assert g.stats()["refreshes"] == 1


def test_alg_confusion_is_rejected_before_signature_check():
    g = make()
    g.add_issuer(ISSUER)
    g.publish_key(ISSUER, "k1", material="secret-one", now=1000)
    forged = token("secret-one", alg="none")
    with pytest.raises(jw.JwksError) as exc:
        g.verify(forged, issuer=ISSUER, now=1000)
    assert exc.value.code == "JWKS_ALG_MISMATCH"


def test_tampered_payload_breaks_signature():
    g = make()
    g.add_issuer(ISSUER)
    g.publish_key(ISSUER, "k1", material="secret-one", now=1000)
    forged = token("secret-one")
    forged["payload"]["scope"] = "admin"
    with pytest.raises(jw.JwksError) as exc:
        g.verify(forged, issuer=ISSUER, now=1000)
    assert exc.value.code == "JWKS_BAD_SIGNATURE"


def test_unknown_kid_triggers_one_refresh_per_cooldown():
    g = make(refresh_cooldown=30)
    g.add_issuer(ISSUER)
    g.publish_key(ISSUER, "k1", material="secret-one", now=1000)
    assert g.verify(token("secret-one"), issuer=ISSUER, now=1000)["kid"] == "k1"
    for offset in (0, 5, 10):
        with pytest.raises(jw.JwksError) as exc:
            g.verify(token("secret-one", kid="ghost"), issuer=ISSUER,
                     now=1000 + offset)
        assert exc.value.code == "JWKS_UNKNOWN_KID"
    assert g.stats()["refreshes"] == 1


def test_cooldown_expiry_allows_a_second_fetch_for_a_new_kid():
    g = make(refresh_cooldown=30)
    g.add_issuer(ISSUER)
    g.publish_key(ISSUER, "k1", material="secret-one", now=1000)
    g.verify(token("secret-one"), issuer=ISSUER, now=1000)
    g.publish_key(ISSUER, "k2", material="secret-two", now=1031)
    out = g.verify(token("secret-two", kid="k2"), issuer=ISSUER, now=1031)
    assert out["kid"] == "k2"
    assert g.stats()["refreshes"] == 2


def test_cache_ttl_refresh_picks_up_new_keys():
    g = make(ttl=300)
    g.add_issuer(ISSUER)
    g.publish_key(ISSUER, "k1", material="secret-one", now=1000)
    g.verify(token("secret-one"), issuer=ISSUER, now=1000)
    g.publish_key(ISSUER, "k2", material="secret-two", now=1100)
    out = g.verify(token("secret-two", kid="k2"), issuer=ISSUER, now=1300)
    assert out["kid"] == "k2"
    assert g.stats()["refreshes"] == 2


def test_stale_cache_serves_verification_when_endpoint_is_down():
    g = make(ttl=300, max_stale=900)
    g.add_issuer(ISSUER)
    g.publish_key(ISSUER, "k1", material="secret-one", now=1000)
    g.verify(token("secret-one"), issuer=ISSUER, now=1000)
    g.set_endpoint_healthy(ISSUER, False)
    out = g.verify(token("secret-one"), issuer=ISSUER, now=1400)
    assert out["stale"] is True
    assert out["kid"] == "k1"
    assert g.stats()["refreshes"] == 1
    assert g.stats()["failures"] == 1


def test_stale_cache_is_rejected_after_max_stale_window():
    g = make(ttl=300, max_stale=900)
    g.add_issuer(ISSUER)
    g.publish_key(ISSUER, "k1", material="secret-one", now=1000)
    g.verify(token("secret-one"), issuer=ISSUER, now=1000)
    g.set_endpoint_healthy(ISSUER, False)
    with pytest.raises(jw.JwksError) as exc:
        g.verify(token("secret-one"), issuer=ISSUER, now=2000)
    assert exc.value.code == "JWKS_CACHE_STALE"


def test_rotation_keeps_old_key_until_overlap_expires():
    g = make()
    g.add_issuer(ISSUER)
    g.publish_key(ISSUER, "k1", material="secret-one", now=1000)
    assert g.verify(token("secret-one"), issuer=ISSUER, now=1000)["kid"] == "k1"
    out = g.rotate(ISSUER, kid="k2", material="secret-two", overlap=60,
                   now=1000)
    assert out["kid"] == "k2"
    assert out["previous"] == "k1"
    assert out["previous_expires_at"] == 1060
    fresh = token("secret-two", kid="k2")
    assert g.verify(fresh, issuer=ISSUER, now=1000)["kid"] == "k2"
    assert g.verify(token("secret-one"), issuer=ISSUER, now=1059)["kid"] == "k1"
    with pytest.raises(jw.JwksError) as exc:
        g.verify(token("secret-one"), issuer=ISSUER, now=1060)
    assert exc.value.code == "JWKS_KEY_EXPIRED"


def test_kid_collision_across_issuers_does_not_cross_verify():
    g = make()
    g.add_issuer(ISSUER)
    g.add_issuer(ISSUER_B)
    g.publish_key(ISSUER, "shared", material="alpha", now=1000)
    g.publish_key(ISSUER_B, "shared", material="beta", now=1000)
    assert g.verify(token("alpha", kid="shared"), issuer=ISSUER,
                    now=1000)["issuer"] == ISSUER
    with pytest.raises(jw.JwksError) as exc:
        g.verify(token("beta", kid="shared"), issuer=ISSUER, now=1000)
    assert exc.value.code == "JWKS_BAD_SIGNATURE"
    with pytest.raises(jw.JwksError) as exc2:
        g.verify(token("beta", kid="shared", iss=ISSUER_B), issuer=ISSUER,
                 now=1000)
    assert exc2.value.code == "JWKS_ISSUER_MISMATCH"


def test_key_not_yet_valid_is_rejected_until_not_before():
    g = make()
    g.add_issuer(ISSUER)
    g.publish_key(ISSUER, "k1", material="secret-one", not_before=1100,
                  now=1000)
    with pytest.raises(jw.JwksError) as exc:
        g.verify(token("secret-one"), issuer=ISSUER, now=1099)
    assert exc.value.code == "JWKS_KEY_NOT_YET_VALID"
    assert g.verify(token("secret-one"), issuer=ISSUER, now=1100)["kid"] == "k1"


def test_duplicate_kid_is_rejected_until_retired():
    g = make()
    g.add_issuer(ISSUER)
    g.publish_key(ISSUER, "k1", material="secret-one", now=1000)
    with pytest.raises(jw.JwksError) as exc:
        g.publish_key(ISSUER, "k1", material="secret-two", now=1000)
    assert exc.value.code == "JWKS_DUP_KID"
    g.retire_key(ISSUER, "k1", now=1000)
    g.publish_key(ISSUER, "k1", material="secret-two", now=1000)
    g.refresh(ISSUER, now=1000, force=True)
    assert g.verify(token("secret-two"), issuer=ISSUER, now=1001)["kid"] == "k1"


def test_concurrent_unknown_kid_verification_refreshes_once():
    g = make(refresh_cooldown=30)
    g.add_issuer(ISSUER)
    g.publish_key(ISSUER, "k1", material="secret-one", now=1000)
    ghost = token("secret-one", kid="ghost")
    barrier = threading.Barrier(8)
    codes = []
    lock = threading.Lock()

    def worker():
        barrier.wait()
        try:
            g.verify(ghost, issuer=ISSUER, now=1000)
        except jw.JwksError as exc:
            with lock:
                codes.append(exc.code)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(codes) == ["JWKS_UNKNOWN_KID"] * 8
    assert g.stats()["refreshes"] == 1


def test_snapshot_restore_keeps_cache_and_does_not_refetch():
    g = make()
    g.add_issuer(ISSUER)
    g.publish_key(ISSUER, "k1", material="secret-one", now=1000)
    assert g.verify(token("secret-one"), issuer=ISSUER, now=1000)["kid"] == "k1"
    state = json.loads(json.dumps(g.snapshot()))
    restored = jw.JwksGuard.restore(state)
    assert restored.stats()["refreshes"] == 1
    out = restored.verify(token("secret-one"), issuer=ISSUER, now=1000)
    assert out["kid"] == "k1"
    assert restored.stats()["refreshes"] == 1
    g.publish_key(ISSUER, "k3", material="secret-three", now=1000)
    g.refresh(ISSUER, now=1000, force=True)
    fresh = token("secret-three", kid="k3")
    assert g.verify(fresh, issuer=ISSUER, now=1000)["kid"] == "k3"
    with pytest.raises(jw.JwksError) as exc:
        restored.verify(fresh, issuer=ISSUER, now=1000)
    assert exc.value.code == "JWKS_UNKNOWN_KID"


def test_key_limit_is_enforced_per_issuer():
    g = make(max_keys=2)
    g.add_issuer(ISSUER)
    g.publish_key(ISSUER, "k1", material="one", now=1000)
    g.publish_key(ISSUER, "k2", material="two", now=1000)
    with pytest.raises(jw.JwksError) as exc:
        g.publish_key(ISSUER, "k3", material="three", now=1000)
    assert exc.value.code == "JWKS_KEY_LIMIT"
    g.retire_key(ISSUER, "k1", now=1000)
    g.publish_key(ISSUER, "k3", material="three", now=1000)
    assert [row["kid"] for row in g.keys(ISSUER, now=1000)["keys"]] == ["k2", "k3"]
