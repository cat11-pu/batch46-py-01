import json
import threading

import pytest

import ci_oidc_trust_guard as oidc

ISSUER = "https://token.ci.example"


def make(**kwargs):
    return oidc.CiOidcGuard(issuer=ISSUER, **kwargs)


def token(**overrides):
    row = {
        "iss": ISSUER,
        "aud": "sts.example",
        "sub": "repo:acme/app:ref:refs/heads/main",
        "jti": "jti-1",
        "iat": 1000,
        "exp": 1600,
        "claims": {"repository": "acme/app"},
    }
    row.update(overrides)
    return row


def test_matching_policy_allows_token_and_reports_session():
    g = make()
    g.register_policy(
        "deploy",
        audiences=["sts.example"],
        subjects=["repo:acme/app:ref:refs/heads/*"],
        claims={"repository": "acme/app"},
        max_session=900,
    )
    verdict = g.evaluate(token(), now=1000)
    assert verdict["allowed"] is True
    assert verdict["policy"] == "deploy"
    assert verdict["code"] is None
    assert verdict["session"] == 600
    out = g.assume(token(jti="jti-2"), now=1000)
    assert out["policy"] == "deploy"
    assert out["session"] == 600
    assert out["expires_at"] == 1600
    assert g.stats()["assumed"] == 1


def test_subject_matching_is_whole_string_and_rejects_prefix_confusion():
    g = make()
    g.register_policy(
        "exact",
        audiences=["sts.example"],
        subjects=["repo:acme/app:ref:refs/heads/main"],
    )
    assert g.evaluate(token(), now=1000)["allowed"] is True
    longer_repo = token(sub="repo:acme/app-extra:ref:refs/heads/main",
                        jti="jti-b")
    verdict = g.evaluate(longer_repo, now=1000)
    assert verdict["allowed"] is False
    assert verdict["code"] == "OIDC_SUBJECT_MISMATCH"
    trailing = token(sub="repo:acme/app:ref:refs/heads/main:pr", jti="jti-c")
    assert g.evaluate(trailing, now=1000)["code"] == "OIDC_SUBJECT_MISMATCH"


def test_wildcard_does_not_cross_colon_separators():
    g = make()
    g.register_policy(
        "wild",
        audiences=["sts.example"],
        subjects=["repo:acme/app:ref:refs/heads/*"],
    )
    ok = token(sub="repo:acme/app:ref:refs/heads/release/1.2", jti="w1")
    assert g.evaluate(ok, now=1000)["allowed"] is True
    crossed = token(sub="repo:acme/app:ref:refs/heads/main:environment:prod",
                    jti="w2")
    assert g.evaluate(crossed, now=1000)["code"] == "OIDC_SUBJECT_MISMATCH"
    other_repo = token(sub="repo:acme/app-other:ref:refs/heads/main",
                       jti="w3")
    assert g.evaluate(other_repo, now=1000)["code"] == "OIDC_SUBJECT_MISMATCH"


def test_audience_mismatch_is_reported_and_assume_raises():
    g = make()
    g.register_policy("svc", audiences=["sts.example", "backup.example"])
    listed = token(aud=["other.example", "backup.example"], jti="a1")
    assert g.evaluate(listed, now=1000)["allowed"] is True
    verdict = g.evaluate(token(aud="other.example", jti="a2"), now=1000)
    assert verdict["allowed"] is False
    assert verdict["code"] == "OIDC_AUDIENCE_MISMATCH"
    with pytest.raises(oidc.CiOidcError) as exc:
        g.assume(token(aud="other.example", jti="a3"), now=1000)
    assert exc.value.code == "OIDC_AUDIENCE_MISMATCH"


def test_expired_token_is_rejected_even_if_policy_matches():
    g = make()
    g.register_policy("svc", audiences=["sts.example"])
    ok = g.evaluate(token(jti="e1"), now=1599)
    assert ok["allowed"] is True
    assert ok["session"] == 1
    bad = g.evaluate(token(jti="e2"), now=1600)
    assert bad["allowed"] is False
    assert bad["code"] == "OIDC_TOKEN_EXPIRED"
    assert bad["session"] == 0


def test_issued_at_skew_tolerance_is_sixty_seconds():
    g = make()
    g.register_policy("svc", audiences=["sts.example"])
    ahead = g.evaluate(token(iat=1030, jti="s1"), now=1000)
    assert ahead["allowed"] is True
    future = g.evaluate(token(iat=1061, jti="s2"), now=1000)
    assert future["allowed"] is False
    assert future["code"] == "OIDC_CLOCK_SKEW"


def test_claim_conditions_require_exact_values_and_ignore_extras():
    g = make()
    g.register_policy(
        "env",
        audiences=["sts.example"],
        claims={"environment": ["prod", "staging"]},
    )
    good = token(claims={"environment": "prod", "extra": "x"}, jti="c1")
    assert g.evaluate(good, now=1000)["allowed"] is True
    missing = g.evaluate(token(claims={"extra": "x"}, jti="c2"), now=1000)
    assert missing["code"] == "OIDC_CLAIM_MISMATCH"
    wrong_case = g.evaluate(token(claims={"environment": "Prod"}, jti="c3"),
                            now=1000)
    assert wrong_case["code"] == "OIDC_CLAIM_MISMATCH"


def test_deny_policy_wins_over_allow_regardless_of_order():
    g = make()
    g.register_policy("allow-all", audiences=["sts.example"])
    g.register_policy(
        "block-main",
        audiences=["sts.example"],
        subjects=["repo:acme/app:ref:refs/heads/main"],
        deny=True,
    )
    verdict = g.evaluate(token(jti="d1"), now=1000)
    assert verdict["allowed"] is False
    assert verdict["code"] == "OIDC_DENY_POLICY"
    assert verdict["policy"] == "block-main"
    with pytest.raises(oidc.CiOidcError) as exc:
        g.assume(token(jti="d2"), now=1000)
    assert exc.value.code == "OIDC_DENY_POLICY"
    g.set_policy_enabled("block-main", False)
    assert g.evaluate(token(jti="d3"), now=1000)["allowed"] is True


def test_assume_consumes_jti_once_and_second_attempt_is_replay():
    g = make()
    g.register_policy("svc", audiences=["sts.example"])
    first = g.assume(token(jti="r1"), now=1000)
    assert first["jti"] == "r1"
    assert g.evaluate(token(jti="r1"), now=1001)["code"] == "OIDC_REPLAY_DETECTED"
    with pytest.raises(oidc.CiOidcError) as exc:
        g.assume(token(jti="r1"), now=1002)
    assert exc.value.code == "OIDC_REPLAY_DETECTED"
    assert g.assume(token(jti="r2"), now=1003)["policy"] == "svc"


def test_session_is_capped_by_policy_and_token_expiry():
    g = make()
    g.register_policy("short", audiences=["sts.example"], max_session=300)
    assert g.assume(token(jti="m1"), now=1000)["session"] == 300
    g2 = make()
    g2.register_policy("long", audiences=["sts.example"], max_session=7200)
    out = g2.assume(token(jti="m2", exp=1450), now=1000)
    assert out["session"] == 450
    assert out["expires_at"] == 1450


def test_issuer_rotation_invalidates_old_issuer_tokens_only():
    g = make()
    g.register_policy("svc", audiences=["sts.example"])
    old = token(jti="i1")
    assert g.evaluate(old, now=1000)["allowed"] is True
    rotated = g.rotate_issuer("https://token.ci2.example")
    assert rotated["issuer"] == "https://token.ci2.example"
    assert g.evaluate(old, now=1001)["code"] == "OIDC_ISSUER_MISMATCH"
    fresh = token(iss="https://token.ci2.example", jti="i2")
    assert g.evaluate(fresh, now=1002)["allowed"] is True


def test_missing_or_disabled_policy_denies_with_no_matching_policy():
    g = make()
    verdict = g.evaluate(token(jti="n1"), now=1000)
    assert verdict["allowed"] is False
    assert verdict["code"] == "OIDC_NO_MATCHING_POLICY"
    with pytest.raises(oidc.CiOidcError) as exc:
        g.assume(token(jti="n2"), now=1000)
    assert exc.value.code == "OIDC_NO_MATCHING_POLICY"
    g.register_policy("svc", audiences=["sts.example"], enabled=False)
    assert g.evaluate(token(jti="n3"), now=1000)["code"] == "OIDC_NO_MATCHING_POLICY"
    assert g.policies()[0]["enabled"] is False


def test_concurrent_assume_allows_exactly_one_winner():
    g = make()
    g.register_policy("svc", audiences=["sts.example"])
    shared = token(jti="race-1")
    barrier = threading.Barrier(8)
    wins = []
    codes = []
    lock = threading.Lock()

    def worker():
        barrier.wait()
        try:
            out = g.assume(shared, now=1000)
        except oidc.CiOidcError as exc:
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
    assert sorted(codes) == ["OIDC_REPLAY_DETECTED"] * 7
    assert g.stats()["assumed"] == 1


def test_snapshot_restore_keeps_consumed_jti_and_policies():
    g = make()
    g.register_policy("svc", audiences=["sts.example"])
    g.assume(token(jti="p1"), now=1000)
    state = json.loads(json.dumps(g.snapshot()))
    restored = oidc.CiOidcGuard.restore(state)
    with pytest.raises(oidc.CiOidcError) as exc:
        restored.assume(token(jti="p1"), now=1001)
    assert exc.value.code == "OIDC_REPLAY_DETECTED"
    out = restored.assume(token(jti="p2"), now=1002)
    assert out["policy"] == "svc"
    assert restored.stats()["used_jti"] == 2


def test_explain_lists_reasons_in_fixed_order_and_purge_drops_expired():
    g = make()
    g.register_policy(
        "svc",
        audiences=["sts.example"],
        subjects=["repo:acme/app:ref:refs/heads/main"],
    )
    bad = token(aud="other.example",
                sub="repo:other/app:ref:refs/heads/main",
                jti="x1", exp=1100)
    report = g.explain(bad, now=1200)
    assert report["allowed"] is False
    assert report["reasons"] == [
        "OIDC_AUDIENCE_MISMATCH",
        "OIDC_TOKEN_EXPIRED",
        "OIDC_SUBJECT_MISMATCH",
    ]
    good = token(jti="x2")
    assert g.explain(good, now=1000)["reasons"] == []
    assert g.assume(good, now=1001)["policy"] == "svc"
    g.assume(token(jti="live", exp=5000), now=1000)
    g.assume(token(jti="dead", exp=1200), now=1000)
    assert g.stats()["used_jti"] == 3
    assert g.purge_used_jti(now=1300) == 1
    assert g.stats()["used_jti"] == 2
    with pytest.raises(oidc.CiOidcError) as exc:
        g.assume(token(jti="live"), now=1301)
    assert exc.value.code == "OIDC_REPLAY_DETECTED"
