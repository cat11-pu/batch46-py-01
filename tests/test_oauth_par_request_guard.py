import threading

import pytest

import oauth_par_request_guard as pg

NOW = 1000.0
WEB_CB = "https://app.example.com/cb"
WEB_CB2 = "https://app.example.com/cb2"
SPA_CB = "https://spa.example.com/cb"


def make(**kwargs):
    guard = pg.ParGuard(**kwargs)
    guard.register_client("web", redirect_uris=(WEB_CB, WEB_CB2), confidential=True)
    guard.register_client("spa", redirect_uris=(SPA_CB,), confidential=False)
    return guard


def request(**overrides):
    base = {
        "client_id": "web",
        "response_type": "code",
        "redirect_uri": WEB_CB,
        "scope": "openid profile",
        "state": "st-1",
    }
    base.update(overrides)
    return base


def test_push_returns_request_uri_and_peek_shows_metadata():
    guard = make()
    out = guard.push(request(), now=NOW)
    assert out["request_uri"].startswith("urn:ietf:params:oauth:request_uri:")
    assert len(out["request_uri"]) > len("urn:ietf:params:oauth:request_uri:")
    assert out["expires_in"] == pytest.approx(60.0)

    meta = guard.peek(out["request_uri"])
    assert meta["client_id"] == "web"
    assert meta["redirect_uri"] == WEB_CB
    assert meta["scopes"] == ["openid", "profile"]
    assert meta["state"] == "st-1"
    assert meta["expires_at"] == pytest.approx(1060.0)
    assert meta["used"] is False
    assert guard.stats()["pushed"] == 1


def test_unknown_and_revoked_clients_are_rejected():
    guard = make()
    with pytest.raises(pg.ParError) as exc:
        guard.push(request(client_id="ghost"), now=NOW)
    assert exc.value.code == "PAR_UNKNOWN_CLIENT"

    guard.register_client("web", redirect_uris=(WEB_CB, WEB_CB2), confidential=True)
    with pytest.raises(pg.ParError) as exc:
        guard.register_client("web", redirect_uris=("https://elsewhere.example.com/cb",),
                              confidential=True)
    assert exc.value.code == "PAR_CONFLICT"

    guard.revoke_client("spa")
    with pytest.raises(pg.ParError) as exc:
        guard.push(request(client_id="spa", redirect_uri=SPA_CB), now=NOW)
    assert exc.value.code == "PAR_CLIENT_REVOKED"
    with pytest.raises(pg.ParError) as exc:
        guard.revoke_client("ghost")
    assert exc.value.code == "PAR_UNKNOWN_CLIENT"


def test_duplicate_parameters_are_rejected():
    guard = make()
    with pytest.raises(pg.ParError) as exc:
        guard.push(request(duplicates=["scope", "state"]), now=NOW)
    assert exc.value.code == "PAR_DUPLICATE_PARAM"
    assert guard.stats()["pushed"] == 0


def test_only_authorization_code_response_type_is_supported():
    guard = make()
    for response_type in ("token", "id_token", "code token", ""):
        with pytest.raises(pg.ParError) as exc:
            guard.push(request(response_type=response_type), now=NOW)
        assert exc.value.code == "PAR_UNSUPPORTED_RESPONSE_TYPE"


def test_redirect_uri_must_match_a_registered_value_exactly():
    guard = make()
    out = guard.push(request(redirect_uri=WEB_CB2), now=NOW)
    assert out["request_uri"].startswith("urn:ietf:params:oauth:request_uri:")
    with pytest.raises(pg.ParError) as exc:
        guard.push(request(redirect_uri="https://app.example.com/cb/../cb2"), now=NOW)
    assert exc.value.code == "PAR_REDIRECT_MISMATCH"
    with pytest.raises(pg.ParError) as exc:
        guard.push(request(redirect_uri="https://app.example.com/CB"), now=NOW)
    assert exc.value.code == "PAR_REDIRECT_MISMATCH"


def test_public_clients_require_s256_pkce():
    guard = make()
    with pytest.raises(pg.ParError) as exc:
        guard.push(request(client_id="spa", redirect_uri=SPA_CB), now=NOW)
    assert exc.value.code == "PAR_PKCE_REQUIRED"

    with pytest.raises(pg.ParError) as exc:
        guard.push(request(client_id="spa", redirect_uri=SPA_CB,
                           code_challenge="abc", code_challenge_method="plain"), now=NOW)
    assert exc.value.code == "PAR_PKCE_METHOD_UNSUPPORTED"

    with pytest.raises(pg.ParError) as exc:
        guard.push(request(client_id="spa", redirect_uri=SPA_CB,
                           code_challenge="abc"), now=NOW)
    assert exc.value.code == "PAR_PKCE_METHOD_UNSUPPORTED"

    accepted = guard.push(request(client_id="spa", redirect_uri=SPA_CB,
                                  code_challenge="abc",
                                  code_challenge_method="S256"), now=NOW)
    assert accepted["request_uri"].startswith("urn:ietf:params:oauth:request_uri:")

    guard.register_client("forced", redirect_uris=("https://forced.example.com/cb",),
                          confidential=True, require_pkce=True)
    with pytest.raises(pg.ParError) as exc:
        guard.push(request(client_id="forced",
                           redirect_uri="https://forced.example.com/cb"), now=NOW)
    assert exc.value.code == "PAR_PKCE_REQUIRED"


def test_confidential_client_can_push_without_pkce_and_scope_is_normalised():
    guard = make()
    out = guard.push(request(scope="  profile   openid profile  "), now=NOW)
    meta = guard.peek(out["request_uri"])
    assert meta["scopes"] == ["openid", "profile"]
    assert meta["state"] == "st-1"


def test_scopes_outside_client_allowlist_are_rejected():
    guard = make()
    guard.register_client("limited", redirect_uris=("https://limited.example.com/cb",),
                          confidential=True, allowed_scopes=("openid", "profile"))
    with pytest.raises(pg.ParError) as exc:
        guard.push(request(client_id="limited",
                           redirect_uri="https://limited.example.com/cb",
                           scope="openid profile admin"), now=NOW)
    assert exc.value.code == "PAR_SCOPE_NOT_ALLOWED"
    ok = guard.push(request(client_id="limited",
                            redirect_uri="https://limited.example.com/cb",
                            scope="profile openid"), now=NOW)
    assert ok["request_uri"].startswith("urn:ietf:params:oauth:request_uri:")


def test_redeem_returns_normalised_request_and_is_single_use():
    guard = make()
    out = guard.push(request(scope="profile openid", state="xyz"), now=NOW)
    result = guard.redeem(out["request_uri"], client_id="web", now=NOW + 1.0)
    assert result == {
        "status": "redeemed",
        "client_id": "web",
        "redirect_uri": WEB_CB,
        "scopes": ["openid", "profile"],
        "state": "xyz",
        "code_challenge": None,
        "code_challenge_method": None,
    }
    assert guard.peek(out["request_uri"])["used"] is True
    with pytest.raises(pg.ParError) as exc:
        guard.redeem(out["request_uri"], client_id="web", now=NOW + 2.0)
    assert exc.value.code == "PAR_REQUEST_URI_USED"
    assert guard.stats() == {"pushed": 1, "redeemed": 1}


def test_expired_request_uri_is_rejected_and_purged():
    guard = make()
    out = guard.push(request(), now=NOW)
    uri = out["request_uri"]
    with pytest.raises(pg.ParError) as exc:
        guard.redeem(uri, client_id="web", now=NOW + 60.0)
    assert exc.value.code == "PAR_REQUEST_EXPIRED"

    assert guard.purge(now=NOW + 60.0) == 1
    with pytest.raises(pg.ParError) as exc:
        guard.redeem(uri, client_id="web", now=NOW + 61.0)
    assert exc.value.code == "PAR_UNKNOWN_REQUEST_URI"


def test_cross_client_redeem_does_not_consume_the_request():
    guard = make()
    guard.register_client("other", redirect_uris=("https://other.example.com/cb",))
    out = guard.push(request(), now=NOW)
    with pytest.raises(pg.ParError) as exc:
        guard.redeem(out["request_uri"], client_id="other", now=NOW + 1.0)
    assert exc.value.code == "PAR_CLIENT_MISMATCH"
    assert guard.quota("web")["pending"] == 1

    ok = guard.redeem(out["request_uri"], client_id="web", now=NOW + 2.0)
    assert ok["status"] == "redeemed"
    assert guard.quota("web")["pending"] == 0


def test_quota_limits_pending_requests_per_client_and_globally():
    guard = make(max_per_client=2, max_pending=10)
    first = guard.push(request(), now=NOW)["request_uri"]
    guard.push(request(), now=NOW)
    assert guard.quota("web") == {"pending": 2, "max_per_client": 2,
                                  "global_pending": 2, "max_pending": 10}
    with pytest.raises(pg.ParError) as exc:
        guard.push(request(), now=NOW)
    assert exc.value.code == "PAR_QUOTA_EXCEEDED"

    guard.redeem(first, client_id="web", now=NOW + 1.0)
    guard.push(request(), now=NOW + 2.0)

    global_guard = make(max_per_client=10, max_pending=2)
    global_guard.push(request(), now=NOW)
    global_guard.push(request(), now=NOW)
    with pytest.raises(pg.ParError) as exc:
        global_guard.push(request(), now=NOW)
    assert exc.value.code == "PAR_QUOTA_EXCEEDED"

    expiring = make(max_per_client=1)
    expiring.push(request(), now=NOW)
    out = expiring.push(request(), now=NOW + 61.0)
    assert out["request_uri"].startswith("urn:ietf:params:oauth:request_uri:")


def test_snapshot_restore_preserves_pending_and_used_markers():
    guard = make()
    used_uri = guard.push(request(state="used"), now=NOW)["request_uri"]
    guard.redeem(used_uri, client_id="web", now=NOW + 1.0)
    live_uri = guard.push(request(state="live"), now=NOW + 2.0)["request_uri"]
    state = guard.snapshot()

    clone = make()
    clone.restore(state)
    redeemed = clone.redeem(live_uri, client_id="web", now=NOW + 3.0)
    assert redeemed["state"] == "live"
    with pytest.raises(pg.ParError) as exc:
        clone.redeem(used_uri, client_id="web", now=NOW + 4.0)
    assert exc.value.code == "PAR_REQUEST_URI_USED"
    assert clone.stats() == {"pushed": 2, "redeemed": 2}


def test_corrupt_snapshot_is_rejected_without_touching_state():
    guard = make()
    uri = guard.push(request(), now=NOW)["request_uri"]
    bad_states = [
        None,
        {},
        {"version": 7, "clients": {}, "pending": {}, "used": {}, "stats": {}},
        {"version": 1, "clients": [], "pending": {}, "used": {}, "stats": {}},
        {"version": 1, "clients": {}, "pending": "nope", "used": {}, "stats": {}},
        {"version": 1, "clients": {}, "pending": {}, "used": {}, "stats": []},
    ]
    for bad in bad_states:
        with pytest.raises(pg.ParError) as exc:
            guard.restore(bad)
        assert exc.value.code == "PAR_SNAPSHOT_INVALID"
    result = guard.redeem(uri, client_id="web", now=NOW + 1.0)
    assert result["status"] == "redeemed"
    guard.reset_stats()
    assert guard.stats() == {"pushed": 0, "redeemed": 0}


def test_concurrent_redeem_succeeds_exactly_once():
    guard = make()
    uri = guard.push(request(), now=NOW)["request_uri"]
    barrier = threading.Barrier(8)
    outcomes = []
    lock = threading.Lock()

    def worker():
        barrier.wait()
        try:
            out = guard.redeem(uri, client_id="web", now=NOW + 1.0)
            item = ("ok", out["status"])
        except pg.ParError as exc:
            item = ("error", exc.code)
        with lock:
            outcomes.append(item)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert [item for item in outcomes if item[0] == "ok"] == [("ok", "redeemed")]
    codes = sorted(item[1] for item in outcomes if item[0] == "error")
    assert codes == ["PAR_REQUEST_URI_USED"] * 7
    assert guard.stats()["redeemed"] == 1
