import threading

import pytest

import saml_assertion_replay_guard as sg

NOW = "2026-11-23T10:00:00+00:00"


def assertion(**overrides):
    base = {
        "id": "assert-1",
        "issuer": "https://idp.example.com",
        "audience": "https://sp.example.com/saml",
        "recipient": "https://sp.example.com/saml/acs",
        "not_before": "2026-11-23T09:55:00+00:00",
        "not_on_or_after": "2026-11-23T10:05:00+00:00",
        "fingerprint": "SHA256:good",
    }
    base.update(overrides)
    return base


def make(**kwargs):
    guard = sg.SamlReplayGuard(**kwargs)
    guard.register_service_provider(
        "sp-main",
        entity_id="https://sp.example.com/saml",
        audiences=("https://sp.example.com/saml",),
        acs_url="https://sp.example.com/saml/acs",
    )
    guard.trust_issuer("https://idp.example.com", fingerprints=("SHA256:good",))
    return guard


def test_replayed_assertion_is_suppressed_and_counted_once():
    guard = make()
    first = guard.consume(assertion(), sp_id="sp-main", now=NOW)
    assert first["status"] == "accepted"
    assert first["assertion_id"] == "assert-1"
    assert first["issuer"] == "https://idp.example.com"
    assert guard.is_seen("assert-1") is True

    second = guard.consume(assertion(), sp_id="sp-main", now=NOW)
    assert second["status"] == "replayed"
    assert second["code"] == "SAML_REPLAY"
    assert second["sp_id"] == "sp-main"
    assert guard.stats() == {"accepted": 1, "replayed": 1, "rejected": 0}


def test_unknown_service_provider_and_conflicting_registration():
    guard = sg.SamlReplayGuard()
    guard.trust_issuer("https://idp.example.com", fingerprints=("SHA256:good",))
    with pytest.raises(sg.SamlError) as exc:
        guard.consume(assertion(), sp_id="sp-missing", now=NOW)
    assert exc.value.code == "SAML_UNKNOWN_SP"

    guard.register_service_provider(
        "sp-main",
        entity_id="https://sp.example.com/saml",
        audiences=("https://sp.example.com/saml",),
        acs_url="https://sp.example.com/saml/acs",
    )
    again = guard.register_service_provider(
        "sp-main",
        entity_id="https://sp.example.com/saml",
        audiences=("https://sp.example.com/saml",),
        acs_url="https://sp.example.com/saml/acs",
    )
    assert again["acs_url"] == "https://sp.example.com/saml/acs"
    with pytest.raises(sg.SamlError) as exc:
        guard.register_service_provider(
            "sp-main",
            entity_id="https://sp.example.com/saml",
            audiences=("https://sp.example.com/saml",),
            acs_url="https://sp.example.com/other/acs",
        )
    assert exc.value.code == "SAML_CONFLICT"


def test_audience_mismatch_is_refused():
    guard = make()
    with pytest.raises(sg.SamlError) as exc:
        guard.consume(assertion(audience="https://other.example.com/saml"),
                      sp_id="sp-main", now=NOW)
    assert exc.value.code == "SAML_AUDIENCE_MISMATCH"
    assert guard.is_seen("assert-1") is False
    assert guard.stats()["accepted"] == 0


def test_recipient_must_equal_registered_acs_url():
    guard = make()
    with pytest.raises(sg.SamlError) as exc:
        guard.consume(assertion(recipient="https://sp.example.com/alt/acs"),
                      sp_id="sp-main", now=NOW)
    assert exc.value.code == "SAML_RECIPIENT_MISMATCH"
    ok = guard.consume(assertion(id="assert-recipient",
                                 recipient="https://sp.example.com/saml/acs"),
                       sp_id="sp-main", now=NOW)
    assert ok["status"] == "accepted"


def test_signature_fingerprint_must_be_trusted():
    guard = make()
    with pytest.raises(sg.SamlError) as exc:
        guard.consume(assertion(fingerprint="SHA256:revoked-cert"),
                      sp_id="sp-main", now=NOW)
    assert exc.value.code == "SAML_SIGNATURE_UNTRUSTED"


def test_untrusted_and_revoked_issuers_are_distinguished():
    guard = make()
    with pytest.raises(sg.SamlError) as exc:
        guard.consume(assertion(issuer="https://evil.example.com"),
                      sp_id="sp-main", now=NOW)
    assert exc.value.code == "SAML_UNTRUSTED_ISSUER"

    guard.revoke_issuer("https://idp.example.com")
    with pytest.raises(sg.SamlError) as exc:
        guard.consume(assertion(id="assert-revoked"), sp_id="sp-main", now=NOW)
    assert exc.value.code == "SAML_ISSUER_REVOKED"
    assert guard.is_seen("assert-revoked") is False

    with pytest.raises(sg.SamlError) as exc:
        guard.revoke_issuer("https://never-trusted.example.com")
    assert exc.value.code == "SAML_UNKNOWN_ISSUER"


def test_in_response_to_binding_is_enforced_for_solicited_flows():
    guard = make()
    with pytest.raises(sg.SamlError) as exc:
        guard.consume(assertion(in_response_to="req-old"), sp_id="sp-main",
                      now=NOW, request_id="req-current")
    assert exc.value.code == "SAML_INRESPONSETO_MISMATCH"
    assert guard.is_seen("assert-1") is False

    with pytest.raises(sg.SamlError) as exc:
        guard.consume(assertion(id="assert-no-binding"), sp_id="sp-main",
                      now=NOW, request_id="req-current")
    assert exc.value.code == "SAML_INRESPONSETO_MISMATCH"

    ok = guard.consume(assertion(id="assert-bound", in_response_to="req-current"),
                       sp_id="sp-main", now=NOW, request_id="req-current")
    assert ok["status"] == "accepted"


def test_clock_skew_absorbs_not_before_but_not_large_skew():
    guard = make(clock_skew=120)
    inside = guard.consume(
        assertion(id="assert-nbf-ok", not_before="2026-11-23T10:01:00+00:00"),
        sp_id="sp-main", now=NOW)
    assert inside["status"] == "accepted"

    with pytest.raises(sg.SamlError) as exc:
        guard.consume(
            assertion(id="assert-nbf-bad", not_before="2026-11-23T10:03:00+00:00"),
            sp_id="sp-main", now=NOW)
    assert exc.value.code == "SAML_NOT_YET_VALID"


def test_expiry_boundary_includes_clock_skew():
    guard = make(clock_skew=60)
    with pytest.raises(sg.SamlError) as exc:
        guard.consume(
            assertion(id="assert-expired",
                      not_on_or_after="2026-11-23T09:59:00+00:00"),
            sp_id="sp-main", now=NOW)
    assert exc.value.code == "SAML_EXPIRED"

    ok = guard.consume(
        assertion(id="assert-last-second",
                  not_on_or_after="2026-11-23T09:59:01+00:00"),
        sp_id="sp-main", now=NOW)
    assert ok["status"] == "accepted"


def test_replay_cache_capacity_rejects_new_assertions_until_purged():
    guard = make(max_seen=2)
    assert guard.consume(assertion(id="cap-1"), sp_id="sp-main", now=NOW)["status"] == "accepted"
    assert guard.consume(assertion(id="cap-2"), sp_id="sp-main", now=NOW)["status"] == "accepted"

    with pytest.raises(sg.SamlError) as exc:
        guard.consume(assertion(id="cap-3"), sp_id="sp-main", now=NOW)
    assert exc.value.code == "SAML_CACHE_FULL"
    assert guard.is_seen("cap-3") is False

    assert guard.purge(now="2026-11-23T10:06:59+00:00") == 0
    assert guard.purge(now="2026-11-23T10:08:00+00:00") == 2
    late = guard.consume(
        assertion(id="cap-3", not_before="2026-11-23T10:09:00+00:00",
                  not_on_or_after="2026-11-23T10:20:00+00:00"),
        sp_id="sp-main", now="2026-11-23T10:10:00+00:00")
    assert late["status"] == "accepted"


def test_batch_reports_each_item_and_rejects_oversized_batches():
    guard = make(batch_limit=3)
    results = guard.consume_batch(
        [
            assertion(id="batch-1"),
            assertion(id="batch-bad", audience="https://wrong.example.com/saml"),
            assertion(id="batch-1"),
        ],
        sp_id="sp-main", now=NOW)
    assert [row["status"] for row in results] == ["accepted", "rejected", "replayed"]
    assert results[1]["code"] == "SAML_AUDIENCE_MISMATCH"
    assert results[2]["code"] == "SAML_REPLAY"
    assert guard.stats() == {"accepted": 1, "replayed": 1, "rejected": 1}

    with pytest.raises(sg.SamlError) as exc:
        guard.consume_batch([assertion(id=f"too-many-{i}") for i in range(4)],
                            sp_id="sp-main", now=NOW)
    assert exc.value.code == "SAML_BATCH_TOO_LARGE"


def test_snapshot_restore_carries_replay_state_and_registrations():
    guard = make()
    assert guard.consume(assertion(id="snap-1"), sp_id="sp-main", now=NOW)["status"] == "accepted"
    state = guard.snapshot()
    assert guard.consume(assertion(id="snap-after"), sp_id="sp-main", now=NOW)["status"] == "accepted"

    restored = sg.SamlReplayGuard()
    restored.restore(state)
    assert restored.is_seen("snap-1") is True
    assert restored.is_seen("snap-after") is False
    replay = restored.consume(assertion(id="snap-1"), sp_id="sp-main", now=NOW)
    assert replay["status"] == "replayed"
    fresh = restored.consume(assertion(id="snap-2"), sp_id="sp-main", now=NOW)
    assert fresh["status"] == "accepted"
    assert restored.stats() == {"accepted": 2, "replayed": 1, "rejected": 0}


def test_corrupt_snapshot_is_rejected_without_touching_state():
    guard = make()
    guard.consume(assertion(id="keep-1"), sp_id="sp-main", now=NOW)
    bad_states = [
        None,
        {},
        {"version": 2, "seen": {}, "sps": {}, "issuers": {}, "revoked": [], "stats": {}},
        {"version": 1, "seen": "not-a-map", "sps": {}, "issuers": {}, "revoked": [], "stats": {}},
        {"version": 1, "seen": {}, "sps": {}, "issuers": {}, "revoked": [], "stats": "nope"},
    ]
    for bad in bad_states:
        with pytest.raises(sg.SamlError) as exc:
            guard.restore(bad)
        assert exc.value.code == "SAML_SNAPSHOT_INVALID"
    assert guard.is_seen("keep-1") is True
    assert guard.consume(assertion(id="keep-1"), sp_id="sp-main", now=NOW)["status"] == "replayed"


def test_concurrent_consume_accepts_exactly_once():
    guard = make()
    barrier = threading.Barrier(8)
    results = []
    lock = threading.Lock()

    def worker():
        barrier.wait()
        try:
            out = guard.consume(assertion(id="race-1"), sp_id="sp-main", now=NOW)
        except Exception as exc:  # pragma: no cover - surfaced via assertion below
            out = {"status": "error", "code": repr(exc)}
        with lock:
            results.append(out)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    statuses = sorted(row["status"] for row in results)
    assert statuses == ["accepted"] + ["replayed"] * 7
    assert guard.stats() == {"accepted": 1, "replayed": 7, "rejected": 0}


def test_purge_and_stats_accounting():
    guard = make()
    guard.consume(assertion(id="stat-1"), sp_id="sp-main", now=NOW)
    guard.consume(assertion(id="stat-1"), sp_id="sp-main", now=NOW)
    with pytest.raises(sg.SamlError):
        guard.consume(assertion(id="stat-bad", fingerprint="SHA256:unknown"),
                      sp_id="sp-main", now=NOW)
    assert guard.stats() == {"accepted": 1, "replayed": 1, "rejected": 1}
    assert guard.purge(now=NOW) == 0
    assert guard.purge(now="2026-11-23T10:08:00+00:00") == 1
    assert guard.is_seen("stat-1") is False
    guard.reset_stats()
    assert guard.stats() == {"accepted": 0, "replayed": 0, "rejected": 0}
