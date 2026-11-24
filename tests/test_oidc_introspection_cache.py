import threading
import time

import pytest

import oidc_introspection_cache as oic

NOW = 1000.0


def counting_factory(result=None):
    calls = []

    def introspect(token):
        calls.append(token)
        if callable(result):
            return result(token)
        return {"active": True, "scope": "read write", "exp": 100000.0}

    introspect.calls = calls
    return introspect


def make(introspect, **kwargs):
    return oic.IntrospectionCache(introspect, **kwargs)


def test_cache_hit_avoids_second_upstream_call():
    introspect = counting_factory()
    cache = make(introspect)
    first = cache.check("tok-1", now=NOW)
    assert first["active"] is True
    assert first["cached"] is False
    assert first["scopes"] == ["read", "write"]
    assert first["ttl"] == pytest.approx(60.0)

    second = cache.check("tok-1", now=NOW + 10.0)
    assert second["active"] is True
    assert second["cached"] is True
    assert second["ttl"] == pytest.approx(50.0)
    assert introspect.calls == ["tok-1"]
    assert cache.stats() == {"upstream_calls": 1, "cache_hits": 1,
                             "cache_misses": 1, "evictions": 0, "revocations": 0}


def test_max_ttl_caps_long_lived_tokens_and_refreshes_at_expiry():
    introspect = counting_factory()
    cache = make(introspect, max_ttl=60.0)
    assert cache.check("long", now=NOW)["ttl"] == pytest.approx(60.0)
    near = cache.check("long", now=NOW + 59.0)
    assert near["cached"] is True
    assert near["ttl"] == pytest.approx(1.0)
    assert introspect.calls == ["long"]

    refreshed = cache.check("long", now=NOW + 60.0)
    assert refreshed["cached"] is False
    assert refreshed["ttl"] == pytest.approx(60.0)
    assert introspect.calls == ["long", "long"]


def test_shorter_exp_wins_over_max_ttl():
    introspect = counting_factory(lambda token: {"active": True, "scope": "read", "exp": 1025.0})
    cache = make(introspect, max_ttl=60.0)
    first = cache.check("short", now=NOW)
    assert first["ttl"] == pytest.approx(25.0)
    hit = cache.check("short", now=NOW + 20.0)
    assert hit["cached"] is True
    assert hit["ttl"] == pytest.approx(5.0)
    assert introspect.calls == ["short"]

    refreshed = cache.check("short", now=NOW + 25.0)
    assert refreshed["cached"] is False
    assert introspect.calls == ["short", "short"]


def test_negative_results_are_cached_for_negative_ttl():
    introspect = counting_factory(lambda token: {"active": False})
    cache = make(introspect, negative_ttl=5.0)
    first = cache.check("bad", now=NOW)
    assert first["active"] is False
    assert first["cached"] is False
    assert first["code"] == "OIDC_INACTIVE"
    assert first["ttl"] == pytest.approx(5.0)

    hit = cache.check("bad", now=NOW + 4.9)
    assert hit["active"] is False
    assert hit["cached"] is True
    assert hit["ttl"] == pytest.approx(0.1)
    assert introspect.calls == ["bad"]

    expired = cache.check("bad", now=NOW + 5.0)
    assert expired["cached"] is False
    assert introspect.calls == ["bad", "bad"]

    capped = make(counting_factory(lambda token: {"active": False}),
                  negative_ttl=90.0, max_ttl=60.0)
    assert capped.check("bad", now=NOW)["ttl"] == pytest.approx(60.0)


def test_revoked_token_is_denied_without_calling_upstream():
    introspect = counting_factory()
    cache = make(introspect)
    cache.check("tok", now=NOW)
    assert cache.revoke("tok", now=NOW) is True
    assert cache.is_revoked("tok", now=NOW) is True
    assert cache.revoke("tok", now=NOW) is False

    denied = cache.check("tok", now=NOW + 1.0)
    assert denied["active"] is False
    assert denied["cached"] is True
    assert denied["code"] == "OIDC_REVOKED"
    assert introspect.calls == ["tok"]
    assert cache.stats()["revocations"] == 1


def test_revocation_expiry_and_purge():
    introspect = counting_factory()
    cache = make(introspect)
    assert cache.revoke("tok", expires_at=1010.0, now=NOW) is True
    assert cache.is_revoked("tok", now=1009.0) is True
    assert cache.is_revoked("tok", now=1010.0) is False

    assert cache.check("tok", now=1009.0)["code"] == "OIDC_REVOKED"
    assert introspect.calls == []
    assert cache.purge(now=1010.0) == 1
    recovered = cache.check("tok", now=1010.0)
    assert recovered["active"] is True
    assert introspect.calls == ["tok"]


def test_required_scopes_are_checked_against_granted_scope():
    introspect = counting_factory()
    cache = make(introspect)
    allowed = cache.check("tok", scopes=["read"], now=NOW)
    assert allowed["active"] is True
    assert allowed["cached"] is False
    assert allowed["scopes"] == ["read", "write"]

    denied = cache.check("tok", scopes=["admin", "write"], now=NOW)
    assert denied["active"] is False
    assert denied["cached"] is True
    assert denied["code"] == "OIDC_SCOPE_MISSING"
    assert denied["missing"] == ["admin"]

    plain = cache.check("tok", now=NOW)
    assert plain["active"] is True
    assert introspect.calls == ["tok"]

    cold = cache.check("tok-2", scopes=["admin"], now=NOW)
    assert cold["active"] is False
    assert cold["cached"] is False
    assert cold["code"] == "OIDC_SCOPE_MISSING"
    assert cold["missing"] == ["admin"]
    assert cache.check("tok-2", now=NOW)["active"] is True
    assert introspect.calls == ["tok", "tok-2"]


def test_lru_eviction_respects_max_entries():
    introspect = counting_factory()
    cache = make(introspect, max_entries=2)
    cache.check("t1", now=NOW)
    cache.check("t2", now=NOW)
    cache.check("t1", now=NOW)
    cache.check("t3", now=NOW)
    assert cache.usage() == {"entries": 2, "max_entries": 2, "revocations": 0}
    assert cache.stats()["evictions"] == 1

    again = cache.check("t2", now=NOW)
    assert again["cached"] is False
    assert introspect.calls == ["t1", "t2", "t3", "t2"]
    assert cache.stats()["evictions"] == 2


def test_concurrent_cold_checks_use_a_single_upstream_call():
    calls = []

    def introspect(token):
        calls.append(token)
        time.sleep(0.05)
        return {"active": True, "scope": "read", "exp": 100000.0}

    cache = make(introspect)
    barrier = threading.Barrier(8)
    results = []
    guard = threading.Lock()

    def worker():
        barrier.wait()
        out = cache.check("shared", now=NOW)
        with guard:
            results.append(out)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert calls == ["shared"]
    assert len(results) == 8
    assert all(item["active"] is True for item in results)
    stats = cache.stats()
    assert stats["upstream_calls"] == 1
    assert stats["cache_hits"] == 7
    assert stats["cache_misses"] == 1


def test_prefetch_deduplicates_and_reports_counts():
    introspect = counting_factory()
    cache = make(introspect)
    cache.check("a", now=NOW)
    summary = cache.prefetch(["a", "a", "b"], now=NOW)
    assert summary == {"requested": 2, "cached": 1, "fetched": 1}
    assert introspect.calls == ["a", "b"]
    assert cache.usage()["entries"] == 2


def test_invalidate_forces_a_fresh_upstream_call():
    introspect = counting_factory()
    cache = make(introspect)
    cache.check("tok", now=NOW)
    assert cache.invalidate("tok") is True
    assert cache.invalidate("tok") is False
    assert cache.check("tok", now=NOW)["cached"] is False
    assert introspect.calls == ["tok", "tok"]


def test_snapshot_restore_preserves_cache_and_revocations():
    introspect = counting_factory()
    cache = make(introspect)
    cache.check("a", now=NOW)
    cache.revoke("b", now=NOW)
    state = cache.snapshot()

    clone_introspect = counting_factory()
    clone = make(clone_introspect)
    clone.restore(state)
    restored = clone.check("a", now=NOW + 1.0)
    assert restored["active"] is True
    assert restored["cached"] is True
    denied = clone.check("b", now=NOW + 1.0)
    assert denied["active"] is False
    assert denied["code"] == "OIDC_REVOKED"
    assert clone_introspect.calls == []
    assert clone.stats()["upstream_calls"] == 1


def test_corrupt_snapshot_is_rejected_without_touching_state():
    introspect = counting_factory()
    cache = make(introspect)
    cache.check("keep", now=NOW)
    bad_states = [
        None,
        {},
        {"version": 9, "entries": {}, "revoked": {}, "stats": {}},
        {"version": 1, "entries": [], "revoked": {}, "stats": {}},
        {"version": 1, "entries": {}, "revoked": [], "stats": {}},
    ]
    for bad in bad_states:
        with pytest.raises(oic.IntrospectionError) as exc:
            cache.restore(bad)
        assert exc.value.code == "OIDC_SNAPSHOT_INVALID"
    still_cached = cache.check("keep", now=NOW)
    assert still_cached["cached"] is True
    assert introspect.calls == ["keep"]


def test_upstream_contract_violations_are_reported():
    cache = make(lambda token: {"active": "yes"})
    with pytest.raises(oic.IntrospectionError) as exc:
        cache.check("tok", now=NOW)
    assert exc.value.code == "OIDC_UPSTREAM_INVALID"

    cache = make(lambda token: "not-a-dict")
    with pytest.raises(oic.IntrospectionError) as exc:
        cache.check("tok", now=NOW)
    assert exc.value.code == "OIDC_UPSTREAM_INVALID"


def test_purge_and_stats_accounting():
    introspect = counting_factory(
        lambda token: {"active": False} if token == "bad"
        else {"active": True, "exp": 1030.0})
    cache = make(introspect, negative_ttl=5.0)
    cache.check("good", now=NOW)
    cache.check("bad", now=NOW)
    cache.check("good", now=NOW)
    cache.revoke("gone", expires_at=1005.0, now=NOW)
    assert cache.stats() == {"upstream_calls": 2, "cache_hits": 1,
                             "cache_misses": 2, "evictions": 0, "revocations": 1}
    assert cache.purge(now=1030.0) == 3
    assert cache.usage()["entries"] == 0
    cache.reset_stats()
    assert cache.stats() == {"upstream_calls": 0, "cache_hits": 0,
                             "cache_misses": 0, "evictions": 0, "revocations": 0}
