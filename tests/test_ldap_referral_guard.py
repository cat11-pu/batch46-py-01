import threading
import time

import pytest

import ldap_referral_guard as lg

BASE = "ldap://dc1.example.com:389/dc=corp,dc=example"
R1 = "ldap://dc2.example.com:389/dc=region,dc=example"
R2 = "ldap://dc3.example.com:389/dc=branch,dc=example"
UNKNOWN = "ldap://dc7.example.com:389/dc=other,dc=example"


class Clock:
    def __init__(self, start=1000.0):
        self.value = start

    def __call__(self):
        return self.value


def make(**kwargs):
    clock = kwargs.pop("clock", None) or Clock()
    guard = lg.LdapReferralGuard(clock=clock, **kwargs)
    for host in ("dc1.example.com", "dc2.example.com", "dc3.example.com"):
        guard.allow_host(host)
    return guard


def fake_resolver(mapping, *, clock=None, step=0.0, fail=()):
    calls = []

    def resolver(url, dn, scope, filter_text, bind_dn):
        calls.append({"url": url, "dn": dn, "scope": scope,
                      "filter": filter_text, "bind_dn": bind_dn})
        if clock is not None:
            clock.value += step
        if url in fail:
            raise RuntimeError("referral failed")
        return mapping.get(url, {"entries": [], "referrals": []})

    resolver.calls = calls
    return resolver


def dns(result):
    return [entry["dn"] for entry in result["entries"]]


def test_basic_search_returns_entries_and_rejects_unknown_base_host():
    guard = make()
    resolver = fake_resolver({BASE: {"entries": [{"dn": "cn=alice", "cn": "alice"}],
                                     "referrals": []}})
    result = guard.search(BASE, dn="dc=corp,dc=example", resolver=resolver)
    assert result == {
        "status": "complete",
        "entries": [{"dn": "cn=alice", "url": BASE}],
        "visited": [BASE],
        "skipped": [],
        "continuation": None,
    }
    assert resolver.calls[0]["dn"] == "dc=corp,dc=example"
    assert resolver.calls[0]["scope"] == "sub"
    assert resolver.calls[0]["bind_dn"] is None

    with pytest.raises(lg.LdapError) as exc:
        guard.search("ldap://evil.example.com:389/dc=x", dn="dc=x",
                     resolver=resolver)
    assert exc.value.code == "LDAP_HOST_NOT_ALLOWED"


def test_allowed_referral_is_followed_and_entries_are_merged():
    guard = make()
    resolver = fake_resolver({
        BASE: {"entries": [{"dn": "cn=a"}], "referrals": [R1]},
        R1: {"entries": [{"dn": "cn=b"}], "referrals": []},
    })
    result = guard.search(BASE, dn="dc=corp,dc=example", resolver=resolver)
    assert result["status"] == "complete"
    assert result["entries"] == [
        {"dn": "cn=a", "url": BASE},
        {"dn": "cn=b", "url": R1},
    ]
    assert result["visited"] == [BASE, R1]
    assert result["skipped"] == []
    assert resolver.calls[1]["dn"] == "dc=region,dc=example"
    assert resolver.calls[1]["scope"] == "sub"


def test_referral_to_unlisted_host_is_skipped():
    guard = make()
    resolver = fake_resolver({
        BASE: {"entries": [{"dn": "cn=a"}], "referrals": [UNKNOWN]},
    })
    result = guard.search(BASE, dn="dc=corp,dc=example", resolver=resolver)
    assert result["status"] == "complete"
    assert dns(result) == ["cn=a"]
    assert result["visited"] == [BASE]
    assert result["skipped"] == [{"url": UNKNOWN, "code": "LDAP_REFERRAL_BLOCKED"}]
    assert len(resolver.calls) == 1


def test_referral_loops_are_detected_by_canonical_url():
    guard = make()
    resolver = fake_resolver({
        BASE: {"entries": [{"dn": "cn=root"}], "referrals": [R1, R1]},
        R1: {"entries": [{"dn": "cn=b"}], "referrals": [BASE]},
    })
    result = guard.search(BASE, dn="dc=corp,dc=example", resolver=resolver)
    assert result["status"] == "complete"
    assert dns(result) == ["cn=root", "cn=b"]
    assert result["visited"] == [BASE, R1]
    codes = [skip["code"] for skip in result["skipped"]]
    assert codes == ["LDAP_REFERRAL_LOOP", "LDAP_REFERRAL_LOOP"]
    assert len(resolver.calls) == 2


def test_url_canonicalisation_and_validation():
    guard = make()
    assert guard.validate_url("LDAP://DC1.EXAMPLE.COM/dc=corp") == (
        "ldap://dc1.example.com:389/dc=corp")
    resolver = fake_resolver({BASE: {"entries": [{"dn": "cn=a"}]}})
    result = guard.search("LDAP://DC1.EXAMPLE.COM:389/DC=CORP,DC=EXAMPLE",
                          dn="dc=corp,dc=example", resolver=resolver)
    assert result["visited"] == [BASE]

    for bad in ("http://dc1.example.com/dc=x",
                "ldap:///dc=x",
                "ldap://dc1.example.com:99999/dc=x",
                "ldap://dc1.example.com:abc/dc=x"):
        with pytest.raises(lg.LdapError) as exc:
            guard.validate_url(bad)
        assert exc.value.code == "LDAP_INVALID_URL"


def test_hop_limit_stops_deep_referral_chains():
    guard = make(max_hops=2)
    deep = "ldap://dc1.example.com:389/dc=deep,dc=example"
    resolver = fake_resolver({
        BASE: {"entries": [{"dn": "cn=0"}], "referrals": [R1]},
        R1: {"entries": [{"dn": "cn=1"}], "referrals": [R2]},
        R2: {"entries": [{"dn": "cn=2"}], "referrals": [deep]},
    })
    result = guard.search(BASE, dn="dc=corp,dc=example", resolver=resolver)
    assert result["status"] == "complete"
    assert dns(result) == ["cn=0", "cn=1", "cn=2"]
    assert result["skipped"] == [{"url": deep, "code": "LDAP_HOP_LIMIT"}]
    assert len(resolver.calls) == 3


def test_credentials_are_not_forwarded_to_hosts_that_forbid_auth():
    clock = Clock()
    guard = lg.LdapReferralGuard(clock=clock)
    guard.allow_host("dc1.example.com", allow_auth=False)
    resolver = fake_resolver({BASE: {"entries": [{"dn": "cn=a"}]}})
    with pytest.raises(lg.LdapError) as exc:
        guard.search(BASE, dn="dc=corp,dc=example", resolver=resolver,
                     bind_dn="cn=svc,dc=example")
    assert exc.value.code == "LDAP_AUTH_NOT_ALLOWED"
    anonymous = guard.search(BASE, dn="dc=corp,dc=example", resolver=resolver)
    assert anonymous["status"] == "complete"

    mixed = lg.LdapReferralGuard(clock=Clock())
    mixed.allow_host("dc1.example.com")
    mixed.allow_host("dc3.example.com", allow_auth=False)
    referral_resolver = fake_resolver({
        BASE: {"entries": [{"dn": "cn=a"}], "referrals": [R2]},
    })
    result = mixed.search(BASE, dn="dc=corp,dc=example",
                          resolver=referral_resolver,
                          bind_dn="cn=svc,dc=example")
    assert dns(result) == ["cn=a"]
    assert result["skipped"] == [{"url": R2, "code": "LDAP_AUTH_NOT_ALLOWED"}]
    assert [call["url"] for call in referral_resolver.calls] == [BASE]


def test_duplicate_entries_are_deduplicated_by_dn():
    guard = make()
    resolver = fake_resolver({
        BASE: {"entries": [{"dn": "cn=a"}, {"dn": "cn=b"}], "referrals": [R1]},
        R1: {"entries": [{"dn": "cn=a"}, {"dn": "cn=c"}], "referrals": []},
    })
    result = guard.search(BASE, dn="dc=corp,dc=example", resolver=resolver)
    assert dns(result) == ["cn=a", "cn=b", "cn=c"]
    assert result["entries"][0]["url"] == BASE
    assert result["entries"][2]["url"] == R1


def test_entry_budget_truncates_and_marks_partial():
    guard = make(max_entries=2)
    resolver = fake_resolver({
        BASE: {"entries": [{"dn": "cn=1"}, {"dn": "cn=2"}, {"dn": "cn=3"}],
               "referrals": [R1]},
    })
    result = guard.search(BASE, dn="dc=corp,dc=example", resolver=resolver)
    assert result["status"] == "partial"
    assert dns(result) == ["cn=1", "cn=2"]
    assert result["continuation"] is None
    assert result["visited"] == [BASE]
    assert result["skipped"] == [{"url": BASE, "code": "LDAP_ENTRY_BUDGET"}]
    assert guard.budget()["remaining_entries"] == 0


def test_deadline_returns_a_resumable_continuation():
    clock = Clock()
    guard = make(clock=clock, deadline_seconds=2.0)
    resolver = fake_resolver({
        BASE: {"entries": [{"dn": "cn=a"}], "referrals": [R1, R2]},
        R1: {"entries": [{"dn": "cn=b"}], "referrals": []},
        R2: {"entries": [{"dn": "cn=c"}], "referrals": []},
    }, clock=clock, step=1.5)

    first = guard.search(BASE, dn="dc=corp,dc=example", resolver=resolver)
    assert first["status"] == "partial"
    assert dns(first) == ["cn=a", "cn=b"]
    assert first["continuation"]["queue"][0]["url"] == R2
    assert guard.continuation() is not None

    second = guard.resume(first["continuation"], resolver=resolver)
    assert second["status"] == "complete"
    assert dns(second) == ["cn=a", "cn=b", "cn=c"]
    assert second["continuation"] is None
    assert guard.continuation() is None
    assert guard.visited() == [BASE, R1, R2]
    assert guard.stats()["resumes"] == 1


def test_visited_budget_and_stats_accounting():
    guard = make()
    resolver = fake_resolver({
        BASE: {"entries": [{"dn": "cn=a"}], "referrals": [R1]},
        R1: {"entries": [{"dn": "cn=b"}], "referrals": []},
    })
    guard.search(BASE, dn="dc=corp,dc=example", resolver=resolver)
    assert guard.budget() == {
        "max_hops": 3,
        "deadline_seconds": 5.0,
        "max_entries": 100,
        "last_entries": 2,
        "last_followed": 1,
        "remaining_entries": 98,
    }
    assert guard.visited() == [BASE, R1]
    assert guard.stats() == {
        "searches": 1,
        "resumes": 0,
        "completed": 1,
        "partials": 0,
        "followed": 1,
        "skipped": 0,
        "entries": 2,
    }
    guard.reset_stats()
    assert guard.stats() == {
        "searches": 0,
        "resumes": 0,
        "completed": 0,
        "partials": 0,
        "followed": 0,
        "skipped": 0,
        "entries": 0,
    }


def test_resolver_failure_on_one_branch_does_not_lose_the_other():
    guard = make()
    resolver = fake_resolver({
        BASE: {"entries": [{"dn": "cn=root"}], "referrals": [R1, R2]},
        R2: {"entries": [{"dn": "cn=c"}], "referrals": []},
    }, fail=(R1,))
    result = guard.search(BASE, dn="dc=corp,dc=example", resolver=resolver)
    assert result["status"] == "complete"
    assert dns(result) == ["cn=root", "cn=c"]
    assert result["skipped"] == [{"url": R1, "code": "LDAP_REFERRAL_FAILED"}]
    assert result["visited"] == [BASE, R1, R2]


def test_snapshot_restore_resumes_after_restart():
    clock = Clock()
    guard = make(clock=clock, deadline_seconds=2.0)
    resolver = fake_resolver({
        BASE: {"entries": [{"dn": "cn=a"}], "referrals": [R1, R2]},
        R1: {"entries": [{"dn": "cn=b"}], "referrals": []},
        R2: {"entries": [{"dn": "cn=c"}], "referrals": []},
    }, clock=clock, step=1.5)
    partial = guard.search(BASE, dn="dc=corp,dc=example", resolver=resolver)
    assert partial["status"] == "partial"
    state = guard.snapshot()

    clone = lg.LdapReferralGuard(clock=clock)
    clone.restore(state)
    resumed = clone.resume(clone.continuation(), resolver=resolver)
    assert resumed["status"] == "complete"
    assert dns(resumed) == ["cn=a", "cn=b", "cn=c"]
    assert clone.stats()["resumes"] == 1

    bad_states = [
        None,
        {},
        {"version": 9, "hosts": {}, "revoked": [], "stats": {},
         "continuation": None, "visited": []},
        {"version": 1, "hosts": [], "revoked": [], "stats": {},
         "continuation": None, "visited": []},
        {"version": 1, "hosts": {}, "revoked": [], "stats": {},
         "continuation": {"version": 2}, "visited": []},
    ]
    for bad in bad_states:
        with pytest.raises(lg.LdapError) as exc:
            clone.restore(bad)
        assert exc.value.code == "LDAP_SNAPSHOT_INVALID"
    assert clone.stats()["resumes"] == 1

    clock.value = 900.0
    probe = clone.search(BASE, dn="dc=corp,dc=example",
                         resolver=fake_resolver({BASE: {"entries": [{"dn": "cn=z"}]}}))
    assert probe["status"] == "complete"
    assert dns(probe) == ["cn=z"]


def test_concurrent_identical_searches_resolve_only_once():
    guard = make()
    calls = []

    def resolver(url, dn, scope, filter_text, bind_dn):
        calls.append(url)
        time.sleep(0.05)
        return {"entries": [{"dn": "cn=race"}], "referrals": []}

    barrier = threading.Barrier(8)
    results = []
    lock = threading.Lock()

    def worker():
        barrier.wait()
        out = guard.search(BASE, dn="dc=corp,dc=example", resolver=resolver)
        with lock:
            results.append(out)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert calls == [BASE]
    assert len(results) == 8
    assert all(row["status"] == "complete" for row in results)
    assert all(row["entries"] == [{"dn": "cn=race", "url": BASE}] for row in results)
    assert guard.stats()["searches"] == 1


def test_corrupt_continuations_are_rejected():
    guard = make()
    empty = {"version": 1, "queue": [], "entries": [], "visited": [],
             "seen_entries": [], "skipped": [], "followed": 0}
    result = guard.resume(empty, resolver=fake_resolver({}))
    assert result == {"status": "complete", "entries": [], "visited": [],
                      "skipped": [], "continuation": None}

    bad_values = [
        None,
        {},
        {"version": 2, "queue": [], "entries": [], "visited": [],
         "seen_entries": [], "skipped": [], "followed": 0},
        {"version": 1, "queue": "nope", "entries": [], "visited": [],
         "seen_entries": [], "skipped": [], "followed": 0},
        {"version": 1, "queue": [], "entries": []},
    ]
    for bad in bad_values:
        with pytest.raises(lg.LdapError) as exc:
            guard.resume(bad, resolver=fake_resolver({}))
        assert exc.value.code == "LDAP_CONTINUATION_INVALID"
