import threading

import pytest

import dns_cache_poison_guard as dns


class Clock:
    def __init__(self, value=0.0):
        self.value = value

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += seconds


def make(clock=None, **kwargs):
    guard = dns.DnsCacheGuard(clock=clock or Clock(), **kwargs)
    guard.define_zone("example.com")
    return guard


def rr(name, ttl=60, rtype="A", data="192.0.2.1"):
    return {"name": name, "type": rtype, "ttl": ttl, "data": data}


def answer(guard, ticket, *, qname=None, answers=(), authority=(), additional=()):
    return {
        "query_id": ticket["query_id"],
        "qname": ticket["case_token"] if qname is None else qname,
        "answers": list(answers),
        "authority": list(authority),
        "additional": list(additional),
    }


def query(guard, name="www.example.com", qtype="A"):
    return guard.register_query(name, qtype, zone="example.com")


def store(guard, name, ttl, data="192.0.2.1", qtype="A"):
    ticket = query(guard, name, qtype)
    out = guard.validate_response(
        answer(guard, ticket, answers=[rr(name, ttl, qtype, data)])
    )
    assert out["status"] == "accepted"
    return out


def test_register_query_normalizes_name_and_returns_mixed_case_token():
    guard = make()
    ticket = query(guard, "WWW.Example.COM", "a")
    assert ticket["qname"] == "www.example.com"
    assert ticket["qtype"] == "A"
    assert ticket["zone"] == "example.com"
    assert ticket["query_id"] == "q-1"
    assert ticket["case_token"].lower() == "www.example.com"
    assert ticket["case_token"] != "www.example.com"
    assert guard.pending_count() == 1


def test_case_mismatch_rejects_response_and_caches_nothing():
    guard = make()
    ticket = query(guard)
    out = guard.validate_response(
        answer(guard, ticket, qname="www.example.com",
               answers=[rr("www.example.com")])
    )
    assert out["status"] == "rejected"
    assert out["code"] == "DNS_CASE_MISMATCH"
    assert guard.lookup("www.example.com", "A")["hit"] is False
    assert guard.stats()["rejected"] == 1


def test_out_of_bailiwick_answer_and_cname_escape_are_rejected():
    guard = make()
    ticket = query(guard)
    out = guard.validate_response(
        answer(guard, ticket, answers=[rr("www.evil.net", data="203.0.113.9")])
    )
    assert out["status"] == "rejected"
    assert out["code"] == "DNS_OUT_OF_BAILIWICK"
    assert guard.lookup("www.evil.net", "A")["hit"] is False

    other = make()
    ticket = query(other, "alias.example.com", "CNAME")
    out = other.validate_response(
        answer(other, ticket,
               answers=[rr("alias.example.com", 60, "CNAME", "target.evil.net")])
    )
    assert out["code"] == "DNS_CNAME_ESCAPE"
    assert other.lookup("alias.example.com", "CNAME")["hit"] is False


def test_authority_record_outside_zone_rejects_whole_response():
    guard = make()
    ticket = query(guard)
    out = guard.validate_response(
        answer(guard, ticket,
               answers=[rr("www.example.com", data="192.0.2.7")],
               authority=[rr("ns.evil.net", 300, "NS", "ns.evil.net")])
    )
    assert out["status"] == "rejected"
    assert out["code"] == "DNS_AUTHORITY_ESCAPE"
    assert guard.lookup("www.example.com", "A")["hit"] is False
    assert guard.stats()["cache_entries"] == 0


def test_out_of_zone_glue_is_dropped_but_answer_is_accepted():
    guard = make()
    ticket = query(guard)
    out = guard.validate_response(
        answer(guard, ticket,
               answers=[rr("www.example.com", 60, data="192.0.2.10")],
               additional=[rr("ns1.example.com", 60, data="192.0.2.53"),
                           rr("ns1.evil.net", 60, data="198.51.100.9")])
    )
    assert out["status"] == "accepted"
    assert out["dropped_glue"] == 1
    assert len(out["additional"]) == 1
    assert guard.stats()["dropped_glue"] == 1
    hit = guard.lookup("www.example.com", "A")
    assert hit["hit"] is True
    assert hit["ttl"] == 60
    assert [rec["data"] for rec in hit["records"]] == ["192.0.2.10"]


def test_duplicate_answers_are_deduped_and_rrset_uses_min_ttl():
    guard = make()
    ticket = query(guard)
    out = guard.validate_response(
        answer(guard, ticket,
               answers=[rr("www.example.com", 120, data="192.0.2.1"),
                        rr("WWW.example.com", 60, data="192.0.2.1"),
                        rr("www.example.com", 300, data="192.0.2.2")])
    )
    assert out["status"] == "accepted"
    assert len(out["answers"]) == 2
    hit = guard.lookup("www.example.com", "A")
    assert hit["ttl"] == 60
    assert len(hit["records"]) == 2
    assert hit["records"][0]["name"] == "www.example.com"


def test_ttl_is_clamped_and_zero_ttl_is_not_cached():
    guard = make(max_ttl=300)
    store(guard, "www.example.com", 900)
    assert guard.lookup("www.example.com", "A")["ttl"] == 300
    out = store(guard, "zero.example.com", 0)
    assert out["cached"] == 0
    assert guard.lookup("zero.example.com", "A")["hit"] is False
    assert guard.stats()["cache_entries"] == 1


def test_query_ticket_is_single_use_and_replay_is_rejected():
    guard = make()
    ticket = query(guard)
    payload = answer(guard, ticket, answers=[rr("www.example.com")])
    first = guard.validate_response(payload)
    second = guard.validate_response(payload)
    assert first["status"] == "accepted"
    assert second["status"] == "rejected"
    assert second["code"] == "DNS_REPLAY"
    assert guard.stats()["replays"] == 1
    assert guard.lookup("www.example.com", "A")["hit"] is True


def test_expired_entry_misses_and_is_removed():
    clock = Clock()
    guard = make(clock=clock)
    store(guard, "www.example.com", 10)
    assert guard.lookup("www.example.com", "A")["ttl"] == 10
    clock.advance(10)
    hit = guard.lookup("www.example.com", "A")
    assert hit["hit"] is False
    assert hit["records"] == []
    assert guard.stats()["cache_entries"] == 0


def test_capacity_evicts_entry_with_earliest_expiry():
    guard = make(max_entries=2)
    store(guard, "a.example.com", 100)
    store(guard, "b.example.com", 5)
    store(guard, "c.example.com", 50)
    assert guard.stats()["cache_entries"] == 2
    assert guard.stats()["evicted"] == 1
    assert guard.lookup("a.example.com", "A")["hit"] is True
    assert guard.lookup("c.example.com", "A")["hit"] is True
    assert guard.lookup("b.example.com", "A")["hit"] is False


def test_flush_zone_removes_only_descendants_of_that_zone():
    guard = make()
    guard.define_zone("other.net")
    for name in ("www.example.com", "deep.example.com"):
        store(guard, name, 60)
    ticket = guard.register_query("api.other.net", "A", zone="other.net")
    guard.validate_response(
        answer(guard, ticket, answers=[rr("api.other.net", 60)])
    )
    removed = guard.flush_zone("example.com")
    assert removed == 2
    assert guard.lookup("www.example.com", "A")["hit"] is False
    assert guard.lookup("deep.example.com", "A")["hit"] is False
    assert guard.lookup("api.other.net", "A")["hit"] is True
    assert guard.stats()["cache_entries"] == 1


def test_pending_cap_evicts_oldest_ticket():
    guard = make(max_pending=2)
    first = query(guard, "one.example.com")
    second = query(guard, "two.example.com")
    third = query(guard, "three.example.com")
    assert guard.pending_count() == 2
    stale = guard.validate_response(
        answer(guard, first, answers=[rr("one.example.com")])
    )
    assert stale["status"] == "rejected"
    assert stale["code"] == "DNS_UNKNOWN_QUERY"
    fresh = guard.validate_response(
        answer(guard, third, answers=[rr("three.example.com")])
    )
    assert fresh["status"] == "accepted"
    assert guard.stats()["pending_evicted"] == 1
    assert second["query_id"] != third["query_id"]


def test_snapshot_restore_preserves_absolute_expiry():
    clock = Clock()
    guard = make(clock=clock)
    store(guard, "www.example.com", 100)
    snap = guard.snapshot()
    assert snap["version"] == dns.DnsCacheGuard.SNAPSHOT_VERSION
    assert snap["entries"]

    later = Clock(30.0)
    restored = dns.DnsCacheGuard(clock=later)
    restored.restore(snap)
    hit = restored.lookup("www.example.com", "A")
    assert hit["hit"] is True
    assert hit["ttl"] == 70
    assert restored.stats()["cache_entries"] == 1
    assert restored.pending_count() == 0


def test_restore_rejects_bad_version_without_touching_cache():
    guard = make()
    store(guard, "www.example.com", 60)
    snap = guard.snapshot()
    bad = dict(snap)
    bad["version"] = snap["version"] - 1
    with pytest.raises(dns.DnsGuardError) as exc:
        guard.restore(bad)
    assert exc.value.code == "DNS_SNAPSHOT_VERSION"
    assert guard.lookup("www.example.com", "A")["hit"] is True
    assert guard.stats()["cache_entries"] == 1


def test_concurrent_validate_accepts_exactly_once():
    guard = make()
    ticket = query(guard)
    payload = answer(guard, ticket, answers=[rr("www.example.com")])
    results = []
    lock = threading.Lock()

    def worker():
        out = guard.validate_response(payload)
        with lock:
            results.append(out)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    accepted = [row for row in results if row["status"] == "accepted"]
    rejected = [row for row in results if row["status"] == "rejected"]
    assert len(accepted) == 1
    assert len(rejected) == 7
    assert {row["code"] for row in rejected} == {"DNS_REPLAY"}
    assert guard.stats()["replays"] == 7
    assert len(guard.lookup("www.example.com", "A")["records"]) == 1
