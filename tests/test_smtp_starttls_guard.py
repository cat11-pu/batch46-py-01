import threading

import pytest

import smtp_starttls_guard as smtp


def make(**kwargs):
    return smtp.StarttlsGuard(**kwargs)


def begin(g, sid, domain, now=0, ip="10.0.0.1"):
    return g.begin_session(sid, peer_ip=ip, ehlo_domain=domain, now=now)


def test_require_policy_rejects_ehlo_without_starttls():
    g = make()
    begin(g, "s1", "mx.example.com", now=100)
    out = g.observe_ehlo("s1", ["SIZE 1000", "8BITMIME"], now=101)
    assert out["decision"] == "reject"
    assert out["code"] == "SMTP_STARTTLS_MISSING"
    assert out["starttls"] is False
    verdict = g.decide("s1")
    assert verdict["decision"] == "reject"
    assert verdict["code"] == "SMTP_STARTTLS_MISSING"
    assert g.metrics()["rejections"] == 1


def test_starttls_stripping_is_detected_from_cached_capability():
    g = make()
    g.set_policy("bank.example", mode="opportunistic")
    begin(g, "s1", "bank.example", now=100)
    first = g.observe_ehlo("s1", ["STARTTLS", "SIZE 100"], now=101)
    assert first["decision"] == "starttls"
    g.close_session("s1")
    begin(g, "s2", "bank.example", now=200)
    second = g.observe_ehlo("s2", ["SIZE 100"], now=201)
    assert second["decision"] == "reject"
    assert second["code"] == "SMTP_STARTTLS_STRIPPED"
    report = g.downgrade_report()
    assert [row["code"] for row in report] == ["SMTP_STARTTLS_STRIPPED"]
    assert report[0]["session"] == "s2"
    assert g.metrics()["downgrades"] == 1


def test_tls_version_must_meet_policy_minimum():
    g = make()
    g.set_policy("secure.example", mode="require", min_version="TLSv1.2")
    begin(g, "s1", "secure.example", now=10)
    g.observe_ehlo("s1", ["STARTTLS"], now=11)
    with pytest.raises(smtp.StarttlsError) as exc:
        g.mark_tls("s1", version="TLSv1.0", cipher="AES256")
    assert exc.value.code == "SMTP_TLS_VERSION"
    out = g.mark_tls("s1", version="TLSv1.2", cipher="TLS_AES_256_GCM_SHA384")
    assert out["state"] == "tls"
    assert g.decide("s1")["decision"] == "accept_tls"
    strict = make()
    strict.set_policy("strict.example", min_version="TLSv1.3")
    begin(strict, "s2", "strict.example", now=10)
    strict.observe_ehlo("s2", ["STARTTLS"], now=11)
    with pytest.raises(smtp.StarttlsError) as exc:
        strict.mark_tls("s2", version="TLSv1.2", cipher="AES256")
    assert exc.value.code == "SMTP_TLS_VERSION"
    assert strict.mark_tls("s2", version="TLSv1.3", cipher="AES256")["state"] == "tls"


def test_session_commands_out_of_order_are_rejected():
    g = make()
    begin(g, "s1", "order.example", now=1)
    with pytest.raises(smtp.StarttlsError) as exc:
        g.mark_tls("s1", version="TLSv1.2", cipher="AES256")
    assert exc.value.code == "SMTP_STATE_ORDER"
    with pytest.raises(smtp.StarttlsError) as exc:
        g.decide("s1")
    assert exc.value.code == "SMTP_STATE_ORDER"
    g.observe_ehlo("s1", ["STARTTLS"], now=2)
    g.mark_tls("s1", version="TLSv1.2", cipher="AES256")
    with pytest.raises(smtp.StarttlsError) as exc:
        g.observe_ehlo("s1", ["STARTTLS"], now=3)
    assert exc.value.code == "SMTP_STATE_ORDER"


def test_capabilities_are_normalized_and_deduplicated():
    g = make()
    begin(g, "s1", "norm.example", now=1)
    out = g.observe_ehlo("s1", [" starttls ", "SIZE 1000", "starttls", "8bitmime"], now=2)
    assert out["starttls"] is True
    assert out["normalized"] == ["8BITMIME", "SIZE 1000", "STARTTLS"]
    assert out["decision"] == "starttls"
    with pytest.raises(smtp.StarttlsError) as exc:
        g.observe_ehlo("s1", [123], now=3)
    assert exc.value.code == "SMTP_EHLO_INVALID"


def test_duplicate_ehlo_is_counted_once():
    g = make()
    begin(g, "s1", "dup.example", now=1)
    first = g.observe_ehlo("s1", ["STARTTLS", "SIZE 10"], now=1)
    second = g.observe_ehlo("s1", ["STARTTLS", "SIZE 10"], now=2)
    assert first["status"] == "observed"
    assert second["status"] == "duplicate"
    assert second["decision"] == first["decision"]
    m = g.metrics()
    assert m["ehlo_observed"] == 1
    assert m["duplicates"] == 1


def test_capability_cache_expires_after_ttl():
    g = make(cache_ttl=600)
    begin(g, "s1", "cache.example", now=1000)
    g.observe_ehlo("s1", ["STARTTLS"], now=1000)
    hit = g.cache_lookup("cache.example", 1599)
    assert hit["hit"] is True
    assert hit["starttls"] is True
    assert hit["age"] == 599
    miss = g.cache_lookup("cache.example", 1601)
    assert miss["hit"] is False
    assert miss["starttls"] is None
    assert g.cache_lookup("never.example", 10)["hit"] is False


def test_session_count_is_capped():
    g = make(max_sessions=2)
    begin(g, "a", "cap.example")
    begin(g, "b", "cap.example")
    with pytest.raises(smtp.StarttlsError) as exc:
        begin(g, "c", "cap.example")
    assert exc.value.code == "SMTP_SESSION_LIMIT"
    g.close_session("a")
    begin(g, "c", "cap.example")
    assert g.metrics()["active_sessions"] == 2


def test_duplicate_session_id_is_rejected_until_closed():
    g = make()
    begin(g, "s1", "dup-id.example")
    with pytest.raises(smtp.StarttlsError) as exc:
        begin(g, "s1", "dup-id.example")
    assert exc.value.code == "SMTP_SESSION_EXISTS"
    assert g.close_session("s1") is True
    begin(g, "s1", "dup-id.example")
    assert g.metrics()["active_sessions"] == 1


def test_closed_session_cannot_be_used():
    g = make()
    begin(g, "s1", "closed.example")
    assert g.close_session("s1") is True
    assert g.close_session("s1") is False
    with pytest.raises(smtp.StarttlsError) as exc:
        g.observe_ehlo("s1", ["STARTTLS"])
    assert exc.value.code == "SMTP_SESSION_MISSING"
    with pytest.raises(smtp.StarttlsError) as exc:
        g.decide("s1")
    assert exc.value.code == "SMTP_SESSION_MISSING"


def test_snapshot_preserves_policy_cache_and_session_state():
    g = make(max_sessions=4)
    g.set_policy("bank.example", mode="opportunistic")
    begin(g, "s1", "bank.example", now=100)
    g.observe_ehlo("s1", ["STARTTLS"], now=101)
    g.mark_tls("s1", version="TLSv1.2", cipher="AES256")
    begin(g, "s2", "plain.example", now=110)
    g.observe_ehlo("s2", ["SIZE 10"], now=111)
    data = g.snapshot()
    h = make()
    h.restore(data)
    assert h.decide("s1")["decision"] == "accept_tls"
    assert h.policy_for("bank.example")["mode"] == "opportunistic"
    assert h.cache_lookup("bank.example", 102)["hit"] is True
    m = h.metrics()
    assert m["tls_established"] == 1
    assert m["active_sessions"] == 2
    assert m["rejections"] == 1
    h.close_session("s2")
    assert h.metrics()["active_sessions"] == 1


def test_restore_of_corrupt_snapshot_leaves_state_intact():
    g = make()
    g.set_policy("keep.example", mode="opportunistic")
    begin(g, "s1", "keep.example", now=5)
    with pytest.raises(smtp.StarttlsError) as exc:
        g.restore({"version": 2})
    assert exc.value.code == "SMTP_SNAPSHOT_INVALID"
    with pytest.raises(smtp.StarttlsError) as exc:
        g.restore("not-a-snapshot")
    assert exc.value.code == "SMTP_SNAPSHOT_INVALID"
    assert g.policy_for("keep.example")["mode"] == "opportunistic"
    assert g.metrics()["active_sessions"] == 1


def test_concurrent_sessions_keep_counters_exact():
    g = make(max_sessions=200)
    errors = []

    def worker(n):
        try:
            for i in range(20):
                sid = "w%d-%d" % (n, i)
                g.begin_session(sid, peer_ip="10.0.0.%d" % (n + 1),
                                ehlo_domain="bulk.example", now=i)
                g.observe_ehlo(sid, ["STARTTLS", "SIZE 10"], now=i + 1)
                g.mark_tls(sid, version="TLSv1.2", cipher="AES256")
        except Exception as err:  # pragma: no cover - failure path
            errors.append(err)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    m = g.metrics()
    assert m["sessions_started"] == 160
    assert m["ehlo_observed"] == 160
    assert m["tls_established"] == 160
    assert m["active_sessions"] == 160
    assert g.decide("w3-7")["decision"] == "accept_tls"


def test_metrics_and_duplicate_counter():
    g = make()
    begin(g, "s1", "metrics.example")
    g.observe_ehlo("s1", ["SIZE 1"])
    g.observe_ehlo("s1", ["SIZE 1"])
    g.close_session("s1")
    m = g.metrics()
    assert m["sessions_started"] == 1
    assert m["ehlo_observed"] == 1
    assert m["rejections"] == 1
    assert m["duplicates"] == 1
    assert m["tls_established"] == 0
    assert m["active_sessions"] == 0


def test_policy_validation_and_defaults():
    g = make()
    with pytest.raises(smtp.StarttlsError) as exc:
        g.set_policy("", mode="require")
    assert exc.value.code == "SMTP_DOMAIN_INVALID"
    with pytest.raises(smtp.StarttlsError) as exc:
        g.set_policy("x.example", mode="bogus")
    assert exc.value.code == "SMTP_POLICY_INVALID"
    with pytest.raises(smtp.StarttlsError) as exc:
        g.set_policy("x.example", min_version="TLSv1.0")
    assert exc.value.code == "SMTP_TLS_VERSION"
    default = g.policy_for("unknown.example")
    assert default["mode"] == "require"
    assert default["min_version"] == "TLSv1.2"
    out = g.set_policy("x.example", mode="opportunistic", min_version="TLSv1.3")
    assert out["mode"] == "opportunistic"
    assert g.policy_for("x.example")["min_version"] == "TLSv1.3"
