import threading

import pytest

import grpc_reflection_guard as rfg


def make(**kwargs):
    return rfg.ReflectionGuard(**kwargs)


def test_service_registration_validates_names_visibility_and_methods():
    g = make()
    with pytest.raises(rfg.ReflectionError) as exc:
        g.register_service("Catalog")
    assert exc.value.code == "RFG_BAD_SERVICE"
    with pytest.raises(rfg.ReflectionError) as exc:
        g.register_service("shop.Catalog", visibility="secret")
    assert exc.value.code == "RFG_BAD_VISIBILITY"
    with pytest.raises(rfg.ReflectionError) as exc:
        g.register_service("shop.Catalog", methods=["Get", "Get"])
    assert exc.value.code == "RFG_BAD_METHOD"
    first = g.register_service(
        "shop.Catalog", methods=["GetItem", "ListItems"],
        labels={"team": "shop"},
    )
    assert first["status"] == "registered"
    assert first["methods"] == ("GetItem", "ListItems")
    again = g.register_service(
        "shop.Catalog", methods=["ListItems", "GetItem"],
        labels={"team": "shop"},
    )
    assert again["status"] == "unchanged"
    with pytest.raises(rfg.ReflectionError) as exc:
        g.register_service("shop.Catalog", methods=["GetItem"])
    assert exc.value.code == "RFG_SERVICE_CONFLICT"


def test_public_service_listing_is_sorted_and_paginated():
    g = make()
    for name in ("shop.Zeta", "shop.Alpha", "shop.Mike", "shop.Bravo",
                 "shop.Yankee"):
        g.register_service(name, methods=["Ping"])
    page1 = g.list_services("alice", page_size=2, now=1000)
    assert page1["services"] == ["shop.Alpha", "shop.Bravo"]
    assert page1["next_cursor"] is not None
    page2 = g.list_services("alice", page_size=2,
                            cursor=page1["next_cursor"], now=1001)
    assert page2["services"] == ["shop.Mike", "shop.Yankee"]
    page3 = g.list_services("alice", page_size=2,
                            cursor=page2["next_cursor"], now=1002)
    assert page3["services"] == ["shop.Zeta"]
    assert page3["next_cursor"] is None
    with pytest.raises(rfg.ReflectionError) as exc:
        g.list_services("alice", cursor="not-a-cursor", now=1003)
    assert exc.value.code == "RFG_BAD_CURSOR"
    with pytest.raises(rfg.ReflectionError) as exc:
        g.list_services("alice", page_size=0, now=1004)
    assert exc.value.code == "RFG_BAD_PAGE"


def test_internal_and_private_services_follow_grants():
    g = make()
    g.register_service("shop.Catalog", methods=["GetItem"])
    g.register_service("ops.Metrics", visibility="internal",
                       methods=["Scrape"])
    g.register_service("ops.Secrets", visibility="private",
                       methods=["Read"])
    assert g.list_services("alice", now=1000)["services"] == ["shop.Catalog"]
    with pytest.raises(rfg.ReflectionError) as exc:
        g.resolve_symbol("alice", "ops.Metrics/Scrape", now=1001)
    assert exc.value.code == "RFG_DENIED"
    g.grant("alice", services=("ops.Metrics",))
    assert g.list_services("alice", now=1002)["services"] == [
        "ops.Metrics", "shop.Catalog"
    ]
    assert g.list_methods("alice", "ops.Metrics",
                          now=1003)["methods"] == ["Scrape"]
    with pytest.raises(rfg.ReflectionError) as exc:
        g.resolve_symbol("alice", "ops.Secrets/Read", now=1004)
    assert exc.value.code == "RFG_DENIED"
    g.grant("alice", services=("ops.Metrics", "ops.Secrets"))
    assert g.list_services("alice", now=1005)["services"] == [
        "ops.Metrics", "shop.Catalog"
    ]
    assert g.resolve_symbol("alice", "ops.Secrets/Read",
                            now=1006)["kind"] == "method"


def test_resolve_symbol_distinguishes_services_methods_and_unknowns():
    g = make()
    g.register_service("shop.Catalog", methods=["GetItem", "ListItems"])
    service = g.resolve_symbol("alice", "shop.Catalog", now=1000)
    assert service["kind"] == "service"
    assert service["service"] == "shop.Catalog"
    assert service["method"] is None
    method = g.resolve_symbol("alice", "shop.Catalog/GetItem", now=1001)
    assert method == {
        "kind": "method",
        "service": "shop.Catalog",
        "method": "GetItem",
    }
    with pytest.raises(rfg.ReflectionError) as exc:
        g.resolve_symbol("alice", "missing.Service", now=1002)
    assert exc.value.code == "RFG_NOT_FOUND"
    with pytest.raises(rfg.ReflectionError) as exc:
        g.resolve_symbol("alice", "shop.Catalog/Nope", now=1003)
    assert exc.value.code == "RFG_NOT_FOUND"
    with pytest.raises(rfg.ReflectionError) as exc:
        g.resolve_symbol("alice", "", now=1004)
    assert exc.value.code == "RFG_BAD_SYMBOL"


def test_page_size_is_clamped_and_methods_listing_is_paginated():
    g = make(max_methods_per_response=2)
    g.register_service("shop.Catalog", methods=["A", "B", "C", "D", "E"])
    page1 = g.list_methods("alice", "shop.Catalog", page_size=999, now=1000)
    assert page1["methods"] == ["A", "B"]
    assert page1["next_cursor"] is not None
    page2 = g.list_methods("alice", "shop.Catalog",
                           cursor=page1["next_cursor"], now=1001)
    assert page2["methods"] == ["C", "D"]
    page3 = g.list_methods("alice", "shop.Catalog",
                           cursor=page2["next_cursor"], now=1002)
    assert page3["methods"] == ["E"]
    assert page3["next_cursor"] is None
    with pytest.raises(rfg.ReflectionError) as exc:
        g.list_methods("alice", "no.Such", now=1003)
    assert exc.value.code == "RFG_NOT_FOUND"


def test_rate_limit_is_per_caller_and_windowed():
    g = make(rate_limit=2, rate_window=60)
    g.register_service("shop.Catalog", methods=["Ping"])
    assert g.list_services("alice", now=1000)["services"] == ["shop.Catalog"]
    assert g.list_services("alice", now=1001)["services"] == ["shop.Catalog"]
    with pytest.raises(rfg.ReflectionError) as exc:
        g.list_services("alice", now=1002)
    assert exc.value.code == "RFG_RATE_LIMIT"
    assert g.list_services("bob", now=1002)["services"] == ["shop.Catalog"]
    assert g.list_services("alice", now=1062)["services"] == ["shop.Catalog"]
    rows = g.audit(client="alice")
    assert any(row["code"] == "RFG_RATE_LIMIT" for row in rows)


def test_repeated_probing_blocks_caller_and_block_expires():
    g = make(enumeration_threshold=3, block_seconds=120, rate_limit=100)
    for stamp in (1000, 1001, 1002):
        with pytest.raises(rfg.ReflectionError) as exc:
            g.resolve_symbol("prober", "no.Such/Probe", now=stamp)
        assert exc.value.code == "RFG_NOT_FOUND"
    assert g.blocked(now=1002) == ["prober"]
    with pytest.raises(rfg.ReflectionError) as exc:
        g.resolve_symbol("prober", "no.Such/Probe", now=1010)
    assert exc.value.code == "RFG_BLOCKED"
    block_rows = [
        row for row in g.audit(caller="prober")
        if row["code"] == "RFG_BLOCKED"
    ]
    assert len(block_rows) == 1
    assert g.blocked(now=1122) == []
    with pytest.raises(rfg.ReflectionError) as exc:
        g.resolve_symbol("prober", "no.Such/Probe", now=1122)
    assert exc.value.code == "RFG_NOT_FOUND"


def test_manual_block_unblock_and_audit_history_are_bounded():
    g = make(audit_limit=3, rate_limit=100)
    g.register_service("shop.Catalog", methods=["Ping"])
    g.block_caller("mallory", 30, now=1000)
    assert g.blocked(now=1005) == ["mallory"]
    with pytest.raises(rfg.ReflectionError) as exc:
        g.list_services("mallory", now=1006)
    assert exc.value.code == "RFG_BLOCKED"
    g.unblock_caller("mallory")
    assert g.blocked(now=1007) == []
    mallory_rows = g.audit(caller="mallory")
    assert [row["code"] for row in mallory_rows] == [
        "RFG_BLOCKED", "RFG_UNBLOCKED"
    ]
    for step in range(4):
        with pytest.raises(rfg.ReflectionError) as exc:
            g.resolve_symbol("alice", f"no.Such{step}", now=1010 + step)
        assert exc.value.code == "RFG_NOT_FOUND"
    rows = g.audit()
    assert len(rows) == 3
    assert [row["caller"] for row in rows] == ["alice", "alice", "alice"]
    assert rows[-1]["ts"] == 1013
    assert g.audit(limit=1)[0]["ts"] == 1013
    assert g.audit(caller="mallory") == []


def test_grant_validation_replacement_and_service_revoke_cascade():
    g = make()
    g.register_service("shop.Catalog", methods=["Ping"])
    g.register_service("ops.Metrics", visibility="internal",
                       methods=["Scrape"])
    with pytest.raises(rfg.ReflectionError) as exc:
        g.grant("alice", services=("no.Such",))
    assert exc.value.code == "RFG_UNKNOWN_SERVICE"
    with pytest.raises(rfg.ReflectionError) as exc:
        g.grant("", services=("shop.Catalog",))
    assert exc.value.code == "RFG_BAD_CALLER"
    first = g.grant("alice", services=("ops.Metrics", "shop.Catalog"))
    assert first["services"] == ("ops.Metrics", "shop.Catalog")
    assert g.resolve_symbol("alice", "ops.Metrics/Scrape",
                            now=1000)["kind"] == "method"
    replaced = g.grant("alice", services=("shop.Catalog",))
    assert replaced["services"] == ("shop.Catalog",)
    with pytest.raises(rfg.ReflectionError) as exc:
        g.resolve_symbol("alice", "ops.Metrics/Scrape", now=1001)
    assert exc.value.code == "RFG_DENIED"
    assert g.revoke_service("ops.Metrics")["status"] == "revoked"
    with pytest.raises(rfg.ReflectionError) as exc:
        g.resolve_symbol("alice", "ops.Metrics/Scrape", now=1002)
    assert exc.value.code == "RFG_NOT_FOUND"
    with pytest.raises(rfg.ReflectionError) as exc:
        g.revoke_service("ops.Metrics")
    assert exc.value.code == "RFG_NOT_FOUND"
    assert g.stats()["services"] == 1


def test_stats_track_requests_and_failures():
    g = make()
    g.register_service("shop.Catalog", methods=["Ping"])
    g.register_service("ops.Metrics", visibility="internal",
                       methods=["Scrape"])
    g.grant("alice", services=("shop.Catalog",))
    g.list_services("alice", now=1000)
    g.list_services("alice", now=1001)
    g.resolve_symbol("alice", "shop.Catalog/Ping", now=1002)
    with pytest.raises(rfg.ReflectionError) as exc:
        g.resolve_symbol("alice", "shop.Catalog/Missing", now=1003)
    assert exc.value.code == "RFG_NOT_FOUND"
    with pytest.raises(rfg.ReflectionError) as exc:
        g.list_methods("alice", "ops.Metrics", now=1004)
    assert exc.value.code == "RFG_DENIED"
    stats = g.stats()
    assert stats["services"] == 2
    assert stats["callers"] == 1
    assert stats["requests"] == 5
    assert stats["not_found"] == 1
    assert stats["denied"] == 1
    assert stats["rate_limited"] == 0
    assert stats["blocked"] == 0
    assert stats["audit"] == 2


def test_snapshot_restore_round_trip_and_corruption_guard():
    g = make()
    g.register_service("shop.Catalog", methods=["Ping"],
                       labels={"team": "shop"})
    g.register_service("ops.Metrics", visibility="internal",
                       methods=["Scrape"])
    g.grant("alice", services=("shop.Catalog", "ops.Metrics"))
    g.block_caller("mallory", 60, now=1000)
    with pytest.raises(rfg.ReflectionError) as exc:
        g.resolve_symbol("alice", "no.Such", now=1001)
    assert exc.value.code == "RFG_NOT_FOUND"
    snap = g.snapshot()
    assert snap["version"] == 1
    snap["services"].clear()
    assert g.stats()["services"] == 2
    snap = g.snapshot()
    clone = make()
    clone.restore(snap)
    assert clone.list_services("alice", now=1002)["services"] == [
        "ops.Metrics", "shop.Catalog"
    ]
    assert clone.resolve_symbol("alice", "ops.Metrics/Scrape",
                                now=1003)["kind"] == "method"
    assert clone.blocked(now=1005) == ["mallory"]
    with pytest.raises(rfg.ReflectionError) as exc:
        clone.restore({"version": 9, "services": {}, "grants": {},
                       "blocked": {}, "rate": {}, "violations": {},
                       "audit": [], "stats": {}})
    assert exc.value.code == "RFG_SNAPSHOT_CORRUPT"
    assert clone.stats()["services"] == 2
    bad = dict(snap)
    bad["services"] = {
        "shop.Catalog": {
            "visibility": "invisible", "methods": [], "labels": {},
        }
    }
    with pytest.raises(rfg.ReflectionError) as exc:
        clone.restore(bad)
    assert exc.value.code == "RFG_SNAPSHOT_CORRUPT"
    assert clone.blocked(now=1005) == ["mallory"]


def test_concurrent_service_registration_respects_capacity():
    g = make(max_services=5)
    errors = []
    registered = []
    lock = threading.Lock()

    def worker(index):
        try:
            out = g.register_service(f"svc.Thing{index}", methods=["Ping"])
            with lock:
                registered.append(out["service"])
        except Exception as exc:  # noqa: BLE001
            with lock:
                errors.append(getattr(exc, "code", repr(exc)))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(registered) == 5
    assert errors == ["RFG_CAPACITY"]
    assert g.stats()["services"] == 5
    assert g.list_services("alice", now=1000)["services"] == sorted(registered)


def test_concurrent_probing_blocks_exactly_once():
    g = make(enumeration_threshold=3, block_seconds=60, rate_limit=1000)
    results = []
    lock = threading.Lock()

    def worker():
        try:
            g.resolve_symbol("prober", "no.Such/Probe", now=2000)
            outcome = "ok"
        except Exception as exc:  # noqa: BLE001
            outcome = getattr(exc, "code", repr(exc))
        with lock:
            results.append(outcome)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert "ok" not in results
    assert all(code in {"RFG_NOT_FOUND", "RFG_BLOCKED"} for code in results)
    assert results.count("RFG_NOT_FOUND") >= 1
    assert g.blocked(now=2000) == ["prober"]
    block_rows = [
        row for row in g.audit(caller="prober")
        if row["code"] == "RFG_BLOCKED"
    ]
    assert len(block_rows) == 1


def test_block_unblock_and_expire_return_sorted_callers():
    g = make(block_seconds=60)
    assert g.block_caller("zeta", 30, now=1000) == {
        "caller": "zeta", "until": 1030, "status": "blocked",
    }
    g.block_caller("alpha", 20, now=1000)
    assert g.blocked(now=1001) == ["alpha", "zeta"]
    assert g.expire(1029) == ["alpha"]
    assert g.expire(1030) == ["zeta"]
    assert g.blocked(now=1030) == []
    with pytest.raises(rfg.ReflectionError) as exc:
        g.block_caller("x", 0, now=1000)
    assert exc.value.code == "RFG_BAD_BLOCK"
    g.block_caller("x", 10, now=1000)
    assert g.unblock_caller("x")["status"] == "unblocked"
    assert g.blocked(now=1001) == []


def test_audit_records_failures_with_operation_and_code():
    g = make(rate_limit=100)
    g.register_service("shop.Catalog", methods=["Ping"])
    g.register_service("ops.Metrics", visibility="internal",
                       methods=["Scrape"])
    with pytest.raises(rfg.ReflectionError) as exc:
        g.resolve_symbol("alice", "no.Such", now=1000)
    assert exc.value.code == "RFG_NOT_FOUND"
    with pytest.raises(rfg.ReflectionError) as exc:
        g.list_methods("alice", "ops.Metrics", now=1001)
    assert exc.value.code == "RFG_DENIED"
    with pytest.raises(rfg.ReflectionError) as exc:
        g.list_services("bob", cursor="bogus", now=1002)
    assert exc.value.code == "RFG_BAD_CURSOR"
    rows = g.audit()
    assert [row["op"] for row in rows] == [
        "resolve_symbol", "list_methods", "list_services"
    ]
    assert [row["code"] for row in rows] == [
        "RFG_NOT_FOUND", "RFG_DENIED", "RFG_BAD_CURSOR"
    ]
    assert [row["caller"] for row in rows] == ["alice", "alice", "bob"]
    assert [row["ts"] for row in rows] == [1000, 1001, 1002]
