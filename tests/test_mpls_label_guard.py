import threading

import pytest

import mpls_label_guard as mpls


def make(**kwargs):
    return mpls.MplsGuard(**kwargs)


def test_reserved_label_is_only_legal_at_stack_bottom():
    g = make()
    with pytest.raises(mpls.MplsError) as exc:
        g.validate_stack("carrier", [16, 3, 17])
    assert exc.value.code == "MPLS_RESERVED_POSITION"
    with pytest.raises(mpls.MplsError) as exc:
        g.validate_stack("carrier", [16, 1])
    assert exc.value.code == "MPLS_RESERVED_LABEL"
    info = g.validate_stack("carrier", [16, 3])
    assert info["depth"] == 2
    assert info["bottom"] == 3


def test_label_must_fit_in_twenty_bits():
    g = make()
    with pytest.raises(mpls.MplsError) as exc:
        g.validate_stack("carrier", [16, 1048576])
    assert exc.value.code == "MPLS_LABEL_RANGE"
    with pytest.raises(mpls.MplsError) as exc:
        g.validate_stack("carrier", [16, -1])
    assert exc.value.code == "MPLS_LABEL_RANGE"
    assert g.validate_stack("carrier", [1048575])["depth"] == 1


def test_depth_limit_can_be_overridden_per_tenant():
    g = make(max_depth=3)
    assert g.validate_stack("carrier", [16, 17, 18])["depth"] == 3
    with pytest.raises(mpls.MplsError) as exc:
        g.validate_stack("carrier", [16, 17, 18, 19])
    assert exc.value.code == "MPLS_DEPTH_EXCEEDED"
    g.register_tenant("carrier", label_min=16, label_max=100, max_depth=5)
    assert g.validate_stack("carrier", [16, 17, 18, 19, 20])["depth"] == 5


def test_tenant_label_range_is_isolated():
    g = make()
    g.register_tenant("alpha", label_min=500, label_max=599)
    assert g.validate_stack("alpha", [500, 599])["depth"] == 2
    with pytest.raises(mpls.MplsError) as exc:
        g.validate_stack("alpha", [499])
    assert exc.value.code == "MPLS_TENANT_RANGE"
    with pytest.raises(mpls.MplsError) as exc:
        g.validate_stack("alpha", [600])
    assert exc.value.code == "MPLS_TENANT_RANGE"
    assert g.validate_stack("beta", [499])["depth"] == 1
    with pytest.raises(mpls.MplsError) as exc:
        g.register_tenant("alpha", label_min=500)
    assert exc.value.code == "MPLS_TENANT_EXISTS"


def test_entropy_label_must_sit_just_above_the_bottom():
    g = make()
    info = g.validate_stack("carrier", [16, 7, 18])
    assert info["entropy"] is True
    assert info["depth"] == 3
    with pytest.raises(mpls.MplsError) as exc:
        g.validate_stack("carrier", [7, 16, 18])
    assert exc.value.code == "MPLS_ENTROPY_POSITION"
    with pytest.raises(mpls.MplsError) as exc:
        g.validate_stack("carrier", [16, 7])
    assert exc.value.code == "MPLS_ENTROPY_POSITION"


def test_pop_underflow_leaves_the_stack_untouched():
    g = make()
    g.push("carrier", "s1", 16)
    g.push("carrier", "s1", 17)
    g.push("carrier", "s1", 18)
    out = g.pop("carrier", "s1", 2)
    assert out["removed"] == [18, 17]
    assert out["depth"] == 1
    with pytest.raises(mpls.MplsError) as exc:
        g.pop("carrier", "s1", 5)
    assert exc.value.code == "MPLS_UNDERFLOW"
    assert g.read_stack("carrier", "s1") == [16]


def test_duplicate_push_token_is_suppressed():
    g = make()
    first = g.push("carrier", "s1", 16, token="k1")
    assert first["status"] == "applied"
    again = g.push("carrier", "s1", 16, token="k1")
    assert again["status"] == "duplicate"
    assert again["code"] == "MPLS_DUP_TOKEN"
    assert again["depth"] == 1
    assert g.metrics()["pushes"] == 1
    g.push("carrier", "s1", 17, token="k2")
    assert g.read_stack("carrier", "s1") == [16, 17]


def test_session_table_has_a_hard_limit():
    g = make(max_sessions=2)
    g.push("carrier", "a", 16)
    g.push("carrier", "b", 17)
    with pytest.raises(mpls.MplsError) as exc:
        g.push("carrier", "c", 18)
    assert exc.value.code == "MPLS_SESSION_LIMIT"
    assert g.close_session("carrier", "a") is True
    g.push("carrier", "c", 19)
    assert g.read_stack("carrier", "c") == [19]


def test_swap_top_is_atomic_on_invalid_label():
    g = make()
    g.push("carrier", "s", 16)
    out = g.swap_top("carrier", "s", 20)
    assert out["previous"] == 16
    assert g.read_stack("carrier", "s") == [20]
    with pytest.raises(mpls.MplsError) as exc:
        g.swap_top("carrier", "s", 1048576)
    assert exc.value.code == "MPLS_LABEL_RANGE"
    assert g.read_stack("carrier", "s") == [20]
    g.pop("carrier", "s", 1)
    with pytest.raises(mpls.MplsError) as exc:
        g.swap_top("carrier", "s", 20)
    assert exc.value.code == "MPLS_UNDERFLOW"
    with pytest.raises(mpls.MplsError) as exc:
        g.swap_top("carrier", "missing", 20)
    assert exc.value.code == "MPLS_SESSION_MISSING"
    assert g.read_stack("carrier", "s") == []


def test_snapshot_restores_stacks_tenants_and_counters():
    g = make(max_depth=4)
    g.register_tenant("carrier", label_min=500, label_max=600, max_depth=3)
    g.push("carrier", "s1", 500)
    g.push("carrier", "s1", 501)
    g.push("other", "s2", 600)
    data = g.snapshot()
    h = make()
    h.restore(data)
    assert h.read_stack("carrier", "s1") == [500, 501]
    assert h.read_stack("other", "s2") == [600]
    assert h.metrics()["pushes"] == 3
    assert h.metrics()["sessions"] == 2
    with pytest.raises(mpls.MplsError) as exc:
        h.push("carrier", "s1", 499)
    assert exc.value.code == "MPLS_TENANT_RANGE"


def test_restore_rejects_broken_snapshot_without_mutating_state():
    g = make()
    g.push("carrier", "s", 16)
    with pytest.raises(mpls.MplsError) as exc:
        g.restore({"version": 99})
    assert exc.value.code == "MPLS_SNAPSHOT_INVALID"
    with pytest.raises(mpls.MplsError) as exc:
        g.restore(None)
    assert exc.value.code == "MPLS_SNAPSHOT_INVALID"
    assert g.read_stack("carrier", "s") == [16]
    assert g.metrics()["pushes"] == 1


def test_concurrent_pushes_do_not_lose_labels():
    g = make(max_depth=512, max_sessions=8)
    errors = []

    def worker(n):
        try:
            for i in range(25):
                g.push("carrier", "shared", 16 + n * 25 + i)
        except Exception as err:  # pragma: no cover - failure path
            errors.append(err)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    stack = g.read_stack("carrier", "shared")
    assert len(stack) == 200
    assert len(set(stack)) == 200
    assert g.metrics()["pushes"] == 200
    assert g.metrics()["max_depth_seen"] == 200


def test_audit_is_newest_first_and_bounded():
    g = make()
    g.push("carrier", "s", 16)
    with pytest.raises(mpls.MplsError):
        g.push("carrier", "s", 1)
    with pytest.raises(mpls.MplsError):
        g.pop("carrier", "s", 3)
    newest = g.audit(limit=1)
    assert len(newest) == 1
    assert newest[0]["code"] == "MPLS_UNDERFLOW"
    rows = g.audit()
    assert [row["code"] for row in rows] == ["MPLS_UNDERFLOW", "MPLS_RESERVED_LABEL"]
    assert len(g.audit(tenant="carrier")) == 2
    assert g.audit(tenant="nobody") == []
    with pytest.raises(mpls.MplsError) as exc:
        g.audit(limit=0)
    assert exc.value.code == "MPLS_BAD_LIMIT"


def test_close_session_is_idempotent_and_releases_the_slot():
    g = make()
    g.push("carrier", "s", 16)
    assert g.close_session("carrier", "s") is True
    assert g.close_session("carrier", "s") is False
    with pytest.raises(mpls.MplsError) as exc:
        g.read_stack("carrier", "s")
    assert exc.value.code == "MPLS_SESSION_MISSING"
    assert g.metrics()["sessions"] == 0


def test_metrics_track_push_pop_and_depth_high_watermark():
    g = make()
    g.push("carrier", "s", 16)
    g.push("carrier", "s", 17)
    g.push("carrier", "s", 18)
    g.pop("carrier", "s", 1)
    m = g.metrics()
    assert m["pushes"] == 3
    assert m["pops"] == 1
    assert m["rejects"] == 0
    assert m["sessions"] == 1
    assert m["max_depth_seen"] == 3
