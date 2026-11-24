import threading

import pytest

import scim_provisioning_guard as sc

TENANT = "t1"


def make(**kwargs):
    guard = sc.ScimGuard(**kwargs)
    guard.register_tenant(TENANT, source="hr-feed",
                          allowed_domains=("corp.example.com",))
    return guard


def resource(**overrides):
    base = {
        "id": "u1",
        "userName": "alice@corp.example.com",
        "displayName": "Alice",
        "active": True,
        "version": 1,
    }
    base.update(overrides)
    return base


def test_upsert_stores_resource_and_get_returns_public_shape():
    guard = make()
    out = guard.upsert(TENANT, resource(event_id="evt-1"))
    assert out == {"status": "applied", "id": "u1", "version": 1, "active": True}
    assert guard.get(TENANT, "u1") == {
        "id": "u1",
        "userName": "alice@corp.example.com",
        "displayName": "Alice",
        "active": True,
        "version": 1,
        "deleted": False,
        "externalId": None,
    }
    assert guard.is_applied(TENANT, "evt-1") is True
    again = guard.register_tenant(TENANT, source="hr-feed",
                                  allowed_domains=("corp.example.com",))
    assert again["source"] == "hr-feed"
    with pytest.raises(sc.ScimError) as exc:
        guard.register_tenant(TENANT, source="other-feed",
                              allowed_domains=("corp.example.com",))
    assert exc.value.code == "SCIM_CONFLICT"


def test_lower_version_is_stale_and_does_not_overwrite():
    guard = make()
    guard.upsert(TENANT, resource(version=3, userName="alice-v3"))
    out = guard.upsert(TENANT, resource(version=2, userName="alice-v2"))
    assert out == {"status": "stale", "code": "SCIM_VERSION_STALE",
                   "id": "u1", "version": 3}
    assert guard.get(TENANT, "u1")["userName"] == "alice-v3"


def test_equal_version_is_also_stale():
    guard = make()
    guard.upsert(TENANT, resource(version=3, userName="alice-v3"))
    out = guard.upsert(TENANT, resource(version=3, userName="alice-other"))
    assert out["status"] == "stale"
    assert out["version"] == 3
    assert guard.get(TENANT, "u1")["userName"] == "alice-v3"


def test_invalid_resources_and_unknown_tenant_are_rejected():
    guard = make()
    bad_resources = [
        resource(version=0),
        resource(version=-1),
        resource(version="3"),
        resource(version=True),
        resource(id=""),
        resource(userName=""),
    ]
    for bad in bad_resources:
        with pytest.raises(sc.ScimError) as exc:
            guard.upsert(TENANT, bad)
        assert exc.value.code == "SCIM_INVALID_RESOURCE"
    with pytest.raises(sc.ScimError) as exc:
        guard.upsert("ghost", resource())
    assert exc.value.code == "SCIM_UNKNOWN_TENANT"
    with pytest.raises(sc.ScimError) as exc:
        guard.get(TENANT, "u1")
    assert exc.value.code == "SCIM_NOT_FOUND"


def test_duplicate_event_id_is_suppressed_before_version_logic():
    guard = make()
    guard.upsert(TENANT, resource(version=1, event_id="evt-1"))
    duplicate = guard.upsert(TENANT, resource(version=99, userName="alice-new",
                                              event_id="evt-1"))
    assert duplicate == {"status": "duplicate", "code": "SCIM_DUPLICATE_EVENT",
                         "id": "u1", "version": 99}
    stored = guard.get(TENANT, "u1")
    assert stored["version"] == 1
    assert stored["userName"] == "alice@corp.example.com"


def test_patch_bumps_version_once_and_honours_expected_version():
    guard = make()
    guard.upsert(TENANT, resource())
    with pytest.raises(sc.ScimError) as exc:
        guard.patch(TENANT, "u1",
                    [{"op": "replace", "path": "displayName", "value": "Bob"}],
                    expected_version=2)
    assert exc.value.code == "SCIM_VERSION_CONFLICT"
    assert guard.get(TENANT, "u1")["displayName"] == "Alice"

    out = guard.patch(
        TENANT, "u1",
        [
            {"op": "replace", "path": "displayName", "value": "Bob"},
            {"op": "add", "path": "externalId", "value": "ext-9"},
        ],
        expected_version=1,
    )
    assert out == {"status": "patched", "id": "u1", "version": 2, "active": True}
    stored = guard.get(TENANT, "u1")
    assert stored["displayName"] == "Bob"
    assert stored["externalId"] == "ext-9"
    assert stored["version"] == 2

    with pytest.raises(sc.ScimError) as exc:
        guard.patch(TENANT, "u1", [{"op": "add", "path": "displayName", "value": "X"}],
                    expected_version=1)
    assert exc.value.code == "SCIM_VERSION_CONFLICT"


def test_patch_is_atomic_when_an_operation_is_invalid():
    guard = make()
    guard.upsert(TENANT, resource())
    with pytest.raises(sc.ScimError) as exc:
        guard.patch(TENANT, "u1", [
            {"op": "replace", "path": "displayName", "value": "Changed"},
            {"op": "remove", "path": "userName"},
        ])
    assert exc.value.code == "SCIM_REQUIRED_ATTRIBUTE"
    assert guard.get(TENANT, "u1")["displayName"] == "Alice"
    assert guard.get(TENANT, "u1")["version"] == 1

    with pytest.raises(sc.ScimError) as exc:
        guard.patch(TENANT, "u1", [{"op": "replace", "path": "emails", "value": []}])
    assert exc.value.code == "SCIM_UNSUPPORTED_PATH"
    with pytest.raises(sc.ScimError) as exc:
        guard.patch(TENANT, "u1", [{"op": "move", "path": "displayName", "value": "X"}])
    assert exc.value.code == "SCIM_UNSUPPORTED_OPERATION"
    with pytest.raises(sc.ScimError) as exc:
        guard.patch(TENANT, "u1", [])
    assert exc.value.code == "SCIM_INVALID_OPERATION"


def test_patch_rejects_missing_and_deactivated_users():
    guard = make()
    with pytest.raises(sc.ScimError) as exc:
        guard.patch(TENANT, "missing",
                    [{"op": "replace", "path": "displayName", "value": "X"}])
    assert exc.value.code == "SCIM_NOT_FOUND"
    with pytest.raises(sc.ScimError) as exc:
        guard.deactivate(TENANT, "missing")
    assert exc.value.code == "SCIM_NOT_FOUND"

    guard.upsert(TENANT, resource())
    guard.deactivate(TENANT, "u1")
    with pytest.raises(sc.ScimError) as exc:
        guard.patch(TENANT, "u1",
                    [{"op": "replace", "path": "displayName", "value": "X"}])
    assert exc.value.code == "SCIM_DELETED"


def test_deactivate_creates_tombstone_and_upsert_can_revive():
    guard = make()
    guard.upsert(TENANT, resource())
    out = guard.deactivate(TENANT, "u1", expected_version=1)
    assert out == {"status": "deactivated", "id": "u1", "version": 2,
                   "deleted": True}
    assert guard.list_users(TENANT) == []
    tombstones = guard.list_users(TENANT, include_deleted=True)
    assert len(tombstones) == 1
    assert tombstones[0]["deleted"] is True
    with pytest.raises(sc.ScimError) as exc:
        guard.deactivate(TENANT, "u1")
    assert exc.value.code == "SCIM_ALREADY_DELETED"

    revived = guard.upsert(TENANT, resource(version=3, userName="alice@corp.example.com"))
    assert revived["status"] == "applied"
    stored = guard.get(TENANT, "u1")
    assert stored["deleted"] is False
    assert stored["active"] is True
    assert stored["version"] == 3


def test_batch_applies_events_in_version_order():
    guard = make()
    events = [
        {"id": "u1", "userName": "alice-v3", "version": 3, "event_id": "b3"},
        {"id": "u1", "userName": "alice-v1", "version": 1, "event_id": "b1"},
        {"id": "u1", "userName": "alice-v2", "version": 2, "event_id": "b2"},
    ]
    out = guard.apply_batch(TENANT, events)
    assert out["applied"] == 3
    assert out["stale"] == 0
    assert out["duplicate"] == 0
    assert out["noop"] == 0
    assert [row["status"] for row in out["results"]] == ["applied"] * 3
    assert [row["version"] for row in out["results"]] == [1, 2, 3]
    stored = guard.get(TENANT, "u1")
    assert stored["userName"] == "alice-v3"
    assert stored["version"] == 3

    tiny = make(max_batch=2)
    with pytest.raises(sc.ScimError) as exc:
        tiny.apply_batch(TENANT, events)
    assert exc.value.code == "SCIM_BATCH_TOO_LARGE"


def test_batch_is_rejected_atomically_on_tenant_or_shape_errors():
    guard = make()
    mixed = [
        resource(event_id="x1"),
        resource(id="u2", userName="bob@corp.example.com", tenant="t2",
                 event_id="x2"),
    ]
    with pytest.raises(sc.ScimError) as exc:
        guard.apply_batch(TENANT, mixed)
    assert exc.value.code == "SCIM_TENANT_MISMATCH"
    with pytest.raises(sc.ScimError) as exc:
        guard.get(TENANT, "u1")
    assert exc.value.code == "SCIM_NOT_FOUND"

    invalid = [resource(), resource(id="u2", userName="bob@corp.example.com",
                                    version=0)]
    with pytest.raises(sc.ScimError) as exc:
        guard.apply_batch(TENANT, invalid)
    assert exc.value.code == "SCIM_INVALID_RESOURCE"
    assert guard.is_applied(TENANT, "x1") is False


def test_tenant_capacity_counts_tombstones():
    guard = make(max_users_per_tenant=2)
    guard.upsert(TENANT, resource())
    guard.upsert(TENANT, resource(id="u2", userName="bob@corp.example.com"))
    with pytest.raises(sc.ScimError) as exc:
        guard.upsert(TENANT, resource(id="u3", userName="carol@corp.example.com"))
    assert exc.value.code == "SCIM_TENANT_CAPACITY"

    guard.deactivate(TENANT, "u1")
    with pytest.raises(sc.ScimError) as exc:
        guard.upsert(TENANT, resource(id="u3", userName="carol@corp.example.com"))
    assert exc.value.code == "SCIM_TENANT_CAPACITY"


def test_tenants_are_isolated_and_can_be_purged():
    guard = make()
    guard.register_tenant("t2", source="okta", allowed_domains=("other.example.com",))
    guard.upsert(TENANT, resource(userName="alice@corp.example.com"))
    guard.upsert("t2", resource(userName="bob@other.example.com"))
    assert guard.get(TENANT, "u1")["userName"] == "alice@corp.example.com"
    assert guard.get("t2", "u1")["userName"] == "bob@other.example.com"
    assert [row["userName"] for row in guard.list_users("t2")] == ["bob@other.example.com"]

    assert guard.purge_tenant(TENANT) == 1
    with pytest.raises(sc.ScimError) as exc:
        guard.get(TENANT, "u1")
    assert exc.value.code == "SCIM_UNKNOWN_TENANT"
    assert guard.get("t2", "u1")["userName"] == "bob@other.example.com"


def test_snapshot_restore_keeps_versions_tombstones_and_dedupe():
    guard = make()
    guard.upsert(TENANT, resource(event_id="evt-1"))
    guard.upsert(TENANT, resource(id="u2", userName="bob@corp.example.com"))
    guard.deactivate(TENANT, "u2", expected_version=1)
    state = guard.snapshot()

    clone = sc.ScimGuard()
    clone.restore(state)
    assert clone.get(TENANT, "u1")["userName"] == "alice@corp.example.com"
    assert clone.get(TENANT, "u2")["deleted"] is True
    assert clone.is_applied(TENANT, "evt-1") is True
    duplicate = clone.upsert(TENANT, resource(version=9, event_id="evt-1"))
    assert duplicate["status"] == "duplicate"

    bad_states = [
        None,
        {},
        {"version": 9, "tenants": {}},
        {"version": 1, "tenants": []},
    ]
    for bad in bad_states:
        with pytest.raises(sc.ScimError) as exc:
            clone.restore(bad)
        assert exc.value.code == "SCIM_SNAPSHOT_INVALID"
    assert clone.get(TENANT, "u1")["version"] == 1


def test_concurrent_patch_with_expected_version_succeeds_exactly_once():
    guard = make()
    guard.upsert(TENANT, resource())
    barrier = threading.Barrier(8)
    outcomes = []
    lock = threading.Lock()

    def worker(index):
        barrier.wait()
        try:
            out = guard.patch(
                TENANT, "u1",
                [{"op": "replace", "path": "displayName", "value": f"name-{index}"}],
                expected_version=1,
            )
            item = ("ok", out["status"])
        except sc.ScimError as exc:
            item = ("error", exc.code)
        with lock:
            outcomes.append(item)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    successes = [item for item in outcomes if item[0] == "ok"]
    assert successes == [("ok", "patched")]
    codes = sorted(item[1] for item in outcomes if item[0] == "error")
    assert codes == ["SCIM_VERSION_CONFLICT"] * 7
    assert guard.get(TENANT, "u1")["version"] == 2
