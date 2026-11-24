import json
import threading

import pytest

import vault_approle_guard as app


def make(**kwargs):
    return app.AppRoleGuard(**kwargs)


def test_login_with_valid_secret_returns_sorted_policies_and_unique_tokens():
    g = make()
    info = g.create_role("app", policies=["app-read", "default"])
    assert info["role"] == "app"
    first = g.generate_secret_id("app", now=1000)
    second = g.generate_secret_id("app", now=1000)
    assert first["secret_id"].startswith("s.")
    assert first["secret_id"] != second["secret_id"]
    out = g.login(info["role_id"], first["secret_id"], cidr="10.0.0.5",
                  now=1000)
    assert out["role"] == "app"
    assert out["policies"] == ["app-read", "default"]
    assert out["token"].startswith("hvs.")
    assert out["accessor"] == first["accessor"]
    other = g.login(info["role_id"], second["secret_id"], cidr="10.0.0.5",
                    now=1000)
    assert other["token"] != out["token"]


def test_single_use_secret_id_cannot_be_replayed():
    g = make()
    info = g.create_role("app", policies=["default"], secret_id_num_uses=1)
    secret = g.generate_secret_id("app", now=1000)
    assert g.login(info["role_id"], secret["secret_id"], cidr="10.0.0.5",
                   now=1000)["role"] == "app"
    with pytest.raises(app.AppRoleError) as exc:
        g.login(info["role_id"], secret["secret_id"], cidr="10.0.0.5",
                now=1001)
    assert exc.value.code == "APPROLE_SECRET_CONSUMED"
    spare = g.generate_secret_id("app", now=1000)
    assert g.login(info["role_id"], spare["secret_id"], cidr="10.0.0.5",
                   now=1002)["role"] == "app"


def test_secret_id_expiry_is_enforced_at_boundary():
    g = make()
    info = g.create_role("app", policies=["default"], secret_id_ttl=60)
    first = g.generate_secret_id("app", now=1000)
    assert first["expires_at"] == 1060
    assert g.login(info["role_id"], first["secret_id"], cidr="10.0.0.5",
                   now=1059)["role"] == "app"
    second = g.generate_secret_id("app", now=1000)
    with pytest.raises(app.AppRoleError) as exc:
        g.login(info["role_id"], second["secret_id"], cidr="10.0.0.5",
                now=1060)
    assert exc.value.code == "APPROLE_SECRET_EXPIRED"


def test_secret_id_cidr_binding_rejects_foreign_network():
    g = make()
    info = g.create_role("app", policies=["default"])
    bound = g.generate_secret_id("app", cidr="10.8.0.0/16", now=1000)
    assert g.login(info["role_id"], bound["secret_id"], cidr="10.8.3.9",
                   now=1000)["role"] == "app"
    foreign = g.generate_secret_id("app", cidr="10.8.0.0/16", now=1000)
    with pytest.raises(app.AppRoleError) as exc:
        g.login(info["role_id"], foreign["secret_id"], cidr="10.9.0.1",
                now=1001)
    assert exc.value.code == "APPROLE_CIDR_DENIED"
    broken = g.generate_secret_id("app", cidr="10.8.0.0/16", now=1000)
    with pytest.raises(app.AppRoleError) as exc2:
        g.login(info["role_id"], broken["secret_id"], cidr="not-a-cidr",
                now=1002)
    assert exc2.value.code == "APPROLE_CIDR_DENIED"


def test_role_level_cidr_binding_covers_unbound_secret():
    g = make()
    info = g.create_role("ops", policies=["ops"],
                         bind_cidrs=("192.168.0.0/24",))
    inside = g.generate_secret_id("ops", now=1000)
    assert g.login(info["role_id"], inside["secret_id"], cidr="192.168.0.7",
                   now=1000)["role"] == "ops"
    outside = g.generate_secret_id("ops", now=1000)
    with pytest.raises(app.AppRoleError) as exc:
        g.login(info["role_id"], outside["secret_id"], cidr="192.168.1.7",
                now=1001)
    assert exc.value.code == "APPROLE_CIDR_DENIED"


def test_required_metadata_must_be_present_and_equal():
    g = make()
    info = g.create_role("app", policies=["default"],
                         require_metadata={"env": "prod", "cluster": "c1"})
    good = g.generate_secret_id("app", now=1000)
    out = g.login(info["role_id"], good["secret_id"], cidr="10.0.0.5",
                  metadata={"env": "prod", "cluster": "c1", "debug": "1"},
                  now=1000)
    assert out["role"] == "app"
    missing = g.generate_secret_id("app", now=1000)
    with pytest.raises(app.AppRoleError) as exc:
        g.login(info["role_id"], missing["secret_id"], cidr="10.0.0.5",
                metadata={"env": "prod"}, now=1001)
    assert exc.value.code == "APPROLE_METADATA_MISMATCH"
    wrong = g.generate_secret_id("app", now=1000)
    with pytest.raises(app.AppRoleError) as exc2:
        g.login(info["role_id"], wrong["secret_id"], cidr="10.0.0.5",
                metadata={"env": "dev", "cluster": "c1"}, now=1002)
    assert exc2.value.code == "APPROLE_METADATA_MISMATCH"


def test_role_id_rotation_invalidates_only_the_previous_role_id():
    g = make()
    info = g.create_role("app", policies=["default"])
    secret = g.generate_secret_id("app", now=1000)
    rotated = g.rotate_role_id("app", now=1001)
    assert rotated["role_id"] != info["role_id"]
    with pytest.raises(app.AppRoleError) as exc:
        g.login(info["role_id"], secret["secret_id"], cidr="10.0.0.5",
                now=1002)
    assert exc.value.code == "APPROLE_ROLE_ID_MISMATCH"
    assert g.login(rotated["role_id"], secret["secret_id"], cidr="10.0.0.5",
                   now=1003)["role"] == "app"
    assert g.role_info("app")["role_id"] == rotated["role_id"]


def test_num_uses_quota_allows_exactly_the_configured_logins():
    g = make()
    info = g.create_role("app", policies=["default"], secret_id_num_uses=3)
    secret = g.generate_secret_id("app", now=1000)
    for tick in range(3):
        assert g.login(info["role_id"], secret["secret_id"], cidr="10.0.0.5",
                       now=1000 + tick)["role"] == "app"
    with pytest.raises(app.AppRoleError) as exc:
        g.login(info["role_id"], secret["secret_id"], cidr="10.0.0.5",
                now=1004)
    assert exc.value.code == "APPROLE_SECRET_CONSUMED"
    assert g.stats()["tokens_issued"] == 3


def test_revoke_by_accessor_blocks_logins_and_updates_counts():
    g = make()
    info = g.create_role("app", policies=["default"])
    secret = g.generate_secret_id("app", now=1000)
    out = g.revoke_secret_id(secret["accessor"], now=1001)
    assert out["revoked"] is True
    with pytest.raises(app.AppRoleError) as exc:
        g.login(info["role_id"], secret["secret_id"], cidr="10.0.0.5",
                now=1002)
    assert exc.value.code == "APPROLE_SECRET_REVOKED"
    info2 = g.role_info("app")
    assert info2["active_secret_ids"] == 0
    assert info2["revoked_secret_ids"] == 1
    assert g.revoke_secret_id(secret["accessor"], now=1003)["revoked"] is True


def test_public_views_never_expose_secret_id_values():
    g = make()
    info = g.create_role("app", policies=["default"])
    secrets = [g.generate_secret_id("app", now=1000) for _ in range(3)]
    g.login(info["role_id"], secrets[0]["secret_id"], cidr="10.0.0.5",
            now=1000)
    blob = (json.dumps(g.role_info("app"), sort_keys=True)
            + json.dumps(g.stats(), sort_keys=True)
            + json.dumps(g.audit_log(), sort_keys=True))
    for row in secrets:
        assert row["secret_id"] not in blob
    assert json.loads(json.dumps(g.snapshot())) is not None


def test_unknown_role_and_unknown_role_id_have_distinct_codes():
    g = make()
    g.create_role("app", policies=["default"])
    with pytest.raises(app.AppRoleError) as exc:
        g.generate_secret_id("missing", now=1000)
    assert exc.value.code == "APPROLE_UNKNOWN_ROLE"
    with pytest.raises(app.AppRoleError) as exc2:
        g.role_info("missing")
    assert exc2.value.code == "APPROLE_UNKNOWN_ROLE"
    with pytest.raises(app.AppRoleError) as exc3:
        g.login("role-id-does-not-exist", "s.deadbeef", cidr="10.0.0.5",
                now=1000)
    assert exc3.value.code == "APPROLE_ROLE_ID_MISMATCH"
    with pytest.raises(app.AppRoleError) as exc4:
        g.create_role("app", policies=["default"])
    assert exc4.value.code == "APPROLE_ROLE_EXISTS"


def test_concurrent_login_consumes_single_use_secret_exactly_once():
    g = make()
    info = g.create_role("app", policies=["default"], secret_id_num_uses=1)
    secret = g.generate_secret_id("app", now=1000)
    barrier = threading.Barrier(8)
    results = []
    errors = []
    lock = threading.Lock()

    def worker():
        barrier.wait()
        try:
            out = g.login(info["role_id"], secret["secret_id"],
                          cidr="10.0.0.5", now=1000)
        except app.AppRoleError as exc:
            with lock:
                errors.append(exc.code)
            return
        with lock:
            results.append(out)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(results) == 1
    assert sorted(errors) == ["APPROLE_SECRET_CONSUMED"] * 7
    assert g.stats()["tokens_issued"] == 1


def test_login_rate_limit_counts_a_rolling_minute_per_role():
    g = make()
    info = g.create_role("app", policies=["default"],
                         max_logins_per_minute=3)
    secret = g.generate_secret_id("app", now=1000)
    for tick in range(3):
        assert g.login(info["role_id"], secret["secret_id"], cidr="10.0.0.5",
                       now=1000 + tick)["role"] == "app"
    with pytest.raises(app.AppRoleError) as exc:
        g.login(info["role_id"], secret["secret_id"], cidr="10.0.0.5",
                now=1003)
    assert exc.value.code == "APPROLE_LIMIT_EXCEEDED"
    assert g.login(info["role_id"], secret["secret_id"], cidr="10.0.0.5",
                   now=1064)["role"] == "app"


def test_snapshot_restore_preserves_use_counts_revocation_and_expiry():
    g = make()
    info = g.create_role("app", policies=["default"], secret_id_num_uses=2,
                         secret_id_ttl=500)
    used = g.generate_secret_id("app", now=1000)
    spare = g.generate_secret_id("app", now=1000)
    revoked = g.generate_secret_id("app", now=1000)
    short = g.generate_secret_id("app", ttl=10, now=1000)
    g.login(info["role_id"], used["secret_id"], cidr="10.0.0.5", now=1000)
    g.revoke_secret_id(revoked["accessor"], now=1000)
    state = json.loads(json.dumps(g.snapshot()))
    restored = app.AppRoleGuard.restore(state, now=1000)
    assert restored.login(info["role_id"], used["secret_id"],
                          cidr="10.0.0.5", now=1001)["role"] == "app"
    with pytest.raises(app.AppRoleError) as exc:
        restored.login(info["role_id"], used["secret_id"], cidr="10.0.0.5",
                       now=1002)
    assert exc.value.code == "APPROLE_SECRET_CONSUMED"
    with pytest.raises(app.AppRoleError) as exc2:
        restored.login(info["role_id"], revoked["secret_id"],
                       cidr="10.0.0.5", now=1003)
    assert exc2.value.code == "APPROLE_SECRET_REVOKED"
    with pytest.raises(app.AppRoleError) as exc3:
        restored.login(info["role_id"], short["secret_id"], cidr="10.0.0.5",
                       now=1011)
    assert exc3.value.code == "APPROLE_SECRET_EXPIRED"
    assert restored.login(info["role_id"], spare["secret_id"],
                          cidr="10.0.0.5", now=1004)["role"] == "app"


def test_sweep_expired_removes_only_expired_secret_ids():
    g = make()
    info = g.create_role("app", policies=["default"])
    early_a = g.generate_secret_id("app", ttl=10, now=1000)
    early_b = g.generate_secret_id("app", ttl=10, now=1000)
    late = g.generate_secret_id("app", ttl=200, now=1000)
    assert g.sweep_expired(now=1100) == 2
    assert g.role_info("app")["active_secret_ids"] == 1
    with pytest.raises(app.AppRoleError) as exc:
        g.login(info["role_id"], early_a["secret_id"], cidr="10.0.0.5",
                now=1100)
    assert exc.value.code == "APPROLE_SECRET_UNKNOWN"
    assert g.login(info["role_id"], late["secret_id"], cidr="10.0.0.5",
                   now=1101)["role"] == "app"
