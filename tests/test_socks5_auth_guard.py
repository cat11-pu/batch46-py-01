import concurrent.futures
import json

import pytest

import socks5_auth_guard as s5

PASSWORD = "pw-alice"


def guard(**overrides):
    return s5.Socks5Guard(clock=lambda: 1000, **overrides)


def ready(**overrides):
    g = guard(**overrides)
    g.add_user("alice", PASSWORD, allow_targets=(".example.com",))
    return g


def opened(g, session_id="sess-1", username="alice", password=PASSWORD,
           host="api.example.com", port=443):
    g.hello(session_id, [s5.METHOD_USERPASS])
    g.authenticate(session_id, username, password)
    return g.connect(session_id, s5.CMD_CONNECT, host, port)


def test_hello_selects_the_strongest_common_method():
    g = ready()
    picked = g.hello("sess-a", [s5.METHOD_NO_AUTH, s5.METHOD_USERPASS])
    assert picked["method"] == s5.METHOD_USERPASS
    assert picked["status"] == "greeted"
    none = g.hello("sess-b", [s5.METHOD_NO_AUTH])
    assert none["method"] == s5.METHOD_NONE
    assert none["status"] == "rejected"
    assert none["code"] == "SOCKS_NO_METHOD"
    relaxed = ready(require_auth=False)
    plain = relaxed.hello("sess-c", [s5.METHOD_USERPASS, s5.METHOD_NO_AUTH])
    assert plain["method"] == s5.METHOD_NO_AUTH


def test_connect_before_authentication_is_rejected():
    g = ready()
    g.hello("sess-1", [s5.METHOD_USERPASS])
    with pytest.raises(s5.Socks5Error) as exc:
        g.connect("sess-1", s5.CMD_CONNECT, "api.example.com", 443)
    assert exc.value.code == "SOCKS_NOT_AUTHENTICATED"
    with pytest.raises(s5.Socks5Error) as unknown:
        g.connect("ghost", s5.CMD_CONNECT, "api.example.com", 443)
    assert unknown.value.code == "SOCKS_SESSION_UNKNOWN"


def test_three_bad_passwords_lock_the_user_until_expiry():
    g = ready()
    g.hello("sess-1", [s5.METHOD_USERPASS])
    for attempt in range(2):
        with pytest.raises(s5.Socks5Error) as exc:
            g.authenticate("sess-1", "alice", "wrong-password")
        assert exc.value.code == "SOCKS_AUTH_FAILED"
    with pytest.raises(s5.Socks5Error) as locked:
        g.authenticate("sess-1", "alice", "wrong-password")
    assert locked.value.code == "SOCKS_USER_LOCKED"
    with pytest.raises(s5.Socks5Error) as still_locked:
        g.authenticate("sess-1", "alice", PASSWORD)
    assert still_locked.value.code == "SOCKS_USER_LOCKED"
    assert g.expire(1000 + s5.LOCK_SECONDS) == ["alice"]
    assert g.authenticate("sess-1", "alice", PASSWORD)["status"] == "authenticated"


def test_credential_lengths_match_rfc1929():
    g = ready()
    g.hello("sess-1", [s5.METHOD_USERPASS])
    with pytest.raises(s5.Socks5Error) as empty_user:
        g.authenticate("sess-1", "", PASSWORD)
    assert empty_user.value.code == "SOCKS_BAD_CREDENTIAL_FORMAT"
    with pytest.raises(s5.Socks5Error) as long_password:
        g.authenticate("sess-1", "alice", "x" * 256)
    assert long_password.value.code == "SOCKS_BAD_CREDENTIAL_FORMAT"


def test_only_connect_command_is_supported():
    g = ready()
    opened(g)
    for cmd in (0x02, 0x03):
        with pytest.raises(s5.Socks5Error) as exc:
            g.connect("sess-1", cmd, "api.example.com", 443)
        assert exc.value.code == "SOCKS_CMD_UNSUPPORTED"
    with pytest.raises(s5.Socks5Error) as again:
        g.connect("sess-1", s5.CMD_CONNECT, "api.example.com", 443)
    assert again.value.code == "SOCKS_ALREADY_CONNECTED"


def test_host_and_port_validation():
    g = ready()
    opened(g)
    for host, port in (("api.example.com", 0), ("api.example.com", 65536),
                       ("", 443)):
        with pytest.raises(s5.Socks5Error) as exc:
            g.connect("sess-1", s5.CMD_CONNECT, host, port)
        assert exc.value.code == "SOCKS_BAD_ADDRESS"


def test_domain_allowlist_uses_suffix_matching():
    g = ready()
    opened(g, session_id="sess-1", host="api.example.com")
    g.close("sess-1")
    for session_id, host in (("sess-2", "example.com"),
                             ("sess-3", "eu.api.example.com")):
        g.hello(session_id, [s5.METHOD_USERPASS])
        g.authenticate(session_id, "alice", PASSWORD)
        assert g.connect(session_id, s5.CMD_CONNECT, host, 443)["status"] == "connected"
    g.hello("sess-4", [s5.METHOD_USERPASS])
    g.authenticate("sess-4", "alice", PASSWORD)
    with pytest.raises(s5.Socks5Error) as exc:
        g.connect("sess-4", s5.CMD_CONNECT, "badexample.com", 443)
    assert exc.value.code == "SOCKS_TARGET_DENIED"


def test_private_ranges_are_denied_unless_opted_in():
    g = ready()
    for index, host in enumerate(("127.0.0.1", "10.1.2.3", "::1")):
        session_id = "sess-%d" % index
        g.hello(session_id, [s5.METHOD_USERPASS])
        g.authenticate(session_id, "alice", PASSWORD)
        with pytest.raises(s5.Socks5Error) as exc:
            g.connect(session_id, s5.CMD_CONNECT, host, 443)
        assert exc.value.code == "SOCKS_TARGET_DENIED"
    g.add_user("svc", "pw-service", allow_private=True)
    g.hello("sess-svc", [s5.METHOD_USERPASS])
    g.authenticate("sess-svc", "svc", "pw-service")
    out = g.connect("sess-svc", s5.CMD_CONNECT, "10.1.2.3", 8080)
    assert out["target"] == "10.1.2.3"
    assert out["port"] == 8080


def test_per_user_session_cap_is_enforced():
    g = guard(default_max_sessions=4)
    g.add_user("alice", PASSWORD, max_sessions=2, allow_targets=(".example.com",))
    g.add_user("bob", PASSWORD, allow_targets=(".example.com",))
    opened(g, "a1")
    opened(g, "a2")
    g.hello("a3", [s5.METHOD_USERPASS])
    g.authenticate("a3", "alice", PASSWORD)
    with pytest.raises(s5.Socks5Error) as exc:
        g.connect("a3", s5.CMD_CONNECT, "api.example.com", 443)
    assert exc.value.code == "SOCKS_SESSION_LIMIT"
    opened(g, "b1", username="bob")
    g.close("a1")
    assert g.connect("a3", s5.CMD_CONNECT, "api.example.com", 443)["status"] == "connected"
    assert g.usage("alice")["sessions"] == 2


def test_global_session_cap_is_enforced():
    g = guard(max_sessions=3)
    g.add_user("alice", PASSWORD, max_sessions=10, allow_targets=(".example.com",))
    for index in range(3):
        opened(g, "sess-%d" % index)
    g.hello("sess-4", [s5.METHOD_USERPASS])
    g.authenticate("sess-4", "alice", PASSWORD)
    with pytest.raises(s5.Socks5Error) as exc:
        g.connect("sess-4", s5.CMD_CONNECT, "api.example.com", 443)
    assert exc.value.code == "SOCKS_SERVER_BUSY"


def test_quota_exhaustion_closes_the_session():
    g = guard()
    g.add_user("alice", PASSWORD, quota_bytes=100,
               allow_targets=(".example.com",))
    opened(g)
    with pytest.raises(s5.Socks5Error) as exc:
        g.record_traffic("sess-1", up=60, down=50)
    assert exc.value.code == "SOCKS_QUOTA_EXCEEDED"
    row = g.session("sess-1")
    assert row["state"] == "closed"
    assert row["closed_reason"] == "SOCKS_QUOTA_EXCEEDED"
    usage = g.usage("alice")
    assert usage["up"] == 60
    assert usage["down"] == 50
    assert usage["remaining"] == 0
    with pytest.raises(s5.Socks5Error) as closed:
        g.record_traffic("sess-1", up=1)
    assert closed.value.code == "SOCKS_NOT_OPEN"


def test_close_is_idempotent_and_counts_once():
    g = ready()
    opened(g)
    first = g.close("sess-1")
    assert first["status"] == "closed"
    second = g.close("sess-1")
    assert second["status"] == "noop"
    assert second["code"] == "SOCKS_ALREADY_CLOSED"
    usage = g.usage("alice")
    assert usage["sessions"] == 0
    assert usage["total"] == 1
    with pytest.raises(s5.Socks5Error) as exc:
        g.close("ghost")
    assert exc.value.code == "SOCKS_SESSION_UNKNOWN"


def test_snapshot_omits_passwords_and_requires_reset_after_restore():
    g = guard()
    g.add_user("alice", PASSWORD, quota_bytes=1000,
               allow_targets=(".example.com",))
    opened(g)
    g.record_traffic("sess-1", up=10, down=20)
    snap = json.loads(json.dumps(g.snapshot()))
    assert snap["version"] == s5.SNAPSHOT_VERSION
    assert PASSWORD not in json.dumps(snap)
    restored = guard()
    restored.restore(snap)
    row = restored.session("sess-1")
    assert row["state"] == "open"
    assert row["target"] == "api.example.com"
    assert restored.usage("alice")["up"] == 10
    restored.hello("sess-2", [s5.METHOD_USERPASS])
    with pytest.raises(s5.Socks5Error) as denied:
        restored.authenticate("sess-2", "alice", PASSWORD)
    assert denied.value.code == "SOCKS_AUTH_FAILED"
    assert restored.set_password("alice", "new-password")["status"] == "password_set"
    assert restored.authenticate("sess-2", "alice", "new-password")["status"] == "authenticated"


def test_corrupt_snapshot_is_rejected_atomically():
    g = ready()
    opened(g)
    snap = json.loads(json.dumps(g.snapshot()))
    bad = json.loads(json.dumps(snap))
    bad["sessions"].append(dict(bad["sessions"][0]))
    with pytest.raises(s5.Socks5Error) as exc:
        g.restore(bad)
    assert exc.value.code == "SOCKS_SNAPSHOT_CORRUPT"
    assert g.usage("alice")["sessions"] == 1
    with pytest.raises(s5.Socks5Error) as version:
        g.restore(dict(snap, version=9))
    assert version.value.code == "SOCKS_SNAPSHOT_CORRUPT"
    assert g.session("sess-1")["state"] == "open"


def test_concurrent_connect_respects_the_user_cap():
    g = guard()
    g.add_user("alice", PASSWORD, max_sessions=8,
               allow_targets=(".example.com",))

    def worker(index):
        session_id = "sess-%d" % index
        g.hello(session_id, [s5.METHOD_USERPASS])
        g.authenticate(session_id, "alice", PASSWORD)
        try:
            g.connect(session_id, s5.CMD_CONNECT, "api.example.com", 443)
            return "connected"
        except s5.Socks5Error as err:
            return err.code

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
        results = [future.result()
                   for future in [pool.submit(worker, index) for index in range(20)]]
    assert results.count("connected") == 8
    assert results.count("SOCKS_SESSION_LIMIT") == 12
    assert g.usage("alice")["sessions"] == 8
