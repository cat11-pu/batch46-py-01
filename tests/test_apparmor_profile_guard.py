import threading

import pytest

import apparmor_profile_guard as apg


def make(**kwargs):
    return apg.AppArmorGuard(**kwargs)


def test_register_profile_defaults_and_duplicate_rejected():
    guard = make()
    out = guard.register_profile("web")
    assert out["status"] == "registered"
    assert out["mode"] == "enforce"
    assert out["generation"] == 0
    state = guard.state("web")
    assert state["mode"] == "enforce"
    assert state["attachments"] == []
    assert state["confined"] == 0
    with pytest.raises(apg.AppArmorError) as exc:
        guard.register_profile("web", mode="complain")
    assert exc.value.code == "APPARMOR_DUP_PROFILE"


def test_invalid_mode_is_rejected_without_creating_profile():
    guard = make()
    with pytest.raises(apg.AppArmorError) as exc:
        guard.register_profile("bad", mode="permissive")
    assert exc.value.code == "APPARMOR_MODE_INVALID"
    assert guard.snapshot()["profiles"] == {}


def test_loading_identical_body_is_idempotent():
    guard = make()
    guard.register_profile("app")
    first = guard.load_profile("app", "profile rules v1")
    assert first["status"] == "applied"
    assert first["generation"] == 1
    again = guard.load_profile("app", "profile rules v1")
    assert again["status"] == "unchanged"
    assert again["generation"] == 1
    second = guard.load_profile("app", "profile rules v2")
    assert second["status"] == "applied"
    assert second["generation"] == 2
    assert guard.state("app")["body"] == "profile rules v2"


def test_replace_with_stale_generation_leaves_profile_untouched():
    guard = make()
    guard.register_profile("app")
    guard.load_profile("app", "v1")
    with pytest.raises(apg.AppArmorError) as exc:
        guard.replace_profile("app", "v2", expect_generation=0)
    assert exc.value.code == "APPARMOR_STALE_GENERATION"
    state = guard.state("app")
    assert state["body"] == "v1"
    assert state["generation"] == 1
    out = guard.replace_profile("app", "v2", expect_generation=1)
    assert out["status"] == "applied"
    assert out["generation"] == 2


def test_switch_to_complain_is_blocked_while_a_pid_is_confined():
    guard = make()
    guard.register_profile("app")
    guard.confine(4242, "app")
    with pytest.raises(apg.AppArmorError) as exc:
        guard.switch_mode("app", "complain")
    assert exc.value.code == "APPARMOR_BUSY"
    assert guard.state("app")["mode"] == "enforce"
    guard.release(4242)
    out = guard.switch_mode("app", "complain")
    assert out["status"] == "applied"
    assert guard.state("app")["mode"] == "complain"
    assert guard.state("app")["generation"] == 1


def test_rollback_restores_body_and_uses_a_fresh_generation():
    guard = make()
    guard.register_profile("app", body="v0")
    guard.load_profile("app", "v1")
    guard.load_profile("app", "v2")
    with pytest.raises(apg.AppArmorError) as exc:
        guard.rollback("app", 99)
    assert exc.value.code == "APPARMOR_UNKNOWN_GENERATION"
    out = guard.rollback("app", 1)
    assert out["status"] == "rolled_back"
    assert out["generation"] == 3
    state = guard.state("app")
    assert state["body"] == "v1"
    assert state["generation"] == 3
    same = guard.rollback("app", 3)
    assert same["status"] == "unchanged"


def test_attach_conflict_rejects_whole_registration():
    guard = make()
    guard.register_profile("first", attachments=("/usr/bin/foo",))
    with pytest.raises(apg.AppArmorError) as exc:
        guard.register_profile("second",
                               attachments=("/usr/bin/foo", "/usr/bin/bar"))
    assert exc.value.code == "APPARMOR_ATTACH_CONFLICT"
    assert sorted(guard.snapshot()["profiles"]) == ["first"]
    out = guard.register_profile("second", attachments=("/usr/bin/bar",))
    assert out["status"] == "registered"
    assert sorted(guard.snapshot()["profiles"]) == ["first", "second"]


def test_attach_and_detach_are_idempotent_then_reject_unknown():
    guard = make()
    guard.register_profile("app")
    first = guard.attach("app", "/usr/bin/tool")
    assert first["status"] == "attached"
    again = guard.attach("app", "/usr/bin/tool")
    assert again["status"] == "unchanged"
    assert guard.state("app")["attachments"] == ["/usr/bin/tool"]
    out = guard.detach("app", "/usr/bin/tool")
    assert out["status"] == "detached"
    assert guard.state("app")["attachments"] == []
    with pytest.raises(apg.AppArmorError) as exc:
        guard.detach("app", "/usr/bin/tool")
    assert exc.value.code == "APPARMOR_ATTACH_UNKNOWN"


def test_profile_cap_rejects_extra_profile_without_state_change():
    guard = make(max_profiles=2)
    guard.register_profile("one")
    guard.register_profile("two")
    with pytest.raises(apg.AppArmorError) as exc:
        guard.register_profile("three")
    assert exc.value.code == "APPARMOR_LIMIT"
    assert sorted(guard.snapshot()["profiles"]) == ["one", "two"]


def test_audit_ring_keeps_only_the_most_recent_entries():
    guard = make(max_audit=5)
    guard.register_profile("app")
    guard.load_profile("app", "v1")
    guard.load_profile("app", "v2")
    guard.switch_mode("app", "complain")
    guard.switch_mode("app", "enforce")
    guard.attach("app", "/usr/bin/x")
    guard.detach("app", "/usr/bin/x")
    rows = guard.audit()
    assert [row["seq"] for row in rows] == [3, 4, 5, 6, 7]
    assert [row["action"] for row in rows] == [
        "load", "mode", "mode", "attach", "detach"
    ]
    tail = guard.audit(2)
    assert [row["seq"] for row in tail] == [6, 7]


def test_confine_release_and_duplicate_confinement():
    guard = make()
    guard.register_profile("app")
    out = guard.confine(100, "app")
    assert out["confined"] == 1
    with pytest.raises(apg.AppArmorError) as exc:
        guard.confine(100, "app")
    assert exc.value.code == "APPARMOR_PID_CONFINED"
    released = guard.release(100)
    assert released["confined"] == 0
    assert guard.state("app")["confined"] == 0
    with pytest.raises(apg.AppArmorError) as exc:
        guard.release(100)
    assert exc.value.code == "APPARMOR_PID_UNKNOWN"


def test_hat_stack_depth_limit_and_empty_exit():
    guard = make(max_hat_depth=3)
    guard.register_profile("app")
    guard.confine(7, "app")
    assert guard.enter_hat(7, "a")["depth"] == 1
    assert guard.enter_hat(7, "b")["depth"] == 2
    assert guard.enter_hat(7, "c")["depth"] == 3
    assert guard.enter_hat(7, "c")["status"] == "unchanged"
    with pytest.raises(apg.AppArmorError) as exc:
        guard.enter_hat(7, "d")
    assert exc.value.code == "APPARMOR_HAT_DEPTH"
    assert guard.exit_hat(7)["hat"] == "c"
    assert guard.exit_hat(7)["hat"] == "b"
    assert guard.exit_hat(7)["hat"] == "a"
    with pytest.raises(apg.AppArmorError) as exc:
        guard.exit_hat(7)
    assert exc.value.code == "APPARMOR_HAT_EMPTY"
    with pytest.raises(apg.AppArmorError) as exc:
        guard.enter_hat(8, "a")
    assert exc.value.code == "APPARMOR_PID_UNCONFINED"


def test_snapshot_is_isolated_and_restore_rolls_back_every_table():
    guard = make()
    guard.register_profile("app", body="v1", attachments=("/usr/bin/a",))
    snap = guard.snapshot()
    guard.load_profile("app", "v2")
    guard.attach("app", "/usr/bin/b")
    guard.confine(9, "app")
    assert guard.state("app")["body"] == "v2"
    out = guard.restore(snap)
    assert out["status"] == "restored"
    state = guard.state("app")
    assert state["body"] == "v1"
    assert state["generation"] == 0
    assert state["attachments"] == ["/usr/bin/a"]
    assert state["confined"] == 0
    assert guard.snapshot()["audit_seq"] == snap["audit_seq"]
    assert snap["profiles"]["app"]["body"] == "v1"


def test_concurrent_replace_has_exactly_one_winner():
    guard = make()
    guard.register_profile("app")
    barrier = threading.Barrier(6)
    results = []
    lock = threading.Lock()

    def worker(body):
        barrier.wait()
        try:
            out = guard.replace_profile("app", body, expect_generation=0)
            with lock:
                results.append(("ok", body, out["generation"]))
        except apg.AppArmorError as error:
            with lock:
                results.append((error.code, body, None))

    threads = [threading.Thread(target=worker, args=(f"body-{i}",))
               for i in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    winners = [row for row in results if row[0] == "ok"]
    stale = [row for row in results if row[0] == "APPARMOR_STALE_GENERATION"]
    assert len(winners) == 1
    assert len(stale) == 5
    assert winners[0][2] == 1
    assert guard.state("app")["body"] == winners[0][1]
    assert guard.state("app")["generation"] == 1


def test_malformed_snapshot_is_rejected_without_mutation():
    guard = make()
    guard.register_profile("app")
    with pytest.raises(apg.AppArmorError) as exc:
        guard.restore({"version": 1})
    assert exc.value.code == "APPARMOR_SNAPSHOT_INVALID"
    assert sorted(guard.snapshot()["profiles"]) == ["app"]
