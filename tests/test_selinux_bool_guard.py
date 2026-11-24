import threading

import pytest

import selinux_bool_guard as sbg


def make(**kwargs):
    return sbg.SelinuxGuard(**kwargs)


def test_define_boolean_defaults_and_persistent_lookup():
    guard = make()
    out = guard.define_boolean("alpha")
    assert out["status"] == "defined"
    info = guard.get_boolean("alpha")
    assert info["value"] is False
    assert info["pending"] is None
    assert info["policy_version"] == 0
    with pytest.raises(sbg.SelinuxError) as exc:
        guard.get_boolean("alpha", persistent=True)
    assert exc.value.code == "SELINUX_NOT_PERSISTENT"
    guard.define_boolean("beta", default=True, persistent=True)
    assert guard.get_boolean("beta", persistent=True)["value"] is True


def test_duplicate_and_bad_declarations_are_rejected():
    guard = make()
    guard.define_boolean("alpha")
    with pytest.raises(sbg.SelinuxError) as exc:
        guard.define_boolean("alpha")
    assert exc.value.code == "SELINUX_DUP_BOOLEAN"
    with pytest.raises(sbg.SelinuxError) as exc:
        guard.get_boolean("missing")
    assert exc.value.code == "SELINUX_UNKNOWN_BOOLEAN"
    with pytest.raises(sbg.SelinuxError) as exc:
        guard.define_boolean("child", requires=("missing", True))
    assert exc.value.code == "SELINUX_UNKNOWN_BOOLEAN"
    with pytest.raises(sbg.SelinuxError) as exc:
        guard.define_boolean("selfref", requires=("selfref", True))
    assert exc.value.code == "SELINUX_DEPENDENCY_CYCLE"


def test_boolean_changes_stay_pending_until_commit():
    guard = make()
    guard.define_boolean("alpha")
    guard.define_boolean("beta")
    first = guard.set_boolean("alpha", True)
    assert first["status"] == "pending"
    assert guard.set_boolean("beta", True)["status"] == "pending"
    assert guard.get_boolean("alpha")["value"] is False
    assert guard.get_boolean("alpha")["pending"] is True
    rows = guard.pending_changes()
    assert [row["name"] for row in rows] == ["alpha", "beta"]
    assert [row["value"] for row in rows] == [True, True]
    out = guard.commit()
    assert out["status"] == "applied"
    assert out["count"] == 2
    assert out["changed"] == ["alpha", "beta"]
    assert out["policy_version"] == 1
    assert guard.pending_changes() == []
    assert guard.get_boolean("beta")["value"] is True


def test_setting_current_value_is_unchanged_and_policy_version_is_checked():
    guard = make()
    guard.define_boolean("flag", default=True)
    out = guard.set_boolean("flag", True)
    assert out["status"] == "unchanged"
    assert guard.pending_changes() == []
    empty = guard.commit()
    assert empty["status"] == "empty"
    assert empty["policy_version"] == 0
    with pytest.raises(sbg.SelinuxError) as exc:
        guard.commit(policy_version=3)
    assert exc.value.code == "SELINUX_POLICY_MISMATCH"


def test_setting_back_to_committed_value_cancels_the_pending_change():
    guard = make()
    guard.define_boolean("flag")
    assert guard.set_boolean("flag", True)["status"] == "pending"
    out = guard.set_boolean("flag", False)
    assert out["status"] == "cancelled"
    assert out["pending"] is None
    assert guard.pending_changes() == []
    assert guard.commit()["status"] == "empty"
    assert guard.get_boolean("flag")["pending"] is None


def test_repeated_stage_does_not_duplicate_the_pending_entry():
    guard = make()
    guard.define_boolean("flag")
    guard.set_boolean("flag", True)
    again = guard.set_boolean("flag", True)
    assert again["status"] == "pending"
    assert len(guard.pending_changes()) == 1
    out = guard.commit()
    assert out["count"] == 1
    assert out["policy_version"] == 1
    assert guard.get_boolean("flag")["value"] is True


def test_abort_discards_pending_without_bumping_policy_version():
    guard = make()
    guard.define_boolean("alpha")
    guard.define_boolean("beta")
    guard.set_boolean("alpha", True)
    guard.set_boolean("beta", True)
    out = guard.abort()
    assert out["status"] == "aborted"
    assert out["count"] == 2
    assert out["policy_version"] == 0
    assert guard.pending_changes() == []
    assert guard.get_boolean("alpha")["value"] is False
    assert guard.commit()["status"] == "empty"


def test_dependency_violation_rejects_the_whole_commit_atomically():
    guard = make()
    guard.define_boolean("parent")
    guard.define_boolean("child", requires=("parent", True))
    guard.set_boolean("child", True)
    with pytest.raises(sbg.SelinuxError) as exc:
        guard.commit()
    assert exc.value.code == "SELINUX_DEPENDENCY_UNMET"
    assert exc.value.detail == ["child"]
    assert guard.get_boolean("child")["value"] is False
    assert len(guard.pending_changes()) == 1
    assert guard.get_boolean("child")["policy_version"] == 0
    guard.set_boolean("parent", True)
    out = guard.commit()
    assert out["status"] == "applied"
    assert out["count"] == 2
    assert guard.get_boolean("child")["value"] is True
    guard.set_boolean("parent", False)
    with pytest.raises(sbg.SelinuxError) as exc:
        guard.commit()
    assert exc.value.code == "SELINUX_DEPENDENCY_UNMET"
    guard.abort()
    assert guard.get_boolean("parent")["value"] is True


def test_boolean_cap_rejects_extra_declaration():
    guard = make(max_booleans=2)
    guard.define_boolean("one")
    guard.define_boolean("two")
    with pytest.raises(sbg.SelinuxError) as exc:
        guard.define_boolean("three")
    assert exc.value.code == "SELINUX_LIMIT"
    assert sorted(guard.snapshot()["booleans"]) == ["one", "two"]


def test_disabled_mode_blocks_boolean_writes_and_pending_blocks_disable():
    guard = make()
    guard.define_boolean("flag")
    guard.set_boolean("flag", True)
    with pytest.raises(sbg.SelinuxError) as exc:
        guard.set_mode("disabled")
    assert exc.value.code == "SELINUX_BUSY"
    assert guard.commit()["count"] == 1
    assert guard.set_mode("disabled")["status"] == "applied"
    assert guard.mode() == "disabled"
    with pytest.raises(sbg.SelinuxError) as exc:
        guard.set_boolean("flag", False)
    assert exc.value.code == "SELINUX_DISABLED"
    with pytest.raises(sbg.SelinuxError) as exc:
        guard.commit()
    assert exc.value.code == "SELINUX_DISABLED"
    assert guard.set_mode("enforcing")["status"] == "applied"
    guard.set_boolean("flag", False)
    assert guard.commit()["policy_version"] == 2


def test_mode_transitions_reject_invalid_and_repeat_values():
    guard = make()
    assert guard.set_mode("permissive")["status"] == "applied"
    same = guard.set_mode("permissive")
    assert same["status"] == "unchanged"
    with pytest.raises(sbg.SelinuxError) as exc:
        guard.set_mode("disabled-typo")
    assert exc.value.code == "SELINUX_MODE_INVALID"
    assert guard.mode() == "permissive"


def test_context_priority_wins_over_path_length():
    guard = make()
    with pytest.raises(sbg.SelinuxError) as exc:
        guard.resolve_context("/srv/data")
    assert exc.value.code == "SELINUX_CONTEXT_UNKNOWN"
    guard.add_context_rule("/", "ctx_root", priority=50)
    guard.add_context_rule("/srv", "ctx_default", priority=100)
    out = guard.resolve_context("/srv/data")
    assert out["context"] == "ctx_default"
    assert out["rule_path"] == "/srv"
    guard.add_context_rule("/srv", "ctx_high", priority=200)
    out = guard.resolve_context("/srv/data")
    assert out["context"] == "ctx_high"
    assert out["matched"] == "priority"


def test_context_longest_path_tiebreak_and_conflict():
    guard = make()
    guard.add_context_rule("/srv", "ctx_a", priority=100)
    guard.add_context_rule("/srv/secret", "ctx_b", priority=100)
    out = guard.resolve_context("/srv/secret/file")
    assert out["context"] == "ctx_b"
    assert out["matched"] == "longest_path"
    exact = guard.resolve_context("/srv/secret")
    assert exact["context"] == "ctx_b"
    assert exact["matched"] == "exact"
    guard.add_context_rule("/srv/secret", "ctx_c", priority=100)
    with pytest.raises(sbg.SelinuxError) as exc:
        guard.resolve_context("/srv/secret/file")
    assert exc.value.code == "SELINUX_CONTEXT_CONFLICT"


def test_relabel_and_snapshot_restore_keep_labels_and_rules():
    guard = make()
    guard.add_context_rule("/srv", "ctx_default")
    assert guard.label_of("/srv/a")["context"] == "ctx_default"
    out = guard.relabel("/srv/a", "custom_t")
    assert out["previous"] is None
    assert guard.label_of("/srv/a") == {"path": "/srv/a",
                                        "context": "custom_t",
                                        "source": "relabel"}
    with pytest.raises(sbg.SelinuxError) as exc:
        guard.relabel("/var/none", "other_t")
    assert exc.value.code == "SELINUX_CONTEXT_UNKNOWN"
    guard.define_boolean("flag")
    guard.set_boolean("flag", True)
    snap = guard.snapshot()
    guard.relabel("/srv/a", "changed_t")
    guard.add_context_rule("/var", "var_t")
    restored = guard.restore(snap)
    assert restored["status"] == "restored"
    assert guard.label_of("/srv/a")["context"] == "custom_t"
    assert guard.pending_changes() == [{"name": "flag", "value": True,
                                       "write_persistent": False}]
    assert len(guard.snapshot()["context_rules"]) == 1
    with pytest.raises(sbg.SelinuxError) as exc:
        guard.restore({"version": 1})
    assert exc.value.code == "SELINUX_SNAPSHOT_INVALID"
    assert guard.label_of("/srv/a")["context"] == "custom_t"


def test_concurrent_commits_apply_pending_changes_once():
    guard = make()
    guard.define_boolean("flag")
    guard.set_boolean("flag", True)
    barrier = threading.Barrier(2)
    results = []
    lock = threading.Lock()

    def worker():
        barrier.wait()
        out = guard.commit()
        with lock:
            results.append(out)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(row["status"] for row in results) == ["applied", "empty"]
    assert [row["policy_version"] for row in results] == [1, 1]
    assert guard.get_boolean("flag")["value"] is True
    assert guard.pending_changes() == []
