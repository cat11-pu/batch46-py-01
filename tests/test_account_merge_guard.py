import threading

import pytest

import account_merge_guard as tbg


def make(**kwargs):
    return tbg.AccountMerge(**kwargs)


def test_max_strategy_and_duplicate_guards():
    m = make()
    m.register_field("level", strategy="max")
    m.register_field("gold", strategy="sum")
    m.create_account("main", fields={"level": 10, "gold": 100})
    m.create_account("alt", fields={"level": 30, "gold": 50})
    with pytest.raises(tbg.MergeError) as exc:
        m.register_field("level", strategy="max")
    assert exc.value.code == "MERGE_DUP_FIELD"
    with pytest.raises(tbg.MergeError) as exc2:
        m.create_account("main", fields={"level": 1})
    assert exc2.value.code == "MERGE_DUP_ACCOUNT"
    planned = m.plan("mg1", "main", "alt")
    assert planned["status"] == "planned"
    assert planned["preview"]["level"] == 30
    assert planned["preview"]["gold"] == 150


def test_sum_strategy_clamps_at_field_cap():
    m = make()
    m.register_field("gold", strategy="sum", cap=1000)
    m.create_account("main", fields={"gold": 800})
    m.create_account("alt", fields={"gold": 500})
    planned = m.plan("mg1", "main", "alt")
    assert planned["preview"]["gold"] == 1000


def test_primary_strategy_keeps_primary_value():
    m = make()
    m.register_field("server", strategy="primary")
    m.create_account("main", fields={"server": "s1"})
    m.create_account("alt", fields={"server": "s9"})
    planned = m.plan("mg1", "main", "alt")
    assert planned["preview"]["server"] == "s1"


def test_union_strategy_dedupes_in_primary_order():
    m = make()
    m.register_field("friends", strategy="union")
    m.create_account("main", fields={"friends": ["a", "b"]})
    m.create_account("alt", fields={"friends": ["b", "c"]})
    planned = m.plan("mg1", "main", "alt")
    assert planned["preview"]["friends"] == ["a", "b", "c"]


def test_manual_strategy_blocks_apply_until_resolved():
    m = make()
    m.register_field("title", strategy="manual")
    m.create_account("main", fields={"title": "knight"})
    m.create_account("alt", fields={"title": "mage"})
    planned = m.plan("mg1", "main", "alt")
    assert [c["field"] for c in planned["conflicts"]] == ["title"]
    assert planned["conflicts"][0]["primary"] == "knight"
    assert planned["conflicts"][0]["secondary"] == "mage"
    assert m.conflicts("mg1")[0]["field"] == "title"
    with pytest.raises(tbg.MergeError) as exc:
        m.resolve("mg1", "ghost", value=1)
    assert exc.value.code == "MERGE_UNKNOWN_FIELD"
    with pytest.raises(tbg.MergeError) as exc2:
        m.apply("mg1")
    assert exc2.value.code == "MERGE_UNRESOLVED"
    assert m.account("main")["fields"]["title"] == "knight"


def test_resolved_conflict_is_written_and_secondary_archived():
    m = make()
    m.register_field("title", strategy="manual")
    m.create_account("main", fields={"title": "knight"})
    m.create_account("alt", fields={"title": "mage"})
    m.plan("mg1", "main", "alt")
    m.resolve("mg1", "title", value="archmage")
    out = m.apply("mg1")
    assert out["status"] == "applied"
    assert m.account("main")["fields"]["title"] == "archmage"
    alt = m.account("alt")
    assert alt["status"] == "merged"
    assert alt["merged_into"] == "main"


def test_apply_twice_does_not_double_sum():
    m = make()
    m.register_field("gold", strategy="sum")
    m.create_account("main", fields={"gold": 100})
    m.create_account("alt", fields={"gold": 50})
    m.plan("mg1", "main", "alt")
    assert m.apply("mg1")["status"] == "applied"
    second = m.apply("mg1")
    assert second["status"] == "already_applied"
    assert m.account("main")["fields"]["gold"] == 150
    assert m.account("alt")["status"] == "merged"


def test_self_merge_and_unknown_account_are_rejected():
    m = make()
    m.create_account("solo", fields={"gold": 1})
    with pytest.raises(tbg.MergeError) as exc:
        m.plan("mg1", "solo", "solo")
    assert exc.value.code == "MERGE_SELF"
    with pytest.raises(tbg.MergeError) as exc2:
        m.plan("mg2", "solo", "ghost")
    assert exc2.value.code == "MERGE_UNKNOWN_ACCOUNT"


def test_merged_secondary_cannot_be_merged_again():
    m = make()
    m.create_account("main", fields={"gold": 1})
    m.create_account("alt", fields={"gold": 2})
    m.create_account("other", fields={"gold": 3})
    m.plan("mg1", "main", "alt")
    m.apply("mg1")
    with pytest.raises(tbg.MergeError) as exc:
        m.plan("mg2", "other", "alt")
    assert exc.value.code == "MERGE_SECONDARY_MERGED"


def test_cancelled_merge_cannot_be_applied():
    m = make()
    m.create_account("main", fields={"gold": 1})
    m.create_account("alt", fields={"gold": 2})
    m.plan("mg1", "main", "alt")
    out = m.cancel("mg1")
    assert out["status"] == "cancelled"
    with pytest.raises(tbg.MergeError) as exc:
        m.apply("mg1")
    assert exc.value.code == "MERGE_NOT_PLANNED"
    with pytest.raises(tbg.MergeError) as exc2:
        m.cancel("mg1")
    assert exc2.value.code == "MERGE_NOT_PLANNED"


def test_field_limit_blocks_oversized_merge():
    m = make(field_limit=5)
    m.create_account("main", fields={"f1": 1, "f2": 2, "f3": 3, "f4": 4})
    m.create_account("alt", fields={"g1": 1, "g2": 2, "g3": 3, "g4": 4})
    with pytest.raises(tbg.MergeError) as exc:
        m.plan("mg1", "main", "alt")
    assert exc.value.code == "MERGE_FIELD_LIMIT"


def test_conflict_list_is_capped_and_flagged():
    m = make(max_conflicts=2)
    for field in ("m1", "m2", "m3"):
        m.register_field(field, strategy="manual")
    m.create_account("main", fields={"m1": "a", "m2": "b", "m3": "c"})
    m.create_account("alt", fields={"m1": "x", "m2": "y", "m3": "z"})
    planned = m.plan("mg1", "main", "alt")
    assert [c["field"] for c in planned["conflicts"]] == ["m1", "m2"]
    assert planned["conflict_total"] == 3
    assert planned["conflict_truncated"] is True


def test_concurrent_apply_runs_once():
    m = make()
    m.register_field("gold", strategy="sum")
    m.create_account("main", fields={"gold": 100})
    m.create_account("alt", fields={"gold": 50})
    m.plan("mg1", "main", "alt")
    barrier = threading.Barrier(2)
    outcomes = []
    lock = threading.Lock()

    def worker():
        barrier.wait()
        try:
            outcome = m.apply("mg1")["status"]
        except Exception as exc:  # unexpected failures must fail the test
            outcome = type(exc).__name__
        with lock:
            outcomes.append(outcome)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    assert sorted(outcomes) == ["already_applied", "applied"]
    assert m.account("main")["fields"]["gold"] == 150


def test_snapshot_restore_reverts_merge_state():
    m = make()
    m.register_field("gold", strategy="sum")
    m.create_account("main", fields={"gold": 100})
    m.create_account("alt", fields={"gold": 50})
    m.plan("mg1", "main", "alt")
    snap = m.snapshot()
    m.apply("mg1")
    assert m.account("main")["fields"]["gold"] == 150
    out = m.restore(snap)
    assert out["status"] == "restored"
    assert m.account("main")["fields"]["gold"] == 100
    alt = m.account("alt")
    assert alt["status"] == "active"
    assert alt["merged_into"] is None
    again = m.apply("mg1")
    assert again["status"] == "applied"
    assert m.account("main")["fields"]["gold"] == 150


def test_audit_is_bounded_and_account_history_is_ordered():
    m = make(history_limit=3)
    m.create_account("main", fields={"gold": 1})
    m.create_account("alt", fields={"gold": 2})
    m.create_account("third", fields={"gold": 3})
    m.plan("mg1", "main", "alt")
    m.cancel("mg1")
    m.plan("mg2", "main", "third")
    m.cancel("mg2")
    log = m.audit()
    assert len(log) == 3
    assert [(row["action"], row["merge_id"]) for row in log] == [
        ("cancel", "mg2"), ("plan", "mg2"), ("cancel", "mg1")]
    hist = m.history("main")
    assert hist[0]["merge_id"] == "mg2"
    assert len(hist) >= 2
