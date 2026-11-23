import hashlib
import threading
from datetime import date, datetime, timedelta, timezone

import pytest

import guild_bank_guard as gb

T0 = datetime(2026, 11, 23, 10, 0, 0, tzinfo=timezone.utc)
DAY = date(2026, 11, 23)


def make(quota=50, capacity=100):
    guard = gb.GuildBankGuard(gb.BankConfig(daily_quota=quota, ledger_capacity=capacity))
    guard.add_member(gb.Member("alice", gb.Rank.OFFICER))
    guard.add_member(gb.Member("bob", gb.Rank.MEMBER))
    guard.create_tab(0, gb.Rank.MEMBER)
    guard.create_tab(1, gb.Rank.OFFICER)
    return guard


def item_hash(prev, op_id, member, tab_index, item_id, count):
    raw = "|".join([prev, op_id, member, str(tab_index), item_id, str(count)])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def test_deposit_updates_stock_and_appends_ledger_row():
    g = make()
    entry = g.deposit("op-1", "alice", 0, gb.Item("ore", 5), T0)
    assert entry.seq == 1
    assert entry.kind == "deposit"
    assert entry.member == "alice"
    assert entry.tab_index == 0
    assert entry.item_id == "ore"
    assert entry.count == 5
    assert entry.at == T0
    assert g.tab_contents(0) == [gb.Item("ore", 5)]
    assert len(g.ledger()) == 1


def test_duplicate_op_id_is_checked_before_everything_else():
    g = make()
    g.deposit("op-1", "alice", 0, gb.Item("ore", 5), T0)
    with pytest.raises(gb.GuildBankError) as exc:
        g.deposit("op-1", "ghost", 9, gb.Item("ore", 1), T0)
    assert exc.value.code == gb.ERR_DUPLICATE_OP
    with pytest.raises(gb.GuildBankError) as exc:
        g.withdraw("op-1", "ghost", 9, "ore", 1, T0)
    assert exc.value.code == gb.ERR_DUPLICATE_OP
    assert g.tab_contents(0) == [gb.Item("ore", 5)]
    assert len(g.ledger()) == 1


def test_rank_below_tab_requirement_is_denied_in_both_directions():
    g = make()
    with pytest.raises(gb.GuildBankError) as exc:
        g.deposit("d1", "bob", 1, gb.Item("ore", 2), T0)
    assert exc.value.code == gb.ERR_RANK_DENIED
    with pytest.raises(gb.GuildBankError) as exc:
        g.withdraw("w1", "bob", 1, "ore", 1, T0)
    assert exc.value.code == gb.ERR_RANK_DENIED
    assert g.ledger() == []
    assert g.tab_contents(1) == []


def test_unknown_member_tab_and_duplicate_registrations():
    g = make()
    with pytest.raises(gb.GuildBankError) as exc:
        g.deposit("d1", "ghost", 0, gb.Item("ore", 1), T0)
    assert exc.value.code == gb.ERR_UNKNOWN_MEMBER
    with pytest.raises(gb.GuildBankError) as exc:
        g.deposit("d2", "alice", 7, gb.Item("ore", 1), T0)
    assert exc.value.code == gb.ERR_UNKNOWN_TAB
    with pytest.raises(gb.GuildBankError) as exc:
        g.add_member(gb.Member("alice", gb.Rank.GUILD_MASTER))
    assert exc.value.code == gb.ERR_MEMBER_EXISTS
    with pytest.raises(gb.GuildBankError) as exc:
        g.create_tab(0, gb.Rank.MEMBER)
    assert exc.value.code == gb.ERR_TAB_EXISTS


def test_locked_tab_refuses_deposit_and_withdraw():
    g = make()
    g.deposit("d1", "alice", 0, gb.Item("ore", 5), T0)
    g.lock_tab(0)
    with pytest.raises(gb.GuildBankError) as exc:
        g.deposit("d2", "alice", 0, gb.Item("ore", 1), T0)
    assert exc.value.code == gb.ERR_TAB_LOCKED
    with pytest.raises(gb.GuildBankError) as exc:
        g.withdraw("w1", "alice", 0, "ore", 1, T0)
    assert exc.value.code == gb.ERR_TAB_LOCKED
    assert g.tab_contents(0) == [gb.Item("ore", 5)]
    assert len(g.ledger()) == 1


def test_non_positive_counts_are_rejected_without_state_change():
    g = make()
    for bad in (0, -3):
        with pytest.raises(gb.GuildBankError) as exc:
            g.deposit("d", "alice", 0, gb.Item("ore", bad), T0)
        assert exc.value.code == gb.ERR_INVALID_COUNT
        with pytest.raises(gb.GuildBankError) as exc:
            g.withdraw("w", "alice", 0, "ore", bad, T0)
        assert exc.value.code == gb.ERR_INVALID_COUNT
    assert g.ledger() == []
    assert g.tab_contents(0) == []


def test_withdraw_beyond_stock_keeps_stock_and_quota():
    g = make()
    g.deposit("d1", "alice", 0, gb.Item("ore", 3), T0)
    with pytest.raises(gb.GuildBankError) as exc:
        g.withdraw("w1", "alice", 0, "ore", 5, T0)
    assert exc.value.code == gb.ERR_INSUFFICIENT
    assert g.tab_contents(0) == [gb.Item("ore", 3)]
    assert g.daily_total("alice", DAY) == 0
    assert len(g.ledger()) == 1


def test_daily_quota_accumulates_per_member_and_utc_day():
    g = make(quota=5)
    g.deposit("d1", "alice", 0, gb.Item("ore", 100), T0)
    g.withdraw("w1", "alice", 0, "ore", 3, T0)
    g.withdraw("w2", "alice", 0, "ore", 2, T0 + timedelta(hours=1))
    assert g.daily_total("alice", DAY) == 5
    with pytest.raises(gb.GuildBankError) as exc:
        g.withdraw("w3", "alice", 0, "ore", 1, T0 + timedelta(hours=2))
    assert exc.value.code == gb.ERR_QUOTA_EXCEEDED
    assert g.daily_total("alice", DAY) == 5
    # 2026-11-24T02:00+08:00 is still 2026-11-23 in UTC, so the same budget.
    with pytest.raises(gb.GuildBankError) as exc:
        g.withdraw("w4", "alice", 0, "ore", 1, datetime(
            2026, 11, 24, 2, 0, tzinfo=timezone(timedelta(hours=8))))
    assert exc.value.code == gb.ERR_QUOTA_EXCEEDED
    later = datetime(2026, 11, 24, 0, 30, tzinfo=timezone.utc)
    g.withdraw("w5", "alice", 0, "ore", 5, later)
    assert g.daily_total("alice", date(2026, 11, 24)) == 5
    assert g.daily_total("bob", date(2026, 11, 24)) == 0


def test_deposit_merges_stacks_in_place_and_empty_stack_disappears():
    g = make()
    g.deposit("d1", "alice", 0, gb.Item("ore", 2), T0)
    g.deposit("d2", "alice", 0, gb.Item("wood", 1), T0)
    g.deposit("d3", "alice", 0, gb.Item("ore", 3), T0)
    assert g.tab_contents(0) == [gb.Item("ore", 5), gb.Item("wood", 1)]
    g.withdraw("w1", "alice", 0, "ore", 5, T0)
    assert g.tab_contents(0) == [gb.Item("wood", 1)]


def test_ledger_hashes_chain_in_sequence_order():
    g = make()
    first = g.deposit("op-1", "alice", 0, gb.Item("ore", 2), T0)
    second = g.withdraw("op-2", "alice", 0, "ore", 1, T0)
    assert first.seq == 1 and second.seq == 2
    assert first.prev_hash == gb.GENESIS_HASH
    assert first.entry_hash == item_hash(
        gb.GENESIS_HASH, "op-1", "alice", 0, "ore", 2)
    assert second.prev_hash == first.entry_hash
    assert second.entry_hash == item_hash(
        first.entry_hash, "op-2", "alice", 0, "ore", 1)
    assert g.verify_chain() is True


def test_ledger_capacity_blocks_state_changes():
    g = make(capacity=2)
    g.deposit("d1", "alice", 0, gb.Item("ore", 1), T0)
    g.deposit("d2", "alice", 0, gb.Item("ore", 2), T0)
    with pytest.raises(gb.GuildBankError) as exc:
        g.deposit("d3", "alice", 0, gb.Item("ore", 4), T0)
    assert exc.value.code == gb.ERR_LEDGER_FULL
    assert g.tab_contents(0) == [gb.Item("ore", 3)]
    assert len(g.ledger()) == 2


def test_snapshot_restore_keeps_chain_dedupe_and_quota():
    g = make(quota=20)
    g.create_tab(2, gb.Rank.GUILD_MASTER)
    g.deposit("d1", "alice", 0, gb.Item("ore", 6), T0)
    g.withdraw("w1", "alice", 0, "ore", 2, T0)
    blob = g.snapshot()
    assert isinstance(blob, bytes)
    restored = gb.GuildBankGuard.from_snapshot(
        gb.BankConfig(daily_quota=20, ledger_capacity=100), blob)
    assert restored.verify_chain() is True
    assert [e.entry_hash for e in restored.ledger()] == [
        e.entry_hash for e in g.ledger()]
    assert restored.tab_contents(0) == [gb.Item("ore", 4)]
    assert restored.daily_total("alice", DAY) == 2
    with pytest.raises(gb.GuildBankError) as exc:
        restored.deposit("w1", "alice", 0, gb.Item("ore", 1), T0)
    assert exc.value.code == gb.ERR_DUPLICATE_OP
    nxt = restored.deposit("d2", "bob", 0, gb.Item("wood", 3), T0)
    assert nxt.seq == 3
    assert nxt.prev_hash == g.ledger()[-1].entry_hash
    assert restored.verify_chain() is True


def test_concurrent_withdrawals_never_oversell():
    g = make(quota=100, capacity=100)
    g.deposit("seed", "alice", 0, gb.Item("gem", 4), T0)
    barrier = threading.Barrier(12)
    results = []
    results_lock = threading.Lock()

    def worker(i):
        barrier.wait(timeout=10)
        try:
            g.withdraw("w-%d" % i, "alice", 0, "gem", 1, T0)
            code = "ok"
        except gb.GuildBankError as exc:
            code = exc.code
        with results_lock:
            results.append(code)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(12)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=20)
    assert len(results) == 12
    assert results.count("ok") == 4
    assert results.count(gb.ERR_INSUFFICIENT) == 8
    assert g.tab_contents(0) == []
    assert [e.kind for e in g.ledger()].count("withdraw") == 4
    assert g.daily_total("alice", DAY) == 4


def test_query_results_are_copies():
    g = make()
    g.deposit("d1", "alice", 0, gb.Item("ore", 2), T0)
    rows = g.ledger()
    rows.clear()
    assert len(g.ledger()) == 1
    stacks = g.tab_contents(0)
    stacks.append(gb.Item("fake", 99))
    assert stacks != g.tab_contents(0)
    assert g.tab_contents(0) == [gb.Item("ore", 2)]


def test_failed_withdraw_consumes_no_quota_and_writes_no_row():
    g = make(quota=5)
    g.deposit("d1", "alice", 0, gb.Item("ore", 5), T0)
    with pytest.raises(gb.GuildBankError) as exc:
        g.withdraw("w1", "alice", 0, "ore", 6, T0)
    assert exc.value.code == gb.ERR_INSUFFICIENT
    assert g.daily_total("alice", DAY) == 0
    entry = g.withdraw("w2", "alice", 0, "ore", 5, T0)
    assert entry.kind == gb.KIND_WITHDRAW
    assert [e.kind for e in g.ledger()] == ["deposit", "withdraw"]
    assert g.tab_contents(0) == []
