import json
import threading

import pytest

import loot_distribution_guard as loot

T0 = "2026-11-23T10:00:00+00:00"


def make_raid(players=("p1", "p2")):
    d = loot.LootDistributor()
    d.open_raid("raid-1", now=T0)
    for player in players:
        d.add_player("raid-1", player, need_score=0)
    return d


def add_drop(d, drop_id="d1", item_id="sword", qty=1, tradeable=True):
    return d.add_drop("raid-1", drop_id,
                      [{"item_id": item_id, "qty": qty, "tradeable": tradeable}],
                      now=T0)


def test_need_claim_beats_higher_greed_roll():
    d = make_raid()
    add_drop(d)
    d.claim("raid-1", "d1", "sword", "p1", mode="need", roll=10, now=T0)
    d.claim("raid-1", "d1", "sword", "p2", mode="greed", roll=95, now=T0)
    out = d.resolve("raid-1", "d1", "sword", now=T0)
    assert out["status"] == "awarded"
    assert out["winners"] == ["p1"]
    assert d.inventory("p1")[0]["item_id"] == "sword"
    assert d.inventory("p2") == []


def test_higher_roll_wins_within_the_same_mode():
    d = make_raid()
    add_drop(d)
    d.claim("raid-1", "d1", "sword", "p1", mode="need", roll=40, now=T0)
    d.claim("raid-1", "d1", "sword", "p2", mode="need", roll=90, now=T0)
    out = d.resolve("raid-1", "d1", "sword", now=T0)
    assert out["winners"] == ["p2"]


def test_roll_tie_goes_to_higher_need_score():
    d = loot.LootDistributor()
    d.open_raid("raid-1", now=T0)
    d.add_player("raid-1", "p1", need_score=5)
    d.add_player("raid-1", "p2", need_score=9)
    add_drop(d)
    d.claim("raid-1", "d1", "sword", "p1", mode="need", roll=50, now=T0)
    d.claim("raid-1", "d1", "sword", "p2", mode="need", roll=50, now=T0)
    out = d.resolve("raid-1", "d1", "sword", now=T0)
    assert out["winners"] == ["p2"]


def test_full_tie_is_broken_by_player_id_ascending():
    d = make_raid(players=("beta", "alpha"))
    add_drop(d)
    d.claim("raid-1", "d1", "sword", "beta", mode="need", roll=50, now=T0)
    d.claim("raid-1", "d1", "sword", "alpha", mode="need", roll=50, now=T0)
    out = d.resolve("raid-1", "d1", "sword", now=T0)
    assert out["winners"] == ["alpha"]


def test_duplicate_and_unknown_claims_are_rejected():
    d = make_raid()
    add_drop(d)
    d.claim("raid-1", "d1", "sword", "p1", mode="need", roll=50, now=T0)
    with pytest.raises(loot.LootError) as exc:
        d.claim("raid-1", "d1", "sword", "p1", mode="greed", roll=99, now=T0)
    assert exc.value.code == "LOOT_DUP_CLAIM"
    with pytest.raises(loot.LootError) as exc:
        d.claim("raid-1", "d1", "sword", "ghost", mode="need", roll=50, now=T0)
    assert exc.value.code == "LOOT_UNKNOWN_PLAYER"
    with pytest.raises(loot.LootError) as exc:
        d.claim("raid-1", "d1", "sword", "p2", mode="need", roll=0, now=T0)
    assert exc.value.code == "LOOT_BAD_ROLL"
    assert len(d.unclaimed("raid-1")) == 1


def test_multiple_copies_go_to_top_winners_in_order():
    d = make_raid(players=("p1", "p2", "p3"))
    add_drop(d, qty=2)
    d.claim("raid-1", "d1", "sword", "p1", mode="need", roll=90, now=T0)
    d.claim("raid-1", "d1", "sword", "p2", mode="greed", roll=95, now=T0)
    d.claim("raid-1", "d1", "sword", "p3", mode="need", roll=80, now=T0)
    out = d.resolve("raid-1", "d1", "sword", now=T0)
    assert out["winners"] == ["p1", "p3"]
    assert len(out["copies"]) == 2
    assert d.inventory("p2") == []


def test_resolve_without_any_claim_is_rejected():
    d = make_raid()
    add_drop(d)
    with pytest.raises(loot.LootError) as exc:
        d.resolve("raid-1", "d1", "sword", now=T0)
    assert exc.value.code == "LOOT_NO_CLAIM"
    assert d.unclaimed("raid-1") == [{"drop_id": "d1", "item_id": "sword"}]


def test_claims_close_after_the_five_minute_window():
    d = make_raid()
    add_drop(d)
    late = d.claim("raid-1", "d1", "sword", "p1", mode="need", roll=50,
                   now="2026-11-23T10:05:00+00:00")
    assert late["status"] == "claimed"
    with pytest.raises(loot.LootError) as exc:
        d.claim("raid-1", "d1", "sword", "p2", mode="greed", roll=99,
                now="2026-11-23T10:05:01+00:00")
    assert exc.value.code == "LOOT_DROP_EXPIRED"


def test_resolving_twice_replays_the_same_award():
    d = make_raid()
    add_drop(d)
    d.claim("raid-1", "d1", "sword", "p1", mode="need", roll=50, now=T0)
    first = d.resolve("raid-1", "d1", "sword", now=T0)
    second = d.resolve("raid-1", "d1", "sword",
                       now="2026-11-23T10:02:00+00:00")
    assert second["status"] == "replayed"
    assert second["winners"] == first["winners"]
    assert second["copies"] == first["copies"]
    assert len(d.inventory("p1")) == 1
    with pytest.raises(loot.LootError) as exc:
        d.claim("raid-1", "d1", "sword", "p2", mode="need", roll=99, now=T0)
    assert exc.value.code == "LOOT_ITEM_RESOLVED"


def test_master_override_budget_is_limited_per_raid():
    d = make_raid()
    for index in (1, 2, 3):
        add_drop(d, drop_id=f"d{index}", item_id=f"item{index}")
    first = d.award("raid-1", "d1", "item1", "p1", reason="tank priority", now=T0)
    assert first["override"] is True
    d.award("raid-1", "d2", "item2", "p2", reason="healer priority", now=T0)
    assert d.ledger("raid-1")["overrides"] == 2
    with pytest.raises(loot.LootError) as exc:
        d.award("raid-1", "d3", "item3", "p1", reason="one more", now=T0)
    assert exc.value.code == "LOOT_OVERRIDE_EXHAUSTED"
    assert d.inventory("p1")[0]["item_id"] == "item1"


def test_trade_moves_the_copy_to_another_player():
    d = make_raid()
    add_drop(d)
    d.claim("raid-1", "d1", "sword", "p1", mode="need", roll=60, now=T0)
    copy_id = d.resolve("raid-1", "d1", "sword", now=T0)["copies"][0]["copy_id"]
    out = d.trade("p1", "p2", copy_id, now="2026-11-23T10:01:00+00:00")
    assert out["status"] == "traded"
    assert d.inventory("p1") == []
    assert d.inventory("p2")[0]["copy_id"] == copy_id
    with pytest.raises(loot.LootError) as exc:
        d.trade("p1", "p2", copy_id, now="2026-11-23T10:01:30+00:00")
    assert exc.value.code == "LOOT_NOT_OWNER"


def test_bound_copy_cannot_be_traded():
    d = make_raid()
    add_drop(d)
    d.claim("raid-1", "d1", "sword", "p1", mode="need", roll=60, now=T0)
    copy_id = d.resolve("raid-1", "d1", "sword", now=T0)["copies"][0]["copy_id"]
    d.bind("p1", copy_id)
    with pytest.raises(loot.LootError) as exc:
        d.trade("p1", "p2", copy_id, now="2026-11-23T10:01:00+00:00")
    assert exc.value.code == "LOOT_ITEM_BOUND"
    assert d.inventory("p1")[0]["bound"] is True


def test_trade_window_closes_after_thirty_minutes():
    d = make_raid()
    add_drop(d, qty=2)
    d.claim("raid-1", "d1", "sword", "p1", mode="need", roll=90, now=T0)
    d.claim("raid-1", "d1", "sword", "p2", mode="greed", roll=95, now=T0)
    copies = {row["player"]: row["copy_id"]
              for row in d.resolve("raid-1", "d1", "sword", now=T0)["copies"]}
    d.trade("p1", "p2", copies["p1"], now="2026-11-23T10:30:00+00:00")
    with pytest.raises(loot.LootError) as exc:
        d.trade("p2", "p1", copies["p2"], now="2026-11-23T10:30:01+00:00")
    assert exc.value.code == "LOOT_TRADE_WINDOW_CLOSED"


def test_concurrent_resolve_awards_exactly_one_copy():
    d = make_raid()
    add_drop(d)
    d.claim("raid-1", "d1", "sword", "p1", mode="need", roll=70, now=T0)
    outcomes = [None] * 6

    def worker(index, barrier):
        barrier.wait()
        outcomes[index] = d.resolve("raid-1", "d1", "sword", now=T0)

    barrier = threading.Barrier(6)
    threads = [threading.Thread(target=worker, args=(i, barrier)) for i in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    awarded = [row for row in outcomes if row["status"] == "awarded"]
    replayed = [row for row in outcomes if row["status"] == "replayed"]
    assert len(awarded) == 1
    assert len(replayed) == 5
    assert all(row["winners"] == ["p1"] for row in outcomes)
    assert len(d.inventory("p1")) == 1


def test_snapshot_restore_roundtrip_and_bad_snapshot_is_atomic():
    d = make_raid()
    add_drop(d)
    d.claim("raid-1", "d1", "sword", "p1", mode="need", roll=70, now=T0)
    copy_id = d.resolve("raid-1", "d1", "sword", now=T0)["copies"][0]["copy_id"]
    snapshot = d.snapshot()
    json.dumps(snapshot)
    saved_inventory = d.inventory("p1")
    d.trade("p1", "p2", copy_id, now="2026-11-23T10:01:00+00:00")
    restored = loot.LootDistributor()
    restored.restore(snapshot)
    assert restored.inventory("p1") == saved_inventory
    assert restored.ledger("raid-1")["claims"] == 1
    assert restored.ledger("raid-1")["awards"][0]["players"] == ["p1"]
    with pytest.raises(loot.LootError) as exc:
        restored.restore({"version": 2})
    assert exc.value.code == "LOOT_BAD_SNAPSHOT"
    assert restored.inventory("p1") == saved_inventory
