import threading

import pytest

import season_reward_grant as srg


def make(**kwargs):
    return srg.SeasonReward(**kwargs)


def test_open_season_validates_window_and_reports_status():
    g = make()
    out = g.open_season("s1", starts_at=1000, ends_at=2000, grace=100,
                        name="Season One")
    assert out["season"] == "s1"
    assert out["status"] == "open"
    assert out["grace"] == 100
    with pytest.raises(srg.SeasonRewardError) as exc:
        g.open_season("s1", starts_at=1000, ends_at=2000)
    assert exc.value.code == "SR_SEASON_EXISTS"
    with pytest.raises(srg.SeasonRewardError) as exc:
        g.open_season("bad1", starts_at=2000, ends_at=1000)
    assert exc.value.code == "SR_BAD_WINDOW"
    with pytest.raises(srg.SeasonRewardError) as exc:
        g.open_season("bad2", starts_at=1000, ends_at=2000, grace=-1)
    assert exc.value.code == "SR_BAD_WINDOW"
    assert g.season_state("s1", now=1500)["status"] == "open"
    assert g.season_state("s1", now=2000)["status"] == "open"
    assert g.season_state("s1", now=2001)["status"] == "grace"
    assert g.season_state("s1", now=2101)["status"] == "expired"


def test_define_tier_validates_order_rewards_and_capacity():
    g = make(max_tiers=2)
    g.open_season("s1", starts_at=1000, ends_at=2000)
    g.define_tier("s1", 2, requirement=100, rewards=["gold:50"])
    with pytest.raises(srg.SeasonRewardError) as exc:
        g.define_tier("s1", 1, requirement=200)
    assert exc.value.code == "SR_TIER_ORDER"
    with pytest.raises(srg.SeasonRewardError) as exc:
        g.define_tier("s1", 0, requirement=10)
    assert exc.value.code == "SR_BAD_TIER"
    with pytest.raises(srg.SeasonRewardError) as exc:
        g.define_tier("s1", 1, requirement=10, rewards=["gold"])
    assert exc.value.code == "SR_BAD_REWARD"
    tier1 = g.define_tier("s1", 1, requirement=10, rewards=["frame:1"])
    assert tier1["status"] == "defined"
    assert tier1["rewards"] == ["frame:1"]
    with pytest.raises(srg.SeasonRewardError) as exc:
        g.define_tier("s1", 1, requirement=10)
    assert exc.value.code == "SR_TIER_EXISTS"
    with pytest.raises(srg.SeasonRewardError) as exc:
        g.define_tier("s1", 3, requirement=150)
    assert exc.value.code == "SR_CAPACITY"
    with pytest.raises(srg.SeasonRewardError) as exc:
        g.define_tier("nope", 1, requirement=1)
    assert exc.value.code == "SR_UNKNOWN_SEASON"


def test_grant_points_validates_ledger_and_returns_totals():
    g = make(max_points=100)
    g.open_season("s1", starts_at=1000, ends_at=2000)
    applied = g.grant_points("alice", "s1", 30, event_id="e1", now=1100)
    assert applied["status"] == "applied"
    assert applied["code"] == "SR_POINTS_GRANTED"
    assert applied["points"] == 30
    assert applied["delta"] == 30
    with pytest.raises(srg.SeasonRewardError) as exc:
        g.grant_points("alice", "s1", 0, now=1101)
    assert exc.value.code == "SR_BAD_POINTS"
    with pytest.raises(srg.SeasonRewardError) as exc:
        g.grant_points("alice", "s1", -1, now=1101)
    assert exc.value.code == "SR_BAD_POINTS"
    with pytest.raises(srg.SeasonRewardError) as exc:
        g.grant_points("", "s1", 1, now=1101)
    assert exc.value.code == "SR_BAD_ACCOUNT"
    with pytest.raises(srg.SeasonRewardError) as exc:
        g.grant_points("alice", "nope", 1, now=1101)
    assert exc.value.code == "SR_UNKNOWN_SEASON"
    with pytest.raises(srg.SeasonRewardError) as exc:
        g.grant_points("alice", "s1", 80, event_id="e2", now=1101)
    assert exc.value.code == "SR_POINTS_CAP"
    assert g.points("alice", "s1")["points"] == 30
    assert g.points("bob", "s1") == {
        "account": "bob", "season": "s1", "points": 0, "claimed_tiers": [],
    }


def test_grant_points_respects_season_window():
    g = make()
    g.open_season("s1", starts_at=1000, ends_at=2000)
    with pytest.raises(srg.SeasonRewardError) as exc:
        g.grant_points("alice", "s1", 10, now=999)
    assert exc.value.code == "SR_SEASON_NOT_STARTED"
    assert g.grant_points("alice", "s1", 10,
                          now=1000)["status"] == "applied"
    assert g.grant_points("alice", "s1", 10, now=2000)["points"] == 20
    with pytest.raises(srg.SeasonRewardError) as exc:
        g.grant_points("alice", "s1", 10, now=2001)
    assert exc.value.code == "SR_SEASON_CLOSED"
    assert g.points("alice", "s1")["points"] == 20


def test_duplicate_event_ids_are_deduplicated_per_account_and_season():
    g = make()
    g.open_season("s1", starts_at=1000, ends_at=2000)
    first = g.grant_points("alice", "s1", 10, event_id="evt-1", now=1100)
    assert first["points"] == 10
    duplicate = g.grant_points("alice", "s1", 10, event_id="evt-1",
                               now=1101)
    assert duplicate["status"] == "duplicate"
    assert duplicate["code"] == "SR_DUP_EVENT"
    assert duplicate["points"] == 10
    other = g.grant_points("bob", "s1", 10, event_id="evt-1", now=1102)
    assert other["status"] == "applied"
    assert other["points"] == 10
    assert g.grant_points("alice", "s1", 5, now=1103)["status"] == "applied"
    assert g.grant_points("alice", "s1", 5, now=1104)["status"] == "applied"
    assert g.points("alice", "s1")["points"] == 20


def test_negative_correction_cannot_drop_below_claimed_floor():
    g = make()
    g.open_season("s1", starts_at=1000, ends_at=2000)
    g.define_tier("s1", 1, requirement=100, rewards=["gold:100"])
    g.grant_points("alice", "s1", 100, event_id="a1", now=1100)
    g.claim("alice", "s1", 1, now=1101)
    with pytest.raises(srg.SeasonRewardError) as exc:
        g.grant_points("alice", "s1", -1, reason="correction", now=1102)
    assert exc.value.code == "SR_POINTS_FLOOR"
    assert g.points("alice", "s1")["points"] == 100
    g.revoke("alice", "s1", 1, reason="cheat", now=1103)
    out = g.grant_points("alice", "s1", -1, reason="correction", now=1104)
    assert out["status"] == "applied"
    assert out["points"] == 99


def test_claim_requires_points_and_only_pays_once():
    g = make()
    g.open_season("s1", starts_at=1000, ends_at=2000)
    g.define_tier("s1", 1, requirement=10, rewards=["gold:100"])
    g.grant_points("alice", "s1", 9, event_id="p1", now=1100)
    with pytest.raises(srg.SeasonRewardError) as exc:
        g.claim("alice", "s1", 1, now=1101)
    assert exc.value.code == "SR_REQUIREMENT_NOT_MET"
    g.grant_points("alice", "s1", 1, event_id="p2", now=1102)
    out = g.claim("alice", "s1", 1, now=1103)
    assert out["status"] == "claimed"
    assert out["code"] == "SR_CLAIMED"
    assert out["rewards"] == ["gold:100"]
    with pytest.raises(srg.SeasonRewardError) as exc:
        g.claim("alice", "s1", 1, now=1104)
    assert exc.value.code == "SR_ALREADY_CLAIMED"
    rows = g.claims("alice")
    assert len(rows) == 1
    assert rows[0]["status"] == "active"
    with pytest.raises(srg.SeasonRewardError) as exc:
        g.claim("alice", "s1", 9, now=1105)
    assert exc.value.code == "SR_UNKNOWN_TIER"


def test_tiers_must_be_claimed_in_order():
    g = make()
    g.open_season("s1", starts_at=1000, ends_at=2000)
    g.define_tier("s1", 1, requirement=10, rewards=["gold:10"])
    g.define_tier("s1", 2, requirement=20, rewards=["gold:20"])
    g.grant_points("alice", "s1", 20, event_id="q1", now=1100)
    with pytest.raises(srg.SeasonRewardError) as exc:
        g.claim("alice", "s1", 2, now=1101)
    assert exc.value.code == "SR_TIER_ORDER"
    first = g.claim("alice", "s1", 1, now=1102)
    assert first["rewards"] == ["gold:10"]
    second = g.claim("alice", "s1", 2, now=1103)
    assert second["status"] == "claimed"
    assert second["rewards"] == ["gold:20"]
    assert g.points("alice", "s1")["claimed_tiers"] == [1, 2]


def test_concurrent_event_grant_and_claim_are_atomic():
    g = make()
    g.open_season("s1", starts_at=1000, ends_at=2000)
    g.define_tier("s1", 1, requirement=5, rewards=["gold:10"])
    codes = []
    lock = threading.Lock()

    def grant_worker():
        try:
            out = g.grant_points("race", "s1", 5, event_id="same", now=1100)
            code = out["code"]
        except Exception as exc:  # noqa: BLE001
            code = getattr(exc, "code", repr(exc))
        with lock:
            codes.append(code)

    threads = [threading.Thread(target=grant_worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert codes.count("SR_POINTS_GRANTED") == 1
    assert codes.count("SR_DUP_EVENT") == 7
    assert g.points("race", "s1")["points"] == 5

    g.grant_points("racer", "s1", 5, event_id="seed", now=1100)
    results = []

    def claim_worker():
        try:
            out = g.claim("racer", "s1", 1, now=1101)
            code = out["code"]
        except Exception as exc:  # noqa: BLE001
            code = getattr(exc, "code", repr(exc))
        with lock:
            results.append(code)

    threads = [threading.Thread(target=claim_worker) for _ in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert results.count("SR_CLAIMED") == 1
    assert results.count("SR_ALREADY_CLAIMED") == 5
    assert len(g.claims("racer")) == 1


def test_exclusive_group_allows_only_one_tier():
    g = make()
    g.open_season("s1", starts_at=1000, ends_at=2000)
    g.define_tier("s1", 1, requirement=10)
    g.define_tier("s1", 2, requirement=20, rewards=["frame:a"],
                  exclusive_group="cosmetic")
    g.define_tier("s1", 3, requirement=30, rewards=["frame:b"],
                  exclusive_group="cosmetic")
    g.grant_points("alice", "s1", 30, event_id="x1", now=1100)
    g.claim("alice", "s1", 1, now=1101)
    g.claim("alice", "s1", 2, now=1102)
    with pytest.raises(srg.SeasonRewardError) as exc:
        g.claim("alice", "s1", 3, now=1103)
    assert exc.value.code == "SR_EXCLUSIVE_CONFLICT"
    assert [row["tier"] for row in g.claims("alice")] == [1, 2]


def test_grace_window_and_expire_transition_season_state():
    g = make()
    g.open_season("s1", starts_at=1000, ends_at=2000, grace=100)
    g.define_tier("s1", 1, requirement=10)
    g.define_tier("s1", 2, requirement=20)
    g.grant_points("alice", "s1", 20, event_id="g1", now=1500)
    assert g.claim("alice", "s1", 1, now=2001)["status"] == "claimed"
    assert g.expire(2100) == []
    with pytest.raises(srg.SeasonRewardError) as exc:
        g.claim("alice", "s1", 2, now=2101)
    assert exc.value.code == "SR_CLAIM_EXPIRED"
    assert g.expire(2101) == ["s1"]
    assert g.season_state("s1", now=2102)["status"] == "expired"


def test_close_season_blocks_grants_but_keeps_grace_claims():
    g = make()
    g.open_season("s1", starts_at=1000, ends_at=2000, grace=100)
    g.define_tier("s1", 1, requirement=10, rewards=["gold:10"])
    g.grant_points("alice", "s1", 10, event_id="c1", now=1100)
    closed = g.close_season("s1", now=1500)
    assert closed["status"] == "closed"
    assert closed["closed_at"] == 1500
    with pytest.raises(srg.SeasonRewardError) as exc:
        g.grant_points("alice", "s1", 1, now=1501)
    assert exc.value.code == "SR_SEASON_CLOSED"
    assert g.claim("alice", "s1", 1, now=1501)["status"] == "claimed"
    again = g.close_season("s1", now=1600)
    assert again["closed_at"] == 1500
    assert g.season_state("s1", now=1600)["status"] == "closed"
    assert g.expire(2101) == ["s1"]
    assert g.season_state("s1", now=2101)["status"] == "expired"


def test_revoke_then_reissue_restores_rewards_once():
    g = make()
    g.open_season("s1", starts_at=1000, ends_at=2000, grace=100)
    g.define_tier("s1", 1, requirement=10, rewards=["gold:10"])
    g.grant_points("alice", "s1", 10, event_id="r1", now=1100)
    g.claim("alice", "s1", 1, now=1101)
    with pytest.raises(srg.SeasonRewardError) as exc:
        g.reissue("alice", "s1", 1, reason="appeal", now=1102)
    assert exc.value.code == "SR_REISSUE_DENIED"
    assert g.revoke("alice", "s1", 1, reason="cheat",
                    now=1103)["status"] == "revoked"
    with pytest.raises(srg.SeasonRewardError) as exc:
        g.claim("alice", "s1", 1, now=1104)
    assert exc.value.code == "SR_CLAIM_REVOKED"
    assert g.claims("alice")[0]["status"] == "revoked"
    out = g.reissue("alice", "s1", 1, reason="appeal", now=1105)
    assert out["status"] == "reissued"
    assert out["rewards"] == ["gold:10"]
    rows = g.claims("alice")
    assert rows[0]["status"] == "active"
    assert rows[0]["reissued"] is True
    with pytest.raises(srg.SeasonRewardError) as exc:
        g.reissue("alice", "s1", 1, reason="appeal", now=1106)
    assert exc.value.code == "SR_DUP_REISSUE"
    with pytest.raises(srg.SeasonRewardError) as exc:
        g.reissue("bob", "s1", 1, reason="appeal", now=1107)
    assert exc.value.code == "SR_CLAIM_NOT_FOUND"


def test_claim_batch_limits_size_and_reports_per_account_results():
    g = make(max_claims_per_batch=2)
    g.open_season("s1", starts_at=1000, ends_at=2000)
    g.define_tier("s1", 1, requirement=10, rewards=["gold:10"])
    g.grant_points("alice", "s1", 10, event_id="b1", now=1100)
    with pytest.raises(srg.SeasonRewardError) as exc:
        g.claim_batch(["alice", "bob", "carol"], "s1", 1, now=1101)
    assert exc.value.code == "SR_BATCH_TOO_LARGE"
    rows = g.claim_batch(["alice", "bob"], "s1", 1, now=1102)
    assert [row["account"] for row in rows] == ["alice", "bob"]
    assert rows[0]["status"] == "claimed"
    assert rows[0]["rewards"] == ["gold:10"]
    assert rows[1]["status"] == "rejected"
    assert rows[1]["code"] == "SR_REQUIREMENT_NOT_MET"
    assert [row["tier"] for row in g.claims("alice")] == [1]
    assert g.claims("bob") == []


def test_snapshot_restore_round_trip_and_corruption_guard():
    g = make()
    g.open_season("s1", starts_at=1000, ends_at=2000, grace=100)
    g.define_tier("s1", 1, requirement=10, rewards=["gold:100"])
    g.grant_points("alice", "s1", 10, event_id="e1", now=1100)
    g.claim("alice", "s1", 1, now=1101)
    g.revoke("alice", "s1", 1, reason="cheat", now=1102)
    snap = g.snapshot()
    assert snap["version"] == 1
    snap["claims"].clear()
    assert len(g.claims("alice")) == 1
    snap = g.snapshot()
    clone = make()
    clone.restore(snap)
    assert clone.points("alice", "s1")["points"] == 10
    rows = clone.claims("alice")
    assert len(rows) == 1
    assert rows[0]["status"] == "revoked"
    assert clone.reissue("alice", "s1", 1, reason="appeal",
                         now=1103)["status"] == "reissued"
    duplicate = clone.grant_points("alice", "s1", 10, event_id="e1",
                                   now=1104)
    assert duplicate["code"] == "SR_DUP_EVENT"
    assert clone.points("alice", "s1")["points"] == 10
    with pytest.raises(srg.SeasonRewardError) as exc:
        clone.restore({"version": 7, "seasons": {}, "tiers": {},
                       "points": {}, "claims": [], "events": []})
    assert exc.value.code == "SR_SNAPSHOT_CORRUPT"
    assert clone.claims("alice")[0]["status"] == "active"
    bad = dict(snap)
    bad["points"] = {"alice": {"s1": "ten"}}
    with pytest.raises(srg.SeasonRewardError) as exc:
        clone.restore(bad)
    assert exc.value.code == "SR_SNAPSHOT_CORRUPT"
    assert clone.claims("alice")[0]["status"] == "active"
