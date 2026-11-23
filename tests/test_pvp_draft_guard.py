import threading
from datetime import datetime, timedelta, timezone

import pytest

import pvp_draft_guard as pd

NOW = datetime(2026, 11, 23, 12, 0, 0, tzinfo=timezone.utc)
POOL = [
    pd.Champion("a1", "mage"),
    pd.Champion("a2", "mage"),
    pd.Champion("b1", "tank"),
    pd.Champion("b2", "tank"),
    pd.Champion("c1", "healer"),
    pd.Champion("c2", "healer"),
]


def make(bans=2, picks=2, seconds=30, pool=None):
    return pd.PvpDraft(
        pd.DraftConfig(bans_per_team=bans, picks_per_team=picks,
                       turn_seconds=seconds),
        list(pool or POOL),
        NOW,
    )


def act(action_id, team, kind, champion_id, at=NOW):
    return pd.Action(action_id, team, kind, champion_id, at)


def test_initial_state_reports_ban_phase_and_first_deadline():
    d = make()
    st = d.state()
    assert st.phase == pd.Phase.BAN
    assert st.turn == 0
    assert st.team == pd.Team.BLUE
    assert st.bans == ()
    assert st.blue_picks == ()
    assert st.red_picks == ()
    assert d.deadline() == NOW + timedelta(seconds=30)
    assert d.available() == ["a1", "a2", "b1", "b2", "c1", "c2"]
    assert d.remaining_bans(pd.Team.BLUE) == 2
    assert d.remaining_bans(pd.Team.RED) == 2


def test_ban_turns_alternate_starting_with_blue():
    d = make(bans=2, picks=1)
    teams = [pd.Team.BLUE, pd.Team.RED, pd.Team.BLUE, pd.Team.RED]
    champions = ["a1", "a2", "b1", "b2"]
    for i, (team, champ) in enumerate(zip(teams, champions)):
        st = d.submit(act("x%d" % i, team, "ban", champ), NOW)
        assert st.turn == i + 1
        if i < 3:
            assert st.team == teams[i + 1]
    assert st.phase == pd.Phase.PICK
    assert st.team == pd.Team.BLUE
    assert st.bans == ("a1", "a2", "b1", "b2")
    assert d.remaining_bans(pd.Team.BLUE) == 0
    assert d.remaining_bans(pd.Team.RED) == 0


def test_pick_phase_starts_after_every_ban_is_used():
    d = make(bans=1, picks=1)
    first = d.submit(act("b1", pd.Team.BLUE, "ban", "a1"), NOW)
    assert first.phase == pd.Phase.BAN
    second = d.submit(act("b2", pd.Team.RED, "ban", "a2"), NOW)
    assert second.phase == pd.Phase.PICK
    assert second.team == pd.Team.BLUE
    assert second.turn == 2


def test_snake_pick_order_and_finished_state():
    d = make(bans=1, picks=2)
    d.submit(act("s1", pd.Team.BLUE, "ban", "a1"), NOW)
    d.submit(act("s2", pd.Team.RED, "ban", "a2"), NOW)
    st = d.submit(act("s3", pd.Team.BLUE, "pick", "b1"), NOW)
    assert st.team == pd.Team.RED
    st = d.submit(act("s4", pd.Team.RED, "pick", "b2"), NOW)
    assert st.team == pd.Team.RED
    st = d.submit(act("s5", pd.Team.RED, "pick", "c1"), NOW)
    assert st.team == pd.Team.BLUE
    st = d.submit(act("s6", pd.Team.BLUE, "pick", "c2"), NOW)
    assert st.phase == pd.Phase.DONE
    assert st.team is None
    assert st.blue_picks == ("b1", "c2")
    assert st.red_picks == ("b2", "c1")
    assert d.picks(pd.Team.BLUE) == ["b1", "c2"]
    assert d.deadline() is None


def test_action_by_the_wrong_team_is_refused():
    d = make()
    with pytest.raises(pd.DraftError) as exc:
        d.submit(act("w1", pd.Team.RED, "ban", "a1"), NOW)
    assert exc.value.code == pd.ERR_NOT_YOUR_TURN
    assert d.state().bans == ()
    ok = d.submit(act("w2", pd.Team.BLUE, "ban", "a1"), NOW)
    assert ok.bans == ("a1",)


def test_action_kind_must_match_the_phase():
    d = make(bans=1, picks=1)
    with pytest.raises(pd.DraftError) as exc:
        d.submit(act("k1", pd.Team.BLUE, "pick", "a1"), NOW)
    assert exc.value.code == pd.ERR_INVALID_PHASE
    d.submit(act("k2", pd.Team.BLUE, "ban", "a1"), NOW)
    d.submit(act("k3", pd.Team.RED, "ban", "a2"), NOW)
    with pytest.raises(pd.DraftError) as exc:
        d.submit(act("k4", pd.Team.BLUE, "ban", "b1"), NOW)
    assert exc.value.code == pd.ERR_INVALID_PHASE
    assert d.state().blue_picks == ()


def test_finished_draft_refuses_submit_and_timeout():
    d = make(bans=1, picks=1)
    d.submit(act("f1", pd.Team.BLUE, "ban", "a1"), NOW)
    d.submit(act("f2", pd.Team.RED, "ban", "a2"), NOW)
    d.submit(act("f3", pd.Team.BLUE, "pick", "b1"), NOW)
    d.submit(act("f4", pd.Team.RED, "pick", "b2"), NOW)
    assert d.state().phase == pd.Phase.DONE
    with pytest.raises(pd.DraftError) as exc:
        d.submit(act("f5", pd.Team.BLUE, "pick", "c1"), NOW)
    assert exc.value.code == pd.ERR_CLOSED
    with pytest.raises(pd.DraftError) as exc:
        d.timeout(NOW + timedelta(hours=1))
    assert exc.value.code == pd.ERR_CLOSED


def test_duplicate_action_id_is_checked_before_turn_and_phase():
    d = make(bans=2, picks=1)
    d.submit(act("dup", pd.Team.BLUE, "ban", "a1"), NOW)
    with pytest.raises(pd.DraftError) as exc:
        d.submit(act("dup", pd.Team.RED, "ban", "a2"), NOW)
    assert exc.value.code == pd.ERR_DUPLICATE_ACTION
    with pytest.raises(pd.DraftError) as exc:
        d.submit(act("dup", pd.Team.BLUE, "ban", "b1"), NOW)
    assert exc.value.code == pd.ERR_DUPLICATE_ACTION
    st = d.state()
    assert st.turn == 1
    assert st.bans == ("a1",)
    assert len(d.history()) == 1


def test_champion_cannot_be_used_twice():
    d = make(bans=1, picks=2)
    d.submit(act("t1", pd.Team.BLUE, "ban", "a1"), NOW)
    with pytest.raises(pd.DraftError) as exc:
        d.submit(act("t2", pd.Team.RED, "ban", "a1"), NOW)
    assert exc.value.code == pd.ERR_CHAMPION_TAKEN
    d.submit(act("t3", pd.Team.RED, "ban", "a2"), NOW)
    with pytest.raises(pd.DraftError) as exc:
        d.submit(act("t4", pd.Team.BLUE, "pick", "a1"), NOW)
    assert exc.value.code == pd.ERR_CHAMPION_TAKEN
    d.submit(act("t5", pd.Team.BLUE, "pick", "b1"), NOW)
    with pytest.raises(pd.DraftError) as exc:
        d.submit(act("t6", pd.Team.RED, "pick", "b1"), NOW)
    assert exc.value.code == pd.ERR_CHAMPION_TAKEN


def test_unknown_champion_and_duplicate_pool():
    d = make()
    with pytest.raises(pd.DraftError) as exc:
        d.submit(act("u1", pd.Team.BLUE, "ban", "zzz"), NOW)
    assert exc.value.code == pd.ERR_UNKNOWN_CHAMPION
    assert d.state().bans == ()
    with pytest.raises(pd.DraftError) as exc:
        make(pool=[pd.Champion("a1", "mage"), pd.Champion("a1", "tank")])
    assert exc.value.code == pd.ERR_DUPLICATE_CHAMPION


def test_available_filters_taken_champions_and_roles():
    d = make(bans=1, picks=2)
    d.submit(act("a1", pd.Team.BLUE, "ban", "a1"), NOW)
    d.submit(act("a2", pd.Team.RED, "ban", "a2"), NOW)
    assert d.available() == ["b1", "b2", "c1", "c2"]
    assert d.available("tank") == ["b1", "b2"]
    assert d.available("rogue") == []
    d.submit(act("a3", pd.Team.BLUE, "pick", "b1"), NOW)
    assert d.available("tank") == ["b2"]


def test_timeout_needs_the_deadline_then_advances_without_history():
    d = make(seconds=45)
    with pytest.raises(pd.DraftError) as exc:
        d.timeout(NOW + timedelta(seconds=44))
    assert exc.value.code == pd.ERR_TURN_NOT_EXPIRED
    later = NOW + timedelta(seconds=45)
    st = d.timeout(later)
    assert st.turn == 1
    assert st.team == pd.Team.RED
    assert d.history() == []
    assert d.deadline() == later + timedelta(seconds=45)
    st = d.submit(act("o1", pd.Team.RED, "ban", "a1"), later)
    assert st.bans == ("a1",)


def test_history_and_champions_are_copies():
    d = make()
    d.submit(act("c1", pd.Team.BLUE, "ban", "a1"), NOW)
    hist = d.history()
    hist.clear()
    assert len(d.history()) == 1
    pool = d.champions()
    pool.clear()
    assert len(d.champions()) == 6
    st = d.state()
    assert isinstance(st.bans, tuple)


def test_snapshot_restore_keeps_state_deadline_and_action_ids():
    d = make(bans=2, picks=1)
    d.submit(act("r1", pd.Team.BLUE, "ban", "a1"), NOW)
    d.timeout(NOW + timedelta(seconds=30))
    d.submit(act("r2", pd.Team.BLUE, "ban", "a2"), NOW)
    d.submit(act("r3", pd.Team.RED, "ban", "b1"), NOW)
    blob = d.snapshot()
    assert isinstance(blob, bytes)
    restored = pd.PvpDraft.from_snapshot(
        pd.DraftConfig(bans_per_team=2, picks_per_team=1, turn_seconds=30),
        list(POOL), blob)
    assert restored.state() == d.state()
    assert [(a.action_id, a.champion_id) for a in restored.history()] == [
        ("r1", "a1"), ("r2", "a2"), ("r3", "b1")]
    assert restored.deadline() == d.deadline()
    with pytest.raises(pd.DraftError) as exc:
        restored.submit(act("r3", pd.Team.BLUE, "pick", "c1"), NOW)
    assert exc.value.code == pd.ERR_DUPLICATE_ACTION
    st = restored.submit(act("r4", pd.Team.BLUE, "pick", "c1"), NOW)
    assert st.turn == 5
    assert st.team == pd.Team.RED


def test_concurrent_duplicate_action_id_is_applied_once():
    d = make(bans=2, picks=1)
    barrier = threading.Barrier(2)
    results = []
    results_lock = threading.Lock()

    def worker(champion):
        barrier.wait(timeout=10)
        try:
            d.submit(act("race", pd.Team.BLUE, "ban", champion), NOW)
            code = "ok"
        except pd.DraftError as exc:
            code = exc.code
        with results_lock:
            results.append(code)

    threads = [threading.Thread(target=worker, args=(c,)) for c in ("a1", "a2")]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=20)
    assert results.count("ok") == 1
    assert results.count(pd.ERR_DUPLICATE_ACTION) == 1
    assert len(d.history()) == 1
    assert len(d.state().bans) == 1
