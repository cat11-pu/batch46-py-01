import threading
from datetime import datetime, timedelta, timezone

import pytest

import party_invite_guard as pg

T0 = datetime(2026, 11, 23, 20, 0, 0, tzinfo=timezone.utc)


def make(max_size=5, ttl=30, cooldown=60, pending=3):
    return pg.PartyInviteGuard(pg.PartyConfig(
        max_size=max_size,
        invite_ttl_seconds=ttl,
        cooldown_seconds=cooldown,
        max_pending_per_invitee=pending,
    ))


def seed(g, party_id="p1", leader="alice", realm="r1"):
    g.create_party(party_id, leader, realm, T0)


def join(g, party_id, leader, realm, invitee, now=T0):
    inv = g.invite(party_id, leader, invitee, realm, now)
    return g.accept(inv.invite_id, now)


def test_create_party_exposes_leader_and_membership():
    g = make()
    seed(g)
    assert g.party_of("alice") == pg.Party("p1", "alice", "r1", ("alice",))
    assert g.leader("p1") == "alice"
    assert g.party_of("bob") is None
    with pytest.raises(pg.PartyError) as exc:
        g.leader("nope")
    assert exc.value.code == pg.ERR_UNKNOWN_PARTY


def test_create_party_rejects_duplicate_id_and_busy_leader():
    g = make()
    seed(g)
    with pytest.raises(pg.PartyError) as exc:
        g.create_party("p1", "bob", "r1", T0)
    assert exc.value.code == pg.ERR_DUPLICATE_PARTY
    with pytest.raises(pg.PartyError) as exc:
        g.create_party("p2", "alice", "r1", T0)
    assert exc.value.code == pg.ERR_PLAYER_BUSY
    assert g.party_of("bob") is None


def test_invite_sets_the_ttl_and_shows_up_as_pending():
    g = make(ttl=45)
    seed(g)
    seed(g, "p2", "bob")
    inv = g.invite("p1", "alice", "carol", "r1", T0)
    assert inv.party_id == "p1"
    assert inv.inviter == "alice"
    assert inv.invitee == "carol"
    assert inv.realm == "r1"
    assert inv.created_at == T0
    assert inv.expires_at == T0 + timedelta(seconds=45)
    assert g.pending_for("carol") == [inv]
    assert g.pending_for("alice") == []
    other = g.invite("p2", "bob", "carol", "r1", T0)
    assert other.invite_id != inv.invite_id
    pending = g.pending_for("carol")
    assert {row.invite_id for row in pending} == {inv.invite_id, other.invite_id}
    assert all(row.expires_at == T0 + timedelta(seconds=45) for row in pending)


def test_invite_permission_realm_and_party_checks():
    g = make()
    seed(g)
    join(g, "p1", "alice", "r1", "bob")
    with pytest.raises(pg.PartyError) as exc:
        g.invite("p1", "bob", "carol", "r1", T0)
    assert exc.value.code == pg.ERR_NOT_LEADER
    with pytest.raises(pg.PartyError) as exc:
        g.invite("p1", "alice", "alice", "r1", T0)
    assert exc.value.code == pg.ERR_SELF_INVITE
    with pytest.raises(pg.PartyError) as exc:
        g.invite("p1", "alice", "carol", "r2", T0)
    assert exc.value.code == pg.ERR_CROSS_REALM
    with pytest.raises(pg.PartyError) as exc:
        g.invite("nope", "alice", "carol", "r1", T0)
    assert exc.value.code == pg.ERR_UNKNOWN_PARTY
    assert g.pending_for("carol") == []


def test_duplicate_pending_invite_is_blocked_and_expired_one_is_inert():
    g = make(ttl=30)
    seed(g)
    g.invite("p1", "alice", "bob", "r1", T0)
    with pytest.raises(pg.PartyError) as exc:
        g.invite("p1", "alice", "bob", "r1", T0 + timedelta(seconds=5))
    assert exc.value.code == pg.ERR_INVITE_PENDING
    assert len(g.pending_for("bob")) == 1
    fresh = g.invite("p1", "alice", "bob", "r1", T0 + timedelta(seconds=30))
    assert len(g.pending_for("bob")) == 1
    assert g.pending_for("bob")[0].invite_id == fresh.invite_id


def test_decline_starts_the_inviter_cooldown():
    g = make(cooldown=60)
    seed(g)
    inv = g.invite("p1", "alice", "bob", "r1", T0)
    g.decline(inv.invite_id, T0 + timedelta(seconds=1))
    assert g.pending_for("bob") == []
    with pytest.raises(pg.PartyError) as exc:
        g.invite("p1", "alice", "bob", "r1", T0 + timedelta(seconds=60))
    assert exc.value.code == pg.ERR_COOLDOWN
    late = g.invite("p1", "alice", "bob", "r1", T0 + timedelta(seconds=61))
    assert late.invitee == "bob"
    with pytest.raises(pg.PartyError) as exc:
        g.decline("ghost", T0)
    assert exc.value.code == pg.ERR_INVITE_NOT_FOUND


def test_inbox_limit_is_per_invitee():
    g = make(pending=2)
    seed(g, "p1", "alice")
    seed(g, "p2", "bob")
    seed(g, "p3", "carol")
    g.invite("p1", "alice", "dave", "r1", T0)
    g.invite("p2", "bob", "dave", "r1", T0)
    with pytest.raises(pg.PartyError) as exc:
        g.invite("p3", "carol", "dave", "r1", T0)
    assert exc.value.code == pg.ERR_INBOX_FULL
    assert len(g.pending_for("dave")) == 2


def test_invitee_already_in_a_party_is_busy():
    g = make()
    seed(g, "p1", "alice")
    seed(g, "p2", "carol")
    join(g, "p1", "alice", "r1", "bob")
    with pytest.raises(pg.PartyError) as exc:
        g.invite("p2", "carol", "bob", "r1", T0)
    assert exc.value.code == pg.ERR_PLAYER_BUSY


def test_party_full_blocks_invites_and_accepts():
    g = make(max_size=2)
    seed(g, "p1", "alice")
    seed(g, "p2", "frank")
    join(g, "p1", "alice", "r1", "bob")
    with pytest.raises(pg.PartyError) as exc:
        g.invite("p1", "alice", "carol", "r1", T0)
    assert exc.value.code == pg.ERR_PARTY_FULL
    inv = g.invite("p2", "frank", "grace", "r1", T0)
    join(g, "p2", "frank", "r1", "heidi")
    with pytest.raises(pg.PartyError) as exc:
        g.accept(inv.invite_id, T0)
    assert exc.value.code == pg.ERR_PARTY_FULL
    assert [row.invite_id for row in g.pending_for("grace")] == [inv.invite_id]


def test_accept_appends_members_in_join_order():
    g = make()
    seed(g)
    party = join(g, "p1", "alice", "r1", "bob")
    assert party == pg.Party("p1", "alice", "r1", ("alice", "bob"))
    party = join(g, "p1", "alice", "r1", "carol")
    assert party.members == ("alice", "bob", "carol")
    assert g.party_of("carol").party_id == "p1"
    assert g.pending_for("carol") == []


def test_expired_invites_are_removed_by_accept_and_expire():
    g = make(ttl=30)
    seed(g, "p1", "alice")
    seed(g, "p2", "bob")
    seed(g, "p3", "carol")
    first = g.invite("p1", "alice", "dave", "r1", T0)
    g.invite("p2", "bob", "dave", "r1", T0 + timedelta(seconds=10))
    g.invite("p3", "carol", "dave", "r1", T0 + timedelta(seconds=20))
    assert len(g.pending_for("dave")) == 3
    with pytest.raises(pg.PartyError) as exc:
        g.accept(first.invite_id, T0 + timedelta(seconds=30))
    assert exc.value.code == pg.ERR_INVITE_EXPIRED
    assert len(g.pending_for("dave")) == 2
    assert g.expire(T0 + timedelta(seconds=40)) == 1
    assert len(g.pending_for("dave")) == 1
    assert g.expire(T0 + timedelta(seconds=50)) == 1
    assert g.pending_for("dave") == []


def test_promote_moves_the_new_leader_to_the_front():
    g = make()
    seed(g)
    join(g, "p1", "alice", "r1", "bob")
    join(g, "p1", "alice", "r1", "carol")
    g.promote("p1", "carol")
    assert g.leader("p1") == "carol"
    assert g.party_of("alice").members == ("carol", "alice", "bob")
    with pytest.raises(pg.PartyError) as exc:
        g.promote("p1", "zed")
    assert exc.value.code == pg.ERR_NOT_IN_PARTY
    with pytest.raises(pg.PartyError) as exc:
        g.promote("nope", "alice")
    assert exc.value.code == pg.ERR_UNKNOWN_PARTY


def test_leave_hands_leadership_over_and_dissolves_the_last_member():
    g = make()
    seed(g)
    join(g, "p1", "alice", "r1", "bob")
    join(g, "p1", "alice", "r1", "carol")
    g.leave("alice", T0)
    assert g.leader("p1") == "bob"
    assert g.party_of("bob").members == ("bob", "carol")
    g.leave("carol", T0)
    assert g.party_of("bob").members == ("bob",)
    g.leave("bob", T0)
    assert g.party_of("bob") is None
    with pytest.raises(pg.PartyError) as exc:
        g.leader("p1")
    assert exc.value.code == pg.ERR_UNKNOWN_PARTY
    with pytest.raises(pg.PartyError) as exc:
        g.leave("zed", T0)
    assert exc.value.code == pg.ERR_NOT_IN_PARTY


def test_snapshot_restore_keeps_parties_invites_cooldown_and_ids():
    g = make(ttl=120, cooldown=60)
    seed(g)
    seed(g, "p2", "carol")
    join(g, "p1", "alice", "r1", "bob")
    g.invite("p1", "alice", "dave", "r1", T0)
    gone = g.invite("p2", "carol", "erin", "r1", T0)
    g.decline(gone.invite_id, T0 + timedelta(seconds=5))
    blob = g.snapshot()
    assert isinstance(blob, bytes)
    restored = pg.PartyInviteGuard.from_snapshot(pg.PartyConfig(
        max_size=5, invite_ttl_seconds=120, cooldown_seconds=60,
        max_pending_per_invitee=3), blob)
    assert restored.party_of("bob") == pg.Party("p1", "alice", "r1", ("alice", "bob"))
    assert [row.invite_id for row in restored.pending_for("dave")] == [
        row.invite_id for row in g.pending_for("dave")]
    assert restored.pending_for("dave")[0].expires_at == T0 + timedelta(seconds=120)
    with pytest.raises(pg.PartyError) as exc:
        restored.create_party("p1", "zed", "r1", T0)
    assert exc.value.code == pg.ERR_DUPLICATE_PARTY
    with pytest.raises(pg.PartyError) as exc:
        restored.invite("p2", "carol", "erin", "r1", T0 + timedelta(seconds=64))
    assert exc.value.code == pg.ERR_COOLDOWN
    fresh = restored.invite("p2", "carol", "erin", "r1", T0 + timedelta(seconds=65))
    known = {row.invite_id for row in restored.pending_for("dave")}
    known.add(gone.invite_id)
    assert fresh.invite_id not in known
    party = restored.accept(fresh.invite_id, T0 + timedelta(seconds=65))
    assert party.members == ("carol", "erin")


def test_concurrent_accept_applies_the_invite_once():
    g = make()
    seed(g)
    inv = g.invite("p1", "alice", "bob", "r1", T0)
    barrier = threading.Barrier(2)
    results = []
    results_lock = threading.Lock()

    def worker():
        barrier.wait(timeout=10)
        try:
            g.accept(inv.invite_id, T0)
            code = "ok"
        except pg.PartyError as exc:
            code = exc.code
        with results_lock:
            results.append(code)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=20)
    assert results.count("ok") == 1
    assert results.count(pg.ERR_INVITE_NOT_FOUND) == 1
    assert g.party_of("bob").members == ("alice", "bob")
    assert g.pending_for("bob") == []
