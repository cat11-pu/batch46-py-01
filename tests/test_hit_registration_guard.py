import copy
import threading

import pytest

import hit_registration_guard as hr


def make(**kwargs):
    return hr.HitRegistration(**kwargs)


def target(h, target_id="boss", **kwargs):
    kwargs.setdefault("hp", 100)
    kwargs.setdefault("team", "blue")
    h.spawn(target_id, **kwargs)


def test_duplicate_shot_id_is_ignored_and_applies_damage_once():
    h = make()
    target(h)
    h.join("p1", "red")
    first = h.submit("s1", shooter="p1", target="boss", damage=30, tick=1)
    assert first["status"] == "pending"
    out = h.resolve("s1")
    assert out["status"] == "applied"
    assert out["damage"] == 30
    assert out["remaining_hp"] == 70
    second = h.submit("s1", shooter="p1", target="boss", damage=30, tick=2)
    assert second["status"] == "ignored"
    assert second["code"] == "HIT_DUP_SHOT"
    assert h.health("boss") == 70
    assert h.damage_log("boss") == ["s1"]


def test_armor_absorbs_half_of_the_effective_damage():
    h = make()
    h.spawn("boss", hp=100, armor=40, team="blue")
    h.join("p1", "red")
    h.submit("s1", shooter="p1", target="boss", damage=30, tick=1)
    first = h.resolve("s1")
    assert first["damage"] == 15
    assert h.health("boss") == 85
    assert h.armor("boss") == 25
    h.submit("s2", shooter="p1", target="boss", damage=30, tick=2)
    second = h.resolve("s2")
    assert second["damage"] == 15
    assert h.health("boss") == 70
    assert h.armor("boss") == 10


def test_headshot_doubles_damage_before_armor():
    h = make()
    h.spawn("boss", hp=100, armor=50, team="blue")
    h.join("p1", "red")
    h.submit("s1", shooter="p1", target="boss", damage=20, tick=1,
             headshot=True)
    out = h.resolve("s1")
    assert out["damage"] == 20
    assert out["killed"] is False
    assert h.health("boss") == 80
    assert h.armor("boss") == 30


def test_overkill_clamps_health_and_counts_one_kill():
    h = make()
    h.spawn("boss", hp=10, armor=0, team="blue")
    h.join("p1", "red")
    h.submit("kill", shooter="p1", target="boss", damage=25, tick=5)
    out = h.resolve("kill")
    assert out["status"] == "applied"
    assert out["killed"] is True
    assert out["remaining_hp"] == 0
    assert h.health("boss") == 0
    assert h.kills("p1") == 1
    h.submit("late", shooter="p1", target="boss", damage=5, tick=6)
    again = h.resolve("late")
    assert again["status"] == "ignored"
    assert again["code"] == "HIT_TARGET_DEAD"
    assert h.kills("p1") == 1
    assert h.health("boss") == 0


def test_friendly_fire_damages_but_credits_no_kill():
    h = make()
    h.join("p1", "red")
    h.spawn("ally", hp=50, armor=0, team="red")
    h.submit("f1", shooter="p1", target="ally", damage=10, tick=1)
    out = h.resolve("f1")
    assert out["status"] == "applied"
    assert h.health("ally") == 40
    assert h.kills("p1") == 0
    assert h.stats()["friendly_kills"] == 1


def test_shots_outside_the_target_lifetime_are_stale():
    h = make()
    h.join("p1", "red")
    h.spawn("npc", hp=100, team="blue", tick=10)
    h.despawn("npc", tick=20)
    h.submit("before", shooter="p1", target="npc", damage=10, tick=9)
    early = h.resolve("before")
    assert early["status"] == "ignored"
    assert early["code"] == "HIT_STALE_TARGET"
    h.submit("after", shooter="p1", target="npc", damage=10, tick=21)
    late = h.resolve("after")
    assert late["status"] == "ignored"
    assert late["code"] == "HIT_STALE_TARGET"
    assert h.health("npc") == 100
    with pytest.raises(hr.HitError) as exc:
        h.despawn("ghost", tick=30)
    assert exc.value.code == "HIT_UNKNOWN_TARGET"


def test_rollback_restores_health_armor_and_damage_log():
    h = make()
    h.spawn("boss", hp=100, armor=40, team="blue")
    h.join("p1", "red")
    h.submit("s1", shooter="p1", target="boss", damage=30, tick=1)
    h.resolve("s1")
    h.submit("s2", shooter="p1", target="boss", damage=80, tick=2)
    second = h.resolve("s2")
    assert second["damage"] == 55
    assert h.health("boss") == 30
    assert h.armor("boss") == 0
    out = h.rollback("s2")
    assert out["status"] == "rolled_back"
    assert out["health"] == 85
    assert h.health("boss") == 85
    assert h.armor("boss") == 25
    assert h.damage_log("boss") == ["s1"]
    h.rollback("s1")
    assert h.health("boss") == 100
    assert h.armor("boss") == 40
    assert h.damage_log("boss") == []


def test_rollback_is_lifo_and_revives_killed_targets():
    h = make()
    h.spawn("boss", hp=10, armor=0, team="blue")
    h.join("p1", "red")
    h.submit("kill", shooter="p1", target="boss", damage=100, tick=1)
    h.resolve("kill")
    assert h.kills("p1") == 1
    assert h.state("boss")["alive"] is False
    restored = h.rollback("kill")
    assert restored["kills_reverted"] == 1
    assert h.health("boss") == 10
    assert h.state("boss")["alive"] is True
    assert h.kills("p1") == 0
    with pytest.raises(hr.HitError) as exc:
        h.rollback("kill")
    assert exc.value.code == "HIT_ROLLBACK_ORDER"
    h.spawn("wall", hp=100, armor=0, team="blue")
    h.submit("s2", shooter="p1", target="wall", damage=10, tick=2)
    h.resolve("s2")
    h.submit("s3", shooter="p1", target="wall", damage=10, tick=3)
    h.resolve("s3")
    with pytest.raises(hr.HitError) as exc:
        h.rollback("s2")
    assert exc.value.code == "HIT_ROLLBACK_ORDER"
    assert h.health("wall") == 80
    assert h.damage_log("wall") == ["s2", "s3"]
    h.rollback("s3")
    h.rollback("s2")
    assert h.health("wall") == 100


def test_pending_shots_resolve_in_tick_then_shot_id_order():
    h = make()
    target(h, hp=100)
    h.join("p1", "red")
    h.submit("z-late", shooter="p1", target="boss", damage=1, tick=9)
    h.submit("b-mid", shooter="p1", target="boss", damage=1, tick=3)
    h.submit("a-early", shooter="p1", target="boss", damage=1, tick=3)
    assert h.pending() == ["a-early", "b-mid", "z-late"]
    results = h.resolve_pending()
    assert [row["shot_id"] for row in results] == [
        "a-early", "b-mid", "z-late"
    ]
    assert [row["status"] for row in results] == ["applied"] * 3
    assert h.damage_log("boss") == ["a-early", "b-mid", "z-late"]
    assert h.pending() == []
    assert h.health("boss") == 97


def test_pending_queue_limit_rejects_new_shots():
    h = make(max_pending=2)
    target(h, hp=1000)
    h.join("p1", "red")
    h.submit("q1", shooter="p1", target="boss", damage=1, tick=2)
    h.submit("q2", shooter="p1", target="boss", damage=1, tick=1)
    assert h.pending() == ["q2", "q1"]
    with pytest.raises(hr.HitError) as exc:
        h.submit("q3", shooter="p1", target="boss", damage=1, tick=3)
    assert exc.value.code == "HIT_QUEUE_FULL"
    assert h.pending() == ["q2", "q1"]
    assert h.health("boss") == 1000


def test_cancelled_shots_never_apply_damage():
    h = make()
    target(h, hp=100)
    h.join("p1", "red")
    h.submit("c1", shooter="p1", target="boss", damage=5, tick=1)
    assert h.cancel("c1") is True
    out = h.resolve("c1")
    assert out["status"] == "ignored"
    assert out["code"] == "HIT_SHOT_CANCELLED"
    assert h.health("boss") == 100
    h.submit("c2", shooter="p1", target="boss", damage=5, tick=2)
    h.resolve("c2")
    with pytest.raises(hr.HitError) as exc:
        h.cancel("c2")
    assert exc.value.code == "HIT_CANCEL_STATE"
    with pytest.raises(hr.HitError) as exc:
        h.cancel("nope")
    assert exc.value.code == "HIT_UNKNOWN_SHOT"
    with pytest.raises(hr.HitError) as exc:
        h.resolve("nope")
    assert exc.value.code == "HIT_UNKNOWN_SHOT"


def test_snapshot_restores_pending_and_applied_state():
    h = make()
    h.spawn("boss", hp=100, armor=40, team="blue")
    h.join("p1", "red")
    h.submit("s1", shooter="p1", target="boss", damage=30, tick=1)
    h.resolve("s1")
    h.submit("s2", shooter="p1", target="boss", damage=10, tick=2)
    snap = h.snapshot()
    assert snap["version"] == 1
    h.resolve("s2")
    h.submit("s3", shooter="p1", target="boss", damage=99, tick=3)
    h.resolve("s3")
    h.restore(snap)
    assert h.health("boss") == 85
    assert h.armor("boss") == 25
    assert h.damage_log("boss") == ["s1"]
    assert h.pending() == ["s2"]
    assert h.kills("p1") == 0
    assert h.stats()["applied"] == 1
    out = h.resolve("s2")
    assert out["status"] == "applied"
    assert h.health("boss") == 80
    bad = copy.deepcopy(h.snapshot())
    bad["version"] = 99
    with pytest.raises(hr.HitError) as exc:
        h.restore(bad)
    assert exc.value.code == "HIT_SNAPSHOT_VERSION"
    assert h.health("boss") == 80


def test_concurrent_distinct_shots_are_applied_exactly_once():
    h = make()
    target(h, hp=100000, armor=0)
    h.join("p1", "red")
    errors = []
    lock = threading.Lock()

    def worker(base):
        for index in range(15):
            shot = "s-%d-%d" % (base, index)
            try:
                h.submit(shot, shooter="p1", target="boss", damage=1,
                         tick=base * 100 + index)
                h.resolve(shot)
            except Exception as exc:  # pragma: no cover - diagnostic path
                with lock:
                    errors.append(exc)

    threads = [threading.Thread(target=worker, args=(base,))
               for base in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    assert h.health("boss") == 100000 - 120
    log = h.damage_log("boss")
    assert len(log) == 120
    assert len(set(log)) == 120
    assert h.stats()["applied"] == 120


def test_concurrent_duplicate_submission_applies_once():
    h = make()
    target(h, hp=100, armor=0)
    h.join("p1", "red")
    barrier = threading.Barrier(6)
    statuses = []
    lock = threading.Lock()

    def worker():
        barrier.wait()
        out = h.submit("same", shooter="p1", target="boss", damage=25,
                       tick=1)
        with lock:
            statuses.append(out["status"])

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert statuses.count("pending") == 1
    assert statuses.count("ignored") == 5
    out = h.resolve("same")
    assert out["status"] == "applied"
    assert h.health("boss") == 75
    again = h.resolve("same")
    assert again["status"] == "ignored"
    assert again["code"] == "HIT_ALREADY_RESOLVED"
    assert h.health("boss") == 75


def test_invalid_spawn_and_submit_inputs_are_rejected():
    h = make()
    h.spawn("x", hp=50, team="blue")
    with pytest.raises(hr.HitError) as exc:
        h.spawn("x", hp=50, team="blue")
    assert exc.value.code == "HIT_TARGET_DUP"
    with pytest.raises(hr.HitError) as exc:
        h.spawn("y", hp=0, team="blue")
    assert exc.value.code == "HIT_INVALID_STAT"
    with pytest.raises(hr.HitError) as exc:
        h.spawn("z", armor=-1, team="blue")
    assert exc.value.code == "HIT_INVALID_STAT"
    h.join("p1", "red")
    with pytest.raises(hr.HitError) as exc:
        h.submit("s1", shooter="p1", target="ghost", damage=1, tick=1)
    assert exc.value.code == "HIT_UNKNOWN_TARGET"
    with pytest.raises(hr.HitError) as exc:
        h.submit("s1", shooter="p1", target="x", damage=0, tick=1)
    assert exc.value.code == "HIT_INVALID_DAMAGE"
    assert h.health("x") == 50
    with pytest.raises(hr.HitError) as exc:
        h.health("ghost")
    assert exc.value.code == "HIT_UNKNOWN_TARGET"
