import json
import threading

import pytest

import stencil_portal_guard as sp


T = [float(index) for index in range(16)]


def make(**kwargs):
    return sp.StencilPortal(**kwargs)


def graph():
    a = make()
    for room in ("a", "b", "c", "d"):
        a.register_room(room, bounds=(0, 0, 10, 10))
    a.register_portal("p1", source="a", target="b", transform=T)
    a.register_portal("p2", source="a", target="c", transform=T)
    a.register_portal("p3", source="b", target="d", transform=T)
    a.register_portal("p4", source="c", target="d", transform=T)
    return a


def test_constructor_validation():
    with pytest.raises(sp.PortalError) as exc:
        make(stencil_bits=3, max_depth=4)
    assert exc.value.code == "PORTAL_BAD_CONFIG"
    with pytest.raises(sp.PortalError) as exc:
        make(max_depth=0)
    assert exc.value.code == "PORTAL_BAD_CONFIG"
    with pytest.raises(sp.PortalError) as exc:
        make(frame_budget=0)
    assert exc.value.code == "PORTAL_BAD_CONFIG"
    assert make().stats()["rooms"] == 0


def test_register_room_duplicate_and_unknown():
    a = make()
    first = a.register_room("lobby", bounds=(0, 0, 100, 100))
    assert first["status"] == "registered"
    again = a.register_room("lobby", bounds=(0, 0, 100, 100))
    assert again["status"] == "unchanged"
    with pytest.raises(sp.PortalError) as exc:
        a.register_room("lobby", bounds=(0, 0, 50, 50))
    assert exc.value.code == "PORTAL_DUP_ROOM"
    with pytest.raises(sp.PortalError) as exc:
        a.register_room("degenerate", bounds=(0, 0, 0, 10))
    assert exc.value.code == "PORTAL_BAD_ROOM"
    with pytest.raises(sp.PortalError) as exc:
        a.unregister_room("nowhere")
    assert exc.value.code == "PORTAL_UNKNOWN_ROOM"


def test_register_portal_validates_endpoints_and_transform():
    a = make()
    a.register_room("a")
    a.register_room("b")
    with pytest.raises(sp.PortalError) as exc:
        a.register_portal("self", source="a", target="a", transform=T)
    assert exc.value.code == "PORTAL_BAD_PORTAL"
    with pytest.raises(sp.PortalError) as exc:
        a.register_portal("ghost", source="a", target="ghost", transform=T)
    assert exc.value.code == "PORTAL_UNKNOWN_ROOM"
    with pytest.raises(sp.PortalError) as exc:
        a.register_portal("short", source="a", target="b", transform=T[:15])
    assert exc.value.code == "PORTAL_BAD_TRANSFORM"
    out = a.register_portal("p1", source="a", target="b", transform=T)
    assert out["status"] == "registered"
    assert a.describe_portal("p1")["source"] == "a"


def test_register_portal_duplicate_is_idempotent_but_conflict_raises():
    a = make()
    a.register_room("a")
    a.register_room("b")
    a.register_portal("p1", source="a", target="b", transform=T)
    again = a.register_portal("p1", source="a", target="b", transform=T)
    assert again["status"] == "unchanged"
    assert a.stats()["portals"] == 1
    with pytest.raises(sp.PortalError) as exc:
        a.register_portal("p1", source="b", target="a", transform=T)
    assert exc.value.code == "PORTAL_DUP_ID"
    assert a.describe_portal("p1")["source"] == "a"


def test_stencil_tag_masks_recursion_bits():
    a = make(stencil_bits=8, max_depth=4)
    assert [a.stencil_tag(depth) for depth in range(5)] == [1, 3, 7, 15, 31]
    deep = make(stencil_bits=8, max_depth=7)
    assert deep.stencil_tag(7) == 255
    with pytest.raises(sp.PortalError) as exc:
        a.stencil_tag(-1)
    assert exc.value.code == "PORTAL_BAD_DEPTH"
    with pytest.raises(sp.PortalError) as exc:
        a.stencil_tag(5)
    assert exc.value.code == "PORTAL_BAD_DEPTH"


def test_frame_state_machine():
    a = graph()
    with pytest.raises(sp.PortalError) as exc:
        a.render_plan("a")
    assert exc.value.code == "PORTAL_FRAME_STATE"
    assert a.begin_frame() == 1
    with pytest.raises(sp.PortalError) as exc:
        a.begin_frame()
    assert exc.value.code == "PORTAL_FRAME_STATE"
    out = a.end_frame()
    assert out["frame"] == 1
    assert out["passes"] == 0
    with pytest.raises(sp.PortalError) as exc:
        a.end_frame()
    assert exc.value.code == "PORTAL_FRAME_STATE"


def test_render_plan_follows_enabled_portals_breadth_first():
    a = graph()
    a.begin_frame()
    plan = a.render_plan("a")
    assert [row["room"] for row in plan] == ["a", "b", "c", "d"]
    assert [row["depth"] for row in plan] == [0, 1, 1, 2]
    assert [row["ref"] for row in plan] == [1, 3, 3, 7]
    assert [row["clip_count"] for row in plan] == [0, 1, 1, 2]
    assert plan[0]["via"] is None
    assert plan[1]["via"] == "p1"
    assert plan[3]["via"] == "p3"
    assert a.reachable_rooms("a") == ["a", "b", "c", "d"]


def test_render_plan_visits_room_once_at_nearest_depth():
    a = graph()
    a.register_portal("p5", source="b", target="a", transform=T)
    assert a.reachable_rooms("a") == ["a", "b", "c", "d"]
    a.begin_frame()
    plan = a.render_plan("a")
    assert [row["room"] for row in plan] == ["a", "b", "c", "d"]
    assert a.stats()["passes"] == 4


def test_disabled_portal_and_reachable_rooms():
    a = graph()
    out = a.set_portal_enabled("p2", False)
    assert out["changed"] is True
    assert a.reachable_rooms("a") == ["a", "b", "d"]
    a.begin_frame()
    plan = a.render_plan("a")
    assert [row["room"] for row in plan] == ["a", "b", "d"]
    assert [row["depth"] for row in plan] == [0, 1, 2]
    again = a.set_portal_enabled("p2", True)
    assert again["changed"] is True
    assert a.reachable_rooms("a") == ["a", "b", "c", "d"]
    with pytest.raises(sp.PortalError) as exc:
        a.set_portal_enabled("missing", True)
    assert exc.value.code == "PORTAL_UNKNOWN_PORTAL"


def test_max_depth_limits_traversal():
    a = make(max_depth=1)
    for room in ("a", "b", "c"):
        a.register_room(room)
    a.register_portal("p1", source="a", target="b", transform=T)
    a.register_portal("p2", source="b", target="c", transform=T)
    assert a.reachable_rooms("a") == ["a", "b"]
    a.begin_frame()
    plan = a.render_plan("a")
    assert [row["room"] for row in plan] == ["a", "b"]
    assert plan[1]["ref"] == 3


def test_unregister_room_cascades_portals():
    a = graph()
    out = a.unregister_room("b")
    assert out["removed_portals"] == ["p1", "p3"]
    assert a.stats()["rooms"] == 3
    assert a.stats()["portals"] == 2
    a.begin_frame()
    plan = a.render_plan("a")
    assert [row["room"] for row in plan] == ["a", "c", "d"]
    assert a.validate()["ok"] is True


def test_frame_budget_rejects_plan_atomically():
    a = make(frame_budget=3)
    for room in ("a", "b", "c", "d"):
        a.register_room(room)
    a.register_portal("p1", source="a", target="b", transform=T)
    a.register_portal("p2", source="a", target="c", transform=T)
    a.register_portal("p3", source="b", target="d", transform=T)
    a.begin_frame()
    with pytest.raises(sp.PortalError) as exc:
        a.render_plan("a")
    assert exc.value.code == "PORTAL_FRAME_BUDGET"
    assert a.stats()["passes"] == 0
    assert a.stats()["budget_rejected"] == 1
    assert a.end_frame()["passes"] == 0


def test_snapshot_restore_round_trips_through_json():
    a = graph()
    a.begin_frame()
    first = a.render_plan("a")
    snap = json.loads(json.dumps(a.snapshot()))
    b = make()
    out = b.restore(snap)
    assert out["rooms"] == 4
    assert out["portals"] == 4
    assert b.stats() == a.stats()
    assert b.render_plan("a") == first
    assert a.render_plan("a") == first
    assert b.stats() == a.stats()
    assert b.end_frame() == a.end_frame()


def test_invalid_snapshot_is_rejected_without_mutating():
    a = graph()
    a.begin_frame()
    a.render_plan("a")
    before = a.stats()
    with pytest.raises(sp.PortalError) as exc:
        a.restore({"version": 9})
    assert exc.value.code == "PORTAL_SNAPSHOT_INVALID"
    broken = a.snapshot()
    broken["portals"][0]["transform"] = T[:15]
    with pytest.raises(sp.PortalError) as exc:
        a.restore(broken)
    assert exc.value.code == "PORTAL_SNAPSHOT_INVALID"
    assert a.stats() == before
    assert a.describe_portal("p1")["source"] == "a"


def test_concurrent_portal_registration_keeps_every_portal():
    a = make()
    a.register_room("hub")
    for index in range(8):
        a.register_room(f"r{index}")

    def worker(index):
        for offset in range(25):
            a.register_portal(f"p{index}-{offset}", source=f"r{index}",
                              target="hub", transform=T)

    threads = [threading.Thread(target=worker, args=(index,)) for index in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert a.stats()["portals"] == 200
    assert a.stats()["enabled_portals"] == 200
    assert a.reachable_rooms("r3") == ["hub", "r3"]
