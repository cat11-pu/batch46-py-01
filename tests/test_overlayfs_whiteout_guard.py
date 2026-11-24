import threading

import pytest

import overlayfs_whiteout_guard as owg


def make(**kwargs):
    return owg.OverlayGuard(**kwargs)


def lower(guard, name, entries):
    return guard.add_lower(name, entries)


def test_lower_layers_resolve_entries():
    guard = make()
    out = lower(guard, "base", [
        {"path": "/etc", "kind": "dir"},
        {"path": "/etc/passwd", "kind": "file", "content": "root"},
    ])
    assert out["status"] == "added"
    assert out["count"] == 2
    resolved = guard.resolve("/etc/passwd")
    assert resolved["kind"] == "file"
    assert resolved["layer"] == "base"
    assert resolved["content"] == "root"
    assert guard.resolve("/etc")["kind"] == "dir"
    assert guard.resolve("/missing")["kind"] == "absent"
    assert guard.resolve("/missing")["hidden_by"] is None
    with pytest.raises(owg.OverlayError) as exc:
        lower(guard, "base", [])
    assert exc.value.code == "OP_DUP_LAYER"
    with pytest.raises(owg.OverlayError) as exc:
        lower(guard, "bad", [{"path": "/x", "kind": "whiteout"}])
    assert exc.value.code == "OP_KIND_INVALID"
    with pytest.raises(owg.OverlayError) as exc:
        lower(guard, "dupes", [{"path": "/x", "kind": "dir"},
                               {"path": "/x/", "kind": "dir"}])
    assert exc.value.code == "OP_DUP_ENTRY"


def test_upper_entry_overrides_lower_and_entry_cap():
    guard = make(max_entries=2)
    lower(guard, "base", [{"path": "/low", "kind": "file",
                           "content": "lower"}])
    out = guard.add_upper("/low", "file", content="upper")
    assert out["status"] == "added"
    resolved = guard.resolve("/low")
    assert resolved["layer"] == "upper"
    assert resolved["content"] == "upper"
    with pytest.raises(owg.OverlayError) as exc:
        guard.add_upper("/low", "file")
    assert exc.value.code == "OP_EXISTS"
    guard.add_upper("/u2", "file", content="two")
    assert guard.stats()["upper"] == 2
    with pytest.raises(owg.OverlayError) as exc:
        guard.add_upper("/u3", "file", content="three")
    assert exc.value.code == "OP_LIMIT"
    assert guard.stats()["upper"] == 2


def test_whiteout_hides_lower_entry_and_merged_listing():
    guard = make()
    lower(guard, "base", [{"path": "/secret", "kind": "file",
                           "content": "s3cr3t"}])
    guard.add_upper("/secret", "whiteout")
    guard.add_upper("/visible", "file", content="ok")
    hidden = guard.resolve("/secret")
    assert hidden["kind"] == "absent"
    assert hidden["hidden_by"] == "whiteout"
    assert hidden["layer"] is None
    rows = guard.list_merged("/")
    assert [row["path"] for row in rows] == ["/visible"]
    assert rows[0]["layer"] == "upper"
    assert guard.stats()["whiteouts"] == 1


def test_removing_upper_only_file_leaves_no_whiteout():
    guard = make()
    guard.add_upper("/tmp/x", "file", content="payload")
    first = guard.remove("/tmp/x")
    assert first["status"] == "removed"
    assert first["whiteout"] is False
    assert guard.resolve("/tmp/x")["kind"] == "absent"
    assert guard.resolve("/tmp/x")["hidden_by"] is None
    assert guard.stats()["whiteouts"] == 0
    with pytest.raises(owg.OverlayError) as exc:
        guard.remove("/tmp/x")
    assert exc.value.code == "OP_NOT_FOUND"
    with pytest.raises(owg.OverlayError) as exc:
        guard.remove("/missing")
    assert exc.value.code == "OP_NOT_FOUND"


def test_removing_lower_only_file_creates_whiteout():
    guard = make()
    lower(guard, "base", [
        {"path": "/data", "kind": "dir"},
        {"path": "/data/log", "kind": "file", "content": "line"},
    ])
    out = guard.remove("/data/log")
    assert out["status"] == "removed"
    assert out["whiteout"] is True
    hidden = guard.resolve("/data/log")
    assert hidden["kind"] == "absent"
    assert hidden["hidden_by"] == "whiteout"
    assert guard.list_merged("/data") == []
    second = guard.remove("/data/log")
    assert second["status"] == "unchanged"
    assert second["whiteout"] is True


def test_directory_remove_requires_recursive_for_populated_tree():
    guard = make()
    lower(guard, "base", [
        {"path": "/var", "kind": "dir"},
        {"path": "/var/a", "kind": "file", "content": "a"},
        {"path": "/var/b", "kind": "file", "content": "b"},
        {"path": "/empty", "kind": "dir"},
    ])
    with pytest.raises(owg.OverlayError) as exc:
        guard.remove("/var")
    assert exc.value.code == "OP_NOT_EMPTY"
    assert guard.resolve("/var/a")["kind"] == "file"
    out = guard.remove("/var", recursive=True)
    assert out["status"] == "removed"
    assert out["opaque"] is True
    state = guard.resolve("/var")
    assert state["kind"] == "dir"
    assert state["opaque"] is True
    assert guard.resolve("/var/a")["kind"] == "absent"
    assert guard.resolve("/var/a")["hidden_by"] == "opaque:/var"
    empty = guard.remove("/empty")
    assert empty["opaque"] is True
    assert guard.stats()["opaque"] == 2


def test_upper_child_under_opaque_directory_stays_visible():
    guard = make()
    lower(guard, "base", [
        {"path": "/a", "kind": "dir"},
        {"path": "/a/lower", "kind": "file", "content": "L"},
    ])
    guard.remove("/a", recursive=True)
    guard.add_upper("/a/upper", "file", content="U")
    child = guard.resolve("/a/upper")
    assert child["kind"] == "file"
    assert child["layer"] == "upper"
    assert child["content"] == "U"
    hidden = guard.resolve("/a/lower")
    assert hidden["kind"] == "absent"
    assert hidden["hidden_by"] == "opaque:/a"
    rows = guard.list_merged("/a")
    assert [row["path"] for row in rows] == ["/a/upper"]


def test_snapshot_restore_rolls_back_whiteouts_and_journal():
    guard = make()
    lower(guard, "base", [
        {"path": "/d", "kind": "dir"},
        {"path": "/d/f", "kind": "file", "content": "lower"},
    ])
    guard.add_upper("/d/f", "file", content="upper")
    snap = guard.snapshot()
    guard.rename("/d/f", "/d/g")
    guard.add_upper("/x", "file", content="x")
    assert guard.stats()["upper"] == 3
    restored = guard.restore(snap)
    assert restored["status"] == "restored"
    assert guard.stats()["upper"] == 1
    assert guard.stats()["seq"] == 1
    assert len(guard.journal()) == 1
    assert guard.resolve("/d/f")["content"] == "upper"
    assert guard.resolve("/d/g")["kind"] == "absent"
    assert len(snap["upper"]) == 1
    with pytest.raises(owg.OverlayError) as exc:
        guard.restore({})
    assert exc.value.code == "OP_SNAPSHOT_INVALID"
    assert guard.stats()["upper"] == 1


def test_rename_upper_file_over_lower_leaves_whiteout_at_source():
    guard = make()
    lower(guard, "base", [{"path": "/a", "kind": "file",
                           "content": "old"}])
    guard.add_upper("/a", "file", content="new")
    out = guard.rename("/a", "/b")
    assert out["status"] == "moved"
    assert out["whiteout"] is True
    assert guard.resolve("/b")["content"] == "new"
    assert guard.resolve("/a")["kind"] == "absent"
    assert guard.resolve("/a")["hidden_by"] == "whiteout"
    rows = guard.list_merged("/")
    assert [row["path"] for row in rows] == ["/b"]


def test_rename_upper_only_file_does_not_create_whiteout():
    guard = make()
    guard.add_upper("/only", "file", content="x")
    out = guard.rename("/only", "/moved")
    assert out["whiteout"] is False
    assert guard.resolve("/only")["kind"] == "absent"
    assert guard.resolve("/only")["hidden_by"] is None
    assert guard.resolve("/moved")["content"] == "x"
    lower(guard, "base", [{"path": "/dst", "kind": "file",
                           "content": "lower"}])
    guard.add_upper("/shadow", "file", content="upper")
    shadow = guard.rename("/shadow", "/dst")
    assert shadow["status"] == "moved"
    assert guard.resolve("/dst")["layer"] == "upper"
    assert guard.resolve("/dst")["content"] == "upper"


def test_rename_rejects_missing_destination_conflict_and_cycles():
    guard = make()
    guard.add_upper("/only", "file", content="x")
    guard.add_upper("/taken", "file", content="y")
    with pytest.raises(owg.OverlayError) as exc:
        guard.rename("/only", "/taken")
    assert exc.value.code == "OP_DST_EXISTS"
    with pytest.raises(owg.OverlayError) as exc:
        guard.rename("/only", "/only/child")
    assert exc.value.code == "OP_INVALID_MOVE"
    with pytest.raises(owg.OverlayError) as exc:
        guard.rename("/missing", "/x")
    assert exc.value.code == "OP_NOT_FOUND"
    guard.add_upper("/ghost", "whiteout")
    with pytest.raises(owg.OverlayError) as exc:
        guard.rename("/ghost", "/x")
    assert exc.value.code == "OP_NOT_FOUND"
    assert guard.rename("/only", "/only")["status"] == "unchanged"


def test_rename_directory_moves_children_and_hides_old_tree():
    guard = make()
    lower(guard, "base", [
        {"path": "/d", "kind": "dir"},
        {"path": "/d/old", "kind": "file", "content": "old"},
    ])
    guard.add_upper("/d", "dir")
    guard.add_upper("/d/x", "file", content="xx")
    guard.add_upper("/d/y", "file", content="yy")
    out = guard.rename("/d", "/e")
    assert out["status"] == "moved"
    assert out["moved"] == 3
    assert out["opaque"] is True
    assert guard.resolve("/e/x")["content"] == "xx"
    assert guard.resolve("/e/y")["content"] == "yy"
    assert guard.resolve("/d/x")["kind"] == "absent"
    assert guard.resolve("/d/x")["hidden_by"] == "opaque:/d"
    rows = guard.list_merged("/e")
    assert [row["path"] for row in rows] == ["/e/x", "/e/y"]
    stats = guard.stats()
    assert stats["upper"] == 4
    assert stats["opaque"] == 1


def test_cleanup_removes_orphan_whiteouts_only():
    guard = make()
    lower(guard, "base", [{"path": "/data", "kind": "file",
                           "content": "d"}])
    guard.add_upper("/ghost", "whiteout")
    guard.add_upper("/data", "whiteout")
    preview = guard.cleanup(dry_run=True)
    assert preview["dry_run"] is True
    assert preview["removed"] == ["/ghost"]
    assert guard.stats()["upper"] == 2
    out = guard.cleanup()
    assert out["removed"] == ["/ghost"]
    assert out["count"] == 1
    assert guard.stats()["upper"] == 1
    assert guard.resolve("/data")["hidden_by"] == "whiteout"
    again = guard.cleanup()
    assert again["count"] == 0
    assert again["removed"] == []


def test_compact_drops_whiteouts_redundant_under_opaque_directories():
    guard = make()
    lower(guard, "base", [{"path": "/b", "kind": "file",
                           "content": "b"}])
    guard.add_upper("/a", "opaque")
    guard.add_upper("/a/gone", "whiteout")
    guard.add_upper("/b", "whiteout")
    out = guard.compact()
    assert out["removed"] == ["/a/gone"]
    assert out["count"] == 1
    stats = guard.stats()
    assert stats["whiteouts"] == 1
    assert stats["opaque"] == 1
    assert guard.resolve("/a/gone")["hidden_by"] == "opaque:/a"
    assert guard.resolve("/b")["hidden_by"] == "whiteout"


def test_concurrent_removes_keep_journal_bounded_and_contiguous():
    guard = make(max_journal=5)
    entries = [{"path": f"/w/{index}", "kind": "file",
                "content": str(index)} for index in range(8)]
    lower(guard, "base", entries)
    barrier = threading.Barrier(8)
    results = []
    lock = threading.Lock()

    def worker(index):
        barrier.wait()
        out = guard.remove(f"/w/{index}")
        with lock:
            results.append(out)

    threads = [threading.Thread(target=worker, args=(index,))
               for index in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(results) == 8
    assert all(row["status"] == "removed" and row["whiteout"]
               for row in results)
    stats = guard.stats()
    assert stats["upper"] == 8
    assert stats["whiteouts"] == 8
    rows = guard.journal()
    assert [row["seq"] for row in rows] == [4, 5, 6, 7, 8]
    for index in range(8):
        state = guard.resolve(f"/w/{index}")
        assert state["kind"] == "absent"
        assert state["hidden_by"] == "whiteout"
