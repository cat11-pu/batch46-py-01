import threading

import pytest

import inotify_watch_guard as iwg


def make(**kwargs):
    return iwg.InotifyGuard(**kwargs)


def test_add_watch_allocates_increasing_descriptors():
    guard = make()
    first = guard.add_watch("/srv/a", ("create",))
    second = guard.add_watch("/srv/b", ("modify",))
    assert first["status"] == "added"
    assert first["wd"] == 1
    assert second["wd"] == 2
    assert guard.watch_for("/srv/b") == 2
    assert guard.path_for(2) == "/srv/b"
    stats = guard.stats()
    assert stats["watches"] == 2
    assert stats["next_wd"] == 3


def test_duplicate_watch_is_unchanged_or_merges_masks():
    guard = make()
    guard.add_watch("/srv", ("create",))
    same = guard.add_watch("/srv", ("create",))
    assert same["status"] == "unchanged"
    assert same["wd"] == 1
    merged = guard.add_watch("/srv", ("modify",))
    assert merged["status"] == "updated"
    assert merged["wd"] == 1
    assert merged["mask"] == ["create", "modify"]
    assert guard.stats()["watches"] == 1


def test_path_normalization_collapses_equivalent_spellings():
    guard = make()
    first = guard.add_watch("/srv/a", ("create",))
    for spelling in ("/srv/a/", "/srv/./a", "/srv/a/./child/.."):
        out = guard.add_watch(spelling, ("create",))
        assert out["status"] == "unchanged"
        assert out["wd"] == first["wd"]
    assert guard.stats()["watches"] == 1


def test_invalid_owner_path_and_mask_are_rejected():
    guard = make()
    with pytest.raises(iwg.InotifyError) as exc:
        guard.add_watch("/srv", ("bogus",))
    assert exc.value.code == "INOTIFY_MASK_INVALID"
    with pytest.raises(iwg.InotifyError) as exc:
        guard.add_watch("relative", ("create",))
    assert exc.value.code == "INOTIFY_PATH_INVALID"
    with pytest.raises(iwg.InotifyError) as exc:
        guard.add_watch("/srv", ("create",), owner="")
    assert exc.value.code == "INOTIFY_OWNER_INVALID"
    with pytest.raises(iwg.InotifyError) as exc:
        guard.add_watch("/srv", ())
    assert exc.value.code == "INOTIFY_MASK_INVALID"
    assert guard.stats()["watches"] == 0


def test_removed_descriptor_becomes_stale_and_not_reusable():
    guard = make()
    with pytest.raises(iwg.InotifyError) as exc:
        guard.remove_watch("/missing")
    assert exc.value.code == "INOTIFY_WD_UNKNOWN"
    guard.add_watch("/srv/a", ("create",))
    out = guard.remove_watch("/srv/a")
    assert out["status"] == "removed"
    assert out["wd"] == 1
    with pytest.raises(iwg.InotifyError) as exc:
        guard.event(1, "create")
    assert exc.value.code == "INOTIFY_WD_STALE"
    with pytest.raises(iwg.InotifyError) as exc:
        guard.remove_watch(1)
    assert exc.value.code == "INOTIFY_WD_STALE"
    with pytest.raises(iwg.InotifyError) as exc:
        guard.remove_watch(99)
    assert exc.value.code == "INOTIFY_WD_UNKNOWN"
    with pytest.raises(iwg.InotifyError) as exc:
        guard.watch_for("/srv/a")
    assert exc.value.code == "INOTIFY_WD_UNKNOWN"


def test_global_quota_and_limit_shrinking_guard():
    guard = make(max_watches=2, max_per_owner=5)
    guard.add_watch("/a", ("create",), owner="root")
    guard.add_watch("/b", ("create",), owner="svc")
    with pytest.raises(iwg.InotifyError) as exc:
        guard.add_watch("/c", ("create",), owner="third")
    assert exc.value.code == "INOTIFY_QUOTA"
    with pytest.raises(iwg.InotifyError) as exc:
        guard.set_limit(max_watches=1)
    assert exc.value.code == "INOTIFY_QUOTA"
    with pytest.raises(iwg.InotifyError) as exc:
        guard.set_limit(max_per_owner=0)
    assert exc.value.code == "INOTIFY_QUOTA"
    assert guard.set_limit(max_watches=4)["limits"]["max_watches"] == 4
    added = guard.add_watch("/c", ("create",), owner="third")
    assert added["wd"] == 3
    assert guard.stats()["watches"] == 3


def test_per_owner_quota_does_not_block_other_owners():
    guard = make(max_watches=10, max_per_owner=1)
    guard.add_watch("/a", ("create",), owner="root")
    with pytest.raises(iwg.InotifyError) as exc:
        guard.add_watch("/b", ("create",), owner="root")
    assert exc.value.code == "INOTIFY_OWNER_QUOTA"
    out = guard.add_watch("/b", ("create",), owner="svc")
    assert out["status"] == "added"
    stats = guard.stats()
    assert stats["owners"] == {"root": 1, "svc": 1}
    assert stats["watches"] == 2


def test_batch_is_atomic_when_quota_is_exceeded():
    guard = make(max_watches=2)
    guard.add_watch("/one", ("create",))
    before = guard.stats()
    entries = [("/two", ("create",)), ("/three", ("create",)),
               ("/four", ("create",))]
    with pytest.raises(iwg.InotifyError) as exc:
        guard.add_watch_batch(entries)
    assert exc.value.code == "INOTIFY_QUOTA"
    after = guard.stats()
    assert after["watches"] == before["watches"] == 1
    assert after["next_wd"] == before["next_wd"] == 2
    out = guard.add_watch("/two", ("create",))
    assert out["wd"] == 2


def test_successful_batch_allocates_in_order_and_rejects_duplicates():
    guard = make()
    out = guard.add_watch_batch([
        ("/alpha", ("create",)),
        ("/beta", ("modify",)),
        ("/gamma", ("delete",)),
    ])
    assert out["status"] == "added"
    assert out["wds"] == [1, 2, 3]
    assert out["new"] == 3
    assert guard.stats()["watches"] == 3
    with pytest.raises(iwg.InotifyError) as exc:
        guard.add_watch_batch([
            ("/alpha", ("create",)),
            ("/alpha/", ("delete",)),
        ])
    assert exc.value.code == "INOTIFY_DUP_BATCH"
    assert guard.stats()["watches"] == 3
    assert guard.stats()["next_wd"] == 4


def test_ignored_event_drops_watch_and_frees_owner_quota():
    guard = make(max_per_owner=1)
    guard.add_watch("/srv/a", ("create",), owner="team")
    out = guard.event(1, "ignored")
    assert out["status"] == "ignored"
    assert guard.stats()["watches"] == 0
    assert guard.stats()["owners"] == {}
    rows = guard.ignored()
    assert len(rows) == 1
    assert rows[0]["wd"] == 1
    assert rows[0]["path"] == "/srv/a"
    with pytest.raises(iwg.InotifyError) as exc:
        guard.event(1, "create")
    assert exc.value.code == "INOTIFY_WD_STALE"
    replacement = guard.add_watch("/srv/b", ("create",), owner="team")
    assert replacement["wd"] == 2
    assert guard.ignored(1)[0]["path"] == "/srv/a"


def test_directory_events_join_names_and_filter_unsubscribed_masks():
    guard = make()
    guard.add_watch("/srv", ("create",), is_dir=True)
    out = guard.event(1, "create", name="app.conf")
    assert out["path"] == "/srv/app.conf"
    assert out["status"] == "delivered"
    guard.add_watch("/srv/app.conf", ("create",))
    with pytest.raises(iwg.InotifyError) as exc:
        guard.event(2, "create", name="child")
    assert exc.value.code == "INOTIFY_NAME_INVALID"
    assert guard.event(2, "modify")["status"] == "filtered"
    with pytest.raises(iwg.InotifyError) as exc:
        guard.event(1, "bogus")
    assert exc.value.code == "INOTIFY_MASK_INVALID"
    assert guard.stats()["delivered"] == 1


def test_move_keeps_descriptor_and_updates_path_index():
    guard = make()
    guard.add_watch("/old", ("create",), is_dir=True)
    out = guard.move_watch("/old", "/new")
    assert out["status"] == "moved"
    assert out["wd"] == 1
    with pytest.raises(iwg.InotifyError) as exc:
        guard.watch_for("/old")
    assert exc.value.code == "INOTIFY_WD_UNKNOWN"
    assert guard.watch_for("/new") == 1
    assert guard.path_for(1) == "/new"
    assert guard.move_watch("/new", "/new")["status"] == "unchanged"
    guard.add_watch("/existing", ("create",))
    with pytest.raises(iwg.InotifyError) as exc:
        guard.move_watch("/new", "/existing")
    assert exc.value.code == "INOTIFY_EXISTS"
    assert guard.event(1, "create", name="leaf")["path"] == "/new/leaf"


def test_same_path_different_owners_are_isolated():
    guard = make()
    root_wd = guard.add_watch("/shared", ("create",), owner="root")["wd"]
    svc_wd = guard.add_watch("/shared", ("create",), owner="svc")["wd"]
    assert root_wd != svc_wd
    guard.remove_watch("/shared", owner="root")
    assert guard.watch_for("/shared", owner="svc") == svc_wd
    assert guard.path_for(svc_wd) == "/shared"
    with pytest.raises(iwg.InotifyError) as exc:
        guard.watch_for("/shared", owner="root")
    assert exc.value.code == "INOTIFY_WD_UNKNOWN"
    assert guard.stats()["owners"] == {"svc": 1}


def test_concurrent_adds_never_exceed_the_owner_quota():
    guard = make(max_watches=64, max_per_owner=4)
    barrier = threading.Barrier(12)
    results = []
    lock = threading.Lock()

    def worker(index):
        barrier.wait()
        try:
            out = guard.add_watch(f"/bulk/{index}", ("create",),
                                  owner="team")
            with lock:
                results.append(("ok", out["wd"]))
        except Exception as error:
            with lock:
                results.append((getattr(error, "code",
                                        type(error).__name__), None))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(12)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    ok = [row for row in results if row[0] == "ok"]
    rejected = [row for row in results
                if row[0] == "INOTIFY_OWNER_QUOTA"]
    assert len(ok) == 4
    assert len(rejected) == 8
    assert len({row[1] for row in ok}) == 4
    stats = guard.stats()
    assert stats["watches"] == 4
    assert stats["owners"] == {"team": 4}
    assert stats["next_wd"] == 5


def test_snapshot_restore_keeps_quota_usage_and_wd_allocator():
    guard = make(max_watches=8)
    guard.add_watch("/a", ("create",))
    guard.add_watch("/b", ("modify",))
    guard.event(2, "ignored")
    snap = guard.snapshot()
    guard.add_watch("/c", ("create",))
    guard.remove_watch("/a")
    restored = guard.restore(snap)
    assert restored["status"] == "restored"
    stats = guard.stats()
    assert stats["watches"] == 1
    assert stats["next_wd"] == 3
    assert guard.watch_for("/a") == 1
    with pytest.raises(iwg.InotifyError) as exc:
        guard.path_for(2)
    assert exc.value.code == "INOTIFY_WD_STALE"
    assert len(guard.ignored()) == 1
    new_wd = guard.add_watch("/d", ("create",))["wd"]
    assert new_wd == 3
    with pytest.raises(iwg.InotifyError) as exc:
        guard.restore({"version": 1})
    assert exc.value.code == "INOTIFY_SNAPSHOT_INVALID"
    assert guard.stats()["watches"] == 2
