import threading

import pytest

import swapchain_resize_guard as swr


def make(**kwargs):
    return swr.SwapchainResize(**kwargs)


def rebuild_to(a, width, height, frame=0, **kwargs):
    a.observe(width, height, frame=frame, **kwargs)
    a.poll(frame + 1)
    return a.rebuild(frame + 1)


def test_steady_surface_reports_no_action():
    a = make()
    assert a.observe(1280, 720, frame=0)["action"] == "none"
    assert a.poll(0)["action"] == "none"
    config = a.config()
    assert config["generation"] == 1
    assert config["images"] == 2
    assert config["width"] == 1280
    assert config["height"] == 720
    assert config["suspended"] is False
    assert a.stats()["rebuilds"] == 0


def test_resize_is_debounced_before_rebuild_is_allowed():
    a = make(debounce_frames=2)
    assert a.observe(1600, 900, frame=10)["action"] == "pending"
    assert a.poll(10)["action"] == "none"
    with pytest.raises(swr.SwapchainResizeError) as exc:
        a.rebuild(10)
    assert exc.value.code == "SWR_DEBOUNCE_PENDING"
    assert a.poll(11)["action"] == "rebuild"
    out = a.rebuild(11)
    assert out["generation"] == 2
    assert out["width"] == 1600
    assert out["height"] == 900
    assert out["cause"] == "resize"
    assert a.poll(12)["action"] == "none"


def test_rebuild_reports_generation_images_and_budget_estimate():
    a = make(min_images=2, max_images=3)
    out = rebuild_to(a, 1600, 900)
    assert out["action"] == "rebuild"
    assert out["images"] == 2
    assert out["cause"] == "resize"
    assert out["required_bytes"] == 1600 * 900 * 2 * 4
    assert a.estimate_bytes(1600, 900) == out["required_bytes"]
    row = a.history()[-1]
    assert row["generation"] == 2
    assert row["cause"] == "resize"
    assert a.config()["images"] == 2


def test_mailbox_and_immediate_image_counts():
    a = make(min_images=2, max_images=4)
    out = rebuild_to(a, 800, 600, present="mailbox")
    assert out["images"] == 3
    b = make(min_images=2, max_images=2)
    out = rebuild_to(b, 800, 600, present="mailbox")
    assert out["images"] == 2
    c = make()
    out = rebuild_to(c, 800, 600, present="immediate")
    assert out["images"] == 2
    with pytest.raises(swr.SwapchainResizeError) as exc:
        c.observe(800, 600, present="fifo2", frame=4)
    assert exc.value.code == "SWR_PRESENT_INVALID"


def test_format_only_change_triggers_rebuild():
    a = make()
    out = rebuild_to(a, 1280, 720, format="rgba16f")
    assert out["cause"] == "format"
    assert out["format"] == "rgba16f"
    assert out["generation"] == 2
    assert a.config()["format"] == "rgba16f"


def test_minimized_surface_suspends_and_blocks_present():
    a = make()
    assert a.observe(0, 0, frame=0)["action"] == "pending"
    assert a.poll(0)["action"] == "suspend"
    a.suspend(frame=0)
    assert a.config()["suspended"] is True
    with pytest.raises(swr.SwapchainResizeError) as exc:
        a.present(1, 0)
    assert exc.value.code == "SWR_SUSPENDED"
    with pytest.raises(swr.SwapchainResizeError) as exc:
        a.acquire(1)
    assert exc.value.code == "SWR_SUSPENDED"
    with pytest.raises(swr.SwapchainResizeError) as exc:
        a.observe(800, 0, frame=1)
    assert exc.value.code == "SWR_SIZE_INVALID"


def test_resume_after_minimize_rebuilds_a_new_generation():
    a = make()
    a.suspend()
    with pytest.raises(swr.SwapchainResizeError) as exc:
        make().resume(800, 600, frame=0)
    assert exc.value.code == "SWR_NOT_SUSPENDED"
    resumed = a.resume(1920, 1080, frame=5)
    assert resumed["action"] == "pending"
    assert a.poll(5)["action"] == "none"
    assert a.poll(6)["action"] == "rebuild"
    out = a.rebuild(6)
    assert out["generation"] == 2
    assert out["cause"] == "resume"
    assert a.config()["suspended"] is False
    assert a.config()["width"] == 1920
    assert a.config()["height"] == 1080


def test_acquire_and_present_cycle_images_in_order():
    a = make(min_images=2, max_images=3)
    first = a.acquire(1)
    assert first["image"] == 0
    assert first["in_flight"] == 1
    assert a.present(1, 0)["presents"] == 1
    second = a.acquire(1)
    assert second["image"] == 1
    a.present(1, 1)
    third = a.acquire(1)
    assert third["image"] == 0
    a.present(1, 2)
    with pytest.raises(swr.SwapchainResizeError) as exc:
        a.present(1, 3)
    assert exc.value.code == "SWR_NOT_ACQUIRED"
    assert a.stats()["presents"] == 3
    assert a.config()["in_flight"] == 0


def test_stale_generation_present_is_rejected():
    a = make()
    rebuild_to(a, 1600, 900)
    with pytest.raises(swr.SwapchainResizeError) as exc:
        a.present(1, 0)
    assert exc.value.code == "SWR_STALE_SWAPCHAIN"
    with pytest.raises(swr.SwapchainResizeError) as exc:
        a.acquire(1)
    assert exc.value.code == "SWR_STALE_SWAPCHAIN"
    assert a.stats()["stale_presents"] == 1
    assert a.stats()["presents"] == 0


def test_in_flight_image_blocks_rebuild_until_presented():
    a = make()
    a.observe(1600, 900, frame=0)
    a.poll(1)
    a.acquire(1)
    with pytest.raises(swr.SwapchainResizeError) as exc:
        a.rebuild(1)
    assert exc.value.code == "SWR_IN_FLIGHT"
    assert a.config()["generation"] == 1
    a.present(1, 1)
    out = a.rebuild(1)
    assert out["generation"] == 2
    assert out["cause"] == "resize"


def test_memory_budget_blocks_oversized_swapchain():
    a = make(max_bytes=8_000_000)
    a.observe(1920, 1080, frame=0)
    a.poll(1)
    required = 1920 * 1080 * 2 * 4
    with pytest.raises(swr.SwapchainResizeError) as exc:
        a.rebuild(1)
    assert exc.value.code == "SWR_BUDGET_EXCEEDED"
    assert exc.value.detail["required"] == required
    config = a.config()
    assert config["generation"] == 1
    assert config["width"] == 1280
    a.observe(800, 600, frame=2)
    a.poll(3)
    out = a.rebuild(3)
    assert out["generation"] == 2
    assert out["width"] == 800
    assert a.estimate_bytes(800, 600) == 800 * 600 * 2 * 4


def test_retire_keeps_bounded_history_and_destroys_oldest():
    a = make(max_retained=1)
    rebuild_to(a, 1600, 900)
    first = a.retire(1)
    assert first["retained"] == [1]
    assert first["destroyed"] == []
    rebuild_to(a, 1800, 1000, frame=2)
    second = a.retire(2)
    assert second["retained"] == [2]
    assert second["destroyed"] == [1]
    with pytest.raises(swr.SwapchainResizeError) as exc:
        a.retire(3)
    assert exc.value.code == "SWR_CURRENT_GENERATION"
    with pytest.raises(swr.SwapchainResizeError) as exc:
        a.retire(2)
    assert exc.value.code == "SWR_GENERATION_RETIRED"
    with pytest.raises(swr.SwapchainResizeError) as exc:
        a.retire(99)
    assert exc.value.code == "SWR_GENERATION_UNKNOWN"
    with pytest.raises(swr.SwapchainResizeError) as exc:
        a.retire(0)
    assert exc.value.code == "SWR_GENERATION_UNKNOWN"
    stats = a.stats()
    assert stats["retired"] == 2
    assert stats["destroyed"] == 1


def test_snapshot_restore_preserves_surface_and_history():
    a = make()
    rebuild_to(a, 1600, 900)
    a.retire(1)
    snapshot = a.snapshot()
    b = make()
    restored = b.restore(snapshot)
    assert restored == {"restored": True, "generation": 2}
    assert b.config() == a.config()
    assert b.history() == a.history()
    assert b.stats() == a.stats()
    assert b.history()[0]["cause"] == "resize"
    with pytest.raises(swr.SwapchainResizeError) as exc:
        b.restore({"version": 4})
    assert exc.value.code == "SWR_SNAPSHOT_INVALID"
    out = rebuild_to(b, 1800, 1000, frame=2)
    assert out["generation"] == 3


def test_concurrent_presents_and_rebuilds_are_serialized():
    a = make()
    barrier = threading.Barrier(8)
    errors = []

    def present_worker():
        barrier.wait()
        try:
            a.acquire(1)
            a.present(1, 0)
        except Exception as exc:  # pragma: no cover - collected below
            errors.append(exc)

    threads = [threading.Thread(target=present_worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    assert a.stats()["presents"] == 8
    assert a.config()["in_flight"] == 0
    a.observe(1600, 900, frame=0)
    a.poll(1)
    barrier = threading.Barrier(4)
    results = []

    def rebuild_worker():
        barrier.wait()
        try:
            results.append(a.rebuild(1)["generation"])
        except swr.SwapchainResizeError as exc:
            results.append(exc.code)
        except Exception as exc:  # pragma: no cover - collected below
            results.append(str(exc))

    threads = [threading.Thread(target=rebuild_worker) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert results.count(2) == 1
    assert results.count("SWR_NO_PENDING") == 3
    assert a.stats()["rebuilds"] == 1
    assert a.config()["generation"] == 2


def test_history_records_causes_in_generation_order():
    a = make()
    rebuild_to(a, 1600, 900, frame=0)
    rebuild_to(a, 1600, 900, frame=2, format="rgba16f")
    rebuild_to(a, 1600, 900, frame=4, format="rgba16f", present="mailbox")
    history = a.history()
    assert [row["generation"] for row in history] == [2, 3, 4]
    assert [row["cause"] for row in history] == ["resize", "format", "present"]
    assert a.stats()["rebuilds"] == 3
    assert a.config()["images"] == 3
    assert a.estimate_bytes() == 1600 * 900 * 3 * 4
