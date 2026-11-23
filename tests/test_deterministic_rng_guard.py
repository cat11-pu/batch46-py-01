import copy
import threading

import pytest

import deterministic_rng_guard as rng


def make(seed=0, **kwargs):
    return rng.DeterministicRng(seed, **kwargs)


def test_same_seed_produces_identical_sequences():
    a = make(7)
    b = make(7)
    seq_a = [a.next_u32() for _ in range(20)]
    seq_b = [b.next_u32() for _ in range(20)]
    assert seq_a == seq_b
    assert all(0 <= value < 2 ** 32 for value in seq_a)
    assert len(set(seq_a)) == 20


def test_different_seeds_produce_different_sequences():
    a = make(1)
    b = make(2)
    seq_a = [a.next_u32() for _ in range(10)]
    seq_b = [b.next_u32() for _ in range(10)]
    assert seq_a != seq_b
    assert len(set(seq_a) & set(seq_b)) < 10


def test_named_streams_advance_independently():
    mixed = make(3)
    solo = make(3)
    mixed.create_stream("loot", 99)
    solo.create_stream("loot", 99)
    solo_seq = [solo.next_u32() for _ in range(5)]
    interleaved = []
    for _ in range(5):
        interleaved.append(mixed.next_u32())
        mixed.next_u32("loot")
    assert interleaved == solo_seq
    assert mixed.position() == 5
    assert mixed.position("loot") == 5
    assert solo.position() == 5


def test_unknown_stream_raises_with_label_in_detail():
    r = make(5)
    with pytest.raises(rng.RngError) as exc:
        r.next_u32("ghost")
    assert exc.value.code == "RNG_UNKNOWN_STREAM"
    assert exc.value.detail == "ghost"
    with pytest.raises(rng.RngError) as exc:
        r.position("ghost")
    assert exc.value.code == "RNG_UNKNOWN_STREAM"
    assert r.streams() == ["default"]
    assert r.has_stream("default") is True
    assert r.has_stream("ghost") is False


def test_snapshot_restore_resumes_the_same_values():
    r = make(11)
    [r.next_u32() for _ in range(4)]
    snap = r.snapshot()
    assert snap["version"] == 1
    continued = [r.next_u32() for _ in range(6)]
    r.restore(snap)
    assert [r.next_u32() for _ in range(6)] == continued
    assert r.position() == 10


def test_restore_rejects_a_foreign_snapshot_version():
    r = make(12)
    r.next_u32()
    snap = copy.deepcopy(r.snapshot())
    snap["version"] = 99
    with pytest.raises(rng.RngError) as exc:
        r.restore(snap)
    assert exc.value.code == "RNG_SNAPSHOT_VERSION"
    assert r.position() == 1


def test_draw_budget_is_shared_across_all_streams():
    r = make(5, max_draws=3)
    r.create_stream("loot", 99)
    assert r.remaining() == 3
    r.next_u32()
    r.next_u32("loot")
    assert r.remaining() == 1
    r.next_u32()
    assert r.remaining() == 0
    with pytest.raises(rng.RngError) as exc:
        r.next_float()
    assert exc.value.code == "RNG_BUDGET_EXCEEDED"


def test_next_int_is_inclusive_and_accepts_equal_bounds():
    r = make(21)
    values = [r.next_int("default", 1, 6) for _ in range(120)]
    assert all(1 <= value <= 6 for value in values)
    assert len(set(values)) >= 3
    assert r.next_int("default", 7, 7) == 7
    assert r.next_int("default", -5, -5) == -5


def test_invalid_range_does_not_consume_budget_or_position():
    r = make(21)
    with pytest.raises(rng.RngError) as exc:
        r.next_int("default", 9, 2)
    assert exc.value.code == "RNG_INVALID_RANGE"
    with pytest.raises(rng.RngError) as exc:
        r.next_below("default", 0)
    assert exc.value.code == "RNG_INVALID_RANGE"
    assert r.position() == 0
    assert r.remaining() == r.max_draws


def test_float_and_below_stay_inside_their_ranges():
    r = make(31)
    assert r.next_below("default", 1) == 0
    floats = [r.next_float() for _ in range(200)]
    assert all(0.0 <= value < 1.0 for value in floats)
    assert len(set(floats)) > 150
    lows = [r.next_below("default", 3) for _ in range(60)]
    assert set(lows) == {0, 1, 2}


def test_chance_endpoints_are_stable_and_probability_is_validated():
    r = make(33)
    assert r.chance("default", 0.0) is False
    assert r.chance("default", 1.0) is True
    draws = [r.chance("default", 0.5) for _ in range(100)]
    assert any(draws) is True
    assert all(draws) is False
    for bad in (-0.1, 1.1, 2.0):
        with pytest.raises(rng.RngError) as exc:
            r.chance("default", bad)
        assert exc.value.code == "RNG_INVALID_PROBABILITY"


def test_shuffle_is_a_permutation_that_does_not_mutate_input():
    r = make(35)
    items = ["a", "b", "c", "d", "e"]
    snap = r.snapshot()
    first = r.shuffle("default", items)
    assert sorted(first) == items
    assert items == ["a", "b", "c", "d", "e"]
    r.restore(snap)
    assert r.shuffle("default", items) == first
    assert first != items
    assert r.shuffle("default", []) == []
    assert r.shuffle("default", ["solo"]) == ["solo"]


def test_fork_does_not_advance_parent_and_children_are_reproducible():
    a = make(13)
    b = make(13)
    before = a.position()
    info = a.fork("default", "combat")
    assert info["label"] == "combat"
    assert a.position() == before
    assert a.has_stream("combat") is True
    b.fork("default", "combat")
    assert [a.next_u32("combat") for _ in range(5)] == [
        b.next_u32("combat") for _ in range(5)
    ]
    assert [a.next_u32() for _ in range(3)] == [b.next_u32() for _ in range(3)]
    with pytest.raises(rng.RngError) as exc:
        a.fork("default", "combat")
    assert exc.value.code == "RNG_STREAM_DUP"
    with pytest.raises(rng.RngError) as exc:
        a.fork("missing", "other")
    assert exc.value.code == "RNG_UNKNOWN_STREAM"


def test_pick_rejects_empty_pool_and_returns_a_member():
    r = make(37)
    with pytest.raises(rng.RngError) as exc:
        r.pick("default", [])
    assert exc.value.code == "RNG_EMPTY_POOL"
    assert r.pick("default", ["only"]) == "only"
    assert r.pick("default", ("a", "b", "c")) in {"a", "b", "c"}


def test_concurrent_draws_are_atomic_and_unique():
    r = make(41, max_draws=500)
    results = []
    lock = threading.Lock()

    def worker():
        local = []
        for _ in range(25):
            local.append(r.next_u32())
        with lock:
            results.extend(local)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(results) == 200
    assert len(set(results)) == 200
    assert r.position() == 200
    assert r.remaining() == 300
