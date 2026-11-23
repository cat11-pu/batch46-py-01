import threading

import pytest

import ebpf_verifier_guard as eg


def make(**kwargs):
    return eg.EbpfGuard(**kwargs)


def spec(name="prog", ptype="xdp", instructions=None, maps=None):
    return {
        "name": name,
        "type": ptype,
        "instructions": list(instructions or [("call", "xdp_pass"), ("exit",)]),
        "maps": list(maps or []),
    }


def map_spec(name="counters", max_entries=8, value_size=8, prog="prog"):
    return spec(
        name=prog,
        instructions=[("call", "map_update", name), ("exit",)],
        maps=[{"name": name, "max_entries": max_entries,
               "value_size": value_size}],
    )


def test_valid_program_loads_and_registers_map():
    g = make(max_instructions=8)
    out = g.load_program(map_spec(max_entries=8, value_size=8))
    assert out["id"] == 1
    assert out["name"] == "prog"
    assert out["type"] == "xdp"
    assert out["instructions"] == 2
    assert out["maps"] == ["counters"]
    info = g.program_info(1)
    assert info["attached"] == []
    assert info["maps"] == ["counters"]
    maps = g.maps()
    assert len(maps) == 1
    assert maps[0]["name"] == "counters"
    assert maps[0]["used"] == 0
    assert maps[0]["refs"] == 1
    assert maps[0]["bytes"] == 64
    assert g.stats()["loads"] == 1


def test_missing_exit_is_rejected_without_state_change():
    g = make()
    bad = spec(instructions=[("call", "xdp_pass")])
    with pytest.raises(eg.EbpfError) as exc:
        g.load_program(bad)
    assert exc.value.code == "EBPF_NO_EXIT"
    assert g.programs() == []
    assert g.maps() == []
    counts = g.stats()
    assert counts["loads"] == 0
    assert counts["rejected"] == 1


def test_instruction_limit_boundary():
    g = make(max_instructions=4)
    exact = spec(instructions=[("call", "xdp_pass"), ("call", "xdp_pass"),
                               ("call", "xdp_pass"), ("exit",)])
    assert g.load_program(exact)["id"] == 1
    oversized = spec(instructions=[("call", "xdp_pass"),
                                   ("call", "xdp_pass"),
                                   ("call", "xdp_pass"),
                                   ("call", "xdp_pass"), ("exit",)])
    with pytest.raises(eg.EbpfError) as exc:
        g.load_program(oversized)
    assert exc.value.code == "EBPF_TOO_MANY_INSNS"
    counts = g.stats()
    assert counts["loads"] == 1
    assert counts["rejected"] == 1


def test_jump_targets_and_loop_bounds():
    g = make()
    with pytest.raises(eg.EbpfError) as exc:
        g.load_program(spec(ptype="tracepoint",
                            instructions=[("jump", 99), ("exit",)]))
    assert exc.value.code == "EBPF_BAD_JUMP"
    with pytest.raises(eg.EbpfError) as exc:
        g.load_program(spec(ptype="tracepoint",
                            instructions=[("jump", -99), ("exit",)]))
    assert exc.value.code == "EBPF_BAD_JUMP"
    with pytest.raises(eg.EbpfError) as exc:
        g.load_program(spec(ptype="tracepoint",
                            instructions=[("call", "trace_printk"),
                                          ("jump", -1), ("exit",)]))
    assert exc.value.code == "EBPF_UNBOUNDED_LOOP"
    with pytest.raises(eg.EbpfError) as exc:
        g.load_program(spec(ptype="tracepoint",
                            instructions=[("call", "trace_printk"),
                                          ("jump", -1, 0), ("exit",)]))
    assert exc.value.code == "EBPF_BAD_BOUND"
    out = g.load_program(spec(ptype="tracepoint",
                              instructions=[("call", "trace_printk"),
                                            ("jump", -1, 4), ("exit",)]))
    assert out["id"] == 1
    assert g.stats()["loads"] == 1
    assert g.stats()["rejected"] == 4


def test_malformed_instructions_and_unknown_maps():
    g = make()
    with pytest.raises(eg.EbpfError) as exc:
        g.load_program(spec(instructions=[("nop",), ("exit",)]))
    assert exc.value.code == "EBPF_BAD_INSN"
    with pytest.raises(eg.EbpfError) as exc:
        g.load_program(spec(instructions=[("call", "does_not_exist"),
                                          ("exit",)]))
    assert exc.value.code == "EBPF_HELPER_UNKNOWN"
    with pytest.raises(eg.EbpfError) as exc:
        g.load_program(spec(instructions=[("call", "map_update"),
                                          ("exit",)]))
    assert exc.value.code == "EBPF_BAD_INSN"
    with pytest.raises(eg.EbpfError) as exc:
        g.load_program(spec(instructions=[("call", "map_update", "missing"),
                                          ("exit",)]))
    assert exc.value.code == "EBPF_MAP_UNKNOWN"
    assert g.stats()["rejected"] == 4
    assert g.programs() == []


def test_helper_allowlist_depends_on_program_type():
    g = make()
    with pytest.raises(eg.EbpfError) as exc:
        g.load_program(spec(ptype="xdp",
                            instructions=[("call", "probe_read"),
                                          ("exit",)]))
    assert exc.value.code == "EBPF_HELPER_DENIED"
    assert g.load_program(spec(ptype="kprobe",
                               instructions=[("call", "probe_read"),
                                             ("exit",)]))["id"] == 1
    assert g.load_program(spec(ptype="tracepoint",
                               instructions=[("call", "trace_printk"),
                                             ("exit",)]))["id"] == 2
    with pytest.raises(eg.EbpfError) as exc:
        g.load_program(spec(ptype="xdp",
                            instructions=[("call", "trace_printk"),
                                          ("exit",)]))
    assert exc.value.code == "EBPF_HELPER_DENIED"
    with pytest.raises(eg.EbpfError) as exc:
        g.load_program(spec(ptype="kprobe",
                            instructions=[("call", "xdp_pass"),
                                          ("exit",)]))
    assert exc.value.code == "EBPF_HELPER_DENIED"
    counts = g.stats()
    assert counts["loads"] == 2
    assert counts["rejected"] == 3


def test_failed_verification_does_not_consume_quota():
    g = make(max_maps=1)
    bad = spec(instructions=[("call", "probe_read"), ("exit",)],
               maps=[{"name": "m1", "max_entries": 4, "value_size": 4}])
    with pytest.raises(eg.EbpfError) as exc:
        g.load_program(bad)
    assert exc.value.code == "EBPF_HELPER_DENIED"
    assert g.maps() == []
    assert g.stats()["loads"] == 0
    good = spec(instructions=[("call", "map_update", "m1"), ("exit",)],
                maps=[{"name": "m1", "max_entries": 4, "value_size": 4}])
    assert g.load_program(good)["id"] == 1
    assert len(g.maps()) == 1


def test_program_quota_is_per_tenant():
    g = make(max_programs=1)
    g.load_program(spec(name="a"), tenant="t1")
    with pytest.raises(eg.EbpfError) as exc:
        g.load_program(spec(name="b"), tenant="t1")
    assert exc.value.code == "EBPF_PROG_QUOTA"
    assert g.load_program(spec(name="c"), tenant="t2")["id"] == 2
    assert len(g.programs("t1")) == 1
    assert len(g.programs("t2")) == 1


def test_map_quota_and_reuse_conflict():
    g = make(max_maps=2)
    first = spec(instructions=[("call", "map_update", "m1"), ("exit",)],
                 maps=[{"name": "m1", "max_entries": 8, "value_size": 8},
                       {"name": "m2", "max_entries": 8, "value_size": 8}])
    assert g.load_program(first)["id"] == 1
    third = spec(instructions=[("call", "map_update", "m3"), ("exit",)],
                 maps=[{"name": "m3", "max_entries": 8, "value_size": 8}])
    with pytest.raises(eg.EbpfError) as exc:
        g.load_program(third)
    assert exc.value.code == "EBPF_MAP_QUOTA"
    shared = spec(instructions=[("call", "map_update", "m1"), ("exit",)],
                  maps=[{"name": "m1", "max_entries": 8, "value_size": 8}])
    assert g.load_program(shared)["id"] == 2
    assert len(g.maps()) == 2
    refs = {entry["name"]: entry["refs"] for entry in g.maps()}
    assert refs["m1"] == 2
    conflict = spec(instructions=[("call", "map_update", "m1"), ("exit",)],
                    maps=[{"name": "m1", "max_entries": 16,
                           "value_size": 8}])
    with pytest.raises(eg.EbpfError) as exc:
        g.load_program(conflict)
    assert exc.value.code == "EBPF_MAP_CONFLICT"


def test_map_memory_budget_and_refcount_release():
    g = make(max_map_bytes=256)
    first = map_spec(name="m1", max_entries=16, value_size=8, prog="a")
    second = map_spec(name="m1", max_entries=16, value_size=8, prog="b")
    assert g.load_program(first)["id"] == 1
    assert g.load_program(second)["id"] == 2
    assert g.load_program(map_spec(name="m2", max_entries=16, value_size=8,
                                   prog="c"))["id"] == 3
    with pytest.raises(eg.EbpfError) as exc:
        g.load_program(map_spec(name="m3", max_entries=1, value_size=8,
                                prog="d"))
    assert exc.value.code == "EBPF_MAP_MEMORY"
    refs = {entry["name"]: entry["refs"] for entry in g.maps()}
    assert refs == {"m1": 2, "m2": 1}
    closed = g.close_program(2)
    assert closed["freed_maps"] == []
    assert {entry["name"] for entry in g.maps()} == {"m1", "m2"}
    closed = g.close_program(1)
    assert closed["freed_maps"] == ["m1"]
    assert {entry["name"] for entry in g.maps()} == {"m2"}
    assert g.load_program(map_spec(name="m3", max_entries=16, value_size=8,
                                   prog="e"))["id"] == 4


def test_map_update_capacity_value_size_and_lookup():
    g = make()
    g.load_program(map_spec(max_entries=2, value_size=4))
    first = g.map_update("counters", "k1", "abcd")
    assert first == {"name": "counters", "key": "k1", "used": 1,
                     "created": True}
    assert g.map_update("counters", "k2", "efgh")["used"] == 2
    with pytest.raises(eg.EbpfError) as exc:
        g.map_update("counters", "k3", "ijkl")
    assert exc.value.code == "EBPF_MAP_FULL"
    again = g.map_update("counters", "k1", "wxyz")
    assert again["used"] == 2
    assert again["created"] is False
    assert g.map_lookup("counters", "k1") == "wxyz"
    assert g.map_lookup("counters", "missing") is None
    with pytest.raises(eg.EbpfError) as exc:
        g.map_update("counters", "k1", "abcde")
    assert exc.value.code == "EBPF_VALUE_TOO_LARGE"
    counts = g.stats()
    assert counts["map_updates"] == 3
    assert counts["map_rejects"] == 2


def test_tenants_are_isolated_for_maps_programs_and_hooks():
    g = make()
    assert g.load_program(map_spec(), tenant="t1")["id"] == 1
    assert g.load_program(map_spec(), tenant="t2")["id"] == 2
    g.map_update("counters", "k", "one", tenant="t1")
    g.map_update("counters", "k", "two", tenant="t2")
    assert g.map_lookup("counters", "k", tenant="t1") == "one"
    assert g.map_lookup("counters", "k", tenant="t2") == "two"
    with pytest.raises(eg.EbpfError) as exc:
        g.program_info(1, tenant="t2")
    assert exc.value.code == "EBPF_TENANT_MISMATCH"
    with pytest.raises(eg.EbpfError) as exc:
        g.attach(1, "hook0", tenant="t2")
    assert exc.value.code == "EBPF_TENANT_MISMATCH"
    assert len(g.maps("t1")) == 1
    assert len(g.maps("t2")) == 1


def test_attach_detach_and_close_release_hooks():
    g = make()
    g.load_program(spec(name="a"))
    g.load_program(spec(name="b"))
    attached = g.attach(1, "eth0")
    assert attached == {"id": 1, "hook": "eth0", "attached": 1}
    with pytest.raises(eg.EbpfError) as exc:
        g.attach(1, "eth0")
    assert exc.value.code == "EBPF_HOOK_BUSY"
    with pytest.raises(eg.EbpfError) as exc:
        g.attach(2, "eth0")
    assert exc.value.code == "EBPF_HOOK_BUSY"
    assert g.attach(1, "eth1")["attached"] == 2
    assert g.detach(1, "eth0") is True
    assert g.detach(1, "eth0") is False
    assert g.detach(2, "eth1") is False
    closed = g.close_program(1)
    assert closed == {"detached": 1, "freed_maps": []}
    with pytest.raises(eg.EbpfError) as exc:
        g.program_info(1)
    assert exc.value.code == "EBPF_PROG_UNKNOWN"
    with pytest.raises(eg.EbpfError):
        g.close_program(1)
    counts = g.stats()
    assert counts["attaches"] == 2
    assert counts["detaches"] == 1
    assert counts["closed"] == 1
    assert counts["hook_busy"] == 2


def test_snapshot_restore_keeps_maps_hooks_and_next_id():
    g = make()
    g.load_program(map_spec())
    g.attach(1, "eth0")
    g.map_update("counters", "k", "value")
    g.set_quota("t2", max_programs=2)
    blob = g.snapshot()
    restored = eg.EbpfGuard.restore(blob)
    info = restored.program_info(1)
    assert info["attached"] == ["eth0"]
    assert info["instructions"] == 2
    assert restored.map_lookup("counters", "k") == "value"
    assert restored.stats()["loads"] == 1
    assert restored.load_program(spec(name="next"))["id"] == 2
    restored.load_program(spec(name="t2-a"), tenant="t2")
    restored.load_program(spec(name="t2-b"), tenant="t2")
    with pytest.raises(eg.EbpfError) as exc:
        restored.load_program(spec(name="t2-c"), tenant="t2")
    assert exc.value.code == "EBPF_PROG_QUOTA"
    with pytest.raises(eg.EbpfError) as exc:
        eg.EbpfGuard.restore("{broken")
    assert exc.value.code == "EBPF_SNAPSHOT_INVALID"


def test_concurrent_map_updates_stop_at_capacity():
    g = make()
    g.load_program(map_spec(max_entries=5, value_size=8))
    barrier = threading.Barrier(8)
    created = []
    full = []
    errors = []

    def worker(number):
        try:
            barrier.wait()
            g.map_update("counters", "k%d" % number, "v")
            created.append(number)
        except eg.EbpfError as exc:
            if exc.code == "EBPF_MAP_FULL":
                full.append(number)
            else:  # pragma: no cover - unexpected code
                errors.append(exc.code)
        except Exception as exc:  # pragma: no cover - failure path
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    assert len(created) == 5
    assert len(full) == 3
    assert g.maps()[0]["used"] == 5
    counts = g.stats()
    assert counts["map_updates"] == 5
    assert counts["map_rejects"] == 3
