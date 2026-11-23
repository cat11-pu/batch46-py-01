import hashlib
import threading
import time

import pytest

import coredump_redact_guard as cd


def make(**kwargs):
    return cd.CoreDumpGuard(**kwargs)


def record(name, value, kind="env"):
    return {"name": name, "value": value, "kind": kind}


def test_process_redacts_registered_fields_and_keeps_others():
    g = make()
    g.register_rule("*_KEY", kind="env", action="mask")
    out = g.process("d1", [record("API_KEY", "abc"),
                           record("HOME", "/root")])
    assert out["status"] == "processed"
    assert out["kept"] == 2
    assert out["dropped"] == 0
    assert len(out["digest"]) == 64
    assert g.get("d1", "API_KEY")["value"] == "***"
    assert g.get("d1", "HOME")["value"] == "/root"
    assert g.list_names("d1") == ["API_KEY", "HOME"]
    assert g.stats()["processed"] == 1


def test_rule_precedence_exact_then_longest_wildcard():
    g = make()
    g.register_rule("*", action="drop")
    g.register_rule("*_TOKEN", action="hash")
    g.register_rule("DB_TOKEN", action="mask")
    out = g.process("d1", [record("DB_TOKEN", "dbpass"),
                           record("AWS_TOKEN", "aws"),
                           record("OTHER", "plain")])
    assert out["kept"] == 2
    assert out["dropped"] == 1
    assert g.get("d1", "DB_TOKEN")["value"] == "***"
    expected = "sha256:" + hashlib.sha256(b"aws").hexdigest()[:16]
    assert g.get("d1", "AWS_TOKEN")["value"] == expected
    with pytest.raises(cd.CoreDumpError) as exc:
        g.get("d1", "OTHER")
    assert exc.value.code == "CD_FIELD_UNKNOWN"


def test_drop_rules_remove_fields_and_keep_order():
    g = make()
    g.register_rule("PRIVATE_*", action="drop")
    out = g.process("d1", [record("PUBLIC_A", "1"),
                           record("PRIVATE_X", "2"),
                           record("PUBLIC_B", "3"),
                           record("PRIVATE_Y", "4")])
    assert out["kept"] == 2
    assert out["dropped"] == 2
    assert g.list_names("d1") == ["PUBLIC_A", "PUBLIC_B"]


def test_duplicate_fields_in_one_dump_keep_first_occurrence():
    g = make()
    out = g.process("d1", [record("DUP", "first"),
                           record("DUP", "second"),
                           record("DUP", "third", kind="arg")])
    assert out["kept"] == 2
    assert out["duplicates"] == 1
    assert g.get("d1", "DUP")["value"] == "first"
    assert g.list_names("d1") == ["DUP", "DUP"]
    assert g.usage()["dumps"] == 1


def test_record_limit_is_enforced_before_any_state_change():
    g = make(max_records=2)
    with pytest.raises(cd.CoreDumpError) as exc:
        g.process("d1", [record("A", "1"), record("B", "2"),
                         record("C", "3")])
    assert exc.value.code == "CD_DUMP_TOO_LARGE"
    assert g.stats()["processed"] == 0
    assert g.stats()["rejected"] == 1
    assert g.usage()["dumps"] == 0
    assert g.audit()[-1]["action"] == "reject"
    assert g.audit()[-1]["code"] == "CD_DUMP_TOO_LARGE"


def test_same_dump_id_with_new_content_is_rejected():
    g = make()
    g.process("d1", [record("A", "one")])
    with pytest.raises(cd.CoreDumpError) as exc:
        g.process("d1", [record("A", "two")])
    assert exc.value.code == "CD_DUMP_ID_CONFLICT"
    assert g.get("d1", "A")["value"] == "one"
    assert g.stats()["processed"] == 1
    assert g.stats()["rejected"] == 1


def test_replaying_identical_dump_is_idempotent():
    g = make()
    first = g.process("d1", [record("A", "one")])
    second = g.process("d1", [record("A", "one")])
    assert first["status"] == "processed"
    assert second["status"] == "duplicate"
    assert second["kept"] == 1
    assert second["dropped"] == 0
    assert g.stats()["processed"] == 1
    assert g.stats()["duplicates"] == 1
    assert g.usage()["dumps"] == 1


def test_purged_dump_cannot_be_resurrected():
    g = make()
    g.process("d1", [record("A", "one")])
    assert g.purge("d1") is True
    assert g.purge("d1") is False
    assert g.usage()["dumps"] == 0
    with pytest.raises(cd.CoreDumpError) as exc:
        g.get("d1", "A")
    assert exc.value.code == "CD_UNKNOWN_DUMP"
    replay = g.process("d1", [record("A", "one")])
    assert replay["status"] == "purged"
    assert replay["kept"] == 0
    assert g.stats()["processed"] == 1
    assert g.stats()["purged"] == 1


def test_tenants_are_isolated_and_mismatch_is_reported():
    g = make()
    g.process("d1", [record("A", "one")], tenant="t1")
    g.process("d1", [record("A", "two")], tenant="t2")
    assert g.get("d1", "A", tenant="t1")["value"] == "one"
    assert g.get("d1", "A", tenant="t2")["value"] == "two"
    with pytest.raises(cd.CoreDumpError) as exc:
        g.get("d1", "A", tenant="t3")
    assert exc.value.code == "CD_TENANT_MISMATCH"
    with pytest.raises(cd.CoreDumpError):
        g.list_names("d1", tenant="t3")
    assert g.usage("t1")["dumps"] == 1
    assert g.usage("t2")["dumps"] == 1
    assert g.usage("t3")["dumps"] == 0


def test_tenant_quota_and_override():
    g = make(max_dumps_per_tenant=1)
    g.process("d1", [record("A", "1")], tenant="t1")
    with pytest.raises(cd.CoreDumpError) as exc:
        g.process("d2", [record("A", "2")], tenant="t1")
    assert exc.value.code == "CD_TENANT_QUOTA"
    assert g.usage("t1") == {"dumps": 1, "limit": 1}
    assert g.set_tenant_quota("t2", 2) == 2
    g.process("d1", [record("A", "1")], tenant="t2")
    g.process("d2", [record("A", "2")], tenant="t2")
    with pytest.raises(cd.CoreDumpError):
        g.process("d3", [record("A", "3")], tenant="t2")
    assert g.usage("t2") == {"dumps": 2, "limit": 2}
    with pytest.raises(cd.CoreDumpError) as exc:
        g.set_tenant_quota("t3", -1)
    assert exc.value.code == "CD_BAD_QUOTA"


def test_values_are_truncated_only_after_redaction():
    g = make(max_value_bytes=16)
    g.register_rule("*_SECRET", kind="env", action="mask")
    g.register_rule("PAYLOAD", kind="mem", action="hash")
    g.process("d1", [record("ARGS", "x" * 40, kind="arg"),
                     record("DB_SECRET", "y" * 40, kind="env"),
                     record("PAYLOAD", "z" * 40, kind="mem"),
                     record("EXACT", "e" * 16, kind="arg")])
    assert g.get("d1", "ARGS")["value"] == "x" * 16 + "…"
    assert g.get("d1", "DB_SECRET")["value"] == "***"
    hashed = g.get("d1", "PAYLOAD")["value"]
    assert hashed.startswith("sha256:") and len(hashed) == 23
    assert g.get("d1", "EXACT")["value"] == "e" * 16


def test_snapshot_restore_keeps_redacted_state_without_secrets():
    g = make()
    g.register_rule("*_SECRET", kind="env", action="mask")
    secret = "S3CRET-VALUE-999"
    g.process("crash-1", [record("DB_SECRET", secret, kind="env")])
    blob = g.snapshot()
    assert secret not in blob
    restored = cd.CoreDumpGuard.restore(blob)
    assert restored.stats()["processed"] == 1
    assert restored.get("crash-1", "DB_SECRET")["value"] == "***"
    replay = restored.process("crash-1",
                              [record("DB_SECRET", secret, kind="env")])
    assert replay["status"] == "duplicate"
    assert restored.purge("crash-1") is True
    with pytest.raises(cd.CoreDumpError) as exc:
        cd.CoreDumpGuard.restore("not-a-snapshot")
    assert exc.value.code == "CD_SNAPSHOT_INVALID"


def test_audit_ring_and_counters():
    g = make(max_records=2, audit_capacity=4)
    g.process("d1", [record("A", "1")])
    g.process("d1", [record("A", "1")])
    with pytest.raises(cd.CoreDumpError):
        g.process("d2", [record("A", "1"), record("B", "2"),
                         record("C", "3")])
    g.purge("d1")
    rows = g.audit()
    assert len(rows) == 4
    assert [row["action"] for row in rows] == ["process", "duplicate",
                                               "reject", "purge"]
    assert len(g.audit(2)) == 2
    stats = g.stats()
    assert stats["processed"] == 1
    assert stats["duplicates"] == 1
    assert stats["rejected"] == 1
    assert stats["purged"] == 1


def test_concurrent_shared_dump_and_distinct_dumps():
    g = make(max_records=4, max_dumps_per_tenant=16)
    g.register_rule("*_SECRET", action="mask")
    barrier = threading.Barrier(8)
    statuses = []
    errors = []

    def shared_worker():
        try:
            barrier.wait()
            out = g.process("shared-dump",
                            [record("API_SECRET", "value", kind="env")])
            statuses.append(out["status"])
        except Exception as exc:  # pragma: no cover - failure path
            errors.append(exc)

    threads = [threading.Thread(target=shared_worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    assert statuses.count("processed") == 1
    assert statuses.count("duplicate") == 7
    assert g.stats()["processed"] == 1
    assert g.stats()["duplicates"] == 7

    barrier2 = threading.Barrier(8)

    def bulk_worker(number):
        try:
            barrier2.wait()
            g.process("bulk-%d" % number, [record("A", str(number))],
                      tenant="bulk")
        except Exception as exc:  # pragma: no cover - failure path
            errors.append(exc)

    threads = [threading.Thread(target=bulk_worker, args=(n,))
               for n in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    assert g.usage("bulk")["dumps"] == 8


def test_redaction_throughput_budget():
    g = make(max_records=2500, max_value_bytes=64)
    g.register_rule("PAYLOAD*", kind="mem", action="hash")
    records = [record("PAYLOAD_%d" % i, "v" * 16, kind="mem")
               for i in range(2000)]
    start = time.monotonic()
    out = g.process("big-dump", records)
    elapsed = time.monotonic() - start
    assert elapsed < 3.0
    assert out["kept"] == 2000
    assert g.get("big-dump", "PAYLOAD_1999")["value"].startswith("sha256:")
