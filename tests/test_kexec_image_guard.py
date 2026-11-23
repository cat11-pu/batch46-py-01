import hashlib
import threading

import pytest

import kexec_image_guard as kg


def make(**kwargs):
    return kg.KexecGuard(**kwargs)


def digest_for(name):
    return hashlib.sha256(name.encode("utf-8")).hexdigest()


def image(name, *, size=10, key_id="k1", digest=None, signature=None):
    digest = digest or digest_for(name)
    if signature is None and key_id is not None:
        signature = kg.expected_signature(key_id, name, digest)
    return {
        "name": name,
        "digest": digest,
        "size": size,
        "key_id": key_id,
        "signature": signature,
    }


def test_valid_signed_image_is_staged():
    g = make()
    g.add_key("k1")
    out = g.load_image(0, image("vmlinuz-a", size=10))
    assert out["status"] == "staged"
    assert out["slot"] == 0
    assert out["verified"] is True
    assert out["usage"]["bytes"] == 10
    assert out["usage"]["slots"] == 1
    info = g.staged(0)
    assert info["name"] == "vmlinuz-a"
    assert info["key_id"] == "k1"
    assert g.stats()["loads"] == 1


def test_unsigned_and_bad_signature_policies():
    g = make()
    unsigned = {"name": "u", "digest": digest_for("u"), "size": 5,
                "key_id": None, "signature": None}
    with pytest.raises(kg.KexecError) as exc:
        g.load_image(0, unsigned)
    assert exc.value.code == "KEXEC_UNSIGNED"
    g.add_key("k1")
    no_signature = {"name": "v", "digest": digest_for("v"), "size": 5,
                    "key_id": "k1", "signature": None}
    with pytest.raises(kg.KexecError) as exc:
        g.load_image(0, no_signature)
    assert exc.value.code == "KEXEC_UNSIGNED"
    with pytest.raises(kg.KexecError) as exc:
        g.load_image(0, image("w", signature="0" * 64))
    assert exc.value.code == "KEXEC_BAD_SIGNATURE"
    permissive = make(allow_unsigned=True)
    out = permissive.load_image(0, unsigned)
    assert out["status"] == "staged"
    assert out["verified"] is False


def test_unknown_and_revoked_keys_are_rejected():
    g = make()
    g.add_key("k1")
    with pytest.raises(kg.KexecError) as exc:
        g.load_image(0, image("a", key_id="k2"))
    assert exc.value.code == "KEXEC_KEY_UNKNOWN"
    g.add_key("k2")
    assert g.revoke_key("k2") is True
    assert g.revoke_key("k2") is False
    with pytest.raises(kg.KexecError) as exc:
        g.load_image(0, image("b", key_id="k2"))
    assert exc.value.code == "KEXEC_KEY_REVOKED"
    with pytest.raises(kg.KexecError) as exc:
        g.revoke_key("ghost")
    assert exc.value.code == "KEXEC_KEY_UNKNOWN"
    assert g.key_info("k2")["revoked"] is True


def test_bad_digest_name_and_signature_values():
    g = make()
    g.add_key("k1")
    with pytest.raises(kg.KexecError) as exc:
        g.load_image(0, image("a", digest="ABC"))
    assert exc.value.code == "KEXEC_BAD_DIGEST"
    with pytest.raises(kg.KexecError) as exc:
        g.load_image(0, image("b", digest=digest_for("b").upper()))
    assert exc.value.code == "KEXEC_BAD_DIGEST"
    with pytest.raises(kg.KexecError) as exc:
        g.load_image(0, {"name": "", "digest": digest_for("c"), "size": 5,
                         "key_id": "k1", "signature": "x"})
    assert exc.value.code == "KEXEC_BAD_IMAGE"
    with pytest.raises(kg.KexecError) as exc:
        g.load_image(0, image("d", signature="0" * 64))
    assert exc.value.code == "KEXEC_BAD_SIGNATURE"
    assert g.stats()["rejected"] == 4


def test_image_and_total_budget_enforced_atomically():
    g = make(slot_count=3, max_image_bytes=50, max_total_bytes=100)
    g.add_key("k1")
    with pytest.raises(kg.KexecError) as exc:
        g.load_image(0, image("big", size=60))
    assert exc.value.code == "KEXEC_IMAGE_TOO_LARGE"
    assert g.load_image(0, image("a", size=40))["status"] == "staged"
    assert g.load_image(1, image("b", size=40))["status"] == "staged"
    with pytest.raises(kg.KexecError) as exc:
        g.load_image(2, image("c", size=30))
    assert exc.value.code == "KEXEC_IMAGE_TOO_LARGE"
    assert g.usage()["bytes"] == 80
    assert g.usage()["slots"] == 2
    assert g.staged(2) is None
    counts = g.stats()
    assert counts["loads"] == 2
    assert counts["rejected"] == 2


def test_same_image_reload_is_idempotent_and_others_get_busy():
    g = make()
    g.add_key("k1")
    first = image("a", size=12)
    assert g.load_image(0, first)["status"] == "staged"
    again = g.load_image(0, image("a", size=12))
    assert again["status"] == "already"
    assert g.usage()["bytes"] == 12
    assert g.stats()["duplicates"] == 1
    with pytest.raises(kg.KexecError) as exc:
        g.load_image(0, image("b", size=12))
    assert exc.value.code == "KEXEC_SLOT_BUSY"
    assert g.staged(0)["name"] == "a"
    assert g.usage()["bytes"] == 12


def test_slot_index_bounds_are_checked():
    g = make(slot_count=2)
    g.add_key("k1")
    with pytest.raises(kg.KexecError) as exc:
        g.load_image(-1, image("a"))
    assert exc.value.code == "KEXEC_BAD_SLOT"
    with pytest.raises(kg.KexecError) as exc:
        g.load_image(2, image("a"))
    assert exc.value.code == "KEXEC_BAD_SLOT"
    with pytest.raises(kg.KexecError) as exc:
        g.staged(-1)
    assert exc.value.code == "KEXEC_BAD_SLOT"
    with pytest.raises(kg.KexecError) as exc:
        g.unload(2)
    assert exc.value.code == "KEXEC_BAD_SLOT"


def test_revocation_after_load_blocks_boot_but_keeps_image():
    g = make()
    g.add_key("k1")
    g.load_image(0, image("a", size=9))
    g.revoke_key("k1")
    with pytest.raises(kg.KexecError) as exc:
        g.boot(0)
    assert exc.value.code == "KEXEC_KEY_REVOKED"
    assert g.staged(0)["name"] == "a"
    assert g.usage()["bytes"] == 9
    assert g.stats()["denied_boots"] == 1
    assert g.unload(0) is True
    assert g.usage()["bytes"] == 0


def test_blacklist_after_load_blocks_boot():
    g = make()
    g.add_key("k1")
    staged = image("a")
    g.load_image(0, staged)
    assert g.blacklist(staged["digest"]) is True
    assert g.blacklist(staged["digest"]) is False
    with pytest.raises(kg.KexecError) as exc:
        g.boot(0)
    assert exc.value.code == "KEXEC_BLACKLISTED"
    assert g.staged(0) is not None
    with pytest.raises(kg.KexecError) as exc:
        g.blacklist("not-a-digest")
    assert exc.value.code == "KEXEC_BAD_DIGEST"


def test_boot_is_one_shot_and_replay_after_reload_is_blocked():
    g = make()
    g.add_key("k1")
    first = image("a", size=10)
    g.load_image(0, first)
    out = g.boot(0)
    assert out["name"] == "a"
    assert out["verified"] is True
    assert g.usage()["bytes"] == 0
    with pytest.raises(kg.KexecError) as exc:
        g.boot(0)
    assert exc.value.code == "KEXEC_SLOT_EMPTY"
    with pytest.raises(kg.KexecError) as exc:
        g.load_image(0, image("a", size=10))
    assert exc.value.code == "KEXEC_ALREADY_BOOTED"
    assert g.load_image(0, image("b", size=10))["status"] == "staged"
    assert g.boot(0)["name"] == "b"
    assert g.stats()["boots"] == 2


def test_unload_refunds_budget_and_tenant_is_enforced():
    g = make()
    g.add_key("k1")
    g.load_image(0, image("a", size=20), tenant="t1")
    with pytest.raises(kg.KexecError) as exc:
        g.staged(0, tenant="t2")
    assert exc.value.code == "KEXEC_TENANT_MISMATCH"
    with pytest.raises(kg.KexecError) as exc:
        g.unload(0, tenant="t2")
    assert exc.value.code == "KEXEC_TENANT_MISMATCH"
    with pytest.raises(kg.KexecError) as exc:
        g.boot(0, tenant="t2")
    assert exc.value.code == "KEXEC_TENANT_MISMATCH"
    assert g.usage()["bytes"] == 20
    assert g.unload(0, tenant="t1") is True
    assert g.unload(0, tenant="t1") is False
    assert g.usage()["bytes"] == 0


def test_audit_ring_and_counters():
    g = make(audit_capacity=4)
    g.add_key("k1")
    staged = image("a", size=10)
    g.load_image(0, staged)
    g.load_image(0, image("a", size=10))
    with pytest.raises(kg.KexecError):
        g.load_image(0, image("bad", signature="0" * 64))
    g.boot(0)
    rows = g.audit()
    assert len(rows) == 4
    assert [row["event"] for row in rows] == ["load", "duplicate", "reject",
                                             "boot"]
    assert rows[2]["code"] == "KEXEC_BAD_SIGNATURE"
    assert len(g.audit(2)) == 2
    counts = g.stats()
    assert counts["loads"] == 1
    assert counts["duplicates"] == 1
    assert counts["rejected"] == 1
    assert counts["boots"] == 1


def test_snapshot_restore_preserves_keys_slots_and_blacklist():
    g = make()
    g.add_key("k1")
    g.add_key("k2")
    g.revoke_key("k2")
    g.load_image(0, image("vmlinuz-1", size=11))
    evil = image("evil")
    g.blacklist(evil["digest"])
    blob = g.snapshot()
    restored = kg.KexecGuard.restore(blob)
    assert restored.staged(0)["name"] == "vmlinuz-1"
    assert restored.key_info("k2")["revoked"] is True
    assert restored.stats()["loads"] == 1
    assert restored.boot(0)["name"] == "vmlinuz-1"
    with pytest.raises(kg.KexecError) as exc:
        restored.load_image(0, image("new", key_id="k2"))
    assert exc.value.code == "KEXEC_KEY_REVOKED"
    with pytest.raises(kg.KexecError) as exc:
        restored.load_image(0, evil)
    assert exc.value.code == "KEXEC_BLACKLISTED"
    with pytest.raises(kg.KexecError) as exc:
        kg.KexecGuard.restore("{bad-json")
    assert exc.value.code == "KEXEC_SNAPSHOT_INVALID"


def test_concurrent_boot_has_a_single_winner():
    g = make()
    g.add_key("k1")
    g.load_image(0, image("a", size=10))
    barrier = threading.Barrier(8)
    wins = []
    empty = []
    errors = []

    def worker():
        try:
            barrier.wait()
            g.boot(0)
            wins.append(1)
        except kg.KexecError as exc:
            if exc.code == "KEXEC_SLOT_EMPTY":
                empty.append(1)
            else:  # pragma: no cover - unexpected code
                errors.append(exc.code)
        except Exception as exc:  # pragma: no cover - failure path
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    assert len(wins) == 1
    assert len(empty) == 7
    assert g.usage()["bytes"] == 0
    counts = g.stats()
    assert counts["boots"] == 1
    assert counts["denied_boots"] == 7


def test_concurrent_loads_into_one_slot_keep_usage_consistent():
    g = make()
    g.add_key("k1")
    barrier = threading.Barrier(8)
    staged = []
    busy = []
    errors = []

    def worker(number):
        try:
            barrier.wait()
            g.load_image(0, image("candidate-%d" % number, size=10))
            staged.append(number)
        except kg.KexecError as exc:
            if exc.code == "KEXEC_SLOT_BUSY":
                busy.append(number)
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
    assert len(staged) == 1
    assert len(busy) == 7
    assert g.usage()["bytes"] == 10
    assert g.usage()["slots"] == 1
    counts = g.stats()
    assert counts["loads"] == 1
    assert counts["rejected"] == 7
