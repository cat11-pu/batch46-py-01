import hashlib
import hmac
import struct
import threading

import pytest

import sctp_chunk_guard as scg

KEY1 = b"a" * 16
KEY2 = b"b" * 16


def guard(**kwargs):
    return scg.SctpGuard(**kwargs)


def chunk(chunk_type, flags, payload=b""):
    length = 4 + len(payload)
    raw = struct.pack("!BBH", chunk_type, flags, length) + payload
    return raw + b"\x00" * ((-len(raw)) % 4)


def auth_chunk(key, signed_chunks, key_id=1, hmac_id=1):
    digest = hmac.new(key, b"".join(signed_chunks), hashlib.sha1).digest()
    payload = struct.pack("!HH", key_id, hmac_id) + digest
    return chunk(15, 0x00, payload)


def signed_bundle(key, payload, key_id=1):
    data = chunk(0, 0x00, payload)
    auth = auth_chunk(key, [data], key_id=key_id)
    return auth + data


def test_parse_bundle_returns_length_payload_and_padded_raw():
    g = guard()
    raw = chunk(0, 0x00, b"abc")
    assert len(raw) == 8
    out = g.parse_bundle(raw)
    assert out == [{
        "type": 0, "flags": 0, "length": 7,
        "payload": b"abc", "raw": raw,
    }]
    assert g.stats()["parsed_bundles"] == 1


def test_bundle_size_and_chunk_count_limits_are_enforced():
    g = guard(max_bundle_bytes=8)
    with pytest.raises(scg.SctpError) as exc:
        g.parse_bundle(chunk(0, 0x00, b"12345"))
    assert exc.value.code == "SCTP_BUNDLE_TOO_LARGE"
    g = guard(max_chunks=1)
    with pytest.raises(scg.SctpError) as exc:
        g.parse_bundle(chunk(0, 0x00, b"a") + chunk(1, 0x00, b"b"))
    assert exc.value.code == "SCTP_CHUNK_LIMIT"


def test_chunk_lengths_are_validated_against_the_bundle():
    g = guard()
    with pytest.raises(scg.SctpError) as exc:
        g.parse_bundle(struct.pack("!BBH", 0, 0, 3) + b"x")
    assert exc.value.code == "SCTP_BAD_LENGTH"
    with pytest.raises(scg.SctpError) as exc:
        g.parse_bundle(struct.pack("!BBH", 0, 0, 20) + b"1234")
    assert exc.value.code == "SCTP_TRUNCATED"
    with pytest.raises(scg.SctpError) as exc:
        g.parse_bundle(chunk(0, 0x00, b"ab") + b"\x00\x00")
    assert exc.value.code == "SCTP_TRUNCATED"


def test_non_zero_padding_is_rejected():
    g = guard()
    raw = struct.pack("!BBH", 0, 0, 5) + b"a" + b"\x00\x00\x01"
    with pytest.raises(scg.SctpError) as exc:
        g.parse_bundle(raw)
    assert exc.value.code == "SCTP_BAD_PADDING"


def test_valid_auth_bundle_verifies_and_records_replay_tag():
    g = guard()
    g.add_key(1, KEY1)
    bundle = signed_bundle(KEY1, b"abc")
    chunks = g.parse_bundle(bundle)
    out = g.verify(chunks, assoc="assoc-1")
    assert out["status"] == "accepted"
    assert out["code"] is None
    assert out["key_id"] == 1
    assert out["chunk_count"] == 2
    assert out["auth_index"] == 0
    assert out["reported"] == []
    assert out["replay_entries"] == 1
    assert g.replay_count("assoc-1") == 1
    assert g.active_key_id() == 1
    assert g.stats()["verified"] == 1


def test_auth_chunk_must_be_first_and_unique():
    g = guard()
    data = chunk(0, 0x00, b"abc")
    auth = auth_chunk(KEY1, [data])
    with pytest.raises(scg.SctpError) as exc:
        g.verify(g.parse_bundle(data), assoc="a")
    assert exc.value.code == "SCTP_NO_AUTH"
    with pytest.raises(scg.SctpError) as exc:
        g.verify(g.parse_bundle(data + auth), assoc="a")
    assert exc.value.code == "SCTP_AUTH_NOT_FIRST"
    with pytest.raises(scg.SctpError) as exc:
        g.verify(g.parse_bundle(auth + auth + data), assoc="a")
    assert exc.value.code == "SCTP_AUTH_DUP"


def test_bad_signature_unknown_key_and_bad_hmac_id():
    g = guard()
    g.add_key(1, KEY1)
    data = chunk(0, 0x00, b"abc")
    auth = auth_chunk(KEY1, [data])
    parsed = g.parse_bundle(auth + data)
    tampered = g.parse_bundle(chunk(0, 0x00, b"abd"))[0]
    with pytest.raises(scg.SctpError) as exc:
        g.verify([parsed[0], tampered], assoc="a")
    assert exc.value.code == "SCTP_BAD_SIGNATURE"

    auth9 = auth_chunk(KEY1, [data], key_id=9)
    with pytest.raises(scg.SctpError) as exc:
        g.verify(g.parse_bundle(auth9 + data), assoc="b")
    assert exc.value.code == "SCTP_UNKNOWN_KEY"

    auth2 = auth_chunk(KEY1, [data], hmac_id=2)
    with pytest.raises(scg.SctpError) as exc:
        g.verify(g.parse_bundle(auth2 + data), assoc="c")
    assert exc.value.code == "SCTP_AUTH_FORMAT"


def test_replayed_bundle_is_rejected_within_the_window():
    g = guard()
    g.add_key(1, KEY1)
    chunks = g.parse_bundle(signed_bundle(KEY1, b"abc"))
    g.verify(chunks, assoc="assoc-1")
    with pytest.raises(scg.SctpError) as exc:
        g.verify(chunks, assoc="assoc-1")
    assert exc.value.code == "SCTP_REPLAY"
    assert g.stats()["replayed"] == 1
    assert g.stats()["rejected"] == 1


def test_replay_window_evicts_old_tags_and_allows_them_again():
    g = guard(replay_window=2)
    g.add_key(1, KEY1)
    bundles = [signed_bundle(KEY1, payload) for payload in (b"a", b"b", b"c")]
    for bundle in bundles:
        g.verify(g.parse_bundle(bundle), assoc="assoc-1")
    g.verify(g.parse_bundle(bundles[0]), assoc="assoc-1")
    assert g.replay_count("assoc-1") == 2
    with pytest.raises(scg.SctpError) as exc:
        g.verify(g.parse_bundle(bundles[2]), assoc="assoc-1")
    assert exc.value.code == "SCTP_REPLAY"


def test_key_rotation_grace_then_expiry_and_new_key_use():
    g = guard(key_grace=300.0)
    g.add_key(1, KEY1)
    g.add_key(2, KEY2, active=False)
    rotated = g.rotate_key(2, now=100.0)
    assert rotated["changed"] is True
    assert g.active_key_id() == 2

    old_bundle = signed_bundle(KEY1, b"old")
    assert g.verify(g.parse_bundle(old_bundle), assoc="a1", now=200.0)["key_id"] == 1
    assert g.verify(g.parse_bundle(old_bundle), assoc="a2", now=200.0)["key_id"] == 1
    with pytest.raises(scg.SctpError) as exc:
        g.verify(g.parse_bundle(old_bundle), assoc="a3", now=401.0)
    assert exc.value.code == "SCTP_KEY_EXPIRED"
    new_bundle = signed_bundle(KEY2, b"new", key_id=2)
    assert g.verify(g.parse_bundle(new_bundle), assoc="a4", now=401.0)["key_id"] == 2


def test_inactive_key_is_rejected_and_removing_active_key_clears_it():
    g = guard()
    g.add_key(1, KEY1)
    g.add_key(2, KEY2, active=False)
    bundle = signed_bundle(KEY2, b"abc", key_id=2)
    with pytest.raises(scg.SctpError) as exc:
        g.verify(g.parse_bundle(bundle), assoc="a1")
    assert exc.value.code == "SCTP_KEY_INACTIVE"
    assert g.active_key_id() == 1
    assert g.remove_key(1) is True
    assert g.active_key_id() is None
    with pytest.raises(scg.SctpError) as exc:
        g.verify(g.parse_bundle(bundle), assoc="a2")
    assert exc.value.code == "SCTP_NO_ACTIVE_KEY"


def test_unknown_chunk_action_bits_control_delivery():
    g = guard()
    g.add_key(1, KEY1)
    data = chunk(0, 0x00, b"abc")

    abort = chunk(60, 0xC0, b"")
    bundle = auth_chunk(KEY1, [data, abort]) + data + abort
    with pytest.raises(scg.SctpError) as exc:
        g.verify(g.parse_bundle(bundle), assoc="a1")
    assert exc.value.code == "SCTP_UNKNOWN_ABORT"

    error = chunk(61, 0x80, b"")
    bundle = auth_chunk(KEY1, [data, error]) + data + error
    with pytest.raises(scg.SctpError) as exc:
        g.verify(g.parse_bundle(bundle), assoc="a2")
    assert exc.value.code == "SCTP_UNKNOWN_ERROR"

    report = chunk(62, 0x40, b"x")
    bundle = auth_chunk(KEY1, [data, report]) + data + report
    out = g.verify(g.parse_bundle(bundle), assoc="a3")
    assert out["reported"] == [62]

    skip = chunk(63, 0x00, b"")
    bundle = auth_chunk(KEY1, [data, skip]) + data + skip
    out = g.verify(g.parse_bundle(bundle), assoc="a4")
    assert out["reported"] == []


def test_snapshot_restore_preserves_keys_replay_cache_and_counters():
    g = guard()
    g.add_key(1, KEY1)
    bundle = signed_bundle(KEY1, b"abc")
    chunks = g.parse_bundle(bundle)
    g.verify(chunks, assoc="assoc-1")
    snap = g.snapshot()
    pristine = g.snapshot()
    snap["keys"]["1"]["key_hex"] = "00" * 16
    snap["counters"]["verified"] = 99
    snap["replay"]["assoc-1"] = []
    assert g.stats()["verified"] == 1
    with pytest.raises(scg.SctpError) as exc:
        g.verify(chunks, assoc="assoc-1")
    assert exc.value.code == "SCTP_REPLAY"

    restored = guard()
    restored.restore(pristine)
    assert restored.active_key_id() == 1
    assert restored.stats()["verified"] == 1
    with pytest.raises(scg.SctpError) as exc:
        restored.verify(restored.parse_bundle(bundle), assoc="assoc-1")
    assert exc.value.code == "SCTP_REPLAY"
    fresh = restored.verify(
        restored.parse_bundle(signed_bundle(KEY1, b"xyz")), assoc="assoc-2"
    )
    assert fresh["status"] == "accepted"
    with pytest.raises(scg.SctpError) as exc:
        restored.restore({"version": 2})
    assert exc.value.code == "SCTP_STATE_VERSION"


def test_concurrent_verifications_are_atomic_per_association():
    g = guard()
    g.add_key(1, KEY1)
    errors = []

    def work(worker):
        try:
            bundle = signed_bundle(KEY1, f"payload-{worker}".encode())
            chunks = g.parse_bundle(bundle)
            g.verify(chunks, assoc=f"a{worker}")
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=work, args=(n,)) for n in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    stats = g.stats()
    assert stats["verified"] == 8
    assert stats["replay_entries"] == 8
    assert all(g.replay_count(f"a{n}") == 1 for n in range(8))


def test_clear_replay_and_remove_key_change_subsequent_verification():
    g = guard()
    g.add_key(1, KEY1)
    bundle = signed_bundle(KEY1, b"abc")
    chunks = g.parse_bundle(bundle)
    assert g.verify(chunks, assoc="a")["status"] == "accepted"
    assert g.clear_replay("a") == 1
    assert g.replay_count("a") == 0
    assert g.verify(chunks, assoc="a")["status"] == "accepted"
    assert g.remove_key(1) is True
    assert g.active_key_id() is None
    with pytest.raises(scg.SctpError) as exc:
        g.verify(g.parse_bundle(signed_bundle(KEY1, b"later")), assoc="b")
    assert exc.value.code == "SCTP_UNKNOWN_KEY"
    assert g.remove_key(1) is False
