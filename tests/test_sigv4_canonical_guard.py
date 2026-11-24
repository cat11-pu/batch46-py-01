import hashlib
import hmac
import threading
from datetime import datetime, timezone

import pytest

import sigv4_canonical_guard as sv


T0 = int(datetime(2026, 11, 23, 10, 0, 0, tzinfo=timezone.utc).timestamp())
CREDENTIALS = {
    "access_key": "AKIDEXAMPLE",
    "secret_key": "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
    "region": "us-east-1",
    "service": "s3",
}


def make():
    return sv.SigV4Guard()


def request(**overrides):
    base = {
        "method": "GET",
        "uri": "/bucket/key",
        "query": {"prefix": "a b"},
        "headers": {"Host": "example.amazonaws.com", "X-Custom": "trace"},
        "payload": "",
    }
    base.update(overrides)
    return base


def hmac_chain(secret, date, region, service):
    key = ("AWS4" + secret).encode()
    for part in (date, region, service, "aws4_request"):
        key = hmac.new(key, part.encode(), hashlib.sha256).digest()
    return key.hex()


def test_canonical_query_encodes_and_sorts_keys_and_values():
    g = make()
    assert g.canonical_query({"b": "2", "a": ["x y", "x/y"], "A": "z"}) == (
        "A=z&a=x%20y&a=x%2Fy&b=2"
    )


def test_canonical_query_handles_plus_space_tilde_and_utf8():
    g = make()
    assert g.canonical_query({"q": ["a+b", "a b", "~"], "z": "ü"}) == (
        "q=a%20b&q=a%2Bb&q=~&z=%C3%BC"
    )


def test_canonical_headers_lowercases_trims_collapses_and_excludes_unsignable():
    g = make()
    block, signed = g.canonical_headers(
        {
            "Host": "Example.COM",
            "X-Amz-Date": " 20261123T100000Z ",
            "User-Agent": "curl",
            "X-Custom": "a   b",
        }
    )
    assert block == (
        "host:Example.COM\n"
        "x-amz-date:20261123T100000Z\n"
        "x-custom:a b\n"
    )
    assert signed == "host;x-amz-date;x-custom"


def test_canonical_uri_normalizes_dots_duplicate_slashes_and_encodes():
    g = make()
    assert g.canonical_uri("/a/./b/../c//d") == "/a/c/d"
    assert g.canonical_uri("/a/b/") == "/a/b/"
    assert g.canonical_uri("") == "/"
    assert g.canonical_uri("/x y/ü") == "/x%20y/%C3%BC"


def test_build_canonical_request_layout_and_payload_hash_modes():
    g = make()
    payload_hash = hashlib.sha256(b"").hexdigest()
    out = g.build_canonical_request(
        {
            "method": "get",
            "uri": "/a/./b",
            "query": {"b": "2", "a": "1"},
            "headers": {"Host": "Example.COM", "X-Custom": "a   b"},
            "payload": "",
        }
    )
    assert out["payload_hash"] == payload_hash
    assert out["canonical_uri"] == "/a/b"
    assert out["canonical_query"] == "a=1&b=2"
    lines = out["canonical_request"].split("\n")
    assert lines == [
        "GET",
        "/a/b",
        "a=1&b=2",
        "host:Example.COM",
        "x-custom:a b",
        "",
        "host;x-custom",
        payload_hash,
    ]
    unsigned = g.build_canonical_request(
        {
            "method": "GET",
            "uri": "/a/b",
            "query": {},
            "headers": {"Host": "example.amazonaws.com"},
            "unsigned_payload": True,
        }
    )
    assert unsigned["payload_hash"] == "UNSIGNED-PAYLOAD"
    empty = g.build_canonical_request(
        {
            "method": "GET",
            "uri": "/a/b",
            "query": {},
            "headers": {"Host": "example.amazonaws.com"},
            "payload": None,
        }
    )
    assert empty["payload_hash"] == payload_hash


def test_string_to_sign_has_four_lines_and_canonical_hash():
    g = make()
    req = {
        "method": "GET",
        "uri": "/",
        "query": {},
        "headers": {"Host": "example.amazonaws.com"},
        "payload": "",
    }
    canonical = g.build_canonical_request(req)["canonical_request"]
    canonical_hash = hashlib.sha256(canonical.encode()).hexdigest()
    out = g.string_to_sign(
        req,
        timestamp="20261123T100000Z",
        scope="20261123/us-east-1/s3/aws4_request",
    )
    expected = (
        "AWS4-HMAC-SHA256\n"
        "20261123T100000Z\n"
        "20261123/us-east-1/s3/aws4_request\n"
        + canonical_hash
    )
    assert out["string_to_sign"] == expected
    assert out["canonical_hash"] == canonical_hash
    assert out["string_to_sign"].count("\n") == 3


def test_signing_key_is_deterministic_and_region_sensitive():
    g = make()
    expected = hmac_chain("secret", "20261123", "us-east-1", "s3")
    got = g.signing_key("secret", date="20261123", region="us-east-1", service="s3")
    assert got == expected
    assert len(got) == 64
    other = g.signing_key("secret", date="20261123", region="eu-west-1", service="s3")
    assert other != expected


def test_sign_adds_amz_date_and_canonical_authorization_then_verifies():
    g = make()
    signed = g.sign(request(), CREDENTIALS, now=T0)
    authorization = signed["authorization"]
    assert authorization.startswith(
        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20261123/us-east-1/s3/aws4_request"
    )
    assert "SignedHeaders=host;x-amz-date;x-custom" in authorization
    assert "Signature=" in authorization
    assert signed["headers"]["X-Amz-Date"] == "20261123T100000Z"
    out = g.verify(signed, CREDENTIALS, now=T0)
    assert out["status"] == "ok"
    assert out["code"] == "SIG_OK"


def test_verify_rejects_tampered_signed_header():
    g = make()
    signed = g.sign(request(), CREDENTIALS, now=T0)
    bad = dict(signed)
    bad["headers"] = dict(signed["headers"])
    bad["headers"]["X-Custom"] = "tampered"
    out = g.verify(bad, CREDENTIALS, now=T0)
    assert out["status"] == "denied"
    assert out["code"] == "SIG_SIGNATURE_MISMATCH"


def test_verify_enforces_clock_skew_boundary():
    g = make()
    signed = g.sign(request(), CREDENTIALS, now=T0)
    assert g.verify(signed, CREDENTIALS, now=T0 + 300)["code"] == "SIG_OK"
    assert g.verify(signed, CREDENTIALS, now=T0 + 301)["code"] == "SIG_CLOCK_SKEW"
    assert g.verify(signed, CREDENTIALS, now=T0 - 301)["code"] == "SIG_CLOCK_SKEW"


def test_verify_detects_replay_and_purge_releases_the_nonce():
    g = make()
    signed = g.sign(request(), CREDENTIALS, now=T0)
    assert g.verify(signed, CREDENTIALS, now=T0)["code"] == "SIG_OK"
    assert g.verify(signed, CREDENTIALS, now=T0)["code"] == "SIG_REPLAY"
    assert g.purge_replays(T0) == 1
    assert g.verify(signed, CREDENTIALS, now=T0)["code"] == "SIG_OK"


def test_presigned_url_expiry_boundary():
    g = make()
    req = request(query={}, uri="/bucket/key")
    signed = g.presign(req, CREDENTIALS, expires=900, now=T0)
    assert signed["query"]["X-Amz-Expires"] == "900"
    assert signed["query"]["X-Amz-Algorithm"] == "AWS4-HMAC-SHA256"
    assert signed["query"]["X-Amz-SignedHeaders"] == "host"
    assert "X-Amz-Signature" in signed["query"]
    assert g.verify_presigned(signed, CREDENTIALS, now=T0 + 899)["code"] == "SIG_OK"
    assert g.verify_presigned(signed, CREDENTIALS, now=T0 + 900)["code"] == "SIG_EXPIRED"


def test_presign_rejects_invalid_expiry_window():
    g = make()
    req = request(query={}, uri="/bucket/key")
    with pytest.raises(sv.SigV4Error) as exc:
        g.presign(req, CREDENTIALS, expires=604801, now=T0)
    assert exc.value.code == "SIG_INVALID_EXPIRY"
    with pytest.raises(sv.SigV4Error) as exc:
        g.presign(req, CREDENTIALS, expires=0, now=T0)
    assert exc.value.code == "SIG_INVALID_EXPIRY"


def test_snapshot_restore_keeps_replay_cache_and_counters():
    g = make()
    signed = g.sign(request(), CREDENTIALS, now=T0)
    assert g.verify(signed, CREDENTIALS, now=T0)["code"] == "SIG_OK"
    stats_before = g.stats()
    snap = g.snapshot()
    other = g.sign(request(uri="/other"), CREDENTIALS, now=T0)
    g.verify(other, CREDENTIALS, now=T0)
    restored = sv.SigV4Guard()
    restored.restore(snap)
    assert restored.stats() == stats_before
    again = restored.verify(signed, CREDENTIALS, now=T0)
    assert again["status"] == "denied"
    assert again["code"] == "SIG_REPLAY"


def test_concurrent_verify_claims_nonce_exactly_once():
    g = make()
    signed = g.sign(request(), CREDENTIALS, now=T0)
    codes = []
    errors = []
    lock = threading.Lock()
    barrier = threading.Barrier(8)

    def worker():
        try:
            barrier.wait()
            result = g.verify(signed, CREDENTIALS, now=T0)
        except Exception as exc:  # pragma: no cover - only on failure
            with lock:
                errors.append(repr(exc))
            return
        with lock:
            codes.append(result["code"])

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    assert codes.count("SIG_OK") == 1
    assert codes.count("SIG_REPLAY") == 7
    assert g.stats()["verified"] == 1
    assert g.stats()["rejected"] == 7
