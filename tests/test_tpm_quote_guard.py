import hashlib
import json
import threading

import pytest

import tpm_quote_guard as tq

T0 = "2026-11-23T09:00:00+00:00"
SECRET = "a" * 64
GOLDEN = {0: "11" * 32, 1: "22" * 32}


def canonical(values):
    rows = sorted((int(key), str(value).lower()) for key, value in values.items())
    return hashlib.sha256("|".join("%d:%s" % (index, digest) for index, digest in rows)
                          .encode("utf-8")).hexdigest()


def make():
    return tq.TpmQuoteGuard()


def enrolled(g, ak="ak-1", profile="baseline", pcrs=None, secret=SECRET):
    values = GOLDEN if pcrs is None else pcrs
    return g.enroll_ak(ak, secret=secret, profile=profile, pcrs=values, now=T0)


def setup(guard=None, min_counter=0):
    g = guard or make()
    g.define_profile("baseline", required_pcrs=(0, 1), golden=GOLDEN,
                     min_counter=min_counter)
    enrolled(g)
    return g


def build(node, nonce, counter, values=None, secret=SECRET, digest=None):
    vals = GOLDEN if values is None else values
    claimed = canonical(vals) if digest is None else digest
    return {
        "nonce": nonce,
        "pcr_values": {str(key): value for key, value in vals.items()},
        "pcr_digest": claimed,
        "counter": counter,
        "signature": tq.quote_signature(secret, node, nonce, claimed, counter),
    }


def test_profile_definition_validates_and_rejects_duplicates():
    g = make()
    spec = g.define_profile("baseline", required_pcrs=(0, 1), golden=GOLDEN)
    assert spec["version"] == 1
    assert spec["required_pcrs"] == [0, 1]
    with pytest.raises(tq.QuoteError) as duplicate:
        g.define_profile("baseline", required_pcrs=(0,), golden={0: "33" * 32})
    assert duplicate.value.code == "TQ_PROFILE_DUPLICATE"
    with pytest.raises(tq.QuoteError) as empty:
        g.define_profile("empty", required_pcrs=(), golden={})
    assert empty.value.code == "TQ_PROFILE_INVALID"
    with pytest.raises(tq.QuoteError) as mismatch:
        g.define_profile("partial", required_pcrs=(0, 1), golden={0: "11" * 32})
    assert mismatch.value.code == "TQ_PROFILE_INVALID"
    with pytest.raises(tq.QuoteError) as bad_digest:
        g.define_profile("bad", required_pcrs=(0,), golden={0: "not-hex"})
    assert bad_digest.value.code == "TQ_PCR_INVALID"
    with pytest.raises(tq.QuoteError) as bad_min:
        g.define_profile("low", required_pcrs=(0, 1), golden=GOLDEN, min_counter=-1)
    assert bad_min.value.code == "TQ_PROFILE_INVALID"
    assert g.stats()["profiles"] == 1


def test_enrollment_validates_secret_pcrs_and_duplicate():
    g = make()
    g.define_profile("baseline", required_pcrs=(0, 1), golden=GOLDEN)
    with pytest.raises(tq.QuoteError) as bad_secret:
        enrolled(g, secret="zz")
    assert bad_secret.value.code == "TQ_AK_SECRET_INVALID"
    with pytest.raises(tq.QuoteError) as missing:
        enrolled(g, pcrs={0: "11" * 32})
    assert missing.value.code == "TQ_PCR_REQUIRED_MISSING"
    with pytest.raises(tq.QuoteError) as bad_pcr:
        enrolled(g, pcrs={0: "11" * 32, 1: "xyz"})
    assert bad_pcr.value.code == "TQ_PCR_INVALID"
    ok = enrolled(g)
    assert ok["profile_version"] == 1
    with pytest.raises(tq.QuoteError) as duplicate:
        enrolled(g, pcrs=GOLDEN)
    assert duplicate.value.code == "TQ_AK_DUPLICATE"


def test_enrollment_rejects_unknown_profile_and_unknown_ak():
    g = make()
    with pytest.raises(tq.QuoteError) as unknown_profile:
        g.enroll_ak("ak-1", secret=SECRET, profile="ghost", pcrs=GOLDEN, now=T0)
    assert unknown_profile.value.code == "TQ_PROFILE_UNKNOWN"
    with pytest.raises(tq.QuoteError) as unknown_ak:
        g.revoke_ak("ghost")
    assert unknown_ak.value.code == "TQ_AK_UNKNOWN"
    with pytest.raises(tq.QuoteError) as bad_ttl:
        g.issue_nonce("node-1", now=T0, ttl_seconds=0)
    assert bad_ttl.value.code == "TQ_TTL_INVALID"


def test_nonce_is_deterministic_and_capped_per_node():
    g = make()
    expected = []
    for seq in range(1, 5):
        reply = g.issue_nonce("node-1", now=T0)
        assert reply["seq"] == seq
        assert reply["nonce"] == hashlib.sha256(
            ("node-1|%d" % seq).encode("utf-8")).hexdigest()[:32]
        assert reply["expires_at"] == "2026-11-23T09:05:00+00:00"
        expected.append(reply["nonce"])
    assert len(set(expected)) == 4
    with pytest.raises(tq.QuoteError) as capped:
        g.issue_nonce("node-1", now=T0)
    assert capped.value.code == "TQ_NONCE_CAP"
    other = g.issue_nonce("node-2", now=T0)
    assert other["seq"] == 1
    assert other["nonce"] != expected[0]


def test_nonce_expires_and_is_not_reissued():
    g = setup()
    first = g.issue_nonce("node-1", now=T0, ttl_seconds=60)
    stale_quote = build("node-1", first["nonce"], 5)
    with pytest.raises(tq.QuoteError) as expired:
        g.verify_quote("node-1", ak_name="ak-1", quote=stale_quote,
                       now="2026-11-23T09:02:00+00:00")
    assert expired.value.code == "TQ_NONCE_EXPIRED"
    second = g.issue_nonce("node-1", now="2026-11-23T09:02:00+00:00")
    assert second["seq"] == 2
    assert second["nonce"] != first["nonce"]
    report = g.sweep(now="2026-11-23T09:10:00+00:00")
    assert report["nonces"] == 1
    with pytest.raises(tq.QuoteError) as unknown:
        g.verify_quote("node-1", ak_name="ak-1", quote=stale_quote,
                       now="2026-11-23T09:10:00+00:00")
    assert unknown.value.code == "TQ_NONCE_UNKNOWN"


def test_successful_quote_consumes_nonce_and_marks_trusted():
    g = setup()
    issued = g.issue_nonce("node-1", now=T0)
    out = g.verify_quote("node-1", ak_name="ak-1",
                         quote=build("node-1", issued["nonce"], 5), now=T0)
    assert out["status"] == "trusted"
    assert out["counter"] == 5
    assert out["profile"] == "baseline"
    state = g.trust_state("node-1")
    assert state["trusted"] is True
    assert state["ak"] == "ak-1"
    assert state["counter"] == 5
    with pytest.raises(tq.QuoteError) as consumed:
        g.verify_quote("node-1", ak_name="ak-1",
                       quote=build("node-1", issued["nonce"], 5), now=T0)
    assert consumed.value.code == "TQ_NONCE_CONSUMED"
    assert g.stats()["quotes"] == 1
    assert g.trust_state("ghost")["trusted"] is False


def test_bad_signature_does_not_consume_nonce_so_retry_succeeds():
    g = setup()
    issued = g.issue_nonce("node-1", now=T0)
    bad = build("node-1", issued["nonce"], 5)
    bad["signature"] = "0" * 64
    with pytest.raises(tq.QuoteError) as invalid:
        g.verify_quote("node-1", ak_name="ak-1", quote=bad, now=T0)
    assert invalid.value.code == "TQ_SIGNATURE_INVALID"
    good = build("node-1", issued["nonce"], 5)
    out = g.verify_quote("node-1", ak_name="ak-1", quote=good, now=T0)
    assert out["status"] == "trusted"


def test_pcr_digest_uses_numeric_index_order():
    g = make()
    values = {2: "aa" * 32, 10: "bb" * 32}
    g.define_profile("wide", required_pcrs=(2, 10), golden=values)
    g.enroll_ak("ak-1", secret=SECRET, profile="wide", pcrs=values, now=T0)
    issued = g.issue_nonce("node-1", now=T0)
    out = g.verify_quote("node-1", ak_name="ak-1",
                         quote=build("node-1", issued["nonce"], 5, values=values), now=T0)
    assert out["status"] == "trusted"
    lexicographic = hashlib.sha256(
        ("10:%s|2:%s" % (values[10], values[2])).encode("utf-8")).hexdigest()
    assert lexicographic != canonical(values)
    second = g.issue_nonce("node-1", now=T0)
    wrong = build("node-1", second["nonce"], 6, values=values, digest=lexicographic)
    with pytest.raises(tq.QuoteError) as mismatch:
        g.verify_quote("node-1", ak_name="ak-1", quote=wrong, now=T0)
    assert mismatch.value.code == "TQ_PCR_DIGEST_MISMATCH"


def test_pcr_mismatch_untrusts_node_and_counts_toward_rate_limit():
    g = setup()
    issued = g.issue_nonce("node-1", now=T0)
    g.verify_quote("node-1", ak_name="ak-1",
                   quote=build("node-1", issued["nonce"], 5), now=T0)
    assert g.trust_state("node-1")["trusted"] is True
    tampered = {0: "11" * 32, 1: "99" * 32}
    for index in range(3):
        nonce = g.issue_nonce("node-1", now=T0)["nonce"]
        with pytest.raises(tq.QuoteError) as mismatch:
            g.verify_quote("node-1", ak_name="ak-1",
                           quote=build("node-1", nonce, 5 + index, values=tampered), now=T0)
        assert mismatch.value.code == "TQ_PCR_MISMATCH"
    assert g.trust_state("node-1")["trusted"] is False
    nonce = g.issue_nonce("node-1", now=T0)["nonce"]
    with pytest.raises(tq.QuoteError) as limited:
        g.verify_quote("node-1", ak_name="ak-1",
                       quote=build("node-1", nonce, 20), now=T0)
    assert limited.value.code == "TQ_RATE_LIMITED"


def test_counter_replay_is_rejected_and_counter_below_min_is_stale():
    g = setup()
    first = g.issue_nonce("node-1", now=T0)
    g.verify_quote("node-1", ak_name="ak-1",
                   quote=build("node-1", first["nonce"], 5), now=T0)
    replay = g.issue_nonce("node-1", now=T0)
    with pytest.raises(tq.QuoteError) as counter_replay:
        g.verify_quote("node-1", ak_name="ak-1",
                       quote=build("node-1", replay["nonce"], 5), now=T0)
    assert counter_replay.value.code == "TQ_COUNTER_REPLAY"
    g.define_profile("strict", required_pcrs=(0, 1), golden=GOLDEN, min_counter=10)
    g.enroll_ak("ak-2", secret="b" * 64, profile="strict", pcrs=GOLDEN, now=T0)
    stale = g.issue_nonce("node-2", now=T0)
    with pytest.raises(tq.QuoteError) as stale_counter:
        g.verify_quote("node-2", ak_name="ak-2",
                       quote=build("node-2", stale["nonce"], 7, secret="b" * 64), now=T0)
    assert stale_counter.value.code == "TQ_COUNTER_STALE"


def test_profile_rotation_invalidates_enrollment():
    g = setup()
    issued = g.issue_nonce("node-1", now=T0)
    g.verify_quote("node-1", ak_name="ak-1",
                   quote=build("node-1", issued["nonce"], 5), now=T0)
    rotated = g.rotate_profile("baseline", required_pcrs=(0, 1, 7),
                               golden=dict(GOLDEN, **{"7": "77" * 32}))
    assert rotated["version"] == 2
    fresh = g.issue_nonce("node-1", now=T0)
    with pytest.raises(tq.QuoteError) as stale:
        g.verify_quote("node-1", ak_name="ak-1",
                       quote=build("node-1", fresh["nonce"], 6), now=T0)
    assert stale.value.code == "TQ_ENROLLMENT_STALE"
    wide = dict(GOLDEN)
    wide[7] = "77" * 32
    g.enroll_ak("ak-2", secret="b" * 64, profile="baseline", pcrs=wide, now=T0)
    second = g.issue_nonce("node-1", now=T0)
    out = g.verify_quote("node-1", ak_name="ak-2",
                         quote=build("node-1", second["nonce"], 6,
                                     values=wide, secret="b" * 64), now=T0)
    assert out["status"] == "trusted"
    assert out["profile"] == "baseline"


def test_revoked_ak_is_rejected_and_untrusts_node():
    g = setup()
    issued = g.issue_nonce("node-1", now=T0)
    g.verify_quote("node-1", ak_name="ak-1",
                   quote=build("node-1", issued["nonce"], 5), now=T0)
    revoked = g.revoke_ak("ak-1", reason="decommissioned")
    assert revoked["status"] == "revoked"
    assert g.trust_state("node-1")["trusted"] is False
    fresh = g.issue_nonce("node-1", now=T0)
    with pytest.raises(tq.QuoteError) as blocked:
        g.verify_quote("node-1", ak_name="ak-1",
                       quote=build("node-1", fresh["nonce"], 6), now=T0)
    assert blocked.value.code == "TQ_AK_REVOKED"
    assert g.revoke_ak("ak-1")["status"] == "revoked"
    assert g.stats()["aks"] == 0


def test_snapshot_restore_preserves_counter_and_nonce_sequence():
    g = setup()
    issued = g.issue_nonce("node-1", now=T0)
    g.verify_quote("node-1", ak_name="ak-1",
                   quote=build("node-1", issued["nonce"], 5), now=T0)
    snap = json.loads(json.dumps(g.snapshot()))
    g.restore(snap)
    assert g.trust_state("node-1")["counter"] == 5
    again = g.issue_nonce("node-1", now=T0)
    assert again["seq"] == 2
    with pytest.raises(tq.QuoteError) as replay:
        g.verify_quote("node-1", ak_name="ak-1",
                       quote=build("node-1", again["nonce"], 5), now=T0)
    assert replay.value.code == "TQ_COUNTER_REPLAY"


def test_stale_snapshot_cannot_roll_back_counters():
    g = setup()
    first = g.issue_nonce("node-1", now=T0)
    g.verify_quote("node-1", ak_name="ak-1",
                   quote=build("node-1", first["nonce"], 5), now=T0)
    snap = g.snapshot()
    second = g.issue_nonce("node-1", now=T0)
    g.verify_quote("node-1", ak_name="ak-1",
                   quote=build("node-1", second["nonce"], 6), now=T0)
    with pytest.raises(tq.QuoteError) as stale:
        g.restore(snap)
    assert stale.value.code == "TQ_SNAPSHOT_STALE"
    with pytest.raises(tq.QuoteError) as invalid:
        g.restore({"version": 9})
    assert invalid.value.code == "TQ_SNAPSHOT_INVALID"
    issued = g.issue_nonce("node-1", now=T0)
    with pytest.raises(tq.QuoteError) as replay:
        g.verify_quote("node-1", ak_name="ak-1",
                       quote=build("node-1", issued["nonce"], 6), now=T0)
    assert replay.value.code == "TQ_COUNTER_REPLAY"
    assert g.trust_state("node-1")["counter"] == 6


def test_concurrent_quotes_with_same_counter_accept_exactly_one():
    g = tq.TpmQuoteGuard(failure_budget=50, nonce_cap=16)
    g.define_profile("baseline", required_pcrs=(0, 1), golden=GOLDEN)
    g.enroll_ak("ak-1", secret=SECRET, profile="baseline", pcrs=GOLDEN, now=T0)
    nonces = [g.issue_nonce("node-1", now=T0)["nonce"] for _ in range(12)]
    barrier = threading.Barrier(12)
    accepted = []
    rejected = []
    errors = []

    def worker(nonce):
        try:
            barrier.wait(timeout=10)
            out = g.verify_quote("node-1", ak_name="ak-1",
                                 quote=build("node-1", nonce, 5), now=T0)
            accepted.append(out["status"])
        except tq.QuoteError as exc:
            rejected.append(exc.code)
        except Exception as exc:  # pragma: no cover - defensive
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(nonce,)) for nonce in nonces]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=20)
    assert errors == []
    assert accepted == ["trusted"]
    assert len(rejected) == 11
    assert set(rejected) == {"TQ_COUNTER_REPLAY"}
    assert g.stats()["quotes"] == 1
