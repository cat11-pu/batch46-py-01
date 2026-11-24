import hashlib
import hmac
import json

import pytest

import ntp_auth_guard as ntp

SECRET = "b7f1c9d2-relay-secret"


def mac_for(packet, secret=SECRET):
    canonical = "|".join([
        str(packet["key_id"]),
        packet["server"],
        str(packet["leap"]),
        str(packet["stratum"]),
        "%.6f" % packet["originate_time"],
        "%.6f" % packet["receive_time"],
        "%.6f" % packet["transmit_time"],
        "%.6f" % packet["root_delay"],
        "%.6f" % packet["root_dispersion"],
    ])
    return hmac.new(secret.encode("utf-8"), canonical.encode("utf-8"),
                    hashlib.sha256).hexdigest()


def build(server="ntp1.example", *, t1=1000.0, offset=0.0, key_id=1, leap=0,
          stratum=2, root_delay=0.1, dispersion=0.05, secret=SECRET):
    packet = {
        "server": server,
        "key_id": key_id,
        "leap": leap,
        "stratum": stratum,
        "originate_time": t1,
        "receive_time": t1 + offset,
        "transmit_time": t1 + offset,
        "root_delay": root_delay,
        "root_dispersion": dispersion,
    }
    packet["mac"] = mac_for(packet, secret)
    packet["arrived_at"] = t1
    return packet


def guard(**overrides):
    return ntp.NtpAuthGuard(clock=lambda: 1000.0, **overrides)


def ready(**overrides):
    g = guard(**overrides)
    g.add_key(1, SECRET)
    g.add_server("ntp1.example", key_id=1)
    return g


def sample(g, server="ntp1.example", *, t1=1000.0, offset=0.0, **overrides):
    g.make_request(server, transmit_time=t1)
    return g.receive(build(server, t1=t1, offset=offset, **overrides))


def test_valid_packet_computes_the_expected_offset():
    g = ready()
    out = sample(g, offset=-0.025)
    assert out["status"] == "accepted"
    assert out["code"] == "NTP_ACCEPTED"
    assert out["offset"] == pytest.approx(-0.025)
    assert g.offset() == pytest.approx(-0.025)
    assert g.state()["phase"] == "slewing"


def test_tampered_mac_is_rejected():
    g = ready()
    g.make_request("ntp1.example", transmit_time=1000.0)
    packet = build(offset=0.0)
    packet["mac"] = "0" * 64
    out = g.receive(packet)
    assert out["status"] == "rejected"
    assert out["code"] == "NTP_AUTH_FAILED"
    assert g.offset() == 0.0


def test_unknown_key_id_is_rejected():
    g = ready()
    g.make_request("ntp1.example", transmit_time=1000.0)
    out = g.receive(build(key_id=99))
    assert out["code"] == "NTP_UNKNOWN_KEY"


def test_key_registration_enforces_strength_and_uniqueness():
    g = guard()
    with pytest.raises(ntp.NtpError) as weak:
        g.add_key(7, "short")
    assert weak.value.code == "NTP_WEAK_KEY"
    g.add_key(1, SECRET)
    again = g.add_key(1, SECRET)
    assert again["key_id"] == 1
    with pytest.raises(ntp.NtpError) as clash:
        g.add_key(1, "another-secret-value")
    assert clash.value.code == "NTP_KEY_CONFLICT"
    with pytest.raises(ntp.NtpError) as bad_alg:
        g.add_key(2, "another-secret-value", algorithm="md5")
    assert bad_alg.value.code == "NTP_UNSUPPORTED_ALGORITHM"


def test_replay_and_stale_transmit_are_rejected():
    g = ready()
    first = sample(g, offset=0.0)
    assert first["status"] == "accepted"
    replayed = g.receive(build(offset=0.0))
    assert replayed["code"] == "NTP_REPLAY"
    stale = sample(g, t1=999.5)
    assert stale["code"] == "NTP_STALE_PACKET"
    assert g.health()["ntp1.example"]["accepted"] == 1


def test_stratum_range_is_enforced():
    g = ready()
    high = sample(g, stratum=16)
    assert high["code"] == "NTP_BAD_STRATUM"
    zero = sample(g, stratum=0, t1=1001.0)
    assert zero["code"] == "NTP_BAD_STRATUM"


def test_root_delay_ceiling_is_enforced():
    g = ready()
    out = sample(g, root_delay=2.0)
    assert out["code"] == "NTP_ROOT_DELAY"
    assert g.health()["ntp1.example"]["rejected"] == 1


def test_unsynchronized_leap_indicator_is_rejected():
    g = ready()
    out = sample(g, leap=3)
    assert out["code"] == "NTP_UNSYNC"


def test_originate_time_must_match_a_pending_request():
    g = ready()
    out = g.receive(build(t1=900.0))
    assert out["code"] == "NTP_BAD_ORIGINATE"
    assert g.offset() == 0.0


def test_excessive_offset_panics_and_requires_clear():
    g = ready()
    out = sample(g, offset=200.0)
    assert out["code"] == "NTP_OFFSET_TOO_LARGE"
    assert g.state()["phase"] == "panic"
    locked = sample(g, offset=0.1, t1=1001.0)
    assert locked["code"] == "NTP_PANIC_LOCKED"
    cleared = g.clear_panic()
    assert cleared["phase"] == "idle"
    assert cleared["offset"] == 0.0
    assert sample(g, offset=0.1, t1=1002.0)["status"] == "accepted"


def test_step_needs_consensus_and_falsetickers_are_excluded():
    g = ready()
    g.add_key(2, "second-key-secret")
    g.add_server("ntp2.example", key_id=2)
    g.add_key(3, "third-key-secret")
    g.add_server("ntp3.example", key_id=3)
    lonely = sample(g, offset=5.0)
    assert lonely["code"] == "NTP_STEP_NEEDS_CONSENSUS"
    assert g.offset() == 0.0
    agreed = sample(g, "ntp2.example", offset=5.0, secret="second-key-secret")
    assert agreed["status"] == "accepted"
    assert g.offset() == pytest.approx(5.0)
    outlier = sample(g, "ntp3.example", offset=50.0, secret="third-key-secret")
    assert outlier["code"] == "NTP_FALSETICKER"
    assert g.offset() == pytest.approx(5.0)


def test_adjust_slews_in_bounded_steps():
    g = ready()
    assert sample(g, offset=0.25)["status"] == "accepted"
    first = g.adjust()
    assert first["applied"] == pytest.approx(0.1)
    assert first["remaining"] == pytest.approx(0.15)
    assert first["phase"] == "slewing"
    rest = g.adjust(steps=2)
    assert rest["applied"] == pytest.approx(0.15)
    assert rest["remaining"] == pytest.approx(0.0)
    assert rest["phase"] == "locked"
    assert g.offset() == pytest.approx(0.0)


def test_server_registration_limits_and_unknown_keys():
    g = guard()
    g.add_key(1, SECRET)
    with pytest.raises(ntp.NtpError) as unknown:
        g.add_server("ghost.example", key_id=99)
    assert unknown.value.code == "NTP_UNKNOWN_KEY"
    for index in range(8):
        g.add_server("ntp%d.example" % index, key_id=1)
    with pytest.raises(ntp.NtpError) as duplicate:
        g.add_server("ntp0.example", key_id=1)
    assert duplicate.value.code == "NTP_SERVER_EXISTS"
    with pytest.raises(ntp.NtpError) as too_many:
        g.add_server("ntp9.example", key_id=1)
    assert too_many.value.code == "NTP_TOO_MANY_SERVERS"


def test_snapshot_never_carries_secrets_and_restore_requires_rekey():
    g = ready()
    assert sample(g, offset=0.25)["status"] == "accepted"
    snap = json.loads(json.dumps(g.snapshot()))
    assert snap["version"] == ntp.SNAPSHOT_VERSION
    assert SECRET not in json.dumps(snap)
    restored = guard()
    restored.restore(snap)
    assert restored.offset() == pytest.approx(0.25)
    assert restored.state()["phase"] == "slewing"
    restored.make_request("ntp1.example", transmit_time=2000.0)
    denied = restored.receive(build(t1=2000.0, offset=0.2))
    assert denied["code"] == "NTP_UNKNOWN_KEY"
    restored.add_key(1, SECRET)
    accepted = sample(restored, t1=2001.0, offset=0.2)
    assert accepted["status"] == "accepted"
    with pytest.raises(ntp.NtpError) as corrupt:
        restored.restore(dict(snap, version=9))
    assert corrupt.value.code == "NTP_SNAPSHOT_CORRUPT"


def test_health_tracks_per_server_counters():
    g = ready()
    sample(g, offset=0.0)
    g.make_request("ntp1.example", transmit_time=1001.0)
    tampered = build(t1=1001.0)
    tampered["mac"] = "f" * 64
    assert g.receive(tampered)["code"] == "NTP_AUTH_FAILED"
    bad = sample(g, stratum=16, t1=1002.0)
    assert bad["code"] == "NTP_BAD_STRATUM"
    row = g.health()["ntp1.example"]
    assert row["accepted"] == 1
    assert row["rejected"] == 2
    assert row["last_code"] == "NTP_BAD_STRATUM"
    assert row["last_transmit"] == pytest.approx(1000.0)
