"""Replay-safe TPM quote verification.

The guard owns profile baselines, enrolled attestation keys, single-use nonce
state, verification counters and the per-node trust view.  Every check and the
corresponding state transition happen while holding one re-entrant lock.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import re
import threading
import time
from datetime import datetime, timezone


SNAPSHOT_VERSION = 1

_HEX_64 = re.compile(r"^[0-9a-fA-F]{64}$")


class TpmQuoteError(ValueError):
    """A verification failure carrying a stable ``TQ_*`` code."""

    def __init__(self, code: str, detail=None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


# Friendly aliases for callers that use a shorter exception name.
TQError = TpmQuoteError
QuoteError = TpmQuoteError
TpmQuoteGuardError = TpmQuoteError
QuoteGuardError = TpmQuoteError
GuardError = TpmQuoteError
TpmError = TpmQuoteError


TQ_PROFILE_INVALID = "TQ_PROFILE_INVALID"
TQ_PROFILE_DUPLICATE = "TQ_PROFILE_DUPLICATE"
TQ_PROFILE_UNKNOWN = "TQ_PROFILE_UNKNOWN"
TQ_PCR_INVALID = "TQ_PCR_INVALID"
TQ_PCR_REQUIRED_MISSING = "TQ_PCR_REQUIRED_MISSING"
TQ_AK_SECRET_INVALID = "TQ_AK_SECRET_INVALID"
TQ_AK_DUPLICATE = "TQ_AK_DUPLICATE"
TQ_AK_REVOKED = "TQ_AK_REVOKED"
TQ_AK_UNKNOWN = "TQ_AK_UNKNOWN"
TQ_TTL_INVALID = "TQ_TTL_INVALID"
TQ_NONCE_CAP = "TQ_NONCE_CAP"
TQ_NONCE_EXPIRED = "TQ_NONCE_EXPIRED"
TQ_NONCE_CONSUMED = "TQ_NONCE_CONSUMED"
TQ_NONCE_UNKNOWN = "TQ_NONCE_UNKNOWN"
TQ_QUOTE_INVALID = "TQ_QUOTE_INVALID"
TQ_PCR_MISSING = "TQ_PCR_MISSING"
TQ_SIGNATURE_INVALID = "TQ_SIGNATURE_INVALID"
TQ_PCR_DIGEST_MISMATCH = "TQ_PCR_DIGEST_MISMATCH"
TQ_PCR_MISMATCH = "TQ_PCR_MISMATCH"
TQ_COUNTER_REPLAY = "TQ_COUNTER_REPLAY"
TQ_COUNTER_STALE = "TQ_COUNTER_STALE"
TQ_RATE_LIMITED = "TQ_RATE_LIMITED"
TQ_ENROLLMENT_STALE = "TQ_ENROLLMENT_STALE"
TQ_SNAPSHOT_INVALID = "TQ_SNAPSHOT_INVALID"
TQ_SNAPSHOT_STALE = "TQ_SNAPSHOT_STALE"


def _is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _parse_time(value) -> float:
    """Accept epoch numbers, datetimes and ISO-8601 strings."""

    if value is None:
        return time.time()
    if isinstance(value, bool):
        raise TpmQuoteError(TQ_QUOTE_INVALID, "boolean timestamp")
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, datetime):
        moment = value
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        return moment.timestamp()
    if isinstance(value, str):
        text = value.strip()
        if not text:
            raise TpmQuoteError(TQ_QUOTE_INVALID, "empty timestamp")
        try:
            return float(text)
        except ValueError:
            pass
        iso = text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text
        try:
            moment = datetime.fromisoformat(iso)
        except ValueError as exc:
            raise TpmQuoteError(TQ_QUOTE_INVALID, text) from exc
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        return moment.timestamp()
    raise TpmQuoteError(TQ_QUOTE_INVALID, repr(value))


def _iso_utc(timestamp: float) -> str:
    return (
        datetime.fromtimestamp(timestamp, timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def quote_signature(
    secret: str,
    node_id: str,
    nonce: str,
    pcr_digest: str,
    counter: int,
) -> str:
    message = "{}|{}|{}|{}|{}".format(
        node_id, nonce, pcr_digest, counter, secret
    )
    return hashlib.sha256(message.encode("utf-8")).hexdigest()


def _normalise_pcrs(pcrs, error_code=TQ_QUOTE_INVALID) -> dict:
    if not isinstance(pcrs, dict):
        raise TpmQuoteError(error_code, "PCRs must be a mapping")
    normalised = {}
    for raw_index, digest in pcrs.items():
        if isinstance(raw_index, bool):
            raise TpmQuoteError(error_code, "PCR index must be an integer")
        if isinstance(raw_index, int):
            index = raw_index
        elif isinstance(raw_index, str) and raw_index.strip().isdigit():
            index = int(raw_index.strip())
        else:
            raise TpmQuoteError(error_code, "PCR index must be an integer")
        if index in normalised:
            raise TpmQuoteError(error_code, "duplicate PCR index")
        if not isinstance(digest, str) or _HEX_64.fullmatch(digest) is None:
            raise TpmQuoteError(TQ_PCR_INVALID, repr(digest))
        normalised[index] = digest
    return normalised


def pcr_digest(pcrs) -> str:
    """Hash ``index:digest`` entries in numeric index order."""

    normalised = _normalise_pcrs(pcrs, TQ_PCR_INVALID)
    payload = "|".join(
        "{}:{}".format(index, normalised[index])
        for index in sorted(normalised)
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# Common alternate spelling used by callers.
compute_pcr_digest = pcr_digest


def _validate_profile_fields(name, required_pcrs, golden, min_counter):
    if not isinstance(name, str) or not name.strip():
        raise TpmQuoteError(TQ_PROFILE_INVALID, "profile name must be non-empty")
    if isinstance(required_pcrs, (str, bytes)) or not isinstance(
        required_pcrs, (list, tuple)
    ):
        raise TpmQuoteError(TQ_PROFILE_INVALID, "required_pcrs must be a list")
    required = list(required_pcrs)
    if not required:
        raise TpmQuoteError(TQ_PROFILE_INVALID, "required_pcrs must not be empty")
    seen = set()
    for index in required:
        if not _is_int(index):
            raise TpmQuoteError(
                TQ_PROFILE_INVALID, "PCR indices must be integers"
            )
        if index in seen:
            raise TpmQuoteError(
                TQ_PROFILE_INVALID, "PCR indices must be unique"
            )
        seen.add(index)

    if not isinstance(golden, dict):
        raise TpmQuoteError(TQ_PROFILE_INVALID, "golden must be a mapping")
    golden_keys = set()
    for index in golden:
        if not _is_int(index):
            raise TpmQuoteError(
                TQ_PROFILE_INVALID, "golden PCR indices must be integers"
            )
        golden_keys.add(index)
    if golden_keys != seen:
        raise TpmQuoteError(
            TQ_PROFILE_INVALID, "golden keys must match required_pcrs"
        )
    for index in required:
        digest = golden[index]
        if not isinstance(digest, str) or _HEX_64.fullmatch(digest) is None:
            raise TpmQuoteError(TQ_PCR_INVALID, repr(digest))

    if not _is_int(min_counter) or min_counter < 0:
        raise TpmQuoteError(
            TQ_PROFILE_INVALID, "min_counter must be a non-negative integer"
        )
    return required, dict(golden), min_counter


class TpmQuoteGuard:
    """Thread-safe TPM quote verifier."""

    def __init__(
        self,
        nonce_ttl_seconds: int = 300,
        nonce_cap: int = 4,
        failure_budget: int = 3,
        failure_window_seconds: int = 60,
        audit_capacity: int = 128,
    ) -> None:
        self.nonce_ttl_seconds = nonce_ttl_seconds
        self.nonce_cap = nonce_cap
        self.failure_budget = failure_budget
        self.failure_window_seconds = failure_window_seconds
        self.audit_capacity = audit_capacity

        self._lock = threading.RLock()
        self._profiles = {}
        self._aks = {}
        self._nonce_seq = {}
        self._pending = {}
        self._consumed = {}
        self._trust = {}
        self._failures = {}
        self._audit = []
        self._snapshot_generation = 0
        self._stats = {
            "profiles_created": 0,
            "profiles_rotated": 0,
            "aks_enrolled": 0,
            "aks_revoked": 0,
            "nonces_issued": 0,
            "nonces_consumed": 0,
            "nonces_expired": 0,
            "verifications": 0,
            "trusted_quotes": 0,
            "rejected": 0,
            "rate_limited": 0,
            "verification_generation": 0,
            "signature_invalid": 0,
            "digest_mismatch": 0,
            "pcr_mismatch": 0,
            "counter_replays": 0,
            "counter_stale": 0,
            "nonce_expired": 0,
        }

    # ------------------------------------------------------------- utilities
    @staticmethod
    def _profile_view(record: dict) -> dict:
        return {
            "name": record["name"],
            "version": record["version"],
            "required_pcrs": list(record["required_pcrs"]),
            "golden": {int(k): v for k, v in record["golden"].items()},
            "min_counter": record["min_counter"],
        }

    @staticmethod
    def _ak_view(record: dict) -> dict:
        return {
            "ak_name": record["ak_name"],
            "name": record["ak_name"],
            "profile": record["profile"],
            "profile_name": record["profile"],
            "profile_version": record["profile_version"],
            "pcrs": {
                int(k): v for k, v in record["pcrs"].items()
            },
            "pubkey_id": record.get("pubkey_id"),
            "enrolled_at": record.get("enrolled_at"),
            "revoked": record.get("revoked", False),
            "revoked_at": record.get("revoked_at"),
            "reason": record.get("reason"),
            "counter": record.get("last_counter"),
            "last_counter": record.get("last_counter"),
            "status": "revoked" if record.get("revoked") else "enrolled",
        }

    def _audit_write(
        self, code: str, *, action: str = "verify", **fields
    ) -> None:
        row = {"action": action, "event": action, "code": code}
        row.update(fields)
        if "at" not in row:
            row["at"] = _iso_utc(time.time())
        if "allowed" not in row:
            row["allowed"] = True
        self._audit.insert(0, row)
        if self.audit_capacity >= 0 and len(self._audit) > self.audit_capacity:
            del self._audit[self.audit_capacity:]

    def _trust_record(self, node_id: str) -> dict:
        record = self._trust.get(node_id)
        if record is None:
            record = {
                "node": node_id,
                "node_id": node_id,
                "trusted": False,
                "status": "unknown",
                "generation": 0,
                "counter": None,
                "last_counter": None,
                "profile": None,
                "profile_version": None,
                "pcr_digest": None,
                "ak_name": None,
                "last_verified_at": None,
                "reason": None,
            }
            self._trust[node_id] = record
        return record

    def _consume_nonce(self, node_id: str, nonce: str) -> None:
        pending = self._pending.get(node_id)
        if pending is not None:
            pending.pop(nonce, None)
        self._consumed.setdefault(node_id, set()).add(nonce)
        self._stats["nonces_consumed"] += 1

    def _prune_expired_for_node(self, node_id: str, now_ts: float) -> int:
        pending = self._pending.get(node_id)
        if not pending:
            return 0
        expired = [
            nonce
            for nonce, entry in pending.items()
            if now_ts >= entry["_expires_ts"]
        ]
        for nonce in expired:
            del pending[nonce]
        self._stats["nonces_expired"] += len(expired)
        return len(expired)

    # -------------------------------------------------------------- profiles
    def define_profile(
        self,
        name: str,
        *,
        required_pcrs: tuple,
        golden: dict,
        min_counter: int = 0,
    ) -> dict:
        with self._lock:
            if name in self._profiles:
                raise TpmQuoteError(TQ_PROFILE_DUPLICATE, name)
            required, golden_copy, min_counter = _validate_profile_fields(
                name, required_pcrs, golden, min_counter
            )
            record = {
                "name": name,
                "version": 1,
                "required_pcrs": tuple(required),
                "golden": golden_copy,
                "min_counter": min_counter,
            }
            self._profiles[name] = record
            self._stats["profiles_created"] += 1
            self._audit_write(
                "TQ_OK",
                action="profile_defined",
                profile=name,
                version=1,
            )
            return self._profile_view(record)

    def rotate_profile(
        self,
        name: str,
        *,
        required_pcrs=None,
        golden=None,
        min_counter=None,
    ) -> dict:
        with self._lock:
            current = self._profiles.get(name)
            if current is None:
                raise TpmQuoteError(TQ_PROFILE_UNKNOWN, name)
            new_required = (
                current["required_pcrs"]
                if required_pcrs is None
                else required_pcrs
            )
            new_golden = (
                dict(current["golden"]) if golden is None else golden
            )
            new_min = (
                current["min_counter"]
                if min_counter is None
                else min_counter
            )
            required, golden_copy, new_min = _validate_profile_fields(
                name, new_required, new_golden, new_min
            )
            record = {
                "name": name,
                "version": current["version"] + 1,
                "required_pcrs": tuple(required),
                "golden": golden_copy,
                "min_counter": new_min,
            }
            self._profiles[name] = record
            self._stats["profiles_rotated"] += 1
            self._audit_write(
                "TQ_OK",
                action="profile_rotated",
                profile=name,
                version=record["version"],
            )
            return self._profile_view(record)

    # ---------------------------------------------------------------- AKs
    def enroll_ak(
        self,
        ak_name: str,
        *,
        secret: str,
        profile: str,
        pcrs: dict,
        pubkey_id=None,
        now=None,
    ) -> dict:
        timestamp = _parse_time(now)
        display = _iso_utc(timestamp)
        with self._lock:
            if not isinstance(ak_name, str) or not ak_name.strip():
                raise TpmQuoteError(TQ_QUOTE_INVALID, "AK name must be non-empty")
            if ak_name in self._aks:
                raise TpmQuoteError(TQ_AK_DUPLICATE, ak_name)
            profile_record = self._profiles.get(profile)
            if profile_record is None:
                raise TpmQuoteError(TQ_PROFILE_UNKNOWN, profile)
            if (
                not isinstance(secret, str)
                or _HEX_64.fullmatch(secret) is None
            ):
                raise TpmQuoteError(TQ_AK_SECRET_INVALID, repr(secret))
            if not isinstance(pcrs, dict):
                raise TpmQuoteError(TQ_QUOTE_INVALID, "PCRs must be a mapping")
            if not isinstance(profile, str):
                raise TpmQuoteError(TQ_PROFILE_UNKNOWN, repr(profile))

            supplied = _normalise_pcrs(pcrs, TQ_QUOTE_INVALID)
            missing = [
                index
                for index in profile_record["required_pcrs"]
                if index not in supplied
            ]
            if missing:
                raise TpmQuoteError(
                    TQ_PCR_REQUIRED_MISSING, tuple(missing)
                )

            record = {
                "ak_name": ak_name,
                "secret": secret,
                "profile": profile,
                "profile_version": profile_record["version"],
                "pcrs": {int(k): v for k, v in supplied.items()},
                "pubkey_id": pubkey_id,
                "enrolled_at": display,
                "revoked": False,
                "revoked_at": None,
                "reason": None,
                "last_counter": None,
            }
            self._aks[ak_name] = record
            self._stats["aks_enrolled"] += 1
            self._audit_write(
                "TQ_OK",
                action="ak_enrolled",
                ak_name=ak_name,
                profile=profile,
                profile_version=record["profile_version"],
                at=display,
            )
            return self._ak_view(record)

    def revoke_ak(self, ak_name: str, *, reason: str = "manual") -> dict:
        timestamp = _parse_time(None)
        display = _iso_utc(timestamp)
        with self._lock:
            record = self._aks.get(ak_name)
            if record is None:
                raise TpmQuoteError(TQ_AK_UNKNOWN, ak_name)
            if not record.get("revoked"):
                record["revoked"] = True
                record["reason"] = reason
                record["revoked_at"] = display
                self._stats["aks_revoked"] += 1
                self._audit_write(
                    "TQ_OK",
                    action="ak_revoked",
                    ak_name=ak_name,
                    reason=reason,
                    at=display,
                )
                for state in self._trust.values():
                    if state.get("ak_name") == ak_name:
                        state["trusted"] = False
                        state["status"] = "untrusted"
                        state["reason"] = "ak_revoked"
            return self._ak_view(record)

    # -------------------------------------------------------------- nonces
    def issue_nonce(
        self,
        node_id: str,
        *,
        ttl_seconds=None,
        now=None,
    ) -> dict:
        timestamp = _parse_time(now)
        ttl = self.nonce_ttl_seconds if ttl_seconds is None else ttl_seconds
        if not _is_int(ttl) or ttl <= 0:
            raise TpmQuoteError(TQ_TTL_INVALID, repr(ttl))

        with self._lock:
            if not isinstance(node_id, str) or not node_id:
                raise TpmQuoteError(TQ_QUOTE_INVALID, "node id must be non-empty")
            self._prune_expired_for_node(node_id, timestamp)
            pending = self._pending.setdefault(node_id, {})
            if self.nonce_cap >= 0 and len(pending) >= self.nonce_cap:
                raise TpmQuoteError(TQ_NONCE_CAP, len(pending))

            sequence = self._nonce_seq.get(node_id, 0) + 1
            nonce = hashlib.sha256(
                "{}|{}".format(node_id, sequence).encode("utf-8")
            ).hexdigest()[:32]
            expires_ts = timestamp + ttl
            pending[nonce] = {
                "node": node_id,
                "nonce": nonce,
                "seq": sequence,
                "expires_at": _iso_utc(expires_ts),
                "_expires_ts": expires_ts,
            }
            self._nonce_seq[node_id] = sequence
            self._stats["nonces_issued"] += 1
            return {
                "node": node_id,
                "nonce": nonce,
                "seq": sequence,
                "expires_at": _iso_utc(expires_ts),
            }

    # -------------------------------------------------------------- verify
    def verify_quote(
        self,
        node_id: str,
        *,
        ak_name: str,
        quote: dict,
        now=None,
    ) -> dict:
        timestamp = _parse_time(now)
        display = _iso_utc(timestamp)
        with self._lock:
            self._stats["verifications"] += 1
            failures = [
                failure_ts
                for failure_ts in self._failures.get(node_id, ())
                if timestamp - failure_ts < self.failure_window_seconds
            ]
            self._failures[node_id] = failures
            if len(failures) >= self.failure_budget:
                self._stats["rate_limited"] += 1
                self._stats["rejected"] += 1
                self._audit_write(
                    TQ_RATE_LIMITED,
                    node=node_id,
                    node_id=node_id,
                    ak_name=ak_name,
                    status="rejected",
                    allowed=False,
                    at=display,
                    ts=timestamp,
                )
                raise TpmQuoteError(TQ_RATE_LIMITED, node_id)

            try:
                result = self._verify_locked(
                    node_id, ak_name, quote, timestamp, display
                )
            except TpmQuoteError as exc:
                self._stats["rejected"] += 1
                error_counter = {
                    TQ_SIGNATURE_INVALID: "signature_invalid",
                    TQ_PCR_DIGEST_MISMATCH: "digest_mismatch",
                    TQ_PCR_MISMATCH: "pcr_mismatch",
                    TQ_COUNTER_REPLAY: "counter_replays",
                    TQ_COUNTER_STALE: "counter_stale",
                    TQ_NONCE_EXPIRED: "nonce_expired",
                }.get(exc.code)
                if error_counter is not None:
                    self._stats[error_counter] += 1
                self._failures.setdefault(node_id, []).append(timestamp)
                self._audit_write(
                    exc.code,
                    node=node_id,
                    node_id=node_id,
                    ak_name=ak_name,
                    status="rejected",
                    allowed=False,
                    at=display,
                    ts=timestamp,
                )
                raise

            self._stats["trusted_quotes"] += 1
            self._stats["verification_generation"] += 1
            # A successful attestation is a state change: snapshots taken
            # before it must not be restorable over the new counter.
            self._snapshot_generation += 1
            self._audit_write(
                "TQ_OK",
                node=node_id,
                node_id=node_id,
                ak_name=ak_name,
                status="trusted",
                allowed=True,
                at=display,
                ts=timestamp,
                counter=result["counter"],
                profile=result["profile"],
                pcr_digest=result["pcr_digest"],
            )
            return result

    def _verify_locked(
        self,
        node_id: str,
        ak_name: str,
        quote: dict,
        timestamp: float,
        display: str,
    ) -> dict:
        if not isinstance(node_id, str) or not node_id:
            raise TpmQuoteError(TQ_QUOTE_INVALID, "node id must be non-empty")
        if not isinstance(quote, dict):
            raise TpmQuoteError(TQ_QUOTE_INVALID, "quote must be a mapping")
        required_fields = ("nonce", "pcrs", "pcr_digest", "counter", "signature")
        if any(field not in quote for field in required_fields):
            raise TpmQuoteError(TQ_QUOTE_INVALID, "quote fields missing")

        nonce = quote["nonce"]
        if not isinstance(nonce, str) or not nonce:
            raise TpmQuoteError(TQ_QUOTE_INVALID, "nonce must be non-empty")
        counter = quote["counter"]
        if not _is_int(counter):
            raise TpmQuoteError(TQ_QUOTE_INVALID, "counter must be an integer")
        declared_digest = quote["pcr_digest"]
        if (
            not isinstance(declared_digest, str)
            or _HEX_64.fullmatch(declared_digest) is None
        ):
            raise TpmQuoteError(TQ_PCR_INVALID, repr(declared_digest))
        signature = quote["signature"]
        if not isinstance(signature, str) or not signature:
            raise TpmQuoteError(TQ_QUOTE_INVALID, "signature must be non-empty")
        pcrs = _normalise_pcrs(quote["pcrs"], TQ_QUOTE_INVALID)

        ak = self._aks.get(ak_name)
        if ak is None:
            raise TpmQuoteError(TQ_AK_UNKNOWN, ak_name)
        if ak.get("revoked"):
            raise TpmQuoteError(TQ_AK_REVOKED, ak_name)
        profile = self._profiles.get(ak["profile"])
        if profile is None:
            raise TpmQuoteError(TQ_PROFILE_UNKNOWN, ak["profile"])
        if ak["profile_version"] < profile["version"]:
            raise TpmQuoteError(
                TQ_ENROLLMENT_STALE,
                "{} < {}".format(ak["profile_version"], profile["version"]),
            )

        for index in profile["required_pcrs"]:
            if index not in pcrs:
                raise TpmQuoteError(TQ_PCR_MISSING, index)

        consumed = self._consumed.get(node_id)
        if consumed is not None and nonce in consumed:
            raise TpmQuoteError(TQ_NONCE_CONSUMED, nonce)
        pending = self._pending.get(node_id, {})
        entry = pending.get(nonce)
        if entry is None:
            raise TpmQuoteError(TQ_NONCE_UNKNOWN, nonce)
        if timestamp >= entry["_expires_ts"]:
            del pending[nonce]
            self._stats["nonces_expired"] += 1
            raise TpmQuoteError(TQ_NONCE_EXPIRED, nonce)

        expected_signature = quote_signature(
            ak["secret"], node_id, nonce, declared_digest, counter
        )
        if not hmac.compare_digest(
            expected_signature.lower(), signature.lower()
        ):
            # An unauthenticated request must not burn the node's nonce.
            raise TpmQuoteError(TQ_SIGNATURE_INVALID, ak_name)

        computed_digest = pcr_digest(pcrs)
        if computed_digest.lower() != declared_digest.lower():
            self._consume_nonce(node_id, nonce)
            raise TpmQuoteError(TQ_PCR_DIGEST_MISMATCH, node_id)

        for index in profile["required_pcrs"]:
            expected = profile["golden"][index]
            if pcrs[index].lower() != expected.lower():
                state = self._trust_record(node_id)
                state.update(
                    trusted=False,
                    status="untrusted",
                    reason="pcr_mismatch",
                    ak_name=ak_name,
                    profile=profile["name"],
                    profile_version=profile["version"],
                    pcr_digest=declared_digest,
                )
                raise TpmQuoteError(TQ_PCR_MISMATCH, index)

        last_counter = ak.get("last_counter")
        if last_counter is not None and counter <= last_counter:
            self._consume_nonce(node_id, nonce)
            raise TpmQuoteError(TQ_COUNTER_REPLAY, counter)
        if counter < profile["min_counter"]:
            self._consume_nonce(node_id, nonce)
            raise TpmQuoteError(TQ_COUNTER_STALE, counter)

        self._consume_nonce(node_id, nonce)
        ak["last_counter"] = counter
        state = self._trust_record(node_id)
        state.update(
            trusted=True,
            status="trusted",
            generation=state["generation"] + 1,
            counter=counter,
            last_counter=counter,
            profile=profile["name"],
            profile_version=profile["version"],
            pcr_digest=declared_digest,
            ak_name=ak_name,
            last_verified_at=display,
            reason=None,
        )
        return {
            "status": "trusted",
            "counter": counter,
            "profile": profile["name"],
            "pcr_digest": declared_digest,
        }

    # ---------------------------------------------------------- node status
    def trust_state(self, node_id: str) -> dict:
        with self._lock:
            record = self._trust_record(node_id)
            return copy.deepcopy(record)

    def sweep(self, now=None) -> dict:
        timestamp = _parse_time(now)
        removed = 0
        with self._lock:
            for node_id, pending in list(self._pending.items()):
                for nonce, entry in list(pending.items()):
                    if timestamp >= entry["_expires_ts"]:
                        del pending[nonce]
                        removed += 1
                if not pending:
                    self._pending.pop(node_id, None)
            self._stats["nonces_expired"] += removed
            if removed:
                self._audit_write(
                    "TQ_OK",
                    action="sweep",
                    nonces=removed,
                    at=_iso_utc(timestamp),
                )
        return {"nonces": removed}

    # ------------------------------------------------------------- snapshots
    def snapshot(self) -> dict:
        with self._lock:
            self._snapshot_generation += 1
            profiles = {}
            for name, record in self._profiles.items():
                profiles[name] = {
                    "name": record["name"],
                    "version": record["version"],
                    "required_pcrs": list(record["required_pcrs"]),
                    "golden": {
                        str(k): v for k, v in record["golden"].items()
                    },
                    "min_counter": record["min_counter"],
                }
            aks = {}
            for name, record in self._aks.items():
                aks[name] = {
                    "ak_name": record["ak_name"],
                    "secret": record["secret"],
                    "profile": record["profile"],
                    "profile_version": record["profile_version"],
                    "pcrs": {
                        str(k): v for k, v in record["pcrs"].items()
                    },
                    "pubkey_id": record.get("pubkey_id"),
                    "enrolled_at": record.get("enrolled_at"),
                    "revoked": bool(record.get("revoked")),
                    "revoked_at": record.get("revoked_at"),
                    "reason": record.get("reason"),
                    "last_counter": record.get("last_counter"),
                }
            pending = {}
            for node_id, entries in self._pending.items():
                pending[node_id] = {
                    nonce: {
                        "node": entry["node"],
                        "nonce": entry["nonce"],
                        "seq": entry["seq"],
                        "expires_at": entry["expires_at"],
                        "_expires_ts": entry["_expires_ts"],
                    }
                    for nonce, entry in entries.items()
                }
            return {
                "version": SNAPSHOT_VERSION,
                "generation": self._snapshot_generation,
                "config": {
                    "nonce_ttl_seconds": self.nonce_ttl_seconds,
                    "nonce_cap": self.nonce_cap,
                    "failure_budget": self.failure_budget,
                    "failure_window_seconds": self.failure_window_seconds,
                    "audit_capacity": self.audit_capacity,
                },
                "profiles": profiles,
                "aks": aks,
                "nonce_seq": dict(self._nonce_seq),
                "pending": pending,
                "consumed": {
                    node_id: sorted(nonces)
                    for node_id, nonces in self._consumed.items()
                },
                "trust": copy.deepcopy(self._trust),
                "failures": {
                    node_id: list(timestamps)
                    for node_id, timestamps in self._failures.items()
                },
                "audit": copy.deepcopy(self._audit),
                "stats": dict(self._stats),
            }

    def restore(self, snap: dict) -> None:
        if isinstance(snap, str):
            try:
                snap = json.loads(snap)
            except (TypeError, ValueError) as exc:
                raise TpmQuoteError(TQ_SNAPSHOT_INVALID, "invalid JSON") from exc

        try:
            if not isinstance(snap, dict):
                raise ValueError("snapshot must be a mapping")
            snapshot_version = snap.get("version")
            if isinstance(snapshot_version, bool) or snapshot_version not in (
                SNAPSHOT_VERSION,
                str(SNAPSHOT_VERSION),
            ):
                raise ValueError("unknown snapshot version")
            required_top = (
                "generation",
                "profiles",
                "aks",
                "nonce_seq",
                "consumed",
            )
            if any(key not in snap for key in required_top):
                raise ValueError("snapshot fields missing")
            generation = snap["generation"]
            if not _is_int(generation) or generation < 0:
                raise ValueError("invalid snapshot generation")
            json.dumps(snap)

            config = snap.get("config", {})
            if not isinstance(config, dict):
                raise ValueError("invalid config")
            nonce_ttl_seconds = config.get(
                "nonce_ttl_seconds", self.nonce_ttl_seconds
            )
            nonce_cap = config.get("nonce_cap", self.nonce_cap)
            failure_budget = config.get("failure_budget", self.failure_budget)
            failure_window_seconds = config.get(
                "failure_window_seconds", self.failure_window_seconds
            )
            audit_capacity = config.get("audit_capacity", self.audit_capacity)
            for value in (
                nonce_ttl_seconds,
                nonce_cap,
                failure_budget,
                failure_window_seconds,
                audit_capacity,
            ):
                if not _is_int(value):
                    raise ValueError("invalid config value")

            profiles = {}
            raw_profiles = snap["profiles"]
            if not isinstance(raw_profiles, dict):
                raise ValueError("invalid profiles")
            for name, raw in raw_profiles.items():
                if not isinstance(raw, dict):
                    raise ValueError("invalid profile")
                required = raw["required_pcrs"]
                golden_raw = raw["golden"]
                if not isinstance(golden_raw, dict):
                    raise ValueError("invalid golden")
                golden = {
                    int(index): digest
                    for index, digest in golden_raw.items()
                }
                required, golden, min_counter = _validate_profile_fields(
                    raw.get("name", name),
                    required,
                    golden,
                    raw.get("min_counter", 0),
                )
                version = raw["version"]
                if not _is_int(version) or version < 1:
                    raise ValueError("invalid profile version")
                profiles[name] = {
                    "name": raw.get("name", name),
                    "version": version,
                    "required_pcrs": tuple(required),
                    "golden": golden,
                    "min_counter": min_counter,
                }

            aks = {}
            raw_aks = snap["aks"]
            if not isinstance(raw_aks, dict):
                raise ValueError("invalid AKs")
            for name, raw in raw_aks.items():
                if not isinstance(raw, dict):
                    raise ValueError("invalid AK")
                if (
                    not isinstance(raw.get("secret"), str)
                    or _HEX_64.fullmatch(raw["secret"]) is None
                ):
                    raise ValueError("invalid AK secret")
                profile_name = raw["profile"]
                if profile_name not in profiles:
                    raise ValueError("unknown AK profile")
                profile_version = raw["profile_version"]
                if not _is_int(profile_version) or profile_version < 1:
                    raise ValueError("invalid AK profile version")
                raw_pcrs = raw.get("pcrs", {})
                if not isinstance(raw_pcrs, dict):
                    raise ValueError("invalid AK PCRs")
                pcrs = {
                    int(index): digest
                    for index, digest in raw_pcrs.items()
                }
                pcrs = _normalise_pcrs(pcrs, TQ_SNAPSHOT_INVALID)
                last_counter = raw.get("last_counter")
                if last_counter is not None and not _is_int(last_counter):
                    raise ValueError("invalid AK counter")
                aks[name] = {
                    "ak_name": raw.get("ak_name", name),
                    "secret": raw["secret"],
                    "profile": profile_name,
                    "profile_version": profile_version,
                    "pcrs": pcrs,
                    "pubkey_id": raw.get("pubkey_id"),
                    "enrolled_at": raw.get("enrolled_at"),
                    "revoked": bool(raw.get("revoked", False)),
                    "revoked_at": raw.get("revoked_at"),
                    "reason": raw.get("reason"),
                    "last_counter": last_counter,
                }

            raw_seq = snap["nonce_seq"]
            if not isinstance(raw_seq, dict):
                raise ValueError("invalid nonce sequence")
            nonce_seq = {}
            for node_id, sequence in raw_seq.items():
                if not _is_int(sequence) or sequence < 0:
                    raise ValueError("invalid nonce sequence value")
                nonce_seq[str(node_id)] = sequence

            pending = {}
            raw_pending = snap.get("pending", {})
            if not isinstance(raw_pending, dict):
                raise ValueError("invalid pending nonces")
            for node_id, entries in raw_pending.items():
                if not isinstance(entries, dict):
                    raise ValueError("invalid pending nonce map")
                restored = {}
                for nonce, raw in entries.items():
                    if not isinstance(raw, dict):
                        raise ValueError("invalid pending nonce")
                    seq = raw.get("seq")
                    if not _is_int(seq) or seq < 1:
                        raise ValueError("invalid pending nonce sequence")
                    expires_ts = raw.get("_expires_ts")
                    if expires_ts is None and raw.get("expires_at") is None:
                        raise ValueError("nonce expiry missing")
                    if expires_ts is None:
                        expires_ts = _parse_time(raw.get("expires_at"))
                    if not isinstance(expires_ts, (int, float)):
                        raise ValueError("invalid nonce expiry")
                    restored[str(nonce)] = {
                        "node": str(node_id),
                        "nonce": str(nonce),
                        "seq": seq,
                        "expires_at": _iso_utc(float(expires_ts)),
                        "_expires_ts": float(expires_ts),
                    }
                pending[str(node_id)] = restored

            raw_consumed = snap["consumed"]
            if not isinstance(raw_consumed, dict):
                raise ValueError("invalid consumed nonces")
            consumed = {}
            for node_id, nonces in raw_consumed.items():
                if not isinstance(nonces, (list, tuple, set, frozenset)):
                    raise ValueError("invalid consumed nonce list")
                if any(not isinstance(nonce, str) for nonce in nonces):
                    raise ValueError("invalid consumed nonce")
                consumed[str(node_id)] = set(nonces)

            raw_trust = snap.get("trust", {})
            if not isinstance(raw_trust, dict):
                raise ValueError("invalid trust state")
            trust = {}
            for node_id, raw in raw_trust.items():
                if not isinstance(raw, dict):
                    raise ValueError("invalid trust record")
                record = self._blank_trust(str(node_id))
                record["trusted"] = bool(raw.get("trusted", False))
                record["status"] = raw.get("status", "unknown")
                raw_generation = raw.get("generation", 0)
                if not _is_int(raw_generation) or raw_generation < 0:
                    raise ValueError("invalid trust generation")
                record["generation"] = raw_generation
                for key in (
                    "counter",
                    "last_counter",
                    "profile",
                    "profile_version",
                    "pcr_digest",
                    "ak_name",
                    "last_verified_at",
                    "reason",
                ):
                    record[key] = copy.deepcopy(raw.get(key))
                trust[str(node_id)] = record

            raw_failures = snap.get("failures", {})
            if not isinstance(raw_failures, dict):
                raise ValueError("invalid failures")
            failures = {}
            for node_id, timestamps in raw_failures.items():
                if not isinstance(timestamps, (list, tuple)):
                    raise ValueError("invalid failure list")
                values = []
                for value in timestamps:
                    if not isinstance(value, (int, float)):
                        raise ValueError("invalid failure timestamp")
                    values.append(float(value))
                failures[str(node_id)] = values

            raw_audit = snap.get("audit", [])
            if not isinstance(raw_audit, list):
                raise ValueError("invalid audit")
            audit = copy.deepcopy(raw_audit)
            if audit_capacity >= 0:
                audit = audit[:audit_capacity]

            stats = dict(self._stats)
            raw_stats = snap.get("stats", {})
            if not isinstance(raw_stats, dict):
                raise ValueError("invalid stats")
            for key, value in raw_stats.items():
                if _is_int(value) and value >= 0:
                    stats[key] = value
        except TpmQuoteError as exc:
            raise TpmQuoteError(TQ_SNAPSHOT_INVALID, str(exc)) from exc
        except (KeyError, TypeError, ValueError) as exc:
            raise TpmQuoteError(TQ_SNAPSHOT_INVALID, str(exc)) from exc

        with self._lock:
            if generation < self._snapshot_generation:
                raise TpmQuoteError(TQ_SNAPSHOT_STALE, generation)

            # Restore the historical snapshot, but never lower replay
            # watermarks established since that snapshot was taken.
            for node_id, sequence in self._nonce_seq.items():
                nonce_seq[node_id] = max(
                    nonce_seq.get(node_id, 0), sequence
                )
            for node_id, nonces in self._consumed.items():
                merged = consumed.setdefault(node_id, set())
                merged.update(nonces)
            for node_id, entries in pending.items():
                used = consumed.get(node_id, set())
                for nonce in list(entries):
                    if nonce in used:
                        del entries[nonce]
            for ak_name, current in self._aks.items():
                restored = aks.get(ak_name)
                if restored is None:
                    continue
                current_counter = current.get("last_counter")
                restored_counter = restored.get("last_counter")
                if current_counter is not None and (
                    restored_counter is None
                    or current_counter > restored_counter
                ):
                    restored["last_counter"] = current_counter
                if current.get("revoked"):
                    restored["revoked"] = True
                    restored["revoked_at"] = current.get("revoked_at")
                    restored["reason"] = current.get("reason")
            for node_id, current in self._trust.items():
                if current.get("reason") != "ak_revoked":
                    continue
                restored = trust.get(node_id)
                if restored is not None:
                    restored["trusted"] = False
                    restored["status"] = "untrusted"
                    restored["reason"] = "ak_revoked"
            for key, value in self._stats.items():
                if _is_int(value):
                    stats[key] = max(stats.get(key, 0), value)

            self.nonce_ttl_seconds = nonce_ttl_seconds
            self.nonce_cap = nonce_cap
            self.failure_budget = failure_budget
            self.failure_window_seconds = failure_window_seconds
            self.audit_capacity = audit_capacity
            self._profiles = profiles
            self._aks = aks
            self._nonce_seq = nonce_seq
            self._pending = pending
            self._consumed = consumed
            self._trust = trust
            self._failures = failures
            self._audit = audit
            self._stats = stats
            self._snapshot_generation = generation

    @staticmethod
    def _blank_trust(node_id: str) -> dict:
        return {
            "node": node_id,
            "node_id": node_id,
            "trusted": False,
            "status": "unknown",
            "generation": 0,
            "counter": None,
            "last_counter": None,
            "profile": None,
            "profile_version": None,
            "pcr_digest": None,
            "ak_name": None,
            "last_verified_at": None,
            "reason": None,
        }

    # ----------------------------------------------------------- observability
    def audit(self, limit: int = 20) -> list:
        with self._lock:
            if limit is None:
                return copy.deepcopy(self._audit)
            if not _is_int(limit):
                return []
            if limit <= 0:
                return []
            return copy.deepcopy(self._audit[:limit])

    def stats(self) -> dict:
        with self._lock:
            pending_count = sum(
                len(entries) for entries in self._pending.values()
            )
            consumed_count = sum(
                len(entries) for entries in self._consumed.values()
            )
            trusted_nodes = sum(
                1 for state in self._trust.values() if state.get("trusted")
            )
            return {
                "profiles": len(self._profiles),
                "profile_count": len(self._profiles),
                "aks": len(self._aks),
                "ak_count": len(self._aks),
                "nodes": len(self._trust),
                "node_count": len(self._trust),
                "trusted": trusted_nodes,
                "trusted_nodes": trusted_nodes,
                "untrusted": len(self._trust) - trusted_nodes,
                "untrusted_nodes": len(self._trust) - trusted_nodes,
                "nonces": pending_count,
                "nonce_count": pending_count,
                "nonces_pending": pending_count,
                "pending_nonces": pending_count,
                "nonces_consumed": consumed_count,
                "consumed_nonces": consumed_count,
                "nonces_used": consumed_count,
                "used_nonces": consumed_count,
                "nonces_issued": self._stats["nonces_issued"],
                "nonces_expired": self._stats["nonces_expired"],
                "verifications": self._stats["verifications"],
                "quote_checks": self._stats["verifications"],
                "trusted_quotes": self._stats["trusted_quotes"],
                "verified": self._stats["trusted_quotes"],
                "allowed": self._stats["trusted_quotes"],
                "rejected": self._stats["rejected"],
                "failures": self._stats["rejected"],
                "denied": self._stats["rejected"],
                "rate_limited": self._stats["rate_limited"],
                "signature_invalid": self._stats["signature_invalid"],
                "digest_mismatch": self._stats["digest_mismatch"],
                "pcr_mismatch": self._stats["pcr_mismatch"],
                "counter_replays": self._stats["counter_replays"],
                "counter_stale": self._stats["counter_stale"],
                "nonce_expired": self._stats["nonce_expired"],
                "aks_enrolled": self._stats["aks_enrolled"],
                "aks_revoked": self._stats["aks_revoked"],
                "profiles_created": self._stats["profiles_created"],
                "profiles_rotated": self._stats["profiles_rotated"],
                "generation": self._stats["verification_generation"],
                "verification_generation": self._stats[
                    "verification_generation"
                ],
                "audit_entries": len(self._audit),
                "audit": len(self._audit),
            }


# Optional module-level facade for callers that do not need multiple guards.
_default_guard = None
_default_lock = threading.RLock()


def _guard() -> TpmQuoteGuard:
    global _default_guard
    with _default_lock:
        if _default_guard is None:
            _default_guard = TpmQuoteGuard()
        return _default_guard


def define_profile(name, *, required_pcrs, golden, min_counter=0):
    return _guard().define_profile(
        name,
        required_pcrs=required_pcrs,
        golden=golden,
        min_counter=min_counter,
    )


def rotate_profile(
    name, *, required_pcrs=None, golden=None, min_counter=None
):
    return _guard().rotate_profile(
        name,
        required_pcrs=required_pcrs,
        golden=golden,
        min_counter=min_counter,
    )


def enroll_ak(
    ak_name, *, secret, profile, pcrs, pubkey_id=None, now=None
):
    return _guard().enroll_ak(
        ak_name,
        secret=secret,
        profile=profile,
        pcrs=pcrs,
        pubkey_id=pubkey_id,
        now=now,
    )


def revoke_ak(ak_name, *, reason="manual"):
    return _guard().revoke_ak(ak_name, reason=reason)


def issue_nonce(node_id, *, ttl_seconds=None, now=None):
    return _guard().issue_nonce(
        node_id, ttl_seconds=ttl_seconds, now=now
    )


def verify_quote(node_id, *, ak_name, quote, now=None):
    return _guard().verify_quote(
        node_id, ak_name=ak_name, quote=quote, now=now
    )


def trust_state(node_id):
    return _guard().trust_state(node_id)


def sweep(now=None):
    return _guard().sweep(now)


def snapshot():
    return _guard().snapshot()


def restore(snap):
    return _guard().restore(snap)


def audit(limit=20):
    return _guard().audit(limit)


def stats():
    return _guard().stats()
