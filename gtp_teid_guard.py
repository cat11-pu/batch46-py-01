"""GTP-U TEID ownership, peer, and echo sequence guard.

All mutable state is protected by one reentrant lock so a TEID can never be
opened, closed, classified, checkpointed, or restored half-way through another
operation.
"""

from __future__ import annotations

import copy
import ipaddress
import threading


_TEID_MAX = 0xFFFFFFFF
_SEQ_MAX = 0xFFFF
_STATE_VERSION = 1


class GtpError(Exception):
    """A validation or protocol error identified by a stable error code."""

    def __init__(self, code, detail=None):
        self.code = code
        self.detail = detail
        super().__init__(code if detail is None else f"{code}: {detail}")


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _message_value(message, *names, default=None):
    for name in names:
        if name in message:
            return message[name]
    return default


class GtpGuard:
    """Owns local TEIDs and enforces peer, tenant, extension, and echo rules."""

    def __init__(
        self,
        *,
        max_tunnels: int = 1024,
        max_ext_headers: int = 4,
        idle_ttl: float = 300.0,
        seq_window: int = 64,
    ) -> None:
        self.max_tunnels = max_tunnels
        self.max_ext_headers = max_ext_headers
        self.idle_ttl = idle_ttl
        self.seq_window = seq_window
        self._lock = threading.RLock()
        self._tunnels = {}
        self._echo = {}
        self._counters = {
            "accepted": 0,
            "rejected": 0,
            "closed": 0,
            "echo_requests": 0,
            "echo_responses": 0,
            "g_pdu": 0,
            "codes": {},
        }

    def _fail(self, code, detail=None, *, rejected=False):
        self._counters["codes"][code] = (
            self._counters["codes"].get(code, 0) + 1
        )
        if rejected:
            self._counters["rejected"] += 1
        raise GtpError(code, detail)

    def _check_teid(self, value):
        if not _is_int(value):
            self._fail("GTP_BAD_TEID")
        if value == 0:
            self._fail("GTP_TEID_RESERVED")
        if value < 0 or value > _TEID_MAX:
            self._fail("GTP_BAD_TEID")
        return value

    def _check_peer(self, peer_ip, *, rejected=False):
        if not isinstance(peer_ip, str) or not peer_ip:
            self._fail("GTP_BAD_PEER", rejected=rejected)
        try:
            return str(ipaddress.ip_address(peer_ip))
        except ValueError:
            self._fail("GTP_BAD_PEER", rejected=rejected)

    def _check_tenant(self, tenant):
        if not isinstance(tenant, str) or not tenant.strip():
            self._fail("GTP_BAD_TENANT")
        return tenant

    def _check_slice(self, slice_id):
        if not _is_int(slice_id) or not 0 <= slice_id <= 255:
            self._fail("GTP_BAD_SLICE")
        return slice_id

    def _check_seq(self, seq, *, rejected=False):
        if not _is_int(seq) or not 0 <= seq <= _SEQ_MAX:
            self._fail("GTP_BAD_SEQ", rejected=rejected)
        return seq

    @staticmethod
    def _flag(message, primary, aliases, bit, default=False):
        for name in (primary, *aliases):
            if name in message:
                return bool(message[name])
        flags = message.get("flags")
        if _is_int(flags):
            return bool(flags & bit)
        return default

    def _s_flag(self, message):
        return self._flag(
            message, "s", ("s_flag", "has_s", "has_seq", "seq_present"), 0x02
        )

    def _e_flag(self, message):
        return self._flag(
            message, "e", ("e_flag", "has_e", "has_ext", "ext_present"), 0x04
        )

    @staticmethod
    def _copy(value):
        return copy.deepcopy(value)

    def open_tunnel(
        self,
        tenant: str,
        *,
        local_teid: int,
        peer_teid: int,
        peer_ip: str,
        slice_id: int = 0,
        now: float = 0.0,
    ) -> dict:
        with self._lock:
            self._check_tenant(tenant)
            local_teid = self._check_teid(local_teid)
            peer_teid = self._check_teid(peer_teid)
            peer_ip = self._check_peer(peer_ip)
            slice_id = self._check_slice(slice_id)

            existing = self._tunnels.get(local_teid)
            if existing is not None:
                same = (
                    existing["tenant"] == tenant
                    and existing["peer_teid"] == peer_teid
                    and existing["peer_ip"] == peer_ip
                    and existing["slice_id"] == slice_id
                )
                if not same:
                    self._fail("GTP_TEID_CONFLICT")
                result = self._copy(existing)
                result["created"] = False
                return result

            if len(self._tunnels) >= self.max_tunnels:
                self._fail("GTP_TUNNEL_LIMIT")

            record = {
                "tenant": tenant,
                "local_teid": local_teid,
                "peer_teid": peer_teid,
                "peer_ip": peer_ip,
                "slice_id": slice_id,
                "created": True,
                "created_at": now,
                "last_seen": now,
            }
            self._tunnels[local_teid] = record
            return self._copy(record)

    def close_tunnel(self, local_teid: int, *, now: float = 0.0) -> dict | None:
        with self._lock:
            record = self._tunnels.pop(local_teid, None)
            if record is None:
                return None
            self._counters["closed"] += 1
            return self._copy(record)

    def tunnel(self, local_teid: int) -> dict | None:
        with self._lock:
            record = self._tunnels.get(local_teid)
            return None if record is None else self._copy(record)

    def tunnels_for(self, tenant: str) -> list[dict]:
        with self._lock:
            records = [
                self._copy(record)
                for record in self._tunnels.values()
                if record["tenant"] == tenant
            ]
            records.sort(key=lambda record: record["local_teid"])
            return records

    def classify(
        self,
        message: dict,
        *,
        peer_ip: str,
        tenant: str | None = None,
        now: float = 0.0,
    ) -> dict:
        with self._lock:
            if not isinstance(message, dict):
                self._fail("GTP_BAD_TYPE", rejected=True)

            version = message.get("version", 1)
            if not _is_int(version) or version != 1:
                self._fail("GTP_BAD_VERSION", rejected=True)

            pt = message.get("pt", 1)
            if not _is_int(pt) or pt != 1:
                self._fail("GTP_BAD_PT", rejected=True)

            msg_type = _message_value(
                message, "msg_type", "message_type", default=None
            )
            if not _is_int(msg_type) or msg_type not in (1, 2, 255):
                self._fail("GTP_BAD_TYPE", rejected=True)

            local_teid = _message_value(
                message, "teid", "local_teid", default=None
            )
            record = self._tunnels.get(local_teid)
            if record is None:
                self._fail("GTP_UNKNOWN_TEID", rejected=True)

            if tenant is not None and record["tenant"] != tenant:
                self._fail("GTP_TENANT_MISMATCH", rejected=True)

            peer_ip = self._check_peer(peer_ip, rejected=True)
            if record["peer_ip"] != peer_ip:
                self._fail("GTP_PEER_MISMATCH", rejected=True)

            payload_bytes = _message_value(
                message,
                "payload_bytes",
                "payload_length",
                "length",
                default=0,
            )
            if (
                not _is_int(payload_bytes)
                or payload_bytes < 0
                or payload_bytes > 0xFFFF
                or (msg_type == 255 and payload_bytes == 0)
            ):
                self._fail("GTP_BAD_LENGTH", rejected=True)

            raw_extensions = _message_value(
                message,
                "extensions",
                "ext_headers",
                "extension_headers",
                default=None,
            )
            if raw_extensions is None:
                raw_extensions = []
            if isinstance(raw_extensions, tuple):
                raw_extensions = list(raw_extensions)
            if not isinstance(raw_extensions, list):
                self._fail("GTP_EXT_TYPE", rejected=True)

            e_flag = self._e_flag(message)
            if e_flag:
                if not raw_extensions:
                    self._fail("GTP_EXT_EMPTY", rejected=True)
                if len(raw_extensions) > self.max_ext_headers:
                    self._fail("GTP_EXT_LIMIT", rejected=True)
                seen_types = set()
                for extension in raw_extensions:
                    if isinstance(extension, dict):
                        ext_type = extension.get("type")
                    else:
                        ext_type = extension
                    if (
                        not _is_int(ext_type)
                        or ext_type < 1
                        or ext_type > 255
                    ):
                        self._fail("GTP_EXT_TYPE", rejected=True)
                    if ext_type in seen_types:
                        self._fail("GTP_EXT_LOOP", rejected=True)
                    seen_types.add(ext_type)
            elif raw_extensions:
                self._fail("GTP_EXT_UNEXPECTED", rejected=True)

            if self._s_flag(message):
                seq = _message_value(message, "seq", "sequence", default=None)
                seq = self._check_seq(seq, rejected=True)
            else:
                seq = None

            record["last_seen"] = max(record["last_seen"], now)
            self._counters["accepted"] += 1
            if msg_type == 255:
                self._counters["g_pdu"] += 1

            result = {
                "status": "accepted",
                "code": None,
                "tenant": record["tenant"],
                "local_teid": record["local_teid"],
                "peer_teid": record["peer_teid"],
                "msg_type": msg_type,
                "payload_bytes": payload_bytes,
                "slice_id": record["slice_id"],
                "last_seen": record["last_seen"],
                "extensions": self._copy(raw_extensions),
            }
            if seq is not None:
                result["seq"] = seq
            if msg_type == 255:
                result["g_pdu"] = self._counters["g_pdu"]
            return result

    def echo(
        self, message: dict, *, peer_ip: str, now: float = 0.0
    ) -> dict:
        with self._lock:
            if not isinstance(message, dict):
                self._fail("GTP_BAD_TYPE")

            peer_ip = self._check_peer(peer_ip)
            known_peer = any(
                record["peer_ip"] == peer_ip
                for record in self._tunnels.values()
            )
            if not known_peer:
                self._fail("GTP_UNKNOWN_PEER")

            msg_type = _message_value(
                message, "msg_type", "message_type", default=None
            )
            if msg_type not in (1, 2) or not _is_int(msg_type):
                self._fail("GTP_BAD_TYPE")

            if not self._s_flag(message):
                self._fail("GTP_BAD_SEQ")
            seq = _message_value(message, "seq", "sequence", default=None)
            seq = self._check_seq(seq)

            if msg_type == 1:
                self._counters["echo_requests"] += 1
                return {
                    "status": "accepted",
                    "code": None,
                    "response": True,
                    "peer_ip": peer_ip,
                    "seq": seq,
                    "msg_type": msg_type,
                }

            entry = self._echo.get(peer_ip)
            if entry is None:
                entry = {"highest": None, "seen": set()}
                self._echo[peer_ip] = entry

            highest = entry["highest"]
            if highest is not None:
                floor = highest - self.seq_window
                if seq < floor:
                    self._fail("GTP_STALE_SEQ")
                if seq in entry["seen"]:
                    self._fail("GTP_DUP_SEQ")

            entry["seen"].add(seq)
            if highest is None or seq > highest:
                entry["highest"] = seq
            highest = entry["highest"]
            floor = highest - self.seq_window
            entry["seen"] = {
                value for value in entry["seen"] if value >= floor
            }

            self._counters["echo_responses"] += 1
            return {
                "status": "accepted",
                "code": None,
                "response": False,
                "peer_ip": peer_ip,
                "seq": seq,
                "msg_type": msg_type,
                "highest": highest,
            }

    def expire_idle(self, *, now: float) -> list[int]:
        with self._lock:
            expired = sorted(
                teid
                for teid, record in self._tunnels.items()
                if now - record["last_seen"] > self.idle_ttl
            )
            for teid in expired:
                self._tunnels.pop(teid, None)
            return expired

    def stats(self) -> dict:
        with self._lock:
            return {
                "tunnels": len(self._tunnels),
                "tenants": len(
                    {record["tenant"] for record in self._tunnels.values()}
                ),
                "accepted": self._counters["accepted"],
                "rejected": self._counters["rejected"],
                "closed": self._counters["closed"],
                "echo_requests": self._counters["echo_requests"],
                "echo_responses": self._counters["echo_responses"],
                "g_pdu": self._counters["g_pdu"],
                "codes": self._copy(self._counters["codes"]),
            }

    def snapshot(self) -> dict:
        with self._lock:
            tunnels = [
                self._copy(record)
                for _, record in sorted(self._tunnels.items())
            ]
            echo = {
                peer_ip: {
                    "highest": entry["highest"],
                    "seen": sorted(entry["seen"]),
                }
                for peer_ip, entry in self._echo.items()
            }
            return {
                "version": _STATE_VERSION,
                "tunnels": tunnels,
                "echo": echo,
                "counters": self._copy(self._counters),
            }

    def restore(self, state: dict) -> None:
        with self._lock:
            if (
                not isinstance(state, dict)
                or not _is_int(state.get("version"))
                or state.get("version") != 1
            ):
                self._fail("GTP_STATE_VERSION")

            restored = self._copy(state)
            tunnels = {}
            for record in restored.get("tunnels", []):
                tunnels[record["local_teid"]] = record

            echo = {}
            for peer_ip, entry in restored.get("echo", {}).items():
                seen = set(entry.get("seen", []))
                highest = entry.get("highest")
                if highest is not None:
                    seen.add(highest)
                    floor = highest - self.seq_window
                    seen = {value for value in seen if value >= floor}
                echo[peer_ip] = {"highest": highest, "seen": seen}

            counters = {
                "accepted": 0,
                "rejected": 0,
                "closed": 0,
                "echo_requests": 0,
                "echo_responses": 0,
                "g_pdu": 0,
                "codes": {},
            }
            saved_counters = restored.get("counters", {})
            if not isinstance(saved_counters, dict):
                saved_counters = {}
            for key in counters:
                if key == "codes":
                    saved_codes = saved_counters.get("codes", {})
                    counters["codes"] = (
                        dict(saved_codes) if isinstance(saved_codes, dict) else {}
                    )
                else:
                    counters[key] = saved_counters.get(key, 0)

            self._tunnels = tunnels
            self._echo = echo
            self._counters = counters
