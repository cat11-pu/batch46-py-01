"""PROXY protocol parsing with peer trust, TTL state and a bounded LRU.

The guard deliberately rejects before parsing whenever the transport peer is
not trusted.  All public methods use one re-entrant lock so a parse decision,
its counters and its audit record are committed as one transaction.
"""

from __future__ import annotations

import copy
import ipaddress
import threading
from collections import OrderedDict, deque
from collections.abc import Iterable, Mapping


PPX_UNTRUSTED_PEER = "PPX_UNTRUSTED_PEER"
PPX_BAD_PEER = "PPX_BAD_PEER"
PPX_BAD_PROTOCOL = "PPX_BAD_PROTOCOL"
PPX_BAD_ADDRESS = "PPX_BAD_ADDRESS"
PPX_TOO_LARGE = "PPX_TOO_LARGE"
PPX_TRUNCATED = "PPX_TRUNCATED"
PPX_TRAILING_DATA = "PPX_TRAILING_DATA"
PPX_BAD_SIGNATURE = "PPX_BAD_SIGNATURE"
PPX_BAD_VERSION = "PPX_BAD_VERSION"
PPX_BAD_COMMAND = "PPX_BAD_COMMAND"
PPX_BAD_FAMILY = "PPX_BAD_FAMILY"
PPX_LENGTH_MISMATCH = "PPX_LENGTH_MISMATCH"
PPX_TLV_TYPE = "PPX_TLV_TYPE"
PPX_TLV_LEN = "PPX_TLV_LEN"
PPX_TLV_DUP = "PPX_TLV_DUP"
PPX_TLV_TOO_LARGE = "PPX_TLV_TOO_LARGE"
PPX_TLV_TRUNCATED = "PPX_TLV_TRUNCATED"
PPX_TLV_ENCODING = "PPX_TLV_ENCODING"
PPX_DUPLICATE = "PPX_DUPLICATE"
PPX_STATE_VERSION = "PPX_STATE_VERSION"


_V2_SIGNATURE = b"\r\n\r\n\x00\r\nQUIT\n"
_V2_HEADER_BYTES = 16
_RECENT_LIMIT = 100
_STATE_VERSION = 1
SNAPSHOT_VERSION = _STATE_VERSION

# type: (result key, maximum value length, utf-8 decoded?)
_TLV_TYPES = {
    0x01: ("alpn", 32, True),
    0x02: ("authority", 128, True),
    0x03: ("unique_id", 64, True),
    0x04: ("ssl", 64, False),
}


class ProxyProtocolError(ValueError):
    """Validation failure carrying a stable machine-readable ``code``."""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class ProxyProtocolGuard:
    """Validate PROXY protocol headers and retain per-connection decisions."""

    SNAPSHOT_VERSION = _STATE_VERSION

    def __init__(
        self,
        *,
        trusted_peers: Iterable[str] = (),
        max_header_bytes: int = 536,
        max_tlv_bytes: int = 256,
        max_connections: int = 1024,
        source_ttl: float = 5.0,
    ) -> None:
        self.max_header_bytes = self._limit(max_header_bytes, "max_header_bytes")
        self.max_tlv_bytes = self._limit(max_tlv_bytes, "max_tlv_bytes")
        self.max_connections = self._limit(max_connections, "max_connections")
        try:
            self.source_ttl = float(source_ttl)
        except (TypeError, ValueError, OverflowError) as exc:
            raise ProxyProtocolError(
                PPX_BAD_ADDRESS, "source_ttl must be numeric"
            ) from exc

        if isinstance(trusted_peers, (str, bytes)):
            initial_peers = [trusted_peers]
        else:
            try:
                initial_peers = list(trusted_peers)
            except TypeError as exc:
                raise ProxyProtocolError(
                    PPX_BAD_PEER, "trusted_peers must be iterable"
                ) from exc

        self._trusted = OrderedDict()
        for peer in initial_peers:
            network = self._network(peer)
            self._trusted[str(network)] = network

        self._connections = OrderedDict()
        self._sources = {}
        self._accepted = 0
        self._rejected = 0
        self._codes = {}
        self._recent = deque(maxlen=_RECENT_LIMIT)
        self._evicted = 0
        self._lock = threading.RLock()

    @staticmethod
    def _limit(value, name):
        if isinstance(value, bool) or not isinstance(value, int):
            raise ProxyProtocolError(PPX_TOO_LARGE, f"{name} must be an integer")
        if value < 0:
            raise ProxyProtocolError(
                PPX_TOO_LARGE, f"{name} must be non-negative"
            )
        return value

    @staticmethod
    def _network(peer):
        if not isinstance(peer, str):
            raise ProxyProtocolError(PPX_BAD_PEER, "peer must be a string")
        text = peer.strip()
        if not text:
            raise ProxyProtocolError(PPX_BAD_PEER, "peer is empty")
        try:
            return ipaddress.ip_network(text, strict=False)
        except (TypeError, ValueError) as exc:
            raise ProxyProtocolError(
                PPX_BAD_PEER, "peer is not an IP address or CIDR"
            ) from exc

    @staticmethod
    def _address(value):
        if not isinstance(value, str):
            raise ValueError("address must be a string")
        text = value.strip()
        if not text:
            raise ValueError("address is empty")
        return ipaddress.ip_address(text)

    @classmethod
    def _canonical_address(cls, value):
        try:
            return str(cls._address(value))
        except (TypeError, ValueError) as exc:
            raise ProxyProtocolError(
                PPX_BAD_ADDRESS, "source is not a valid IP address"
            ) from exc

    def _peer_is_trusted(self, peer):
        try:
            address = self._address(peer)
        except (TypeError, ValueError):
            return False
        return any(address in network for network in self._trusted.values())

    def allow_peer(self, peer: str) -> None:
        network = self._network(peer)
        with self._lock:
            self._trusted[str(network)] = network

    def revoke_peer(self, peer: str) -> None:
        network = self._network(peer)
        with self._lock:
            self._trusted.pop(str(network), None)

    def is_trusted(self, peer: str) -> bool:
        with self._lock:
            return self._peer_is_trusted(peer)

    @staticmethod
    def _raw_bytes(raw):
        if isinstance(raw, (bytes, bytearray, memoryview)):
            return bytes(raw)
        raise ProxyProtocolError(PPX_TRUNCATED, "raw header must be bytes")

    @staticmethod
    def _looks_like_v2(raw):
        if raw.startswith(_V2_SIGNATURE):
            return True
        # A damaged signature should still be classified as a v2 framing
        # error.  Keep the heuristic narrow so ordinary v1/HTTP input is not
        # mistaken for v2.
        if raw.startswith(b"\r\n\r\n"):
            return True
        if len(raw) < len(_V2_SIGNATURE) and _V2_SIGNATURE.startswith(raw):
            return True
        if (
            len(raw) >= _V2_HEADER_BYTES
            and not raw.startswith(b"PROXY")
            and (raw[12] >> 4) == 2
            and (raw[12] & 0x0F) <= 1
            and raw[13] in (0x00, 0x11, 0x21)
        ):
            return True
        return False

    def parse(
        self,
        raw: bytes,
        *,
        peer: str,
        connection: str | None = None,
        now: float = 0.0,
    ) -> dict:
        with self._lock:
            # Trust is checked before the header is even inspected.
            if not self._peer_is_trusted(peer):
                self._reject(PPX_UNTRUSTED_PEER, peer)
                raise ProxyProtocolError(
                    PPX_UNTRUSTED_PEER, "transport peer is not trusted"
                )

            # A connection may carry at most one accepted header.  Do not
            # touch its LRU position for a duplicate or rejected replay.
            if connection is not None and connection in self._connections:
                self._reject(PPX_DUPLICATE, peer)
                raise ProxyProtocolError(
                    PPX_DUPLICATE, "connection already has a PROXY header"
                )

            try:
                result = self._parse_raw(raw)
            except ProxyProtocolError as exc:
                self._reject(exc.code, peer)
                raise
            except Exception as exc:  # keep the public error surface stable
                error = ProxyProtocolError(PPX_TRUNCATED, "cannot parse header")
                self._reject(error.code, peer)
                raise error from exc

            self._accepted += 1
            self._recent.append(
                {"status": "accepted", "code": None, "peer": peer}
            )
            if connection is not None:
                self._connections[connection] = copy.deepcopy(result)
                self._connections.move_to_end(connection)
                while len(self._connections) > self.max_connections:
                    self._connections.popitem(last=False)
                    self._evicted += 1
            return copy.deepcopy(result)

    def _parse_raw(self, raw):
        raw = self._raw_bytes(raw)
        if len(raw) > self.max_header_bytes:
            raise ProxyProtocolError(
                PPX_TOO_LARGE, "header exceeds max_header_bytes"
            )

        if self._looks_like_v2(raw):
            return self._parse_v2(raw)
        if raw.startswith(b"PROXY"):
            return self._parse_v1(raw)
        raise ProxyProtocolError(
            PPX_BAD_PROTOCOL, "missing PROXY protocol signature"
        )

    def _parse_v1(self, raw):
        end = raw.find(b"\r\n")
        if end < 0:
            raise ProxyProtocolError(PPX_TRUNCATED, "missing CRLF")
        if end + 2 != len(raw):
            raise ProxyProtocolError(
                PPX_TRAILING_DATA, "bytes follow the v1 header"
            )

        fields = raw[:end].split()
        if not fields or fields[0] != b"PROXY":
            raise ProxyProtocolError(PPX_BAD_PROTOCOL, "missing PROXY token")
        if len(fields) < 2:
            raise ProxyProtocolError(PPX_BAD_PROTOCOL, "missing protocol token")

        protocol = fields[1]
        if protocol == b"UNKNOWN":
            return self._result(1, "UNKNOWN", None, None, {}, len(raw))
        if protocol not in (b"TCP4", b"TCP6"):
            raise ProxyProtocolError(
                PPX_BAD_PROTOCOL, "unsupported v1 protocol token"
            )
        if len(fields) != 6:
            raise ProxyProtocolError(
                PPX_BAD_ADDRESS, "v1 address fields are incomplete"
            )

        source_ip = self._parse_v1_ip(fields[2], protocol)
        destination_ip = self._parse_v1_ip(fields[3], protocol)
        source_port = self._parse_port(fields[4])
        destination_port = self._parse_port(fields[5])
        return self._result(
            1,
            "PROXY",
            (source_ip, source_port),
            (destination_ip, destination_port),
            {},
            len(raw),
        )

    @staticmethod
    def _parse_v1_ip(token, protocol):
        try:
            address = ipaddress.ip_address(token.decode("ascii"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise ProxyProtocolError(
                PPX_BAD_ADDRESS, "invalid v1 IP address"
            ) from exc
        expected = 4 if protocol == b"TCP4" else 6
        if address.version != expected:
            raise ProxyProtocolError(
                PPX_BAD_ADDRESS, "IP version does not match protocol"
            )
        return str(address)

    @staticmethod
    def _parse_port(token):
        try:
            text = token.decode("ascii")
        except UnicodeDecodeError as exc:
            raise ProxyProtocolError(PPX_BAD_ADDRESS, "invalid port") from exc
        if not text or not text.isdigit():
            raise ProxyProtocolError(PPX_BAD_ADDRESS, "port is not numeric")
        port = int(text)
        if not 1 <= port <= 65535:
            raise ProxyProtocolError(PPX_BAD_ADDRESS, "port is out of range")
        return port

    def _parse_v2(self, raw):
        if len(raw) < len(_V2_SIGNATURE) or raw[:12] != _V2_SIGNATURE:
            raise ProxyProtocolError(
                PPX_BAD_SIGNATURE, "invalid v2 signature"
            )
        if len(raw) < _V2_HEADER_BYTES:
            raise ProxyProtocolError(PPX_TRUNCATED, "incomplete v2 header")

        version_command = raw[12]
        version = version_command >> 4
        if version != 2:
            raise ProxyProtocolError(PPX_BAD_VERSION, "unsupported v2 version")

        command_nibble = version_command & 0x0F
        if command_nibble == 0:
            command = "LOCAL"
        elif command_nibble == 1:
            command = "PROXY"
        else:
            raise ProxyProtocolError(PPX_BAD_COMMAND, "unsupported command")

        family_protocol = raw[13]
        if family_protocol not in (0x00, 0x11, 0x21):
            raise ProxyProtocolError(PPX_BAD_FAMILY, "unsupported family")

        declared = int.from_bytes(raw[14:16], "big")
        body = raw[16:]
        if len(body) != declared:
            raise ProxyProtocolError(
                PPX_LENGTH_MISMATCH, "declared body length does not match input"
            )

        source, destination, tlvs = self._parse_v2_body(
            command, family_protocol, body
        )
        return self._result(
            2, command, source, destination, tlvs, len(raw)
        )

    def _parse_v2_body(self, command, family_protocol, body):
        if family_protocol == 0x11:
            address_length = 12
        elif family_protocol == 0x21:
            address_length = 36
        else:
            address_length = 0

        source = None
        destination = None

        if command == "LOCAL":
            # LOCAL never exposes addresses.  If a complete address block is
            # nevertheless present, skip it before reading TLVs.
            if address_length and len(body) < address_length:
                address_length = 0
            address_length = min(address_length, len(body))
        else:
            if address_length and len(body) < address_length:
                raise ProxyProtocolError(
                    PPX_BAD_ADDRESS, "incomplete v2 address block"
                )
            if family_protocol == 0x11:
                source = (
                    str(ipaddress.IPv4Address(body[0:4])),
                    self._parse_binary_port(body[8:10]),
                )
                destination = (
                    str(ipaddress.IPv4Address(body[4:8])),
                    self._parse_binary_port(body[10:12]),
                )
            elif family_protocol == 0x21:
                source = (
                    str(ipaddress.IPv6Address(body[0:16])),
                    self._parse_binary_port(body[32:34]),
                )
                destination = (
                    str(ipaddress.IPv6Address(body[16:32])),
                    self._parse_binary_port(body[34:36]),
                )

        tlv_region = body[address_length:]
        if len(tlv_region) > self.max_tlv_bytes:
            raise ProxyProtocolError(
                PPX_TLV_TOO_LARGE, "TLV region exceeds max_tlv_bytes"
            )
        return source, destination, self._parse_tlvs(tlv_region)

    @staticmethod
    def _parse_binary_port(raw):
        port = int.from_bytes(raw, "big")
        if not 1 <= port <= 65535:
            raise ProxyProtocolError(
                PPX_BAD_ADDRESS, "v2 port is out of range"
            )
        return port

    @staticmethod
    def _parse_tlvs(region):
        tlvs = {}
        offset = 0
        seen = set()
        while offset < len(region):
            if len(region) - offset < 3:
                raise ProxyProtocolError(
                    PPX_TLV_TRUNCATED, "incomplete TLV header"
                )
            tlv_type = region[offset]
            value_length = int.from_bytes(region[offset + 1:offset + 3], "big")
            offset += 3

            registration = _TLV_TYPES.get(tlv_type)
            if registration is None:
                raise ProxyProtocolError(
                    PPX_TLV_TYPE, "unknown TLV type"
                )
            if tlv_type in seen:
                raise ProxyProtocolError(PPX_TLV_DUP, "duplicate TLV type")
            key, maximum, textual = registration
            if value_length > maximum:
                raise ProxyProtocolError(
                    PPX_TLV_LEN, "TLV value exceeds type limit"
                )
            if len(region) - offset < value_length:
                raise ProxyProtocolError(
                    PPX_TLV_TRUNCATED, "incomplete TLV value"
                )

            seen.add(tlv_type)
            value = region[offset:offset + value_length]
            offset += value_length
            if textual:
                try:
                    tlvs[key] = value.decode("utf-8")
                except UnicodeDecodeError as exc:
                    raise ProxyProtocolError(
                        PPX_TLV_ENCODING, "TLV is not valid UTF-8"
                    ) from exc
            else:
                tlvs[key] = value.hex()
        return tlvs

    @staticmethod
    def _result(version, command, source, destination, tlvs, header_bytes):
        return {
            "status": "accepted",
            "code": None,
            "version": version,
            "command": command,
            "source": source,
            "destination": destination,
            "tlvs": tlvs,
            "header_bytes": header_bytes,
        }

    def _reject(self, code, peer):
        self._rejected += 1
        self._codes[code] = self._codes.get(code, 0) + 1
        self._recent.append(
            {"status": "rejected", "code": code, "peer": peer}
        )

    def trust_source(
        self, source_ip: str, *, now: float, ttl: float | None = None
    ) -> dict:
        canonical = self._canonical_address(source_ip)
        if ttl is None:
            ttl = self.source_ttl
        try:
            expires_at = float(now) + float(ttl)
        except (TypeError, ValueError, OverflowError) as exc:
            raise ProxyProtocolError(
                PPX_BAD_ADDRESS, "TTL must be numeric"
            ) from exc
        with self._lock:
            self._sources[canonical] = expires_at
            return {"source_ip": canonical, "expires_at": expires_at}

    def check_source(self, source_ip: str, *, now: float) -> bool:
        try:
            canonical = str(self._address(source_ip))
            current = float(now)
        except (TypeError, ValueError):
            return False
        with self._lock:
            expires_at = self._sources.get(canonical)
            return expires_at is not None and current < expires_at

    def purge_sources(self, *, now: float) -> int:
        try:
            current = float(now)
        except (TypeError, ValueError) as exc:
            raise ProxyProtocolError(
                PPX_BAD_ADDRESS, "now must be numeric"
            ) from exc
        with self._lock:
            expired = [
                source
                for source, expires_at in self._sources.items()
                if expires_at <= current
            ]
            for source in expired:
                del self._sources[source]
            return len(expired)

    def stats(self) -> dict:
        with self._lock:
            return {
                "accepted": self._accepted,
                "rejected": self._rejected,
                "codes": copy.deepcopy(self._codes),
                "connections": len(self._connections),
                "sources": len(self._sources),
                "recent": len(self._recent),
                "evicted": self._evicted,
            }

    def recent(self, limit: int = 10) -> list[dict]:
        with self._lock:
            if limit <= 0:
                return []
            entries = list(self._recent)
            if limit < len(entries):
                entries = entries[-limit:]
            return copy.deepcopy(entries)

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": self.SNAPSHOT_VERSION,
                "trusted_peers": list(self._trusted.keys()),
                "connections": copy.deepcopy(dict(self._connections)),
                "sources": copy.deepcopy(dict(self._sources)),
                "counters": {
                    "accepted": self._accepted,
                    "rejected": self._rejected,
                    "codes": copy.deepcopy(self._codes),
                },
                "recent": copy.deepcopy(list(self._recent)),
                "evicted": self._evicted,
            }

    def restore(self, state: dict) -> None:
        with self._lock:
            if not isinstance(state, Mapping):
                raise ProxyProtocolError(
                    PPX_STATE_VERSION, "snapshot must be a mapping"
                )
            if state.get("version") != self.SNAPSHOT_VERSION:
                raise ProxyProtocolError(
                    PPX_STATE_VERSION, "unsupported snapshot version"
                )

            try:
                fresh = copy.deepcopy(dict(state))
                peers_data = fresh.get("trusted_peers", [])
                connections_data = fresh.get("connections", {})
                sources_data = fresh.get("sources", {})
                counters_data = fresh.get("counters", {})
                recent_data = fresh.get("recent", [])
                evicted_data = fresh.get("evicted", 0)
            except Exception as exc:
                raise ProxyProtocolError(
                    PPX_STATE_VERSION, "snapshot cannot be copied"
                ) from exc

            if not isinstance(peers_data, (list, tuple, set, frozenset)):
                raise ProxyProtocolError(
                    PPX_STATE_VERSION, "trusted_peers must be iterable"
                )
            if not isinstance(connections_data, Mapping):
                raise ProxyProtocolError(
                    PPX_STATE_VERSION, "connections must be a mapping"
                )
            if not isinstance(sources_data, Mapping):
                raise ProxyProtocolError(
                    PPX_STATE_VERSION, "sources must be a mapping"
                )
            if not isinstance(counters_data, Mapping):
                raise ProxyProtocolError(
                    PPX_STATE_VERSION, "counters must be a mapping"
                )
            if not isinstance(recent_data, (list, tuple)):
                raise ProxyProtocolError(
                    PPX_STATE_VERSION, "recent must be a list"
                )

            new_trusted = OrderedDict()
            for peer in peers_data:
                network = self._network(peer)
                new_trusted[str(network)] = network

            new_connections = OrderedDict()
            for connection, result in connections_data.items():
                new_connections[connection] = copy.deepcopy(result)
            if len(new_connections) > self.max_connections:
                overflow = len(new_connections) - self.max_connections
                for _ in range(overflow):
                    new_connections.popitem(last=False)

            new_sources = {}
            for source, expires_at in sources_data.items():
                canonical = self._canonical_address(source)
                if isinstance(expires_at, bool) or not isinstance(
                    expires_at, (int, float)
                ):
                    raise ProxyProtocolError(
                        PPX_STATE_VERSION, "source expiry must be numeric"
                    )
                new_sources[canonical] = float(expires_at)

            accepted = counters_data.get("accepted", 0)
            rejected = counters_data.get("rejected", 0)
            codes = counters_data.get("codes", {})
            if (
                isinstance(accepted, bool)
                or not isinstance(accepted, int)
                or accepted < 0
            ):
                raise ProxyProtocolError(
                    PPX_STATE_VERSION, "accepted counter is invalid"
                )
            if (
                isinstance(rejected, bool)
                or not isinstance(rejected, int)
                or rejected < 0
            ):
                raise ProxyProtocolError(
                    PPX_STATE_VERSION, "rejected counter is invalid"
                )
            if not isinstance(codes, Mapping):
                raise ProxyProtocolError(
                    PPX_STATE_VERSION, "codes counter is invalid"
                )
            new_codes = {}
            for code, count in codes.items():
                if not isinstance(code, str):
                    raise ProxyProtocolError(
                        PPX_STATE_VERSION, "code counter key is invalid"
                    )
                if isinstance(count, bool) or not isinstance(count, int) or count < 0:
                    raise ProxyProtocolError(
                        PPX_STATE_VERSION, "code counter value is invalid"
                    )
                new_codes[code] = count

            if (
                isinstance(evicted_data, bool)
                or not isinstance(evicted_data, int)
                or evicted_data < 0
            ):
                raise ProxyProtocolError(
                    PPX_STATE_VERSION, "evicted counter is invalid"
                )

            new_recent = deque(
                (copy.deepcopy(entry) for entry in recent_data),
                maxlen=_RECENT_LIMIT,
            )

            self._trusted = new_trusted
            self._connections = new_connections
            self._sources = new_sources
            self._accepted = accepted
            self._rejected = rejected
            self._codes = new_codes
            self._recent = new_recent
            self._evicted = evicted_data


__all__ = [
    "ProxyProtocolError",
    "ProxyProtocolGuard",
    "SNAPSHOT_VERSION",
    "PPX_UNTRUSTED_PEER",
    "PPX_BAD_PEER",
    "PPX_BAD_PROTOCOL",
    "PPX_BAD_ADDRESS",
    "PPX_TOO_LARGE",
    "PPX_TRUNCATED",
    "PPX_TRAILING_DATA",
    "PPX_BAD_SIGNATURE",
    "PPX_BAD_VERSION",
    "PPX_BAD_COMMAND",
    "PPX_BAD_FAMILY",
    "PPX_LENGTH_MISMATCH",
    "PPX_TLV_TYPE",
    "PPX_TLV_LEN",
    "PPX_TLV_DUP",
    "PPX_TLV_TOO_LARGE",
    "PPX_TLV_TRUNCATED",
    "PPX_TLV_ENCODING",
    "PPX_DUPLICATE",
    "PPX_STATE_VERSION",
]
