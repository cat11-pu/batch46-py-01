"""BGP FlowSpec injection guard (implementation skeleton)."""

from __future__ import annotations

import threading

SNAPSHOT_VERSION = 1
PEER_ROLES = ("edge", "customer", "upstream", "untrusted")
RULE_ACTIONS = ("discard", "rate-limit", "redirect")
MATCH_FIELDS = (
    "destination",
    "source",
    "protocol",
    "port",
    "tcp_flags",
    "packet_length",
    "dscp",
    "icmp_type",
)
TCP_FLAGS = ("syn", "ack", "fin", "rst", "psh", "urg")


class FlowspecError(ValueError):
    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class FlowspecGuard:
    """Peer registry, FlowSpec validation, conflict resolution and rate limits."""

    def __init__(self, *, max_rules: int = 256, max_components: int = 8,
                 rate_limit: int = 20, rate_window: int = 60,
                 violation_threshold: int = 3, block_seconds: int = 300,
                 allowed_next_hops: tuple = ()) -> None:
        self.max_rules = max_rules
        self.max_components = max_components
        self.rate_limit = rate_limit
        self.rate_window = rate_window
        self.violation_threshold = violation_threshold
        self.block_seconds = block_seconds
        self.allowed_next_hops = tuple(allowed_next_hops)
        self._lock = threading.RLock()
        self._peers = {}
        self._rules = {}
        self._stats = {}
        self._blocked = {}
        self._recent = {}
        self._violations = {}

    def register_peer(self, peer: str, *, role: str, asn: int,
                      prefixes: tuple = ()) -> dict:
        raise NotImplementedError

    def ingest(self, rule: dict, *, peer: str, now: int | None = None) -> dict:
        raise NotImplementedError

    def ingest_batch(self, rules: list, *, peer: str,
                     now: int | None = None) -> list:
        raise NotImplementedError

    def rules(self, *, peer: str | None = None,
              now: int | None = None) -> list:
        raise NotImplementedError

    def effective(self, destination: str, *,
                  now: int | None = None) -> list:
        raise NotImplementedError

    def withdraw(self, rule_id: str) -> dict:
        raise NotImplementedError

    def stats(self, peer: str | None = None) -> dict:
        raise NotImplementedError

    def block_peer(self, peer: str, seconds: int, *,
                   now: int | None = None) -> dict:
        raise NotImplementedError

    def release_peer(self, peer: str) -> dict:
        raise NotImplementedError

    def blocked(self, *, now: int | None = None) -> list:
        raise NotImplementedError

    def expire(self, now: int) -> list:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, snapshot: dict) -> None:
        raise NotImplementedError
