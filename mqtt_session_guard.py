"""MQTT session state, offline queues, wills and topic matching."""

from __future__ import annotations


class MqttSessionError(ValueError):
    """Raised for invalid MQTT names, packets and session operations."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class MqttSessionGuard:
    """Keeps per-client subscriptions, packet ids, queues and will state."""

    SNAPSHOT_VERSION = 2
    MAX_PACKET_ID = 65535

    def __init__(self, *, clock=None, max_offline: int = 3,
                 max_inflight: int = 5, keepalive_grace: float = 1.5) -> None:
        self._clock = clock
        self.max_offline = max_offline
        self.max_inflight = max_inflight
        self.keepalive_grace = keepalive_grace

    def match(self, topic: str, topic_filter: str) -> bool:
        """Return whether a topic name is matched by a subscription filter."""
        raise NotImplementedError

    def connect(self, client_id: str, *, clean_start: bool = False,
                will: dict | None = None, keepalive: int = 60,
                now: float | None = None) -> dict:
        """Open or take over a session and replay any queued messages."""
        raise NotImplementedError

    def subscribe(self, client_id: str, topic_filter: str,
                  qos: int = 0) -> dict:
        """Add or replace one subscription for a client."""
        raise NotImplementedError

    def unsubscribe(self, client_id: str, topic_filter: str) -> dict:
        """Remove one subscription and report whether it existed."""
        raise NotImplementedError

    def deliver(self, client_id: str, topic: str, payload: bytes, *,
                qos: int = 0, expire_at: float | None = None) -> dict:
        """Route one message into a session, delivering or queueing it."""
        raise NotImplementedError

    def acknowledge(self, client_id: str, packet_id: int, *,
                    kind: str = "puback") -> dict:
        """Apply PUBACK, PUBREC or PUBREL to an in-flight message."""
        raise NotImplementedError

    def disconnect(self, client_id: str, *, graceful: bool = True,
                   now: float | None = None) -> dict:
        """Close a connection, publishing or suppressing the will."""
        raise NotImplementedError

    def keepalive_check(self, client_id: str, now: float | None = None) -> dict:
        """Refresh the keepalive clock or drop a silent connection."""
        raise NotImplementedError

    def pending(self, client_id: str) -> dict:
        """Return queued messages and in-flight packet ids."""
        raise NotImplementedError

    def will_for(self, client_id: str) -> dict | None:
        """Return the will that is still armed for a session, if any."""
        raise NotImplementedError

    def wills(self) -> list[dict]:
        """Return every will that has already been published."""
        raise NotImplementedError

    def purge(self, now: float | None = None) -> dict:
        """Publish due delayed wills and expire queued messages."""
        raise NotImplementedError

    def session_state(self, client_id: str) -> dict:
        """Return connection flag, subscriptions and clean-start mode."""
        raise NotImplementedError

    def snapshot(self) -> dict:
        """Return a JSON-serializable image of sessions, wills and counters."""
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        """Atomically replace guard state from a snapshot image."""
        raise NotImplementedError

    def stats(self) -> dict:
        """Return session, queue, will and duplicate counters."""
        raise NotImplementedError
