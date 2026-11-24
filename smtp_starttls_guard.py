"""SMTP STARTTLS downgrade guard."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

TLS_ORDER = ("TLSv1.3", "TLSv1.2")
MODES = ("require", "opportunistic")


class StarttlsError(ValueError):
    def __init__(self, code: str, detail: str | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class StarttlsGuard:
    TLS_VERSIONS = TLS_ORDER
    MODES = MODES

    def __init__(self, *, cache_ttl: int = 600, max_sessions: int = 64) -> None:
        self.cache_ttl = cache_ttl
        self.max_sessions = max_sessions

    def set_policy(self, domain: str, *, mode: str = "require",
                   min_version: str = "TLSv1.2") -> dict:
        raise NotImplementedError

    def policy_for(self, domain: str) -> dict:
        raise NotImplementedError

    def begin_session(self, session_id: str, *, peer_ip: str,
                      ehlo_domain: str, now: int = 0) -> dict:
        raise NotImplementedError

    def observe_ehlo(self, session_id: str, capabilities: Sequence[str],
                     *, now: int = 0) -> dict:
        raise NotImplementedError

    def decide(self, session_id: str, now: int = 0) -> dict:
        raise NotImplementedError

    def mark_tls(self, session_id: str, *, version: str, cipher: str) -> dict:
        raise NotImplementedError

    def cache_lookup(self, domain: str, now: int) -> dict:
        raise NotImplementedError

    def downgrade_report(self, limit: int = 50) -> list[dict]:
        raise NotImplementedError

    def close_session(self, session_id: str) -> bool:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, payload: Mapping[str, object] | None) -> dict:
        raise NotImplementedError

    def metrics(self) -> dict:
        raise NotImplementedError
