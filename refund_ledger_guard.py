"""Refund ledger with holds, credit limits, windows and chargebacks."""

from __future__ import annotations

import copy
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping


class RefundError(ValueError):
    def __init__(self, code: str, detail: Any = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


_SNAPSHOT_VERSION = 1
_ENTRY_KINDS = {"credit", "debit", "refund", "chargeback", "settle"}
_HOLD_STATUSES = {"open", "released", "settled"}


class RefundLedger:
    def __init__(self, credit_limit: int = 500, window_days: int = 14,
                 max_holds: int = 32, max_entries: int = 5000) -> None:
        self.credit_limit = credit_limit
        self.window_days = window_days
        self.max_holds = max_holds
        self.max_entries = max_entries

        self._lock = threading.RLock()
        self._reset_state()

    # ------------------------------------------------------------------
    # internal helpers
    # ------------------------------------------------------------------
    def _reset_state(self) -> None:
        self._balances: dict[str, int] = {}
        self._holds: dict[str, dict[str, Any]] = {}
        self._transactions: dict[str, dict[str, Any]] = {}
        self._refunds: dict[str, dict[str, Any]] = {}
        self._chargebacks: dict[str, dict[str, Any]] = {}
        self._entries: dict[str, list[dict[str, Any]]] = {}
        self._next_seq = 1

    @staticmethod
    def _require_amount(amount: Any) -> int:
        if (isinstance(amount, bool) or not isinstance(amount, int)
                or amount <= 0):
            raise RefundError("REFUND_BAD_AMOUNT", amount)
        return amount

    @staticmethod
    def _parse_time(value: Any) -> datetime:
        if not isinstance(value, str) or not value.strip():
            raise RefundError("REFUND_BAD_TIME", value)
        text = value.strip()
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except (TypeError, ValueError) as exc:
            raise RefundError("REFUND_BAD_TIME", value) from exc
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise RefundError("REFUND_BAD_TIME", value)
        return parsed.astimezone(timezone.utc)

    @staticmethod
    def _canonical_time(parsed: datetime) -> str:
        return parsed.astimezone(timezone.utc).isoformat()

    def _balance_of(self, account: str) -> int:
        return self._balances.get(account, 0)

    def _held_of(self, account: str) -> int:
        return sum(
            hold["amount"]
            for hold in self._holds.values()
            if hold["account"] == account and hold["status"] == "open"
        )

    def _open_hold_count(self, account: str) -> int:
        return sum(
            1
            for hold in self._holds.values()
            if hold["account"] == account and hold["status"] == "open"
        )

    def _available_of(self, account: str) -> int:
        return self._balance_of(account) - self._held_of(account)

    def _account_entries(self, account: str) -> list[dict[str, Any]]:
        return self._entries.get(account, [])

    def _check_entry_capacity(self, account: str) -> None:
        if len(self._account_entries(account)) >= self.max_entries:
            raise RefundError("REFUND_LEDGER_FULL", account)

    def _append_entry(self, account: str, kind: str, amount: int,
                      balance_after: int, at: str,
                      reference: str | None = None,
                      **extra: Any) -> dict[str, Any]:
        entry: dict[str, Any] = {
            "seq": self._next_seq,
            "kind": kind,
            "amount": amount,
            "balance_after": balance_after,
            "at": at,
        }
        if reference is not None:
            entry["reference"] = reference
        entry.update(extra)
        self._next_seq += 1
        self._entries.setdefault(account, []).append(entry)
        return entry

    # ------------------------------------------------------------------
    # credit / debit
    # ------------------------------------------------------------------
    def credit(self, account: str, amount: int, tx_id: str,
               at: str) -> dict[str, Any]:
        with self._lock:
            amount = self._require_amount(amount)
            parsed_at = self._canonical_time(self._parse_time(at))

            existing = self._transactions.get(tx_id)
            if existing is not None:
                return {
                    "status": "duplicate",
                    "kind": existing["kind"],
                    "account": existing["account"],
                    "amount": existing["amount"],
                    "balance": self._balance_of(existing["account"]),
                }

            self._check_entry_capacity(account)
            new_balance = self._balance_of(account) + amount
            self._transactions[tx_id] = {
                "tx_id": tx_id,
                "account": account,
                "amount": amount,
                "kind": "credit",
                "at": parsed_at,
                "refunded_total": 0,
                "reversed": False,
            }
            self._balances[account] = new_balance
            entry = self._append_entry(
                account, "credit", amount, new_balance, parsed_at,
                reference=tx_id, tx_id=tx_id,
            )
            return {
                "status": "applied",
                "account": account,
                "amount": amount,
                "balance": new_balance,
                "seq": entry["seq"],
            }

    def debit(self, account: str, amount: int, tx_id: str, at: str,
              reason: str = "purchase") -> dict[str, Any]:
        with self._lock:
            amount = self._require_amount(amount)
            parsed_at = self._canonical_time(self._parse_time(at))

            existing = self._transactions.get(tx_id)
            if existing is not None:
                return {
                    "status": "duplicate",
                    "kind": existing["kind"],
                    "account": existing["account"],
                    "amount": existing["amount"],
                    "balance": self._balance_of(existing["account"]),
                }

            held = self._held_of(account)
            new_balance = self._balance_of(account) - amount
            new_available = new_balance - held
            if new_available < -self.credit_limit:
                raise RefundError("REFUND_CREDIT_LIMIT", {
                    "balance": self._balance_of(account),
                    "held": held,
                    "amount": amount,
                    "credit_limit": self.credit_limit,
                })

            self._check_entry_capacity(account)
            self._transactions[tx_id] = {
                "tx_id": tx_id,
                "account": account,
                "amount": amount,
                "kind": "debit",
                "at": parsed_at,
                "refunded_total": 0,
                "reversed": False,
                "reason": reason,
            }
            self._balances[account] = new_balance
            entry = self._append_entry(
                account, "debit", -amount, new_balance, parsed_at,
                reference=tx_id, tx_id=tx_id, reason=reason,
            )
            return {
                "status": "applied",
                "account": account,
                "amount": amount,
                "balance": new_balance,
                "seq": entry["seq"],
            }

    # ------------------------------------------------------------------
    # refunds / chargebacks
    # ------------------------------------------------------------------
    def refund(self, account: str, tx_id: str, amount: int, refund_id: str,
               at: str) -> dict[str, Any]:
        with self._lock:
            amount = self._require_amount(amount)

            existing_refund = self._refunds.get(refund_id)
            if existing_refund is not None:
                original = self._transactions[existing_refund["tx_id"]]
                return {
                    "status": "duplicate",
                    "account": original["account"],
                    "tx_id": original["tx_id"],
                    "amount": existing_refund["amount"],
                    "refunded_total": original["refunded_total"],
                    "balance": self._balance_of(original["account"]),
                }

            transaction = self._transactions.get(tx_id)
            if transaction is None:
                raise RefundError("REFUND_TX_NOT_FOUND", tx_id)
            if transaction["kind"] != "debit":
                raise RefundError("REFUND_NOT_REFUNDABLE", tx_id)
            if transaction["account"] != account:
                raise RefundError("REFUND_TX_ACCOUNT", tx_id)

            parsed_at_dt = self._parse_time(at)
            debit_at = self._parse_time(transaction["at"])
            if parsed_at_dt > debit_at + timedelta(days=self.window_days):
                raise RefundError("REFUND_WINDOW_EXPIRED", {
                    "debit_at": transaction["at"],
                    "at": at,
                    "window_days": self.window_days,
                })

            refunded_total = transaction["refunded_total"]
            if refunded_total + amount > transaction["amount"]:
                raise RefundError("REFUND_OVER_REFUND", {
                    "amount": transaction["amount"],
                    "refunded_total": refunded_total,
                    "requested": amount,
                })

            self._check_entry_capacity(account)
            parsed_at = self._canonical_time(parsed_at_dt)
            new_balance = self._balance_of(account) + amount
            transaction["refunded_total"] = refunded_total + amount
            self._balances[account] = new_balance
            self._refunds[refund_id] = {
                "refund_id": refund_id,
                "account": account,
                "tx_id": tx_id,
                "amount": amount,
                "at": parsed_at,
            }
            entry = self._append_entry(
                account, "refund", amount, new_balance, parsed_at,
                reference=refund_id, tx_id=tx_id, refund_id=refund_id,
            )
            return {
                "status": "applied",
                "account": account,
                "tx_id": tx_id,
                "amount": amount,
                "refunded_total": transaction["refunded_total"],
                "balance": new_balance,
                "seq": entry["seq"],
            }

    def chargeback(self, account: str, tx_id: str, chargeback_id: str,
                   at: str) -> dict[str, Any]:
        with self._lock:
            transaction = self._transactions.get(tx_id)
            if transaction is None:
                raise RefundError("REFUND_TX_NOT_FOUND", tx_id)
            if transaction["account"] != account:
                raise RefundError("REFUND_TX_ACCOUNT", tx_id)
            if transaction["kind"] != "credit":
                raise RefundError("REFUND_NOT_CHARGEABLE", tx_id)
            if transaction["reversed"]:
                return {
                    "status": "ignored",
                    "code": "REFUND_ALREADY_REVERSED",
                    "account": account,
                    "tx_id": tx_id,
                    "amount": transaction["amount"],
                    "balance": self._balance_of(account),
                }

            parsed_at_dt = self._parse_time(at)
            amount = transaction["amount"]
            new_balance = self._balance_of(account) - amount
            if new_balance < -self.credit_limit:
                raise RefundError("REFUND_CREDIT_LIMIT", {
                    "balance": self._balance_of(account),
                    "amount": amount,
                    "credit_limit": self.credit_limit,
                })

            self._check_entry_capacity(account)
            parsed_at = self._canonical_time(parsed_at_dt)
            transaction["reversed"] = True
            self._balances[account] = new_balance
            self._chargebacks[chargeback_id] = {
                "chargeback_id": chargeback_id,
                "account": account,
                "tx_id": tx_id,
                "amount": amount,
                "at": parsed_at,
            }
            entry = self._append_entry(
                account, "chargeback", -amount, new_balance, parsed_at,
                reference=chargeback_id, tx_id=tx_id,
                chargeback_id=chargeback_id,
            )
            return {
                "status": "applied",
                "account": account,
                "tx_id": tx_id,
                "amount": amount,
                "balance": new_balance,
                "seq": entry["seq"],
            }

    # ------------------------------------------------------------------
    # balances / holds
    # ------------------------------------------------------------------
    def balance(self, account: str) -> dict[str, int]:
        with self._lock:
            balance = self._balance_of(account)
            held = self._held_of(account)
            return {
                "balance": balance,
                "held": held,
                "available": balance - held,
            }

    def outstanding(self, account: str) -> int:
        with self._lock:
            return self._held_of(account)

    def hold(self, account: str, amount: int, hold_id: str) -> dict[str, Any]:
        with self._lock:
            amount = self._require_amount(amount)

            existing = self._holds.get(hold_id)
            if existing is not None:
                return {
                    "status": "duplicate",
                    "hold_id": hold_id,
                    "account": existing["account"],
                    "amount": existing["amount"],
                    "hold_status": existing["status"],
                    "held": self._held_of(existing["account"]),
                    "available": self._available_of(existing["account"]),
                }

            available = self._available_of(account)
            if amount > available:
                raise RefundError("REFUND_INSUFFICIENT_AVAILABLE", {
                    "available": available,
                    "amount": amount,
                })
            if self._open_hold_count(account) >= self.max_holds:
                raise RefundError("REFUND_TOO_MANY_HOLDS", account)

            self._holds[hold_id] = {
                "hold_id": hold_id,
                "account": account,
                "amount": amount,
                "status": "open",
            }
            return {
                "status": "held",
                "hold_id": hold_id,
                "account": account,
                "amount": amount,
                "held": self._held_of(account),
                "available": self._available_of(account),
            }

    def release(self, account: str, hold_id: str) -> dict[str, Any]:
        with self._lock:
            hold = self._holds.get(hold_id)
            if hold is None or hold["account"] != account:
                raise RefundError("REFUND_HOLD_NOT_FOUND", hold_id)
            if hold["status"] != "open":
                return {
                    "status": "ignored",
                    "code": "REFUND_HOLD_CLOSED",
                    "hold_id": hold_id,
                    "account": account,
                    "amount": hold["amount"],
                    "held": self._held_of(account),
                    "available": self._available_of(account),
                }

            hold["status"] = "released"
            return {
                "status": "released",
                "hold_id": hold_id,
                "account": account,
                "amount": hold["amount"],
                "held": self._held_of(account),
                "available": self._available_of(account),
            }

    def settle(self, account: str, hold_id: str, at: str) -> dict[str, Any]:
        with self._lock:
            hold = self._holds.get(hold_id)
            if hold is None or hold["account"] != account:
                raise RefundError("REFUND_HOLD_NOT_FOUND", hold_id)
            if hold["status"] != "open":
                return {
                    "status": "ignored",
                    "code": "REFUND_HOLD_CLOSED",
                    "hold_id": hold_id,
                    "account": account,
                    "amount": hold["amount"],
                    "balance": self._balance_of(account),
                }

            parsed_at = self._canonical_time(self._parse_time(at))
            amount = hold["amount"]
            self._check_entry_capacity(account)

            new_balance = self._balance_of(account) - amount
            hold["status"] = "settled"
            hold["settled_at"] = parsed_at
            self._balances[account] = new_balance
            entry = self._append_entry(
                account, "settle", -amount, new_balance, parsed_at,
                reference=hold_id, hold_id=hold_id,
            )
            return {
                "status": "settled",
                "hold_id": hold_id,
                "account": account,
                "amount": amount,
                "balance": new_balance,
                "held": self._held_of(account),
                "available": self._available_of(account),
                "seq": entry["seq"],
            }

    # ------------------------------------------------------------------
    # read APIs
    # ------------------------------------------------------------------
    def history(self, account: str) -> list[dict[str, Any]]:
        with self._lock:
            return copy.deepcopy(self._entries.get(account, []))

    def statement(self, account: str, from_at: str,
                  to_at: str) -> dict[str, Any]:
        with self._lock:
            start = self._parse_time(from_at)
            end = self._parse_time(to_at)
            if start > end:
                raise RefundError("REFUND_BAD_TIME", {
                    "from_at": from_at,
                    "to_at": to_at,
                })

            opening = 0
            total = 0
            entries = 0
            for entry in self._entries.get(account, []):
                entry_at = self._parse_time(entry["at"])
                if entry_at < start:
                    opening += entry["amount"]
                elif entry_at <= end:
                    total += entry["amount"]
                    entries += 1

            return {
                "account": account,
                "from": self._canonical_time(start),
                "to": self._canonical_time(end),
                "opening": opening,
                "closing": opening + total,
                "total": total,
                "entries": entries,
            }

    # ------------------------------------------------------------------
    # persistence
    # ------------------------------------------------------------------
    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "version": _SNAPSHOT_VERSION,
                "config": {
                    "credit_limit": self.credit_limit,
                    "window_days": self.window_days,
                    "max_holds": self.max_holds,
                    "max_entries": self.max_entries,
                },
                "balances": copy.deepcopy(self._balances),
                "holds": copy.deepcopy(self._holds),
                "transactions": copy.deepcopy(self._transactions),
                "refunds": copy.deepcopy(self._refunds),
                "chargebacks": copy.deepcopy(self._chargebacks),
                "entries": copy.deepcopy(self._entries),
                "next_seq": self._next_seq,
            }

    def restore(self, payload: Mapping[str, Any]) -> None:
        with self._lock:
            try:
                restored = self._validate_snapshot(payload)
            except RefundError as exc:
                if exc.code == "REFUND_BAD_SNAPSHOT":
                    raise
                raise RefundError("REFUND_BAD_SNAPSHOT", exc.code) from exc
            except Exception as exc:
                raise RefundError("REFUND_BAD_SNAPSHOT", None) from exc

            config = restored["config"]
            self.credit_limit = config["credit_limit"]
            self.window_days = config["window_days"]
            self.max_holds = config["max_holds"]
            self.max_entries = config["max_entries"]
            self._balances = restored["balances"]
            self._holds = restored["holds"]
            self._transactions = restored["transactions"]
            self._refunds = restored["refunds"]
            self._chargebacks = restored["chargebacks"]
            self._entries = restored["entries"]
            self._next_seq = restored["next_seq"]

    def _validate_snapshot(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(payload, Mapping):
            raise RefundError("REFUND_BAD_SNAPSHOT", None)
        if payload.get("version") != _SNAPSHOT_VERSION:
            raise RefundError("REFUND_BAD_SNAPSHOT", payload.get("version"))

        config = payload.get("config")
        if not isinstance(config, Mapping):
            raise RefundError("REFUND_BAD_SNAPSHOT", "config")

        def require_int(mapping: Mapping[str, Any], key: str,
                        minimum: int | None = None) -> int:
            value = mapping[key]
            if isinstance(value, bool) or not isinstance(value, int):
                raise RefundError("REFUND_BAD_SNAPSHOT", key)
            if minimum is not None and value < minimum:
                raise RefundError("REFUND_BAD_SNAPSHOT", key)
            return value

        new_config = {
            "credit_limit": require_int(config, "credit_limit", 0),
            "window_days": require_int(config, "window_days", 0),
            "max_holds": require_int(config, "max_holds", 0),
            "max_entries": require_int(config, "max_entries", 0),
        }

        balances_raw = payload.get("balances", {})
        holds_raw = payload.get("holds", {})
        transactions_raw = payload.get("transactions", {})
        refunds_raw = payload.get("refunds", {})
        chargebacks_raw = payload.get("chargebacks", {})
        entries_raw = payload.get("entries", {})
        next_seq = require_int(payload, "next_seq", 1)

        if not isinstance(balances_raw, Mapping):
            raise RefundError("REFUND_BAD_SNAPSHOT", "balances")
        balances: dict[str, int] = {}
        for account, value in balances_raw.items():
            if not isinstance(account, str):
                raise RefundError("REFUND_BAD_SNAPSHOT", "balances")
            if isinstance(value, bool) or not isinstance(value, int):
                raise RefundError("REFUND_BAD_SNAPSHOT", "balances")
            balances[account] = value

        if not isinstance(holds_raw, Mapping):
            raise RefundError("REFUND_BAD_SNAPSHOT", "holds")
        holds: dict[str, dict[str, Any]] = {}
        for hold_id, raw in holds_raw.items():
            if not isinstance(hold_id, str) or not isinstance(raw, Mapping):
                raise RefundError("REFUND_BAD_SNAPSHOT", "holds")
            account = raw.get("account")
            if not isinstance(account, str):
                raise RefundError("REFUND_BAD_SNAPSHOT", "holds.account")
            status = raw.get("status")
            if status not in _HOLD_STATUSES:
                raise RefundError("REFUND_BAD_SNAPSHOT", "holds.status")
            amount = require_int(raw, "amount", 1)
            hold = {
                "hold_id": hold_id,
                "account": account,
                "amount": amount,
                "status": status,
            }
            if "settled_at" in raw:
                hold["settled_at"] = self._canonical_time(
                    self._parse_time(raw["settled_at"])
                )
            holds[hold_id] = hold

        if not isinstance(transactions_raw, Mapping):
            raise RefundError("REFUND_BAD_SNAPSHOT", "transactions")
        transactions: dict[str, dict[str, Any]] = {}
        for tx_id, raw in transactions_raw.items():
            if not isinstance(tx_id, str) or not isinstance(raw, Mapping):
                raise RefundError("REFUND_BAD_SNAPSHOT", "transactions")
            account = raw.get("account")
            kind = raw.get("kind")
            if not isinstance(account, str) or kind not in {"credit", "debit"}:
                raise RefundError("REFUND_BAD_SNAPSHOT", "transactions")
            amount = require_int(raw, "amount", 1)
            refunded_total = require_int(raw, "refunded_total", 0)
            if refunded_total > amount:
                raise RefundError(
                    "REFUND_BAD_SNAPSHOT", "transactions.refunded_total"
                )
            transaction = {
                "tx_id": tx_id,
                "account": account,
                "amount": amount,
                "kind": kind,
                "at": self._canonical_time(
                    self._parse_time(raw.get("at"))
                ),
                "refunded_total": refunded_total,
                "reversed": bool(raw.get("reversed", False)),
            }
            if "reason" in raw:
                transaction["reason"] = raw["reason"]
            transactions[tx_id] = transaction

        if not isinstance(refunds_raw, Mapping):
            raise RefundError("REFUND_BAD_SNAPSHOT", "refunds")
        refunds: dict[str, dict[str, Any]] = {}
        for refund_id, raw in refunds_raw.items():
            if not isinstance(refund_id, str) or not isinstance(raw, Mapping):
                raise RefundError("REFUND_BAD_SNAPSHOT", "refunds")
            account = raw.get("account")
            tx_id = raw.get("tx_id")
            if not isinstance(account, str) or not isinstance(tx_id, str):
                raise RefundError("REFUND_BAD_SNAPSHOT", "refunds")
            amount = require_int(raw, "amount", 1)
            refunds[refund_id] = {
                "refund_id": refund_id,
                "account": account,
                "tx_id": tx_id,
                "amount": amount,
                "at": self._canonical_time(
                    self._parse_time(raw.get("at"))
                ),
            }

        if not isinstance(chargebacks_raw, Mapping):
            raise RefundError("REFUND_BAD_SNAPSHOT", "chargebacks")
        chargebacks: dict[str, dict[str, Any]] = {}
        for chargeback_id, raw in chargebacks_raw.items():
            if (not isinstance(chargeback_id, str)
                    or not isinstance(raw, Mapping)):
                raise RefundError("REFUND_BAD_SNAPSHOT", "chargebacks")
            account = raw.get("account")
            tx_id = raw.get("tx_id")
            if not isinstance(account, str) or not isinstance(tx_id, str):
                raise RefundError("REFUND_BAD_SNAPSHOT", "chargebacks")
            amount = require_int(raw, "amount", 1)
            chargebacks[chargeback_id] = {
                "chargeback_id": chargeback_id,
                "account": account,
                "tx_id": tx_id,
                "amount": amount,
                "at": self._canonical_time(
                    self._parse_time(raw.get("at"))
                ),
            }

        if not isinstance(entries_raw, Mapping):
            raise RefundError("REFUND_BAD_SNAPSHOT", "entries")
        entries: dict[str, list[dict[str, Any]]] = {}
        for account, rows in entries_raw.items():
            if not isinstance(account, str) or not isinstance(rows, list):
                raise RefundError("REFUND_BAD_SNAPSHOT", "entries")
            if len(rows) > new_config["max_entries"]:
                raise RefundError("REFUND_BAD_SNAPSHOT", "entries")
            copied_rows: list[dict[str, Any]] = []
            for row in rows:
                if not isinstance(row, Mapping):
                    raise RefundError("REFUND_BAD_SNAPSHOT", "entries")
                kind = row.get("kind")
                if kind not in _ENTRY_KINDS:
                    raise RefundError("REFUND_BAD_SNAPSHOT", "entries.kind")
                seq = require_int(row, "seq", 1)
                amount = require_int(row, "amount", None)
                balance_after = require_int(row, "balance_after", None)
                at = self._canonical_time(self._parse_time(row.get("at")))
                copied = copy.deepcopy(dict(row))
                copied["seq"] = seq
                copied["amount"] = amount
                copied["balance_after"] = balance_after
                copied["at"] = at
                copied_rows.append(copied)
            entries[account] = copied_rows

        max_seq = max(
            (row["seq"] for rows in entries.values() for row in rows),
            default=0,
        )
        if next_seq <= max_seq:
            raise RefundError("REFUND_BAD_SNAPSHOT", "next_seq")

        return {
            "config": new_config,
            "balances": balances,
            "holds": holds,
            "transactions": transactions,
            "refunds": refunds,
            "chargebacks": chargebacks,
            "entries": entries,
            "next_seq": next_seq,
        }
