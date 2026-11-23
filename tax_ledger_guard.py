"""Auction tax accrual, batching, waivers, reversals and payments.

All four write paths (sale entry, settlement, reversal and payment) mutate the
same in-memory tax ledger.  Operations are serialized with a re-entrant lock so
that a sale and its batch assignment, a reversal and its adjustment, or a
payment and its outstanding balance become visible atomically.

The ledger is deliberately self-contained: ``snapshot`` produces a plain JSON
value and ``restore`` rebuilds the complete state (including idempotency sets
and sequence counters) from it.
"""

from __future__ import annotations

import copy
import threading
from collections.abc import Mapping as MappingABC
from datetime import datetime, timezone
from typing import Any, Mapping


SNAPSHOT_VERSION = 1

_SALE_FIELDS = (
    "sale_id",
    "seller",
    "buyer",
    "gross",
    "category",
    "occurred_at",
    "tax",
    "status",
    "waived",
    "settled_batch",
)


class TaxError(ValueError):
    def __init__(self, code: str, detail: Any = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class TaxLedger:
    def __init__(self, rate_bps: int = 500, min_fee: int = 1, cap: int = 100000,
                 exempt_below: int = 0, batch_limit: int = 500,
                 max_pending: int = 2000) -> None:
        self.rate_bps = rate_bps
        self.min_fee = min_fee
        self.cap = cap
        self.exempt_below = exempt_below
        self.batch_limit = batch_limit
        self.max_pending = max_pending

        self._lock = threading.RLock()
        self._category_rates: dict[str, dict[str, int]] = {}
        self._sales: dict[str, dict[str, Any]] = {}
        self._batches: dict[str, dict[str, Any]] = {}
        self._reversals: dict[str, dict[str, Any]] = {}
        self._payments: dict[str, dict[str, Any]] = {}
        self._journal: list[dict[str, Any]] = []
        self._seq = 0

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _next_seq(self) -> int:
        self._seq += 1
        return self._seq

    @staticmethod
    def _parse_time(value: Any) -> datetime:
        if not isinstance(value, str) or not value.strip():
            raise TaxError("TAX_BAD_TIME", value)
        text = value.strip()
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except (TypeError, ValueError):
            raise TaxError("TAX_BAD_TIME", value) from None
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise TaxError("TAX_BAD_TIME", value)
        return parsed

    @staticmethod
    def _utc_iso(value: datetime) -> str:
        return value.astimezone(timezone.utc).isoformat()

    @staticmethod
    def _nonempty_text(value: Any) -> bool:
        return isinstance(value, str) and bool(value.strip())

    def _rate_rule(self, category: str) -> tuple[int, int]:
        rule = self._category_rates.get(category)
        if rule is None:
            return self.rate_bps, self.exempt_below
        return rule["rate_bps"], rule["exempt_below"]

    def _public_sale(self, sale: Mapping[str, Any]) -> dict[str, Any]:
        row = {field: copy.deepcopy(sale[field]) for field in _SALE_FIELDS}
        row["reversed"] = bool(sale.get("reversed", False))
        return row

    @staticmethod
    def _limit_value(default: int, limit: Any) -> int:
        if limit is None:
            if not isinstance(default, int):
                return 0
            return max(0, default)
        if not isinstance(limit, int) or isinstance(limit, bool):
            raise TaxError("TAX_BAD_AMOUNT", limit)
        return max(0, limit)

    def _pending_records(self, seller: str | None, upto: datetime | None = None
                         ) -> list[dict[str, Any]]:
        rows = []
        for sale in self._sales.values():
            if sale["status"] != "pending":
                continue
            if seller is not None and sale["seller"] != seller:
                continue
            if upto is not None and sale["_occurred"] > upto:
                continue
            rows.append(sale)
        rows.sort(key=lambda sale: (sale["_occurred"], sale["seq"]))
        return rows

    def _build_batch(self, batch_id: str, seller: str | None, upto: str,
                     selected: list[dict[str, Any]]) -> dict[str, Any]:
        allocations: dict[str, dict[str, Any]] = {}
        gross_total = 0
        tax_total = 0
        for sale in selected:
            sale_seller = sale["seller"]
            allocation = allocations.setdefault(
                sale_seller,
                {
                    "seller": sale_seller,
                    "gross": 0,
                    "tax": 0,
                    "count": 0,
                    "sale_ids": [],
                },
            )
            allocation["gross"] += sale["gross"]
            allocation["tax"] += sale["tax"]
            allocation["count"] += 1
            allocation["sale_ids"].append(sale["sale_id"])
            gross_total += sale["gross"]
            tax_total += sale["tax"]

        return {
            "batch_id": batch_id,
            "seller": seller,
            "upto": upto,
            "seq": self._next_seq(),
            "settled": len(selected),
            "gross": gross_total,
            "tax": tax_total,
            "sale_ids": [sale["sale_id"] for sale in selected],
            "allocations": allocations,
        }

    def _commit_batch(self, batch: dict[str, Any]) -> None:
        batch_id = batch["batch_id"]
        for sale_id in batch["sale_ids"]:
            sale = self._sales[sale_id]
            sale["status"] = "settled"
            sale["settled_batch"] = batch_id
        self._batches[batch_id] = batch

        for allocation in batch["allocations"].values():
            self._journal.append(
                {
                    "seq": batch["seq"],
                    "type": "settlement",
                    "seller": allocation["seller"],
                    "batch_id": batch_id,
                    "sale_ids": list(allocation["sale_ids"]),
                    "gross": allocation["gross"],
                    "tax": allocation["tax"],
                    "amount": allocation["tax"],
                    "upto": batch["upto"],
                }
            )

    def _batch_duplicate(self, batch: Mapping[str, Any]) -> dict[str, Any]:
        result = {
            "status": "duplicate",
            "batch_id": batch["batch_id"],
            "settled": batch["settled"],
            "gross": batch["gross"],
            "tax": batch["tax"],
            "sale_ids": list(batch["sale_ids"]),
        }
        if batch.get("seller") is not None:
            result["seller"] = batch["seller"]
        result["allocations"] = copy.deepcopy(batch["allocations"])
        return result

    def _totals_unlocked(self, seller: str) -> dict[str, Any]:
        gross = 0
        tax_accrued = 0
        pending = 0
        for sale in self._sales.values():
            if sale["seller"] != seller or sale["status"] == "voided":
                continue
            gross += sale["gross"]
            tax_accrued += sale["tax"]
            if sale["status"] == "pending":
                pending += 1

        tax_settled = 0
        for batch in self._batches.values():
            allocation = batch["allocations"].get(seller)
            if allocation is not None:
                tax_settled += allocation["tax"]

        adjustments = 0
        for reversal in self._reversals.values():
            if reversal["seller"] == seller:
                adjustments += reversal["amount"]

        paid = 0
        for payment in self._payments.values():
            if payment["seller"] == seller:
                paid += payment["amount"]

        outstanding = tax_settled + adjustments - paid
        return {
            "gross": gross,
            "tax_accrued": tax_accrued,
            "tax_settled": tax_settled,
            "adjustments": adjustments,
            "paid": paid,
            "outstanding": outstanding,
            "pending": pending,
        }

    # ------------------------------------------------------------------
    # Tax rules
    # ------------------------------------------------------------------
    def tax_for(self, gross: int, category: str = "item") -> int:
        with self._lock:
            if not isinstance(gross, int) or isinstance(gross, bool):
                raise TaxError("TAX_BAD_AMOUNT", gross)
            if gross < 0:
                raise TaxError("TAX_BAD_AMOUNT", gross)
            if gross == 0:
                return 0

            rate_bps, exempt_below = self._rate_rule(category)
            if gross < exempt_below:
                return 0

            tax = gross * rate_bps // 10000
            if tax < self.min_fee:
                tax = self.min_fee
            if self.cap is not None and tax > self.cap:
                tax = self.cap
            return int(tax)

    def set_category_rate(self, category: str, rate_bps: int,
                          exempt_below: int = 0) -> dict[str, Any]:
        with self._lock:
            if not self._nonempty_text(category):
                raise TaxError("TAX_BAD_CATEGORY", category)
            if (not isinstance(rate_bps, int) or isinstance(rate_bps, bool)
                    or rate_bps < 0 or rate_bps > 10000):
                raise TaxError("TAX_BAD_RATE", rate_bps)
            if (not isinstance(exempt_below, int)
                    or isinstance(exempt_below, bool)
                    or exempt_below < 0):
                raise TaxError("TAX_BAD_RATE", exempt_below)

            self._category_rates[category] = {
                "rate_bps": rate_bps,
                "exempt_below": exempt_below,
            }
            return {
                "status": "updated",
                "category": category,
                "rate_bps": rate_bps,
                "exempt_below": exempt_below,
            }

    # ------------------------------------------------------------------
    # Sales and pending work
    # ------------------------------------------------------------------
    def record_sale(self, sale_id: str, seller: str, buyer: str, gross: int,
                    occurred_at: str,
                    category: str = "item") -> dict[str, Any]:
        with self._lock:
            if not self._nonempty_text(sale_id):
                raise TaxError("TAX_BAD_SALE", sale_id)

            existing = self._sales.get(sale_id)
            if existing is not None:
                result = self._public_sale(existing)
                result["status"] = "duplicate"
                return result

            if not self._nonempty_text(seller) or not self._nonempty_text(buyer):
                raise TaxError("TAX_BAD_SALE", sale_id)
            if seller == buyer:
                raise TaxError("TAX_SELF_TRADE", sale_id)
            if not isinstance(gross, int) or isinstance(gross, bool) or gross <= 0:
                raise TaxError("TAX_BAD_AMOUNT", gross)

            occurred = self._parse_time(occurred_at)

            pending_count = sum(
                1 for sale in self._sales.values()
                if sale["seller"] == seller and sale["status"] == "pending"
            )
            if pending_count >= self.max_pending:
                raise TaxError("TAX_PENDING_LIMIT", seller)

            tax = self.tax_for(gross, category)
            seq = self._next_seq()
            sale = {
                "sale_id": sale_id,
                "seller": seller,
                "buyer": buyer,
                "gross": gross,
                "category": category,
                "occurred_at": occurred_at,
                "occurred_utc": self._utc_iso(occurred),
                "seq": seq,
                "tax": tax,
                "status": "pending",
                "waived": False,
                "waiver_reason": None,
                "settled_batch": None,
                "reversed": False,
                "reversal_id": None,
                "reversed_at": None,
                "_occurred": occurred,
            }
            self._sales[sale_id] = sale
            self._journal.append(
                {
                    "seq": seq,
                    "type": "sale",
                    "seller": seller,
                    "sale_id": sale_id,
                    "buyer": buyer,
                    "gross": gross,
                    "tax": tax,
                    "category": category,
                    "occurred_at": occurred_at,
                }
            )
            return {
                "status": "accrued",
                "sale_id": sale_id,
                "seller": seller,
                "buyer": buyer,
                "gross": gross,
                "tax": tax,
                "category": category,
                "occurred_at": occurred_at,
            }

    def pending(self, seller: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            return [self._public_sale(sale)
                    for sale in self._pending_records(seller)]

    # ------------------------------------------------------------------
    # Settlement
    # ------------------------------------------------------------------
    def settle(self, seller: str, upto: str, batch_id: str,
               limit: int | None = None) -> dict[str, Any]:
        with self._lock:
            existing_batch = self._batches.get(batch_id)
            if existing_batch is not None:
                return self._batch_duplicate(existing_batch)

            cutoff = self._parse_time(upto)
            budget = self._limit_value(self.batch_limit, limit)
            candidates = self._pending_records(seller, cutoff)
            selected = candidates[:budget]
            remaining = max(0, len(candidates) - len(selected))

            batch = self._build_batch(batch_id, seller, upto, selected)
            self._commit_batch(batch)
            return {
                "status": "settled",
                "batch_id": batch_id,
                "seller": seller,
                "settled": batch["settled"],
                "gross": batch["gross"],
                "tax": batch["tax"],
                "remaining": remaining,
                "sale_ids": list(batch["sale_ids"]),
                "allocations": copy.deepcopy(batch["allocations"]),
            }

    def settle_all(self, upto: str, batch_id: str,
                   limit: int | None = None) -> dict[str, Any]:
        with self._lock:
            existing_batch = self._batches.get(batch_id)
            if existing_batch is not None:
                return self._batch_duplicate(existing_batch)

            cutoff = self._parse_time(upto)
            budget = self._limit_value(self.batch_limit, limit)
            candidates = self._pending_records(None, cutoff)
            selected = candidates[:budget]
            remaining = max(0, len(candidates) - len(selected))

            batch = self._build_batch(batch_id, None, upto, selected)
            self._commit_batch(batch)
            return {
                "status": "settled",
                "batch_id": batch_id,
                "settled": batch["settled"],
                "gross": batch["gross"],
                "tax": batch["tax"],
                "remaining": remaining,
                "sale_ids": list(batch["sale_ids"]),
                "allocations": copy.deepcopy(batch["allocations"]),
            }

    def batches(self, seller: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            rows = []
            for batch in sorted(self._batches.values(),
                                key=lambda item: item["seq"]):
                if seller is not None:
                    if batch.get("seller") != seller and (
                            seller not in batch["allocations"]):
                        continue
                rows.append(copy.deepcopy(batch))
            return rows

    # ------------------------------------------------------------------
    # Waivers, reversals and payments
    # ------------------------------------------------------------------
    def waiver(self, seller: str, sale_id: str,
               reason: str) -> dict[str, Any]:
        with self._lock:
            sale = self._sales.get(sale_id)
            if sale is None:
                raise TaxError("TAX_SALE_NOT_FOUND", sale_id)
            if sale["seller"] != seller:
                raise TaxError("TAX_SALE_OWNER", sale_id)
            if sale["status"] == "settled":
                raise TaxError("TAX_ALREADY_SETTLED", sale_id)
            if sale["status"] != "pending":
                raise TaxError("TAX_SALE_NOT_FOUND", sale_id)
            if sale["waived"]:
                return {
                    "status": "duplicate",
                    "sale_id": sale_id,
                    "seller": seller,
                    "tax": 0,
                }

            previous_tax = sale["tax"]
            sale["waived"] = True
            sale["waiver_reason"] = reason
            sale["tax"] = 0
            seq = self._next_seq()
            self._journal.append(
                {
                    "seq": seq,
                    "type": "waiver",
                    "seller": seller,
                    "sale_id": sale_id,
                    "reason": reason,
                    "amount": -previous_tax,
                    "tax": 0,
                }
            )
            return {
                "status": "waived",
                "sale_id": sale_id,
                "seller": seller,
                "tax": 0,
                "reason": reason,
            }

    def reversal(self, sale_id: str, reversal_id: str,
                 at: str) -> dict[str, Any]:
        with self._lock:
            sale = self._sales.get(sale_id)
            if sale is None:
                raise TaxError("TAX_SALE_NOT_FOUND", sale_id)

            if sale.get("reversed"):
                previous = self._reversals.get(sale.get("reversal_id"))
                return {
                    "status": "duplicate",
                    "sale_id": sale_id,
                    "reversal_id": reversal_id,
                    "amount": 0 if previous is None else previous["amount"],
                }
            if reversal_id in self._reversals:
                return {
                    "status": "duplicate",
                    "sale_id": sale_id,
                    "reversal_id": reversal_id,
                    "amount": self._reversals[reversal_id]["amount"],
                }

            reversed_at = self._parse_time(at)
            if reversed_at < sale["_occurred"]:
                raise TaxError("TAX_BAD_ORDER", sale_id)

            seq = self._next_seq()
            if sale["status"] == "pending":
                sale["status"] = "voided"
                sale["reversed"] = True
                sale["reversal_id"] = reversal_id
                sale["reversed_at"] = at
                amount = 0
                status = "voided"
            else:
                sale["reversed"] = True
                sale["reversal_id"] = reversal_id
                sale["reversed_at"] = at
                amount = -sale["tax"]
                status = "adjusted"

            record = {
                "reversal_id": reversal_id,
                "sale_id": sale_id,
                "seller": sale["seller"],
                "amount": amount,
                "status": status,
                "at": at,
                "seq": seq,
            }
            self._reversals[reversal_id] = record
            self._journal.append(
                {
                    "seq": seq,
                    "type": "reversal",
                    "seller": sale["seller"],
                    "sale_id": sale_id,
                    "reversal_id": reversal_id,
                    "amount": amount,
                    "status": status,
                    "at": at,
                }
            )
            return {
                "status": status,
                "sale_id": sale_id,
                "reversal_id": reversal_id,
                "amount": amount,
            }

    def pay(self, seller: str, amount: int, payment_id: str,
            at: str) -> dict[str, Any]:
        with self._lock:
            existing = self._payments.get(payment_id)
            if existing is not None:
                totals = self._totals_unlocked(existing["seller"])
                return {
                    "status": "duplicate",
                    "payment_id": payment_id,
                    "seller": existing["seller"],
                    "amount": existing["amount"],
                    "at": existing["at"],
                    "paid": totals["paid"],
                    "outstanding": totals["outstanding"],
                }

            if (not isinstance(amount, int) or isinstance(amount, bool)
                    or amount <= 0):
                raise TaxError("TAX_BAD_AMOUNT", amount)
            self._parse_time(at)

            totals = self._totals_unlocked(seller)
            outstanding = totals["outstanding"]
            if amount > outstanding:
                raise TaxError(
                    "TAX_OVERPAY",
                    {"amount": amount, "outstanding": outstanding},
                )

            seq = self._next_seq()
            payment = {
                "payment_id": payment_id,
                "seller": seller,
                "amount": amount,
                "at": at,
                "seq": seq,
            }
            self._payments[payment_id] = payment
            self._journal.append(
                {
                    "seq": seq,
                    "type": "payment",
                    "seller": seller,
                    "payment_id": payment_id,
                    "amount": -amount,
                    "at": at,
                }
            )
            paid = totals["paid"] + amount
            return {
                "status": "paid",
                "payment_id": payment_id,
                "seller": seller,
                "amount": amount,
                "at": at,
                "paid": paid,
                "outstanding": outstanding - amount,
            }

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------
    def totals(self, seller: str) -> dict[str, Any]:
        with self._lock:
            return self._totals_unlocked(seller)

    def ledger(self, seller: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = [
                copy.deepcopy(entry)
                for entry in self._journal
                if entry.get("seller") == seller
            ]
            rows.sort(key=lambda entry: entry["seq"])
            return rows

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------
    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            sales = []
            for sale in sorted(self._sales.values(), key=lambda item: item["seq"]):
                row = {
                    key: copy.deepcopy(value)
                    for key, value in sale.items()
                    if not key.startswith("_")
                }
                sales.append(row)
            batches = [
                copy.deepcopy(batch)
                for batch in sorted(self._batches.values(),
                                    key=lambda item: item["seq"])
            ]
            reversals = [
                copy.deepcopy(self._reversals[key])
                for key in sorted(self._reversals,
                                  key=lambda item: self._reversals[item]["seq"])
            ]
            payments = [
                copy.deepcopy(self._payments[key])
                for key in sorted(self._payments,
                                  key=lambda item: self._payments[item]["seq"])
            ]
            return {
                "version": SNAPSHOT_VERSION,
                "config": {
                    "rate_bps": self.rate_bps,
                    "min_fee": self.min_fee,
                    "cap": self.cap,
                    "exempt_below": self.exempt_below,
                    "batch_limit": self.batch_limit,
                    "max_pending": self.max_pending,
                },
                "category_rates": copy.deepcopy(self._category_rates),
                "sales": sales,
                "batches": batches,
                "reversals": reversals,
                "payments": payments,
                "journal": copy.deepcopy(self._journal),
                "seq": self._seq,
            }

    def restore(self, payload: Mapping[str, Any]) -> None:
        if not isinstance(payload, MappingABC):
            raise TaxError("TAX_BAD_SNAPSHOT", "not-a-mapping")
        if payload.get("version") != SNAPSHOT_VERSION:
            raise TaxError("TAX_BAD_SNAPSHOT", payload.get("version"))

        try:
            config = payload["config"]
            category_rates = payload.get("category_rates", {})
            sale_rows = payload["sales"]
            batch_rows = payload["batches"]
            reversal_rows = payload["reversals"]
            payment_rows = payload["payments"]
            journal_rows = payload.get("journal", [])
            seq = payload.get("seq", 0)

            if not isinstance(config, MappingABC):
                raise ValueError("config")
            if not isinstance(category_rates, MappingABC):
                raise ValueError("category_rates")
            if not isinstance(sale_rows, list):
                raise ValueError("sales")
            if not isinstance(batch_rows, list):
                raise ValueError("batches")
            if not isinstance(reversal_rows, list):
                raise ValueError("reversals")
            if not isinstance(payment_rows, list):
                raise ValueError("payments")
            if not isinstance(journal_rows, list):
                raise ValueError("journal")
            if not isinstance(seq, int):
                raise ValueError("seq")

            new_config = {
                "rate_bps": int(config["rate_bps"]),
                "min_fee": int(config["min_fee"]),
                "cap": (None if config["cap"] is None
                        else int(config["cap"])),
                "exempt_below": int(config["exempt_below"]),
                "batch_limit": int(config["batch_limit"]),
                "max_pending": int(config["max_pending"]),
            }
            new_categories: dict[str, dict[str, int]] = {}
            for category, rule in category_rates.items():
                new_categories[str(category)] = {
                    "rate_bps": int(rule["rate_bps"]),
                    "exempt_below": int(rule["exempt_below"]),
                }

            new_sales: dict[str, dict[str, Any]] = {}
            for row in sale_rows:
                sale = copy.deepcopy(row)
                sale_id = sale["sale_id"]
                occurred = self._parse_time(sale.get("occurred_utc",
                                                     sale.get("occurred_at")))
                sale["_occurred"] = occurred
                sale.setdefault("waived", False)
                sale.setdefault("waiver_reason", None)
                sale.setdefault("settled_batch", None)
                sale.setdefault("reversed", False)
                sale.setdefault("reversal_id", None)
                sale.setdefault("reversed_at", None)
                new_sales[sale_id] = sale

            new_batches: dict[str, dict[str, Any]] = {}
            for row in batch_rows:
                batch = copy.deepcopy(row)
                new_batches[batch["batch_id"]] = batch

            new_reversals: dict[str, dict[str, Any]] = {}
            for row in reversal_rows:
                record = copy.deepcopy(row)
                new_reversals[record["reversal_id"]] = record

            new_payments: dict[str, dict[str, Any]] = {}
            for row in payment_rows:
                record = copy.deepcopy(row)
                new_payments[record["payment_id"]] = record

            new_journal = copy.deepcopy(journal_rows)
            highest_seq = max(
                [seq]
                + [sale["seq"] for sale in new_sales.values()]
                + [batch["seq"] for batch in new_batches.values()]
                + [record["seq"] for record in new_reversals.values()]
                + [record["seq"] for record in new_payments.values()],
                default=seq,
            )
            if highest_seq > seq:
                seq = highest_seq
        except (KeyError, TypeError, ValueError, TaxError):
            raise TaxError("TAX_BAD_SNAPSHOT", "malformed") from None

        with self._lock:
            self.rate_bps = new_config["rate_bps"]
            self.min_fee = new_config["min_fee"]
            self.cap = new_config["cap"]
            self.exempt_below = new_config["exempt_below"]
            self.batch_limit = new_config["batch_limit"]
            self.max_pending = new_config["max_pending"]
            self._category_rates = new_categories
            self._sales = new_sales
            self._batches = new_batches
            self._reversals = new_reversals
            self._payments = new_payments
            self._journal = new_journal
            self._seq = seq
