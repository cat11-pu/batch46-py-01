"""Multi-currency wallet: quoted exchange, frozen funds and settlement."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation, ROUND_FLOOR, ROUND_HALF_UP
import threading


class CurrencyError(ValueError):
    """Structured error carrying a machine readable code."""

    def __init__(self, code: str, detail=None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class CurrencyExchange:
    SNAPSHOT_VERSION = 1

    _CENT = Decimal("0.01")
    _RATE_PLACES = Decimal("0.00000001")

    def __init__(self, *, base_currency: str = "GOLD", fee_rate="0.005",
                 fee_min="0.01", quote_ttl: int = 60, max_quotes: int = 32) -> None:
        self._lock = threading.RLock()
        self.base_currency = self._currency(base_currency)
        self._fee_rate = self._decimal(fee_rate, "FX_BAD_CONFIG")
        self._fee_min = self._money(fee_min, "FX_BAD_CONFIG")
        self._quote_ttl = self._positive_int(quote_ttl, "FX_BAD_CONFIG",
                                             allow_zero=True)
        self._max_quotes = self._positive_int(max_quotes, "FX_BAD_CONFIG",
                                              allow_zero=True)
        if self._fee_rate < 0 or self._fee_min < 0:
            raise CurrencyError("FX_BAD_CONFIG")

        self._rates: dict = {}
        self._wallets: dict = {}
        self._freezes: dict = {}
        self._quotes: dict = {}
        self._history: list = []
        self._seq = 0

    def add_rate(self, base: str, quote: str, rate, *,
                 effective_at=None) -> dict:
        base = self._currency(base)
        quote = self._currency(quote)
        if base == quote:
            raise CurrencyError("FX_BAD_CURRENCY")
        value = self._decimal(rate, "FX_BAD_RATE")
        if value <= 0:
            raise CurrencyError("FX_BAD_RATE")
        effective = None
        if effective_at is not None:
            effective = self._iso(self._time(effective_at))
        with self._lock:
            self._rates[(base, quote)] = {
                "rate": value,
                "effective_at": effective,
            }
        return {
            "base": base,
            "quote": quote,
            "rate": value,
            "effective_at": effective,
        }

    def rate(self, base: str, quote: str) -> Decimal:
        base = self._currency(base)
        quote = self._currency(quote)
        with self._lock:
            return self._rate_unlocked(base, quote)

    def open_wallet(self, account_id: str, balances: dict | None = None) -> dict:
        if not isinstance(account_id, str) or not account_id:
            raise CurrencyError("FX_BAD_ACCOUNT")
        if balances is None:
            balances = {}
        if not isinstance(balances, dict):
            raise CurrencyError("FX_BAD_BALANCE")

        wallet = {}
        for currency, amount in balances.items():
            currency = self._currency(currency)
            value = self._money(amount, "FX_BAD_BALANCE")
            if value < 0 or value.is_signed():
                raise CurrencyError("FX_BAD_BALANCE")
            wallet[currency] = value

        with self._lock:
            if account_id in self._wallets:
                raise CurrencyError("FX_WALLET_EXISTS")
            self._wallets[account_id] = wallet
            return {
                "account_id": account_id,
                "balances": deepcopy(wallet),
            }

    def balance(self, account_id: str) -> dict:
        with self._lock:
            wallet = self._wallet_unlocked(account_id)
            return deepcopy(wallet)

    def available(self, account_id: str) -> dict:
        with self._lock:
            self._wallet_unlocked(account_id)
            return self._available_unlocked(account_id)

    def quote(self, account_id: str, from_currency: str, to_currency: str,
              amount, *, now=None) -> dict:
        with self._lock:
            self._wallet_unlocked(account_id)
            from_currency = self._currency(from_currency)
            to_currency = self._currency(to_currency)
            raw_amount = self._decimal(amount, "FX_BAD_AMOUNT")
            spent = self._money(raw_amount, "FX_BAD_AMOUNT", ROUND_FLOOR)
            if raw_amount <= 0 or spent <= 0:
                raise CurrencyError("FX_BAD_AMOUNT")

            rate = self._rate_unlocked(from_currency, to_currency)
            gross = self._money(spent * rate, "FX_BAD_AMOUNT", ROUND_FLOOR)
            if gross <= 0:
                raise CurrencyError("FX_BAD_AMOUNT")
            fee = self._money(gross * self._fee_rate, "FX_BAD_AMOUNT",
                              ROUND_HALF_UP)
            if fee < self._fee_min:
                fee = self._fee_min
            fee = min(fee, gross)
            received = gross - fee

            timestamp = self._time(now)
            self._expire_quotes_unlocked(account_id, timestamp)
            active = sum(
                1 for item in self._quotes.values()
                if item["account_id"] == account_id
                and item["status"] == "open"
                and self._parse_time(item["expires_at"]) > timestamp
            )
            if active >= self._max_quotes:
                raise CurrencyError("FX_QUOTE_LIMIT")

            self._seq += 1
            quote_id = f"q-{self._seq:010d}"
            record = {
                "quote_id": quote_id,
                "account_id": account_id,
                "from_currency": from_currency,
                "to_currency": to_currency,
                "spent": spent,
                "gross": gross,
                "fee": fee,
                "received": received,
                "rate": rate,
                "created_at": self._iso(timestamp),
                "expires_at": self._iso(timestamp + timedelta(
                    seconds=self._quote_ttl
                )),
                "used": False,
                "used_at": None,
                "status": "open",
            }
            self._quotes[quote_id] = record
            return self._quote_view(record)

    def exchange(self, account_id: str, quote_id: str, *, now=None) -> dict:
        with self._lock:
            wallet = self._wallet_unlocked(account_id)
            record = self._quotes.get(quote_id)
            if record is None:
                raise CurrencyError("FX_UNKNOWN_QUOTE")
            if record["account_id"] != account_id:
                raise CurrencyError("FX_QUOTE_OWNER")
            if record["used"] or record["status"] == "used":
                raise CurrencyError("FX_QUOTE_USED")

            timestamp = self._time(now)
            if (record["status"] == "expired"
                    or timestamp >= self._parse_time(record["expires_at"])):
                record["status"] = "expired"
                raise CurrencyError("FX_QUOTE_EXPIRED")

            available = self._available_unlocked(account_id)
            source = record["from_currency"]
            target = record["to_currency"]
            if available.get(source, Decimal("0.00")) < record["spent"]:
                raise CurrencyError("FX_INSUFFICIENT_FUNDS")

            wallet[source] = self._money(
                wallet[source] - record["spent"], "FX_BAD_BALANCE"
            )
            wallet[target] = self._money(
                wallet.get(target, Decimal("0.00")) + record["received"],
                "FX_BAD_BALANCE",
            )
            record["used"] = True
            record["used_at"] = self._iso(timestamp)
            record["status"] = "used"

            balance_after = deepcopy(wallet)
            movements = [
                {
                    "currency": source,
                    "delta": -record["spent"],
                    "balance_after": balance_after[source],
                },
                {
                    "currency": target,
                    "delta": record["received"],
                    "balance_after": balance_after[target],
                },
            ]
            self._record_history(
                "exchange",
                account_id,
                timestamp,
                quote_id=record["quote_id"],
                from_currency=source,
                to_currency=target,
                spent=record["spent"],
                gross=record["gross"],
                fee=record["fee"],
                received=record["received"],
                rate=record["rate"],
                movements=movements,
                balance_after=balance_after,
            )
            return {
                "status": "applied",
                "account_id": account_id,
                "quote_id": record["quote_id"],
                "from_currency": source,
                "to_currency": target,
                "spent": record["spent"],
                "received": record["received"],
                "fee": record["fee"],
                "rate": record["rate"],
            }

    def freeze(self, account_id: str, currency: str, amount, *,
               reason: str = "hold", now=None) -> dict:
        with self._lock:
            self._wallet_unlocked(account_id)
            currency = self._currency(currency)
            value = self._money(amount, "FX_BAD_AMOUNT", ROUND_HALF_UP)
            if value <= 0:
                raise CurrencyError("FX_BAD_AMOUNT")

            available = self._available_unlocked(account_id)
            if available.get(currency, Decimal("0.00")) < value:
                raise CurrencyError("FX_INSUFFICIENT_AVAILABLE")

            timestamp = self._time(now)
            self._seq += 1
            freeze_id = f"f-{self._seq:010d}"
            record = {
                "freeze_id": freeze_id,
                "account_id": account_id,
                "currency": currency,
                "amount": value,
                "reason": reason,
                "status": "open",
                "created_at": self._iso(timestamp),
                "closed_at": None,
            }
            self._freezes[freeze_id] = record
            return self._freeze_view(record)

    def release(self, freeze_id: str) -> dict:
        with self._lock:
            record = self._freezes.get(freeze_id)
            if record is None:
                raise CurrencyError("FX_UNKNOWN_FREEZE")
            if record["status"] != "open":
                raise CurrencyError("FX_FREEZE_CLOSED")

            timestamp = self._iso(self._time(None))
            record["status"] = "released"
            record["closed_at"] = timestamp
            result = self._freeze_view(record)
            result["status"] = "released"
            result["balance"] = self.balance(record["account_id"])[
                record["currency"]
            ]
            result["available"] = self.available(record["account_id"])[
                record["currency"]
            ]
            return result

    def settle(self, freeze_id: str, *, currency: str | None = None,
               amount=None, now=None) -> dict:
        with self._lock:
            record = self._freezes.get(freeze_id)
            if record is None:
                raise CurrencyError("FX_UNKNOWN_FREEZE")
            if record["status"] != "open":
                raise CurrencyError("FX_FREEZE_CLOSED")
            if currency is not None and currency != record["currency"]:
                raise CurrencyError("FX_CURRENCY_MISMATCH")
            if amount is not None:
                try:
                    requested = self._decimal(amount, "FX_AMOUNT_MISMATCH")
                except CurrencyError:
                    raise CurrencyError("FX_AMOUNT_MISMATCH") from None
                if requested != record["amount"]:
                    raise CurrencyError("FX_AMOUNT_MISMATCH")

            timestamp = self._time(now)
            wallet = self._wallet_unlocked(record["account_id"])
            frozen_currency = record["currency"]
            wallet[frozen_currency] = self._money(
                wallet[frozen_currency] - record["amount"], "FX_BAD_BALANCE"
            )
            record["status"] = "settled"
            record["closed_at"] = self._iso(timestamp)

            balance_after = deepcopy(wallet)
            movements = [{
                "currency": frozen_currency,
                "delta": -record["amount"],
                "balance_after": balance_after[frozen_currency],
            }]
            self._record_history(
                "settle",
                record["account_id"],
                timestamp,
                freeze_id=freeze_id,
                currency=frozen_currency,
                amount=record["amount"],
                movements=movements,
                balance_after=balance_after,
            )
            return {
                "status": "settled",
                "freeze_id": freeze_id,
                "account_id": record["account_id"],
                "currency": frozen_currency,
                "amount": record["amount"],
                "balance": balance_after[frozen_currency],
            }

    def history(self, account_id: str, limit: int = 10) -> list:
        with self._lock:
            self._wallet_unlocked(account_id)
            if not isinstance(limit, int) or isinstance(limit, bool):
                raise CurrencyError("FX_BAD_AMOUNT")
            if limit <= 0:
                return []
            rows = [
                item for item in self._history
                if item["account_id"] == account_id
            ]
            rows.sort(
                key=lambda item: (
                    self._parse_time(item["timestamp"]),
                    item["entry_id"],
                ),
                reverse=True,
            )
            return deepcopy(rows[:limit])

    def stats(self) -> dict:
        with self._lock:
            now = self._time(None)
            open_freezes = sum(
                1 for item in self._freezes.values()
                if item["status"] == "open"
            )
            active_quotes = sum(
                1 for item in self._quotes.values()
                if item["status"] == "open"
                and self._parse_time(item["expires_at"]) > now
            )
            return {
                "rates": len(self._rates),
                "wallets": len(self._wallets),
                "freezes": open_freezes,
                "open_freezes": open_freezes,
                "quotes": active_quotes,
                "history": len(self._history),
            }

    def snapshot(self) -> dict:
        with self._lock:
            state = {
                "version": self.SNAPSHOT_VERSION,
                "base_currency": self.base_currency,
                "fee_rate": self._fee_rate,
                "fee_min": self._fee_min,
                "quote_ttl": self._quote_ttl,
                "max_quotes": self._max_quotes,
                "seq": self._seq,
                "rates": [
                    {
                        "base": base,
                        "quote": quote,
                        "rate": entry["rate"],
                        "effective_at": entry["effective_at"],
                    }
                    for (base, quote), entry in self._rates.items()
                ],
                "wallets": deepcopy(self._wallets),
                "freezes": deepcopy(self._freezes),
                "quotes": deepcopy(self._quotes),
                "history": deepcopy(self._history),
            }
            return self._jsonable(state)

    def restore(self, state: dict) -> None:
        with self._lock:
            try:
                (
                    base_currency,
                    fee_rate,
                    fee_min,
                    quote_ttl,
                    max_quotes,
                    seq,
                    rates,
                    wallets,
                    freezes,
                    quotes,
                    history,
                ) = self._parse_snapshot(state)
            except (CurrencyError, KeyError, TypeError, ValueError,
                    InvalidOperation, OverflowError) as error:
                detail = getattr(error, "code", None) or str(error)
                raise CurrencyError("FX_BAD_SNAPSHOT", detail) from None

            self.base_currency = base_currency
            self._fee_rate = fee_rate
            self._fee_min = fee_min
            self._quote_ttl = quote_ttl
            self._max_quotes = max_quotes
            self._seq = seq
            self._rates = rates
            self._wallets = wallets
            self._freezes = freezes
            self._quotes = quotes
            self._history = history

    def _rate_unlocked(self, base: str, quote: str) -> Decimal:
        if base == quote:
            return Decimal("1")
        direct = self._rates.get((base, quote))
        if direct is not None:
            return direct["rate"]
        reverse = self._rates.get((quote, base))
        if reverse is not None:
            return self._inverse(reverse["rate"])
        if base != self.base_currency and quote != self.base_currency:
            left = self._base_pair_unlocked(self.base_currency, base)
            right = self._base_pair_unlocked(self.base_currency, quote)
            if left is not None and right is not None:
                return (right / left).quantize(
                    self._RATE_PLACES, rounding=ROUND_HALF_UP
                )
        raise CurrencyError("FX_UNKNOWN_RATE", (base, quote))

    def _base_pair_unlocked(self, base: str, quote: str):
        if base == quote:
            return Decimal("1")
        direct = self._rates.get((base, quote))
        if direct is not None:
            return direct["rate"]
        reverse = self._rates.get((quote, base))
        if reverse is not None:
            return self._inverse(reverse["rate"])
        return None

    def _inverse(self, value: Decimal) -> Decimal:
        return (Decimal("1") / value).quantize(
            self._RATE_PLACES, rounding=ROUND_HALF_UP
        )

    def _wallet_unlocked(self, account_id: str) -> dict:
        wallet = self._wallets.get(account_id)
        if wallet is None:
            raise CurrencyError("FX_UNKNOWN_ACCOUNT", account_id)
        return wallet

    def _available_unlocked(self, account_id: str) -> dict:
        wallet = self._wallet_unlocked(account_id)
        held = {}
        for item in self._freezes.values():
            if item["account_id"] == account_id and item["status"] == "open":
                currency = item["currency"]
                held[currency] = held.get(currency, Decimal("0.00")) + item["amount"]
        result = {}
        for currency, amount in wallet.items():
            result[currency] = self._money(
                amount - held.get(currency, Decimal("0.00")),
                "FX_BAD_BALANCE",
            )
        return result

    def _expire_quotes_unlocked(self, account_id: str, now: datetime) -> None:
        for item in self._quotes.values():
            if (item["account_id"] == account_id
                    and item["status"] == "open"
                    and self._parse_time(item["expires_at"]) <= now):
                item["status"] = "expired"

    def _record_history(self, kind: str, account_id: str,
                        timestamp: datetime, **fields) -> dict:
        self._seq += 1
        entry = {
            "entry_id": f"h-{self._seq:010d}",
            "type": kind,
            "timestamp": self._iso(timestamp),
            "account_id": account_id,
        }
        entry.update(fields)
        self._history.append(entry)
        return entry

    def _quote_view(self, record: dict) -> dict:
        result = deepcopy(record)
        result["amount"] = result["spent"]
        result["net"] = result["received"]
        return result

    def _freeze_view(self, record: dict) -> dict:
        return deepcopy(record)

    def _parse_snapshot(self, state: dict):
        if not isinstance(state, dict):
            raise ValueError("snapshot")
        required = {
            "version", "base_currency", "fee_rate", "fee_min", "quote_ttl",
            "max_quotes", "seq", "rates", "wallets", "freezes", "quotes",
            "history",
        }
        if set(state.keys()) != required:
            raise ValueError("fields")
        version = state["version"]
        if type(version) is not int or version != self.SNAPSHOT_VERSION:
            raise ValueError("version")

        base_currency = self._currency(state["base_currency"])
        fee_rate = self._decimal(state["fee_rate"], "snapshot")
        fee_min = self._snapshot_money(state["fee_min"])
        quote_ttl = self._positive_int(state["quote_ttl"], "snapshot",
                                       allow_zero=True)
        max_quotes = self._positive_int(state["max_quotes"], "snapshot",
                                        allow_zero=True)
        if fee_rate < 0 or fee_min < 0:
            raise ValueError("config")
        seq = state["seq"]
        if type(seq) is not int or seq < 0:
            raise ValueError("seq")

        if not isinstance(state["rates"], list):
            raise ValueError("rates")
        rates = {}
        for item in state["rates"]:
            if not isinstance(item, dict):
                raise ValueError("rate")
            base = self._currency(item["base"])
            quote = self._currency(item["quote"])
            if base == quote or (base, quote) in rates:
                raise ValueError("rate")
            value = self._decimal(item["rate"], "snapshot")
            if value <= 0:
                raise ValueError("rate")
            effective_at = item.get("effective_at")
            if effective_at is not None:
                effective_at = self._iso(self._time(effective_at))
            rates[(base, quote)] = {
                "rate": value,
                "effective_at": effective_at,
            }

        if not isinstance(state["wallets"], dict):
            raise ValueError("wallets")
        wallets = {}
        for account_id, balances in state["wallets"].items():
            if not isinstance(account_id, str) or not account_id:
                raise ValueError("account")
            if account_id in wallets or not isinstance(balances, dict):
                raise ValueError("wallet")
            wallet = {}
            for currency, amount in balances.items():
                currency = self._currency(currency)
                if currency in wallet:
                    raise ValueError("currency")
                wallet[currency] = self._snapshot_money(amount)
            wallets[account_id] = wallet

        if not isinstance(state["freezes"], dict):
            raise ValueError("freezes")
        freezes = {}
        for freeze_id, item in state["freezes"].items():
            if not isinstance(freeze_id, str) or not freeze_id:
                raise ValueError("freeze")
            if freeze_id in freezes or not isinstance(item, dict):
                raise ValueError("freeze")
            account_id = item["account_id"]
            if account_id not in wallets:
                raise ValueError("freeze account")
            currency = self._currency(item["currency"])
            if currency not in wallets[account_id]:
                raise ValueError("freeze currency")
            amount = self._snapshot_money(item["amount"])
            if amount <= 0:
                raise ValueError("freeze amount")
            status = item["status"]
            if status not in {"open", "released", "settled"}:
                raise ValueError("freeze status")
            created_at = self._iso(self._time(item["created_at"]))
            closed_at = item.get("closed_at")
            if closed_at is not None:
                closed_at = self._iso(self._time(closed_at))
            if status == "open" and closed_at is not None:
                raise ValueError("freeze closed")
            if status != "open" and closed_at is None:
                raise ValueError("freeze closed")
            reason = item.get("reason", "hold")
            if not isinstance(reason, str):
                raise ValueError("freeze reason")
            freezes[freeze_id] = {
                "freeze_id": freeze_id,
                "account_id": account_id,
                "currency": currency,
                "amount": amount,
                "reason": reason,
                "status": status,
                "created_at": created_at,
                "closed_at": closed_at,
            }

        held = {}
        for item in freezes.values():
            if item["status"] == "open":
                key = (item["account_id"], item["currency"])
                held[key] = held.get(key, Decimal("0.00")) + item["amount"]
        for (account_id, currency), amount in held.items():
            if amount > wallets[account_id][currency]:
                raise ValueError("freeze balance")

        if not isinstance(state["quotes"], dict):
            raise ValueError("quotes")
        quotes = {}
        for quote_id, item in state["quotes"].items():
            if not isinstance(quote_id, str) or not quote_id:
                raise ValueError("quote")
            if quote_id in quotes or not isinstance(item, dict):
                raise ValueError("quote")
            account_id = item["account_id"]
            if account_id not in wallets:
                raise ValueError("quote account")
            from_currency = self._currency(item["from_currency"])
            to_currency = self._currency(item["to_currency"])
            if from_currency not in wallets[account_id]:
                raise ValueError("quote currency")
            spent = self._snapshot_money(item["spent"])
            gross = self._snapshot_money(item["gross"])
            fee = self._snapshot_money(item["fee"])
            received = self._snapshot_money(item["received"])
            rate = self._decimal(item["rate"], "snapshot")
            if (spent <= 0 or gross <= 0 or rate <= 0 or fee < 0
                    or received < 0 or received != gross - fee):
                raise ValueError("quote amounts")
            used = item["used"]
            if type(used) is not bool:
                raise ValueError("quote used")
            status = item["status"]
            if status not in {"open", "used", "expired"}:
                raise ValueError("quote status")
            if used != (status == "used"):
                raise ValueError("quote status")
            created_at = self._iso(self._time(item["created_at"]))
            expires_at = self._iso(self._time(item["expires_at"]))
            if self._parse_time(expires_at) <= self._parse_time(created_at):
                raise ValueError("quote expiry")
            used_at = item.get("used_at")
            if used_at is not None:
                used_at = self._iso(self._time(used_at))
            if used and used_at is None:
                raise ValueError("quote used_at")
            quotes[quote_id] = {
                "quote_id": quote_id,
                "account_id": account_id,
                "from_currency": from_currency,
                "to_currency": to_currency,
                "spent": spent,
                "gross": gross,
                "fee": fee,
                "received": received,
                "rate": rate,
                "created_at": created_at,
                "expires_at": expires_at,
                "used": used,
                "used_at": used_at,
                "status": status,
            }

        if not isinstance(state["history"], list):
            raise ValueError("history")
        history = []
        for item in state["history"]:
            if not isinstance(item, dict):
                raise ValueError("history")
            entry_id = item["entry_id"]
            kind = item["type"]
            account_id = item["account_id"]
            if not isinstance(entry_id, str) or not entry_id:
                raise ValueError("history id")
            if account_id not in wallets:
                raise ValueError("history account")
            timestamp = self._iso(self._time(item["timestamp"]))
            movements = []
            if not isinstance(item["movements"], list):
                raise ValueError("movements")
            for movement in item["movements"]:
                if not isinstance(movement, dict):
                    raise ValueError("movement")
                currency = self._currency(movement["currency"])
                delta = self._snapshot_signed_money(movement["delta"])
                balance_after = self._snapshot_money(
                    movement["balance_after"]
                )
                movements.append({
                    "currency": currency,
                    "delta": delta,
                    "balance_after": balance_after,
                })
            balance_after = {}
            if not isinstance(item["balance_after"], dict):
                raise ValueError("balance_after")
            for currency, amount in item["balance_after"].items():
                currency = self._currency(currency)
                balance_after[currency] = self._snapshot_money(amount)
            parsed = {
                "entry_id": entry_id,
                "type": kind,
                "timestamp": timestamp,
                "account_id": account_id,
                "movements": movements,
                "balance_after": balance_after,
            }
            if kind == "exchange":
                parsed.update({
                    "quote_id": item["quote_id"],
                    "from_currency": self._currency(item["from_currency"]),
                    "to_currency": self._currency(item["to_currency"]),
                    "spent": self._snapshot_money(item["spent"]),
                    "gross": self._snapshot_money(item["gross"]),
                    "fee": self._snapshot_money(item["fee"]),
                    "received": self._snapshot_money(item["received"]),
                    "rate": self._decimal(item["rate"], "snapshot"),
                })
            elif kind == "settle":
                parsed.update({
                    "freeze_id": item["freeze_id"],
                    "currency": self._currency(item["currency"]),
                    "amount": self._snapshot_money(item["amount"]),
                })
            else:
                raise ValueError("history type")
            history.append(parsed)

        return (
            base_currency, fee_rate, fee_min, quote_ttl, max_quotes, seq,
            rates, wallets, freezes, quotes, history,
        )

    @staticmethod
    def _currency(value) -> str:
        if not isinstance(value, str) or not value:
            raise CurrencyError("FX_BAD_CURRENCY")
        return value

    @staticmethod
    def _decimal(value, code: str) -> Decimal:
        if isinstance(value, bool) or isinstance(value, float):
            value = str(value)
        try:
            result = value if isinstance(value, Decimal) else Decimal(value)
        except (InvalidOperation, TypeError, ValueError):
            raise CurrencyError(code) from None
        if not result.is_finite():
            raise CurrencyError(code)
        return result

    def _money(self, value, code: str,
               rounding=ROUND_HALF_UP) -> Decimal:
        result = self._decimal(value, code)
        return result.quantize(self._CENT, rounding=rounding)

    def _snapshot_money(self, value) -> Decimal:
        if not isinstance(value, str):
            raise ValueError("amount")
        result = self._money(value, "snapshot")
        if result < 0 or result != self._decimal(value, "snapshot"):
            raise ValueError("amount")
        return result

    def _snapshot_signed_money(self, value) -> Decimal:
        if not isinstance(value, str):
            raise ValueError("amount")
        result = self._money(value, "snapshot")
        if result != self._decimal(value, "snapshot"):
            raise ValueError("amount")
        return result

    @staticmethod
    def _positive_int(value, code: str, *, allow_zero: bool = False) -> int:
        if type(value) is not int or value < 0 or (value == 0 and not allow_zero):
            raise CurrencyError(code)
        return value

    @staticmethod
    def _time(value) -> datetime:
        if value is None:
            return datetime.now(timezone.utc)
        if isinstance(value, datetime):
            result = value
        elif isinstance(value, (int, float)) and not isinstance(value, bool):
            result = datetime.fromtimestamp(value, timezone.utc)
        elif isinstance(value, str):
            text = value.strip()
            if text.endswith("Z"):
                text = text[:-1] + "+00:00"
            result = datetime.fromisoformat(text)
        else:
            raise CurrencyError("FX_BAD_TIME")
        if result.tzinfo is None:
            result = result.replace(tzinfo=timezone.utc)
        return result.astimezone(timezone.utc)

    @classmethod
    def _parse_time(cls, value) -> datetime:
        return cls._time(value)

    @staticmethod
    def _iso(value: datetime) -> str:
        return value.astimezone(timezone.utc).isoformat()

    @classmethod
    def _jsonable(cls, value):
        if isinstance(value, Decimal):
            return format(value, "f")
        if isinstance(value, dict):
            return {key: cls._jsonable(item) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [cls._jsonable(item) for item in value]
        return value
