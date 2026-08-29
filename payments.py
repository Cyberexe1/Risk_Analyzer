"""Payment provider abstraction.

WHY THIS MODULE EXISTS
----------------------
FraudShield's risk engine must not know or care which payment provider is in
front of it. Before this module, `create_order` called `simulate_authorisation()`
directly, so wiring in a real provider meant editing the order path itself.

The seam was already in the right place -- settlement is decided AFTER scoring,
server-side, from a single call site -- so this formalises that seam rather than
moving it.

    FraudShield order request
            v
    validation + Scorer.score()      <-- unchanged, stays in backend.py
            v
    PaymentProvider.authorise()      <-- this module
       /                  \\
    Simulated           Razorpay
                            v
                     Razorpay Test Mode API

WHAT THIS MODULE DOES NOT DO
----------------------------
No risk scoring. No feature building. No persistence. No audit. Providers speak
to providers; FraudShield decides risk. Mixing the two is how a provider outage
turns into a scoring bug.

HONEST STATUS
-------------
`RazorpayProvider` is a real adapter against the official SDK's documented
surface, exercised in tests against a mocked client. It has NEVER been run
against a live Razorpay account, because this project has no Razorpay business
account and therefore no test credentials. Nothing here fabricates that.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Protocol

# ---------------------------------------------------------------------------
# internal vocabulary
# ---------------------------------------------------------------------------
#
# These are FraudShield's OWN settlement values, not any provider's. The first
# two already existed and are unchanged; PENDING is new and is explained below.

SETTLED_SUCCESS = "success"
SETTLED_FAILED = "failed"

# A payment that has been created with the provider but not yet resolved.
#
# This value is new, and it is added reluctantly. It exists because a real
# provider's settlement is ASYNCHRONOUS: creating a Razorpay order tells you
# nothing about whether the customer will complete the payment, and the answer
# arrives later by webhook. The simulator answers immediately, so it never needs
# this.
#
# The alternative -- reporting `success` at order-creation time -- would be the
# exact failure this whole module is meant to prevent. So an unresolved payment
# is PENDING, and the customer sees the existing "verifying" state, which already
# means "we don't know yet, a human or a callback will resolve it".
SETTLED_PENDING = "pending"

VALID_SETTLEMENTS = (SETTLED_SUCCESS, SETTLED_FAILED, SETTLED_PENDING)


# ---------------------------------------------------------------------------
# provider status mapping -- ONE place, deliberately
# ---------------------------------------------------------------------------
#
# Provider status strings appear in exactly one table so they cannot leak into
# business logic. Anything not listed here is UNKNOWN, and unknown never becomes
# a successful payment.

# Razorpay payment entity `status` values, per their documented lifecycle.
RAZORPAY_PAYMENT_STATUS = {
    "captured": SETTLED_SUCCESS,
    # Authorised but not captured: money is held, not taken. Treated as
    # unresolved rather than successful -- an auto-capture failure would
    # otherwise silently read as a completed sale.
    "authorized": SETTLED_PENDING,
    "created": SETTLED_PENDING,
    "pending": SETTLED_PENDING,
    "failed": SETTLED_FAILED,
    "refunded": SETTLED_SUCCESS,      # it was captured before it was refunded
}

# Razorpay webhook event names.
RAZORPAY_EVENT_STATUS = {
    "payment.captured": SETTLED_SUCCESS,
    "payment.failed": SETTLED_FAILED,
    "payment.authorized": SETTLED_PENDING,
}

# Provider method names -> the five payment methods this model was trained on.
# `emi` and `cardless_emi` are card-funded, so they map to card rather than being
# dropped: silently discarding an event would lose a transaction from the graph.
RAZORPAY_METHOD = {
    "card": "card", "emi": "card", "cardless_emi": "card",
    "upi": "upi", "netbanking": "netbanking",
    "wallet": "wallet", "cod": "cod", "cash": "cod",
}


def settlement_from_payment_status(status: str | None) -> str:
    """Map a provider payment status onto an internal settlement.

    Unknown, absent or malformed input returns PENDING, never SUCCESS. A payment
    whose state we cannot interpret is unresolved by definition, and treating it
    as taken money is the one outcome that cannot be walked back.
    """
    if not status or not isinstance(status, str):
        return SETTLED_PENDING
    return RAZORPAY_PAYMENT_STATUS.get(status.strip().lower(), SETTLED_PENDING)


def settlement_from_event(event: str | None) -> str:
    """Map a provider webhook event name onto an internal settlement."""
    if not event or not isinstance(event, str):
        return SETTLED_PENDING
    return RAZORPAY_EVENT_STATUS.get(event.strip().lower(), SETTLED_PENDING)


def method_from_provider(method: str | None, default: str = "card") -> str:
    """Map a provider method name onto one of the five modelled methods."""
    if not method or not isinstance(method, str):
        return default
    return RAZORPAY_METHOD.get(method.strip().lower(), default)


def to_minor_units(rupees: float) -> int:
    """Rupees -> paise. Providers quote amounts in the currency's minor unit.

    Rounded, not truncated: int(2499.0 * 100) can land on 249899 for values that
    are not exactly representable in binary floating point, which would quietly
    undercharge by a paisa.
    """
    return int(round(float(rupees) * 100))


def from_minor_units(paise: int | float) -> float:
    """Paise -> rupees."""
    return round(float(paise) / 100.0, 2)


# ---------------------------------------------------------------------------
# results
# ---------------------------------------------------------------------------

@dataclass
class ProviderOrder:
    """The outcome of asking a provider to register an order.

    `provider_order_id` is kept strictly separate from FraudShield's own
    `order_id`. They are different identifiers owned by different systems, and
    collapsing them would make the internal model provider-shaped.
    """

    provider: str
    settlement: str
    provider_order_id: str | None = None
    provider_payment_id: str | None = None
    # Set when the provider could not be reached or gave an answer we could not
    # interpret. Never leaks to a customer; surfaced to analysts and logs.
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


@dataclass
class ProviderPayment:
    """A normalised view of a provider payment, for reconciliation."""

    provider: str
    settlement: str
    provider_payment_id: str | None = None
    provider_order_id: str | None = None
    amount: float | None = None
    method: str | None = None
    raw_status: str | None = None
    notes: dict = field(default_factory=dict)
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


class ProviderError(Exception):
    """A provider could not be used. Carries an operator-facing reason only."""


# ---------------------------------------------------------------------------
# interface
# ---------------------------------------------------------------------------

class PaymentProvider(Protocol):
    """Only the operations this application actually performs.

    Deliberately absent: refund(). FraudShield records return requests
    (`request_return` writes `status: "under_review"`) and never moves money, so
    a refund method would be an unused stub that made the interface look more
    capable than the product is.
    """

    name: str

    def is_configured(self) -> bool: ...

    def authorise(self, *, order_id: str, amount: float, method: str,
                  decision: str, customer_id: str,
                  metadata: dict | None = None) -> ProviderOrder: ...

    def fetch_payment(self, provider_payment_id: str) -> ProviderPayment: ...


# ---------------------------------------------------------------------------
# simulated provider -- unchanged behaviour
# ---------------------------------------------------------------------------

class SimulatedProvider:
    """The existing stand-in gateway, moved behind the interface.

    The decline model is byte-for-byte what `simulate_authorisation()` has always
    done, and that function remains in backend.py as the single implementation --
    this delegates to it rather than copying the arithmetic, so the two can never
    drift.
    """

    name = "simulated"

    def __init__(self, authorise_fn):
        # Injected rather than imported to avoid a circular import: backend.py
        # imports this module, so this module must not import backend.py.
        self._authorise_fn = authorise_fn

    def is_configured(self) -> bool:
        return True

    def authorise(self, *, order_id: str, amount: float, method: str,
                  decision: str, customer_id: str,
                  metadata: dict | None = None) -> ProviderOrder:
        settled = self._authorise_fn(method, amount, decision)
        return ProviderOrder(provider=self.name, settlement=settled)

    def fetch_payment(self, provider_payment_id: str) -> ProviderPayment:
        # The simulator has no provider-side record to reconcile against.
        return ProviderPayment(
            provider=self.name, settlement=SETTLED_PENDING,
            provider_payment_id=provider_payment_id,
            error="the simulated provider holds no server-side payment records",
        )


# ---------------------------------------------------------------------------
# Razorpay provider
# ---------------------------------------------------------------------------

class RazorpayProvider:
    """Adapter for Razorpay Test Mode.

    NOT VERIFIED AGAINST A LIVE ACCOUNT. This project has no Razorpay business
    account, so there are no test credentials to run it with. It is written
    against the SDK's documented surface and tested against a mocked client. That
    distinction is stated here, in the README, and on /health rather than being
    glossed over.

    The SDK is imported lazily, the same way DynamoUserStore imports boto3, so
    the serving image does not need a dependency for a provider that may never be
    configured.
    """

    name = "razorpay"

    def __init__(self, key_id: str = "", key_secret: str = "", client=None,
                 timeout: int = 15):
        self.key_id = key_id or ""
        self.key_secret = key_secret or ""
        self.timeout = timeout
        # Injectable for tests. Nothing here ever constructs a real network
        # client unless credentials are present.
        self._client = client
        self._init_error: str | None = None

    # ---- configuration --------------------------------------------------

    def is_configured(self) -> bool:
        """Credentials present. Says nothing about whether they are valid --
        only a real API call can establish that."""
        return bool(self.key_id and self.key_secret)

    def client(self):
        """The SDK client, built on first use.

        Raises ProviderError with an operator-facing reason. Never raises the
        SDK's own exception upward, because those can carry request context.
        """
        if self._client is not None:
            return self._client
        if not self.is_configured():
            raise ProviderError(
                "Razorpay credentials are not configured "
                "(RAZORPAY_KEY_ID / RAZORPAY_KEY_SECRET)")
        try:
            import razorpay  # noqa: PLC0415  -- lazy on purpose, see class docs
        except ImportError:
            raise ProviderError(
                "the razorpay SDK is not installed; run: pip install razorpay"
            ) from None
        try:
            c = razorpay.Client(auth=(self.key_id, self.key_secret))
            # Identify ourselves, which is what Razorpay asks integrations to do.
            if hasattr(c, "set_app_details"):
                c.set_app_details({"title": "FraudShield", "version": "0.4.0"})
            self._client = c
            return c
        except Exception as exc:  # noqa: BLE001
            raise ProviderError(
                f"could not construct the Razorpay client: {type(exc).__name__}"
            ) from None

    # ---- operations -----------------------------------------------------

    def authorise(self, *, order_id: str, amount: float, method: str,
                  decision: str, customer_id: str,
                  metadata: dict | None = None) -> ProviderOrder:
        """Register the order with Razorpay.

        Returns PENDING on success, not SUCCESS: creating an order means the
        provider is ready to accept a payment, not that one has happened.
        Settlement arrives later by webhook.

        A BLOCK never reaches the provider at all. Sending a transaction we have
        already decided to refuse would be pointless traffic and would create a
        real provider order for a sale that is not going to happen.
        """
        if decision == "BLOCK":
            return ProviderOrder(provider=self.name, settlement=SETTLED_FAILED)

        try:
            client = self.client()
        except ProviderError as exc:
            return self._unresolved(str(exc))

        # `receipt` carries OUR order id, which is how a provider order is traced
        # back to a FraudShield order. Razorpay treats it as an idempotency-ish
        # reference on their dashboard; it does not replace our identifier.
        payload = {
            "amount": to_minor_units(amount),
            "currency": "INR",
            "receipt": order_id,
            # Razorpay caps notes at 15 keys / 256 chars per value. Only the
            # fields the risk engine needs are forwarded, and only if the caller
            # actually has them -- see the metadata note in authorise_metadata.
            "notes": authorise_metadata(customer_id=customer_id,
                                        metadata=metadata),
        }

        try:
            resp = client.order.create(data=payload)
        except Exception as exc:  # noqa: BLE001
            # Network failure, timeout, 4xx and 5xx all land here. None of them
            # may become a successful payment, and none of the exception text
            # reaches a customer.
            return self._unresolved(
                f"Razorpay order.create failed: {type(exc).__name__}")

        if not isinstance(resp, dict) or not resp.get("id"):
            return self._unresolved(
                "Razorpay order.create returned a malformed response")

        return ProviderOrder(provider=self.name, settlement=SETTLED_PENDING,
                             provider_order_id=str(resp["id"]))

    def fetch_payment(self, provider_payment_id: str) -> ProviderPayment:
        """Read a payment back from the provider, for reconciliation."""
        try:
            client = self.client()
        except ProviderError as exc:
            return ProviderPayment(provider=self.name,
                                   settlement=SETTLED_PENDING,
                                   provider_payment_id=provider_payment_id,
                                   error=str(exc))
        try:
            resp = client.payment.fetch(provider_payment_id)
        except Exception as exc:  # noqa: BLE001
            return ProviderPayment(
                provider=self.name, settlement=SETTLED_PENDING,
                provider_payment_id=provider_payment_id,
                error=f"Razorpay payment.fetch failed: {type(exc).__name__}")

        if not isinstance(resp, dict):
            return ProviderPayment(
                provider=self.name, settlement=SETTLED_PENDING,
                provider_payment_id=provider_payment_id,
                error="Razorpay payment.fetch returned a malformed response")

        raw_status = resp.get("status")
        notes = resp.get("notes") if isinstance(resp.get("notes"), dict) else {}
        amount = resp.get("amount")
        return ProviderPayment(
            provider=self.name,
            settlement=settlement_from_payment_status(raw_status),
            provider_payment_id=str(resp.get("id") or provider_payment_id),
            provider_order_id=(str(resp["order_id"])
                               if resp.get("order_id") else None),
            amount=from_minor_units(amount) if amount is not None else None,
            method=method_from_provider(resp.get("method")),
            raw_status=raw_status if isinstance(raw_status, str) else None,
            notes=notes,
        )

    # `refund()` is intentionally not implemented. See PaymentProvider.

    def _unresolved(self, reason: str) -> ProviderOrder:
        """A provider problem leaves the payment UNRESOLVED, never successful."""
        return ProviderOrder(provider=self.name, settlement=SETTLED_PENDING,
                             error=reason)


# ---------------------------------------------------------------------------
# metadata forwarding
# ---------------------------------------------------------------------------

def authorise_metadata(*, customer_id: str, metadata: dict | None) -> dict:
    """Build provider `notes` from what the caller genuinely has.

    A webhook arrives from the PROVIDER's servers, not the payer's browser, so a
    device fingerprint and a client IP cannot be recovered at that point. The only
    honest way for those signals to survive the round trip is for the merchant to
    forward them at order-creation time, which is what this does.

    Absent values are OMITTED, never filled in. Inventing a device fingerprint
    would either fuse unrelated accounts into a fake cluster or split one actor
    across several; inventing an IP would attribute the provider's own address to
    a customer. Both are worse than a missing signal, which the existing
    `signals_complete: false` already represents faithfully.
    """
    notes: dict[str, str] = {"customer_id": str(customer_id)}
    for key in ("device_fp", "ip_hash"):
        value = (metadata or {}).get(key)
        if value:
            notes[key] = str(value)[:256]
    return notes


# ---------------------------------------------------------------------------
# selection
# ---------------------------------------------------------------------------

PROVIDER_SIMULATED = "simulated"
PROVIDER_RAZORPAY = "razorpay"


def resolve_provider(
    requested: str,
    *,
    authorise_fn,
    key_id: str = "",
    key_secret: str = "",
) -> tuple[object, dict]:
    """Pick a provider from explicit configuration.

    Returns (provider, status) where `status` is safe to publish on /health --
    it names the mode and whether credentials exist, and contains no secret.

    Selection is EXPLICIT. Razorpay is never switched on merely because two
    environment variables happen to be set: a stray key in a shell profile must
    not silently redirect real checkout traffic at a payment provider. And if
    Razorpay is asked for but not configured, the service falls back to the
    simulator and says so loudly rather than failing every checkout.
    """
    requested = (requested or PROVIDER_SIMULATED).strip().lower()
    sim = SimulatedProvider(authorise_fn)

    status = {
        "payment_provider": PROVIDER_SIMULATED,
        "requested_provider": requested,
        "razorpay_configured": bool(key_id and key_secret),
        "degraded": False,
        "note": "",
    }

    if requested == PROVIDER_RAZORPAY:
        rp = RazorpayProvider(key_id=key_id, key_secret=key_secret)
        if rp.is_configured():
            status["payment_provider"] = PROVIDER_RAZORPAY
            status["note"] = (
                "Razorpay credentials present. This adapter has never been "
                "exercised against a live Razorpay account."
            )
            return rp, status
        status["degraded"] = True
        status["note"] = (
            "PAYMENT_PROVIDER=razorpay but RAZORPAY_KEY_ID / "
            "RAZORPAY_KEY_SECRET are unset. Falling back to the simulator."
        )
        return sim, status

    if requested != PROVIDER_SIMULATED:
        status["degraded"] = True
        status["note"] = (
            f"unknown PAYMENT_PROVIDER={requested!r}; using the simulator"
        )
        return sim, status

    status["note"] = "simulated gateway; no external payment provider is called"
    return sim, status


def provider_config_from_env() -> dict:
    """Read provider configuration.

    Naming follows the two conventions already in this repository: FraudShield's
    own settings are FRAUDSHIELD_-prefixed, while third-party credentials use the
    vendor's standard names, exactly as AWS_ACCESS_KEY_ID already does.
    """
    return {
        "requested": os.environ.get("FRAUDSHIELD_PAYMENT_PROVIDER",
                                    PROVIDER_SIMULATED),
        "key_id": os.environ.get("RAZORPAY_KEY_ID", ""),
        "key_secret": os.environ.get("RAZORPAY_KEY_SECRET", ""),
    }
