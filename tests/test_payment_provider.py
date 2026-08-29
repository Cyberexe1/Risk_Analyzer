"""Payment provider adapter tests.

WHAT THESE PROVE, AND WHAT THEY DO NOT
--------------------------------------
These tests exercise `payments.py` and its wiring into `backend.py`. Every
Razorpay interaction runs against a MOCKED client. No test in this file opens a
socket, and none of them requires a Razorpay account, a key, or Test Mode
credentials -- this project has none.

So these tests establish that the ADAPTER is correct: that it converts amounts to
paise, forwards our order id, maps provider statuses onto our vocabulary, and --
most importantly -- that no provider failure can ever be reported as a successful
payment. They do NOT establish that Razorpay accepts the payload, because that can
only be shown by running it against a live account.

The properties worth the most here are the negative ones:
  - a provider timeout, 4xx, 5xx or malformed body yields PENDING, never SUCCESS
  - an `authorized` payment is PENDING: money held is not money taken
  - a BLOCK never reaches the provider at all
  - a provider error never reaches the customer's response body
  - /health names the running provider and leaks no key material

Run:  python -m pytest tests/test_payment_provider.py -v
"""
from __future__ import annotations

import os
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

os.environ["FRAUDSHIELD_USERS_BACKEND"] = "memory"
os.environ["FRAUDSHIELD_WARM_ROWS"] = "0"
os.environ["FRAUDSHIELD_DEV_SEED_STAFF"] = "0"
os.environ["FRAUDSHIELD_JWT_SECRET"] = "test-only-jwt-secret-payments"
os.environ["FRAUDSHIELD_IP_PEPPER"] = "test-only-pepper-payments"
os.environ.pop("FRAUDSHIELD_API_KEY", None)

from fastapi.testclient import TestClient  # noqa: E402

import backend  # noqa: E402
import payments  # noqa: E402

PW = "payment-provider-test-password-8823"
CARD = {"number": "4111 1111 1111 1111", "expiry_month": 12,
        "expiry_year": 2029, "cvv": "123", "holder": "Provider Tester"}
P_ALLOW = ("p1", 2499.0)


# ---------------------------------------------------------------------------
# fakes
# ---------------------------------------------------------------------------

class FakeOrderResource:
    def __init__(self, response=None, raises=None):
        self._response = response
        self._raises = raises
        self.calls: list[dict] = []

    def create(self, data=None):
        self.calls.append(data or {})
        if self._raises is not None:
            raise self._raises
        return self._response


class FakePaymentResource:
    def __init__(self, response=None, raises=None):
        self._response = response
        self._raises = raises
        self.calls: list[str] = []

    def fetch(self, payment_id):
        self.calls.append(payment_id)
        if self._raises is not None:
            raise self._raises
        return self._response


class FakeClient:
    """Stands in for razorpay.Client. Never touches the network."""

    def __init__(self, order=None, payment=None):
        self.order = order or FakeOrderResource(response={"id": "order_FAKE123"})
        self.payment = payment or FakePaymentResource(response={})
        self.app_details: list[dict] = []

    def set_app_details(self, details):
        self.app_details.append(details)


def rp(client=None, key_id="rzp_test_fake", key_secret="fake_secret"):
    return payments.RazorpayProvider(key_id=key_id, key_secret=key_secret,
                                     client=client)


# =============================================================================
# 1. status and event mapping
# =============================================================================

def test_captured_is_success():
    assert payments.settlement_from_payment_status("captured") == \
        payments.SETTLED_SUCCESS


def test_failed_status_is_failed():
    assert payments.settlement_from_payment_status("failed") == \
        payments.SETTLED_FAILED


def test_authorized_is_pending_not_success():
    """Money held is not money taken.

    If `authorized` mapped to success, an auto-capture that later failed would
    already have been recorded as a completed sale, and nothing downstream would
    ever revisit it.
    """
    assert payments.settlement_from_payment_status("authorized") == \
        payments.SETTLED_PENDING


@pytest.mark.parametrize("status", ["created", "pending"])
def test_unresolved_statuses_are_pending(status):
    assert payments.settlement_from_payment_status(status) == \
        payments.SETTLED_PENDING


@pytest.mark.parametrize("status", ["", None, "COMPLETELY_MADE_UP", "succeeded", 42])
def test_unknown_status_never_becomes_success(status):
    """The fail-safe direction. An uninterpretable state is unresolved, not paid."""
    assert payments.settlement_from_payment_status(status) != \
        payments.SETTLED_SUCCESS
    assert payments.settlement_from_payment_status(status) == \
        payments.SETTLED_PENDING


def test_status_mapping_is_case_and_whitespace_insensitive():
    assert payments.settlement_from_payment_status("  CAPTURED ") == \
        payments.SETTLED_SUCCESS


def test_event_mapping_matches_the_webhook_vocabulary():
    assert payments.settlement_from_event("payment.captured") == \
        payments.SETTLED_SUCCESS
    assert payments.settlement_from_event("payment.failed") == \
        payments.SETTLED_FAILED
    assert payments.settlement_from_event("payment.authorized") == \
        payments.SETTLED_PENDING


@pytest.mark.parametrize("event", ["", None, "order.paid", "refund.created"])
def test_unknown_event_never_becomes_success(event):
    assert payments.settlement_from_event(event) == payments.SETTLED_PENDING


def test_emi_methods_map_to_card_rather_than_being_dropped():
    """emi and cardless_emi are card-funded. Dropping them would lose the
    transaction from the entity graph entirely, which is worse than a coarse
    label."""
    assert payments.method_from_provider("emi") == "card"
    assert payments.method_from_provider("cardless_emi") == "card"
    assert payments.method_from_provider("cash") == "cod"


@pytest.mark.parametrize("method", ["", None, "bharat_qr", "paylater"])
def test_unknown_method_falls_back_to_the_default(method):
    assert payments.method_from_provider(method) == "card"
    assert payments.method_from_provider(method, default="upi") == "upi"


def test_backend_webhook_map_is_the_shared_table():
    """One definition, not two. A second copy is how `authorized` eventually gets
    read differently in two code paths."""
    assert backend.WEBHOOK_METHOD_MAP is payments.RAZORPAY_METHOD


# =============================================================================
# 2. amount conversion
# =============================================================================

def test_rupees_to_paise_rounds_rather_than_truncates():
    """int(2499.0 * 100) can land on 249899 for values that are not exactly
    representable in binary floating point, which silently undercharges."""
    assert payments.to_minor_units(2499.0) == 249900
    assert payments.to_minor_units(27499.0) == 2749900
    assert payments.to_minor_units(0.01) == 1
    assert payments.to_minor_units(1.005) in (100, 101)   # rounding, not truncation


def test_paise_to_rupees_round_trips():
    for rupees in (2499.0, 27499.0, 42999.0, 0.01, 199.99):
        assert payments.from_minor_units(payments.to_minor_units(rupees)) == rupees


def test_webhook_amount_conversion_is_the_shared_helper():
    assert payments.from_minor_units(249900) == 2499.0


# =============================================================================
# 3. metadata forwarding
# =============================================================================

def test_metadata_forwards_device_and_ip_when_present():
    notes = payments.authorise_metadata(
        customer_id="cust_1",
        metadata={"device_fp": "dev_abc", "ip_hash": "ip_abc"})
    assert notes == {"customer_id": "cust_1", "device_fp": "dev_abc",
                     "ip_hash": "ip_abc"}


@pytest.mark.parametrize("metadata", [None, {}, {"device_fp": "", "ip_hash": None}])
def test_metadata_omits_absent_signals_instead_of_inventing_them(metadata):
    """A fabricated device fingerprint fuses unrelated accounts into a fake
    cluster; a fabricated IP attributes the provider's own address to a customer.
    A missing key is the honest representation, and `signals_complete: false`
    already carries it."""
    notes = payments.authorise_metadata(customer_id="cust_1", metadata=metadata)
    assert notes == {"customer_id": "cust_1"}
    assert "device_fp" not in notes and "ip_hash" not in notes


def test_metadata_values_are_bounded():
    """Razorpay caps note values at 256 characters."""
    notes = payments.authorise_metadata(
        customer_id="cust_1", metadata={"device_fp": "d" * 5000})
    assert len(notes["device_fp"]) == 256


# =============================================================================
# 4. simulated provider
# =============================================================================

def test_simulated_provider_delegates_to_the_injected_function():
    """The decline model must have exactly one implementation. This provider
    delegates to backend.simulate_authorisation rather than copying it."""
    seen: list[tuple] = []

    def fake_authorise(method, amount, decision):
        seen.append((method, amount, decision))
        return payments.SETTLED_FAILED

    sim = payments.SimulatedProvider(fake_authorise)
    out = sim.authorise(order_id="ord_1", amount=2499.0, method="card",
                        decision="ALLOW", customer_id="cust_1")
    assert seen == [("card", 2499.0, "ALLOW")]
    assert out.settlement == payments.SETTLED_FAILED
    assert out.provider == "simulated"
    assert out.provider_order_id is None
    assert out.ok


def test_simulated_provider_only_ever_returns_resolved_settlements():
    """No pending from the simulator: it answers synchronously, so an unresolved
    state would be meaningless."""
    sim = payments.SimulatedProvider(backend.simulate_authorisation)
    for _ in range(200):
        out = sim.authorise(order_id="ord_x", amount=2499.0, method="card",
                            decision="ALLOW", customer_id="cust_1")
        assert out.settlement in (payments.SETTLED_SUCCESS,
                                  payments.SETTLED_FAILED)


def test_simulated_provider_is_always_configured():
    assert payments.SimulatedProvider(backend.simulate_authorisation).is_configured()


def test_simulated_provider_has_no_payment_to_reconcile():
    got = payments.SimulatedProvider(
        backend.simulate_authorisation).fetch_payment("pay_x")
    assert got.settlement == payments.SETTLED_PENDING
    assert not got.ok
    assert got.error


# =============================================================================
# 5. Razorpay adapter -- authorise
# =============================================================================

def test_block_never_reaches_the_provider():
    """A refused sale must not create a real provider order."""
    client = FakeClient()
    out = rp(client).authorise(order_id="ord_1", amount=42999.0, method="card",
                               decision="BLOCK", customer_id="cust_1")
    assert client.order.calls == []
    assert out.settlement == payments.SETTLED_FAILED
    assert out.provider_order_id is None


def test_successful_order_creation_is_pending_not_success():
    """Creating an order means the provider is ready to accept a payment. It does
    not mean one happened. Settlement arrives later by webhook."""
    client = FakeClient(order=FakeOrderResource(response={"id": "order_ABC999"}))
    out = rp(client).authorise(order_id="ord_real1", amount=2499.0, method="card",
                               decision="ALLOW", customer_id="cust_1")
    assert out.settlement == payments.SETTLED_PENDING
    assert out.settlement != payments.SETTLED_SUCCESS
    assert out.provider_order_id == "order_ABC999"
    assert out.provider == "razorpay"
    assert out.ok


def test_authorise_sends_paise_inr_and_our_order_id_as_receipt():
    client = FakeClient()
    rp(client).authorise(order_id="ord_real2", amount=27499.0, method="card",
                        decision="ALLOW", customer_id="cust_7",
                        metadata={"device_fp": "dev_1", "ip_hash": "ip_1"})
    sent = client.order.calls[0]
    assert sent["amount"] == 2749900
    assert sent["currency"] == "INR"
    assert sent["receipt"] == "ord_real2"
    assert sent["notes"] == {"customer_id": "cust_7", "device_fp": "dev_1",
                             "ip_hash": "ip_1"}


@pytest.mark.parametrize("failure", [
    TimeoutError("read timeout"),
    ConnectionError("dns failure"),
    RuntimeError("BAD_REQUEST_ERROR: amount must be at least 100"),
    Exception("500 from provider"),
])
def test_any_provider_failure_is_unresolved_never_successful(failure):
    """The single most important property in this file. A network failure, a 4xx
    and a 5xx all leave the payment unresolved -- none of them may be reported as
    taken money."""
    client = FakeClient(order=FakeOrderResource(raises=failure))
    out = rp(client).authorise(order_id="ord_1", amount=2499.0, method="card",
                               decision="ALLOW", customer_id="cust_1")
    assert out.settlement == payments.SETTLED_PENDING
    assert out.settlement != payments.SETTLED_SUCCESS
    assert not out.ok
    assert out.error


def test_provider_error_does_not_carry_the_exception_message():
    """Only the exception TYPE is surfaced. Provider exception text can carry
    request context, and it is not something a payer or a log reader needs."""
    client = FakeClient(order=FakeOrderResource(
        raises=RuntimeError("secret-ish request id 0xDEADBEEF")))
    out = rp(client).authorise(order_id="ord_1", amount=2499.0, method="card",
                               decision="ALLOW", customer_id="cust_1")
    assert "0xDEADBEEF" not in (out.error or "")
    assert "RuntimeError" in out.error


@pytest.mark.parametrize("response", [None, {}, {"no_id": True}, "order_ABC", 7])
def test_malformed_provider_response_is_unresolved(response):
    client = FakeClient(order=FakeOrderResource(response=response))
    out = rp(client).authorise(order_id="ord_1", amount=2499.0, method="card",
                               decision="ALLOW", customer_id="cust_1")
    assert out.settlement == payments.SETTLED_PENDING
    assert not out.ok


def test_unconfigured_adapter_makes_no_call_and_reports_unresolved():
    out = payments.RazorpayProvider(key_id="", key_secret="").authorise(
        order_id="ord_1", amount=2499.0, method="card", decision="ALLOW",
        customer_id="cust_1")
    assert out.settlement == payments.SETTLED_PENDING
    assert not out.ok
    assert "RAZORPAY_KEY_ID" in out.error


def test_is_configured_requires_both_halves_of_the_credential():
    assert not payments.RazorpayProvider("", "").is_configured()
    assert not payments.RazorpayProvider("rzp_test_x", "").is_configured()
    assert not payments.RazorpayProvider("", "secret").is_configured()
    assert payments.RazorpayProvider("rzp_test_x", "secret").is_configured()


# =============================================================================
# 6. Razorpay adapter -- SDK loading
# =============================================================================

def test_missing_sdk_is_reported_as_a_configuration_problem(monkeypatch):
    """Deterministic whether or not the SDK is installed: a None entry in
    sys.modules makes `import razorpay` raise ImportError."""
    monkeypatch.setitem(sys.modules, "razorpay", None)
    with pytest.raises(payments.ProviderError) as exc:
        payments.RazorpayProvider("rzp_test_x", "secret").client()
    assert "pip install razorpay" in str(exc.value)


def test_client_is_built_lazily_and_identifies_itself(monkeypatch):
    """Constructed on first use only, mirroring the lazy boto3 import in
    DynamoUserStore, so the simulated default needs no Razorpay dependency."""
    built: list[tuple] = []
    fake = FakeClient()

    def Client(auth):                                    # noqa: N802
        built.append(auth)
        return fake

    module = types.SimpleNamespace(Client=Client)
    monkeypatch.setitem(sys.modules, "razorpay", module)

    provider = payments.RazorpayProvider("rzp_test_x", "secret")
    assert built == []                                   # nothing built yet
    got = provider.client()
    assert got is fake
    assert built == [("rzp_test_x", "secret")]
    assert fake.app_details and fake.app_details[0]["title"] == "FraudShield"
    assert provider.client() is fake                     # cached, built once
    assert len(built) == 1


def test_sdk_construction_failure_is_a_provider_error(monkeypatch):
    def Client(auth):                                    # noqa: N802
        raise ValueError("bad auth tuple")

    monkeypatch.setitem(sys.modules, "razorpay",
                        types.SimpleNamespace(Client=Client))
    with pytest.raises(payments.ProviderError):
        payments.RazorpayProvider("rzp_test_x", "secret").client()


# =============================================================================
# 7. Razorpay adapter -- fetch_payment
# =============================================================================

def test_fetch_payment_normalises_a_provider_payment():
    client = FakeClient(payment=FakePaymentResource(response={
        "id": "pay_ABC", "order_id": "order_ABC", "status": "captured",
        "amount": 249900, "method": "emi",
        "notes": {"device_fp": "dev_1", "ip_hash": "ip_1"},
    }))
    got = rp(client).fetch_payment("pay_ABC")
    assert got.settlement == payments.SETTLED_SUCCESS
    assert got.amount == 2499.0
    assert got.method == "card"
    assert got.raw_status == "captured"
    assert got.provider_order_id == "order_ABC"
    assert got.notes == {"device_fp": "dev_1", "ip_hash": "ip_1"}
    assert got.ok


def test_fetch_payment_of_an_authorized_payment_is_pending():
    client = FakeClient(payment=FakePaymentResource(response={
        "id": "pay_ABC", "status": "authorized", "amount": 249900}))
    assert rp(client).fetch_payment("pay_ABC").settlement == \
        payments.SETTLED_PENDING


@pytest.mark.parametrize("response,raises", [
    (None, None),
    ("not a dict", None),
    (None, TimeoutError("read timeout")),
    (None, RuntimeError("404 not found")),
])
def test_fetch_payment_failure_is_unresolved_never_successful(response, raises):
    client = FakeClient(payment=FakePaymentResource(response=response,
                                                   raises=raises))
    got = rp(client).fetch_payment("pay_ABC")
    assert got.settlement == payments.SETTLED_PENDING
    assert not got.ok


def test_no_refund_method_is_exposed():
    """FraudShield records return requests (`request_return` writes
    `under_review`) and never moves money, so a refund adapter would make the
    interface look more capable than the product is."""
    assert not hasattr(payments.RazorpayProvider, "refund")
    assert not hasattr(payments.SimulatedProvider, "refund")
    assert not hasattr(payments.PaymentProvider, "refund")


# =============================================================================
# 8. provider selection
# =============================================================================

def test_default_selection_is_the_simulator():
    provider, st = payments.resolve_provider(
        "", authorise_fn=backend.simulate_authorisation)
    assert isinstance(provider, payments.SimulatedProvider)
    assert st["payment_provider"] == "simulated"
    assert st["degraded"] is False
    assert st["razorpay_configured"] is False


def test_razorpay_selected_only_when_asked_for_explicitly():
    """Credentials alone must never switch providers: a key left in a shell
    profile would otherwise redirect live checkout traffic."""
    provider, st = payments.resolve_provider(
        "simulated", authorise_fn=backend.simulate_authorisation,
        key_id="rzp_test_x", key_secret="secret")
    assert isinstance(provider, payments.SimulatedProvider)
    assert st["payment_provider"] == "simulated"
    assert st["razorpay_configured"] is True     # present, deliberately unused
    assert st["degraded"] is False


def test_razorpay_selected_when_asked_for_and_configured():
    provider, st = payments.resolve_provider(
        "RAZORPAY", authorise_fn=backend.simulate_authorisation,
        key_id="rzp_test_x", key_secret="secret")
    assert isinstance(provider, payments.RazorpayProvider)
    assert st["payment_provider"] == "razorpay"
    assert st["degraded"] is False
    assert "never been exercised against a live" in st["note"]


def test_razorpay_without_credentials_degrades_to_the_simulator():
    """Falls back rather than crashing startup or failing every checkout -- and
    says so loudly instead of pretending Razorpay is live."""
    provider, st = payments.resolve_provider(
        "razorpay", authorise_fn=backend.simulate_authorisation)
    assert isinstance(provider, payments.SimulatedProvider)
    assert st["payment_provider"] == "simulated"
    assert st["requested_provider"] == "razorpay"
    assert st["degraded"] is True
    assert "RAZORPAY_KEY_ID" in st["note"]


def test_unknown_provider_degrades_to_the_simulator():
    provider, st = payments.resolve_provider(
        "stripe", authorise_fn=backend.simulate_authorisation)
    assert isinstance(provider, payments.SimulatedProvider)
    assert st["degraded"] is True
    assert "stripe" in st["note"]


def test_status_never_contains_key_material():
    """/health publishes this dict verbatim."""
    _, st = payments.resolve_provider(
        "razorpay", authorise_fn=backend.simulate_authorisation,
        key_id="rzp_test_SECRETID", key_secret="SUPER_SECRET_VALUE")
    blob = repr(st)
    assert "rzp_test_SECRETID" not in blob
    assert "SUPER_SECRET_VALUE" not in blob
    assert st["razorpay_configured"] is True


def test_config_is_read_from_the_documented_variable_names(monkeypatch):
    monkeypatch.setenv("FRAUDSHIELD_PAYMENT_PROVIDER", "razorpay")
    monkeypatch.setenv("RAZORPAY_KEY_ID", "rzp_test_env")
    monkeypatch.setenv("RAZORPAY_KEY_SECRET", "env_secret")
    cfg = payments.provider_config_from_env()
    assert cfg == {"requested": "razorpay", "key_id": "rzp_test_env",
                   "key_secret": "env_secret"}


# =============================================================================
# 9. backend wiring
# =============================================================================

@pytest.fixture
def memory_stores(monkeypatch):
    """Never touch a real DynamoDB table, whatever .env says."""
    records = backend.InMemoryRecordStore()
    users = backend.InMemoryUserStore()
    monkeypatch.setattr(backend, "USERS_BACKEND", "memory")
    monkeypatch.setattr(backend, "make_record_store",
                        lambda: (records, "memory:payments-test"))
    monkeypatch.setattr(backend, "make_user_store",
                        lambda: (users, "memory:payments-test"))
    monkeypatch.setattr(backend, "API_KEY", "")
    return records


def register(c, email: str) -> dict:
    r = c.post("/v1/auth/register", json={"email": email, "password": PW})
    assert r.status_code == 201, r.text
    return {"authorization": f"Bearer {r.json()['access_token']}"}


def place(c, headers, product=P_ALLOW):
    return c.post("/v1/orders", headers=headers, json={
        "items": [{"product_id": product[0], "qty": 1}],
        "payment_method": "card", "device_fp": "dev_payments_test",
        "card": CARD,
    })


class StubProvider:
    """A provider with a fixed answer, injected into a running app."""

    name = "razorpay"

    def __init__(self, order: payments.ProviderOrder):
        self._order = order
        self.calls: list[dict] = []

    def is_configured(self) -> bool:
        return True

    def authorise(self, **kwargs) -> payments.ProviderOrder:
        self.calls.append(kwargs)
        return self._order

    def fetch_payment(self, provider_payment_id):    # pragma: no cover
        raise AssertionError("not used")


def test_default_app_runs_the_simulator(memory_stores):
    with TestClient(backend.app) as c:
        assert isinstance(backend.STATE["payment_provider"],
                          payments.SimulatedProvider)
        h = register(c, f"sim-{os.urandom(4).hex()}@example.com")
        body = place(c, h).json()
        # Unchanged storefront behaviour: the simulator resolves synchronously.
        assert body["settlement"] in ("success", "failed")


def test_checkout_passes_our_order_id_amount_and_signals_to_the_provider(
        memory_stores):
    stub = StubProvider(payments.ProviderOrder(
        provider="razorpay", settlement=payments.SETTLED_PENDING,
        provider_order_id="order_STUB1"))
    with TestClient(backend.app) as c:
        backend.STATE["payment_provider"] = stub
        h = register(c, f"pass-{os.urandom(4).hex()}@example.com")
        body = place(c, h).json()

    call = stub.calls[0]
    assert call["order_id"] == body["order_id"]
    assert call["amount"] == P_ALLOW[1]
    assert call["method"] == "card"
    assert call["decision"] in ("ALLOW", "MANUAL_REVIEW", "BLOCK")
    assert call["metadata"]["device_fp"] == "dev_payments_test"
    assert call["metadata"]["ip_hash"]              # derived server-side


def test_pending_settlement_shows_the_customer_verifying_not_confirmed(
        memory_stores):
    """The failure this whole seam exists to prevent: an unresolved provider
    payment must not be presented as a completed order."""
    stub = StubProvider(payments.ProviderOrder(
        provider="razorpay", settlement=payments.SETTLED_PENDING,
        provider_order_id="order_STUB2"))
    with TestClient(backend.app) as c:
        backend.STATE["payment_provider"] = stub
        h = register(c, f"pend-{os.urandom(4).hex()}@example.com")
        body = place(c, h).json()
        assert body["settlement"] == "pending"
        assert body["status"] == "verifying"
        assert body["status"] != "confirmed"
        # And the persisted order agrees.
        one = c.get(f"/v1/orders/{body['order_id']}", headers=h).json()
        assert one["status"] == "verifying"


def test_pending_settlement_records_no_failed_attempt(memory_stores):
    """Unresolved is not declined. Counting it as a failure would inflate the
    IP failure rate and could flag an address on payments still in flight."""
    stub = StubProvider(payments.ProviderOrder(
        provider="razorpay", settlement=payments.SETTLED_PENDING))
    with TestClient(backend.app) as c:
        backend.STATE["payment_provider"] = stub
        h = register(c, f"nofail-{os.urandom(4).hex()}@example.com")
        place(c, h)
        assert backend.STATE["fail_ips"] == set()


def test_provider_error_is_never_shown_to_the_customer(memory_stores):
    stub = StubProvider(payments.ProviderOrder(
        provider="razorpay", settlement=payments.SETTLED_PENDING,
        error="Razorpay order.create failed: TimeoutError"))
    with TestClient(backend.app) as c:
        backend.STATE["payment_provider"] = stub
        h = register(c, f"err-{os.urandom(4).hex()}@example.com")
        body = place(c, h).json()

    blob = repr(body)
    assert "TimeoutError" not in blob
    assert "Razorpay" not in blob
    assert "risk" not in body                       # customer role, no risk block


def test_provider_error_is_visible_to_staff(memory_stores):
    stub = StubProvider(payments.ProviderOrder(
        provider="razorpay", settlement=payments.SETTLED_PENDING,
        error="Razorpay order.create failed: TimeoutError"))
    with TestClient(backend.app) as c:
        backend.STATE["payment_provider"] = stub
        email = f"staff-{os.urandom(4).hex()}@example.com"
        h = register(c, email)
        backend.STATE["users"].get_by_email(email).role = "analyst"
        body = place(c, h).json()

    assert body["risk"]["provider"] == "razorpay"
    assert "TimeoutError" in body["risk"]["provider_error"]


def test_provider_ids_are_stored_alongside_ours_not_instead_of_them(
        memory_stores):
    """Two systems, two identifiers. Collapsing them would make the internal model
    provider-shaped and unrecoverable if the provider ever changed."""
    stub = StubProvider(payments.ProviderOrder(
        provider="razorpay", settlement=payments.SETTLED_PENDING,
        provider_order_id="order_STUB3"))
    with TestClient(backend.app) as c:
        backend.STATE["payment_provider"] = stub
        h = register(c, f"ids-{os.urandom(4).hex()}@example.com")
        body = place(c, h).json()
        order_id = body["order_id"]
        idx = memory_stores.get("INDEX#ORDER", order_id)
        stored = memory_stores.get(f"CUSTOMER#{idx['customer_id']}", idx["sk"])

    assert order_id.startswith("ord_")               # ours, unchanged
    assert stored["order_id"] == order_id
    assert stored["transaction_id"].startswith("pay_")
    assert stored["provider"] == "razorpay"
    assert stored["provider_order_id"] == "order_STUB3"
    assert stored["settlement"] == "pending"
    assert stored["customer_status"] == "verifying"


def test_health_reports_the_running_provider_without_leaking_keys(memory_stores,
                                                                  monkeypatch):
    monkeypatch.setattr(backend, "PAYMENT_PROVIDER", "razorpay")
    monkeypatch.setattr(backend, "RAZORPAY_KEY_ID", "rzp_test_HEALTHID")
    monkeypatch.setattr(backend, "RAZORPAY_KEY_SECRET", "HEALTH_SECRET_VALUE")
    with TestClient(backend.app) as c:
        h = c.get("/health").json()

    assert h["payment_provider"] == "razorpay"
    assert h["razorpay_configured"] is True
    assert h["payment_provider_status"]["degraded"] is False
    blob = repr(h)
    assert "rzp_test_HEALTHID" not in blob
    assert "HEALTH_SECRET_VALUE" not in blob


def test_health_reports_degradation_when_razorpay_is_unconfigured(memory_stores,
                                                                 monkeypatch):
    monkeypatch.setattr(backend, "PAYMENT_PROVIDER", "razorpay")
    monkeypatch.setattr(backend, "RAZORPAY_KEY_ID", "")
    monkeypatch.setattr(backend, "RAZORPAY_KEY_SECRET", "")
    with TestClient(backend.app) as c:
        h = c.get("/health").json()

    assert h["payment_provider"] == "simulated"
    assert h["razorpay_configured"] is False
    assert h["payment_provider_status"]["degraded"] is True


# =============================================================================
# 10. webhook secret fallback -- an alternative source, not a weaker check
# =============================================================================

def test_fraudshield_webhook_secret_wins_over_the_razorpay_one(monkeypatch):
    monkeypatch.setattr(backend, "WEBHOOK_SECRET", "fraudshield-one")
    monkeypatch.setattr(backend, "RAZORPAY_WEBHOOK_SECRET", "razorpay-one")
    assert backend.webhook_secret() == "fraudshield-one"


def test_razorpay_webhook_secret_is_accepted_as_a_fallback(monkeypatch):
    monkeypatch.setattr(backend, "WEBHOOK_SECRET", "")
    monkeypatch.setattr(backend, "RAZORPAY_WEBHOOK_SECRET", "razorpay-one")
    assert backend.webhook_secret() == "razorpay-one"


def test_neither_secret_still_means_webhooks_are_refused(memory_stores,
                                                        monkeypatch):
    """The fail-closed control is unchanged. This must stay a 503, not a 200."""
    monkeypatch.setattr(backend, "WEBHOOK_SECRET", "")
    monkeypatch.setattr(backend, "RAZORPAY_WEBHOOK_SECRET", "")
    with TestClient(backend.app) as c:
        r = c.post("/v1/webhooks/payment", content=b"{}",
                   headers={"x-razorpay-signature": "whatever"})
    assert r.status_code == 503
