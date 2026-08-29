"""Bounded automated-action policy and per-decision audit completeness.

TWO PROPERTIES, ONE FILE
------------------------
1. The automation is BOUNDED. It refuses payments and it queues them for people.
   It does not conclude anything about a customer. The single inference this suite
   exists to forbid:

       BLOCK != FRAUD

   A BLOCK means the score crossed the configured block threshold and the payment
   was refused. It is not a finding, not a label, and not an accusation. Only a
   human can create ground truth, through a separate audited action.

2. Every real decision is AUDITED, exactly once. Three scoring entry points
   (storefront order, webhook ingestion, service scoring) and every decision band
   must each produce exactly one RISK_DECISION -- no gaps, no duplicates.

   The one deliberate exception is a dry run. `commit=false` is documented as a
   preview that applies nothing to entity state; auditing it would fill the
   decision log with transactions that never happened and break the equality
   between "decisions taken" and "RISK_DECISION events".

Run:  python -m pytest tests/test_action_policy.py -v
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

WEBHOOK_SECRET = "test-only-webhook-secret-action-policy"
os.environ["FRAUDSHIELD_USERS_BACKEND"] = "memory"
os.environ["FRAUDSHIELD_WARM_ROWS"] = "0"
os.environ["FRAUDSHIELD_DEV_SEED_STAFF"] = "0"
os.environ["FRAUDSHIELD_JWT_SECRET"] = "test-only-jwt-secret-action-policy"
os.environ["FRAUDSHIELD_IP_PEPPER"] = "test-only-pepper-action-policy"
os.environ["FRAUDSHIELD_WEBHOOK_SECRET"] = WEBHOOK_SECRET
os.environ.pop("FRAUDSHIELD_API_KEY", None)

from fastapi.testclient import TestClient  # noqa: E402

import backend  # noqa: E402
import payments  # noqa: E402

PW = "action-policy-test-password-9042"

CARD = {"number": "4111 1111 1111 1111", "expiry_month": 12,
        "expiry_year": 2029, "cvv": "123", "holder": "Policy Tester"}

P_ALLOW = ("p1", 2499.0)
P_REVIEW = ("p10", 27499.0)
P_BLOCK = ("p3", 42999.0)


def _decision_for(amount: float) -> backend.Decision:
    if amount >= 40000:
        decision, score = "BLOCK", 91.4
    elif amount >= 20000:
        decision, score = "MANUAL_REVIEW", 47.2
    else:
        decision, score = "ALLOW", 3.1
    return backend.Decision(
        risk_score=score, decision=decision,
        sub_scores={"ml": score * 0.7, "rules": score * 0.2, "network": 0.0},
        reason_codes=[], fired_rules=[], override=None,
        model_version="test-model-1", degraded=False,
    )


@pytest.fixture
def pinned_scorer(monkeypatch):
    """Pin the decision by amount. Weights, thresholds and rules untouched."""
    def fake_score(self, store, txn):
        return _decision_for(float(txn["amount"])), {"amount": float(txn["amount"])}

    monkeypatch.setattr(backend.Scorer, "score", fake_score)


@pytest.fixture
def db(monkeypatch):
    records = backend.InMemoryRecordStore()
    users = backend.InMemoryUserStore()
    monkeypatch.setattr(backend, "USERS_BACKEND", "memory")
    monkeypatch.setattr(backend, "make_record_store",
                        lambda: (records, "memory:shared-test"))
    monkeypatch.setattr(backend, "make_user_store",
                        lambda: (users, "memory:shared-test"))
    monkeypatch.setattr(backend, "API_KEY", "")
    monkeypatch.setattr(backend, "WEBHOOK_SECRET", WEBHOOK_SECRET)
    return records


@contextmanager
def app_run():
    with TestClient(backend.app) as c:
        yield c


def register(c, email: str) -> dict:
    r = c.post("/v1/auth/register", json={"email": email, "password": PW})
    assert r.status_code == 201, r.text
    return {"authorization": f"Bearer {r.json()['access_token']}"}


def staff(c, tag: str, role: str = "admin") -> dict:
    email = f"{tag}-{uuid.uuid4().hex[:8]}@example.com"
    h = register(c, email)
    backend.STATE["users"].get_by_email(email).role = role
    return h


def order(c, headers, product):
    r = c.post("/v1/orders", headers=headers, json={
        "items": [{"product_id": product[0], "qty": 1}],
        "payment_method": "card", "device_fp": "dev_policy_test", "card": CARD,
    })
    assert r.status_code == 201, r.text
    return r.json()


def risk_events(source: str | None = None) -> list[dict]:
    rows = [e for e in backend.STATE["audit"]
            if e["action"] == backend.RISK_DECISION]
    if source is not None:
        rows = [e for e in rows if e["before"].get("source") == source]
    return rows


def signed_event(*, status="captured", amount_paise=249900):
    pid = f"pay_{uuid.uuid4().hex[:12]}"
    eid = f"evt_{uuid.uuid4().hex[:12]}"
    body = {
        "id": eid, "entity": "event", "event": f"payment.{status}",
        "created_at": time.time(),
        "payload": {"payment": {"entity": {
            "id": pid, "amount": amount_paise, "currency": "INR",
            "status": status, "method": "card",
            "email": f"payer-{uuid.uuid4().hex[:6]}@example.com",
            "contact": "+919876543210", "notes": {},
        }}},
    }
    raw = json.dumps(body).encode()
    sig = hmac.new(WEBHOOK_SECRET.encode(), raw, hashlib.sha256).hexdigest()
    return raw, sig


# ===========================================================================
# the policy table itself
# ===========================================================================

def test_policy_covers_exactly_the_three_decision_bands():
    assert set(backend.ACTION_POLICY) == {"ALLOW", "MANUAL_REVIEW", "BLOCK"}


def test_policy_is_versioned():
    assert backend.POLICY_VERSION
    assert isinstance(backend.POLICY_VERSION, str)


@pytest.mark.parametrize("band,expected", [
    ("ALLOW", "PROCEED_TO_AUTHORISATION"),
    ("MANUAL_REVIEW", "ENQUEUE_FOR_HUMAN_REVIEW"),
    ("BLOCK", "REFUSE_BEFORE_AUTHORISATION"),
])
def test_each_band_maps_to_one_deterministic_action(band, expected):
    assert backend.ACTION_POLICY[band]["automated_action"] == expected
    # Deterministic: same input, same action, every time.
    for _ in range(5):
        rec = backend.automated_action(band, transaction_id="pay_x",
                                       risk_score=50.0)
        assert rec["action"] == expected


def test_block_refuses_before_the_provider_is_contacted():
    """Refusing after authorisation would mean a real charge to reverse."""
    permitted = backend.ACTION_POLICY["BLOCK"]["permitted"]
    assert any("before it reaches the payment provider" in p for p in permitted)


def test_every_automated_action_is_reversible_by_a_human():
    for band, spec in backend.ACTION_POLICY.items():
        assert spec["reversible_by_human"] is True, band


def test_no_band_permits_a_forbidden_action():
    """Cross-check the two tables against each other: nothing in `permitted` may
    describe anything in `never_automated`."""
    forbidden_verbs = ("refund", "ban", "suspend", "label", "ground truth",
                       "retrain", "delete", "threshold")
    for band, spec in backend.ACTION_POLICY.items():
        for entry in spec["permitted"]:
            low = entry.lower()
            for verb in forbidden_verbs:
                assert verb not in low, f"{band} permits {verb!r}: {entry}"


def test_never_automated_names_the_dangerous_actions():
    joined = " ".join(backend.NEVER_AUTOMATED).lower()
    for required in ("fraudulent", "ground-truth", "refund", "ban",
                     "threshold", "weights", "delete"):
        assert required in joined, f"policy does not forbid {required}"


def test_policy_note_denies_the_block_equals_fraud_inference():
    note = backend.POLICY_NOTE.lower()
    assert "not a finding of fraud" in note
    assert "not a label" in note
    assert "human reviewer" in note


def test_unknown_decision_routes_to_a_human_not_through():
    """A band this build does not understand must land in front of a person."""
    rec = backend.automated_action("SOME_FUTURE_BAND", transaction_id="pay_x",
                                   risk_score=12.0)
    assert rec["action"] == "ENQUEUE_FOR_HUMAN_REVIEW"
    assert rec["action"] != "PROCEED_TO_AUTHORISATION"
    assert "unrecognised" in rec["reason"]


def test_action_record_carries_every_mandated_field():
    rec = backend.automated_action("BLOCK", transaction_id="pay_abc",
                                   risk_score=91.4)
    for field in ("action", "reason", "transaction_id", "risk_score", "at",
                  "policy_version"):
        assert field in rec, field
    assert rec["transaction_id"] == "pay_abc"
    assert rec["risk_score"] == 91.4
    assert rec["policy_version"] == backend.POLICY_VERSION
    assert rec["at"].endswith("+00:00")


def test_action_record_denies_creating_labels_or_moving_money():
    for band in backend.ACTION_POLICY:
        rec = backend.automated_action(band, transaction_id="pay_x",
                                       risk_score=1.0)
        assert rec["creates_ground_truth"] is False
        assert rec["creates_fraud_label"] is False
        assert rec["moves_money"] is False


# ===========================================================================
# the published policy endpoint
# ===========================================================================

def test_policy_endpoint_serves_the_same_tables_the_emitter_uses(db):
    with app_run() as c:
        h = staff(c, "pol_s", role="analyst")
        got = c.get("/v1/admin/policy", headers=h).json()

    assert got["policy_version"] == backend.POLICY_VERSION
    assert set(got["decisions"]) == set(backend.ACTION_POLICY)
    assert got["never_automated"] == list(backend.NEVER_AUTOMATED)
    assert "human only" in got["ground_truth_source"]


def test_policy_endpoint_is_read_only(db):
    """There is no runtime way to widen what the automation may do."""
    with app_run() as c:
        h = staff(c, "ro_s")
        for verb in ("PUT", "POST", "PATCH", "DELETE"):
            r = c.request(verb, "/v1/admin/policy", headers=h)
            assert r.status_code == 405, f"{verb} is routable"


def test_policy_endpoint_requires_staff(db):
    with app_run() as c:
        h = register(c, f"cust-{uuid.uuid4().hex[:8]}@example.com")
        assert c.get("/v1/admin/policy", headers=h).status_code == 403
        assert c.get("/v1/admin/policy").status_code in (401, 403)


# ===========================================================================
# BLOCK does not do the forbidden things
# ===========================================================================

def test_block_creates_no_fraud_ground_truth(db, pinned_scorer):
    with app_run() as c:
        h = register(c, f"blk-{uuid.uuid4().hex[:8]}@example.com")
        body = order(c, h, P_BLOCK)
        txn_id = next(t for t, v in backend.STATE["txns"].items()
                      if v.get("order_id") == body["order_id"])
        stored = backend.STATE["txns"][txn_id]

        assert stored["decision"] == "BLOCK"
        # No label, and no OUTCOME_RECORDED event.
        assert stored["label"] is None
        assert [e for e in backend.STATE["audit"]
                if e["action"] == backend.OUTCOME_RECORDED] == []
        # And the RISK_DECISION says so explicitly.
        ev = risk_events()[0]
        assert ev["after"]["is_ground_truth"] is False
        assert ev["after"]["automated_action"]["creates_ground_truth"] is False


def test_block_does_not_label_the_customer_fraudulent(db, pinned_scorer):
    with app_run() as c:
        email = f"nolabel-{uuid.uuid4().hex[:8]}@example.com"
        h = register(c, email)
        order(c, h, P_BLOCK)
        user = backend.STATE["users"].get_by_email(email)

    # The account is untouched: same role, still active, no flag of any kind.
    assert user.role == "customer"
    assert user.status == "active"
    blob = repr(vars(user)).lower()
    assert "fraud" not in blob
    assert "banned" not in blob and "suspended" not in blob


def test_block_issues_no_refund_and_moves_no_money(db, pinned_scorer):
    """There is no refund path at all, and a BLOCK never settles."""
    with app_run() as c:
        h = register(c, f"norefund-{uuid.uuid4().hex[:8]}@example.com")
        body = order(c, h, P_BLOCK)
        ev = risk_events()[0]

    assert body["settlement"] == payments.SETTLED_FAILED
    # No provider exposes a refund operation, by design.
    assert not hasattr(payments.RazorpayProvider, "refund")
    assert not hasattr(payments.SimulatedProvider, "refund")
    assert ev["after"]["automated_action"]["moves_money"] is False
    # And no route exists that could execute one.
    paths = {r.path for r in backend.app.routes if hasattr(r, "path")}
    assert not any("refund" in p for p in paths)


def test_block_does_not_modify_thresholds(db, pinned_scorer):
    with app_run() as c:
        before = (backend.STATE["scorer"].review_t,
                  backend.STATE["scorer"].block_t)
        h = register(c, f"nothresh-{uuid.uuid4().hex[:8]}@example.com")
        order(c, h, P_BLOCK)
        after = (backend.STATE["scorer"].review_t,
                 backend.STATE["scorer"].block_t)
        # No threshold_update event, and no persisted configuration item.
        assert [e for e in backend.STATE["audit"]
                if e["action"] == backend.THRESHOLD_UPDATE] == []

    assert after == before
    assert db.get(backend.CONFIG_PK, backend.CONFIG_SK_THRESHOLDS) is None


def test_block_does_not_delete_the_transaction_or_its_evidence(db,
                                                              pinned_scorer):
    with app_run() as c:
        h = register(c, f"keep-{uuid.uuid4().hex[:8]}@example.com")
        body = order(c, h, P_BLOCK)
        txn_id = next(t for t, v in backend.STATE["txns"].items()
                      if v.get("order_id") == body["order_id"])

    # Durable record retained, evidence intact.
    stored = db.get(f"TXN#{txn_id}", "DETAIL")
    assert stored is not None
    assert stored["decision"] == "BLOCK"
    assert stored.get("features") is not None


def test_block_customer_message_makes_no_accusation(db, pinned_scorer):
    with app_run() as c:
        h = register(c, f"msg-{uuid.uuid4().hex[:8]}@example.com")
        body = order(c, h, P_BLOCK)

    text = (body["message"] + body["status"]).lower()
    for word in ("fraud", "suspicious", "abuse", "criminal", "blocked",
                 "risk", "score"):
        assert word not in text, f"customer message leaks {word!r}: {body}"
    # And no risk evidence at all for a customer role.
    assert "risk" not in body


@pytest.mark.parametrize("product,band", [
    (P_ALLOW, "ALLOW"), (P_REVIEW, "MANUAL_REVIEW"), (P_BLOCK, "BLOCK"),
])
def test_no_band_creates_a_label(db, pinned_scorer, product, band):
    with app_run() as c:
        h = register(c, f"nolab-{uuid.uuid4().hex[:8]}@example.com")
        body = order(c, h, product)
        txn_id = next(t for t, v in backend.STATE["txns"].items()
                      if v.get("order_id") == body["order_id"])
        stored = backend.STATE["txns"][txn_id]
        outcomes = [e for e in backend.STATE["audit"]
                    if e["action"] == backend.OUTCOME_RECORDED]

    assert stored["decision"] == band
    assert stored["label"] is None
    assert outcomes == []


def test_manual_review_queues_but_does_not_decide(db, pinned_scorer):
    with app_run() as c:
        h = register(c, f"mr-{uuid.uuid4().hex[:8]}@example.com")
        body = order(c, h, P_REVIEW)
        txn_id = next(t for t, v in backend.STATE["txns"].items()
                      if v.get("order_id") == body["order_id"])

        assert txn_id in backend.STATE["queue"]
        assert backend.STATE["txns"][txn_id]["label"] is None
        ev = risk_events()[0]
        assert ev["after"]["automated_action"]["action"] == \
            "ENQUEUE_FOR_HUMAN_REVIEW"


def test_only_a_human_action_creates_ground_truth(db, pinned_scorer):
    with app_run() as c:
        h = register(c, f"gt-{uuid.uuid4().hex[:8]}@example.com")
        body = order(c, h, P_REVIEW)
        txn_id = next(t for t, v in backend.STATE["txns"].items()
                      if v.get("order_id") == body["order_id"])
        assert [e for e in backend.STATE["audit"]
                if e["action"] == backend.OUTCOME_RECORDED] == []

        st = staff(c, "gt_s")
        assert c.post(f"/v1/admin/transactions/{txn_id}/outcome", headers=st,
                      json={"label": "fraud"}).status_code == 200
        outcomes = [e for e in backend.STATE["audit"]
                    if e["action"] == backend.OUTCOME_RECORDED]

    assert len(outcomes) == 1
    assert outcomes[0]["after"]["ground_truth"] is True
    assert "@" in outcomes[0]["actor"]          # a person, not system:scorer


# ===========================================================================
# per-decision audit completeness
# ===========================================================================

@pytest.mark.parametrize("product", [P_ALLOW, P_REVIEW, P_BLOCK])
def test_storefront_order_emits_exactly_one_event(db, pinned_scorer, product):
    with app_run() as c:
        h = register(c, f"sf-{uuid.uuid4().hex[:8]}@example.com")
        order(c, h, product)
        events = risk_events()

    assert len(events) == 1
    assert events[0]["before"]["source"] == "storefront"
    assert events[0]["actor"] == "system:scorer"


def test_service_scoring_emits_exactly_one_event(db, pinned_scorer):
    """This path had NO audit event before. A service-to-service refusal is a real
    decision affecting a real payment."""
    with app_run() as c:
        r = c.post("/v1/risk/score", json={
            "customer_id": "cust_svc", "amount": P_BLOCK[1],
            "payment_method": "card", "device_fp": "dev_svc",
            "ip_hash": "ip_svc", "commit": True,
        })
        assert r.status_code == 200, r.text
        events = risk_events()

    assert len(events) == 1
    ev = events[0]
    assert ev["before"]["source"] == "service"
    assert ev["before"]["transaction_id"] == r.json()["transaction_id"]
    assert ev["after"]["decision"] == "BLOCK"
    # No order exists on this path, and none is invented.
    assert ev["before"]["order_id"] is None


def test_checkout_emits_one_event_named_as_checkout(db, pinned_scorer):
    """/v1/checkout used to call the /v1/risk/score handler, which would have
    attributed a customer-facing checkout to the service path."""
    with app_run() as c:
        r = c.post("/v1/checkout", json={
            "customer_id": "cust_co", "amount": P_ALLOW[1],
            "payment_method": "upi", "device_fp": "dev_co",
            "ip_hash": "ip_co",
        })
        assert r.status_code == 200, r.text
        events = risk_events()

    assert len(events) == 1
    assert events[0]["before"]["source"] == "checkout"


def test_dry_run_emits_no_event(db, pinned_scorer):
    """commit=false is a preview. Auditing it would break the equality between
    decisions taken and RISK_DECISION events."""
    with app_run() as c:
        r = c.post("/v1/risk/score", json={
            "customer_id": "cust_dry", "amount": P_BLOCK[1],
            "payment_method": "card", "device_fp": "dev_dry",
            "ip_hash": "ip_dry", "commit": False,
        })
        assert r.status_code == 200, r.text
        events = risk_events()
        # The stored record still marks itself as uncommitted.
        stored = backend.STATE["txns"][r.json()["transaction_id"]]

    assert events == []
    assert stored["committed"] is False


def test_committed_and_preview_scorings_are_counted_separately(db,
                                                              pinned_scorer):
    with app_run() as c:
        for commit in (True, False, True, False, False):
            c.post("/v1/risk/score", json={
                "customer_id": "cust_mix", "amount": P_ALLOW[1],
                "payment_method": "card", "device_fp": "dev_mix",
                "ip_hash": "ip_mix", "commit": commit,
            })
        events = risk_events()

    assert len(events) == 2, "one event per committed scoring, none for previews"


def test_webhook_ingestion_emits_exactly_one_event(db, pinned_scorer):
    with app_run() as c:
        raw, sig = signed_event()
        r = c.post("/v1/webhooks/payment", content=raw,
                   headers={"x-razorpay-signature": sig,
                            "content-type": "application/json"})
        assert r.status_code == 200, r.text
        assert r.json()["ingested"] is True
        events = risk_events()

    assert len(events) == 1
    assert events[0]["before"]["source"] == "webhook"


def test_webhook_redelivery_does_not_duplicate_the_event(db, pinned_scorer):
    with app_run() as c:
        raw, sig = signed_event()
        headers = {"x-razorpay-signature": sig,
                   "content-type": "application/json"}
        first = c.post("/v1/webhooks/payment", content=raw, headers=headers)
        again = c.post("/v1/webhooks/payment", content=raw, headers=headers)
        assert first.json()["ingested"] is True
        assert again.json()["duplicate"] is True
        events = risk_events()

    assert len(events) == 1


def test_all_three_entry_points_together_produce_one_event_each(db,
                                                               pinned_scorer):
    """The completeness check: three scorings, three events, three sources."""
    with app_run() as c:
        h = register(c, f"all-{uuid.uuid4().hex[:8]}@example.com")
        order(c, h, P_ALLOW)

        c.post("/v1/risk/score", json={
            "customer_id": "cust_all", "amount": P_REVIEW[1],
            "payment_method": "card", "device_fp": "dev_all",
            "ip_hash": "ip_all", "commit": True,
        })

        raw, sig = signed_event()
        c.post("/v1/webhooks/payment", content=raw,
               headers={"x-razorpay-signature": sig,
                        "content-type": "application/json"})

        events = risk_events()

    assert len(events) == 3
    assert {e["before"]["source"] for e in events} == {
        "storefront", "service", "webhook"}
    assert len({e["event_id"] for e in events}) == 3


def test_degraded_model_still_emits_one_event_marked_degraded(db, monkeypatch):
    """A fallback scoring is still a decision and must still be audited."""
    def degraded_score(self, store, txn):
        d = _decision_for(float(txn["amount"]))
        return backend.Decision(
            risk_score=d.risk_score, decision=d.decision,
            sub_scores=d.sub_scores, reason_codes=[], fired_rules=[],
            override=None, model_version="degraded", degraded=True,
        ), {"amount": float(txn["amount"])}

    monkeypatch.setattr(backend.Scorer, "score", degraded_score)
    with app_run() as c:
        h = register(c, f"deg-{uuid.uuid4().hex[:8]}@example.com")
        order(c, h, P_BLOCK)
        events = risk_events()

    assert len(events) == 1
    assert events[0]["after"]["degraded"] is True


def test_provider_pending_still_emits_exactly_one_event(db, pinned_scorer):
    """An unresolved provider payment is still a routed decision."""
    class StubProvider:
        name = "razorpay"

        def is_configured(self):
            return True

        def authorise(self, **kw):
            return payments.ProviderOrder(
                provider="razorpay", settlement=payments.SETTLED_PENDING,
                provider_order_id="order_STUB")

        def fetch_payment(self, pid):    # pragma: no cover
            raise AssertionError

    with app_run() as c:
        backend.STATE["payment_provider"] = StubProvider()
        h = register(c, f"pend-{uuid.uuid4().hex[:8]}@example.com")
        body = order(c, h, P_ALLOW)
        events = risk_events()

    assert body["settlement"] == payments.SETTLED_PENDING
    assert len(events) == 1
    assert events[0]["after"]["settlement"] == payments.SETTLED_PENDING


def test_provider_failure_still_emits_exactly_one_event(db, pinned_scorer):
    """A gateway error must not cost the decision its audit record."""
    class FailingProvider:
        name = "razorpay"

        def is_configured(self):
            return True

        def authorise(self, **kw):
            return payments.ProviderOrder(
                provider="razorpay", settlement=payments.SETTLED_PENDING,
                error="Razorpay order.create failed: TimeoutError")

        def fetch_payment(self, pid):    # pragma: no cover
            raise AssertionError

    with app_run() as c:
        backend.STATE["payment_provider"] = FailingProvider()
        h = register(c, f"fail-{uuid.uuid4().hex[:8]}@example.com")
        body = order(c, h, P_ALLOW)
        events = risk_events()

    assert len(events) == 1
    # The provider error is an operator diagnostic, never a customer's problem.
    assert "TimeoutError" not in repr(body)


def test_scoring_is_not_run_twice_per_decision(db, monkeypatch):
    """One event per scoring, and one scoring per request. If the audit emitter
    re-scored, the audited numbers could differ from the served ones."""
    calls = {"n": 0}
    real = _decision_for

    def counting(self, store, txn):
        calls["n"] += 1
        return real(float(txn["amount"])), {"amount": float(txn["amount"])}

    monkeypatch.setattr(backend.Scorer, "score", counting)
    with app_run() as c:
        h = register(c, f"once-{uuid.uuid4().hex[:8]}@example.com")
        order(c, h, P_REVIEW)
        assert calls["n"] == 1
        assert len(risk_events()) == 1


def test_audited_action_matches_the_audited_decision(db, pinned_scorer):
    """The action and the decision come from the same event, so they cannot
    disagree -- asserted because a mismatch would misdescribe what happened."""
    expected = {"ALLOW": "PROCEED_TO_AUTHORISATION",
                "MANUAL_REVIEW": "ENQUEUE_FOR_HUMAN_REVIEW",
                "BLOCK": "REFUSE_BEFORE_AUTHORISATION"}
    with app_run() as c:
        for product in (P_ALLOW, P_REVIEW, P_BLOCK):
            h = register(c, f"match-{uuid.uuid4().hex[:8]}@example.com")
            order(c, h, product)
        events = risk_events()

    assert len(events) == 3
    for ev in events:
        act = ev["after"]["automated_action"]
        assert act["action"] == expected[ev["after"]["decision"]]
        assert act["risk_score"] == ev["after"]["risk_score"]
        assert act["transaction_id"] == ev["before"]["transaction_id"]
        assert act["policy_version"] == backend.POLICY_VERSION


def test_events_are_retrievable_and_filterable_by_admin(db, pinned_scorer):
    with app_run() as c:
        h = register(c, f"ret-{uuid.uuid4().hex[:8]}@example.com")
        order(c, h, P_BLOCK)
        st = staff(c, "ret_s")
        got = c.get(f"/v1/admin/audit?action={backend.RISK_DECISION}",
                    headers=st).json()

    assert got["count"] >= 1
    assert got["entries"][0]["after"]["automated_action"]["policy_version"] == \
        backend.POLICY_VERSION
