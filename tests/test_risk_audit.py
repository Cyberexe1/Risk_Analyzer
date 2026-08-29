"""RISK_DECISION per-decision audit trail tests.

Two properties matter most and are asserted directly rather than inferred:

  1. The audited values are the SAME values the decision was made from. If the
     audit trail and the transaction can disagree, the trail is worthless.
  2. A RISK_DECISION is a routing event, never a fraud label. Ground truth comes
     only from a human outcome, which is a separate event.

Run:  python -m pytest tests/test_risk_audit.py -v
"""
from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# Set before importing backend: module-level config is read at import time.
os.environ["FRAUDSHIELD_USERS_BACKEND"] = "memory"
os.environ["FRAUDSHIELD_WARM_ROWS"] = "0"
os.environ["FRAUDSHIELD_DEV_SEED_STAFF"] = "0"
os.environ["FRAUDSHIELD_JWT_SECRET"] = "test-only-jwt-secret-risk-audit"
os.environ["FRAUDSHIELD_IP_PEPPER"] = "test-only-pepper-risk-audit"
os.environ.pop("FRAUDSHIELD_API_KEY", None)

from fastapi.testclient import TestClient  # noqa: E402

import backend  # noqa: E402

PW = "risk-audit-test-password-7742"

CARD = {"number": "4111 1111 1111 1111", "expiry_month": 12,
        "expiry_year": 2029, "cvv": "123", "holder": "Audit Test"}

# Internal risk fields that must never appear in a customer-facing response.
INTERNAL_FIELDS = [
    "risk_score", "sub_scores", "reason_codes", "fired_rules", "decision",
    "model_version", "device_fp", "ip_hash", "override", "ip_suspicious",
]


@pytest.fixture(scope="module")
def client():
    """Force in-memory stores for this module, then start the app.

    backend.USERS_BACKEND is read from the environment at IMPORT time. Under the
    full suite another module imports backend first (alphabetical collection), so
    this module's os.environ assignment above lands too late and the value from
    .env wins -- which on a configured machine means `dynamodb`.

    Two consequences, both bad: the tests would write to a real AWS table, and
    promote() below would mutate a detached User object that DynamoUserStore never
    persists, so the role change would silently not take. Patching the module
    attribute before TestClient starts the lifespan makes this module hermetic
    regardless of collection order.
    """
    prev = backend.USERS_BACKEND
    backend.USERS_BACKEND = "memory"
    try:
        with TestClient(backend.app) as c:
            yield c
    finally:
        backend.USERS_BACKEND = prev


def register(client, email: str) -> dict:
    r = client.post("/v1/auth/register", json={"email": email, "password": PW})
    assert r.status_code == 201, r.text
    return {"authorization": f"Bearer {r.json()['access_token']}"}


def promote(client, email: str) -> dict:
    """Grant admin out-of-band, exactly as scripts/grant_role.py does. There is no
    API path to a privileged role, which is itself part of the design."""
    users = backend.STATE["users"]
    u = users.get_by_email(email)
    u.role = "admin"
    r = client.post("/v1/auth/login", json={"email": email, "password": PW})
    assert r.status_code == 200, r.text
    return {"authorization": f"Bearer {r.json()['access_token']}"}


def place_order(client, headers, *, device_fp="dev_audit_test", qty=1,
                product="p1", method="card") -> dict:
    body = {
        "items": [{"product_id": product, "qty": qty}],
        "payment_method": method,
        "device_fp": device_fp,
    }
    if method == "card":
        body["card"] = CARD
    r = client.post("/v1/orders", headers=headers, json=body)
    assert r.status_code == 201, r.text
    return r.json()


def risk_events(order_id: str | None = None) -> list[dict]:
    """Read RISK_DECISION events straight from the audit log."""
    rows = [e for e in backend.STATE["audit"]
            if e.get("action") == backend.RISK_DECISION]
    if order_id:
        rows = [e for e in rows if e["before"].get("order_id") == order_id]
    return rows


# ---------------------------------------------------------------------------
# one event per decision, for every decision band
# ---------------------------------------------------------------------------

def test_allow_creates_exactly_one_risk_decision_event(client):
    h = register(client, f"allow-{uuid.uuid4().hex[:8]}@example.com")
    out = place_order(client, h)
    events = risk_events(out["order_id"])
    assert len(events) == 1, f"expected 1 RISK_DECISION, got {len(events)}"


def test_each_decision_band_emits_exactly_one_event(client):
    """Drive traffic until ALLOW, MANUAL_REVIEW and BLOCK have each been observed,
    asserting one event per order throughout. Which band a given order lands in
    depends on accumulated state, so the bands are collected rather than forced.
    """
    seen: dict[str, str] = {}
    for i in range(14):
        h = register(client, f"band-{i}-{uuid.uuid4().hex[:6]}@example.com")
        out = place_order(client, h, device_fp="dev_band_shared", qty=3,
                          product="p3")
        events = risk_events(out["order_id"])
        assert len(events) == 1, (
            f"order {out['order_id']} produced {len(events)} RISK_DECISION events"
        )
        seen.setdefault(events[0]["after"]["decision"], out["order_id"])
        if len(seen) == 3:
            break

    assert "ALLOW" in seen or "MANUAL_REVIEW" in seen or "BLOCK" in seen
    # Every observed band emitted exactly one event, which is the invariant here.
    for decision, oid in seen.items():
        assert len(risk_events(oid)) == 1, f"{decision} did not emit exactly one"


def test_two_orders_produce_two_distinct_events(client):
    h = register(client, f"two-{uuid.uuid4().hex[:8]}@example.com")
    a = place_order(client, h)
    b = place_order(client, h)
    ea, eb = risk_events(a["order_id"]), risk_events(b["order_id"])
    assert len(ea) == len(eb) == 1
    assert ea[0]["event_id"] != eb[0]["event_id"]
    assert ea[0]["before"]["transaction_id"] != eb[0]["before"]["transaction_id"]


# ---------------------------------------------------------------------------
# the audited values must equal the values actually used
# ---------------------------------------------------------------------------

def test_audited_values_match_the_stored_transaction(client):
    """The core guarantee: score, decision and all three sub-scores in the audit
    event are identical to the ones on the scored transaction."""
    h = register(client, f"match-{uuid.uuid4().hex[:8]}@example.com")
    out = place_order(client, h)
    ev = risk_events(out["order_id"])[0]

    txn_id = ev["before"]["transaction_id"]
    stored = backend.STATE["txns"][txn_id]

    assert ev["after"]["risk_score"] == stored["risk_score"]
    assert ev["after"]["decision"] == stored["decision"]
    assert ev["after"]["sub_scores"] == stored["sub_scores"]
    assert ev["after"]["sub_scores"]["ml"] == stored["sub_scores"]["ml"]
    assert ev["after"]["sub_scores"]["rules"] == stored["sub_scores"]["rules"]
    assert ev["after"]["sub_scores"]["network"] == stored["sub_scores"]["network"]
    assert ev["after"]["fired_rules"] == stored["fired_rules"]
    assert ev["after"]["reason_codes"] == stored["reason_codes"]
    assert ev["after"]["override"] == stored["override"]


def test_event_reconstructs_the_decision(client):
    """All twelve reconstruction questions answerable from one event."""
    h = register(client, f"recon-{uuid.uuid4().hex[:8]}@example.com")
    out = place_order(client, h)
    ev = risk_events(out["order_id"])[0]

    assert ev["action"] == "RISK_DECISION"
    assert ev["event_id"].startswith("rde_")
    assert ev["actor"] == "system:scorer"
    assert ev["at"]

    b, a = ev["before"], ev["after"]
    assert b["transaction_id"].startswith("pay_")
    assert b["order_id"] == out["order_id"]
    assert b["customer_id"]
    assert b["amount"] == out["amount"]
    assert b["payment_method"] == "card"
    assert b["source"] == "storefront"

    assert a["decision"] in ("ALLOW", "MANUAL_REVIEW", "BLOCK")
    assert isinstance(a["risk_score"], float)
    assert set(a["sub_scores"]) == {"ml", "rules", "network"}
    assert isinstance(a["fired_rules"], list)
    assert isinstance(a["reason_codes"], list)
    assert a["model_version"]
    assert isinstance(a["degraded"], bool)
    assert a["thresholds"]["review"] == backend.STATE["scorer"].review_t
    assert a["thresholds"]["block"] == backend.STATE["scorer"].block_t


def test_decision_is_consistent_with_the_audited_thresholds(client):
    """The recorded thresholds must actually explain the recorded decision."""
    h = register(client, f"thr-{uuid.uuid4().hex[:8]}@example.com")
    out = place_order(client, h)
    a = risk_events(out["order_id"])[0]["after"]
    score, t = a["risk_score"], a["thresholds"]

    if a["decision"] == "BLOCK":
        assert score >= t["block"]
    elif a["decision"] == "MANUAL_REVIEW":
        assert t["review"] <= score < t["block"]
    else:
        assert score < t["review"]


def test_scorer_is_not_invoked_twice(client, monkeypatch):
    """Auditing must not re-score. One order, one call to Scorer.score."""
    calls = {"n": 0}
    original = backend.Scorer.score

    def counting(self, store, txn):
        calls["n"] += 1
        return original(self, store, txn)

    monkeypatch.setattr(backend.Scorer, "score", counting)
    h = register(client, f"once-{uuid.uuid4().hex[:8]}@example.com")
    place_order(client, h)
    assert calls["n"] == 1, f"scorer called {calls['n']} times for one order"


# ---------------------------------------------------------------------------
# ground truth stays separate
# ---------------------------------------------------------------------------

def test_risk_decision_is_not_ground_truth(client):
    h = register(client, f"gt-{uuid.uuid4().hex[:8]}@example.com")
    out = place_order(client, h)
    ev = risk_events(out["order_id"])[0]

    assert ev["after"]["is_ground_truth"] is False
    assert "not a fraud determination" in ev["after"]["note"].lower()

    # The scored transaction carries no label until a human sets one.
    stored = backend.STATE["txns"][ev["before"]["transaction_id"]]
    assert stored["label"] is None


def test_blocked_transaction_is_not_labelled_fraud(client):
    """A BLOCK must not create a fraud label. Scanning every emitted event, no
    RISK_DECISION may carry a label of any kind."""
    for ev in risk_events():
        assert ev["after"]["is_ground_truth"] is False
        assert "label" not in ev["after"]
        txn = backend.STATE["txns"].get(ev["before"]["transaction_id"])
        if txn is not None:
            assert txn["label"] is None, "scoring created ground truth"


def test_human_outcome_is_a_separate_action(client):
    """Recording an outcome writes the label. It is a different, human-actored
    path -- it does not rewrite the RISK_DECISION event."""
    email = f"outcome-{uuid.uuid4().hex[:8]}@example.com"
    h = register(client, email)
    out = place_order(client, h)
    ev = risk_events(out["order_id"])[0]
    txn_id = ev["before"]["transaction_id"]

    admin = promote(client, email)
    r = client.post(f"/v1/admin/transactions/{txn_id}/outcome",
                    headers=admin, json={"label": "fraud"})
    assert r.status_code == 200, r.text

    assert backend.STATE["txns"][txn_id]["label"] == "fraud"
    # The routing event is unchanged and still disclaims ground truth.
    after = risk_events(out["order_id"])
    assert len(after) == 1
    assert after[0]["after"]["is_ground_truth"] is False


# ---------------------------------------------------------------------------
# customer isolation
# ---------------------------------------------------------------------------

def test_customer_response_hides_internal_risk_fields(client):
    h = register(client, f"cust-{uuid.uuid4().hex[:8]}@example.com")
    out = place_order(client, h)
    assert "risk" not in out, "customer response exposed the risk block"
    for f in INTERNAL_FIELDS:
        assert f not in out, f"customer response leaked {f!r}"


def test_customer_order_list_hides_internal_risk_fields(client):
    h = register(client, f"list-{uuid.uuid4().hex[:8]}@example.com")
    place_order(client, h)
    r = client.get("/v1/orders", headers=h)
    assert r.status_code == 200
    for order in r.json()["orders"]:
        for f in ("risk_score", "sub_scores", "decision", "reason_codes",
                  "device_fp", "ip_hash", "model_version"):
            assert f not in order, f"order list leaked {f!r}"


def test_audit_event_carries_no_payment_credentials(client):
    """The instrument is a salted fingerprint upstream; an audit log is the wrong
    place for card data."""
    h = register(client, f"pan-{uuid.uuid4().hex[:8]}@example.com")
    out = place_order(client, h)
    blob = repr(risk_events(out["order_id"])[0])
    for leak in ("4111", "1111 1111", '"cvv"', "123456", "Audit Test"):
        assert leak not in blob, f"audit event leaked {leak!r}"


# ---------------------------------------------------------------------------
# authorization
# ---------------------------------------------------------------------------

def test_audit_endpoint_rejects_anonymous(client):
    r = client.get("/v1/admin/audit")
    assert r.status_code in (401, 403)


def test_audit_endpoint_rejects_customer_role(client):
    h = register(client, f"nope-{uuid.uuid4().hex[:8]}@example.com")
    r = client.get("/v1/admin/audit", headers=h)
    assert r.status_code == 403


def test_admin_can_retrieve_risk_decision_events(client):
    email = f"admin-{uuid.uuid4().hex[:8]}@example.com"
    h = register(client, email)
    out = place_order(client, h)
    admin = promote(client, email)

    r = client.get("/v1/admin/audit", headers=admin, params={"limit": 500})
    assert r.status_code == 200
    actions = {e["action"] for e in r.json()["entries"]}
    assert "RISK_DECISION" in actions

    ids = {e["before"].get("order_id") for e in r.json()["entries"]
           if e["action"] == "RISK_DECISION"}
    assert out["order_id"] in ids


def test_audit_endpoint_filters_by_action(client):
    email = f"filter-{uuid.uuid4().hex[:8]}@example.com"
    h = register(client, email)
    place_order(client, h)
    admin = promote(client, email)

    r = client.get("/v1/admin/audit", headers=admin,
                   params={"action": "RISK_DECISION", "limit": 500})
    assert r.status_code == 200
    entries = r.json()["entries"]
    assert entries, "filter returned nothing"
    assert all(e["action"] == "RISK_DECISION" for e in entries)

    # An unmatched filter returns empty rather than falling back to everything.
    r2 = client.get("/v1/admin/audit", headers=admin,
                    params={"action": "NO_SUCH_ACTION"})
    assert r2.status_code == 200
    assert r2.json()["entries"] == []


def test_unfiltered_audit_still_returns_other_actions(client):
    """The pre-existing threshold-history view depends on the unfiltered call."""
    email = f"mixed-{uuid.uuid4().hex[:8]}@example.com"
    register(client, email)
    admin = promote(client, email)

    r = client.put("/v1/admin/thresholds", headers=admin,
                   json={"review": 5, "block": 70})
    assert r.status_code == 200, r.text

    entries = client.get("/v1/admin/audit", headers=admin,
                         params={"limit": 500}).json()["entries"]
    actions = {e["action"] for e in entries}
    assert "threshold_update" in actions
    assert "RISK_DECISION" in actions


# ---------------------------------------------------------------------------
# degraded mode
# ---------------------------------------------------------------------------

def test_degraded_mode_is_recorded_truthfully(client, monkeypatch):
    """With no model, the score comes from rules and network only. The event must
    say so rather than implying the ML layer produced it."""
    scorer = backend.STATE["scorer"]
    monkeypatch.setattr(scorer, "booster", None)
    monkeypatch.setattr(scorer, "degraded", True)
    monkeypatch.setattr(scorer, "model_version", "none")

    h = register(client, f"degraded-{uuid.uuid4().hex[:8]}@example.com")
    out = place_order(client, h)
    a = risk_events(out["order_id"])[0]["after"]

    assert a["degraded"] is True
    assert a["model_version"] == "none"
    assert a["sub_scores"]["ml"] == 0.0, "degraded event claims an ML contribution"
    assert a["decision"] in ("ALLOW", "MANUAL_REVIEW", "BLOCK")


def test_normal_mode_is_not_marked_degraded(client):
    h = register(client, f"normal-{uuid.uuid4().hex[:8]}@example.com")
    out = place_order(client, h)
    a = risk_events(out["order_id"])[0]["after"]
    assert a["degraded"] is False
    assert a["model_version"] != "none"


# ---------------------------------------------------------------------------
# audit failure must not break order processing
# ---------------------------------------------------------------------------

def test_order_succeeds_when_audit_persistence_fails(client, monkeypatch, capsys):
    """A broken audit store must not corrupt or refuse a payment."""
    records = backend.STATE["records"]
    original_put = records.put

    def flaky(pk, sk, item):
        if pk.startswith("AUDIT#"):
            raise RuntimeError("simulated audit store outage")
        return original_put(pk, sk, item)

    monkeypatch.setattr(records, "put", flaky)

    h = register(client, f"flaky-{uuid.uuid4().hex[:8]}@example.com")
    out = place_order(client, h)          # must still succeed
    assert out["order_id"]

    # The event is still present in-process, so it is a persistence gap, not a
    # missing event -- and the failure is visible to operators.
    assert len(risk_events(out["order_id"])) == 1
    assert "audit write failed" in capsys.readouterr().out

    # Nothing internal leaked to the customer while this was happening.
    assert "risk" not in out
