"""OUTCOME_RECORDED — human ground-truth audit tests.

The audit trail has to tell two separate stories about the same transaction:

    SYSTEM  "I scored this and routed it this way."      -> RISK_DECISION
    HUMAN   "I reviewed it and this is what it was."     -> OUTCOME_RECORDED

These tests assert that both remain independent, immutable facts: recording a
human verdict must never rewrite the machine's original judgement, and the
machine's judgement must never masquerade as ground truth.

Run:  python -m pytest tests/test_outcome_audit.py -v
"""
from __future__ import annotations

import copy
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
os.environ["FRAUDSHIELD_JWT_SECRET"] = "test-only-jwt-secret-outcome-audit"
os.environ["FRAUDSHIELD_IP_PEPPER"] = "test-only-pepper-outcome-audit"
os.environ.pop("FRAUDSHIELD_API_KEY", None)

from fastapi.testclient import TestClient  # noqa: E402

import backend  # noqa: E402

PW = "outcome-audit-test-password-5518"

CARD = {"number": "4111 1111 1111 1111", "expiry_month": 12,
        "expiry_year": 2029, "cvv": "123", "holder": "Outcome Tester"}


@pytest.fixture(scope="module")
def client():
    """Force in-memory stores regardless of collection order.

    backend.USERS_BACKEND is bound at import; another module may import backend
    first, in which case the value from .env wins and these tests would otherwise
    write to a real DynamoDB table.
    """
    prev = backend.USERS_BACKEND
    backend.USERS_BACKEND = "memory"
    try:
        with TestClient(backend.app) as c:
            yield c
    finally:
        backend.USERS_BACKEND = prev


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def register(client, email: str) -> dict:
    r = client.post("/v1/auth/register", json={"email": email, "password": PW})
    assert r.status_code == 201, r.text
    return {"authorization": f"Bearer {r.json()['access_token']}"}


def set_role(client, email: str, role: str, headers: dict) -> dict:
    """Grant a staff role out-of-band, as scripts/grant_role.py does. There is no
    API path to a privileged role, which is part of the design.

    Deliberately does NOT log in again. `current_user` re-reads the user from the
    store on every request and `require_role` reads the role off that fresh object,
    so the existing token picks up the change immediately. Re-logging in per test
    would trip the login rate limiter -- which is correct behaviour that these
    tests must not weaken -- and would also mean asserting against a token whose
    embedded role could go stale.
    """
    backend.STATE["users"].get_by_email(email).role = role
    return headers


def make_txn(client, tag: str) -> tuple[str, dict]:
    """Place an order and return (transaction_id, customer headers)."""
    email = f"{tag}-{uuid.uuid4().hex[:8]}@example.com"
    h = register(client, email)
    r = client.post("/v1/orders", headers=h, json={
        "items": [{"product_id": "p1", "qty": 1}],
        "payment_method": "card", "device_fp": f"dev_{tag}", "card": CARD,
    })
    assert r.status_code == 201, r.text
    order_id = r.json()["order_id"]
    txn_id = next(t for t, v in backend.STATE["txns"].items()
                  if v["order_id"] == order_id)
    return txn_id, h


def staff(client, tag: str, role: str = "analyst") -> dict:
    """A fresh staff account with a usable token."""
    email = f"{tag}-staff-{uuid.uuid4().hex[:8]}@example.com"
    h = register(client, email)
    return set_role(client, email, role, h)


def staff_with_email(client, tag: str, role: str = "analyst") -> tuple[dict, str]:
    """Same, but returns the identity too, for tests that assert on the actor."""
    email = f"{tag}-{uuid.uuid4().hex[:8]}@example.com"
    h = register(client, email)
    return set_role(client, email, role, h), email


def outcome_events(txn_id: str | None = None) -> list[dict]:
    rows = [e for e in backend.STATE["audit"]
            if e.get("action") == backend.OUTCOME_RECORDED]
    if txn_id:
        rows = [e for e in rows if e["before"].get("transaction_id") == txn_id]
    return rows


def risk_events(txn_id: str) -> list[dict]:
    return [e for e in backend.STATE["audit"]
            if e.get("action") == backend.RISK_DECISION
            and e["before"].get("transaction_id") == txn_id]


def record(client, headers, txn_id: str, label: str):
    return client.post(f"/v1/admin/transactions/{txn_id}/outcome",
                       headers=headers, json={"label": label})


# ---------------------------------------------------------------------------
# authorization
# ---------------------------------------------------------------------------

def test_analyst_can_record_confirm_fraud(client):
    txn_id, _ = make_txn(client, "fraud")
    r = record(client, staff(client, "a1", "analyst"), txn_id, "fraud")
    assert r.status_code == 200, r.text
    assert r.json()["label"] == "fraud"


def test_analyst_can_record_mark_legitimate(client):
    txn_id, _ = make_txn(client, "legit")
    r = record(client, staff(client, "a2", "analyst"), txn_id, "legitimate")
    assert r.status_code == 200, r.text
    assert r.json()["label"] == "legitimate"


def test_admin_can_record_outcomes(client):
    txn_id, _ = make_txn(client, "adminrec")
    r = record(client, staff(client, "a3", "admin"), txn_id, "fraud")
    assert r.status_code == 200, r.text


def test_customer_cannot_record_outcomes(client):
    txn_id, cust = make_txn(client, "custdeny")
    r = record(client, cust, txn_id, "fraud")
    assert r.status_code == 403
    assert outcome_events(txn_id) == [], "rejected call created an audit event"
    assert backend.STATE["txns"][txn_id]["label"] is None


def test_anonymous_cannot_record_outcomes(client):
    txn_id, _ = make_txn(client, "anondeny")
    r = client.post(f"/v1/admin/transactions/{txn_id}/outcome",
                    json={"label": "fraud"})
    assert r.status_code in (401, 403)
    assert outcome_events(txn_id) == []
    assert backend.STATE["txns"][txn_id]["label"] is None


# ---------------------------------------------------------------------------
# exactly one event, with the right contents
# ---------------------------------------------------------------------------

def test_one_outcome_creates_exactly_one_event(client):
    txn_id, _ = make_txn(client, "oneevent")
    record(client, staff(client, "a4"), txn_id, "fraud")
    assert len(outcome_events(txn_id)) == 1


def test_event_records_the_actor(client):
    txn_id, _ = make_txn(client, "actor")
    h, email = staff_with_email(client, "actor", "analyst")
    record(client, h, txn_id, "fraud")

    ev = outcome_events(txn_id)[0]
    assert ev["actor"] == email
    assert ev["action"] == "OUTCOME_RECORDED"
    assert ev["event_id"].startswith("out_")
    assert ev["at"]


def test_a_body_supplied_actor_is_rejected_not_ignored(client):
    """`analyst_id` used to be accepted and silently discarded.

    That was worse than refusing it: a caller got a 200 and could reasonably
    believe the identity they sent had been recorded. The endpoint that creates
    ground truth now rejects any field it does not use.
    """
    txn_id, _ = make_txn(client, "spoof")
    h, _ = staff_with_email(client, "real", "analyst")

    r = client.post(f"/v1/admin/transactions/{txn_id}/outcome", headers=h,
                    json={"label": "fraud", "analyst_id": "attacker@evil.example"})
    assert r.status_code == 422, r.text

    # Nothing happened: no label, no event.
    assert backend.STATE["txns"][txn_id]["label"] is None
    assert outcome_events(txn_id) == []
    assert "attacker@evil.example" not in repr(backend.STATE["audit"])


def test_the_audited_actor_is_the_authenticated_one(client):
    txn_id, _ = make_txn(client, "tokenactor")
    h, email = staff_with_email(client, "real2", "analyst")
    assert record(client, h, txn_id, "fraud").status_code == 200

    ev = outcome_events(txn_id)[0]
    assert ev["actor"] == email
    assert ev["actor_identity"]["email"] == email
    assert ev["actor_identity"]["role"] == "analyst"
    assert ev["actor_identity"]["user_id"]


def test_omitting_the_field_still_works(client):
    """The rejection must not break callers that simply send a label."""
    txn_id, _ = make_txn(client, "onlylabel")
    r = client.post(f"/v1/admin/transactions/{txn_id}/outcome",
                    headers=staff(client, "onlylabel_s"),
                    json={"label": "legitimate"})
    assert r.status_code == 200, r.text


def test_event_records_the_transaction_id(client):
    txn_id, _ = make_txn(client, "txnid")
    record(client, staff(client, "a5"), txn_id, "legitimate")
    ev = outcome_events(txn_id)[0]
    assert ev["before"]["transaction_id"] == txn_id
    assert ev["before"]["order_id"] == backend.STATE["txns"][txn_id]["order_id"]


def test_event_records_previous_and_new_label(client):
    txn_id, _ = make_txn(client, "labels")
    h = staff(client, "a6")

    record(client, h, txn_id, "fraud")
    first = outcome_events(txn_id)[0]
    assert first["before"]["previous_label"] is None
    assert first["before"]["label"] is None
    assert first["before"]["is_first_label"] is True
    assert first["before"]["is_correction"] is False
    assert first["after"]["label"] == "fraud"

    # A conflicting second submission is now refused, so there is no second
    # event to inspect -- and the first one is untouched.
    assert record(client, h, txn_id, "legitimate").status_code == 409
    assert outcome_events(txn_id) == [first]


def test_event_records_original_decision_and_score(client):
    txn_id, _ = make_txn(client, "original")
    txn = backend.STATE["txns"][txn_id]
    expected_decision = txn["decision"]
    expected_score = txn["risk_score"]
    expected_subs = copy.deepcopy(txn["sub_scores"])

    record(client, staff(client, "a7"), txn_id, "fraud")
    a = outcome_events(txn_id)[0]["after"]

    assert a["original_decision"] == expected_decision
    assert a["original_risk_score"] == expected_score
    assert a["original_sub_scores"] == expected_subs
    assert a["original_scored_at"] == txn["scored_at"]


def test_event_marks_itself_as_ground_truth(client):
    txn_id, _ = make_txn(client, "gt")
    record(client, staff(client, "a8"), txn_id, "fraud")
    a = outcome_events(txn_id)[0]["after"]
    assert a["ground_truth"] is True
    assert "ground truth" in a["note"].lower()


def test_confusion_cell_is_derived_correctly(client):
    """Machine judgement vs human verdict, from stored values only."""
    cell = backend._confusion_cell
    assert cell("BLOCK", "fraud") == "true_positive"
    assert cell("MANUAL_REVIEW", "fraud") == "true_positive"
    assert cell("BLOCK", "legitimate") == "false_positive"
    assert cell("MANUAL_REVIEW", "legitimate") == "false_positive"
    assert cell("ALLOW", "fraud") == "false_negative"
    assert cell("ALLOW", "legitimate") == "true_negative"

    txn_id, _ = make_txn(client, "cell")
    txn = backend.STATE["txns"][txn_id]
    record(client, staff(client, "a9"), txn_id, "fraud")
    a = outcome_events(txn_id)[0]["after"]
    assert a["confusion_cell"] == cell(txn["decision"], "fraud")


# ---------------------------------------------------------------------------
# the original RISK_DECISION must remain untouched
# ---------------------------------------------------------------------------

def test_risk_decision_event_is_not_mutated(client):
    txn_id, _ = make_txn(client, "immutable")
    before = copy.deepcopy(risk_events(txn_id))
    assert len(before) == 1

    h = staff(client, "a10")
    record(client, h, txn_id, "fraud")
    record(client, h, txn_id, "legitimate")

    after = risk_events(txn_id)
    assert len(after) == 1, "labelling created or removed a RISK_DECISION event"
    assert after[0] == before[0], "RISK_DECISION was mutated by labelling"
    assert after[0]["after"]["is_ground_truth"] is False


def test_both_events_coexist_in_history(client):
    """The full story: system routed it, then a human ruled on it."""
    txn_id, _ = make_txn(client, "story")
    record(client, staff(client, "a11"), txn_id, "legitimate")

    rd = risk_events(txn_id)[0]
    oc = outcome_events(txn_id)[0]

    assert rd["actor"] == "system:scorer"
    assert rd["after"]["is_ground_truth"] is False
    assert oc["actor"] != "system:scorer"
    assert oc["after"]["ground_truth"] is True
    assert oc["after"]["original_decision"] == rd["after"]["decision"]
    assert oc["after"]["original_risk_score"] == rd["after"]["risk_score"]
    assert rd["at"] <= oc["at"]


def test_recording_ground_truth_does_not_rerun_the_scorer(client, monkeypatch):
    txn_id, _ = make_txn(client, "noscore")
    h = staff(client, "a12")

    calls = {"n": 0}
    original = backend.Scorer.score

    def counting(self, store, txn):
        calls["n"] += 1
        return original(self, store, txn)

    monkeypatch.setattr(backend.Scorer, "score", counting)
    r = record(client, h, txn_id, "fraud")
    assert r.status_code == 200
    assert calls["n"] == 0, f"labelling invoked the scorer {calls['n']} times"


# ---------------------------------------------------------------------------
# labels actually land
# ---------------------------------------------------------------------------

def test_confirm_fraud_creates_the_label(client):
    txn_id, _ = make_txn(client, "setfraud")
    record(client, staff(client, "a13"), txn_id, "fraud")
    txn = backend.STATE["txns"][txn_id]
    assert txn["label"] == "fraud"
    assert txn["labelled_by"]
    assert txn["labelled_at"]


def test_mark_legitimate_creates_the_label(client):
    txn_id, _ = make_txn(client, "setlegit")
    record(client, staff(client, "a14"), txn_id, "legitimate")
    assert backend.STATE["txns"][txn_id]["label"] == "legitimate"


# ---------------------------------------------------------------------------
# rejected operations leave no trace
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("bad", ["FRAUD", "confirm_fraud", "maybe", "",
                                 "fraudulent", "legit", "true"])
def test_invalid_label_creates_no_event(client, bad):
    txn_id, _ = make_txn(client, "badlabel")
    r = record(client, staff(client, "a15"), txn_id, bad)
    assert r.status_code == 422, f"{bad!r} was accepted"
    assert outcome_events(txn_id) == []
    assert backend.STATE["txns"][txn_id]["label"] is None


def test_unknown_transaction_creates_no_event(client):
    before = len(outcome_events())
    r = record(client, staff(client, "a16"), "pay_does_not_exist", "fraud")
    assert r.status_code == 404
    assert len(outcome_events()) == before


# ---------------------------------------------------------------------------
# repeated / corrected outcomes
# ---------------------------------------------------------------------------

def test_relabelling_is_refused_rather_than_silently_applied(client):
    """Ground truth is not implicitly overwritable.

    This test previously asserted the opposite -- that unlimited re-labelling was
    permitted and each change was audited. That behaviour meant an accidental
    click on the opposite button destroyed a considered verdict with a 200 and no
    warning. Reversing a ruling is a real operation; it is not a side effect of
    re-submitting a form.
    """
    txn_id, _ = make_txn(client, "relabel")
    h = staff(client, "a17")

    assert record(client, h, txn_id, "fraud").status_code == 200
    assert record(client, h, txn_id, "legitimate").status_code == 409
    assert record(client, h, txn_id, "legitimate").status_code == 409

    events = outcome_events(txn_id)
    assert len(events) == 1
    assert events[0]["after"]["label"] == "fraud"
    # The original label stands.
    assert backend.STATE["txns"][txn_id]["label"] == "fraud"


def test_repeating_the_same_label_is_idempotent_and_emits_no_second_event(client):
    """A retry or a double-click succeeds but must not double-count one human
    decision in the data a retrain learns from."""
    txn_id, _ = make_txn(client, "same")
    h = staff(client, "a18")
    first = record(client, h, txn_id, "fraud")
    again = record(client, h, txn_id, "fraud")

    assert first.status_code == 200
    assert first.json()["idempotent"] is False
    assert again.status_code == 200
    assert again.json()["idempotent"] is True

    assert len(outcome_events(txn_id)) == 1
    assert backend.STATE["txns"][txn_id]["label"] == "fraud"


def test_a_second_analyst_cannot_overwrite_the_first(client):
    """Two people, two opinions, one label. The first stands until someone decides
    to change it deliberately -- and the conflict names who set it."""
    txn_id, _ = make_txn(client, "twoanalysts")
    h1, e1 = staff_with_email(client, "first", "analyst")
    h2, _ = staff_with_email(client, "second", "admin")
    assert record(client, h1, txn_id, "fraud").status_code == 200

    r = record(client, h2, txn_id, "legitimate")
    assert r.status_code == 409
    detail = r.json()["detail"]
    assert detail["error"] == "GROUND_TRUTH_CONFLICT"
    assert detail["existing_label"] == "fraud"
    assert detail["requested_label"] == "legitimate"
    assert detail["existing_labelled_by"] == e1

    events = outcome_events(txn_id)
    assert len(events) == 1
    assert events[0]["actor"] == e1
    assert backend.STATE["txns"][txn_id]["labelled_by"] == e1


def test_an_admin_agreeing_with_an_analyst_is_idempotent(client):
    txn_id, _ = make_txn(client, "agree")
    h1, e1 = staff_with_email(client, "agree1", "analyst")
    h2, _ = staff_with_email(client, "agree2", "admin")
    record(client, h1, txn_id, "fraud")

    r = record(client, h2, txn_id, "fraud")
    assert r.status_code == 200
    assert r.json()["idempotent"] is True
    # Still one event, still attributed to whoever actually decided.
    events = outcome_events(txn_id)
    assert len(events) == 1
    assert events[0]["actor"] == e1


# ---------------------------------------------------------------------------
# retrieval
# ---------------------------------------------------------------------------

def test_event_appears_in_the_audit_endpoint(client):
    txn_id, _ = make_txn(client, "retrieve")
    admin = staff(client, "ret", "admin")
    record(client, admin, txn_id, "fraud")

    r = client.get("/v1/admin/audit", headers=admin, params={"limit": 500})
    assert r.status_code == 200
    actions = {e["action"] for e in r.json()["entries"]}
    assert "OUTCOME_RECORDED" in actions


def test_audit_endpoint_filters_outcome_recorded(client):
    txn_id, _ = make_txn(client, "filter")
    admin = staff(client, "flt", "admin")
    record(client, admin, txn_id, "legitimate")

    r = client.get("/v1/admin/audit", headers=admin,
                   params={"action": "OUTCOME_RECORDED", "limit": 500})
    assert r.status_code == 200
    entries = r.json()["entries"]
    assert entries
    assert all(e["action"] == "OUTCOME_RECORDED" for e in entries)
    assert any(e["before"]["transaction_id"] == txn_id for e in entries)


def test_both_actions_retrievable_for_one_transaction(client):
    txn_id, _ = make_txn(client, "bothactions")
    admin = staff(client, "both", "admin")
    record(client, admin, txn_id, "fraud")

    entries = client.get("/v1/admin/audit", headers=admin,
                         params={"limit": 500}).json()["entries"]
    mine = [e for e in entries
            if e.get("before", {}).get("transaction_id") == txn_id]
    assert {e["action"] for e in mine} == {"RISK_DECISION", "OUTCOME_RECORDED"}


def test_audit_endpoint_stays_admin_only(client):
    """analyst may record outcomes but may NOT read the audit log."""
    txn_id, _ = make_txn(client, "analystread")
    h = staff(client, "a19", "analyst")
    assert record(client, h, txn_id, "fraud").status_code == 200
    assert client.get("/v1/admin/audit", headers=h).status_code == 403


# ---------------------------------------------------------------------------
# security and customer isolation
# ---------------------------------------------------------------------------

def test_event_carries_no_payment_credentials(client):
    txn_id, _ = make_txn(client, "nopan")
    record(client, staff(client, "a20"), txn_id, "fraud")
    blob = repr(outcome_events(txn_id)[0])
    for leak in ("4111", "1111 1111", '"cvv"', "Outcome Tester", PW):
        assert leak not in blob, f"audit event leaked {leak!r}"


def test_event_carries_no_authentication_material(client):
    txn_id, _ = make_txn(client, "notoken")
    h, _email = staff_with_email(client, "tok", "analyst")
    record(client, h, txn_id, "fraud")

    blob = repr(outcome_events(txn_id)[0])
    token = h["authorization"].split(" ", 1)[1]
    assert token not in blob
    assert "Bearer" not in blob
    assert PW not in blob


def test_customer_order_view_hides_label_and_analyst(client):
    """A labelled transaction must not start leaking the verdict or who set it."""
    email = f"iso-{uuid.uuid4().hex[:8]}@example.com"
    h = register(client, email)
    r = client.post("/v1/orders", headers=h, json={
        "items": [{"product_id": "p1", "qty": 1}],
        "payment_method": "card", "device_fp": "dev_iso", "card": CARD,
    })
    order_id = r.json()["order_id"]
    txn_id = next(t for t, v in backend.STATE["txns"].items()
                  if v["order_id"] == order_id)

    record(client, staff(client, "a21"), txn_id, "fraud")

    orders = client.get("/v1/orders", headers=h).json()["orders"]
    mine = next(o for o in orders if o["order_id"] == order_id)
    for f in ("label", "labelled_by", "labelled_at", "risk_score", "decision",
              "sub_scores", "reason_codes", "fired_rules", "device_fp",
              "ip_hash"):
        assert f not in mine, f"customer order view leaked {f!r}"


def test_customer_cannot_read_transaction_detail(client):
    txn_id, cust = make_txn(client, "detaildeny")
    record(client, staff(client, "a22"), txn_id, "fraud")
    r = client.get(f"/v1/admin/transactions/{txn_id}", headers=cust)
    assert r.status_code == 403


# ---------------------------------------------------------------------------
# audit failure must not corrupt the label
# ---------------------------------------------------------------------------

def test_label_survives_audit_persistence_failure(client, monkeypatch, capsys):
    txn_id, _ = make_txn(client, "flaky")
    h = staff(client, "a23")

    records = backend.STATE["records"]
    original_put = records.put

    def flaky(pk, sk, item):
        if pk.startswith("AUDIT#"):
            raise RuntimeError("simulated audit store outage")
        return original_put(pk, sk, item)

    monkeypatch.setattr(records, "put", flaky)
    r = record(client, h, txn_id, "fraud")

    assert r.status_code == 200, "audit failure broke the operation"
    assert backend.STATE["txns"][txn_id]["label"] == "fraud"
    assert len(outcome_events(txn_id)) == 1
    assert "audit write failed" in capsys.readouterr().out
    # No internal error text reached the caller.
    assert "outage" not in r.text
