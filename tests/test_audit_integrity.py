"""Audit integrity tests.

WHAT THIS SUITE DEFENDS
-----------------------
The audit trail has to answer nine questions, and each one is only really
answered if a test proves it:

    WHO           actor + actor_identity{user_id, email, role}, from the token
    WHAT          action, and a human `outcome` verb distinct from the label
    WHEN          `at`, timezone-aware
    WHAT BEFORE   the automated decision the human action resolved
    WHAT CHANGED  after
    WHAT DID NOT  the machine decision, quoted and never rewritten
    GROUND TRUTH  explicit boolean, per event category
    SURVIVES?     the same event, read back after a restart
    RECONSTRUCT?  RISK_DECISION and OUTCOME_RECORDED joinable by transaction_id

Two properties get the most attention because they are the ones that quietly rot:

  * **Ground truth is never silently overwritten.** Identical resubmission is
    idempotent; a conflicting one is refused. Tested for all five cases.
  * **An incomplete audit trail never looks complete.** The endpoint reports its
    own source and completeness, so a failed durable write cannot masquerade as a
    healthy read.

Run:  python -m pytest tests/test_audit_integrity.py -v
"""
from __future__ import annotations

import os
import sys
import uuid
from contextlib import contextmanager
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

os.environ["FRAUDSHIELD_USERS_BACKEND"] = "memory"
os.environ["FRAUDSHIELD_WARM_ROWS"] = "0"
os.environ["FRAUDSHIELD_DEV_SEED_STAFF"] = "0"
os.environ["FRAUDSHIELD_JWT_SECRET"] = "test-only-jwt-secret-audit-integrity"
os.environ["FRAUDSHIELD_IP_PEPPER"] = "test-only-pepper-audit-integrity"
os.environ.pop("FRAUDSHIELD_API_KEY", None)

from fastapi.testclient import TestClient  # noqa: E402

import backend  # noqa: E402

PW = "audit-integrity-password-6604"
CARD = {"number": "4111 1111 1111 1111", "expiry_month": 12,
        "expiry_year": 2029, "cvv": "123", "holder": "Audit Tester"}

P_ALLOW = ("p1", 2499.0)
P_REVIEW = ("p10", 27499.0)
P_BLOCK = ("p3", 42999.0)

OUTCOME_PATH = "/v1/admin/transactions/{}/outcome"


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------

def _decision_for(amount: float) -> backend.Decision:
    if amount >= 40000:
        decision, score = "BLOCK", 91.4
    elif amount >= 20000:
        decision, score = "MANUAL_REVIEW", 63.4
    else:
        decision, score = "ALLOW", 3.1
    return backend.Decision(
        risk_score=score, decision=decision,
        sub_scores={"ml": score * 0.7, "rules": score * 0.2, "network": 0.0},
        reason_codes=[{"code": "VELOCITY_10M", "severity": "high",
                       "detail": "7 attempts in 10 minutes", "source": "rule"}],
        fired_rules=["velocity_burst"], override=None,
        model_version="test-model-1", degraded=False,
    )


@pytest.fixture
def pinned_scorer(monkeypatch):
    def fake_score(self, store, txn):
        return _decision_for(float(txn["amount"])), {"amount": float(txn["amount"])}

    monkeypatch.setattr(backend.Scorer, "score", fake_score)


@pytest.fixture
def db(monkeypatch):
    records = backend.InMemoryRecordStore()
    users = backend.InMemoryUserStore()
    monkeypatch.setattr(backend, "USERS_BACKEND", "memory")
    monkeypatch.setattr(backend, "make_record_store",
                        lambda: (records, "memory:audit-test"))
    monkeypatch.setattr(backend, "make_user_store",
                        lambda: (users, "memory:audit-test"))
    monkeypatch.setattr(backend, "API_KEY", "")
    return records


@contextmanager
def app_run():
    with TestClient(backend.app) as c:
        yield c


def register(c, email: str) -> dict:
    r = c.post("/v1/auth/register", json={"email": email, "password": PW})
    assert r.status_code == 201, r.text
    return {"authorization": f"Bearer {r.json()['access_token']}"}


def staff(c, tag: str, role: str = "admin") -> tuple[dict, str, str]:
    """Returns (headers, email, user_id).

    The email returned is the STORED one. Registration normalises (lower-cases)
    the address, so comparing against the string we sent would fail for any tag
    containing an upper-case letter -- which is a property of the auth layer, not
    of the audit trail.
    """
    h = register(c, f"{tag}-{uuid.uuid4().hex[:8]}@example.com")
    me = c.get("/v1/auth/me", headers=h).json()
    u = backend.STATE["users"].get(me["user_id"])
    u.role = role
    return h, u.email, u.user_id


def order(c, headers, product):
    r = c.post("/v1/orders", headers=headers, json={
        "items": [{"product_id": product[0], "qty": 1}],
        "payment_method": "card", "device_fp": "dev_audit", "card": CARD,
    })
    assert r.status_code == 201, r.text
    return r.json()


def make_txn(c, tag: str, product=P_REVIEW) -> str:
    h = register(c, f"{tag}-{uuid.uuid4().hex[:8]}@example.com")
    body = order(c, h, product)
    return next(t for t, v in backend.STATE["txns"].items()
                if v.get("order_id") == body["order_id"])


def record(c, headers, txn_id: str, label: str):
    return c.post(OUTCOME_PATH.format(txn_id), headers=headers,
                  json={"label": label})


def events(action: str) -> list[dict]:
    return [e for e in backend.STATE["audit"] if e.get("action") == action]


def outcome_events(txn_id: str) -> list[dict]:
    return [e for e in events(backend.OUTCOME_RECORDED)
            if e["before"].get("transaction_id") == txn_id]


def held_rid(c, tag: str) -> str:
    for i in range(6):
        h = register(c, f"{tag}{i}-{uuid.uuid4().hex[:8]}@example.com")
        r = c.post("/v1/promo/redeem", headers=h, json={
            "promo_code": "WELCOME500", "device_fp": "dev_audit_promo",
            "payout_ref": "upi_audit_promo"})
        rid = r.json()["redemption_id"]
        if rid in backend.STATE["promo_queue"]:
            return rid
    raise AssertionError("could not produce a promo hold")


# ===========================================================================
# 1. actor identity  (F1, F2)
# ===========================================================================

def test_outcome_records_the_full_authenticated_identity(db, pinned_scorer):
    with app_run() as c:
        txn_id = make_txn(c, "ident")
        h, email, uid = staff(c, "ident_s", role="analyst")
        record(c, h, txn_id, "fraud")
        ev = outcome_events(txn_id)[0]

        assert ev["actor"] == email
        assert ev["actor_identity"] == {"user_id": uid, "email": email,
                                        "role": "analyst"}


def test_promo_override_records_the_full_authenticated_identity(db):
    with app_run() as c:
        rid = held_rid(c, "pident")
        h, email, uid = staff(c, "pident_s", role="admin")
        c.post(f"/v1/admin/promo-holds/{rid}/override", headers=h, json={})
        ev = events(backend.PROMO_OVERRIDE)[0]

        assert ev["actor"] == email
        assert ev["actor_identity"] == {"user_id": uid, "email": email,
                                        "role": "admin"}


def test_threshold_update_records_the_full_authenticated_identity(db):
    with app_run() as c:
        h, email, uid = staff(c, "tident_s", role="admin")
        c.put("/v1/admin/thresholds", headers=h,
              json={"review": 7, "block": 77})
        ev = events(backend.THRESHOLD_UPDATE)[0]

        assert ev["actor"] == email
        assert ev["actor_identity"] == {"user_id": uid, "email": email,
                                        "role": "admin"}


def test_role_at_the_time_is_captured_not_looked_up_later(db, pinned_scorer):
    """Roles are granted out-of-band and can change. 'Was this person allowed to
    do it?' is unanswerable later if the role at the time is not recorded."""
    with app_run() as c:
        txn_id = make_txn(c, "rolechange")
        h, email, _ = staff(c, "rolechange_s", role="analyst")
        record(c, h, txn_id, "fraud")

        # Role changes afterwards. The event must still say `analyst`.
        backend.STATE["users"].get_by_email(email).role = "admin"
        assert outcome_events(txn_id)[0]["actor_identity"]["role"] == "analyst"


def test_automated_events_carry_no_actor_identity(db, pinned_scorer):
    """`actor_identity` means a person. A system event must not fabricate one."""
    with app_run() as c:
        make_txn(c, "sysident")
        for action in (backend.RISK_DECISION, backend.NOTIFICATION_SENT):
            for ev in events(action):
                assert "actor_identity" not in ev, action


def test_identity_carries_no_authentication_material(db, pinned_scorer):
    with app_run() as c:
        txn_id = make_txn(c, "nocreds")
        h, _, _ = staff(c, "nocreds_s")
        record(c, h, txn_id, "fraud")
        ident = outcome_events(txn_id)[0]["actor_identity"]

        assert set(ident) == {"user_id", "email", "role"}
        blob = repr(ident).lower()
        for forbidden in ("password", "hash", "token", "argon", "$"):
            assert forbidden not in blob


@pytest.mark.parametrize("extra", [
    {"analyst_id": "attacker@evil.example"},
    {"actor": "attacker@evil.example"},
    {"actor_identity": {"role": "admin"}},
    {"is_ground_truth": False},
    {"labl": "fraud"},
])
def test_unknown_body_fields_are_rejected(db, pinned_scorer, extra):
    """The endpoint that creates ground truth accepts no field it does not use."""
    with app_run() as c:
        txn_id = make_txn(c, "extra")
        h, _, _ = staff(c, "extra_s")
        r = c.post(OUTCOME_PATH.format(txn_id), headers=h,
                   json={"label": "fraud", **extra})

        assert r.status_code == 422, r.text
        assert backend.STATE["txns"][txn_id]["label"] is None
        assert outcome_events(txn_id) == []


# ===========================================================================
# 2. OUTCOME_RECORDED shape  (F4)
# ===========================================================================

def test_before_holds_the_automated_state_the_human_resolved(db, pinned_scorer):
    with app_run() as c:
        txn_id = make_txn(c, "before", P_REVIEW)
        stored = dict(backend.STATE["txns"][txn_id])
        h, _, _ = staff(c, "before_s")
        record(c, h, txn_id, "legitimate")
        ev = outcome_events(txn_id)[0]

        b = ev["before"]
        assert b["transaction_id"] == txn_id
        assert b["order_id"] == stored["order_id"]
        assert b["decision"] == "MANUAL_REVIEW"
        assert b["risk_score"] == 63.4
        assert b["label"] is None
        assert b["settlement"] == stored["settlement"]
        assert b["customer_status"] == stored["customer_status"]


def test_after_holds_the_human_conclusion(db, pinned_scorer):
    with app_run() as c:
        txn_id = make_txn(c, "after", P_REVIEW)
        h, _, _ = staff(c, "after_s")
        record(c, h, txn_id, "legitimate")
        a = outcome_events(txn_id)[0]["after"]

        assert a["label"] == "legitimate"
        assert a["outcome"] == "MARK_LEGITIMATE"
        assert a["ground_truth"] is True
        assert a["is_ground_truth"] is True
        assert a["note"]


def test_confirm_fraud_uses_the_confirm_verb(db, pinned_scorer):
    with app_run() as c:
        txn_id = make_txn(c, "verb")
        h, _, _ = staff(c, "verb_s")
        record(c, h, txn_id, "fraud")
        assert outcome_events(txn_id)[0]["after"]["outcome"] == "CONFIRM_FRAUD"


def test_the_automated_decision_and_the_human_conclusion_are_distinguishable(
        db, pinned_scorer):
    """The sentence an auditor is reading: MANUAL_REVIEW / 63.4 -> MARK_LEGITIMATE."""
    with app_run() as c:
        txn_id = make_txn(c, "distinct", P_REVIEW)
        h, _, _ = staff(c, "distinct_s")
        record(c, h, txn_id, "legitimate")
        ev = outcome_events(txn_id)[0]

        assert ev["before"]["decision"] == "MANUAL_REVIEW"
        assert ev["before"]["risk_score"] == 63.4
        assert ev["after"]["outcome"] == "MARK_LEGITIMATE"
        # Neither is derived from the other.
        assert ev["before"]["decision"] != ev["after"]["outcome"]
        assert ev["after"]["confusion_cell"] == "false_positive"


def test_compatibility_aliases_are_retained(db, pinned_scorer):
    """`original_*` moved to `before` but the old names still resolve, so nothing
    reading historical events breaks."""
    with app_run() as c:
        txn_id = make_txn(c, "alias", P_BLOCK)
        h, _, _ = staff(c, "alias_s")
        record(c, h, txn_id, "fraud")
        ev = outcome_events(txn_id)[0]

        assert ev["after"]["original_decision"] == ev["before"]["decision"]
        assert ev["after"]["original_risk_score"] == ev["before"]["risk_score"]
        assert ev["before"]["previous_label"] == ev["before"]["label"]


def test_the_risk_decision_event_is_not_mutated(db, pinned_scorer):
    with app_run() as c:
        txn_id = make_txn(c, "immutable", P_BLOCK)
        risk = [e for e in events(backend.RISK_DECISION)
                if e["before"]["transaction_id"] == txn_id][0]
        snapshot = repr(risk)

        h, _, _ = staff(c, "immutable_s")
        record(c, h, txn_id, "legitimate")

        assert repr(risk) == snapshot
        assert risk["after"]["is_ground_truth"] is False
        assert risk["actor"] == "system:scorer"
        assert "label" not in risk["after"]


def test_the_pair_is_joinable_by_transaction_id(db, pinned_scorer):
    """Phase 9: existing identifiers already correlate the automated decision to
    the human one. No extra UUID chain is needed."""
    with app_run() as c:
        txn_id = make_txn(c, "join", P_REVIEW)
        h, _, _ = staff(c, "join_s")
        record(c, h, txn_id, "fraud")

        risk = [e for e in events(backend.RISK_DECISION)
                if e["before"]["transaction_id"] == txn_id]
        out = outcome_events(txn_id)
        assert len(risk) == 1 and len(out) == 1
        assert risk[0]["before"]["order_id"] == out[0]["before"]["order_id"]
        # And the human event is strictly later.
        assert out[0]["at"] >= risk[0]["at"]


# ===========================================================================
# 3. PROMO_OVERRIDE shape  (F5)
# ===========================================================================

def test_promo_before_and_after_are_self_contained(db):
    with app_run() as c:
        rid = held_rid(c, "pshape")
        idx = db.get("INDEX#PROMO", rid)
        stored = db.get(f"CUSTOMER#{idx['customer_id']}", idx["sk"])
        h, email, _ = staff(c, "pshape_s")
        c.post(f"/v1/admin/promo-holds/{rid}/override", headers=h,
               json={"reason": "verified with support"})
        ev = events(backend.PROMO_OVERRIDE)[0]

        b, a = ev["before"], ev["after"]
        assert b["redemption_id"] == rid
        # The PRE-override state. `stored` was fetched before the override, but
        # InMemoryRecordStore hands out the live dict, so it has since been
        # mutated -- these are asserted against literals on purpose.
        assert b["decision"] in backend.PROMO_QUEUED_DECISIONS
        # HOLD -> under_review, DENY -> denied. Either way it is the PRE-override
        # status, never "credited".
        assert b["status"] == {"HOLD": "under_review",
                               "DENY": "denied"}[b["decision"]]
        assert b["status"] != "credited"
        assert b["label"] is None
        # Retained aliases.
        assert b["machine_decision"] == b["decision"]
        assert b["machine_status"] == b["status"]

        assert a["status"] == "credited"
        assert a["resolved_status"] == "credited"
        assert a["label"] == "legitimate"
        assert a["override_by"] == email
        assert a["override_at"]
        assert a["is_ground_truth"] is True
        assert a["reason"] == "verified with support"


def test_promo_event_override_at_matches_the_record(db):
    """Self-contained means the event agrees with the record, not that it guesses."""
    with app_run() as c:
        rid = held_rid(c, "pmatch")
        idx = db.get("INDEX#PROMO", rid)
        h, _, _ = staff(c, "pmatch_s")
        c.post(f"/v1/admin/promo-holds/{rid}/override", headers=h, json={})
        stored = db.get(f"CUSTOMER#{idx['customer_id']}", idx["sk"])
        ev = events(backend.PROMO_OVERRIDE)[0]

        assert ev["after"]["override_by"] == stored["override_by"]
        assert ev["after"]["override_at"] == stored["override_at"]


def test_promo_machine_decision_is_never_rewritten(db):
    with app_run() as c:
        rid = held_rid(c, "pimm")
        idx = db.get("INDEX#PROMO", rid)
        before = db.get(f"CUSTOMER#{idx['customer_id']}", idx["sk"])["decision"]
        h, _, _ = staff(c, "pimm_s")
        c.post(f"/v1/admin/promo-holds/{rid}/override", headers=h, json={})
        after = db.get(f"CUSTOMER#{idx['customer_id']}", idx["sk"])
        ev = events(backend.PROMO_OVERRIDE)[0]

        assert after["decision"] == before
        assert after["decision"] != "ALLOW"
        assert ev["before"]["decision"] == before
        assert ev["after"]["machine_decision_unchanged"] == before


def test_promo_override_emits_exactly_one_event_and_repeat_is_refused(db):
    with app_run() as c:
        rid = held_rid(c, "ponce")
        h, _, _ = staff(c, "ponce_s")
        first = c.post(f"/v1/admin/promo-holds/{rid}/override", headers=h, json={})
        again = c.post(f"/v1/admin/promo-holds/{rid}/override", headers=h, json={})

        assert first.status_code == 200
        assert again.status_code == 409
        assert len(events(backend.PROMO_OVERRIDE)) == 1


# ===========================================================================
# 4. conflict protection -- Phase 6 cases A-E  (F3)
# ===========================================================================

def test_case_a_first_ruling_is_accepted(db, pinned_scorer):
    with app_run() as c:
        txn_id = make_txn(c, "caseA")
        h, _, _ = staff(c, "caseA_s")
        r = record(c, h, txn_id, "fraud")

        assert r.status_code == 200
        assert r.json()["idempotent"] is False
        assert len(outcome_events(txn_id)) == 1
        assert backend.STATE["txns"][txn_id]["label"] == "fraud"


@pytest.mark.parametrize("label", ["fraud", "legitimate"])
def test_cases_b_and_d_identical_resubmission_is_idempotent(db, pinned_scorer,
                                                            label):
    with app_run() as c:
        txn_id = make_txn(c, f"caseBD_{label}")
        h, _, _ = staff(c, f"caseBD_{label}_s")
        record(c, h, txn_id, label)
        stamp = backend.STATE["txns"][txn_id]["labelled_at"]

        for _ in range(3):
            r = record(c, h, txn_id, label)
            assert r.status_code == 200
            assert r.json()["idempotent"] is True

        assert len(outcome_events(txn_id)) == 1
        assert backend.STATE["txns"][txn_id]["label"] == label
        # Not even the timestamp moves: nothing was written.
        assert backend.STATE["txns"][txn_id]["labelled_at"] == stamp


@pytest.mark.parametrize("first,second", [("fraud", "legitimate"),
                                         ("legitimate", "fraud")])
def test_cases_c_and_e_conflicting_outcome_is_refused(db, pinned_scorer,
                                                      first, second):
    with app_run() as c:
        txn_id = make_txn(c, f"caseCE_{first}")
        h, email, _ = staff(c, f"caseCE_{first}_s")
        record(c, h, txn_id, first)
        original = outcome_events(txn_id)[0]
        snapshot = repr(original)

        r = record(c, h, txn_id, second)
        assert r.status_code == 409
        d = r.json()["detail"]
        assert d["error"] == "GROUND_TRUTH_CONFLICT"
        assert d["existing_label"] == first
        assert d["requested_label"] == second
        assert d["existing_labelled_by"] == email
        assert d["transaction_id"] == txn_id

        # Label preserved, event preserved and unmutated, no second event.
        assert backend.STATE["txns"][txn_id]["label"] == first
        assert len(outcome_events(txn_id)) == 1
        assert repr(original) == snapshot


def test_a_conflict_writes_nothing_at_all(db, pinned_scorer):
    with app_run() as c:
        txn_id = make_txn(c, "nowrite")
        h, email, _ = staff(c, "nowrite_s")
        record(c, h, txn_id, "fraud")
        before_stamp = backend.STATE["txns"][txn_id]["labelled_at"]
        before_audit = len(backend.STATE["audit"])

        record(c, h, txn_id, "legitimate")

        assert backend.STATE["txns"][txn_id]["labelled_at"] == before_stamp
        assert backend.STATE["txns"][txn_id]["labelled_by"] == email
        assert len(backend.STATE["audit"]) == before_audit
        assert db.get(f"TXN#{txn_id}", "DETAIL")["label"] == "fraud"


def test_conflict_survives_a_restart(db, pinned_scorer):
    """The refusal must be based on durable state, not process memory."""
    with app_run() as c:
        txn_id = make_txn(c, "conflictrestart")
        h, _, _ = staff(c, "cr_s")
        record(c, h, txn_id, "fraud")

    with app_run() as c:
        h, _, _ = staff(c, "cr_s2")
        assert record(c, h, txn_id, "legitimate").status_code == 409
        assert record(c, h, txn_id, "fraud").json()["idempotent"] is True
        assert backend.STATE["txns"][txn_id]["label"] == "fraud"


def test_an_unknown_transaction_still_404s(db, pinned_scorer):
    with app_run() as c:
        h, _, _ = staff(c, "unknown_s")
        r = c.post(OUTCOME_PATH.format("pay_does_not_exist"), headers=h,
                   json={"label": "fraud"})
        assert r.status_code == 404
        assert events(backend.OUTCOME_RECORDED) == []


# ===========================================================================
# 5. restart durability of the complete event  (F6)
# ===========================================================================

def test_the_complete_outcome_event_survives_a_restart(db, pinned_scorer):
    """Not the label -- the EVENT. Actor, identity, timestamp, before, after and
    the ground-truth marker, read back through the API after a restart."""
    with app_run() as c:
        txn_id = make_txn(c, "durable", P_REVIEW)
        h, email, uid = staff(c, "durable_s", role="analyst")
        record(c, h, txn_id, "legitimate")
        before_restart = outcome_events(txn_id)[0]

    assert backend.STATE == {}, "STATE must be wiped between runs"

    with app_run() as c:
        h2, _, _ = staff(c, "durable_s2", role="admin")
        got = c.get(f"/v1/admin/audit?action={backend.OUTCOME_RECORDED}",
                    headers=h2).json()
        assert got["count"] == 1
        after_restart = got["entries"][0]

    assert after_restart["event_id"] == before_restart["event_id"]
    assert after_restart["actor"] == email
    assert after_restart["actor_identity"] == {"user_id": uid, "email": email,
                                               "role": "analyst"}
    assert after_restart["at"] == before_restart["at"]
    assert after_restart["before"] == before_restart["before"]
    assert after_restart["after"] == before_restart["after"]
    assert after_restart["before"]["transaction_id"] == txn_id
    assert after_restart["before"]["decision"] == "MANUAL_REVIEW"
    assert after_restart["before"]["risk_score"] == 63.4
    assert after_restart["after"]["is_ground_truth"] is True
    assert after_restart["after"]["outcome"] == "MARK_LEGITIMATE"


def test_the_risk_decision_and_outcome_pair_both_survive(db, pinned_scorer):
    """An analyst must be able to reconstruct the whole history after a restart."""
    with app_run() as c:
        txn_id = make_txn(c, "pairdurable", P_BLOCK)
        h, _, _ = staff(c, "pd_s")
        record(c, h, txn_id, "fraud")

    with app_run() as c:
        h, _, _ = staff(c, "pd_s2", role="admin")
        rows = c.get("/v1/admin/audit?limit=500", headers=h).json()["entries"]

    by_action = {}
    for r in rows:
        by_action.setdefault(r["action"], []).append(r)
    risk = [r for r in by_action[backend.RISK_DECISION]
            if r["before"]["transaction_id"] == txn_id]
    out = [r for r in by_action[backend.OUTCOME_RECORDED]
           if r["before"]["transaction_id"] == txn_id]

    assert len(risk) == 1 and len(out) == 1
    assert risk[0]["after"]["is_ground_truth"] is False
    assert out[0]["after"]["is_ground_truth"] is True
    assert out[0]["at"] >= risk[0]["at"]


def test_the_promo_override_event_survives_a_restart(db):
    with app_run() as c:
        rid = held_rid(c, "pdurable")
        h, email, uid = staff(c, "pdurable_s", role="analyst")
        c.post(f"/v1/admin/promo-holds/{rid}/override", headers=h, json={})
        before_restart = events(backend.PROMO_OVERRIDE)[0]

    with app_run() as c:
        h2, _, _ = staff(c, "pdurable_s2", role="admin")
        got = c.get(f"/v1/admin/audit?action={backend.PROMO_OVERRIDE}",
                    headers=h2).json()
        assert got["count"] == 1
        after = got["entries"][0]

    assert after["actor_identity"] == {"user_id": uid, "email": email,
                                       "role": "analyst"}
    assert after["before"] == before_restart["before"]
    assert after["after"] == before_restart["after"]
    assert after["after"]["is_ground_truth"] is True


def test_the_threshold_event_survives_a_restart(db):
    with app_run() as c:
        h, email, uid = staff(c, "tdurable_s", role="admin")
        c.put("/v1/admin/thresholds", headers=h,
              json={"review": 9, "block": 79, "reason": "audit test"})

    with app_run() as c:
        h, _, _ = staff(c, "tdurable_s2", role="admin")
        got = c.get(f"/v1/admin/audit?action={backend.THRESHOLD_UPDATE}",
                    headers=h).json()

    assert got["count"] == 1
    ev = got["entries"][0]
    assert ev["actor_identity"] == {"user_id": uid, "email": email,
                                    "role": "admin"}
    assert ev["before"]["review"] == 5.0
    assert ev["after"]["review"] == 9.0
    assert ev["after"]["reason"] == "audit test"
    # A threshold change is an admin action but NOT ground truth.
    assert "is_ground_truth" not in ev["after"]
    assert "ground_truth" not in ev["after"]


# ===========================================================================
# 6. DynamoDB parity via the existing FakeTable  (F7)
# ===========================================================================
#
# Reuses the FakeTable pattern from tests/test_persistence.py rather than
# inventing a second fake store: it drives the REAL DynamoRecordStore, so the
# actual Decimal coercion and key handling are exercised without AWS.

class FakeTable:
    """Minimal boto3 Table stand-in: put/get/query/update."""

    def __init__(self):
        self.items: dict[tuple[str, str], dict] = {}

    def put_item(self, Item):  # noqa: N803
        self.items[(Item["PK"], Item["SK"])] = dict(Item)

    def get_item(self, Key):  # noqa: N803
        it = self.items.get((Key["PK"], Key["SK"]))
        return {"Item": dict(it)} if it else {}

    def query(self, KeyConditionExpression, ExpressionAttributeValues,  # noqa: N803
              ScanIndexForward=True):  # noqa: N803
        pk = ExpressionAttributeValues[":p"]
        prefix = ExpressionAttributeValues.get(":s")
        rows = [dict(v) for (p, s), v in self.items.items()
                if p == pk and (prefix is None or s.startswith(prefix))]
        rows.sort(key=lambda r: r["SK"], reverse=not ScanIndexForward)
        return {"Items": rows}

    def update_item(self, Key, UpdateExpression,  # noqa: N803
                    ExpressionAttributeNames, ExpressionAttributeValues):  # noqa: N803
        it = self.items.get((Key["PK"], Key["SK"]))
        if it is None:
            return
        for placeholder, name in ExpressionAttributeNames.items():
            it[name] = ExpressionAttributeValues[":v" + placeholder[2:]]


def _dynamo_store() -> backend.DynamoRecordStore:
    """The real adapter, with a fake table injected. No boto3, no network."""
    s = object.__new__(backend.DynamoRecordStore)
    s._t = FakeTable()
    return s


@pytest.fixture
def dynamo_db(monkeypatch):
    store = _dynamo_store()
    users = backend.InMemoryUserStore()
    monkeypatch.setattr(backend, "USERS_BACKEND", "memory")
    monkeypatch.setattr(backend, "make_record_store",
                        lambda: (store, "dynamodb:fake-table"))
    monkeypatch.setattr(backend, "make_user_store",
                        lambda: (users, "memory:audit-test"))
    monkeypatch.setattr(backend, "API_KEY", "")
    return store


def test_audit_event_is_written_through_the_dynamo_adapter(dynamo_db,
                                                           pinned_scorer):
    with app_run() as c:
        txn_id = make_txn(c, "dyn")
        h, _, _ = staff(c, "dyn_s", role="analyst")
        record(c, h, txn_id, "fraud")

    day = backend.datetime.now(backend.timezone.utc).isoformat()[:10]
    rows = dynamo_db.query_prefix(f"AUDIT#{day}", "")
    actions = {r["action"] for r in rows}
    assert backend.RISK_DECISION in actions
    assert backend.OUTCOME_RECORDED in actions


def test_risk_score_round_trips_through_decimal_coercion(dynamo_db,
                                                        pinned_scorer):
    """DynamoDB has no float type. The adapter coerces to Decimal on write and
    back on read; a corrupted round trip would silently change audited evidence."""
    with app_run() as c:
        txn_id = make_txn(c, "dec", P_REVIEW)
        h, _, _ = staff(c, "dec_s")
        record(c, h, txn_id, "legitimate")

    day = backend.datetime.now(backend.timezone.utc).isoformat()[:10]
    out = [r for r in dynamo_db.query_prefix(f"AUDIT#{day}", "")
           if r["action"] == backend.OUTCOME_RECORDED][0]

    # 63.4 must come back as 63.4, as a float, not a Decimal and not 63.
    assert out["before"]["risk_score"] == 63.4
    assert isinstance(out["before"]["risk_score"], float)
    assert out["after"]["original_risk_score"] == 63.4
    # Nested sub-scores survive too.
    subs = out["after"]["original_sub_scores"]
    assert subs["ml"] == pytest.approx(63.4 * 0.7)


def test_actor_identity_and_ground_truth_survive_the_dynamo_path(dynamo_db,
                                                                 pinned_scorer):
    with app_run() as c:
        txn_id = make_txn(c, "dynid")
        h, email, uid = staff(c, "dynid_s", role="analyst")
        record(c, h, txn_id, "fraud")

    day = backend.datetime.now(backend.timezone.utc).isoformat()[:10]
    out = [r for r in dynamo_db.query_prefix(f"AUDIT#{day}", "")
           if r["action"] == backend.OUTCOME_RECORDED][0]

    assert out["actor"] == email
    assert out["actor_identity"] == {"user_id": uid, "email": email,
                                     "role": "analyst"}
    assert out["after"]["is_ground_truth"] is True
    assert out["after"]["outcome"] == "CONFIRM_FRAUD"
    assert out["before"]["decision"] == "MANUAL_REVIEW"


def test_the_api_representation_matches_between_both_stores(monkeypatch,
                                                            pinned_scorer):
    """The point of parity: an auditor must see the same event whichever store is
    configured. Compared at the API level, not byte-for-byte in storage."""
    def run(store):
        users = backend.InMemoryUserStore()
        monkeypatch.setattr(backend, "USERS_BACKEND", "memory")
        monkeypatch.setattr(backend, "make_record_store",
                            lambda: (store, "test"))
        monkeypatch.setattr(backend, "make_user_store",
                            lambda: (users, "test"))
        monkeypatch.setattr(backend, "API_KEY", "")
        with app_run() as c:
            txn_id = make_txn(c, "parity", P_REVIEW)
            h, _, _ = staff(c, "parity_s", role="analyst")
            record(c, h, txn_id, "legitimate")
            adm, _, _ = staff(c, "parity_a", role="admin")
            got = c.get(f"/v1/admin/audit?action={backend.OUTCOME_RECORDED}",
                        headers=adm).json()
        return got["entries"][0]

    mem = run(backend.InMemoryRecordStore())
    dyn = run(_dynamo_store())

    # Identifiers and timestamps differ per run; the SHAPE and the evidence must
    # not.
    assert set(mem) == set(dyn)
    assert set(mem["before"]) == set(dyn["before"])
    assert set(mem["after"]) == set(dyn["after"])
    assert mem["before"]["decision"] == dyn["before"]["decision"] == "MANUAL_REVIEW"
    assert mem["before"]["risk_score"] == dyn["before"]["risk_score"] == 63.4
    assert mem["after"]["outcome"] == dyn["after"]["outcome"] == "MARK_LEGITIMATE"
    assert mem["after"]["is_ground_truth"] is dyn["after"]["is_ground_truth"] is True
    assert set(mem["actor_identity"]) == set(dyn["actor_identity"])


def test_promo_before_snapshot_is_correct_in_dynamo_mode_too(dynamo_db):
    """The bug this guards: InMemoryRecordStore.get() returns the live dict, so an
    un-copied `before` reported the AFTER status -- and only in memory mode, so
    the two stores disagreed about what the audit trail said."""
    with app_run() as c:
        rid = held_rid(c, "dynpromo")
        h, _, _ = staff(c, "dynpromo_s")
        c.post(f"/v1/admin/promo-holds/{rid}/override", headers=h, json={})

    day = backend.datetime.now(backend.timezone.utc).isoformat()[:10]
    ev = [r for r in dynamo_db.query_prefix(f"AUDIT#{day}", "")
          if r["action"] == backend.PROMO_OVERRIDE][0]

    assert ev["before"]["status"] != "credited"
    assert ev["before"]["label"] is None
    assert ev["after"]["status"] == "credited"
    assert ev["after"]["label"] == "legitimate"


# ===========================================================================
# 7. audit API projection  (F8)
# ===========================================================================

def test_the_audit_endpoint_never_returns_storage_keys(db, pinned_scorer):
    """This was the only admin projection in the codebase that was not an
    allow-list, which made it the one place a future field would leak from."""
    with app_run() as c:
        txn_id = make_txn(c, "proj")
        h, _, _ = staff(c, "proj_s", role="admin")
        record(c, h, txn_id, "fraud")
        got = c.get("/v1/admin/audit?limit=500", headers=h).json()

    assert got["entries"]
    for entry in got["entries"]:
        assert "PK" not in entry
        assert "SK" not in entry
    blob = repr(got["entries"])
    assert "'PK'" not in blob and "'SK'" not in blob
    assert "AUDIT#" not in blob


def test_the_projection_keeps_every_audit_domain_field(db, pinned_scorer):
    with app_run() as c:
        txn_id = make_txn(c, "keep")
        h, _, _ = staff(c, "keep_s", role="admin")
        record(c, h, txn_id, "fraud")
        entry = [e for e in c.get(f"/v1/admin/audit?action={backend.OUTCOME_RECORDED}",
                                  headers=h).json()["entries"]][0]

    for field in ("event_id", "action", "actor", "actor_identity", "at",
                  "before", "after"):
        assert field in entry, field


def test_the_dynamo_projection_also_strips_storage_keys(dynamo_db,
                                                        pinned_scorer):
    """Dynamo stamps PK/SK into the item itself, so this is where the leak was
    most visible."""
    with app_run() as c:
        txn_id = make_txn(c, "dynproj")
        h, _, _ = staff(c, "dynproj_s", role="admin")
        record(c, h, txn_id, "fraud")
        got = c.get("/v1/admin/audit?limit=500", headers=h).json()

    assert got["entries"]
    for entry in got["entries"]:
        assert "PK" not in entry and "SK" not in entry


# ===========================================================================
# 8. persistence failure visibility  (F10)
# ===========================================================================

def test_a_healthy_read_reports_persistent_and_complete(db, pinned_scorer):
    with app_run() as c:
        txn_id = make_txn(c, "healthy")
        h, _, _ = staff(c, "healthy_s", role="admin")
        record(c, h, txn_id, "fraud")
        got = c.get("/v1/admin/audit", headers=h).json()

    assert got["source"] == "persistent"
    assert got["complete"] is True
    assert got["warning"] is None
    assert got["count"] >= 1


def test_an_empty_audit_log_is_empty_not_degraded(db):
    """A fresh day's partition is legitimately empty. Calling that degraded would
    cry wolf every midnight."""
    with app_run() as c:
        h, _, _ = staff(c, "empty_s", role="admin")
        # Registration itself emits no audit event.
        got = c.get("/v1/admin/audit", headers=h).json()

    assert got["count"] == 0
    assert got["source"] == "empty"
    assert got["complete"] is True
    assert got["warning"] is None


def test_a_failed_read_reports_memory_fallback_and_incomplete(db, pinned_scorer,
                                                             monkeypatch):
    """This used to be `persisted or memory`, which silently substituted the
    in-process log when the durable read FAILED -- so the endpoint looked healthy
    while serving a list that dies with the process."""
    with app_run() as c:
        txn_id = make_txn(c, "readfail")
        h, _, _ = staff(c, "readfail_s", role="admin")
        record(c, h, txn_id, "fraud")

        original = backend.InMemoryRecordStore.query_prefix

        def flaky(self, pk, sk_prefix, desc=True):
            if pk.startswith("AUDIT#"):
                raise RuntimeError("simulated store outage")
            return original(self, pk, sk_prefix, desc)

        monkeypatch.setattr(backend.InMemoryRecordStore, "query_prefix", flaky)
        got = c.get("/v1/admin/audit", headers=h).json()

    assert got["source"] == "memory_fallback"
    assert got["complete"] is False
    assert "incomplete" in got["warning"].lower()
    # Still serves what it has -- degraded, not broken.
    assert got["count"] >= 1


def test_a_failed_read_exposes_no_stack_trace(db, pinned_scorer, monkeypatch):
    with app_run() as c:
        txn_id = make_txn(c, "notrace")
        h, _, _ = staff(c, "notrace_s", role="admin")
        record(c, h, txn_id, "fraud")

        def boom(self, pk, sk_prefix, desc=True):
            raise RuntimeError("internal-host-db-07.corp.example connection refused")

        monkeypatch.setattr(backend.InMemoryRecordStore, "query_prefix", boom)
        got = c.get("/v1/admin/audit", headers=h).json()

    blob = repr(got)
    assert "internal-host-db-07" not in blob
    assert "Traceback" not in blob
    assert "RuntimeError" not in blob


def test_a_failed_durable_write_makes_the_read_report_incomplete(db,
                                                                pinned_scorer,
                                                                monkeypatch):
    """The subtler case: the READ works, but the process holds events the store
    does not. That is still not a complete picture."""
    with app_run() as c:
        original = backend.InMemoryRecordStore.put

        def flaky(self, pk, sk, item):
            if pk.startswith("AUDIT#"):
                raise RuntimeError("simulated write outage")
            return original(self, pk, sk, item)

        monkeypatch.setattr(backend.InMemoryRecordStore, "put", flaky)
        txn_id = make_txn(c, "writefail")
        h, _, _ = staff(c, "writefail_s", role="admin")
        record(c, h, txn_id, "fraud")

        got = c.get("/v1/admin/audit", headers=h).json()
        # Read inside the context: lifespan clears STATE on exit.
        # The label still landed -- an audit failure must not fail the audited
        # action.
        assert backend.STATE["txns"][txn_id]["label"] == "fraud"

    assert got["source"] == "memory_fallback"
    assert got["complete"] is False
    assert got["warning"]


def test_restored_persistence_reports_persistent_again(db, pinned_scorer,
                                                       monkeypatch):
    with app_run() as c:
        txn_id = make_txn(c, "restored")
        h, _, _ = staff(c, "restored_s", role="admin")
        record(c, h, txn_id, "fraud")

        original = backend.InMemoryRecordStore.query_prefix
        broken = {"on": True}

        def flaky(self, pk, sk_prefix, desc=True):
            if broken["on"] and pk.startswith("AUDIT#"):
                raise RuntimeError("outage")
            return original(self, pk, sk_prefix, desc)

        monkeypatch.setattr(backend.InMemoryRecordStore, "query_prefix", flaky)
        assert c.get("/v1/admin/audit", headers=h).json()["complete"] is False

        broken["on"] = False
        got = c.get("/v1/admin/audit", headers=h).json()

    assert got["source"] == "persistent"
    assert got["complete"] is True
    assert got["warning"] is None


def test_an_audit_write_failure_never_fabricates_ground_truth(db, pinned_scorer,
                                                             monkeypatch,
                                                             capsys):
    """An audit failure must not invent a label, and must not hide itself."""
    with app_run() as c:
        original = backend.InMemoryRecordStore.put

        def flaky(self, pk, sk, item):
            if pk.startswith("AUDIT#"):
                raise RuntimeError("simulated")
            return original(self, pk, sk, item)

        monkeypatch.setattr(backend.InMemoryRecordStore, "put", flaky)
        txn_id = make_txn(c, "nofab")
        h, _, _ = staff(c, "nofab_s")
        r = record(c, h, txn_id, "fraud")

        assert r.status_code == 200, "an audit failure broke the audited action"
        assert "audit write failed" in capsys.readouterr().out


# ===========================================================================
# 9. authorization  (Phase 11)
# ===========================================================================

@pytest.mark.parametrize("method,path,body", [
    ("get", "/v1/admin/audit", None),
    ("post", "/v1/admin/transactions/pay_x/outcome", {"label": "fraud"}),
    ("post", "/v1/admin/promo-holds/rdm_x/override", {}),
    ("put", "/v1/admin/thresholds", {"review": 6, "block": 71}),
    ("get", "/v1/admin/notifications", None),
])
def test_anonymous_is_refused(db, method, path, body):
    with app_run() as c:
        r = c.request(method.upper(), path, json=body)
        assert r.status_code in (401, 403), f"{method} {path} -> {r.status_code}"


@pytest.mark.parametrize("method,path,body", [
    ("get", "/v1/admin/audit", None),
    ("post", "/v1/admin/transactions/pay_x/outcome", {"label": "fraud"}),
    ("post", "/v1/admin/promo-holds/rdm_x/override", {}),
    ("put", "/v1/admin/thresholds", {"review": 6, "block": 71}),
    ("get", "/v1/admin/notifications", None),
])
def test_a_customer_is_refused(db, method, path, body):
    with app_run() as c:
        h = register(c, f"cust-{uuid.uuid4().hex[:8]}@example.com")
        r = c.request(method.upper(), path, headers=h, json=body)
        assert r.status_code == 403, f"{method} {path} -> {r.status_code}"


def test_analyst_permissions_match_policy(db, pinned_scorer):
    """An analyst decides individual cases. They may create ground truth but may
    not browse everyone else's trail or move a threshold."""
    with app_run() as c:
        txn_id = make_txn(c, "anpol")
        rid = held_rid(c, "anpol_p")
        h, _, _ = staff(c, "anpol_s", role="analyst")

        assert record(c, h, txn_id, "fraud").status_code == 200
        assert c.post(f"/v1/admin/promo-holds/{rid}/override",
                      headers=h, json={}).status_code == 200
        assert c.get("/v1/admin/notifications", headers=h).status_code == 200
        # Denied.
        assert c.get("/v1/admin/audit", headers=h).status_code == 403
        assert c.put("/v1/admin/thresholds", headers=h,
                     json={"review": 6, "block": 71}).status_code == 403


def test_admin_permissions(db, pinned_scorer):
    with app_run() as c:
        txn_id = make_txn(c, "admpol")
        rid = held_rid(c, "admpol_p")
        h, _, _ = staff(c, "admpol_s", role="admin")

        assert record(c, h, txn_id, "fraud").status_code == 200
        assert c.post(f"/v1/admin/promo-holds/{rid}/override",
                      headers=h, json={}).status_code == 200
        assert c.get("/v1/admin/audit", headers=h).status_code == 200
        assert c.put("/v1/admin/thresholds", headers=h,
                     json={"review": 6, "block": 71}).status_code == 200


def test_a_refused_action_writes_no_audit_event(db, pinned_scorer):
    with app_run() as c:
        txn_id = make_txn(c, "refused")
        h = register(c, f"cust2-{uuid.uuid4().hex[:8]}@example.com")
        c.post(OUTCOME_PATH.format(txn_id), headers=h, json={"label": "fraud"})

        assert outcome_events(txn_id) == []
        assert backend.STATE["txns"][txn_id]["label"] is None


# ===========================================================================
# 10. notification separation  (Phase 10)
# ===========================================================================

def test_notification_events_create_no_label(db, pinned_scorer, monkeypatch):
    monkeypatch.setattr(backend, "_EMAIL_CFG", {
        "requested": "console", "sender": "a@x.com",
        "recipients_raw": "analyst@fraudshield.local", "host": "", "port": 587,
        "username": "", "password": "", "use_tls": True, "console_url": "",
    })
    with app_run() as c:
        txn_id = make_txn(c, "notiflabel", P_BLOCK)

        assert events(backend.NOTIFICATION_SENT), "no alert was produced"
        assert backend.STATE["txns"][txn_id]["label"] is None
        assert events(backend.OUTCOME_RECORDED) == []
        for ev in events(backend.NOTIFICATION_SENT):
            assert ev["after"]["is_ground_truth"] is False
            assert "label" not in ev["after"]


def test_a_notification_failure_creates_no_label(db, pinned_scorer, monkeypatch):
    class Failing:
        provider_name = "failing"

        def is_configured(self):
            return True

        def send_email(self, **kw):
            import notifications as nf
            return nf.SendResult(provider="failing", status=nf.STATUS_FAILED,
                                 recipient_count=1, error="x",
                                 error_category="auth_failed")

    monkeypatch.setattr(backend, "_EMAIL_CFG", {
        "requested": "console", "sender": "a@x.com",
        "recipients_raw": "analyst@fraudshield.local", "host": "", "port": 587,
        "username": "", "password": "", "use_tls": True, "console_url": "",
    })
    with app_run() as c:
        backend.STATE["email_provider"] = Failing()
        txn_id = make_txn(c, "notiffail", P_BLOCK)

        assert events(backend.NOTIFICATION_FAILED)
        assert backend.STATE["txns"][txn_id]["label"] is None
        assert events(backend.OUTCOME_RECORDED) == []
        # And the decision stands.
        assert backend.STATE["txns"][txn_id]["decision"] == "BLOCK"


def test_notification_never_changes_the_score_or_decision(db, pinned_scorer,
                                                          monkeypatch):
    monkeypatch.setattr(backend, "_EMAIL_CFG", {
        "requested": "console", "sender": "a@x.com",
        "recipients_raw": "analyst@fraudshield.local", "host": "", "port": 587,
        "username": "", "password": "", "use_tls": True, "console_url": "",
    })
    with app_run() as c:
        txn_id = make_txn(c, "notifscore", P_REVIEW)
        stored = backend.STATE["txns"][txn_id]
        risk = [e for e in events(backend.RISK_DECISION)
                if e["before"]["transaction_id"] == txn_id][0]

        assert stored["risk_score"] == 63.4
        assert stored["decision"] == "MANUAL_REVIEW"
        assert risk["after"]["risk_score"] == 63.4


def test_the_five_event_categories_stay_distinct(db, pinned_scorer, monkeypatch):
    """RISK_DECISION / OUTCOME_RECORDED / PROMO_OVERRIDE / NOTIFICATION_SENT /
    threshold_update must never collapse into one another."""
    monkeypatch.setattr(backend, "_EMAIL_CFG", {
        "requested": "console", "sender": "a@x.com",
        "recipients_raw": "analyst@fraudshield.local", "host": "", "port": 587,
        "username": "", "password": "", "use_tls": True, "console_url": "",
    })
    with app_run() as c:
        txn_id = make_txn(c, "fivecat", P_REVIEW)
        rid = held_rid(c, "fivecat_p")
        h, email, _ = staff(c, "fivecat_s", role="admin")
        record(c, h, txn_id, "fraud")
        c.post(f"/v1/admin/promo-holds/{rid}/override", headers=h, json={})
        c.put("/v1/admin/thresholds", headers=h, json={"review": 8, "block": 78})

        risk = events(backend.RISK_DECISION)[0]
        out = events(backend.OUTCOME_RECORDED)[0]
        promo = events(backend.PROMO_OVERRIDE)[0]
        notif = events(backend.NOTIFICATION_SENT)[0]
        thr = events(backend.THRESHOLD_UPDATE)[0]

    # Distinct actions.
    assert len({risk["action"], out["action"], promo["action"],
                notif["action"], thr["action"]}) == 5
    # Automated and communication events name a system actor; human ones a person.
    assert risk["actor"] == "system:scorer"
    assert notif["actor"] == "system:notifier"
    assert out["actor"] == promo["actor"] == thr["actor"] == email
    # Only the two human ground-truth events claim ground truth.
    assert out["after"]["is_ground_truth"] is True
    assert promo["after"]["is_ground_truth"] is True
    assert risk["after"]["is_ground_truth"] is False
    assert notif["after"]["is_ground_truth"] is False
    assert "is_ground_truth" not in thr["after"]
    # Only human events carry an identity.
    assert "actor_identity" in out and "actor_identity" in promo
    assert "actor_identity" in thr
    assert "actor_identity" not in risk and "actor_identity" not in notif


# ===========================================================================
# 11. security regressions  (Phase 10 of the brief)
# ===========================================================================

def test_no_audit_event_contains_any_credential(db, pinned_scorer, monkeypatch):
    """One sweep over every event type this system can emit."""
    monkeypatch.setattr(backend, "_EMAIL_CFG", {
        "requested": "console", "sender": "alerts@x.com",
        "recipients_raw": "analyst@fraudshield.local", "host": "smtp.x.com",
        "port": 587, "username": "smtp-user@x.com",
        "password": "SMTP-SECRET-MUST-NOT-APPEAR", "use_tls": True,
        "console_url": "",
    })
    monkeypatch.setattr(backend, "RAZORPAY_KEY_SECRET", "RZP-SECRET-MUST-NOT-APPEAR")
    monkeypatch.setattr(backend, "WEBHOOK_SECRET", "WEBHOOK-SECRET-MUST-NOT-APPEAR")

    with app_run() as c:
        txn_id = make_txn(c, "sweep", P_BLOCK)
        rid = held_rid(c, "sweep_p")
        h, _, _ = staff(c, "sweep_s", role="admin")
        record(c, h, txn_id, "fraud")
        c.post(f"/v1/admin/promo-holds/{rid}/override", headers=h, json={})
        c.put("/v1/admin/thresholds", headers=h, json={"review": 8, "block": 78})
        api = repr(c.get("/v1/admin/audit?limit=500", headers=h).json())
        raw = repr(backend.STATE["audit"])

    for blob in (api, raw):
        # Payment credentials.
        assert "4111111111111111" not in blob.replace(" ", "")
        assert "4111 1111 1111 1111" not in blob
        assert '"cvv"' not in blob and "'cvv'" not in blob
        # Auth material.
        assert PW not in blob
        assert os.environ["FRAUDSHIELD_JWT_SECRET"] not in blob
        assert backend.IP_PEPPER not in blob
        assert "argon2" not in blob.lower()
        assert "password_hash" not in blob
        assert "refresh" not in blob.lower()
        assert "authorization" not in blob.lower()
        # Provider and mail secrets.
        assert "SMTP-SECRET-MUST-NOT-APPEAR" not in blob
        assert "RZP-SECRET-MUST-NOT-APPEAR" not in blob
        assert "WEBHOOK-SECRET-MUST-NOT-APPEAR" not in blob
        assert "smtp-user@x.com" not in blob


def test_legitimate_audit_fields_are_not_over_redacted(db, pinned_scorer):
    """The inverse risk: an audit trail redacted into uselessness."""
    with app_run() as c:
        txn_id = make_txn(c, "notredacted", P_REVIEW)
        h, email, _ = staff(c, "notredacted_s", role="admin")
        record(c, h, txn_id, "fraud")
        ev = [e for e in c.get(f"/v1/admin/audit?action={backend.OUTCOME_RECORDED}",
                               headers=h).json()["entries"]][0]

    assert ev["actor"] == email
    assert ev["actor_identity"]["role"] == "admin"
    assert ev["before"]["decision"] == "MANUAL_REVIEW"
    assert ev["before"]["risk_score"] == 63.4
    assert ev["before"]["transaction_id"] == txn_id
    assert ev["after"]["label"] == "fraud"
    assert ev["after"]["confusion_cell"]
    assert ev["at"]


def test_a_provider_exception_message_never_reaches_the_audit_trail(db,
                                                                   pinned_scorer,
                                                                   monkeypatch):
    import payments

    class Leaky:
        name = "razorpay"

        def is_configured(self):
            return True

        def authorise(self, **kw):
            return payments.ProviderOrder(
                provider="razorpay", settlement=payments.SETTLED_PENDING,
                error="Razorpay said: key rzp_test_LEAKED at host internal-07")

        def fetch_payment(self, pid):  # pragma: no cover
            raise AssertionError

    with app_run() as c:
        backend.STATE["payment_provider"] = Leaky()
        make_txn(c, "leaky", P_REVIEW)
        blob = repr(backend.STATE["audit"])

    assert "rzp_test_LEAKED" not in blob
    assert "internal-07" not in blob


def test_the_customer_api_exposes_no_audit_evidence(db, pinned_scorer):
    with app_run() as c:
        email = f"cust3-{uuid.uuid4().hex[:8]}@example.com"
        h = register(c, email)
        body = order(c, h, P_REVIEW)
        txn_id = next(t for t, v in backend.STATE["txns"].items()
                      if v.get("order_id") == body["order_id"])
        st, _, _ = staff(c, "custev_s", role="admin")
        record(c, st, txn_id, "fraud")

        one = c.get(f"/v1/orders/{body['order_id']}", headers=h).json()
        listed = c.get("/v1/orders", headers=h).json()
        assert c.get(f"/v1/admin/transactions/{txn_id}",
                     headers=h).status_code == 403

    for blob in (repr(one), repr(listed)):
        assert "label" not in blob
        assert "labelled_by" not in blob
        assert "actor" not in blob
        assert "OUTCOME_RECORDED" not in blob
        assert "risk_score" not in blob
        assert "reason_codes" not in blob
