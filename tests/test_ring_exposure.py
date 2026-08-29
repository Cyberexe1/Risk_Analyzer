"""Fraud-ring estimated exposure tests.

THE CLAIM UNDER TEST, STATED PRECISELY
--------------------------------------
`estimated_exposure` is the sum of transaction amounts belonging to the accounts in
a connected component, over the transactions FraudShield retains. That is all it
is. It is not money stolen, not merchant loss, and not a fraud verdict.

Most of these tests defend the honesty of the number rather than the arithmetic:

  - blocked money is reported separately, because a BLOCK never settled
  - `confirmed_fraud_amount` is NULL until a human labels something, because
    deriving it from BLOCK would be the BLOCK == FRAUD inference this system
    refuses to make
  - an incomplete or truncated component reports `complete: false` instead of
    presenting a floor as a total
  - the window is described as retained history, not invented as "last 30 days"

Run:  python -m pytest tests/test_ring_exposure.py -v
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
os.environ["FRAUDSHIELD_JWT_SECRET"] = "test-only-jwt-secret-exposure"
os.environ["FRAUDSHIELD_IP_PEPPER"] = "test-only-pepper-exposure"
os.environ.pop("FRAUDSHIELD_API_KEY", None)

from fastapi.testclient import TestClient  # noqa: E402

import backend  # noqa: E402

PW = "ring-exposure-test-password-3388"

CARD = {"number": "4111 1111 1111 1111", "expiry_month": 12,
        "expiry_year": 2029, "cvv": "123", "holder": "Exposure Tester"}

# Chosen so the pinned scorer below lands on a known decision band.
P_ALLOW = ("p1", 2499.0)        # earbuds
P_REVIEW = ("p10", 27499.0)     # 4K monitor
P_BLOCK = ("p3", 42999.0)       # phone


# ---------------------------------------------------------------------------
# deterministic decisions
# ---------------------------------------------------------------------------
#
# Real scores depend on accumulated entity state, which makes "produce a BLOCK"
# non-deterministic. These tests are about the EXPOSURE ARITHMETIC, so the decision
# is pinned by amount. Weights, thresholds and rules are untouched.

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


def order(c, headers, product, device: str):
    r = c.post("/v1/orders", headers=headers, json={
        "items": [{"product_id": product[0], "qty": 1}],
        "payment_method": "card", "device_fp": device, "card": CARD,
    })
    assert r.status_code == 201, r.text
    return r.json()


def ring(c, headers, device: str) -> dict:
    r = c.get(f"/v1/admin/rings/device/{device}", headers=headers)
    assert r.status_code == 200, r.text
    return r.json()


def txn_ids_for(customer_id: str) -> list[str]:
    return [t for t, v in backend.STATE["txns"].items()
            if v.get("customer_id") == customer_id]


# ===========================================================================
# a known ring with known amounts
# ===========================================================================

def test_known_ring_sums_the_amounts_it_can_see(db, pinned_scorer):
    """Three accounts on one device, one order each, amounts known exactly."""
    device = f"dev_ring_{uuid.uuid4().hex[:6]}"
    with app_run() as c:
        for i, product in enumerate((P_ALLOW, P_REVIEW, P_BLOCK)):
            h = register(c, f"ring{i}-{uuid.uuid4().hex[:8]}@example.com")
            order(c, h, product, device)

        st = staff(c, "ring_s")
        ex = ring(c, st, device)["exposure"]

    assert ex["transactions_counted"] == 3
    assert ex["accounts_in_component"] == 3
    assert ex["accounts_with_transactions"] == 3
    assert ex["gross_exposure"] == pytest.approx(
        P_ALLOW[1] + P_REVIEW[1] + P_BLOCK[1])
    assert ex["complete"] is True


def test_amounts_are_split_by_the_decision_the_engine_made(db, pinned_scorer):
    device = f"dev_split_{uuid.uuid4().hex[:6]}"
    with app_run() as c:
        for i, product in enumerate((P_ALLOW, P_REVIEW, P_BLOCK)):
            h = register(c, f"split{i}-{uuid.uuid4().hex[:8]}@example.com")
            order(c, h, product, device)
        st = staff(c, "split_s")
        ex = ring(c, st, device)["exposure"]

    assert ex["allowed_amount"] == pytest.approx(P_ALLOW[1])
    assert ex["review_amount"] == pytest.approx(P_REVIEW[1])
    assert ex["blocked_amount"] == pytest.approx(P_BLOCK[1])
    assert ex["unclassified_amount"] == 0
    # The four slices reconstruct the gross exactly.
    assert (ex["allowed_amount"] + ex["review_amount"] + ex["blocked_amount"]
            + ex["unclassified_amount"]) == pytest.approx(ex["gross_exposure"])


def test_blocked_money_never_settled(db, pinned_scorer):
    """A BLOCK is refused before settlement, so it cannot be part of money that
    moved. This is why blocked_amount is reported separately from settled."""
    device = f"dev_settle_{uuid.uuid4().hex[:6]}"
    with app_run() as c:
        h = register(c, f"settle-{uuid.uuid4().hex[:8]}@example.com")
        body = order(c, h, P_BLOCK, device)
        assert body["settlement"] == "failed"
        st = staff(c, "settle_s")
        ex = ring(c, st, device)["exposure"]

    assert ex["blocked_amount"] == pytest.approx(P_BLOCK[1])
    assert ex["settled_amount"] == 0.0
    assert ex["settled_amount"] < ex["gross_exposure"]


def test_multiple_transactions_from_one_account_all_count(db, pinned_scorer):
    device = f"dev_multi_{uuid.uuid4().hex[:6]}"
    with app_run() as c:
        h = register(c, f"multi-{uuid.uuid4().hex[:8]}@example.com")
        for _ in range(3):
            order(c, h, P_ALLOW, device)
        st = staff(c, "multi_s")
        ex = ring(c, st, device)["exposure"]

    assert ex["transactions_counted"] == 3
    assert ex["accounts_with_transactions"] == 1
    assert ex["gross_exposure"] == pytest.approx(P_ALLOW[1] * 3)


# ===========================================================================
# no ring
# ===========================================================================

def test_unknown_device_reports_zero_not_an_error(db, pinned_scorer):
    with app_run() as c:
        st = staff(c, "none_s")
        ex = ring(c, st, "dev_that_never_existed")["exposure"]

    assert ex["gross_exposure"] == 0.0
    assert ex["transactions_counted"] == 0
    assert ex["accounts_in_component"] == 0
    assert ex["accounts_with_transactions"] == 0
    assert ex["complete"] is True
    # Zero exposure is still not a claim of innocence.
    assert ex["confirmed_fraud_amount"] is None


def test_single_account_is_not_treated_as_a_ring_but_still_reports(db,
                                                                  pinned_scorer):
    device = f"dev_single_{uuid.uuid4().hex[:6]}"
    with app_run() as c:
        h = register(c, f"single-{uuid.uuid4().hex[:8]}@example.com")
        order(c, h, P_ALLOW, device)
        st = staff(c, "single_s")
        ex = ring(c, st, device)["exposure"]

    assert ex["accounts_in_component"] == 1
    assert ex["gross_exposure"] == pytest.approx(P_ALLOW[1])


def test_accounts_outside_the_component_are_excluded():
    """The number must be about the given accounts, not the whole store.

    Asserted against ring_exposure() directly rather than through the endpoint,
    because every TestClient request arrives from the same peer address: two
    accounts created over TestClient share an ip_hash and therefore genuinely DO
    land in one component. That is correct engine behaviour -- shared IP is a real
    edge -- so driving this through HTTP would test the fixture, not the scoping.
    """
    backend.STATE["txns"] = {
        "pay_in1": {"customer_id": "inside", "amount": 100.0,
                    "decision": "ALLOW", "settlement": "success",
                    "created_at": "2026-01-01T00:00:00+00:00"},
        "pay_in2": {"customer_id": "inside", "amount": 250.0,
                    "decision": "BLOCK", "settlement": "failed",
                    "created_at": "2026-01-02T00:00:00+00:00"},
        "pay_out": {"customer_id": "outside", "amount": 999999.0,
                    "decision": "BLOCK", "settlement": "failed",
                    "created_at": "2026-01-03T00:00:00+00:00"},
    }
    try:
        ex = backend.ring_exposure({"inside"})
    finally:
        backend.STATE.clear()

    assert ex["gross_exposure"] == 350.0
    assert ex["transactions_counted"] == 2
    assert ex["accounts_with_transactions"] == 1
    assert ex["blocked_amount"] == 250.0
    assert ex["allowed_amount"] == 100.0


def test_component_members_with_no_transactions_are_counted_separately():
    """An account in the graph that has never transacted contributes nothing to the
    money, but it is still part of the component. Conflating the two counts would
    make a large cluster look financially larger than it is."""
    backend.STATE["txns"] = {
        "pay_1": {"customer_id": "has_txns", "amount": 100.0,
                  "decision": "ALLOW", "settlement": "success",
                  "created_at": "2026-01-01T00:00:00+00:00"},
    }
    try:
        ex = backend.ring_exposure({"has_txns", "silent_a", "silent_b"})
    finally:
        backend.STATE.clear()

    assert ex["accounts_in_component"] == 3
    assert ex["accounts_with_transactions"] == 1
    assert ex["gross_exposure"] == 100.0


# ===========================================================================
# incomplete and duplicate data
# ===========================================================================

@pytest.mark.parametrize("bad_amount", [None, "not-a-number", float("nan"), -5.0])
def test_unusable_amounts_are_skipped_and_declared(bad_amount):
    """A partial figure must announce itself rather than looking complete."""
    backend.STATE["txns"] = {
        "pay_good": {"customer_id": "c1", "amount": 100.0, "decision": "ALLOW",
                     "settlement": "success", "created_at": "2026-01-01T00:00:00+00:00"},
        "pay_bad": {"customer_id": "c1", "amount": bad_amount, "decision": "ALLOW",
                    "created_at": "2026-01-02T00:00:00+00:00"},
    }
    try:
        ex = backend.ring_exposure({"c1"})
    finally:
        backend.STATE.clear()

    assert ex["gross_exposure"] == 100.0
    assert ex["transactions_counted"] == 1
    assert ex["transactions_skipped"] == 1
    assert ex["complete"] is False


def test_a_missing_decision_is_unclassified_not_silently_allowed():
    """Folding an unknown decision into `allowed` would understate what was
    refused."""
    backend.STATE["txns"] = {
        "pay_x": {"customer_id": "c1", "amount": 50.0, "decision": None,
                  "created_at": "2026-01-01T00:00:00+00:00"},
    }
    try:
        ex = backend.ring_exposure({"c1"})
    finally:
        backend.STATE.clear()

    assert ex["unclassified_amount"] == 50.0
    assert ex["allowed_amount"] == 0.0
    assert ex["gross_exposure"] == 50.0


def test_one_transaction_cannot_be_counted_twice(db, pinned_scorer):
    """Keyed by transaction_id, so an account appearing repeatedly in the
    component walk cannot inflate the total."""
    device = f"dev_dup_{uuid.uuid4().hex[:6]}"
    with app_run() as c:
        h = register(c, f"dup-{uuid.uuid4().hex[:8]}@example.com")
        order(c, h, P_ALLOW, device)
        st = staff(c, "dup_s")
        first = ring(c, st, device)["exposure"]
        # Same seed, deeper walk: the same account is reached by several paths.
        deeper = c.get(f"/v1/admin/rings/device/{device}?depth=3",
                       headers=st).json()["exposure"]

    assert first["gross_exposure"] == pytest.approx(P_ALLOW[1])
    assert deeper["gross_exposure"] == pytest.approx(P_ALLOW[1])
    assert deeper["transactions_counted"] == 1


def test_repeated_calls_are_stable(db, pinned_scorer):
    device = f"dev_stable_{uuid.uuid4().hex[:6]}"
    with app_run() as c:
        h = register(c, f"stable-{uuid.uuid4().hex[:8]}@example.com")
        order(c, h, P_REVIEW, device)
        st = staff(c, "stable_s")
        a = ring(c, st, device)["exposure"]
        b = ring(c, st, device)["exposure"]

    assert a["gross_exposure"] == b["gross_exposure"]
    assert a["review_amount"] == b["review_amount"]


# ===========================================================================
# honesty of the label
# ===========================================================================

def test_confirmed_fraud_is_null_until_a_human_labels_something(db,
                                                                pinned_scorer):
    """BLOCK is not fraud. Deriving a fraud amount from a routing decision is the
    exact inference this system refuses to make."""
    device = f"dev_gt_{uuid.uuid4().hex[:6]}"
    with app_run() as c:
        h = register(c, f"gt-{uuid.uuid4().hex[:8]}@example.com")
        order(c, h, P_BLOCK, device)
        st = staff(c, "gt_s")
        ex = ring(c, st, device)["exposure"]

    assert ex["blocked_amount"] > 0
    assert ex["confirmed_fraud_amount"] is None
    assert ex["labelled_transactions"] == 0


def test_confirmed_fraud_appears_only_after_a_human_outcome(db, pinned_scorer):
    device = f"dev_lab_{uuid.uuid4().hex[:6]}"
    with app_run() as c:
        h = register(c, f"lab-{uuid.uuid4().hex[:8]}@example.com")
        body = order(c, h, P_BLOCK, device)
        st = staff(c, "lab_s")
        txn_id = next(t for t, v in backend.STATE["txns"].items()
                      if v.get("order_id") == body["order_id"])
        r = c.post(f"/v1/admin/transactions/{txn_id}/outcome", headers=st,
                   json={"label": "fraud"})
        assert r.status_code == 200, r.text
        ex = ring(c, st, device)["exposure"]

    assert ex["labelled_transactions"] == 1
    assert ex["confirmed_fraud_amount"] == pytest.approx(P_BLOCK[1])


def test_response_carries_the_definition_and_denies_being_a_loss(db,
                                                                 pinned_scorer):
    device = f"dev_def_{uuid.uuid4().hex[:6]}"
    with app_run() as c:
        h = register(c, f"def-{uuid.uuid4().hex[:8]}@example.com")
        order(c, h, P_ALLOW, device)
        st = staff(c, "def_s")
        ex = ring(c, st, device)["exposure"]

    assert ex["is_loss_estimate"] is False
    d = ex["definition"].lower()
    assert "not a loss estimate" in d
    assert "not a fraud verdict" in d
    # And it must not use the language the spec forbids.
    assert "money stolen" not in d.replace("not money confirmed stolen", "")
    assert "merchant loss" not in d


def test_window_is_described_as_retained_history_not_invented_as_a_date_range(
        db, pinned_scorer):
    device = f"dev_win_{uuid.uuid4().hex[:6]}"
    with app_run() as c:
        h = register(c, f"win-{uuid.uuid4().hex[:8]}@example.com")
        order(c, h, P_ALLOW, device)
        st = staff(c, "win_s")
        ex = ring(c, st, device)["exposure"]

    w = ex["window"]
    assert w["kind"] == "retained transaction history"
    assert w["retained_transaction_cap"] == backend.REHYDRATE_TXNS
    assert "Not a fixed time range" in w["note"]
    assert w["earliest"] and w["latest"]


def test_truncated_component_reports_incomplete(monkeypatch, db, pinned_scorer):
    """A truncated walk drops accounts, so the figure is a floor. Saying
    `complete: true` there would present a floor as a total."""
    monkeypatch.setattr(backend, "MAX_COMPONENT", 1)
    device = f"dev_trunc_{uuid.uuid4().hex[:6]}"
    with app_run() as c:
        for i in range(3):
            h = register(c, f"trunc{i}-{uuid.uuid4().hex[:8]}@example.com")
            order(c, h, P_ALLOW, device)
        st = staff(c, "trunc_s")
        body = ring(c, st, device)


    assert body["truncated"] is True
    assert body["exposure"]["complete"] is False
    assert "truncated at MAX_COMPONENT" in body["exposure"]["window"]["note"]


# ===========================================================================
# durability
# ===========================================================================

def test_exposure_is_consistent_after_restart(db, pinned_scorer):
    """The figure is computed from the rehydrated transaction cache, so it must
    survive a restart with the same value."""
    device = f"dev_rest_{uuid.uuid4().hex[:6]}"
    with app_run() as c:
        for product in (P_ALLOW, P_REVIEW, P_BLOCK):
            h = register(c, f"rest-{uuid.uuid4().hex[:8]}@example.com")
            order(c, h, product, device)
        st = staff(c, "rest_s")
        before = ring(c, st, device)["exposure"]

    assert backend.STATE == {}

    with app_run() as c:
        st = staff(c, "rest_s2")
        after = ring(c, st, device)["exposure"]

    for field in ("gross_exposure", "blocked_amount", "review_amount",
                  "allowed_amount", "settled_amount", "transactions_counted",
                  "accounts_with_transactions"):
        assert after[field] == before[field], f"{field} changed across restart"


# ===========================================================================
# access control
# ===========================================================================

def test_customer_cannot_read_exposure(db, pinned_scorer):
    device = f"dev_acl_{uuid.uuid4().hex[:6]}"
    with app_run() as c:
        h = register(c, f"acl-{uuid.uuid4().hex[:8]}@example.com")
        order(c, h, P_ALLOW, device)
        assert c.get(f"/v1/admin/rings/device/{device}",
                     headers=h).status_code == 403
        assert c.get(f"/v1/admin/rings/device/{device}").status_code in (401, 403)


def test_analyst_can_read_exposure(db, pinned_scorer):
    device = f"dev_an_{uuid.uuid4().hex[:6]}"
    with app_run() as c:
        h = register(c, f"anx-{uuid.uuid4().hex[:8]}@example.com")
        order(c, h, P_ALLOW, device)
        st = staff(c, "an_s", role="analyst")
        assert "exposure" in ring(c, st, device)
