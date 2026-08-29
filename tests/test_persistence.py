"""Durable transaction + review queue persistence tests.

HOW "RESTART" IS SIMULATED
--------------------------
A shared record-store instance plays the role of the database; entering and
leaving a TestClient context plays the role of an application run. So:

    with client(store) as c: ...        # run 1
    with client(store) as c: ...        # run 2, same database, fresh process state

STATE is wiped between runs by lifespan's STATE.clear(), so anything that
survives did so because it was genuinely persisted and rehydrated -- not because
a dictionary happened to still be in memory.

No AWS credentials are required. Stores are forced in-memory, and the
DynamoRecordStore parity test drives a fake table object rather than boto3.

Run:  python -m pytest tests/test_persistence.py -v
"""
from __future__ import annotations

import copy
import os
import sys
import threading
import uuid
from contextlib import contextmanager
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

os.environ["FRAUDSHIELD_USERS_BACKEND"] = "memory"
os.environ["FRAUDSHIELD_WARM_ROWS"] = "0"
os.environ["FRAUDSHIELD_DEV_SEED_STAFF"] = "0"
os.environ["FRAUDSHIELD_JWT_SECRET"] = "test-only-jwt-secret-persistence"
os.environ["FRAUDSHIELD_IP_PEPPER"] = "test-only-pepper-persistence"
os.environ.pop("FRAUDSHIELD_API_KEY", None)

from fastapi.testclient import TestClient  # noqa: E402

import backend  # noqa: E402

PW = "persistence-test-password-4417"

CARD = {"number": "4111 1111 1111 1111", "expiry_month": 12,
        "expiry_year": 2029, "cvv": "123", "holder": "Persistence Tester"}

# Products chosen so the deterministic scorer below lands on a known decision.
P_ALLOW = ("p1", 2499.0)        # earbuds
P_REVIEW = ("p10", 27499.0)     # 4K monitor
P_BLOCK = ("p3", 42999.0)       # phone


# ---------------------------------------------------------------------------
# deterministic scoring
# ---------------------------------------------------------------------------
#
# Real scores depend on accumulated entity state, which makes "produce a BLOCK"
# non-deterministic. These tests are about PERSISTENCE, so the decision is pinned
# by amount. The real scorer is exercised unpatched in
# test_real_scoring_still_persists.

def _decision_for(amount: float) -> backend.Decision:
    if amount >= 40000:
        decision, score = "BLOCK", 91.4
    elif amount >= 20000:
        decision, score = "MANUAL_REVIEW", 47.2
    else:
        decision, score = "ALLOW", 3.1
    return backend.Decision(
        risk_score=score,
        decision=decision,
        sub_scores={"ml": score * 0.7, "rules": score * 0.2, "network": 0.0},
        reason_codes=[{"code": "TEST_SIGNAL", "severity": "medium",
                       "detail": "deterministic test reason", "source": "rule"}],
        fired_rules=["new_device"],
        override=None,
        model_version="test-model-1",
        degraded=False,
    )


@pytest.fixture
def pinned_scorer(monkeypatch):
    """Pin the decision by amount, without touching weights or thresholds."""
    def fake_score(self, store, txn):
        return _decision_for(float(txn["amount"])), {"amount": float(txn["amount"])}

    monkeypatch.setattr(backend.Scorer, "score", fake_score)


# ---------------------------------------------------------------------------
# shared "database" across application runs
# ---------------------------------------------------------------------------

@pytest.fixture
def db(monkeypatch):
    """One record store and one user store, shared across every app run in a test.

    Forced in-memory. Patching the factories is what makes the store outlive
    lifespan, which is precisely the property under test.
    """
    records = backend.InMemoryRecordStore()
    users = backend.InMemoryUserStore()
    monkeypatch.setattr(backend, "USERS_BACKEND", "memory")
    monkeypatch.setattr(backend, "make_record_store",
                        lambda: (records, "memory:shared-test"))
    monkeypatch.setattr(backend, "make_user_store",
                        lambda: (users, "memory:shared-test"))
    return records


@contextmanager
def app_run():
    """One application lifecycle."""
    with TestClient(backend.app) as c:
        yield c


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def register(c, email: str) -> dict:
    r = c.post("/v1/auth/register", json={"email": email, "password": PW})
    assert r.status_code == 201, r.text
    return {"authorization": f"Bearer {r.json()['access_token']}"}


def staff_headers(c, email: str, role: str = "admin") -> dict:
    """Existing token picks up the role change; current_user re-reads the store."""
    h = register(c, email)
    backend.STATE["users"].get_by_email(email).role = role
    return h


def order(c, headers, product=P_ALLOW, device="dev_persist"):
    r = c.post("/v1/orders", headers=headers, json={
        "items": [{"product_id": product[0], "qty": 1}],
        "payment_method": "card", "device_fp": device, "card": CARD,
    })
    assert r.status_code == 201, r.text
    body = r.json()
    txn_id = next(t for t, v in backend.STATE["txns"].items()
                  if v.get("order_id") == body["order_id"])
    return body, txn_id


def stored(db, txn_id: str) -> dict | None:
    return db.get(f"TXN#{txn_id}", "DETAIL")


def queue_item(db, txn_id: str) -> dict | None:
    return db.get("QUEUE#REVIEW", f"ITEM#{txn_id}")


# ===========================================================================
# A. transaction persistence
# ===========================================================================

def test_scored_transaction_is_persisted(db, pinned_scorer):
    with app_run() as c:
        h = register(c, f"p1-{uuid.uuid4().hex[:8]}@example.com")
        body, txn_id = order(c, h)
    it = stored(db, txn_id)
    assert it is not None, "transaction was not written to the record store"
    assert it["transaction_id"] == txn_id
    assert it["order_id"] == body["order_id"]


def test_persisted_transaction_contains_the_risk_evidence(db, pinned_scorer):
    with app_run() as c:
        h = register(c, f"p2-{uuid.uuid4().hex[:8]}@example.com")
        _, txn_id = order(c, h, P_REVIEW)
    it = stored(db, txn_id)
    for field in ("risk_score", "decision", "sub_scores", "reason_codes",
                  "fired_rules", "model_version", "degraded", "device_fp",
                  "ip_hash", "amount", "payment_method", "customer_id",
                  "created_at", "label"):
        assert field in it, f"persisted transaction is missing {field!r}"
    assert set(it["sub_scores"]) == {"ml", "rules", "network"}
    assert it["label"] is None


def test_rehydration_pointer_is_written(db, pinned_scorer):
    with app_run() as c:
        h = register(c, f"p3-{uuid.uuid4().hex[:8]}@example.com")
        _, txn_id = order(c, h)
    pointers = db.query_prefix("INDEX#TXN", "", desc=True)
    assert any(p["transaction_id"] == txn_id for p in pointers)


def test_persisted_transaction_holds_no_payment_credentials(db, pinned_scorer):
    with app_run() as c:
        h = register(c, f"p4-{uuid.uuid4().hex[:8]}@example.com")
        _, txn_id = order(c, h)
    blob = repr(stored(db, txn_id))
    for leak in ("4111", "1111 1111", '"cvv"', CARD["holder"], PW):
        assert leak not in blob, f"persisted transaction leaked {leak!r}"


def test_transaction_survives_restart_with_identical_evidence(db, pinned_scorer):
    with app_run() as c:
        h = staff_headers(c, f"p5-{uuid.uuid4().hex[:8]}@example.com")
        _, txn_id = order(c, h, P_BLOCK)
        before = c.get(f"/v1/admin/transactions/{txn_id}", headers=h).json()

    with app_run() as c:
        h = staff_headers(c, f"p5b-{uuid.uuid4().hex[:8]}@example.com")
        r = c.get(f"/v1/admin/transactions/{txn_id}", headers=h)
        assert r.status_code == 200, "transaction vanished across restart"
        after = r.json()

    assert after["risk_score"] == before["risk_score"]
    assert after["decision"] == before["decision"]
    assert after["reason_codes"] == before["reason_codes"]
    assert after["fired_rules"] == before["fired_rules"]
    assert after["sub_scores"] == before["sub_scores"]
    assert after["model_version"] == before["model_version"]


def test_reload_does_not_rescore(db, pinned_scorer, monkeypatch):
    """Rehydration must read, never re-decide."""
    with app_run() as c:
        h = register(c, f"p6-{uuid.uuid4().hex[:8]}@example.com")
        _, txn_id = order(c, h, P_REVIEW)

    calls = {"n": 0}
    real = backend.Scorer.score

    def counting(self, store, txn):
        calls["n"] += 1
        return real(self, store, txn)

    monkeypatch.setattr(backend.Scorer, "score", counting)
    with app_run():
        pass
    assert calls["n"] == 0, "rehydration invoked the scorer"


def test_scorer_runs_exactly_once_per_order(db, monkeypatch):
    calls = {"n": 0}
    real = backend.Scorer.score

    def counting(self, store, txn):
        calls["n"] += 1
        return real(self, store, txn)

    monkeypatch.setattr(backend.Scorer, "score", counting)
    with app_run() as c:
        h = register(c, f"p7-{uuid.uuid4().hex[:8]}@example.com")
        order(c, h)
    assert calls["n"] == 1, f"scorer ran {calls['n']} times for one order"


def test_real_scoring_still_persists(db):
    """Unpatched scorer, to prove the pinned fixture is not hiding a break."""
    with app_run() as c:
        h = staff_headers(c, f"p8-{uuid.uuid4().hex[:8]}@example.com")
        _, txn_id = order(c, h)
        live = c.get(f"/v1/admin/transactions/{txn_id}", headers=h).json()
    it = stored(db, txn_id)
    assert it["risk_score"] == live["risk_score"]
    assert it["decision"] == live["decision"]


# ===========================================================================
# B. review queue
# ===========================================================================

def test_manual_review_enters_the_durable_queue(db, pinned_scorer):
    with app_run() as c:
        h = register(c, f"q1-{uuid.uuid4().hex[:8]}@example.com")
        _, txn_id = order(c, h, P_REVIEW)
    q = queue_item(db, txn_id)
    assert q is not None
    assert q["status"] == "open"
    assert q["decision"] == "MANUAL_REVIEW"


def test_allow_does_not_enter_the_queue(db, pinned_scorer):
    with app_run() as c:
        h = register(c, f"q2-{uuid.uuid4().hex[:8]}@example.com")
        _, txn_id = order(c, h, P_ALLOW)
        assert txn_id not in backend.STATE["queue"]
    assert queue_item(db, txn_id) is None


def test_block_is_queued_matching_existing_behaviour(db, pinned_scorer):
    """BLOCK has always been queued alongside MANUAL_REVIEW. Preserved, not
    changed -- a blocked transaction still needs a human to confirm the call."""
    assert "BLOCK" in backend.QUEUED_DECISIONS
    with app_run() as c:
        h = register(c, f"q3-{uuid.uuid4().hex[:8]}@example.com")
        _, txn_id = order(c, h, P_BLOCK)
        assert txn_id in backend.STATE["queue"]
    assert queue_item(db, txn_id)["status"] == "open"


def test_review_item_survives_restart(db, pinned_scorer):
    with app_run() as c:
        h = staff_headers(c, f"q4-{uuid.uuid4().hex[:8]}@example.com")
        _, txn_id = order(c, h, P_REVIEW)
        ids = [i["transaction_id"] for i in c.get("/v1/admin/queue",
                                                  headers=h).json()["items"]]
        assert txn_id in ids

    with app_run() as c:
        h = staff_headers(c, f"q4b-{uuid.uuid4().hex[:8]}@example.com")
        items = c.get("/v1/admin/queue", headers=h).json()["items"]
        assert txn_id in [i["transaction_id"] for i in items], \
            "review item lost across restart"
        item = next(i for i in items if i["transaction_id"] == txn_id)
        assert item["risk_score"] == 47.2
        assert item["decision"] == "MANUAL_REVIEW"


def test_queue_ordering_is_risk_descending_after_restart(db, pinned_scorer):
    with app_run() as c:
        h = register(c, f"q5-{uuid.uuid4().hex[:8]}@example.com")
        _, low = order(c, h, P_REVIEW, device="dev_q5a")
        _, high = order(c, h, P_BLOCK, device="dev_q5b")

    with app_run() as c:
        h = staff_headers(c, f"q5b-{uuid.uuid4().hex[:8]}@example.com")
        items = c.get("/v1/admin/queue", headers=h).json()["items"]
        scores = [i["risk_score"] for i in items]
        assert scores == sorted(scores, reverse=True), "queue order not by risk"
        ids = [i["transaction_id"] for i in items]
        assert ids.index(high) < ids.index(low)


def test_resolved_item_leaves_the_queue_and_stays_gone(db, pinned_scorer):
    with app_run() as c:
        h = staff_headers(c, f"q6-{uuid.uuid4().hex[:8]}@example.com")
        _, txn_id = order(c, h, P_REVIEW)
        assert c.post(f"/v1/admin/transactions/{txn_id}/outcome",
                      headers=h, json={"label": "fraud"}).status_code == 200
        ids = [i["transaction_id"] for i in c.get("/v1/admin/queue",
                                                  headers=h).json()["items"]]
        assert txn_id not in ids

    assert queue_item(db, txn_id)["status"] == "resolved"

    with app_run() as c:
        h = staff_headers(c, f"q6b-{uuid.uuid4().hex[:8]}@example.com")
        ids = [i["transaction_id"] for i in c.get("/v1/admin/queue",
                                                  headers=h).json()["items"]]
        assert txn_id not in ids, "resolved item came back after restart"


def test_open_review_item_is_not_dropped_by_the_history_cap(db, pinned_scorer,
                                                            monkeypatch):
    """History is capped for rehydration; an unreviewed backlog item never is."""
    with app_run() as c:
        h = register(c, f"q7-{uuid.uuid4().hex[:8]}@example.com")
        _, queued = order(c, h, P_REVIEW, device="dev_q7_queued")
        for i in range(4):
            order(c, h, P_ALLOW, device=f"dev_q7_{i}")

    monkeypatch.setattr(backend, "REHYDRATE_TXNS", 1)
    with app_run() as c:
        h = staff_headers(c, f"q7b-{uuid.uuid4().hex[:8]}@example.com")
        ids = [i["transaction_id"] for i in c.get("/v1/admin/queue",
                                                  headers=h).json()["items"]]
        assert queued in ids, "capped rehydration dropped an open review item"
        assert c.get(f"/v1/admin/transactions/{queued}",
                     headers=h).status_code == 200


# ===========================================================================
# C. customer
# ===========================================================================

def test_customer_order_history_survives_restart(db, pinned_scorer):
    email = f"c1-{uuid.uuid4().hex[:8]}@example.com"
    with app_run() as c:
        h = register(c, email)
        body, _ = order(c, h)
        order_id = body["order_id"]

    with app_run() as c:
        r = c.post("/v1/auth/login", json={"email": email, "password": PW})
        h = {"authorization": f"Bearer {r.json()['access_token']}"}
        orders = c.get("/v1/orders", headers=h).json()["orders"]
        assert order_id in [o["order_id"] for o in orders]
        one = c.get(f"/v1/orders/{order_id}", headers=h)
        assert one.status_code == 200
        assert one.json()["order_id"] == order_id


def test_customer_projection_still_hides_internals_after_restart(db, pinned_scorer):
    email = f"c2-{uuid.uuid4().hex[:8]}@example.com"
    with app_run() as c:
        h = register(c, email)
        body, _ = order(c, h, P_BLOCK)
        order_id = body["order_id"]

    with app_run() as c:
        r = c.post("/v1/auth/login", json={"email": email, "password": PW})
        h = {"authorization": f"Bearer {r.json()['access_token']}"}
        one = c.get(f"/v1/orders/{order_id}", headers=h).json()
        for f in ("risk_score", "sub_scores", "reason_codes", "fired_rules",
                  "model_version", "degraded", "device_fp", "ip_hash",
                  "features", "label", "labelled_by"):
            assert f not in one, f"customer order leaked {f!r} after restart"


# ===========================================================================
# D. admin / authorization
# ===========================================================================

def test_customer_cannot_read_transaction_detail_after_restart(db, pinned_scorer):
    email = f"d1-{uuid.uuid4().hex[:8]}@example.com"
    with app_run() as c:
        h = register(c, email)
        _, txn_id = order(c, h, P_REVIEW)

    with app_run() as c:
        r = c.post("/v1/auth/login", json={"email": email, "password": PW})
        h = {"authorization": f"Bearer {r.json()['access_token']}"}
        assert c.get(f"/v1/admin/transactions/{txn_id}",
                     headers=h).status_code == 403
        assert c.get("/v1/admin/queue", headers=h).status_code == 403


def test_analyst_can_read_rehydrated_queue(db, pinned_scorer):
    with app_run() as c:
        h = register(c, f"d2-{uuid.uuid4().hex[:8]}@example.com")
        _, txn_id = order(c, h, P_REVIEW)

    with app_run() as c:
        h = staff_headers(c, f"d2b-{uuid.uuid4().hex[:8]}@example.com",
                          role="analyst")
        r = c.get("/v1/admin/queue", headers=h)
        assert r.status_code == 200
        assert txn_id in [i["transaction_id"] for i in r.json()["items"]]


def test_anonymous_still_refused(db, pinned_scorer):
    with app_run() as c:
        assert c.get("/v1/admin/queue").status_code in (401, 403)


# ===========================================================================
# E. webhook
# ===========================================================================

def _signed(c, secret, *, amount_paise=2749900, event_id=None, payment_id=None):
    import hashlib
    import hmac
    import json
    import time

    pid = payment_id or f"pay_{uuid.uuid4().hex[:12]}"
    eid = event_id or f"evt_{uuid.uuid4().hex[:12]}"
    body = {
        "id": eid, "entity": "event", "event": "payment.captured",
        "created_at": time.time(),
        "payload": {"payment": {"entity": {
            "id": pid, "amount": amount_paise, "currency": "INR",
            "status": "captured", "method": "card",
            "email": "webhook-persist@example.com", "contact": "+919876543210",
            "notes": {"device_fp": "dev_wh_persist", "ip_hash": "ip_wh_persist"},
        }}},
    }
    raw = json.dumps(body).encode()
    sig = hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
    return c.post("/v1/webhooks/payment", content=raw, headers={
        "content-type": "application/json",
        "x-razorpay-signature": sig,
        "x-razorpay-event-id": eid,
    }), eid


@pytest.fixture
def webhook_secret(monkeypatch):
    secret = "persistence-test-webhook-secret"
    monkeypatch.setattr(backend, "WEBHOOK_SECRET", secret)
    return secret


def test_webhook_transaction_is_persisted_and_survives_restart(
        db, pinned_scorer, webhook_secret):
    with app_run() as c:
        r, _ = _signed(c, webhook_secret)
        assert r.status_code == 200, r.text
        txn_id = r.json()["transaction_id"]
    assert stored(db, txn_id) is not None

    with app_run() as c:
        h = staff_headers(c, f"e1-{uuid.uuid4().hex[:8]}@example.com")
        assert c.get(f"/v1/admin/transactions/{txn_id}",
                     headers=h).status_code == 200


def test_webhook_replay_does_not_duplicate_transaction_or_queue(
        db, pinned_scorer, webhook_secret):
    with app_run() as c:
        r, eid = _signed(c, webhook_secret)
        txn_id = r.json()["transaction_id"]
        again, _ = _signed(c, webhook_secret, event_id=eid,
                           payment_id=r.json()["payment_id"])
        assert again.status_code == 200
        assert again.json()["duplicate"] is True
        assert again.json()["transaction_id"] is None

    pointers = [p for p in db.query_prefix("INDEX#TXN", "", desc=True)]
    assert sum(1 for p in pointers if p["transaction_id"] == txn_id) == 1
    queued = [q for q in db.query_prefix("QUEUE#REVIEW", "ITEM#")]
    assert sum(1 for q in queued if q["transaction_id"] == txn_id) <= 1


def test_webhook_review_item_survives_restart(db, pinned_scorer, webhook_secret):
    with app_run() as c:
        # 27,499 -> MANUAL_REVIEW under the pinned scorer.
        r, _ = _signed(c, webhook_secret, amount_paise=2749900)
        txn_id = r.json()["transaction_id"]
        assert r.json()["decision"] == "MANUAL_REVIEW"

    with app_run() as c:
        h = staff_headers(c, f"e3-{uuid.uuid4().hex[:8]}@example.com")
        ids = [i["transaction_id"] for i in c.get("/v1/admin/queue",
                                                  headers=h).json()["items"]]
        assert txn_id in ids


# ===========================================================================
# F. outcome / ground truth
# ===========================================================================

def test_outcome_survives_restart(db, pinned_scorer):
    with app_run() as c:
        h = staff_headers(c, f"f1-{uuid.uuid4().hex[:8]}@example.com")
        _, txn_id = order(c, h, P_REVIEW)
        c.post(f"/v1/admin/transactions/{txn_id}/outcome", headers=h,
               json={"label": "legitimate"})

    assert stored(db, txn_id)["label"] == "legitimate"

    with app_run() as c:
        h = staff_headers(c, f"f1b-{uuid.uuid4().hex[:8]}@example.com")
        d = c.get(f"/v1/admin/transactions/{txn_id}", headers=h).json()
        assert d["label"] == "legitimate"
        assert d["labelled_by"]
        assert d["labelled_at"]


def test_machine_decision_unchanged_by_the_outcome(db, pinned_scorer):
    with app_run() as c:
        h = staff_headers(c, f"f2-{uuid.uuid4().hex[:8]}@example.com")
        _, txn_id = order(c, h, P_BLOCK)
        before = copy.deepcopy(stored(db, txn_id))
        c.post(f"/v1/admin/transactions/{txn_id}/outcome", headers=h,
               json={"label": "legitimate"})
    after = stored(db, txn_id)
    for f in ("risk_score", "decision", "sub_scores", "reason_codes",
              "fired_rules", "model_version"):
        assert after[f] == before[f], f"outcome altered {f!r}"


def test_block_alone_never_becomes_ground_truth(db, pinned_scorer):
    with app_run() as c:
        h = staff_headers(c, f"f3-{uuid.uuid4().hex[:8]}@example.com")
        _, txn_id = order(c, h, P_BLOCK)
        assert stored(db, txn_id)["decision"] == "BLOCK"
        assert stored(db, txn_id)["label"] is None

    with app_run() as c:
        h = staff_headers(c, f"f3b-{uuid.uuid4().hex[:8]}@example.com")
        assert c.get(f"/v1/admin/transactions/{txn_id}",
                     headers=h).json()["label"] is None


def test_outcome_audit_intact_and_no_rescore_on_reload(db, pinned_scorer):
    with app_run() as c:
        h = staff_headers(c, f"f4-{uuid.uuid4().hex[:8]}@example.com")
        _, txn_id = order(c, h, P_REVIEW)
        c.post(f"/v1/admin/transactions/{txn_id}/outcome", headers=h,
               json={"label": "fraud"})
        rd = [e for e in backend.STATE["audit"]
              if e["action"] == backend.RISK_DECISION
              and e["before"]["transaction_id"] == txn_id]
        oc = [e for e in backend.STATE["audit"]
              if e["action"] == backend.OUTCOME_RECORDED
              and e["before"]["transaction_id"] == txn_id]
        assert len(rd) == 1 and len(oc) == 1
        assert rd[0]["after"]["is_ground_truth"] is False
        assert oc[0]["after"]["ground_truth"] is True

    with app_run():
        # Reload emits nothing: audit records decisions, not reads.
        assert [e for e in backend.STATE["audit"]
                if e["action"] == backend.RISK_DECISION] == []


# ===========================================================================
# G. store parity -- DynamoRecordStore against a fake table
# ===========================================================================

class FakeTable:
    """Minimal stand-in for a boto3 Table: enough for put/get/query/update.

    Exists so DynamoRecordStore's real Decimal coercion and key handling are
    exercised without AWS credentials or a network call.
    """

    def __init__(self):
        self.items: dict[tuple[str, str], dict] = {}
        self._lock = threading.Lock()

    def put_item(self, Item):  # noqa: N803
        with self._lock:
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
        with self._lock:
            it = self.items.get((Key["PK"], Key["SK"]))
            if it is None:
                return
            for placeholder, name in ExpressionAttributeNames.items():
                val_key = ":v" + placeholder[2:]
                it[name] = ExpressionAttributeValues[val_key]


def _dynamo_store() -> backend.DynamoRecordStore:
    """Build the real adapter without boto3, by injecting a fake table."""
    s = object.__new__(backend.DynamoRecordStore)
    s._t = FakeTable()
    return s


@pytest.mark.parametrize("factory", [backend.InMemoryRecordStore, _dynamo_store],
                         ids=["in_memory", "dynamo_fake"])
def test_both_stores_support_the_persistence_operations(factory):
    """Same logical operations, no store-specific business logic."""
    store = factory()
    record = {
        "transaction_id": "pay_parity01", "order_id": "ord_parity01",
        "customer_id": "cust_parity", "amount": 27499.0, "risk_score": 47.2,
        "decision": "MANUAL_REVIEW",
        "sub_scores": {"ml": 33.04, "rules": 9.44, "network": 0.0},
        "reason_codes": [{"code": "X", "severity": "medium", "detail": "d",
                          "source": "rule"}],
        "fired_rules": ["new_device"], "created_at": "2026-08-27T10:00:00+00:00",
        "label": None,
    }

    assert backend.persist_scored_transaction(store, record) is True
    got = store.get("TXN#pay_parity01", "DETAIL")
    assert got["risk_score"] == 47.2
    assert got["decision"] == "MANUAL_REVIEW"
    assert got["sub_scores"]["ml"] == 33.04
    assert got["sub_scores"]["network"] == 0
    assert got["reason_codes"][0]["code"] == "X"
    assert got["label"] is None

    assert [p["transaction_id"] for p in store.query_prefix("INDEX#TXN", "")] \
        == ["pay_parity01"]

    assert backend.enqueue_review_item(store, record) is True
    q = store.get("QUEUE#REVIEW", "ITEM#pay_parity01")
    assert q["status"] == "open" and q["risk_score"] == 47.2

    store.update_fields("QUEUE#REVIEW", "ITEM#pay_parity01",
                        {"status": "resolved"})
    assert store.get("QUEUE#REVIEW", "ITEM#pay_parity01")["status"] == "resolved"

    store.update_fields("TXN#pay_parity01", "DETAIL", {"label": "fraud"})
    assert store.get("TXN#pay_parity01", "DETAIL")["label"] == "fraud"


def test_dynamo_store_round_trips_floats_exactly():
    """DynamoDB has no float type; the adapter coerces to Decimal and back."""
    store = _dynamo_store()
    rec = {"transaction_id": "pay_dec", "risk_score": 74.6,
           "sub_scores": {"ml": 52.22, "rules": 0.0, "network": 91.4},
           "created_at": "2026-08-27T10:00:00+00:00"}
    backend.persist_scored_transaction(store, rec)
    got = store.get("TXN#pay_dec", "DETAIL")
    assert got["risk_score"] == 74.6
    assert got["sub_scores"]["ml"] == 52.22
    assert got["sub_scores"]["network"] == 91.4
    assert got["sub_scores"]["rules"] == 0


def test_no_aws_credentials_are_required():
    """Guards the isolation regression this repository had before: tests must
    never depend on, or reach, a real table."""
    assert backend.USERS_BACKEND == "memory"
    for var in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"):
        os.environ.pop(var, None)
    store = _dynamo_store()
    backend.persist_scored_transaction(
        store, {"transaction_id": "pay_nocred",
                "created_at": "2026-08-27T10:00:00+00:00"})
    assert store.get("TXN#pay_nocred", "DETAIL") is not None


# ===========================================================================
# H. failure handling
# ===========================================================================

def test_order_succeeds_but_is_flagged_when_persistence_fails(db, pinned_scorer,
                                                              capsys):
    original = db.put

    def flaky(pk, sk, item):
        if pk.startswith("TXN#") or pk == "INDEX#TXN":
            raise RuntimeError("simulated transaction store outage")
        return original(pk, sk, item)

    with app_run() as c:
        h = register(c, f"h1-{uuid.uuid4().hex[:8]}@example.com")
        db.put = flaky
        try:
            body, txn_id = order(c, h, P_REVIEW)
        finally:
            db.put = original

        # The payment was authorised, so it is not refused.
        assert body["order_id"]
        # But durability is not claimed.
        assert backend.STATE["txns"][txn_id]["durable"] is False
        assert stored(db, txn_id) is None

    out = capsys.readouterr().out
    assert "durable write failed" in out
    assert "will NOT survive a restart" in out
    assert "MANUAL_REVIEW/BLOCK item may be lost" in out


def test_successful_persistence_is_flagged_durable(db, pinned_scorer):
    with app_run() as c:
        h = register(c, f"h2-{uuid.uuid4().hex[:8]}@example.com")
        _, txn_id = order(c, h)
        assert backend.STATE["txns"][txn_id]["durable"] is True


def test_queue_resolution_failure_is_reported(db, pinned_scorer, capsys):
    with app_run() as c:
        h = staff_headers(c, f"h3-{uuid.uuid4().hex[:8]}@example.com")
        _, txn_id = order(c, h, P_REVIEW)

        original = db.update_fields

        def flaky(pk, sk, fields):
            if pk == "QUEUE#REVIEW":
                raise RuntimeError("simulated queue outage")
            return original(pk, sk, fields)

        db.update_fields = flaky
        try:
            r = c.post(f"/v1/admin/transactions/{txn_id}/outcome",
                       headers=h, json={"label": "fraud"})
        finally:
            db.update_fields = original

        assert r.status_code == 200, "audit/queue failure broke the outcome"
        assert backend.STATE["txns"][txn_id]["label"] == "fraud"

    out = capsys.readouterr().out
    assert "could not mark review item" in out


def test_rehydration_survives_a_broken_store(db, pinned_scorer, capsys):
    with app_run() as c:
        h = register(c, f"h4-{uuid.uuid4().hex[:8]}@example.com")
        order(c, h, P_REVIEW)

    original = db.query_prefix

    def flaky(pk, prefix, desc=True):
        if pk == "INDEX#TXN":
            raise RuntimeError("simulated rehydration outage")
        return original(pk, prefix, desc)

    db.query_prefix = flaky
    try:
        with app_run() as c:
            # Comes up with an empty cache rather than refusing to start.
            assert c.get("/health").json()["status"] == "ok"
            h = register(c, f"h4b-{uuid.uuid4().hex[:8]}@example.com")
            assert order(c, h, P_ALLOW)[0]["order_id"]
    finally:
        db.query_prefix = original

    assert "could not list transactions for rehydration" in capsys.readouterr().out


# ===========================================================================
# I. restart lifecycle
# ===========================================================================

def test_full_lifecycle_create_shutdown_start_retrieve(db, pinned_scorer):
    with app_run() as c:
        h = staff_headers(c, f"i1-{uuid.uuid4().hex[:8]}@example.com")
        _, txn_id = order(c, h, P_BLOCK)
        assert backend.STATE["txns"]

    # STATE really was cleared, so anything found next is genuinely from storage.
    assert backend.STATE == {}

    with app_run() as c:
        h = staff_headers(c, f"i1b-{uuid.uuid4().hex[:8]}@example.com")
        assert txn_id in backend.STATE["txns"]
        assert c.get(f"/v1/admin/transactions/{txn_id}",
                     headers=h).status_code == 200


def test_repeated_restarts_do_not_duplicate_records(db, pinned_scorer):
    with app_run() as c:
        h = register(c, f"i2-{uuid.uuid4().hex[:8]}@example.com")
        _, txn_id = order(c, h, P_REVIEW)

    for _ in range(3):
        with app_run():
            pass

    pointers = db.query_prefix("INDEX#TXN", "", desc=True)
    assert sum(1 for p in pointers if p["transaction_id"] == txn_id) == 1
    assert len([q for q in db.query_prefix("QUEUE#REVIEW", "ITEM#")
                if q["transaction_id"] == txn_id]) == 1

    with app_run() as c:
        h = staff_headers(c, f"i2b-{uuid.uuid4().hex[:8]}@example.com")
        items = c.get("/v1/admin/queue", headers=h).json()["items"]
        assert [i["transaction_id"] for i in items].count(txn_id) == 1
        assert list(backend.STATE["queue"]).count(txn_id) == 1


def test_state_starts_empty_and_app_is_still_correct(db, pinned_scorer):
    """Nothing persisted yet: the app must work from an empty cache."""
    with app_run() as c:
        assert backend.STATE["txns"] == {}
        assert backend.STATE["queue"] == []
        h = staff_headers(c, f"i3-{uuid.uuid4().hex[:8]}@example.com")
        assert c.get("/v1/admin/queue", headers=h).json()["count"] == 0
        _, txn_id = order(c, h, P_REVIEW)
        assert c.get(f"/v1/admin/transactions/{txn_id}",
                     headers=h).status_code == 200
