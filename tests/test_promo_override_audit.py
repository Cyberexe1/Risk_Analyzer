"""PROMO_OVERRIDE audit tests.

WHY THIS EXISTS
---------------
A promo override is the ONLY label source for the promotion-abuse gate: it ships
with no training data, so an analyst reversing a HOLD is how we learn the rules
are wrong. That makes it ground truth, and ground truth with no audit record is
not ground truth -- nobody can say who created it or what the machine had decided
first.

THE SEPARATION UNDER TEST
-------------------------
    machine_decision   HOLD / DENY     what the gate decided, NEVER rewritten
    human_outcome      OVERRIDDEN      what a person decided afterwards
    label              legitimate      the ground-truth label that follows

Rewriting HOLD into ALLOW would destroy the only evidence that the gate ever
flagged the claim, and with it the false-positive count this gate is measured by.
That is the property most of these tests defend.

Run:  python -m pytest tests/test_promo_override_audit.py -v
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
os.environ["FRAUDSHIELD_JWT_SECRET"] = "test-only-jwt-secret-promo-audit"
os.environ["FRAUDSHIELD_IP_PEPPER"] = "test-only-pepper-promo-audit"
os.environ.pop("FRAUDSHIELD_API_KEY", None)

from fastapi.testclient import TestClient  # noqa: E402

import backend  # noqa: E402

PW = "promo-override-audit-password-7731"


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


def staff(c, tag: str, role: str = "admin") -> tuple[dict, str]:
    """Returns (headers, email). Role is granted by mutating the store, which the
    existing token picks up because current_user re-reads it."""
    email = f"{tag}-{uuid.uuid4().hex[:8]}@example.com"
    h = register(c, email)
    backend.STATE["users"].get_by_email(email).role = role
    return h, email


def make_hold(c, tag: str, *, device="dev_shared_audit",
              payout="upi_shared_audit", code="WELCOME500"):
    """Force HOLD/DENY by reusing one device and payout across accounts."""
    h = register(c, f"{tag}-{uuid.uuid4().hex[:8]}@example.com")
    r = c.post("/v1/promo/redeem", headers=h, json={
        "promo_code": code, "device_fp": device, "payout_ref": payout,
    })
    assert r.status_code == 201, r.text
    return r.json(), h


def held_rid(c, tag: str) -> str:
    """A redemption id that is genuinely queued as a hold."""
    make_hold(c, f"{tag}_seed")
    for i in range(6):
        body, _ = make_hold(c, f"{tag}_{i}")
        if body["redemption_id"] in backend.STATE["promo_queue"]:
            return body["redemption_id"]
    raise AssertionError("could not produce a promo hold")


def promo_events() -> list[dict]:
    return [e for e in backend.STATE["audit"]
            if e.get("action") == backend.PROMO_OVERRIDE]


# ===========================================================================
# one event per override, for both privileged roles
# ===========================================================================

@pytest.mark.parametrize("role", ["analyst", "admin"])
def test_override_creates_exactly_one_audit_event(db, role):
    with app_run() as c:
        rid = held_rid(c, f"one_{role}")
        h, _ = staff(c, f"one_{role}_s", role=role)
        assert promo_events() == []
        r = c.post(f"/v1/admin/promo-holds/{rid}/override", headers=h, json={})
        assert r.status_code == 200, r.text
        events = promo_events()

    assert len(events) == 1
    assert events[0]["action"] == "PROMO_OVERRIDE"


def test_two_overrides_produce_two_distinct_events(db):
    with app_run() as c:
        make_hold(c, "two_seed")
        rids = []
        for i in range(6):
            body, _ = make_hold(c, f"two_{i}")
            if body["redemption_id"] in backend.STATE["promo_queue"]:
                rids.append(body["redemption_id"])
        assert len(rids) >= 2
        h, _ = staff(c, "two_s")
        for rid in rids[:2]:
            assert c.post(f"/v1/admin/promo-holds/{rid}/override",
                          headers=h, json={}).status_code == 200
        events = promo_events()

    assert len(events) == 2
    assert len({e["event_id"] for e in events}) == 2
    assert {e["before"]["redemption_id"] for e in events} == set(rids[:2])


def test_duplicate_override_is_refused_and_creates_no_second_event(db):
    """A double-click must not manufacture a second ground-truth label."""
    with app_run() as c:
        rid = held_rid(c, "dup")
        h, _ = staff(c, "dup_s")
        assert c.post(f"/v1/admin/promo-holds/{rid}/override",
                      headers=h, json={}).status_code == 200
        again = c.post(f"/v1/admin/promo-holds/{rid}/override",
                       headers=h, json={})
        assert again.status_code == 409
        events = promo_events()

    assert len(events) == 1


def test_duplicate_override_across_a_restart_is_still_refused(db):
    with app_run() as c:
        rid = held_rid(c, "dupr")
        h, _ = staff(c, "dupr_s")
        assert c.post(f"/v1/admin/promo-holds/{rid}/override",
                      headers=h, json={}).status_code == 200

    with app_run() as c:
        h, _ = staff(c, "dupr_s2")
        assert c.post(f"/v1/admin/promo-holds/{rid}/override",
                      headers=h, json={}).status_code == 409
        assert promo_events() == []


def test_unknown_redemption_creates_no_event(db):
    with app_run() as c:
        h, _ = staff(c, "unk_s")
        assert c.post("/v1/admin/promo-holds/rdm_nope/override",
                      headers=h, json={}).status_code == 404
        assert promo_events() == []


# ===========================================================================
# event content
# ===========================================================================

def test_event_names_the_human_actor_not_the_system(db):
    with app_run() as c:
        rid = held_rid(c, "actor")
        h, email = staff(c, "actor_s", role="analyst")
        c.post(f"/v1/admin/promo-holds/{rid}/override", headers=h, json={})
        ev = promo_events()[0]

    assert ev["actor"] == email
    assert ev["actor"] != "system:scorer"
    assert "@" in ev["actor"]


def test_event_carries_a_timestamp_and_a_unique_event_id(db):
    with app_run() as c:
        rid = held_rid(c, "stamp")
        h, _ = staff(c, "stamp_s")
        c.post(f"/v1/admin/promo-holds/{rid}/override", headers=h, json={})
        ev = promo_events()[0]

    assert ev["at"].endswith("+00:00")           # timezone-aware ISO 8601
    assert ev["event_id"].startswith("pov_")


def test_event_records_the_redemption_customer_and_offer(db):
    with app_run() as c:
        rid = held_rid(c, "ids")
        idx = db.get("INDEX#PROMO", rid)
        stored = db.get(f"CUSTOMER#{idx['customer_id']}", idx["sk"])
        h, _ = staff(c, "ids_s")
        c.post(f"/v1/admin/promo-holds/{rid}/override", headers=h, json={})
        ev = promo_events()[0]

    assert ev["before"]["redemption_id"] == rid
    assert ev["before"]["customer_id"] == stored["customer_id"]
    assert ev["before"]["promo_code"] == stored["promo_code"]
    assert ev["before"]["value"] == stored["value"]


def test_event_quotes_the_original_machine_decision_and_evidence(db):
    with app_run() as c:
        rid = held_rid(c, "evid")
        idx = db.get("INDEX#PROMO", rid)
        stored = db.get(f"CUSTOMER#{idx['customer_id']}", idx["sk"])
        h, _ = staff(c, "evid_s")
        c.post(f"/v1/admin/promo-holds/{rid}/override", headers=h, json={})
        ev = promo_events()[0]

    assert ev["before"]["machine_decision"] == stored["decision"]
    assert ev["before"]["machine_decision"] in backend.PROMO_QUEUED_DECISIONS
    # The gate is rule-only, so the fired rules ARE its explanation. No score is
    # invented for a gate that produces none.
    assert ev["before"]["fired_rules"] == stored["fired_rules"]
    assert ev["before"]["reasons"] == stored["reasons"]
    assert ev["before"]["machine_decided_at"] == stored["created_at"]


def test_event_marks_itself_as_ground_truth(db):
    with app_run() as c:
        rid = held_rid(c, "gt")
        h, _ = staff(c, "gt_s")
        c.post(f"/v1/admin/promo-holds/{rid}/override", headers=h, json={})
        ev = promo_events()[0]

    assert ev["after"]["is_ground_truth"] is True
    assert ev["after"]["human_outcome"] == "OVERRIDDEN"
    assert ev["after"]["label"] == "legitimate"
    assert "not rewrite the machine decision" in ev["after"]["note"].lower() \
        or "does NOT rewrite" in ev["after"]["note"]


def test_machine_decision_is_not_rewritten_in_the_event_or_the_record(db):
    """The core invariant. HOLD must never become ALLOW anywhere."""
    with app_run() as c:
        rid = held_rid(c, "nomut")
        idx = db.get("INDEX#PROMO", rid)
        before = db.get(f"CUSTOMER#{idx['customer_id']}", idx["sk"])["decision"]
        h, _ = staff(c, "nomut_s")
        c.post(f"/v1/admin/promo-holds/{rid}/override", headers=h, json={})
        after = db.get(f"CUSTOMER#{idx['customer_id']}", idx["sk"])
        ev = promo_events()[0]

    assert after["decision"] == before, "machine decision was rewritten"
    assert after["decision"] != "ALLOW"
    assert ev["before"]["machine_decision"] == before
    assert ev["after"]["machine_decision_unchanged"] == before
    # Human verdict lives in its own fields.
    assert after["override_by"] and after["override_at"]
    assert after["label"] == "legitimate"


def test_human_label_is_separate_from_the_machine_decision(db):
    with app_run() as c:
        rid = held_rid(c, "sep")
        h, _ = staff(c, "sep_s")
        c.post(f"/v1/admin/promo-holds/{rid}/override", headers=h, json={})
        ev = promo_events()[0]

    # Two distinct keys, two distinct meanings, neither derived from the other.
    assert ev["before"]["machine_decision"] in ("HOLD", "DENY")
    assert ev["after"]["human_outcome"] == "OVERRIDDEN"
    assert ev["before"]["machine_decision"] != ev["after"]["human_outcome"]


def test_optional_reason_is_recorded_when_supplied(db):
    with app_run() as c:
        rid = held_rid(c, "why")
        h, _ = staff(c, "why_s")
        c.post(f"/v1/admin/promo-holds/{rid}/override", headers=h,
               json={"reason": "verified student ID with support"})
        ev = promo_events()[0]

    assert ev["after"]["reason"] == "verified student ID with support"


def test_absent_reason_is_null_not_an_invented_string(db):
    with app_run() as c:
        rid = held_rid(c, "noreason")
        h, _ = staff(c, "noreason_s")
        c.post(f"/v1/admin/promo-holds/{rid}/override", headers=h, json={})
        ev = promo_events()[0]

    assert ev["after"]["reason"] is None


def test_endpoint_still_accepts_no_body_at_all(db):
    """Existing callers post no body. That must keep working."""
    with app_run() as c:
        rid = held_rid(c, "nobody")
        h, _ = staff(c, "nobody_s")
        r = c.post(f"/v1/admin/promo-holds/{rid}/override", headers=h)
        assert r.status_code == 200, r.text
        assert len(promo_events()) == 1


def test_event_carries_no_payout_destination_or_device_secret(db):
    """The audit record is metadata plus gate evidence. A payout reference is a
    real UPI id or bank reference -- it identifies where money would go, and an
    audit log readable by every admin is the wrong place for it."""
    with app_run() as c:
        rid = held_rid(c, "leak")
        h, _ = staff(c, "leak_s")
        c.post(f"/v1/admin/promo-holds/{rid}/override", headers=h, json={})
        ev = promo_events()[0]

    blob = repr(ev)
    assert "upi_shared_audit" not in blob
    assert "payout_ref" not in blob


# ===========================================================================
# access control
# ===========================================================================

def test_customer_cannot_override_and_cannot_read_the_audit_event(db):
    with app_run() as c:
        rid = held_rid(c, "cust")
        h = register(c, f"cust-{uuid.uuid4().hex[:8]}@example.com")
        assert c.post(f"/v1/admin/promo-holds/{rid}/override",
                      headers=h, json={}).status_code == 403
        assert promo_events() == []

        # And once an override does exist, a customer still cannot read it.
        st, _ = staff(c, "cust_s")
        c.post(f"/v1/admin/promo-holds/{rid}/override", headers=st, json={})
        assert len(promo_events()) == 1
        assert c.get("/v1/admin/audit", headers=h).status_code == 403
        assert c.get("/v1/admin/audit").status_code in (401, 403)


def test_analyst_cannot_read_the_audit_log(db):
    """Audit retrieval is admin-only and stays that way. An analyst may create a
    PROMO_OVERRIDE event but may not browse the trail of everyone else's."""
    with app_run() as c:
        rid = held_rid(c, "anread")
        h, _ = staff(c, "anread_s", role="analyst")
        assert c.post(f"/v1/admin/promo-holds/{rid}/override",
                      headers=h, json={}).status_code == 200
        assert c.get("/v1/admin/audit", headers=h).status_code == 403


def test_customer_response_does_not_expose_audit_information(db):
    """The override response is for the console. It must not become a channel for
    audit internals."""
    with app_run() as c:
        rid = held_rid(c, "resp")
        h, _ = staff(c, "resp_s")
        body = c.post(f"/v1/admin/promo-holds/{rid}/override",
                      headers=h, json={}).json()

    for forbidden in ("event_id", "actor", "before", "after", "is_ground_truth"):
        assert forbidden not in body, f"{forbidden} leaked into the response"


# ===========================================================================
# retrieval and filtering
# ===========================================================================

def test_admin_can_retrieve_the_event_by_filter(db):
    with app_run() as c:
        rid = held_rid(c, "filt")
        h, _ = staff(c, "filt_s")
        c.post(f"/v1/admin/promo-holds/{rid}/override", headers=h, json={})

        got = c.get("/v1/admin/audit?action=PROMO_OVERRIDE", headers=h).json()
        assert got["count"] == 1
        assert got["entries"][0]["before"]["redemption_id"] == rid

        # Filtering is exact: a promo override is not an OUTCOME_RECORDED.
        assert c.get("/v1/admin/audit?action=OUTCOME_RECORDED",
                     headers=h).json()["count"] == 0


def test_unfiltered_audit_still_returns_the_event(db):
    with app_run() as c:
        rid = held_rid(c, "unfilt")
        h, _ = staff(c, "unfilt_s")
        c.post(f"/v1/admin/promo-holds/{rid}/override", headers=h, json={})
        actions = {e["action"]
                   for e in c.get("/v1/admin/audit?limit=200",
                                  headers=h).json()["entries"]}

    assert "PROMO_OVERRIDE" in actions
    # The promo gate's own decisions are not risk decisions, so a redemption never
    # produces a RISK_DECISION. This asserts the two paths stay distinct.
    assert backend.RISK_DECISION not in actions


def test_event_survives_a_restart_because_it_is_persisted(db):
    with app_run() as c:
        rid = held_rid(c, "durable")
        h, _ = staff(c, "durable_s")
        c.post(f"/v1/admin/promo-holds/{rid}/override", headers=h, json={})

    assert backend.STATE == {}

    with app_run() as c:
        h, _ = staff(c, "durable_s2")
        got = c.get("/v1/admin/audit?action=PROMO_OVERRIDE", headers=h).json()
        assert got["count"] == 1
        assert got["entries"][0]["before"]["redemption_id"] == rid
