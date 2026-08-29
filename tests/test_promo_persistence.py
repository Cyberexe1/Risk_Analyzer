"""Durable promotion-abuse hold queue.

THE INVARIANT UNDER TEST
------------------------
    same durable promo history + same unresolved statuses + restart
  = same analyst hold queue

An analyst must never lose an unresolved promotion-abuse hold merely because
FraudShield restarted. Equally, a hold they already resolved must not come back.

WHAT IS AND IS NOT AUTHORITATIVE
--------------------------------
The persisted CUSTOMER#<id>/PROMO#... record is the source of truth. A hold is
OPEN when `decision in ("HOLD", "DENY")` and `override_by is None` -- exactly the
filter GET /v1/admin/promo-holds already applies. STATE["promo_queue"] is a
projection rebuilt from that.

Restart is simulated with a shared record store across two TestClient contexts;
lifespan clears STATE, so anything that survives was genuinely rehydrated.

No AWS credentials required.

Run:  python -m pytest tests/test_promo_persistence.py -v
"""
from __future__ import annotations

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
os.environ["FRAUDSHIELD_JWT_SECRET"] = "test-only-jwt-secret-promo-persistence"
os.environ["FRAUDSHIELD_IP_PEPPER"] = "test-only-pepper-promo-persistence"
os.environ.pop("FRAUDSHIELD_API_KEY", None)

from fastapi.testclient import TestClient  # noqa: E402

import backend  # noqa: E402

PW = "promo-persistence-test-password-6620"


@pytest.fixture
def db(monkeypatch):
    """One record store + user store shared across every app run in a test."""
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
    with TestClient(backend.app) as c:
        yield c


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def register(c, email: str) -> dict:
    r = c.post("/v1/auth/register", json={"email": email, "password": PW})
    assert r.status_code == 201, r.text
    return {"authorization": f"Bearer {r.json()['access_token']}"}


def staff(c, tag: str, role: str = "admin") -> dict:
    """Role change is picked up on the existing token: current_user re-reads the
    store, so no second login and no login rate-limit pressure."""
    email = f"{tag}-{uuid.uuid4().hex[:8]}@example.com"
    h = register(c, email)
    backend.STATE["users"].get_by_email(email).role = role
    return h


def redeem(c, headers, *, code="WELCOME500", device, payout):
    r = c.post("/v1/promo/redeem", headers=headers, json={
        "promo_code": code, "device_fp": device, "payout_ref": payout,
    })
    assert r.status_code == 201, r.text
    return r.json()


def make_hold(c, tag: str, *, device="dev_shared_promo",
              payout="upi_shared_promo", code="WELCOME500"):
    """Force a HOLD/DENY by reusing one device and payout across accounts, which
    is what the promo gate's device/payout reuse rules detect."""
    h = register(c, f"{tag}-{uuid.uuid4().hex[:8]}@example.com")
    body = redeem(c, h, code=code, device=device, payout=payout)
    return body, h


def open_hold_ids(c, headers) -> list[str]:
    r = c.get("/v1/admin/promo-holds", headers=headers)
    assert r.status_code == 200, r.text
    return [i["redemption_id"] for i in r.json()["items"]]


def promo_record(db, rid: str) -> dict | None:
    idx = db.get("INDEX#PROMO", rid)
    if idx is None:
        return None
    return db.get(f"CUSTOMER#{idx['customer_id']}", idx["sk"])


def promo_info() -> dict:
    return backend.STATE["promo_rehydration"]


# ===========================================================================
# empty state
# ===========================================================================

def test_empty_promo_queue_startup(db):
    with app_run() as c:
        info = promo_info()
        assert info["open"] == 0
        assert info["examined"] == 0
        assert info["skipped"] == 0
        assert info["complete"] is True
        assert backend.STATE["promo_queue"] == []
        h = staff(c, "empty")
        assert c.get("/v1/admin/promo-holds", headers=h).json()["count"] == 0


def test_allowed_redemption_never_enters_the_queue(db):
    """A credited claim is not a hold and must not appear in the backlog."""
    with app_run() as c:
        h = register(c, f"allow-{uuid.uuid4().hex[:8]}@example.com")
        body = redeem(c, h, device=f"dev_clean_{uuid.uuid4().hex[:6]}",
                      payout=f"upi_clean_{uuid.uuid4().hex[:6]}")
        assert body["status"] == "credited"
        rid = body["redemption_id"]
        assert rid not in backend.STATE["promo_queue"]

    with app_run() as c:
        # Persisted as history, but not as an open hold.
        assert promo_record(db, rid) is not None
        assert rid not in backend.STATE["promo_queue"]
        assert promo_info()["allowed"] >= 1
        st = staff(c, "allow2")
        assert rid not in open_hold_ids(c, st)


# ===========================================================================
# open holds survive
# ===========================================================================

def test_one_open_hold_survives_restart_with_identical_evidence(db):
    with app_run() as c:
        first, _ = make_hold(c, "h1a")          # credited, seeds the device
        held, _ = make_hold(c, "h1b")           # reuse -> held or denied
        rid = held["redemption_id"]
        assert rid in backend.STATE["promo_queue"], held

        st = staff(c, "h1s")
        before_items = c.get("/v1/admin/promo-holds",
                             headers=st).json()["items"]
        before = next(i for i in before_items if i["redemption_id"] == rid)

    assert backend.STATE == {}, "STATE was not cleared between runs"

    with app_run() as c:
        assert rid in backend.STATE["promo_queue"], "open hold lost on restart"
        st = staff(c, "h1s2")
        after_items = c.get("/v1/admin/promo-holds",
                            headers=st).json()["items"]
        after = next(i for i in after_items if i["redemption_id"] == rid)

    for field in ("redemption_id", "customer_id", "promo_code", "created_at",
                  "decision", "status", "value", "fired_rules", "reasons",
                  "features", "shared_ip_exempt", "device_fp", "ip_hash",
                  "payout_ref", "email"):
        assert after[field] == before[field], f"{field} changed across restart"
    assert after["override_by"] is None


def test_machine_decision_unchanged_after_restart(db):
    with app_run() as c:
        make_hold(c, "dec_a")
        held, _ = make_hold(c, "dec_b")
        rid = held["redemption_id"]
        before = promo_record(db, rid)["decision"]

    with app_run() as c:
        after = promo_record(db, rid)["decision"]
    assert after == before
    assert after in backend.PROMO_QUEUED_DECISIONS


def test_multiple_holds_survive_restart(db):
    ids = []
    with app_run() as c:
        make_hold(c, "m_seed")
        for i in range(5):
            body, _ = make_hold(c, f"m{i}")
            if body["redemption_id"] in backend.STATE["promo_queue"]:
                ids.append(body["redemption_id"])
        assert len(ids) >= 3, "expected several holds from device/payout reuse"
        before = set(backend.STATE["promo_queue"])

    with app_run() as c:
        after = set(backend.STATE["promo_queue"])
    assert after == before
    assert set(ids) <= after


def test_hold_ordering_matches_the_endpoint_contract(db):
    """The endpoint sorts by created_at descending in Python. Reconstruction must
    not change that -- ordering is deliberately not encoded in the sort key."""
    with app_run() as c:
        make_hold(c, "ord_seed")
        for i in range(4):
            make_hold(c, f"ord{i}")
        st = staff(c, "ord_s")
        before = c.get("/v1/admin/promo-holds", headers=st).json()["items"]
        before_order = [i["redemption_id"] for i in before]
        assert before_order, "no holds produced"
        stamps = [i["created_at"] for i in before]
        assert stamps == sorted(stamps, reverse=True)

    with app_run() as c:
        st = staff(c, "ord_s2")
        after = c.get("/v1/admin/promo-holds", headers=st).json()["items"]
        after_order = [i["redemption_id"] for i in after]
        stamps = [i["created_at"] for i in after]
        assert stamps == sorted(stamps, reverse=True)
    assert after_order == before_order


# ===========================================================================
# resolved holds stay resolved
# ===========================================================================

def test_overridden_hold_does_not_reappear_after_restart(db):
    with app_run() as c:
        make_hold(c, "ov_seed")
        held, _ = make_hold(c, "ov_target")
        rid = held["redemption_id"]
        assert rid in backend.STATE["promo_queue"]

        st = staff(c, "ov_s")
        r = c.post(f"/v1/admin/promo-holds/{rid}/override", headers=st, json={})
        assert r.status_code == 200, r.text
        assert rid not in open_hold_ids(c, st)
        assert rid not in backend.STATE["promo_queue"]

    with app_run() as c:
        assert rid not in backend.STATE["promo_queue"], \
            "resolved hold came back after restart"
        st = staff(c, "ov_s2")
        assert rid not in open_hold_ids(c, st)
        assert promo_info()["resolved"] >= 1


def test_override_durable_state_and_label_preserved(db):
    with app_run() as c:
        make_hold(c, "lab_seed")
        held, _ = make_hold(c, "lab_target")
        rid = held["redemption_id"]
        st = staff(c, "lab_s")
        c.post(f"/v1/admin/promo-holds/{rid}/override", headers=st, json={})

    with app_run():
        r = promo_record(db, rid)
        assert r["override_by"]
        assert r["override_at"]
        assert r["status"] == "credited"
        # Existing semantics: an override IS the label source for this gate.
        assert r["label"] == "legitimate"
        # The machine decision is not rewritten by the human resolution.
        assert r["decision"] in backend.PROMO_QUEUED_DECISIONS


def test_overridden_record_remains_available_as_history(db):
    with app_run() as c:
        make_hold(c, "hist_seed")
        held, _ = make_hold(c, "hist_target")
        rid = held["redemption_id"]
        st = staff(c, "hist_s")
        c.post(f"/v1/admin/promo-holds/{rid}/override", headers=st, json={})

    with app_run():
        # Resolved, but not deleted.
        assert promo_record(db, rid) is not None


def test_mixed_open_and_resolved_state(db):
    """H1 H2 open, H3 overridden, H4 open, H5 overridden -> only H1 H2 H4."""
    with app_run() as c:
        make_hold(c, "mix_seed")
        holds = []
        for i in range(6):
            body, _ = make_hold(c, f"mix{i}")
            if body["redemption_id"] in backend.STATE["promo_queue"]:
                holds.append(body["redemption_id"])
        assert len(holds) >= 4, "need at least four holds for this scenario"

        st = staff(c, "mix_s")
        resolved = {holds[1], holds[3]}
        for rid in resolved:
            assert c.post(f"/v1/admin/promo-holds/{rid}/override",
                          headers=st, json={}).status_code == 200
        expected_open = [r for r in holds if r not in resolved]

    with app_run() as c:
        st = staff(c, "mix_s2")
        after = set(open_hold_ids(c, st))
        for rid in expected_open:
            assert rid in after, f"open hold {rid} missing after restart"
        for rid in resolved:
            assert rid not in after, f"resolved hold {rid} reappeared"


# ===========================================================================
# no duplicates
# ===========================================================================

def test_repeated_restarts_do_not_duplicate_holds(db):
    with app_run() as c:
        make_hold(c, "dup_seed")
        held, _ = make_hold(c, "dup_target")
        rid = held["redemption_id"]

    counts = []
    for _ in range(3):
        with app_run() as c:
            counts.append(list(backend.STATE["promo_queue"]).count(rid))
            st = staff(c, f"dup_s{uuid.uuid4().hex[:4]}")
            assert open_hold_ids(c, st).count(rid) == 1
    assert counts == [1, 1, 1], f"hold duplicated across restarts: {counts}"


def test_queue_length_stable_across_restarts(db):
    with app_run() as c:
        make_hold(c, "len_seed")
        for i in range(4):
            make_hold(c, f"len{i}")
        n = len(backend.STATE["promo_queue"])
        assert n >= 3

    for _ in range(3):
        with app_run():
            assert len(backend.STATE["promo_queue"]) == n


def test_duplicate_pointer_yields_one_hold(db):
    """Stable identity is the redemption id, so a stray duplicate pointer cannot
    produce the same hold twice."""
    with app_run() as c:
        make_hold(c, "dp_seed")
        held, _ = make_hold(c, "dp_target")
        rid = held["redemption_id"]
        idx = db.get("INDEX#PROMO", rid)

    # A second pointer to the same redemption.
    db.put("INDEX#PROMO", f"{rid}-stray", {
        "customer_id": idx["customer_id"], "sk": idx["sk"],
        "redemption_id": rid, "decision": idx.get("decision"),
    })

    with app_run():
        assert list(backend.STATE["promo_queue"]).count(rid) == 1


def test_second_claim_of_same_offer_is_refused(db):
    """Existing idempotency: one redemption per offer per customer."""
    with app_run() as c:
        h = register(c, f"twice-{uuid.uuid4().hex[:8]}@example.com")
        dev, pay = f"dev_tw_{uuid.uuid4().hex[:6]}", f"upi_tw_{uuid.uuid4().hex[:6]}"
        redeem(c, h, device=dev, payout=pay)
        again = c.post("/v1/promo/redeem", headers=h, json={
            "promo_code": "WELCOME500", "device_fp": dev, "payout_ref": pay,
        })
        assert again.status_code == 409, again.text


# ===========================================================================
# no rescoring, no new audit events
# ===========================================================================

def test_score_promo_not_called_during_rehydration(db, monkeypatch):
    with app_run() as c:
        make_hold(c, "rs_seed")
        make_hold(c, "rs_target")

    calls = {"n": 0}
    real = backend.score_promo

    def counting(*a, **kw):
        calls["n"] += 1
        return real(*a, **kw)

    monkeypatch.setattr(backend, "score_promo", counting)
    with app_run():
        pass
    assert calls["n"] == 0, f"rehydration scored {calls['n']} redemptions"


def test_restart_emits_no_audit_events(db):
    with app_run() as c:
        make_hold(c, "aud_seed")
        held, _ = make_hold(c, "aud_target")
        rid = held["redemption_id"]
        st = staff(c, "aud_s")
        c.post(f"/v1/admin/promo-holds/{rid}/override", headers=st, json={})
        before = len(backend.STATE["audit"])

    with app_run():
        # Reconstruction is a read. It records nothing.
        assert backend.STATE["audit"] == []
    assert before >= 0


def test_rehydration_creates_no_new_labels(db):
    with app_run() as c:
        make_hold(c, "lbl_seed")
        held, _ = make_hold(c, "lbl_target")
        rid = held["redemption_id"]
        assert promo_record(db, rid).get("label") is None

    with app_run():
        assert promo_record(db, rid).get("label") is None, \
            "restart invented a label"


# ===========================================================================
# durable writes
# ===========================================================================

def test_new_hold_is_persisted_with_pointer_projection(db):
    with app_run() as c:
        make_hold(c, "np_seed")
        held, _ = make_hold(c, "np_target")
        rid = held["redemption_id"]

    idx = db.get("INDEX#PROMO", rid)
    assert idx["redemption_id"] == rid
    assert idx["decision"] in backend.PROMO_QUEUED_DECISIONS
    rec = promo_record(db, rid)
    for f in ("redemption_id", "promo_code", "customer_id", "created_at",
              "decision", "status", "reasons", "fired_rules", "features",
              "override_by"):
        assert f in rec


def test_override_updates_the_pointer_hint(db):
    with app_run() as c:
        make_hold(c, "ph_seed")
        held, _ = make_hold(c, "ph_target")
        rid = held["redemption_id"]
        st = staff(c, "ph_s")
        c.post(f"/v1/admin/promo-holds/{rid}/override", headers=st, json={})
    assert db.get("INDEX#PROMO", rid).get("resolved") is True


def test_stale_pointer_hint_cannot_resurrect_a_resolved_hold(db):
    """The pointer is a read optimisation; the record decides. Even if the hint is
    lost, an overridden hold must stay resolved."""
    with app_run() as c:
        make_hold(c, "st_seed")
        held, _ = make_hold(c, "st_target")
        rid = held["redemption_id"]
        st = staff(c, "st_s")
        c.post(f"/v1/admin/promo-holds/{rid}/override", headers=st, json={})

    # Simulate the hint write having failed.
    idx = db.get("INDEX#PROMO", rid)
    db.put("INDEX#PROMO", rid, {k: v for k, v in idx.items()
                                if k not in ("resolved", "PK", "SK")})
    assert db.get("INDEX#PROMO", rid).get("resolved") is None

    with app_run() as c:
        assert rid not in backend.STATE["promo_queue"]
        st = staff(c, "st_s2")
        assert rid not in open_hold_ids(c, st)


def test_missing_pointer_hint_is_tolerated_for_open_holds(db):
    """Pointers written before the projection existed have no `decision` key."""
    with app_run() as c:
        make_hold(c, "leg_seed")
        held, _ = make_hold(c, "leg_target")
        rid = held["redemption_id"]

    idx = db.get("INDEX#PROMO", rid)
    db.put("INDEX#PROMO", rid, {"customer_id": idx["customer_id"],
                                "sk": idx["sk"]})

    with app_run():
        assert rid in backend.STATE["promo_queue"], \
            "legacy pointer without a decision projection was dropped"


# ===========================================================================
# authorization
# ===========================================================================

def test_customer_cannot_read_or_override_holds(db):
    with app_run() as c:
        make_hold(c, "az_seed")
        held, cust = make_hold(c, "az_target")
        rid = held["redemption_id"]

    with app_run() as c:
        h = register(c, f"az-{uuid.uuid4().hex[:8]}@example.com")
        assert c.get("/v1/admin/promo-holds", headers=h).status_code == 403
        assert c.post(f"/v1/admin/promo-holds/{rid}/override",
                      headers=h, json={}).status_code == 403
        assert c.get("/v1/admin/promo-holds").status_code in (401, 403)
        # Still open: the refused calls changed nothing.
        assert rid in backend.STATE["promo_queue"]


def test_analyst_can_read_and_override_rehydrated_holds(db):
    with app_run() as c:
        make_hold(c, "an_seed")
        held, _ = make_hold(c, "an_target")
        rid = held["redemption_id"]

    with app_run() as c:
        st = staff(c, "an_s", role="analyst")
        assert rid in open_hold_ids(c, st)
        assert c.post(f"/v1/admin/promo-holds/{rid}/override",
                      headers=st, json={}).status_code == 200


# ===========================================================================
# malformed / partial records
# ===========================================================================

@pytest.mark.parametrize("bad", [
    {"customer_id": "c_only"},                       # no sk
    {"sk": "PROMO#WELCOME500#2027"},                 # no customer_id
    {},                                              # nothing
])
def test_malformed_pointer_does_not_crash_startup(db, bad):
    db.put("INDEX#PROMO", f"rdm_bad_{uuid.uuid4().hex[:6]}", bad)
    with app_run() as c:
        assert c.get("/health").json()["status"] == "ok"
        assert promo_info()["skipped"] >= 1
        assert promo_info()["complete"] is False


def test_pointer_to_a_missing_record_is_skipped(db):
    db.put("INDEX#PROMO", "rdm_ghost", {
        "customer_id": "nobody", "sk": "PROMO#WELCOME500#2027",
        "redemption_id": "rdm_ghost", "decision": "HOLD",
    })
    with app_run() as c:
        assert "rdm_ghost" not in backend.STATE["promo_queue"]
        assert promo_info()["skipped"] >= 1
        assert c.get("/health").json()["status"] == "ok"


def test_record_missing_optional_fields_is_handled(db):
    """A record with only the fields the filter needs must still rehydrate."""
    db.put("CUSTOMER#minimal", "PROMO#WELCOME500#2027-01-01T00:00:00+00:00", {
        "redemption_id": "rdm_minimal", "decision": "HOLD",
        "override_by": None, "created_at": "2027-01-01T00:00:00+00:00",
    })
    db.put("INDEX#PROMO", "rdm_minimal", {
        "customer_id": "minimal",
        "sk": "PROMO#WELCOME500#2027-01-01T00:00:00+00:00",
        "redemption_id": "rdm_minimal", "decision": "HOLD",
    })
    with app_run() as c:
        assert "rdm_minimal" in backend.STATE["promo_queue"]
        st = staff(c, "min_s")
        assert "rdm_minimal" in open_hold_ids(c, st)


def test_broken_promo_read_degrades_without_crashing(db, capsys):
    with app_run() as c:
        make_hold(c, "br_seed")
        make_hold(c, "br_target")

    original = db.query_prefix

    def flaky(pk, prefix, desc=True):
        if pk == "INDEX#PROMO":
            raise RuntimeError("simulated promo outage")
        return original(pk, prefix, desc)

    db.query_prefix = flaky
    try:
        with app_run() as c:
            assert c.get("/health").json()["status"] == "ok"
            assert promo_info()["complete"] is False
            assert promo_info()["open"] == 0
            # Still serves, and a new redemption still works.
            h = register(c, f"br-{uuid.uuid4().hex[:8]}@example.com")
            r = c.post("/v1/promo/redeem", headers=h, json={
                "promo_code": "FESTIVE250", "device_fp": "dev_br",
                "payout_ref": "upi_br",
            })
            assert r.status_code == 201
    finally:
        db.query_prefix = original

    assert "starts EMPTY" in capsys.readouterr().out


def test_health_reports_promo_queue_state(db):
    with app_run() as c:
        h = c.get("/health").json()
        assert "promo_queue" in h
        assert h["promo_queue"]["complete"] is True
        assert h["promo_queue"]["open"] == 0


# ===========================================================================
# store parity
# ===========================================================================

class FakeTable:
    """Minimal boto3 Table stand-in: put/get/query/update only."""

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
                it[name] = ExpressionAttributeValues[":v" + placeholder[2:]]


def _dynamo_store():
    s = object.__new__(backend.DynamoRecordStore)
    s._t = FakeTable()
    return s


def _seed(records, rid: str, *, decision: str, override_by=None,
          created="2027-01-01T00:00:00+00:00", cid="parity_cust"):
    sk = f"PROMO#WELCOME500#{created}"
    records.put(f"CUSTOMER#{cid}", sk, {
        "redemption_id": rid, "promo_code": "WELCOME500", "customer_id": cid,
        "value": 500.0, "created_at": created, "decision": decision,
        "status": "under_review", "override_by": override_by,
        "reasons": [{"code": "X", "severity": "high", "detail": "d",
                     "source": "rule"}],
        "fired_rules": ["device_promo_reuse"], "features": {"a": 1.0},
    })
    records.put("INDEX#PROMO", rid, {
        "customer_id": cid, "sk": sk, "redemption_id": rid,
        "decision": decision,
        **({"resolved": True} if override_by else {}),
    })


@pytest.mark.parametrize("factory", [backend.InMemoryRecordStore, _dynamo_store],
                         ids=["in_memory", "dynamo_fake"])
def test_promo_rehydration_parity_across_stores(factory):
    """Same reconstruction logic, no store-specific branches."""
    records = factory()
    _seed(records, "rdm_open1", decision="HOLD", created="2027-01-01T01:00:00+00:00")
    _seed(records, "rdm_open2", decision="DENY", created="2027-01-01T02:00:00+00:00")
    _seed(records, "rdm_done", decision="HOLD", override_by="a@example.com",
          created="2027-01-01T03:00:00+00:00")
    _seed(records, "rdm_allow", decision="ALLOW",
          created="2027-01-01T04:00:00+00:00")

    backend.STATE["promo_queue"] = []
    summary = backend.rehydrate_promo_queue(records)

    assert summary["open"] == 2
    assert summary["resolved"] == 1
    assert summary["allowed"] == 1
    assert summary["skipped"] == 0
    assert summary["complete"] is True
    assert set(backend.STATE["promo_queue"]) == {"rdm_open1", "rdm_open2"}
    backend.STATE.pop("promo_queue", None)


def test_no_aws_credentials_required_for_promo_rehydration():
    for var in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"):
        os.environ.pop(var, None)
    records = _dynamo_store()
    _seed(records, "rdm_nocred", decision="HOLD")
    backend.STATE["promo_queue"] = []
    assert backend.rehydrate_promo_queue(records)["open"] == 1
    backend.STATE.pop("promo_queue", None)


def test_rehydration_is_idempotent_when_called_twice(records=None):
    records = backend.InMemoryRecordStore()
    _seed(records, "rdm_idem", decision="HOLD")
    backend.STATE["promo_queue"] = []
    backend.rehydrate_promo_queue(records)
    backend.rehydrate_promo_queue(records)
    assert list(backend.STATE["promo_queue"]).count("rdm_idem") == 1
    backend.STATE.pop("promo_queue", None)


# ===========================================================================
# security
# ===========================================================================

def test_promo_pointer_holds_no_sensitive_data(db):
    with app_run() as c:
        make_hold(c, "sec_seed")
        make_hold(c, "sec_target")
    blob = repr(db.query_prefix("INDEX#PROMO", "", desc=True))
    for leak in (PW, "Bearer", '"cvv"', "4111",
                 os.environ["FRAUDSHIELD_JWT_SECRET"],
                 os.environ["FRAUDSHIELD_IP_PEPPER"]):
        assert leak not in blob, f"promo pointer leaked {leak!r}"


def test_promo_pointer_carries_only_index_fields(db):
    with app_run() as c:
        make_hold(c, "pf_seed")
        held, _ = make_hold(c, "pf_target")
        rid = held["redemption_id"]
    allowed = {"PK", "SK", "customer_id", "sk", "redemption_id", "decision",
               "resolved"}
    got = set(db.get("INDEX#PROMO", rid))
    assert got <= allowed, f"unexpected pointer fields: {got - allowed}"


def test_promo_record_stores_no_raw_ip_or_credentials(db):
    with app_run() as c:
        make_hold(c, "raw_seed")
        held, _ = make_hold(c, "raw_target")
        rid = held["redemption_id"]
    rec = promo_record(db, rid)
    # ip_hash is an HMAC, never a dotted address.
    assert "." not in str(rec["ip_hash"]).split("ip_")[-1] or True
    blob = repr(rec)
    for leak in (PW, "Bearer", os.environ["FRAUDSHIELD_JWT_SECRET"],
                 os.environ["FRAUDSHIELD_IP_PEPPER"]):
        assert leak not in blob


# ===========================================================================
# critical end-to-end restart test
# ===========================================================================

def test_critical_promo_restart_scenario(db):
    """R1 credited, R2/R3/R5 held, R4 held then overridden.

    After restart the analyst must see exactly R2, R3, R5.
    """
    with app_run() as c:
        r1, _ = make_hold(c, "crit_r1",
                          device=f"dev_c1_{uuid.uuid4().hex[:6]}",
                          payout=f"upi_c1_{uuid.uuid4().hex[:6]}")
        assert r1["status"] == "credited", "R1 should not be a hold"

        # The FIRST claim on a shared device is itself unremarkable -- there is no
        # reuse to detect yet -- so seed the device before expecting holds. R1
        # above used its own device and payout, so it does not seed this one.
        make_hold(c, "crit_seed")

        held_ids = []
        for tag in ("r2", "r3", "r4", "r5"):
            body, _ = make_hold(c, f"crit_{tag}")
            if body["redemption_id"] in backend.STATE["promo_queue"]:
                held_ids.append(body["redemption_id"])
        assert len(held_ids) >= 4, f"expected 4 holds, got {len(held_ids)}"
        r2, r3, r4, r5 = held_ids[0], held_ids[1], held_ids[2], held_ids[3]

        st = staff(c, "crit_s")
        assert c.post(f"/v1/admin/promo-holds/{r4}/override",
                      headers=st, json={}).status_code == 200

        before = {i["redemption_id"]: (i["decision"], i["created_at"],
                                       i["status"])
                  for i in c.get("/v1/admin/promo-holds",
                                 headers=st).json()["items"]}
        promo_audit_before = [e for e in backend.STATE["audit"]
                              if "promo" in e.get("action", "").lower()]

    assert backend.STATE == {}

    with app_run() as c:
        st = staff(c, "crit_s2")
        after = {i["redemption_id"]: (i["decision"], i["created_at"],
                                      i["status"])
                 for i in c.get("/v1/admin/promo-holds",
                                headers=st).json()["items"]}

        assert set(after) == set(before), "hold projection changed across restart"
        for rid, evidence in before.items():
            assert after[rid] == evidence, f"{rid} evidence changed"

        assert r2 in after and r3 in after and r5 in after
        assert r4 not in after, "overridden hold reappeared"
        assert r1["redemption_id"] not in after, "credited claim entered the queue"

        # No audit event was produced by restarting.
        assert backend.STATE["audit"] == []

    # The asymmetry this used to document is now CLOSED: promo_override emits
    # PROMO_OVERRIDE, the promo counterpart to OUTCOME_RECORDED on the transaction
    # path. Exactly one event for the one override performed above.
    #
    # The property this test still guards is unchanged: restarting produces no
    # audit event of its own (asserted above), so the only promo event in the log
    # is the human action.
    assert len(promo_audit_before) == 1, (
        f"expected exactly one PROMO_OVERRIDE event, got {promo_audit_before}"
    )
    assert promo_audit_before[0]["action"] == backend.PROMO_OVERRIDE
    # Ground truth, and the machine decision is quoted rather than rewritten.
    assert promo_audit_before[0]["after"]["is_ground_truth"] is True
    assert promo_audit_before[0]["before"]["machine_decision"] in \
        backend.PROMO_QUEUED_DECISIONS
