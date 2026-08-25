"""Payment webhook ingestion tests.

The point of these is the security boundary. `/v1/webhooks/payment` is a public,
unauthenticated endpoint whose only defence is the signature, so the tests that
matter most are the ones proving a forged, absent, or replayed request is refused.
An unverified webhook would let anyone who finds the URL inject transactions into
the risk engine and move the entity graph at will.

Run:  python -m pytest tests/test_webhook.py -v
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
import time
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# Must be set BEFORE importing backend: module-level config is read at import.
SECRET = "test-webhook-secret-not-used-anywhere-else"
os.environ["FRAUDSHIELD_WEBHOOK_SECRET"] = SECRET
os.environ["FRAUDSHIELD_USERS_BACKEND"] = "memory"
os.environ["FRAUDSHIELD_WARM_ROWS"] = "0"          # now genuinely means "none"
os.environ["FRAUDSHIELD_DEV_SEED_STAFF"] = "0"
os.environ["FRAUDSHIELD_JWT_SECRET"] = "test-only-jwt-secret"
os.environ["FRAUDSHIELD_IP_PEPPER"] = "test-only-pepper"
os.environ.pop("FRAUDSHIELD_API_KEY", None)

from fastapi.testclient import TestClient  # noqa: E402

import backend  # noqa: E402

PATH = "/v1/webhooks/payment"


def sign(raw: bytes, secret: str = SECRET) -> str:
    return hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()


def event(
    *,
    status: str = "captured",
    amount_paise: int = 249900,
    method: str = "card",
    email: str = "payer@example.com",
    device_fp: str | None = "dev_webhook_test",
    ip_hash: str | None = "ip_webhook_test",
    payment_id: str | None = None,
    event_id: str | None = None,
    created_at: float | None = None,
) -> tuple[bytes, str, str]:
    """Build a provider-shaped event. Returns (raw_body, event_id, payment_id)."""
    pid = payment_id or f"pay_{uuid.uuid4().hex[:12]}"
    eid = event_id or f"evt_{uuid.uuid4().hex[:12]}"
    notes: dict[str, str] = {}
    if device_fp:
        notes["device_fp"] = device_fp
    if ip_hash:
        notes["ip_hash"] = ip_hash
    body = {
        "id": eid,
        "entity": "event",
        "event": f"payment.{status}",
        "contains": ["payment"],
        "created_at": created_at if created_at is not None else time.time(),
        "payload": {
            "payment": {
                "entity": {
                    "id": pid,
                    "entity": "payment",
                    "amount": amount_paise,
                    "currency": "INR",
                    "status": status,
                    "method": method,
                    "email": email,
                    "contact": "+919876543210",
                    "notes": notes,
                    "created_at": int(time.time()),
                }
            }
        },
    }
    raw = json.dumps(body).encode()
    return raw, eid, pid


@pytest.fixture(scope="module")
def client():
    with TestClient(backend.app) as c:
        yield c


def post(client, raw: bytes, signature: str | None, event_id: str | None = None):
    headers = {"content-type": "application/json"}
    if signature is not None:
        headers["x-razorpay-signature"] = signature
    if event_id:
        headers["x-razorpay-event-id"] = event_id
    return client.post(PATH, content=raw, headers=headers)


# ---------------------------------------------------------------------------
# signature verification -- the security boundary
# ---------------------------------------------------------------------------

def test_valid_signature_is_ingested(client):
    raw, eid, pid = event()
    r = post(client, raw, sign(raw), eid)
    assert r.status_code == 200, r.text
    b = r.json()
    assert b["ingested"] is True
    assert b["duplicate"] is False
    assert b["payment_id"] == pid
    assert b["decision"] in ("ALLOW", "MANUAL_REVIEW", "BLOCK")
    assert isinstance(b["risk_score"], float)
    assert b["transaction_id"].startswith("pay_")


def test_forged_signature_is_rejected(client):
    raw, eid, _ = event()
    r = post(client, raw, "deadbeef" * 8, eid)
    assert r.status_code == 401


def test_missing_signature_is_rejected(client):
    raw, eid, _ = event()
    r = post(client, raw, None, eid)
    assert r.status_code == 401


def test_empty_signature_is_rejected(client):
    raw, eid, _ = event()
    r = post(client, raw, "", eid)
    assert r.status_code == 401


def test_signature_from_a_different_secret_is_rejected(client):
    raw, eid, _ = event()
    r = post(client, raw, sign(raw, "the-wrong-secret"), eid)
    assert r.status_code == 401


def test_tampered_body_invalidates_the_signature(client):
    """The attack this actually stops: capture a legitimate event, raise the
    amount, keep the signature."""
    raw, eid, _ = event(amount_paise=100_00)
    good = sign(raw)
    tampered = raw.replace(b'"amount": 10000', b'"amount": 9999900')
    assert tampered != raw
    r = post(client, tampered, good, eid)
    assert r.status_code == 401


def test_verify_helper_units():
    raw = b'{"a":1}'
    good = sign(raw)
    v = backend.verify_webhook_signature
    assert v(raw, good, SECRET) is True
    assert v(raw, good.upper(), SECRET) is True        # hex case-insensitive
    assert v(raw, f"  {good}  ", SECRET) is True       # tolerates whitespace
    assert v(raw, "", SECRET) is False
    assert v(raw, good, "") is False                   # no secret -> never valid
    assert v(b'{"a":2}', good, SECRET) is False


# ---------------------------------------------------------------------------
# idempotency / replay
# ---------------------------------------------------------------------------

def test_replay_of_same_event_is_deduplicated(client):
    raw, eid, pid = event()
    first = post(client, raw, sign(raw), eid)
    assert first.status_code == 200
    assert first.json()["ingested"] is True

    second = post(client, raw, sign(raw), eid)
    assert second.status_code == 200
    b = second.json()
    assert b["ingested"] is False
    assert b["duplicate"] is True
    assert b["transaction_id"] is None


def test_replay_does_not_double_count_velocity(client):
    """A redelivered event must not inflate the customer's counters, or one honest
    payer's retries would look like a burst."""
    raw, eid, _ = event(email="velocity@example.com")
    post(client, raw, sign(raw), eid)

    store = backend.STATE["store"]
    cid, _res = backend._webhook_customer_id("velocity@example.com", "")
    before, _ = store.account_totals(cid)

    for _ in range(4):
        post(client, raw, sign(raw), eid)

    after, _ = store.account_totals(cid)
    assert after == before, "replayed event mutated entity state"


# ---------------------------------------------------------------------------
# payload handling
# ---------------------------------------------------------------------------

def test_amount_is_converted_from_paise(client):
    raw, eid, pid = event(amount_paise=249900)     # Rs 2,499.00
    r = post(client, raw, sign(raw), eid)
    txn_id = r.json()["transaction_id"]
    assert backend.STATE["txns"][txn_id]["amount"] == 2499.00


def test_unmodelled_event_returns_200_without_ingesting(client):
    """Non-2xx would earn an indefinite provider retry loop for an event we simply
    do not model."""
    raw, eid, _ = event()
    body = json.loads(raw)
    body["event"] = "refund.processed"
    raw2 = json.dumps(body).encode()
    r = post(client, raw2, sign(raw2), eid)
    assert r.status_code == 200
    assert r.json()["ingested"] is False
    assert r.json()["duplicate"] is False


def test_malformed_payload_is_rejected(client):
    body = {"id": "evt_x", "event": "payment.captured", "payload": {"nope": {}}}
    raw = json.dumps(body).encode()
    r = post(client, raw, sign(raw), "evt_malformed")
    assert r.status_code == 422


def test_non_json_body_is_rejected(client):
    raw = b"this is not json"
    r = post(client, raw, sign(raw), "evt_notjson")
    assert r.status_code == 400


def test_zero_amount_is_rejected(client):
    raw, eid, _ = event(amount_paise=0)
    r = post(client, raw, sign(raw), eid)
    assert r.status_code == 422


def test_stale_event_is_rejected(client):
    old = time.time() - (backend.WEBHOOK_MAX_AGE_S + 3600)
    raw, eid, _ = event(created_at=old)
    r = post(client, raw, sign(raw), eid)
    assert r.status_code == 422


def test_emi_method_maps_to_card(client):
    raw, eid, _ = event(method="emi")
    r = post(client, raw, sign(raw), eid)
    assert r.status_code == 200
    txn_id = r.json()["transaction_id"]
    assert backend.STATE["txns"][txn_id]["payment_method"] == "card"


def test_missing_notes_marks_signals_incomplete(client):
    """No device_fp / ip_hash in notes means those signals are unavailable, and the
    record must say so rather than silently scoring on sentinels."""
    raw, eid, _ = event(device_fp=None, ip_hash=None)
    r = post(client, raw, sign(raw), eid)
    assert r.status_code == 200
    rec = backend.STATE["txns"][r.json()["transaction_id"]]
    assert rec["signals_complete"] is False
    assert rec["source"] == "webhook"


def test_customer_resolution_is_stable_for_unknown_payers():
    """A random id per event would make every webhook look like a new customer and
    permanently poison account_age_hours for repeat payers."""
    a, res_a = backend._webhook_customer_id("repeat@example.com", "")
    b, res_b = backend._webhook_customer_id("repeat@example.com", "")
    assert a == b
    assert res_a == res_b == "derived"
    c, _ = backend._webhook_customer_id("someone-else@example.com", "")
    assert c != a


# ---------------------------------------------------------------------------
# integration with the rest of the engine
# ---------------------------------------------------------------------------

def test_failed_payment_burst_flags_the_ip(client):
    """Same threshold the storefront uses: a burst from one address is flagged."""
    ip = f"ip_burst_{uuid.uuid4().hex[:8]}"
    store = backend.STATE["store"]
    assert store.ip_is_suspicious(ip) is False

    for i in range(backend.IP_FAIL_THRESHOLD):
        raw, eid, _ = event(
            status="failed", ip_hash=ip, device_fp=f"dev_burst_{i}",
            email=f"burst{i}@example.com",
        )
        r = post(client, raw, sign(raw), eid)
        assert r.status_code == 200, r.text

    assert store.ip_is_suspicious(ip) is True, "burst did not flag the address"


def test_ingested_event_is_audited(client):
    raw, eid, pid = event()
    post(client, raw, sign(raw), eid)
    actions = [e for e in backend.STATE["audit"]
               if e.get("action") == "payment_event_ingested"]
    assert actions, "ingestion was not audited"
    assert any(a["before"].get("payment_id") == pid for a in actions)


def test_risky_event_lands_in_the_review_queue(client):
    """Drive the rules hard enough to leave ALLOW, then assert it is queued."""
    ip = f"ip_queue_{uuid.uuid4().hex[:8]}"
    dev = f"dev_queue_{uuid.uuid4().hex[:8]}"
    queued = False
    for i in range(8):
        raw, eid, _ = event(
            status="failed", amount_paise=9_999_00, ip_hash=ip, device_fp=dev,
            email=f"queue{i}@example.com",
        )
        r = post(client, raw, sign(raw), eid)
        assert r.status_code == 200
        if r.json()["decision"] in ("MANUAL_REVIEW", "BLOCK"):
            queued = r.json()["transaction_id"] in backend.STATE["queue"]
            if queued:
                break
    assert queued, "no risky webhook event reached the review queue"


# ---------------------------------------------------------------------------
# fail-closed when unconfigured
# ---------------------------------------------------------------------------

def test_disabled_when_secret_is_unset(client, monkeypatch):
    """An unverified webhook is worse than none, so the endpoint refuses to run
    rather than accepting anything."""
    monkeypatch.setattr(backend, "WEBHOOK_SECRET", "")
    raw, eid, _ = event()
    r = post(client, raw, sign(raw), eid)
    assert r.status_code == 503
