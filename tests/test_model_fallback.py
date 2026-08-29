"""MODEL_FALLBACK_TRIGGERED — degraded-mode transition audit tests.

The property under test: when the ML artifact disappears, FraudShield keeps
serving on rules + network AND says so once, auditably. It must fail toward
"rules + network + auditability", not toward a crash or a silent downgrade.

Degradation is induced through the real artifact-loading path by pointing
FRAUDSHIELD_ARTIFACTS at an empty directory -- the same mechanism production uses
to relocate artifacts. The repository's own artifacts are never renamed, moved or
modified.

Run:  python -m pytest tests/test_model_fallback.py -v
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
os.environ["FRAUDSHIELD_JWT_SECRET"] = "test-only-jwt-secret-model-fallback"
os.environ["FRAUDSHIELD_IP_PEPPER"] = "test-only-pepper-model-fallback"
os.environ.pop("FRAUDSHIELD_API_KEY", None)

from fastapi.testclient import TestClient  # noqa: E402

import backend  # noqa: E402

PW = "model-fallback-test-password-3390"

CARD = {"number": "4111 1111 1111 1111", "expiry_month": 12,
        "expiry_year": 2029, "cvv": "123", "holder": "Fallback Tester"}


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def degraded_client(tmp_path, monkeypatch):
    """An app whose Scorer finds no artifacts, via the production load path.

    Points ARTIFACTS at an empty tmp dir. The real ml/artifacts/ is untouched.
    Forces in-memory stores so nothing reaches a real DynamoDB table.
    """
    monkeypatch.setattr(backend, "ARTIFACTS", tmp_path / "empty-artifacts")
    monkeypatch.setattr(backend, "USERS_BACKEND", "memory")
    with TestClient(backend.app) as c:
        yield c


@pytest.fixture
def healthy_client(monkeypatch):
    """An app with the real artifacts present."""
    monkeypatch.setattr(backend, "USERS_BACKEND", "memory")
    with TestClient(backend.app) as c:
        yield c


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def fallback_events() -> list[dict]:
    return [e for e in backend.STATE["audit"]
            if e.get("action") == backend.MODEL_FALLBACK_TRIGGERED]


def risk_events() -> list[dict]:
    return [e for e in backend.STATE["audit"]
            if e.get("action") == backend.RISK_DECISION]


def register(client, email: str) -> dict:
    r = client.post("/v1/auth/register", json={"email": email, "password": PW})
    assert r.status_code == 201, r.text
    return {"authorization": f"Bearer {r.json()['access_token']}"}


def admin(client, tag: str) -> dict:
    """Staff token without a second login -- current_user re-reads the store, so
    require_role sees the new role on the existing token. Avoids the login rate
    limiter."""
    email = f"{tag}-{uuid.uuid4().hex[:8]}@example.com"
    h = register(client, email)
    backend.STATE["users"].get_by_email(email).role = "admin"
    return h


def place_order(client, headers, *, device="dev_fallback"):
    return client.post("/v1/orders", headers=headers, json={
        "items": [{"product_id": "p1", "qty": 1}],
        "payment_method": "card", "device_fp": device, "card": CARD,
    })


# ---------------------------------------------------------------------------
# normal startup stays silent
# ---------------------------------------------------------------------------

def test_normal_startup_emits_no_fallback_event(healthy_client):
    assert backend.STATE["scorer"].degraded is False
    assert fallback_events() == []


def test_normal_startup_reports_model_loaded(healthy_client):
    h = healthy_client.get("/health").json()
    assert h["model_loaded"] is True
    assert h["model_version"] != "none"


def test_bare_scorer_construction_emits_nothing(monkeypatch, tmp_path):
    """ml/ and test_score_parity.py build a Scorer with no application STATE. A
    constructor that audited would crash or pollute a log it does not own."""
    monkeypatch.setattr(backend, "ARTIFACTS", tmp_path / "nope")
    before = len(backend.STATE.get("audit", []))
    s = backend.Scorer(artifacts=tmp_path / "nope")
    assert s.degraded is True
    assert len(backend.STATE.get("audit", [])) == before


# ---------------------------------------------------------------------------
# degraded startup emits exactly one event
# ---------------------------------------------------------------------------

def test_missing_artifacts_cause_degraded_mode(degraded_client):
    s = backend.STATE["scorer"]
    assert s.degraded is True
    assert s.booster is None
    assert s.model_version == "none"


def test_missing_artifacts_emit_exactly_one_event(degraded_client):
    assert len(fallback_events()) == 1


def test_event_action_and_actor(degraded_client):
    ev = fallback_events()[0]
    assert ev["action"] == "MODEL_FALLBACK_TRIGGERED"
    assert ev["actor"] == "system:scorer"
    assert ev["event_id"].startswith("mfb_")
    assert ev["at"]


def test_event_records_the_transition(degraded_client):
    ev = fallback_events()[0]
    assert ev["before"]["model_loaded"] is True
    assert ev["before"]["degraded"] is False
    assert ev["after"]["model_loaded"] is False
    assert ev["after"]["degraded"] is True


def test_event_records_model_version_none(degraded_client):
    assert fallback_events()[0]["after"]["model_version"] == "none"
    assert backend.STATE["scorer"].model_version == "none"


def test_event_identifies_fallback_layers(degraded_client):
    a = fallback_events()[0]["after"]
    assert a["fallback_layers"] == ["rules", "network"]


def test_event_weights_match_what_the_scorer_applies(degraded_client):
    """The audited weights must be the ones actually used, not a restatement."""
    a = fallback_events()[0]["after"]
    assert a["fallback_weights"]["rules"] == backend.W_FALLBACK_RULES
    assert a["fallback_weights"]["network"] == backend.W_FALLBACK_NETWORK
    assert (a["fallback_weights"]["rules"]
            + a["fallback_weights"]["network"]) == pytest.approx(1.0)


def test_event_names_the_missing_artifacts(degraded_client):
    a = fallback_events()[0]["after"]
    assert set(a["missing_artifacts"]) == {
        "feature_spec.json", "model.json", "calibrator.json"}
    assert a["artifacts_dir"]


def test_event_attributes_failure_to_load_not_scoring(degraded_client):
    """The model failed at load time. Saying otherwise would misdirect a reader."""
    a = fallback_events()[0]["after"]
    assert a["phase"] == "artifact_load"
    assert "unavailable" in a["note"].lower()


def test_event_is_not_ground_truth_and_writes_no_label(degraded_client):
    ev = fallback_events()[0]
    assert ev["after"]["is_ground_truth"] is False
    assert "label" not in ev["after"]
    assert "label" not in ev["before"]
    # No transaction exists yet, so nothing could have been labelled.
    assert all(t.get("label") is None for t in backend.STATE["txns"].values())


def test_event_carries_no_secrets(degraded_client):
    """Checks actual secret VALUES, not the words. An earlier version of this test
    searched for the substring "secret" and tripped on pytest's own tmp path, which
    is derived from this test's name -- a false positive that proves nothing.
    """
    ev = fallback_events()[0]
    blob = repr(ev)

    for value in (
        PW,
        os.environ["FRAUDSHIELD_JWT_SECRET"],
        os.environ["FRAUDSHIELD_IP_PEPPER"],
        os.environ.get("FRAUDSHIELD_WEBHOOK_SECRET", "\0unset\0"),
        os.environ.get("AWS_SECRET_ACCESS_KEY", "\0unset\0"),
        CARD["number"], CARD["cvv"], CARD["holder"],
        "Bearer ",
    ):
        if value and value != "\0unset\0":
            assert value not in blob, "fallback event leaked a secret value"

    # Operational metadata only: no credential-shaped keys anywhere.
    keys = set(ev["before"]) | set(ev["after"])
    for banned in ("password", "token", "secret", "pepper", "cvv", "card",
                   "api_key", "authorization"):
        assert not any(banned in k.lower() for k in keys), (
            f"fallback event has a {banned!r} field")


# ---------------------------------------------------------------------------
# scoring continues, and does not re-emit
# ---------------------------------------------------------------------------

def test_transactions_still_score_after_fallback(degraded_client):
    h = register(degraded_client, f"deg-{uuid.uuid4().hex[:8]}@example.com")
    r = place_order(degraded_client, h)
    assert r.status_code == 201, r.text
    assert r.json()["order_id"]


def test_risk_decision_records_degraded_true(degraded_client):
    h = register(degraded_client, f"rd-{uuid.uuid4().hex[:8]}@example.com")
    place_order(degraded_client, h)
    ev = risk_events()[-1]
    assert ev["after"]["degraded"] is True
    assert ev["after"]["model_version"] == "none"
    # ML contributed nothing; the score came from the surviving layers.
    assert ev["after"]["sub_scores"]["ml"] == 0.0
    assert ev["after"]["decision"] in ("ALLOW", "MANUAL_REVIEW", "BLOCK")


def test_degraded_score_uses_the_fallback_weights(degraded_client):
    """Reproduce the aggregate from the audited sub-scores."""
    h = register(degraded_client, f"w-{uuid.uuid4().hex[:8]}@example.com")
    place_order(degraded_client, h)
    a = risk_events()[-1]["after"]
    expected = (backend.W_FALLBACK_RULES * a["sub_scores"]["rules"]
                + backend.W_FALLBACK_NETWORK * a["sub_scores"]["network"])
    assert a["risk_score"] == pytest.approx(expected, abs=0.15)


def test_many_transactions_do_not_re_emit_the_event(degraded_client):
    """The bug this guards: one fallback event per transaction."""
    assert len(fallback_events()) == 1
    for i in range(6):
        h = register(degraded_client,
                     f"many{i}-{uuid.uuid4().hex[:6]}@example.com")
        assert place_order(degraded_client, h).status_code == 201
    assert len(risk_events()) >= 6
    assert len(fallback_events()) == 1, "fallback event re-emitted during scoring"


def test_health_reflects_degraded_state(degraded_client):
    h = degraded_client.get("/health").json()
    assert h["model_loaded"] is False
    assert h["model_version"] == "none"
    # Thresholds and the rest of the contract are unchanged.
    assert h["thresholds"]["review"] == backend.STATE["scorer"].review_t
    assert h["status"] == "ok"


def test_fallback_event_is_not_mutated_by_later_scoring(degraded_client):
    before = copy.deepcopy(fallback_events()[0])
    h = register(degraded_client, f"imm-{uuid.uuid4().hex[:8]}@example.com")
    place_order(degraded_client, h)
    assert fallback_events()[0] == before


# ---------------------------------------------------------------------------
# customer isolation
# ---------------------------------------------------------------------------

def test_customer_response_hides_the_fallback(degraded_client):
    h = register(degraded_client, f"cust-{uuid.uuid4().hex[:8]}@example.com")
    body = place_order(degraded_client, h).json()

    assert "risk" not in body
    for f in ("degraded", "model_version", "fallback_layers",
              "fallback_weights", "risk_score", "sub_scores", "decision"):
        assert f not in body, f"customer response leaked {f!r}"

    blob = repr(body).lower()
    for word in ("xgboost", "model", "degraded", "fallback", "artifact"):
        assert word not in blob, f"customer response mentioned {word!r}"


def test_customer_order_list_hides_the_fallback(degraded_client):
    h = register(degraded_client, f"list-{uuid.uuid4().hex[:8]}@example.com")
    place_order(degraded_client, h)
    orders = degraded_client.get("/v1/orders", headers=h).json()["orders"]
    for o in orders:
        for f in ("degraded", "model_version", "risk_score", "decision",
                  "sub_scores"):
            assert f not in o


def test_customer_cannot_read_the_audit_log(degraded_client):
    h = register(degraded_client, f"deny-{uuid.uuid4().hex[:8]}@example.com")
    assert degraded_client.get("/v1/admin/audit", headers=h).status_code == 403


def test_anonymous_cannot_read_the_audit_log(degraded_client):
    assert degraded_client.get("/v1/admin/audit").status_code in (401, 403)


# ---------------------------------------------------------------------------
# admin retrieval
# ---------------------------------------------------------------------------

def test_admin_can_retrieve_the_fallback_event(degraded_client):
    h = admin(degraded_client, "ret")
    r = degraded_client.get("/v1/admin/audit", headers=h, params={"limit": 500})
    assert r.status_code == 200
    assert "MODEL_FALLBACK_TRIGGERED" in {e["action"] for e in r.json()["entries"]}


def test_action_filter_retrieves_only_fallback_events(degraded_client):
    h = admin(degraded_client, "flt")
    place_order(degraded_client, admin(degraded_client, "noise"))

    r = degraded_client.get("/v1/admin/audit", headers=h,
                            params={"action": "MODEL_FALLBACK_TRIGGERED",
                                    "limit": 500})
    assert r.status_code == 200
    entries = r.json()["entries"]
    assert len(entries) == 1
    assert entries[0]["action"] == "MODEL_FALLBACK_TRIGGERED"
    assert entries[0]["after"]["degraded"] is True


def test_fallback_and_risk_decision_both_retrievable(degraded_client):
    h = admin(degraded_client, "both")
    place_order(degraded_client, h)
    entries = degraded_client.get("/v1/admin/audit", headers=h,
                                  params={"limit": 500}).json()["entries"]
    actions = {e["action"] for e in entries}
    assert "MODEL_FALLBACK_TRIGGERED" in actions
    assert "RISK_DECISION" in actions


# ---------------------------------------------------------------------------
# startup resilience
# ---------------------------------------------------------------------------

def test_startup_survives_audit_persistence_failure(tmp_path, monkeypatch, capsys):
    """A broken audit store must not stop the service coming up in fallback mode.
    Turning degraded-but-serving into dead would be a worse failure."""
    monkeypatch.setattr(backend, "ARTIFACTS", tmp_path / "empty")
    monkeypatch.setattr(backend, "USERS_BACKEND", "memory")

    real_make = backend.make_record_store

    def broken_store():
        store, desc = real_make()
        original_put = store.put

        def flaky(pk, sk, item):
            if pk.startswith("AUDIT#"):
                raise RuntimeError("simulated audit outage at startup")
            return original_put(pk, sk, item)

        store.put = flaky
        return store, desc

    monkeypatch.setattr(backend, "make_record_store", broken_store)

    with TestClient(backend.app) as c:
        assert c.get("/health").json()["model_loaded"] is False
        # Still in-process, so the event is not lost -- only unpersisted.
        assert len(fallback_events()) == 1
        h = register(c, f"resil-{uuid.uuid4().hex[:8]}@example.com")
        assert place_order(c, h).status_code == 201

    assert "audit write failed" in capsys.readouterr().out


def test_recovery_when_artifacts_return(healthy_client):
    """A later startup with artifacts present is healthy and silent again."""
    assert backend.STATE["scorer"].degraded is False
    assert fallback_events() == []
    assert healthy_client.get("/health").json()["model_loaded"] is True
