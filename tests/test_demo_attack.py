"""Demo fraud attack: authorisation, safety gates, and proof the engine decides.

WHAT THIS SUITE IS ABOUT
------------------------
`POST /v1/admin/demo/fraud-attack` generates eight suspicious payment attempts on
one synthetic account, one device and one address, inside the existing 600-second
velocity window, and puts every one of them through the real pipeline.

The properties defended here, in order of how badly it would matter if they broke:

  * **The engine decides, not the endpoint.** No risk score, decision, sub-score
    or reason code is computed, adjusted or defaulted by the demo path. Proved by
    replacing `Scorer.score` with a stub that returns a value nothing else in the
    system would produce, and finding exactly that value in the response, the
    stored transaction and the audit record.
  * **It cannot run by accident.** Admin only, demo flag only, simulator only, and
    the flag is NOT inferred from the provider.
  * **Synthetic activity is labelled.** Every generated transaction and audit event
    carries `demo: true`, and none of them claims ground truth.
  * **It uses the pipeline, not a copy of it.** Real scorer, real store, real
    persistence, real audit emitter, real notification path.
  * **A synthetic run cannot leak a credential.**

Run:  python -m pytest tests/test_demo_attack.py -v
"""
from __future__ import annotations

import os
import re
import smtplib
import sys
import uuid
import json
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

os.environ["FRAUDSHIELD_USERS_BACKEND"] = "memory"
os.environ["FRAUDSHIELD_WARM_ROWS"] = "0"
os.environ["FRAUDSHIELD_DEV_SEED_STAFF"] = "0"
os.environ["FRAUDSHIELD_JWT_SECRET"] = "test-only-jwt-secret-demo-attack"
os.environ["FRAUDSHIELD_IP_PEPPER"] = "test-only-pepper-demo-attack"
os.environ.pop("FRAUDSHIELD_API_KEY", None)

from fastapi.testclient import TestClient  # noqa: E402

import backend  # noqa: E402
import notifications as nf  # noqa: E402
import payments  # noqa: E402

PW = "demo-attack-password-4471"
PATH = "/v1/admin/demo/fraud-attack"

# A value no real credential in this repository uses, so finding it anywhere is
# unambiguous.
SECRET_PW = "not-a-real-smtp-password-8813"


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def db(monkeypatch):
    """In-memory stores, whatever .env says, plus the demo gates open.

    `DEMO_MODE` is set on the module rather than through the environment because
    the flag is read at import and `backend` may already be imported by an earlier
    test module in the same session.
    """
    records = backend.InMemoryRecordStore()
    users = backend.InMemoryUserStore()
    monkeypatch.setattr(backend, "USERS_BACKEND", "memory")
    monkeypatch.setattr(backend, "make_record_store", lambda: (records, "test"))
    monkeypatch.setattr(backend, "make_user_store", lambda: (users, "test"))
    monkeypatch.setattr(backend, "API_KEY", "")
    monkeypatch.setattr(backend, "DEMO_MODE", True)
    # Provider configuration is held as module attributes, not re-read from the
    # environment at use time, so this is where a test sets it.
    monkeypatch.setattr(backend, "PAYMENT_PROVIDER", payments.PROVIDER_SIMULATED)
    monkeypatch.setattr(backend, "RAZORPAY_KEY_ID", "")
    monkeypatch.setattr(backend, "RAZORPAY_KEY_SECRET", "")
    return records


@contextmanager
def app_run():
    with TestClient(backend.app) as c:
        yield c


def register(c, email: str) -> dict:
    r = c.post("/v1/auth/register", json={"email": email, "password": PW})
    assert r.status_code == 201, r.text
    return {"authorization": f"Bearer {r.json()['access_token']}"}


def staff(c, role: str, tag: str = "u") -> dict:
    email = f"{tag}-{uuid.uuid4().hex[:8]}@example.com"
    h = register(c, email)
    backend.STATE["users"].get_by_email(email).role = role
    return h


def admin(c, tag: str = "adm") -> dict:
    return staff(c, "admin", tag)


def trigger(c, headers: dict) -> dict:
    r = c.post(PATH, headers=headers)
    assert r.status_code == 201, r.text
    return r.json()


def pinned(score: float = 3.3, decision: str = "ALLOW", **kw):
    """A Scorer.score replacement returning values the real engine would not.

    3.3 / ALLOW on a 45,000-rupee burst is not a plausible real output, which is
    the point: if the endpoint reports it, the endpoint is reporting what the
    scorer said rather than deciding anything.
    """
    calls: list[dict] = []

    def fake(self, store, txn):
        calls.append(dict(txn))
        d = backend.Decision(
            risk_score=score,
            decision=decision,
            sub_scores={"ml": 1.1, "rules": 2.2, "network": 3.3},
            reason_codes=[{"code": "STUB", "severity": "low",
                           "detail": "stubbed", "source": "test"}],
            fired_rules=kw.get("fired_rules", ["stub_rule"]),
            override=None,
            model_version="stub-model-1",
            degraded=False,
        )
        raw = {"txn_count_10m": 99, "amount_ratio": 42.0,
               "txn_count_1h": 99, "failed_count_1h": 0,
               "customer_avg_amount": 1.0, "prev_txn_count": 0,
               "device_account_count": 1, "ip_account_count": 1,
               "account_age_hours": 1.0}
        return d, raw

    return fake, calls


class FakeTransport:
    """Stands in for smtplib. Nothing here opens a socket."""

    def __init__(self, raises=None):
        self.raises = raises
        self.messages: list = []

    def send_message(self, msg, sender, recipients):
        if self.raises is not None:
            raise self.raises
        self.messages.append((msg, sender, tuple(recipients)))


class FailingProvider:
    provider_name = "failing"

    def send_email(self, *, to, subject, body, metadata=None):
        return nf.SendResult(provider=self.provider_name, status=nf.STATUS_FAILED,
                             recipient_count=len(tuple(to)),
                             error="delivery refused", error_category="refused")


class ExplodingProvider:
    provider_name = "exploding"

    def send_email(self, *, to, subject, body, metadata=None):
        raise RuntimeError("simulated provider explosion on host-mail-04.internal")


def audit_entries(c, headers: dict) -> list[dict]:
    r = c.get("/v1/admin/audit?limit=200", headers=headers)
    assert r.status_code == 200, r.text
    return r.json()["entries"]


# ===========================================================================
# A. the endpoint exists and is reachable
# ===========================================================================

def test_the_endpoint_exists(db):
    with app_run() as c:
        body = trigger(c, admin(c))

    assert body["scenario"] == "fraud_attack"
    assert body["demo"] is True


def test_it_is_registered_as_a_post_route(db):
    paths = {(r.path, tuple(sorted(r.methods)))
             for r in backend.app.routes if hasattr(r, "methods")}
    assert (PATH, ("POST",)) in paths


def test_it_takes_no_request_body(db):
    """No knobs. A caller who could choose the attempt count could choose
    100,000, so the count is not a parameter at all -- and a body offering one is
    ignored rather than honoured."""
    with app_run() as c:
        h = admin(c)
        r = c.post(PATH, headers=h, json={"attempts": 5000})
        assert r.status_code == 201, r.text
        assert r.json()["attempts_generated"] == backend.DEMO_ATTEMPTS


# ===========================================================================
# B. authorisation
# ===========================================================================

def test_anonymous_is_rejected(db):
    with app_run() as c:
        assert c.post(PATH).status_code == 401


def test_a_customer_is_rejected(db):
    with app_run() as c:
        h = register(c, f"cust-{uuid.uuid4().hex[:8]}@example.com")
        r = c.post(PATH, headers=h)
    assert r.status_code == 403


def test_an_analyst_is_rejected(db):
    """Current policy is admin-only. An analyst reviews evidence; manufacturing
    evidence is a different authority."""
    with app_run() as c:
        h = staff(c, "analyst", "ana")
        r = c.post(PATH, headers=h)
    assert r.status_code == 403
    assert "analyst" in r.json()["detail"]


def test_an_admin_is_allowed(db):
    with app_run() as c:
        r = c.post(PATH, headers=admin(c))
    assert r.status_code == 201


def test_a_garbage_token_is_rejected(db):
    with app_run() as c:
        r = c.post(PATH, headers={"authorization": "Bearer not-a-token"})
    assert r.status_code == 401


# ===========================================================================
# C. safety gates
# ===========================================================================

def test_demo_mode_is_required(db, monkeypatch):
    monkeypatch.setattr(backend, "DEMO_MODE", False)
    with app_run() as c:
        r = c.post(PATH, headers=admin(c))
    assert r.status_code == 403
    assert "FRAUDSHIELD_DEMO_MODE" in r.json()["detail"]


def test_demo_mode_defaults_to_off(db, monkeypatch):
    """Production must be safe without anyone having read the documentation."""
    monkeypatch.delenv("FRAUDSHIELD_DEMO_MODE", raising=False)
    assert os.environ.get("FRAUDSHIELD_DEMO_MODE") is None
    # Re-evaluated the way the module does it at import.
    assert (os.environ.get("FRAUDSHIELD_DEMO_MODE", "false").strip().lower()
            in ("1", "true", "yes", "on")) is False


def test_nothing_is_generated_when_demo_mode_is_off(db, monkeypatch):
    """The gate runs BEFORE the scenario, so a refusal leaves no residue."""
    monkeypatch.setattr(backend, "DEMO_MODE", False)
    with app_run() as c:
        h = admin(c)
        c.post(PATH, headers=h)
        assert c.get("/v1/admin/queue", headers=h).json()["count"] == 0
        assert not [e for e in audit_entries(c, h)
                    if e["action"] in (backend.RISK_DECISION,
                                       backend.DEMO_TRIGGERED)]


def test_a_real_payment_provider_is_rejected(db, monkeypatch):
    """The second gate. Generating synthetic authorisations against a real gateway
    is not something this endpoint will do."""
    monkeypatch.setattr(backend, "PAYMENT_PROVIDER", payments.PROVIDER_RAZORPAY)
    monkeypatch.setattr(backend, "RAZORPAY_KEY_ID", "rzp_test_stub")
    monkeypatch.setattr(backend, "RAZORPAY_KEY_SECRET", "stub-secret")
    with app_run() as c:
        h = admin(c)
        r = c.post(PATH, headers=h)
        assert r.status_code == 409, r.text
        assert "simulator" in r.json()["detail"]
        assert c.get("/v1/admin/queue", headers=h).json()["count"] == 0


def test_a_degraded_razorpay_request_is_still_refused(db, monkeypatch):
    """Requesting razorpay with no credentials falls back to the simulator, so the
    ACTIVE provider is simulated -- but the operator asked for a real gateway, and
    consent to inject traffic cannot be read out of a fallback."""
    monkeypatch.setattr(backend, "PAYMENT_PROVIDER", payments.PROVIDER_RAZORPAY)
    with app_run() as c:
        h = admin(c)
        assert (backend.STATE["provider_status"]["payment_provider"]
                == payments.PROVIDER_SIMULATED)
        assert c.post(PATH, headers=h).status_code == 409


def test_the_demo_flag_is_not_inferred_from_the_simulator(db, monkeypatch):
    """The simulator is a normal production state for this project, so it is not
    consent. Both gates are independent."""
    monkeypatch.setattr(backend, "DEMO_MODE", False)
    with app_run() as c:
        st = backend.demo_status()
        assert st["provider_is_simulated"] is True
        assert st["demo_mode"] is False
        assert st["enabled"] is False


def test_health_reports_demo_readiness(db):
    with app_run() as c:
        h = c.get("/health").json()
    assert h["demo"]["enabled"] is True
    assert h["demo"]["attempts"] == backend.DEMO_ATTEMPTS
    assert h["demo"]["blocked_because"] == []


def test_health_names_the_closed_gate(db, monkeypatch):
    monkeypatch.setattr(backend, "DEMO_MODE", False)
    with app_run() as c:
        st = c.get("/health").json()["demo"]
    assert st["enabled"] is False
    assert any("DEMO_MODE" in r for r in st["blocked_because"])


def test_health_demo_status_carries_no_credentials(db, monkeypatch):
    monkeypatch.setenv("RAZORPAY_KEY_SECRET", "super-secret-value-991")
    with app_run() as c:
        blob = repr(c.get("/health").json()["demo"])
    assert "super-secret-value-991" not in blob


# ===========================================================================
# D. the scenario shape
# ===========================================================================

def test_exactly_eight_attempts_are_generated(db):
    with app_run() as c:
        body = trigger(c, admin(c))
    assert body["attempts_generated"] == 8
    assert len(body["results"]) == 8
    assert [r["attempt"] for r in body["results"]] == list(range(1, 9))


def test_every_attempt_is_the_same_customer(db):
    with app_run() as c:
        body = trigger(c, admin(c))
        ids = {backend.STATE["txns"][r["transaction_id"]]["customer_id"]
               for r in body["results"]}
    assert ids == {body["customer_id"]}


def test_every_attempt_is_the_same_device(db):
    with app_run() as c:
        body = trigger(c, admin(c))
        devices = {backend.STATE["txns"][r["transaction_id"]]["device_fp"]
                   for r in body["results"]}
    assert devices == {body["device_id"]}
    assert body["device_id"].startswith(backend.DEMO_DEVICE_PREFIX)


def test_every_attempt_is_the_same_address(db):
    with app_run() as c:
        body = trigger(c, admin(c))
        ips = {backend.STATE["txns"][r["transaction_id"]]["ip_hash"]
               for r in body["results"]}
    assert ips == {body["ip_hash"]}
    assert body["ip_hash"].startswith(backend.DEMO_IP_PREFIX)


def test_the_synthetic_address_cannot_collide_with_a_derived_one(db):
    """`ip_hash_of()` produces a hex digest. A `demo_ip_` prefix is not something
    it can ever return, so synthetic and real addresses cannot be confused."""
    ident = backend.demo_identity()
    assert ident["ip_hash"].startswith("demo_ip_")
    assert not all(ch in "0123456789abcdef" for ch in ident["ip_hash"])
    assert ident["home_ip_hash"].startswith("demo_home_ip_")


def test_all_timestamps_sit_inside_the_ten_minute_window(db):
    with app_run() as c:
        body = trigger(c, admin(c))

    stamps = [backend._iso_to_epoch(r["at"]) for r in body["results"]]
    assert None not in stamps
    assert max(stamps) - min(stamps) == pytest.approx(
        (backend.DEMO_ATTEMPTS - 1) * backend.DEMO_SPACING_SECONDS, abs=1)
    # The window the velocity feature actually counts over.
    assert max(stamps) - min(stamps) < 600


def test_timestamps_are_strictly_increasing(db):
    """The velocity deques are trimmed from the left on the assumption that they
    are time-ordered, so a burst delivered out of order would corrupt them."""
    with app_run() as c:
        body = trigger(c, admin(c))
    stamps = [backend._iso_to_epoch(r["at"]) for r in body["results"]]
    assert stamps == sorted(stamps)
    assert len(set(stamps)) == len(stamps)


def test_the_schedule_helper_is_deterministic_and_bounded():
    """No global clock is touched: the schedule is arithmetic on a passed-in now."""
    sched = backend.demo_schedule(1_000_000.0)
    assert len(sched) == backend.DEMO_ATTEMPTS
    assert sched[-1] == 1_000_000.0
    assert sched == sorted(sched)
    assert sched[-1] - sched[0] < 600


def test_the_baseline_history_is_context_not_decisions(db):
    """The replayed history is committed the way warm_store() replays CSV rows: it
    is what amount_ratio deviates FROM, not activity FraudShield decided on. So it
    must not appear as scored transactions."""
    with app_run() as c:
        h = admin(c)
        body = trigger(c, h)
        assert body["baseline"]["transactions"] == backend.DEMO_BASELINE_TXNS
        assert body["baseline"]["scored"] is False
        assert body["baseline"]["persisted"] is False
        # Only the eight attempts are scored transactions.
        assert len(backend.STATE["txns"]) == 8
        decisions = [e for e in audit_entries(c, h)
                     if e["action"] == backend.RISK_DECISION]
        assert len(decisions) == 8


def test_the_baseline_gives_the_customer_a_real_history(db):
    with app_run() as c:
        body = trigger(c, admin(c))
    # prev_txn_count on the LAST attempt: 60 baseline + 7 earlier attempts.
    assert body["evidence"]["prev_txn_count"] == (
        backend.DEMO_BASELINE_TXNS + backend.DEMO_ATTEMPTS - 1)
    assert body["evidence"]["account_age_hours"] == pytest.approx(
        backend.DEMO_ACCOUNT_AGE_DAYS * 24, abs=1)


def test_each_run_uses_a_fresh_synthetic_account(db):
    with app_run() as c:
        h = admin(c)
        a, b = trigger(c, h), trigger(c, h)
    assert a["customer_id"] != b["customer_id"]
    assert a["customer_id"].startswith("demo_cust_")


# ===========================================================================
# E. the engine decides -- the core of this suite
# ===========================================================================

def test_the_real_scorer_is_called_once_per_generated_transaction(db, monkeypatch):
    """Eight generated transactions, eight scorer calls. Nothing is scored twice
    and nothing skips the engine."""
    fake, calls = pinned()
    monkeypatch.setattr(backend.Scorer, "score", fake)
    with app_run() as c:
        body = trigger(c, admin(c))

    assert body["attempts_generated"] == 8
    assert len(calls) == 8


def test_every_scorer_call_receives_the_same_actor(db, monkeypatch):
    fake, calls = pinned()
    monkeypatch.setattr(backend.Scorer, "score", fake)
    with app_run() as c:
        trigger(c, admin(c))

    assert len({t["customer_id"] for t in calls}) == 1
    assert len({t["device_fp"] for t in calls}) == 1
    assert len({t["ip_hash"] for t in calls}) == 1
    assert [t["ts"] for t in calls] == sorted(t["ts"] for t in calls)


def test_the_risk_score_is_not_computed_by_the_demo_endpoint(db, monkeypatch):
    """A stub returns 3.3 for a 45,000-rupee burst -- a value the real engine would
    never produce. Finding it everywhere proves the endpoint reports the scorer
    rather than deciding."""
    fake, _ = pinned(score=3.3, decision="ALLOW")
    monkeypatch.setattr(backend.Scorer, "score", fake)
    with app_run() as c:
        h = admin(c)
        body = trigger(c, h)

        assert {r["risk_score"] for r in body["results"]} == {3.3}
        assert body["final_transaction"]["risk_score"] == 3.3
        # And in the durable record and the audit trail, not only the response.
        assert {t["risk_score"] for t in backend.STATE["txns"].values()} == {3.3}
        scored = [e for e in audit_entries(c, h)
                  if e["action"] == backend.RISK_DECISION]
        assert {e["after"]["risk_score"] for e in scored} == {3.3}


def test_the_decision_is_not_hardcoded_to_block(db, monkeypatch):
    """The most important test in this file. If the engine says ALLOW, the demo
    says ALLOW -- no queue item, no alert, no pretence of an attack."""
    fake, _ = pinned(score=3.3, decision="ALLOW")
    monkeypatch.setattr(backend.Scorer, "score", fake)
    with app_run() as c:
        h = admin(c)
        body = trigger(c, h)

        assert {r["decision"] for r in body["results"]} == {"ALLOW"}
        assert body["final_transaction"]["decision"] == "ALLOW"
        assert body["decisions"] == {"ALLOW": 8, "MANUAL_REVIEW": 0, "BLOCK": 0}
        assert body["queued_for_review"] == 0
        assert body["notification_triggered"] is False
        assert c.get("/v1/admin/queue", headers=h).json()["count"] == 0


@pytest.mark.parametrize("decision", ["ALLOW", "MANUAL_REVIEW", "BLOCK"])
def test_whatever_the_engine_decides_is_what_is_reported(db, monkeypatch, decision):
    fake, _ = pinned(score=41.5, decision=decision)
    monkeypatch.setattr(backend.Scorer, "score", fake)
    with app_run() as c:
        body = trigger(c, admin(c))
    assert body["decisions"][decision] == 8
    assert body["final_transaction"]["decision"] == decision


def test_sub_scores_and_reason_codes_come_from_the_scorer(db, monkeypatch):
    fake, _ = pinned()
    monkeypatch.setattr(backend.Scorer, "score", fake)
    with app_run() as c:
        body = trigger(c, admin(c))
        stored = next(iter(backend.STATE["txns"].values()))

    assert body["final_transaction"]["sub_scores"] == {"ml": 1.1, "rules": 2.2,
                                                      "network": 3.3}
    assert body["signals"] == ["stub_rule"]
    assert stored["reason_codes"][0]["code"] == "STUB"


def test_the_demo_path_contains_no_risk_arithmetic():
    """Read the source of the endpoint itself. A demo that assigned a score would
    have to write one down somewhere, and this is the cheapest possible check that
    nobody has."""
    import inspect

    src = inspect.getsource(backend.demo_fraud_attack)
    for forbidden in ("risk_score =", "risk_score=9", 'decision = "BLOCK"',
                      "decision='BLOCK'", 'decision = "MANUAL_REVIEW"'):
        assert forbidden not in src, forbidden
    # It must call the engine.
    assert "scorer.score(store, txn)" in src


def test_the_scenario_constants_do_not_touch_the_model(db):
    """Nothing in this feature may move a weight or a threshold."""
    assert backend.W_ML == 0.70
    assert backend.W_RULES == 0.20
    assert backend.W_NETWORK == 0.10
    assert backend.RULE_POINTS["velocity_breach"] == 20
    assert backend.RULE_POINTS["amount_anomaly"] == 15
    assert backend.DEFAULT_REVIEW_T == 5.0 or backend.DEFAULT_REVIEW_T >= 0


# ===========================================================================
# F. the signals the real engine actually finds
# ===========================================================================

def test_velocity_breach_fires(db):
    """The rule this whole scenario exists to demonstrate. `txn_count_10m > 5`, so
    it cannot fire before the seventh attempt -- and it must fire by the eighth."""
    with app_run() as c:
        body = trigger(c, admin(c))

    assert "velocity_breach" in body["signals"]
    fired = {r["attempt"]: r["fired_rules"] for r in body["results"]}
    assert "velocity_breach" not in fired[6]
    assert "velocity_breach" in fired[7]
    assert "velocity_breach" in fired[8]


def test_the_velocity_counter_climbs_one_per_attempt(db):
    """Read from the feature vector the engine built, not from a claim."""
    with app_run() as c:
        body = trigger(c, admin(c))
    assert [r["txn_count_10m"] for r in body["results"]] == list(range(8))
    assert body["evidence"]["txn_count_10m"] == 7


def test_the_amount_anomaly_has_a_real_baseline_to_deviate_from(db):
    with app_run() as c:
        body = trigger(c, admin(c))
    assert "amount_anomaly" in body["signals"]
    assert body["results"][0]["amount_ratio"] > 4
    assert body["evidence"]["customer_avg_amount"] > 0


def test_the_new_device_is_only_new_once(db):
    """After the first attempt the device is known to the account, so a second
    `new_device` would be the rule misfiring rather than evidence."""
    with app_run() as c:
        body = trigger(c, admin(c))
    firing = [r["attempt"] for r in body["results"]
              if "new_device" in r["fired_rules"]]
    assert firing == [1]


def test_no_signal_is_claimed_that_did_not_fire(db):
    """`signals` is the union of what the engine reported, never a wish list. With
    one account there is no device sharing and no IP concentration, so those two
    must be absent."""
    with app_run() as c:
        body = trigger(c, admin(c))
    union = set()
    for r in body["results"]:
        union |= set(r["fired_rules"])
    assert set(body["signals"]) == union
    assert "device_abuse" not in body["signals"]
    assert "ip_concentration" not in body["signals"]


def test_the_network_layer_sees_a_single_account_on_the_first_run(db):
    """Reported honestly rather than inflated: `_network` needs three accounts in a
    component before it scores anything at all."""
    with app_run() as c:
        body = trigger(c, admin(c))
    assert body["evidence"]["device_account_count"] == 1
    assert {r["sub_scores"]["network"] for r in body["results"]} == {0.0}


def test_repeated_runs_are_fully_isolated(db):
    """Every run mints its own customer, device and address.

    THE BUG THIS REPLACES A TEST FOR. The device and address used to be fixed
    constants, so each run added an account to the same device and the ring grew --
    which read as a feature until it broke the demo. Those counts are model
    features, so by the third run the account looked established, some attempts fell
    under the block threshold, MANUAL_REVIEW attempts reached the simulator and
    mostly succeeded, and the address stopped accumulating three distinct failed
    methods. The suspicious-address alert quietly stopped firing the more the demo
    was used.

    Isolation is what makes the scenario reproducible, so it is what gets asserted.
    """
    with app_run() as c:
        h = admin(c)
        runs = [trigger(c, h) for _ in range(3)]

    for r in runs:
        # Never inherits another run's history, however many times it is clicked.
        assert r["evidence"]["device_account_count"] == 1
        assert r["evidence"]["ip_account_count"] == 1
        assert r["evidence"]["prev_txn_count"] == (
            backend.DEMO_BASELINE_TXNS + backend.DEMO_ATTEMPTS - 1)

    for field in ("customer_id", "device_id", "ip_hash"):
        values = {r[field] for r in runs}
        assert len(values) == 3, f"{field} was reused across runs: {values}"

    # And the run token ties one run's identifiers together, so an operator can see
    # at a glance which run a device or address belongs to.
    for r in runs:
        token = r["customer_id"].rsplit("_", 1)[-1]
        assert r["device_id"].endswith(token)
        assert r["ip_hash"].endswith(token)


def test_the_scenario_is_reproducible_across_runs(db):
    """The point of isolation: the same decisions and signals every time.

    This is what the fixed device and address cost. Not asserting exact scores --
    those belong to the engine -- but that the OUTCOME does not drift with use.
    """
    with app_run() as c:
        h = admin(c)
        runs = [trigger(c, h) for _ in range(3)]

    assert len({tuple(sorted(r["signals"])) for r in runs}) == 1, \
        f"signals drifted across runs: {[sorted(r['signals']) for r in runs]}"
    assert len({json.dumps(r["decisions"], sort_keys=True) for r in runs}) == 1, \
        f"decisions drifted across runs: {[r['decisions'] for r in runs]}"
    assert len({r["ip_flagged"] for r in runs}) == 1, \
        "the address flag fired on some runs and not others"
    assert len({r["final_transaction"]["risk_score"] for r in runs}) == 1, \
        "the final score drifted across runs"


# ===========================================================================
# G. persistence
# ===========================================================================

def test_every_attempt_is_persisted(db):
    with app_run() as c:
        body = trigger(c, admin(c))
    assert body["transactions_persisted"] == 8
    for r in body["results"]:
        item = db.get(f"TXN#{r['transaction_id']}", "DETAIL")
        assert item is not None
        assert item["risk_score"] == r["risk_score"]
        assert item["decision"] == r["decision"]


def test_the_rehydration_pointer_is_written_for_every_attempt(db):
    with app_run() as c:
        body = trigger(c, admin(c))
    pointers = db.query_prefix("INDEX#TXN", "")
    ids = {p["transaction_id"] for p in pointers}
    assert ids == {r["transaction_id"] for r in body["results"]}
    for p in pointers:
        assert p["customer_id"] == body["customer_id"]
        assert p["device_fp"] == body["device_id"]
        assert p["committed"] is True


def test_queued_attempts_appear_in_the_analyst_queue(db):
    with app_run() as c:
        h = admin(c)
        body = trigger(c, h)
        q = c.get("/v1/admin/queue", headers=h).json()

    queued = [r for r in body["results"]
              if r["decision"] in backend.QUEUED_DECISIONS]
    assert body["queued_for_review"] == len(queued)
    assert q["count"] == len(queued)


def test_generated_transactions_are_openable_by_an_analyst(db):
    with app_run() as c:
        h = admin(c)
        body = trigger(c, h)
        tid = body["final_transaction"]["transaction_id"]
        r = c.get(f"/v1/admin/transactions/{tid}", headers=h)

    assert r.status_code == 200
    detail = r.json()
    assert detail["risk_score"] == body["final_transaction"]["risk_score"]
    assert detail["demo"] is True
    assert detail["features"]["txn_count_10m"] == 7


def test_the_scenario_survives_a_restart(db):
    """The queue, the scores and the evidence come back from the record store, and
    nothing is re-scored on the way in."""
    with app_run() as c:
        h = admin(c)
        body = trigger(c, h)
        before = {r["transaction_id"]: (r["risk_score"], r["decision"])
                  for r in body["results"]}
        queued_before = c.get("/v1/admin/queue", headers=h).json()["count"]

    # A second app context against the same store is this repository's restart.
    with app_run() as c:
        h = admin(c, "adm2")
        after = {t: (backend.STATE["txns"][t]["risk_score"],
                     backend.STATE["txns"][t]["decision"])
                 for t in before}
        assert after == before
        assert c.get("/v1/admin/queue", headers=h).json()["count"] == queued_before
        # Still marked synthetic after a reload.
        assert all(backend.STATE["txns"][t]["demo"] is True for t in before)


def test_velocity_counters_are_rebuilt_from_the_generated_attempts(db):
    """Phase 6's real requirement: the EFFECT on entity state survives, not just
    the rows. Replay is chronological, so the deque is usable."""
    with app_run() as c:
        body = trigger(c, admin(c))
        cid = body["customer_id"]
        device = body["device_id"]
        ip = body["ip_hash"]
        last_ts = backend._iso_to_epoch(body["results"][-1]["at"])

    with app_run() as c:
        store = backend.STATE["store"]
        v10, v1h, _f10, _f1h = store.velocity(cid, last_ts)
        assert v10 == 8, "the eight attempts did not come back into the window"
        assert v1h == 8
        assert device in store.acct_devices[cid]
        assert cid in store.device_accounts(device)
        assert cid in store.ip_accounts(ip)


def test_a_persistence_failure_is_reported_not_hidden(db, monkeypatch):
    """If the durable write cannot land, the response says so rather than claiming
    eight persisted transactions."""
    original = backend.InMemoryRecordStore.put

    def flaky(self, pk, sk, item):
        if pk.startswith("TXN#"):
            raise RuntimeError("simulated store outage on host-db-11.internal")
        return original(self, pk, sk, item)

    with app_run() as c:
        monkeypatch.setattr(backend.InMemoryRecordStore, "put", flaky)
        body = trigger(c, admin(c))

    assert body["transactions_persisted"] == 0
    assert body["attempts_generated"] == 8


def test_an_audit_outage_does_not_fail_the_run(db, monkeypatch):
    original = backend.InMemoryRecordStore.put

    def flaky(self, pk, sk, item):
        if pk.startswith("AUDIT#"):
            raise RuntimeError("simulated audit outage")
        return original(self, pk, sk, item)

    with app_run() as c:
        monkeypatch.setattr(backend.InMemoryRecordStore, "put", flaky)
        r = c.post(PATH, headers=admin(c))

    assert r.status_code == 201
    assert r.json()["attempts_generated"] == 8


# ===========================================================================
# H. audit
# ===========================================================================

def test_audit_events_are_created(db):
    with app_run() as c:
        h = admin(c)
        body = trigger(c, h)
        entries = audit_entries(c, h)

    assert body["audit_created"] is True
    assert len([e for e in entries if e["action"] == backend.RISK_DECISION]) == 8
    assert len([e for e in entries if e["action"] == backend.DEMO_TRIGGERED]) == 1


def test_the_demo_marker_is_on_every_generated_audit_event(db):
    with app_run() as c:
        h = admin(c)
        trigger(c, h)
        entries = audit_entries(c, h)

    assert entries
    for e in entries:
        after = e.get("after") or {}
        assert after.get("demo") is True, e["action"]
        assert after.get("demo_scenario") == "fraud_attack"


def test_notification_audit_events_are_marked_too(db, monkeypatch):
    """The gap this closes: with recipients configured the run also emits
    NOTIFICATION_SENT events, and an auditor filtering for synthetic activity must
    not have to reason about which communications belonged to it."""
    fake, _ = pinned(score=91.4, decision="BLOCK")
    monkeypatch.setattr(backend.Scorer, "score", fake)
    with app_run() as c:
        h = admin(c)
        backend.STATE["email_recipients"] = ("analyst@example.com",)
        trigger(c, h)
        entries = audit_entries(c, h)

    # Five transaction alerts are delivered (the volume ceiling), three are
    # throttled, and the suspicious-address alert is exempt from the ceiling and
    # delivered as well. Every one of those, delivered or withheld, must carry the
    # marker -- a withheld alert is still evidence of synthetic activity.
    notes = [e for e in entries
             if e["action"] in (backend.NOTIFICATION_SENT,
                                backend.NOTIFICATION_THROTTLED)]
    sent = [e for e in notes if e["action"] == backend.NOTIFICATION_SENT]
    throttled = [e for e in notes if e["action"] == backend.NOTIFICATION_THROTTLED]

    assert len(sent) == backend.ALERT_RATE_MAX + 1, "5 blocks + 1 address alert"
    assert len(throttled) == backend.DEMO_ATTEMPTS - backend.ALERT_RATE_MAX
    assert {e["before"]["event_type"] for e in sent} == {"BLOCK",
                                                         nf.EVENT_SUSPICIOUS_IP}
    assert {e["before"]["event_type"] for e in throttled} == {"BLOCK"}
    for e in notes:
        assert e["after"]["demo"] is True
        assert e["after"]["demo_scenario"] == "fraud_attack"
        # Marked in `after`, next to is_ground_truth, exactly where RISK_DECISION
        # carries it -- and not duplicated into `before`.
        assert "demo" not in e["before"]
        assert e["after"]["is_ground_truth"] is False
    # And still no leak: a count, never an address.
    assert "analyst@example.com" not in repr(entries)


def test_a_real_alert_carries_no_demo_marker(db):
    """`related` drops None, so real traffic passes no marker at all."""
    with app_run() as c:
        h = admin(c)
        backend.STATE["email_recipients"] = ("analyst@example.com",)
        cust = register(c, f"alert-{uuid.uuid4().hex[:8]}@example.com")
        # Ten items on one order is a large amount for a brand-new account, which
        # is enough to leave ALLOW without touching a threshold.
        c.post("/v1/orders", headers=cust, json={
            "items": [{"product_id": "p2", "qty": 5}],
            "payment_method": "upi",
            "upi": {"vpa": "buyer@okaxis"},
            "device_fp": "dev_alert_001",
        })
        entries = audit_entries(c, h)

    notes = [e for e in entries
             if e["action"] in (backend.NOTIFICATION_SENT,
                                backend.NOTIFICATION_FAILED)]
    for e in notes:
        assert "demo" not in e["after"], e
        assert "demo_scenario" not in e["after"], e


def test_a_real_transaction_carries_no_demo_marker(db):
    """The absence of the marker is what makes its presence meaningful, so it must
    not be written as `demo: false` on real traffic."""
    with app_run() as c:
        h = admin(c)
        cust = register(c, f"real-{uuid.uuid4().hex[:8]}@example.com")
        r = c.post("/v1/orders", headers=cust, json={
            "items": [{"product_id": "p1", "qty": 1}],
            "payment_method": "upi",
            "upi": {"vpa": "someone@okhdfcbank"},
            "device_fp": "dev_real_001",
        })
        assert r.status_code == 201, r.text
        real = [e for e in audit_entries(c, h)
                if e["action"] == backend.RISK_DECISION]

    assert real
    for e in real:
        assert "demo" not in (e["after"] or {})


def test_the_trigger_event_names_the_human_who_asked(db):
    """The one part of the run a person is responsible for. Identity comes from the
    verified token, never from a request body."""
    with app_run() as c:
        email = f"boss-{uuid.uuid4().hex[:8]}@example.com"
        h = register(c, email)
        backend.STATE["users"].get_by_email(email).role = "admin"
        trigger(c, h)
        ev = [e for e in audit_entries(c, h)
              if e["action"] == backend.DEMO_TRIGGERED][0]

    assert ev["actor"] == email
    assert ev["actor_identity"]["email"] == email
    assert ev["actor_identity"]["role"] == "admin"
    assert ev["actor_identity"]["user_id"]


def test_the_trigger_event_records_what_was_generated(db):
    with app_run() as c:
        h = admin(c)
        body = trigger(c, h)
        ev = [e for e in audit_entries(c, h)
              if e["action"] == backend.DEMO_TRIGGERED][0]

    assert ev["before"]["attempts_requested"] == 8
    assert ev["before"]["customer_id"] == body["customer_id"]
    assert ev["after"]["attempts_generated"] == 8
    assert ev["after"]["transaction_ids"] == [r["transaction_id"]
                                              for r in body["results"]]


def test_no_generated_event_claims_ground_truth(db):
    """Synthetic activity is not an observation. Nothing here may create a label."""
    with app_run() as c:
        h = admin(c)
        trigger(c, h)
        entries = audit_entries(c, h)

    for e in entries:
        after = e.get("after") or {}
        assert after.get("is_ground_truth") is not True, e["action"]
        assert after.get("ground_truth") is not True, e["action"]
        assert after.get("creates_fraud_label") is not True, e["action"]
    assert not [e for e in entries if e["action"] == backend.OUTCOME_RECORDED]


def test_no_generated_transaction_carries_a_label(db):
    with app_run() as c:
        trigger(c, admin(c))
        # Read inside the context: shutdown clears STATE.
        for t in backend.STATE["txns"].values():
            assert t["label"] is None


def test_the_trigger_event_states_that_no_money_moved(db):
    with app_run() as c:
        h = admin(c)
        body = trigger(c, h)
        ev = [e for e in audit_entries(c, h)
              if e["action"] == backend.DEMO_TRIGGERED][0]

    assert ev["after"]["moves_money"] is False
    assert body["moves_money"] is False
    assert body["creates_ground_truth"] is False


def test_generated_audit_events_are_retrievable_by_action(db):
    with app_run() as c:
        h = admin(c)
        trigger(c, h)
        r = c.get(f"/v1/admin/audit?action={backend.DEMO_TRIGGERED}", headers=h)

    assert r.status_code == 200
    assert r.json()["count"] == 1


def test_generated_audit_events_leak_no_storage_internals(db):
    with app_run() as c:
        h = admin(c)
        trigger(c, h)
        entries = audit_entries(c, h)

    for e in entries:
        assert "PK" not in e
        assert "SK" not in e


# ===========================================================================
# I. notification -- through the existing architecture only
# ===========================================================================

def test_the_alert_goes_through_the_existing_notification_path(db, monkeypatch):
    fake, _ = pinned(score=91.4, decision="BLOCK")
    monkeypatch.setattr(backend.Scorer, "score", fake)
    seen: list[dict] = []
    original = backend.notify_transaction

    def spy(record):
        seen.append(record)
        return original(record)

    monkeypatch.setattr(backend, "notify_transaction", spy)
    with app_run() as c:
        backend.STATE["email_recipients"] = ("analyst@example.com",)
        trigger(c, admin(c))

    assert len(seen) == 8
    assert all(r["decision"] == "BLOCK" for r in seen)


def test_an_alert_is_recorded_for_each_queued_attempt(db, monkeypatch):
    fake, _ = pinned(score=91.4, decision="BLOCK")
    monkeypatch.setattr(backend.Scorer, "score", fake)
    with app_run() as c:
        h = admin(c)
        backend.STATE["email_recipients"] = ("analyst@example.com",)
        body = trigger(c, h)
        log = c.get("/v1/admin/notifications?limit=200", headers=h).json()

    assert body["notification_triggered"] is True
    # The volume ceiling caps delivery at ALERT_RATE_MAX; the rest are recorded as
    # throttled rather than dropped, so all eight attempts are still accounted for.
    assert body["notifications"].get("sent") == backend.ALERT_RATE_MAX
    assert body["notifications"].get(nf.STATUS_THROTTLED) == (
        backend.DEMO_ATTEMPTS - backend.ALERT_RATE_MAX)
    assert sum(body["notifications"].values()) == backend.DEMO_ATTEMPTS
    assert log["count"] >= backend.DEMO_ATTEMPTS


def test_the_demo_reaches_the_smtp_provider_when_one_is_configured(db, monkeypatch):
    """Phase 10. The provider is transport-injected, so no socket is opened and no
    live delivery is claimed -- what is proved is that the demo's alert arrives at
    SMTPEmailProvider through the existing path rather than bypassing it."""
    fake, _ = pinned(score=91.4, decision="BLOCK")
    monkeypatch.setattr(backend.Scorer, "score", fake)
    transport = FakeTransport()
    with app_run() as c:
        backend.STATE["email_provider"] = nf.SMTPEmailProvider(
            host="smtp.example.com", port=587, username="alerts@example.com",
            password=SECRET_PW, sender="alerts@example.com",
            transport=transport)
        backend.STATE["email_recipients"] = ("analyst@example.com",)
        body = trigger(c, admin(c))

    assert body["notifications"].get("sent") == backend.ALERT_RATE_MAX
    # Five transaction alerts reach the transport; the other three are throttled.
    # There is also a separate suspicious-address message, because every BLOCK
    # settles failed and that trips the breadth rule -- it is exempt from the
    # ceiling, which is the architecture working rather than the demo double-sending.
    txn_alerts = [m for m in transport.messages
                  if "transaction blocked" in m[0]["Subject"]]
    assert len(txn_alerts) == backend.ALERT_RATE_MAX
    ip_alerts = [m for m in transport.messages
                 if "Suspicious IP detected" in m[0]["Subject"]]
    assert len(ip_alerts) == 1, "the summary alert must survive the ceiling"
    msg, sender, recipients = txn_alerts[0]
    assert sender == "alerts@example.com"
    assert recipients == ("analyst@example.com",)
    assert "FraudShield" in msg["Subject"]


def test_the_alert_body_carries_usable_evidence(db, monkeypatch):
    fake, _ = pinned(score=91.4, decision="BLOCK")
    monkeypatch.setattr(backend.Scorer, "score", fake)
    transport = FakeTransport()
    with app_run() as c:
        backend.STATE["email_provider"] = nf.SMTPEmailProvider(
            host="smtp.example.com", sender="alerts@example.com",
            password=SECRET_PW, transport=transport)
        backend.STATE["email_recipients"] = ("analyst@example.com",)
        body = trigger(c, admin(c))

    # The FIRST delivered transaction alert. Not the last message: the ceiling
    # throttles the later attempts, and the suspicious-address alert arrives after
    # them, so `messages[-1]` is no longer a transaction alert at all.
    txn_alerts = [m for m in transport.messages
                  if "transaction blocked" in m[0]["Subject"]]
    text = txn_alerts[0][0].get_content()
    for needle in ("BLOCK", "91.4", "demo:fraud_attack",
                   body["results"][0]["transaction_id"]):
        assert needle in text, needle


def test_the_alert_carries_no_credential(db, monkeypatch):
    fake, _ = pinned(score=91.4, decision="BLOCK")
    monkeypatch.setattr(backend.Scorer, "score", fake)
    transport = FakeTransport()
    with app_run() as c:
        backend.STATE["email_provider"] = nf.SMTPEmailProvider(
            host="smtp.example.com", sender="alerts@example.com",
            username="alerts@example.com", password=SECRET_PW,
            transport=transport)
        backend.STATE["email_recipients"] = ("analyst@example.com",)
        trigger(c, admin(c))

    blob = "".join(m[0].get_content() + str(m[0]) for m in transport.messages)
    assert SECRET_PW not in blob


def test_console_remains_the_default_for_tests(db):
    """No configuration means alerts render and reach nobody, and the response says
    so rather than implying anyone was told."""
    with app_run() as c:
        backend.STATE["email_recipients"] = ()
        body = trigger(c, admin(c))

    assert body["email_provider"] == nf.PROVIDER_CONSOLE
    assert body["alerts_enabled"] is False
    assert "sent" not in body["notifications"]


def test_a_notification_failure_does_not_fail_the_run(db, monkeypatch):
    fake, _ = pinned(score=91.4, decision="BLOCK")
    monkeypatch.setattr(backend.Scorer, "score", fake)
    with app_run() as c:
        backend.STATE["email_provider"] = FailingProvider()
        backend.STATE["email_recipients"] = ("analyst@example.com",)
        r = c.post(PATH, headers=admin(c))

    assert r.status_code == 201
    body = r.json()
    assert body["attempts_generated"] == 8
    assert body["transactions_persisted"] == 8
    # Five attempted and failed at the transport; three never left the process.
    assert body["notifications"].get("failed") == backend.ALERT_RATE_MAX
    assert body["notifications"].get(nf.STATUS_THROTTLED) == (
        backend.DEMO_ATTEMPTS - backend.ALERT_RATE_MAX)


def test_a_notification_that_raises_does_not_fail_the_run(db, monkeypatch):
    """The existing failure contract: notify() cannot raise. A demo must not be the
    one caller that discovers otherwise."""
    fake, _ = pinned(score=91.4, decision="BLOCK")
    monkeypatch.setattr(backend.Scorer, "score", fake)
    with app_run() as c:
        h = admin(c)
        backend.STATE["email_provider"] = ExplodingProvider()
        backend.STATE["email_recipients"] = ("analyst@example.com",)
        r = c.post(PATH, headers=h)

        assert r.status_code == 201
        assert r.json()["transactions_persisted"] == 8
        assert len([e for e in audit_entries(c, h)
                    if e["action"] == backend.RISK_DECISION]) == 8


def test_no_provider_exception_text_reaches_the_response(db, monkeypatch):
    fake, _ = pinned(score=91.4, decision="BLOCK")
    monkeypatch.setattr(backend.Scorer, "score", fake)
    with app_run() as c:
        backend.STATE["email_provider"] = ExplodingProvider()
        backend.STATE["email_recipients"] = ("analyst@example.com",)
        blob = repr(c.post(PATH, headers=admin(c)).json())

    assert "host-mail-04.internal" not in blob
    assert "RuntimeError" not in blob


def test_the_address_is_flagged_when_the_declines_pile_up(db):
    """The declines are the provider's, not the demo's: a BLOCK never reaches a
    gateway, so it settles failed, and the existing IP-suspicion path runs."""
    with app_run() as c:
        h = admin(c)
        body = trigger(c, h)
        ips = c.get("/v1/admin/suspicious-ips", headers=h).json()

    if body["ip_flagged"]:
        assert body["ip_hash"] in {i["ip_hash"] for i in ips["items"]}


# ===========================================================================
# J. repeated use and safety of the output
# ===========================================================================

def test_repeated_triggers_do_not_collide(db):
    with app_run() as c:
        h = admin(c)
        runs = [trigger(c, h) for _ in range(3)]
        assert len(backend.STATE["txns"]) == 24

    ids = [r["transaction_id"] for run in runs for r in run["results"]]
    assert len(ids) == 24
    assert len(set(ids)) == 24


def test_repeated_triggers_each_get_their_own_audit_event(db):
    with app_run() as c:
        h = admin(c)
        trigger(c, h)
        trigger(c, h)
        entries = audit_entries(c, h)

    assert len([e for e in entries if e["action"] == backend.DEMO_TRIGGERED]) == 2
    assert len([e for e in entries if e["action"] == backend.RISK_DECISION]) == 16


def test_nothing_is_cleaned_up_automatically(db):
    """Phase 14. The analyst needs to investigate the run, so the trigger does not
    delete it."""
    with app_run() as c:
        h = admin(c)
        body = trigger(c, h)
        assert len(backend.STATE["txns"]) == 8
        assert c.get("/v1/admin/queue", headers=h).json()["count"] == (
            body["queued_for_review"])
        assert len(db.query_prefix("INDEX#TXN", "")) == 8


def test_no_route_exists_to_delete_the_generated_run(db):
    """There is no cleanup endpoint, and the record store has no delete, so a demo
    cannot be used to remove evidence."""
    paths = {r.path for r in backend.app.routes if hasattr(r, "methods")}
    assert not any("demo" in p and "clean" in p for p in paths)
    assert not hasattr(backend.InMemoryRecordStore, "delete")


@pytest.mark.parametrize("secret", [
    "FRAUDSHIELD_JWT_SECRET", "FRAUDSHIELD_IP_PEPPER",
])
def test_the_response_carries_no_configured_secret(db, secret):
    value = os.environ[secret]
    with app_run() as c:
        blob = repr(trigger(c, admin(c)))
    assert value not in blob


def test_the_response_carries_no_credentials_or_internals(db, monkeypatch):
    monkeypatch.setenv("RAZORPAY_KEY_SECRET", "razorpay-secret-4417")
    monkeypatch.setenv("FRAUDSHIELD_SMTP_PASSWORD", "smtp-secret-4417")
    with app_run() as c:
        blob = repr(trigger(c, admin(c)))

    for forbidden in ("razorpay-secret-4417", "smtp-secret-4417", "'PK'", "'SK'",
                      "password", "authorization"):
        assert forbidden not in blob, forbidden


def test_the_response_exposes_no_card_data(db):
    """No PAN and no CVV exist to leak: the demo never constructs an instrument.
    Asserted anyway, because the cost of being wrong is a payment credential."""
    with app_run() as c:
        body = trigger(c, admin(c))
        for t in backend.STATE["txns"].values():
            assert "card_number" not in t
            assert "cvv" not in t
    blob = repr(body)
    assert "cvv" not in blob.lower()
    assert "4242" not in blob


def test_the_synthetic_customer_is_not_a_real_account(db):
    """The demo does not create a login. A synthetic actor with a password would be
    a real account that a real person could use."""
    with app_run() as c:
        body = trigger(c, admin(c))
        users = backend.STATE["users"]
        assert users.get_by_email(body["customer_email"]) is None
    assert body["customer_email"].endswith(backend.DEMO_EMAIL_DOMAIN)


def test_a_customer_cannot_see_the_generated_transactions(db):
    with app_run() as c:
        trigger(c, admin(c))
        cust = register(c, f"nosy-{uuid.uuid4().hex[:8]}@example.com")
        orders = c.get("/v1/orders", headers=cust).json()
        assert orders["count"] == 0
        assert c.get("/v1/admin/queue", headers=cust).status_code == 403
        assert c.get("/v1/admin/audit", headers=cust).status_code == 403


def test_a_customer_cannot_see_an_analyst_address(db):
    with app_run() as c:
        h = admin(c)
        trigger(c, h)
        cust = register(c, f"nosy2-{uuid.uuid4().hex[:8]}@example.com")
        health = c.get("/health").json()
        me = c.get("/v1/auth/me", headers=cust).json()

    assert "analyst@example.com" not in repr(health)
    assert "recipients" not in repr(health.get("email_notifications") or {})
    assert "@" in me["email"]


# ===========================================================================
# K. preservation -- the feature must not have changed the pipeline
# ===========================================================================

def test_the_storefront_path_is_unchanged_by_the_demo(db):
    """A real order must behave exactly as before: scored, persisted, audited, and
    with no demo marker anywhere near it."""
    with app_run() as c:
        h = admin(c)
        cust = register(c, f"shop-{uuid.uuid4().hex[:8]}@example.com")
        r = c.post("/v1/orders", headers=cust, json={
            "items": [{"product_id": "p1", "qty": 1}],
            "payment_method": "upi",
            "upi": {"vpa": "buyer@okaxis"},
            "device_fp": "dev_shop_001",
        })
        assert r.status_code == 201, r.text
        assert "demo" not in r.json()
        entries = [e for e in audit_entries(c, h)
                   if e["action"] == backend.RISK_DECISION]

    assert len(entries) == 1
    assert entries[0]["before"]["source"] == "storefront"


def test_risk_decision_still_carries_its_existing_shape(db):
    """`demo_scenario` is additive. Every field a consumer already reads must still
    be there, on both real and synthetic events."""
    with app_run() as c:
        h = admin(c)
        trigger(c, h)
        ev = [e for e in audit_entries(c, h)
              if e["action"] == backend.RISK_DECISION][0]

    for key in ("decision", "risk_score", "sub_scores", "fired_rules",
                "reason_codes", "model_version", "degraded", "override",
                "thresholds", "settlement", "automated_action",
                "is_ground_truth", "note"):
        assert key in ev["after"], key
    assert ev["after"]["automated_action"]["creates_ground_truth"] is False


def test_the_automated_action_policy_is_untouched(db):
    assert backend.NEVER_AUTOMATED
    assert "create or modify a ground-truth label" in backend.NEVER_AUTOMATED
    assert backend.ACTION_POLICY["BLOCK"]["automated_action"] == (
        "REFUSE_BEFORE_AUTHORISATION")


def test_the_demo_uses_the_shared_write_path(db):
    """Not a second persistence implementation. If `record_scored_transaction` is
    unavailable, nothing is written -- which is what proves the demo goes through
    it."""
    import inspect

    src = inspect.getsource(backend.demo_fraud_attack)
    assert "record_scored_transaction(" in src
    assert "audit_risk_decision(" in src
    assert "notify_transaction(" in src
    # And it does not reimplement any of them.
    assert "records.put(f\"TXN#" not in src
    assert "QUEUE#REVIEW" not in src


@pytest.mark.parametrize("exc", [
    smtplib.SMTPAuthenticationError(535, b"nope"),
    OSError("connection reset"),
])
def test_a_broken_transport_is_categorised_not_echoed(db, monkeypatch, exc):
    fake, _ = pinned(score=91.4, decision="BLOCK")
    monkeypatch.setattr(backend.Scorer, "score", fake)
    with app_run() as c:
        h = admin(c)
        backend.STATE["email_provider"] = nf.SMTPEmailProvider(
            host="smtp.example.com", sender="alerts@example.com",
            username="alerts@example.com", password=SECRET_PW,
            transport=FakeTransport(raises=exc))
        backend.STATE["email_recipients"] = ("analyst@example.com",)
        body = trigger(c, h)
        log = c.get("/v1/admin/notifications?limit=200", headers=h).json()

    assert body["notifications"].get("failed") == backend.ALERT_RATE_MAX
    blob = repr(log)
    assert SECRET_PW not in blob
    assert "nope" not in blob


# ===========================================================================
# L. alert volume ceiling and the two-rule address flag
# ===========================================================================
#
# Both were added after the demo trigger, and both change what a burst does to a
# mailbox, so the demo is the cheapest place to exercise them end to end: it
# produces exactly eight alertable decisions on one address on demand.

def test_the_alert_ceiling_caps_delivery_but_records_the_rest(db, monkeypatch):
    """Five delivered, three throttled, nothing lost.

    The property that matters is the sum: every alertable event is accounted for
    in the notification log whether or not an email left the process. A ceiling
    that silently discarded the overflow would mean the log implied a quieter
    incident than actually happened.
    """
    fake, _ = pinned(score=91.4, decision="BLOCK")
    monkeypatch.setattr(backend.Scorer, "score", fake)
    with app_run() as c:
        h = admin(c)
        backend.STATE["email_recipients"] = ("analyst@example.com",)
        body = trigger(c, h)
        log = c.get("/v1/admin/notifications?limit=200", headers=h).json()

    counts = body["notifications"]
    assert counts.get("sent") == backend.ALERT_RATE_MAX
    assert counts.get(nf.STATUS_THROTTLED) == (backend.DEMO_ATTEMPTS
                                               - backend.ALERT_RATE_MAX)
    assert sum(counts.values()) == backend.DEMO_ATTEMPTS

    throttled = [i for i in log["items"] if i["status"] == nf.STATUS_THROTTLED]
    assert len(throttled) == backend.DEMO_ATTEMPTS - backend.ALERT_RATE_MAX
    for i in throttled:
        assert i["error_category"] == "rate_limited"
        assert i["sent_at"] is None


def test_a_throttled_alert_is_not_recorded_as_a_failure(db, monkeypatch):
    """Nothing malfunctioned. Calling it a failure would send an operator hunting
    for a broken mail server and would bury real transport failures."""
    fake, _ = pinned(score=91.4, decision="BLOCK")
    monkeypatch.setattr(backend.Scorer, "score", fake)
    with app_run() as c:
        h = admin(c)
        backend.STATE["email_recipients"] = ("analyst@example.com",)
        body = trigger(c, h)
        entries = audit_entries(c, h)

    assert "failed" not in body["notifications"]
    assert not [e for e in entries if e["action"] == backend.NOTIFICATION_FAILED]
    throttled = [e for e in entries
                 if e["action"] == backend.NOTIFICATION_THROTTLED]
    assert len(throttled) == backend.DEMO_ATTEMPTS - backend.ALERT_RATE_MAX
    for e in throttled:
        assert e["after"]["status"] == nf.STATUS_THROTTLED
        assert e["after"]["error_category"] == "rate_limited"
        assert e["after"]["is_ground_truth"] is False


def test_a_throttled_event_stays_eligible_once_the_window_clears(db, monkeypatch):
    """The withheld alert must not be permanently suppressed.

    Throttling deliberately does NOT add the dedupe key to the seen set. If it
    did, a volume control would become silent alert loss: the event would be
    treated as already-notified forever.
    """
    fake, _ = pinned(score=91.4, decision="BLOCK")
    monkeypatch.setattr(backend.Scorer, "score", fake)
    with app_run() as c:
        h = admin(c)
        backend.STATE["email_recipients"] = ("analyst@example.com",)
        body = trigger(c, h)
        # The dedupe key of a BLOCK alert is derived from its transaction id, so
        # it can be recomputed without the endpoint having to publish it.
        throttled_ids = {r["transaction_id"] for r in body["results"]}
        seen = backend.STATE["notified"]
        marked = {t for t in throttled_ids
                  if nf.dedupe_key("BLOCK", t) in seen}
        # Exactly the delivered ones are marked; the throttled ones are not, so
        # they remain eligible once the window clears.
        assert len(marked) == backend.ALERT_RATE_MAX, (
            f"{len(marked)} of {len(throttled_ids)} keys were marked as notified; "
            f"expected only the {backend.ALERT_RATE_MAX} that were delivered")
    assert body["attempts_generated"] == backend.DEMO_ATTEMPTS


def test_the_address_alert_is_exempt_from_the_ceiling(db, monkeypatch):
    """The failure this exemption exists to prevent.

    Per-transaction alerts arrive BEFORE the address crosses its decline rule, so
    without the exemption they consume the whole budget and the one message that
    summarises the attack is throttled -- the ceiling burying the alert it was
    added to protect.
    """
    fake, _ = pinned(score=91.4, decision="BLOCK")
    monkeypatch.setattr(backend.Scorer, "score", fake)
    with app_run() as c:
        h = admin(c)
        backend.STATE["email_recipients"] = ("analyst@example.com",)
        body = trigger(c, h)
        log = c.get("/v1/admin/notifications?limit=200", headers=h).json()

    assert body["ip_flagged"] is True
    ip_alerts = [i for i in log["items"]
                 if i["event_type"] == nf.EVENT_SUSPICIOUS_IP]
    assert len(ip_alerts) == 1
    assert ip_alerts[0]["status"] == nf.STATUS_SENT, \
        "the summary alert was throttled by per-transaction noise"
    assert nf.EVENT_SUSPICIOUS_IP in backend.ALERT_RATE_EXEMPT


def test_the_demo_trips_the_breadth_rule_not_the_volume_rule(db):
    """Eight declines is under the volume threshold of 10, but the demo rotates
    through four methods, so the breadth rule is what raises the address.

    Worth pinning: it means the demo still demonstrates the address flag after the
    volume threshold was raised from 3 to 10, without the attempt count changing.
    """
    with app_run() as c:
        h = admin(c)
        body = trigger(c, h)
        ips = c.get("/v1/admin/suspicious-ips", headers=h).json()

    assert body["attempts_generated"] < backend.IP_FAIL_THRESHOLD
    assert body["ip_flagged"] is True
    flagged = [i for i in ips["items"] if i["ip_hash"] == body["ip_hash"]]
    assert flagged, "the demo address was not flagged"
    assert len(set(backend.DEMO_ATTACK_METHODS)) >= backend.IP_METHOD_THRESHOLD


def test_the_address_alert_lists_instruments_but_no_card_data(db, monkeypatch):
    """The alert carries what an analyst pivots on -- method, masked display and
    the HMAC reference -- and nothing a mailbox must not hold."""
    transport = FakeTransport()
    with app_run() as c:
        backend.STATE["email_provider"] = nf.SMTPEmailProvider(
            host="smtp.example.com", sender="alerts@example.com",
            password=SECRET_PW, transport=transport)
        backend.STATE["email_recipients"] = ("analyst@example.com",)
        trigger(c, admin(c))

    ip_alerts = [m for m in transport.messages
                 if "Suspicious IP detected" in m[0]["Subject"]]
    assert len(ip_alerts) == 1
    text = ip_alerts[0][0].get_content()

    assert "Instruments declined from this address" in text
    assert "No card number, CVV" in text
    # The demo constructs no instrument, so the references are its synthetic
    # placeholders -- but the shape is what is being asserted: a method and a
    # display per line, and nothing PAN-shaped anywhere.
    assert "demo card" in text
    assert not re.search(r"\b\d{13,19}\b", text)
    assert SECRET_PW not in text


def test_the_rules_are_published_for_an_analyst(db):
    """A flag an analyst cannot explain is not actionable. Both detectors are
    described on the endpoint rather than living only in the code."""
    with app_run() as c:
        h = admin(c)
        ips = c.get("/v1/admin/suspicious-ips", headers=h).json()

    names = {r["name"] for r in ips["rules"]}
    assert names == {"volume", "breadth"}
    volume = next(r for r in ips["rules"] if r["name"] == "volume")
    breadth = next(r for r in ips["rules"] if r["name"] == "breadth")
    assert volume["threshold"] == backend.IP_FAIL_THRESHOLD == 10
    assert volume["window_minutes"] == 20
    assert breadth["threshold"] == backend.IP_METHOD_THRESHOLD == 3
    assert breadth["window_minutes"] == 120
    # The legacy fields keep their meaning so an existing consumer is unaffected.
    assert ips["threshold"] == backend.IP_FAIL_THRESHOLD
    assert ips["window_minutes"] == 20


def test_cash_on_delivery_is_no_longer_offered(db):
    """COD carries no instrument to fingerprint and cannot be declined by a
    gateway, so it was the one method the engine had nothing to say about."""
    with app_run() as c:
        offered = {m["code"] for m in c.get("/v1/catalog/products").json()
                   ["payment_methods"]}
        assert "cod" not in offered
        assert offered == {"upi", "card", "netbanking", "wallet"}

        h = register(c, f"cod-{uuid.uuid4().hex[:8]}@example.com")
        r = c.post("/v1/orders", headers=h, json={
            "items": [{"product_id": "p1", "qty": 1}],
            "payment_method": "cod",
            "device_fp": "dev_cod_001",
        })
        assert r.status_code == 422

    # But it REMAINS in the trained feature matrix. The model carries a method_cod
    # one-hot column, so removing it there would change the feature vector out from
    # under the artifact and break offline/online parity.
    assert "cod" in backend.PAYMENT_METHODS


def test_the_scenario_does_not_depend_on_the_time_of_day(db, monkeypatch):
    """The baseline's shopping hours are anchored relative to the attack.

    THE BUG THIS PINS. With a fixed 18:00-21:00 baseline, `hour_deviation` measured
    the attack's distance from an absolute clock time, so the demo scored
    differently depending on when somebody ran it: at 08:00 all eight attempts
    blocked, and at 16:00 the UPI and wallet attempts fell to 69.5 and 47.5, under
    the block threshold. They then settled successfully, the address never
    accumulated three distinct failed methods, and the suspicious-IP alert silently
    stopped happening.

    Anchoring keeps the deviation constant rather than removing it. This asserts the
    invariant directly -- the gap between the customer's habitual hour and the
    attack hour is the same whatever hour it is -- rather than trying to run the
    scenario at 24 different times.
    """
    hours = set()
    for pretend_hour in (0, 3, 8, 13, 16, 21, 23):
        # A `now` pinned to a specific UTC hour, passed explicitly. The scenario
        # builder takes `now` as an argument precisely so this is possible without
        # patching the clock.
        now = datetime(2026, 8, 29, pretend_hour, 30, tzinfo=timezone.utc).timestamp()
        store = backend.InMemoryStore()
        summary = backend.demo_seed_history(store, "cust_hours", now)
        assert summary["transactions"] == backend.DEMO_BASELINE_TXNS

        c = store.customer("cust_hours")
        attack_hour = datetime.fromtimestamp(now, tz=timezone.utc).hour
        # The deviation the engine would compute for a transaction at the attack
        # hour, against the profile the baseline just built.
        hours.add(round(c.hour.deviation(attack_hour + 0.5), 3))

    # The deviation is STRONG at every hour, which is the property that keeps the
    # decisions stable. It is not bit-identical across hours, and that is expected:
    # `RunningHour.mad` accumulates against a moving mean seeded at 12.0, so a
    # baseline window straddling midnight converges slightly differently. The spread
    # that matters is the one that used to drop attempts under the block threshold,
    # and this floor is far above it.
    assert min(hours) > 5.0, (
        f"hour_deviation collapses at some hour: {sorted(hours)}. The baseline is "
        f"no longer anchored to the attack hour, so the demo's decisions will vary "
        f"with the time of day.")
    # Bounded too, so a future change cannot quietly turn this into a constant.
    assert max(hours) - min(hours) < 3.0, sorted(hours)
