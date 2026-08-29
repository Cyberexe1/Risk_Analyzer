"""Durable threshold configuration tests.

THE BUG THIS SUITE PINS DOWN
----------------------------
A threshold change used to live only on the Scorer instance. `PUT
/v1/admin/thresholds` validated it, applied it, audited it -- and the next restart
threw it away. The audit trail then insisted an admin had tightened the block gate
while the running service was back on the default. The log and the behaviour
disagreed, which is worse than having no control at all.

    change threshold -> restart -> SAME threshold

HOW "RESTART" IS SIMULATED
--------------------------
A shared record store plays the database; entering and leaving a TestClient
context plays one application run. lifespan clears STATE, so anything that
survives was genuinely persisted and reloaded.

WHAT IS DELIBERATELY NOT TESTED HERE
------------------------------------
Re-scoring. Restoring a threshold must NOT re-decide stored transactions, and the
existing persistence suites already assert that reloading emits no RISK_DECISION.
This suite asserts the configuration half.

Run:  python -m pytest tests/test_threshold_persistence.py -v
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
os.environ["FRAUDSHIELD_JWT_SECRET"] = "test-only-jwt-secret-thresholds"
os.environ["FRAUDSHIELD_IP_PEPPER"] = "test-only-pepper-thresholds"
os.environ.pop("FRAUDSHIELD_API_KEY", None)

from fastapi.testclient import TestClient  # noqa: E402

import backend  # noqa: E402

PW = "threshold-persistence-password-5194"
PATH = "/v1/admin/thresholds"


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


@pytest.fixture(autouse=True)
def _restore_scorer_defaults():
    """The Scorer is rebuilt per lifespan, but DEFAULT_* are module constants and
    a test that leaves them moved would poison the next one."""
    review, block = backend.DEFAULT_REVIEW_T, backend.DEFAULT_BLOCK_T
    yield
    backend.DEFAULT_REVIEW_T, backend.DEFAULT_BLOCK_T = review, block


@contextmanager
def app_run():
    with TestClient(backend.app) as c:
        yield c


def register(c, email: str) -> dict:
    r = c.post("/v1/auth/register", json={"email": email, "password": PW})
    assert r.status_code == 201, r.text
    return {"authorization": f"Bearer {r.json()['access_token']}"}


def staff(c, tag: str, role: str = "admin") -> tuple[dict, str]:
    email = f"{tag}-{uuid.uuid4().hex[:8]}@example.com"
    h = register(c, email)
    backend.STATE["users"].get_by_email(email).role = role
    return h, email


def live() -> tuple[float, float]:
    s = backend.STATE["scorer"]
    return s.review_t, s.block_t


def config_item(db) -> dict | None:
    return db.get(backend.CONFIG_PK, backend.CONFIG_SK_THRESHOLDS)


# ===========================================================================
# validator -- one rule, shared by the endpoint and the startup loader
# ===========================================================================

def test_valid_pairs_are_accepted():
    assert backend.validate_thresholds(5, 70) == (5.0, 70.0)
    assert backend.validate_thresholds(0, 100) == (0.0, 100.0)
    assert backend.validate_thresholds("12", "88") == (12.0, 88.0)


@pytest.mark.parametrize("review,block", [
    (70, 5),          # inverted
    (50, 50),         # equal: no MANUAL_REVIEW band would exist at all
    (-1, 70),
    (5, 101),
    (5, -5),
    (float("nan"), 70),
    (5, float("nan")),
    (None, 70),
    ("abc", 70),
])
def test_invalid_pairs_are_rejected(review, block):
    with pytest.raises(ValueError):
        backend.validate_thresholds(review, block)


def test_equal_thresholds_are_rejected_with_a_stated_reason():
    """review == block would delete the human-review band silently."""
    with pytest.raises(ValueError, match="must be below"):
        backend.validate_thresholds(40, 40)


# ===========================================================================
# the core invariant: change, restart, still changed
# ===========================================================================

def test_threshold_change_survives_restart(db):
    with app_run() as c:
        h, email = staff(c, "surv")
        r = c.put(PATH, headers=h, json={"review": 12, "block": 88})
        assert r.status_code == 200, r.text
        assert r.json()["current"] == {"review": 12.0, "block": 88.0}
        assert live() == (12.0, 88.0)

    assert backend.STATE == {}, "STATE must be wiped between runs"

    with app_run() as c:
        assert live() == (12.0, 88.0), "threshold reset after restart"
        h, _ = staff(c, "surv2")
        got = c.get(PATH, headers=h).json()
        assert got["current"] == {"review": 12.0, "block": 88.0}
        assert got["source"] == "persisted"
        assert got["config"]["updated_by"] == email
        assert got["config"]["degraded"] is False


def test_repeated_changes_survive_and_version_increments(db):
    with app_run() as c:
        h, _ = staff(c, "ver")
        assert c.put(PATH, headers=h,
                     json={"review": 8, "block": 80}).json()["version"] == 1
        assert c.put(PATH, headers=h,
                     json={"review": 9, "block": 81}).json()["version"] == 2
        assert c.put(PATH, headers=h,
                     json={"review": 10, "block": 82}).json()["version"] == 3

    with app_run():
        assert live() == (10.0, 82.0)
        assert config_item(db)["version"] == 3


def test_stored_item_shape(db):
    with app_run() as c:
        h, email = staff(c, "shape")
        c.put(PATH, headers=h, json={"review": 15, "block": 75,
                                     "reason": "two analysts on leave"})

    item = config_item(db)
    assert item["review_threshold"] == 15.0
    assert item["block_threshold"] == 75.0
    assert item["updated_by"] == email
    assert item["updated_at"].endswith("+00:00")
    assert item["version"] == 1
    assert item["reason"] == "two analysts on leave"


def test_thresholds_the_scorer_actually_uses_are_the_restored_ones(db):
    """Not just reported -- routing must genuinely use them."""
    with app_run() as c:
        h, _ = staff(c, "use")
        c.put(PATH, headers=h, json={"review": 1, "block": 2})

    with app_run():
        s = backend.STATE["scorer"]
        assert s.review_t == 1.0 and s.block_t == 2.0
        # The band arithmetic in Scorer._route reads these attributes directly, so
        # asserting the attributes is asserting the behaviour.
        assert s.block_t > s.review_t


# ===========================================================================
# fallback to environment defaults
# ===========================================================================

def test_no_persisted_config_uses_env_defaults(db):
    with app_run() as c:
        assert live() == (backend.DEFAULT_REVIEW_T, backend.DEFAULT_BLOCK_T)
        cfg = backend.STATE["threshold_config"]
        assert cfg["source"] == "env"
        assert cfg["degraded"] is False
        assert config_item(db) is None
        h, _ = staff(c, "envdef")
        assert c.get(PATH, headers=h).json()["source"] == "env"


def test_existing_defaults_are_unchanged(db):
    """This task must not silently move the shipped operating point."""
    assert backend.DEFAULT_REVIEW_T == 5.0
    assert backend.DEFAULT_BLOCK_T == 70.0
    with app_run():
        assert live() == (5.0, 70.0)


@pytest.mark.parametrize("bad", [
    {"review_threshold": 90, "block_threshold": 10, "version": 4},
    {"review_threshold": 50, "block_threshold": 50, "version": 4},
    {"review_threshold": -3, "block_threshold": 70, "version": 4},
    {"review_threshold": 5, "block_threshold": 400, "version": 4},
    {"review_threshold": "nonsense", "block_threshold": 70, "version": 4},
    {"review_threshold": None, "block_threshold": None, "version": 4},
    {"version": 4},
])
def test_invalid_persisted_config_falls_back_safely(db, bad):
    """One bad write must not become a total outage, and must not be applied."""
    db.put(backend.CONFIG_PK, backend.CONFIG_SK_THRESHOLDS, bad)

    with app_run() as c:
        assert live() == (5.0, 70.0), "invalid stored config was applied"
        cfg = backend.STATE["threshold_config"]
        assert cfg["degraded"] is True
        assert cfg["source"] == "env"
        assert "IGNORED" in cfg["note"]
        # And the service is genuinely serving.
        assert c.get("/health").status_code == 200


def test_degraded_config_is_reported_on_health(db):
    db.put(backend.CONFIG_PK, backend.CONFIG_SK_THRESHOLDS,
           {"review_threshold": 99, "block_threshold": 1, "version": 7})

    with app_run() as c:
        h = c.get("/health").json()

    assert h["threshold_config"]["degraded"] is True
    assert h["threshold_config"]["source"] == "env"
    assert h["thresholds"] == {"review": 5.0, "block": 70.0}
    assert h["threshold_config"]["rejected"]["version"] == 7


def test_degraded_config_warns_at_startup(db, capsys):
    db.put(backend.CONFIG_PK, backend.CONFIG_SK_THRESHOLDS,
           {"review_threshold": 99, "block_threshold": 1})
    with app_run():
        pass
    assert "THRESHOLD CONFIGURATION DEGRADED" in capsys.readouterr().out


def test_unreadable_store_does_not_prevent_startup(db, monkeypatch):
    original = backend.InMemoryRecordStore.get

    def flaky(self, pk, sk):
        if pk == backend.CONFIG_PK:
            raise RuntimeError("simulated store failure")
        return original(self, pk, sk)

    monkeypatch.setattr(backend.InMemoryRecordStore, "get", flaky)
    with app_run() as c:
        assert live() == (5.0, 70.0)
        assert backend.STATE["threshold_config"]["degraded"] is True
        assert c.get("/health").status_code == 200


def test_a_failed_persist_leaves_the_running_thresholds_alone(db, monkeypatch):
    """Persist first, apply second. Otherwise the process and the table drift."""
    with app_run() as c:
        h, _ = staff(c, "failput")

        def boom(self, pk, sk, item):
            raise RuntimeError("simulated write failure")

        monkeypatch.setattr(backend.InMemoryRecordStore, "put", boom)
        r = c.put(PATH, headers=h, json={"review": 33, "block": 99})
        assert r.status_code == 503
        assert live() == (5.0, 70.0), "thresholds moved despite a failed write"


# ===========================================================================
# authorisation -- unchanged, and re-asserted because this is now durable
# ===========================================================================

def test_admin_can_modify(db):
    with app_run() as c:
        h, _ = staff(c, "adm", role="admin")
        assert c.put(PATH, headers=h,
                     json={"review": 6, "block": 71}).status_code == 200


def test_analyst_cannot_modify(db):
    """An analyst decides individual cases. Moving a threshold changes every future
    decision -- different blast radius, different permission. Now that the change
    is durable, an analyst-authored one would outlive the process too."""
    with app_run() as c:
        h, _ = staff(c, "an", role="analyst")
        assert c.put(PATH, headers=h,
                     json={"review": 6, "block": 71}).status_code == 403
        assert live() == (5.0, 70.0)
        assert config_item(db) is None


def test_customer_cannot_modify_or_read(db):
    with app_run() as c:
        h = register(c, f"cust-{uuid.uuid4().hex[:8]}@example.com")
        assert c.put(PATH, headers=h,
                     json={"review": 6, "block": 71}).status_code == 403
        assert c.get(PATH, headers=h).status_code == 403
        assert config_item(db) is None


def test_anonymous_cannot_modify(db):
    with app_run() as c:
        assert c.put(PATH, json={"review": 6,
                                 "block": 71}).status_code in (401, 403)
        assert config_item(db) is None


def test_analyst_may_read_the_current_configuration(db):
    """Read stays analyst-visible: the cost curve is how an analyst understands
    their own queue. Only the write is admin-only."""
    with app_run() as c:
        h, _ = staff(c, "anread", role="analyst")
        assert c.get(PATH, headers=h).status_code == 200


# ===========================================================================
# rejected updates
# ===========================================================================

@pytest.mark.parametrize("body", [
    {"review": 80, "block": 20},
    {"review": 50, "block": 50},
    {"review": 5, "block": 101},
    {"review": -1, "block": 70},
])
def test_invalid_update_is_rejected_and_persists_nothing(db, body):
    with app_run() as c:
        h, _ = staff(c, "rej")
        assert c.put(PATH, headers=h, json=body).status_code == 422
        assert live() == (5.0, 70.0)
        assert config_item(db) is None


def test_rejected_update_does_not_emit_an_audit_event(db):
    with app_run() as c:
        h, _ = staff(c, "rejaud")
        c.put(PATH, headers=h, json={"review": 80, "block": 20})
        events = [e for e in backend.STATE["audit"]
                  if e["action"] == backend.THRESHOLD_UPDATE]
    assert events == []


# ===========================================================================
# audit
# ===========================================================================

def test_update_emits_exactly_one_audit_event_with_before_after_actor(db):
    with app_run() as c:
        h, email = staff(c, "aud")
        c.put(PATH, headers=h, json={"review": 20, "block": 60,
                                     "reason": "queue backlog"})
        events = [e for e in backend.STATE["audit"]
                  if e["action"] == backend.THRESHOLD_UPDATE]

    assert len(events) == 1
    ev = events[0]
    assert ev["actor"] == email
    assert ev["at"].endswith("+00:00")
    assert ev["before"]["review"] == 5.0 and ev["before"]["block"] == 70.0
    assert ev["after"]["review"] == 20.0 and ev["after"]["block"] == 60.0
    assert ev["after"]["reason"] == "queue backlog"
    assert ev["after"]["persisted"] is True


def test_audit_action_name_is_stable_for_historical_records(db):
    """Renaming this event type would orphan every persisted record: a filter for
    the new name would return nothing for past changes."""
    assert backend.THRESHOLD_UPDATE == "threshold_update"
    with app_run() as c:
        h, _ = staff(c, "stable")
        c.put(PATH, headers=h, json={"review": 7, "block": 77})
        got = c.get(f"/v1/admin/audit?action={backend.THRESHOLD_UPDATE}",
                    headers=h).json()
        assert got["count"] == 1


def test_threshold_history_survives_restart_alongside_the_value(db):
    with app_run() as c:
        h, email = staff(c, "hist")
        c.put(PATH, headers=h, json={"review": 11, "block": 66})

    with app_run() as c:
        h, _ = staff(c, "hist2")
        got = c.get(f"/v1/admin/audit?action={backend.THRESHOLD_UPDATE}",
                    headers=h).json()
        assert got["count"] == 1
        assert got["entries"][0]["actor"] == email
        assert live() == (11.0, 66.0)


def test_reason_is_optional_and_absent_reads_as_null(db):
    with app_run() as c:
        h, _ = staff(c, "noreason")
        c.put(PATH, headers=h, json={"review": 4, "block": 44})
        ev = [e for e in backend.STATE["audit"]
              if e["action"] == backend.THRESHOLD_UPDATE][0]
    assert ev["after"]["reason"] is None
    assert config_item(db)["reason"] is None


def test_audit_event_carries_no_secret_material(db):
    with app_run() as c:
        h, _ = staff(c, "nosecret")
        c.put(PATH, headers=h, json={"review": 4, "block": 44})
        ev = [e for e in backend.STATE["audit"]
              if e["action"] == backend.THRESHOLD_UPDATE][0]

    blob = repr(ev)
    for secret in (backend.IP_PEPPER, os.environ["FRAUDSHIELD_JWT_SECRET"], PW):
        assert secret not in blob
