"""Entity graph + velocity counter restart durability.

THE INVARIANT UNDER TEST
------------------------
    same historical transactions
  + same new transaction at the same timestamp
  + same model and configuration
  = same features, same ML / rules / network sub-scores, same final score,
    same decision, same reason codes

A restart must not weaken FraudShield's memory. Before this work the transaction
RECORDS were durable but their EFFECT on state was not, so after a restart an
established customer scored like a brand-new one.

HOW "RESTART" IS SIMULATED
--------------------------
A shared record store plays the database; entering/leaving a TestClient context
plays an application run. lifespan clears STATE, so anything that survives did so
because it was persisted and replayed.

Scoring is driven through POST /v1/risk/score, which takes an explicit `ts`. That
is what makes an exact before/after comparison possible: the same transaction can
be scored at the same instant in both runs.

No AWS credentials required.

Run:  python -m pytest tests/test_entity_rehydration.py -v
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
os.environ["FRAUDSHIELD_JWT_SECRET"] = "test-only-jwt-secret-entity-rehydration"
os.environ["FRAUDSHIELD_IP_PEPPER"] = "test-only-pepper-entity-rehydration"
os.environ.pop("FRAUDSHIELD_API_KEY", None)

from fastapi.testclient import TestClient  # noqa: E402

import backend  # noqa: E402

# A fixed clock. Every timestamp below is an offset from this, so windows are
# deterministic instead of depending on when the suite runs.
T0 = 1800000000.0          # 2027-01-15T08:00:00Z, arbitrary but fixed
MIN = 60.0
HOUR = 3600.0


@pytest.fixture(autouse=True)
def _open_service_key(monkeypatch):
    """Run the service scoring endpoint in open mode for these tests.

    `API_KEY` is read at import, and the .env loader supplies a value on a
    configured machine, so popping the env var before importing backend is not
    enough. Patching the module attribute is test-local and leaves the production
    guard untouched -- require_key still enforces the key whenever one is set.
    """
    monkeypatch.setattr(backend, "API_KEY", "")


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


def score(c, *, customer, ts, amount=5000.0, device="dev_x", ip="ip_x",
          method="card", status="success", commit=True):
    """Score through the service endpoint, which accepts an explicit timestamp."""
    r = c.post("/v1/risk/score", json={
        "customer_id": customer, "amount": amount, "payment_method": method,
        "device_fp": device, "ip_hash": ip, "ts": ts, "status": status,
        "commit": commit,
    })
    assert r.status_code == 200, r.text
    return r.json()


def features_of(c, txn_id: str) -> dict:
    """The 22 raw features recorded for a scored transaction."""
    return backend.STATE["txns"][txn_id]["features"]


def graph_info() -> dict:
    return backend.STATE["graph_rehydration"]


# ===========================================================================
# A. velocity windows
# ===========================================================================

def test_velocity_counters_are_reconstructed(db):
    cid = "cust_velocity"
    with app_run() as c:
        # Three inside 10 minutes, two more inside the hour, one well outside.
        score(c, customer=cid, ts=T0 - 2 * HOUR, device="dev_v", ip="ip_v")
        score(c, customer=cid, ts=T0 - 40 * MIN, device="dev_v", ip="ip_v")
        score(c, customer=cid, ts=T0 - 20 * MIN, device="dev_v", ip="ip_v")
        score(c, customer=cid, ts=T0 - 9 * MIN, device="dev_v", ip="ip_v")
        score(c, customer=cid, ts=T0 - 5 * MIN, device="dev_v", ip="ip_v")
        probe = score(c, customer=cid, ts=T0, device="dev_v", ip="ip_v",
                      commit=False)
        before = features_of(c, probe["transaction_id"])

    with app_run() as c:
        probe = score(c, customer=cid, ts=T0, device="dev_v", ip="ip_v",
                      commit=False)
        after = features_of(c, probe["transaction_id"])

    assert before["txn_count_10m"] == after["txn_count_10m"] == 2
    assert before["txn_count_1h"] == after["txn_count_1h"] == 4


def test_failed_counters_are_reconstructed(db):
    cid = "cust_fails"
    with app_run() as c:
        score(c, customer=cid, ts=T0 - 50 * MIN, status="failed",
              device="dev_f", ip="ip_f")
        score(c, customer=cid, ts=T0 - 8 * MIN, status="failed",
              device="dev_f", ip="ip_f")
        score(c, customer=cid, ts=T0 - 3 * MIN, status="failed",
              device="dev_f", ip="ip_f")
        p = score(c, customer=cid, ts=T0, device="dev_f", ip="ip_f", commit=False)
        before = features_of(c, p["transaction_id"])

    with app_run() as c:
        p = score(c, customer=cid, ts=T0, device="dev_f", ip="ip_f", commit=False)
        after = features_of(c, p["transaction_id"])

    assert before["failed_count_10m"] == after["failed_count_10m"] == 2
    assert before["failed_count_1h"] == after["failed_count_1h"] == 3


def test_old_transactions_are_excluded_from_active_windows(db):
    cid = "cust_old"
    with app_run() as c:
        for i in range(5):
            score(c, customer=cid, ts=T0 - (10 + i) * HOUR,
                  device="dev_o", ip="ip_o")

    with app_run() as c:
        p = score(c, customer=cid, ts=T0, device="dev_o", ip="ip_o", commit=False)
        f = features_of(c, p["transaction_id"])
    assert f["txn_count_10m"] == 0
    assert f["txn_count_1h"] == 0
    # But the long-horizon history is still there.
    assert f["prev_txn_count"] == 5


def test_window_boundary_semantics_are_preserved(db):
    """_count uses `now - t <= window`, so a transaction exactly 600s old counts.
    Reconstruction must reproduce that inclusive boundary, not approximate it."""
    cid = "cust_boundary"
    with app_run() as c:
        score(c, customer=cid, ts=T0 - 600.0, device="dev_b", ip="ip_b")  # exactly 10m
        score(c, customer=cid, ts=T0 - 601.0, device="dev_b", ip="ip_b")  # just outside
        p = score(c, customer=cid, ts=T0, device="dev_b", ip="ip_b", commit=False)
        before = features_of(c, p["transaction_id"])

    with app_run() as c:
        p = score(c, customer=cid, ts=T0, device="dev_b", ip="ip_b", commit=False)
        after = features_of(c, p["transaction_id"])

    assert before["txn_count_10m"] == after["txn_count_10m"] == 1
    assert after["txn_count_1h"] == 2


# ===========================================================================
# B. customer history
# ===========================================================================

def test_customer_history_survives_restart(db):
    cid = "cust_history"
    with app_run() as c:
        for i, amt in enumerate([1000.0, 2000.0, 3000.0, 4000.0]):
            score(c, customer=cid, ts=T0 - (10 - i) * HOUR, amount=amt,
                  device="dev_h", ip="ip_h", method="upi",
                  status="failed" if i == 0 else "success")
        p = score(c, customer=cid, ts=T0, amount=2500.0, device="dev_h",
                  ip="ip_h", method="upi", commit=False)
        before = features_of(c, p["transaction_id"])

    with app_run() as c:
        p = score(c, customer=cid, ts=T0, amount=2500.0, device="dev_h",
                  ip="ip_h", method="upi", commit=False)
        after = features_of(c, p["transaction_id"])

    for f in ("prev_txn_count", "customer_avg_amount", "historical_failure_rate",
              "seconds_since_last_txn", "amount_ratio", "is_new_payment_method",
              "hour_deviation"):
        assert before[f] == after[f], f"{f} changed across restart"
    assert after["prev_txn_count"] == 4
    assert after["customer_avg_amount"] == 2500.0
    assert after["is_new_payment_method"] == 0


def test_trusted_floor_survives_restart(db):
    """The override needs prev_txn_count > 50 and an account older than 180 days,
    so it is the feature most sensitive to a truncated replay."""
    cid = "cust_trusted"
    old = T0 - 400 * 24 * HOUR
    with app_run() as c:
        for i in range(55):
            score(c, customer=cid, ts=old + i * HOUR, amount=5000.0,
                  device="dev_t", ip="ip_t")
        p = score(c, customer=cid, ts=T0, amount=5200.0, device="dev_t",
                  ip="ip_t", commit=False)
        before = features_of(c, p["transaction_id"])
        before_override = backend.STATE["txns"][p["transaction_id"]]["override"]

    with app_run() as c:
        p = score(c, customer=cid, ts=T0, amount=5200.0, device="dev_t",
                  ip="ip_t", commit=False)
        after = features_of(c, p["transaction_id"])
        after_override = backend.STATE["txns"][p["transaction_id"]]["override"]

    assert after["prev_txn_count"] == before["prev_txn_count"] == 55
    assert after["account_age_hours"] == pytest.approx(
        before["account_age_hours"], abs=0.01)
    assert after["account_age_hours"] > 180 * 24
    assert after_override == before_override


def test_account_age_is_not_reset_by_restart(db):
    """first_seen is set by build_online_features, not commit(). A commit-only
    replay would leave it None, age every customer from `now`, and fire
    new_account across the board."""
    cid = "cust_age"
    with app_run() as c:
        score(c, customer=cid, ts=T0 - 300 * HOUR, device="dev_a", ip="ip_a")
        p = score(c, customer=cid, ts=T0, device="dev_a", ip="ip_a", commit=False)
        before = features_of(c, p["transaction_id"])["account_age_hours"]

    with app_run() as c:
        p = score(c, customer=cid, ts=T0, device="dev_a", ip="ip_a", commit=False)
        after = features_of(c, p["transaction_id"])["account_age_hours"]

    assert after == pytest.approx(before, abs=0.01)
    assert after > 24, "account looked brand new after restart"


# ===========================================================================
# C. device state
# ===========================================================================

def test_device_state_survives_restart(db):
    dev = "dev_shared_c"
    with app_run() as c:
        score(c, customer="c_dev_1", ts=T0 - 5 * HOUR, device=dev, ip="ip_d1")
        score(c, customer="c_dev_2", ts=T0 - 4 * HOUR, device=dev, ip="ip_d2")
        score(c, customer="c_dev_3", ts=T0 - 3 * HOUR, device=dev, ip="ip_d3",
              status="failed")
        p = score(c, customer="c_dev_1", ts=T0, device=dev, ip="ip_d1",
                  commit=False)
        before = features_of(c, p["transaction_id"])

    with app_run() as c:
        p = score(c, customer="c_dev_1", ts=T0, device=dev, ip="ip_d1",
                  commit=False)
        after = features_of(c, p["transaction_id"])

    assert before["device_account_count"] == after["device_account_count"] == 3
    assert before["device_txn_count"] == after["device_txn_count"] == 3
    assert before["device_failure_rate"] == after["device_failure_rate"]
    assert after["is_new_device"] == before["is_new_device"] == 0


def test_new_device_detection_still_correct_after_restart(db):
    with app_run() as c:
        score(c, customer="c_nd", ts=T0 - HOUR, device="dev_known", ip="ip_nd")

    with app_run() as c:
        seen = score(c, customer="c_nd", ts=T0, device="dev_known", ip="ip_nd",
                     commit=False)
        fresh = score(c, customer="c_nd", ts=T0, device="dev_brand_new",
                      ip="ip_nd", commit=False)
        assert features_of(c, seen["transaction_id"])["is_new_device"] == 0
        assert features_of(c, fresh["transaction_id"])["is_new_device"] == 1


# ===========================================================================
# D. IP state
# ===========================================================================

def test_ip_state_survives_restart(db):
    ip = "ip_shared_d"
    with app_run() as c:
        for i in range(4):
            score(c, customer=f"c_ip_{i}", ts=T0 - (5 - i) * HOUR,
                  device=f"dev_ip_{i}", ip=ip)
        p = score(c, customer="c_ip_0", ts=T0, device="dev_ip_0", ip=ip,
                  commit=False)
        before = features_of(c, p["transaction_id"])

    with app_run() as c:
        p = score(c, customer="c_ip_0", ts=T0, device="dev_ip_0", ip=ip,
                  commit=False)
        after = features_of(c, p["transaction_id"])

    assert before["ip_account_count"] == after["ip_account_count"] == 4
    assert before["ip_txn_count"] == after["ip_txn_count"] == 4


def test_ip_failure_state_survives_restart(db):
    """Both suspicious-IP counters are rebuilt by the replay, not just the count.

    Three declines on three DIFFERENT methods, so this exercises the breadth rule
    (>= 3 distinct methods inside 2 hours) rather than the volume rule. That is the
    stricter test of the replay: the count alone would survive a replay that
    discarded `payment_method`, and the flag would then silently stop firing after
    every restart.
    """
    ip = "ip_burst_d"
    methods = ("card", "upi", "netbanking")
    with app_run() as c:
        # Inside the 20-minute volume window as well as the 2-hour breadth window,
        # so both counters are non-zero and the replay of both is observable.
        for i, m in enumerate(methods):
            score(c, customer=f"c_burst_{i}", ts=T0 - (10 - i) * MIN,
                  device=f"dev_burst_{i}", ip=ip, method=m, status="failed")
        store = backend.STATE["store"]
        before = store.ip_failures_recent(ip, T0)
        before_methods = store.ip_failed_methods_recent(ip, T0)
        assert store.evaluate_ip_suspicion(ip, T0)["rule"] == "breadth"

    with app_run() as c:
        store = backend.STATE["store"]
        after = store.ip_failures_recent(ip, T0)
        after_methods = store.ip_failed_methods_recent(ip, T0)
        flag = store.evaluate_ip_suspicion(ip, T0)
        assert flag is not None, "the breadth rule stopped firing after a restart"
        assert flag["rule"] == "breadth"

    assert before == after == 3
    assert before_methods == after_methods == set(methods)


# ===========================================================================
# E. network graph
# ===========================================================================

def _build_ring(c):
    """Account A -D1- Account B, A -P1- Account C, B -P2-, C -D2-."""
    score(c, customer="ring_A", ts=T0 - 6 * HOUR, device="D1", ip="P1")
    score(c, customer="ring_B", ts=T0 - 5 * HOUR, device="D1", ip="P2")
    score(c, customer="ring_C", ts=T0 - 4 * HOUR, device="D2", ip="P1")
    score(c, customer="ring_A", ts=T0 - 3 * HOUR, device="D1", ip="P1",
          status="failed")
    score(c, customer="ring_B", ts=T0 - 2 * HOUR, device="D1", ip="P2")


def test_network_score_survives_restart(db):
    with app_run() as c:
        _build_ring(c)
        p = score(c, customer="ring_A", ts=T0, device="D1", ip="P1",
                  commit=False)
        before = p["sub_scores"]["network"]
        assert before > 0, "test ring produced no network signal"

    with app_run() as c:
        p = score(c, customer="ring_A", ts=T0, device="D1", ip="P1",
                  commit=False)
        after = p["sub_scores"]["network"]

    assert after == pytest.approx(before, abs=0.05), \
        f"network score changed across restart: {before} -> {after}"


def test_shared_device_and_ip_edges_survive_restart(db):
    with app_run() as c:
        _build_ring(c)

    with app_run() as c:
        store = backend.STATE["store"]
        assert store.device_accounts("D1") == {"ring_A", "ring_B"}
        assert store.ip_accounts("P1") == {"ring_A", "ring_C"}
        assert store.acct_devices["ring_A"] == {"D1"}
        assert store.acct_ips["ring_B"] == {"P2"}


def test_depth2_expansion_survives_restart(db):
    """ring_A reaches ring_C only via the second hop through P1."""
    with app_run() as c:
        _build_ring(c)

    with app_run() as c:
        r = c.get("/v1/admin/rings/device/D1?depth=2")
        # Endpoint is role-gated; assert graph reachability directly instead.
        store = backend.STATE["store"]
        reachable = set(store.device_accounts("D1")) | set(store.ip_accounts("P1"))
        assert {"ring_A", "ring_B", "ring_C"} <= reachable
        assert r.status_code in (401, 403)


def test_cluster_minimum_still_applies_after_restart(db):
    """Under three accounts, the network layer scores 0 -- family tablets and
    office networks look like clusters otherwise."""
    with app_run() as c:
        score(c, customer="pair_A", ts=T0 - 2 * HOUR, device="Dpair", ip="Ppair")
        score(c, customer="pair_B", ts=T0 - HOUR, device="Dpair", ip="Ppair")

    with app_run() as c:
        p = score(c, customer="pair_A", ts=T0, device="Dpair", ip="Ppair",
                  commit=False)
        assert p["sub_scores"]["network"] == 0.0


def test_high_population_ip_damping_survives_restart(db):
    """Above HIGH_POP_IP_ACCOUNTS the IP is treated as shared infrastructure and
    is not followed. Reconstruction must not turn a carrier range into a ring."""
    busy = "ip_carrier"
    with app_run() as c:
        for i in range(30):
            score(c, customer=f"carrier_{i}", ts=T0 - (40 - i) * MIN,
                  device=f"dev_carrier_{i}", ip=busy)
        p = score(c, customer="carrier_0", ts=T0, device="dev_carrier_0",
                  ip=busy, commit=False)
        before = p["sub_scores"]["network"]

    with app_run() as c:
        store = backend.STATE["store"]
        assert len(store.ip_accounts(busy)) > backend.HIGH_POP_IP_ACCOUNTS
        p = score(c, customer="carrier_0", ts=T0, device="dev_carrier_0",
                  ip=busy, commit=False)
        after = p["sub_scores"]["network"]

    assert after == pytest.approx(before, abs=0.05)


# ===========================================================================
# F. full score parity -- the critical integration test
# ===========================================================================

def _mixed_history(c):
    """Customers, devices and IPs overlapping across several time windows."""
    score(c, customer="X_A", ts=T0 - 8 * HOUR, amount=3000.0, device="XD1", ip="XP1")
    score(c, customer="X_B", ts=T0 - 7 * HOUR, amount=9000.0, device="XD1", ip="XP2")
    score(c, customer="X_C", ts=T0 - 6 * HOUR, amount=1500.0, device="XD2", ip="XP1")
    score(c, customer="X_A", ts=T0 - 90 * MIN, amount=4000.0, device="XD1",
          ip="XP1", status="failed")
    score(c, customer="X_A", ts=T0 - 40 * MIN, amount=2500.0, device="XD1",
          ip="XP1", method="upi")
    score(c, customer="X_A", ts=T0 - 8 * MIN, amount=6000.0, device="XD1",
          ip="XP1", status="failed")
    score(c, customer="X_B", ts=T0 - 4 * MIN, amount=7000.0, device="XD1", ip="XP2")


TARGET = dict(customer="X_A", ts=T0, amount=25000.0, device="XD1", ip="XP1",
              method="card", commit=False)


def test_every_feature_and_subscore_identical_across_restart(db):
    """The headline invariant, asserted field by field."""
    with app_run() as c:
        _mixed_history(c)
        p = score(c, **TARGET)
        before = {
            "features": dict(features_of(c, p["transaction_id"])),
            "ml": p["sub_scores"]["ml"],
            "rules": p["sub_scores"]["rules"],
            "network": p["sub_scores"]["network"],
            "final": p["risk_score"],
            "decision": p["decision"],
            "reasons": p["reason_codes"],
            "override": p["override"],
        }

    assert backend.STATE == {}, "STATE was not cleared between runs"

    with app_run() as c:
        p = score(c, **TARGET)
        after = {
            "features": dict(features_of(c, p["transaction_id"])),
            "ml": p["sub_scores"]["ml"],
            "rules": p["sub_scores"]["rules"],
            "network": p["sub_scores"]["network"],
            "final": p["risk_score"],
            "decision": p["decision"],
            "reasons": p["reason_codes"],
            "override": p["override"],
        }

    # Every one of the 22 features, named individually on failure.
    for key in sorted(before["features"]):
        assert before["features"][key] == after["features"][key], (
            f"feature {key!r} changed: {before['features'][key]} -> "
            f"{after['features'][key]}")

    assert after["ml"] == before["ml"]
    assert after["rules"] == before["rules"]
    assert after["network"] == pytest.approx(before["network"], abs=0.05)
    assert after["final"] == pytest.approx(before["final"], abs=0.05)
    assert after["decision"] == before["decision"]
    assert after["reasons"] == before["reasons"]
    assert after["override"] == before["override"]


def test_parity_holds_across_two_restarts(db):
    scores = []
    for _ in range(3):
        with app_run() as c:
            if not scores:
                _mixed_history(c)
            p = score(c, **TARGET)
            scores.append((p["risk_score"], p["decision"],
                           p["sub_scores"]["network"]))
    assert scores[0][0] == pytest.approx(scores[1][0], abs=0.05)
    assert scores[1][0] == pytest.approx(scores[2][0], abs=0.05)
    assert scores[0][1] == scores[1][1] == scores[2][1]


# ===========================================================================
# G. no rescoring
# ===========================================================================

def test_rehydration_never_calls_the_scorer(db, monkeypatch):
    with app_run() as c:
        _mixed_history(c)

    calls = {"n": 0}
    real = backend.Scorer.score

    def counting(self, store, txn):
        calls["n"] += 1
        return real(self, store, txn)

    monkeypatch.setattr(backend.Scorer, "score", counting)
    with app_run():
        pass
    assert calls["n"] == 0, f"rehydration scored {calls['n']} transactions"


def test_rehydration_emits_no_risk_decision_events(db):
    with app_run() as c:
        _mixed_history(c)

    with app_run():
        assert [e for e in backend.STATE["audit"]
                if e["action"] == backend.RISK_DECISION] == []


# ===========================================================================
# H. no double counting
# ===========================================================================

def test_repeated_restarts_do_not_inflate_counters(db):
    cid = "cust_nodouble"
    with app_run() as c:
        for i in range(4):
            score(c, customer=cid, ts=T0 - (4 - i) * HOUR, device="dev_nd",
                  ip="ip_nd")

    seen = []
    for _ in range(3):
        with app_run() as c:
            p = score(c, customer=cid, ts=T0, device="dev_nd", ip="ip_nd",
                      commit=False)
            f = features_of(c, p["transaction_id"])
            seen.append((f["prev_txn_count"], f["device_txn_count"],
                         f["ip_txn_count"], f["device_account_count"]))
    assert seen[0] == seen[1] == seen[2] == (4, 4, 4, 1)


def test_new_transaction_after_rehydration_counted_once(db):
    cid = "cust_once"
    with app_run() as c:
        score(c, customer=cid, ts=T0 - 2 * HOUR, device="dev_o1", ip="ip_o1")

    with app_run() as c:
        score(c, customer=cid, ts=T0 - MIN, device="dev_o1", ip="ip_o1")
        p = score(c, customer=cid, ts=T0, device="dev_o1", ip="ip_o1",
                  commit=False)
        f = features_of(c, p["transaction_id"])
    assert f["prev_txn_count"] == 2, "new transaction was double counted"
    assert f["txn_count_1h"] == 1


def test_graph_edges_are_sets_not_multisets(db):
    with app_run() as c:
        for i in range(5):
            score(c, customer="edge_A", ts=T0 - (5 - i) * HOUR,
                  device="Dedge", ip="Pedge")

    with app_run() as c:
        store = backend.STATE["store"]
        assert store.acct_devices["edge_A"] == {"Dedge"}
        assert store.acct_ips["edge_A"] == {"Pedge"}
        assert store.device_accounts("Dedge") == {"edge_A"}


# ===========================================================================
# I. cold start
# ===========================================================================

def test_empty_store_startup_and_first_transaction(db):
    with app_run() as c:
        info = graph_info()
        assert info["replayed"] == 0
        assert info["skipped"] == 0
        assert info["complete"] is True

        p = score(c, customer="brand_new", ts=T0, device="dev_first",
                  ip="ip_first")
        f = features_of(c, p["transaction_id"])
        assert f["prev_txn_count"] == 0
        assert f["is_new_device"] == 1
        assert f["device_account_count"] == 0
        assert f["customer_avg_amount"] == backend.GLOBAL_AMOUNT_PRIOR
        assert f["seconds_since_last_txn"] == backend.NO_PRIOR_TXN_GAP
        assert p["decision"] in ("ALLOW", "MANUAL_REVIEW", "BLOCK")


def test_health_reports_entity_state(db):
    with app_run() as c:
        h = c.get("/health").json()
        assert "entity_state" in h
        assert h["entity_state"]["complete"] is True
        assert h["entity_state"]["horizon"] == backend.REHYDRATE_GRAPH_TXNS


# ===========================================================================
# J. incomplete / malformed records
# ===========================================================================

def test_missing_device_does_not_create_a_fake_edge(db):
    with app_run() as c:
        score(c, customer="partial_A", ts=T0 - HOUR, device="Dgood", ip="Pgood")
    # A record with no device_fp must be skipped, not stitched to anything.
    db.put("INDEX#TXN", f"2027-01-15T06:00:00+00:00#pay_nodev", {
        "transaction_id": "pay_nodev", "customer_id": "partial_B",
        "amount": 100.0, "payment_method": "card", "device_fp": "",
        "ip_hash": "Pgood", "settlement": "success",
        "created_at": "2027-01-15T06:00:00+00:00",
    })

    with app_run() as c:
        store = backend.STATE["store"]
        assert "partial_B" not in store.ip_accounts("Pgood")
        assert graph_info()["skipped"] >= 1
        assert graph_info()["complete"] is False


def test_missing_ip_does_not_create_a_fake_edge(db):
    with app_run() as c:
        score(c, customer="partial_C", ts=T0 - HOUR, device="Dc", ip="Pc")
    db.put("INDEX#TXN", "2027-01-15T06:00:00+00:00#pay_noip", {
        "transaction_id": "pay_noip", "customer_id": "partial_D",
        "amount": 100.0, "payment_method": "card", "device_fp": "Dc",
        "ip_hash": None, "settlement": "success",
        "created_at": "2027-01-15T06:00:00+00:00",
    })

    with app_run() as c:
        assert "partial_D" not in backend.STATE["store"].device_accounts("Dc")


@pytest.mark.parametrize("bad", [
    {"transaction_id": "pay_b1", "created_at": "not-a-timestamp",
     "customer_id": "c", "device_fp": "d", "ip_hash": "i",
     "payment_method": "card", "amount": 1.0},
    {"transaction_id": "pay_b2", "created_at": "2027-01-15T06:00:00+00:00",
     "customer_id": "c", "device_fp": "d", "ip_hash": "i",
     "payment_method": "card", "amount": "not-a-number"},
    {"transaction_id": "pay_b3"},
])
def test_malformed_records_do_not_crash_startup(db, bad):
    db.put("INDEX#TXN", f"2027-01-15T06:00:00+00:00#{bad['transaction_id']}", bad)
    with app_run() as c:
        assert c.get("/health").json()["status"] == "ok"
        assert graph_info()["skipped"] >= 1
        # Still serves new traffic.
        p = score(c, customer="after_bad", ts=T0, device="dev_ab", ip="ip_ab")
        assert p["decision"] in ("ALLOW", "MANUAL_REVIEW", "BLOCK")


def test_broken_history_read_degrades_without_crashing(db, capsys):
    with app_run() as c:
        score(c, customer="broken_A", ts=T0 - HOUR, device="Db", ip="Pb")

    original = db.query_prefix

    def flaky(pk, prefix, desc=True):
        if pk == "INDEX#TXN":
            raise RuntimeError("simulated history outage")
        return original(pk, prefix, desc)

    db.query_prefix = flaky
    try:
        with app_run() as c:
            assert c.get("/health").json()["status"] == "ok"
            assert graph_info()["complete"] is False
            assert graph_info()["replayed"] == 0
            p = score(c, customer="broken_A", ts=T0, device="Db", ip="Pb")
            assert p["decision"] in ("ALLOW", "MANUAL_REVIEW", "BLOCK")
    finally:
        db.query_prefix = original

    assert "start COLD" in capsys.readouterr().out


def test_horizon_truncation_is_reported_not_hidden(db, monkeypatch):
    with app_run() as c:
        for i in range(6):
            score(c, customer=f"trunc_{i}", ts=T0 - (10 - i) * HOUR,
                  device=f"Dt{i}", ip=f"Pt{i}")

    monkeypatch.setattr(backend, "REHYDRATE_GRAPH_TXNS", 3)
    with app_run() as c:
        info = graph_info()
        assert info["truncated"] is True
        assert info["complete"] is False
        assert info["replayed"] == 3
        assert c.get("/health").json()["entity_state"]["complete"] is False


# ===========================================================================
# K. store parity
# ===========================================================================

class FakeTable:
    """Minimal boto3 Table stand-in: enough for put/get/query/update."""

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


@pytest.mark.parametrize("factory", [backend.InMemoryRecordStore, _dynamo_store],
                         ids=["in_memory", "dynamo_fake"])
def test_entity_rehydration_works_against_both_stores(factory):
    """Same reconstruction logic, no store-specific branches. The Dynamo path also
    proves the Decimal round-trip does not corrupt amounts or timestamps."""
    records = factory()
    for i, (cid, dev, ip, amt, settled) in enumerate([
        ("par_A", "PD1", "PP1", 1000.0, "success"),
        ("par_B", "PD1", "PP2", 2000.0, "failed"),
        ("par_C", "PD2", "PP1", 3000.0, "success"),
    ]):
        backend.persist_scored_transaction(records, {
            "transaction_id": f"pay_par{i}", "customer_id": cid,
            "amount": amt, "payment_method": "card", "device_fp": dev,
            "ip_hash": ip, "settlement": settled,
            "created_at": f"2027-01-15T0{i}:00:00+00:00",
        })

    store = backend.InMemoryStore()
    summary = backend.rehydrate_entity_state(store, records, users=None)

    assert summary["replayed"] == 3
    assert summary["skipped"] == 0
    assert summary["complete"] is True
    assert store.device_accounts("PD1") == {"par_A", "par_B"}
    assert store.ip_accounts("PP1") == {"par_A", "par_C"}
    assert store.customer("par_A").sum_amount == 1000.0
    assert store.customer("par_B").n_fail == 1
    assert store.device("PD1").n_txn == 2


def test_replay_is_chronological_regardless_of_query_order():
    """commit() trims velocity deques from the left, so out-of-order replay would
    corrupt every window. Newest-first pointers must be re-sorted."""
    records = backend.InMemoryRecordStore()
    stamps = ["2027-01-15T05:00:00+00:00", "2027-01-15T07:00:00+00:00",
              "2027-01-15T06:00:00+00:00"]
    for i, ts in enumerate(stamps):
        backend.persist_scored_transaction(records, {
            "transaction_id": f"pay_ord{i}", "customer_id": "ord_A",
            "amount": 100.0, "payment_method": "card", "device_fp": "OD",
            "ip_hash": "OP", "settlement": "success", "created_at": ts,
        })

    store = backend.InMemoryStore()
    backend.rehydrate_entity_state(store, records, users=None)

    c = store.customer("ord_A")
    attempts = list(c.attempts)
    assert attempts == sorted(attempts), "velocity deque is not time-ordered"
    assert c.last_ts == max(backend._iso_to_epoch(s) for s in stamps)


def test_no_aws_credentials_needed():
    for var in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"):
        os.environ.pop(var, None)
    records = _dynamo_store()
    backend.persist_scored_transaction(records, {
        "transaction_id": "pay_nocred2", "customer_id": "nc",
        "amount": 10.0, "payment_method": "upi", "device_fp": "ncd",
        "ip_hash": "nci", "settlement": "success",
        "created_at": "2027-01-15T05:00:00+00:00",
    })
    store = backend.InMemoryStore()
    assert backend.rehydrate_entity_state(store, records,
                                          users=None)["replayed"] == 1


# ===========================================================================
# L. security
# ===========================================================================

def test_replay_projection_holds_no_sensitive_data(db):
    with app_run() as c:
        score(c, customer="sec_A", ts=T0 - HOUR, device="Dsec", ip="Psec")
    blob = repr(db.query_prefix("INDEX#TXN", "", desc=True))
    for leak in ("4111", '"cvv"', "password", "Bearer",
                 os.environ["FRAUDSHIELD_JWT_SECRET"],
                 os.environ["FRAUDSHIELD_IP_PEPPER"]):
        assert leak not in blob, f"replay projection leaked {leak!r}"


def test_projection_carries_only_replay_fields(db):
    with app_run() as c:
        score(c, customer="sec_B", ts=T0 - HOUR, device="Dsec2", ip="Psec2")
    p = db.query_prefix("INDEX#TXN", "", desc=True)[0]
    # Exactly the fields commit() needs, plus `committed` which decides whether a
    # record is replayed at all. Deliberately a closed allow-list: it fails when
    # the projection grows, forcing a decision instead of silent duplication.
    allowed = {"PK", "SK", "transaction_id", "customer_id", "amount",
               "payment_method", "device_fp", "ip_hash", "settlement",
               "created_at", "committed"}
    assert set(p) <= allowed, f"unexpected fields in projection: {set(p) - allowed}"
    # Mutable state stays in one place only.
    for f in ("label", "labelled_by", "risk_score", "decision", "features"):
        assert f not in p
