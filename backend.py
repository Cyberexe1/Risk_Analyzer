"""
FraudShield backend -- the complete serving path in one module.

    uvicorn backend:app --port 8000

Contents, in order:
    1. Feature matrix builder   -- CANONICAL. ml/train.py imports it from here.
    2. Entity state store       -- counters an online scorer reads before scoring
    3. Online feature builder   -- the 22 documented features for one transaction
    4. Scoring layers           -- ML + rules + entity graph + aggregation
    5. FastAPI application      -- score, checkout, queue, detail, outcome

Deliberately EXCLUDED, because none of it runs in production:
    ml/generate_dataset.py   dataset simulation
    ml/train.py              model fitting        (needs scikit-learn)
    ml/evaluate.py           metrics + cost model
    ml/scoring.py            batch scoring, kept as the parity reference
    tests/                   parity suite

That split is the point. This module needs numpy, pandas, xgboost, fastapi,
uvicorn and pydantic. It does not need scikit-learn, and a serving container
should not carry a dataset generator.

--------------------------------------------------------------------------------
PARITY WARNING -- read before refactoring
--------------------------------------------------------------------------------
`build_online_features()` in section 3 is an INDEPENDENT reimplementation of the
forward pass in ml/generate_dataset.py::compute_features. The two look similar on
purpose. tests/test_parity.py proves they agree across 2.1M feature comparisons,
and that agreement is the only evidence that the metrics in docs/EVALUATION.md
describe a model that can actually ship.

If you "deduplicate" these two into a shared helper, the test will still pass and
will prove nothing -- a function equalling itself. Leave them separate.
--------------------------------------------------------------------------------

SECURITY -- read before exposing this service
---------------------------------------------
Guarded by a single shared API key (`FRAUDSHIELD_API_KEY`). That is NOT the auth
model docs/ARCHITECTURE.md section 4 specifies (JWT access + refresh, Argon2id
credentials in DynamoDB, per-route role gating). Missing today:

  - no per-user identity; nothing distinguishes one caller from another
  - no roles, so no analyst/admin separation
  - no rate limiting on any endpoint
  - review queue is in process memory and is lost on restart

If FRAUDSHIELD_API_KEY is unset, every endpoint is OPEN and startup says so.
Binds 127.0.0.1 by default. Keep it there until the auth layer exists.
"""

from __future__ import annotations

import json
import math
import os
import re
import secrets
import threading
import time
import uuid
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

import numpy as np
import pandas as pd
import xgboost as xgb
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

_HERE = Path(__file__).resolve().parent

# Artifacts can be relocated for containers without touching code.
ARTIFACTS = Path(os.environ.get("FRAUDSHIELD_ARTIFACTS", _HERE / "ml" / "artifacts"))
DATA_CSV = Path(os.environ.get("FRAUDSHIELD_DATA", _HERE / "ml" / "data" / "transactions.csv"))

API_KEY = os.environ.get("FRAUDSHIELD_API_KEY", "")
WARM_ROWS = int(os.environ.get("FRAUDSHIELD_WARM_ROWS", "40000"))

# Explicit origin allow-list. Never "*" -- a wildcard with credentials is rejected
# by browsers anyway, and a wildcard without them still lets any site read
# responses from a service that returns fraud reason codes.
CORS_ORIGINS = [
    o.strip()
    for o in os.environ.get(
        "FRAUDSHIELD_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
    ).split(",")
    if o.strip()
]


# =============================================================================
# 1. Feature matrix builder -- CANONICAL
# =============================================================================
#
# ml/train.py imports build_matrix and RAW_FEATURES from this module rather than
# defining its own. One copy of the log1p transforms and the column ordering. Two
# copies would eventually drift by a single transform and the served model would
# silently be scoring a different matrix than the one it was fitted on -- a bug
# that produces plausible numbers and no error.

RAW_FEATURES = [
    # transaction (4)
    "amount", "payment_method", "transaction_hour", "is_weekend",
    # velocity (4)
    "txn_count_10m", "txn_count_1h", "failed_count_10m", "failed_count_1h",
    # customer baseline (5)
    "account_age_hours", "customer_avg_amount", "amount_ratio",
    "prev_txn_count", "historical_failure_rate",
    # device / ip (5)
    "device_account_count", "device_txn_count", "device_failure_rate",
    "ip_account_count", "ip_txn_count",
    # behavioural (4)
    "is_new_device", "is_new_payment_method", "seconds_since_last_txn",
    "hour_deviation",
]

PAYMENT_METHODS = ["upi", "card", "netbanking", "wallet", "cod"]

# Columns that must NEVER enter the matrix, and why.
#
#   status              -- the authorisation outcome of THIS transaction. A real
#                          scorer runs BEFORE authorisation, so it does not have
#                          this. Card testing declines ~72% of the time, so
#                          including it leaks the label almost directly. Easiest
#                          way to build a 0.99 AUC model that cannot ship.
#   fraud_type          -- the archetype name. Trivially the label.
#   account_created_at  -- absolute signup time. Exists so the online scorer can
#                          be seeded identically. As a feature it leaks cohort
#                          timing: "created in June" is a property of the test
#                          split, not of fraud. account_age_hours is the relative
#                          version, and that one IS a feature.
#   segment             -- generator metadata, kept only for fairness slicing.
#   customer_id
#   device_fp           -- raw identifiers. Memorising specific devices is not
#   ip_hash                generalisation, and in production these are unbounded-
#                          cardinality strings that shift constantly.
#   ts_epoch            -- absolute time. Model would learn "week 8 = test set".
LEAKY_OR_ID = {
    "status", "fraud_type", "segment", "customer_id", "device_fp", "ip_hash",
    "ts_epoch", "timestamp", "transaction_id", "fraud_label", "split",
    "account_created_at",
}

# Heavy right skew: rupee amounts, ages in hours and inter-arrival gaps span
# several orders of magnitude. Trees do not need this for splits, but it keeps
# SHAP contributions readable and stabilises the isotonic calibrator.
LOG1P_COLS = [
    "amount", "customer_avg_amount", "account_age_hours",
    "seconds_since_last_txn", "device_txn_count", "ip_txn_count",
    "txn_count_1h", "prev_txn_count",
]


def build_matrix(df: pd.DataFrame) -> tuple[pd.DataFrame, list[str]]:
    """Raw features -> numeric matrix. Deterministic column order."""
    x = pd.DataFrame(index=df.index)

    for col in RAW_FEATURES:
        if col == "payment_method":
            continue
        x[col] = pd.to_numeric(df[col], errors="coerce")

    for col in LOG1P_COLS:
        x[col] = np.log1p(np.clip(x[col].to_numpy(dtype=float), 0, None))

    # Hour is cyclical: 23:00 and 00:00 are one hour apart, not 23. A raw integer
    # forces the tree to spend splits rediscovering that.
    hour = pd.to_numeric(df["transaction_hour"], errors="coerce").fillna(12).to_numpy()
    x["hour_sin"] = np.sin(2 * np.pi * hour / 24)
    x["hour_cos"] = np.cos(2 * np.pi * hour / 24)
    x.drop(columns=["transaction_hour"], inplace=True)

    method = df["payment_method"].astype(str)
    for m in PAYMENT_METHODS:
        x[f"method_{m}"] = (method == m).astype(np.int8)

    x = x.astype(np.float32)
    x.fillna(0.0, inplace=True)
    return x, list(x.columns)


def assert_no_leakage(feature_names: list[str]) -> None:
    """Fail loudly rather than silently training on the answer."""
    bad = sorted(set(feature_names) & LEAKY_OR_ID)
    if bad:
        raise ValueError(f"leaky columns reached the feature matrix: {bad}")


# =============================================================================
# 2. Entity state store
# =============================================================================
#
# The offline pipeline computes features in one chronological pass over a sorted
# file. Production has no sorted file -- it has one transaction and whatever
# counters earlier traffic left behind. If those two paths disagree, every metric
# in docs/EVALUATION.md describes a model that cannot ship. tests/test_parity.py
# is what checks that.


class RunningHour:
    """Circular running mean of hour-of-day plus mean absolute deviation.

    Same update rule as ml/generate_dataset.py. MAD accumulates against a moving
    mean rather than being recomputed, which is what an online scorer can afford.
    """

    __slots__ = ("s", "c", "n", "mad")

    def __init__(self) -> None:
        self.s = 0.0
        self.c = 0.0
        self.n = 0
        self.mad = 0.0

    def mean_hour(self) -> float:
        if self.n == 0:
            return 12.0
        ang = math.atan2(self.s / self.n, self.c / self.n)
        return (ang * 24 / (2 * math.pi)) % 24.0

    def deviation(self, hour: float) -> float:
        if self.n < 5:
            return 0.0
        d = abs(hour - self.mean_hour())
        d = min(d, 24 - d)
        return d / max(1.0, self.mad)

    def update(self, hour: float) -> None:
        d = abs(hour - self.mean_hour())
        d = min(d, 24 - d)
        ang = hour * 2 * math.pi / 24
        self.s += math.sin(ang)
        self.c += math.cos(ang)
        self.n += 1
        self.mad += (d - self.mad) / self.n


@dataclass
class CustomerState:
    created_at: float | None = None
    first_seen: float | None = None
    n_txn: int = 0
    n_fail: int = 0
    sum_amount: float = 0.0
    last_ts: float | None = None
    devices: set[str] = field(default_factory=set)
    methods: set[str] = field(default_factory=set)
    hour: RunningHour = field(default_factory=RunningHour)
    attempts: deque = field(default_factory=deque)
    failures: deque = field(default_factory=deque)
    method_hist: deque = field(default_factory=deque)   # (ts, method), rule input
    recent: deque = field(default_factory=deque)        # 24h activity, graph term


@dataclass
class DeviceState:
    accounts: set[str] = field(default_factory=set)
    n_txn: int = 0
    n_fail: int = 0


@dataclass
class IPState:
    accounts: set[str] = field(default_factory=set)
    n_txn: int = 0


class Store(Protocol):
    def customer(self, cid: str) -> CustomerState: ...
    def device(self, fp: str) -> DeviceState: ...
    def ip(self, h: str) -> IPState: ...
    def commit(self, ev: dict) -> None: ...


class InMemoryStore:
    """Reference implementation with exact velocity windows via deques.

    This is what the parity tests run against and what the API uses. The
    DynamoDB adapter is NOT built; see the mapping note at the end of this
    section for why it will need its own parity measurement.
    """

    def __init__(self) -> None:
        self._cust: dict[str, CustomerState] = defaultdict(CustomerState)
        self._dev: dict[str, DeviceState] = defaultdict(DeviceState)
        self._ip: dict[str, IPState] = defaultdict(IPState)
        self.acct_devices: dict[str, set[str]] = defaultdict(set)
        self.acct_ips: dict[str, set[str]] = defaultdict(set)

    def customer(self, cid: str) -> CustomerState:
        return self._cust[cid]

    def device(self, fp: str) -> DeviceState:
        return self._dev[fp]

    def ip(self, h: str) -> IPState:
        return self._ip[h]

    def register_customer(self, cid: str, created_at: float) -> None:
        """Called at signup, so created_at is known rather than inferred."""
        c = self._cust[cid]
        if c.created_at is None:
            c.created_at = created_at

    def account_age_hours(self, cid: str, now: float) -> float:
        c = self._cust[cid]
        base = c.created_at if c.created_at is not None else c.first_seen
        if base is None:
            base = now
        return max(0.0, (now - base) / 3600.0)

    @staticmethod
    def _trim(dq: deque, now: float, window: float) -> int:
        while dq and now - dq[0] > window:
            dq.popleft()
        return len(dq)

    @staticmethod
    def _count(dq: deque, now: float, window: float) -> int:
        return sum(1 for t in dq if now - t <= window)

    def velocity(self, cid: str, now: float) -> tuple[int, int, int, int]:
        """(attempts_10m, attempts_1h, failures_10m, failures_1h).

        One deque per series, trimmed to the LONGEST window (1h) and counted
        within the shorter one. Trimming to 600s would silently destroy the 1h
        count -- the offline pass kept separate deques per window, so this has to
        preserve those semantics from shared storage.
        """
        c = self._cust[cid]
        n_att_1h = self._trim(c.attempts, now, 3600)
        n_fail_1h = self._trim(c.failures, now, 3600)
        return (
            self._count(c.attempts, now, 600),
            n_att_1h,
            self._count(c.failures, now, 600),
            n_fail_1h,
        )

    def methods_last_hour(self, cid: str, now: float) -> int:
        c = self._cust[cid]
        while c.method_hist and now - c.method_hist[0][0] > 3600:
            c.method_hist.popleft()
        return len({m for _, m in c.method_hist})

    def commit(self, ev: dict) -> None:
        """Apply a scored transaction to state. Call ONLY after features have been
        read, mirroring the offline forward pass."""
        cid, ts = ev["customer_id"], ev["ts"]
        dev, ipa = ev["device_fp"], ev["ip_hash"]
        failed = ev["status"] == "failed"

        c = self._cust[cid]
        c.n_txn += 1
        c.sum_amount += ev["amount"]
        if failed:
            c.n_fail += 1
        c.last_ts = ts
        c.devices.add(dev)
        c.methods.add(ev["payment_method"])
        c.hour.update(ev["hour"])
        c.attempts.append(ts)
        if failed:
            c.failures.append(ts)
        c.method_hist.append((ts, ev["payment_method"]))
        c.recent.append(ts)

        d = self._dev[dev]
        d.accounts.add(cid)
        d.n_txn += 1
        if failed:
            d.n_fail += 1

        p = self._ip[ipa]
        p.accounts.add(cid)
        p.n_txn += 1

        self.acct_devices[cid].add(dev)
        self.acct_ips[cid].add(ipa)

    # graph reads
    def device_accounts(self, fp: str) -> set[str]:
        return self._dev[fp].accounts

    def ip_accounts(self, h: str) -> set[str]:
        return self._ip[h].accounts

    def account_activity_24h(self, cid: str, now: float) -> int:
        c = self._cust[cid]
        while c.recent and now - c.recent[0] > 86400:
            c.recent.popleft()
        return len(c.recent)

    def account_totals(self, cid: str) -> tuple[int, int]:
        c = self._cust[cid]
        return c.n_txn, c.n_fail


# DynamoDB mapping, for when the adapter is built
# -----------------------------------------------
#   CustomerState  -> CUSTOMER#<id> / PROFILE   atomic ADD on n_txn, n_fail,
#                                               sum_amount; SET last_ts
#   devices/methods-> string sets (SS) on the same item, ADD to append
#   RunningHour    -> s, c, n, mad as numbers. All ADD except mad, which needs
#                     the read value, making the hour update non-atomic.
#                     Acceptable: hour_deviation ranks 10th by gain.
#   attempts/fails -> CUSTOMER#<id> / WINDOW#10M#<epoch//600> with TTL, ADD on
#                     count. NOTE: bucketed counts APPROXIMATE the exact deque.
#                     A transaction at t sees buckets, not a true trailing 600s.
#                     This is the one place the online path will legitimately
#                     diverge from the offline pipeline, and it needs its own
#                     parity measurement before it is trusted.
#   DeviceState    -> DEVICE#<fp> / COUNTERS + DEVICE#<fp> / ACCT#<cid> edges
#   IPState        -> IP#<hash> / COUNTERS   + IP#<hash> / ACCT#<cid> edges
#
# commit() becomes one TransactWriteItems call, so the transaction record and its
# counters land together or not at all.


# =============================================================================
# 3. Online feature builder
# =============================================================================
#
# See the PARITY WARNING at the top of this file before touching this function.

# Same fallback the generator uses for a customer with no history. A production
# scorer faces exactly this cold-start gap, so the model must see the sentinel it
# was trained on rather than a quietly imputed per-customer value.
GLOBAL_AMOUNT_PRIOR = 1500.0
NO_PRIOR_TXN_GAP = 999999.0


def build_online_features(store: InMemoryStore, txn: dict) -> dict:
    """Return the 22 raw features for `txn` given current state.

    Every value comes from state as it stands BEFORE this transaction is applied.
    store.commit() is the caller's job, never called from here.

    txn requires: customer_id, ts (epoch), amount, payment_method, device_fp,
    ip_hash.
    """
    cid = txn["customer_id"]
    ts = float(txn["ts"])
    dev = txn["device_fp"]
    ipa = txn["ip_hash"]
    amount = float(txn["amount"])
    method = txn["payment_method"]

    c = store.customer(cid)
    if c.first_seen is None:
        c.first_seen = ts

    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    hour = dt.hour + dt.minute / 60.0

    n_prev = c.n_txn
    prior_avg = (c.sum_amount / n_prev) if n_prev else GLOBAL_AMOUNT_PRIOR

    v10, v1h, f10, f1h = store.velocity(cid, ts)
    d = store.device(dev)
    p = store.ip(ipa)

    return {
        # transaction (4)
        "amount": round(amount, 2),
        "payment_method": method,
        "transaction_hour": dt.hour,
        "is_weekend": int(dt.weekday() >= 5),
        # velocity (4)
        "txn_count_10m": v10,
        "txn_count_1h": v1h,
        "failed_count_10m": f10,
        "failed_count_1h": f1h,
        # customer baseline (5)
        "account_age_hours": round(store.account_age_hours(cid, ts), 3),
        "customer_avg_amount": round(prior_avg, 2),
        "amount_ratio": round(min(50.0, amount / max(1.0, prior_avg)), 4),
        "prev_txn_count": n_prev,
        "historical_failure_rate": round((c.n_fail + 1) / (n_prev + 2), 4),
        # device / ip (5)
        "device_account_count": len(d.accounts),
        "device_txn_count": d.n_txn,
        "device_failure_rate": round((d.n_fail + 1) / (d.n_txn + 2), 4),
        "ip_account_count": len(p.accounts),
        "ip_txn_count": p.n_txn,
        # behavioural (4)
        "is_new_device": int(dev not in c.devices),
        "is_new_payment_method": int(method not in c.methods),
        "seconds_since_last_txn": round(
            ts - c.last_ts if c.last_ts is not None else NO_PRIOR_TXN_GAP, 1
        ),
        "hour_deviation": round(c.hour.deviation(hour), 4),
    }


# =============================================================================
# 4. Scoring layers
# =============================================================================

RULE_POINTS = {
    "velocity_breach": 20,
    "device_abuse": 15,
    "ip_concentration": 10,
    "amount_anomaly": 15,
    "failure_spike": 10,
    "new_account": 5,
    "new_device": 5,
    "method_switching": 10,
}

# Correlated rules are grouped and only the highest scorer in each group counts.
# device_abuse and ip_concentration both measure "one actor, many accounts";
# adding both punishes the same evidence twice. This is the structural fix for the
# additive blow-up in the original hand-picked formula: the layer is capped at 100
# and weighted 0.20, so a ninth rule cannot inflate the total, only redistribute.
RULE_GROUPS = {
    "entity_sharing": ["device_abuse", "ip_concentration"],
    "velocity": ["velocity_breach", "failure_spike", "method_switching"],
    "novelty": ["new_account", "new_device"],
    "amount": ["amount_anomaly"],
}

# Analyst-facing only. Customers never see these -- telling an attacker which
# signal fired is free reconnaissance.
RULE_TEXT = {
    "velocity_breach": "{txn_count_10m:.0f} attempts in 10 minutes",
    "device_abuse": "Device linked to {device_account_count:.0f} accounts",
    "ip_concentration": "{ip_account_count:.0f} accounts on this IP",
    "amount_anomaly": "Amount {amount_ratio:.1f}x customer baseline",
    "failure_spike": "{failed_count_1h:.0f} failures in the last hour",
    "new_account": "Account created {account_age_hours:.0f} hours ago",
    "new_device": "First transaction from this device",
    "method_switching": "{methods_1h:.0f} payment methods in an hour",
}

SHAP_TEXT = {
    "amount_ratio": "Amount {v:.1f}x customer baseline",
    "txn_count_10m": "{v:.0f} attempts in 10 minutes",
    "txn_count_1h": "{v:.0f} attempts in the last hour",
    "failed_count_1h": "{v:.0f} failed attempts in the last hour",
    "failed_count_10m": "{v:.0f} failed attempts in 10 minutes",
    "device_account_count": "Device linked to {v:.0f} accounts",
    "device_failure_rate": "High failure rate on this device",
    "ip_account_count": "{v:.0f} accounts on this IP",
    "account_age_hours": "New account",
    "historical_failure_rate": "High historical failure rate",
    "is_new_device": "First transaction from this device",
    "is_new_payment_method": "First use of this payment method",
    "hour_deviation": "Unusual hour for this customer",
    "seconds_since_last_txn": "Very short gap since last attempt",
    "amount": "Transaction amount",
    "customer_avg_amount": "Customer spending baseline",
    "prev_txn_count": "Thin transaction history",
}

W_ML, W_RULES, W_NETWORK = 0.70, 0.20, 0.10

HIGH_POP_IP_ACCOUNTS = 25   # above this, an IP is shared infrastructure
MAX_COMPONENT = 200

# Defaults chosen on the validation split by expected-cost minimisation under an
# analyst-capacity ceiling. See docs/EVALUATION.md section 5 -- the review
# threshold is an OPERATIONS parameter (how many analysts you employ), not a
# property of the model.
DEFAULT_REVIEW_T = float(os.environ.get("FRAUDSHIELD_REVIEW_T", "5"))
DEFAULT_BLOCK_T = float(os.environ.get("FRAUDSHIELD_BLOCK_T", "70"))


@dataclass
class Decision:
    risk_score: float
    decision: str
    sub_scores: dict
    reason_codes: list
    fired_rules: list
    override: str | None
    model_version: str
    degraded: bool


class Scorer:
    """One transaction, three layers, one decision, with evidence.

    Never writes state. store.commit() is the caller's job, which is what keeps
    the read-before-write ordering that tests/test_parity.py verifies.
    """

    def __init__(self, artifacts: Path = ARTIFACTS,
                 review_t: float = DEFAULT_REVIEW_T,
                 block_t: float = DEFAULT_BLOCK_T):
        self.review_t = review_t
        self.block_t = block_t
        self.degraded = False
        self.best_iteration = None

        spec_p, model_p, cal_p = (
            artifacts / "feature_spec.json",
            artifacts / "model.json",
            artifacts / "calibrator.json",
        )

        if not (spec_p.exists() and model_p.exists() and cal_p.exists()):
            # Degrade to rules+network rather than refusing to serve. Checkout is
            # on the other side of this call.
            self.booster = None
            self.spec = {"feature_names": []}
            self.degraded = True
            self.model_version = "none"
            self._cal_x = self._cal_y = None
            return

        self.spec = json.loads(spec_p.read_text())
        self.booster = xgb.Booster()
        self.booster.load_model(str(model_p))
        cal = json.loads(cal_p.read_text())
        self._cal_x = np.array(cal["x"], dtype=float)
        self._cal_y = np.array(cal["y"], dtype=float)
        self.best_iteration = self.spec.get("best_iteration")
        self.model_version = self.spec.get("trained_at", "unknown")

    # ---- ML layer ----------------------------------------------------------
    def calibrate(self, p):
        """Isotonic calibration. Raw XGBoost margins are not probabilities, and
        the cost model multiplies probability by rupees -- uncalibrated scores
        would make that arithmetic meaningless."""
        return np.interp(p, self._cal_x, self._cal_y,
                         left=self._cal_y[0], right=self._cal_y[-1])

    def _ml_score(self, raw: dict) -> tuple[float, np.ndarray, list[str]]:
        if self.booster is None:
            return 0.0, np.array([]), []
        X, names = build_matrix(pd.DataFrame([raw]))
        if names != self.spec["feature_names"]:
            raise RuntimeError(
                "online feature order differs from training; retrain or fix "
                "build_matrix"
            )
        dm = xgb.DMatrix(X.to_numpy(), feature_names=names)
        rng = (0, self.best_iteration + 1) if self.best_iteration is not None else None
        p = float(self.booster.predict(dm, iteration_range=rng)[0]) if rng \
            else float(self.booster.predict(dm)[0])
        contribs = self.booster.predict(dm, pred_contribs=True)[0][:-1]
        return float(np.clip(self.calibrate(p) * 100.0, 0, 100)), contribs, names

    # ---- rule layer --------------------------------------------------------
    @staticmethod
    def _rules(raw: dict, methods_1h: int) -> tuple[float, list[str]]:
        fired = {
            "velocity_breach": raw["txn_count_10m"] > 5,
            "device_abuse": raw["device_account_count"] > 4,
            "ip_concentration": raw["ip_account_count"] > 6,
            "amount_anomaly": raw["amount_ratio"] > 4,
            "failure_spike": raw["failed_count_1h"] > 5,
            "new_account": raw["account_age_hours"] < 24,
            "new_device": raw["is_new_device"] == 1,
            "method_switching": methods_1h > 3,
        }
        score = 0.0
        for members in RULE_GROUPS.values():
            best = 0
            for r in members:
                if fired[r]:
                    best = max(best, RULE_POINTS[r])
            score += best
        return min(100.0, score), [r for r, f in fired.items() if f]

    # ---- network layer -----------------------------------------------------
    @staticmethod
    def _network(store: InMemoryStore, cid: str, dev: str, ipa: str,
                 now: float) -> float:
        """Shared-entity graph score from live adjacency.

        Depth-2 expansion only runs when the depth-1 component is small, to keep
        this O(1)-ish per request. Bounded at MAX_COMPONENT because carrier CGNAT
        and campus ranges can reach thousands of accounts.
        """
        ip_is_shared = len(store.ip_accounts(ipa)) > HIGH_POP_IP_ACCOUNTS

        accounts = set(store.device_accounts(dev))
        if not ip_is_shared:
            accounts |= store.ip_accounts(ipa)
        accounts.add(cid)

        if len(accounts) < 20:
            for a in list(accounts):
                for d in store.acct_devices[a]:
                    accounts |= store.device_accounts(d)
                    if len(accounts) > MAX_COMPONENT:
                        break
                if len(accounts) > MAX_COMPONENT:
                    break
        if len(accounts) > MAX_COMPONENT:
            accounts = set(list(accounts)[:MAX_COMPONENT])

        n_acct = len(accounts)
        if n_acct < 3:
            return 0.0

        edges = txn24 = fails = total = active = 0
        for a in accounts:
            edges += len(store.acct_devices[a]) + len(store.acct_ips[a])
            act = store.account_activity_24h(a, now)
            if act:
                active += 1
            txn24 += act
            n, f = store.account_totals(a)
            total += n
            fails += f

        size = min(1.0, math.log1p(n_acct) / math.log1p(20))
        density = min(1.0, (edges / n_acct) / 4.0)
        burst = min(1.0, txn24 / (3.0 * n_acct))
        fail = (fails / total) if total else 0.0
        sync = active / n_acct

        raw = 0.30 * size + 0.25 * density + 0.20 * burst + 0.15 * fail + 0.10 * sync

        # Damp components whose only link is high-population infrastructure.
        # Without this every customer on a large mobile carrier inherits a ring
        # score -- the most expensive false-positive source found in testing.
        penalty = 0.35 if ip_is_shared and len(store.device_accounts(dev)) <= 2 else 1.0
        return min(100.0, raw * 100.0 * penalty)

    # ---- explanation -------------------------------------------------------
    @staticmethod
    def _reasons(raw: dict, fired: list[str], methods_1h: int,
                 contribs: np.ndarray, names: list[str]) -> list[dict]:
        out: list[dict] = []
        ctx = dict(raw)
        ctx["methods_1h"] = methods_1h

        for r in fired:
            out.append({
                "code": r.upper(),
                "severity": "high" if RULE_POINTS[r] >= 15 else "medium",
                "detail": RULE_TEXT[r].format(**ctx),
                "source": "rule",
            })

        if len(contribs):
            for i in np.argsort(-np.abs(contribs))[:5]:
                f = names[i]
                if contribs[i] <= 0 or f not in SHAP_TEXT:
                    continue
                detail = SHAP_TEXT[f].format(v=float(raw.get(f, 0)))
                if detail in {o["detail"] for o in out}:
                    continue
                out.append({
                    "code": f.upper(),
                    "severity": "medium",
                    "detail": detail,
                    "source": "model",
                    "contribution": round(float(contribs[i]), 4),
                })
        return out[:8]

    # ---- entry point -------------------------------------------------------
    def score(self, store: InMemoryStore, txn: dict) -> tuple[Decision, dict]:
        """Score one transaction. Returns (decision, raw_features). Does NOT commit."""
        raw = build_online_features(store, txn)
        methods_1h = store.methods_last_hour(txn["customer_id"], float(txn["ts"]))

        ml, contribs, names = self._ml_score(raw)
        rules, fired = self._rules(raw, methods_1h)
        net = self._network(store, txn["customer_id"], txn["device_fp"],
                            txn["ip_hash"], float(txn["ts"]))

        if self.booster is None:
            # Reweight so the two surviving layers still span 0-100.
            final = 0.70 * rules + 0.30 * net
        else:
            final = W_ML * ml + W_RULES * rules + W_NETWORK * net
        final = float(np.clip(final, 0, 100))

        override = None
        if rules >= 100 and net > 85:
            final, override = 100.0, "hard_block"
        elif (
            raw["account_age_hours"] > 180 * 24
            and raw["prev_txn_count"] > 50
            and raw["amount_ratio"] < 2
            and rules == 0
        ):
            # Stops the model harassing the merchant's best customers over a new
            # device.
            if final > 39.0:
                override = "trusted_floor"
            final = min(final, 39.0)

        if final >= self.block_t:
            decision = "BLOCK"
        elif final >= self.review_t:
            decision = "MANUAL_REVIEW"
        else:
            decision = "ALLOW"

        return (
            Decision(
                risk_score=round(final, 1),
                decision=decision,
                sub_scores={"ml": round(ml, 1), "rules": round(rules, 1),
                            "network": round(net, 1)},
                reason_codes=self._reasons(raw, fired, methods_1h, contribs, names),
                fired_rules=fired,
                override=override,
                model_version=self.model_version,
                degraded=self.degraded,
            ),
            raw,
        )


# =============================================================================
# 4a. Promotion abuse gate
# =============================================================================
#
# A separate gate for a separate loss class. One person opening five accounts to
# claim a Rs 500 welcome offer five times is invisible to the transaction scorer
# for two reasons:
#
#   1. WRONG MOMENT. The loss happens at signup and redemption. By the time a
#      payment is scored, the cashback is already credited.
#   2. WRONG UNIT. Each account looks unremarkable on its own. The evidence lives
#      in the relationships BETWEEN accounts, and a per-transaction model has
#      nowhere to put that.
#
# Rules-first on purpose, not as a shortcut: promo abuse patterns are structural
# and stable, the class is small, and a merchant launching a new promotion has
# zero labels to train on. An ML layer here would be over-engineering.
#
# Denials are cheap to be wrong about, which changes the risk posture. Refusing a
# cashback is not refusing a sale -- the customer can still buy, they just lose
# the bonus, and support can reverse it. So the thresholds are deliberately more
# aggressive than anything acceptable at checkout.

PROMO_FEATURES = [
    "promo_redemptions_on_device",
    "promo_redemptions_on_ip",
    "accounts_on_device_7d",
    "signup_to_redeem_seconds",
    "email_pattern_similarity",
    "component_account_count",
    "payout_destination_reuse",
]

# An IP with more than this many accounts is treated as shared infrastructure --
# office NAT, campus, carrier CGNAT. IP-only signals cannot deny or hold on their
# own there; they need a device or payout match. Without this, every customer on a
# large mobile carrier inherits an abuse score.
PROMO_SHARED_IP_ACCOUNTS = 25

PROMO_RULES = {
    # action, human-readable reason
    "device_promo_reuse": ("DENY", "This promotion was already claimed {promo_redemptions_on_device:.0f} times from this device"),
    "payout_reuse": ("DENY", "This payout destination already received this promotion"),
    "device_account_cluster": ("HOLD", "{accounts_on_device_7d:.0f} accounts on this device in 7 days"),
    "ip_burst_fast_signup": ("HOLD", "{promo_redemptions_on_ip:.0f} claims from this IP, redeemed {signup_to_redeem_seconds:.0f}s after signup"),
    "email_cluster": ("HOLD", "{component_account_count:.0f} linked accounts with similar email patterns"),
}


@dataclass(frozen=True)
class PromoThresholds:
    """Tuned on the VALIDATION split by expected cost, then frozen for test.
    See ml/evaluate_promo.py --tune.

    The first version of these was hand-picked, and measurement showed the gate
    cost MORE than the abuse it prevented: `device_reuse_deny=1` and
    `device_accounts_hold=3` both sit inside the legitimate range, because a
    shared family tablet genuinely has one prior claim and three accounts. An
    off-by-one here is the difference between saving money and destroying it.
    """

    device_reuse_deny: int = 2        # legit tops out at 1
    device_accounts_hold: int = 4     # legit tops out at 3
    ip_claims_hold: int = 3           # legit tops out at 2
    fast_signup_seconds: float = 120.0
    component_hold: int = 4
    email_similarity_hold: float = 0.70


PROMO_T = PromoThresholds()


@dataclass
class PromoDecision:
    decision: str            # ALLOW | HOLD | DENY
    fired: list[str]
    reasons: list[dict]
    shared_ip_exempt: bool


def score_promo(f: dict, t: PromoThresholds = PROMO_T) -> PromoDecision:
    """Evaluate one redemption. Pure function of the 7 features and thresholds.

    Shared by ml/evaluate_promo.py and POST /v1/promo/redeem, so the measured
    numbers describe the code that actually serves traffic.
    """
    shared_ip = f.get("component_account_count", 0) > PROMO_SHARED_IP_ACCOUNTS
    device_evidence = (
        f.get("promo_redemptions_on_device", 0) >= t.device_reuse_deny
        or f.get("accounts_on_device_7d", 0) >= t.device_accounts_hold
        or f.get("payout_destination_reuse", 0) == 1
    )
    # Exempt only when the ONLY thing linking these accounts is a busy IP.
    exempt = shared_ip and not device_evidence

    fired = {
        "device_promo_reuse":
            f.get("promo_redemptions_on_device", 0) >= t.device_reuse_deny,
        "payout_reuse": f.get("payout_destination_reuse", 0) == 1,
        "device_account_cluster":
            f.get("accounts_on_device_7d", 0) >= t.device_accounts_hold,
        "ip_burst_fast_signup": (
            not exempt
            and f.get("promo_redemptions_on_ip", 0) >= t.ip_claims_hold
            and f.get("signup_to_redeem_seconds", 1e9) < t.fast_signup_seconds
        ),
        "email_cluster": (
            not exempt
            and f.get("component_account_count", 0) >= t.component_hold
            and f.get("email_pattern_similarity", 0.0) >= t.email_similarity_hold
        ),
    }

    hits = [r for r, ok in fired.items() if ok]
    decision = "ALLOW"
    if any(PROMO_RULES[r][0] == "DENY" for r in hits):
        decision = "DENY"
    elif hits:
        decision = "HOLD"

    reasons = [
        {"code": r.upper(),
         "severity": "high" if PROMO_RULES[r][0] == "DENY" else "medium",
         "detail": PROMO_RULES[r][1].format(**{k: float(f.get(k, 0)) for k in PROMO_FEATURES}),
         "source": "rule"}
        for r in hits
    ]
    return PromoDecision(decision=decision, fired=hits, reasons=reasons,
                         shared_ip_exempt=exempt)


def email_stem_similarity(email: str, others: list[str]) -> float:
    """Highest similarity between this email's local part and any other account's
    in the same cluster.

    Abusers reuse a stem: ravi+1@, ravi.k2@, ravi_3@. Normalising away plus-tags,
    dots and trailing digits collapses those to one string. Real families
    sometimes do this too (ravi1@/ravi2@), which is why a match is a HOLD signal
    and never a DENY on its own.
    """
    def stem(e: str) -> str:
        local = e.split("@", 1)[0].lower()
        local = local.split("+", 1)[0]
        local = local.replace(".", "").replace("_", "").replace("-", "")
        return re.sub(r"\d+$", "", local)

    a = stem(email)
    if not a or not others:
        return 0.0
    best = 0.0
    for o in others:
        b = stem(o)
        if not b:
            continue
        if a == b:
            return 1.0
        # Longest common prefix over the longer stem: cheap, no dependency, and
        # good enough for stem reuse. Not a general string-distance metric.
        n = 0
        for x, y in zip(a, b):
            if x != y:
                break
            n += 1
        best = max(best, n / max(len(a), len(b)))
    return round(best, 4)


# =============================================================================
# 5. Authentication
# =============================================================================
#
# Implements docs/ARCHITECTURE.md section 4: Argon2id credentials, short-lived
# JWT access tokens, rotating opaque refresh tokens with family revocation, and
# per-route role gating.
#
# What is real:
#   - Argon2id hashing, per-user salt, parameters versioned in the hash string
#   - access token: JWT HS256, 15 min, held in browser MEMORY only
#   - refresh token: 256-bit opaque, SHA-256 hashed at rest, httpOnly cookie
#   - reuse of a rotated refresh token revokes the whole family (theft signal)
#   - login rate limits per email and per client
#   - identical response shape and timing for unknown-email vs wrong-password
#
# What is NOT real yet:
#   - the DynamoDB user store is implemented but OFF by default. It is opt-in via
#     FRAUDSHIELD_USERS_BACKEND=dynamodb because enabling it creates and writes
#     to a real AWS table, which costs money and should be a deliberate act.
#   - the default in-memory store LOSES ALL USERS ON RESTART.

import hashlib
import hmac

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

# Argon2id. Parameters are on the conservative side of the RFC 9106 guidance:
# 64 MiB, 3 passes, 4 lanes. Tuned so a single verify costs ~50-100 ms, which is
# a rounding error for a human login and expensive for an offline cracker.
PWD = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4,
                     hash_len=32, salt_len=16)

ACCESS_TTL = 15 * 60             # seconds
REFRESH_TTL = 30 * 24 * 3600
ROLES = ("customer", "analyst", "admin")

_JWT_SECRET = os.environ.get("FRAUDSHIELD_JWT_SECRET", "")
if not _JWT_SECRET:
    # Ephemeral: every restart invalidates every issued token. Acceptable for a
    # local demo, unusable behind more than one worker process.
    _JWT_SECRET = secrets.token_urlsafe(48)
    _JWT_EPHEMERAL = True
else:
    _JWT_EPHEMERAL = False

USERS_BACKEND = os.environ.get("FRAUDSHIELD_USERS_BACKEND", "memory").lower()
USERS_TABLE = os.environ.get("FRAUDSHIELD_USERS_TABLE", "fraudshield")
AWS_REGION = os.environ.get("FRAUDSHIELD_AWS_REGION",
                            os.environ.get("AWS_REGION", "ap-south-1"))

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s.]+\.[^@\s]{2,}$")
MIN_PASSWORD = 10

# Rejected outright. A 10-character minimum still admits "password12", and the
# most common passwords are the first thing any credential-stuffing list tries.
WEAK_PASSWORDS = {
    "password", "password1", "password12", "password123", "passw0rd123",
    "1234567890", "12345678910", "qwertyuiop", "letmein123", "iloveyou1",
    "admin12345", "welcome123", "abc12345678", "changeme123", "fraudshield",
}


def _pw_problem(pw: str) -> str | None:
    if len(pw) < MIN_PASSWORD:
        return f"Password must be at least {MIN_PASSWORD} characters."
    if pw.lower() in WEAK_PASSWORDS:
        return "That password is too common. Choose something less predictable."
    if pw.isdigit():
        return "Password cannot be only digits."
    return None


def _norm_email(e: str) -> str:
    return e.strip().lower()


# Verified against when the email is unknown, so a failed login costs the same
# time whether or not the account exists. Without this, response timing is an
# account-enumeration oracle.
_DUMMY_HASH = PWD.hash("timing-equalisation-placeholder")

# Cookies must be Secure in production. Off by default because localhost is
# plain HTTP and a Secure cookie would simply never be sent.
COOKIE_SECURE = os.environ.get("FRAUDSHIELD_COOKIE_SECURE", "false").lower() == "true"


def _tok_hash(raw: str) -> str:
    """Refresh tokens are stored hashed. A dump of the token table must not be
    usable to mint sessions."""
    return hashlib.sha256(raw.encode()).hexdigest()


@dataclass
class User:
    user_id: str
    email: str
    password_hash: str
    role: str
    created_at: str
    status: str = "active"


class UserStore(Protocol):
    def get_by_email(self, email: str) -> User | None: ...
    def get(self, user_id: str) -> User | None: ...
    def create(self, u: User) -> bool: ...
    def save_refresh(self, user_id: str, tid: str, token_hash: str, exp: float) -> None: ...
    def take_refresh(self, user_id: str, tid: str) -> dict | None: ...
    def revoke_family(self, user_id: str) -> None: ...


class InMemoryUserStore:
    """Default. Loses every account on restart -- stated loudly at startup."""

    def __init__(self) -> None:
        self._by_email: dict[str, User] = {}
        self._by_id: dict[str, User] = {}
        self._refresh: dict[tuple[str, str], dict] = {}
        self._lock = threading.Lock()

    def get_by_email(self, email: str) -> User | None:
        return self._by_email.get(_norm_email(email))

    def get(self, user_id: str) -> User | None:
        return self._by_id.get(user_id)

    def create(self, u: User) -> bool:
        with self._lock:
            if _norm_email(u.email) in self._by_email:
                return False
            self._by_email[_norm_email(u.email)] = u
            self._by_id[u.user_id] = u
            return True

    def save_refresh(self, user_id, tid, token_hash, exp) -> None:
        with self._lock:
            self._refresh[(user_id, tid)] = {
                "token_hash": token_hash, "expires_at": exp, "used": False,
            }

    def take_refresh(self, user_id, tid) -> dict | None:
        with self._lock:
            return self._refresh.get((user_id, tid))

    def mark_used(self, user_id, tid) -> None:
        with self._lock:
            r = self._refresh.get((user_id, tid))
            if r:
                r["used"] = True

    def revoke_family(self, user_id: str) -> None:
        with self._lock:
            for k in [k for k in self._refresh if k[0] == user_id]:
                self._refresh.pop(k, None)


class DynamoUserStore:
    """Single-table adapter matching docs/ARCHITECTURE.md section 3.

    OFF BY DEFAULT. Enabling it creates and writes real AWS resources.
    Create the table first:

        aws dynamodb create-table \
          --table-name fraudshield \
          --attribute-definitions AttributeName=PK,AttributeType=S \
                                  AttributeName=SK,AttributeType=S \
          --key-schema AttributeName=PK,KeyType=HASH \
                       AttributeName=SK,KeyType=RANGE \
          --billing-mode PAY_PER_REQUEST

    The IAM principal needs GetItem, PutItem, UpdateItem, Query and
    DeleteItem on that table only. Long-lived IAM user keys are the riskiest
    AWS credential type -- prefer an instance/task role in any real deployment.
    """

    def __init__(self, table: str = USERS_TABLE, region: str = AWS_REGION):
        import boto3  # imported lazily so boto3 is not a hard dependency

        # Accept the standard names first, then the lowercase ones used in .env.
        ak = (os.environ.get("AWS_ACCESS_KEY_ID")
              or os.environ.get("access_key") or None)
        sk = (os.environ.get("AWS_SECRET_ACCESS_KEY")
              or os.environ.get("secret_key") or None)
        kw = {"region_name": region}
        if ak and sk:
            kw["aws_access_key_id"] = ak
            kw["aws_secret_access_key"] = sk
        self._t = boto3.resource("dynamodb", **kw).Table(table)

    def get_by_email(self, email: str) -> User | None:
        idx = self._t.get_item(
            Key={"PK": f"EMAIL#{_norm_email(email)}", "SK": "USER"}
        ).get("Item")
        return self.get(idx["user_id"]) if idx else None

    def get(self, user_id: str) -> User | None:
        it = self._t.get_item(
            Key={"PK": f"USER#{user_id}", "SK": "PROFILE"}
        ).get("Item")
        if not it:
            return None
        return User(
            user_id=user_id, email=it["email"], password_hash=it["password_hash"],
            role=it.get("role", "customer"), created_at=it.get("created_at", ""),
            status=it.get("status", "active"),
        )

    def create(self, u: User) -> bool:
        from botocore.exceptions import ClientError

        try:
            # Conditional put on the email index enforces uniqueness atomically.
            self._t.put_item(
                Item={"PK": f"EMAIL#{_norm_email(u.email)}", "SK": "USER",
                      "user_id": u.user_id},
                ConditionExpression="attribute_not_exists(PK)",
            )
        except ClientError as e:
            if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
                return False
            raise
        self._t.put_item(Item={
            "PK": f"USER#{u.user_id}", "SK": "PROFILE", "email": u.email,
            "password_hash": u.password_hash, "role": u.role,
            "created_at": u.created_at, "status": u.status,
        })
        return True

    def save_refresh(self, user_id, tid, token_hash, exp) -> None:
        self._t.put_item(Item={
            "PK": f"USER#{user_id}", "SK": f"RT#{tid}",
            "token_hash": token_hash, "expires_at": int(exp),
            "used": False, "ttl": int(exp) + 86400,
        })

    def take_refresh(self, user_id, tid) -> dict | None:
        return self._t.get_item(
            Key={"PK": f"USER#{user_id}", "SK": f"RT#{tid}"}
        ).get("Item")

    def mark_used(self, user_id, tid) -> None:
        self._t.update_item(
            Key={"PK": f"USER#{user_id}", "SK": f"RT#{tid}"},
            UpdateExpression="SET #u = :t", ExpressionAttributeNames={"#u": "used"},
            ExpressionAttributeValues={":t": True},
        )

    def revoke_family(self, user_id: str) -> None:
        items = self._t.query(
            KeyConditionExpression=(
                "PK = :p AND begins_with(SK, :s)"
            ),
            ExpressionAttributeValues={":p": f"USER#{user_id}", ":s": "RT#"},
        ).get("Items", [])
        for it in items:
            self._t.delete_item(Key={"PK": it["PK"], "SK": it["SK"]})


class InMemoryRecordStore:
    """Orders, returns and the review queue when DynamoDB is off. Lost on restart."""

    def __init__(self) -> None:
        self._items: dict[tuple[str, str], dict] = {}
        self._lock = threading.Lock()

    def put(self, pk: str, sk: str, item: dict) -> None:
        with self._lock:
            self._items[(pk, sk)] = {**item, "PK": pk, "SK": sk}

    def get(self, pk: str, sk: str) -> dict | None:
        return self._items.get((pk, sk))

    def query_prefix(self, pk: str, sk_prefix: str, desc: bool = True) -> list[dict]:
        rows = [
            v for (p, s), v in self._items.items()
            if p == pk and s.startswith(sk_prefix)
        ]
        rows.sort(key=lambda r: r["SK"], reverse=desc)
        return rows

    def update_fields(self, pk: str, sk: str, fields: dict) -> None:
        with self._lock:
            it = self._items.get((pk, sk))
            if it:
                it.update(fields)


class DynamoRecordStore:
    """Same interface, backed by the single table."""

    def __init__(self, table: str = USERS_TABLE, region: str = AWS_REGION):
        import boto3

        ak = os.environ.get("AWS_ACCESS_KEY_ID") or os.environ.get("access_key")
        sk = os.environ.get("AWS_SECRET_ACCESS_KEY") or os.environ.get("secret_key")
        kw = {"region_name": region}
        if ak and sk:
            kw["aws_access_key_id"] = ak
            kw["aws_secret_access_key"] = sk
        self._t = boto3.resource("dynamodb", **kw).Table(table)

    @staticmethod
    def _clean(v):
        """DynamoDB has no float type. Decimal round-trips exactly; float does not,
        so amounts and scores are stored as strings-to-Decimal via this coercion."""
        from decimal import Decimal

        if isinstance(v, float):
            return Decimal(str(round(v, 4)))
        if isinstance(v, dict):
            return {k: DynamoRecordStore._clean(x) for k, x in v.items()}
        if isinstance(v, (list, tuple)):
            return [DynamoRecordStore._clean(x) for x in v]
        return v

    @staticmethod
    def _unclean(v):
        from decimal import Decimal

        if isinstance(v, Decimal):
            f = float(v)
            return int(f) if f.is_integer() else f
        if isinstance(v, dict):
            return {k: DynamoRecordStore._unclean(x) for k, x in v.items()}
        if isinstance(v, list):
            return [DynamoRecordStore._unclean(x) for x in v]
        return v

    def put(self, pk: str, sk: str, item: dict) -> None:
        self._t.put_item(Item=self._clean({**item, "PK": pk, "SK": sk}))

    def get(self, pk: str, sk: str) -> dict | None:
        it = self._t.get_item(Key={"PK": pk, "SK": sk}).get("Item")
        return self._unclean(it) if it else None

    def query_prefix(self, pk: str, sk_prefix: str, desc: bool = True) -> list[dict]:
        r = self._t.query(
            KeyConditionExpression="PK = :p AND begins_with(SK, :s)",
            ExpressionAttributeValues={":p": pk, ":s": sk_prefix},
            ScanIndexForward=not desc,
        )
        return [self._unclean(i) for i in r.get("Items", [])]

    def update_fields(self, pk: str, sk: str, fields: dict) -> None:
        names = {f"#f{i}": k for i, k in enumerate(fields)}
        vals = {f":v{i}": self._clean(v) for i, v in enumerate(fields.values())}
        expr = "SET " + ", ".join(
            f"{n} = {v}" for n, v in zip(names, vals)
        )
        self._t.update_item(
            Key={"PK": pk, "SK": sk}, UpdateExpression=expr,
            ExpressionAttributeNames=names, ExpressionAttributeValues=vals,
        )


def make_record_store() -> tuple[object, str]:
    if USERS_BACKEND == "dynamodb":
        try:
            return DynamoRecordStore(), f"dynamodb:{USERS_TABLE}"
        except Exception as exc:  # noqa: BLE001
            print(f"WARNING: DynamoDB record store unavailable ({type(exc).__name__}). "
                  "Orders and returns will not persist.")
    return InMemoryRecordStore(), "memory (orders lost on restart)"


def make_user_store() -> tuple[UserStore, str]:
    if USERS_BACKEND == "dynamodb":
        try:
            return DynamoUserStore(), f"dynamodb:{USERS_TABLE}@{AWS_REGION}"
        except Exception as exc:  # noqa: BLE001
            print(f"WARNING: DynamoDB user store unavailable ({type(exc).__name__}: "
                  f"{exc}). Falling back to in-memory; accounts will not persist.")
    return InMemoryUserStore(), "memory (accounts lost on restart)"


# ---- rate limiting -------------------------------------------------------
# Credential stuffing is the reason this exists. Two independent buckets so
# neither a single account nor a single source can be hammered.
_ATTEMPTS: dict[str, deque] = defaultdict(deque)
_RL_LOCK = threading.Lock()
LOGIN_MAX_PER_EMAIL = 5
LOGIN_MAX_PER_CLIENT = 20
LOGIN_WINDOW = 15 * 60


def _rate_limited(key: str, limit: int) -> bool:
    now = time.time()
    with _RL_LOCK:
        dq = _ATTEMPTS[key]
        while dq and now - dq[0] > LOGIN_WINDOW:
            dq.popleft()
        if len(dq) >= limit:
            return True
        dq.append(now)
        return False


# ---- tokens --------------------------------------------------------------


def issue_access(u: User) -> str:
    now = int(time.time())
    return jwt.encode(
        {"sub": u.user_id, "email": u.email, "role": u.role,
         "iat": now, "exp": now + ACCESS_TTL, "jti": uuid.uuid4().hex},
        _JWT_SECRET, algorithm="HS256",
    )


def issue_refresh(store: UserStore, u: User) -> str:
    tid = uuid.uuid4().hex
    raw = secrets.token_urlsafe(32)
    store.save_refresh(u.user_id, tid, _tok_hash(raw), time.time() + REFRESH_TTL)
    # user_id is in the cookie so /refresh needs no prior access token.
    return f"{u.user_id}.{tid}.{raw}"


def decode_access(token: str) -> dict:
    return jwt.decode(token, _JWT_SECRET, algorithms=["HS256"])


# =============================================================================
# 6. FastAPI application
# =============================================================================

STATE: dict = {
    "store": None, "scorer": None, "queue": [], "txns": {},
    "users": None, "users_backend": "?", "records": None, "records_backend": "?",
    "promo_queue": [],
}


def warm_store(store: InMemoryStore, limit: int, csv: Path = DATA_CSV) -> int:
    """Replay historical traffic so device/IP/velocity counters are populated.

    Without this every request hits a cold graph and looks like a brand-new
    entity, which is exactly the case the network layer cannot score.

    TRAIN SPLIT ONLY. Warming from validation or test would leak the evaluation
    period into serving state.
    """
    if not csv.exists():
        return 0
    df = pd.read_csv(csv)
    df = df[df.split == "train"].sort_values("ts_epoch")
    if limit:
        df = df.tail(limit)
    for r in df.groupby("customer_id", sort=False).head(1).itertuples():
        store.register_customer(r.customer_id, float(r.account_created_at))
    for r in df.itertuples():
        dt = datetime.fromtimestamp(float(r.ts_epoch), tz=timezone.utc)
        store.commit({
            "customer_id": r.customer_id, "ts": float(r.ts_epoch),
            "amount": float(r.amount), "payment_method": r.payment_method,
            "device_fp": r.device_fp, "ip_hash": r.ip_hash, "status": r.status,
            "hour": dt.hour + dt.minute / 60.0,
        })
    return len(df)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    store = InMemoryStore()
    n = warm_store(store, WARM_ROWS)
    scorer = Scorer()
    users, backend_desc = make_user_store()

    # Local-development convenience only. With the in-memory store there is no
    # out-of-band way to create a staff account, so the console would be
    # unreachable. Gated behind an explicit env var and prints a random password
    # rather than shipping a known one.
    if os.environ.get("FRAUDSHIELD_DEV_SEED_STAFF") == "1":
        pw = secrets.token_urlsafe(12)
        seeded = User(
            user_id=uuid.uuid4().hex, email="analyst@fraudshield.local",
            password_hash=PWD.hash(pw), role="analyst",
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        if users.create(seeded):
            print("\n  DEV SEED (never enable outside local development)")
            print(f"    analyst@fraudshield.local  /  {pw}\n")

    records, records_desc = make_record_store()
    STATE["store"] = store
    STATE["scorer"] = scorer
    STATE["users"] = users
    STATE["users_backend"] = backend_desc
    STATE["records"] = records
    STATE["records_backend"] = records_desc
    print(f"warmed store with {n:,} historical transactions")
    print(f"model: {'DEGRADED (no artifact)' if scorer.degraded else scorer.model_version}")
    print(f"thresholds: review >= {scorer.review_t}, block >= {scorer.block_t}")
    print(f"user store:   {backend_desc}")
    print(f"record store: {records_desc}")
    if not API_KEY:
        print("WARNING: FRAUDSHIELD_API_KEY is unset -- service endpoints are OPEN. "
              "Set it before exposing this service anywhere.")
    if _JWT_EPHEMERAL:
        print("WARNING: FRAUDSHIELD_JWT_SECRET is unset. Using an ephemeral secret: "
              "every restart invalidates all sessions, and multiple workers will "
              "reject each other's tokens.")
    yield
    STATE.clear()


app = FastAPI(
    title="FraudShield",
    description="Defense-only transaction risk scoring. Returns a decision and "
                "evidence, never a fraud verdict.",
    version="0.4.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    # Needed for the httpOnly refresh cookie. Safe only because the origin list
    # is explicit -- a wildcard with credentials is rejected by browsers, and
    # would be a serious hole if it were not.
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["x-api-key", "content-type", "authorization"],
)


def require_key(x_api_key: str = Header(default="")) -> None:
    """Service-to-service guard. A payment gateway calling the scorer server-side
    has no user session, so a shared key is the right shape there. It is NOT
    accepted on admin routes -- those need a real identity."""
    if not API_KEY:
        return  # open mode, warned about at startup
    if not secrets.compare_digest(x_api_key, API_KEY):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid or missing API key")


def current_user(authorization: str = Header(default="")) -> User:
    if not authorization.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing bearer token")
    try:
        claims = decode_access(authorization[7:])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "token expired") from None
    except jwt.PyJWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid token") from None
    u = STATE["users"].get(claims["sub"])
    if u is None or u.status != "active":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "account not active")
    return u


def require_role(*allowed: str):
    """Role gating, enforced server-side on every request.

    A hidden button in the React router is a UX affordance, not a security
    control. This is the control.
    """

    def dep(u: User = Depends(current_user)) -> User:
        if u.role not in allowed:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"role '{u.role}' cannot access this resource",
            )
        return u

    return dep


class ScoreRequest(BaseModel):
    customer_id: str
    amount: float = Field(gt=0)
    payment_method: str
    device_fp: str
    ip_hash: str
    ts: float | None = Field(default=None, description="epoch seconds; defaults to now")
    status: str = Field(default="success", pattern="^(success|failed)$")
    commit: bool = Field(default=True,
                         description="apply this transaction to entity state after scoring")


class SubScores(BaseModel):
    ml: float
    rules: float
    network: float


class ScoreResponse(BaseModel):
    transaction_id: str
    risk_score: float
    decision: str
    sub_scores: SubScores
    reason_codes: list
    override: str | None
    model_version: str
    degraded: bool
    scored_at: str
    latency_ms: float


class CustomerView(BaseModel):
    """Allow-list projection. A customer must never see a score, a sub-score or a
    reason code -- telling an attacker which signal fired is free reconnaissance."""

    order_id: str
    status: str
    message: str


class OutcomeRequest(BaseModel):
    label: str = Field(pattern="^(fraud|legitimate)$")
    analyst_id: str = "unknown"


class RegisterRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=1024)


class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=1024)


class PublicUser(BaseModel):
    user_id: str
    email: str
    role: str
    created_at: str


class AuthResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: PublicUser


# ---------------------------------------------------------------------------
# auth routes
# ---------------------------------------------------------------------------

REFRESH_COOKIE = "fs_refresh"


def _set_refresh_cookie(response: Response, raw: str) -> None:
    response.set_cookie(
        REFRESH_COOKIE, raw,
        httponly=True,              # unreadable from JavaScript, so XSS cannot lift it
        samesite="lax",
        secure=COOKIE_SECURE,       # MUST be True in production; see .env.example
        max_age=REFRESH_TTL,
        path="/v1/auth",
    )


def _public(u: User) -> PublicUser:
    return PublicUser(user_id=u.user_id, email=u.email, role=u.role,
                      created_at=u.created_at)


@app.post("/v1/auth/register", response_model=AuthResponse, status_code=201)
def register(req: RegisterRequest, response: Response) -> AuthResponse:
    email = _norm_email(req.email)
    if not EMAIL_RE.match(email):
        raise HTTPException(422, "Enter a valid email address.")
    problem = _pw_problem(req.password)
    if problem:
        raise HTTPException(422, problem)

    users: UserStore = STATE["users"]
    u = User(
        user_id=uuid.uuid4().hex,
        email=email,
        password_hash=PWD.hash(req.password),
        # Self-service signup ALWAYS produces a customer. Analyst and admin roles
        # can only be granted by a direct write to the user store -- there is no
        # API path to privilege escalation.
        role="customer",
        created_at=datetime.now(timezone.utc).isoformat(),
    )
    if not users.create(u):
        # Deliberately the same message a caller gets for any conflict, so this
        # endpoint is not an email-enumeration oracle.
        raise HTTPException(409, "That email cannot be registered.")

    _set_refresh_cookie(response, issue_refresh(users, u))
    return AuthResponse(access_token=issue_access(u), expires_in=ACCESS_TTL,
                        user=_public(u))


@app.post("/v1/auth/login", response_model=AuthResponse)
def login(req: LoginRequest, response: Response,
          x_forwarded_for: str = Header(default="local")) -> AuthResponse:
    email = _norm_email(req.email)

    if _rate_limited(f"e:{email}", LOGIN_MAX_PER_EMAIL) or \
       _rate_limited(f"c:{x_forwarded_for}", LOGIN_MAX_PER_CLIENT):
        raise HTTPException(429, "Too many attempts. Try again in a few minutes.")

    users: UserStore = STATE["users"]
    u = users.get_by_email(email)

    # Verify against a dummy hash when the user does not exist, so an attacker
    # cannot distinguish unknown-email from wrong-password by response time.
    if u is None:
        try:
            PWD.verify(_DUMMY_HASH, "not-the-password")
        except (VerifyMismatchError, InvalidHashError):
            pass
        raise HTTPException(401, "Incorrect email or password.")

    try:
        PWD.verify(u.password_hash, req.password)
    except (VerifyMismatchError, InvalidHashError):
        raise HTTPException(401, "Incorrect email or password.") from None

    if u.status != "active":
        raise HTTPException(403, "This account is not active.")

    _set_refresh_cookie(response, issue_refresh(users, u))
    return AuthResponse(access_token=issue_access(u), expires_in=ACCESS_TTL,
                        user=_public(u))


@app.post("/v1/auth/refresh", response_model=AuthResponse)
def refresh(request: Request, response: Response) -> AuthResponse:
    raw = request.cookies.get(REFRESH_COOKIE, "")
    parts = raw.split(".")
    if len(parts) != 3:
        raise HTTPException(401, "No valid session.")
    user_id, tid, secret = parts

    users: UserStore = STATE["users"]
    rec = users.take_refresh(user_id, tid)
    if rec is None:
        raise HTTPException(401, "No valid session.")

    # Rotation + theft detection: a token id is single-use. Seeing it twice means
    # either a replay or a stolen cookie, and we cannot tell which, so the safe
    # move is to kill every session for the account.
    if rec.get("used"):
        users.revoke_family(user_id)
        raise HTTPException(
            401, "Session reuse detected. All sessions were revoked; please log in."
        )
    if float(rec["expires_at"]) < time.time():
        raise HTTPException(401, "Session expired.")
    if not hmac.compare_digest(rec["token_hash"], _tok_hash(secret)):
        users.revoke_family(user_id)
        raise HTTPException(401, "Invalid session.")

    u = users.get(user_id)
    if u is None or u.status != "active":
        raise HTTPException(401, "Account not active.")

    users.mark_used(user_id, tid)
    _set_refresh_cookie(response, issue_refresh(users, u))
    return AuthResponse(access_token=issue_access(u), expires_in=ACCESS_TTL,
                        user=_public(u))


@app.post("/v1/auth/logout")
def logout(request: Request, response: Response) -> dict:
    raw = request.cookies.get(REFRESH_COOKIE, "")
    parts = raw.split(".")
    if len(parts) == 3:
        STATE["users"].revoke_family(parts[0])
    response.delete_cookie(REFRESH_COOKIE, path="/v1/auth")
    return {"ok": True}


@app.get("/v1/auth/me", response_model=PublicUser)
def me(u: User = Depends(current_user)) -> PublicUser:
    return _public(u)


# ---------------------------------------------------------------------------
# orders and returns  (the customer dashboard's backing endpoints)
# ---------------------------------------------------------------------------

CATALOGUE = {
    "p1": {"name": "Wireless earbuds", "price": 2499.0},
    "p2": {"name": "Mechanical keyboard", "price": 6799.0},
    "p3": {"name": "Smartphone", "price": 42999.0},
    "p4": {"name": "Phone case", "price": 449.0},
}

CUSTOMER_MESSAGE = {
    "ALLOW": ("confirmed", "Order confirmed."),
    "MANUAL_REVIEW": ("verifying",
                      "We're verifying your payment. This usually takes about "
                      "2 minutes."),
    "BLOCK": ("declined",
              "We couldn't process this payment. Please try a different method "
              "or contact support."),
}


class OrderRequest(BaseModel):
    product_id: str
    payment_method: str = Field(pattern="^(upi|card|netbanking|wallet|cod)$")
    device_fp: str = Field(min_length=3, max_length=128)
    ip_hash: str = Field(min_length=3, max_length=128)


class ReturnRequest(BaseModel):
    order_id: str
    reason: str = Field(min_length=3, max_length=60)
    detail: str = Field(default="", max_length=500)


@app.get("/v1/catalog/products")
def catalog() -> dict:
    return {"products": [{"id": k, **v} for k, v in CATALOGUE.items()]}


@app.post("/v1/orders", status_code=201)
def create_order(req: OrderRequest, u: User = Depends(current_user)) -> dict:
    """Create an order, score it, persist it.

    The response is role-dependent: a customer gets status and a message, staff
    additionally get the risk breakdown. Enforced here rather than in the client,
    because a customer who can read reason codes learns which signal to avoid.
    """
    product = CATALOGUE.get(req.product_id)
    if product is None:
        raise HTTPException(404, "Unknown product.")

    store: InMemoryStore = STATE["store"]
    scorer: Scorer = STATE["scorer"]
    records = STATE["records"]

    ts = datetime.now(timezone.utc).timestamp()
    # The scorer keys on customer_id, so the account IS the risk subject. Using
    # anything client-supplied here would let a caller reset their own history.
    txn = {
        "customer_id": u.user_id, "ts": ts, "amount": product["price"],
        "payment_method": req.payment_method, "device_fp": req.device_fp,
        "ip_hash": req.ip_hash,
    }

    try:
        d, raw = scorer.score(store, txn)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            503, detail={"decision": "MANUAL_REVIEW", "reason": "SCORING_UNAVAILABLE",
                         "error": type(exc).__name__},
        ) from exc

    settled = "failed" if d.decision == "BLOCK" else "success"
    # Read-before-write: features were read above; state is applied only now.
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    store.commit({**txn, "status": settled, "hour": dt.hour + dt.minute / 60.0})

    order_id = f"ord_{uuid.uuid4().hex[:10]}"
    txn_id = f"pay_{uuid.uuid4().hex[:10]}"
    status_key, message = CUSTOMER_MESSAGE[d.decision]

    record = {
        "order_id": order_id, "transaction_id": txn_id, "customer_id": u.user_id,
        "email": u.email, "product_id": req.product_id,
        "product_name": product["name"], "amount": product["price"],
        "payment_method": req.payment_method, "created_at": dt.isoformat(),
        "customer_status": status_key, "risk_score": d.risk_score,
        "decision": d.decision, "sub_scores": d.sub_scores,
        "reason_codes": d.reason_codes, "fired_rules": d.fired_rules,
        "override": d.override, "return_status": None, "label": None,
    }
    records.put(f"CUSTOMER#{u.user_id}", f"ORDER#{dt.isoformat()}#{order_id}", record)
    records.put("INDEX#ORDER", order_id, {"customer_id": u.user_id,
                                          "sk": f"ORDER#{dt.isoformat()}#{order_id}"})

    STATE["txns"][txn_id] = {**record, "features": raw, "scored_at": dt.isoformat()}
    if d.decision in ("MANUAL_REVIEW", "BLOCK"):
        STATE["queue"].append(txn_id)

    out: dict = {"order_id": order_id, "status": status_key, "message": message,
                 "product_name": product["name"], "amount": product["price"]}
    if u.role in ("analyst", "admin"):
        out["risk"] = {
            "transaction_id": txn_id, "risk_score": d.risk_score,
            "decision": d.decision, "sub_scores": d.sub_scores,
            "reason_codes": d.reason_codes, "override": d.override,
        }
    return out


def _customer_order_view(r: dict, staff: bool) -> dict:
    """Allow-list projection. Adding a field to the stored record must not leak it
    to customers by default, so this enumerates what they may see."""
    view = {
        "order_id": r["order_id"], "product_name": r.get("product_name"),
        "amount": r.get("amount"), "payment_method": r.get("payment_method"),
        "created_at": r.get("created_at"), "status": r.get("customer_status"),
        "return_status": r.get("return_status"),
    }
    if staff:
        view |= {
            "risk_score": r.get("risk_score"), "decision": r.get("decision"),
            "sub_scores": r.get("sub_scores"), "transaction_id": r.get("transaction_id"),
        }
    return view


@app.get("/v1/orders")
def list_orders(u: User = Depends(current_user)) -> dict:
    rows = STATE["records"].query_prefix(f"CUSTOMER#{u.user_id}", "ORDER#")
    staff = u.role in ("analyst", "admin")
    return {"count": len(rows),
            "orders": [_customer_order_view(r, staff) for r in rows]}


def _find_order(user_id: str, order_id: str) -> dict | None:
    idx = STATE["records"].get("INDEX#ORDER", order_id)
    if idx is None or idx.get("customer_id") != user_id:
        return None
    return STATE["records"].get(f"CUSTOMER#{user_id}", idx["sk"])


@app.get("/v1/orders/{order_id}")
def get_order(order_id: str, u: User = Depends(current_user)) -> dict:
    r = _find_order(u.user_id, order_id)
    # Same 404 whether the order does not exist or belongs to someone else. A
    # distinguishable response would let a caller enumerate other people's orders.
    if r is None:
        raise HTTPException(404, "Order not found.")
    return _customer_order_view(r, u.role in ("analyst", "admin"))


@app.post("/v1/returns", status_code=201)
def request_return(req: ReturnRequest, u: User = Depends(current_user)) -> dict:
    r = _find_order(u.user_id, req.order_id)
    if r is None:
        raise HTTPException(404, "Order not found.")
    if r.get("customer_status") != "confirmed":
        raise HTTPException(409, "Only confirmed orders can be returned.")
    if r.get("return_status"):
        raise HTTPException(409, "A return has already been requested.")

    now = datetime.now(timezone.utc).isoformat()
    return_id = f"ret_{uuid.uuid4().hex[:10]}"
    records = STATE["records"]
    records.put(f"CUSTOMER#{u.user_id}", f"RETURN#{now}#{return_id}", {
        "return_id": return_id, "order_id": req.order_id,
        "customer_id": u.user_id, "reason": req.reason, "detail": req.detail,
        "amount": r.get("amount"), "product_name": r.get("product_name"),
        "created_at": now, "status": "under_review",
    })
    idx = records.get("INDEX#ORDER", req.order_id)
    if idx:
        records.update_fields(f"CUSTOMER#{u.user_id}", idx["sk"],
                              {"return_status": "under_review"})

    # Every return goes to a human. Return abuse recall is 0.455 at payment time
    # (docs/EVALUATION.md section 3), so auto-approving on the transaction score
    # would be approving on evidence we know is weak.
    return {"return_id": return_id, "status": "under_review",
            "message": "Return request received. We'll email you within 2 business days."}


# ---------------------------------------------------------------------------
# promotion redemption
# ---------------------------------------------------------------------------

PROMOS = {
    "WELCOME500": {"name": "Welcome cashback", "value": 500.0,
                   "blurb": "Rs 500 back on your first order"},
    "FESTIVE250": {"name": "Festive bonus", "value": 250.0,
                   "blurb": "Rs 250 back this week"},
}


class RedeemRequest(BaseModel):
    promo_code: str = Field(min_length=3, max_length=32)
    device_fp: str = Field(min_length=3, max_length=128)
    ip_hash: str = Field(min_length=3, max_length=128)
    payout_ref: str = Field(min_length=3, max_length=128,
                            description="UPI id or bank ref receiving the cashback")


def _promo_features(u: User, req: RedeemRequest) -> dict:
    """Build the 7 documented features from live state.

    Reads the same entity graph the transaction scorer uses (device and IP
    adjacency) plus promo-specific counters from the record store.
    """
    records = STATE["records"]
    entity: InMemoryStore = STATE["store"]
    users: UserStore = STATE["users"]
    code = req.promo_code.upper()

    dev_hits = records.query_prefix(f"PROMODEV#{req.device_fp}", f"{code}#")
    ip_hits = records.query_prefix(f"PROMOIP#{req.ip_hash}", f"{code}#")
    payout_hits = records.query_prefix(f"PAYOUT#{req.payout_ref}", f"{code}#")

    # Distinct accounts seen on this device, from the transaction entity graph
    # plus anyone who redeemed from it. A brand-new device has neither.
    dev_accounts = set(entity.device_accounts(req.device_fp))
    dev_accounts |= {h["customer_id"] for h in dev_hits}
    dev_accounts.add(u.user_id)

    component = set(dev_accounts)
    ip_accounts = set(entity.ip_accounts(req.ip_hash)) | {
        h["customer_id"] for h in ip_hits
    }
    component |= ip_accounts

    others = []
    for cid in component:
        if cid == u.user_id:
            continue
        other = users.get(cid)
        if other is not None:
            others.append(other.email)

    try:
        created = datetime.fromisoformat(u.created_at).timestamp()
    except (ValueError, TypeError):
        created = time.time()

    return {
        "promo_redemptions_on_device": len(dev_hits),
        "promo_redemptions_on_ip": len(ip_hits),
        "accounts_on_device_7d": len(dev_accounts),
        "signup_to_redeem_seconds": max(0.0, time.time() - created),
        "email_pattern_similarity": email_stem_similarity(u.email, others),
        "component_account_count": len(component),
        "payout_destination_reuse": 1 if payout_hits else 0,
    }


@app.get("/v1/promo/offers")
def promo_offers() -> dict:
    return {"offers": [{"code": k, **v} for k, v in PROMOS.items()]}


@app.post("/v1/promo/redeem", status_code=201)
def redeem_promo(req: RedeemRequest, u: User = Depends(current_user)) -> dict:
    """Claim an offer. ALLOW credits it, HOLD queues it, DENY refuses it.

    A refused cashback is not a refused sale: the customer can still buy, and a
    wrong denial is reversible from the admin queue with one click. That is why
    the rules are more aggressive than anything acceptable at checkout.
    """
    code = req.promo_code.upper()
    promo = PROMOS.get(code)
    if promo is None:
        raise HTTPException(404, "Unknown promotion.")

    records = STATE["records"]
    if records.query_prefix(f"CUSTOMER#{u.user_id}", f"PROMO#{code}#"):
        raise HTTPException(409, "You have already claimed this promotion.")

    feats = _promo_features(u, req)
    d = score_promo(feats)

    now = datetime.now(timezone.utc).isoformat()
    rid = f"rdm_{uuid.uuid4().hex[:10]}"
    status_map = {"ALLOW": "credited", "HOLD": "under_review", "DENY": "denied"}
    state = status_map[d.decision]

    record = {
        "redemption_id": rid, "promo_code": code, "customer_id": u.user_id,
        "email": u.email, "value": promo["value"], "created_at": now,
        "status": state, "decision": d.decision, "fired_rules": d.fired,
        "reasons": d.reasons, "features": feats,
        "shared_ip_exempt": d.shared_ip_exempt,
        "device_fp": req.device_fp, "ip_hash": req.ip_hash,
        "payout_ref": req.payout_ref, "override_by": None,
    }
    records.put(f"CUSTOMER#{u.user_id}", f"PROMO#{code}#{now}", record)
    records.put("INDEX#PROMO", rid, {"customer_id": u.user_id,
                                     "sk": f"PROMO#{code}#{now}"})

    # Counters are written even on DENY. An abuser who is refused must still
    # count against the device and payout, or retrying with a new account would
    # see a clean slate every time.
    records.put(f"PROMODEV#{req.device_fp}", f"{code}#{now}#{u.user_id}",
                {"customer_id": u.user_id, "redemption_id": rid})
    records.put(f"PROMOIP#{req.ip_hash}", f"{code}#{now}#{u.user_id}",
                {"customer_id": u.user_id, "redemption_id": rid})
    if d.decision != "DENY":
        # Only a credited or pending payout occupies the destination. A denied
        # one never pays out, so blocking that destination forever would punish
        # a legitimate retry.
        records.put(f"PAYOUT#{req.payout_ref}", f"{code}#{now}#{u.user_id}",
                    {"customer_id": u.user_id, "redemption_id": rid})

    if d.decision in ("HOLD", "DENY"):
        STATE["promo_queue"].append(rid)

    message = {
        "credited": f"Rs {promo['value']:.0f} credited to your account.",
        "under_review": "We're reviewing this claim. You'll hear from us within "
                        "2 business days.",
        "denied": "This promotion isn't available on your account. If you think "
                  "that's wrong, contact support.",
    }[state]

    out: dict = {"redemption_id": rid, "promo_code": code, "status": state,
                 "message": message}
    if u.role in ("analyst", "admin"):
        # Reason codes are staff-only. Telling a promo abuser which signal fired
        # tells them exactly what to rotate next.
        out["risk"] = {"decision": d.decision, "fired_rules": d.fired,
                       "reasons": d.reasons, "features": feats,
                       "shared_ip_exempt": d.shared_ip_exempt}
    return out


@app.get("/v1/promo/mine")
def my_promos(u: User = Depends(current_user)) -> dict:
    rows = STATE["records"].query_prefix(f"CUSTOMER#{u.user_id}", "PROMO#")
    return {"count": len(rows), "redemptions": [
        {"redemption_id": r["redemption_id"], "promo_code": r["promo_code"],
         "value": r["value"], "status": r["status"], "created_at": r["created_at"]}
        for r in rows
    ]}


@app.get("/v1/admin/promo-holds",
         dependencies=[Depends(require_role("analyst", "admin"))])
def promo_holds(limit: int = 50) -> dict:
    records = STATE["records"]
    items = []
    for rid in STATE["promo_queue"]:
        idx = records.get("INDEX#PROMO", rid)
        if idx is None:
            continue
        r = records.get(f"CUSTOMER#{idx['customer_id']}", idx["sk"])
        if r and r.get("override_by") is None:
            items.append(r)
    items.sort(key=lambda r: r["created_at"], reverse=True)
    return {"count": len(items), "items": items[:limit]}


@app.post("/v1/admin/promo-holds/{rid}/override",
          dependencies=[Depends(require_role("analyst", "admin"))])
def promo_override(rid: str, actor: User = Depends(require_role("analyst", "admin"))) -> dict:
    """Grant a held or denied offer.

    Overrides are the ONLY label source for this gate -- it ships with no training
    data, so an analyst reversing a decision is how we learn the rules are wrong.
    """
    records = STATE["records"]
    idx = records.get("INDEX#PROMO", rid)
    if idx is None:
        raise HTTPException(404, "Unknown redemption.")
    pk, sk = f"CUSTOMER#{idx['customer_id']}", idx["sk"]
    r = records.get(pk, sk)
    if r is None:
        raise HTTPException(404, "Unknown redemption.")

    records.update_fields(pk, sk, {
        "status": "credited", "override_by": actor.email,
        "override_at": datetime.now(timezone.utc).isoformat(),
        "label": "legitimate",
    })
    if rid in STATE["promo_queue"]:
        STATE["promo_queue"].remove(rid)
    return {"redemption_id": rid, "status": "credited",
            "note": "override recorded as a false-positive label for this gate"}


@app.get("/v1/returns")
def list_returns(u: User = Depends(current_user)) -> dict:
    rows = STATE["records"].query_prefix(f"CUSTOMER#{u.user_id}", "RETURN#")
    return {"count": len(rows), "returns": [
        {k: v for k, v in r.items() if k not in ("PK", "SK", "customer_id")}
        for r in rows
    ]}


@app.get("/health")
def health() -> dict:
    s: Scorer = STATE["scorer"]
    return {
        "status": "ok",
        "model_loaded": s is not None and not s.degraded,
        "model_version": s.model_version if s else None,
        "thresholds": {"review": s.review_t, "block": s.block_t} if s else None,
        "store": "in-memory (DynamoDB adapter not built)",
        "service_auth": "api-key" if API_KEY else "OPEN -- set FRAUDSHIELD_API_KEY",
        "user_auth": "jwt + argon2id",
        "user_store": STATE.get("users_backend"),
        "record_store": STATE.get("records_backend"),
        "admin_requires_role": ["analyst", "admin"],
    }


@app.post("/v1/risk/score", response_model=ScoreResponse,
          dependencies=[Depends(require_key)])
def score(req: ScoreRequest) -> ScoreResponse:
    """Analyst-facing scoring. Full evidence."""
    store: InMemoryStore = STATE["store"]
    scorer: Scorer = STATE["scorer"]
    ts = req.ts if req.ts is not None else datetime.now(timezone.utc).timestamp()
    txn = {
        "customer_id": req.customer_id, "ts": ts, "amount": req.amount,
        "payment_method": req.payment_method, "device_fp": req.device_fp,
        "ip_hash": req.ip_hash,
    }

    t0 = time.perf_counter()
    try:
        d, raw = scorer.score(store, txn)
    except Exception as exc:  # noqa: BLE001
        # Fail to a human, never silently allow. Failing open would make the
        # engine bypassable by inducing errors; failing closed would kill
        # legitimate checkout.
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"decision": "MANUAL_REVIEW", "reason": "SCORING_UNAVAILABLE",
                    "error": type(exc).__name__},
        ) from exc
    latency = (time.perf_counter() - t0) * 1000

    txn_id = f"pay_{uuid.uuid4().hex[:10]}"

    # Read-before-write: features were read above, state is applied only now.
    if req.commit:
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        store.commit({**txn, "status": req.status, "hour": dt.hour + dt.minute / 60.0})

    record = {
        "transaction_id": txn_id, "customer_id": req.customer_id,
        "amount": req.amount, "risk_score": d.risk_score, "decision": d.decision,
        "sub_scores": d.sub_scores, "reason_codes": d.reason_codes,
        "fired_rules": d.fired_rules, "override": d.override, "features": raw,
        "scored_at": datetime.now(timezone.utc).isoformat(), "label": None,
    }
    STATE["txns"][txn_id] = record
    if d.decision in ("MANUAL_REVIEW", "BLOCK"):
        STATE["queue"].append(txn_id)

    return ScoreResponse(
        transaction_id=txn_id, risk_score=d.risk_score, decision=d.decision,
        sub_scores=SubScores(**d.sub_scores), reason_codes=d.reason_codes,
        override=d.override, model_version=d.model_version, degraded=d.degraded,
        scored_at=record["scored_at"], latency_ms=round(latency, 2),
    )


@app.post("/v1/checkout", response_model=CustomerView,
          dependencies=[Depends(require_key)])
def checkout(req: ScoreRequest) -> CustomerView:
    """Customer-facing. Same scoring, deliberately impoverished response."""
    res = score(req)
    mapping = {
        "ALLOW": ("confirmed", "Order confirmed."),
        "MANUAL_REVIEW": ("verifying",
                          "We're verifying your payment. This usually takes "
                          "about 2 minutes."),
        "BLOCK": ("declined",
                  "We couldn't process this payment. Please try a different "
                  "method or contact support."),
    }[res.decision]
    return CustomerView(order_id=res.transaction_id, status=mapping[0],
                        message=mapping[1])


@app.get("/v1/admin/queue",
         dependencies=[Depends(require_role("analyst", "admin"))])
def queue(limit: int = 50) -> dict:
    items = [STATE["txns"][t] for t in STATE["queue"]]
    items.sort(key=lambda r: -r["risk_score"])
    return {
        "count": len(items),
        "items": [{k: v for k, v in r.items() if k != "features"}
                  for r in items[:limit]],
    }


@app.get("/v1/admin/transactions/{txn_id}",
         dependencies=[Depends(require_role("analyst", "admin"))])
def detail(txn_id: str) -> dict:
    r = STATE["txns"].get(txn_id)
    if r is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown transaction")
    return r


@app.post("/v1/admin/transactions/{txn_id}/outcome")
def outcome(txn_id: str, req: OutcomeRequest,
            actor: User = Depends(require_role("analyst", "admin"))) -> dict:
    """Record ground truth. The ONLY place a fraud label is created -- a risk
    score never becomes a label on its own."""
    r = STATE["txns"].get(txn_id)
    if r is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown transaction")
    r["label"] = req.label
    # Identity comes from the verified token, never from the request body. A
    # client-supplied analyst_id would make the audit trail worthless.
    r["labelled_by"] = actor.email
    r["labelled_at"] = datetime.now(timezone.utc).isoformat()
    if txn_id in STATE["queue"]:
        STATE["queue"].remove(txn_id)
    return {"transaction_id": txn_id, "label": req.label,
            "note": "label recorded for retraining; score was not a verdict"}
