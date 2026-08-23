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
import secrets
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
from fastapi import Depends, FastAPI, Header, HTTPException, status
from pydantic import BaseModel, Field

_HERE = Path(__file__).resolve().parent

# Artifacts can be relocated for containers without touching code.
ARTIFACTS = Path(os.environ.get("FRAUDSHIELD_ARTIFACTS", _HERE / "ml" / "artifacts"))
DATA_CSV = Path(os.environ.get("FRAUDSHIELD_DATA", _HERE / "ml" / "data" / "transactions.csv"))

API_KEY = os.environ.get("FRAUDSHIELD_API_KEY", "")
WARM_ROWS = int(os.environ.get("FRAUDSHIELD_WARM_ROWS", "40000"))


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
# 5. FastAPI application
# =============================================================================

STATE: dict = {"store": None, "scorer": None, "queue": [], "txns": {}}


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
    STATE["store"] = store
    STATE["scorer"] = scorer
    print(f"warmed store with {n:,} historical transactions")
    print(f"model: {'DEGRADED (no artifact)' if scorer.degraded else scorer.model_version}")
    print(f"thresholds: review >= {scorer.review_t}, block >= {scorer.block_t}")
    if not API_KEY:
        print("WARNING: FRAUDSHIELD_API_KEY is unset -- all endpoints are OPEN. "
              "Set it before exposing this service anywhere.")
    yield
    STATE.clear()


app = FastAPI(
    title="FraudShield",
    description="Defense-only transaction risk scoring. Returns a decision and "
                "evidence, never a fraud verdict.",
    version="0.4.0",
    lifespan=lifespan,
)


def require_key(x_api_key: str = Header(default="")) -> None:
    if not API_KEY:
        return  # open mode, warned about at startup
    if not secrets.compare_digest(x_api_key, API_KEY):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid or missing API key")


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


@app.get("/health")
def health() -> dict:
    s: Scorer = STATE["scorer"]
    return {
        "status": "ok",
        "model_loaded": s is not None and not s.degraded,
        "model_version": s.model_version if s else None,
        "thresholds": {"review": s.review_t, "block": s.block_t} if s else None,
        "store": "in-memory (DynamoDB adapter not built)",
        "auth": "api-key" if API_KEY else "OPEN -- set FRAUDSHIELD_API_KEY",
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


@app.get("/v1/admin/queue", dependencies=[Depends(require_key)])
def queue(limit: int = 50) -> dict:
    items = [STATE["txns"][t] for t in STATE["queue"]]
    items.sort(key=lambda r: -r["risk_score"])
    return {
        "count": len(items),
        "items": [{k: v for k, v in r.items() if k != "features"}
                  for r in items[:limit]],
    }


@app.get("/v1/admin/transactions/{txn_id}", dependencies=[Depends(require_key)])
def detail(txn_id: str) -> dict:
    r = STATE["txns"].get(txn_id)
    if r is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown transaction")
    return r


@app.post("/v1/admin/transactions/{txn_id}/outcome",
          dependencies=[Depends(require_key)])
def outcome(txn_id: str, req: OutcomeRequest) -> dict:
    """Record ground truth. The ONLY place a fraud label is created -- a risk
    score never becomes a label on its own."""
    r = STATE["txns"].get(txn_id)
    if r is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown transaction")
    r["label"] = req.label
    r["labelled_by"] = req.analyst_id
    r["labelled_at"] = datetime.now(timezone.utc).isoformat()
    if txn_id in STATE["queue"]:
        STATE["queue"].remove(txn_id)
    return {"transaction_id": txn_id, "label": req.label,
            "note": "label recorded for retraining; score was not a verdict"}
