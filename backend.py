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
and that agreement is the only evidence that the metrics in
ml/artifacts/metrics.json describe a model that can actually ship.

If you "deduplicate" these two into a shared helper, the test will still pass and
will prove nothing -- a function equalling itself. Leave them separate.
--------------------------------------------------------------------------------

SECURITY -- read before exposing this service
---------------------------------------------
Guarded by a single shared API key (`FRAUDSHIELD_API_KEY`). That is NOT the auth
model the browser-facing routes use (JWT access + refresh, Argon2id credentials in
DynamoDB, per-route role gating -- all implemented below). Missing today:

  - no per-user identity; nothing distinguishes one caller from another
  - no roles, so no analyst/admin separation
  - no rate limiting on any endpoint
  - review queue is in process memory and is lost on restart

If FRAUDSHIELD_API_KEY is unset, every endpoint is OPEN and startup says so.
Binds 127.0.0.1 by default. Keep it there until the auth layer exists.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
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
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Protocol

import numpy as np
import pandas as pd
import xgboost as xgb
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# Local. Provider vocabulary and adapters live outside this module so a gateway
# change cannot reach into the risk engine. The dependency is one-way: backend
# imports payments, payments never imports backend.
import payments

# Analyst alerting. Same one-way rule: notifications.py knows nothing about
# scoring, persistence or audit, so an email transport can never reach into a
# risk decision.
import notifications

_HERE = Path(__file__).resolve().parent


def _load_dotenv(path: Path = _HERE / ".env") -> int:
    """Read .env into os.environ before any config below is evaluated.

    Hand-rolled rather than depending on python-dotenv: this is ~20 lines and the
    serving image should not grow a dependency for it.

    Two rules that matter:

      - A variable already present in the real environment WINS. Otherwise a
        stale .env on a server would silently override what the orchestrator
        injected, which is the wrong precedence for a deployed service.
      - A missing file is a no-op, so containers that inject config directly are
        unaffected.

    Without this the file is decorative: every os.environ.get below would fall to
    its default, which is how a filled-in .env still produced an open API, an
    ephemeral JWT secret and an in-memory store.
    """
    if not path.is_file():
        return 0
    loaded = 0
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return 0
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if key.startswith("export "):
            key = key[7:].strip()
        value = value.strip()
        # Strip one layer of matching quotes; leave inner characters alone.
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if key and key not in os.environ:
            os.environ[key] = value
            loaded += 1
    return loaded


_DOTENV_COUNT = _load_dotenv()

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

# ---------------------------------------------------------------------------
# Client IP derivation
# ---------------------------------------------------------------------------
#
# The IP identifier MUST be derived server-side. It used to be a request-body
# field, which made every IP-based control decorative: an attacker who read the
# API could send a fresh `ip_hash` per request and walk straight past
# ip_concentration, ring detection, and the promo gate's IP signals. Worse, they
# could deliberately trigger the shared-IP exemption to suppress those signals.
#
# X-Forwarded-For is only honoured from a configured trusted proxy. Blindly
# trusting that header is the same hole with extra steps -- anyone can send it.
IP_PEPPER = os.environ.get("FRAUDSHIELD_IP_PEPPER", "")
if not IP_PEPPER:
    IP_PEPPER = secrets.token_urlsafe(32)
    _IP_PEPPER_EPHEMERAL = True
else:
    _IP_PEPPER_EPHEMERAL = False

TRUSTED_PROXIES = {
    p.strip()
    for p in os.environ.get("FRAUDSHIELD_TRUSTED_PROXIES", "").split(",")
    if p.strip()
}

# ---------------------------------------------------------------------------
# Payment provider selection
# ---------------------------------------------------------------------------
#
# Read here, resolved in lifespan(). The choice is EXPLICIT: Razorpay is never
# enabled just because credentials happen to exist in the environment, because a
# key left in a shell profile must not silently redirect live checkout traffic at
# a payment provider.
#
# Naming follows the two conventions already in this file -- FraudShield's own
# settings are FRAUDSHIELD_-prefixed, third-party credentials use the vendor's
# documented names, exactly as AWS_ACCESS_KEY_ID already does.
_PROVIDER_CFG = payments.provider_config_from_env()
PAYMENT_PROVIDER = _PROVIDER_CFG["requested"]
# Held as module attributes rather than re-read from os.environ at use time so the
# effective configuration is inspectable, and so a test can set it without
# mutating the process environment.
RAZORPAY_KEY_ID = _PROVIDER_CFG["key_id"]
RAZORPAY_KEY_SECRET = _PROVIDER_CFG["key_secret"]

# ---------------------------------------------------------------------------
# Analyst email notification
# ---------------------------------------------------------------------------
#
# Read here, resolved in lifespan(), exactly like the payment provider. Defaults
# to `console`, which renders alerts instead of transmitting them -- so the
# feature works in a demo, in CI and on a fresh clone with no credentials at all.
#
# The config dict holds the SMTP password. It is passed straight to the provider
# and is never logged, never published on /health, never persisted and never put
# in an audit record. Held as a module attribute rather than re-read at use time
# so a test can point it somewhere harmless without touching os.environ.
_EMAIL_CFG = notifications.email_config_from_env()
EMAIL_PROVIDER = _EMAIL_CFG["requested"]


def client_ip(request: "Request") -> str:
    """The peer address, or the client end of X-Forwarded-For behind a trusted proxy.

    DEPLOYMENT REQUIREMENT -- uvicorn undermines this by default.

    uvicorn ships with proxy-header handling enabled and `forwarded_allow_ips`
    defaulting to 127.0.0.1. When a request arrives from loopback it REWRITES
    request.client.host from X-Forwarded-For before this function ever runs, so a
    local caller can pick its own address and the check below never sees the real
    peer. Verified: sending `X-Forwarded-For: 203.0.113.7` changed the derived IP.

    So the server must be started with forwarded headers disabled unless a real
    proxy sits in front:

        uvicorn backend:app --forwarded-allow-ips=""

    That is what the Dockerfile does. With it disabled, this function is the only
    thing deciding the address, and TRUSTED_PROXIES is the only way to opt into
    X-Forwarded-For.
    """
    peer = request.client.host if request.client else "unknown"
    if peer in TRUSTED_PROXIES:
        xff = request.headers.get("x-forwarded-for", "")
        if xff:
            # Leftmost entry is the original client. Only trustworthy because the
            # immediate peer is a proxy we control.
            return xff.split(",")[0].strip()
    return peer


def ip_hash_of(request: "Request") -> str:
    """HMAC-SHA256(ip, pepper), truncated.

    Raw addresses are never stored, so counters work but a table dump does not
    reveal who connected from where.
    """
    ip = client_ip(request)
    mac = hmac.new(IP_PEPPER.encode(), ip.encode(), hashlib.sha256).hexdigest()
    return f"ip_{mac[:24]}"


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
# in ml/artifacts/metrics.json describes a model that cannot ship.
# tests/test_parity.py is what checks that.


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


# Failed-payment tracking per IP.
#
# A declined authorisation is not evidence of fraud on its own -- cards expire,
# balances run out, issuers have bad days. A BURST of declines from one address is
# different: it is the shape card testing leaves behind, where an attacker walks a
# list of stolen numbers until one authorises.
#
# So the trigger is a count inside a window, not a lifetime total. Without the
# window a legitimate customer who mistypes a card three times over six months is
# eventually indistinguishable from an attacker.
#
# TWO RULES, TWO WINDOWS -- because the same attack has a fast and a slow form.
#
#   VOLUME    more than 9 failures inside 20 minutes.
#             A machine working a list. Nobody types ten declining payments in
#             twenty minutes by hand.
#
#   BREADTH   3 or more DISTINCT payment methods failing inside 2 hours.
#             The patient version: card, then UPI, then netbanking, spread out
#             enough to stay under the volume rule. The long window is the point --
#             a burst detector cannot see this at all.
#
# Either fires the flag. They are deliberately not combined with AND: an attacker
# only has to be caught by one.
#
# WHY BREADTH IS 3 AND NOT 2. Two methods failing is an ordinary bad afternoon --
# an expired card followed by a UPI app that is having problems. Three distinct
# instrument TYPES failing from one address is someone working through whatever
# they have. Set IP_METHOD_THRESHOLD = 2 for the literal reading of "multiple";
# it will flag noticeably more honest customers.
IP_FAIL_WINDOW = 1200.0          # 20 minutes
IP_FAIL_THRESHOLD = 10           # fires at 10, i.e. MORE than 9
IP_METHOD_WINDOW = 7200.0        # 2 hours
IP_METHOD_THRESHOLD = 3          # distinct failed methods


@dataclass
class IPState:
    accounts: set[str] = field(default_factory=set)
    n_txn: int = 0
    # Failed authorisations. NOT a model feature -- see the note on
    # evaluate_ip_suspicion for why this stays out of the scoring path.
    n_fail: int = 0
    failures: deque = field(default_factory=deque)
    # (ts, payment_method) per failed authorisation, trimmed to IP_METHOD_WINDOW.
    # Kept separately from `failures` because the two rules read different windows:
    # trimming one deque to 20 minutes would destroy the 2-hour breadth count, the
    # same trap the customer velocity deques already document.
    method_failures: deque = field(default_factory=deque)
    suspicious_at: float | None = None
    suspicious_reason: str = ""
    # Which rule fired, so the alert and the console can say WHY rather than
    # leaving an analyst to infer it from a count.
    suspicious_rule: str = ""


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
        # Counted here so the historical warm-up and the live path agree. Counting
        # is not flagging: evaluate_ip_suspicion decides that, and only for live
        # traffic, so replaying months of archived declines cannot manufacture a
        # backlog of flagged addresses.
        if failed:
            p.n_fail += 1
            p.failures.append(ts)
            p.method_failures.append((ts, ev["payment_method"]))

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

    # ---- failed-payment tracking -------------------------------------------
    #
    # Deliberately NOT wired into build_online_features. Adding a 23rd feature
    # would invalidate every number in ml/artifacts/metrics.json, because the model was
    # trained and measured on 22. This is an operational signal for analysts, and
    # promoting it into the score is a retrain, not an edit.

    def ip_failures_recent(self, h: str, now: float, window: float = IP_FAIL_WINDOW) -> int:
        """Failed authorisations from this address inside the trailing window."""
        p = self._ip[h]
        while p.failures and now - p.failures[0] > window:
            p.failures.popleft()
        return len(p.failures)

    def ip_failed_methods_recent(self, h: str, now: float,
                                 window: float = IP_METHOD_WINDOW) -> set[str]:
        """Distinct payment methods that FAILED from this address in the window.

        The breadth signal. One customer whose card keeps declining produces a
        single method however many times they retry; somebody working through a
        card, then a UPI handle, then a bank produces three.
        """
        p = self._ip[h]
        while p.method_failures and now - p.method_failures[0][0] > window:
            p.method_failures.popleft()
        return {m for _ts, m in p.method_failures}

    def ip_is_suspicious(self, h: str) -> bool:
        return self._ip[h].suspicious_at is not None

    def evaluate_ip_suspicion(self, h: str, now: float) -> dict | None:
        """Flag an address once either decline rule crosses its threshold.

        Returns the mark when one is newly applied or already standing, else None.

        TWO RULES, EITHER SUFFICIENT:
          VOLUME   > 9 failures inside IP_FAIL_WINDOW (20 min) -- a fast burst.
          BREADTH  >= 3 distinct methods failing inside IP_METHOD_WINDOW (2 h) --
                   the same attack run slowly enough to duck the volume rule.

        Both counters are always evaluated, even once the address is already
        flagged, because the console and the alert report the live numbers rather
        than the ones that happened to trip the flag first.

        Shared infrastructure is exempt: a mobile carrier NAT or an office range
        legitimately carries many unrelated accounts, and their declines pool at
        one address through no fault of anyone behind it. Without this carve-out
        the flag would fire on the busiest honest IPs first. The same reasoning
        and the same threshold guard the promo gate.
        """
        p = self._ip[h]
        recent = self.ip_failures_recent(h, now)
        methods = self.ip_failed_methods_recent(h, now)

        by_volume = recent >= IP_FAIL_THRESHOLD
        by_breadth = len(methods) >= IP_METHOD_THRESHOLD
        if not (by_volume or by_breadth):
            return None
        if len(p.accounts) > HIGH_POP_IP_ACCOUNTS:
            return None

        newly = p.suspicious_at is None
        if newly:
            p.suspicious_at = now
            # Volume is named first when both are true: it is the stronger claim,
            # and an analyst reading "11 failures in 20 minutes" needs no further
            # explanation of why this address was raised.
            if by_volume:
                p.suspicious_rule = "volume"
                p.suspicious_reason = (
                    f"{recent} failed payment attempts within "
                    f"{int(IP_FAIL_WINDOW // 60)} minutes"
                )
            else:
                p.suspicious_rule = "breadth"
                p.suspicious_reason = (
                    f"{len(methods)} different payment methods failed "
                    f"({', '.join(sorted(methods))}) within "
                    f"{int(IP_METHOD_WINDOW // 3600)} hours"
                )
        return {
            # True only on the transition. Callers audit on `new` so an address
            # that keeps failing does not write an audit entry per attempt --
            # the attempts themselves are already recorded individually.
            "new": newly,
            "ip_hash": h,
            "since": datetime.fromtimestamp(p.suspicious_at, tz=timezone.utc).isoformat(),
            "reason": p.suspicious_reason,
            "rule": p.suspicious_rule,
            "failures_in_window": recent,
            "failed_methods": sorted(methods),
            "failed_method_count": len(methods),
            "matched_volume_rule": by_volume,
            "matched_breadth_rule": by_breadth,
            "failures_total": p.n_fail,
            "accounts": len(p.accounts),
        }

    def suspicious_ips(self) -> list[dict]:
        out = []
        for h, p in self._ip.items():
            if p.suspicious_at is None:
                continue
            out.append({
                "ip_hash": h,
                "since": datetime.fromtimestamp(p.suspicious_at, tz=timezone.utc).isoformat(),
                "reason": p.suspicious_reason,
                # Which rule raised this address. Absent on records flagged before
                # the second rule existed, which is why the console must tolerate
                # null rather than assume it.
                "rule": p.suspicious_rule or None,
                "failed_methods": sorted({m for _ts, m in p.method_failures}),
                "failed_method_count": len({m for _ts, m in p.method_failures}),
                "failures_total": p.n_fail,
                "accounts": len(p.accounts),
                "transactions": p.n_txn,
            })
        out.sort(key=lambda r: r["since"], reverse=True)
        return out


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

# Degraded-mode weights, used when no model artifact could be loaded. Same values
# the fallback branch of Scorer.score has always used, now named so the
# MODEL_FALLBACK_TRIGGERED audit event cannot report weights the scorer does not
# actually apply. Extracting them changes no arithmetic.
W_FALLBACK_RULES, W_FALLBACK_NETWORK = 0.70, 0.30

HIGH_POP_IP_ACCOUNTS = 25   # above this, an IP is shared infrastructure
MAX_COMPONENT = 200

# Defaults chosen on the validation split by expected-cost minimisation under an
# analyst-capacity ceiling. See README section 20 -- the review threshold is an
# OPERATIONS parameter (how many analysts you employ), not a property of the model.
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

    def __init__(self, artifacts: Path | None = None,
                 review_t: float = DEFAULT_REVIEW_T,
                 block_t: float = DEFAULT_BLOCK_T):
        # Resolved at call time, not bound as a default. A default of `ARTIFACTS`
        # is evaluated once when the function is defined, so relocating the
        # directory afterwards -- which is exactly what a fallback test needs to
        # do -- would silently have no effect and the scorer would keep loading
        # the real model.
        artifacts = Path(artifacts) if artifacts is not None else ARTIFACTS
        self.review_t = review_t
        self.block_t = block_t
        self.degraded = False
        self.best_iteration = None

        spec_p, model_p, cal_p = (
            artifacts / "feature_spec.json",
            artifacts / "model.json",
            artifacts / "calibrator.json",
        )

        # Recorded so MODEL_FALLBACK_TRIGGERED can name what was actually absent
        # rather than reporting a generic failure. Filenames only -- no paths to
        # anything secret.
        self.artifacts_dir = str(artifacts)
        self.missing_artifacts = [
            p.name for p in (spec_p, model_p, cal_p) if not p.exists()
        ]

        if self.missing_artifacts:
            # Degrade to rules+network rather than refusing to serve. Checkout is
            # on the other side of this call.
            #
            # No audit event is emitted here on purpose: lifespan constructs the
            # Scorer BEFORE the record store exists, so there is nothing to persist
            # to yet, and a bare Scorer() built outside the app (ml/, tests) has no
            # STATE at all. lifespan emits it once initialisation is complete.
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
            final = W_FALLBACK_RULES * rules + W_FALLBACK_NETWORK * net
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

# ---------------------------------------------------------------------------
# Unit costs -- CANONICAL. ml/cost_model.py imports these.
# ---------------------------------------------------------------------------
#
# Defined here rather than in ml/ because the serving path needs them (for the
# threshold tuner's cost curve) and ml/ is deliberately absent from the Docker
# image. Same inversion as build_matrix: serving code is canonical.
#
# Industry-typical estimates for a mid-size Indian D2C merchant at an average
# order value near Rs 2,400. NOT audited figures from a real merchant. The churn
# term inside COST_BLOCK_LEGIT is the softest input -- see cost_model.sensitivity().
COST_AOV = 2400.0
COST_FRAUD = COST_AOV + 750.0 + 400.0          # goods + chargeback fee + handling
COST_REVIEW = 35.0                             # analyst, ~3 min, loaded
COST_BLOCK_LEGIT = COST_AOV * 0.12 + 5750.0 * 0.20   # lost margin + churn EV = 1438
COST_PROMO_VALUE = 500.0
COST_PROMO_WRONG_DENY = COST_PROMO_VALUE + 260.0

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
# Argon2id credentials, short-lived JWT access tokens, rotating opaque refresh
# tokens with family revocation, and per-route role gating. See README section 23.
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
    """Single-table adapter; item shapes are documented in README section 17.

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
        # Sorted on SK, never on dict insertion order. Python preserves insertion
        # order, which makes an unsorted read LOOK deterministic in tests while
        # being meaningless after a rehydration reorders the writes.
        rows.sort(key=lambda r: r["SK"], reverse=desc)
        return rows

    def query_page(self, pk: str, sk_prefix: str, *, limit: int,
                   after_sk: str | None = None,
                   desc: bool = True) -> tuple[list[dict], str | None]:
        """One bounded page. Returns (rows, next_after_sk).

        Keyset pagination on the sort key, not an offset. `after_sk` is exclusive.
        Offsets would drift as new events are written to the partition mid-scroll
        -- and audit partitions are append-only and busiest exactly while someone
        is reading them.

        The same contract is implemented by DynamoRecordStore, so the endpoint
        above needs no knowledge of which store it is talking to.
        """
        rows = self.query_prefix(pk, sk_prefix, desc=desc)
        if after_sk is not None:
            rows = [r for r in rows
                    if (r["SK"] < after_sk if desc else r["SK"] > after_sk)]
        page = rows[:limit]
        # A next cursor only when there is genuinely more, so `has_more: false`
        # is trustworthy rather than "probably done".
        nxt = page[-1]["SK"] if len(rows) > limit and page else None
        return page, nxt

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

    def _query_args(self, pk: str, sk_prefix: str, desc: bool) -> dict:
        # DynamoDB rejects begins_with("") -- a key attribute cannot be an empty
        # string. An empty prefix means "everything under this partition", which
        # is a plain PK query.
        if sk_prefix:
            return {
                "KeyConditionExpression": "PK = :p AND begins_with(SK, :s)",
                "ExpressionAttributeValues": {":p": pk, ":s": sk_prefix},
                "ScanIndexForward": not desc,
            }
        return {
            "KeyConditionExpression": "PK = :p",
            "ExpressionAttributeValues": {":p": pk},
            "ScanIndexForward": not desc,
        }

    def query_prefix(self, pk: str, sk_prefix: str, desc: bool = True) -> list[dict]:
        """Every matching item in the partition, following DynamoDB's paging.

        THE BUG THIS LOOP FIXES
        -----------------------
        This used to issue ONE query() and return whatever came back. DynamoDB caps
        a query response at 1 MB and reports the rest through `LastEvaluatedKey`,
        which was never read -- so on any partition larger than 1 MB the tail was
        silently dropped. No error, no warning, no indication in the response.

        For the audit partition that is the exact failure the `complete` flag on
        GET /v1/admin/audit exists to prevent, reappearing one layer down: the read
        "succeeded", so the endpoint would have reported `complete: true` while
        serving a truncated day. Rehydration had the same exposure, quietly losing
        the oldest transactions once history grew.

        Bounded by MAX_QUERY_PAGES so a pathological partition cannot spin
        forever; the cap is high enough that hitting it means something is wrong.
        """
        out: list[dict] = []
        args = self._query_args(pk, sk_prefix, desc)
        for _ in range(MAX_QUERY_PAGES):
            r = self._t.query(**args)
            out.extend(self._unclean(i) for i in r.get("Items", []))
            last = r.get("LastEvaluatedKey")
            if not last:
                return out
            args = {**args, "ExclusiveStartKey": last}
        print(f"WARNING: query on {pk} stopped after {MAX_QUERY_PAGES} pages; "
              f"the result is TRUNCATED and callers relying on completeness "
              f"should treat it as partial")
        return out

    def query_page(self, pk: str, sk_prefix: str, *, limit: int,
                   after_sk: str | None = None,
                   desc: bool = True) -> tuple[list[dict], str | None]:
        """One bounded page, using DynamoDB's own Limit and ExclusiveStartKey.

        `after_sk` is translated into an ExclusiveStartKey rather than being
        applied after the fact, so a page costs one query of `limit` items instead
        of reading the whole partition and slicing it.

        The returned cursor is the last item's SK -- never DynamoDB's
        `LastEvaluatedKey`, which is an internal structure this API has no business
        publishing.
        """
        args = self._query_args(pk, sk_prefix, desc)
        args["Limit"] = max(1, limit)
        if after_sk is not None:
            args["ExclusiveStartKey"] = {"PK": pk, "SK": after_sk}
        r = self._t.query(**args)
        rows = [self._unclean(i) for i in r.get("Items", [])]
        # `LastEvaluatedKey` means DynamoDB stopped early; translate it into our
        # own opaque position, which is just the last SK we actually returned.
        nxt = rows[-1]["SK"] if r.get("LastEvaluatedKey") and rows else None
        return rows, nxt

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
    # Addresses that have produced at least one failed authorisation. Needed
    # because neither record store supports a scan, so listing failed attempts
    # requires knowing which IPFAIL# partitions exist. Bounded by distinct
    # failing IPs, not by attempt count.
    "fail_ips": set(),
    # Provider event ids already ingested. A fast in-process guard in front of the
    # WEBHOOK#EVENT lookup, since providers redeliver aggressively. The persisted
    # item is what survives a restart; this only saves a read.
    "webhook_seen": set(),
    "store": None, "scorer": None, "queue": [], "txns": {},
    "users": None, "users_backend": "?", "records": None, "records_backend": "?",
    "promo_queue": [], "audit": [],
}


def warm_store(store: InMemoryStore, limit: int, csv: Path = DATA_CSV) -> int:
    """Replay historical traffic so device/IP/velocity counters are populated.

    Without this every request hits a cold graph and looks like a brand-new
    entity, which is exactly the case the network layer cannot score.

    TRAIN SPLIT ONLY. Warming from validation or test would leak the evaluation
    period into serving state.

    `limit` semantics, which used to be a trap:
        0        warm nothing, return immediately
        n > 0    warm the most recent n rows
        n < 0    warm the entire train split

    This was previously `if limit:`, so 0 fell through to "no slice applied" and
    replayed all 69,593 train rows -- the exact opposite of what the value reads
    like, and of what the Dockerfile's FRAUDSHIELD_WARM_ROWS=0 intends. It only
    looked correct there because the image ships no CSV and returns early below.
    """
    if limit == 0:
        return 0
    if not csv.exists():
        return 0
    df = pd.read_csv(csv)
    df = df[df.split == "train"].sort_values("ts_epoch")
    if limit > 0:
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

    # ---- staff account seeding -------------------------------------------
    #
    # There is no API path to a privileged role (self-service signup always makes
    # a customer), so a staff account has to come from outside the API. This is
    # that path.
    #
    # Credentials come from the environment, NOT from source. A password literal
    # in a tracked file is one `git push` from being public, and this one grants
    # threshold control over every future decision. .env is gitignored;
    # .env.example holds placeholders only.
    #
    # If FRAUDSHIELD_ADMIN_PASSWORD is unset a random one is generated and
    # printed, so the console is still reachable but nothing predictable exists.
    if os.environ.get("FRAUDSHIELD_DEV_SEED_STAFF") == "1":
        seeds = [
            ("admin",
             os.environ.get("FRAUDSHIELD_ADMIN_EMAIL", "admin@fraudshield.local"),
             os.environ.get("FRAUDSHIELD_ADMIN_PASSWORD", "")),
            ("analyst",
             os.environ.get("FRAUDSHIELD_ANALYST_EMAIL", "analyst@fraudshield.local"),
             os.environ.get("FRAUDSHIELD_ANALYST_PASSWORD", "")),
        ]
        banner: list[str] = []
        for role, email, pw in seeds:
            generated = not pw
            if generated:
                pw = secrets.token_urlsafe(12)
            u = User(
                user_id=uuid.uuid4().hex, email=_norm_email(email),
                password_hash=PWD.hash(pw), role=role,
                created_at=datetime.now(timezone.utc).isoformat(),
            )
            if users.create(u):
                banner.append(f"    {role:<8} {email}  /  {pw}"
                              + ("   (generated)" if generated else ""))
            else:
                banner.append(f"    {role:<8} {email}  /  (already exists, unchanged)")
        if banner:
            print("\n  STAFF SEED -- local development only. Set "
                  "FRAUDSHIELD_DEV_SEED_STAFF=0 before exposing this service.")
            print("\n".join(banner) + "\n")

    records, records_desc = make_record_store()

    # The gateway behind checkout. `simulate_authorisation` is injected rather
    # than imported by payments.py, which keeps the dependency one-way and means
    # the simulator keeps exactly one implementation of its decline model.
    provider, provider_status = payments.resolve_provider(
        PAYMENT_PROVIDER,
        authorise_fn=simulate_authorisation,
        key_id=RAZORPAY_KEY_ID,
        key_secret=RAZORPAY_KEY_SECRET,
    )

    STATE["store"] = store
    STATE["scorer"] = scorer
    STATE["users"] = users
    STATE["users_backend"] = backend_desc
    STATE["records"] = records
    STATE["records_backend"] = records_desc
    STATE["payment_provider"] = provider
    STATE["provider_status"] = provider_status

    # Per-process collections, (re)initialised here rather than relying only on the
    # module-level literal.
    #
    # Shutdown calls STATE.clear(), which removes every key including the ones
    # declared at module scope. A single process that starts the app twice -- which
    # is exactly what a test session with more than one TestClient context does --
    # would otherwise come back up missing `fail_ips` and `webhook_seen` and raise
    # KeyError on the first webhook. Production only ever runs one lifecycle, so
    # this stayed invisible until the suite grew a second app context.
    STATE.setdefault("queue", [])
    STATE.setdefault("txns", {})
    STATE.setdefault("promo_queue", [])
    STATE.setdefault("audit", [])
    STATE["fail_ips"] = set()
    STATE["webhook_seen"] = set()

    # Rebuild the transaction cache and review queue from durable storage before
    # the app serves a request, so an analyst's backlog is present on the first
    # page load rather than only after new traffic arrives.
    #
    # Reloading is not re-deciding: no scoring runs here and no RISK_DECISION is
    # emitted. The stored score and decision stay authoritative.
    n_txn, n_queue = rehydrate_state(records)

    # Then rebuild the velocity counters and entity graph those transactions
    # imply. Runs after warm_store() above so the replay order stays globally
    # chronological: warm rows are historical training data, persisted rows are
    # live traffic that came later.
    graph = rehydrate_entity_state(store, records, users)
    STATE["graph_rehydration"] = graph

    # Unresolved promotion-abuse holds. Status-bounded, not age-bounded: an
    # analyst must not lose the oldest item in their backlog to a restart.
    promo = rehydrate_promo_queue(records)
    STATE["promo_rehydration"] = promo

    # Durable threshold configuration, applied to the scorer before the first
    # request is served.
    #
    # Deliberately AFTER the rehydration calls above and not before: reloading a
    # transaction never re-decides it, so a restored threshold cannot retroactively
    # change a stored decision either way. Ordering it here keeps that obvious --
    # the thresholds an admin set apply to new traffic only, which is exactly what
    # PUT /v1/admin/thresholds has always promised.
    threshold_config = load_persisted_thresholds(records, scorer)
    STATE["threshold_config"] = threshold_config

    # Analyst alerting. Resolved here so the mode is fixed for the process and
    # reported at startup alongside every other backend.
    #
    # `_EMAIL_CFG` holds the SMTP password; `email_status` deliberately does not,
    # which is why the two are kept apart and only the latter reaches STATE,
    # /health and the console.
    email_provider, email_status = notifications.resolve_email_provider(_EMAIL_CFG)
    STATE["email_provider"] = email_provider
    STATE["email_status"] = email_status
    STATE["email_recipients"] = notifications.parse_recipients(
        _EMAIL_CFG.get("recipients_raw", ""))
    STATE["console_url"] = _EMAIL_CFG.get("console_url", "")
    # Per-process dedupe guard and the in-memory notification list. Re-created
    # here for the same reason as fail_ips and webhook_seen: shutdown clears
    # STATE, and a second app context in one test session would otherwise come up
    # missing them.
    STATE["notified"] = set()
    STATE["notifications"] = []
    if _DOTENV_COUNT:
        print(f"loaded {_DOTENV_COUNT} variables from .env "
              "(real environment variables take precedence)")
    else:
        print("no .env loaded -- using real environment variables and defaults")
    # Emitted here, not in Scorer.__init__: the scorer is constructed above before
    # make_record_store(), so this is the first point where there is anywhere to
    # persist an audit event. One startup produces at most one event, which is what
    # keeps scored transactions from ever adding another.
    #
    # A failure to record the fallback must not prevent the service from starting in
    # fallback mode -- that would turn a degraded-but-serving system into a dead
    # one. audit() already swallows and reports persistence errors; this guards the
    # emit call itself for the same reason.
    if scorer.degraded:
        try:
            audit_model_fallback(scorer)
        except Exception as exc:  # noqa: BLE001
            print(f"WARNING: could not record MODEL_FALLBACK_TRIGGERED "
                  f"({type(exc).__name__}); serving in degraded mode regardless")

    print(f"warmed store with {n:,} historical transactions")
    print(f"rehydrated {n_txn:,} scored transactions and {n_queue:,} open review "
          f"items from the record store"
          + (f" (history capped at {REHYDRATE_TXNS:,}; open review items are "
             f"never capped)" if n_txn >= REHYDRATE_TXNS else ""))
    print(f"entity state: replayed {graph['replayed']:,} transactions "
          f"({graph['customers']:,} customers, {graph['devices']:,} devices, "
          f"{graph['ips']:,} IPs, {graph['edges']:,} edges) in "
          f"{graph['duration_ms']:.0f} ms")
    print(f"promo holds: {promo['open']:,} unresolved rebuilt from "
          f"{promo['examined']:,} redemptions "
          f"({promo['resolved']:,} already resolved) in "
          f"{promo['duration_ms']:.0f} ms")
    if not promo["complete"]:
        print(f"WARNING: promo hold queue is PARTIAL "
              f"({promo['skipped']:,} redemptions unreadable). Some unresolved "
              f"holds may not be visible to analysts.")
    if not graph["complete"]:
        print(f"WARNING: entity state is PARTIAL "
              f"({graph['skipped']:,} records skipped"
              + (f", history truncated at {graph['horizon']:,}"
                 if graph["truncated"] else "")
              + "). Velocity and network signals may under-score for entities "
                "outside the replayed window.")
    print(f"model: {'DEGRADED (no artifact)' if scorer.degraded else scorer.model_version}")
    if scorer.degraded:
        print(f"WARNING: MODEL FALLBACK ACTIVE -- missing "
              f"{', '.join(scorer.missing_artifacts) or 'artifacts'} in "
              f"{scorer.artifacts_dir}. Scoring uses rules "
              f"({W_FALLBACK_RULES:.0%}) + network ({W_FALLBACK_NETWORK:.0%}) only. "
              f"Audit event MODEL_FALLBACK_TRIGGERED recorded.")
    print(f"thresholds: review >= {scorer.review_t}, block >= {scorer.block_t} "
          f"(source={threshold_config['source']}"
          + (f", v{threshold_config['version']} set by "
             f"{threshold_config['updated_by']}"
             if threshold_config["source"] == "persisted" else "")
          + ")")
    if threshold_config["degraded"]:
        # Loud, because the running thresholds are not the configured ones. A
        # quiet fallback here would recreate the exact log-versus-behaviour
        # mismatch that persisting thresholds was meant to eliminate.
        print(f"WARNING: THRESHOLD CONFIGURATION DEGRADED -- "
              f"{threshold_config['note']}")
    print(f"user store:   {backend_desc}")
    print(f"record store: {records_desc}")
    print(f"payment provider: {provider_status['payment_provider']} "
          f"(requested={provider_status['requested_provider']}, "
          f"razorpay_configured={provider_status['razorpay_configured']})")
    if provider_status["degraded"]:
        # Loud, because the running mode is not the configured one. Silently
        # serving the simulator while an operator believes Razorpay is live is the
        # precise misunderstanding this whole seam exists to prevent.
        print(f"WARNING: PAYMENT PROVIDER DEGRADED -- {provider_status['note']}")
    elif provider_status["payment_provider"] == payments.PROVIDER_RAZORPAY:
        print("NOTE: the Razorpay adapter has never been exercised against a "
              "live Razorpay account. Verify Test Mode end-to-end before "
              "trusting settlement values from it.")
    print(f"email alerts: {email_status['provider']} "
          f"(requested={email_status['requested_provider']}, "
          f"recipients={email_status['recipient_count']}, "
          f"enabled={email_status['alerts_enabled']})")
    if email_status["degraded"]:
        # Loud, because the running mode is not the configured one and an
        # operator who believes alerts are being emailed would stop watching the
        # queue.
        print(f"WARNING: EMAIL ALERTS DEGRADED -- {email_status['note']}")
    elif not email_status["alerts_enabled"]:
        print(f"NOTE: {email_status['note']}")
    if email_status["recipients_rejected"]:
        print(f"WARNING: {email_status['recipients_rejected']} entr"
              f"{'y' if email_status['recipients_rejected'] == 1 else 'ies'} in "
              f"FRAUDSHIELD_ALERT_RECIPIENTS could not be parsed and "
              f"{'was' if email_status['recipients_rejected'] == 1 else 'were'} "
              f"dropped. Check for typos -- those addresses receive nothing.")
    if not API_KEY:
        print("WARNING: FRAUDSHIELD_API_KEY is unset -- service endpoints are OPEN. "
              "Set it before exposing this service anywhere.")
    if _JWT_EPHEMERAL:
        print("WARNING: FRAUDSHIELD_JWT_SECRET is unset. Using an ephemeral secret: "
              "every restart invalidates all sessions, and multiple workers will "
              "reject each other's tokens.")
    if _IP_PEPPER_EPHEMERAL:
        print("WARNING: FRAUDSHIELD_IP_PEPPER is unset. Using an ephemeral pepper: "
              "IP and card fingerprints change on every restart, so entity counters "
              "and instrument-reuse detection reset with them.")
    print(f"client ip: derived server-side, trusted proxies="
          f"{sorted(TRUSTED_PROXIES) or 'none (using peer address)'}")
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
    allow_methods=["GET", "POST", "PUT"],
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
    """Service-to-service scoring, guarded by the shared API key.

    This endpoint DOES accept `ip_hash` and `status` from the caller, unlike
    /v1/orders. That is deliberate and it is the one legitimate case: a merchant's
    own server relaying a checkout knows the end customer's address and the
    gateway's authorisation result, and must pass both. The API key is what makes
    that trustworthy.

    Never expose this endpoint to a browser. A caller who can choose its own
    ip_hash walks straight past ip_concentration and ring detection.
    """

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
    """The human ground-truth submission. Label only.

    `analyst_id` USED TO EXIST HERE and was silently ignored: accepted, validated,
    never read. That is worse than rejecting it. A caller sending
    `analyst_id: "someone@else"` got a 200 and could reasonably believe that
    identity had been recorded, when the audited actor came from the token all
    along. An accountability API must not accept a field it discards.

    `extra="forbid"` now makes that a 422. It also rejects any other unknown key,
    which is the correct trade: on the one endpoint that creates ground truth, a
    typo should fail loudly rather than be absorbed.
    """

    model_config = {"extra": "forbid"}

    label: str = Field(pattern="^(fraud|legitimate)$")


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
    "p1":  {"name": "Wireless earbuds", "price": 2499.0, "category": "Audio", "stock": 42},
    "p2":  {"name": "Mechanical keyboard", "price": 6799.0, "category": "Peripherals", "stock": 18},
    "p3":  {"name": "Smartphone 5G 128GB", "price": 42999.0, "category": "Phones", "stock": 7},
    "p4":  {"name": "Silicone phone case", "price": 449.0, "category": "Accessories", "stock": 260},
    "p5":  {"name": "Noise-cancelling headphones", "price": 12999.0, "category": "Audio", "stock": 23},
    "p6":  {"name": "Smartwatch", "price": 8499.0, "category": "Wearables", "stock": 31},
    "p7":  {"name": "65W USB-C charger", "price": 1899.0, "category": "Accessories", "stock": 140},
    "p8":  {"name": "1TB portable SSD", "price": 7299.0, "category": "Storage", "stock": 26},
    "p9":  {"name": "Laptop backpack", "price": 2199.0, "category": "Accessories", "stock": 88},
    "p10": {"name": "27in 4K monitor", "price": 27499.0, "category": "Displays", "stock": 5},
    "p11": {"name": "Wireless mouse", "price": 1299.0, "category": "Peripherals", "stock": 175},
    "p12": {"name": "Tablet 11in", "price": 31999.0, "category": "Tablets", "stock": 9},
}

BANKS = {
    "HDFC": "HDFC Bank", "ICIC": "ICICI Bank", "SBIN": "State Bank of India",
    "AXIS": "Axis Bank", "KKBK": "Kotak Mahindra", "PUNB": "Punjab National Bank",
}
WALLETS = ["Paytm", "PhonePe", "Amazon Pay", "Mobikwik"]

# Card BIN -> network, for display and for the `card_fingerprint` namespace. Only
# the first digit is needed to name the network; we never keep more than that
# plus the last four.
CARD_NETWORKS = {"4": "Visa", "5": "Mastercard", "6": "RuPay", "3": "Amex"}


def _luhn_ok(number: str) -> bool:
    """Checksum used by every real card. Rejects typos before they reach a gateway."""
    digits = [int(c) for c in number if c.isdigit()]
    if len(digits) < 12:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def card_fingerprint(number: str) -> str:
    """Stable, non-reversible identifier for a card.

    HMAC with the server pepper, so two accounts using the same card produce the
    same fingerprint (which is the fraud signal) while a table dump yields no PANs.
    """
    digits = "".join(c for c in number if c.isdigit())
    mac = hmac.new(IP_PEPPER.encode(), digits.encode(), hashlib.sha256).hexdigest()
    return f"card_{mac[:24]}"


def validate_instrument(req: "OrderRequest") -> tuple[str, str]:
    """Validate the method-specific payload. Returns (instrument_ref, display).

    instrument_ref is what gets stored and counted. For cards that is the
    fingerprint, never the number.
    """
    m = req.payment_method
    if m == "card":
        if req.card is None:
            raise HTTPException(422, "Card details are required.")
        digits = "".join(c for c in req.card.number if c.isdigit())
        if not _luhn_ok(digits):
            raise HTTPException(422, "That card number is not valid.")
        if not req.card.cvv.isdigit():
            raise HTTPException(422, "CVV must be numeric.")
        now = datetime.now(timezone.utc)
        if (req.card.expiry_year, req.card.expiry_month) < (now.year, now.month):
            raise HTTPException(422, "That card has expired.")
        network = CARD_NETWORKS.get(digits[0], "Card")
        return card_fingerprint(digits), f"{network} \u2022\u2022\u2022\u2022 {digits[-4:]}"

    if m == "upi":
        if req.upi is None:
            raise HTTPException(422, "A UPI ID is required.")
        vpa = req.upi.vpa.strip().lower()
        if not re.fullmatch(r"[a-z0-9._-]{3,}@[a-z]{2,}", vpa):
            raise HTTPException(422, "Enter a UPI ID like name@bank.")
        return f"upi_{vpa}", vpa

    if m == "netbanking":
        if req.netbanking is None or req.netbanking.bank_code.upper() not in BANKS:
            raise HTTPException(422, "Choose a bank.")
        code = req.netbanking.bank_code.upper()
        return f"nb_{code}", BANKS[code]

    if m == "wallet":
        if req.wallet is None:
            raise HTTPException(422, "Wallet details are required.")
        phone = re.sub(r"\D", "", req.wallet.phone)
        if len(phone) < 10:
            raise HTTPException(422, "Enter a valid phone number.")
        mac = hmac.new(IP_PEPPER.encode(), phone.encode(), hashlib.sha256).hexdigest()
        return f"wal_{mac[:20]}", f"{req.wallet.provider} \u2022\u2022\u2022{phone[-4:]}"

    # Unreachable through /v1/orders, whose pattern already rejects anything not
    # listed above. Kept as a refusal rather than a default so a future method
    # added to the pattern without a branch here fails loudly instead of being
    # silently recorded as an instrument-less order.
    raise HTTPException(422, f"Unsupported payment method {m!r}.")


def simulate_authorisation(method: str, amount: float, decision: str) -> str:
    """Stand-in for a gateway response.

    The point is that settlement status is decided SERVER-SIDE. It used to be a
    request-body field, which let a caller declare its own outcome and poison the
    velocity and failure-rate features -- the same class of bug as client-supplied
    ip_hash.

    A BLOCK never reaches a gateway. Otherwise we model a small background decline
    rate, higher on cards, which is what produces the innocent failures the model
    was trained to tolerate.
    """
    if decision == "BLOCK":
        return "failed"
    if method == "cod":
        return "success"
    base = {"card": 0.06, "netbanking": 0.05, "wallet": 0.03, "upi": 0.02}.get(method, 0.03)
    if amount > 25000:
        base += 0.03          # issuers decline high-value more often
    return "failed" if secrets.randbelow(10000) / 10000.0 < base else "success"

CUSTOMER_MESSAGE = {
    "ALLOW": ("confirmed", "Order confirmed."),
    "MANUAL_REVIEW": ("verifying",
                      "We're verifying your payment. This usually takes about "
                      "2 minutes."),
    "BLOCK": ("declined",
              "We couldn't process this payment. Please try a different method "
              "or contact support."),
}


def actor_identity(u: "User") -> dict:
    """The authenticated identity of a human actor, for the audit record.

    Derived ONLY from the verified token's user. Never from a request body --
    that is the whole point, and `OutcomeRequest` now rejects the field that used
    to invite it.

    Three values, each answering a different question an auditor asks:

      user_id  WHICH ACCOUNT did this? The stable answer. An email can be
               re-registered after a deletion, so email alone cannot identify an
               account across time.
      email    WHO, in human terms. Kept because every existing consumer, test
               and UI column reads it.
      role     WITH WHAT AUTHORITY? An analyst and an admin can both record an
               outcome, and "was this person allowed to?" is unanswerable later
               if the role at the time is not captured -- roles are granted
               out-of-band and can change.

    Deliberately absent: password hash, tokens, refresh state, session data.
    """
    return {"user_id": u.user_id, "email": u.email, "role": u.role}


def audit(actor: str, action: str, before: dict, after: dict,
          event_id: str | None = None,
          identity: dict | None = None) -> dict:
    """Append an entry to the in-process log and the append-only audit item.

    A persistence failure must not fail the operation being audited -- refusing a
    threshold change because the log is unreachable would be worse than the gap.
    The warning is printed instead, so the gap is at least visible.

    `event_id` is optional and additive: callers that want a stable identifier for
    the event (RISK_DECISION does) pass one, and it becomes part of the sort key so
    the persisted item is traceable back to the emitting operation.
    """
    now = datetime.now(timezone.utc).isoformat()
    entry: dict = {"actor": actor, "action": action,
                   "before": before, "after": after, "at": now}
    if event_id:
        entry["event_id"] = event_id
    if identity:
        # Additive. `actor` stays the email string so every existing consumer,
        # test and UI column keeps working; `actor_identity` answers which account
        # and with what authority.
        entry["actor_identity"] = identity
    STATE["audit"].append(entry)
    suffix = event_id or uuid.uuid4().hex[:8]
    try:
        STATE["records"].put(f"AUDIT#{now[:10]}", f"{now}#{suffix}", entry)
    except Exception as exc:  # noqa: BLE001
        # Observable to operators, invisible to customers, and never fabricated as
        # a success: the in-process entry above is still present and the endpoint
        # falls back to it, so the gap is a persistence gap and not a missing event.
        print(f"WARNING: audit write failed ({type(exc).__name__}); "
              f"'{action}' applied but not persisted")
    return entry


# The one automatic decision event. Named as a constant so the emitter, the
# retrieval filter and the tests cannot drift apart on spelling.
RISK_DECISION = "RISK_DECISION"

# Stated on every RISK_DECISION record. A score routes attention; it does not
# determine that a transaction was fraudulent. Ground truth is created only by a
# human via POST /v1/admin/transactions/{id}/outcome, which is a separate event.
RISK_DECISION_NOTE = (
    "Routing decision, not a fraud determination. Ground truth is created only "
    "by a human outcome (CONFIRM_FRAUD / MARK_LEGITIMATE)."
)


# ---------------------------------------------------------------------------
# Bounded automated-action policy
# ---------------------------------------------------------------------------
#
# WHY THIS IS A TABLE AND NOT AN AGENT
# ------------------------------------
# FraudShield is defense-only. It refuses payments and it queues them for people.
# It has no authority to conclude anything about a customer, and this table is the
# written form of that limit -- deterministic, finite, and version-stamped, so
# "what is the system allowed to do on its own?" has an answer you can read rather
# than infer from scattered call sites.
#
# THE INFERENCE THIS EXISTS TO FORBID
# -----------------------------------
#     BLOCK != FRAUD
#
# A BLOCK means one thing: the score crossed the configured block threshold and the
# payment was refused. It is not a finding, not an accusation, and not a label. The
# system cannot create ground truth; only a human reviewer can, through a separate
# audited action. Every automated action below is reversible by a person and none of
# them writes a label.
#
# Nothing in this module CHANGES behaviour. It names the behaviour that already
# exists so it can be audited and tested. If a future change added an automated
# action, this table is where it would have to be declared first.

POLICY_VERSION = "action-policy-1"

ACTION_POLICY: dict[str, dict] = {
    "ALLOW": {
        "automated_action": "PROCEED_TO_AUTHORISATION",
        "reason": "risk score below the configured review threshold",
        "reversible_by_human": True,
        "permitted": (
            "let the payment proceed to the payment provider",
            "persist the scored transaction",
            "emit one RISK_DECISION audit event",
        ),
    },
    "MANUAL_REVIEW": {
        "automated_action": "ENQUEUE_FOR_HUMAN_REVIEW",
        "reason": "risk score at or above the review threshold and below the "
                  "block threshold",
        "reversible_by_human": True,
        "permitted": (
            "let the payment proceed to the payment provider",
            "add the transaction to the analyst review queue",
            "persist the scored transaction",
            "emit one RISK_DECISION audit event",
        ),
    },
    "BLOCK": {
        "automated_action": "REFUSE_BEFORE_AUTHORISATION",
        "reason": "risk score at or above the configured block threshold",
        "reversible_by_human": True,
        "permitted": (
            "refuse the payment before it reaches the payment provider",
            "add the transaction to the analyst review queue",
            "persist the scored transaction",
            "emit one RISK_DECISION audit event",
        ),
    },
}

# Actions the automated path must never take, in any decision band. Published on
# /v1/admin/policy and asserted by tests, so this is a checked commitment rather
# than a paragraph of documentation.
NEVER_AUTOMATED: tuple[str, ...] = (
    "confirm that a transaction was fraudulent",
    "create or modify a ground-truth label",
    "issue a refund or move money in any direction",
    "ban, suspend, close or permanently restrict a customer account",
    "change a risk threshold",
    "change model weights or retrain the model",
    "delete or alter evidence, audit records or stored transactions",
    "notify a customer that they are suspected of fraud",
    "share a decision with a third party",
)

POLICY_NOTE = (
    "A BLOCK means the risk score crossed the configured block threshold and the "
    "payment was refused. It is NOT a finding of fraud, NOT a label, and NOT an "
    "accusation against the customer. Ground truth is created only by a human "
    "reviewer through a separate audited action."
)


def automated_action(decision: str, *, transaction_id: str,
                     risk_score: float) -> dict:
    """The bounded action record for one decision.

    Carries the fields an automated action must always disclose -- what was done,
    why, to which transaction, at what score, when, and under which policy version
    -- so an auditor can reconstruct the action without consulting the code that
    performed it.

    An unrecognised decision resolves to REVIEW rather than to a default of
    PROCEED. A band this build does not understand must land in front of a human,
    never through unexamined.
    """
    entry = ACTION_POLICY.get(decision)
    if entry is None:
        entry = {
            "automated_action": "ENQUEUE_FOR_HUMAN_REVIEW",
            "reason": f"unrecognised decision {decision!r}; routed to a human",
            "reversible_by_human": True,
            "permitted": ACTION_POLICY["MANUAL_REVIEW"]["permitted"],
        }
    return {
        "action": entry["automated_action"],
        "reason": entry["reason"],
        "transaction_id": transaction_id,
        "risk_score": risk_score,
        "at": datetime.now(timezone.utc).isoformat(),
        "policy_version": POLICY_VERSION,
        "reversible_by_human": entry["reversible_by_human"],
        # Restated per action so a single audit row is self-describing.
        "creates_ground_truth": False,
        "creates_fraud_label": False,
        "moves_money": False,
    }


def audit_risk_decision(
    *,
    d: "Decision",
    scorer: "Scorer",
    transaction_id: str,
    order_id: str,
    customer_id: str,
    amount: float,
    payment_method: str,
    settlement: str,
    source: str,
    demo_scenario: str | None = None,
) -> dict:
    """Emit the RISK_DECISION audit event for one scored transaction.

    Takes the ALREADY-COMPUTED Decision. It never re-scores and never derives a
    second risk number -- the audited values are, by construction, the exact ones
    the customer response and the analyst queue were built from. Re-deriving them
    here would let the audit trail and the decision disagree, which is the one
    thing an audit trail must never do.

    Deliberately absent from this record: card numbers, CVV, UPI ids, bank codes,
    wallet phone numbers, tokens and headers. The instrument is already reduced to
    a salted fingerprint upstream, and an audit log is the wrong place to hold
    payment credentials. What is recorded is transaction metadata plus the risk
    evidence.

    `demo_scenario` marks the event as synthetic. It is additive and omitted
    entirely for real traffic, so the ABSENCE of `demo` on a RISK_DECISION is
    itself the statement that the transaction was real -- which is why it is not
    written as `demo: false` on every record. Nothing else about the event changes:
    a synthetic transaction was still scored by the same engine, and its
    `is_ground_truth` was already false.
    """
    after = {
        "decision": d.decision,
        "risk_score": d.risk_score,
        # Per-layer contributions, so a reviewer can see which evidence source
        # drove the routing rather than only the aggregate.
        "sub_scores": d.sub_scores,
        "fired_rules": d.fired_rules,
        "reason_codes": d.reason_codes,
        "model_version": d.model_version,
        # True means the ML layer did NOT contribute: the score came from
        # rules and network only. Without this a degraded-mode record would
        # imply the model produced it.
        "degraded": d.degraded,
        "override": d.override,
        "thresholds": {"review": scorer.review_t, "block": scorer.block_t},
        "settlement": settlement,
        # What the system did on its own authority, from the bounded policy
        # table. Recorded on every decision so "the automation acted" is never
        # something a reader has to infer from the decision alone.
        "automated_action": automated_action(
            d.decision, transaction_id=transaction_id,
            risk_score=d.risk_score),
        # Machine-checkable restatement of RISK_DECISION_NOTE, so downstream
        # consumers cannot mistake a routing event for a fraud label.
        "is_ground_truth": False,
        "note": RISK_DECISION_NOTE,
    }
    if demo_scenario:
        after["demo"] = True
        after["demo_scenario"] = demo_scenario

    return audit(
        actor="system:scorer",
        action=RISK_DECISION,
        event_id=f"rde_{uuid.uuid4().hex[:12]}",
        before={
            "transaction_id": transaction_id,
            "order_id": order_id,
            "customer_id": customer_id,
            "amount": amount,
            "payment_method": payment_method,
            "source": source,
        },
        after=after,
    )


# The human counterpart to RISK_DECISION. Separate action, separate actor, and
# separate meaning: this one IS ground truth.
OUTCOME_RECORDED = "OUTCOME_RECORDED"

OUTCOME_NOTE = (
    "Human-reviewed ground truth. An observed outcome recorded by an authorised "
    "reviewer, not a model output. It does not alter the RISK_DECISION that "
    "routed this transaction."
)

# The human verdict, stated as the action a reviewer took rather than as the
# stored label. `MANUAL_REVIEW -> MARK_LEGITIMATE` is the sentence an auditor is
# reading; `MANUAL_REVIEW -> legitimate` reads like the machine changed its mind.
OUTCOME_VERB = {"fraud": "CONFIRM_FRAUD", "legitimate": "MARK_LEGITIMATE"}


def _confusion_cell(decision: str | None, label: str) -> str:
    """Where this transaction lands once a human has ruled on it.

    Derived only from values already stored -- the routing decision and the label
    a person just recorded. Nothing is recomputed and the scorer is not consulted.

    MANUAL_REVIEW counts as flagged: the system did raise it for attention, so a
    'legitimate' verdict on a reviewed transaction is still a false positive in
    the sense that matters to the cost model, even though no sale was refused.
    """
    flagged = decision in ("BLOCK", "MANUAL_REVIEW")
    if label == "fraud":
        return "true_positive" if flagged else "false_negative"
    return "false_positive" if flagged else "true_negative"


def audit_outcome_recorded(
    *,
    txn_id: str,
    txn: dict,
    previous_label: str | None,
    new_label: str,
    actor_email: str,
    identity: dict | None = None,
) -> dict:
    """Emit the OUTCOME_RECORDED audit event for a human ground-truth decision.

    Reads the original decision and score from the STORED transaction. It never
    re-runs the scorer: the point of this record is to sit beside the machine's
    original judgement, so re-deriving that judgement now -- possibly against a
    retrained model -- would defeat it.

    The corresponding RISK_DECISION event is left completely untouched. The audit
    history keeps both as independent facts: what the system did, then what a
    person found.

    `model_version` is deliberately absent. The stored transaction does not carry
    it, and reading the CURRENT scorer's version could name a model that never saw
    this transaction. The RISK_DECISION event for the same transaction_id does
    record it, which is where a reviewer should look.
    """
    return audit(
        actor=actor_email,
        action=OUTCOME_RECORDED,
        event_id=f"out_{uuid.uuid4().hex[:12]}",
        identity=identity,
        before={
            "transaction_id": txn_id,
            "order_id": txn.get("order_id"),
            # ---- the automated state this human action resolved -------------
            # Moved into `before` where it belongs. It used to live only in
            # `after` as `original_*`, which read as though the machine decision
            # were an outcome of the human action rather than its input. An
            # auditor reconstructing the timeline needs the machine's position
            # BEFORE the person acted, in the field named `before`.
            "decision": txn.get("decision"),
            "risk_score": txn.get("risk_score"),
            "label": previous_label,
            # Added: what the payment and the customer actually saw. Without
            # these, "was money taken?" and "what were they told?" cannot be
            # answered from the event, only inferred.
            "settlement": txn.get("settlement"),
            "customer_status": txn.get("customer_status"),
            # Retained: the previous label under its original name, so existing
            # consumers keep working.
            "previous_label": previous_label,
            # Distinguishes a first ruling from a reversal, so a reviewer can find
            # the cases where a human changed their mind.
            "is_first_label": previous_label is None,
            "is_correction": previous_label is not None
            and previous_label != new_label,
        },
        after={
            "label": new_label,
            # The human conclusion in the vocabulary a reviewer used, distinct
            # from the stored label. `MANUAL_REVIEW -> MARK_LEGITIMATE` is the
            # sentence an auditor is trying to read.
            "outcome": OUTCOME_VERB[new_label],
            # The inverse of RISK_DECISION's is_ground_truth: False. Both spellings
            # are emitted: `ground_truth` is what existing tests and the frontend
            # read, `is_ground_truth` is the name used by every other event type.
            "ground_truth": True,
            "is_ground_truth": True,
            # COMPATIBILITY ALIASES. Same values as `before.decision` /
            # `before.risk_score`. Kept because tests and any stored historical
            # event read them; the canonical location is now `before`.
            "original_decision": txn.get("decision"),
            "original_risk_score": txn.get("risk_score"),
            "original_sub_scores": txn.get("sub_scores"),
            "original_override": txn.get("override"),
            "original_scored_at": txn.get("scored_at"),
            # Machine judgement vs human verdict, from stored values only.
            "confusion_cell": _confusion_cell(txn.get("decision"), new_label),
            "note": OUTCOME_NOTE,
        },
    )


# The promo gate's human counterpart to OUTCOME_RECORDED. Kept as a SEPARATE
# action rather than reusing OUTCOME_RECORDED: the two describe different
# subjects (a redemption, not a transaction), carry different evidence, and the
# promo gate is rule-only with no model version to cite. Merging them would make
# `?action=OUTCOME_RECORDED` return two record shapes.
PROMO_OVERRIDE = "PROMO_OVERRIDE"

PROMO_OVERRIDE_NOTE = (
    "Human-reviewed ground truth for the promotion-abuse gate. An authorised "
    "reviewer granted a claim the rules had held or denied. It does NOT rewrite "
    "the machine decision: `machine_decision` remains what the gate decided, and "
    "`human_outcome` is the separate, later verdict."
)


def audit_promo_override(
    *,
    rid: str,
    redemption: dict,
    actor_email: str,
    override_by: str | None = None,
    override_at: str | None = None,
    identity: dict | None = None,
    reason: str | None = None,
) -> dict:
    """Emit PROMO_OVERRIDE for a human granting a held or denied redemption.

    Reads everything from the STORED redemption, exactly as audit_outcome_recorded
    reads from the stored transaction. The promo gate is not re-run: the point of
    this record is to sit beside the gate's original judgement, so recomputing
    that judgement now -- against possibly different promo thresholds -- would
    defeat it.

    The separation this preserves is the same one the transaction path already
    uses:

        machine_decision  HOLD / DENY      what the gate decided, never rewritten
        human_outcome     OVERRIDDEN       what a person decided afterwards
        label             legitimate       the ground-truth label that follows

    Nothing here is written back into `decision`. An override that mutated HOLD
    into ALLOW would destroy the only record that the gate ever flagged the claim,
    and with it the false-positive count this gate is measured by.
    """
    return audit(
        actor=actor_email,
        action=PROMO_OVERRIDE,
        event_id=f"pov_{uuid.uuid4().hex[:12]}",
        identity=identity,
        before={
            "redemption_id": rid,
            "customer_id": redemption.get("customer_id"),
            "promo_code": redemption.get("promo_code"),
            "value": redemption.get("value"),
            # The machine's original judgement, quoted not recomputed.
            "machine_decision": redemption.get("decision"),
            "machine_status": redemption.get("status"),
            # Evidence the gate acted on, where the record carries it. The promo
            # gate is deterministic and rule-only, so `fired_rules` and `reasons`
            # ARE its explanation -- there is no score to report and none is
            # invented here.
            "fired_rules": redemption.get("fired_rules"),
            "reasons": redemption.get("reasons"),
            "shared_ip_exempt": redemption.get("shared_ip_exempt"),
            "machine_decided_at": redemption.get("created_at"),
            # Canonical names, matching OUTCOME_RECORDED's `before`. Same values
            # as `machine_decision` / `machine_status` above, which are retained
            # because existing tests read them.
            "decision": redemption.get("decision"),
            "status": redemption.get("status"),
            # Always None before the first override -- stated explicitly rather
            # than omitted, so a reader can tell "no prior label" from "field not
            # recorded".
            "label": redemption.get("label"),
        },
        after={
            # The human verdict, in its own field.
            "human_outcome": "OVERRIDDEN",
            "label": "legitimate",
            "resolved_status": "credited",
            # Canonical name for the resolved state, alongside `resolved_status`.
            "status": "credited",
            # WHO and WHEN, as written to the redemption record. Present so the
            # event is self-contained: an auditor reading only the audit partition
            # can reconstruct the resolution without joining to the redemption.
            "override_by": override_by,
            "override_at": override_at,
            # Matches OUTCOME_RECORDED's `ground_truth: True`, and the inverse of
            # RISK_DECISION's `is_ground_truth: False`.
            "is_ground_truth": True,
            # Restated so a consumer reading only `after` cannot conclude the gate
            # had decided to allow this claim all along.
            "machine_decision_unchanged": redemption.get("decision"),
            "reason": reason or None,
            "note": PROMO_OVERRIDE_NOTE,
        },
    )


# ---------------------------------------------------------------------------
# Notification audit events
# ---------------------------------------------------------------------------
#
# A COMMUNICATION event, and nothing more. The three-way distinction the audit
# trail already maintains gets a third column rather than a blurred one:
#
#   RISK_DECISION      automated risk routing        is_ground_truth: false
#   NOTIFICATION_SENT  we told a human about it      is_ground_truth: false
#   OUTCOME_RECORDED   a human ruled on it           is_ground_truth: true
#
# Delivering an email proves only that an email was delivered. It is not evidence
# about the transaction, it does not label anything, and it must never be counted
# as a review having happened -- an analyst reading an alert is not an analyst
# recording an outcome.
NOTIFICATION_SENT = "NOTIFICATION_SENT"
NOTIFICATION_FAILED = "NOTIFICATION_FAILED"
# A distinct action, deliberately NOT folded into NOTIFICATION_FAILED. Nothing
# malfunctioned: the alert was withheld because the volume ceiling had been reached,
# which is a policy outcome. Recording it as a failure would put an operator on a
# hunt for a broken mail server, and would bury real transport failures in noise.
NOTIFICATION_THROTTLED = "NOTIFICATION_THROTTLED"

NOTIFICATION_NOTE = (
    "Communication event. Records that an alert about an existing decision was "
    "dispatched to authorised staff. It is NOT a risk decision, NOT ground "
    "truth, and NOT evidence about the transaction. No customer is contacted."
)


def audit_notification(*, notification_id: str, event_type: str, result,
                       dedupe_key: str, subject_id: str,
                       related: dict) -> dict:
    """Emit NOTIFICATION_SENT or NOTIFICATION_FAILED for one delivery attempt.

    Deliberately absent from this record: the SMTP password, the SMTP username,
    the recipient addresses, the message body and the raw transport error. What is
    kept is a recipient COUNT and an error CATEGORY.

    That is not excessive caution. The audit partition is readable by every admin
    and is the most-copied data in the system, so it holds the least that still
    answers the question an auditor asks -- "was somebody told, and if not, why
    not?" -- and nothing that would help an attacker enumerate the analyst team
    or replay a credential.
    """
    if result.status == notifications.STATUS_THROTTLED:
        action = NOTIFICATION_THROTTLED
    elif result.status == notifications.STATUS_SENT:
        action = NOTIFICATION_SENT
    else:
        action = NOTIFICATION_FAILED
    # The synthetic-activity marker travels in `related`, but it belongs in
    # `after` next to `is_ground_truth`, which is where RISK_DECISION carries it.
    # An auditor filtering for demo activity must not have to look in two places.
    demo = bool(related.get("demo"))
    demo_scenario = related.get("demo_scenario")
    subject = {k: v for k, v in related.items()
               if v is not None and k not in ("demo", "demo_scenario")}
    after = {
            "status": result.status,
            "provider": result.provider,
            # Count, never addresses.
            "recipient_count": result.recipient_count,
            "error_category": result.error_category,
            # Machine-checkable, matching RISK_DECISION's field of the same name.
            "is_ground_truth": False,
            "note": NOTIFICATION_NOTE,
    }
    if demo:
        after["demo"] = True
        after["demo_scenario"] = demo_scenario

    return audit(
        actor="system:notifier",
        action=action,
        event_id=notification_id,
        before={
            "notification_id": notification_id,
            "event_type": event_type,
            "dedupe_key": dedupe_key,
            "subject_id": subject_id,
            # Which transaction / redemption / address this alert was about, so an
            # auditor can join the communication back to the decision.
            **subject,
        },
        after=after,
    )


# ---------------------------------------------------------------------------
# Notification dispatch
# ---------------------------------------------------------------------------
#
# PK = NOTIFICATION#<dedupe_key>    SK = DELIVERY
#
# One item per alertable EVENT, not per attempt. The key is deterministic
# (`manual_review:pay_abc`), so a redelivered webhook, a retried request or a
# burst of declines from one address all resolve to the same key and notify once.

NOTIFICATION_PK = "NOTIFICATION"
NOTIFICATION_SK = "DELIVERY"

# How many DynamoDB pages a single query_prefix() will follow before giving up and
# saying so. At 1 MB per page this is ~200 MB in one partition, which no partition
# in this design should ever reach -- reaching it means a bug, not a busy day.
MAX_QUERY_PAGES = 200


def _notification_item(dedupe_key: str) -> dict | None:
    records = STATE.get("records")
    if records is None:
        return None
    try:
        return records.get(f"{NOTIFICATION_PK}#{dedupe_key}", NOTIFICATION_SK)
    except Exception:  # noqa: BLE001
        # An unreadable store must not stop the alert. Worst case is a duplicate
        # email, which is strictly better than a missed one.
        return None


def notify(event_type: str, *, subject_id: str, subject: str, body: str,
           related: dict | None = None) -> dict | None:
    """Send one analyst alert. Best effort, deduplicated, audited, and INERT.

    THE FAILURE CONTRACT -- the most important property in this function
    ---------------------------------------------------------------------
    This function CANNOT raise. Every path is wrapped, including the persistence
    of its own bookkeeping and the emission of its own audit event.

    That is not defensive habit, it is the whole design. This is called from
    `create_order`, from the webhook and from the promo gate, all AFTER the
    decision has been made and persisted. If it could raise, an SMTP timeout
    would become an HTTP 500 on a payment that was already scored, already
    audited and already refused or queued -- turning an alerting outage into a
    checkout outage. A BLOCK must still block, a MANUAL_REVIEW must still reach
    the queue, and the audit trail must still be written, whether or not anybody
    can be told about it.

    Returns the notification record, or None when nothing was attempted. Callers
    ignore the return value; it exists for tests and for the admin endpoint.
    """
    try:
        return _notify(event_type, subject_id=subject_id, subject=subject,
                       body=body, related=related or {})
    except Exception as exc:  # noqa: BLE001
        # The last line of defence. Reaching here means the notification system
        # itself is broken in a way not otherwise handled -- which is an operator
        # problem, never a reason to fail a payment.
        print(f"WARNING: notification for {event_type}:{subject_id} raised "
              f"{type(exc).__name__} and was swallowed. The risk decision, its "
              f"persistence and its audit record are unaffected.")
        return None


# Alert volume ceiling. Five alerts per ten minutes, counted across every event
# type: a burst of transaction blocks and a suspicious-address flag draw from the
# same budget, because they arrive in the same mailbox.
#
# Chosen to be readable rather than clever. Five is enough that a genuine incident
# still produces a visible cluster, and low enough that a card-testing run cannot
# bury the one alert an analyst most needs to see.
ALERT_RATE_MAX = 5
ALERT_RATE_WINDOW = 600.0        # 10 minutes


# Event types the ceiling does NOT apply to.
#
# THE FAILURE THIS PREVENTS, found by a test rather than by inspection:
# a card-testing burst produces one transaction alert per declined payment, and
# those arrive BEFORE the address has crossed its decline threshold. So the
# per-transaction noise consumed the whole budget and the suspicious-address alert
# -- the one message that summarises the entire attack -- was throttled. The cap
# existed to stop noise burying the important alert and was doing the opposite.
#
# Exempt because it cannot flood on its own: SUSPICIOUS_IP is deduplicated to one
# alert per address for the life of the flag, so the number of these is bounded by
# distinct addresses crossing a threshold, not by traffic volume.
ALERT_RATE_EXEMPT = (notifications.EVENT_SUSPICIOUS_IP,)


def _alert_budget_available(event_type: str) -> bool:
    """Whether an alert may be sent now. Trims the window as a side effect.

    Called once per candidate alert, immediately before the send is claimed, so
    the count reflects deliveries ATTEMPTED rather than events considered.

    Exempt event types neither consume budget nor are blocked by it.
    """
    if event_type in ALERT_RATE_EXEMPT:
        return True
    now = time.time()
    sent: deque = STATE.setdefault("alert_times", deque())
    while sent and now - sent[0] > ALERT_RATE_WINDOW:
        sent.popleft()
    if len(sent) >= ALERT_RATE_MAX:
        return False
    sent.append(now)
    return True


def _notify(event_type: str, *, subject_id: str, subject: str, body: str,
            related: dict) -> dict | None:
    provider = STATE.get("email_provider")
    status = STATE.get("email_status") or {}
    if provider is None:
        return None

    key = notifications.dedupe_key(event_type, subject_id)
    records = STATE.get("records")

    # ---- in-process guard ------------------------------------------------
    # Checked before the store because a burst arrives faster than a round trip,
    # and because it works even when persistence is unavailable.
    seen: set = STATE.setdefault("notified", set())
    if key in seen:
        return {"dedupe_key": key, "status": notifications.STATUS_SUPPRESSED,
                "event_type": event_type, "duplicate": True}

    # ---- durable guard ---------------------------------------------------
    # Survives a restart, so a redelivered webhook after a deploy does not
    # re-alert on a transaction an analyst already has in their inbox.
    existing = _notification_item(key)
    if existing is not None:
        seen.add(key)
        return {**existing, "status": notifications.STATUS_SUPPRESSED,
                "duplicate": True}

    # ---- rate limit ------------------------------------------------------
    #
    # A cap on how many alerts leave the process in a rolling window, on top of
    # deduplication. Dedup answers "is this the same event twice?"; this answers
    # "is anyone going to read the 40th distinct alert this minute?"
    #
    # Deliberately NOT silent. A rate-limited alert is recorded with status
    # `throttled` and its own audit event, so the alert still exists as evidence
    # even though no email was sent. Dropping it quietly would mean the
    # notification log implied nothing happened.
    #
    # ORDERED AFTER THE RECIPIENT CHECK, and that ordering is load-bearing. With
    # no recipients configured there is no delivery to ration, so throttling first
    # would spend budget on alerts that were never going to be sent and would
    # record "withheld by volume" for a system where alerting is simply off. A test
    # caught this: an unrelated suite with no recipients started producing
    # NOTIFICATION_THROTTLED events attached to its transactions.
    #
    # This is a per-process counter, not a distributed one. Two instances would
    # each allow ALERT_RATE_MAX, which is the honest limitation of keeping it in
    # memory; it is a mailbox-volume control, not a security boundary.
    recipients_now = STATE.get("email_recipients") or ()
    if recipients_now and not _alert_budget_available(event_type):
        item = {
            "notification_id": f"ntf_{uuid.uuid4().hex[:12]}",
            "event_type": event_type,
            "dedupe_key": key,
            "subject_id": subject_id,
            "recipient_count": len(STATE.get("email_recipients") or ()),
            "provider": getattr(provider, "provider_name", "unknown"),
            "status": notifications.STATUS_THROTTLED,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "sent_at": None,
            "error": (f"rate limit reached: {ALERT_RATE_MAX} alerts per "
                      f"{int(ALERT_RATE_WINDOW // 60)} minutes"),
            "error_category": "rate_limited",
            "attempts": 0,
            **{k: v for k, v in related.items() if v is not None},
        }
        # NOT added to `seen`: a throttled alert was never delivered, so the same
        # event must remain eligible once the window clears. Suppressing it
        # permanently would turn a volume control into silent alert loss.
        _persist_notification(item)
        # Audited, because the withheld alert is still evidence that the situation
        # occurred. An audit trail that recorded only the alerts that happened to
        # fit inside the ceiling would under-report the incident it exists to
        # document.
        try:
            audit_notification(
                notification_id=item["notification_id"], event_type=event_type,
                result=notifications.SendResult(
                    provider=item["provider"],
                    status=notifications.STATUS_THROTTLED,
                    recipient_count=item["recipient_count"],
                    error=item["error"], error_category="rate_limited"),
                dedupe_key=key, subject_id=subject_id, related=related)
        except Exception as exc:  # noqa: BLE001
            print(f"WARNING: could not audit a throttled alert "
                  f"({type(exc).__name__}); the notification record is still "
                  f"present")
        print(f"NOTE: alert {event_type}:{subject_id} was rate limited "
              f"({ALERT_RATE_MAX} per {int(ALERT_RATE_WINDOW // 60)} min). It is "
              f"recorded with status={notifications.STATUS_THROTTLED} and remains "
              f"visible in the notification log.")
        return item

    # Claimed BEFORE sending. If the send hangs and the request is retried, the
    # retry is suppressed rather than sending a second copy -- the failure mode
    # this ordering prevents is a mailbox full of duplicates, and the cost of
    # getting it wrong the other way is one missed alert, which is visible in the
    # notification list and on /health.
    seen.add(key)

    notification_id = f"ntf_{uuid.uuid4().hex[:12]}"
    now = datetime.now(timezone.utc).isoformat()
    recipients = STATE.get("email_recipients") or ()

    item = {
        "notification_id": notification_id,
        "event_type": event_type,
        "dedupe_key": key,
        "subject_id": subject_id,
        # A count and the addresses. The addresses are needed here so an operator
        # can answer "who was told?" -- this item is admin-only and is NOT what
        # /health or the audit record publish.
        "recipient_count": len(recipients),
        "recipients": list(recipients),
        "provider": getattr(provider, "provider_name", "unknown"),
        "status": "pending",
        "created_at": now,
        "sent_at": None,
        "error": None,
        "error_category": None,
        "attempts": 0,
        **{k: v for k, v in related.items() if v is not None},
    }

    if not recipients:
        # Nothing to send to. Recorded as skipped rather than failed: an operator
        # who has configured no recipients has not suffered a delivery failure,
        # and calling it one would bury real failures in noise.
        item |= {"status": notifications.STATUS_SKIPPED,
                 "error": "no recipients configured",
                 "error_category": "no_recipients"}
        _persist_notification(item)
        return item

    result = None
    try:
        item["attempts"] = 1
        result = provider.send_email(
            to=recipients, subject=subject, body=body,
            metadata={"event_type": event_type, "subject_id": subject_id,
                      "notification_id": notification_id},
        )
    except Exception as exc:  # noqa: BLE001
        # A provider that raises rather than returning a result. Converted to a
        # failed result so the record and the audit event still happen.
        result = notifications.SendResult(
            provider=getattr(provider, "provider_name", "unknown"),
            status=notifications.STATUS_FAILED,
            recipient_count=len(recipients),
            error=f"provider raised {type(exc).__name__}",
            error_category="provider_exception")

    item |= {
        "status": result.status,
        "provider": result.provider,
        "error": result.error,
        "error_category": result.error_category,
        "sent_at": datetime.now(timezone.utc).isoformat() if result.ok else None,
    }
    _persist_notification(item)

    # Audited last, and guarded: a failure to record the communication must not
    # propagate into the caller's request.
    try:
        audit_notification(
            notification_id=notification_id, event_type=event_type,
            result=result, dedupe_key=key, subject_id=subject_id,
            related=related,
        )
    except Exception as exc:  # noqa: BLE001
        print(f"WARNING: could not audit notification {notification_id} "
              f"({type(exc).__name__}); the alert outcome is still recorded in "
              f"the notification list")

    if not result.ok:
        # Visible to operators without being a failure of the request. The status
        # is also on /v1/admin/notifications and counted on /health.
        print(f"WARNING: analyst alert {event_type} for {subject_id} was not "
              f"delivered ({result.error_category}). The risk decision stands "
              f"and is unaffected.")
    return item


def _persist_notification(item: dict) -> None:
    """Durable bookkeeping. Never raises.

    Cached in process regardless, so the admin endpoint and the tests still see
    the record even when the store is unavailable -- and `durable` says which.
    """
    records = STATE.get("records")
    durable = False
    if records is not None:
        try:
            records.put(f"{NOTIFICATION_PK}#{item['dedupe_key']}",
                        NOTIFICATION_SK, item)
            durable = True
        except Exception as exc:  # noqa: BLE001
            print(f"WARNING: could not persist notification "
                  f"{item.get('notification_id')} ({type(exc).__name__}); it is "
                  f"served from memory for this process only")
    item["durable"] = durable
    STATE.setdefault("notifications", []).append(item)


def notify_transaction(record: dict) -> dict | None:
    """Alert on a transaction that needs a human. Called after persistence.

    ALLOW returns immediately and sends nothing. That is the whole point of the
    gate being here rather than inside `notify()`: the decision about what
    deserves a human's attention belongs next to the decision itself, and it is
    one readable line.
    """
    decision = record.get("decision")
    if decision not in QUEUED_DECISIONS:      # MANUAL_REVIEW, BLOCK
        return None
    txn_id = record.get("transaction_id") or ""
    if not txn_id:
        return None
    subject, body = notifications.build_transaction_alert(
        event_type=decision, record=record,
        console_url=STATE.get("console_url", ""))
    return notify(decision, subject_id=txn_id, subject=subject, body=body,
                  related={"transaction_id": txn_id,
                           "order_id": record.get("order_id"),
                           "decision": decision,
                           "risk_score": record.get("risk_score"),
                           "amount": record.get("amount"),
                           # Propagated from the record, never invented here. None
                           # on real traffic, and `related` drops None, so a real
                           # alert carries no marker at all.
                           "demo": record.get("demo"),
                           "demo_scenario": record.get("demo_scenario")})


def notify_suspicious_ip(flag: dict) -> dict | None:
    """Alert on a newly flagged address.

    Called only where `flag["new"]` is true, mirroring the existing
    `ip_marked_suspicious` audit call -- so a persistently failing address
    produces one alert on the transition, not one per declined attempt.
    """
    ip_hash = flag.get("ip_hash") or ""
    if not ip_hash:
        return None
    subject, body = notifications.build_suspicious_ip_alert(
        flag=flag, window_minutes=int(IP_FAIL_WINDOW // 60),
        threshold=IP_FAIL_THRESHOLD,
        method_window_hours=int(IP_METHOD_WINDOW // 3600),
        method_threshold=IP_METHOD_THRESHOLD,
        instruments=_declined_instruments(ip_hash),
        console_url=STATE.get("console_url", ""))
    return notify(notifications.EVENT_SUSPICIOUS_IP, subject_id=ip_hash,
                  subject=subject, body=body,
                  related={"ip_hash": ip_hash,
                           "failures_total": flag.get("failures_total"),
                           "rule": flag.get("rule"),
                           "failed_method_count": flag.get("failed_method_count"),
                           "demo": flag.get("demo"),
                           "demo_scenario": flag.get("demo_scenario")})


def _declined_instruments(ip_hash: str) -> list[dict]:
    """The distinct instruments that failed from one address, newest first.

    Read from the IPFAIL# attempt records that create_order already writes, so
    this adds no new storage and no new field. Each entry carries only what those
    records hold: the method, the masked display, and the HMAC reference.

    Deliberately absent, because it is absent from the records too: the card
    number, the CVV and any bank credential. `validate_instrument` reduces a card
    to a fingerprint and discards the digits before an attempt is ever stored.

    Never raises. An alert that cannot list instruments is still worth sending.
    """
    records = STATE.get("records")
    if records is None:
        return []
    try:
        rows = records.query_prefix(f"IPFAIL#{ip_hash}", "ATTEMPT#")
    except Exception as exc:  # noqa: BLE001
        print(f"WARNING: could not read declined instruments for an alert "
              f"({type(exc).__name__}); the alert is sent without them")
        return []

    rows.sort(key=lambda r: r.get("created_at", ""), reverse=True)
    seen: set[str] = set()
    out: list[dict] = []
    for r in rows:
        ref = str(r.get("instrument_ref") or "")
        # Deduplicated on the reference: one card retried nine times is one
        # instrument, and listing it nine times would hide the breadth the alert
        # exists to show.
        if ref and ref in seen:
            continue
        if ref:
            seen.add(ref)
        out.append({
            "payment_method": r.get("payment_method"),
            "instrument_display": r.get("instrument_display"),
            "instrument_ref": ref or None,
        })
    return out


def notify_promo_hold(redemption: dict) -> dict | None:
    """Alert on a held or denied cashback claim."""
    if redemption.get("decision") not in PROMO_QUEUED_DECISIONS:
        return None
    rid = redemption.get("redemption_id") or ""
    if not rid:
        return None
    subject, body = notifications.build_promo_hold_alert(
        redemption=redemption, console_url=STATE.get("console_url", ""))
    return notify(notifications.EVENT_PROMO_HOLD, subject_id=rid,
                  subject=subject, body=body,
                  related={"redemption_id": rid,
                           "promo_code": redemption.get("promo_code"),
                           "decision": redemption.get("decision"),
                           "value": redemption.get("value")})


# System transition event: the ML layer could not be loaded and scoring fell back
# to rules + network. Not a decision, not ground truth, and it touches no label.
MODEL_FALLBACK_TRIGGERED = "MODEL_FALLBACK_TRIGGERED"

MODEL_FALLBACK_NOTE = (
    "ML model unavailable; rules + network fallback activated. Scoring continues "
    "with reweighted surviving layers. This is an operational state change, not a "
    "risk decision, and it does not label any transaction."
)


def audit_model_fallback(scorer: "Scorer") -> dict:
    """Emit MODEL_FALLBACK_TRIGGERED for a startup that could not load the model.

    Called once from lifespan, after the record store and STATE collections exist.
    It is NOT called from Scorer.__init__ for two reasons found by inspection:

      1. lifespan builds the Scorer before make_record_store(), so at construction
         time there is no audit persistence to write to.
      2. ml/ and tests/test_score_parity.py construct a bare Scorer() with no
         application STATE at all, and a constructor that audited would either
         crash there or silently pollute a log that does not belong to it.

    Emitting from lifespan also gives the duplicate protection for free: one
    application startup is one event, so no volume of scored transactions can add
    another.

    The failure is at LOAD time, not at scoring time, and the wording says so --
    claiming the model failed mid-scoring would misdirect whoever reads this later.
    """
    return audit(
        actor="system:scorer",
        action=MODEL_FALLBACK_TRIGGERED,
        event_id=f"mfb_{uuid.uuid4().hex[:12]}",
        before={
            # The nominal state this startup was expected to reach. The process
            # never actually held a loaded model, so this is the expectation that
            # was not met rather than an observed earlier state.
            "model_loaded": True,
            "degraded": False,
        },
        after={
            "model_loaded": False,
            "degraded": True,
            "model_version": scorer.model_version,
            "phase": "artifact_load",
            "missing_artifacts": list(scorer.missing_artifacts),
            "artifacts_dir": scorer.artifacts_dir,
            "fallback_layers": ["rules", "network"],
            "fallback_weights": {
                "rules": W_FALLBACK_RULES,
                "network": W_FALLBACK_NETWORK,
            },
            "thresholds": {"review": scorer.review_t, "block": scorer.block_t},
            "is_ground_truth": False,
            "note": MODEL_FALLBACK_NOTE,
        },
    )


# =============================================================================
# 5c. Durable transaction + review queue persistence
# =============================================================================
#
# Before this existed, STATE["txns"] and STATE["queue"] were the only home for
# scored transactions and the analyst backlog, so a restart emptied the console.
#
# SOURCE OF TRUTH is the record store. STATE["txns"] / STATE["queue"] are now a
# read cache, rebuilt from the store at startup by rehydrate_state(). The app is
# correct if they start empty; they exist so the hot path and the admin reads stay
# in-process rather than issuing a query per request.
#
# Item shapes, following the existing single-table PK/SK conventions:
#
#   TXN#<transaction_id>  / DETAIL
#       The full scored transaction: score, decision, sub-scores, reason codes,
#       fired rules, model version, degraded flag, raw features, label. This is
#       the authoritative copy that the analyst detail view reads.
#
#   INDEX#TXN             / <iso>#<transaction_id>
#       Pointer only. Exists so startup can rehydrate the most recent N
#       transactions with a single bounded query instead of a table scan. Sorted
#       by time so "most recent N" is a query limit, not a filter.
#
#   QUEUE#REVIEW          / ITEM#<transaction_id>
#       Queue membership plus `status` (open | resolved).
#
# Two deliberate choices worth stating:
#
#   The queue SK is keyed on transaction_id ALONE, not on time or risk. That makes
#   resolving an item a direct update_fields() rather than a scan for its sort key,
#   and costs nothing in ordering because /v1/admin/queue has always sorted by
#   -risk_score in Python. Encoding risk into the SK would have made the stored
#   order authoritative and silently changed queue ordering semantics.
#
#   Resolution is a status flip, not a delete: the record store interface has no
#   delete, and inventing one for this would be a wider change than the task
#   needs. Rehydration loads only `status == "open"`, so the observable behaviour
#   of /v1/admin/queue is identical to the old list.remove().

# How many recent transactions to pull back into the cache at startup. Bounded on
# purpose: this is a query on ONE partition plus N point-gets, never a scan, and it
# runs once per process rather than per request.
REHYDRATE_TXNS = int(os.environ.get("FRAUDSHIELD_REHYDRATE_TXNS", "200"))

# Decisions that place a transaction in the analyst queue. Read from here rather
# than repeated inline, but the membership is unchanged: BLOCK is queued alongside
# MANUAL_REVIEW, which is the behaviour that already existed.
QUEUED_DECISIONS = ("MANUAL_REVIEW", "BLOCK")


# ---------------------------------------------------------------------------
# Durable threshold configuration
# ---------------------------------------------------------------------------
#
# THE GAP THIS CLOSES
# -------------------
# A threshold change used to live only on the Scorer instance, so `PUT
# /v1/admin/thresholds` was audited, applied, and then silently discarded by the
# next restart. An admin who tightened the block gate at 3am found it back at 70
# after a deploy, with an audit trail insisting they had changed it. That is worse
# than not having the control: the log and the behaviour disagreed.
#
# Stored through the SAME single-table record store as everything else -- no ORM,
# no new datastore, one item:
#
#     PK = CONFIG            SK = RISK_THRESHOLDS
#
# ONE ITEM, OVERWRITTEN, NOT AN EVENT LOG
# ---------------------------------------
# The current configuration is a single mutable item. Its history lives in the
# append-only audit partition, which already records before/after/actor for every
# change -- so the history is not lost, it is just not kept here. Keeping a second
# copy would create two answers to "what changed when".
CONFIG_PK = "CONFIG"
CONFIG_SK_THRESHOLDS = "RISK_THRESHOLDS"

# The audited action name for a threshold change.
#
# Deliberately lower-case, unlike RISK_DECISION / OUTCOME_RECORDED / PROMO_OVERRIDE.
# This event type already exists in persisted audit partitions and in the console's
# threshold-history view under this exact spelling. Renaming it would orphan every
# historical record -- a filter for the new name would silently return nothing for
# past changes, which is precisely the failure mode an audit trail must not have.
# The constant exists so the emitter, the retrieval filter and the UI cannot drift.
THRESHOLD_UPDATE = "threshold_update"


def validate_thresholds(review: float, block: float) -> tuple[float, float]:
    """Coerce and check a threshold pair. Raises ValueError with a stated reason.

    The invariant is 0 <= review < block <= 100. `review == block` is rejected
    rather than tolerated: with both equal there is no MANUAL_REVIEW band at all,
    so every flagged transaction would be refused outright and the human review
    step -- the thing that makes this system defensible -- would vanish silently.
    """
    try:
        r, b = float(review), float(block)
    except (TypeError, ValueError):
        raise ValueError("thresholds must be numbers") from None
    if r != r or b != b:                      # NaN, which compares false to all
        raise ValueError("thresholds must not be NaN")
    if not 0 <= r <= 100:
        raise ValueError(f"review threshold {r} is outside 0..100")
    if not 0 <= b <= 100:
        raise ValueError(f"block threshold {b} is outside 0..100")
    if r >= b:
        raise ValueError(
            f"review threshold {r} must be below block threshold {b}")
    return r, b


def persist_thresholds(records, *, review: float, block: float,
                       actor: str, reason: str = "") -> dict:
    """Write the configuration item. Returns the stored payload.

    `version` is a monotonically increasing counter read from the existing item.
    It is NOT optimistic concurrency control -- there is no conditional write here
    -- it is a human-readable "this is the 4th change" for an operator comparing a
    running process against the table. Two simultaneous admins would both write
    version 4; the audit trail still records both changes, which is what matters.
    """
    previous = 0
    try:
        existing = records.get(CONFIG_PK, CONFIG_SK_THRESHOLDS)
        if isinstance(existing, dict):
            previous = int(existing.get("version") or 0)
    except Exception:  # noqa: BLE001
        # An unreadable existing item must not block a threshold change. Version
        # restarts from 1 and the audit trail is unaffected.
        previous = 0

    item = {
        "review_threshold": float(review),
        "block_threshold": float(block),
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "updated_by": actor,
        "version": previous + 1,
        # Free text from the operator. Recorded, never interpreted.
        "reason": reason or None,
    }
    records.put(CONFIG_PK, CONFIG_SK_THRESHOLDS, item)
    return item


def load_persisted_thresholds(records, scorer: "Scorer") -> dict:
    """Apply stored thresholds to the scorer. Returns a /health-safe status dict.

    FAILURE POLICY -- this function must never stop the service from starting.
    A corrupt configuration item is an operator problem, not a reason to refuse
    every checkout. So an unreadable, absent or invalid item leaves the scorer on
    the environment defaults it was constructed with, and the reason is printed and
    published rather than raised.

    That choice has a sharp edge worth naming: falling back means the running
    thresholds are NOT the ones an admin last set. Silently serving the defaults
    while the table says otherwise would be the same log-versus-behaviour lie this
    whole feature exists to fix, which is why `degraded` is surfaced on /health and
    warned about at startup rather than only logged at debug level.
    """
    status = {
        "source": "env",
        "review": scorer.review_t,
        "block": scorer.block_t,
        "env_defaults": {"review": DEFAULT_REVIEW_T, "block": DEFAULT_BLOCK_T},
        "version": None,
        "updated_at": None,
        "updated_by": None,
        "degraded": False,
        "note": ("no persisted configuration; using environment defaults "
                 "FRAUDSHIELD_REVIEW_T / FRAUDSHIELD_BLOCK_T"),
    }

    try:
        item = records.get(CONFIG_PK, CONFIG_SK_THRESHOLDS)
    except Exception as exc:  # noqa: BLE001
        status["degraded"] = True
        status["note"] = (
            f"could not read persisted thresholds ({type(exc).__name__}); "
            f"serving environment defaults")
        return status

    if not isinstance(item, dict):
        return status                          # absent, which is not a failure

    try:
        review, block = validate_thresholds(item.get("review_threshold"),
                                            item.get("block_threshold"))
    except ValueError as exc:
        # Invalid stored configuration. Refusing to start would turn one bad write
        # into a total outage; applying it would move every future decision to a
        # value nobody validated.
        status["degraded"] = True
        status["note"] = (
            f"persisted thresholds are invalid and were IGNORED ({exc}); "
            f"serving environment defaults "
            f"review >= {DEFAULT_REVIEW_T}, block >= {DEFAULT_BLOCK_T}")
        status["rejected"] = {
            "review": item.get("review_threshold"),
            "block": item.get("block_threshold"),
            "version": item.get("version"),
        }
        return status

    scorer.review_t = review
    scorer.block_t = block
    status.update({
        "source": "persisted",
        "review": review,
        "block": block,
        "version": item.get("version"),
        "updated_at": item.get("updated_at"),
        "updated_by": item.get("updated_by"),
        "note": "restored from the record store; survives restart",
    })
    return status


def _txn_created_at(record: dict) -> str:
    """Timestamp used for the rehydration sort key.

    create_order and payment_webhook set `created_at`; /v1/risk/score records only
    `scored_at`. Falls back through both rather than assuming one shape.
    """
    return (record.get("created_at") or record.get("scored_at")
            or datetime.now(timezone.utc).isoformat())


def persist_scored_transaction(records, record: dict) -> bool:
    """Write the authoritative transaction item and its rehydration pointer.

    Returns True only if BOTH writes landed. The caller decides what to do with a
    False -- nothing here pretends a failed write succeeded.
    """
    txn_id = record["transaction_id"]
    records.put(f"TXN#{txn_id}", "DETAIL", record)
    # The pointer carries a minimal REPLAY PROJECTION: exactly the fields
    # InMemoryStore.commit() consumes, and nothing else.
    #
    # Why project rather than point: rebuilding entity state needs to walk
    # thousands of historical transactions, and doing that as one query over this
    # partition costs a single read instead of N point-gets against
    # TXN#<id>/DETAIL. That is what a GSI projection would buy, without creating
    # a GSI the access pattern does not otherwise need.
    #
    # These fields cannot drift from the authoritative record: both items are
    # written here from the same dict in the same call, and nothing ever updates
    # the projection afterwards. Mutable state -- label, labelled_by, queue status
    # -- is deliberately NOT projected, so there is still exactly one place to
    # write it.
    records.put("INDEX#TXN", f"{_txn_created_at(record)}#{txn_id}", {
        "transaction_id": txn_id,
        "customer_id": record.get("customer_id"),
        "amount": record.get("amount"),
        "payment_method": record.get("payment_method"),
        "device_fp": record.get("device_fp"),
        "ip_hash": record.get("ip_hash"),
        "settlement": record.get("settlement"),
        "created_at": _txn_created_at(record),
        # Absent means committed: the storefront and webhook paths always apply
        # their transaction to entity state. Only /v1/risk/score can decline.
        "committed": record.get("committed", True),
    })
    return True


def enqueue_review_item(records, record: dict) -> bool:
    """Add a transaction to the durable review queue."""
    txn_id = record["transaction_id"]
    records.put(f"QUEUE#REVIEW", f"ITEM#{txn_id}", {
        "transaction_id": txn_id,
        "order_id": record.get("order_id"),
        "customer_id": record.get("customer_id"),
        "risk_score": record.get("risk_score"),
        "decision": record.get("decision"),
        "created_at": _txn_created_at(record),
        "status": "open",
    })
    return True


def record_scored_transaction(record: dict) -> bool:
    """The single write path for a scored transaction, used by all three entry
    points (storefront order, webhook ingestion, service scoring).

    Updates the in-process cache first so the transaction is visible to this
    process even if the durable write fails, then persists. Returns whether the
    durable write succeeded.

    A persistence failure must not fail a payment that has already been
    authorised, so the exception is caught -- but the record is flagged
    `durable: False` and a warning is printed, so the gap is observable rather
    than silent. The alternative, raising, would reject a payment the customer
    has already made.
    """
    txn_id = record["transaction_id"]
    queued = record.get("decision") in QUEUED_DECISIONS
    records = STATE.get("records")

    durable = False
    if records is not None:
        try:
            persist_scored_transaction(records, record)
            if queued:
                enqueue_review_item(records, record)
            durable = True
        except Exception as exc:  # noqa: BLE001
            print(f"WARNING: durable write failed for {txn_id} "
                  f"({type(exc).__name__}). Transaction is served from memory for "
                  f"this process only and will NOT survive a restart"
                  + ("; a MANUAL_REVIEW/BLOCK item may be lost" if queued else ""))

    STATE["txns"][txn_id] = {**record, "durable": durable}
    if queued and txn_id not in STATE["queue"]:
        STATE["queue"].append(txn_id)
    return durable


def resolve_review_item(txn_id: str) -> bool:
    """Mark a queue item resolved, and drop it from the in-process queue.

    Mirrors the pre-existing STATE["queue"].remove(txn_id): the item stops
    appearing in /v1/admin/queue. The durable item is retained with
    status=resolved rather than deleted, so the fact that it was once queued
    survives -- and because the store has no delete.
    """
    if txn_id in STATE["queue"]:
        STATE["queue"].remove(txn_id)

    records = STATE.get("records")
    if records is None:
        return False
    try:
        records.update_fields(f"QUEUE#REVIEW", f"ITEM#{txn_id}", {
            "status": "resolved",
            "resolved_at": datetime.now(timezone.utc).isoformat(),
        })
        return True
    except Exception as exc:  # noqa: BLE001
        print(f"WARNING: could not mark review item {txn_id} resolved "
              f"({type(exc).__name__}); it may reappear in the queue after a "
              f"restart")
        return False


def update_persisted_transaction(txn_id: str, fields: dict) -> bool:
    """Apply a field update to the durable transaction item.

    Used when a human records an outcome. The in-process cache is updated by the
    caller; this makes the change survive a restart.
    """
    records = STATE.get("records")
    if records is None:
        return False
    try:
        records.update_fields(f"TXN#{txn_id}", "DETAIL", fields)
        return True
    except Exception as exc:  # noqa: BLE001
        print(f"WARNING: could not persist update to {txn_id} "
              f"({type(exc).__name__}); the change is in memory only")
        return False


def rehydrate_state(records) -> tuple[int, int]:
    """Rebuild the transaction cache and review queue from durable storage.

    Returns (transactions_loaded, queue_items_loaded).

    Access pattern, deliberately bounded and scan-free:
      1. one query on INDEX#TXN, newest first, take at most REHYDRATE_TXNS ids
      2. one point-get per id for the authoritative TXN#<id>/DETAIL item
      3. one query on QUEUE#REVIEW for membership, keeping only status == "open"

    No GSI is created. Both access patterns fall out of the primary key design, so
    adding one would cost money and buy nothing.

    Reloading NEVER re-scores. The stored decision and score are authoritative, and
    no RISK_DECISION event is emitted here -- those record the moment a decision was
    made, not the moment it was read back.
    """
    if records is None:
        return 0, 0

    txns: dict[str, dict] = {}
    try:
        pointers = records.query_prefix("INDEX#TXN", "", desc=True)
    except Exception as exc:  # noqa: BLE001
        print(f"WARNING: could not list transactions for rehydration "
              f"({type(exc).__name__}); starting with an empty cache")
        pointers = []

    for p in pointers[:REHYDRATE_TXNS]:
        tid = p.get("transaction_id")
        if not tid:
            continue
        try:
            item = records.get(f"TXN#{tid}", "DETAIL")
        except Exception:  # noqa: BLE001
            continue
        if item:
            txns[tid] = {k: v for k, v in item.items() if k not in ("PK", "SK")}

    queue: list[str] = []
    try:
        for q in records.query_prefix("QUEUE#REVIEW", "ITEM#", desc=True):
            if q.get("status") != "open":
                continue
            tid = q.get("transaction_id")
            if not tid:
                continue
            if tid not in txns:
                # Queued but outside the rehydration window. Load it anyway: an
                # unreviewed item is exactly what must not be dropped, so the
                # cap applies to history, never to the backlog.
                try:
                    item = records.get(f"TXN#{tid}", "DETAIL")
                except Exception:  # noqa: BLE001
                    continue
                if not item:
                    continue
                txns[tid] = {k: v for k, v in item.items()
                             if k not in ("PK", "SK")}
            queue.append(tid)
    except Exception as exc:  # noqa: BLE001
        print(f"WARNING: could not rebuild the review queue "
              f"({type(exc).__name__}); it will be empty until new traffic arrives")

    STATE["txns"] = txns
    STATE["queue"] = queue
    return len(txns), len(queue)


# How many persisted transactions to replay into entity state at startup.
#
# Separate from REHYDRATE_TXNS, and larger, because the two serve different needs.
# REHYDRATE_TXNS bounds what the CONSOLE shows; this bounds what the SCORER
# remembers, and the scorer's features reach further back:
#
#   txn_count_10m / 1h, failed_count_*   minutes -- a few records
#   seconds_since_last_txn, methods_1h   the customer's most recent activity
#   prev_txn_count, customer_avg_amount  the customer's WHOLE history
#   trusted_floor override               requires prev_txn_count > 50
#   device/ip account+txn counts          every transaction on that entity
#
# So a 200-record horizon would be wrong here: it would shrink prev_txn_count and
# customer_avg_amount, and could silently drop an established customer below the
# trusted_floor threshold. This is a bounded window, not "all history" -- see the
# horizon note in README section 17.
REHYDRATE_GRAPH_TXNS = int(os.environ.get("FRAUDSHIELD_REHYDRATE_GRAPH_TXNS",
                                          "5000"))

# Fields the replay needs from a pointer before it can be committed.
_REPLAY_REQUIRED = ("customer_id", "device_fp", "ip_hash", "payment_method")


def _iso_to_epoch(value: str | None) -> float | None:
    """ISO-8601 -> epoch seconds, or None if unparseable."""
    if not value or not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value).timestamp()
    except ValueError:
        return None


def rehydrate_entity_state(store: InMemoryStore, records, users) -> dict:
    """Rebuild velocity counters and the entity graph from persisted transactions.

    Without this a restart leaves the graph and every velocity counter at zero, so
    an established customer scores like a brand-new one: `new_account` and
    `new_device` fire, `prev_txn_count` is 0, `customer_avg_amount` falls back to
    the global prior, and the network layer sees no cluster at all. The transaction
    records were already durable; their EFFECT on state was not.

    Replays through the existing InMemoryStore.commit(), which is the same path
    warm_store() has always used for historical CSV rows. The scoring algorithm,
    the feature builder and every weight and threshold are untouched -- this
    restores inputs, it does not compute anything new.

    CHRONOLOGICAL ORDER IS MANDATORY, not a preference. The velocity deques are
    trimmed from the left on the assumption that they are time-ordered
    (`while dq and now - dq[0] > window`), and RunningHour plus the running amount
    mean accumulate incrementally. Replaying newest-first would corrupt all three.
    Pointers are therefore re-sorted ascending even though they are queried
    newest-first for the horizon cut.

    Returns a summary dict, also surfaced on /health.
    """
    summary = {
        "replayed": 0, "skipped": 0, "customers": 0, "devices": 0, "ips": 0,
        "edges": 0, "horizon": REHYDRATE_GRAPH_TXNS, "truncated": False,
        "complete": False, "duration_ms": 0.0,
    }
    if records is None:
        return summary

    t0 = time.perf_counter()
    try:
        pointers = records.query_prefix("INDEX#TXN", "", desc=True)
    except Exception as exc:  # noqa: BLE001
        print(f"WARNING: could not read transaction history for entity-state "
              f"rehydration ({type(exc).__name__}). Velocity counters and the "
              f"entity graph start COLD; network risk will under-score until "
              f"traffic rebuilds")
        summary["duration_ms"] = round((time.perf_counter() - t0) * 1000, 1)
        return summary

    summary["truncated"] = len(pointers) > REHYDRATE_GRAPH_TXNS
    window = pointers[:REHYDRATE_GRAPH_TXNS]

    # Newest-first for the cut, then ascending for the replay itself.
    events: list[dict] = []
    for p in window:
        # A dry-run scoring (commit=false) was deliberately never applied to
        # entity state. Replaying it would apply an effect the caller declined,
        # so the record stays queryable but contributes nothing to counters.
        # Not counted as skipped: nothing is missing, it was never meant to land.
        if p.get("committed") is False:
            continue

        ts = _iso_to_epoch(p.get("created_at"))
        if ts is None:
            summary["skipped"] += 1
            continue
        # Missing device or IP must never be invented: a fabricated value would
        # either fuse unrelated accounts into a fake cluster or split one real
        # actor across several. Skipping keeps the graph honest and is what the
        # sentinel behaviour elsewhere already implies.
        if any(not p.get(f) for f in _REPLAY_REQUIRED):
            summary["skipped"] += 1
            continue
        try:
            amount = float(p.get("amount") or 0.0)
        except (TypeError, ValueError):
            summary["skipped"] += 1
            continue
        events.append({
            "customer_id": str(p["customer_id"]),
            "ts": ts,
            "amount": amount,
            "payment_method": str(p["payment_method"]),
            "device_fp": str(p["device_fp"]),
            "ip_hash": str(p["ip_hash"]),
            # commit() reads `status`; the record stores it as `settlement`.
            "status": "failed" if p.get("settlement") == "failed" else "success",
        })

    events.sort(key=lambda e: e["ts"])

    # Account creation time, preferred over first_seen by account_age_hours. Taken
    # from the user store, mirroring what warm_store() does with
    # account_created_at, so an established customer is not aged from their first
    # REPLAYED transaction when their real signup is older.
    earliest: dict[str, float] = {}
    for e in events:
        cid = e["customer_id"]
        if cid not in earliest:
            earliest[cid] = e["ts"]
            created = None
            if users is not None:
                try:
                    u = users.get(cid)
                    created = _iso_to_epoch(u.created_at) if u else None
                except Exception:  # noqa: BLE001
                    created = None
            if created is not None:
                store.register_customer(cid, created)

    for e in events:
        try:
            dt = datetime.fromtimestamp(e["ts"], tz=timezone.utc)
            store.commit({**e, "hour": dt.hour + dt.minute / 60.0})
            summary["replayed"] += 1
        except Exception:  # noqa: BLE001
            # One malformed row must not abort startup and lose the rest.
            summary["skipped"] += 1

    # first_seen is set by build_online_features, NOT by commit(), so a
    # commit-only replay would leave it None and account_age_hours would measure
    # from `now` -- making every rehydrated customer look brand new and firing the
    # new_account rule across the board. Set it explicitly from the earliest
    # replayed transaction; register_customer above still takes precedence.
    for cid, first_ts in earliest.items():
        c = store.customer(cid)
        if c.first_seen is None or first_ts < c.first_seen:
            c.first_seen = first_ts

    summary["customers"] = len(earliest)
    summary["devices"] = len(store._dev)
    summary["ips"] = len(store._ip)
    summary["edges"] = sum(len(v) for v in store.acct_devices.values()) + \
        sum(len(v) for v in store.acct_ips.values())
    # "complete" means every persisted transaction was replayed. False whenever
    # the horizon truncated history or any record was skipped, so /health never
    # implies a fully warm graph that is not.
    summary["complete"] = not summary["truncated"] and summary["skipped"] == 0
    summary["duration_ms"] = round((time.perf_counter() - t0) * 1000, 1)
    return summary


# Promo decisions that place a redemption in the analyst hold queue. Unchanged
# from what redeem_promo has always done -- DENY is queued alongside HOLD, because
# a refused claim still needs a human to confirm the gate was right.
PROMO_QUEUED_DECISIONS = ("HOLD", "DENY")


def rehydrate_promo_queue(records) -> dict:
    """Rebuild STATE["promo_queue"] from persisted promo redemptions.

    The durable records already carry everything needed, so nothing new is
    authoritative here. A hold is OPEN when both are true:

        decision in ("HOLD", "DENY")      the gate held or refused it
        override_by is None               no analyst has resolved it

    That is exactly the filter GET /v1/admin/promo-holds already applies, so the
    reconstructed queue and the endpoint agree by construction rather than by
    coincidence.

    ACCESS PATTERN, no scan and no new GSI:
        1. one query on INDEX#PROMO -- every redemption pointer lives in that
           single partition, keyed by redemption id
        2. skip pointers whose (immutable) decision was ALLOW, and those already
           hinted resolved
        3. one point-get per remaining candidate for the authoritative record
        4. confirm override_by is None on that record before enqueueing

    Step 2 is a read optimisation only. The authoritative CUSTOMER#/PROMO# item is
    always what decides, so a stale or missing hint can cost an extra get but can
    never resurrect a resolved hold or hide an open one.

    NO TIME HORIZON. Unlike transaction history, an unresolved analyst hold must
    never age out of view -- losing the oldest backlog item is precisely the
    failure this is meant to prevent. The bound here is status, not age, and the
    open set is naturally small because analysts drain it.

    Never calls score_promo(): the stored decision is authoritative, and
    re-deciding on restart could contradict what the customer was already told.
    Emits no audit event either -- reconstruction is a read, not an action.
    """
    summary = {"open": 0, "resolved": 0, "allowed": 0, "skipped": 0,
               "examined": 0, "complete": False, "duration_ms": 0.0}
    if records is None:
        return summary

    t0 = time.perf_counter()
    try:
        pointers = records.query_prefix("INDEX#PROMO", "", desc=True)
    except Exception as exc:  # noqa: BLE001
        print(f"WARNING: could not read promo redemptions ({type(exc).__name__}). "
              f"The analyst promo hold queue starts EMPTY; unresolved holds are "
              f"not lost from storage but are not visible until this is fixed")
        summary["duration_ms"] = round((time.perf_counter() - t0) * 1000, 1)
        return summary

    queue: list[str] = []
    for p in pointers:
        summary["examined"] += 1
        rid = p.get("redemption_id") or p.get("SK")
        cid, sk = p.get("customer_id"), p.get("sk")
        if not rid or not cid or not sk:
            summary["skipped"] += 1
            continue

        # Immutable, so safe to filter on. Absent on pointers written before this
        # projection existed -- fall through and let the record decide.
        if p.get("decision") not in (None, *PROMO_QUEUED_DECISIONS):
            summary["allowed"] += 1
            continue
        if p.get("resolved") is True:
            summary["resolved"] += 1
            continue

        try:
            r = records.get(f"CUSTOMER#{cid}", sk)
        except Exception:  # noqa: BLE001
            summary["skipped"] += 1
            continue
        if not r:
            summary["skipped"] += 1
            continue

        if r.get("decision") not in PROMO_QUEUED_DECISIONS:
            summary["allowed"] += 1
            continue
        if r.get("override_by") is not None:
            summary["resolved"] += 1
            continue

        # Stable identity: the redemption id. Guards against a duplicate pointer
        # producing the same hold twice across repeated startups.
        if rid not in queue:
            queue.append(rid)

    STATE["promo_queue"] = queue
    summary["open"] = len(queue)
    summary["complete"] = summary["skipped"] == 0
    summary["duration_ms"] = round((time.perf_counter() - t0) * 1000, 1)
    return summary


class CartLine(BaseModel):
    product_id: str
    qty: int = Field(default=1, ge=1, le=10)


class CardDetails(BaseModel):
    """Captured, fingerprinted, then discarded.

    The PAN is NEVER stored, logged, or passed to the risk engine. Only a salted
    fingerprint of it survives this request, which is enough to count instrument
    reuse across accounts without holding card data. A real integration would let
    the gateway tokenise client-side so the PAN never reaches this server at all.
    """

    number: str = Field(min_length=12, max_length=19)
    expiry_month: int = Field(ge=1, le=12)
    expiry_year: int = Field(ge=2024, le=2100)
    cvv: str = Field(min_length=3, max_length=4)
    holder: str = Field(default="", max_length=80)


class UpiDetails(BaseModel):
    vpa: str = Field(min_length=5, max_length=60)


class NetbankingDetails(BaseModel):
    bank_code: str = Field(min_length=2, max_length=12)


class WalletDetails(BaseModel):
    provider: str = Field(min_length=2, max_length=24)
    phone: str = Field(min_length=10, max_length=13)


class OrderRequest(BaseModel):
    """`ip_hash` is deliberately absent. It is derived from the connection.

    `device_fp` stays client-supplied because a browser fingerprint inherently is
    — which is exactly why device signals must be corroborated by payout reuse or
    velocity rather than trusted alone.
    """

    items: list[CartLine] = Field(min_length=1, max_length=20)
    # `cod` is deliberately NOT accepted any more. Cash on delivery carries no
    # instrument to fingerprint, so it produces no card/UPI/wallet reuse signal and
    # cannot be declined by a gateway -- it was the one method the risk engine had
    # nothing to say about.
    #
    # Note it REMAINS in PAYMENT_METHODS and in feature_spec.json. The model was
    # trained with a `method_cod` one-hot column, so deleting it there would change
    # the feature matrix out from under the artifact and break offline/online
    # parity. Historical COD transactions still score correctly; new ones are simply
    # not offered.
    payment_method: str = Field(pattern="^(upi|card|netbanking|wallet)$")
    device_fp: str = Field(min_length=3, max_length=128)
    card: CardDetails | None = None
    upi: UpiDetails | None = None
    netbanking: NetbankingDetails | None = None
    wallet: WalletDetails | None = None


class ReturnRequest(BaseModel):
    order_id: str
    reason: str = Field(min_length=3, max_length=60)
    detail: str = Field(default="", max_length=500)


@app.get("/v1/catalog/products")
def catalog() -> dict:
    return {
        "products": [{"id": k, **v} for k, v in CATALOGUE.items()],
        "payment_methods": [
            {"code": "upi", "label": "UPI", "needs": "vpa"},
            {"code": "card", "label": "Card", "needs": "card"},
            {"code": "netbanking", "label": "Netbanking", "needs": "bank"},
            {"code": "wallet", "label": "Wallet", "needs": "wallet"},
        ],
        "banks": [{"code": k, "name": v} for k, v in BANKS.items()],
        "wallets": WALLETS,
    }


@app.post("/v1/orders", status_code=201)
def create_order(req: OrderRequest, request: Request,
                 u: User = Depends(current_user)) -> dict:
    """Create a multi-item order, score it, authorise it, persist it.

    Three inputs are deliberately NOT taken from the request body:
      - ip_hash   derived from the connection (see ip_hash_of)
      - amount    computed from the catalogue, never trusted from the client
      - status    decided by the payment provider, not declared by the caller

    All three were previously client-controlled, and each one let a caller poison
    the features the model depends on.

    Authorisation goes through STATE["payment_provider"], which is either the
    simulator or the Razorpay adapter. Scoring happens BEFORE that call and does
    not depend on its result, so swapping providers cannot change a decision.
    """
    lines = []
    total = 0.0
    for line in req.items:
        p = CATALOGUE.get(line.product_id)
        if p is None:
            raise HTTPException(404, f"Unknown product {line.product_id}.")
        if line.qty > p["stock"]:
            raise HTTPException(409, f"{p['name']}: only {p['stock']} left.")
        total += p["price"] * line.qty
        lines.append({"product_id": line.product_id, "name": p["name"],
                      "qty": line.qty, "unit_price": p["price"]})

    instrument_ref, instrument_display = validate_instrument(req)

    store: InMemoryStore = STATE["store"]
    scorer: Scorer = STATE["scorer"]
    records = STATE["records"]

    ts = datetime.now(timezone.utc).timestamp()
    ipa = ip_hash_of(request)
    txn = {
        "customer_id": u.user_id, "ts": ts, "amount": round(total, 2),
        "payment_method": req.payment_method, "device_fp": req.device_fp,
        "ip_hash": ipa,
    }

    try:
        d, raw = scorer.score(store, txn)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            503, detail={"decision": "MANUAL_REVIEW", "reason": "SCORING_UNAVAILABLE",
                         "error": type(exc).__name__},
        ) from exc

    # Minted before authorisation so OUR order id can be handed to the provider as
    # the reference that ties their order back to this one. They stay separate
    # identifiers: provider ids are recorded alongside these, never in place of
    # them.
    order_id = f"ord_{uuid.uuid4().hex[:10]}"
    txn_id = f"pay_{uuid.uuid4().hex[:10]}"

    # Settlement is decided here, AFTER scoring and server-side, exactly as before.
    # The only change is that the gateway is now behind an interface.
    auth = STATE["payment_provider"].authorise(
        order_id=order_id, amount=total, method=req.payment_method,
        decision=d.decision, customer_id=u.user_id,
        # Forwarded so a later webhook from a real provider can still be joined to
        # this device and address. Absent values are omitted, not invented -- see
        # payments.authorise_metadata.
        metadata={"device_fp": req.device_fp, "ip_hash": ipa},
    )
    settled = auth.settlement

    # Read-before-write: features were read above; state is applied only now.
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    store.commit({**txn, "status": settled, "hour": dt.hour + dt.minute / 60.0})

    if settled == payments.SETTLED_FAILED and d.decision != "BLOCK":
        # An innocent decline, not a risk decision. Saying "we couldn't process
        # this" is accurate; implying suspicion would be wrong.
        status_key = "declined_by_bank"
        message = ("Your bank declined this payment. Try another method or "
                   "contact them.")
    elif settled == payments.SETTLED_PENDING:
        # A real provider settles asynchronously: the order exists, the payment
        # does not yet. Reporting "confirmed" here would claim money we have not
        # taken, so the customer gets the existing "verifying" state, which already
        # means "unresolved, something will resolve it". The simulator never
        # reaches this branch.
        status_key, message = CUSTOMER_MESSAGE["MANUAL_REVIEW"]
    else:
        status_key, message = CUSTOMER_MESSAGE[d.decision]

    # ---- failed attempt: persist it, then reconsider the address -------------
    #
    # The attempt is stored whether or not it trips the threshold. A flag with no
    # underlying records is unauditable -- an analyst asked "why is this IP
    # flagged?" needs the individual declines, not just a count.
    #
    # Note what is NOT recorded: no card number, no CVV, no VPA. validate_instrument
    # has already reduced the instrument to a salted fingerprint by this point, and
    # a table of failed attempts is exactly the wrong place to hold raw PANs.
    ip_flag: dict | None = None
    if settled == payments.SETTLED_FAILED:
        attempt_id = f"fail_{uuid.uuid4().hex[:10]}"
        attempt = {
            "attempt_id": attempt_id, "order_id": order_id,
            "transaction_id": txn_id, "customer_id": u.user_id, "email": u.email,
            "amount": round(total, 2), "payment_method": req.payment_method,
            "instrument_display": instrument_display,
            "instrument_ref": instrument_ref,
            "device_fp": req.device_fp, "ip_hash": ipa,
            "risk_score": d.risk_score, "decision": d.decision,
            "customer_status": status_key, "created_at": dt.isoformat(),
        }
        records.put(f"IPFAIL#{ipa}", f"ATTEMPT#{dt.isoformat()}#{attempt_id}", attempt)
        records.put(f"CUSTOMER#{u.user_id}", f"FAILED#{dt.isoformat()}#{attempt_id}",
                    attempt)
        STATE["fail_ips"].add(ipa)

        ip_flag = store.evaluate_ip_suspicion(ipa, ts)
        if ip_flag is not None:
            # Mirrored into the record store so the mark survives a process
            # restart even though the counters behind it do not.
            records.put("SUSPICIOUS#IP", ipa, {
                "ip_hash": ipa, "since": ip_flag["since"],
                "reason": ip_flag["reason"],
                "last_seen": dt.isoformat(),
                "failures_total": ip_flag["failures_total"],
                "accounts": ip_flag["accounts"],
            })
            if ip_flag["new"]:
                audit(actor="system", action="ip_marked_suspicious",
                      before={"ip_hash": ipa}, after=ip_flag)

    # Instrument reuse across accounts is a strong signal, so it is counted the
    # same way payout destinations are for the promo gate.
    records.put(f"INSTRUMENT#{instrument_ref}", f"{dt.isoformat()}#{u.user_id}",
                {"customer_id": u.user_id, "order_id": order_id})
    instrument_accounts = {
        r["customer_id"]
        for r in records.query_prefix(f"INSTRUMENT#{instrument_ref}", "")
    }

    record = {
        "order_id": order_id, "transaction_id": txn_id, "customer_id": u.user_id,
        "email": u.email, "items": lines, "item_count": sum(x["qty"] for x in lines),
        "product_name": lines[0]["name"] + (f" +{len(lines) - 1} more" if len(lines) > 1 else ""),
        "amount": round(total, 2), "payment_method": req.payment_method,
        "instrument_display": instrument_display, "instrument_ref": instrument_ref,
        "instrument_account_count": len(instrument_accounts),
        # Stored so the analyst console can pivot from a transaction to its ring.
        # Both are opaque: ip_hash is an HMAC, device_fp is a client-generated
        # token. Neither is in the customer projection.
        "device_fp": req.device_fp, "ip_hash": ipa,
        "ip_suspicious": ip_flag is not None,
        "settlement": settled, "created_at": dt.isoformat(),
        "customer_status": status_key, "risk_score": d.risk_score,
        "decision": d.decision, "sub_scores": d.sub_scores,
        "reason_codes": d.reason_codes, "fired_rules": d.fired_rules,
        "override": d.override, "return_status": None, "label": None,
        # Which gateway produced `settlement`, and its own identifiers. Kept
        # separate from order_id / transaction_id, which remain ours. None under
        # the simulator, which has no server-side records.
        "provider": auth.provider,
        "provider_order_id": auth.provider_order_id,
        "provider_payment_id": auth.provider_payment_id,
        # Operator/analyst diagnostic. Never surfaced to a customer: it can carry
        # provider-side detail, and "your payment is unresolved because our
        # gateway call failed" is not information a payer can act on.
        "provider_error": auth.error,
    }
    records.put(f"CUSTOMER#{u.user_id}", f"ORDER#{dt.isoformat()}#{order_id}", record)
    records.put("INDEX#ORDER", order_id, {"customer_id": u.user_id,
                                          "sk": f"ORDER#{dt.isoformat()}#{order_id}"})

    # Durable write + cache + queue, all through the one shared path. `d` is not
    # re-consulted and nothing is re-scored.
    record_scored_transaction({**record, "features": raw,
                              "model_version": d.model_version,
                              "degraded": d.degraded,
                              "scored_at": dt.isoformat()})

    # One RISK_DECISION per scoring event, using the same Decision `d` that built
    # the record above and the response below. Emitted after persistence so the
    # audited transaction is one an analyst can actually open.
    audit_risk_decision(
        d=d, scorer=scorer, transaction_id=txn_id, order_id=order_id,
        customer_id=u.user_id, amount=round(total, 2),
        payment_method=req.payment_method, settlement=settled,
        source="storefront",
    )

    # Analyst alert, LAST. Everything that matters -- the decision, the refusal,
    # the queue item, the durable record, the audit event -- has already happened
    # by this line, so an email failure cannot affect any of it. `notify_*` cannot
    # raise; see the failure contract on notify(). ALLOW sends nothing.
    notify_transaction({**record, "model_version": d.model_version,
                        "degraded": d.degraded, "source": "storefront"})
    if ip_flag is not None and ip_flag.get("new"):
        notify_suspicious_ip(ip_flag)

    out: dict = {"order_id": order_id, "status": status_key, "message": message,
                 "items": lines, "amount": round(total, 2),
                 "payment_method": req.payment_method,
                 "instrument_display": instrument_display,
                 # The customer is told the payment failed, because it did. They
                 # are NOT told the address was flagged: naming the signal tells a
                 # card tester exactly what to rotate next.
                 "settlement": settled}
    if u.role in ("analyst", "admin"):
        out["risk"] = {
            "transaction_id": txn_id, "risk_score": d.risk_score,
            "decision": d.decision, "sub_scores": d.sub_scores,
            "reason_codes": d.reason_codes, "override": d.override,
            "settlement": settled, "ip_hash": ipa,
            "instrument_account_count": len(instrument_accounts),
            "ip_suspicious": ip_flag,
            "provider": auth.provider,
            "provider_order_id": auth.provider_order_id,
            "provider_error": auth.error,
        }
    return out


def _customer_order_view(r: dict, staff: bool) -> dict:
    """Allow-list projection. Adding a field to the stored record must not leak it
    to customers by default, so this enumerates what they may see."""
    view = {
        "order_id": r["order_id"], "product_name": r.get("product_name"),
        "items": r.get("items", []), "item_count": r.get("item_count", 1),
        "amount": r.get("amount"), "payment_method": r.get("payment_method"),
        "instrument_display": r.get("instrument_display"),
        "created_at": r.get("created_at"), "status": r.get("customer_status"),
        "return_status": r.get("return_status"),
    }
    if staff:
        view |= {
            "risk_score": r.get("risk_score"), "decision": r.get("decision"),
            "sub_scores": r.get("sub_scores"), "transaction_id": r.get("transaction_id"),
            "settlement": r.get("settlement"),
            "instrument_account_count": r.get("instrument_account_count"),
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
    # (ml/artifacts/metrics.json, per-archetype recall), so auto-approving on the score
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
    """`ip_hash` is absent on purpose -- derived from the connection.

    Letting a caller choose it would break ip_burst_fast_signup outright and,
    worse, let an abuser deliberately trigger the shared-IP exemption to suppress
    the IP signals entirely.
    """

    promo_code: str = Field(min_length=3, max_length=32)
    device_fp: str = Field(min_length=3, max_length=128)
    payout_ref: str = Field(min_length=3, max_length=128,
                            description="UPI id or bank ref receiving the cashback")


def _promo_features(u: User, req: RedeemRequest, ip_hash: str) -> dict:
    """Build the 7 documented features from live state.

    Reads the same entity graph the transaction scorer uses (device and IP
    adjacency) plus promo-specific counters from the record store.
    """
    records = STATE["records"]
    entity: InMemoryStore = STATE["store"]
    users: UserStore = STATE["users"]
    code = req.promo_code.upper()

    dev_hits = records.query_prefix(f"PROMODEV#{req.device_fp}", f"{code}#")
    ip_hits = records.query_prefix(f"PROMOIP#{ip_hash}", f"{code}#")
    payout_hits = records.query_prefix(f"PAYOUT#{req.payout_ref}", f"{code}#")

    # Distinct accounts seen on this device, from the transaction entity graph
    # plus anyone who redeemed from it. A brand-new device has neither.
    dev_accounts = set(entity.device_accounts(req.device_fp))
    dev_accounts |= {h["customer_id"] for h in dev_hits}
    dev_accounts.add(u.user_id)

    component = set(dev_accounts)
    ip_accounts = set(entity.ip_accounts(ip_hash)) | {
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
def redeem_promo(req: RedeemRequest, request: Request,
                 u: User = Depends(current_user)) -> dict:
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

    ipa = ip_hash_of(request)
    feats = _promo_features(u, req, ipa)
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
        "device_fp": req.device_fp, "ip_hash": ipa,
        "payout_ref": req.payout_ref, "override_by": None,
    }
    records.put(f"CUSTOMER#{u.user_id}", f"PROMO#{code}#{now}", record)
    # `redemption_id` and `decision` are added so startup can rebuild the hold
    # queue without fetching every redemption ever made. Both are immutable, so
    # neither can drift from the authoritative record above -- and the record is
    # still what decides whether a hold is open.
    records.put("INDEX#PROMO", rid, {"customer_id": u.user_id,
                                     "sk": f"PROMO#{code}#{now}",
                                     "redemption_id": rid,
                                     "decision": d.decision})

    # Counters are written even on DENY. An abuser who is refused must still
    # count against the device and payout, or retrying with a new account would
    # see a clean slate every time.
    records.put(f"PROMODEV#{req.device_fp}", f"{code}#{now}#{u.user_id}",
                {"customer_id": u.user_id, "redemption_id": rid})
    records.put(f"PROMOIP#{ipa}", f"{code}#{now}#{u.user_id}",
                {"customer_id": u.user_id, "redemption_id": rid})
    if d.decision != "DENY":
        # Only a credited or pending payout occupies the destination. A denied
        # one never pays out, so blocking that destination forever would punish
        # a legitimate retry.
        records.put(f"PAYOUT#{req.payout_ref}", f"{code}#{now}#{u.user_id}",
                    {"customer_id": u.user_id, "redemption_id": rid})

    if d.decision in ("HOLD", "DENY"):
        STATE["promo_queue"].append(rid)
        # Analyst alert, after the record and the queue entry exist. An override
        # is the only label source this gate has, so a hold nobody looks at is a
        # rule that never gets corrected. Cannot raise; ALLOW never reaches here.
        notify_promo_hold(record)

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


class ThresholdUpdate(BaseModel):
    review: float = Field(ge=0, le=100)
    block: float = Field(ge=0, le=100)
    # Optional and free-text. Recorded in the audit event, never used to decide
    # whether the change is allowed -- an operator must not be able to talk their
    # way past the ordering validation below.
    reason: str = Field(default="", max_length=280)


class PromoOverrideRequest(BaseModel):
    """Optional body for a promo override. Every field defaults, so the endpoint
    still accepts no body at all and an empty object -- the shape existing callers
    already send."""

    reason: str = Field(default="", max_length=280)


@app.get("/v1/admin/thresholds",
         dependencies=[Depends(require_role("analyst", "admin"))])
def get_thresholds() -> dict:
    """Current cut-offs, the measured cost curve, and their effect on live traffic.

    The review threshold is an OPERATIONS parameter, not a model property: at a
    100:1 cost ratio between a missed fraud and a review, expected-cost
    minimisation always wants to review more, so the binding constraint is how
    many analysts you employ. That is why this is a control surface rather than a
    constant baked into the model.
    """
    s: Scorer = STATE["scorer"]

    sweep: list[dict] = []
    mp = ARTIFACTS / "metrics.json"
    if mp.exists():
        try:
            m = json.loads(mp.read_text())
            sweep = m.get("threshold_sweep") or m.get("threshold_sweep_top10") or []
        except (json.JSONDecodeError, OSError):
            sweep = []

    # What the current queue would look like at other cut-offs. Small sample, but
    # it is this merchant's actual traffic rather than the evaluation split.
    scored = [r for r in STATE["txns"].values() if r.get("risk_score") is not None]
    live = []
    for rt in (2, 5, 10, 20, 30, 40, 50, 60, 70):
        for bt in (60, 70, 80, 90):
            if bt <= rt:
                continue
            n_block = sum(1 for r in scored if r["risk_score"] >= bt)
            n_review = sum(1 for r in scored if rt <= r["risk_score"] < bt)
            live.append({"review": rt, "block": bt, "would_block": n_block,
                         "would_review": n_review,
                         "review_share": round(n_review / len(scored), 4) if scored else 0})

    return {
        "current": {"review": s.review_t, "block": s.block_t},
        # Reported from the loaded configuration rather than asserted, so this
        # cannot claim "persisted" for a process that fell back to env defaults.
        "config": STATE.get("threshold_config"),
        "source": (STATE.get("threshold_config") or {}).get(
            "source", "env (FRAUDSHIELD_REVIEW_T / _BLOCK_T)"),
        "cost_curve": sweep,
        "cost_curve_note": (
            "Expected rupee cost on the VALIDATION split. Costs assume "
            f"Rs {COST_FRAUD:.0f} per missed fraud, Rs {COST_REVIEW:.0f} per review, "
            f"Rs {COST_BLOCK_LEGIT:.0f} per wrongly blocked customer."
        ),
        "live_projection": live,
        "live_sample_size": len(scored),
        "caveat": (
            "Changing thresholds does NOT re-decide transactions already scored. "
            "It applies to new traffic only, and the queue is not recomputed."
        ),
    }


@app.put("/v1/admin/thresholds",
         dependencies=[Depends(require_role("admin"))])
def put_thresholds(req: ThresholdUpdate,
                   actor: User = Depends(require_role("admin"))) -> dict:
    """Move the cut-offs at runtime. Admin only, and audited.

    Restricted to `admin` rather than `analyst`: an analyst decides individual
    cases, but moving a threshold silently changes every future decision and the
    merchant's whole false-positive exposure. Different blast radius, different
    permission.
    """
    # One validator, shared with the startup loader, so a pair that would be
    # rejected on restart cannot be accepted at runtime. Without that shared rule
    # an admin could set a configuration the next boot refuses to honour.
    try:
        review, block = validate_thresholds(req.review, req.block)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None

    s: Scorer = STATE["scorer"]
    records = STATE["records"]
    before = {"review": s.review_t, "block": s.block_t}

    # Persist FIRST, apply second. If the write fails the running thresholds are
    # left alone, so the process and the table still agree -- the alternative
    # (apply, then fail to persist) is the drift this feature exists to remove.
    try:
        item = persist_thresholds(records, review=review, block=block,
                                  actor=actor.email, reason=req.reason)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            503, "Could not persist the threshold change; nothing was applied. "
                 f"({type(exc).__name__})") from None

    s.review_t = review
    s.block_t = block
    after = {"review": s.review_t, "block": s.block_t}

    # The running configuration state, refreshed so /health and GET /thresholds
    # report the change without waiting for a restart.
    STATE["threshold_config"] = {
        "source": "persisted",
        "review": review,
        "block": block,
        "env_defaults": {"review": DEFAULT_REVIEW_T, "block": DEFAULT_BLOCK_T},
        "version": item["version"],
        "updated_at": item["updated_at"],
        "updated_by": item["updated_by"],
        "degraded": False,
        "note": "set at runtime and persisted; survives restart",
    }

    # Append-only. A threshold change that leaves no trace makes every later
    # "why was this blocked?" unanswerable.
    entry = audit(actor.email, THRESHOLD_UPDATE,
                  before | {"version": item["version"] - 1},
                  after | {"version": item["version"],
                           "reason": req.reason or None,
                           "persisted": True},
                  identity=actor_identity(actor))
    now = entry["at"]

    return {
        "current": after, "previous": before, "actor": actor.email, "at": now,
        "version": item["version"],
        "persisted": True,
        "note": "Applies to new traffic only. Already-scored transactions keep "
                "their original decision. Survives restart.",
    }


@app.get("/v1/admin/policy",
         dependencies=[Depends(require_role("analyst", "admin"))])
def action_policy() -> dict:
    """The bounded automated-action policy, as the code actually holds it.

    Served from the same tables the emitter uses, not from a copy, so this cannot
    describe a policy the system does not follow. Read-only: there is no endpoint
    to widen what the automation may do, because that is a code change and a review,
    not a runtime setting.

    Analyst-visible rather than admin-only on purpose -- the people acting on the
    queue are the ones who most need to know what the machine already did and what
    it is forbidden from doing.
    """
    return {
        "policy_version": POLICY_VERSION,
        "decisions": {
            band: {
                "automated_action": spec["automated_action"],
                "reason": spec["reason"],
                "permitted": list(spec["permitted"]),
                "reversible_by_human": spec["reversible_by_human"],
            }
            for band, spec in ACTION_POLICY.items()
        },
        "never_automated": list(NEVER_AUTOMATED),
        "thresholds": {"review": STATE["scorer"].review_t,
                       "block": STATE["scorer"].block_t},
        "ground_truth_source": (
            "human only: POST /v1/admin/transactions/{id}/outcome "
            "(OUTCOME_RECORDED) and POST /v1/admin/promo-holds/{rid}/override "
            "(PROMO_OVERRIDE)"
        ),
        "note": POLICY_NOTE,
    }


@app.get("/v1/admin/notifications",
         dependencies=[Depends(require_role("analyst", "admin"))])
def notification_log(limit: int = 50, status: str | None = None,
                     event_type: str | None = None) -> dict:
    """Analyst alert delivery history, newest first.

    Analyst-visible rather than admin-only: the people working the queue are the
    ones who need to know whether they were actually told about an item, and a
    silent alerting failure is exactly what this view exists to expose.

    WHAT IS DELIBERATELY WITHHELD
    -----------------------------
    Recipient addresses, the message body, and the SMTP transport error. The
    stored item carries the addresses so an operator can answer "who was told?",
    but this projection is an explicit ALLOW-LIST -- adding a field to the stored
    record must not leak it here by default. `error_category` is published;
    the raw error is not, because it can echo the username or a server banner.

    `counts` is computed over everything this process knows about, before the
    filter, so an analyst can see there are failures even while looking at a
    filtered view.
    """
    rows = list(reversed(STATE.get("notifications") or []))

    counts = {
        "total": len(rows),
        "sent": sum(1 for r in rows if r.get("status") == notifications.STATUS_SENT),
        "failed": sum(1 for r in rows
                      if r.get("status") == notifications.STATUS_FAILED),
        "skipped": sum(1 for r in rows
                       if r.get("status") == notifications.STATUS_SKIPPED),
    }

    if status:
        rows = [r for r in rows if r.get("status") == status.strip().lower()]
    if event_type:
        wanted = event_type.strip().upper()
        rows = [r for r in rows if str(r.get("event_type", "")).upper() == wanted]

    def view(r: dict) -> dict:
        return {
            "notification_id": r.get("notification_id"),
            "event_type": r.get("event_type"),
            "status": r.get("status"),
            "provider": r.get("provider"),
            "recipient_count": r.get("recipient_count"),
            "transaction_id": r.get("transaction_id"),
            "order_id": r.get("order_id"),
            "redemption_id": r.get("redemption_id"),
            "ip_hash": r.get("ip_hash"),
            "created_at": r.get("created_at"),
            "sent_at": r.get("sent_at"),
            "error_category": r.get("error_category"),
            "attempts": r.get("attempts"),
            "durable": r.get("durable"),
        }

    return {
        "count": len(rows),
        "counts": counts,
        # Mode and health, so this view is self-contained for an analyst asking
        # "am I actually being alerted?". No credentials, no addresses.
        "email": {k: v for k, v in (STATE.get("email_status") or {}).items()
                  if k != "note"} | {
            "note": (STATE.get("email_status") or {}).get("note", "")},
        "items": [view(r) for r in rows[:limit]],
        "note": ("Delivery of an alert is a communication event. It is not a risk "
                 "decision and not ground truth: an analyst reading an email is "
                 "not an analyst recording an outcome."),
    }


# Audit-domain fields. An explicit allow-list, for the same reason
# `_customer_order_view` is one: adding a field to a stored item must not
# publish it by default.
#
# `PK` and `SK` were being returned verbatim. They are not secrets, but they are
# storage implementation detail -- and this was the only admin projection in the
# codebase that was not an allow-list, which made it the one place a future field
# would leak from.
_AUDIT_FIELDS = ("event_id", "action", "actor", "actor_identity", "at",
                 "before", "after")

# ---------------------------------------------------------------------------
# Audit history retrieval
# ---------------------------------------------------------------------------
#
# WHERE THE OLD LIMITATION ACTUALLY WAS
# -------------------------------------
# Not in storage. `audit()` has always written to AUDIT#<utc-date> with a sort key
# of "<iso-timestamp>#<suffix>", so every day already has its own partition and all
# of them persist. The endpoint simply computed today's date and queried that one
# partition -- a single line. Nothing needed migrating.

# Page size. Clamped because an unbounded `limit` on an append-only partition is a
# way to pull an entire history into memory through one request.
AUDIT_PAGE_DEFAULT = 50
AUDIT_PAGE_MAX = 200

# How many date partitions one range request will touch. A range is served one
# partition at a time -- never a scan -- so this bounds the work per request rather
# than the amount of history that exists.
AUDIT_MAX_DAYS = 31

# Filters applied after a partition is read. Cheap, because the page is already in
# memory; they do NOT cause extra reads and they are NOT indexed.
#
# `action` is matched exactly. The identifier filters look in `before`, which is
# where every emitter puts its subject.
_AUDIT_ID_FILTERS = ("transaction_id", "order_id", "redemption_id", "event_id")


def _audit_partition(day: str) -> str:
    return f"AUDIT#{day}"


def _parse_day(value: str, field: str) -> str:
    """Validate a YYYY-MM-DD string. Raises 422 with the offending field named.

    Strict rather than lenient: a silently-misparsed date would return an empty
    page that looks like "nothing happened that day", which is the most misleading
    possible answer from an audit endpoint.
    """
    try:
        d = datetime.strptime(value.strip(), "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except (ValueError, AttributeError):
        raise HTTPException(
            422, f"{field} must be a date in YYYY-MM-DD form, got {value!r}"
        ) from None
    return d.date().isoformat()


def _day_range(start: str, end: str) -> list[str]:
    """Dates from `end` back to `start`, newest first, bounded.

    Newest-first because that is the order the console reads, and because a range
    request that gets truncated should lose the OLDEST day rather than the most
    recent one.
    """
    s = datetime.strptime(start, "%Y-%m-%d").date()
    e = datetime.strptime(end, "%Y-%m-%d").date()
    if s > e:
        raise HTTPException(422, "start_date must not be after end_date.")
    span = (e - s).days + 1
    if span > AUDIT_MAX_DAYS:
        raise HTTPException(
            422,
            f"That range covers {span} days; the maximum is {AUDIT_MAX_DAYS}. "
            f"Request a narrower range -- audit history is partitioned by UTC "
            f"date and each day is read separately.",
        )
    return [(e - timedelta(days=i)).isoformat() for i in range(span)]


def _encode_cursor(day: str, sk: str) -> str:
    """An opaque continuation token.

    Base64 of "<day>|<sk>". Deliberately NOT DynamoDB's LastEvaluatedKey: that is
    an internal structure whose shape is an implementation detail, and publishing
    it would leak the storage model into the API contract and pin us to it.

    Not signed, because it carries no secret and grants nothing. It names a date
    and a sort key, both of which the caller already supplied or received. The
    endpoint re-validates that the cursor's day falls inside the range actually
    requested, so a tampered token cannot reach a partition the caller did not ask
    for.
    """
    raw = f"{day}|{sk}".encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _decode_cursor(token: str, allowed_days: list[str]) -> tuple[str, str]:
    """Decode and authorise a continuation token. Raises 422 when unusable."""
    try:
        pad = "=" * (-len(token) % 4)
        raw = base64.urlsafe_b64decode(token + pad).decode("utf-8")
        day, sk = raw.split("|", 1)
    except Exception:  # noqa: BLE001
        raise HTTPException(422, "cursor is not a valid continuation token.") from None
    if not day or not sk:
        raise HTTPException(422, "cursor is not a valid continuation token.")
    if day not in allowed_days:
        # The guard that makes an unsigned token safe: a cursor can only resume
        # inside the range this request asked for.
        raise HTTPException(
            422, "cursor does not belong to the requested date range.")
    return day, sk


def _audit_matches(row: dict, action: str | None, actor: str | None,
                   ids: dict) -> bool:
    if action and row.get("action") != action:
        return False
    if actor:
        # Case-insensitive because actors are email addresses, which are stored
        # normalised but are typed by hand into a filter box.
        if str(row.get("actor", "")).lower() != actor.strip().lower():
            return False
    before = row.get("before") or {}
    for field, wanted in ids.items():
        if str(before.get(field, "")) != wanted:
            return False
    return True


def _read_audit_page(records, day: str, *, limit: int,
                     after_sk: str | None) -> tuple[list[dict], str | None, bool]:
    """One partition, one page. Returns (rows, next_sk, ok).

    `ok` is False when the read failed. The caller must not treat a failed
    partition as an empty one -- that is the difference between "nothing happened"
    and "we cannot tell you what happened".
    """
    try:
        page_fn = getattr(records, "query_page", None)
        if page_fn is not None:
            rows, nxt = page_fn(_audit_partition(day), "", limit=limit,
                               after_sk=after_sk, desc=True)
            return rows, nxt, True
        # A store without query_page still works, just without server-side
        # paging. No such store ships here; this keeps a third-party
        # implementation of the interface from breaking the endpoint.
        rows = records.query_prefix(_audit_partition(day), "", desc=True)
        if after_sk is not None:
            rows = [r for r in rows if r["SK"] < after_sk]
        page = rows[:limit]
        return page, (page[-1]["SK"] if len(rows) > limit and page else None), True
    except Exception as exc:  # noqa: BLE001
        print(f"WARNING: audit partition AUDIT#{day} could not be read "
              f"({type(exc).__name__})")
        return [], None, False


def _audit_view(row: dict) -> dict:
    """Project one stored audit item onto the audit domain.

    Omits `PK`/`SK` and anything else the store adds. Keeps `before`/`after`
    whole: they are already minimal projections built by the emitters, and
    re-filtering them here would mean two places deciding what an event contains.
    """
    return {k: row[k] for k in _AUDIT_FIELDS if k in row}


@app.get("/v1/admin/audit", dependencies=[Depends(require_role("admin"))])
def audit_log(
    limit: int = AUDIT_PAGE_DEFAULT,
    action: str | None = None,
    date: str | None = None,
    start_date: str | None = None,
    end_date: str | None = None,
    cursor: str | None = None,
    actor: str | None = None,
    transaction_id: str | None = None,
    order_id: str | None = None,
    redemption_id: str | None = None,
    event_id: str | None = None,
) -> dict:
    """Audit events, newest first. Admin only.

    HISTORY IS NOW REACHABLE. This used to compute today's UTC date and query that
    one partition, so yesterday was unretrievable even though it had always been
    persisted. The storage model is unchanged; the endpoint now takes a date.

        (no params)                          today
        ?date=2026-08-28                     one day
        ?start_date=…&end_date=…             a range, newest day first
        ?limit=100&cursor=…                  the next page

    PAGINATION IS KEYSET, NOT OFFSET. The cursor names the last sort key returned,
    so new events written while an analyst is scrolling cannot shift the window and
    duplicate or skip a row. Audit partitions are append-only and busiest exactly
    while somebody is reading them.

    A RANGE READS ONE PARTITION AT A TIME. Never a scan, never a new index. The
    range is bounded to AUDIT_MAX_DAYS days per request so the work per request is
    bounded rather than the amount of history that exists.

    FILTERS ARE POST-READ AND UNINDEXED. `action`, `actor` and the identifier
    filters are applied to partitions already being read, so they add no reads --
    but they cannot make a query cheaper, and a filter that matches nothing still
    costs the partitions it looked through. That is documented rather than hidden
    behind a GSI nobody asked for.
    """
    limit = max(1, min(int(limit or AUDIT_PAGE_DEFAULT), AUDIT_PAGE_MAX))
    today = datetime.now(timezone.utc).date().isoformat()

    # A blank query parameter is an ABSENT one, not a malformed one. `?date=` is
    # what a form submits for an empty field, and 422-ing that would make the
    # console's own date picker an error source. A non-blank but unparseable value
    # is still rejected below -- that is a typo, and answering it with an empty
    # page would read as "nothing happened that day".
    date = (date or "").strip() or None
    start_date = (start_date or "").strip() or None
    end_date = (end_date or "").strip() or None
    cursor = (cursor or "").strip() or None
    action = (action or "").strip() or None
    actor = (actor or "").strip() or None

    # ---- which partitions -------------------------------------------------
    if date and (start_date or end_date):
        raise HTTPException(
            422, "Use either `date` or `start_date`/`end_date`, not both.")
    if date:
        days = [_parse_day(date, "date")]
    elif start_date or end_date:
        s = _parse_day(start_date, "start_date") if start_date else None
        e = _parse_day(end_date, "end_date") if end_date else None
        days = _day_range(s or e, e or s)
    else:
        days = [today]

    start_day, start_sk = (_decode_cursor(cursor, days) if cursor
                           else (days[0], None))

    ids = {k: v for k, v in (("transaction_id", transaction_id),
                             ("order_id", order_id),
                             ("redemption_id", redemption_id),
                             ("event_id", event_id)) if v}

    # ---- read, newest day first, stopping as soon as the page is full -----
    collected: list[dict] = []
    failed_days: list[str] = []
    read_days: list[str] = []
    next_cursor: str | None = None
    after_sk = start_sk
    # Whether anything is genuinely left. Tracked explicitly rather than inferred
    # from "the page filled up": a page that fills on the LAST available row would
    # otherwise report has_more, and a client walking the cursor would make one
    # extra request per page forever.
    leftover = False
    remaining_days: list[str] = []

    todo = days[days.index(start_day):]
    for idx, day in enumerate(todo):
        remaining_days = todo[idx + 1:]
        read_days.append(day)
        while len(collected) < limit:
            # Over-read when filtering: a filter can reject most of a page, and
            # returning three rows for a limit of fifty because the rest were
            # filtered out would make `has_more` useless. Bounded by the page cap
            # so this cannot become an unbounded read.
            want = limit - len(collected)
            fetch = min(AUDIT_PAGE_MAX, want * 4) if (action or actor or ids) else want
            rows, nxt, ok = _read_audit_page(records_for_audit(), day,
                                             limit=fetch, after_sk=after_sk)
            if not ok:
                failed_days.append(day)
                break
            matched = [r for r in rows if _audit_matches(r, action, actor, ids)]
            taken = 0
            for r in matched:
                if len(collected) >= limit:
                    break
                collected.append(r)
                taken += 1
            if len(collected) >= limit:
                # Matched rows we read but could not fit, plus anything the store
                # says is still behind us in this partition.
                leftover = taken < len(matched) or nxt is not None
                # Resume from the last row actually CONSUMED, which may be earlier
                # than the last row read.
                next_cursor = _encode_cursor(day, collected[-1]["SK"])
                break
            if nxt is None:
                after_sk = None
                break
            after_sk = nxt
        if len(collected) >= limit:
            break
        after_sk = None

    # A cursor is only worth issuing if following it can return something.
    if next_cursor is not None and not leftover and not remaining_days:
        next_cursor = None

    # ---- source and completeness (F10, extended to ranges) ----------------
    memory = list(reversed(STATE.get("audit") or []))
    single_today = days == [today]

    if failed_days:
        # At least one partition is unreadable. For today we can still fall back
        # to the in-process log; for a past date there is nothing to fall back to,
        # and saying so is the only honest answer.
        rows = collected or (memory if single_today else [])
        if single_today and not collected:
            rows = [r for r in memory if _audit_matches(r, action, actor, ids)]
        meta = {
            "source": "memory_fallback" if single_today else "partial",
            "complete": False,
            "warning": (
                f"Audit persistence unavailable for {', '.join(failed_days)}; "
                f"this result is incomplete. "
                + ("Serving this process's in-memory log instead; events from "
                   "other workers or before the last restart are not shown."
                   if single_today else
                   "Those dates are omitted from this result.")
            ),
        }
        collected = rows
    elif collected:
        meta = {"source": "persistent", "complete": True, "warning": None}
    elif single_today and memory:
        # The read worked and returned nothing, but this process holds events --
        # so the durable writes must have failed earlier. Still not complete.
        collected = [r for r in memory if _audit_matches(r, action, actor, ids)]
        meta = {
            "source": "memory_fallback",
            "complete": False,
            "warning": ("No persisted audit events for today, but this process "
                        "holds some. Durable writes appear to have failed; "
                        "results may be incomplete."),
        }
    else:
        meta = {"source": "empty", "complete": True, "warning": None}

    return {
        "count": len(collected),
        "entries": [_audit_view(r) for r in collected],
        "has_more": next_cursor is not None,
        "next_cursor": next_cursor,
        "limit": limit,
        "days_requested": days,
        "days_read": read_days,
        "days_failed": failed_days,
        **meta,
        # Retained for compatibility: callers written against the single-day
        # response read `day`.
        "day": days[0],
        "filters": {"action": action, "actor": actor, **ids} if (
            action or actor or ids) else None,
        "note": ("Audit history is partitioned by UTC date. Pass ?date= or "
                 "?start_date=&end_date= to read earlier days; filters are "
                 "applied to the partitions read and are not indexed."),
    }


def records_for_audit():
    """The record store, resolved at call time.

    A function rather than a captured reference so a test can swap the store
    between requests, and so a missing store raises here rather than at import.
    """
    return STATE["records"]


# ---------------------------------------------------------------------------
# Ring exposure
# ---------------------------------------------------------------------------
#
# WHAT THIS NUMBER IS, AND WHAT IT IS EMPHATICALLY NOT
# ---------------------------------------------------
# `estimated_exposure` is the sum of transaction amounts belonging to the accounts
# in a connected component, over the transactions FraudShield currently retains.
#
# It is NOT:
#   - money stolen. No ground truth says these transactions were fraudulent.
#   - merchant loss. A BLOCK never settled, so no money moved on it at all.
#   - a complete figure. The transaction cache is bounded (see the horizon note),
#     so anything older than the retained window is simply not counted.
#
# Every one of those three would be a lie that flatters the product, which is why
# the response carries the definition alongside the number and the UI prints it.
#
# Composed only from amounts already stored by the three scoring paths. Nothing is
# modelled, extrapolated or inferred.

EXPOSURE_DEFINITION = (
    "Estimated exposure is the sum of transaction amounts associated with "
    "accounts in this connected component, over the transactions FraudShield "
    "currently retains. It is NOT a loss estimate, NOT money confirmed stolen, "
    "and NOT a fraud verdict -- no ground truth is involved. Blocked amounts "
    "never settled, so no money moved on them."
)


def ring_exposure(accounts: set[str]) -> dict:
    """Money associated with a set of accounts, split by what the engine decided.

    Reads STATE["txns"] -- the retained transaction cache -- keyed by
    transaction_id, so a transaction cannot be double-counted no matter how many
    times an account appears in the component.

    Splitting by DECISION rather than reporting one total is the point. A single
    "exposure" figure invites the reader to treat it as a loss, when in fact the
    blocked slice is money the engine refused and the allowed slice is ordinary
    revenue that merely happens to sit in the same component.

    Fields that the stored data cannot support honestly are reported as null
    rather than estimated:

      - `confirmed_fraud_amount` is null whenever no human has labelled any of
        these transactions. Deriving it from BLOCK would be exactly the
        BLOCK == FRAUD inference this system refuses to make.
    """
    txns: dict = STATE.get("txns") or {}

    gross = blocked = review = allowed = unclassified = 0.0
    settled_success = 0.0
    counted = skipped = 0
    seen_accounts: set[str] = set()
    labelled_fraud = 0.0
    label_count = 0
    oldest: str | None = None
    newest: str | None = None

    for record in txns.values():
        cid = record.get("customer_id")
        if cid not in accounts:
            continue
        try:
            amount = float(record.get("amount"))
        except (TypeError, ValueError):
            # A record without a usable amount is skipped and COUNTED as skipped,
            # so a partial figure announces itself instead of looking complete.
            skipped += 1
            continue
        if amount != amount or amount < 0:      # NaN or negative
            skipped += 1
            continue

        counted += 1
        seen_accounts.add(cid)
        gross += amount

        decision = record.get("decision")
        if decision == "BLOCK":
            blocked += amount
        elif decision == "MANUAL_REVIEW":
            review += amount
        elif decision == "ALLOW":
            allowed += amount
        else:
            unclassified += amount

        # Money that actually moved. A BLOCK is always `failed`, and an ALLOW can
        # still be declined by the bank, so this is strictly smaller than gross and
        # is the only slice where value genuinely changed hands.
        if record.get("settlement") == "success":
            settled_success += amount

        if record.get("label") == "fraud":
            labelled_fraud += amount
            label_count += 1

        at = record.get("created_at") or record.get("scored_at")
        if at:
            oldest = at if oldest is None or at < oldest else oldest
            newest = at if newest is None or at > newest else newest

    def r(x: float) -> float:
        return round(x, 2)

    return {
        "gross_exposure": r(gross),
        "blocked_amount": r(blocked),
        "review_amount": r(review),
        "allowed_amount": r(allowed),
        # Only present because some records can carry a decision this build does
        # not know (an older item, a future band). Reported rather than folded into
        # `allowed`, which would understate what was refused.
        "unclassified_amount": r(unclassified),
        "settled_amount": r(settled_success),
        # Null, not zero, when nobody has ruled on any of it. Zero would read as
        # "reviewed and found clean".
        "confirmed_fraud_amount": r(labelled_fraud) if label_count else None,
        "labelled_transactions": label_count,
        "transactions_counted": counted,
        "transactions_skipped": skipped,
        "accounts_in_component": len(accounts),
        "accounts_with_transactions": len(seen_accounts),
        "window": {
            "kind": "retained transaction history",
            "earliest": oldest,
            "latest": newest,
            # The real bound. Not a time window: the cache holds the most recent
            # REHYDRATE_TXNS transactions after a restart, plus everything scored
            # since. Calling it "last 30 days" would be an invention.
            "retained_transaction_cap": REHYDRATE_TXNS,
            "note": (
                "Not a fixed time range. After a restart the cache is rebuilt "
                f"from at most {REHYDRATE_TXNS} recent transactions (plus every "
                "open review item), and grows with new traffic. Transactions "
                "outside that window are not counted."
            ),
        },
        "complete": skipped == 0,
        "definition": EXPOSURE_DEFINITION,
        "is_loss_estimate": False,
    }


@app.get("/v1/admin/rings/{entity_type}/{entity_id}",
         dependencies=[Depends(require_role("analyst", "admin"))])
def ring_graph(entity_type: str, entity_id: str, depth: int = 2) -> dict:
    """Expand the shared-entity component around a device, IP or account.

    Returns nodes and edges for the analyst console's graph view. Same adjacency
    the network score walks -- so the picture and the number cannot disagree.

    Bounded at MAX_COMPONENT. A carrier CGNAT range or campus network can reach
    thousands of accounts, and an unbounded walk would both time out and produce a
    component with no meaning.
    """
    if entity_type not in ("device", "ip", "account"):
        raise HTTPException(422, "entity_type must be device, ip or account.")
    depth = max(1, min(3, depth))

    store: InMemoryStore = STATE["store"]
    accounts: set[str] = set()
    if entity_type == "device":
        accounts |= set(store.device_accounts(entity_id))
    elif entity_type == "ip":
        accounts |= set(store.ip_accounts(entity_id))
    else:
        accounts.add(entity_id)

    devices: set[str] = set()
    ips: set[str] = set()
    truncated = False

    # Breadth-first: accounts -> their devices and IPs -> accounts on those.
    for _ in range(depth):
        for a in list(accounts):
            devices |= set(store.acct_devices[a])
            ips |= set(store.acct_ips[a])
        grew = set()
        for d in devices:
            grew |= set(store.device_accounts(d))
        for p in ips:
            # Skip high-population infrastructure. Following a carrier IP pulls in
            # unrelated strangers and drowns the actual cluster.
            if len(store.ip_accounts(p)) <= HIGH_POP_IP_ACCOUNTS:
                grew |= set(store.ip_accounts(p))
        if len(accounts | grew) > MAX_COMPONENT:
            truncated = True
            grew = set(list(grew)[: max(0, MAX_COMPONENT - len(accounts))])
        if grew <= accounts:
            break
        accounts |= grew

    users: UserStore = STATE["users"]
    nodes, edges = [], []

    for a in accounts:
        n, f = store.account_totals(a)
        u = users.get(a) if users else None
        nodes.append({
            "id": a, "type": "account",
            "label": (u.email if u else a)[:38],
            "txn_count": n, "fail_count": f,
            "active_24h": store.account_activity_24h(a, time.time()),
            "is_seed": entity_type == "account" and a == entity_id,
        })
    for d in devices:
        shared = len(store.device_accounts(d))
        nodes.append({"id": d, "type": "device", "label": d[:26],
                      "account_count": shared,
                      "is_seed": entity_type == "device" and d == entity_id,
                      "suspicious": shared > 4})
    for p in ips:
        shared = len(store.ip_accounts(p))
        nodes.append({"id": p, "type": "ip", "label": p[:26],
                      "account_count": shared,
                      "is_seed": entity_type == "ip" and p == entity_id,
                      "shared_infra": shared > HIGH_POP_IP_ACCOUNTS,
                      "suspicious": 6 < shared <= HIGH_POP_IP_ACCOUNTS})

    node_ids = {n["id"] for n in nodes}
    for a in accounts:
        for d in store.acct_devices[a]:
            if d in node_ids:
                edges.append({"source": a, "target": d, "kind": "device"})
        for p in store.acct_ips[a]:
            if p in node_ids:
                edges.append({"source": a, "target": p, "kind": "ip"})

    exposure = ring_exposure(accounts)
    if truncated:
        # A truncated component means accounts were dropped from the walk, so the
        # exposure computed over the survivors is a floor, not a total. Saying so
        # is the difference between an estimate and a wrong number.
        exposure["complete"] = False
        exposure["window"]["note"] += (
            f" The component was also truncated at MAX_COMPONENT="
            f"{MAX_COMPONENT} accounts, so this figure omits accounts that were "
            f"not expanded."
        )

    return {
        "seed": {"type": entity_type, "id": entity_id},
        "depth": depth,
        "truncated": truncated,
        "counts": {"accounts": len(accounts), "devices": len(devices),
                   "ips": len(ips), "edges": len(edges)},
        # Money associated with this component, split by what the engine decided.
        # Read the `definition` field before quoting the number anywhere.
        "exposure": exposure,
        "nodes": nodes,
        "edges": edges,
    }


@app.get("/v1/admin/metrics",
         dependencies=[Depends(require_role("analyst", "admin"))])
def admin_metrics() -> dict:
    """Serve the evaluation artifacts.

    The dashboard reads these rather than hardcoding numbers, so a retrain shows
    up in the UI instead of quietly making the interface lie.
    """
    def load(name: str) -> dict | None:
        p = ARTIFACTS / name
        if not p.exists():
            return None
        try:
            return json.loads(p.read_text())
        except (json.JSONDecodeError, OSError):
            return None

    txn = load("metrics.json")
    promo = load("promo_metrics.json")
    return {
        "transaction": txn,
        "promo": promo,
        "missing": [n for n, v in (("metrics.json", txn),
                                   ("promo_metrics.json", promo)) if v is None],
    }


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
def promo_override(rid: str, req: PromoOverrideRequest = PromoOverrideRequest(),
                   actor: User = Depends(require_role("analyst", "admin"))) -> dict:
    """Grant a held or denied offer. Human ground truth, and audited as such.

    Overrides are the ONLY label source for this gate -- it ships with no training
    data, so an analyst reversing a decision is how we learn the rules are wrong.
    That makes an override a ground-truth event, so it emits PROMO_OVERRIDE, the
    promo counterpart to OUTCOME_RECORDED on the transaction path.

    The machine decision is NOT rewritten. `decision` keeps its original HOLD or
    DENY, and the human verdict lives in `override_by` / `override_at` / `label`
    and in the audit event's `human_outcome`. Collapsing the two would erase the
    fact that the gate flagged this claim, which is exactly the number this gate's
    false-positive rate is computed from.
    """
    records = STATE["records"]
    idx = records.get("INDEX#PROMO", rid)
    if idx is None:
        raise HTTPException(404, "Unknown redemption.")
    pk, sk = f"CUSTOMER#{idx['customer_id']}", idx["sk"]
    r = records.get(pk, sk)
    if r is None:
        raise HTTPException(404, "Unknown redemption.")

    # Idempotency guard, and the reason it exists is the audit trail rather than
    # the state: re-running the update would be harmless, but it would emit a
    # SECOND ground-truth event for one human decision and inflate the label count
    # this gate is measured by. 409 rather than a silent 200 so a double-click is
    # visible to the caller instead of being absorbed.
    if r.get("override_by") is not None:
        raise HTTPException(409, "This redemption has already been overridden.")

    # SNAPSHOT BEFORE MUTATING, and this copy is load-bearing.
    #
    # InMemoryRecordStore.get() returns the stored dict BY REFERENCE, so
    # update_fields() below mutates this very object. Passing `r` to the audit
    # emitter afterwards made the "before" snapshot report the AFTER values --
    # `machine_status` came out as "credited" rather than "under_review".
    #
    # Worse, it only happened in memory mode: DynamoRecordStore.get() rebuilds a
    # fresh dict from the item, so the two stores silently disagreed about what
    # the audit trail said. A shallow copy is sufficient -- every field the update
    # touches is a scalar.
    before_snapshot = dict(r)

    override_at = datetime.now(timezone.utc).isoformat()
    records.update_fields(pk, sk, {
        "status": "credited", "override_by": actor.email,
        "override_at": override_at,
        "label": "legitimate",
    })
    if rid in STATE["promo_queue"]:
        STATE["promo_queue"].remove(rid)

    # Emitted after the durable write, so an audited override is one an analyst can
    # actually open -- the same ordering the transaction outcome path uses. `r` is
    # the record as it was BEFORE the update, which is what makes the audited
    # machine decision the original one.
    audit_promo_override(rid=rid, redemption=before_snapshot,
                         actor_email=actor.email,
                         override_by=actor.email, override_at=override_at,
                         identity=actor_identity(actor), reason=req.reason)

    # Best-effort hint so startup can skip this redemption without fetching it.
    # Purely an optimisation: rehydration re-checks override_by on the
    # authoritative record above, so losing this write costs one extra read and
    # never resurrects the hold.
    try:
        records.update_fields("INDEX#PROMO", rid, {"resolved": True})
    except Exception as exc:  # noqa: BLE001
        print(f"WARNING: could not mark promo pointer {rid} resolved "
              f"({type(exc).__name__}); the authoritative record is correct and "
              f"the hold will still not reappear")
    return {"redemption_id": rid, "status": "credited",
            "note": "override recorded as a false-positive label for this gate"}


@app.get("/v1/admin/suspicious-ips",
         dependencies=[Depends(require_role("analyst", "admin"))])
def suspicious_ips(limit: int = 50) -> dict:
    """Addresses flagged for a burst of failed payments, newest first.

    Two sources, deliberately merged rather than picked between:

      - live counters in the store, which have the exact trailing window but die
        with the process
      - SUSPICIOUS#IP records, which survive a restart but carry no window

    After a restart the store is empty and only the records remain, so reading
    just the counters would silently report zero flags on a system that has them.
    """
    store: InMemoryStore = STATE["store"]
    records = STATE["records"]

    live = {r["ip_hash"]: {**r, "source": "live"} for r in store.suspicious_ips()}

    try:
        for r in records.query_prefix("SUSPICIOUS#IP", ""):
            h = r.get("ip_hash")
            if h and h not in live:
                live[h] = {
                    "ip_hash": h, "since": r.get("since"),
                    "reason": r.get("reason"),
                    "failures_total": int(r.get("failures_total", 0)),
                    "accounts": int(r.get("accounts", 0)),
                    "transactions": 0, "source": "persisted",
                }
    except Exception:  # noqa: BLE001
        pass

    items = sorted(live.values(), key=lambda r: r.get("since") or "", reverse=True)

    # Attach the individual declines. The count is the trigger; these are the
    # evidence, and a flag an analyst cannot drill into is not actionable.
    for it in items[:limit]:
        try:
            rows = records.query_prefix(f"IPFAIL#{it['ip_hash']}", "ATTEMPT#")
        except Exception:  # noqa: BLE001
            rows = []
        it["attempts"] = [
            {k: v for k, v in r.items() if k not in ("PK", "SK")} for r in rows[:10]
        ]
        it["attempt_count"] = len(rows)
        it["accounts_involved"] = sorted({r.get("email", "") for r in rows} - {""})

    # `threshold` / `window_minutes` keep their existing names and meaning so no
    # existing consumer breaks; `rules` is additive and describes both detectors,
    # which a single threshold pair can no longer express on its own.
    return {"count": len(items), "threshold": IP_FAIL_THRESHOLD,
            "window_minutes": int(IP_FAIL_WINDOW // 60),
            "method_threshold": IP_METHOD_THRESHOLD,
            "method_window_hours": int(IP_METHOD_WINDOW // 3600),
            "rules": [
                {"name": "volume",
                 "description": (f"more than {IP_FAIL_THRESHOLD - 1} declines "
                                 f"within {int(IP_FAIL_WINDOW // 60)} minutes"),
                 "threshold": IP_FAIL_THRESHOLD,
                 "window_minutes": int(IP_FAIL_WINDOW // 60)},
                {"name": "breadth",
                 "description": (f"{IP_METHOD_THRESHOLD} or more distinct payment "
                                 f"methods failing within "
                                 f"{int(IP_METHOD_WINDOW // 3600)} hours"),
                 "threshold": IP_METHOD_THRESHOLD,
                 "window_minutes": int(IP_METHOD_WINDOW // 60)},
            ],
            "items": items[:limit]}


@app.get("/v1/admin/failed-attempts",
         dependencies=[Depends(require_role("analyst", "admin"))])
def failed_attempts(limit: int = 100) -> dict:
    """Every stored failed authorisation, newest first, across all addresses."""
    store: InMemoryStore = STATE["store"]
    records = STATE["records"]
    flagged = {r["ip_hash"] for r in store.suspicious_ips()}

    rows: list[dict] = []
    for ipa in STATE["fail_ips"]:
        try:
            rows.extend(records.query_prefix(f"IPFAIL#{ipa}", "ATTEMPT#"))
        except Exception:  # noqa: BLE001
            continue

    rows.sort(key=lambda r: r.get("created_at", ""), reverse=True)
    return {"count": len(rows), "items": [
        {**{k: v for k, v in r.items() if k not in ("PK", "SK")},
         "ip_suspicious": r.get("ip_hash") in flagged}
        for r in rows[:limit]
    ]}


# =============================================================================
# 12. Demo fraud attack  (admin-only, demo mode only)
# =============================================================================
#
# WHAT THIS IS FOR
# ----------------
# Demonstrating FraudShield end-to-end used to require either waiting ten real
# minutes at a checkout form or running `scripts/emit_webhook.py --burst`, which
# deliberately varies the customer and device on every event and therefore cannot
# produce customer velocity at all. Neither shows the thing the system is actually
# built to detect: one actor hammering one account from one device.
#
# WHAT THIS IS NOT
# ----------------
# It does not decide anything. There is no risk score, no decision, no sub-score
# and no reason code anywhere in this section. It builds transactions and hands
# each one to `Scorer.score()` -- the same call `create_order` makes -- then writes
# whatever the engine returned through the same persistence, audit and notification
# helpers the storefront uses. If the engine decides ALLOW, this endpoint reports
# ALLOW. A demo that hardcoded BLOCK would demonstrate nothing except that a
# constant can be printed.
#
# TWO INDEPENDENT SAFETY GATES
# ----------------------------
# Synthetic transactions in a production console would be indistinguishable from a
# real attack to the analyst reading them, so being switched off by default is not
# enough on its own:
#
#   1. FRAUDSHIELD_DEMO_MODE must be explicitly true. Default false.
#   2. The payment provider must be the simulator, both as REQUESTED and as
#      RESOLVED.
#
# The second gate is deliberately not inferred from the first, and the first is
# deliberately not inferred from the second: "the simulator is active" is a
# perfectly normal production state for this project (Razorpay needs a business
# account), so it cannot be taken as consent to inject synthetic traffic.
#
# WHY THE ATTACK IS NOT MERELY EIGHT LARGE PAYMENTS
# -------------------------------------------------
# `amount_ratio` is a deviation from the customer's own running mean, so an account
# with no history has nothing to deviate from -- its baseline falls back to
# GLOBAL_AMOUNT_PRIOR and the anomaly is measured against a stranger. So the
# scenario first replays an ordinary spending history for the account, exactly the
# way `warm_store()` replays historical CSV rows: `store.commit()` only, no
# scoring, no persistence, no queue, no audit. That history is context, not
# activity FraudShield decided anything about, and recording it as scored
# transactions would mean inventing scores for it.

# Explicit opt-in. Read from the environment at import; tests set the module
# attribute directly, which works because every read below resolves the global at
# call time.
DEMO_MODE = os.environ.get("FRAUDSHIELD_DEMO_MODE", "false").strip().lower() in (
    "1", "true", "yes", "on")

DEMO_SCENARIO = "fraud_attack"

# The audited action name for one run of the trigger. Distinct from RISK_DECISION:
# this event records that a human asked for synthetic traffic, which is a different
# fact from the engine's routing of any one transaction.
DEMO_TRIGGERED = "DEMO_ATTACK_TRIGGERED"

# Eight attempts, sixty seconds apart, so the whole burst spans 420s and sits
# inside the 600s window `txn_count_10m` counts over. Fixed, with no request body
# anywhere in this endpoint: a caller-supplied count is how a demo control becomes
# a way to write a million rows.
DEMO_ATTEMPTS = 8
DEMO_SPACING_SECONDS = 60

# Prefixes, not fixed values. Every run mints its own device and address from one
# token, so the run is self-contained.
#
# WHY THESE ARE NO LONGER CONSTANTS. They used to be, and repeated runs shared
# them. That was deliberate -- the device's account count genuinely grew, so the
# ring got denser each time -- but it had a consequence nobody wanted: the shared
# device and address ARE model features (`device_account_count`, `ip_account_count`,
# `device_failure_rate`), so by the third run the account looked more established,
# some attempts scored under the block threshold, MANUAL_REVIEW attempts reached
# the simulator and mostly SUCCEEDED, and the address then never accumulated three
# distinct failed methods. Repeated demoing quietly stopped the address flag
# firing. A demo that gets weaker the more you run it is the wrong trade.
#
# Fresh identities per run cost the cross-run ring story and buy a scenario that
# behaves identically every time.
#
# The prefixes are kept recognisable on purpose. `ip_hash` is normally an HMAC hex
# digest derived server-side from the connection, so a `demo_ip_` prefix is not a
# value `ip_hash_of()` can ever produce -- a synthetic address cannot be confused
# with, or collide with, a real one.
DEMO_DEVICE_PREFIX = "demo_device_"
DEMO_IP_PREFIX = "demo_ip_"
DEMO_HOME_DEVICE_PREFIX = "demo_home_device_"
DEMO_HOME_IP_PREFIX = "demo_home_ip_"
DEMO_EMAIL_DOMAIN = "example.test"

# Depth of the replayed history. Sized so the account is a plausible established
# customer AND so its running mean is not swamped by the attack itself: with only a
# handful of prior transactions, eight large amounts drag the mean up fast enough
# that `amount_ratio` falls back under the rule's threshold by the fifth attempt.
# This is a property of the existing running-mean feature, not a threshold being
# tuned -- nothing in RULE_POINTS, the weights or the thresholds is touched.
DEMO_BASELINE_TXNS = 60
DEMO_BASELINE_SPAN_DAYS = 84
DEMO_ACCOUNT_AGE_DAYS = 96

# An ordinary evening shopper: modest amounts, two familiar methods, one device,
# one address. Deterministic rather than random so two runs of the demo produce the
# same baseline and a test can reason about it.
DEMO_BASELINE_AMOUNTS = (1499.0, 2199.0, 1899.0, 2699.0, 1749.0, 2899.0,
                         2049.0, 1649.0)
DEMO_BASELINE_METHODS = ("upi", "card", "upi", "netbanking", "upi", "card")

# The burst. Escalating amounts on an unfamiliar device, rotating methods -- the
# shape of both the account-takeover and card-testing archetypes the model was
# trained on. What the engine makes of it is the engine's business.
DEMO_ATTACK_AMOUNTS = (21999.0, 24999.0, 27999.0, 31999.0,
                       35999.0, 39999.0, 42999.0, 44999.0)
DEMO_ATTACK_METHODS = ("card", "card", "upi", "card",
                       "netbanking", "card", "wallet", "card")

DEMO_NOTE = (
    "Synthetic activity generated by the admin-only demo trigger. Every "
    "transaction was scored by the real engine; no score or decision was "
    "assigned by the trigger. No money moved."
)


def demo_status() -> dict:
    """Whether the trigger would run, and why not if it would not.

    Published on /health so an operator can see the state without attempting the
    action, and read by the console so it can hide a control that could only 409.
    Contains no credentials.
    """
    provider = (STATE.get("provider_status") or {})
    active = provider.get("payment_provider")
    requested = provider.get("requested_provider")
    simulated = (active == payments.PROVIDER_SIMULATED
                 and requested == payments.PROVIDER_SIMULATED)
    reasons: list[str] = []
    if not DEMO_MODE:
        reasons.append("FRAUDSHIELD_DEMO_MODE is not enabled")
    if not simulated:
        reasons.append(
            f"the payment provider must be '{payments.PROVIDER_SIMULATED}' "
            f"(requested={requested!r}, active={active!r})")
    return {
        "enabled": bool(DEMO_MODE and simulated),
        "demo_mode": bool(DEMO_MODE),
        "provider_is_simulated": simulated,
        "scenario": DEMO_SCENARIO,
        "attempts": DEMO_ATTEMPTS,
        "window_seconds": (DEMO_ATTEMPTS - 1) * DEMO_SPACING_SECONDS,
        "blocked_because": reasons,
    }


def _demo_guard() -> dict:
    """Both gates, checked before anything is generated. Raises otherwise.

    403 for the flag and 409 for the provider, deliberately different: the first
    is "you have not turned this on", the second is "this cannot be turned on
    here". Neither message names an environment variable's value, only its name.
    """
    if not DEMO_MODE:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "The demo fraud attack is disabled. It generates synthetic "
            "transactions that an analyst cannot distinguish from real ones, so "
            "it must be enabled explicitly with FRAUDSHIELD_DEMO_MODE=true. It "
            "is off by default and should stay off in production.",
        )
    st = demo_status()
    if not st["provider_is_simulated"]:
        provider = (STATE.get("provider_status") or {})
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"The demo fraud attack refuses to run unless the payment provider "
            f"is the simulator. Requested "
            f"{provider.get('requested_provider')!r}, active "
            f"{provider.get('payment_provider')!r}. Generating synthetic "
            f"authorisations against a real gateway is not something this "
            f"endpoint will do.",
        )
    return st


def demo_identity() -> dict:
    """Every identifier one run needs, minted fresh and sharing one token.

    Nothing here is a fixed id. A stable customer would carry the previous run's
    velocity deque and running mean into the next; a stable device or address would
    carry its account count and failure rate, which are model features, so the
    second demo of the afternoon would score differently from the first for reasons
    nobody watching could see.

    One token across all five values so an operator reading the console can tell at
    a glance which run a transaction, device or address belongs to.
    """
    token = uuid.uuid4().hex[:10]
    return {
        "run": token,
        "customer_id": f"demo_cust_{token}",
        "email": f"demo_fraudster+{token[-6:]}@{DEMO_EMAIL_DOMAIN}",
        # The attack: an unfamiliar device on an unfamiliar address.
        "device_fp": f"{DEMO_DEVICE_PREFIX}{token}",
        "ip_hash": f"{DEMO_IP_PREFIX}{token}",
        # The baseline: the customer's own device and address.
        "home_device_fp": f"{DEMO_HOME_DEVICE_PREFIX}{token}",
        "home_ip_hash": f"{DEMO_HOME_IP_PREFIX}{token}",
    }


def demo_schedule(now: float) -> list[float]:
    """The attack timestamps: newest last, all inside the velocity window.

    Explicit arithmetic on one passed-in `now`. Nothing here changes the process
    clock, patches `datetime`, or touches the velocity implementation -- the
    counters simply see the timestamps they are given, which is what they do for
    the historical CSV replay too.
    """
    return [now - (DEMO_ATTEMPTS - 1 - i) * DEMO_SPACING_SECONDS
            for i in range(DEMO_ATTEMPTS)]


def demo_seed_history(store: InMemoryStore, cid: str, now: float,
                      home_device_fp: str = "", home_ip_hash: str = "") -> dict:
    """Replay an ordinary spending history for the demo account.

    `store.commit()` only -- the same mechanism `warm_store()` uses for historical
    rows. These are NOT scored, NOT persisted, NOT queued and NOT audited, because
    they are not decisions FraudShield made; they are the baseline the attack
    deviates from. Returns a small summary for the response.
    """
    # Derived from the customer id when not supplied, so a caller that only has a
    # cid (a test, typically) still gets a self-consistent run.
    token = cid.rsplit("_", 1)[-1]
    home_device = home_device_fp or f"{DEMO_HOME_DEVICE_PREFIX}{token}"
    home_ip = home_ip_hash or f"{DEMO_HOME_IP_PREFIX}{token}"

    created_at = now - DEMO_ACCOUNT_AGE_DAYS * 86400.0
    store.register_customer(cid, created_at)

    first = datetime.fromtimestamp(now, tz=timezone.utc) - timedelta(
        days=DEMO_BASELINE_SPAN_DAYS)
    step = DEMO_BASELINE_SPAN_DAYS / DEMO_BASELINE_TXNS

    # The customer's shopping hours are anchored RELATIVE TO THE ATTACK, twelve
    # hours away from it, rather than to a fixed clock time.
    #
    # WHY, and it is not cosmetic. `hour_deviation` measures the attack's distance
    # from this customer's own habitual hour. With a fixed 18:00-21:00 baseline the
    # signal depended on what time of day somebody happened to run the demo: at
    # 08:00 every attempt scored BLOCK, and at 16:00 the same scenario dropped the
    # UPI and wallet attempts to 69.5 and 47.5 -- under the block threshold -- so
    # they settled successfully and the address never accumulated enough distinct
    # failed methods to be flagged. A demo that behaves differently every hour is
    # not a demo.
    #
    # Anchoring keeps the deviation constant instead of eliminating it, which is
    # also how the training data builds account takeover: an off-hours transaction
    # is off-hours relative to THIS customer, never against an absolute "3am is
    # suspicious" rule.
    attack_hour = datetime.fromtimestamp(now, tz=timezone.utc).hour
    base_hour = (attack_hour + 12) % 24

    total = 0.0
    for i in range(DEMO_BASELINE_TXNS):
        dt = (first + timedelta(days=i * step)).replace(
            # A habitual four-hour shopping window, so the hour profile is a real
            # profile rather than noise spread evenly around the clock.
            hour=(base_hour + (i % 4)) % 24,
            minute=(i * 7) % 60, second=0, microsecond=0)
        amount = DEMO_BASELINE_AMOUNTS[i % len(DEMO_BASELINE_AMOUNTS)]
        total += amount
        store.commit({
            "customer_id": cid,
            "ts": dt.timestamp(),
            "amount": amount,
            "payment_method": DEMO_BASELINE_METHODS[i % len(DEMO_BASELINE_METHODS)],
            "device_fp": home_device,
            "ip_hash": home_ip,
            "status": "success",
            "hour": dt.hour + dt.minute / 60.0,
        })
    return {
        "transactions": DEMO_BASELINE_TXNS,
        "span_days": DEMO_BASELINE_SPAN_DAYS,
        "account_age_days": DEMO_ACCOUNT_AGE_DAYS,
        "average_amount": round(total / DEMO_BASELINE_TXNS, 2),
        "device_fp": home_device,
        "ip_hash": home_ip,
        "persisted": False,
        "scored": False,
        "note": ("in-process context only, replayed exactly like the historical "
                 "CSV warm-up; the eight scored attempts below are durable"),
    }


@app.post("/v1/admin/demo/fraud-attack", status_code=201)
def demo_fraud_attack(actor: User = Depends(require_role("admin"))) -> dict:
    """Generate one synthetic attack and put it through the real engine.

    Takes no parameters. There is nothing to configure, which is the point: a
    caller who could choose the attempt count could choose 100,000.

    THE PIPELINE IS THE PRODUCTION PIPELINE
    ---------------------------------------
        Scorer.score()               the real ML + rules + network layers
        payment_provider.authorise() the simulator, gated above
        store.commit()               the real velocity deques and entity graph
        record_scored_transaction()  the real durable write + review queue
        audit_risk_decision()        the real RISK_DECISION emitter
        notify_transaction()         the real alert path and EmailProvider

    Every risk number in the response was returned by the scorer. None of them is
    computed, adjusted or defaulted here.

    WHAT REPEATED RUNS DO
    ---------------------
    Nothing to each other. Every run mints its own customer, device and address, so
    two runs are fully isolated and the scenario behaves identically the tenth time
    as the first.

    It used to share one fixed device and address, which made the ring genuinely
    grow across runs -- and quietly broke the demo. Those identifiers feed
    `device_account_count`, `ip_account_count` and `device_failure_rate`, all model
    features, so by the third run the account looked established, some attempts fell
    under the block threshold, MANUAL_REVIEW attempts reached the simulator and
    mostly succeeded, and the address then never accumulated three distinct failed
    methods. The suspicious-address alert stopped firing the more the demo was used.
    Reproducibility won.
    """
    _demo_guard()

    store: InMemoryStore = STATE["store"]
    scorer: Scorer = STATE["scorer"]
    records = STATE["records"]
    provider = STATE["payment_provider"]

    ident = demo_identity()
    cid = ident["customer_id"]
    email = ident["email"]
    device_fp = ident["device_fp"]
    ip_hash = ident["ip_hash"]
    now = datetime.now(timezone.utc).timestamp()

    baseline = demo_seed_history(store, cid, now,
                                home_device_fp=ident["home_device_fp"],
                                home_ip_hash=ident["home_ip_hash"])

    results: list[dict] = []
    signals: set[str] = set()
    notifications_by_status: dict[str, int] = {}
    audit_events = 0
    persisted = 0
    ip_flag: dict | None = None
    last_raw: dict = {}

    for i, ts in enumerate(demo_schedule(now), start=1):
        method = DEMO_ATTACK_METHODS[i - 1]
        amount = DEMO_ATTACK_AMOUNTS[i - 1]
        txn = {
            "customer_id": cid,
            "ts": ts,
            "amount": amount,
            "payment_method": method,
            "device_fp": device_fp,
            "ip_hash": ip_hash,
        }

        # THE REAL ENGINE. Nothing below reinterprets what it returns.
        d, raw = scorer.score(store, txn)
        last_raw = raw

        order_id = f"ord_demo_{uuid.uuid4().hex[:8]}"
        txn_id = f"pay_demo_{uuid.uuid4().hex[:8]}"

        # The simulator, which the guard above has already established is the
        # active provider. It moves no money and holds no server-side records.
        auth = provider.authorise(
            order_id=order_id, amount=amount, method=method,
            decision=d.decision, customer_id=cid,
            metadata={"device_fp": device_fp, "ip_hash": ip_hash},
        )
        settled = auth.settlement

        # Read-before-write, in the same order create_order does it: features were
        # read by score() above, state is applied only now.
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        store.commit({**txn, "status": settled,
                      "hour": dt.hour + dt.minute / 60.0})

        status_key, _message = CUSTOMER_MESSAGE.get(
            d.decision, CUSTOMER_MESSAGE["MANUAL_REVIEW"])
        if settled == payments.SETTLED_FAILED and d.decision != "BLOCK":
            status_key = "declined_by_bank"

        # A declined attempt is stored and the address reconsidered, exactly as in
        # create_order -- this is what makes the Suspicious IPs tab light up for a
        # card-testing shape rather than staying empty.
        if settled == payments.SETTLED_FAILED:
            attempt_id = f"fail_demo_{uuid.uuid4().hex[:8]}"
            attempt = {
                "attempt_id": attempt_id, "order_id": order_id,
                "transaction_id": txn_id, "customer_id": cid, "email": email,
                "amount": amount, "payment_method": method,
                "instrument_display": f"demo {method}",
                "device_fp": device_fp, "ip_hash": ip_hash,
                "risk_score": d.risk_score, "decision": d.decision,
                "customer_status": status_key, "created_at": dt.isoformat(),
                "demo": True, "demo_scenario": DEMO_SCENARIO,
            }
            try:
                records.put(f"IPFAIL#{ip_hash}",
                            f"ATTEMPT#{dt.isoformat()}#{attempt_id}", attempt)
            except Exception as exc:  # noqa: BLE001
                print(f"WARNING: demo failed-attempt write did not land "
                      f"({type(exc).__name__})")
            STATE["fail_ips"].add(ip_hash)
            flag = store.evaluate_ip_suspicion(ip_hash, ts)
            if flag is not None:
                ip_flag = flag
                try:
                    records.put("SUSPICIOUS#IP", ip_hash, {
                        "ip_hash": ip_hash, "since": flag["since"],
                        "reason": flag["reason"], "last_seen": dt.isoformat(),
                        "failures_total": flag["failures_total"],
                        "accounts": flag["accounts"],
                        "demo": True, "demo_scenario": DEMO_SCENARIO,
                    })
                except Exception as exc:  # noqa: BLE001
                    print(f"WARNING: demo suspicious-IP write did not land "
                          f"({type(exc).__name__})")
                if flag["new"]:
                    audit(actor="system", action="ip_marked_suspicious",
                          before={"ip_hash": ip_hash},
                          after={**flag, "demo": True,
                                 "demo_scenario": DEMO_SCENARIO})
                    audit_events += 1
                    # Marked copy, so the alert this raises is audited as
                    # synthetic too. The stored flag itself is untouched.
                    notify_suspicious_ip({**flag, "demo": True,
                                          "demo_scenario": DEMO_SCENARIO})

        record = {
            "order_id": order_id, "transaction_id": txn_id, "customer_id": cid,
            "email": email,
            "items": [], "item_count": 1,
            "product_name": f"Demo attempt {i} of {DEMO_ATTEMPTS}",
            "amount": amount, "payment_method": method,
            "instrument_display": f"demo {method}",
            "device_fp": device_fp, "ip_hash": ip_hash,
            "ip_suspicious": ip_flag is not None,
            "settlement": settled, "created_at": dt.isoformat(),
            "customer_status": status_key,
            # Straight from the Decision the scorer returned.
            "risk_score": d.risk_score, "decision": d.decision,
            "sub_scores": d.sub_scores, "reason_codes": d.reason_codes,
            "fired_rules": d.fired_rules, "override": d.override,
            "return_status": None, "label": None,
            "provider": auth.provider,
            "provider_order_id": auth.provider_order_id,
            "provider_payment_id": auth.provider_payment_id,
            "provider_error": auth.error,
            # The marker. Present on the stored transaction, its audit event and
            # its alert, so synthetic activity is separable everywhere it lands.
            "demo": True, "demo_scenario": DEMO_SCENARIO,
            "demo_attempt": i, "demo_note": DEMO_NOTE,
            "source": f"demo:{DEMO_SCENARIO}",
        }

        if record_scored_transaction({**record, "features": raw,
                                      "model_version": d.model_version,
                                      "degraded": d.degraded,
                                      "scored_at": dt.isoformat()}):
            persisted += 1

        audit_risk_decision(
            d=d, scorer=scorer, transaction_id=txn_id, order_id=order_id,
            customer_id=cid, amount=amount, payment_method=method,
            settlement=settled, source=f"demo:{DEMO_SCENARIO}",
            demo_scenario=DEMO_SCENARIO,
        )
        audit_events += 1

        note = notify_transaction({**record, "model_version": d.model_version,
                                   "degraded": d.degraded})
        if note is not None:
            key = str(note.get("status") or "unknown")
            notifications_by_status[key] = notifications_by_status.get(key, 0) + 1

        signals.update(d.fired_rules)
        results.append({
            "attempt": i,
            "transaction_id": txn_id,
            "order_id": order_id,
            "at": dt.isoformat(),
            "amount": amount,
            "payment_method": method,
            "settlement": settled,
            # Reported, never decided, here.
            "risk_score": d.risk_score,
            "decision": d.decision,
            "sub_scores": d.sub_scores,
            "fired_rules": d.fired_rules,
            "override": d.override,
            # The velocity the engine actually saw on THIS attempt, so a reader
            # can watch the counter climb rather than take the claim on trust.
            "txn_count_10m": raw["txn_count_10m"],
            "amount_ratio": raw["amount_ratio"],
        })

    final = results[-1]
    summary = {
        "scenario": DEMO_SCENARIO,
        "demo": True,
        "attempts_generated": len(results),
        "customer_id": cid,
        "customer_email": email,
        "device_id": device_fp,
        "ip_hash": ip_hash,
        "window_seconds": (DEMO_ATTEMPTS - 1) * DEMO_SPACING_SECONDS,
        "first_attempt_at": results[0]["at"],
        "last_attempt_at": final["at"],
        "baseline": baseline,
        "results": results,
        "final_transaction": {
            "transaction_id": final["transaction_id"],
            "risk_score": final["risk_score"],
            "decision": final["decision"],
            "sub_scores": final["sub_scores"],
            "fired_rules": final["fired_rules"],
        },
        "decisions": {
            band: sum(1 for r in results if r["decision"] == band)
            for band in ("ALLOW", "MANUAL_REVIEW", "BLOCK")
        },
        # Union across the burst: a signal that fired on attempt 3 is evidence the
        # scenario produced it, even if attempt 8 no longer trips the same rule.
        "signals": sorted(signals),
        # What the engine saw at the end, from the last feature vector it built.
        "evidence": {
            "txn_count_10m": last_raw.get("txn_count_10m"),
            "txn_count_1h": last_raw.get("txn_count_1h"),
            "failed_count_1h": last_raw.get("failed_count_1h"),
            "amount_ratio": last_raw.get("amount_ratio"),
            "customer_avg_amount": last_raw.get("customer_avg_amount"),
            "prev_txn_count": last_raw.get("prev_txn_count"),
            "device_account_count": last_raw.get("device_account_count"),
            "ip_account_count": last_raw.get("ip_account_count"),
            "account_age_hours": last_raw.get("account_age_hours"),
        },
        "thresholds": {"review": scorer.review_t, "block": scorer.block_t},
        "model_version": scorer.model_version,
        "degraded": scorer.degraded,
        "transactions_persisted": persisted,
        "queued_for_review": sum(1 for r in results
                                 if r["decision"] in QUEUED_DECISIONS),
        "ip_flagged": ip_flag is not None,
        "notification_triggered": bool(notifications_by_status),
        "notifications": notifications_by_status,
        # Mode only. No addresses, no username, no password.
        "email_provider": (STATE.get("email_status") or {}).get("provider"),
        "alerts_enabled": bool((STATE.get("email_status") or {})
                               .get("alerts_enabled")),
        "audit_created": audit_events > 0,
        "audit_events": audit_events,
        "creates_ground_truth": False,
        "moves_money": False,
        "note": DEMO_NOTE,
    }

    # One event naming the human who asked for this. The synthetic transactions
    # each carry their own RISK_DECISION; this records the request itself, which is
    # the only part of the run a person is responsible for.
    audit(
        actor=actor.email,
        action=DEMO_TRIGGERED,
        identity=actor_identity(actor),
        before={
            "scenario": DEMO_SCENARIO,
            "attempts_requested": DEMO_ATTEMPTS,
            "customer_id": cid,
            "device_fp": device_fp,
            "ip_hash": ip_hash,
            "window_seconds": summary["window_seconds"],
        },
        after={
            "demo": True,
            "demo_scenario": DEMO_SCENARIO,
            "attempts_generated": summary["attempts_generated"],
            "decisions": summary["decisions"],
            "signals": summary["signals"],
            "final_transaction": summary["final_transaction"],
            "transaction_ids": [r["transaction_id"] for r in results],
            "transactions_persisted": persisted,
            "queued_for_review": summary["queued_for_review"],
            "notifications": notifications_by_status,
            "thresholds": summary["thresholds"],
            # Synthetic test activity. A human asked for it; nobody observed it,
            # and no outcome was recorded.
            "is_ground_truth": False,
            "creates_fraud_label": False,
            "moves_money": False,
            "note": DEMO_NOTE,
        },
    )
    summary["audit_events"] = audit_events + 1
    return summary


@app.get("/v1/returns")
def list_returns(u: User = Depends(current_user)) -> dict:
    rows = STATE["records"].query_prefix(f"CUSTOMER#{u.user_id}", "RETURN#")
    return {"count": len(rows), "returns": [
        {k: v for k, v in r.items() if k not in ("PK", "SK", "customer_id")}
        for r in rows
    ]}


# =============================================================================
# 12. Payment webhook ingestion
# =============================================================================
#
# WHAT THIS IS, PRECISELY
# -----------------------
# The ingestion contract a payment provider calls, implemented against
# Razorpay's documented webhook shape and signature scheme.
#
# What is REAL here:
#   - HMAC-SHA256 verification over the raw request body, constant-time compared
#   - replay/idempotency protection keyed on the provider's event id
#   - a staleness window bounding how long a captured signature stays useful
#   - paise-to-rupee conversion, method mapping, customer resolution
#   - scoring and persistence through the same Scorer the storefront uses
#
# What is SIMULATED:
#   - the sender. Razorpay Test Mode requires a business account we do not have,
#     so scripts/emit_webhook.py signs and posts events instead.
#
# This distinction is the whole point. The security-critical half -- verifying
# that an unauthenticated public endpoint is really being called by the provider
# -- is genuinely implemented and tested, including that a forged signature is
# rejected. Pointing this at Razorpay is a secret and a URL, not a rewrite.
#
# Do NOT read this as "Razorpay integration works". It does not. There is no
# Razorpay account, no API call to Razorpay, and no order created through them.

WEBHOOK_SECRET = os.environ.get("FRAUDSHIELD_WEBHOOK_SECRET", "")

# Razorpay's dashboard calls this the "webhook secret", and an operator wiring a
# real account will already have it under that name. Accepted as a FALLBACK only:
# FRAUDSHIELD_WEBHOOK_SECRET still wins where both are set, and an empty value
# changes nothing. This adds a way to supply the same secret, not a way to skip
# verification -- the fail-closed check below is untouched.
RAZORPAY_WEBHOOK_SECRET = os.environ.get("RAZORPAY_WEBHOOK_SECRET", "")


def webhook_secret() -> str:
    """The secret webhook signatures are verified against, or "" if unset."""
    return WEBHOOK_SECRET or RAZORPAY_WEBHOOK_SECRET

# How long a signed event stays acceptable. A captured request body plus its
# signature is replayable forever without this; the idempotency check already
# stops a duplicate of a SEEN event, but a bound also limits an unseen one held
# back and fired later. Razorpay retries for up to 24h, so this is generous.
WEBHOOK_MAX_AGE_S = 86400.0

# Provider method names and event names are mapped in payments.py, which is the
# single table for provider vocabulary. This used to be an inline duplicate here;
# two copies of a status map is how "authorized" eventually gets read as a
# completed sale in one code path and not the other.
#
# Kept as a module-level alias so the mapping is still inspectable from here.
WEBHOOK_METHOD_MAP = payments.RAZORPAY_METHOD


def verify_webhook_signature(raw: bytes, signature: str, secret: str) -> bool:
    """HMAC-SHA256 over the RAW body, hex digest, constant-time compared.

    Two things here are load-bearing:

      - The digest is computed over the exact bytes received. Re-serialising the
        parsed JSON and hashing that is the classic mistake: key order, spacing
        and unicode escaping all change the bytes, so a valid signature fails and
        the usual "fix" is to stop verifying.
      - compare_digest, not ==. A short-circuiting comparison leaks how many
        leading bytes matched, which is enough to forge a signature byte by byte.
    """
    if not secret or not signature:
        return False
    expected = hmac.new(secret.encode("utf-8"), raw, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature.strip().lower())


def _webhook_customer_id(email: str, contact: str) -> tuple[str, str]:
    """Resolve the provider's payer to one of our accounts.

    Returns (customer_id, resolution) where resolution is 'account' or 'derived'.

    A real account is preferred so the transaction joins that customer's existing
    velocity and baseline history. When there is no match we derive a STABLE
    pseudo-id from the identifier rather than minting a random one: a random id
    would make every webhook event look like a brand-new customer, permanently
    poisoning account_age_hours and prev_txn_count for genuine repeat payers.
    """
    ident = (email or contact or "").strip().lower()
    if ident:
        try:
            users = STATE["users"]
            u = users.get_by_email(ident) if "@" in ident else None
            if u is not None:
                return u.user_id, "account"
        except Exception:  # noqa: BLE001
            pass
    if not ident:
        return f"wh_anon_{uuid.uuid4().hex[:10]}", "derived"
    digest = hmac.new(
        IP_PEPPER.encode("utf-8"), ident.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return f"wh_{digest[:16]}", "derived"


class WebhookResult(BaseModel):
    event_id: str
    payment_id: str
    ingested: bool
    duplicate: bool
    decision: str | None = None
    risk_score: float | None = None
    transaction_id: str | None = None


@app.post("/v1/webhooks/payment", response_model=WebhookResult)
async def payment_webhook(request: Request) -> WebhookResult:
    """Ingest a signed payment event, score it, persist it.

    Unauthenticated by design -- a provider has no session and no API key. The
    signature IS the authentication, which is why a missing or wrong one is a 401
    and not a 400.

    Accepts `X-Razorpay-Signature` or `X-Webhook-Signature` so the header name
    does not have to change when a real provider is wired in.
    """
    raw = await request.body()

    secret = webhook_secret()
    if not secret:
        # Fail closed. An unverified webhook is strictly worse than no webhook:
        # anyone who finds the URL could inject transactions into the risk engine
        # and move the entity graph at will.
        raise HTTPException(
            503, "Webhook ingestion disabled: FRAUDSHIELD_WEBHOOK_SECRET is unset.",
        )

    signature = (
        request.headers.get("x-razorpay-signature")
        or request.headers.get("x-webhook-signature")
        or ""
    )
    if not verify_webhook_signature(raw, signature, secret):
        # Deliberately does not say whether the signature was absent, malformed or
        # simply wrong.
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid webhook signature.")

    try:
        body = json.loads(raw)
    except json.JSONDecodeError:
        raise HTTPException(400, "Body is not valid JSON.") from None
    if not isinstance(body, dict):
        raise HTTPException(400, "Body must be a JSON object.")

    event = body.get("event", "")
    if event not in ("payment.captured", "payment.failed"):
        # 200, not 4xx. A provider retries non-2xx, so rejecting an event we
        # simply do not model would earn an indefinite retry loop.
        return WebhookResult(
            event_id=str(body.get("id", "")), payment_id="",
            ingested=False, duplicate=False,
        )

    try:
        entity = body["payload"]["payment"]["entity"]
        payment_id = str(entity["id"])
        amount_paise = int(entity["amount"])
    except (KeyError, TypeError, ValueError):
        raise HTTPException(422, "Malformed payment.* event payload.") from None

    if amount_paise <= 0:
        raise HTTPException(422, "Payment amount must be positive.")

    event_id = (
        request.headers.get("x-razorpay-event-id")
        or str(body.get("id") or "")
        or f"evt_{payment_id}"
    )

    created_at = float(body.get("created_at") or entity.get("created_at") or 0) or None
    now = datetime.now(timezone.utc).timestamp()
    if created_at and now - created_at > WEBHOOK_MAX_AGE_S:
        raise HTTPException(422, "Event is older than the accepted window.")

    records = STATE["records"]

    # ---- idempotency ------------------------------------------------------
    # Providers redeliver on any non-2xx and occasionally on success. Scoring the
    # same payment twice would double every velocity counter it touches, which is
    # the fastest way to manufacture a fraud ring out of one honest customer.
    if event_id in STATE["webhook_seen"]:
        return WebhookResult(event_id=event_id, payment_id=payment_id,
                             ingested=False, duplicate=True)
    try:
        if records.get("WEBHOOK#EVENT", event_id) is not None:
            STATE["webhook_seen"].add(event_id)
            return WebhookResult(event_id=event_id, payment_id=payment_id,
                                 ingested=False, duplicate=True)
    except Exception:  # noqa: BLE001
        pass

    # ---- map the provider's shape onto ours --------------------------------
    # Amount arrives in paise. Treating it as rupees would inflate every amount
    # 100x and fire amount_anomaly on the entire event stream.
    amount = payments.from_minor_units(amount_paise)
    method = payments.method_from_provider(entity.get("method"))
    # Only payment.captured and payment.failed reach here (see the event gate
    # above), so this resolves to success or failed exactly as the inline
    # conditional it replaces did. It routes through the shared table so the event
    # vocabulary has one definition.
    settled = payments.settlement_from_event(event)
    email = str(entity.get("email") or "")
    contact = str(entity.get("contact") or "")
    customer_id, resolution = _webhook_customer_id(email, contact)

    # device_fp and ip_hash cannot come from the connection here: the request is
    # from the provider's servers, not the payer's browser. The merchant must
    # forward them in `notes` at order-creation time. When absent, IP and device
    # signals for this transaction are unavailable rather than wrong -- sentinels
    # keep it out of real clusters instead of joining an arbitrary one.
    notes = entity.get("notes") if isinstance(entity.get("notes"), dict) else {}
    device_fp = str(notes.get("device_fp") or f"wh_nodev_{payment_id}")
    note_ip = str(notes.get("ip_hash") or "")
    ip_hash = note_ip or f"wh_noip_{payment_id}"
    signals_complete = bool(notes.get("device_fp")) and bool(note_ip)

    ts = created_at or now
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    txn = {
        "customer_id": customer_id, "ts": ts, "amount": amount,
        "payment_method": method, "device_fp": device_fp, "ip_hash": ip_hash,
    }

    store: InMemoryStore = STATE["store"]
    scorer: Scorer = STATE["scorer"]

    try:
        d, feats = scorer.score(store, txn)
    except Exception as exc:  # noqa: BLE001
        # 503 so the provider retries. Idempotency was not recorded, so the retry
        # will be scored rather than discarded as a duplicate.
        raise HTTPException(
            503, detail={"decision": "MANUAL_REVIEW", "reason": "SCORING_UNAVAILABLE",
                         "error": type(exc).__name__},
        ) from exc

    store.commit({**txn, "status": settled,
                 "hour": dt.hour + dt.minute / 60.0})

    txn_id = f"pay_{uuid.uuid4().hex[:10]}"
    record = {
        "order_id": f"whk_{payment_id}", "transaction_id": txn_id,
        "customer_id": customer_id, "email": email or contact,
        "items": [], "item_count": 0,
        "product_name": f"Webhook payment {payment_id}",
        "amount": amount, "payment_method": method,
        "instrument_display": f"{method} via provider",
        "instrument_ref": payment_id, "instrument_account_count": 1,
        "device_fp": device_fp, "ip_hash": ip_hash,
        "settlement": settled, "created_at": dt.isoformat(),
        "customer_status": "confirmed" if settled == "success" else "declined_by_bank",
        "risk_score": d.risk_score, "decision": d.decision,
        "sub_scores": d.sub_scores, "reason_codes": d.reason_codes,
        "fired_rules": d.fired_rules, "override": d.override,
        "return_status": None, "label": None,
        # Provenance. An analyst must be able to tell an ingested event from a
        # storefront order, because their available signals differ.
        "source": "webhook", "provider_payment_id": payment_id,
        "provider_event_id": event_id,
        "customer_resolution": resolution,
        "signals_complete": signals_complete,
        "ip_suspicious": False,
    }
    records.put(f"CUSTOMER#{customer_id}", f"ORDER#{dt.isoformat()}#{record['order_id']}",
                record)
    records.put("INDEX#ORDER", record["order_id"],
                {"customer_id": customer_id,
                 "sk": f"ORDER#{dt.isoformat()}#{record['order_id']}"})

    # Same failed-attempt path the storefront uses, so a card-testing burst
    # arriving by webhook flags the address exactly as one at checkout would.
    webhook_ip_flag: dict | None = None
    if settled == "failed" and ip_hash and not ip_hash.startswith("wh_noip_"):
        attempt_id = f"fail_{uuid.uuid4().hex[:10]}"
        attempt = {
            "attempt_id": attempt_id, "order_id": record["order_id"],
            "transaction_id": txn_id, "customer_id": customer_id,
            "email": email or contact, "amount": amount,
            "payment_method": method,
            "instrument_display": record["instrument_display"],
            "instrument_ref": payment_id, "device_fp": device_fp,
            "ip_hash": ip_hash, "risk_score": d.risk_score,
            "decision": d.decision, "customer_status": record["customer_status"],
            "created_at": dt.isoformat(), "source": "webhook",
        }
        records.put(f"IPFAIL#{ip_hash}", f"ATTEMPT#{dt.isoformat()}#{attempt_id}",
                    attempt)
        STATE["fail_ips"].add(ip_hash)
        flag = store.evaluate_ip_suspicion(ip_hash, ts)
        webhook_ip_flag = flag
        if flag is not None:
            record["ip_suspicious"] = True
            records.put("SUSPICIOUS#IP", ip_hash, {
                "ip_hash": ip_hash, "since": flag["since"],
                "reason": flag["reason"], "last_seen": dt.isoformat(),
                "failures_total": flag["failures_total"],
                "accounts": flag["accounts"],
            })
            if flag["new"]:
                audit(actor="system", action="ip_marked_suspicious",
                      before={"ip_hash": ip_hash}, after=flag)

    # Same shared durable path as the storefront. Reached only for events that
    # passed the idempotency guard above, so a redelivery cannot write a second
    # transaction or a second queue item.
    record_scored_transaction({**record, "features": feats,
                              "model_version": d.model_version,
                              "degraded": d.degraded,
                              "scored_at": dt.isoformat()})

    # Same event, same shape, different source. An ingested event is still a risk
    # decision, so it gets one too. The idempotency guard above means a redelivery
    # never reaches here, so a retried webhook cannot produce a second one.
    audit_risk_decision(
        d=d, scorer=scorer, transaction_id=txn_id, order_id=record["order_id"],
        customer_id=customer_id, amount=amount, payment_method=method,
        settlement=settled, source="webhook",
    )

    # Same alert path as the storefront, after the same guarantees. The idempotency
    # guard above means a redelivered event never reaches here, and the dedupe key
    # in notify() is a second, independent defence against a duplicate email.
    notify_transaction({**record, "model_version": d.model_version,
                        "degraded": d.degraded})
    if webhook_ip_flag is not None and webhook_ip_flag.get("new"):
        notify_suspicious_ip(webhook_ip_flag)

    # Recorded only after successful processing, so a failure earlier can retry.
    STATE["webhook_seen"].add(event_id)
    try:
        records.put("WEBHOOK#EVENT", event_id, {
            "event_id": event_id, "payment_id": payment_id, "event": event,
            "transaction_id": txn_id, "received_at": dt.isoformat(),
            "decision": d.decision, "risk_score": d.risk_score,
        })
    except Exception:  # noqa: BLE001
        pass

    audit(actor="webhook", action="payment_event_ingested",
          before={"event": event, "payment_id": payment_id, "event_id": event_id},
          after={"transaction_id": txn_id, "decision": d.decision,
                 "risk_score": d.risk_score, "settlement": settled,
                 "customer_resolution": resolution,
                 "signals_complete": signals_complete})

    return WebhookResult(
        event_id=event_id, payment_id=payment_id, ingested=True, duplicate=False,
        decision=d.decision, risk_score=d.risk_score, transaction_id=txn_id,
    )


@app.get("/health")
def health() -> dict:
    s: Scorer = STATE["scorer"]
    return {
        "status": "ok",
        "model_loaded": s is not None and not s.degraded,
        "model_version": s.model_version if s else None,
        "thresholds": {"review": s.review_t, "block": s.block_t} if s else None,
        # Where the live thresholds came from, and whether a stored configuration
        # had to be ignored. `degraded: true` means the running values are NOT the
        # ones an admin last set -- an operator has to be able to see that without
        # reading startup logs.
        "threshold_config": STATE.get("threshold_config"),
        "store": "in-memory (DynamoDB adapter not built)",
        "service_auth": "api-key" if API_KEY else "OPEN -- set FRAUDSHIELD_API_KEY",
        "user_auth": "jwt + argon2id",
        "user_store": STATE.get("users_backend"),
        "record_store": STATE.get("records_backend"),
        # Whether velocity counters and the entity graph were fully rebuilt from
        # persisted history. `complete: false` means some entities are colder than
        # they would have been without a restart, and network risk may under-score
        # for them -- stated rather than implied.
        "entity_state": STATE.get("graph_rehydration"),
        # Unresolved promo holds rebuilt from durable records. `complete: false`
        # means some redemptions could not be read, so the visible backlog may be
        # short of what storage actually holds.
        "promo_queue": STATE.get("promo_rehydration"),
        # Which gateway is actually in front of checkout, and whether Razorpay
        # credentials exist. Booleans and mode names only -- no key, no secret, no
        # prefix of either. `degraded: true` means the configured provider could
        # not be used and the simulator is serving instead, which an operator
        # needs to see without reading logs.
        "payment_provider": (STATE.get("provider_status") or {}).get(
            "payment_provider"),
        "razorpay_configured": (STATE.get("provider_status") or {}).get(
            "razorpay_configured", False),
        "payment_provider_status": STATE.get("provider_status"),
        # Whether the admin-only synthetic-attack trigger would run. Published so
        # an operator can see that it is off without having to try it, and so the
        # console can hide a control that could only fail. Names no credential and
        # no environment value, only which gate is closed.
        "demo": demo_status(),
        "webhook_ingestion": "enabled" if webhook_secret() else (
            "disabled -- set FRAUDSHIELD_WEBHOOK_SECRET"),
        # Analyst alerting mode. Mode name, booleans and a COUNT only.
        # Deliberately absent: the SMTP password, the SMTP username, the sender
        # address and the recipient list. /health is the least authenticated
        # surface in the service, and a recipient list is an internal distribution
        # list -- publishing it would hand an attacker the analyst roster.
        "email_notifications": {
            "provider": (STATE.get("email_status") or {}).get("provider"),
            "configured": (STATE.get("email_status") or {}).get("configured", False),
            "degraded": (STATE.get("email_status") or {}).get("degraded", False),
            "alerts_enabled": (STATE.get("email_status") or {}).get(
                "alerts_enabled", False),
            "recipient_count": (STATE.get("email_status") or {}).get(
                "recipient_count", 0),
            "note": (STATE.get("email_status") or {}).get("note", ""),
            "sent": sum(1 for r in (STATE.get("notifications") or [])
                        if r.get("status") == notifications.STATUS_SENT),
            "failed": sum(1 for r in (STATE.get("notifications") or [])
                          if r.get("status") == notifications.STATUS_FAILED),
        },
        "admin_requires_role": ["analyst", "admin"],
    }


def _perform_scoring(req: ScoreRequest, source: str) -> tuple[ScoreResponse, str]:
    """The one scoring body behind /v1/risk/score and /v1/checkout.

    Factored out so both routes share a single implementation AND can name their
    own `source` in the audit trail. Previously /v1/checkout called the /v1/risk/score
    handler directly, which meant an audit event emitted from here would have
    attributed a customer-facing checkout to the service-to-service path.

    Returns (response, txn_id).

    WHEN THIS AUDITS, AND WHY THE DISTINCTION IS KEPT
    -------------------------------------------------
    A RISK_DECISION event is emitted only when `commit=True`.

    That is not a shortcut, it is the repository's existing definition of a
    decision. `commit=false` is documented on ScoreRequest as a dry run: the caller
    asks for a score WITHOUT applying it to entity state, and the stored record is
    already flagged `committed: false` so startup replay skips it. Such a call
    changes nothing and routes nothing -- it is a preview.

    Auditing previews would be actively harmful, not merely noisy: an analyst
    exploring "what would this score?" would fill the decision log with events for
    transactions that never happened, and the count of RISK_DECISION events would
    stop matching the count of decisions actually taken. The threshold tuner and
    any future reconciliation both depend on that equality.

    So: one committed scoring -> exactly one RISK_DECISION. One preview -> none.
    """
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
        # Persisted so this transaction is replayable into entity state after a
        # restart, exactly like the storefront and webhook paths. Every value is
        # already on the request or decided above -- nothing new is collected.
        "payment_method": req.payment_method,
        "device_fp": req.device_fp,
        "ip_hash": req.ip_hash,
        "settlement": req.status,
        "model_version": d.model_version,
        "degraded": d.degraded,
        # The transaction's OWN timestamp, not the wall clock. This endpoint
        # accepts an explicit `ts`, so `scored_at` (when we ran) and `created_at`
        # (when the payment happened) can be far apart -- during a replay or a
        # backfill they always are. Replaying against `scored_at` would collapse
        # every velocity window onto the moment of scoring.
        "created_at": datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(),
        # Whether this scoring was applied to entity state. `commit=false` is a
        # dry run: the caller asked for a score WITHOUT mutating counters, so
        # replaying it after a restart would apply an effect the caller declined.
        "committed": bool(req.commit),
    }
    record_scored_transaction(record)

    # One RISK_DECISION per COMMITTED scoring, using the same Decision `d` that
    # built the record above. This path used to be the one scoring entry point with
    # no audit event, which meant a service-to-service decision -- a real refusal,
    # affecting a real payment -- left no trace, while the identical decision made
    # at the storefront left one.
    #
    # `order_id` is None because this endpoint scores a transaction, not an order.
    # Reported as absent rather than filled with the transaction id, which would
    # fabricate an order that does not exist.
    if req.commit:
        audit_risk_decision(
            d=d, scorer=scorer, transaction_id=txn_id, order_id=None,
            customer_id=req.customer_id, amount=req.amount,
            payment_method=req.payment_method, settlement=req.status,
            source=source,
        )
        # Alerted on the same condition as the audit event, and for the same
        # reason: a committed scoring is a real decision affecting a real payment,
        # so it belongs in the queue AND in somebody's inbox. A `commit=false`
        # preview routes nothing and therefore alerts nobody -- otherwise an
        # analyst exploring "what would this score?" would email the whole team.
        notify_transaction({**record, "source": source})

    return ScoreResponse(
        transaction_id=txn_id, risk_score=d.risk_score, decision=d.decision,
        sub_scores=SubScores(**d.sub_scores), reason_codes=d.reason_codes,
        override=d.override, model_version=d.model_version, degraded=d.degraded,
        scored_at=record["scored_at"], latency_ms=round(latency, 2),
    ), txn_id


@app.post("/v1/risk/score", response_model=ScoreResponse,
          dependencies=[Depends(require_key)])
def score(req: ScoreRequest) -> ScoreResponse:
    """Analyst-facing scoring. Full evidence."""
    response, _ = _perform_scoring(req, "service")
    return response


@app.post("/v1/checkout", response_model=CustomerView,
          dependencies=[Depends(require_key)])
def checkout(req: ScoreRequest) -> CustomerView:
    """Customer-facing. Same scoring, deliberately impoverished response."""
    res, _ = _perform_scoring(req, "checkout")
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
    score never becomes a label on its own.

    Emits exactly one OUTCOME_RECORDED per accepted first ruling.

    GROUND TRUTH IS NOT SILENTLY OVERWRITABLE. Re-submitting the SAME label is
    idempotent and writes nothing; submitting a DIFFERENT label is refused with
    409. This replaced unlimited re-labelling, which let an accidental click on
    the opposite button destroy a considered verdict.

    A rejected call writes nothing: an unknown field or an invalid label is
    refused by OutcomeRequest before this function runs, an unknown transaction
    404s, and a conflict 409s before any state is touched. The audit history must
    never imply an operation that did not happen.
    """
    r = STATE["txns"].get(txn_id)
    if r is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown transaction")

    # Captured BEFORE any write -- it is the only remaining evidence of what the
    # previous ruling was.
    previous_label = r.get("label")

    # ---- conflict protection ------------------------------------------------
    #
    # Ground truth is the scarcest data in this system: it is the only thing a
    # future retrain can learn from, and the only basis on which the model's
    # precision can ever be measured. It used to be silently overwritable -- an
    # analyst could POST `fraud`, then `legitimate`, and the second call would win
    # with a 200 and no warning. An accidental click on the opposite button
    # destroyed a considered verdict with no trace beyond a second audit event.
    #
    # Two distinct cases, deliberately answered differently:
    if previous_label is not None:
        if previous_label == req.label:
            # IDEMPOTENT. A retry, a double-click, or a duplicated request. The
            # state is already what the caller is asking for, so this succeeds --
            # but it writes nothing and emits NO second ground-truth event,
            # because one human decision must not be counted twice in the data a
            # retrain learns from.
            return {
                "transaction_id": txn_id, "label": previous_label,
                "previous_label": previous_label,
                "idempotent": True,
                "note": "this outcome was already recorded; nothing changed",
            }
        # CONFLICT. A different verdict already exists. Refused rather than
        # applied: the existing label may be wrong, but silently replacing it
        # would erase a human judgement without anyone deciding to. Reversing a
        # ruling is a real operation that deserves an explicit path, not a side
        # effect of re-submitting a form.
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail={
                "error": "GROUND_TRUTH_CONFLICT",
                "message": (
                    f"This transaction is already labelled {previous_label!r}. "
                    f"Recording {req.label!r} would overwrite an existing human "
                    f"decision, which is not done implicitly."
                ),
                "transaction_id": txn_id,
                "existing_label": previous_label,
                "requested_label": req.label,
                "existing_labelled_by": r.get("labelled_by"),
                "existing_labelled_at": r.get("labelled_at"),
            },
        )

    r["label"] = req.label
    # Identity comes from the verified token, never from the request body. A
    # client-supplied analyst_id would make the audit trail worthless.
    r["labelled_by"] = actor.email
    r["labelled_at"] = datetime.now(timezone.utc).isoformat()

    # Make the human outcome and the queue resolution survive a restart. Both are
    # updates to items that already exist, so neither can create a duplicate.
    update_persisted_transaction(txn_id, {
        "label": r["label"],
        "labelled_by": r["labelled_by"],
        "labelled_at": r["labelled_at"],
    })
    resolve_review_item(txn_id)

    audit_outcome_recorded(
        txn_id=txn_id, txn=r, previous_label=previous_label,
        new_label=req.label, actor_email=actor.email,
        identity=actor_identity(actor),
    )

    return {"transaction_id": txn_id, "label": req.label,
            "previous_label": previous_label,
            "idempotent": False,
            "note": "label recorded for retraining; score was not a verdict"}
