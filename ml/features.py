"""
Feature matrix construction, shared by train.py and evaluate.py.

Both must build the matrix identically or the evaluation is measuring a different
model than the one that was trained. That is why this lives in one place.
"""

from __future__ import annotations

import numpy as np
import pandas as pd

# The 22 features from docs/RISK_ENGINE.md, as they appear in the raw CSV.
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
#   status         -- the authorisation outcome of THIS transaction. A real scorer
#                     runs BEFORE authorisation, so it does not have this. Card
#                     testing declines ~72% of the time, so including it would
#                     leak the label almost directly. This is the single easiest
#                     way to accidentally build a 0.99 AUC model that cannot ship.
#   fraud_type     -- the archetype name. Trivially the label.
#   segment        -- generator metadata, kept only for fairness slicing.
#   customer_id
#   device_fp      -- raw identifiers. Memorising specific devices is not
#   ip_hash           generalisation, and in production these are unbounded-
#                     cardinality strings that shift constantly.
#   ts_epoch       -- absolute time. The model would learn "week 8 = test set".
#   timestamp
#   transaction_id
#   account_created_at
#                  -- absolute signup time. Exists so the online scorer can be
#                     seeded identically (see tests/test_parity.py). As a feature
#                     it would leak cohort timing: "accounts created in June" is a
#                     property of the test split, not of fraud. account_age_hours
#                     is the relative version, and that one IS a feature.
LEAKY_OR_ID = {
    "status", "fraud_type", "segment", "customer_id", "device_fp", "ip_hash",
    "ts_epoch", "timestamp", "transaction_id", "fraud_label", "split",
    "account_created_at",
}

# Heavy right skew: rupee amounts, ages in hours, and inter-arrival gaps all span
# several orders of magnitude. Trees do not need this for splits, but it keeps
# SHAP contributions readable and stabilises the isotonic calibrator.
LOG1P_COLS = [
    "amount", "customer_avg_amount", "account_age_hours",
    "seconds_since_last_txn", "device_txn_count", "ip_txn_count",
    "txn_count_1h", "prev_txn_count",
]


def build_matrix(df: pd.DataFrame) -> tuple[pd.DataFrame, list[str]]:
    """Turn the raw CSV into a numeric matrix.

    Returns (X, feature_names). Deterministic column order, so a model trained on
    one call scores correctly on another.
    """
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


def load(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    df.sort_values("ts_epoch", inplace=True)
    df.reset_index(drop=True, inplace=True)
    return df


def split_frames(df: pd.DataFrame):
    return (
        df[df.split == "train"].copy(),
        df[df.split == "validation"].copy(),
        df[df.split == "test"].copy(),
    )
