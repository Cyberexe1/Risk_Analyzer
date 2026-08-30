"""
Offline/online feature parity.

The central claim behind ml/artifacts/metrics.json is that features were built the way a
production scorer would build them. Until now that was an assertion. This test
replays the generated dataset one transaction at a time through the store and
online feature builder in backend.py -- which have no access to a sorted file,
only to counters left behind by earlier traffic -- and compares every feature
against the offline CSV.

If they diverge, the metrics describe a model that cannot ship.

    python tests/test_parity.py
    python tests/test_parity.py --limit 20000     # faster

Integer and categorical features must match EXACTLY. Floats get a small tolerance
only where the CSV's own rounding makes exactness impossible (account_age_hours is
stored to 3dp, and created_at has to be reconstructed from it).
"""

from __future__ import annotations

import argparse
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend import InMemoryStore, build_online_features as build  # noqa: E402

EXACT_INT = [
    "transaction_hour", "is_weekend",
    "txn_count_10m", "txn_count_1h", "failed_count_10m", "failed_count_1h",
    "prev_txn_count",
    "device_account_count", "device_txn_count", "ip_account_count", "ip_txn_count",
    "is_new_device", "is_new_payment_method",
]
EXACT_STR = ["payment_method"]

# Tolerances. amount/ratio/rates are deterministic given identical inputs, so they
# are held to floating-point noise. account_age_hours is looser because we have to
# reconstruct created_at from a value the CSV already rounded to 3dp.
TOL = {
    "amount": 1e-6,
    "customer_avg_amount": 1e-2,
    "amount_ratio": 1e-3,
    "historical_failure_rate": 1e-6,
    "device_failure_rate": 1e-6,
    "seconds_since_last_txn": 0.2,
    "hour_deviation": 1e-3,
    # The CSV rounds this to 3dp and the online path computes it at full
    # precision, so 1e-3 is the rounding floor, not a fudge factor. It used to be
    # 0.02 because created_at had to be reconstructed from this very column; the
    # generator now emits account_created_at, so the test is strict.
    "account_age_hours": 1e-3,
}

ALL_FEATURES = EXACT_INT + EXACT_STR + list(TOL)


def run(data: Path, limit: int | None = None) -> int:
    df = pd.read_csv(data)
    df.sort_values("ts_epoch", inplace=True)
    df.reset_index(drop=True, inplace=True)
    if limit:
        df = df.head(limit).copy()

    print(f"replaying {len(df):,} transactions through the online store")

    store = InMemoryStore()

    # Seed signup times from the generator's own account_created_at column. In
    # production this is the signup write, so the online scorer genuinely knows it
    # rather than inferring it from the first transaction it happens to see.
    for r in df.groupby("customer_id", sort=False).head(1).itertuples():
        store.register_customer(r.customer_id, float(r.account_created_at))

    mismatches: dict[str, int] = defaultdict(int)
    worst: dict[str, tuple] = {}
    checked = 0

    for r in df.itertuples():
        txn = {
            "customer_id": r.customer_id,
            "ts": float(r.ts_epoch),
            "amount": float(r.amount),
            "payment_method": r.payment_method,
            "device_fp": r.device_fp,
            "ip_hash": r.ip_hash,
        }
        got = build(store, txn)

        for f in EXACT_STR:
            if got[f] != getattr(r, f):
                mismatches[f] += 1
        for f in EXACT_INT:
            if int(got[f]) != int(getattr(r, f)):
                mismatches[f] += 1
                if f not in worst:
                    worst[f] = (r.transaction_id, getattr(r, f), got[f])
        for f, tol in TOL.items():
            exp = float(getattr(r, f))
            act = float(got[f])
            d = abs(exp - act)
            if d > tol:
                mismatches[f] += 1
                if f not in worst or d > worst[f][3]:
                    worst[f] = (r.transaction_id, exp, act, d)

        checked += 1

        # Commit AFTER reading, mirroring the offline forward pass exactly.
        # hour must include minutes: the offline pass uses dt.hour + dt.minute/60,
        # and the circular running mean is sensitive to that.
        dt = datetime.fromtimestamp(float(r.ts_epoch), tz=timezone.utc)
        store.commit(
            {
                "customer_id": r.customer_id,
                "ts": float(r.ts_epoch),
                "amount": float(r.amount),
                "payment_method": r.payment_method,
                "device_fp": r.device_fp,
                "ip_hash": r.ip_hash,
                "status": r.status,
                "hour": dt.hour + dt.minute / 60.0,
            }
        )

    print(f"checked {checked:,} rows x {len(ALL_FEATURES)} features "
          f"= {checked * len(ALL_FEATURES):,} comparisons")

    if not mismatches:
        print("\nPARITY OK -- online path reproduces every offline feature")
        return 0

    print("\nMISMATCHES")
    for f in sorted(mismatches, key=lambda k: -mismatches[k]):
        n = mismatches[f]
        print(f"  {f:<26} {n:>7,} rows  ({n / checked:.2%})")
        if f in worst:
            w = worst[f]
            if len(w) == 4:
                print(f"      worst: {w[0]}  offline={w[1]}  online={w[2]}  diff={w[3]:.4g}")
            else:
                print(f"      first: {w[0]}  offline={w[1]}  online={w[2]}")
    return 1


def test_parity() -> None:
    """pytest entry point."""
    assert run(Path("ml/data/transactions.csv"), limit=20000) == 0


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--data", type=Path, default=Path("ml/data/transactions.csv"))
    p.add_argument("--limit", type=int, default=None)
    a = p.parse_args()
    raise SystemExit(run(a.data, a.limit))


if __name__ == "__main__":
    main()
