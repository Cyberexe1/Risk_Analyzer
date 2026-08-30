"""
Offline/online SCORE parity.

test_parity.py proves the 22 features agree. That is necessary but not sufficient:
the final risk score also depends on the rule layer and the entity-graph network
layer, and those are implemented twice -- batch in ml/scoring.py, incremental in
backend.py. If they disagree, the metrics in ml/artifacts/metrics.json were produced by a
scorer that is not the one serving traffic.

This replays the dataset through the online path and compares the ML score, rule
score, network score and final aggregate against the batch computation.

    python tests/test_score_parity.py --limit 20000

The network layer is expected to match exactly here because both implementations
walk the same adjacency in the same time order. It will NOT match once DynamoDB
bucketed velocity windows replace exact deques -- that divergence needs its own
measurement, and is called out in the DynamoDB mapping note in backend.py.
"""

from __future__ import annotations

import argparse
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "ml"))

import scoring  # noqa: E402  (ml/scoring.py, the batch implementation)

from backend import InMemoryStore, Scorer, build_matrix  # noqa: E402

TOL_ML = 0.05        # score points, out of 100
TOL_RULE = 1e-9
TOL_NET = 0.05
TOL_FINAL = 0.05


def run(data: Path, limit: int | None) -> int:
    df = pd.read_csv(data)
    df.sort_values("ts_epoch", inplace=True)
    df.reset_index(drop=True, inplace=True)
    if limit:
        df = df.head(limit).copy()

    print(f"batch pass over {len(df):,} rows")
    m1h = scoring.methods_per_hour(df)
    rule_batch, _ = scoring.rule_scores(df, m1h)
    net_batch = scoring.network_scores(df)

    scorer = Scorer()
    if scorer.booster is None:
        print("no model artifact found -- run python ml/train.py first")
        return 1

    # Batch ML scores, one DMatrix for the whole file (fast path).
    import xgboost as xgb

    X, names = build_matrix(df)
    dm = xgb.DMatrix(X.to_numpy(), feature_names=names)
    bi = scorer.best_iteration
    raw_p = scorer.booster.predict(dm, iteration_range=(0, bi + 1)) if bi is not None \
        else scorer.booster.predict(dm)
    ml_batch = np.clip(scorer.calibrate(raw_p) * 100.0, 0, 100)
    final_batch = np.clip(
        scoring.W_ML * ml_batch + scoring.W_RULES * rule_batch
        + scoring.W_NETWORK * net_batch,
        0, 100,
    )
    final_batch, _kind = scoring.apply_overrides(final_batch, rule_batch, net_batch, df)

    print("online replay, one transaction at a time")
    store = InMemoryStore()
    for r in df.groupby("customer_id", sort=False).head(1).itertuples():
        store.register_customer(r.customer_id, float(r.account_created_at))

    bad = defaultdict(int)
    worst = {}

    for i, r in enumerate(df.itertuples()):
        txn = {
            "customer_id": r.customer_id,
            "ts": float(r.ts_epoch),
            "amount": float(r.amount),
            "payment_method": r.payment_method,
            "device_fp": r.device_fp,
            "ip_hash": r.ip_hash,
        }
        d, _raw = scorer.score(store, txn)

        for nm, got, exp, tol in (
            ("ml", d.sub_scores["ml"], ml_batch[i], TOL_ML),
            ("rules", d.sub_scores["rules"], rule_batch[i], TOL_RULE),
            ("network", d.sub_scores["network"], net_batch[i], TOL_NET),
            ("final", d.risk_score, final_batch[i], TOL_FINAL),
        ):
            diff = abs(float(got) - float(exp))
            if diff > tol:
                bad[nm] += 1
                if nm not in worst or diff > worst[nm][3]:
                    worst[nm] = (r.transaction_id, float(exp), float(got), diff)

        dt = datetime.fromtimestamp(float(r.ts_epoch), tz=timezone.utc)
        store.commit({
            "customer_id": r.customer_id, "ts": float(r.ts_epoch),
            "amount": float(r.amount), "payment_method": r.payment_method,
            "device_fp": r.device_fp, "ip_hash": r.ip_hash, "status": r.status,
            "hour": dt.hour + dt.minute / 60.0,
        })

    n = len(df)
    print(f"\ncompared {n:,} rows x 4 scores")
    if not bad:
        print("SCORE PARITY OK -- online scorer reproduces the batch pipeline")
        return 0

    print("\nMISMATCHES")
    for k in sorted(bad, key=lambda k: -bad[k]):
        w = worst[k]
        print(f"  {k:<10} {bad[k]:>7,} rows ({bad[k] / n:.2%})   "
              f"worst {w[0]}: batch={w[1]:.3f} online={w[2]:.3f} diff={w[3]:.3f}")
    return 1


def test_score_parity() -> None:
    assert run(Path("ml/data/transactions.csv"), 20000) == 0


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--data", type=Path, default=Path("ml/data/transactions.csv"))
    p.add_argument("--limit", type=int, default=20000)
    a = p.parse_args()
    raise SystemExit(run(a.data, a.limit))


if __name__ == "__main__":
    main()
