"""
Train the FraudShield XGBoost model and calibrate it.

    python ml/train.py
    python ml/train.py --data ml/data/transactions_dev.csv

Writes to ml/artifacts/:
    model.json          XGBoost booster
    calibrator.json     isotonic calibration knots
    feature_spec.json   exact column order + training config
    train_report.json   fit diagnostics and learned feature importance
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.isotonic import IsotonicRegression
from sklearn.metrics import average_precision_score, brier_score_loss, roc_auc_score
from xgboost import XGBClassifier

from features import RAW_FEATURES, assert_no_leakage, build_matrix, load, split_frames

ARTIFACTS = Path("ml/artifacts")

PARAMS = dict(
    n_estimators=400,
    max_depth=5,              # shallow: generalises better on a ~2% positive class
    learning_rate=0.05,
    subsample=0.8,
    colsample_bytree=0.8,
    min_child_weight=5,
    reg_lambda=1.5,
    eval_metric="aucpr",      # NOT accuracy: at 2% positives, "never fraud" = 98%
    early_stopping_rounds=40,
    tree_method="hist",
    n_jobs=-1,
    random_state=20260822,
)


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--data", type=Path, default=Path("ml/data/transactions.csv"))
    p.add_argument("--out", type=Path, default=ARTIFACTS)
    a = p.parse_args()

    print("loading", a.data)
    df = load(str(a.data))
    tr, va, te = split_frames(df)
    print(f"  train {len(tr):,}  validation {len(va):,}  test {len(te):,}")
    print(f"  fraud rate  train {tr.fraud_label.mean():.4f}  "
          f"val {va.fraud_label.mean():.4f}  test {te.fraud_label.mean():.4f}")

    Xtr, names = build_matrix(tr)
    Xva, _ = build_matrix(va)
    assert_no_leakage(names)
    ytr = tr.fraud_label.to_numpy()
    yva = va.fraud_label.to_numpy()

    pos, neg = int(ytr.sum()), int(len(ytr) - ytr.sum())
    spw = neg / max(1, pos)
    print(f"\n  {len(names)} features, scale_pos_weight = {spw:.1f}")
    print("  (reweighting the loss rather than SMOTE: synthetic oversampling on top"
          "\n   of an already synthetic dataset compounds generator artefacts)")

    model = XGBClassifier(**PARAMS, scale_pos_weight=spw)
    model.fit(Xtr, ytr, eval_set=[(Xva, yva)], verbose=False)

    best_it = getattr(model, "best_iteration", None)
    print(f"\n  early stopping at iteration {best_it} of {PARAMS['n_estimators']}")

    raw_va = model.predict_proba(Xva)[:, 1]

    # Raw XGBoost outputs are not probabilities. The cost model multiplies
    # probability by rupees, so uncalibrated scores make that arithmetic
    # meaningless. Isotonic is fit on validation only.
    cal = IsotonicRegression(out_of_bounds="clip", y_min=0.0, y_max=1.0)
    cal.fit(raw_va, yva)
    cal_va = cal.predict(raw_va)

    print("\n  validation")
    print(f"    PR-AUC              {average_precision_score(yva, raw_va):.4f}")
    print(f"    ROC-AUC             {roc_auc_score(yva, raw_va):.4f}")
    print(f"    Brier raw           {brier_score_loss(yva, raw_va):.5f}")
    print(f"    Brier calibrated    {brier_score_loss(yva, cal_va):.5f}")

    # Learned importance, to compare against the MVP's hand-picked ranking.
    gain = model.get_booster().get_score(importance_type="gain")
    imp = sorted(gain.items(), key=lambda kv: -kv[1])
    print("\n  top features by gain (vs. the MVP's guesses)")
    for k, v in imp[:12]:
        print(f"    {k:<26} {v:>10.1f}")

    a.out.mkdir(parents=True, exist_ok=True)
    model.get_booster().save_model(str(a.out / "model.json"))

    (a.out / "calibrator.json").write_text(json.dumps({
        "x": [float(v) for v in cal.X_thresholds_],
        "y": [float(v) for v in cal.y_thresholds_],
    }))

    (a.out / "feature_spec.json").write_text(json.dumps({
        "feature_names": names,
        "raw_features": RAW_FEATURES,
        "params": {k: v for k, v in PARAMS.items()},
        "scale_pos_weight": spw,
        "best_iteration": int(best_it) if best_it is not None else None,
        "data_file": str(a.data),
        "trained_at": datetime.now(timezone.utc).isoformat(),
    }, indent=2))

    (a.out / "train_report.json").write_text(json.dumps({
        "rows": {"train": len(tr), "validation": len(va), "test": len(te)},
        "fraud_rate": {
            "train": round(float(tr.fraud_label.mean()), 5),
            "validation": round(float(va.fraud_label.mean()), 5),
            "test": round(float(te.fraud_label.mean()), 5),
        },
        "validation_metrics": {
            "pr_auc": round(float(average_precision_score(yva, raw_va)), 4),
            "roc_auc": round(float(roc_auc_score(yva, raw_va)), 4),
            "brier_raw": round(float(brier_score_loss(yva, raw_va)), 5),
            "brier_calibrated": round(float(brier_score_loss(yva, cal_va)), 5),
        },
        "importance_gain": {k: round(float(v), 2) for k, v in imp},
    }, indent=2))

    print(f"\n  wrote {a.out}/model.json, calibrator.json, feature_spec.json")
    print("  next: python ml/evaluate.py")


if __name__ == "__main__":
    main()
