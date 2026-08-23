"""
Measure the promotion-abuse gate on its held-out split.

    python ml/evaluate_promo.py

Scored by backend.score_promo -- the same function POST /v1/promo/redeem calls, so
these numbers describe the code that actually serves traffic rather than a
parallel evaluation-only implementation.

Reported separately from the transaction scorer on purpose. Different population,
different base rate (~8% vs ~2%), different unit cost. Folding them into one
confusion matrix would be meaningless.

Writes ml/artifacts/promo_metrics.json.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend import (  # noqa: E402
    PROMO_FEATURES, PROMO_RULES, PromoThresholds, score_promo,
)
from cost_model import COSTS  # noqa: E402

ARTIFACTS = Path("ml/artifacts")


def gate_cost(frame: pd.DataFrame, t: PromoThresholds) -> tuple[float, dict]:
    """Expected rupee cost of one threshold set.

    Asymmetry that drives everything here: letting abuse through costs the offer
    value (Rs 500), but wrongly DENYING a real customer costs the offer plus
    goodwill (Rs 760). A hold is nearly free (Rs 35). So a gate that denies
    aggressively can easily cost more than the abuse it prevents -- which is
    exactly what the first hand-picked thresholds did.
    """
    y = frame.abuse_label.to_numpy()
    decisions = [score_promo(r, t).decision
                 for r in frame[PROMO_FEATURES].to_dict("records")]
    dec = pd.Series(decisions, index=frame.index)

    denied = (dec == "DENY").to_numpy()
    held = (dec == "HOLD").to_numpy()
    allowed = (dec == "ALLOW").to_numpy()

    stats = {
        "deny_tp": int((denied & (y == 1)).sum()),
        "deny_fp": int((denied & (y == 0)).sum()),
        "hold_tp": int((held & (y == 1)).sum()),
        "hold_fp": int((held & (y == 0)).sum()),
        "missed": int((allowed & (y == 1)).sum()),
        "clean_allow": int((allowed & (y == 0)).sum()),
    }
    cost = (
        stats["missed"] * COSTS.promo_value
        + stats["deny_fp"] * COSTS.promo_wrong_deny_cost
        + (stats["hold_tp"] + stats["hold_fp"]) * COSTS.promo_review_cost
        # A held abusive claim is caught, but if we hold it and then approve it on
        # review the offer is still paid. Holds that turn out abusive are counted
        # as reviewed-and-refused, so no offer cost.
    )
    return cost, stats


def tune(va: pd.DataFrame) -> tuple[PromoThresholds, list[dict]]:
    """Grid search on VALIDATION only. Test is scored once with the winner."""
    grid = []
    for dev_deny in (1, 2, 3):
        for dev_acc in (3, 4, 5, 6):
            for ip_claims in (2, 3, 5):
                for comp in (3, 4, 5):
                    for sim in (0.6, 0.7, 0.8):
                        t = PromoThresholds(
                            device_reuse_deny=dev_deny,
                            device_accounts_hold=dev_acc,
                            ip_claims_hold=ip_claims,
                            component_hold=comp,
                            email_similarity_hold=sim,
                        )
                        cost, st = gate_cost(va, t)
                        grid.append({"t": t, "cost": cost, **st})
    grid.sort(key=lambda r: r["cost"])
    return grid[0]["t"], grid


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--data", type=Path,
                   default=Path("ml/data/promo_redemptions.csv"))
    p.add_argument("--artifacts", type=Path, default=ARTIFACTS)
    p.add_argument("--tune", action="store_true",
                   help="grid-search thresholds on validation before scoring test")
    a = p.parse_args()

    df = pd.read_csv(a.data)
    print(f"loaded {len(df):,} redemptions from {a.data}")
    print(f"  abuse rate overall {df.abuse_label.mean():.2%}")

    va = df[df.split == "validation"].copy()
    te = df[df.split == "test"].copy()
    print(f"  validation {len(va):,} rows, {int(va.abuse_label.sum())} abusive "
          f"({va.abuse_label.mean():.2%})")
    print(f"  test       {len(te):,} rows, {int(te.abuse_label.sum())} abusive "
          f"({te.abuse_label.mean():.2%})")

    thresholds = PromoThresholds()
    grid_rows: list[dict] = []
    if a.tune:
        print("\ntuning thresholds on validation by expected cost")
        base_cost, _ = gate_cost(va, thresholds)
        thresholds, grid = tune(va)
        grid_rows = [
            {"thresholds": vars(r["t"]), "cost": round(r["cost"], 2),
             "deny_fp": r["deny_fp"], "missed": r["missed"]}
            for r in grid[:8]
        ]
        print(f"  current defaults    Rs {base_cost:>9,.0f}")
        for r in grid[:5]:
            t = r["t"]
            print(f"  dev_deny>={t.device_reuse_deny} dev_acct>={t.device_accounts_hold} "
                  f"ip>={t.ip_claims_hold} comp>={t.component_hold} "
                  f"sim>={t.email_similarity_hold}  "
                  f"Rs {r['cost']:>9,.0f}  denied_legit={r['deny_fp']} "
                  f"missed={r['missed']}")
        print(f"\n  chosen: {vars(thresholds)}")
        print("  frozen for the test split")

    decisions, fired_sets, exempts = [], [], []
    for row in te[PROMO_FEATURES].to_dict("records"):
        d = score_promo(row, thresholds)
        decisions.append(d.decision)
        fired_sets.append(set(d.fired))
        exempts.append(d.shared_ip_exempt)

    te["decision"] = decisions
    te["exempt"] = exempts
    y = te.abuse_label.to_numpy()
    flagged = te.decision.isin(["HOLD", "DENY"]).to_numpy()
    denied = (te.decision == "DENY").to_numpy()

    tp = int((flagged & (y == 1)).sum())
    fp = int((flagged & (y == 0)).sum())
    fn = int((~flagged & (y == 1)).sum())
    tn = int((~flagged & (y == 0)).sum())

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    fp_rate = fp / (fp + tn) if fp + tn else 0.0

    print("\nconfusion at the redemption gate (HOLD or DENY counts as flagged)")
    print("                   DENY/HOLD    ALLOW")
    print(f"  abuse         {tp:>10}{fn:>9}     recall     {recall:.4f}")
    print(f"  legitimate    {fp:>10}{tn:>9}     FP rate    {fp_rate:.4f}")
    print(f"                                        precision  {precision:.4f}")

    # Split by action: a DENY is the consequential one, a HOLD costs a review.
    d_tp = int((denied & (y == 1)).sum())
    d_fp = int((denied & (y == 0)).sum())
    held = flagged & ~denied
    h_tp = int((held & (y == 1)).sum())
    h_fp = int((held & (y == 0)).sum())
    print(f"\n  DENY  {d_tp + d_fp:>4} rows   precision "
          f"{d_tp / (d_tp + d_fp) if d_tp + d_fp else 0:.4f}   "
          f"({d_fp} legitimate customers refused)")
    print(f"  HOLD  {h_tp + h_fp:>4} rows   precision "
          f"{h_tp / (h_tp + h_fp) if h_tp + h_fp else 0:.4f}")

    # Per-rule precision: which signals are actually trustworthy.
    print("\nper-signal contribution")
    per_rule = {}
    for rule in PROMO_RULES:  # noqa: PLC0206
        mask = pd.Series([rule in s for s in fired_sets], index=te.index).to_numpy()
        n = int(mask.sum())
        if n == 0:
            per_rule[rule] = {"detections": 0, "precision": None}
            print(f"  {rule:<24} never fired")
            continue
        prec = float((y[mask] == 1).mean())
        per_rule[rule] = {"detections": n, "precision": round(prec, 4),
                          "action": PROMO_RULES[rule][0]}
        print(f"  {rule:<24} {n:>4} fired   precision {prec:.3f}   "
              f"({PROMO_RULES[rule][0]})")

    n_exempt = int(te.exempt.sum())
    print(f"\n  shared-IP exemption applied to {n_exempt} rows "
          f"({n_exempt / len(te):.1%})")

    # ---- cost ----
    without = int(y.sum()) * COSTS.promo_value
    with_gate = (
        fn * COSTS.promo_value                      # abuse we let through
        + d_fp * COSTS.promo_wrong_deny_cost        # real customers refused
        + (h_tp + h_fp) * COSTS.promo_review_cost   # every hold costs a review
    )
    fp_cost = d_fp * COSTS.promo_wrong_deny_cost + h_fp * COSTS.promo_review_cost

    print(f"\ncost, test split ({len(te):,} redemptions, Rs "
          f"{COSTS.promo_value:.0f} offer)")
    print(f"  no gate                    Rs {without:>10,.0f}")
    print(f"  with gate                  Rs {with_gate:>10,.0f}")
    print(f"  net saving                 Rs {without - with_gate:>10,.0f}"
          f"   ({(without - with_gate) / without:.1%})" if without else "")
    print(f"  false-positive cost        Rs {fp_cost:>10,.0f}"
          f"   ({fp_cost / with_gate:.1%} of remaining)" if with_gate else "")
    print(f"    {d_fp} wrongly denied           Rs "
          f"{d_fp * COSTS.promo_wrong_deny_cost:>10,.0f}")
    print(f"    {h_fp} legitimate held          Rs "
          f"{h_fp * COSTS.promo_review_cost:>10,.0f}")

    out = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "data_file": str(a.data),
        "scored_by": "backend.score_promo (same code path as POST /v1/promo/redeem)",
        "thresholds": vars(thresholds),
        "tuned_on_validation": a.tune,
        "validation_grid_top8": grid_rows,
        "rows": {"total": len(df), "validation": len(va), "test": len(te)},
        "abuse_rate": {"overall": round(float(df.abuse_label.mean()), 5),
                       "validation": round(float(va.abuse_label.mean()), 5),
                       "test": round(float(te.abuse_label.mean()), 5)},
        "gate": {"precision": round(precision, 4), "recall": round(recall, 4),
                 "fp_rate": round(fp_rate, 5), "tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "deny": {"n": d_tp + d_fp, "tp": d_tp, "fp": d_fp,
                 "precision": round(d_tp / (d_tp + d_fp), 4) if d_tp + d_fp else None},
        "hold": {"n": h_tp + h_fp, "tp": h_tp, "fp": h_fp,
                 "precision": round(h_tp / (h_tp + h_fp), 4) if h_tp + h_fp else None},
        "per_rule": per_rule,
        "shared_ip_exempt_rows": n_exempt,
        "cost": {
            "offer_value": COSTS.promo_value,
            "wrong_deny_cost": COSTS.promo_wrong_deny_cost,
            "review_cost": COSTS.promo_review_cost,
            "no_gate": round(without, 2),
            "with_gate": round(with_gate, 2),
            "net_saving": round(without - with_gate, 2),
            "false_positive_cost": round(fp_cost, 2),
        },
        "caveats": [
            "Rules-only gate tuned on the same generator that produced the abuse "
            "patterns. This is the least transferable measurement in the project.",
            "Real abusers rotate payout destinations and use cloud devices; the "
            "generator does neither, so payout-reuse precision is optimistic.",
            "A denied cashback is not a denied sale, which is the only reason "
            "these thresholds are defensible.",
        ],
    }
    a.artifacts.mkdir(parents=True, exist_ok=True)
    (a.artifacts / "promo_metrics.json").write_text(json.dumps(out, indent=2))
    print(f"\nwrote {a.artifacts / 'promo_metrics.json'}")


if __name__ == "__main__":
    main()
