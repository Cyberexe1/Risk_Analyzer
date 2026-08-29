"""
Evaluate FraudShield on the held-out test split and cost every error in rupees.

    python ml/evaluate.py

Writes ml/artifacts/metrics.json. Thresholds and aggregation weights are chosen on
VALIDATION; the test split is scored once, at the end, with those choices frozen.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.metrics import average_precision_score, brier_score_loss, roc_auc_score

import scoring
from cost_model import COSTS, do_nothing_cost, sensitivity, transaction_cost

# build_matrix comes from the serving module so training, evaluation and serving
# all use one implementation. See the note in ml/train.py.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from backend import build_matrix  # noqa: E402

ARTIFACTS = Path("ml/artifacts")


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


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def load_calibrator(path: Path):
    d = json.loads(path.read_text())
    x, y = np.array(d["x"], dtype=float), np.array(d["y"], dtype=float)
    return lambda p: np.interp(p, x, y, left=y[0], right=y[-1])


def confusion(score, y, review_t, block_t):
    block = score >= block_t
    review = (score >= review_t) & ~block
    allow = ~block & ~review
    return dict(
        tp_block=int((block & (y == 1)).sum()),
        fp_block=int((block & (y == 0)).sum()),
        tp_review=int((review & (y == 1)).sum()),
        fp_review=int((review & (y == 0)).sum()),
        fn=int((allow & (y == 1)).sum()),
        tn=int((allow & (y == 0)).sum()),
    )


def f1_of(precision: float, recall: float) -> float:
    """Harmonic mean of precision and recall.

    Added because the evaluation reported precision and recall but not F1, so a
    reader had to compute it themselves -- and the two gates trade off in opposite
    directions, which is exactly the case where a single balanced number is worth
    having.

    Stated plainly so nobody has to guess the definition:

        F1 = 2PR / (P + R)

    Zero when both are zero, which is the degenerate case rather than an error.

    F1 is reported ALONGSIDE precision and recall, never instead of them. It
    weights a missed fraud and a wrongly blocked customer equally, and this
    system's own cost model says they differ by about 41x -- so F1 is the wrong
    number to optimise here and is published for comparability, not for tuning.
    """
    return round(2 * precision * recall / (precision + recall), 4) \
        if (precision + recall) else 0.0


def gate_metrics(score, y, t):
    flagged = score >= t
    tp = int((flagged & (y == 1)).sum())
    fp = int((flagged & (y == 0)).sum())
    fn = int((~flagged & (y == 1)).sum())
    tn = int((~flagged & (y == 0)).sum())
    precision = round(tp / (tp + fp), 4) if tp + fp else 0.0
    recall = round(tp / (tp + fn), 4) if tp + fn else 0.0
    return {
        "threshold": float(t),
        "precision": precision,
        "recall": recall,
        "f1": f1_of(precision, recall),
        "fp_rate": round(fp / (fp + tn), 5) if fp + tn else 0.0,
        "volume_share": round(float(flagged.mean()), 5),
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
    }


def cost_of(score, y, review_t, block_t):
    c = confusion(score, y, review_t, block_t)
    return transaction_cost(
        c["tp_block"], c["tp_review"], c["fp_block"], c["fp_review"], c["fn"]
    ), c


# ---------------------------------------------------------------------------


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--data", type=Path, default=Path("ml/data/transactions.csv"))
    p.add_argument("--artifacts", type=Path, default=ARTIFACTS)
    p.add_argument(
        "--max-review-rate",
        type=float,
        default=0.04,
        help="analyst capacity ceiling as a share of traffic. Without this the cost "
             "optimiser sends nearly everything to review, because Rs 35 per review "
             "is so much cheaper than Rs 3,550 per missed fraud that an unbounded "
             "queue always wins on paper. Real queues are not unbounded.",
    )
    a = p.parse_args()

    print("loading data and model")
    df = load(str(a.data))

    # Rule and network layers need a full chronological pass over ALL rows: the
    # graph a test-week transaction sits in was built by earlier traffic. Computed
    # forward-only, so no test row sees a later edge.
    print("computing rule + network layers (chronological forward pass)")
    m1h = scoring.methods_per_hour(df)
    rule_all, fired_all = scoring.rule_scores(df, m1h)
    net_all = scoring.network_scores(df)
    df["_rule"] = rule_all
    df["_net"] = net_all

    booster = xgb.Booster()
    booster.load_model(str(a.artifacts / "model.json"))
    calibrate = load_calibrator(a.artifacts / "calibrator.json")
    spec = json.loads((a.artifacts / "feature_spec.json").read_text())
    best_it = spec.get("best_iteration")

    X, names = build_matrix(df)
    if names != spec["feature_names"]:
        raise SystemExit("feature order differs from training; retrain before evaluating")

    dm = xgb.DMatrix(X.to_numpy(), feature_names=names)
    rng_lim = (0, best_it + 1) if best_it is not None else None
    raw = booster.predict(dm, iteration_range=rng_lim) if rng_lim else booster.predict(dm)
    df["_ml"] = np.clip(calibrate(raw) * 100.0, 0, 100)
    df["_ml_raw"] = raw

    tr, va, te = split_frames(df)
    print(f"  train {len(tr):,}  validation {len(va):,}  test {len(te):,}")

    # ---------------- aggregation weight search (validation) ----------------
    print("\nsearching aggregation weights on validation")
    yva = va.fraud_label.to_numpy()
    weight_grid = [
        (1.00, 0.00, 0.00), (0.80, 0.15, 0.05), (0.70, 0.20, 0.10),
        (0.60, 0.25, 0.15), (0.50, 0.30, 0.20),
    ]
    def best_point(s, y, cap):
        """Lowest-cost (review, block) pair whose review band fits analyst capacity."""
        opts = []
        for rt in range(5, 80, 5):
            for bt in range(40, 101, 5):
                if bt <= rt:
                    continue
                vol = float(((s >= rt) & (s < bt)).mean())
                if vol > cap:
                    continue
                cost, conf = cost_of(s, y, rt, bt)
                opts.append((cost, rt, bt, vol, conf))
        if not opts:  # capacity impossible to satisfy; fall back to unconstrained
            for rt in range(5, 80, 5):
                for bt in range(40, 101, 5):
                    if bt > rt:
                        cost, conf = cost_of(s, y, rt, bt)
                        opts.append(
                            (cost, rt, bt,
                             float(((s >= rt) & (s < bt)).mean()), conf)
                        )
        return min(opts, key=lambda o: o[0])

    weight_rows = []
    for wm, wr, wn in weight_grid:
        s = np.clip(wm * va._ml + wr * va._rule + wn * va._net, 0, 100).to_numpy()
        cost, rt, bt, vol, _ = best_point(s, yva, a.max_review_rate)
        weight_rows.append({
            "weights": [wm, wr, wn],
            "pr_auc": round(float(average_precision_score(yva, s)), 4),
            "best_cost": round(cost, 2),
            "at": [rt, bt],
        })
        print(f"  {wm:.2f}/{wr:.2f}/{wn:.2f}  PR-AUC {weight_rows[-1]['pr_auc']:.4f}"
              f"  cost Rs {cost:,.0f}  at review>={rt} block>={bt}")

    W = (scoring.W_ML, scoring.W_RULES, scoring.W_NETWORK)
    best_w = min(weight_rows, key=lambda r: r["best_cost"])
    print(f"  lowest cost at weights {best_w['weights']}")
    print(f"  proceeding with the documented {W[0]}/{W[1]}/{W[2]} -- see the note in")
    print("  docs/EVALUATION.md if these disagree; the measurement wins, not the doc.")

    def final_score(frame):
        s = scoring.aggregate(
            frame._ml.to_numpy(), frame._rule.to_numpy(), frame._net.to_numpy()
        )
        s, kind = scoring.apply_overrides(
            s, frame._rule.to_numpy(), frame._net.to_numpy(), frame
        )
        return s, kind

    s_va, _ = final_score(va)

    # ---------------- threshold selection (validation only) ----------------
    print("\nselecting thresholds on validation by expected cost")
    print(f"  analyst capacity ceiling: review band <= {a.max_review_rate:.1%} of traffic")
    sweep = []
    for rt in range(5, 80, 5):
        for bt in range(40, 101, 5):
            if bt <= rt:
                continue
            cost, c = cost_of(s_va, yva, rt, bt)
            vol = float(((s_va >= rt) & (s_va < bt)).mean())
            sweep.append({
                "review": rt, "block": bt, "cost": round(cost, 2),
                "review_volume": round(vol, 5),
                "legit_blocked": c["fp_block"],
                "within_capacity": vol <= a.max_review_rate,
            })
    sweep.sort(key=lambda r: r["cost"])
    feasible = [r for r in sweep if r["within_capacity"]] or sweep
    REVIEW_T, BLOCK_T = feasible[0]["review"], feasible[0]["block"]

    unconstrained = sweep[0]
    if not unconstrained["within_capacity"]:
        print(f"  unconstrained optimum would be review>={unconstrained['review']} "
              f"block>={unconstrained['block']} at {unconstrained['review_volume']:.1%} "
              f"review volume -- rejected, exceeds capacity")
    for r in feasible[:6]:
        print(f"  review>={r['review']:>2} block>={r['block']:>3}  "
              f"cost Rs {r['cost']:>10,.0f}  review vol {r['review_volume']:.2%}  "
              f"legit blocked {r['legit_blocked']}")
    print(f"  chosen: review >= {REVIEW_T}, block >= {BLOCK_T}  (frozen for test)")

    # Score distribution: isotonic calibration on a 2% base rate pushes most rows
    # to near-zero, so the 0-100 scale is heavily bimodal rather than spread. Worth
    # knowing before reading any threshold as if the scale were uniform.
    dist = {
        f"{lo}-{hi}": int(((s_va >= lo) & (s_va < hi)).sum())
        for lo, hi in [(0, 10), (10, 20), (20, 40), (40, 60), (60, 80), (80, 101)]
    }
    print(f"  validation score distribution: {dist}")

    # ---------------- test set, scored once ----------------
    print("\n" + "=" * 70)
    print("HELD-OUT TEST SET")
    print("=" * 70)
    yte = te.fraud_label.to_numpy()
    s_te, kind_te = final_score(te)

    pr_auc = float(average_precision_score(yte, s_te))
    roc = float(roc_auc_score(yte, s_te))
    brier = float(brier_score_loss(yte, np.clip(te._ml.to_numpy() / 100, 0, 1)))
    print(f"\nranking quality")
    print(f"  PR-AUC                {pr_auc:.4f}")
    print(f"  ROC-AUC               {roc:.4f}   (inflated by the 98% negative class)")
    print(f"  Brier (calibrated ML) {brier:.5f}")
    print(f"  fraud in test         {int(yte.sum()):,} of {len(yte):,} "
          f"({yte.mean():.2%})")

    review_gate = gate_metrics(s_te, yte, REVIEW_T)
    block_gate = gate_metrics(s_te, yte, BLOCK_T)
    print(f"\noperating points")
    for nm, g in (("review", review_gate), ("block", block_gate)):
        print(f"  {nm:<7} >= {g['threshold']:>2.0f}   precision {g['precision']:.3f}"
              f"   recall {g['recall']:.3f}   F1 {g['f1']:.3f}"
              f"   FP rate {g['fp_rate']:.4f}"
              f"   volume {g['volume_share']:.2%}")

    c = confusion(s_te, yte, REVIEW_T, BLOCK_T)
    print(f"\nconfusion at the chosen operating point")
    print(f"                  BLOCK   REVIEW    ALLOW")
    print(f"  fraud       {c['tp_block']:>8}{c['tp_review']:>9}{c['fn']:>9}")
    print(f"  legitimate  {c['fp_block']:>8}{c['fp_review']:>9}{c['tn']:>9}")

    # ---------------- per-archetype recall ----------------
    print(f"\nrecall by fraud archetype (review gate)")
    arche = {}
    flagged = s_te >= REVIEW_T
    for t in sorted(te[te.fraud_label == 1].fraud_type.unique()):
        mask = (te.fraud_type == t).to_numpy()
        r = float(flagged[mask].mean())
        arche[t] = round(r, 4)
        note = "  <- undetectable by design" if t == "first_party_abuse" else ""
        print(f"  {t:<22} {r:.3f}  (n={int(mask.sum())}){note}")

    # ---------------- baselines ----------------
    print(f"\nbaselines (same test split, review gate tuned per model)")
    rs = np.random.default_rng(7)
    cand = {
        "random": rs.random(len(te)) * 100,
        "amount_threshold_10k": np.where(te.amount.to_numpy() > 10000, 90.0, 10.0),
        "mvp_hand_picked_formula": scoring.mvp_formula(te),
        "rules_only": te._rule.to_numpy(),
        "network_only": te._net.to_numpy(),
        "xgboost_only": te._ml.to_numpy(),
        "fraudshield_ensemble": s_te,
    }
    baselines = {}
    for nm, sc in cand.items():
        sc = np.asarray(sc, dtype=float)
        ap = float(average_precision_score(yte, sc))
        # Each baseline gets its own cost-optimal thresholds under the SAME analyst
        # capacity ceiling, so the comparison is like-for-like rather than a
        # favourable gate for one model and an unfavourable one for another.
        cost, rt, bt, vol, conf = best_point(sc, yte, a.max_review_rate)
        g = gate_metrics(sc, yte, rt)
        baselines[nm] = {
            "pr_auc": round(ap, 4), "review_gate": g,
            "thresholds": [rt, bt], "cost": round(cost, 2),
        }
        print(f"  {nm:<26} PR-AUC {ap:.4f}   precision {g['precision']:.3f}"
              f"   recall {g['recall']:.3f}   cost Rs {cost:>10,.0f}")

    # ---------------- cost ----------------
    total_cost, _ = cost_of(s_te, yte, REVIEW_T, BLOCK_T)
    nothing = do_nothing_cost(int(yte.sum()))
    fp_cost = c["fp_block"] * COSTS.block_legit_cost + c["fp_review"] * COSTS.review_cost
    print(f"\ncost model, test split ({len(te):,} transactions)")
    print(f"  do nothing (allow all)        Rs {nothing:>12,.0f}")
    print(f"  with FraudShield              Rs {total_cost:>12,.0f}")
    print(f"  net saving                    Rs {nothing - total_cost:>12,.0f}"
          f"   ({(nothing - total_cost) / nothing:.1%})")
    print(f"  ---- of which paid by legitimate customers ----")
    print(f"  {c['fp_block']} wrongly blocked      Rs "
          f"{c['fp_block'] * COSTS.block_legit_cost:>12,.0f}")
    print(f"  {c['fp_review']} sent to review        Rs "
          f"{c['fp_review'] * COSTS.review_cost:>12,.0f}")
    print(f"  false-positive cost           Rs {fp_cost:>12,.0f}"
          f"   ({fp_cost / total_cost:.1%} of remaining cost)")
    print(f"  ---- and paid on fraud we missed ----")
    print(f"  {c['fn']} allowed through       Rs "
          f"{c['fn'] * COSTS.fraud_loss:>12,.0f}")
    print(f"\n  blocking is {COSTS.block_legit_cost / COSTS.review_cost:.0f}x more "
          f"expensive per error than reviewing -- which is why most risk is routed"
          f"\n  to a human instead of declined outright.")

    # ---------------- fairness slices ----------------
    print(f"\nslice review rates (no protected attribute is a model input)")
    slices = {
        "overall": np.ones(len(te), bool),
        "new_customers_under_7d": te.account_age_hours.to_numpy() < 168,
        "established_over_1y": te.account_age_hours.to_numpy() > 8760,
        "cod_primary": (te.payment_method == "cod").to_numpy(),
        "upi_primary": (te.payment_method == "upi").to_numpy(),
        "high_value_top_decile": te.amount.to_numpy()
        >= np.percentile(te.amount.to_numpy(), 90),
    }
    base = float((s_te >= REVIEW_T).mean())
    fairness = {}
    for nm, m in slices.items():
        if m.sum() == 0:
            continue
        rr = float((s_te[m] >= REVIEW_T).mean())
        br = float((s_te[m] >= BLOCK_T).mean())
        fairness[nm] = {
            "n": int(m.sum()), "review_rate": round(rr, 4),
            "block_rate": round(br, 4), "ratio_vs_overall": round(rr / base, 3),
        }
        print(f"  {nm:<24} n={int(m.sum()):>6}  review {rr:.3%}  "
              f"block {br:.3%}  ratio {rr / base:.2f}")

    # ---------------- one worked explanation ----------------
    contribs = booster.predict(dm, pred_contribs=True)
    te_idx = te.index.to_numpy()
    order = np.argsort(-s_te)
    pick = te_idx[order[0]]
    row = df.loc[pick]
    cvec = contribs[df.index.get_loc(pick)][:-1]
    top = sorted(zip(names, cvec), key=lambda kv: -abs(kv[1]))[:5]
    example = {
        "transaction_id": row.transaction_id,
        "amount": float(row.amount),
        "risk_score": round(float(s_te[order[0]]), 1),
        "sub_scores": {
            "ml": round(float(row._ml), 1),
            "rules": round(float(row._rule), 1),
            "network": round(float(row._net), 1),
        },
        "fired_rules": fired_all[df.index.get_loc(pick)],
        "top_shap": [{"feature": k, "contribution": round(float(v), 4)} for k, v in top],
        "true_label": int(row.fraud_label),
        "fraud_type": row.fraud_type,
    }
    print(f"\nhighest-risk test transaction, explained")
    print(f"  {example['transaction_id']}  Rs {example['amount']:,.0f}  "
          f"risk {example['risk_score']:.0f}/100")
    print(f"  ML {example['sub_scores']['ml']:.0f}  "
          f"rules {example['sub_scores']['rules']:.0f}  "
          f"network {example['sub_scores']['network']:.0f}")
    print(f"  rules fired: {', '.join(example['fired_rules']) or 'none'}")
    for t in example["top_shap"]:
        print(f"    {t['feature']:<26} {t['contribution']:+.3f}")
    print(f"  actual label: {example['true_label']} ({example['fraud_type'] or 'legitimate'})")

    # ---------------- write ----------------
    out = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "data_file": str(a.data),
        "model": {"best_iteration": best_it, "n_features": len(names)},
        "test_rows": len(te),
        "test_fraud": int(yte.sum()),
        "test_fraud_rate": round(float(yte.mean()), 5),
        "ranking": {"pr_auc": round(pr_auc, 4), "roc_auc": round(roc, 4),
                    "brier_calibrated": round(brier, 5)},
        "thresholds": {"review": REVIEW_T, "block": BLOCK_T,
                       "selected_on": "validation", "method": "expected cost minimisation"},
        "review_gate": review_gate,
        "block_gate": block_gate,
        # Classification metrics at the SELECTED operating point, grouped and
        # defined explicitly so nobody has to reverse-engineer what "precision"
        # refers to when a system has two gates.
        #
        # The operating point is NOT chosen to flatter these numbers: it was fixed
        # on the validation split by expected-cost minimisation under an
        # analyst-capacity ceiling, BEFORE the test split was scored. F1 at the
        # cost-optimal point is reported as-is, including the fact that the block
        # gate's F1 is dragged down by recall while its precision is 1.000.
        "classification": {
            "operating_point": {"review": REVIEW_T, "block": BLOCK_T},
            "operating_point_selection": (
                "expected-cost minimisation on the validation split under an "
                "analyst-capacity ceiling; not tuned on test, and not chosen to "
                "improve any metric reported here"
            ),
            # `flagged` = score >= review threshold. This is the detector's own
            # operating point: everything at or above it receives attention, and
            # BLOCK is the subset that is refused outright.
            "flagged_gate": {
                "definition": "score >= review threshold (review OR block)",
                "precision": review_gate["precision"],
                "recall": review_gate["recall"],
                "f1": review_gate["f1"],
                "tp": review_gate["tp"], "fp": review_gate["fp"],
                "fn": review_gate["fn"], "tn": review_gate["tn"],
            },
            "block_gate": {
                "definition": "score >= block threshold (payment refused)",
                "precision": block_gate["precision"],
                "recall": block_gate["recall"],
                "f1": block_gate["f1"],
                "tp": block_gate["tp"], "fp": block_gate["fp"],
                "fn": block_gate["fn"], "tn": block_gate["tn"],
            },
            "definitions": {
                "precision": "TP / (TP + FP)",
                "recall": "TP / (TP + FN)",
                "f1": "2PR / (P + R), the harmonic mean",
                "positive_class": "fraud_label == 1 in the held-out test split",
                "f1_caveat": (
                    "F1 weights a missed fraud and a wrongly blocked customer "
                    "equally. This system's own cost model puts them ~41x apart, "
                    "so F1 is published for comparability and is deliberately NOT "
                    "what the thresholds optimise."
                ),
            },
        },
        "confusion": c,
        "recall_by_archetype": arche,
        "baselines": baselines,
        "aggregation_weight_search": weight_rows,
        "threshold_sweep_top10": sweep[:10],
        # Full grid, ordered by threshold rather than cost, so the admin console can
        # draw a cost curve instead of only showing the winner. Cheap to store
        # (~200 rows) and it is the only way an operator can see that the optimum
        # is flat-bottomed rather than a sharp peak.
        "threshold_sweep": sorted(sweep, key=lambda r: (r["review"], r["block"])),
        "cost": {
            "unit_costs": COSTS.as_dict(),
            "do_nothing": round(nothing, 2),
            "with_fraudshield": round(total_cost, 2),
            "net_saving": round(nothing - total_cost, 2),
            "net_saving_pct": round((nothing - total_cost) / nothing, 4),
            "false_positive_cost": round(fp_cost, 2),
            "false_positive_share_of_remaining": round(fp_cost / total_cost, 4),
            # The other side of the ledger, previously only implicit in
            # `with_fraudshield`. Reported explicitly so the two error types can be
            # compared directly instead of one being visible and the other buried.
            "false_negative_cost": round(c["fn"] * COSTS.fraud_loss, 2),
            "cost_breakdown": {
                "fraud_allowed_through": round(c["fn"] * COSTS.fraud_loss, 2),
                "legit_blocked": round(c["fp_block"] * COSTS.block_legit_cost, 2),
                "legit_reviewed": round(c["fp_review"] * COSTS.review_cost, 2),
                "fraud_reviewed": round(c["tp_review"] * COSTS.review_cost, 2),
                "fraud_blocked": round(c["tp_block"] * COSTS.fraud_blocked_cost, 2),
            },
            "legit_blocked": c["fp_block"],
            "fraud_missed": c["fn"],
            # Named here as well as in `caveats`, because this block is what the
            # console renders and an unlabelled rupee figure reads as accounting.
            "basis": (
                "Estimated economic model. Unit costs are industry-typical "
                "assumptions used to compare operating points, NOT observed losses "
                "and NOT a real merchant's audited figures."
            ),
            "sensitivity": sensitivity(),
        },
        "fairness": fairness,
        "worked_example": example,
        "caveats": [
            "Synthetic data generated by ml/generate_dataset.py. Production "
            "performance will be worse.",
            "first_party_abuse is undetectable at payment time by construction and "
            "caps achievable recall.",
            "Ring detection is partly evaluated against its own generator's "
            "assumptions -- the least transferable figure here.",
            "Unit costs are industry-typical estimates, not a real merchant's "
            "audited figures.",
        ],
    }
    a.artifacts.mkdir(parents=True, exist_ok=True)
    (a.artifacts / "metrics.json").write_text(json.dumps(out, indent=2))
    print(f"\nwrote {a.artifacts / 'metrics.json'}")


if __name__ == "__main__":
    main()
