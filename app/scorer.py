"""
Online scorer: one transaction, three layers, one decision, with reasons.

This is the production path. It reads counters from a Store, builds the 22
features, runs the calibrated model, applies the rule and network layers, and
returns a decision with evidence.

Two design rules, both load-bearing:

1. The feature matrix is built by ml/features.build_matrix -- the SAME function
   train.py used. A second implementation here would eventually drift by a
   log1p or a column order and silently score against a different model.

2. Nothing in this module writes state. `store.commit()` is the caller's job,
   after scoring, so the read-before-write ordering that the parity test verifies
   cannot be broken by accident here.
"""

from __future__ import annotations

import json
import math
import sys
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd
import xgboost as xgb

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT / "ml"))

from features import build_matrix  # noqa: E402  (shared with train.py by design)

from app.online_features import build as build_raw_features
from app.store import InMemoryStore

ARTIFACTS = _ROOT / "ml" / "artifacts"

# ---------------------------------------------------------------------------
# Rule layer -- thresholds and grouping mirror ml/scoring.py
# ---------------------------------------------------------------------------

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

RULE_GROUPS = {
    "entity_sharing": ["device_abuse", "ip_concentration"],
    "velocity": ["velocity_breach", "failure_spike", "method_switching"],
    "novelty": ["new_account", "new_device"],
    "amount": ["amount_anomaly"],
}

# Analyst-facing text. Customers never see these -- telling an attacker which
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

HIGH_POP_IP_ACCOUNTS = 25
MAX_COMPONENT = 200


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
    def __init__(self, artifacts: Path = ARTIFACTS, review_t: float = 5.0,
                 block_t: float = 70.0):
        self.review_t = review_t
        self.block_t = block_t
        self.degraded = False

        spec_path = artifacts / "feature_spec.json"
        model_path = artifacts / "model.json"
        cal_path = artifacts / "calibrator.json"

        if not (spec_path.exists() and model_path.exists() and cal_path.exists()):
            # Fail to a rules+network-only score rather than refusing to serve.
            # Checkout is on the other side of this call.
            self.booster = None
            self.spec = {"feature_names": []}
            self.degraded = True
            self.model_version = "none"
            self._cal_x = self._cal_y = None
            return

        self.spec = json.loads(spec_path.read_text())
        self.booster = xgb.Booster()
        self.booster.load_model(str(model_path))
        cal = json.loads(cal_path.read_text())
        self._cal_x = np.array(cal["x"], dtype=float)
        self._cal_y = np.array(cal["y"], dtype=float)
        self.best_iteration = self.spec.get("best_iteration")
        self.model_version = self.spec.get("trained_at", "unknown")

    # ---- ML layer ------------------------------------------------------
    def _calibrate(self, p: float) -> float:
        return float(
            np.interp(p, self._cal_x, self._cal_y,
                      left=self._cal_y[0], right=self._cal_y[-1])
        )

    def _ml_score(self, raw: dict) -> tuple[float, np.ndarray, list[str]]:
        if self.booster is None:
            return 0.0, np.array([]), []
        row = pd.DataFrame([raw])
        X, names = build_matrix(row)
        if names != self.spec["feature_names"]:
            raise RuntimeError(
                "online feature order differs from training; retrain or fix features.py"
            )
        dm = xgb.DMatrix(X.to_numpy(), feature_names=names)
        rng = (0, self.best_iteration + 1) if self.best_iteration is not None else None
        p = float(self.booster.predict(dm, iteration_range=rng)[0]) if rng \
            else float(self.booster.predict(dm)[0])
        contribs = self.booster.predict(dm, pred_contribs=True)[0][:-1]
        return min(100.0, max(0.0, self._calibrate(p) * 100.0)), contribs, names

    # ---- rule layer ----------------------------------------------------
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

    # ---- network layer -------------------------------------------------
    @staticmethod
    def _network(store: InMemoryStore, cid: str, dev: str, ipa: str,
                 now: float) -> float:
        """Same shape as ml/scoring.network_scores, read from live adjacency."""
        ip_pop = len(store.ip_accounts(ipa))
        ip_is_shared = ip_pop > HIGH_POP_IP_ACCOUNTS

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
        penalty = 0.35 if ip_is_shared and len(store.device_accounts(dev)) <= 2 else 1.0
        return min(100.0, raw * 100.0 * penalty)

    # ---- explanation ---------------------------------------------------
    @staticmethod
    def _reasons(raw: dict, fired: list[str], methods_1h: int,
                 contribs: np.ndarray, names: list[str]) -> list[dict]:
        out = []
        seen = set()
        ctx = dict(raw)
        ctx["methods_1h"] = methods_1h

        for r in fired:
            out.append({
                "code": r.upper(),
                "severity": "high" if RULE_POINTS[r] >= 15 else "medium",
                "detail": RULE_TEXT[r].format(**ctx),
                "source": "rule",
            })
            seen.add(r)

        if len(contribs):
            order = np.argsort(-np.abs(contribs))
            for i in order[:5]:
                f = names[i]
                if contribs[i] <= 0:
                    continue
                base = f.split("_")[0]
                key = f if f in SHAP_TEXT else None
                if key is None:
                    continue
                detail = SHAP_TEXT[key].format(v=float(raw.get(key, 0)))
                if detail in {o["detail"] for o in out}:
                    continue
                out.append({
                    "code": key.upper(),
                    "severity": "medium",
                    "detail": detail,
                    "source": "model",
                    "contribution": round(float(contribs[i]), 4),
                })
        return out[:8]

    # ---- entry point ---------------------------------------------------
    def score(self, store: InMemoryStore, txn: dict) -> tuple[Decision, dict]:
        """Score one transaction. Returns (decision, raw_features).

        Does NOT commit. The caller applies store.commit() after the payment
        outcome is known, which is what preserves read-before-write.
        """
        raw = build_raw_features(store, txn)
        methods_1h = store.methods_last_hour(txn["customer_id"], float(txn["ts"]))

        ml, contribs, names = self._ml_score(raw)
        rules, fired = self._rules(raw, methods_1h)
        net = self._network(
            store, txn["customer_id"], txn["device_fp"], txn["ip_hash"],
            float(txn["ts"]),
        )

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
                sub_scores={
                    "ml": round(ml, 1),
                    "rules": round(rules, 1),
                    "network": round(net, 1),
                },
                reason_codes=self._reasons(raw, fired, methods_1h, contribs, names),
                fired_rules=fired,
                override=override,
                model_version=self.model_version,
                degraded=self.degraded,
            ),
            raw,
        )
