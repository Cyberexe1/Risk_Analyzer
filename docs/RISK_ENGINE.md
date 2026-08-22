# FraudShield — Risk Engine

The scoring internals: features, the XGBoost model, the rule layer, ring detection, and how the three combine into one defensible number.

---

## 1. Why not just add points

The MVP scored transactions with five hand-chosen weights summing to 91. The five *signals* were right. The *numbers* were not evidence, they were opinion.

Two failure modes follow from hand-picked weights:

1. **No grounding.** "Velocity is worth 25" is unfalsifiable. If velocity turns out to be weakly predictive in this merchant's traffic, the score is wrong and nothing tells you.
2. **Additive blow-up.** Every new signal tempts another `+N`. Ten signals in, you have a 40-line arbitrary formula that nobody can reason about, and correlated signals double-count. Device reuse and IP reuse fire together constantly; adding both punishes the same evidence twice.

So: keep the five signals, expand them, and let a model learn the weights. Keep the thresholds as a *separate, capped* layer where determinism is genuinely valuable.

---

## 2. Feature set — 22 features

Deliberately 22, not 50. Every feature must be computable from at most two DynamoDB reads on the checkout path, and must have a plausible causal story. Features you cannot explain to an analyst are features you cannot defend to a regulator.

### Transaction (4)

| Feature | Type | Notes |
| --- | --- | --- |
| `amount` | float | Log-transformed; raw rupee amounts are heavily right-skewed |
| `payment_method` | categorical | card / upi / netbanking / wallet / cod, one-hot |
| `transaction_hour` | cyclical | Encoded as sin/cos so 23:00 and 00:00 are adjacent |
| `is_weekend` | bool | Weekday/weekend traffic mixes differ materially |

### Velocity (4)

| Feature | Type | Notes |
| --- | --- | --- |
| `txn_count_10m` | int | Attempts in the last 10 minutes |
| `txn_count_1h` | int | Attempts in the last hour |
| `failed_count_10m` | int | Failures in 10 minutes — distinct from total attempts |
| `failed_count_1h` | int | Failures in an hour |

Failure velocity earns its own features. One failure a day is a mistyped CVV. Eight failures in ten minutes is someone working through a list. Total volume alone cannot separate those.

### Customer baseline (5)

| Feature | Type | Notes |
| --- | --- | --- |
| `account_age_hours` | float | Log-transformed; the 0–24 h band carries most of the signal |
| `customer_avg_amount` | float | The customer's own historical mean |
| `amount_ratio` | float | `amount / customer_avg_amount`, clipped at 50 |
| `prev_txn_count` | int | Successful history depth |
| `historical_failure_rate` | float | Laplace-smoothed to avoid a 1/1 = 100% artefact |

`amount_ratio` is the single most useful engineered feature. A flat "over Rs 10,000 is suspicious" rule is wrong in both directions: it flags a wealthy customer's normal purchase and misses a Rs 7,500 charge on an account that has never exceeded Rs 800. Comparing a customer against **their own** baseline fixes both.

```text
customer_avg = Rs 800
current      = Rs 7,500
amount_ratio = 9.37   <- meaningful
```

### Device and IP (5)

| Feature | Type | Notes |
| --- | --- | --- |
| `device_account_count` | int | Distinct accounts on this fingerprint |
| `device_txn_count` | int | Volume from this device |
| `device_failure_rate` | float | Failures over attempts for this device |
| `ip_account_count` | int | Distinct accounts on this IP hash |
| `ip_txn_count` | int | Volume from this IP hash |

Device history is richer than a single "linked to 5 accounts" flag. A shared family tablet and a fraud farm's emulator both show multiple accounts; failure rate and volume separate them, and the model works out how.

`device_confirmed_fraud_count` exists in the table but is **excluded from the model**. It is a downstream product of our own past decisions, and feeding it back creates a self-reinforcing loop that entrenches earlier errors. It is shown to analysts as context, never used as a feature.

### Behavioural (4)

| Feature | Type | Notes |
| --- | --- | --- |
| `is_new_device` | bool | First transaction from this fingerprint for this account |
| `is_new_payment_method` | bool | First use of this instrument |
| `seconds_since_last_txn` | float | Log-transformed; captures burst structure |
| `hour_deviation` | float | Std deviations from the customer's typical activity hours |

A 03:17 transaction from a 09:00–20:00 customer is not automatically fraud. It is one more signal, and the model gets to decide how much it is worth in combination with the rest.

### Excluded on purpose

Name, gender, city, pin code, age, device brand as a proxy for income. They correlate with fraud in most datasets, but through demographics rather than behaviour. Including them builds a system that declines people for who they are instead of what they did. See [Fairness checks](EVALUATION.md#fairness-checks).

---

## 3. ML layer — XGBoost

```python
XGBClassifier(
    n_estimators=400,
    max_depth=5,
    learning_rate=0.05,
    subsample=0.8,
    colsample_bytree=0.8,
    min_child_weight=5,
    reg_lambda=1.5,
    scale_pos_weight=neg / pos,      # ~1:60 in our data
    eval_metric="aucpr",
    early_stopping_rounds=40,
)
```

Design notes:

- **Depth 5, not 12.** Fraud features interact, but shallow trees generalise better on a ~1.7% positive class and keep SHAP explanations readable.
- **`aucpr`, not `accuracy`.** At 1.7% positives, a model that predicts "never fraud" scores 98.3% accuracy and is worthless. PR-AUC is the metric that moves when the model actually improves.
- **`scale_pos_weight` over SMOTE.** Synthetic minority oversampling on top of an already synthetic dataset compounds generator artefacts. Reweighting the loss keeps the real distribution.
- **Temporal split.** Train weeks 1–6, validate week 7, test week 8. A random split lets the model see a ring's later transactions while training on its earlier ones, which inflates recall enormously and is pure leakage.

### Calibration

Raw XGBoost margins are not probabilities. We fit isotonic regression on the validation fold so that a predicted 0.30 means roughly 30% of such transactions are fraud. This matters because the whole cost model in [EVALUATION.md](EVALUATION.md) multiplies probability by rupees — uncalibrated scores make that arithmetic meaningless.

```text
ml_score = round(calibrator(model.predict_proba(x)[1]) * 100)
```

### Learned importance vs. our guesses

Top features by mean absolute SHAP on the test set, against the MVP's hand-picked ranking:

| Feature | Learned rank | MVP rank | Comment |
| --- | --- | --- | --- |
| `amount_ratio` | 1 | 3 | Baseline-relative amount beats raw velocity |
| `txn_count_10m` | 2 | 1 | Strong, but not the top signal |
| `device_account_count` | 3 | 2 | Roughly as expected |
| `account_age_hours` | 4 | 5 | Materially more predictive than we assumed |
| `failed_count_10m` | 5 | — | Not in the MVP at all; highly predictive |
| `hour_deviation` | 14 | 4 | We badly over-weighted time-of-day |

The MVP would have paid too much attention to the clock and too little to failure bursts. That gap is the concrete argument for learning weights rather than choosing them.

---

## 4. Rule layer — deterministic and capped

Rules are not a fallback for a weak model. They cover three things a trained model cannot:

1. **Novel attack shapes.** A pattern absent from training data gets a low ML score by construction. Thresholds still fire.
2. **Auditability.** "Blocked because 9 attempts in 10 minutes exceeded the limit of 5" is a sentence a compliance reviewer accepts. "SHAP contribution 0.34" is not.
3. **Cold start.** A brand-new merchant has no labels. Rules work on day zero.

| Signal | Condition | Points |
| --- | --- | --- |
| Velocity breach | `> 5 attempts / 10 min` | 20 |
| Device abuse | `> 4 accounts / device` | 15 |
| IP concentration | `> 6 accounts / IP` | 10 |
| Amount anomaly | `> 4x customer average` | 15 |
| Failure spike | `> 5 failures / hour` | 10 |
| New account | `account_age < 24 h` | 5 |
| New device | first transaction from fingerprint | 5 |
| Payment-method switching | `> 3 methods / hour` | 10 |

Raw maximum is 90. Two constraints keep it honest:

**Correlated rules are grouped.** Device abuse and IP concentration measure the same underlying thing — one actor behind many accounts. Within a group only the highest-scoring member counts:

```python
GROUPS = {
    "entity_sharing": ["device_abuse", "ip_concentration"],
    "velocity":       ["velocity_breach", "failure_spike", "method_switching"],
    "novelty":        ["new_account", "new_device"],
    "amount":         ["amount_anomaly"],
}

rule_score = min(100, sum(max(points[r] for r in fired_in_group)
                          for group in GROUPS.values()
                          if (fired_in_group := fired & set(group))))
```

**The layer is capped at 100 and weighted 0.20.** No accumulation of rules can push the final score past 20 points of rule contribution. This is the structural fix for additive blow-up: adding a tenth rule cannot inflate the total, it only redistributes within a fixed budget.

Thresholds are config, not code (`app/scoring/rules.yaml`), versioned, and every change is audited.

---

## 5. Network layer — ring detection

The question the MVP never asked: **is this transaction connected to other suspicious entities?**

```text
Account A --+
Account B --+-- Device X -- IP Y
Account C --+
Account D --+
```

Each account in isolation may look clean: small amounts, no velocity breach, plausible hours. The structure does not.

### Expansion

From the transaction, walk the shared-entity graph to depth 2 using the `DEVICE#<fp>/ACCT#*` and `IP#<hash>/ACCT#*` edge items:

```text
txn -> device_fp, ip_hash, card_fingerprint
     -> accounts sharing any of those      (depth 1)
     -> devices / IPs used by those accts  (depth 2)
```

Expansion is bounded at 200 nodes. Shared corporate NATs and mobile carrier IPs can reach thousands of accounts, and an unbounded walk would both time out and produce a meaningless component.

### Score

```python
def network_score(component, txn):
    if len(component.accounts) < 3:
        return 0

    size      = min(1.0, log1p(len(component.accounts)) / log1p(20))
    density   = component.edges / max(1, len(component.accounts))
    burst     = min(1.0, component.txns_last_24h / (3 * len(component.accounts)))
    fail      = component.failure_rate
    sync      = component.median_pairwise_time_similarity   # 0..1

    raw = 0.30 * size + 0.25 * density + 0.20 * burst + 0.15 * fail + 0.10 * sync
    return round(min(100, raw * 100 * shared_ip_penalty(component)))
```

`shared_ip_penalty` damps components whose only link is an IP known to be high-population (carrier CGNAT ranges, campus networks). Without it, every customer on a large mobile carrier inherits a ring score, which is the single most expensive false-positive source we found in testing.

### Why only 0.10 weight

Ring signals are high precision and low recall. When they fire, they are usually right; they fire on a small minority of fraud. Weighting them higher would swamp the score for the common single-actor case. The admin ring view surfaces them visually, which is where they do the most good — an analyst seeing four accounts on one device decides faster than any number can convey.

---

## 5a. Promotion abuse — a separate scoring path

One person opening five accounts to claim a Rs 500 welcome cashback five times ([PROBLEM.md, Loss 2](PROBLEM.md#loss-2--one-person-many-accounts)) is a real loss class that the transaction scorer **cannot** see. Two reasons:

1. **Wrong moment.** The loss happens at signup and redemption. By the time a payment is scored, the cashback is already credited.
2. **Wrong unit.** Each individual account looks unremarkable. The evidence lives in the relationships between accounts, and a per-transaction model has no place to put that.

So promo abuse gets its own gate at redemption time, reusing the entity graph from the network layer:

```text
POST /v1/promo/redeem
  |
  1. Resolve device_fp, ip_hash, card_fingerprint for this account
  2. Query DEVICE#<fp>/ACCT#*  and  IP#<hash>/ACCT#*
  3. Count prior redemptions of THIS promo across the component
  4. Score
  |
  v
ALLOW  /  HOLD FOR REVIEW  /  DENY OFFER
```

### Redemption features (7)

| Feature | Notes |
| --- | --- |
| `promo_redemptions_on_device` | Same promo already claimed from this fingerprint |
| `promo_redemptions_on_ip` | Same promo already claimed from this IP hash |
| `accounts_on_device_7d` | New accounts created on this device in a week |
| `signup_to_redeem_seconds` | Real customers browse first; scripted signups redeem in seconds |
| `email_pattern_similarity` | Normalised edit distance to other accounts in the component (catches `ravi+1@`, `ravi.k2@`) |
| `component_account_count` | Size of the shared-entity cluster |
| `payout_destination_reuse` | Same bank account or UPI ID receiving multiple cashbacks — the strongest single signal |

`payout_destination_reuse` is the one that closes the case. Devices and IPs have innocent explanations — a family tablet, an office network, a shared hostel connection. Five different accounts paying cashback into one UPI ID does not.

### Rules at redemption

| Condition | Action |
| --- | --- |
| Same promo already redeemed on this device | `DENY OFFER` |
| Same payout destination as a prior redemption | `DENY OFFER` |
| `>= 3` accounts on this device within 7 days | `HOLD FOR REVIEW` |
| `>= 5` accounts on this IP within 24 h **and** signup-to-redeem `< 60 s` | `HOLD FOR REVIEW` |
| Component size `>= 4` with high email similarity | `HOLD FOR REVIEW` |

Denials here are deliberately cheap to be wrong about, and that changes the risk posture. Refusing a cashback is not refusing a sale — the customer can still buy, they just don't get the bonus. So we allow harder denial rules than we ever would at checkout, and a wrongly denied customer is recoverable through support rather than lost.

Two guards against over-blocking:

- **Shared-network exemption.** The same `shared_ip_penalty` from the network layer applies. Campus and CGNAT ranges cannot trigger an IP-only denial; they require a device or payout match.
- **Appeal path.** Any denial surfaces in the admin queue with a one-click override, and the override writes a label. This is the main source of training data for this gate, since we start with no labels at all.

This gate is rules-first on purpose. Promo abuse patterns are structural and stable, the class is small, and a merchant launching a new promotion has zero history to train on. ML here would be over-engineering for the volume.

---

## 6. Aggregation

```python
FINAL = 0.70 * ml_score + 0.20 * rule_score + 0.10 * network_score
```

Worked example:

```text
ml_score      = 82
rule_score    = 76
network_score = 91

0.70 * 82 = 57.4
0.20 * 76 = 15.2
0.10 * 91 =  9.1
            -----
             81.7  ->  82 / 100
```

Not `82 + 76 + 91 = 249`, and not `82 + 10 + 8 + 7 = 107`. A weighted mean of three bounded scores is bounded, monotonic, and explainable one term at a time.

### Weight selection

The 0.70 / 0.20 / 0.10 split is itself a choice, so we grid-searched it on the validation fold against net rupee cost:

| ML | Rules | Network | Val PR-AUC | Net cost (Rs) |
| --- | --- | --- | --- | --- |
| 1.00 | 0.00 | 0.00 | 0.81 | 1,42,000 |
| 0.80 | 0.15 | 0.05 | 0.82 | 1,31,000 |
| **0.70** | **0.20** | **0.10** | **0.83** | **1,24,000** |
| 0.60 | 0.25 | 0.15 | 0.82 | 1,29,000 |
| 0.50 | 0.30 | 0.20 | 0.79 | 1,47,000 |

Differences are small, which is the honest reading: the aggregation weights matter far less than the features and the decision thresholds. We report the search rather than presenting 0.70 as revealed truth.

### Override paths

Two cases bypass the weighted mean, both logged with an explicit reason:

- **Hard block.** `rule_score == 100` and `network_score > 85` → `BLOCK` regardless of ML. Reserved for unambiguous ring activity.
- **Trusted floor.** Account older than 180 days, more than 50 successful transactions, zero chargebacks, `amount_ratio < 2`, no rule fired → cap at `ALLOW`. Prevents the model harassing the merchant's best customers over a new device.

---

## 7. Decision, not verdict

```text
risk_score
    0 - 39   ALLOW           ~96.9% of traffic, no friction
   40 - 74   MANUAL REVIEW   ~3.1%, held, analyst decides
   75 - 100  BLOCK           ~0.4%, soft decline with retry path
```

The engine outputs a **decision**, never a fraud determination. `87` means "high risk, route to a human", not "this is fraud." Ground truth arrives later, from an analyst investigation or a chargeback, and only then does a `LABEL` item get written.

This distinction is not pedantry. It sets what the system is accountable for: routing attention well. Precision and recall in [EVALUATION.md](EVALUATION.md) are measured against those later labels, not against the score itself.

Thresholds are derived from the cost model rather than picked at round numbers — derivation in [EVALUATION.md](EVALUATION.md#threshold-selection).

---

## 8. Explainability

Every decision carries reason codes built from two sources:

1. **SHAP** — top 5 features by absolute contribution for this specific prediction, mapped to templated English.
2. **Fired rules** — each rule already carries its own human-readable statement.

```python
TEMPLATES = {
    "amount_ratio":         "Amount {v:.1f}x customer baseline",
    "txn_count_10m":        "{v:.0f} attempts in 10 minutes",
    "device_account_count": "Device linked to {v:.0f} accounts",
    "failed_count_10m":     "{v:.0f} failed attempts in 10 minutes",
    "account_age_hours":    "Account created {v:.0f} hours ago",
    "is_new_payment_method":"First use of this payment method",
    "hour_deviation":       "Unusual hour for this customer",
}
```

SHAP runs with `TreeExplainer`, which is exact for tree ensembles — no sampling approximation, no added latency worth measuring. Reason codes are stored on the transaction item so an explanation is reproducible months later even after the model has been retrained.

Reason codes go to analysts only. Customers get "we're verifying your payment." Telling an attacker which signal fired is free reconnaissance.

---

## 9. Retraining

```text
analyst decision or chargeback outcome
        -> LABEL#<txn_id> item
        -> weekly job: rebuild dataset from labelled transactions
        -> retrain, temporal split
        -> gate: new model must beat current on held-out PR-AUC
                 AND not regress FP rate by more than 0.2pp
        -> shadow score live traffic for 48 h, compare distributions
        -> promote, bump model_version
```

Two guards on the loop:

- **Selection bias.** We only learn outcomes for transactions we allowed or reviewed. Blocked transactions have no label, so training only on labelled rows teaches the model our own past decisions. We keep a 1% random holdback that is allowed regardless of score, which gives an unbiased sample of what blocking would have cost. It is expensive and it is the only way to measure the counterfactual.
- **Drift.** Feature distributions are monitored with population stability index per feature. PSI above 0.25 raises an alert; that usually means a genuine traffic change (a sale, a new payment method) rather than an attack, but it invalidates the model's calibration until retrained.
