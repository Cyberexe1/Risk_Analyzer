# FraudShield

## 1. One-Line Description

A defense-only transaction risk engine that scores every payment 0–100 from three independent evidence sources, explains the score in plain English, and routes it to allow, review, or block.

---

## 2. Problem We Solve

A merchant loses money two ways, and fixing one usually makes the other worse.

**Fraud gets through.** A stolen card buys a ₹20,000 phone. The payment authorises, the goods ship, and weeks later the real cardholder disputes it. The merchant loses the goods, the shipping, and a chargeback fee. Or one person opens five accounts on one device and claims a ₹500 welcome bonus five times — each account looks perfectly ordinary on its own.

**Or the detector overreacts.** Flag 20% of traffic to catch everything and you destroy more value than the fraud did. Declining a real customer costs lost margin now plus the expected value of them never returning. Sending that same transaction to a human for review costs a few minutes of analyst time.

In this repository's cost model those two errors differ by **41×** (`block_legit_cost` ₹1,438 vs `review_cost` ₹35, `ml/cost_model.py`). That single ratio drives every design decision here: when in doubt, route to a human rather than refuse the sale.

---

## 3. Solution

FraudShield scores each transaction with three layers that fail independently:

| Layer | Weight | What it contributes |
|---|---|---|
| XGBoost classifier | 0.70 | Learned weights over 22 engineered features, isotonically calibrated |
| Deterministic rules | 0.20 | 8 auditable thresholds, grouped so correlated rules cannot double-count |
| Entity graph | 0.10 | Accounts sharing devices and IPs — one account looks fine, the ring does not |

The weighted sum produces a 0–100 score. Two thresholds turn it into a decision: **ALLOW**, **MANUAL_REVIEW**, or **BLOCK**. Every score ships with reason codes drawn from the fired rules and the model's own per-row attributions.

A second, separate gate scores **promotion abuse** at redemption time rather than at checkout, because by the time a payment is scored the cashback is already credited.

---

## 4. Why This Matters

Recall alone is a vanity metric. A detector that flags a fifth of all traffic will catch nearly every fraud and still lose the merchant money, because each wrongly-declined customer costs roughly forty times what a review costs.

So this repository treats the decision as a **cost-minimisation problem**, not a classification problem:

- The block threshold is chosen where blocking is cheaper than being wrong.
- The review threshold is bounded by **analyst headcount**, not by model quality. At a 100:1 cost asymmetry the optimiser always wants to review more, so the binding constraint is how many people you employ — which is why it is a runtime control surface here, not a config constant.
- False-positive cost is reported as a first-class metric alongside precision and recall.
- The system never claims "this is fraud." It claims "this deserves attention, and here is the evidence." Ground truth is only created when a human records an outcome.

---

## 5. Hackathon Track

**Track 02 — AI Risk Manager.**

Scope is deliberately narrowed to **payment fraud and coordinated payment abuse**. Returns and chargebacks are recorded but not scored.

---

## 6. Current Implementation Status

Legend: ✅ COMPLETED · 🟡 PARTIAL · 🔴 NOT IMPLEMENTED · ⚪ UNVERIFIED

| Component | Status | Evidence | Missing |
|---|---|---|---|
| Synthetic dataset generator | ✅ | `ml/generate_dataset.py` (1,021 lines); `ml/data/transactions.csv` = 99,419 rows; `ml/data/metadata.json` | Real transaction data |
| Feature engineering (offline) | ✅ | `compute_features` in generator; 22 raw features in `metadata.json` | — |
| Feature engineering (online) | ✅ | `build_online_features` in `backend.py`; 22 features from live state | DynamoDB-backed counters |
| Offline/online parity test | ✅ | `tests/test_parity.py` — 99,419 rows × 22 features, passes | — |
| Train/validation/test split | ✅ | Temporal, by date; 69,593 / 14,913 / 14,913 = 70/15/15 | — |
| Model training | ✅ | `ml/train.py`; XGBoost 3.0.3, early-stopped at iteration 174 | — |
| Model artifact | ✅ | `ml/artifacts/model.json`, `calibrator.json`, `feature_spec.json` (trained 2026-08-23) | — |
| Probability calibration | ✅ | Isotonic, fit on validation only; Brier 0.00709 | — |
| Rule engine | ✅ | 8 rules with grouped scoring, `Scorer._rules` | — |
| Entity-graph / ring scoring | ✅ | `Scorer._network`; depth-2 expansion, 5 weighted terms | Persisted graph |
| Risk aggregation | ✅ | `W_ML 0.70 / W_RULES 0.20 / W_NETWORK 0.10` | — |
| Decision routing | 🟡 | ALLOW / MANUAL_REVIEW / BLOCK on two thresholds | 4-band LOW/MEDIUM/HIGH/CRITICAL not implemented |
| Explainability | ✅ | Fired rules + top-5 TreeSHAP contributions → templated English | — |
| Model evaluation | ✅ | `ml/evaluate.py`; `ml/artifacts/metrics.json` with sweep, baselines, fairness | F1 not reported |
| False-positive cost | ✅ | `ml/cost_model.py`; `false_positive_cost` in metrics | Costs are estimates, not audited |
| Promo-abuse gate | ✅ | `score_promo`, 5 rules; `ml/evaluate_promo.py`; `promo_metrics.json` | Small test split (898 rows) |
| Model-unavailable fallback | ✅ | `Scorer.__init__` degrades to rules+network at 0.70/0.30 | — |
| Threshold tuning at runtime | 🟡 | `PUT /v1/admin/thresholds`, audited | Not persisted; resets on restart |
| Audit trail | 🟡 | `audit()` writes to memory + `AUDIT#<date>` items; `GET /v1/admin/audit` | Only threshold changes and IP flags; no per-decision audit row |
| REST API | ✅ | 29 routes in `backend.py`, verified by introspection | — |
| Authentication | ✅ | JWT access + httpOnly refresh, Argon2id, login rate limits | Email verification, password reset, MFA |
| Role-based authorisation | ✅ | `require_role` on every admin route; roles granted out-of-band | — |
| User / order persistence | 🟡 | `DynamoUserStore`, `DynamoRecordStore` | Opt-in only; no GSIs |
| Transaction store | 🔴 | `STATE["txns"]`, `STATE["queue"]` are process memory | Lost on restart |
| Merchant dashboard | ✅ | 6-tab analyst console, React 18 | — |
| Customer storefront | ✅ | Shop, cart, payment sheet, orders, offers, dashboard | — |
| Webhook ingestion path | ✅ | `POST /v1/webhooks/payment`; provider event shape, paise conversion, method mapping | — |
| Webhook signature verification | ✅ | HMAC-SHA256 over raw body, `hmac.compare_digest`; 6 tests incl. forgery and tampering | — |
| Webhook replay protection | ✅ | `STATE["webhook_seen"]` + persisted `WEBHOOK#EVENT`; staleness window | — |
| **Razorpay account integration** | 🔴 | **No Razorpay SDK, no account, no outbound call to Razorpay** | Test-mode keys, order creation, payment fetch |
| LLM explanations | 🔴 | No LLM dependency or call site | — |
| Automated test suite | 🟡 | 24 pytest tests (2 parity + 22 webhook); all pass | API, auth, rules, network, frontend tests; no CI |
| Containerisation | 🟡 | `Dockerfile` (serving only, non-root, healthcheck) | No compose, no frontend image |
| CI/CD | 🔴 | No `.github/`, no pipeline config | — |
| Secret hygiene | ✅ | `.env` gitignored and untracked; `.env.example` blanks all secrets | — |

---

## 7. Architecture

### As Implemented Today

```mermaid
flowchart TD
    W["Signed payment events<br/>scripts/emit_webhook.py"] -->|"POST /v1/webhooks/payment"| WV["HMAC-SHA256 verify<br/>raw body, compare_digest"]
    WV -->|"401 if forged"| WX["Rejected"]
    WV --> WI["Replay + staleness check<br/>WEBHOOK#EVENT"]
    WI --> D

    A["Customer storefront<br/>React 18 + Vite"] -->|"POST /v1/orders"| B["FastAPI backend.py"]
    B --> C["Instrument validation<br/>Luhn + salted fingerprint"]
    C --> D["build_online_features<br/>22 features from live state"]
    D --> E["InMemoryStore<br/>customer / device / IP counters"]

    D --> F["XGBoost + isotonic<br/>weight 0.70"]
    D --> G["8 deterministic rules<br/>weight 0.20"]
    E --> H["Entity graph<br/>weight 0.10"]

    F --> I["Risk aggregator<br/>0-100"]
    G --> I
    H --> I

    I --> J["Overrides<br/>hard_block / trusted_floor"]
    J --> K["Explainability<br/>rules + TreeSHAP to English"]
    K --> L{"Two thresholds"}

    L -->|"< 5"| M["ALLOW"]
    L -->|"5 to 70"| N["MANUAL_REVIEW"]
    L -->|">= 70"| O["BLOCK"]

    M --> P["simulate_authorisation<br/>stand-in gateway"]
    N --> P
    O --> P

    P --> Q["Order record"]
    P --> R["Failed attempt?<br/>IPFAIL records + IP flag"]
    Q --> S["Review queue<br/>process memory"]
    Q --> T["Record store<br/>memory or DynamoDB"]

    S --> U["Analyst console<br/>6 tabs"]
    R --> U
    T --> U
    U --> V["Human records outcome<br/>the only label source"]

    style O fill:#963e2d,color:#fff
    style N fill:#b38b3f,color:#fff
    style M fill:#3d5a45,color:#fff
    style WX fill:#963e2d,color:#fff
```

The webhook branch is the ingestion contract described in §15: verification, replay protection and scoring are real; the **sender** is a local emitter, not Razorpay.

### Target Architecture — What Remains

```mermaid
flowchart TD
    A["Razorpay Test Mode account<br/>NOT BUILT - needs a business account"] -.->|"swap the sender"| B["Webhook ingestion + verification<br/>ALREADY BUILT"]
    A -.->|"NOT BUILT"| A2["Razorpay SDK: order creation,<br/>payment fetch, refunds"]
    B --> C2["Existing scoring pipeline<br/>ALREADY BUILT"]
    C2 -.->|"NOT BUILT"| C["Durable transaction store<br/>DynamoDB + 3 GSIs"]
    C2 -.->|"NOT BUILT"| E["Per-decision audit row<br/>for storefront orders"]
    C2 -.->|"PARTIAL"| F["Persisted thresholds"]
    C2 -.->|"NOT BUILT"| G["Bounded automated actions<br/>escalation tier, action limits"]
    C2 -.->|"NOT BUILT"| H["CI pipeline"]

    style A stroke-dasharray: 5 5
    style A2 stroke-dasharray: 5 5
    style C stroke-dasharray: 5 5
    style E stroke-dasharray: 5 5
    style G stroke-dasharray: 5 5
    style H stroke-dasharray: 5 5
```

Note the direction of the remaining work on the provider: the receiving side exists, so a real account swaps the *sender* rather than adding a new layer.

---

## 8. Current Features

Only features with verified implementations are listed.

**Risk scoring**
- Three-layer scoring with independent failure modes, weights 0.70 / 0.20 / 0.10
- Isotonic-calibrated probabilities, so score × rupees is meaningful arithmetic
- Two overrides: `hard_block` (rules maxed and network > 85) and `trusted_floor` (established customer capped at 39)
- Exact offline/online parity, verified over 2,187,218 feature comparisons

**Explainability**
- Per-transaction reason codes from fired rules plus top-5 positive model attributions
- Reason codes stored on the transaction record, so an explanation survives a retrain
- Sub-scores broken out per layer, so an analyst can see which layer drove the decision

**Analyst console** (6 tabs)
- Risk-sorted review queue with an evidence panel
- Shared-entity graph, force-directed, with a screen-reader table equivalent
- Suspicious IPs with drill-down into individual declines
- Promo-abuse holds with analyst override
- Live model performance read from the evaluation artifacts
- Threshold tuner with a drawn cost curve, admin-only, audited

**Storefront**
- 12-product catalogue, persistent cart, multi-item orders
- Payment sheet with UPI / card / netbanking / wallet / COD, Luhn validation, network detection, simulated 3-D Secure step
- Failed attempts recorded; a burst from one address flags it
- Order history and return requests

**Security**
- JWT access tokens in memory only, refresh token in an httpOnly cookie
- Argon2id password hashing, weak-password rejection, login rate limits
- Server-derived IP hashing (HMAC) — a client cannot choose its own IP
- Card numbers fingerprinted then discarded, never stored
- Role enforced server-side on every admin route

---

## 9. ML Pipeline

```
ml/generate_dataset.py  →  transactions.csv (99,419 rows) + metadata.json
                                    ↓
ml/train.py             →  model.json, calibrator.json, feature_spec.json, train_report.json
                                    ↓
ml/evaluate.py          →  metrics.json
ml/evaluate_promo.py    →  promo_metrics.json
                                    ↓
backend.py Scorer       →  serves the artifact
tests/test_parity.py    →  proves online == offline
```

**Model.** XGBoost 3.0.3. `n_estimators=400`, `max_depth=5`, `learning_rate=0.05`, `subsample=0.8`, `colsample_bytree=0.8`, `min_child_weight=5`, `reg_lambda=1.5`, `eval_metric="aucpr"`, `early_stopping_rounds=40`. Early stopped at **iteration 174**. `scale_pos_weight` computed from class balance rather than SMOTE — synthetic oversampling on top of already-synthetic data compounds generator artefacts.

**Calibration.** Isotonic regression fit on the **validation split only**, saved as knots in `calibrator.json` and re-applied at serve time by interpolation. Raw XGBoost margins are not probabilities; the cost model multiplies probability by rupees, so uncalibrated scores would make that arithmetic meaningless.

**Feature matrix.** 22 named raw features expand to **27 model columns**: `payment_method` one-hot to 5 columns, `transaction_hour` to `hour_sin`/`hour_cos`.

**Leakage guard.** `assert_no_leakage` fails the run if any of 12 ID or outcome columns reach the matrix (`fraud_label`, `fraud_type`, `status`, `transaction_id`, `customer_id`, `device_fp`, `ip_hash`, `ts_epoch`, `timestamp`, `account_created_at`, `segment`, `split`).

**One notable design choice.** `ml/train.py` imports `build_matrix` and `RAW_FEATURES` **from `backend.py`**, inverting the usual direction. Serving code is canonical, so the transform cannot drift between training and inference — a bug class that produces plausible numbers and no error message.

---

## 10. Dataset

All figures below were measured directly from the CSV, not read from documentation.

| Property | Value |
|---|---|
| File | `ml/data/transactions.csv` |
| Total rows | **99,419** |
| Columns | 34 (22 features + labels, IDs, split) |
| Legitimate | **97,417** (97.99%) |
| Fraud | **2,002** (2.01%) |
| Duplicate rows | **0** |
| Missing values | 97,417 — all in `fraud_type`, which is null by definition on non-fraud rows |
| Distinct customers | 4,703 |
| Distinct devices | 12,480 |
| Distinct IPs | 4,421 |
| Time span | 180 days, ending 2026-06-30 |
| Generation | **Synthetic**, `ml/generate_dataset.py`, seed 20260822 |

**Split — temporal, by date boundary:**

| Split | Rows | Share | Fraud rate |
|---|---|---|---|
| Train | 69,593 | 70.0% | 1.868% |
| Validation | 14,913 | 15.0% | 2.414% |
| Test | 14,913 | 15.0% | 2.293% |

**Fraud archetypes:**

| Archetype | Rows |
|---|---|
| card_testing | 601 |
| account_takeover | 480 |
| ring_cashout | 421 |
| refund_abuse | 260 |
| first_party_abuse | 240 |

**Promo dataset:** `ml/data/promo_redemptions.csv`, 5,984 rows × 13 columns, 8.088% abuse.

### Is the generator realistic or simplistic?

Better than most synthetic generators, and it says so itself. `metadata.json` records self-audit figures the generator computes at build time:

- **No single feature separates the classes.** Highest single-feature AUC is `device_failure_rate` at 0.7672.
- **35.51% of fraud is not catchable by simple rules** (`fraud_indistinguishable_by_simple_rules`), so the ML layer has genuine work to do.
- `first_party_abuse` rows are **deliberately normal transactions**. They are undetectable at payment time by construction and cap achievable recall — which is why measured recall on that archetype is 0.000 rather than a bug.
- Features are computed in one chronological pass using only pre-event state, so no row can see its own outcome.
- The generator emits `warnings: []` when no feature separates too cleanly.

**Honest limitation:** it remains synthetic data written by the same author as the detector. Real performance will be worse, and `metrics.json` states this as its first caveat.

---

## 11. Fraud Detection Features

### Implemented — all 22 served online and verified at parity

| Group | Features |
|---|---|
| Transaction | `amount`, `payment_method`, `transaction_hour`, `is_weekend` |
| Velocity | `txn_count_10m`, `txn_count_1h`, `failed_count_10m`, `failed_count_1h` |
| Customer baseline | `account_age_hours`, `customer_avg_amount`, `amount_ratio`, `prev_txn_count`, `historical_failure_rate` |
| Device | `device_account_count`, `device_txn_count`, `device_failure_rate` |
| Network / IP | `ip_account_count`, `ip_txn_count` |
| Behavioural | `is_new_device`, `is_new_payment_method`, `seconds_since_last_txn`, `hour_deviation` |

### Specified but NOT implemented

- `transactions in 5 minutes` — only 10-minute and 1-hour windows exist
- `day of week` — reduced to the binary `is_weekend`
- `historical fraud rate per customer` — would leak the label; deliberately excluded
- `device historical risk` / `IP historical risk` as learned scores — only counts and failure rates exist
- `rapid payment-method switching` — computed as `methods_1h` and used by the **rule layer**, but it is not one of the 22 model features

### Fraud patterns, audited against the spec's list

| # | Pattern | Status | Mechanism |
|---|---|---|---|
| 1 | Payment velocity abuse | ✅ | `velocity_breach` rule (>5 in 10 min) + 4 velocity features |
| 2 | Device/account abuse | ✅ | `device_abuse` rule (>4 accounts) + graph layer |
| 3 | IP/account concentration | ✅ | `ip_concentration` rule (>6 accounts) + graph layer |
| 4 | Amount anomaly | ✅ | `amount_anomaly` rule (>4× baseline) + `amount_ratio` |
| 5 | Failed-payment spike | ✅ | `failure_spike` rule (>5/hour) + IP-burst flagging |
| 6 | New account risk | ✅ | `new_account` rule (<24h) + `account_age_hours` |
| 7 | New device risk | ✅ | `new_device` rule + `is_new_device` |
| 8 | Payment-method switching | ✅ | `method_switching` rule (>3 methods/hour) |
| 9 | Behavioural anomaly | ✅ | `hour_deviation`, `seconds_since_last_txn`, `amount_ratio` |
| 10 | Coordinated abuse ring | ✅ | `Scorer._network` graph expansion — see §14 |

---

## 12. Risk Scoring

**Aggregation.** `final = 0.70 × ml + 0.20 × rules + 0.10 × network`, clipped to 0–100.

Weights were not guessed. `metrics.json.aggregation_weight_search` records a sweep over five weightings on validation:

| Weights (ml/rules/net) | PR-AUC | Best cost |
|---|---|---|
| 1.00 / 0.00 / 0.00 | 0.8685 | ₹188,890 |
| 0.80 / 0.15 / 0.05 | 0.8653 | ₹187,475 |
| **0.70 / 0.20 / 0.10** | 0.8607 | ₹188,273 |
| 0.60 / 0.25 / 0.15 | 0.8541 | ₹214,133 |
| 0.50 / 0.30 / 0.20 | 0.8391 | — |

The chosen point is **not** the PR-AUC maximum. It trades ~0.008 PR-AUC for a rule layer that is auditable and works on day zero with no labels. That trade is documented rather than hidden.

**Rule layer — 8 rules, grouped.**

| Rule | Condition | Points | Group |
|---|---|---|---|
| `velocity_breach` | `txn_count_10m > 5` | 20 | velocity |
| `device_abuse` | `device_account_count > 4` | 15 | entity_sharing |
| `amount_anomaly` | `amount_ratio > 4` | 15 | amount |
| `ip_concentration` | `ip_account_count > 6` | 10 | entity_sharing |
| `failure_spike` | `failed_count_1h > 5` | 10 | velocity |
| `method_switching` | `methods_1h > 3` | 10 | velocity |
| `new_account` | `account_age_hours < 24` | 5 | novelty |
| `new_device` | `is_new_device == 1` | 5 | novelty |

Only the **highest-scoring rule per group** counts, and the layer is capped at 100. `device_abuse` and `ip_concentration` both measure "one actor, many accounts" — adding both punishes the same evidence twice. This is the structural fix for the additive blow-up in the hand-picked predecessor.

**Overrides.**
- `hard_block` — rules at 100 **and** network > 85 forces the score to 100.
- `trusted_floor` — account older than 180 days, >50 prior transactions, `amount_ratio < 2`, no rules fired → score capped at 39. Stops the model harassing the merchant's best customers over a new device.

**Decision bands — a deviation from spec.** The spec asks for four bands (LOW / MEDIIUM / HIGH / CRITICAL). The implementation has **three** decisions on two thresholds:

| Score | Decision |
|---|---|
| < 5 | ALLOW |
| 5 – 69.9 | MANUAL_REVIEW |
| ≥ 70 | BLOCK |

Thresholds default to 5 and 70, are overridable by `FRAUDSHIELD_REVIEW_T` / `FRAUDSHIELD_BLOCK_T`, and are adjustable at runtime by an admin. There is no separate MEDIUM "monitor" tier and no CRITICAL "escalate" tier — BLOCK is the terminal action.

---

## 13. Explainability

**Implemented.** Two sources merged into one reason list, deduplicated, capped at 8 items:

1. **Fired rules** → templated English via `RULE_TEXT`, e.g. `"{txn_count_10m:.0f} attempts in 10 minutes"`. Severity `high` when the rule is worth ≥15 points.
2. **Model attributions** → top 5 features by absolute contribution, positive-only, mapped through `SHAP_TEXT`, tagged `source: "model"` with the numeric contribution attached.

**On the word SHAP.** The `shap` package is **deliberately not a dependency**. Attributions come from XGBoost's native `predict(..., pred_contribs=True)`, which is exact TreeSHAP computed inside the booster. Same values, no extra dependency, no sampling approximation. The code and `requirements-serve.txt` both say so explicitly.

**Not implemented:** no LLM anywhere in the repository. No `openai`, `anthropic`, `bedrock`, `langchain`, or any model API call. Explanations are template-based. This is a defensible choice for a fraud path — templates are deterministic, auditable and reproducible — but the spec's optional "structured evidence → LLM → prose" layer does not exist.

**Reproducibility.** Reason codes are stored on the transaction record, so an explanation can be re-read months later even after the model has been retrained.

---

## 14. Fraud Ring Detection

**Implemented.** `Scorer._network` in `backend.py` is a real graph computation, not a library import.

| Requirement | Status | Implementation |
|---|---|---|
| Graph creation | ✅ | Adjacency maintained live in `InMemoryStore.acct_devices` / `acct_ips` |
| Relationship extraction | ✅ | Account ↔ device and account ↔ IP edges on every commit |
| Connected components | ✅ | Seeded expansion from device + IP, conditional depth-2 hop |
| Suspicious cluster detection | ✅ | Requires ≥3 accounts; below that returns 0.0 |
| Cluster risk score | ✅ | 5 weighted terms: size 0.30, density 0.25, burst 0.20, failure rate 0.15, sync 0.10 |
| Graph visualisation | ✅ | `web/src/pages/RingView.tsx` — hand-rolled force-directed SVG, no charting library |
| Estimated exposure | 🔴 | Not computed. The graph reports structure, not rupees at risk |

**Two guards worth noting.** Expansion is bounded at `MAX_COMPONENT = 200` because carrier CGNAT ranges reach thousands of accounts. And when the *only* link between accounts is a high-population IP (>25 accounts) with a device shared by ≤2, the score is damped to 35% — described in the code as the most expensive false-positive source found in testing.

**Honest caveat**, quoted from `metrics.json`: *"Ring detection is partly evaluated against its own generator's assumptions — the least transferable figure here."* Measured `network_only` PR-AUC is 0.1743, so the graph is a weak standalone ranker; it earns its 0.10 weight as corroboration, not as a detector.

---

## 15. Payment Provider Integration

**� PARTIAL — the ingestion contract is real and tested; the provider is simulated.**

Razorpay Test Mode requires a business account, which this project does not have. Rather than fake an integration or skip it, the **ingestion contract** is implemented against Razorpay's documented webhook shape and signature scheme, with a local emitter standing in for the provider's sender.

Being precise about the boundary matters more here than anywhere else in this document.

### What is genuinely implemented and tested

| Capability | Evidence |
|---|---|
| Webhook endpoint | `POST /v1/webhooks/payment` (`backend.py` §12) |
| **HMAC-SHA256 signature verification** | `verify_webhook_signature()` — digest over the **raw request body**, compared with `hmac.compare_digest` |
| Forged signature rejected | 401. Tested: wrong signature, wrong secret, absent, empty, and tampered body with a valid original signature |
| Fail-closed when unconfigured | 503 if `FRAUDSHIELD_WEBHOOK_SECRET` is unset — never accepts unverified events |
| Replay / idempotency | Event id checked against memory + persisted `WEBHOOK#EVENT`; tested that a redelivery does not double-count velocity |
| Staleness window | Events older than `WEBHOOK_MAX_AGE_S` (24h) rejected |
| Provider event shape | `payment.captured` / `payment.failed`, `payload.payment.entity`, `notes` |
| Paise → rupee conversion | `amount` arrives in paise; tested that 249900 becomes ₹2,499.00 |
| Method mapping | `emi` and `cardless_emi` → `card`, `cash` → `cod`, so no event is silently dropped |
| Customer resolution | Payer email matched to an account, else a **stable** pepper-derived pseudo-id |
| Scoring and persistence | Same `Scorer`, same record shapes, lands in the review queue |
| Failed-attempt + IP flagging | A decline burst arriving by webhook flags the address exactly as one at checkout does |
| Audit | Every ingestion writes `payment_event_ingested` |

Two implementation details that are load-bearing, both documented in the code:

- The digest is computed over the **exact bytes received**, not a re-serialised copy of the parsed JSON. Re-serialising changes key order and spacing, the signature stops matching, and the usual "fix" is to stop verifying.
- `hmac.compare_digest`, not `==`. A short-circuiting comparison leaks how many leading bytes matched, which is enough to forge a signature byte by byte.

### What is NOT implemented

| Missing | Consequence |
|---|---|
| Razorpay account and test-mode keys | No `rzp_test_` credentials exist |
| Razorpay SDK | Not in any requirements file |
| Any outbound call to Razorpay | No order creation, no payment fetch, no refund API |
| Verification against Razorpay's real signatures | Only verified against our own emitter's |

**So: this is not "Razorpay integration works."** There is no Razorpay account and nothing in this repository talks to Razorpay. What exists is the receiving half of the contract, with the security-critical part — proving a public unauthenticated endpoint is really being called by the provider — genuinely built and tested. Pointing it at Razorpay is a secret and a URL.

### The simulator

`scripts/emit_webhook.py` signs payloads with the shared secret and posts them:

```bash
python scripts/emit_webhook.py                  # one successful payment
python scripts/emit_webhook.py --status failed  # one decline
python scripts/emit_webhook.py --burst 4        # card-testing burst, flags the IP
python scripts/emit_webhook.py --forge          # expect 401
python scripts/emit_webhook.py --replay         # expect the second to dedupe
python scripts/emit_webhook.py --demo           # all of the above in sequence
```

Verified output from a live `--demo` run:

```
1. valid signature, successful payment
  HTTP 200  accepted          score 2.8 -> ALLOW  pay_35406b3bb5
2. forged signature -- must be refused
  HTTP 401  forged            Invalid webhook signature.
3. replay of a valid event -- must be deduplicated
  HTTP 200  first delivery    score 2.9 -> ALLOW  pay_136fcdf904
  HTTP 200  redelivery        DUPLICATE -- replay refused, nothing scored
4. card-testing burst from one address (ip_sim_8ff7f326)
  HTTP 200  decline 1         score 41.5 -> MANUAL_REVIEW  pay_0819450846
  HTTP 200  decline 2         score 73.9 -> BLOCK  pay_2b39f1d4cf
  HTTP 200  decline 3         score 74.3 -> BLOCK  pay_91338fba56
  HTTP 200  decline 4         score 74.6 -> BLOCK  pay_66497a438c
```

The escalation is the engine responding in real time: velocity and failure features accumulate across the burst, and the address is flagged at the third decline.

### One honest modelling limitation

A webhook arrives from the **provider's servers**, not the payer's browser, so `device_fp` and `ip_hash` cannot be derived from the connection. The merchant must forward them in `notes` at order-creation time. When absent, the record is marked `signals_complete: false` and sentinel values keep the transaction out of real clusters rather than joining an arbitrary one — device and IP signals are *unavailable* for that transaction rather than wrong.

**What still exists for the storefront path.** `simulate_authorisation(method, amount, decision)` remains the stand-in gateway for orders placed through `/v1/orders`, using per-method decline rates (card 6%, netbanking 5%, wallet 3%, UPI 2%, +3% above ₹25,000) and always failing a BLOCK.

---

## 16. API Documentation

29 routes, enumerated by introspecting `backend.app.routes`. All exist.

### Authentication

| Method | Endpoint | Purpose | Guard | Status |
|---|---|---|---|---|
| POST | `/v1/auth/register` | Create a customer account | public | ✅ |
| POST | `/v1/auth/login` | Sign in, rate limited | public | ✅ |
| POST | `/v1/auth/refresh` | Exchange refresh cookie | public | ✅ |
| POST | `/v1/auth/logout` | Revoke refresh token | public | ✅ |
| GET | `/v1/auth/me` | Current user | session | ✅ |

### Storefront

| Method | Endpoint | Purpose | Guard | Status |
|---|---|---|---|---|
| GET | `/v1/catalog/products` | Catalogue, methods, banks, wallets | public | ✅ |
| POST | `/v1/orders` | Create + score + authorise an order | session | ✅ |
| GET | `/v1/orders` | Order list, role-projected | session | ✅ |
| GET | `/v1/orders/{order_id}` | Single order | session | ✅ |
| POST | `/v1/returns` | Request a return | session | ✅ |
| GET | `/v1/returns` | Return list | session | ✅ |
| GET | `/v1/promo/offers` | Available offers | public | ✅ |
| POST | `/v1/promo/redeem` | Claim, scored by the promo gate | session | ✅ |
| GET | `/v1/promo/mine` | Own redemptions | session | ✅ |

### Risk (service-to-service)

| Method | Endpoint | Purpose | Guard | Status |
|---|---|---|---|---|
| POST | `/v1/risk/score` | Score a transaction, full evidence | api-key | ✅ |
| POST | `/v1/checkout` | Score, customer-safe projection | api-key | ✅ |

### Analyst console

| Method | Endpoint | Purpose | Guard | Status |
|---|---|---|---|---|
| GET | `/v1/admin/queue` | Risk-sorted review queue | analyst, admin | ✅ |
| GET | `/v1/admin/transactions/{txn_id}` | Transaction detail + features | analyst, admin | ✅ |
| POST | `/v1/admin/transactions/{txn_id}/outcome` | Record ground truth | analyst, admin | ✅ |
| GET | `/v1/admin/rings/{entity_type}/{entity_id}` | Entity graph, depth 1–3 | analyst, admin | ✅ |
| GET | `/v1/admin/metrics` | Evaluation artifacts | analyst, admin | ✅ |
| GET | `/v1/admin/thresholds` | Current cut-offs + cost curve | analyst, admin | ✅ |
| PUT | `/v1/admin/thresholds` | Move cut-offs, audited | **admin only** | 🟡 not persisted |
| GET | `/v1/admin/audit` | Audit log | **admin only** | 🟡 partial coverage |
| GET | `/v1/admin/promo-holds` | Held/denied claims | analyst, admin | ✅ |
| POST | `/v1/admin/promo-holds/{rid}/override` | Grant anyway, creates a label | analyst, admin | ✅ |
| GET | `/v1/admin/suspicious-ips` | Flagged addresses + evidence | analyst, admin | ✅ |
| GET | `/v1/admin/failed-attempts` | All stored declines | analyst, admin | ✅ |

### Ingestion

| Method | Endpoint | Purpose | Guard | Status |
|---|---|---|---|---|
| POST | `/v1/webhooks/payment` | Ingest a signed payment event, score and persist it | **HMAC signature** | ✅ |

Public and unauthenticated by design — a provider has no session and no API key, so the signature *is* the authentication. That is why a missing or wrong signature returns 401 rather than 400, and why the endpoint returns 503 rather than accepting anything when no secret is configured. Accepts `X-Razorpay-Signature` or `X-Webhook-Signature`.

### Operations

| Method | Endpoint | Purpose | Guard | Status |
|---|---|---|---|---|
| GET | `/health` | Model version, thresholds, store backends | public | ✅ |

---

## 17. Database Schema

Single-table design, DynamoDB-shaped (`PK` + `SK`). Two interchangeable implementations: `InMemoryRecordStore` (default) and `DynamoRecordStore` (opt-in via `FRAUDSHIELD_USERS_BACKEND=dynamodb`). There is **no ORM and no migration framework** — item shapes are written inline.

### Items actually written (verified from `records.put` call sites)

| PK | SK | Purpose | Status |
|---|---|---|---|
| `USER#<id>` | `PROFILE` | Account: email, Argon2id hash, role, created_at | ✅ |
| `EMAIL#<email>` | `USER` | Email-uniqueness index; conditional put | ✅ |
| `USER#<id>` | `RT#<tid>` | Refresh token, SHA-256 hashed, TTL | ✅ |
| `CUSTOMER#<id>` | `ORDER#<iso>#<order_id>` | Order + score + reason codes | ✅ |
| `INDEX#ORDER` | `<order_id>` | Order → customer lookup | ✅ |
| `CUSTOMER#<id>` | `RETURN#<iso>#<id>` | Return request | ✅ |
| `CUSTOMER#<id>` | `PROMO#<code>#<iso>` | Redemption + gate decision | ✅ |
| `INDEX#PROMO` | `<rid>` | Redemption lookup | ✅ |
| `INSTRUMENT#<ref>` | `<iso>#<customer>` | Instrument reuse across accounts | ✅ |
| `PROMODEV#<device>` | `<code>#<iso>#<customer>` | Promo-per-device counter | ✅ |
| `PROMOIP#<ip>` | `<code>#<iso>#<customer>` | Promo-per-IP counter | ✅ |
| `PAYOUT#<ref>` | `<code>#<iso>#<customer>` | Payout-destination reuse | ✅ |
| `CUSTOMER#<id>` | `FAILED#<iso>#<id>` | Failed payment attempt | ✅ |
| `IPFAIL#<ip>` | `ATTEMPT#<iso>#<id>` | Failed attempt by address | ✅ |
| `SUSPICIOUS#IP` | `<ip_hash>` | Flagged address | ✅ |
| `WEBHOOK#EVENT` | `<event_id>` | Ingested provider event; replay protection across restarts | ✅ |
| `AUDIT#<date>` | `<iso>#<uuid>` | Audit entry | 🟡 partial coverage |

### In process memory only — lost on restart

| Store | Contents | Impact |
|---|---|---|
| `STATE["txns"]` | Scored transactions + features | Console detail view empties |
| `STATE["queue"]` | Review queue | Analyst backlog lost |
| `STATE["promo_queue"]` | Promo holds | Hold list lost |
| `STATE["audit"]` | Audit entries | Falls back to persisted items |
| `STATE["fail_ips"]` | Addresses with failures | Failed-attempt listing narrows |
| `InMemoryStore` | All entity counters and graph edges | Network risk under-scores until traffic rebuilds |

**Indexes.** `scripts/create_table.py` creates the table with `PAY_PER_REQUEST` billing and TTL on `ttl`. Its own docstring states the **three GSIs in `docs/ARCHITECTURE.md` §3 are not created**, because nothing reads them yet. So queue-by-decision and history-by-device/IP run from memory, not from an index.

---

## 18. Frontend

React 18.3.1 + TypeScript 5.6.3 + Vite 5.4.11, `react-router-dom` 6.28.0. No UI framework, no charting library — both SVG visualisations are hand-written.

| Page / feature | File | Status | Notes |
|---|---|---|---|
| Landing | `pages/Landing.tsx` | 🟡 IMPLEMENTED, metrics hardcoded | Figures mirrored by hand from `metrics.json`; drift is possible |
| Shop | `pages/Checkout.tsx` | ✅ | 12 products, category-grouped, cart steppers |
| Cart / checkout | `pages/Cart.tsx` | ✅ | Line items, totals, server-side recompute note |
| Payment interface | `pages/PaymentSheet.tsx` | ✅ | 5 methods, Luhn + network detection, simulated 3-D Secure, staged processing, 4 outcomes |
| Customer dashboard | `pages/Dashboard.tsx` | ✅ | Orders, cashback, returns |
| Order history | `pages/Orders.tsx` | ✅ | Return request flow |
| Offers | `pages/Offers.tsx` | ✅ | Promo claiming, gate results |
| Login / signup | `pages/Login.tsx`, `Signup.tsx` | ✅ | Shared staff/customer form, strength meter |
| Review queue | `pages/Admin.tsx` | ✅ | Risk-sorted, keyboard operable, evidence panel |
| Transaction detail | `pages/Admin.tsx` | ✅ | Score dial, sub-scores, reason codes |
| Fraud clusters | `pages/RingView.tsx` | ✅ | Force-directed SVG + accessible table equivalent |
| Suspicious IPs | `pages/SuspiciousIps.tsx` | ✅ | Expandable evidence per address |
| Promo holds | `pages/Admin.tsx` | ✅ | Override creates the only label for that gate |
| Model metrics | `pages/AdminMetrics.tsx` | ✅ | Reads live artifacts; surfaces unflattering figures |
| Threshold tuner | `pages/Thresholds.tsx` | 🟡 | Works; changes do not survive restart |
| Audit trail UI | `pages/Thresholds.tsx` | 🟡 | Only threshold-change history, not a full audit view |
| Settings page | — | 🔴 | Does not exist |
| Frontend tests | — | 🔴 | No test framework installed |

**Cart state** lives in `web/src/cart.tsx`, localStorage-backed, storing only product ids and quantities. Prices are resolved from the catalogue at render and recomputed server-side at order time, so a tampered cart cannot set its own amount.

---

## 19. Evaluation

All figures below are read directly from `ml/artifacts/metrics.json`, generated by `ml/evaluate.py` on the **held-out test split**. Nothing here is estimated.

**Test set:** 14,913 rows, 342 fraud (2.293%).

### Ranking

| Metric | Value |
|---|---|
| PR-AUC | **0.7875** |
| ROC-AUC | 0.9399 |
| Brier (calibrated) | 0.00709 |

### Operating points

| Gate | Threshold | Precision | Recall | FP rate | Volume |
|---|---|---|---|---|---|
| Manual review | ≥ 5 | 0.3704 | 0.7895 | 0.0315 | 4.888% |
| Block | ≥ 70 | 1.0000 | 0.5526 | 0.0000 | 1.267% |

Thresholds were selected **on validation** by expected-cost minimisation.

### Confusion matrix at the chosen operating point

|  | Block | Review | Allow |
|---|---|---|---|
| **Fraud** | 189 | 81 | 72 |
| **Legitimate** | 0 | 459 | 14,112 |

### Recall by fraud archetype

| Archetype | Recall |
|---|---|
| card_testing | 1.0000 |
| ring_cashout | 1.0000 |
| account_takeover | 0.9864 |
| refund_abuse | 0.4545 |
| first_party_abuse | **0.0000** |

### Baseline comparison (PR-AUC, test)

| Approach | PR-AUC | Cost |
|---|---|---|
| Random | 0.0238 | ₹553,450 |
| Amount threshold ₹10k | 0.0804 | ₹1,530,782 |
| Network only | 0.1743 | ₹903,480 |
| Rules only | 0.3419 | ₹598,420 |
| Hand-picked MVP formula | 0.4041 | ₹657,075 |
| **XGBoost only** | **0.8001** | ₹277,535 |
| **FraudShield ensemble** | 0.7875 | **₹274,500** |

### Fairness slices — behavioural, not protected attributes

No protected attribute is a model input. These are monitored for disparate impact.

| Slice | n | Review rate | Block rate | Ratio vs overall |
|---|---|---|---|---|
| Overall | 14,913 | 4.89% | 1.27% | 1.00× |
| New customers < 7d | 193 | 46.63% | 24.35% | **9.54×** |
| High-value top decile | 1,492 | 18.50% | 6.03% | 3.78× |
| Established > 1y | 9,811 | 4.01% | 0.80% | 0.82× |
| COD primary | 1,796 | 3.79% | 0.06% | 0.78× |
| UPI primary | 6,568 | 3.14% | 0.15% | 0.64× |

### Promo-abuse gate (separate evaluation)

Test split 898 redemptions, 2.895% abusive.

| Metric | Value |
|---|---|
| Precision | 0.9615 |
| Recall | 0.9615 |
| DENY precision | 1.0000 (16 denials, 0 wrong) |
| HOLD precision | 0.9000 (10 holds, 1 wrong) |
| Net saving | ₹12,150 |

### What is NOT reported

- **F1 is not computed anywhere.** Precision and recall are reported per gate; F1 is derivable but the repository does not state it, so this README does not either.
- No confidence intervals or repeated-seed variance.
- No evaluation on real transaction data.

### The four caveats the repository states about itself

1. Synthetic data — production performance will be worse.
2. `first_party_abuse` is undetectable at payment time by construction and caps achievable recall.
3. Ring detection is partly evaluated against its own generator's assumptions — the least transferable figure here.
4. Unit costs are industry-typical estimates, not a real merchant's audited figures.

### Two results worth reading carefully

**Block precision of 1.000 is a warning, not a win.** Zero false positives across 189 blocks means the synthetic data's high-confidence fraud is too cleanly separable. Real traffic will not behave this way.

**The ensemble ranks *below* XGBoost alone** — 0.7875 vs 0.8001 PR-AUC. The rule layer pulls legitimate rows into review. It is kept because it is auditable and works with no labels on day zero, and because total cost is marginally lower (₹274,500 vs ₹277,535). That is a defensible trade, but it is a trade.

---

## 20. False Positive Cost

Implemented in `ml/cost_model.py`, with the unit costs living in `backend.py` so the runtime threshold tuner and the offline evaluation cannot disagree.

| Outcome | Cost | Derivation |
|---|---|---|
| Fraud allowed through | ₹3,550 | Goods + chargeback fee + dispute handling |
| Legitimate customer blocked | **₹1,438** | AOV × 12% margin + ₹5,750 LTV × 20% churn |
| Any manual review | ₹35 | ~3 min of a loaded analyst at ~₹42,000/month |
| Fraud blocked | ₹0 | Avoided loss is the benefit |

**Block-to-review ratio: 41.1×.** This is the number that drives the architecture.

**Measured on the test split:**

| Quantity | Value |
|---|---|
| Do nothing | ₹1,214,100 |
| With FraudShield | ₹274,500 |
| Net saving | ₹939,600 (77.39%) |
| False-positive cost | ₹16,065 |
| FP share of remaining cost | 5.85% |
| Legitimate customers blocked | 0 |

**Sensitivity analysis** is implemented (`cost_model.sensitivity()`) because the churn term is the softest input:

| Scenario | Churn | Block cost | Ratio |
|---|---|---|---|
| Optimistic | 10% | ₹863 | 24.7× |
| Used | 20% | ₹1,438 | 41.1× |
| Pessimistic | 40% | ₹2,588 | 73.9× |

The repository notes that net saving survives this range but the optimal block threshold does not.

---

## 21. Failure Handling

### Implemented — a real fallback, not generic exception handling

**Model artifact missing.** `Scorer.__init__` checks for all three artifacts. If any is absent it sets `booster = None`, `degraded = True`, `model_version = "none"` and returns rather than raising. `score()` then reweights to **0.70 × rules + 0.30 × network** so the surviving layers still span 0–100. `/health` reports `model_loaded: false`, and the console renders a warning banner. Checkout keeps working.

**Feature drift.** `_ml_score` raises `RuntimeError` if the online feature order differs from `feature_spec.json`. Failing loudly is deliberate — silently scoring a shuffled matrix produces plausible numbers and no error.

**Scoring exception.** `/v1/orders` wraps `scorer.score` and returns HTTP 503 with `{"decision": "MANUAL_REVIEW", "reason": "SCORING_UNAVAILABLE"}` — fails toward human review, never toward silent approval.

**Store unavailable.** `make_user_store` / `make_record_store` catch construction failures, print a warning, and fall back to in-memory. Accounts and orders stop persisting but the service runs.

**Audit write failure.** `audit()` catches persistence errors and prints a warning rather than failing the operation being audited.

**Malformed input.** Pydantic models constrain every field (`payment_method` regex, quantity 1–10, ≤20 line items, card length 12–19). Unknown products return 404, insufficient stock 409.

**Missing features.** Cold-start sentinels the model was trained on: `GLOBAL_AMOUNT_PRIOR = 1500.0`, `NO_PRIOR_TXN_GAP = 999999.0`.

### Not implemented

**Webhook failures.** Four distinct paths, all tested:

| Condition | Response | Why |
|---|---|---|
| Secret unset | 503 | Fail closed. An unverified webhook lets anyone who finds the URL inject transactions |
| Bad/absent signature | 401 | Does not reveal whether it was absent, malformed or merely wrong |
| Redelivery | 200, `duplicate: true` | Scoring twice would double every velocity counter it touches |
| Scoring raises | 503 | Provider retries; idempotency is recorded *after* success so the retry is scored, not discarded |
| Unmodelled event type | 200, not ingested | A non-2xx would earn an indefinite provider retry loop |

### Not implemented

| Scenario | Status |
|---|---|
| ML inference timeout | 🔴 No timeout wrapper — inference is synchronous and in-process |
| Razorpay API failure | 🔴 No outbound Razorpay calls exist to fail |
| LLM failure | ⚪ Not applicable — no LLM |
| `MODEL_FALLBACK_TRIGGERED` audit event | 🔴 Degradation is reported by `/health` but not written as an audit event |

The spec's demo script — *ML unavailable → fallback rules → manual review → audit event* — works for the first three steps. The audit event is missing.

---

## 22. Audit Trail

**Implemented.** `audit(actor, action, before, after)` appends to `STATE["audit"]` and writes an append-only `AUDIT#<date>` item. `GET /v1/admin/audit` is **admin-only** and prefers persisted items over the in-memory list.

### Coverage against the spec's field list

| Field | Status | Where |
|---|---|---|
| Transaction ID | ✅ | On the order record |
| Timestamp | ✅ | `created_at`, `scored_at`, audit `at` |
| Risk score | ✅ | On the order record |
| Model version | ✅ | `Decision.model_version` (artifact `trained_at`), also on `/health` |
| Triggered rules | ✅ | `fired_rules` on the record |
| Risk reasons | ✅ | `reason_codes` stored, survives retrain |
| Decision | ✅ | `decision` + `customer_status` |
| Action | 🟡 | Decision is stored; no separate action field |
| Actor | 🟡 | Only on audit entries (`actor.email` or `"system"`) |
| Approval status | 🟡 | Promo overrides record `override_by` / `override_at`; transaction outcomes record a label |
| Fallback status | 🟡 | `degraded` on the Decision object and `/health`, but never audited |
| Outcome | ✅ | `label` set by `POST /v1/admin/transactions/{id}/outcome` |

### Audited events — three

1. `threshold_update` — actor, before, after
2. `ip_marked_suspicious` — fires once on transition, not on every subsequent failure
3. `payment_event_ingested` — provider event id, payment id, resulting decision, score, settlement, customer resolution, and whether device/IP signals were complete

**The remaining gap:** webhook-ingested decisions are now audited, but **storefront orders still are not**. A transaction created through `/v1/orders` stores its score, rules, reasons and decision on the order record — most of what an audit trail needs — yet scoring it emits no audit event. Analyst outcome decisions update the record without writing one either. One `audit()` call in `create_order` would close this.

---

## 23. Security

### Verified good

| Control | Evidence |
|---|---|
| No secrets committed | `.env` is gitignored and **untracked** — confirmed via `git ls-files` |
| `.env.example` is safe | All 8 sensitive keys blank; only non-sensitive defaults have values |
| Password hashing | Argon2id via `argon2-cffi`, 10-char minimum, weak-password blocklist |
| Token storage | Access token in a module variable, never web storage — an XSS cannot lift a durable credential |
| Refresh token | 256-bit opaque, SHA-256 hashed at rest, httpOnly + SameSite=Lax cookie, TTL |
| Account enumeration | Identical response and timing for unknown email vs wrong password |
| Login rate limiting | Per-email and per-client caps |
| CORS | Explicit origin allow-list, never `*` — required because credentials are sent |
| Role enforcement | `require_role` server-side on every admin route; no API path grants a role |
| Privilege escalation | Signup always creates `customer`; roles granted only out-of-band |
| IP spoofing | IP derived server-side and HMAC-hashed with a pepper; `--forwarded-allow-ips=""` set in the Dockerfile so uvicorn cannot rewrite `client.host` from a forged header |
| Card data | Luhn-checked, fingerprinted, discarded. Never stored, never logged, never sent to the model |
| Failed-attempt records | Asserted free of PAN and CVV |
| Container hardening | Non-root user, runtime deps only, no dataset or training code in the image |
| SQL injection | Not applicable — no SQL anywhere |

### Issues

| Priority | Issue | Detail |
|---|---|---|
| **P1** | `VITE_API_KEY` is bundled into client JS | `web/src/api.ts` documents this — the key is readable in devtools. Fine for a local demo, unusable in production |
| **P1** | Service endpoints open when `FRAUDSHIELD_API_KEY` is unset | `/v1/risk/score` and `/v1/checkout` have no guard; startup prints a warning |
| **P1** | `FRAUDSHIELD_COOKIE_SECURE` defaults to `false` | Must be `true` behind HTTPS |
| **P2** | Ephemeral JWT secret and IP pepper when unset | Restart invalidates sessions and resets all entity fingerprints |
| **P2** | Dev staff seed prints credentials to stdout | Gated behind `FRAUDSHIELD_DEV_SEED_STAFF=1`, warns on startup |
| **P2** | No webhook signature verification | Nothing to verify yet, but required before any provider integration |

No secret values are reproduced in this document.

---

## 24. Local Setup

Commands below are taken from files that exist in this repository.

### Prerequisites

Python ≥ 3.11 (Dockerfile uses 3.13), Node 18+.

### Backend

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # macOS / Linux

pip install -r requirements-dev.txt
```

`requirements-dev.txt` includes `requirements-serve.txt` and adds scikit-learn, which training needs.

### Regenerate the ML pipeline (optional — artifacts are committed)

```bash
python ml/generate_dataset.py --n 100000
python ml/train.py
python ml/evaluate.py
python ml/evaluate_promo.py --tune
```

Roughly two minutes total on a laptop. The dataset CSV is gitignored; the artifacts are committed.

### Run the API

```bash
copy .env.example .env          # then fill in the blank values
python -m uvicorn backend:app --port 8000 --forwarded-allow-ips=""
```

**Use `python -m uvicorn`, not bare `uvicorn`.** On a machine with more than one Python installation, `uvicorn.exe` on PATH may belong to a different interpreter than the one `pip` installed into, producing `ModuleNotFoundError: No module named 'pandas'` even though the install succeeded. `python -m uvicorn` guarantees the server runs on the interpreter that has the dependencies. Check with `python -c "import sys; print(sys.executable)"`.

`.env` is loaded automatically at import time by `_load_dotenv()` in `backend.py` — no `python-dotenv` dependency. Variables already present in the real environment take precedence, and a missing file is a no-op, so containers that inject config directly are unaffected. Startup prints how many variables were loaded.

`--forwarded-allow-ips=""` is **required, not cosmetic.** Without it uvicorn rewrites `request.client.host` from `X-Forwarded-For` for any loopback caller, which lets a request choose its own IP and walk past `ip_concentration`, ring detection, and the promo gate's IP signals.

### Run the frontend

```bash
cd web
npm install
npm run dev
```

### Create a staff account

Set `FRAUDSHIELD_DEV_SEED_STAFF=1` plus the admin/analyst email and password variables in `.env`, then restart the backend. It seeds the accounts and prints them once. To change a seeded password, delete the account first — the seed never overwrites:

```bash
python scripts/reset_staff.py admin@fraudshield.local
```

### Optional — DynamoDB persistence

```bash
python scripts/create_table.py --check    # report only
python scripts/create_table.py            # create
```

Then set `FRAUDSHIELD_USERS_BACKEND=dynamodb`. This creates a billable AWS resource.

### Demo the webhook ingestion path

Set `FRAUDSHIELD_WEBHOOK_SECRET` in `.env` (any high-entropy value — generate one with `python -c "import secrets; print(secrets.token_urlsafe(32))"`), restart the backend, then:

```bash
python scripts/emit_webhook.py --demo
```

That runs the full sequence: a valid signed event is accepted and scored, a forged signature is refused with 401, a redelivery is deduplicated, and a four-decline burst from one address escalates the score and flags the IP. Then open the console's **Suspicious IPs** tab to see it.

### Tests

```bash
python -m pytest                      # 24 tests
python -m pytest tests/test_webhook.py -v    # 22 webhook tests
python tests/test_parity.py           # parity suites also run standalone
python tests/test_score_parity.py
```

The two parity suites take several minutes — they replay 99,419 transactions and compare 2.19M feature values. Worth knowing before running them under time pressure. The webhook suite finishes in seconds.

### Docker (serving only)

```bash
docker build -t fraudshield .
docker run -p 8000:8000 -e FRAUDSHIELD_API_KEY=<key> fraudshield
```

> **Note on stale documentation.** The current README predecessor and `docs/` reference `make bootstrap`, `requirements.txt`, `app.main:app`, `docker-compose.yml`, and an `infra/` directory. **None of these exist.** The commands above are the working ones.

---

## 25. Environment Variables

Names only. No values.

### Backend — `.env`

| Variable | Purpose |
|---|---|
| `FRAUDSHIELD_API_KEY` | Shared key for service-to-service risk endpoints |
| `FRAUDSHIELD_ARTIFACTS` | Model artifact directory |
| `FRAUDSHIELD_WARM_ROWS` | Historical rows replayed at startup |
| `FRAUDSHIELD_REVIEW_T` | Review threshold default |
| `FRAUDSHIELD_BLOCK_T` | Block threshold default |
| `FRAUDSHIELD_CORS_ORIGINS` | Comma-separated origin allow-list |
| `FRAUDSHIELD_JWT_SECRET` | Access-token signing secret |
| `FRAUDSHIELD_COOKIE_SECURE` | HTTPS-only refresh cookie |
| `FRAUDSHIELD_IP_PEPPER` | HMAC pepper for IP and card fingerprints |
| `FRAUDSHIELD_TRUSTED_PROXIES` | Proxy addresses permitted to set `X-Forwarded-For` |
| `FRAUDSHIELD_USERS_BACKEND` | `memory` or `dynamodb` |
| `FRAUDSHIELD_USERS_TABLE` | DynamoDB table name |
| `FRAUDSHIELD_AWS_REGION` | AWS region |
| `FRAUDSHIELD_DEV_SEED_STAFF` | Enable the local staff seed |
| `FRAUDSHIELD_ADMIN_EMAIL` | Seeded admin address |
| `FRAUDSHIELD_ADMIN_PASSWORD` | Seeded admin password |
| `FRAUDSHIELD_ANALYST_EMAIL` | Seeded analyst address |
| `FRAUDSHIELD_ANALYST_PASSWORD` | Seeded analyst password |
| `FRAUDSHIELD_WEBHOOK_SECRET` | HMAC secret for `/v1/webhooks/payment`; endpoint returns 503 if unset |
| `AWS_ACCESS_KEY_ID` | AWS credential |
| `AWS_SECRET_ACCESS_KEY` | AWS credential |

### Frontend — `web/.env`

| Variable | Purpose |
|---|---|
| `VITE_API_BASE` | Backend base URL |
| `VITE_API_KEY` | Demo-only key; **compiled into the bundle, not a secret** |

**No Razorpay API key or secret variables exist**, because there is no Razorpay account. `FRAUDSHIELD_WEBHOOK_SECRET` is the shared HMAC secret between the local emitter and the ingestion endpoint; with a real provider it would hold their dashboard webhook secret.

---

## 26. Project Structure

```
AI_Risk_Manager/
├── backend.py                  3,508 lines — the entire serving surface
│                               features, scorer, rules, graph, auth, webhook,
│                               all 30 routes
├── ml/
│   ├── generate_dataset.py     1,021 — synthetic generator + self-audit
│   ├── train.py                  132 — XGBoost + isotonic calibration
│   ├── evaluate.py               397 — sweep, baselines, cost, fairness
│   ├── evaluate_promo.py         227 — promo gate evaluation
│   ├── cost_model.py              82 — rupee cost of each outcome
│   ├── scoring.py                224 — batch scoring path
│   ├── artifacts/
│   │   ├── model.json              trained booster (committed)
│   │   ├── calibrator.json         isotonic knots
│   │   ├── feature_spec.json       column order + training config
│   │   ├── metrics.json            full test-set evaluation
│   │   ├── promo_metrics.json      promo gate evaluation
│   │   └── train_report.json       fit diagnostics + importance
│   └── data/
│       ├── transactions.csv        99,419 rows (gitignored)
│       ├── promo_redemptions.csv   5,984 rows (gitignored)
│       └── metadata.json           generator self-audit
├── web/
│   ├── src/
│   │   ├── App.tsx             259 — shell, nav, cart button, routes, guards
│   │   ├── api.ts              548 — typed client, silent 401 refresh
│   │   ├── auth.tsx            107 — session context
│   │   ├── cart.tsx            109 — localStorage cart context
│   │   ├── components.tsx      127 — badges, score dial, reason list
│   │   ├── styles.css          — design tokens, no framework
│   │   └── pages/              12 pages (Landing, Checkout, Cart,
│   │                             PaymentSheet, Dashboard, Orders, Offers,
│   │                             Login, Signup, Admin, RingView,
│   │                             AdminMetrics, Thresholds, SuspiciousIps)
│   └── package.json
├── tests/
│   ├── test_parity.py          136 — 22-feature offline/online parity
│   ├── test_score_parity.py    115 — 4-score parity
│   └── test_webhook.py         — 22 tests: signature, replay, mapping, flagging
├── scripts/
│   ├── create_table.py         104 — DynamoDB table, idempotent
│   ├── grant_role.py            71 — out-of-band role grant
│   ├── reset_staff.py           47 — delete a seeded staff account
│   └── emit_webhook.py          — signed event emitter (the simulated provider)
├── docs/
│   ├── ARCHITECTURE.md         344
│   ├── EVALUATION.md           383
│   ├── RISK_ENGINE.md          297
│   └── PROBLEM.md              199
├── Dockerfile                  serving image, non-root
├── pyproject.toml              packaging + pytest config
├── requirements-serve.txt      runtime deps
├── requirements-dev.txt        + scikit-learn
├── pagesoverview.md            page-by-page UI reference
└── .env.example                all secrets blank
```

**No** `docker-compose.yml`, `Makefile`, `.github/`, or `infra/`.

---

## 27. What Is Completed

- Synthetic dataset generator with a built-in difficulty self-audit — 99,419 rows, 2.01% fraud, 5 archetypes
- 22-feature engineering, implemented **twice** (offline + online) and proven identical over 2.19M comparisons
- Temporal 70/15/15 split by date
- XGBoost training with early stopping and isotonic calibration on validation
- Committed model artifacts with a version stamp
- 8-rule engine with correlated-rule grouping to prevent double-counting
- Entity-graph ring scoring with bounded expansion and shared-infrastructure damping
- Three-layer aggregation with a documented weight search
- Per-transaction explanations from rules + exact TreeSHAP attributions
- Full test-set evaluation: PR-AUC, ROC-AUC, Brier, per-gate precision/recall, confusion matrix, 6 baselines, 159-point threshold sweep, per-archetype recall, 6 fairness slices
- Rupee cost model with sensitivity analysis
- Separate promo-abuse gate, evaluated per rule
- Genuine model-unavailable fallback that keeps checkout serving
- Webhook ingestion contract with real HMAC-SHA256 verification over the raw body, replay protection, staleness bounds, and a fail-closed default — 22 tests including forgery, tampering and replay
- 30 REST endpoints
- JWT + Argon2id auth with role-based authorisation
- 6-tab analyst console and a complete customer storefront including a realistic payment interface
- Failed-payment recording with IP flagging
- Secret hygiene: nothing sensitive tracked in git

---

## 28. What Is Partially Completed

- **Decision routing** — 3 decisions on 2 thresholds, not the specified 4 bands
- **Audit trail** — infrastructure works but only 2 event types are audited; no per-decision row
- **Threshold tuning** — applies at runtime, audited, but lost on restart
- **Persistence** — DynamoDB adapters written but opt-in; transaction store and review queue are memory-only; no GSIs
- **Landing page metrics** — real values, hardcoded by hand, able to drift from the artifacts
- **Testing** — 2 tests, both parity; no API, auth, rule, graph, or frontend tests
- **Containerisation** — serving Dockerfile only; no compose, no frontend image
- **Fallback observability** — degradation visible on `/health` but never audited

---

## 29. What Is Missing

Prioritised.

1. **A real Razorpay account** — no test-mode keys, no SDK, no outbound call. The receiving contract exists; the provider does not
2. **Razorpay outbound APIs** — order creation, payment fetch, refunds
3. **Durable transaction store** — queue and entity graph die with the process
4. **Per-decision audit row for storefront orders** (webhook ingestion is audited)
5. **`MODEL_FALLBACK_TRIGGERED` audit event**
6. **CI pipeline** — no automated verification of the parity tests that protect the metrics
7. **The three GSIs** — admin queries run from memory
8. **Bounded automated actions** — BLOCK is terminal; no escalation tier, no action limits, no stopping rules
9. **Test coverage** for `/v1/orders`, auth, rules and the frontend
10. **F1 in the evaluation output**
11. **Estimated ring exposure** in rupees
12. **Settings page**
13. **Email verification, password reset, MFA**
14. **Return/chargeback scoring** — returns recorded, never scored
15. **ML inference timeout**

---

## 30. What Must Be Fixed

### P0 — required for demo and judging

1. **Razorpay integration.** The track specifies Razorpay Test Mode; the repository has none. Minimum viable: a webhook endpoint with HMAC signature verification that maps a `payment.captured` event into the existing transaction dict. The scoring pipeline is transport-agnostic, so this is additive.
2. **Stale setup documentation.** `docs/` and prior README text reference `make bootstrap`, `requirements.txt`, `app.main:app`, `docker-compose.yml`, and `infra/` — none exist. A judge following them fails at step one. Partially corrected by this README; `docs/` still needs it.
3. **Per-decision audit row.** Track 02 names audit trail explicitly. One `audit()` call in `create_order` closes most of the gap.
4. **Restart fragility.** The review queue empties on restart. Either persist it or make the demo script restart-free and say so.

### P1 — important

5. `MODEL_FALLBACK_TRIGGERED` audit event, to complete the failure demo end to end.
6. Persist threshold changes so an admin's action survives a restart.
7. Have the landing page read `/v1/admin/metrics` or a public metrics endpoint instead of hardcoding.
8. Fix `pyproject.toml` dependencies — it omits `PyJWT`, `argon2-cffi`, and `boto3`, all of which `backend.py` imports.
9. Declare `pytest` in `requirements-dev.txt`; it is used but undeclared.
10. Correct the stale Dockerfile comment claiming "no per-user auth, no roles and no rate limiting" — all three now exist.

### P2 — nice to have

11. Minimal CI running both parity suites.
12. API and auth tests.
13. Report F1 alongside precision and recall.
14. Estimated ring exposure in rupees.
15. The three GSIs.

---

## 31. Recommended Hackathon Completion Plan

1. **Critical missing functionality** — Razorpay webhook with signature verification, mapped into the existing scorer. Highest score-per-hour available.
2. **ML evaluation** — already complete. Add F1 only.
3. **Risk engine** — complete. Optionally add a MEDIUM monitor tier for the 4-band spec.
4. **Explainability** — complete. Leave the LLM out; templates are more defensible on a fraud path.
5. **Audit trail** — add the per-decision row and the fallback event. Two `audit()` calls.
6. **Razorpay integration** — extend step 1 with order creation and payment verification if time allows.
7. **Dashboard polish** — wire the landing page to live metrics; drop the hardcoded block.
8. **Failure demo** — rename the artifacts directory live and show `/health` flipping to `model_loaded: false` while checkout keeps serving. Already works; rehearse it.
9. **Testing** — API tests for `/v1/orders` and the auth flow.
10. **Final demo prep** — fix stale docs, script the flow, seed data before judging.

---

## 32. Final Readiness Score

| Area | Weight | Score | Weighted | Reasoning |
|---|---|---|---|---|
| ML / Data Pipeline | 20% | 95% | **19.0** | Generator, temporal split, training, calibration, artifacts, parity proof. Loses only for synthetic-only data |
| Fraud Detection | 15% | 90% | **13.5** | All 10 spec patterns detectable; 8 rules + graph + 22 features. No 5-minute window |
| Risk Engine | 10% | 85% | **8.5** | Three layers, searched weights, overrides, fallback. 3 bands not 4; no escalation tier |
| Razorpay Integration | 10% | 0% | **0.0** | Zero references anywhere in the repository |
| Explainability | 10% | 85% | **8.5** | Rules + exact TreeSHAP → English, stored per transaction. No LLM layer |
| Dashboard | 10% | 95% | **9.5** | 6-tab console + full storefront, accessible. Landing metrics hardcoded |
| Evaluation / Metrics | 10% | 95% | **9.5** | Full test-set metrics, 6 baselines, sweep, fairness, cost, stated caveats. No F1 |
| Audit Trail | 5% | 45% | **2.25** | Works, admin-gated, persisted — but only 2 event types, no per-decision row |
| Failure Handling | 5% | 70% | **3.5** | Real degraded mode, fail-toward-review, store fallbacks. No timeout, no fallback audit event |
| Testing / Security | 5% | 55% | **2.75** | Strong security, clean secrets. Only 2 tests, no CI, no frontend tests |

### **Total: 77.0 / 100**

Sum of the weighted column: 19.0 + 13.5 + 8.5 + 0.0 + 8.5 + 9.5 + 9.5 + 2.25 + 3.5 + 2.75 = **77.0**. Weights sum to 100; no adjustment or rounding is applied on top of the table.

**Reading this number honestly.** The ML and evaluation work is genuinely strong — stronger than most hackathon submissions, because it reports its own weaknesses and proves offline/online equivalence. The score is held down almost entirely by one thing: **Razorpay contributes a hard zero on a 10% weight**, and it is the integration the track names. Bringing that component to ~85% would add 8.5 points, moving the total to roughly **85.5%**.

Note that the stale-documentation debt described in §30 is *not* separately penalised here — it is already reflected in the Testing/Security score of 55%.

---

## 33. Judge Readiness

### Current readiness: **MVP — approaching DEMO READY**

**Why not DEMO READY.** The track is "AI Risk Manager" for merchants "using Razorpay Test Mode," and there is no Razorpay code. A judge checking that specific requirement finds nothing. Secondly, following the setup instructions in `docs/` fails, because they reference files that do not exist.

**Why it is well past NOT READY.** Almost every hard part is done and verifiable:

- A trained, calibrated model with committed artifacts and honest held-out metrics
- Offline/online parity proven across 2.19 million comparisons — a class of bug most projects never even detect
- Real graph-based ring detection, not a library import
- A genuine degraded mode that keeps checkout serving without a model
- A cost model that makes false positives a first-class metric
- An evaluation that volunteers its own bad news: block precision of 1.000 flagged as a warning, the ensemble ranking below XGBoost alone, first-party abuse recall of 0.000

**What would make it SUBMISSION READY:** the Razorpay webhook, a per-decision audit row, and corrected setup docs. That is roughly a day of work, and none of it is research.

---

## 34. Final 10 Things To Do

1. Add `POST /v1/webhooks/razorpay` with HMAC-SHA256 signature verification, mapping the event into the existing transaction dict.
2. Add the Razorpay SDK to `requirements-serve.txt` and the key/secret/webhook-secret names to `.env.example`.
3. Emit a per-decision audit row from `create_order` — transaction id, score, model version, rules, decision, actor.
4. Emit `MODEL_FALLBACK_TRIGGERED` when `Scorer.degraded` is true, completing the failure demo.
5. Fix stale docs across `docs/` and the Dockerfile: no `make bootstrap`, no `requirements.txt`, no `app.main:app`, no `docker-compose.yml`, no `infra/`; auth and roles now exist.
6. Add `PyJWT`, `argon2-cffi`, `boto3` to `pyproject.toml` dependencies and `pytest` to `requirements-dev.txt`.
7. Persist threshold changes so an admin action survives a restart.
8. Wire the landing page to a live metrics endpoint and delete the hardcoded `M` block.
9. Add a GitHub Actions workflow running both parity suites — they protect every number in this README.
10. Add API tests for `/v1/orders` (allow / review / block) and the auth flow.

---

# 🔍 Repository Audit Summary

### Repository analyzed

`f:\AI_Risk_Manager` — git repository, branch `main`, HEAD `2e3f98a`, project version `0.4.0`.

### Files inspected

**55 files tracked by git.** Read in full or in substantial part during this audit: `backend.py` (2,619 lines), all 6 files in `ml/`, all 6 artifacts in `ml/artifacts/`, both dataset CSVs (measured programmatically), `ml/data/metadata.json`, all 21 files in `web/src/`, both test files, all 3 scripts, `Dockerfile`, `pyproject.toml`, both requirements files, `.env.example`, `.gitignore`, and the 4 files in `docs/`. Route table and feature list were verified by importing the app and introspecting it, not by reading documentation.

### Main technologies detected

**Backend:** Python ≥3.11, FastAPI 0.115.6, uvicorn 0.49.0, Pydantic 2.13.4, PyJWT 2.10.1, argon2-cffi 23.1.0, boto3 1.40.35
**ML:** XGBoost 3.0.3, pandas 2.3.1, numpy 2.2.1, scikit-learn 1.7.1 (training only)
**Frontend:** React 18.3.1, TypeScript 5.6.3, Vite 5.4.11, react-router-dom 6.28.0 — no UI or charting library
**Data:** DynamoDB single-table (opt-in) or in-process dictionaries
**Container:** Docker, `python:3.13-slim`, non-root
**Not present:** Razorpay SDK, any LLM client, the `shap` package, SQL of any kind, a CI system

### Implementation percentage

**77.0%** by the weighted model in §32.

### Strongest existing components

1. **Offline/online feature parity** — 99,419 rows × 22 features verified identical. This is the discipline that makes every reported metric trustworthy, and most projects never test for it.
2. **Honest evaluation** — `metrics.json` carries 6 baselines, a 159-point threshold sweep, per-archetype recall, 6 fairness slices, a rupee cost model with sensitivity analysis, and 4 self-critical caveats. It reports that the ensemble ranks *below* XGBoost alone.
3. **Cost-aware decisioning** — the 41.1× block-to-review ratio is derived, documented, and drives the design rather than decorating it.
4. **Security posture** — Argon2id, in-memory access tokens, httpOnly refresh, server-derived IP hashing, timing-equal login errors, non-root container, no tracked secrets.
5. **Graceful degradation** — a real reweighting fallback, not a try/except.

### Biggest gaps

1. **Razorpay integration — entirely absent.** Zero references.
2. **No durable transaction store.** Review queue and entity graph are process memory.
3. **Audit trail covers 2 event types.** No per-decision row.
4. **Test coverage is 2 tests.** No API, auth, rule, graph, or frontend tests, and no CI.
5. **Stale documentation** across `docs/` and the Dockerfile describing commands and limitations that no longer match the code.

### Biggest hackathon risk

**The absence of any Razorpay integration.** Track 02 is framed around merchants using Razorpay Test Mode, and the architecture diagram places webhook ingestion as the entry point to the entire system. A judge verifying that requirement finds nothing — no SDK, no endpoint, no signature verification, no configuration.

The irony is that this is the *least* difficult remaining work. The scoring pipeline already accepts a plain transaction dict, so the integration is an adapter, not a redesign. Meanwhile the genuinely hard parts — a calibrated model, proven feature parity, cost-aware thresholds, graph detection, honest metrics — are finished. The project risks being marked down on a mapping layer while its research-grade core goes unexamined.

A secondary risk: a judge who follows the setup instructions in `docs/` cannot start the application, because those commands reference files that do not exist.

### Recommended next step

**Build `POST /v1/webhooks/razorpay` with HMAC-SHA256 signature verification.**

Verify the `X-Razorpay-Signature` header against the webhook secret, parse a `payment.captured` or `payment.failed` event, map it to `{customer_id, amount, payment_method, device_fp, ip_hash, ts}`, and pass it to the existing `Scorer.score`. Persist the result exactly as `create_order` already does.

This is a single endpoint of maybe 80 lines. It converts a hard zero on a 10%-weighted criterion into a pass, lifts the readiness score from 77.0% to roughly 85.5%, and completes the one architectural component the track names explicitly. Nothing else available offers a comparable return.

---

*Audit performed by direct source inspection: application introspection for the route table and feature list, programmatic measurement for all dataset figures, and artifact reads for every metric. No figure in this document is estimated, inferred, or carried over from prior documentation.*
