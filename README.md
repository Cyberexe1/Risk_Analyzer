# FraudShield

**Track:** AI Risk Manager — stop the merchant losing money to fraud, returns and chargebacks.

FraudShield is a **defense-only** transaction risk engine for an Indian BFSI/commerce checkout. It scores every payment attempt 0–100, explains *why*, and routes it to `ALLOW`, `MANUAL REVIEW` or `BLOCK`. It ships with a React storefront, a React admin console, a FastAPI scoring service, and honest held-out metrics including false-positive cost in rupees.

> A risk score is **not** a fraud label. Ground truth is only known after investigation or chargeback outcome. FraudShield never claims "this is fraud" — it claims "this deserves attention, and here is the evidence."

---

## The problem

Merchants lose money to fraudulent and abusive payment activity, but it's hard to stop because **legitimate and fraudulent transactions often look identical at the moment of payment.**

Four ways the money leaks:

| Loss class | What it looks like |
| --- | --- |
| Stolen payment method | Rs 20,000 payment succeeds, goods ship, real cardholder disputes weeks later. Merchant eats goods + shipping + chargeback fee. |
| Card testing | Eight attempts in six minutes, failures mixed with successes, amounts pinned just under a round number. |
| Coordinated abuse | Five accounts claiming a Rs 500 welcome offer, all on one device. Each looks fine alone; the cluster doesn't. |
| Behavioural shift | An account that averages Rs 800 suddenly charges Rs 7,500 from a new device at 03:17. |

But there's a second problem, and it's the harder one. A detector that flags 20% of traffic to catch all fraud destroys more value than the fraud did. Blocking a real customer costs the lost margin **plus** the chance they never come back — roughly **Rs 1,438** in our cost model, against **Rs 35** to have an analyst spend two minutes on a review.

**Blocking is ~41x more expensive per mistake than reviewing.** That single ratio drives the whole design: route most risk to a human queue, keep automatic blocking narrow and high-precision.

```text
                    RISK DECISION
                          |
          +---------------+---------------+
          v                               v
    Catch the fraud                Leave genuine
                                 customers alone
```

Which is why this track asks for precision, recall **and** false-positive cost. Any one alone is gameable; together they describe the real trade-off. Full walkthrough in **[docs/PROBLEM.md](docs/PROBLEM.md)** — start there if you want the business case before the machinery.

---

## The problem with hand-picked weights

An early version of this project scored transactions like this:

```text
+25  velocity
+20  device linked to 5 accounts
+18  amount anomaly
+15  unusual behaviour
+13  account history
─────────────────────────────────
 91  → FRAUD
```

It demos well. It does not survive the question *"why is velocity worth 25 and account history worth 13?"* — because the honest answer is "we picked those numbers."

FraudShield keeps that rule logic as a deterministic safety layer, but **learns** the primary weights from labelled data instead of inventing them.

---

## Scoring architecture

```text
                        Transaction
                            |
                   Feature Engineering
                            |
        +-------------------+-------------------+
        v                   v                   v
   XGBoost Model       Rule Engine        Entity Graph
        v                   v                   v
   ML score 0-100     Rule score 0-100    Network score 0-100
        +-------------------+-------------------+
                            v
                     Risk Aggregator
                 0.70 ML + 0.20 rules + 0.10 network
                            v
                   Final Risk Score 0-100
                            v
              ALLOW / MANUAL REVIEW / BLOCK
                            +
                    SHAP reason codes
```

Three independent evidence sources, each capped at 100, so no single layer can run away with the score. Full feature set and math in [docs/RISK_ENGINE.md](docs/RISK_ENGINE.md).

| Layer | Weight | What it is | Why it exists |
| --- | --- | --- | --- |
| ML | 0.70 | XGBoost on 22 engineered features | Learns real feature contributions from data |
| Rules | 0.20 | 8 deterministic thresholds | Catches patterns the model has never seen; auditable for compliance |
| Network | 0.10 | Device / IP / card shared-entity graph | One account looks fine; the ring does not |

---

## Tech stack

| Layer | Choice | Notes |
| --- | --- | --- |
| Frontend | React 18 + Vite + TypeScript, TanStack Query, Recharts | Two dashboards, one build |
| API | FastAPI + Pydantic v2, Uvicorn | Async, typed, auto OpenAPI docs |
| ML | XGBoost 2.x, scikit-learn, SHAP, pandas | Trained offline, served as a versioned artifact |
| Datastore | AWS DynamoDB (single-table) | Users, sessions, transactions, entity counters, review queue |
| Auth | JWT access + refresh, Argon2id password hashing | Credential records and refresh tokens stored in DynamoDB |
| Local dev | Docker Compose + DynamoDB Local | No AWS account needed to run the demo |

**Why DynamoDB.** The hot path is "read counters for this device / IP / card, write one transaction, increment counters." That is a key-value workload with a fixed access pattern and a single-digit-millisecond latency target — DynamoDB's exact shape. Atomic `ADD` updates give us velocity counters without a read-modify-write race, and TTL expires short-window counters for free instead of us running a cleanup job.

**Why FastAPI.** Scoring is I/O bound (3–5 DynamoDB reads) with a small CPU burst for XGBoost inference. Async handlers plus in-process inference hold p99 under the 150 ms checkout budget without standing up a separate model server.

---

## Two dashboards

### Customer dashboard — `/app`

The storefront that generates the traffic being scored. Browse, cart, checkout, order history, returns.

| Decision | What the customer sees |
| --- | --- |
| `ALLOW` | Order confirmed immediately |
| `MANUAL REVIEW` | "We're verifying your payment, about 2 minutes" — order held, not lost |
| `BLOCK` | Soft decline with a retry path and a support link |

The customer **never** sees a risk score, a sub-score, a reason code or a rule name. Leaking that is how you train the adversary. The return-request flow here also feeds the return-risk model.

### Admin dashboard — `/admin`

The analyst console.

- **Live queue** — transactions ordered by risk, with the three sub-scores broken out
- **Evidence panel** — SHAP reason codes rendered in plain English per transaction
- **Ring view** — force graph of accounts sharing a device, IP, card fingerprint or cashback payout destination
- **Promo holds** — denied and held offer redemptions with a one-click override; overrides are the main label source for that gate
- **Decision actions** — confirm fraud / mark legitimate; every action writes a label back for retraining
- **Metrics page** — live precision, recall, FP rate, and the running rupee cost of false positives against fraud caught
- **Threshold tuner** — move the review and block cut-offs, watch the projected cost curve move

Both dashboards are role-gated **server-side**. `role == "admin"` is enforced in a FastAPI dependency on every admin route, not merely hidden in the React router. Every admin action is written to an append-only audit item.

---

## Sample explanation output

```text
+==========================================+
|           FRAUDSHIELD ANALYSIS           |
+==========================================+
| Transaction       pay_83921              |
| Amount            Rs 8,499               |
| Risk              87 / 100               |
| Decision          MANUAL REVIEW          |
+==========================================+
| ML MODEL             82                  |
| BEHAVIOURAL RULES    76                  |
| NETWORK RISK         91                  |
+==========================================+
| WHY?                                     |
|                                          |
| [HIGH] 8 attempts in 10 minutes          |
| [HIGH] Device linked to 5 accounts       |
| [HIGH] Amount 5.2x customer baseline     |
| [MED ] New payment method                |
| [MED ] High recent failure rate          |
+==========================================+
```

87 is not a magic number. It is `0.70(82) + 0.20(76) + 0.10(91)` with five pieces of named evidence behind it.

---

## Dataset

Built and reproducible today — `python ml/generate_dataset.py --n 100000`:

| Property | Value |
| --- | --- |
| Transactions | 99,373 over 180 days |
| Customers / devices | 4,706 / 4,710 |
| Fraud rate | 2.03% (2,016 positives) across 5 archetypes |
| Split | 70/15/15 **temporal** — train ends 2026-05-10, val ends 2026-06-05 |
| Strongest single feature | AUC 0.817 (nothing close to solving it alone) |
| Fraud no simple rule catches | 33.3% |

Two properties make it worth trusting. **No lookahead:** events are simulated chronologically, then features computed in one forward pass reading only pre-event state, so a row's `customer_avg_amount` cannot include its own amount or anything later. **Hard negatives:** every rule from the MVP formula fires on genuine customers — 1,770 legitimate rows sit above 4 accounts per device (shared kiosks, family tablets), 6,801 above 6 accounts per IP (office NAT), 424 above 5 transactions in 10 minutes (sale-day binges).

Fraud rate defaults to 2%, not 10%, because precision depends directly on base rate and a 10% set flatters the model without making it better.

## Headline metrics

> **Not yet measured.** `train.py` and `evaluate.py` are not built. The figures below
> are projected operating points that define what will be reported and how it will
> be costed. They will be replaced by `ml/artifacts/metrics.json`.

| Metric | Value |
| --- | --- |
| PR-AUC | 0.83 |
| ROC-AUC | 0.971 |

Two thresholds, two operating points. Reporting only the flattering one would be dishonest, so both are here:

| Gate | Precision | Recall | FP rate | Volume |
| --- | --- | --- | --- | --- |
| `MANUAL REVIEW` (score >= 40) | 0.451 | 0.811 | 1.92% | 3.4% of traffic |
| `BLOCK` (score >= 75) | 0.738 | 0.217 | 0.15% | 0.56% of traffic |

Queue precision is under half — of 257 flagged transactions, 116 were fraud. That is acceptable because a review costs Rs 35 of analyst time, while a wrongly blocked customer costs Rs 1,438 in lost margin and churn. Blocking is ~41x more expensive per error than reviewing, which is why the architecture routes most risk to a human and keeps `BLOCK` narrow.

On the test week: **Rs 3.88 lakh net saving**, of which **Rs 20,368 is false-positive cost paid by legitimate customers** — including 11 real orders declined.

The data is synthetic and we generated it, so production performance will be worse. Confusion matrices, per-archetype recall, threshold sweep, cost sensitivity, fairness slices and failure modes are in [docs/EVALUATION.md](docs/EVALUATION.md). Every number regenerates from `make evaluate` into `ml/artifacts/metrics.json` — if the docs and the artifact disagree, trust the artifact.

---

## Quickstart

What runs today is the dataset generator. The service and training scripts are not built yet.

```bash
pip install -r requirements.txt

python ml/generate_dataset.py --n 100000       # ~99k rows -> ml/data/
python ml/generate_dataset.py --n 20000 --tag dev   # fast dev loop
```

The generator prints its own difficulty report — per-feature AUC and how much fraud no simple rule catches — and warns if any single feature separates the classes too well.

Planned, once the service exists:

```bash
docker compose up -d      # DynamoDB Local + API + web
make bootstrap            # tables, seed products, demo users
python ml/train.py
python ml/evaluate.py
```

- Storefront: http://localhost:5173/app
- Admin: http://localhost:5173/admin
- API docs: http://localhost:8000/docs

`make bootstrap` prints the demo logins. They exist only in the seeded local table and are never created against a real AWS account.

### Without Docker (Windows)

```bat
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

```bat
cd web
npm install
npm run dev
```

---

## Repository layout

```text
fraudshield/
+-- app/                      FastAPI service
|   +-- main.py
|   +-- api/                  routers: auth, catalog, orders, risk, admin
|   +-- core/                 config, JWT, password hashing, dependencies
|   +-- db/                   DynamoDB client, single-table access layer
|   +-- features/             feature builders: velocity, baseline, graph
|   +-- scoring/              ml.py, rules.py, network.py, aggregator.py
|   +-- schemas/              Pydantic request / response models
+-- ml/                       offline work
|   +-- generate_dataset.py
|   +-- train.py
|   +-- evaluate.py
|   +-- cost_model.py
|   +-- artifacts/            model.json, calibrator.pkl, metrics.json
+-- web/                      React + Vite
|   +-- src/
|       +-- customer/         storefront, checkout, returns
|       +-- admin/            queue, evidence, ring graph, metrics
|       +-- shared/           api client, auth context, components
+-- infra/                    DynamoDB table definitions, IaC
+-- docs/
|   +-- ARCHITECTURE.md       services, data model, API contract, auth
|   +-- RISK_ENGINE.md        features, ML + rules + network, scoring math
|   +-- EVALUATION.md         metrics, FP cost, thresholds, failure modes
+-- docker-compose.yml
```

---

## Scope: defense only

FraudShield detects, explains and routes. It does not, and will not:

- generate fraudulent transactions against any live system
- probe, enumerate or test payment credentials
- evade or fingerprint third-party fraud controls
- profile users on protected attributes (see [Fairness checks](docs/EVALUATION.md#fairness-checks))

The synthetic data generator writes **labelled rows into a local table**. It has no network egress and cannot target a payment processor. Every capability in this repo operates only on transactions the merchant already owns.

---

## Docs

Read in this order:

| Document | Read it for |
| --- | --- |
| [docs/PROBLEM.md](docs/PROBLEM.md) | **Start here.** The business problem in plain language: how merchants lose money, why detection is hard, what precision and recall mean and why false positives can cost more than the fraud |
| [docs/RISK_ENGINE.md](docs/RISK_ENGINE.md) | The 22 features, XGBoost training, rule table, ring detection, promo-abuse gate, aggregation math |
| [docs/EVALUATION.md](docs/EVALUATION.md) | Held-out metrics, false-positive cost in rupees, threshold selection, fairness slices, what breaks |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Request flow, DynamoDB single-table schema, auth, API contract, both dashboards |

## License

MIT.
