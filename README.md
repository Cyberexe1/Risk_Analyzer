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

Measured on the held-out test split (14,913 transactions, 342 fraud, 2.29%). Regenerate with `python ml/train.py && python ml/evaluate.py`.

| Metric | Value |
| --- | --- |
| PR-AUC | **0.788** (validation 0.874) |
| ROC-AUC | 0.940 — inflated by the 98% negative class |
| Brier, calibrated | 0.0071, down from 0.0269 raw |

Two thresholds, two operating points. Reporting only the flattering one would be dishonest:

| Gate | Precision | Recall | FP rate | Volume |
| --- | --- | --- | --- | --- |
| `MANUAL REVIEW` (>= 5) | 0.370 | 0.789 | 3.15% | 4.89% of traffic |
| `BLOCK` (>= 70) | 1.000 | 0.553 | 0.00% | 1.27% of traffic |

**Cost:** Rs 12.14 lakh loss if nothing is done, Rs 2.75 lakh with FraudShield — **Rs 9.40 lakh saved (77.4%)**. Of the remaining cost, Rs 16,065 is false-positive cost: 459 legitimate customers sent to review, zero blocked.

Three results that are not flattering, and matter more than the ones above:

- **Block precision of 1.000 is a warning, not a win.** Zero false positives on 189 blocks means the synthetic generator's high-confidence fraud is too cleanly separable. Card-testing and ring recall both land at exactly 1.000. Real traffic will not behave this way.
- **The ensemble is worse than XGBoost alone on ranking** — 0.788 vs 0.800 PR-AUC, precision 0.370 vs 0.675. The rule layer's floor contribution alone clears a review threshold of 5, dragging in legitimate rows the model had correctly ranked near zero. The rules and network layers earn their place on auditability and cold start, not accuracy.
- **First-party abuse recall is 0.000.** Those rows are genuinely normal transactions that were relabelled, so there is nothing to detect. They plus refund abuse account for 70 of the 72 missed frauds, and missed fraud is 93% of all remaining cost. Better transaction scoring cannot fix this; it needs post-purchase evidence.

Also worth knowing: the review threshold is set by **analyst capacity, not model quality**. At 100:1 cost asymmetry the optimiser always wants to review more, so `evaluate.py` enforces a queue-rate ceiling and the threshold sits against it.

Full confusion matrices, per-archetype recall, threshold sweep, fairness slices and failure modes in [docs/EVALUATION.md](docs/EVALUATION.md). If the docs and `ml/artifacts/metrics.json` disagree, trust the artifact.

---

## Offline/online parity

Every metric above came from a batch pass over a sorted file. Production gets one transaction and whatever counters earlier traffic left behind. If those disagree, the metrics describe something unshippable — so it's tested:

```text
tests/test_parity.py         99,419 rows x 22 features = 2,187,218 comparisons  -> agree
tests/test_score_parity.py   30,000 rows x 4 scores                            -> agree
```

`backend.py::build_online_features` is an independent reimplementation of the generator's forward pass. Merging the two into a shared helper would make the test pass while proving nothing, so there's a warning block at the top of `backend.py`. The scorer never writes state; `store.commit()` is the caller's job afterwards, so a read-after-write bug shows up instantly as a velocity mismatch.

Caveat: DynamoDB can't hold an exact trailing-600-second deque, so the planned bucketed windows will diverge from these results. That needs its own measurement before it's trusted.

## Quickstart

The ML pipeline and the scoring API run today. The DynamoDB adapter, JWT auth and React dashboards do not.

```bash
pip install -r requirements-dev.txt        # serve deps + scikit-learn

python ml/generate_dataset.py --n 100000   # ~99k rows -> ml/data/
python ml/train.py                         # -> ml/artifacts/model.json + calibrator
python ml/evaluate.py                      # -> ml/artifacts/metrics.json

python tests/test_parity.py                # offline/online feature parity
python tests/test_score_parity.py          # offline/online score parity
```

Run the service:

```bash
set FRAUDSHIELD_API_KEY=devkey
python -m uvicorn backend:app --port 8000
```

Startup replays the **train split only** into the entity store, so device, IP and velocity counters are warm — warming from validation or test would leak the evaluation period into serving state. Docs at http://localhost:8000/docs.

Run the frontend (needs the backend up):

```bash
cd web
npm install
npm run dev          # http://localhost:5173
```

Three pages:

| Route | What it is |
| --- | --- |
| `/` | Landing page: the problem, the three-layer design, and the measured metrics including the unflattering ones |
| `/signup` | Create an account. Live password strength, confirm field, show/hide toggle |
| `/login` | Log in. Returns you to wherever you were headed |
| `/checkout` | Storefront. Requires sign-in, because the account is what the risk engine builds history against. Creates a **real, persisted, scored order** |
| `/orders` | Customer dashboard: order history, payment status, return-request flow |
| `/offers` | Claim a cashback. Toggle "shared device" to watch the promo gate refuse the 2nd through 5th claim |
| `/admin` | Analyst console, two tabs: transaction queue and promo holds. **Requires `analyst` or `admin`**, enforced server-side |

The header shows **Log in** and **Sign up** when anonymous, and your email, role badge and **Log out** once signed in. The Console link only appears for staff — but that's a courtesy, not a control: the backend checks the role on every admin request.

The same order endpoint returns different things by role. A customer gets status and a message; staff additionally get the risk breakdown. Verified: a customer's order history contains **no** `risk_score`, `decision`, `sub_scores` or `reason_codes` fields at all — they're stripped server-side by an allow-list, not hidden in the client.

To reach the console locally, set `FRAUDSHIELD_DEV_SEED_STAFF=1` and the backend prints a seeded analyst login with a random password at startup. Local development only.

The checkout page puts both projections side by side on purpose. In production they are never on one screen: the shopper gets `{"status":"declined"}` and nothing else, while the analyst gets the score, all three sub-scores and every reason code. Seeing them together makes the split legible.

A card-testing burst against one device, nine attempts 35 seconds apart:

```text
 1  failed  score 51.6  MANUAL_REVIEW  ml  72.2  rules  5.0  net 0.0
 2  failed  score 71.0  BLOCK          ml 100.0  rules  5.0  net 0.0
 ...
 7  failed  score 75.0  BLOCK          ml 100.0  rules 25.0  net 0.0
```

The rule layer only joins at attempt 7, when `velocity_breach` crosses 5-in-10-minutes. The model had it at attempt 2. Same transaction through `/v1/checkout` returns `{"status":"declined","message":"We couldn't process this payment..."}` — no score, no sub-score, no reason code. Telling an attacker which signal fired is free reconnaissance.

Roughly two minutes total on a laptop. The generator prints its own difficulty report — per-feature AUC and how much fraud no simple rule catches — and warns if any single feature separates the classes too well. `evaluate.py` prints the full threshold sweep, baseline comparison, cost breakdown, fairness slices and one worked SHAP explanation.

### Configure

```bash
copy .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(32))"   # paste into .env
```

`.env` and `web/.env` are gitignored; `.env.example` is committed and holds no secrets.

Useful flags:

```bash
python ml/generate_dataset.py --n 20000 --tag dev   # fast iteration loop
python ml/generate_dataset.py --fraud-rate 0.10     # demo mode, warns about base rate
python ml/evaluate.py --max-review-rate 0.02        # tighter analyst capacity
```

- App: http://localhost:5173
- API docs: http://localhost:8000/docs

There is no `docker compose` for the full stack and no `make bootstrap` — the backend has a `Dockerfile`, the frontend does not, and there is no orchestration tying them together with the table.

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

## Deployment

The whole serving path is one module, `backend.py` (~1,050 lines). Deploying means shipping that file plus three model artifacts.

```bash
docker build -t fraudshield .
docker run -p 8000:8000 -e FRAUDSHIELD_API_KEY=<secret> fraudshield
```

Or install it:

```bash
pip install .          # -> import backend works from any directory
uvicorn backend:app
```

What the image deliberately does **not** contain: the dataset generator, the trainer, the evaluator, the batch scorer, the test suite, or the 20 MB dataset CSV. None of it runs in production, and a payment-path container has no business carrying a dataset generator.

It also doesn't contain scikit-learn. That's only needed to *fit* the isotonic calibrator; serving reads the fitted knots from `calibrator.json` and interpolates with numpy. Six runtime dependencies total.

One dependency is inverted on purpose: `build_matrix` lives in `backend.py` and `ml/train.py` imports it from there, rather than the reverse. Serving code is canonical. Two copies of the log1p transforms and column ordering would eventually drift, and the served model would silently score a different matrix than the one it was fitted on — a bug that produces plausible numbers and no error.

Configuration is environment-driven, so nothing needs a code change to deploy:

| Variable | Default | Purpose |
| --- | --- | --- |
| `FRAUDSHIELD_API_KEY` | *unset* | **Unset means every endpoint is open.** Startup warns. |
| `FRAUDSHIELD_ARTIFACTS` | `ml/artifacts` | Where `model.json` and friends live |
| `FRAUDSHIELD_WARM_ROWS` | `40000` | History replayed into the store at boot; `0` in Docker |
| `FRAUDSHIELD_REVIEW_T` | `5` | Review threshold — an ops parameter, not a model property |
| `FRAUDSHIELD_BLOCK_T` | `70` | Block threshold |
| `FRAUDSHIELD_CORS_ORIGINS` | `localhost:5173` | Explicit allow-list, never `*` |
| `VITE_API_BASE` | `localhost:8000` | Frontend → backend (in `web/.env`) |
| `VITE_API_KEY` | *unset* | **Compiled into the JS bundle. Not a secret.** |

`VITE_API_KEY` is worth dwelling on: anything with a `VITE_` prefix is baked into the built JavaScript and readable by anyone who opens devtools. It exists so the local demo can reach the local backend. In production the browser must never hold the backend key — put a session-authenticated server between them, or implement the JWT flow in [ARCHITECTURE.md §4](docs/ARCHITECTURE.md) and drop the shared key entirely.

### DynamoDB

The table is live: `fraudshield` in `ap-south-1`, `PAY_PER_REQUEST`, TTL enabled on `ttl`. It holds users, refresh tokens, orders and returns.

```bash
python scripts/create_table.py --check   # report only
python scripts/create_table.py           # create if absent, idempotent
```

Then `FRAUDSHIELD_USERS_BACKEND=dynamodb`. Verified across a restart: account, 8 orders and 1 return all survived.

What is **not** in DynamoDB yet: the transaction and entity-counter items, and the review queue. Those still live in process memory, so a restart loses the queue and cools the entity graph — network risk under-scores until traffic rebuilds it. The three GSIs from [ARCHITECTURE.md §3](docs/ARCHITECTURE.md) are also not created, since nothing reads them while the queue is in memory.

### Before this goes anywhere real

**Set `FRAUDSHIELD_COOKIE_SECURE=true` and `FRAUDSHIELD_JWT_SECRET`.** Without the first, the refresh cookie travels over plain HTTP. Without the second, a random key is generated per process: every restart invalidates all sessions, and two uvicorn workers reject each other's tokens.

**On AWS credentials.** Long-lived IAM user keys are the riskiest credential type — they don't expire, and a leak is a standing breach. Prefer an instance/task role and leave the keys blank. If you must use static keys, scope the IAM policy to `GetItem/PutItem/UpdateItem/Query/DeleteItem` on the one table and rotate on a schedule. Never give them a `VITE_` prefix; Vite compiles every `VITE_*` variable into the browser bundle, which would publish your AWS credentials to every visitor.

**A fresh container starts with a cold entity graph.** `WARM_ROWS=0` because the CSV isn't in the image, and there's no DynamoDB adapter for the *transaction* store yet. Network risk under-scores until traffic accumulates.

Still missing from the auth layer: email verification, password reset, and MFA.

## Repository layout

```text
fraudshield/
+-- backend.py                THE SERVING PATH, one module (~1,050 lines)
|                              1. build_matrix -- canonical, ml/ imports it
|                              2. entity state store (in-memory)
|                              3. online feature builder (22 features)
|                              4. scoring: ML + rules + graph + aggregation
|                              5. FastAPI app
+-- pyproject.toml            pip install . -> import backend works anywhere
+-- Dockerfile                serving image: backend.py + artifacts only
+-- requirements-serve.txt    6 runtime deps, no scikit-learn
+-- requirements-dev.txt      adds sklearn for training
+-- tests/
|   +-- test_parity.py        22 features, offline vs online
|   +-- test_score_parity.py  4 scores, offline vs online
+-- web/                      React 18 + Vite + TypeScript -- BUILT
|   +-- src/
|       +-- styles.css        design tokens; radius is a scale, not scattered values
|       +-- api.ts            typed client, risk-band helper
|       +-- components.tsx    ScoreDial, SubScoreBars, Reasons, Badge, Stat
|       +-- App.tsx           nav + routing
|       +-- auth.tsx          access token in memory, silent refresh
|       +-- pages/
|           +-- Landing.tsx   marketing + honest metrics
|           +-- Signup.tsx    account creation, strength meter
|           +-- Login.tsx     sign in
|           +-- Checkout.tsx  creates a real persisted order
|           +-- Orders.tsx    customer dashboard: history + returns
|           +-- Admin.tsx     queue, evidence panel, label actions
+-- scripts/
|   +-- create_table.py       idempotent DynamoDB table creation
|   +-- grant_role.py         promote an account to analyst/admin
+-- .env / .env.example       backend + frontend config
+-- ml/                       OFFLINE ONLY -- never deployed
|   +-- generate_dataset.py   event simulation + forward feature pass
|   +-- scoring.py            batch scoring, the parity reference
|   +-- cost_model.py         rupee cost of every outcome
|   +-- train.py              XGBoost + isotonic calibration
|   +-- evaluate.py           thresholds, baselines, cost, fairness slices
|   +-- data/                 transactions.csv, promo_redemptions.csv
|   +-- artifacts/            model.json, calibrator.json, metrics.json
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

## Build status

Verified working end to end:

| Area | State |
| --- | --- |
| Dataset generator | 99,373 rows, no-lookahead features, self-reported difficulty check |
| Training + calibration | XGBoost, isotonic, early stop at 174/400 |
| Evaluation | Thresholds, baselines, rupee cost, fairness slices, worked SHAP example |
| Offline/online parity | 2,187,218 feature comparisons + 30,000 score comparisons agree |
| Scoring service | `/v1/risk/score`, `/v1/checkout`, ~25 ms p50 |
| Auth | Argon2id, JWT, rotating refresh with theft detection, role gating |
| Orders + returns | Persisted to DynamoDB, survive restart |
| Promo abuse gate | Tuned on validation, measured on test: precision 0.962, **0 legitimate denials**, Rs 12,150 saved |
| Frontend | Landing, signup, login, checkout, customer orders, analyst console |
| DynamoDB | `fraudshield` table live, holds users, tokens, orders, returns |

### Not done

Ordered by how much they'd matter to a reviewer.

| Gap | Why it matters |
| --- | --- |
| **Review queue is in process memory** | A backend restart loses the queue. Analyst decisions in flight vanish. |
| **Entity counters are in process memory** | A restart cools the graph, so network risk under-scores until traffic rebuilds it. The DynamoDB transaction store is designed in `ARCHITECTURE.md` §3 but not written — and its bucketed velocity windows will break exact score parity, which needs its own measurement. |
| **Rule layer hurts precision** | 0.370 vs 0.675 for XGBoost alone. Measured, reported, deliberately not tuned away. The fix (require nonzero ML contribution before rules can escalate) would weaken the cold-start argument, so it needs a decision rather than a patch. |
| **Review threshold has no controller** | It's a constant tuned against a capacity ceiling. It held on validation (3.83%) and breached on test (4.89%). Production needs a controller targeting a queue rate. |
| **Returns are recorded but never scored** | Refund abuse sits at 0.455 recall at payment time. Every return routes to a human, which is correct but manual. |
| No GSIs | The three indexes in `ARCHITECTURE.md` §3 aren't created. Nothing reads them while the queue is in memory. |
| No email verification, password reset, or MFA | Anyone can register any address. |
| Landing page metrics are hardcoded | They match `metrics.json` today but won't track a retrain automatically. |
| No CI, no compose, no frontend Dockerfile | Parity tests and builds are run by hand. |
| First-party abuse recall 0.000 | Not fixable here by design — needs delivery evidence, not payment features. |

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
