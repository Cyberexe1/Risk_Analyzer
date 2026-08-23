# FraudShield — Architecture

System design, data model, authentication and API contract. For scoring internals see [RISK_ENGINE.md](RISK_ENGINE.md); for metrics see [EVALUATION.md](EVALUATION.md).

---

> **Build status.** The scoring service, promo abuse gate, JWT auth, React
> dashboards and the DynamoDB user/order store are built and verified. Still
> unbuilt: the **DynamoDB transaction/entity store** (counters and the review
> queue remain in process memory) and the **three GSIs** in section 3. Concretely:
>
> | Component | Status |
> | --- | --- |
> | Online scorer (`backend.py` §4) | Built, score-parity verified against the batch pipeline |
> | Entity state store (`backend.py` §2) | Built, **in-memory only** — does not survive restart |
> | FastAPI service (`backend.py` §5) | Built: score, checkout, queue, detail, outcome |
> | Packaging | `pyproject.toml` + `Dockerfile`; `pip install .` verified |
> | User auth (`backend.py` §5) | Built: Argon2id, JWT access, rotating refresh with theft detection, role gating |
> | User store | Built. **DynamoDB live** (`fraudshield`, ap-south-1); in-memory fallback |
> | Orders / returns | Built and persisted: `POST /v1/orders`, `GET /v1/orders`, `POST /v1/returns` |
> | Customer dashboard | Built: `/orders` — history, status, return-request flow |
> | Service auth | Shared API key on `/v1/risk/score` and `/v1/checkout` only |
> | Frontend (`web/`) | Built: landing, checkout, console, signup, login |
> | DynamoDB single-table | **Created** via `scripts/create_table.py`, PAY_PER_REQUEST, TTL on `ttl`. Holds users, refresh tokens, orders, returns. **No GSIs** and the transaction/entity store is still in-memory |
> | React dashboards | Built: landing, checkout, customer orders, analyst console |
>
> The entire serving path is one module, `backend.py`. Training, evaluation, the
> dataset generator and the batch scorer stay in `ml/` and are never deployed —
> see [README, Deployment](../README.md#deployment) for why.
>
> Section 3 (data model) and section 4 (auth) describe the intended design. Treat
> them as a specification to build against, not a description of running code.

---

## 0. Offline/online parity — the claim this architecture rests on

Every metric in [EVALUATION.md](EVALUATION.md) was produced by a batch pass over a sorted CSV. Production has no sorted CSV. It has one transaction and whatever counters earlier traffic left behind.

If those two paths disagree, the metrics describe a model that cannot ship. So the agreement is tested rather than asserted:

```text
tests/test_parity.py         99,419 rows x 22 features = 2,187,218 comparisons
                             -> all agree

tests/test_score_parity.py   30,000 rows x 4 scores (ml, rules, network, final)
                             -> all agree
```

`backend.py::build_online_features` is a **deliberately independent** implementation of `ml/generate_dataset.py::compute_features`. Sharing that code would make the test vacuous — the point is that two separately written paths produce identical output.

This is worth guarding. The two functions look similar, they now live in different files, and the obvious "cleanup" is to merge them into a shared helper. Do that and `test_parity.py` still passes while proving only that a function equals itself. There is a warning block at the top of `backend.py` saying so.

The one thing the paths *do* share is `build_matrix`, and that sharing is deliberate in the opposite direction: `backend.py` owns it and `ml/train.py` imports it, so there is exactly one copy of the log1p transforms and the column ordering. Two copies would drift and the served model would silently score a different matrix than it was fitted on.

The tests also pin the read-before-write discipline: `Scorer.score()` never mutates state, and `store.commit()` is the caller's job afterwards. A commit that landed before the feature read would surface immediately as a velocity mismatch.

### Known future divergence

DynamoDB cannot hold an exact trailing-600-second deque per customer. The schema in section 3 uses bucketed windows (`WINDOW#10M#<epoch//600>`) with TTL, which is an **approximation**. When that adapter is written it will not reproduce these parity results exactly, and it needs its own measurement of how far it drifts before it is trusted. Flagged in the DynamoDB mapping note in `backend.py` §2 rather than discovered later.

---

## 1. Components

```text
                    +---------------------------+
                    |   React SPA (Vite)        |
                    |  /app     customer        |
                    |  /admin   analyst         |
                    +-------------+-------------+
                                  | HTTPS, JWT bearer
                    +-------------v-------------+
                    |      FastAPI service      |
                    |                           |
                    |  auth    catalog  orders  |
                    |  risk    admin    returns |
                    |                           |
                    |  +---------------------+  |
                    |  |  Scoring pipeline   |  |
                    |  |  features -> ML     |  |
                    |  |  rules -> network   |  |
                    |  |  -> aggregator      |  |
                    |  +---------------------+  |
                    +------+-------------+------+
                           |             |
              +------------v---+   +-----v--------------+
              |  DynamoDB      |   |  Model artifacts   |
              |  single table  |   |  model.json        |
              |  + GSIs        |   |  calibrator.pkl    |
              +----------------+   |  feature_spec.json |
                                   +--------------------+
```

The model is loaded once at process start and held in memory. There is no separate inference service: XGBoost prediction on 22 features is roughly 1 ms, so a network hop would cost more than the compute.

---

## 2. Scoring request flow

```text
POST /v1/risk/score
  |
  1. Auth dependency        verify JWT, resolve customer_id, check role
  |
  2. Feature assembly       BatchGetItem:
  |                           CUSTOMER#<id>#PROFILE      baseline stats
  |                           DEVICE#<fp>#COUNTERS       device counters
  |                           IP#<hash>#COUNTERS         ip counters
  |                           CUSTOMER#<id>#WINDOW#10M   velocity counters
  |                         -> 22-feature vector
  |
  3. ML score               XGBoost predict_proba -> isotonic calibration -> x100
  |
  4. Rule score             8 deterministic checks, capped at 100
  |
  5. Network score          shared-entity graph expansion, depth 2, capped at 100
  |
  6. Aggregate              0.70 ML + 0.20 rules + 0.10 network
  |
  7. Decide                 threshold lookup -> ALLOW / REVIEW / BLOCK
  |
  8. Explain                top 5 SHAP contributions + fired rules -> reason codes
  |
  9. Persist                TransactWriteItems:
  |                           put TXN item with scores and reasons
  |                           ADD velocity + entity counters
  |                           put REVIEW queue item if REVIEW or BLOCK
  |
  v
Response: score, sub-scores, decision, reason codes
```

Steps 3, 4 and 5 are independent and run concurrently with `asyncio.gather`. Latency budget:

| Stage | Target p99 |
| --- | --- |
| Feature assembly (DynamoDB) | 25 ms |
| ML + rules + network | 20 ms |
| Persist (transactional write) | 30 ms |
| Total endpoint | **< 150 ms** |

### Failure behaviour

The scorer is on the checkout path, so it must degrade rather than block revenue.

| Failure | Behaviour |
| --- | --- |
| Model artifact missing or corrupt | Rules + network only, reweighted 0.7 / 0.3, response flagged `degraded: true` |
| DynamoDB counter read timeout | Missing features imputed to training medians, confidence flag set |
| Total scoring failure | Return `REVIEW` with reason `SCORING_UNAVAILABLE` — fail to human, never silently allow |

Failing open to `ALLOW` would make the engine trivially bypassable by inducing errors. Failing closed to `BLOCK` would kill legitimate checkout. `REVIEW` is the only safe default.

---

## 3. DynamoDB data model

Single table, `fraudshield`, on-demand capacity. Key schema `PK` (partition) + `SK` (sort).

> **Deployed, partially.** `scripts/create_table.py` creates the base table with
> TTL on the `ttl` attribute. Live item types: `USER`, `EMAIL` index, `RT#`
> refresh tokens, `ORDER#`, `RETURN#`, and an `INDEX#ORDER` lookup.
>
> Not created: **the three GSIs below**, and the transaction / device / IP
> counter items. Each GSI bills separately, and nothing reads them yet — the
> admin queue and the entity graph both still run from process memory, so a
> backend restart loses the queue and cools the graph. The `Order` item shape
> below also differs slightly from what the code writes (`ORDER#<iso>#<id>`
> rather than `TXN#<ts>#<id>`), because orders and scored transactions turned out
> to need separate records.

### Item types

| Entity | PK | SK | Notable attributes |
| --- | --- | --- | --- |
| User | `USER#<user_id>` | `PROFILE` | `email`, `password_hash`, `role`, `created_at`, `status` |
| Email index | `EMAIL#<lower(email)>` | `USER` | `user_id` — enforces email uniqueness |
| Refresh token | `USER#<user_id>` | `RT#<token_id>` | `token_hash`, `expires_at`, `revoked`, TTL |
| Customer profile | `CUSTOMER#<id>` | `PROFILE` | `avg_amount`, `stddev_amount`, `txn_count`, `failure_rate`, `typical_hours`, `account_created_at` |
| Transaction | `CUSTOMER#<id>` | `TXN#<ts>#<txn_id>` | `amount`, `payment_method`, `status`, `risk_score`, `ml_score`, `rule_score`, `network_score`, `decision`, `reasons`, `device_fp`, `ip_hash` |
| Velocity window | `CUSTOMER#<id>` | `WINDOW#10M#<bucket>` | `attempts`, `failures`, `methods_seen`, TTL 1 h |
| Device counters | `DEVICE#<fp>` | `COUNTERS` | `account_count`, `txn_count`, `failure_count`, `confirmed_fraud_count`, `first_seen` |
| Device edge | `DEVICE#<fp>` | `ACCT#<customer_id>` | `first_seen`, `txn_count` — powers ring expansion |
| IP counters | `IP#<hash>` | `COUNTERS` | `account_count`, `txn_count`, `first_seen` |
| IP edge | `IP#<hash>` | `ACCT#<customer_id>` | `first_seen` |
| Review queue | `QUEUE#<yyyy-mm-dd>` | `RISK#<zero-padded>#<txn_id>` | denormalised summary for the admin list |
| Promo redemption | `CUSTOMER#<id>` | `PROMO#<code>#<iso>` | `decision`, `status`, `reasons`, `features`, `override_by` |
| Promo device counter | `PROMODEV#<fp>` | `<code>#<iso>#<customer_id>` | Written even on DENY, so a retry from a new account sees the history |
| Promo IP counter | `PROMOIP#<hash>` | `<code>#<iso>#<customer_id>` | |
| Payout destination | `PAYOUT#<ref>` | `<code>#<iso>#<customer_id>` | Powers payout-reuse detection. **Not** written on DENY — a denied claim never pays out, so blocking that destination forever would punish a legitimate retry |
| Label | `LABEL#<txn_id>` | `OUTCOME` | `label`, `source` (`analyst` / `chargeback`), `decided_at`, `analyst_id` |
| Audit | `AUDIT#<yyyy-mm-dd>` | `<ts>#<event_id>` | `actor`, `action`, `target`, `before`, `after` |

### Global secondary indexes

| Index | PK | SK | Serves |
| --- | --- | --- | --- |
| `GSI1` | `decision` | `created_at` | "all REVIEW items in the last hour" |
| `GSI2` | `device_fp` | `created_at` | device history and ring expansion |
| `GSI3` | `ip_hash` | `created_at` | IP concentration lookups |

### Access patterns

| Need | Operation |
| --- | --- |
| Login | `GetItem EMAIL#<email>` then `GetItem USER#<id>` |
| Promo already claimed on this payout | `Query PAYOUT#<hash>` where `SK begins_with REDEEM#<promo>` |
| Promo redemption history | `Query PROMO#<code>` where `SK begins_with REDEEM#` |
| Customer baseline | `GetItem CUSTOMER#<id> / PROFILE` |
| Velocity features | `Query CUSTOMER#<id>` where `SK begins_with WINDOW#10M#` |
| Device / IP features | `BatchGetItem` on the two `COUNTERS` items |
| Ring expansion | `Query DEVICE#<fp>` where `SK begins_with ACCT#` |
| Order history | `Query CUSTOMER#<id>` where `SK begins_with TXN#`, descending |
| Admin queue | `Query QUEUE#<today>`, descending, limit 50 |
| Metrics recompute | `Query GSI1` over the window, join labels |

### Counter integrity

Velocity and entity counters are updated with atomic `ADD` inside the same `TransactWriteItems` call that writes the transaction. Either the transaction and its counters both land, or neither does — no drift between what we scored and what we recorded.

Short-window counters use bucketed sort keys (`WINDOW#10M#<epoch/600>`) plus DynamoDB TTL. The 10-minute count is a query over the current and previous bucket, so it needs no scheduled cleanup.

### Retention and PII

- Raw IPs are **never** stored. We store `HMAC-SHA256(ip, server_pepper)`, so counters work but the address is not recoverable from a table dump.
- Device fingerprints are client-generated opaque hashes. No canvas or audio fingerprinting, no cross-site tracking.
- Card data never reaches FraudShield. The gateway returns a token; we store the token and a `card_fingerprint` for reuse counting.
- Transaction items carry a 24-month TTL. Labels are retained for model lineage.

---

## 4. Authentication

> **Built, with one gap.** Implemented in `backend.py` §5 and verified end to end:
> Argon2id hashing (64 MiB, t=3, p=4), JWT HS256 access tokens at 15 min, opaque
> 256-bit refresh tokens stored SHA-256 hashed in an httpOnly cookie, single-use
> rotation with **family revocation on reuse**, login rate limits (5/email and
> 20/client per 15 min), and identical response text and timing for unknown-email
> versus wrong-password.
>
> Admin routes now require `role in {analyst, admin}` via a FastAPI dependency.
> The shared API key is **no longer accepted** there — it guards only
> `/v1/risk/score` and `/v1/checkout`, where a payment gateway calling
> server-side genuinely has no user session.
>
> Self-service signup always produces a `customer`. There is no API path to a
> privileged role; promotion is `scripts/grant_role.py`.
>
> **The gap: the default user store is in-memory, so accounts vanish on restart.**
> The DynamoDB adapter matching section 3 is written but opt-in via
> `FRAUDSHIELD_USERS_BACKEND=dynamodb`, because enabling it creates billable AWS
> resources. Also unbuilt: email verification, password reset, MFA.

DynamoDB is the credential store. No Cognito, so that the whole flow is inspectable in a demo.

```text
POST /v1/auth/register
  email + password
  -> conditional put on EMAIL#<email> (attribute_not_exists) for uniqueness
  -> Argon2id hash, m=64MB t=3 p=4
  -> put USER#<id>/PROFILE with role="customer"

POST /v1/auth/login
  -> resolve email index, verify hash
  -> access token   JWT HS256, 15 min, claims: sub, role, jti
  -> refresh token  opaque 256-bit random, SHA-256 hash stored under USER#<id>/RT#<id>, 30 d
  -> refresh returned as httpOnly + Secure + SameSite=Strict cookie
  -> access token held in memory only, never localStorage

POST /v1/auth/refresh
  -> rotate: revoke old token id, issue new pair
  -> reuse of a revoked token id revokes the entire family (theft detection)

POST /v1/auth/logout
  -> revoke the token family
```

Controls in place:

- Argon2id with per-user salt; parameters live in config and are versioned so hashes can be upgraded on next login
- Login rate limit: 5 attempts per email per 15 min, 20 per IP hash per 15 min, both as DynamoDB counters with TTL
- Constant-time comparison, and identical response shape and timing for unknown-email vs. wrong-password
- Roles: `customer`, `analyst`, `admin`. Admin routes sit behind `Depends(require_role("admin"))`, enforced server-side on every request
- Admin role can only be granted by a direct table write, never through an API endpoint
- CORS locked to the known web origin; no wildcard with credentials

`.env` needs `JWT_SECRET` and `IP_PEPPER` set to strong random values. The committed `.env.example` contains placeholders only. In AWS these come from Secrets Manager, and the task role gets scoped `dynamodb:GetItem / PutItem / Query / UpdateItem / TransactWriteItems` on the one table plus its indexes — nothing broader.

---

## 5. API contract

All routes are prefixed `/v1`. Full OpenAPI at `/docs`.

### Public

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/auth/register` | Create customer account |
| POST | `/auth/login` | Issue token pair |
| POST | `/auth/refresh` | Rotate token pair |
| POST | `/auth/logout` | Revoke token family |
| GET | `/catalog/products` | Product list |

### Customer (role `customer`)

| Method | Path | Purpose | Status |
| --- | --- | --- | --- |
| POST | `/orders` | Create order, score it, persist it | Built |
| GET | `/orders` | Order history | Built |
| GET | `/orders/{id}` | Order detail, customer-safe projection | Built |
| POST | `/returns` | Request a return | Built |
| GET | `/returns` | Return history | Built |
| GET | `/catalog/products` | Product list | Built |
| GET | `/promo/offers` | Available offers | Built |
| POST | `/promo/redeem` | Claim an offer, triggers the redemption gate | Built |
| GET | `/promo/mine` | Your claims | Built |
| POST | `/risk/score` | Service-to-service scoring, shared API key | Built |

The order response is **role-dependent**: a `customer` gets `order_id`, `status` and a message; `analyst`/`admin` additionally get `risk` with the score, sub-scores and reason codes. Enforced server-side in `_customer_order_view`, which is allow-list based — adding a field to the stored record cannot leak it to customers by default.

`GET /orders/{id}` returns the same 404 whether the order does not exist or belongs to another account. A distinguishable response would let a caller enumerate other people's orders. Verified: a second account reading the first account's order gets 404, and its own history returns 0.

### Admin (role `admin` or `analyst`)

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/admin/queue` | Review queue, filter by decision and score range |
| GET | `/admin/promo-holds` | Held and denied redemptions |
| POST | `/admin/promo-holds/{id}/override` | Grant a denied offer, writes a label |
| GET | `/admin/transactions/{id}` | Full scoring breakdown and reason codes |
| GET | `/admin/rings/{entity_type}/{entity_id}` | Ring graph, nodes and edges |
| POST | `/admin/transactions/{id}/decision` | Record `fraud` / `legitimate`, writes a label |
| GET | `/admin/metrics` | Live precision, recall, FP rate, cost |
| GET | `/admin/thresholds` | Current cut-offs |
| PUT | `/admin/thresholds` | Update cut-offs, audited |

### Scoring response

```json
{
  "transaction_id": "pay_83921",
  "risk_score": 87,
  "decision": "MANUAL_REVIEW",
  "sub_scores": { "ml": 82, "rules": 76, "network": 91 },
  "reason_codes": [
    { "code": "VELOCITY_BURST",   "severity": "high",   "detail": "8 attempts in 10 minutes", "contribution": 0.21 },
    { "code": "DEVICE_SHARED",    "severity": "high",   "detail": "Device linked to 5 accounts", "contribution": 0.18 },
    { "code": "AMOUNT_ANOMALY",   "severity": "high",   "detail": "Amount 5.2x customer baseline", "contribution": 0.15 },
    { "code": "NEW_PAY_METHOD",   "severity": "medium", "detail": "First use of this payment method", "contribution": 0.07 },
    { "code": "FAILURE_SPIKE",    "severity": "medium", "detail": "4 failures in the last hour", "contribution": 0.06 }
  ],
  "model_version": "xgb-2026-08-14-a",
  "threshold_version": "th-7",
  "degraded": false,
  "scored_at": "2026-08-22T09:14:03Z",
  "latency_ms": 61
}
```

`model_version` and `threshold_version` are on every response and every stored item. Without them you cannot answer "which model produced this decision" three months later, which makes an audit impossible.

### Customer-facing projection

The customer endpoints return a strict subset. The serialiser is allow-list based, so a new internal field cannot leak by default:

```json
{ "order_id": "ord_5512", "status": "verifying", "message": "We're verifying your payment. This usually takes about 2 minutes." }
```

---

## 6. Frontend structure

```text
web/src/
+-- shared/
|   +-- api/client.ts          fetch wrapper, refresh-on-401, retry
|   +-- auth/AuthContext.tsx   in-memory access token, silent refresh
|   +-- components/            buttons, tables, badges, empty states
+-- customer/
|   +-- Catalog.tsx
|   +-- Cart.tsx
|   +-- Checkout.tsx           handles allow / review / block branches
|   +-- Orders.tsx
|   +-- ReturnRequest.tsx
+-- admin/
    +-- Queue.tsx              virtualised table, risk-sorted
    +-- TransactionDetail.tsx  sub-score bars + reason codes
    +-- RingGraph.tsx          force-directed shared-entity view
    +-- Metrics.tsx            PR curve, confusion matrix, cost panel
    +-- Thresholds.tsx         cut-off tuner with projected cost
```

Route guards read the role claim, but that is a UX affordance only — authorisation lives in FastAPI. A hidden button is not a security control.

Accessibility: risk levels are conveyed by label and icon as well as colour, so red/green is not the only signal. The queue table uses proper `<th scope>` headers, the ring graph has a table-based equivalent view for screen readers, and all interactive controls are keyboard reachable with visible focus rings. Full WCAG conformance would need manual testing with assistive technology and an expert accessibility review — we have covered the automated and structural layer.

---

## 7. Local development

```text
docker compose up -d
  dynamodb-local   :8000 internal, mapped :8001
  api              :8000  uvicorn --reload
  web              :5173  vite dev server
```

`make bootstrap` creates the table and its three GSIs, seeds 40 products, and creates one admin and three customer accounts. `make dataset` generates labelled synthetic history. `make train` writes to `ml/artifacts/`. `make evaluate` writes `metrics.json` and the plots the admin metrics page reads.

The generator is offline and local. It emits rows into DynamoDB Local, has no outbound network calls, and contains nothing that can be pointed at a payment processor.
