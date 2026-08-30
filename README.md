# FraudShield

A defense-only payment risk engine. It scores every transaction 0–100 from three
independent evidence sources, explains the score in plain English, and routes the
payment to **allow**, **review**, or **block**.

It refuses payments and it queues them for people. It never concludes that a
customer committed fraud — only a human reviewer can do that, through a separate
audited action.

```
POST /v1/orders
      │
      ├─ features      22 values, computed from state observed strictly BEFORE this transaction
      ├─ ML            XGBoost + isotonic calibration          weight 0.70
      ├─ rules         8 deterministic signals, grouped        weight 0.20
      └─ network       shared device/IP graph, live             weight 0.10
      │
      ▼
   score 0–100  ──▶  < 5  ALLOW        payment proceeds
                     ≥ 5  MANUAL_REVIEW  proceeds, queued for a human
                     ≥ 70 BLOCK        refused before the gateway is contacted
```

---

## Contents

1. [Quick start](#quick-start)
2. [The five-minute demo](#the-five-minute-demo)
3. [How scoring works](#how-scoring-works)
4. [Evaluation](#evaluation)
5. [What this system will not do](#what-this-system-will-not-do)
6. [Architecture](#architecture)
7. [API](#api)
8. [Operational controls](#operational-controls)
9. [Security](#security)
10. [Configuration](#configuration)
11. [Tests](#tests)
12. [Project layout](#project-layout)
13. [Honest limitations](#honest-limitations)

---

## Quick start

Requires **Python 3.13** and **Node 20**. No AWS account, no payment provider
account, no API keys.

```powershell
copy .env.example .env

pip install -r requirements.txt
python -m uvicorn backend:app --port 8000 --forwarded-allow-ips=""
```

```powershell
cd web
npm ci
npm run dev            # http://127.0.0.1:5173
```

Log in with the seeded staff accounts printed at startup:

| Role | Email | Password |
|---|---|---|
| admin | `admin@fraudshield.local` | `FraudShield-Admin-2026!` |
| analyst | `analyst@fraudshield.local` | `FraudShield-Analyst-2026!` |

Two flags that are **not** cosmetic:

- **`python -m uvicorn`, not bare `uvicorn`.** On a machine with several Python
  installations the `uvicorn.exe` on `PATH` may belong to a different interpreter
  than the one `pip` installed into, producing `ModuleNotFoundError: No module
  named 'pandas'` despite a successful install.
- **`--forwarded-allow-ips=""` is required.** Without it uvicorn rewrites
  `request.client.host` from `X-Forwarded-For` for any loopback caller, which lets
  a request choose its own IP and walk straight past `ip_concentration`, ring
  detection and the promo gate's address signals.

Defaults are deliberately credential-free: in-memory stores, the simulated
payment gateway, and alerts rendered to the console rather than emailed. Nothing
external is contacted.

---

## The five-minute demo

### Option A — the synthetic attack trigger

Admin only, and off unless you switch it on:

```powershell
$env:FRAUDSHIELD_DEMO_MODE='true'
python -m uvicorn backend:app --port 8000 --forwarded-allow-ips=""
```

Log in as **admin** and click **Trigger demo fraud attack** in the console header.
It generates 8 suspicious payment attempts on one synthetic account, one device
and one address, 60 seconds apart, and sends every one of them through the real
scoring, persistence, audit and notification pipeline.

> **The trigger does not assign a fraud score or decision. It generates synthetic
> transactions and sends them through the same FraudShield scoring pipeline.**

Then walk the console: the queue fills, a row opens to its reason codes and layer
breakdown, **Ring by device** shows the graph, **Suspicious IPs** shows the
address flag with the rule that raised it, and **Audit trail** shows the
`DEMO_ATTACK_TRIGGERED` event plus 8 `RISK_DECISION` events, all marked
`demo: true`.

Details in [Demo fraud attack](#demo-fraud-attack).

### Option B — the payment webhook

Provider-shaped, HMAC-signed events. Everything the server does with them is real:
signature verification over the raw body, replay protection, scoring, persistence.

```powershell
python scripts/emit_webhook.py --demo     # accept, forge (401), replay (dedupe), decline burst
```

### Option C — shop as a customer

Create an account, add items, check out. The **Fails checksum** test card in the
payment sheet is the quickest way to produce declines.

---

## How scoring works

### Features — 22, all backward-looking

Computed in `build_online_features()` from state observed **strictly before** the
transaction being scored. A row never sees its own outcome.

| Group | Features |
|---|---|
| Transaction | `amount`, `payment_method`, `transaction_hour`, `is_weekend` |
| Velocity | `txn_count_10m`, `txn_count_1h`, `failed_count_10m`, `failed_count_1h` |
| Customer baseline | `account_age_hours`, `customer_avg_amount`, `amount_ratio`, `prev_txn_count`, `historical_failure_rate` |
| Device / address | `device_account_count`, `device_txn_count`, `device_failure_rate`, `ip_account_count`, `ip_txn_count` |
| Behavioural | `is_new_device`, `is_new_payment_method`, `seconds_since_last_txn`, `hour_deviation` |

**Deliberately excluded** and enumerated in code with reasons: `status`,
`fraud_type`, `fraud_label` (outcome leakage); `customer_id`, `device_fp`,
`ip_hash` (memorising identifiers is not generalisation, and in production they
are unbounded-cardinality strings); `ts_epoch` (the model would learn "week 8 =
test set").

### Layer 1 — ML, weight 0.70

XGBoost, best iteration 174, 27 columns (the 22 raw features with
`payment_method` expanded to one-hots). Probabilities are calibrated with isotonic
regression fitted offline; serving reads the fitted knots from
`ml/artifacts/calibrator.json` and interpolates with numpy, so **scikit-learn is
not in the request path**.

Attributions come from XGBoost's native `pred_contribs=True` — exact TreeSHAP
inside the booster. The `shap` package is deliberately not a dependency.

### Layer 2 — rules, weight 0.20

Eight deterministic signals. Correlated rules are **grouped, and only the highest
scorer in each group counts**, so adding a ninth rule can redistribute the layer
but cannot inflate it.

| Rule | Fires when | Points | Group |
|---|---|---|---|
| `velocity_breach` | `txn_count_10m` > 5 | 20 | velocity |
| `failure_spike` | `failed_count_1h` > 5 | 10 | velocity |
| `method_switching` | > 3 methods in an hour | 10 | velocity |
| `device_abuse` | device on > 4 accounts | 15 | entity sharing |
| `ip_concentration` | > 6 accounts on the address | 10 | entity sharing |
| `amount_anomaly` | `amount_ratio` > 4 | 15 | amount |
| `new_account` | `account_age_hours` < 24 | 5 | novelty |
| `new_device` | first transaction from this device | 5 | novelty |

`device_abuse` and `ip_concentration` both measure "one actor, many accounts";
counting both would punish the same evidence twice.

### Layer 3 — network, weight 0.10

A real graph computation in `Scorer._network`, not a library import. It expands the
connected component around the customer's device and address, and scores it on
size, edge density, 24-hour burstiness, failure rate and synchrony.

Two guards that matter more than the formula:

- **Components below three accounts score 0.0.** Two accounts sharing a device is
  a couple, not a ring.
- **High-population addresses are damped by 0.35.** A carrier NAT or an office
  range legitimately carries thousands of unrelated accounts. Without this every
  customer on a large mobile network inherits a ring score — the most expensive
  false-positive source found in testing.

### Aggregation and overrides

```
final = 0.70 × ml + 0.20 × rules + 0.10 × network        clipped to 0–100
```

If the ML artifact is missing, the layer is dropped and the survivors are
reweighted to **0.70 × rules + 0.30 × network** so the score still spans 0–100.

Two overrides, both named in the audit record when they apply:

- **`hard_block`** — rules at 100 and network above 85 forces 100.
- **`trusted_floor`** — an account older than 180 days with more than 50 prior
  transactions, an amount under 2× its own baseline, and **zero** rules fired is
  capped at 39. This stops the model harassing the merchant's best customers over
  a new phone.

### Explanations

Reason codes merge two sources — fired rules with their measured values, and the
top five positive model contributions mapped through `SHAP_TEXT` — deduplicated
and capped at eight items. Analyst-facing only: telling an attacker which signal
fired is free reconnaissance.

---

## Evaluation

Every figure below is read from `ml/artifacts/metrics.json`, produced by
`ml/evaluate.py` on the **held-out test split**. Nothing is estimated.

**Test split:** 14,913 rows, 342 fraud (2.293%).

### Ranking

| Metric | Value |
|---|---|
| PR-AUC | **0.7875** |
| ROC-AUC | 0.9399 |
| Brier (calibrated) | 0.00709 |

### Decision gates

| Gate | Precision | Recall | F1 | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|
| Review (≥ 5) | 0.3704 | 0.7895 | 0.5042 | 270 | 459 | 72 | 14,112 |
| Block (≥ 70) | **1.0000** | 0.5526 | 0.7118 | 189 | **0** | 153 | 14,571 |

**Block precision of 1.000 is a warning, not a trophy.** On 14,913 test rows the
block gate refused 189 payments and got none of them wrong. That is a small sample
at a conservative threshold on synthetic data. It will not survive real traffic,
and reading it as "we never decline a good customer" would be exactly the wrong
conclusion.

**F1 is published for comparability and is deliberately not what the thresholds
optimise.** F1 weights a missed fraud and a wrongly blocked customer equally; this
system's own cost model puts them roughly 41× apart.

### Recall by fraud archetype

| Archetype | Recall |
|---|---|
| `card_testing` | 1.0000 |
| `ring_cashout` | 1.0000 |
| `account_takeover` | 0.9864 |
| `refund_abuse` | 0.4545 |
| `first_party_abuse` | **0.0000** |

`first_party_abuse` is a real customer making a real purchase and later denying
it. There is nothing anomalous at payment time, so it is undetectable by this
design and it caps achievable recall. Recording that as 0.000 rather than omitting
the archetype is the point.

### Against baselines

| Approach | PR-AUC | Expected cost |
|---|---|---|
| Random | 0.0238 | 553,450 |
| Amount threshold ≥ ₹10k | 0.0804 | 1,530,782 |
| Hand-picked point formula | 0.4041 | 657,075 |
| Rules only | 0.3419 | 598,420 |
| Network only | 0.1743 | 903,480 |
| XGBoost only | **0.8001** | 277,535 |
| FraudShield ensemble | 0.7875 | **274,500** |

**The ensemble ranks slightly worse than XGBoost alone** (0.7875 vs 0.8001) while
costing marginally less. That is reported because it is true. The rules and network
layers earn their place on interpretability and on catching coordinated behaviour
the model has not seen, not on lifting PR-AUC — and if you only care about ranking,
the honest answer is to use the model alone.

### The caveat that governs every number above

The data is generated by `ml/generate_dataset.py`, written by the same author as
the detector. **Real-world performance will be worse.** No figure here should be
read as a production result.

### Dataset

99,419 transactions across 4,703 customers, 12,480 devices and 4,421 addresses,
over 180 days, at a 2.014% fraud rate. Split chronologically: 69,593 train /
14,913 validation / 14,913 test. Seed 20260822.

Fraud is generated from **behaviour**, never by setting a feature value:
`card_testing` 601, `account_takeover` 480, `ring_cashout` 421, `refund_abuse`
260, `first_party_abuse` 240. Roughly 30% of card-testing accounts are dormant
"sleepers" aged deliberately before use, because otherwise `account_age_hours`
separates fraud far too easily. The generator runs its own difficulty self-audit
and reports that 35.5% of fraud is indistinguishable by simple rules.

Offline and online feature construction are implemented twice — a vectorised batch
pass in `ml/scoring.py` and an incremental online path in `backend.py` — and
`tests/test_parity.py` proves they agree across 2.1 million feature comparisons.
Without that, every metric above would describe a model that cannot ship.

---

## What this system will not do

`ACTION_POLICY` in `backend.py` is a table, not an agent. It is version-stamped,
published read-only at `GET /v1/admin/policy`, and recorded on every
`RISK_DECISION`, so "what is the automation allowed to do on its own?" has an
answer you can read rather than infer.

The inference the table exists to forbid:

```
BLOCK != FRAUD
```

A BLOCK means one thing: the score crossed the configured block threshold and the
payment was refused. It is not a finding, not an accusation, and not a label.

**`NEVER_AUTOMATED`** — asserted by tests, not just documented:

- confirm that a transaction was fraudulent
- create or modify a ground-truth label
- issue a refund or move money in any direction
- ban, suspend, close or permanently restrict an account
- change a risk threshold
- change model weights or retrain
- delete or alter evidence, audit records or stored transactions
- notify a customer that they are suspected of fraud
- share a decision with a third party

No provider exposes a `refund` method and no route exists that could execute one.

---

## Architecture

```
                     ┌──────────────────────────────────────────┐
   browser  ───JWT──▶│  FastAPI  (backend.py)                   │
                     │                                          │
   webhook ──HMAC───▶│  scorer ─▶ provider ─▶ store ─▶ records   │
                     │     │                            │       │
   service ──key────▶│     └────▶ audit ─▶ notify        │       │
                     └──────────────────────────────────┼───────┘
                                                        │
                              ┌─────────────────────────┴────────┐
                              │  single-table store (PK + SK)    │
                              │  InMemoryRecordStore  (default)  │
                              │  DynamoRecordStore    (opt-in)   │
                              └──────────────────────────────────┘
```

Four scoring entry points, one scorer: the storefront order path, the payment
webhook, the service-to-service scoring endpoint, and the demo trigger. All four
emit exactly one `RISK_DECISION` per committed scoring.

Module dependencies are **one-way** and enforced by convention:
`backend → payments`, `backend → notifications`, never the reverse.
`payments.py` takes `authorise_fn` by injection specifically so it never has to
import `backend`.

### Storage

Single table, DynamoDB-shaped, no ORM and no migration framework. Item shapes are
written inline.

| PK | SK | Holds |
|---|---|---|
| `CUSTOMER#<id>` | `ORDER#…`, `RETURN#…`, `PROMO#…`, `FAILED#…` | one account's activity |
| `TXN#<id>` | `DETAIL` | the authoritative scored transaction |
| `INDEX#TXN` | `<created_at>#<id>` | replay projection: exactly the fields `commit()` consumes |
| `QUEUE#REVIEW` | `ITEM#<txn_id>` | the analyst backlog |
| `AUDIT#<utc-date>` | `<timestamp>#<event_id>` | append-only audit partition |
| `NOTIFICATION#<dedupe_key>` | `DELIVERY` | one item per alertable event |
| `IPFAIL#<ip_hash>` | `ATTEMPT#<iso>#<id>` | individual declines behind an address flag |
| `SUSPICIOUS#IP` | `<ip_hash>` | the flag itself, so the mark survives a restart |
| `INSTRUMENT#<ref>` | `<iso>#<customer>` | card/UPI/wallet reuse across accounts |
| `INDEX#ORDER` | `<order_id>` | order lookup without knowing the customer |
| `INDEX#PROMO` | `<redemption_id>` | rebuilds the promo hold queue at startup |
| `PROMODEV#<device>` · `PROMOIP#<ip>` · `PAYOUT#<ref>` | `<code>#<iso>#<customer>` | promo-abuse counters |
| `CONFIG` | `RISK_THRESHOLDS` | the live threshold pair |
| `WEBHOOK#EVENT` | `<provider_event_id>` | replay protection |

**No GSI is created.** Every access pattern above falls out of the primary key
design, so adding one would cost money and buy nothing. Entity state — the velocity
deques and the graph — is *not* in this table; it is rebuilt at startup by replaying
`INDEX#TXN`.

`InMemoryRecordStore` is the default and loses everything on restart.
`DynamoRecordStore` is opt-in via `FRAUDSHIELD_USERS_BACKEND=dynamodb` and needs
`python scripts/create_table.py` once.

### Restart durability

Nothing is re-scored on reload. Stored decisions are authoritative, and no
`RISK_DECISION` is emitted when reading one back — those record the moment a
decision was made, not the moment it was read.

- `rehydrate_state()` — one query on `INDEX#TXN`, then point-gets, then the queue.
  History is capped; **open review items are never capped**, because an unreviewed
  item is exactly what must not be dropped.
- `rehydrate_entity_state()` — replays transactions through the same
  `InMemoryStore.commit()` the historical CSV warm-up uses, so velocity deques and
  the entity graph come back. **Chronological order is mandatory**: the deques trim
  from the left, so a newest-first replay would corrupt every window. Pointers are
  queried newest-first for the horizon cut, then re-sorted ascending.
- Threshold configuration is applied before the first request is served.

---

## API

33 routes, enumerated by introspecting `backend.app.routes`. All 15
`/v1/admin/*` routes enforce a role, verified programmatically.

### Authentication

| Method | Path | Guard |
|---|---|---|
| POST | `/v1/auth/register` | public — always creates a `customer` |
| POST | `/v1/auth/login` | public, rate limited |
| POST | `/v1/auth/refresh` | refresh cookie |
| POST | `/v1/auth/logout` | revokes the token family |
| GET | `/v1/auth/me` | session |

### Storefront

| Method | Path | Guard |
|---|---|---|
| GET | `/v1/catalog/products` | public |
| POST | `/v1/orders` | session — scores, authorises, persists |
| GET | `/v1/orders`, `/v1/orders/{id}` | session, role-projected |
| POST/GET | `/v1/returns` | session |
| GET | `/v1/promo/offers`, `/v1/promo/mine` | public / session |
| POST | `/v1/promo/redeem` | session — scored by the promo gate |

Four payment methods are offered: **upi, card, netbanking, wallet**. Cash on
delivery was removed — it carries no instrument to fingerprint, so it produces no
reuse signal, and it cannot be declined by a gateway. It was the one method the
risk engine had nothing to say about.

`cod` nonetheless **remains** in `PAYMENT_METHODS` and in `feature_spec.json`,
because the model was trained with a `method_cod` one-hot column. Deleting it there
would change the feature matrix out from under the artifact and break
offline/online parity. Historical COD transactions still score correctly; new ones
are simply not offered.

Three inputs to `POST /v1/orders` are deliberately **not** taken from the request
body: the address (derived from the connection), the amount (computed from the
catalogue) and the settlement status (decided by the provider). All three were once
client-controlled, and each one let a caller poison the features the model depends
on.

### Analyst console

| Method | Path | Guard |
|---|---|---|
| GET | `/v1/admin/queue` | analyst, admin |
| GET | `/v1/admin/transactions/{id}` | analyst, admin |
| POST | `/v1/admin/transactions/{id}/outcome` | analyst, admin — **the only ground truth** |
| GET | `/v1/admin/rings/{type}/{id}` | analyst, admin |
| GET | `/v1/admin/metrics` | analyst, admin |
| GET | `/v1/admin/suspicious-ips`, `/v1/admin/failed-attempts` | analyst, admin |
| GET | `/v1/admin/promo-holds` | analyst, admin |
| POST | `/v1/admin/promo-holds/{rid}/override` | analyst, admin |
| GET | `/v1/admin/notifications` | analyst, admin |
| GET | `/v1/admin/policy` | analyst, admin |
| GET | `/v1/admin/thresholds` | analyst, admin |
| PUT | `/v1/admin/thresholds` | **admin only** |
| GET | `/v1/admin/audit` | **admin only** |
| POST | `/v1/admin/demo/fraud-attack` | **admin only**, demo mode + simulator only |

### Ingestion and service

| Method | Path | Guard |
|---|---|---|
| POST | `/v1/webhooks/payment` | HMAC-SHA256 over the raw body |
| POST | `/v1/risk/score` | shared API key |
| POST | `/v1/checkout` | shared API key |
| GET | `/health` | public |

`/v1/risk/score` accepts `ip_hash` and `status` from the caller, unlike
`/v1/orders`. That is the one legitimate case — a merchant's own server relaying a
checkout knows both — and the API key is what makes it trustworthy. **Never expose
it to a browser.**

---

## Operational controls

### Thresholds

`PUT /v1/admin/thresholds` is admin-only, validated, audited, and **persisted** to
`CONFIG/RISK_THRESHOLDS`. It used to live only on the Scorer instance, so a change
made at 3am was silently discarded by the next deploy while the audit trail
insisted it had happened — a log that disagrees with behaviour is worse than no
control at all.

Invariant: `0 ≤ review < block ≤ 100`. `review == block` is rejected rather than
tolerated, because with both equal there is no review band and every flagged
transaction is refused outright.

An unreadable stored item does not stop the service starting. It falls back to the
environment defaults, and says so loudly on `/health` with `degraded: true`,
because silently serving defaults while the table says otherwise is the same
log-versus-behaviour lie.

**The review threshold is an operations parameter, not a model property.** It is
set by how many analysts you employ. `GET /v1/admin/thresholds` returns the cost
curve so an admin can see the trade before moving it.

### Audit trail

`AUDIT#<utc-date>`, append-only, admin-only to read. Nine event types:

| Event | Actor | Ground truth? |
|---|---|---|
| `RISK_DECISION` | `system:scorer` | no — a routing decision |
| `OUTCOME_RECORDED` | a human | **yes** |
| `PROMO_OVERRIDE` | a human | **yes** |
| `threshold_update` | a human | no |
| `NOTIFICATION_SENT` / `_FAILED` / `_THROTTLED` | `system:notifier` | no |
| `ip_marked_suspicious` | `system` | no |
| `payment_event_ingested` | `webhook` | no |
| `MODEL_FALLBACK_TRIGGERED` | `system` | no |
| `DEMO_ATTACK_TRIGGERED` | a human | no — synthetic |

`GET /v1/admin/audit` supports a single date, a bounded date range, keyset
pagination and filters:

```
GET /v1/admin/audit
GET /v1/admin/audit?date=2026-08-29&limit=100
GET /v1/admin/audit?start_date=2026-08-01&end_date=2026-08-29
GET /v1/admin/audit?action=RISK_DECISION&transaction_id=pay_abc
```

The continuation token is opaque — base64 `<day>|<sort-key>` — never a raw
DynamoDB `LastEvaluatedKey`, which would pin the API to a storage detail. Ranges
read **one partition at a time**, newest day first, never a scan. Default page 50,
max 200, range capped at 31 days.

A partial answer never looks complete: if one day in a range fails to read, the
response reports `source: "partial"` and `complete: false` rather than claiming the
range is whole.

### Alerts

Two providers behind one protocol. `ConsoleEmailProvider` is the default and
renders the full alert without any credential. `SMTPEmailProvider` uses STARTTLS
with certificate **and hostname** verification.

Selection is explicit: `FRAUDSHIELD_EMAIL_PROVIDER=smtp` is required. A stray SMTP
host in a shell profile must never start mailing an unknown relay. Ask for SMTP
without a host or sender and the service logs `DEGRADED`, reports it on `/health`,
and falls back to console — it never crashes, and it never pretends an email was
delivered.

**Deduplication.** The key is `<event_type>:<subject_id>`, so a redelivered
webhook, a retried request, or the fourth through fortieth decline from one
address all resolve to one alert. Deduplication survives restarts via
`NOTIFICATION#<key>`.

**Volume ceiling — 5 alerts per 10 minutes.** Dedup cannot answer "will anyone
read the fortieth *distinct* alert this minute?", because eight blocked payments
are eight different transactions with eight different keys. Over the cap an alert
is recorded `throttled` with its own audit event. Three properties, each of which
took a mistake to find:

- **Throttled is not failed.** Nothing malfunctioned; the alert was withheld by
  policy. Calling it a failure would send an operator hunting a broken mail server.
- **A throttled key is not marked as notified,** so the event stays eligible once
  the window clears. Otherwise a volume control becomes silent alert loss.
- **`SUSPICIOUS_IP` is exempt.** Per-transaction alerts arrive *before* an address
  crosses its decline rule, so without the exemption they consumed the whole budget
  and the one message summarising the attack was throttled — the ceiling burying
  the alert it exists to protect.

The counter is per-process, not distributed. Two instances would each allow five.
That is a mailbox-volume control, not a security boundary.

**An alert failure can never affect a risk decision.** `notify()` cannot raise;
every path is wrapped, including the persistence of its own bookkeeping. A BLOCK
still blocks, a MANUAL_REVIEW still reaches the queue, and the audit record is
still written, whether or not anybody can be told.

### Suspicious-address detection

An operational flag on an *address*, not a model feature and not a label on any
transaction. Two rules, **either sufficient**, because the same attack has a fast
and a slow form:

| Rule | Trigger | Window | Catches |
|---|---|---|---|
| **Volume** | more than 9 declines | 20 min | a machine working a list |
| **Breadth** | 3+ distinct payment methods failing | 2 hours | the patient version, spread out to duck the volume rule |

Breadth is 3 rather than 2 because two methods failing is an ordinary bad
afternoon — an expired card then a UPI app having problems. Three distinct
instrument *types* from one address is somebody working through what they have.

Two deques, two windows, deliberately: sharing one would destroy the breadth
count. Addresses carrying more than 25 accounts are exempt, because a carrier NAT
pools unrelated declines through no fault of anyone behind it. Both rules survive
a restart — the replay carries `payment_method`, so a replay that dropped it would
keep the count intact while silently killing the breadth rule.

The alert lists every distinct instrument that declined: method, masked display
(`Visa •••• 4242`) and the HMAC reference (`card_9a8b7c…`), deduplicated on the
reference. **No card number, no CVV, no bank credential** — in the alert or in the
database. See [Security](#security).

### Demo fraud attack

Two independent gates, both closed by default:

| Gate | Requirement | Failure |
|---|---|---|
| Explicit opt-in | `FRAUDSHIELD_DEMO_MODE=true` | `403` |
| Simulator only | provider is `simulated`, both requested **and** resolved | `409` |

Neither is inferred from the other. The simulator being active is a normal
production state for this project, so it is not consent to inject synthetic
traffic. Requesting `razorpay` without credentials falls back to the simulator —
and that fallback is still refused, because the operator asked for a real gateway.

**The scenario.** 8 attempts, 60 seconds apart, spanning 420s — inside the 600s
window `txn_count_10m` counts over. Fixed in the backend with no request body, so
no caller can ask for 100,000. Amounts escalate ₹21,999 → ₹44,999 across rotating
methods on an unfamiliar device.

First it replays an ordinary history: 60 purchases averaging ~₹2,080 over 84 days
on a familiar device, on an account aged 96 days. `amount_ratio` is a deviation
from the customer's own running mean, so an account with no history has nothing to
deviate from. That history is committed the way the historical CSV warm-up is —
**not scored, not persisted, not queued, not audited** — because it is context,
not decisions FraudShield made, and recording it as scored transactions would mean
inventing scores for it.

**Every run is isolated.** Customer, device and address are minted fresh from one
shared token. They were originally fixed constants, which made the ring grow
across runs — a nice story that quietly broke the demo, because those identifiers
feed `device_account_count`, `ip_account_count` and `device_failure_rate`, all
model features. By the third run the account looked established, some attempts
fell under the block threshold, and a MANUAL_REVIEW *reaches* the gateway and
usually succeeds where a BLOCK never does and always settles failed. Fewer
failures meant fewer distinct failed methods, so the address stopped reaching the
breadth rule and the suspicious-address alert silently stopped firing the more the
demo was used. Reproducibility won.

The baseline's shopping hours are anchored 12 hours from the attack hour for the
same reason: with a fixed evening baseline, `hour_deviation` varied with the wall
clock, and the same scenario scored differently at 08:00 than at 16:00.

**Marked everywhere.** Every generated transaction and audit event carries
`demo: true`. The marker is **omitted entirely** on real traffic rather than
written as `demo: false` — the absence is what makes the presence meaningful. One
`DEMO_ATTACK_TRIGGERED` event records the admin who asked, with identity taken
from the verified token.

**No ground truth is created,** nothing is cleaned up afterwards (the analyst
needs to investigate it, and no cleanup route exists), and no money moves.

---

## Security

### Verified

| Concern | Control |
|---|---|
| Passwords | Argon2id via `argon2-cffi`. Never logged, never returned |
| Sessions | Short-lived JWT access tokens; rotating opaque refresh tokens with family revocation |
| Refresh token storage | `httpOnly` cookie, `SameSite=Lax`, path-scoped to `/v1/auth` |
| Access token storage | A module variable in the browser — **never** `localStorage`, where any injected script could lift it and turn an XSS into a durable takeover |
| Login abuse | Rate limited to 5 attempts per email per 15 minutes; identical error whether or not the email exists, so the form is not an account-enumeration oracle |
| Role enforcement | `require_role` server-side on every admin route. A hidden nav link is a UX affordance, not a control |
| Privilege escalation | Signup always creates `customer`. There is **no API path** to a privileged role — `scripts/grant_role.py` writes directly to the store |
| IP spoofing | The address is derived server-side and HMAC-hashed with a pepper. It used to be a request-body field, which made every address control decorative |
| `X-Forwarded-For` | Honoured only from a peer in `FRAUDSHIELD_TRUSTED_PROXIES`, empty by default |
| CORS | Explicit origin allow-list. Never `*`: this service returns fraud reason codes |
| Webhooks | HMAC-SHA256 over the **raw body** with `compare_digest`, plus replay and staleness checks. Fails closed |
| Provider errors | A timeout, 4xx, 5xx or malformed response resolves to `pending`, never `success` |
| Audit projection | An allow-list, so a field added to a stored item cannot leak into the API |

### Card data

**Not stored. Not logged. Not sent to the model.**

`validate_instrument()` checks Luhn and expiry, derives
`HMAC-SHA256(digits, pepper)` as a `card_fingerprint`, and **discards the number**.
The CVV is validated and discarded — retaining it after authorisation is
prohibited outright by **PCI DSS Requirement 3.2**.

The fingerprint is not a reduced version of the evidence, it is the right
evidence: the question an analyst asks is *"is this the same card as the other four
accounts?"*, and the same card always produces the same fingerprint. That is what
detects card reuse across accounts, verified at three accounts sharing one card. A
PAN in the database would answer it no better and could not be un-leaked.

A production integration would tokenise client-side so the number never reaches
this server at all.

What *is* stored per instrument type: card → fingerprint + last four; UPI → the
VPA; netbanking → the bank code only, because the form never collects a
credential; wallet → HMAC of the phone + last four.

### Known gaps

No email verification, no password reset, no MFA. Refresh-token rotation is
implemented but there is no admin session-revocation UI. The service-to-service
API key is a single shared secret with no rotation mechanism.

---

## Configuration

Copy `.env.example` to `.env`. Everything has a safe default; `.env` is
gitignored.

| Variable | Purpose |
|---|---|
| `FRAUDSHIELD_ARTIFACTS` | Where `model.json`, `calibrator.json`, `feature_spec.json` live |
| `FRAUDSHIELD_REVIEW_T` / `_BLOCK_T` | Env defaults, overridden by persisted config |
| `FRAUDSHIELD_WARM_ROWS` | Historical rows replayed into entity state at startup |
| `FRAUDSHIELD_REHYDRATE_TXNS` | Transactions reloaded into the console cache (default 200) |
| `FRAUDSHIELD_REHYDRATE_GRAPH_TXNS` | Transactions replayed into velocity and the graph (default 5,000) |
| `FRAUDSHIELD_JWT_SECRET` | Signing key. **Required in production** |
| `FRAUDSHIELD_IP_PEPPER` | Pepper for address and instrument fingerprints |
| `FRAUDSHIELD_COOKIE_SECURE` | Must be `true` in production |
| `FRAUDSHIELD_TRUSTED_PROXIES` | Peers allowed to set `X-Forwarded-For`. Empty by default |
| `FRAUDSHIELD_CORS_ORIGINS` | Explicit allow-list |
| `FRAUDSHIELD_USERS_BACKEND` | `memory` (default) or `dynamodb` |
| `FRAUDSHIELD_DEV_SEED_STAFF` | Seeds the staff accounts. **Local development only** |
| `FRAUDSHIELD_API_KEY` | Guards the service-to-service routes |
| `FRAUDSHIELD_WEBHOOK_SECRET` | HMAC secret. The webhook returns 503 if unset |
| `FRAUDSHIELD_PAYMENT_PROVIDER` | `simulated` (default) or `razorpay` |
| `FRAUDSHIELD_DEMO_MODE` | Enables the synthetic attack trigger. **Default false** |
| `FRAUDSHIELD_EMAIL_PROVIDER` | `console` (default) or `smtp` |
| `FRAUDSHIELD_ALERT_FROM` / `_RECIPIENTS` | Sender and staff recipients |
| `FRAUDSHIELD_SMTP_*` | Host, port, username, password, TLS |
| `RAZORPAY_KEY_ID` / `_KEY_SECRET` | Vendor-standard names. Blank here — no account exists |

### Enabling real email

`FRAUDSHIELD_ALERT_FROM` **must** be the account that owns the app password.
Gmail refuses `535` for any other sender.

```powershell
$env:FRAUDSHIELD_EMAIL_PROVIDER   = 'smtp'
$env:FRAUDSHIELD_SMTP_HOST        = 'smtp.gmail.com'
$env:FRAUDSHIELD_SMTP_PORT        = '587'
$env:FRAUDSHIELD_ALERT_FROM       = '<the account owning the app password>'
$env:FRAUDSHIELD_SMTP_USERNAME    = '<the same account>'
$env:FRAUDSHIELD_SMTP_PASSWORD    = '<app password>'
$env:FRAUDSHIELD_ALERT_RECIPIENTS = '<who to alert>'
```

Set these in the shell, **not in `.env`**. `backend.py` loads `.env` at import, so
a configured provider there would make the test suite resolve the real transport
and mail an analyst on every BLOCK it generates. `tests/conftest.py` forces the
console provider before `backend` is imported as a second line of defence.

---

## Tests

**830 backend tests, 88 frontend tests.** Last full run: 830 passed, 0 failed, 0
skipped in 18m 56s.

```powershell
python -m pytest                              # full backend suite, ~19 min
python -m pytest tests/test_demo_attack.py -v # 102 tests, ~40 s
python tests/test_parity.py                   # parity suites also run standalone

cd web
npm test                                      # 88 tests, ~8 s
npm run build                                 # tsc -b && vite build
```

The two parity suites dominate the runtime and are the ones that matter most: they
replay the generated dataset one transaction at a time and compare 2.1 million
feature values plus every sub-score against the offline batch implementation.

The frontend suite uses vitest + Testing Library and stubs every API call — an
unmocked `fetch` throws, because a test asserting what a given role receives must
not depend on a running backend.

Every backend test uses in-memory stores or an injected fake, so the suite contacts no
network, no AWS and no mail server. CI additionally **fails** if
`RAZORPAY_KEY_ID`, `AWS_ACCESS_KEY_ID`, `FRAUDSHIELD_SMTP_PASSWORD` or
`FRAUDSHIELD_ALERT_RECIPIENTS` is present — if a test ever starts depending on a
real external service, "all green" stops meaning what it says.

---

## Project layout

```
backend.py                  the whole serving surface: features, scoring, auth, routes
payments.py                 PaymentProvider protocol, simulated + Razorpay adapters
notifications.py            EmailProvider protocol, console + SMTP, message builders
requirements.txt            runtime + training + test dependencies, one file
Dockerfile                  serving image, non-root, artifacts only

ml/
  generate_dataset.py       synthetic data with a difficulty self-audit
  train.py                  XGBoost + isotonic calibration
  evaluate.py               metrics, baselines, threshold sweep
  evaluate_promo.py         promo-gate evaluation
  scoring.py                offline batch feature pass (the parity reference)
  cost_model.py             expected-cost model behind threshold selection
  artifacts/                model.json, calibrator.json, feature_spec.json, metrics.json
  data/                     generated CSVs (gitignored) + metadata.json

scripts/
  create_table.py           creates the DynamoDB table, idempotent
  grant_role.py             the only way to grant a role
  reset_staff.py            deletes a seeded staff account so it can be recreated
  emit_webhook.py           signed event emitter — the stand-in provider

tests/                      backend suite, in-memory only
web/src/                    React console + storefront
  pages/Admin.tsx           queue, evidence panel, tabs
  pages/RingView.tsx        force-directed SVG + accessible table equivalent
  pages/Audit.tsx           date, range, cursor pagination, four event categories
  pages/SuspiciousIps.tsx   flagged addresses with per-decline drill-down
  pages/DemoAttack.tsx      the synthetic attack trigger
```

No `docker-compose.yml`, no `Makefile`, no `infra/`, and no `docs/`. This README is
the only prose documentation, deliberately: a `docs/` directory existed and its
setup instructions had drifted far enough from the code to be actively misleading,
so it was removed rather than left to rot alongside a README that contradicted it.

---

## Honest limitations

**Payments.** No Razorpay account exists, so **no part of this has ever called
Razorpay.** The webhook contract with real HMAC verification exists, and so does
the outbound adapter behind an explicit provider switch, both tested against a
mock. What is missing is not code — it is a business account. The simulator is the
default and the service states which provider it is running on startup, on
`/health`, and in the console.

**Email.** `ConsoleEmailProvider` is fully exercised. `SMTPEmailProvider` is
tested against an injected fake transport across ten failure modes. The automated
suite does not verify live delivery and cannot, since no credentials ship.
Separately, one manual send was performed against `smtp.gmail.com:587` and Gmail
accepted it — a single observation about one account on one day, recorded here
rather than asserted by a test.

**DynamoDB.** `InMemoryRecordStore` and `FakeTable`/`DynamoRecordStore` parity are
covered by tests. No real DynamoDB is contacted by the suite. The DynamoDB
adapter for the *entity state* store (`InMemoryStore`) is not built at all — the
mapping is documented in code, and it will need its own parity measurement.

**Decision routing.** Three decisions on two thresholds. There is no MEDIUM
monitor tier and no CRITICAL escalation tier, and BLOCK is terminal.

**Detection ceiling.** `first_party_abuse` recall is 0.000 by construction and
`refund_abuse` is 0.4545. Neither is anomalous at payment time.

**Graceful failure.** Model-missing fallback, fail-toward-review on scoring
errors, webhook fail-closed, store fallback, degraded threshold config. **No ML
inference timeout** and **no retry or backoff** on a failed provider call.

**Audit retrieval.** Ranges are capped at 31 days per request. Filters are applied
after a partition is read and are **not indexed** — supporting them efficiently
would need a GSI, which was out of scope. `MAX_QUERY_PAGES` truncation logs a
warning but is not surfaced in the response body.

**Scale.** Entity state is a per-process in-memory graph rebuilt at startup from a
bounded window of recent transactions, not a distributed store. The alert rate
limit is per-process. Neither survives horizontal scaling as written.

**Session handling.** When a token refresh fails, the API client clears the access
token but the React `user` state is not cleared, so the console can render a
logged-in header over a dead session until the page is reloaded.

**The data.** Every performance figure in this README is measured on data this
project generated. Real-world performance will be worse.
