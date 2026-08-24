# FraudShield — Pages Overview

Every page in the web app, what it renders, which API it calls, and who is allowed to see it.

Source of truth: `web/src/`. This document was written by reading the components, not from a plan, so what follows is what the code actually renders today.

- **Stack:** React 18 + TypeScript, Vite, `react-router-dom` v6, no UI framework. All styling is hand-written in `web/src/styles.css`.
- **Entry:** `web/src/main.tsx` mounts `<StrictMode><BrowserRouter><AuthProvider><App/>`.
- **Shell:** `web/src/App.tsx` — header, routes, footer.
- **Shared widgets:** `web/src/components.tsx`.
- **API client:** `web/src/api.ts`.
- **Session:** `web/src/auth.tsx`.

---

## 1. Route table

| Path | Page file | Access | Purpose |
|---|---|---|---|
| `/` | `pages/Landing.tsx` | Public | Marketing + honest metrics |
| `/checkout` | `pages/Checkout.tsx` | Public route, needs login to pay | Shop, cart, payment, live score |
| `/login` | `pages/Login.tsx` | Public | Sign in (`?staff=1` for staff copy) |
| `/signup` | `pages/Signup.tsx` | Public | Create a customer account |
| `/dashboard` | `pages/Dashboard.tsx` | `RequireAuth` | Account overview |
| `/orders` | `pages/Orders.tsx` | `RequireAuth` | Order history + return requests |
| `/offers` | `pages/Offers.tsx` | `RequireAuth` | Claim cashback offers |
| `/admin` | `pages/Admin.tsx` | `RequireStaff` | Analyst console (5 tabs) |
| `*` | inline in `App.tsx` | Public | Not-found page |

Three sub-panels are not routes. They render inside `/admin` as tabs: `pages/RingView.tsx`, `pages/AdminMetrics.tsx`, `pages/Thresholds.tsx`.

### Route guards

Both guards live in `App.tsx` and both render a `Checking your session…` placeholder while `auth.loading` is true.

- **`RequireAuth`** — redirects to `/login` when there is no user, passing `state.from` so login can return you to where you were headed.
- **`RequireStaff`** — same redirect for anonymous users. For a signed-in `customer` it renders a "Not your console" card explaining that roles are granted by a direct write to the user store (`python scripts/grant_role.py`), never through the API.

These guards are convenience only. The backend re-checks the role on every admin request via `require_role(...)`, so a hidden nav link is not a control.

---

## 2. Header

Rendered by the `Nav()` component in `App.tsx` as `<header className="nav">`, present on every page.

**Left — brand:** a `◆` glyph mark plus the wordmark "FraudShield", linking to `/`.

**Centre — nav links** (`<nav aria-label="Main">`):

| Link | Visible to |
|---|---|
| Overview (`/`) | Everyone |
| Checkout (`/checkout`) | Everyone |
| Dashboard (`/dashboard`) | Signed in |
| Orders (`/orders`) | Signed in |
| Offers (`/offers`) | Signed in |
| Console (`/admin`) | `analyst` or `admin` only |

**Right — `UserMenu()`,** separated by a 1px vertical divider:

- While the session is resolving: a muted `…`.
- Anonymous: an "Admin login" text link to `/login?staff=1`, a ghost "Log in" button, and a solid "Sign up" button.
- Signed in: an email chip (truncated at 200px, full email plus role in the `title`), a role badge, and a ghost "Log out" button.

Above the header sits a `Skip to content` link targeting `#main`, visually hidden until focused.

---

## 3. Footer

Rendered directly in `App.tsx`, on every page. A top border, 28px vertical padding, 40px top margin, and two muted strings spread apart:

- Left: `FraudShield · defense-only risk scoring · synthetic data`
- Right: `Routing decisions, not fraud verdicts.`

No links, no columns, no newsletter form. It exists to restate scope.

---

## 4. Shared components (`components.tsx`)

Used across many pages, so described once here.

| Component | Renders |
|---|---|
| `Badge` | Decision pill. Colour **plus** a label and a glyph (`▲` block, `◆` review, `●` allow) so it survives greyscale and colour blindness. |
| `Stat` | Metric tile: small key, large value, optional note line. |
| `ScoreDial` | Big `NN / 100` in the band colour, a `Badge`, and an ARIA `meter` bar. |
| `SubScoreBars` | Three labelled meters — ML model, Behavioural rules, Network/ring. A single number hides which layer drove the decision. |
| `Reasons` | Reason-code list with severity glyph, human detail, and a source tag (`rule`/`model`). Empty state: "No signals fired." |
| `ErrorNote` | `role="alert"` warning for an unreachable backend. |

---

## 5. Public pages

### 5.1 Landing — `/`

The only page with hardcoded metrics. It is public, so it cannot call the staff-only metrics endpoint; the figures are mirrored from `ml/artifacts/metrics.json` into a single `M` object at the top of the file so a retrain means editing one block.

Five sections, top to bottom:

1. **Hero** — a `hero-glow` background flourish, a "Defense only" badge, the headline "Stop losing money to fraud without punishing real customers", a paragraph explaining the 0–100 score, and two CTAs (`Try a checkout` → `/checkout`, `Open analyst console` → `/admin`). Below sit four `Stat` tiles: PR-AUC 0.788, Recall 0.789, Cost reduction 77.4%, Latency ~25 ms.
2. **Two problems, not one** — two cards. One on fraud getting through (stolen card, chargeback fee, multi-account bonus abuse). One on the detector overreacting, landing on the ratio that drives the whole design: blocking is ~41× more expensive per mistake than reviewing.
3. **Three evidence sources** — three weighted cards: XGBoost (70%), deterministic rules (20%), entity graph (10%). Opens by admitting an earlier hand-picked-points version demoed well and collapsed under questioning.
4. **The numbers we would rather not show you** — a precision/recall/volume table for both gates, then four caveat notes: block precision of 1.000 is a warning not a win; the ensemble ranks *below* XGBoost alone (0.788 vs 0.800); first-party abuse recall is 0.000; the review threshold is set by analyst headcount, not model quality. Closes with "Production performance will be worse."
5. **Scope: defense only** — what the system cannot do: generate fraudulent transactions, probe payment credentials, evade third-party controls, or profile on protected attributes. Notes the data generator has no network egress.

### 5.2 Login — `/login`

One form for every role. `?staff=1` changes only the copy and the post-login destination (`/admin` instead of `/dashboard`) — same endpoint, same Argon2id verification, same rate limits. The role comes from the account record, not from which button was pressed.

**Contains:** an optional "Staff access" badge, a heading that flips between "Log in" and "Analyst console", an `role="alert"` error note, then the form — email (`autoComplete="email"`), password, a "Show password" checkbox, and a full-width submit disabled until both fields are non-empty and no request is in flight. Below: cross-links (customer mode offers `/signup` and `/login?staff=1`; staff mode offers a way back).

**Closing note, which differs by mode:**
- Staff: roles are granted out-of-band via `scripts/grant_role.py`; there is no API path to a privileged role, so signup can never escalate.
- Customer: failed logins return the same message whether or not the email exists, and are limited to 5 attempts per email per 15 minutes. Distinguishable errors would turn the form into an account-enumeration oracle.

**Calls:** `authApi.login` through `useAuth().login`.

### 5.3 Signup — `/signup`

**Contains:** email, password, confirm password, a "Show password" checkbox, and a submit button gated on `email.includes('@')`, no password problem, and a match.

The password field carries a **three-segment strength meter** and a live help line. `passwordStrength` in `auth.tsx` counts bits for length ≥10, length ≥16, mixed case, a digit, and a symbol, mapping to Too weak / Weak / Reasonable / Strong. `passwordProblem` rejects under 10 characters, digit-only passwords, and a 15-entry common-password list. Both are a client-side mirror of the backend policy — UX, not enforcement, since the backend re-checks everything.

Validation waits for blur or submit (`touched`) rather than scolding you mid-keystroke. `aria-invalid` and `aria-describedby` wire the errors to the inputs.

On success, redirects to `/checkout`. Closing note: signup always creates a **customer**; analyst and admin require a direct write to the user store.

**Calls:** `authApi.register` through `useAuth().register`.

---

## 6. Authenticated customer pages

### 6.1 Checkout — `/checkout`

The largest customer page (476 lines). Publicly routed, but gated inside the component: anonymous visitors get a card offering "Create an account" or "Log in", because orders are tied to an account and the account is what the risk engine builds history against.

**Left column — catalogue.** Products from `GET /v1/catalog/products`, grouped by category derived at render time. Twelve items across Audio, Peripherals, Phones, Accessories, Wearables, Storage, Displays, Tablets, ₹449 to ₹42,999. Each card shows name, price, and either a stock count or "Only N left". Add-to-cart becomes a `−` / count / `+` stepper, with `+` disabled at the stock ceiling and aria-labels on both.

**Right column — sticky cart and payment panel** (`position: sticky; top: 82`):

- **Cart card** — line items with quantity and line total, then a bordered total row with the item count.
- **Payment card** — a method `<select>` driven by the catalogue's `payment_methods`, then conditional fields keyed off that method's `needs` value:

| Method | `needs` | Fields shown |
|---|---|---|
| UPI | `vpa` | UPI ID, prefilled `<email-local-part>@okhdfcbank` |
| Card | `card` | Number, month, year, CVV, optional holder |
| Netbanking | `bank` | Bank select (6 Indian banks) |
| Wallet | `wallet` | Provider select (Paytm, PhonePe, Amazon Pay, Mobikwik) + phone |
| COD | `null` | "Pay in cash when the order arrives." |

  The card branch adds three one-click test-number chips: Visa valid (`4111…1111`), Mastercard valid (`5555…4444`), and one that deliberately **fails Luhn** (`…1112`) so you can watch validation reject a typo. A note states the number is checksum-validated, fingerprinted, then discarded — never stored, never reaching the risk model.

- **"Order from a flagged shared device" checkbox** — swaps the device fingerprint for `dev_demo_shared` to raise device-linkage signals on demand. The sub-label notes your IP is derived server-side and cannot be spoofed from here.
- **Pay button** showing the live total, disabled on an empty cart or while busy.

**Result card, after payment.** A status note colour-keyed to `confirmed` / `verifying` / `declined` / `declined_by_bank`, chips for order ID, instrument display and amount, and a link to `/orders`.

Then the **role-dependent half**. For staff, a "Risk detail (staff only)" block: `ScoreDial`, `SubScoreBars`, `Reasons`, plus chips for settlement, IP hash, and how many accounts the instrument appears on. For a customer, one line explaining the backend omitted those fields for a `customer` role — the fields are absent from the response, not hidden by CSS.

**Device fingerprint:** a `dev_web_<random>` value persisted in `localStorage` under `fs_device`. The code comments that this is inherently client-controlled, which is exactly why device signals must be corroborated by payout reuse or velocity rather than trusted alone.

**Calls:** `shopApi.catalogue()`, `shopApi.createOrder()`.

### 6.2 Dashboard — `/dashboard`

Account overview. Loads orders, returns and promo claims in one `Promise.all`.

**Contains:** a page head with the heading, the signed-in email, and Shop / Offers buttons. Then four `Stat` tiles computed client-side — Orders (with confirmed count), Total spend (confirmed only), Cashback earned (credited claims only), and Needs attention (verifying orders + open returns).

Below that, a two-column split:

- **Recent orders** — the five most recent in a table: product name with date, payment instrument, amount, and a status `Pill`. A "View all →" link goes to `/orders`.
- **Sidebar** — a Cashback card listing each claim's code, value and status, and a Returns card listing product, status and reason, footed with "Every return is reviewed by a person, not auto-approved."

Empty state offers a "Start shopping" button.

Everything here is the allow-listed customer projection — no score, no sub-scores, no reason codes.

**Calls:** `shopApi.orders()`, `shopApi.returns()`, `promoApi.mine()`.

### 6.3 Orders — `/orders`

Full history plus the return-request flow.

**Contains:** a header with the signed-in email and a "Place an order" button, three `Stat` tiles (Orders, Confirmed spend, Open returns), then one card per order.

Each order card shows product name, a comma-joined item line when there is more than one, a mono line with order ID / timestamp / instrument, the amount, and an outlined status badge. Four statuses are styled distinctly, and `declined_by_bank` is deliberately labelled "Bank declined" rather than plain "Declined" — showing an innocent bank decline as a refusal would imply suspicion the system never expressed.

Below each card, the action area resolves in order:
1. Already returned → "Return under review".
2. `confirmed` → a "Request a return" button that expands inline into a reason `<select>` (five preset reasons), an optional 500-character detail input, and Submit / Cancel.
3. Anything else → a status explanation ("Payment verification in progress", "Your bank declined this payment. Try another method", or "This payment did not go through").

For staff only, a chip row appears with the risk score, decision, an `ml / rules / net` breakdown, settlement, and an instrument-reuse count when above 1.

A Returns table follows when any exist, footed with the reason returns are not auto-approved: return abuse is only 0.455 recall at payment time, so auto-approving on the transaction score would be approving on evidence known to be weak.

**Calls:** `shopApi.orders()`, `shopApi.returns()`, `shopApi.requestReturn()`.

### 6.4 Offers — `/offers`

The promo-abuse gate's customer-facing surface. Promo abuse is scored here rather than at checkout, because by the time a payment is scored the cashback is already credited — and the evidence lives in relationships between accounts, which a per-transaction model has nowhere to put.

**Contains:**

- Heading and a line explaining claims are checked against accounts, devices and payout destinations already linked to yours.
- A **"Claim from a shared device and payout destination" toggle** styled as a card. It swaps in `dev_demo_shared_promo` and `upi_demo_shared` to simulate one person cycling accounts through the same tablet and UPI id. The first claim goes through; the rest do not.
- Two offer cards from `GET /v1/promo/offers`: **WELCOME500** (₹500, welcome cashback) and **FESTIVE250** (₹250, festive bonus). Each shows name, value, blurb, a code chip, and a claim button that reads "Already claimed" once used.
- A **result card** with a status badge (Credited / Under review / Not available) and the backend's message.
- For staff, a "Why (staff only)" block with the fired `Reasons`, plus a line when the shared-IP exemption applied (the IP looks like office or carrier infrastructure, so IP-only signals were suppressed). For customers, a note that the backend omits reason codes for a `customer` role — telling a promo abuser which signal fired tells them exactly what to rotate next.
- A "Your claims" table: offer, value, status, timestamp.
- A closing note on why this gate may be stricter than the checkout scorer: a refused cashback is not a refused sale. You can still order, and support can reverse it.

No `ip_hash` is sent. The backend derives it from the connection; a client that could choose its own would walk past every IP-based signal.

**Calls:** `promoApi.offers()`, `promoApi.mine()`, `promoApi.redeem()`.

---

## 7. Analyst console — `/admin`

`analyst` or `admin` only. Polls every 5 seconds via `setInterval`, with the selected transaction re-resolved from the fresh list so the evidence panel cannot go stale.

**Always visible:**

- Page head: heading, "Queue refreshes every 5 seconds", a chip reading `DynamoDB` or `in-memory` from `/health`, and a manual Refresh button.
- A `role="alert"` warning when `health.model_loaded` is false: running on rules and network only, train with `python ml/train.py`.
- Four `Stat` tiles: In queue, Blocked ("no human in the loop"), For review ("held, not declined"), Promo holds.
- A `role="tablist"` bar with five tabs, counts inlined.
- A closing caveat: the review queue lives in the backend's process memory and is lost on restart. Users, orders and promo claims persist to DynamoDB; the transaction store does not yet.

### Tab 1 — Transactions

Two panes. **Left:** a table sorted by risk descending — risk score in its band colour, decision `Badge`, transaction ID, amount. Rows are keyboard operable (`tabIndex={0}`, Enter/Space select, `aria-selected`). Empty state points at the shop.

**Right:** a sticky evidence aside. Nothing selected shows "Select a transaction to see its evidence." Once selected:

1. Transaction ID and `ScoreDial`.
2. Customer ID and amount.
3. `SubScoreBars` — which of the three layers drove this.
4. "Why" — the full `Reasons` list.
5. An override note when score aggregation was bypassed.
6. **"Investigate the cluster"** — Ring by device / Ring by IP / Ring by account buttons that jump to the Rings tab pre-seeded. The network sub-score says how connected this is; the graph shows what it is connected to.
7. **"Record the outcome"** — Confirm fraud / Mark legitimate, prefaced with "This writes a label for retraining. The score was a routing decision, not a verdict." This is the only place ground truth is created, which is what keeps the system accountable for routing attention rather than declaring fraud.

**Calls:** `api.queue()`, `api.health()`, `api.outcome()`.

### Tab 2 — Rings (`RingView.tsx`)

A lookup card (entity type select — device / IP hash / account — plus an identifier field and Expand) and, when populated, up to six device chips harvested from the current queue as shortcuts.

The graph itself is a **hand-rolled force-directed layout** in a 660×460 SVG: all-pairs repulsion, edge springs, mild centring, ~220 iterations. Deliberately not a charting library — the physics and SVG are about 60 lines, where d3 would add roughly 90 KB to a 251 KB bundle. The backend's 200-node cap keeps the O(n²) repulsion cheap.

**Contains:** a header with the seed, a depth select (1/2/3), a "Show as table" toggle, and Close. Then a count chip row (accounts, devices, IPs, edges, plus a "truncated at 200" badge when hit), and one of two contextual notes:

- 3+ accounts with flagged nodes: "N accounts share M entities… The structure is the evidence."
- Under 3 accounts: the network layer scores it 0, because not every shared device is a ring — family tablets and office networks look like this too.

Node styling: accounts are circles, devices squares, IPs triangles, each with its own colour. Seed nodes get a larger radius and a `--text` stroke; over-threshold nodes get a red halo. Hovering shows a floating card with the label and per-type detail (transaction and failure counts for accounts, account counts for devices and IPs). A legend chip row explains all four states.

**Accessibility:** the SVG carries a descriptive `aria-label` and the "Show as table" toggle gives the same adjacency data in a linear table — node, type, connection count, detail — because a force graph is not usable with a screen reader.

Footer note: this is the same adjacency the network score walks, so the picture and the number cannot disagree. IPs above 26 accounts are treated as shared infrastructure and not followed; without that, a carrier range pulls in unrelated strangers.

**Calls:** `api.ring(type, id, depth)`.

### Tab 3 — Promo abuse

A table of held and denied claims: status badge (Denied / Held), account email, offer code with value, the full `Reasons` list in a 360px column with a shared-IP-exemption note where it applied, and a "Grant anyway" override button.

Footed with why the override matters: it is the **only** label source for this gate. The gate ships with no training data, so an analyst reversing a decision is how we learn the rules are wrong.

**Calls:** `promoApi.holds()`, `promoApi.override()`.

### Tab 4 — Model performance (`AdminMetrics.tsx`)

Live figures read from `ml/artifacts/*.json` through `GET /v1/admin/metrics`. Falls back to a warning naming the three commands to run when artifacts are absent, and flags partial artifacts individually.

**Transaction scorer section:**

- Four `Stat` tiles: PR-AUC ("the honest ranking metric"), ROC-AUC ("inflated by the negative class"), Net saving, FP cost with a blocked-customer count.
- **Operating points** table — precision, recall and volume at both gates. Auto-attaches a warning when block precision ≥ 0.999, explaining that zero false positives means the synthetic data's high-confidence fraud is too cleanly separable.
- **Confusion at the chosen point** — a Fraud/Legitimate × Block/Review/Allow matrix with false negatives and false positives in red, review FPs in amber. Footed with the block-to-review cost ratio computed live from the unit costs.
- **Recall by fraud type** — horizontal bars coloured red under 0.5, amber under 0.8, green above. Attaches a specific note when first-party-abuse recall falls under 0.05: those are genuinely normal transactions, and catching them needs delivery evidence, not better scoring.
- **Model vs. baselines** — PR-AUC bars with the ensemble highlighted and the hand-picked MVP formula in amber. States plainly that learned weights roughly double the hand-picked formula, and that the ensemble ranks slightly *below* XGBoost alone.
- **Review rate by slice** — a fairness table (n, review rate, block rate, ratio vs overall) with ratios above 1.4× in amber and above 3× in red. Prefaced: no protected attribute is a model input; these are behavioural slices monitored for disparate impact.

**Promotion abuse gate section:** four tiles (precision, recall, wrongly-denied count out of total denials, net saving) plus per-signal precision bars coloured by action (DENY red, HOLD amber).

**Caveats section:** every caveat string from both artifacts, rendered as notes.

**Calls:** `api.metrics()`.

### Tab 5 — Thresholds (`Thresholds.tsx`)

Read-only for `analyst`, editable for `admin`. The reasoning is in the file: the review threshold is an operations parameter, not a model property. At a 100:1 cost ratio between a missed fraud and a review, expected-cost minimisation always wants to review more, so the binding constraint is analyst headcount — and that belongs in a control surface, not a config file.

**Contains:**

- Four `Stat` tiles: current review cut-off, current block cut-off, the cost-optimal review point with its projected cost, and the queue size at the current settings as a share of the live sample.
- **Adjust card** — two range sliders (review 0–99, block 1–100), disabled entirely for non-admins. Validates that block sits above review. Three live projections update as you drag: projected cost with its distance above the optimum, review volume flagged "within capacity" or "EXCEEDS capacity", and the count of legitimate customers refused. Admins get Apply / Reset; analysts get a note explaining that moving a threshold changes every future decision and the merchant's whole false-positive exposure, so it needs `admin` — an `analyst` decides individual cases.
- **Cost curve** — an SVG line chart of expected cost against the review threshold at the nearest sampled block value. Points are colour-coded: current in `--text`, optimum in green, over-capacity in red. The current and optimal points carry numeric labels, and the whole chart has an `aria-label` stating the optimum, its cost, and the current projection. The copy points at the flat bottom explicitly: being in the right region matters, the exact value does not. The curve is drawn rather than reduced to "the optimum is 5" because an operator who can see the shape makes better calls than one handed a single number.
- **Change history** (admin only) — an audit table of when, who, from and to, filtered to `threshold_update` entries. The empty state explains the point: a change that leaves no trace makes every later "why was this blocked?" unanswerable, so each one is written to an append-only audit item.

**Calls:** `api.thresholds()`, `api.setThresholds()`, `api.audit()`.

---

## 8. Not-found page

Defined inline on the `path="*"` route in `App.tsx`. A centred "Not found" heading and one line: "Nothing at this address." with a plain `<a href="/">` back to the overview. Header and footer still render.

---

## 9. Cross-cutting behaviour

### Session handling (`auth.tsx`)

The access token lives in a **module variable** inside `api.ts` — never `localStorage` or `sessionStorage`. Web storage is readable by any injected script, so an XSS there becomes a durable account takeover; in memory the token dies with the tab. The refresh token is an httpOnly cookie that JavaScript cannot read at all. On mount, `AuthProvider` attempts one refresh to exchange that cookie for a fresh access token, which is what keeps a reload from logging you out without parking a long-lived credential where a script can reach it.

`api.ts` retries once on a 401 by silently refreshing, so a 15-minute access token does not surface as a spurious logout every quarter hour. Auth routes themselves are exempt from the retry to avoid a loop.

### Role-dependent rendering

Risk detail appears on Checkout, Orders and Offers for staff and not for customers. In every case the backend strips those fields from the response for a `customer` role — the pages render what arrives rather than hiding what they were given, so a UI bug cannot leak a score.

### Accessibility patterns in use

- A skip link to `#main` on every page.
- Decisions never rely on colour alone: every band carries a label and a glyph.
- `sr-only` `<caption>` on every data table.
- ARIA `meter` roles with min/max/now on all score bars.
- `role="tablist"` / `role="tab"` with `aria-selected` on the console tabs.
- Both SVG visualisations carry descriptive `aria-label`s, and the ring graph offers a full table equivalent.
- Keyboard-operable table rows in the queue.
- `role="alert"` on errors, `role="status"` on confirmations.

### Currency and formatting

`rupees()` in `api.ts` formats with `en-IN` grouping and a `₹` prefix, no decimals. The landing page adds its own `lakh()` helper for large figures.

---

## 10. Known gaps

- The landing page's metrics are a hardcoded mirror of `ml/artifacts/metrics.json`. A retrain requires editing the `M` object in `Landing.tsx`; nothing warns you if it drifts.
- `VITE_API_KEY` is compiled into the bundle and readable in devtools. It is not a secret — it exists so the local demo can reach the local backend, as `api.ts` states at the top.
- The console's transaction queue is backend process memory and is lost on restart.
- No password reset, email verification, or MFA screens exist.
- Returns are recorded and listed, but never scored.
