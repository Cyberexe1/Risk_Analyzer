/**
 * Backend client.
 *
 * SECURITY NOTE: VITE_API_KEY is compiled into the JavaScript bundle and is
 * readable by anyone who opens devtools. It is not a secret. It exists so the
 * local demo can reach the local backend.
 *
 * In production the browser must never hold the backend key. Put a
 * session-authenticated server in front, or implement the JWT flow in
 * docs/ARCHITECTURE.md section 4 and drop the shared key.
 */

const BASE: string = import.meta.env.VITE_API_BASE ?? 'http://localhost:8000'
const KEY: string = import.meta.env.VITE_API_KEY ?? ''

export type Decision = 'ALLOW' | 'MANUAL_REVIEW' | 'BLOCK'

export interface SubScores {
  ml: number
  rules: number
  network: number
}

export interface ReasonCode {
  code: string
  severity: 'high' | 'medium'
  detail: string
  source: 'rule' | 'model'
  contribution?: number
}

export interface ScoreResponse {
  transaction_id: string
  risk_score: number
  decision: Decision
  sub_scores: SubScores
  reason_codes: ReasonCode[]
  override: string | null
  model_version: string
  degraded: boolean
  scored_at: string
  latency_ms: number
}

export interface CustomerView {
  order_id: string
  status: 'confirmed' | 'verifying' | 'declined'
  message: string
}

export interface QueueItem {
  transaction_id: string
  customer_id: string
  amount: number
  risk_score: number
  decision: Decision
  sub_scores: SubScores
  reason_codes: ReasonCode[]
  fired_rules: string[]
  override: string | null
  scored_at: string
  label: string | null
  /** present on orders placed through /v1/orders; lets the console pivot to the ring */
  device_fp?: string
  ip_hash?: string
  /** origin address flagged for a burst of failed payments; not a scoring input */
  ip_suspicious?: boolean
}

export interface Health {
  status: string
  model_loaded: boolean
  model_version: string | null
  thresholds: { review: number; block: number } | null
  store: string
  service_auth: string
  user_auth: string
  user_store: string
  record_store: string
  /** Analyst alerting mode. Optional because an older backend will not send it.
   *  Never carries credentials, a sender or recipient addresses. */
  email_notifications?: {
    provider: string
    configured: boolean
    degraded: boolean
    alerts_enabled: boolean
    recipient_count: number
    note: string
    sent: number
    failed: number
  } | null
  // Which gateway is actually serving checkout, and whether Razorpay credentials
  // exist. Optional because an older backend will not send them.
  payment_provider?: string | null
  razorpay_configured?: boolean
  payment_provider_status?: {
    payment_provider: string
    requested_provider: string
    razorpay_configured: boolean
    degraded: boolean
    note: string
  } | null
  /** Whether the admin-only synthetic-attack trigger would run, and which gate is
   *  closed if it would not. Optional because an older backend will not send it,
   *  which is why the console treats `undefined` as "not available" rather than
   *  as "enabled". Carries no credentials and no environment values. */
  demo?: DemoStatus | null
  admin_requires_role: string[]
}

/** Readiness of the demo fraud-attack trigger. Both gates are reported
 *  separately so the console can say WHY the control is unavailable instead of
 *  showing a button that can only fail. */
export interface DemoStatus {
  enabled: boolean
  demo_mode: boolean
  provider_is_simulated: boolean
  scenario: string
  attempts: number
  window_seconds: number
  blocked_because: string[]
}

/** One generated attempt.
 *
 *  `risk_score`, `decision`, `sub_scores` and `fired_rules` are values the real
 *  scorer returned. The trigger does not compute them, and the console must not
 *  re-derive them either — a UI that recomputed a score could disagree with the
 *  queue and the audit trail. */
export interface DemoAttempt {
  attempt: number
  transaction_id: string
  order_id: string
  at: string
  amount: number
  payment_method: string
  settlement: string
  risk_score: number
  decision: Decision
  sub_scores: { ml: number; rules: number; network: number }
  fired_rules: string[]
  override: string | null
  txn_count_10m: number
  amount_ratio: number
}

export interface DemoAttackResult {
  scenario: string
  demo: true
  attempts_generated: number
  customer_id: string
  customer_email: string
  device_id: string
  ip_hash: string
  window_seconds: number
  first_attempt_at: string
  last_attempt_at: string
  baseline: {
    transactions: number
    span_days: number
    account_age_days: number
    average_amount: number
    device_fp: string
    persisted: boolean
    scored: boolean
    note: string
  }
  results: DemoAttempt[]
  final_transaction: {
    transaction_id: string
    risk_score: number
    decision: Decision
    sub_scores: { ml: number; rules: number; network: number }
    fired_rules: string[]
  }
  decisions: Record<string, number>
  /** Union across the burst: a rule that fired on attempt 3 is evidence the
   *  scenario produced it even if attempt 8 no longer trips it. */
  signals: string[]
  evidence: Record<string, number | null>
  thresholds: { review: number; block: number }
  model_version: string | null
  degraded: boolean
  transactions_persisted: number
  queued_for_review: number
  ip_flagged: boolean
  notification_triggered: boolean
  /** Counts keyed by the existing notification statuses: sent, failed, skipped,
   *  suppressed. `skipped` means no recipients are configured — which is not a
   *  delivery failure and must not be shown as one. */
  notifications: Record<string, number>
  email_provider: string | null
  alerts_enabled: boolean
  audit_created: boolean
  audit_events: number
  creates_ground_truth: false
  moves_money: false
  note: string
}

export interface ScoreRequest {
  customer_id: string
  amount: number
  payment_method: string
  device_fp: string
  ip_hash: string
  ts?: number
  status?: 'success' | 'failed'
  commit?: boolean
}

export interface PublicUser {
  user_id: string
  email: string
  role: 'customer' | 'analyst' | 'admin'
  created_at: string
}

export interface AuthResponse {
  access_token: string
  token_type: string
  expires_in: number
  user: PublicUser
}

export class ApiError extends Error {
  constructor(
    message: string,
    readonly httpStatus: number,
  ) {
    super(message)
    this.name = 'ApiError'
  }
}

/**
 * Access token lives in a module variable — deliberately NOT localStorage or
 * sessionStorage. Web storage is readable by any injected script, so an XSS
 * there becomes a durable account takeover. In memory it dies with the tab, and
 * the httpOnly refresh cookie restores the session on reload.
 */
let accessToken: string | null = null

export function setAccessToken(t: string | null) {
  accessToken = t
}
export function getAccessToken() {
  return accessToken
}

async function raw(path: string, init?: RequestInit): Promise<Response> {
  // PUT is used by the threshold tuner; the backend's CORS allow_methods must
  // include it or the preflight fails.
  try {
    return await fetch(`${BASE}${path}`, {
      ...init,
      // Sends the httpOnly refresh cookie. Works only because the backend's
      // CORS origin list is explicit; a wildcard plus credentials is rejected.
      credentials: 'include',
      headers: {
        'content-type': 'application/json',
        ...(KEY ? { 'x-api-key': KEY } : {}),
        ...(accessToken ? { authorization: `Bearer ${accessToken}` } : {}),
        ...(init?.headers ?? {}),
      },
    })
  } catch {
    throw new ApiError(
      `Cannot reach the backend at ${BASE}. Start it with: uvicorn backend:app --port 8000`,
      0,
    )
  }
}

async function fail(res: Response): Promise<never> {
  let detail = res.statusText
  try {
    const body = (await res.json()) as { detail?: unknown }
    if (body.detail) {
      detail = typeof body.detail === 'string' ? body.detail : JSON.stringify(body.detail)
    }
  } catch {
    /* no JSON body */
  }
  throw new ApiError(detail, res.status)
}

/** One silent refresh attempt on 401, then retry. Prevents a 15-minute access
 *  token from surfacing as a spurious "logged out" every quarter hour. */
async function req<T>(path: string, init?: RequestInit, retry = true): Promise<T> {
  let res = await raw(path, init)

  if (res.status === 401 && retry && !path.startsWith('/v1/auth/')) {
    try {
      const r = await req<AuthResponse>('/v1/auth/refresh', { method: 'POST' }, false)
      setAccessToken(r.access_token)
      res = await raw(path, init)
    } catch {
      setAccessToken(null)
      return fail(res)
    }
  }

  if (!res.ok) return fail(res)
  return (await res.json()) as T
}

export const authApi = {
  register: (email: string, password: string) =>
    req<AuthResponse>('/v1/auth/register', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    }),
  login: (email: string, password: string) =>
    req<AuthResponse>('/v1/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    }),
  refresh: () => req<AuthResponse>('/v1/auth/refresh', { method: 'POST' }, false),
  logout: () => req<{ ok: boolean }>('/v1/auth/logout', { method: 'POST' }, false),
  me: () => req<PublicUser>('/v1/auth/me'),
}

export interface Product {
  id: string
  name: string
  price: number
  category: string
  stock: number
}

export interface PaymentMethodMeta {
  code: string
  label: string
  needs: 'vpa' | 'card' | 'bank' | 'wallet' | null
}

export interface Catalogue {
  products: Product[]
  payment_methods: PaymentMethodMeta[]
  banks: { code: string; name: string }[]
  wallets: string[]
}

export interface OrderLine {
  product_id: string
  name: string
  qty: number
  unit_price: number
}

export type OrderStatus = 'confirmed' | 'verifying' | 'declined' | 'declined_by_bank'

export interface Order {
  order_id: string
  product_name: string
  items: OrderLine[]
  item_count: number
  amount: number
  payment_method: string
  instrument_display: string | null
  created_at: string
  status: OrderStatus
  return_status: string | null
  /** staff only — the backend omits these for customers */
  risk_score?: number
  decision?: Decision
  sub_scores?: SubScores
  transaction_id?: string
  settlement?: string
  instrument_account_count?: number
}

/** `ip_hash` is deliberately absent: the backend derives it from the connection.
 *  A client that could choose its own would walk past every IP-based control. */
export interface CreateOrderBody {
  items: { product_id: string; qty: number }[]
  payment_method: string
  device_fp: string
  card?: {
    number: string
    expiry_month: number
    expiry_year: number
    cvv: string
    holder?: string
  }
  upi?: { vpa: string }
  netbanking?: { bank_code: string }
  wallet?: { provider: string; phone: string }
}

/** An address flagged for a burst of failed payments. */
export interface IpFlag {
  /** True only on the attempt that first raised the flag. */
  new?: boolean
  ip_hash: string
  since: string
  reason: string
  failures_in_window?: number
  failures_total: number
  accounts: number
}

export interface OrderResult {
  order_id: string
  status: OrderStatus
  message: string
  items: OrderLine[]
  amount: number
  payment_method: string
  instrument_display: string
  /** 'success' | 'failed' — the authorisation outcome, distinct from the risk decision. */
  settlement?: string
  risk?: {
    transaction_id: string
    risk_score: number
    decision: Decision
    sub_scores: SubScores
    reason_codes: ReasonCode[]
    override: string | null
    settlement: string
    ip_hash: string
    instrument_account_count: number
    /** Present and non-null only when this attempt left the address flagged. */
    ip_suspicious?: IpFlag | null
  }
}

export interface FailedAttempt {
  attempt_id: string
  order_id: string
  transaction_id: string
  customer_id: string
  email: string
  amount: number
  payment_method: string
  instrument_display: string
  device_fp: string
  ip_hash: string
  risk_score: number
  decision: Decision
  customer_status: string
  created_at: string
  ip_suspicious?: boolean
}

export interface SuspiciousIp extends IpFlag {
  transactions: number
  source: 'live' | 'persisted'
  attempts: FailedAttempt[]
  attempt_count: number
  accounts_involved: string[]
}

export interface ReturnRecord {
  return_id: string
  order_id: string
  reason: string
  detail: string
  amount: number
  product_name: string
  created_at: string
  status: string
}

export const shopApi = {
  catalogue: () => req<Catalogue>('/v1/catalog/products'),
  createOrder: (body: CreateOrderBody) =>
    req<OrderResult>('/v1/orders', { method: 'POST', body: JSON.stringify(body) }),
  orders: () => req<{ count: number; orders: Order[] }>('/v1/orders'),
  requestReturn: (order_id: string, reason: string, detail: string) =>
    req<{ return_id: string; status: string; message: string }>('/v1/returns', {
      method: 'POST',
      body: JSON.stringify({ order_id, reason, detail }),
    }),
  returns: () => req<{ count: number; returns: ReturnRecord[] }>('/v1/returns'),
}

export interface Offer {
  code: string
  name: string
  value: number
  blurb: string
}

export interface RedeemResult {
  redemption_id: string
  promo_code: string
  status: 'credited' | 'under_review' | 'denied'
  message: string
  risk?: {
    decision: 'ALLOW' | 'HOLD' | 'DENY'
    fired_rules: string[]
    reasons: ReasonCode[]
    features: Record<string, number>
    shared_ip_exempt: boolean
  }
}

export interface MyRedemption {
  redemption_id: string
  promo_code: string
  value: number
  status: string
  created_at: string
}

export interface PromoHold {
  redemption_id: string
  promo_code: string
  email: string
  value: number
  status: string
  decision: string
  created_at: string
  reasons: ReasonCode[]
  fired_rules: string[]
  shared_ip_exempt: boolean
  features: Record<string, number>
}

export interface GateMetrics {
  threshold: number
  precision: number
  recall: number
  /** 2PR/(P+R). Optional because artifacts generated before F1 was reported do
   *  not carry it, and a missing metric must render as absent rather than 0. */
  f1?: number
  fp_rate: number
  volume_share: number
  tp: number
  fp: number
  fn: number
  tn: number
}

/** Classification metrics at the selected operating point, with the definitions
 *  spelled out. Optional for the same backwards-compatibility reason as `f1`. */
export interface ClassificationMetrics {
  operating_point: { review: number; block: number }
  operating_point_selection: string
  flagged_gate: {
    definition: string
    precision: number
    recall: number
    f1: number
    tp: number
    fp: number
    fn: number
    tn: number
  }
  block_gate: {
    definition: string
    precision: number
    recall: number
    f1: number
    tp: number
    fp: number
    fn: number
    tn: number
  }
  definitions: Record<string, string>
}

export interface TransactionMetrics {
  test_rows: number
  test_fraud: number
  test_fraud_rate: number
  ranking: { pr_auc: number; roc_auc: number; brier_calibrated: number }
  thresholds: { review: number; block: number }
  review_gate: GateMetrics
  block_gate: GateMetrics
  classification?: ClassificationMetrics
  confusion: {
    tp_block: number
    fp_block: number
    tp_review: number
    fp_review: number
    fn: number
    tn: number
  }
  recall_by_archetype: Record<string, number>
  baselines: Record<string, { pr_auc: number; cost: number; review_gate?: GateMetrics }>
  cost: {
    do_nothing: number
    with_fraudshield: number
    net_saving: number
    net_saving_pct: number
    false_positive_cost: number
    false_positive_share_of_remaining: number
    /** Cost of fraud allowed through. Optional: older artifacts omit it. */
    false_negative_cost?: number
    cost_breakdown?: {
      fraud_allowed_through: number
      legit_blocked: number
      legit_reviewed: number
      fraud_reviewed: number
      fraud_blocked: number
    }
    legit_blocked: number
    fraud_missed?: number
    /** States that these are assumptions, not observed losses. */
    basis?: string
    unit_costs: Record<string, number>
  }
  fairness: Record<string, { n: number; review_rate: number; block_rate: number; ratio_vs_overall: number }>
  caveats: string[]
}

export interface PromoMetrics {
  abuse_rate: { overall: number; validation: number; test: number }
  rows: { total: number; validation: number; test: number }
  gate: {
    precision: number
    recall: number
    f1?: number
    fp_rate: number
    tp: number
    fp: number
    fn: number
    tn: number
  }
  deny: { n: number; fp: number; precision: number | null }
  hold: { n: number; fp: number; precision: number | null }
  per_rule: Record<string, { detections: number; precision: number | null; action?: string }>
  thresholds: Record<string, number>
  cost: {
    no_gate: number
    with_gate: number
    net_saving: number
    false_positive_cost: number
  }
  caveats: string[]
}

export interface AdminMetrics {
  transaction: TransactionMetrics | null
  promo: PromoMetrics | null
  missing: string[]
}

export interface RingNode {
  id: string
  type: 'account' | 'device' | 'ip'
  label: string
  is_seed: boolean
  txn_count?: number
  fail_count?: number
  active_24h?: number
  account_count?: number
  suspicious?: boolean
  shared_infra?: boolean
}

export interface RingEdge {
  source: string
  target: string
  kind: 'device' | 'ip'
}

/** Money associated with a connected component, split by what the engine decided.
 *
 *  Read `definition` before showing any of these numbers. This is NOT a loss
 *  estimate: `blocked_amount` never settled, and `confirmed_fraud_amount` is null
 *  until a human has actually labelled something. */
export interface RingExposure {
  gross_exposure: number
  blocked_amount: number
  review_amount: number
  allowed_amount: number
  unclassified_amount: number
  settled_amount: number
  confirmed_fraud_amount: number | null
  labelled_transactions: number
  transactions_counted: number
  transactions_skipped: number
  accounts_in_component: number
  accounts_with_transactions: number
  window: {
    kind: string
    earliest: string | null
    latest: string | null
    retained_transaction_cap: number
    note: string
  }
  complete: boolean
  definition: string
  is_loss_estimate: boolean
}

export interface RingGraph {
  seed: { type: string; id: string }
  depth: number
  truncated: boolean
  counts: { accounts: number; devices: number; ips: number; edges: number }
  exposure?: RingExposure
  nodes: RingNode[]
  edges: RingEdge[]
}

export interface SweepPoint {
  review: number
  block: number
  cost: number
  review_volume: number
  legit_blocked: number
  within_capacity: boolean
}

export interface LiveProjection {
  review: number
  block: number
  would_block: number
  would_review: number
  review_share: number
}

/** Where the live thresholds came from. `degraded: true` means a stored
 *  configuration was rejected and the running values are NOT the ones an admin
 *  last set. */
export interface ThresholdConfig {
  source: 'persisted' | 'env'
  review: number
  block: number
  env_defaults: { review: number; block: number }
  version: number | null
  updated_at: string | null
  updated_by: string | null
  degraded: boolean
  note: string
  rejected?: { review: unknown; block: unknown; version: unknown }
}

export interface ThresholdInfo {
  current: { review: number; block: number }
  config?: ThresholdConfig | null
  source: string
  cost_curve: SweepPoint[]
  cost_curve_note: string
  live_projection: LiveProjection[]
  live_sample_size: number
  caveat: string
}

/** One audit row.
 *
 *  `before`/`after` are deliberately loose: the partition holds several event
 *  shapes (RISK_DECISION, OUTCOME_RECORDED, PROMO_OVERRIDE, threshold_update,
 *  MODEL_FALLBACK_TRIGGERED, payment_event_ingested) and narrowing the type here
 *  would mean either lying about one of them or maintaining six near-duplicates.
 *  The Audit view reads the fields it recognises and shows the rest as JSON. */
export interface AuditEntry {
  actor: string
  action: string
  before: Record<string, unknown>
  after: Record<string, unknown>
  at: string
  event_id?: string
  /** Present only on human-originated events, derived from the authenticated
   *  token. Absent on automated, communication and system events — which is how
   *  the UI can tell a person acted without trusting the action name. */
  actor_identity?: { user_id: string; email: string; role: string } | null
}

/** Response envelope for the audit log.
 *
 *  `source` and `complete` are not decoration. The endpoint used to fall back to
 *  its in-process log whenever the durable read came back empty — including when
 *  it came back empty because it failed — so an incomplete trail looked healthy. */
export interface AuditQuery {
  limit?: number
  action?: string
  /** A single UTC date, YYYY-MM-DD. */
  date?: string
  startDate?: string
  endDate?: string
  /** Opaque continuation token from a previous page. */
  cursor?: string
  actor?: string
  transactionId?: string
  orderId?: string
  redemptionId?: string
}

export interface AuditLog {
  count: number
  entries: AuditEntry[]
  /** `partial` means at least one date in a range could not be read. */
  source: 'persistent' | 'memory_fallback' | 'partial' | 'empty'
  complete: boolean
  warning: string | null
  has_more: boolean
  next_cursor: string | null
  limit: number
  days_requested: string[]
  days_read: string[]
  days_failed: string[]
  day: string
  filters: Record<string, string | null> | null
  note: string
}

/** One analyst alert delivery.
 *
 *  This is the server's allow-listed projection, not the stored record. Recipient
 *  addresses, the message body and the raw transport error are deliberately NOT
 *  in it — only a count and an error category. */
export interface NotificationRecord {
  notification_id: string
  event_type: string
  status: 'sent' | 'failed' | 'skipped' | 'suppressed'
  provider: string
  recipient_count: number
  transaction_id?: string | null
  order_id?: string | null
  redemption_id?: string | null
  ip_hash?: string | null
  created_at: string
  sent_at: string | null
  error_category: string | null
  attempts: number
  durable?: boolean
}

/** Email mode as published by the backend. Carries no credentials, no sender and
 *  no recipient addresses — a count only. */
export interface EmailStatus {
  provider: string
  requested_provider?: string
  configured: boolean
  degraded: boolean
  alerts_enabled: boolean
  recipient_count: number
  recipients_rejected?: number
  note: string
}

export interface NotificationLog {
  count: number
  counts: { total: number; sent: number; failed: number; skipped: number }
  email: EmailStatus
  items: NotificationRecord[]
  note: string
}

/** The bounded automated-action policy, as the backend actually holds it. */
export interface ActionPolicy {
  policy_version: string
  decisions: Record<
    string,
    {
      automated_action: string
      reason: string
      permitted: string[]
      reversible_by_human: boolean
    }
  >
  never_automated: string[]
  thresholds: { review: number; block: number }
  ground_truth_source: string
  note: string
}

export const promoApi = {
  offers: () => req<{ offers: Offer[] }>('/v1/promo/offers'),
  redeem: (body: { promo_code: string; device_fp: string; payout_ref: string }) =>
    req<RedeemResult>('/v1/promo/redeem', { method: 'POST', body: JSON.stringify(body) }),
  mine: () => req<{ count: number; redemptions: MyRedemption[] }>('/v1/promo/mine'),
  holds: () => req<{ count: number; items: PromoHold[] }>('/v1/admin/promo-holds'),
  /** An override is human ground truth and is audited as PROMO_OVERRIDE. The
   *  optional reason is recorded on that event, never used to decide anything. */
  override: (rid: string, reason = '') =>
    req<{ redemption_id: string; status: string; note: string }>(
      `/v1/admin/promo-holds/${rid}/override`,
      { method: 'POST', body: JSON.stringify({ reason }) },
    ),
}

export const api = {
  health: () => req<Health>('/health'),
  score: (body: ScoreRequest) =>
    req<ScoreResponse>('/v1/risk/score', {
      method: 'POST',
      body: JSON.stringify(body),
    }),
  checkout: (body: ScoreRequest) =>
    req<CustomerView>('/v1/checkout', {
      method: 'POST',
      body: JSON.stringify(body),
    }),
  queue: () => req<{ count: number; items: QueueItem[] }>('/v1/admin/queue'),
  metrics: () => req<AdminMetrics>('/v1/admin/metrics'),
  ring: (type: 'device' | 'ip' | 'account', id: string, depth = 2) =>
    req<RingGraph>(`/v1/admin/rings/${type}/${encodeURIComponent(id)}?depth=${depth}`),
  thresholds: () => req<ThresholdInfo>('/v1/admin/thresholds'),
  setThresholds: (review: number, block: number, reason = '') =>
    req<{
      current: { review: number; block: number }
      previous: { review: number; block: number }
      version?: number
      persisted?: boolean
    }>('/v1/admin/thresholds', {
      method: 'PUT',
      body: JSON.stringify({ review, block, reason }),
    }),
  /** Audit rows, newest first. `action` filters by event type; `limit` is applied
   *  after filtering, and `count` is the pre-limit total so the caller can tell
   *  more exist. */
  /** Audit history. Omit the dates for today; pass `date` for one UTC day, or
   *  `startDate`+`endDate` for a bounded range read newest day first. `cursor` is
   *  the opaque token from a previous page's `next_cursor`. */
  audit: (opts: AuditQuery = {}) => {
    const q = new URLSearchParams({ limit: String(opts.limit ?? 50) })
    for (const [k, v] of [
      ['action', opts.action],
      ['date', opts.date],
      ['start_date', opts.startDate],
      ['end_date', opts.endDate],
      ['cursor', opts.cursor],
      ['actor', opts.actor],
      ['transaction_id', opts.transactionId],
      ['order_id', opts.orderId],
      ['redemption_id', opts.redemptionId],
    ] as [string, string | undefined][]) {
      if (v) q.set(k, v)
    }
    return req<AuditLog>(`/v1/admin/audit?${q}`)
  },
  policy: () => req<ActionPolicy>('/v1/admin/policy'),
  /** Analyst alert delivery history. `status` and `event_type` filter
   *  server-side; `counts` is always pre-filter so a filtered view still shows
   *  that failures exist. */
  notifications: (status?: string, eventType?: string, limit = 50) => {
    const q = new URLSearchParams({ limit: String(limit) })
    if (status) q.set('status', status)
    if (eventType) q.set('event_type', eventType)
    return req<NotificationLog>(`/v1/admin/notifications?${q}`)
  },
  suspiciousIps: () =>
    req<{
      count: number
      threshold: number
      window_minutes: number
      items: SuspiciousIp[]
    }>('/v1/admin/suspicious-ips'),
  failedAttempts: () =>
    req<{ count: number; items: FailedAttempt[] }>('/v1/admin/failed-attempts'),
  outcome: (id: string, label: 'fraud' | 'legitimate') =>
    req<{ transaction_id: string; label: string }>(
      `/v1/admin/transactions/${id}/outcome`,
      { method: 'POST', body: JSON.stringify({ label }) },
    ),
  /** Generate one synthetic attack. Admin-only and demo-mode-only, both enforced
   *  server-side; 403 when the flag is off, 409 when a real gateway is active.
   *
   *  Deliberately takes NO arguments. The attempt count, amounts, timing, device
   *  and address are all fixed in the backend — a caller-supplied count is how a
   *  demo control turns into a way to write a million rows. */
  demoFraudAttack: () =>
    req<DemoAttackResult>('/v1/admin/demo/fraud-attack', { method: 'POST' }),
}

/** The audit event types the console can filter on.
 *
 *  `action` is the exact wire value the backend emits, and `threshold_update` is
 *  deliberately lower-case unlike the rest: that spelling already exists in
 *  persisted audit partitions, so renaming it would orphan every historical
 *  record. The `label` is what the UI shows. */
/** Four categories, because three conflated two different things.
 *
 *  `NOTIFICATION_*` used to be bucketed as `system` alongside a model fallback.
 *  They are not the same kind of fact: a fallback changed how the engine scores,
 *  an alert changed nothing at all and only says somebody was told. Splitting
 *  COMMUNICATION out keeps "what the system did" separate from "who we informed". */
export const AUDIT_ACTIONS = [
  { action: 'RISK_DECISION', label: 'Risk decision', kind: 'automated' },
  { action: 'OUTCOME_RECORDED', label: 'Human outcome', kind: 'human' },
  { action: 'PROMO_OVERRIDE', label: 'Promo override', kind: 'human' },
  { action: 'threshold_update', label: 'Threshold update', kind: 'human' },
  { action: 'NOTIFICATION_SENT', label: 'Alert sent', kind: 'communication' },
  { action: 'NOTIFICATION_FAILED', label: 'Alert failed', kind: 'communication' },
  { action: 'payment_event_ingested', label: 'Payment event', kind: 'system' },
  { action: 'ip_marked_suspicious', label: 'IP flagged', kind: 'system' },
  { action: 'MODEL_FALLBACK_TRIGGERED', label: 'Model fallback', kind: 'system' },
  // A human asked for synthetic traffic. Filterable on purpose: an operator
  // investigating a real incident needs to be able to separate demo runs from it,
  // and the individual synthetic RISK_DECISIONs carry `demo: true` in `after`.
  { action: 'DEMO_ATTACK_TRIGGERED', label: 'Demo attack', kind: 'human' },
] as const

export type AuditKind = 'automated' | 'human' | 'communication' | 'system'

/** Who or what produced an audit event, and how to present it.
 *
 *  This distinction is the whole point of the audit view. An automated routing
 *  decision and a human ground-truth verdict are different KINDS of fact, and a
 *  reader who confuses them will believe the machine confirmed fraud. So the
 *  classification is derived from the actor, not guessed from the action name:
 *  an email address is a person, `system:*` and `webhook` are not.
 *
 *  Falls back on the action table, so an event type added to the backend before
 *  this list is updated is still classified rather than silently rendered as
 *  human. */
export function auditKind(entry: AuditEntry): AuditKind {
  const known = AUDIT_ACTIONS.find((a) => a.action === entry.action)?.kind
  const actor = (entry.actor || '').toLowerCase()

  // An emailed actor is a person. Checked FIRST and allowed to override the
  // table, because the actor is the ground truth about who acted — the action
  // name is only a hint.
  if (actor.includes('@')) return 'human'

  // A system actor can never be classified human, whatever the table says.
  if (actor.startsWith('system:') || actor === 'system' || actor === 'webhook') {
    return known && known !== 'human' ? known : 'automated'
  }

  // Unknown actor AND unknown action: default to automated, never human. A
  // machine action mislabelled as a human verdict would invent ground truth that
  // nobody created.
  return known ?? 'automated'
}

export function auditKindLabel(kind: AuditKind) {
  switch (kind) {
    case 'human':
      return { label: 'HUMAN', cls: 'chip-human', glyph: '\u25C6' }
    case 'communication':
      return { label: 'COMMUNICATION', cls: 'chip-communication', glyph: '\u25B2' }
    case 'system':
      return { label: 'SYSTEM', cls: 'chip-system', glyph: '\u25A0' }
    default:
      return { label: 'AUTOMATED', cls: 'chip-automated', glyph: '\u25CF' }
  }
}

/** Whether an event claims to be ground truth, read from the event rather than
 *  inferred from its category.
 *
 *  Both spellings are accepted: `OUTCOME_RECORDED` has always used
 *  `ground_truth`, every other event uses `is_ground_truth`. Returns null when
 *  the event states neither — a threshold change is an authorised human action
 *  that is deliberately NOT ground truth, and showing "false" there would imply
 *  it had been evaluated and rejected. */
export function auditGroundTruth(entry: AuditEntry): boolean | null {
  const a = entry.after ?? {}
  if (typeof a.is_ground_truth === 'boolean') return a.is_ground_truth
  if (typeof a.ground_truth === 'boolean') return a.ground_truth
  return null
}

/** The authenticated identity behind a human event, when one was recorded. */
export function auditActorRole(entry: AuditEntry): string | null {
  const id = entry.actor_identity
  return id && typeof id.role === 'string' ? id.role : null
}

/** Human-readable label for an audit action, falling back to the raw value so an
 *  unknown event type is still shown rather than hidden. */
export function auditActionLabel(action: string) {
  return AUDIT_ACTIONS.find((a) => a.action === action)?.label ?? action
}

/** Risk band presentation. Colour is never the only signal — each band carries
 *  a label and a glyph so the UI works in greyscale and for colour-blind users. */
export function band(decision: Decision) {
  switch (decision) {
    case 'BLOCK':
      return { cls: 'block', label: 'Block', glyph: '\u25B2', colour: 'var(--block)' }
    case 'MANUAL_REVIEW':
      return { cls: 'review', label: 'Review', glyph: '\u25C6', colour: 'var(--review)' }
    default:
      return { cls: 'allow', label: 'Allow', glyph: '\u25CF', colour: 'var(--allow)' }
  }
}

export const rupees = (n: number) =>
  `\u20B9${n.toLocaleString('en-IN', { maximumFractionDigits: 0 })}`
