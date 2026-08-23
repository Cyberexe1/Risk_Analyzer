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
  admin_requires_role: string[]
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
}

export interface Order {
  order_id: string
  product_name: string
  amount: number
  payment_method: string
  created_at: string
  status: 'confirmed' | 'verifying' | 'declined'
  return_status: string | null
  /** staff only — the backend omits these for customers */
  risk_score?: number
  decision?: Decision
  sub_scores?: SubScores
  transaction_id?: string
}

export interface OrderResult {
  order_id: string
  status: 'confirmed' | 'verifying' | 'declined'
  message: string
  product_name: string
  amount: number
  risk?: {
    transaction_id: string
    risk_score: number
    decision: Decision
    sub_scores: SubScores
    reason_codes: ReasonCode[]
    override: string | null
  }
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
  products: () => req<{ products: Product[] }>('/v1/catalog/products'),
  createOrder: (body: {
    product_id: string
    payment_method: string
    device_fp: string
    ip_hash: string
  }) => req<OrderResult>('/v1/orders', { method: 'POST', body: JSON.stringify(body) }),
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

export const promoApi = {
  offers: () => req<{ offers: Offer[] }>('/v1/promo/offers'),
  redeem: (body: {
    promo_code: string
    device_fp: string
    ip_hash: string
    payout_ref: string
  }) => req<RedeemResult>('/v1/promo/redeem', { method: 'POST', body: JSON.stringify(body) }),
  mine: () => req<{ count: number; redemptions: MyRedemption[] }>('/v1/promo/mine'),
  holds: () => req<{ count: number; items: PromoHold[] }>('/v1/admin/promo-holds'),
  override: (rid: string) =>
    req<{ redemption_id: string; status: string; note: string }>(
      `/v1/admin/promo-holds/${rid}/override`,
      { method: 'POST', body: JSON.stringify({}) },
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
  outcome: (id: string, label: 'fraud' | 'legitimate') =>
    req<{ transaction_id: string; label: string }>(
      `/v1/admin/transactions/${id}/outcome`,
      { method: 'POST', body: JSON.stringify({ label }) },
    ),
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
