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
  auth: string
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

export class ApiError extends Error {
  constructor(
    message: string,
    readonly httpStatus: number,
  ) {
    super(message)
    this.name = 'ApiError'
  }
}

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response
  try {
    res = await fetch(`${BASE}${path}`, {
      ...init,
      headers: {
        'content-type': 'application/json',
        ...(KEY ? { 'x-api-key': KEY } : {}),
        ...(init?.headers ?? {}),
      },
    })
  } catch {
    throw new ApiError(
      `Cannot reach the backend at ${BASE}. Start it with: uvicorn backend:app --port 8000`,
      0,
    )
  }

  if (res.status === 401) {
    throw new ApiError(
      'Rejected by the backend (401). VITE_API_KEY in web/.env must match FRAUDSHIELD_API_KEY.',
      401,
    )
  }
  if (!res.ok) {
    let detail = res.statusText
    try {
      const body = (await res.json()) as { detail?: unknown }
      if (body.detail) detail = JSON.stringify(body.detail)
    } catch {
      /* response had no JSON body */
    }
    throw new ApiError(detail, res.status)
  }
  return (await res.json()) as T
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
      { method: 'POST', body: JSON.stringify({ label, analyst_id: 'web' }) },
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
