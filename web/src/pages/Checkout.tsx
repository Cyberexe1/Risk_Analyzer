import { useState } from 'react'
import {
  api,
  ApiError,
  rupees,
  type CustomerView,
  type ScoreResponse,
} from '../api'
import { ErrorNote, Reasons, ScoreDial, SubScoreBars } from '../components'

const PRODUCTS = [
  { id: 'p1', name: 'Wireless earbuds', price: 2499 },
  { id: 'p2', name: 'Mechanical keyboard', price: 6799 },
  { id: 'p3', name: 'Smartphone', price: 42999 },
  { id: 'p4', name: 'Phone case', price: 449 },
]

const PRESETS = {
  normal: {
    label: 'Returning customer',
    hint: 'Established account, own device, ordinary amount.',
    customer_id: 'CUST_000123',
    device_fp: 'dev_000123',
    ip_hash: 'ip_000123',
    payment_method: 'upi',
    repeats: 1,
    status: 'success' as const,
  },
  testing: {
    label: 'Card testing',
    hint: 'Fresh account hammering one device with mostly declines.',
    customer_id: 'CUST_DEMO_ATTACK',
    device_fp: 'dev_demo_attack',
    ip_hash: 'ip_demo_attack',
    payment_method: 'card',
    repeats: 8,
    status: 'failed' as const,
  },
  ring: {
    label: 'Ring member',
    hint: 'One of several fresh accounts sharing a device and IP.',
    customer_id: `CUST_DEMO_RING_${Math.floor(Math.random() * 6)}`,
    device_fp: 'dev_demo_ring',
    ip_hash: 'ip_demo_ring',
    payment_method: 'wallet',
    repeats: 2,
    status: 'success' as const,
  },
}

type PresetKey = keyof typeof PRESETS

/**
 * Customer checkout, with the analyst view shown side by side.
 *
 * In production these two are never on the same screen. A customer must never
 * see a score or a reason code — telling an attacker which signal fired is free
 * reconnaissance. They are together here only to make the split visible: the
 * left panel is what the shopper gets, the right is what the analyst gets, from
 * the exact same scoring call.
 */
export default function Checkout() {
  const [product, setProduct] = useState(PRODUCTS[0])
  const [preset, setPreset] = useState<PresetKey>('normal')
  const [busy, setBusy] = useState(false)
  const [customer, setCustomer] = useState<CustomerView | null>(null)
  const [analyst, setAnalyst] = useState<ScoreResponse | null>(null)
  const [error, setError] = useState<string | null>(null)

  async function pay() {
    setBusy(true)
    setError(null)
    setCustomer(null)
    setAnalyst(null)
    const p = PRESETS[preset]
    const now = Date.now() / 1000

    try {
      // Replay the preset's earlier attempts first so velocity and device
      // counters actually build. Scoring the last one cold would show nothing.
      for (let i = 0; i < p.repeats - 1; i++) {
        await api.score({
          customer_id: p.customer_id,
          amount: Math.max(60, Math.round(product.price / 12)),
          payment_method: p.payment_method,
          device_fp: p.device_fp,
          ip_hash: p.ip_hash,
          ts: now + i * 25,
          status: p.status,
        })
      }

      const body = {
        customer_id: p.customer_id,
        amount: product.price,
        payment_method: p.payment_method,
        device_fp: p.device_fp,
        ip_hash: p.ip_hash,
        ts: now + p.repeats * 25,
        status: 'success' as const,
      }
      // Two calls so both projections of the same decision are visible. A real
      // checkout calls one endpoint.
      const view = await api.checkout({ ...body, commit: false })
      const full = await api.score(body)
      setCustomer(view)
      setAnalyst(full)
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="wrap section-sm">
      <h1 style={{ fontSize: '1.9rem' }}>Checkout</h1>
      <p style={{ maxWidth: 620 }}>
        Pick a product and a behaviour pattern. The same scoring call feeds both panels
        below.
      </p>

      {error && (
        <div style={{ margin: '16px 0' }}>
          <ErrorNote error={error} />
        </div>
      )}

      <div className="grid" style={{ gridTemplateColumns: 'minmax(300px, 380px) 1fr' }}>
        {/* ---- cart ---- */}
        <div className="card">
          <h3>Basket</h3>
          <div className="field">
            <label htmlFor="product">Product</label>
            <select
              id="product"
              value={product.id}
              onChange={(e) =>
                setProduct(PRODUCTS.find((p) => p.id === e.target.value) ?? PRODUCTS[0])
              }
            >
              {PRODUCTS.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name} &mdash; {rupees(p.price)}
                </option>
              ))}
            </select>
          </div>

          <div className="field">
            <label htmlFor="preset">Behaviour pattern</label>
            <select
              id="preset"
              value={preset}
              onChange={(e) => setPreset(e.target.value as PresetKey)}
            >
              {Object.entries(PRESETS).map(([k, v]) => (
                <option key={k} value={k}>
                  {v.label}
                </option>
              ))}
            </select>
            <p className="muted" style={{ marginTop: 8, marginBottom: 0 }}>
              {PRESETS[preset].hint}
            </p>
          </div>

          <div
            className="spread"
            style={{ borderTop: '1px solid var(--line)', paddingTop: 16, marginTop: 4 }}
          >
            <span className="muted">Total</span>
            <strong className="mono" style={{ fontSize: 20 }}>
              {rupees(product.price)}
            </strong>
          </div>

          <button
            className="btn"
            onClick={pay}
            disabled={busy}
            style={{ width: '100%', marginTop: 16 }}
          >
            {busy ? 'Scoring\u2026' : 'Pay now'}
          </button>
        </div>

        {/* ---- results ---- */}
        <div className="stack">
          <div className="card">
            <div className="spread" style={{ marginBottom: 14 }}>
              <h3 style={{ margin: 0 }}>What the customer sees</h3>
              <span className="badge badge-neutral">shopper view</span>
            </div>
            {!customer && (
              <p className="muted" style={{ marginBottom: 0 }}>
                Nothing yet. Press &ldquo;Pay now&rdquo;.
              </p>
            )}
            {customer && (
              <>
                <div
                  className="note"
                  style={{
                    borderColor:
                      customer.status === 'declined'
                        ? 'rgba(242,84,91,.35)'
                        : customer.status === 'verifying'
                          ? 'rgba(242,177,52,.35)'
                          : 'rgba(53,200,138,.35)',
                  }}
                >
                  {customer.message}
                </div>
                <p className="muted" style={{ marginTop: 10, marginBottom: 0 }}>
                  Order <code>{customer.order_id}</code> &middot; no score, no sub-score, no
                  reason codes. That is deliberate.
                </p>
              </>
            )}
          </div>

          <div className="card">
            <div className="spread" style={{ marginBottom: 14 }}>
              <h3 style={{ margin: 0 }}>What the analyst sees</h3>
              <span className="badge badge-neutral">console view</span>
            </div>
            {!analyst && (
              <p className="muted" style={{ marginBottom: 0 }}>
                Same transaction, full evidence.
              </p>
            )}
            {analyst && (
              <div className="stack" style={{ gap: 20 }}>
                <ScoreDial score={analyst.risk_score} decision={analyst.decision} />
                <SubScoreBars sub={analyst.sub_scores} />
                <div>
                  <div className="sub-head" style={{ marginBottom: 8 }}>
                    <span>Why</span>
                  </div>
                  <Reasons codes={analyst.reason_codes} />
                </div>
                <div className="pill-row">
                  <span className="chip">{analyst.latency_ms} ms</span>
                  <span className="chip">{analyst.transaction_id}</span>
                  {analyst.override && <span className="chip">override: {analyst.override}</span>}
                  {analyst.degraded && <span className="chip">DEGRADED: no model</span>}
                </div>
                <p className="muted" style={{ marginBottom: 0 }}>
                  {Math.round(analyst.risk_score)} is a routing decision, not a verdict.
                  Ground truth only exists after an investigation or a chargeback.
                </p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
