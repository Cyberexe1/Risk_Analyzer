import { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { ApiError, rupees, shopApi, type OrderResult, type Product } from '../api'
import { ErrorNote, Reasons, ScoreDial, SubScoreBars } from '../components'
import { useAuth } from '../auth'

/** Stand-in for a real device fingerprint. A production integration would use an
 *  opaque client-generated hash; this is stable per browser and good enough to
 *  make device-linkage signals move in a demo. */
function deviceFingerprint(): string {
  const k = 'fs_device'
  let v = localStorage.getItem(k)
  if (!v) {
    v = `dev_web_${Math.random().toString(36).slice(2, 10)}`
    localStorage.setItem(k, v)
  }
  return v
}

const PATTERNS = {
  self: {
    label: 'This browser (normal)',
    hint: 'Your own device and network. What an ordinary customer looks like.',
    device: null as string | null,
    ip: 'ip_web_self',
    repeats: 1,
  },
  testing: {
    label: 'Card-testing device',
    hint: 'A device already associated with rapid declined attempts.',
    device: 'dev_demo_attack',
    ip: 'ip_demo_attack',
    repeats: 6,
  },
  ring: {
    label: 'Shared ring device',
    hint: 'A device and IP shared by several other fresh accounts.',
    device: 'dev_demo_ring',
    ip: 'ip_demo_ring',
    repeats: 2,
  },
}

type PatternKey = keyof typeof PATTERNS

export default function Checkout() {
  const { user, loading: authLoading } = useAuth()
  const nav = useNavigate()

  const [products, setProducts] = useState<Product[]>([])
  const [pid, setPid] = useState('p1')
  const [method, setMethod] = useState('upi')
  const [pattern, setPattern] = useState<PatternKey>('self')
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState<OrderResult | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    void shopApi
      .products()
      .then((r) => setProducts(r.products))
      .catch((e) => setError(e instanceof ApiError ? e.message : String(e)))
  }, [])

  const product = products.find((p) => p.id === pid)

  async function pay() {
    setBusy(true)
    setError(null)
    setResult(null)
    const p = PATTERNS[pattern]
    const device = p.device ?? deviceFingerprint()

    try {
      // Build up history first so velocity and device-linkage signals actually
      // have something to see. A single cold request shows nothing interesting.
      for (let i = 0; i < p.repeats - 1; i++) {
        await shopApi.createOrder({
          product_id: 'p4',
          payment_method: 'card',
          device_fp: device,
          ip_hash: p.ip,
        })
      }
      setResult(
        await shopApi.createOrder({
          product_id: pid,
          payment_method: method,
          device_fp: device,
          ip_hash: p.ip,
        }),
      )
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }

  if (authLoading) {
    return <div className="wrap section center muted">Checking your session&hellip;</div>
  }

  if (!user) {
    return (
      <div className="wrap-narrow section" style={{ maxWidth: 480 }}>
        <div className="card card-lift center">
          <h1 style={{ fontSize: '1.5rem' }}>Sign in to check out</h1>
          <p>
            Orders are tied to an account, because the account is what the risk engine
            builds a history against.
          </p>
          <div className="row" style={{ justifyContent: 'center' }}>
            <button className="btn" onClick={() => nav('/signup')} style={{ flex: '0 0 auto' }}>
              Create an account
            </button>
            <button
              className="btn btn-ghost"
              onClick={() => nav('/login', { state: { from: '/checkout' } })}
              style={{ flex: '0 0 auto' }}
            >
              Log in
            </button>
          </div>
        </div>
      </div>
    )
  }

  const staff = user.role === 'analyst' || user.role === 'admin'
  const statusColour =
    result?.status === 'declined'
      ? 'rgba(242,84,91,.35)'
      : result?.status === 'verifying'
        ? 'rgba(242,177,52,.35)'
        : 'rgba(53,200,138,.35)'

  return (
    <div className="wrap section-sm">
      <h1 style={{ fontSize: '1.9rem' }}>Checkout</h1>
      <p style={{ maxWidth: 640 }}>
        Every order here is real: it is scored, persisted, and shows up in{' '}
        <Link to="/orders">your orders</Link>.
      </p>

      {error && (
        <div style={{ margin: '16px 0' }}>
          <ErrorNote error={error} />
        </div>
      )}

      <div className="grid" style={{ gridTemplateColumns: 'minmax(300px, 380px) 1fr' }}>
        <div className="card">
          <h3>Basket</h3>

          <div className="field">
            <label htmlFor="product">Product</label>
            <select id="product" value={pid} onChange={(e) => setPid(e.target.value)}>
              {products.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name} &mdash; {rupees(p.price)}
                </option>
              ))}
            </select>
          </div>

          <div className="field">
            <label htmlFor="method">Payment method</label>
            <select id="method" value={method} onChange={(e) => setMethod(e.target.value)}>
              {['upi', 'card', 'netbanking', 'wallet', 'cod'].map((m) => (
                <option key={m} value={m}>
                  {m.toUpperCase()}
                </option>
              ))}
            </select>
          </div>

          <div className="field">
            <label htmlFor="pattern">Device / network</label>
            <select
              id="pattern"
              value={pattern}
              onChange={(e) => setPattern(e.target.value as PatternKey)}
            >
              {Object.entries(PATTERNS).map(([k, v]) => (
                <option key={k} value={k}>
                  {v.label}
                </option>
              ))}
            </select>
            <p className="muted" style={{ marginTop: 8, marginBottom: 0 }}>
              {PATTERNS[pattern].hint}
            </p>
          </div>

          <div
            className="spread"
            style={{ borderTop: '1px solid var(--line)', paddingTop: 16 }}
          >
            <span className="muted">Total</span>
            <strong className="mono" style={{ fontSize: 20 }}>
              {product ? rupees(product.price) : '\u2014'}
            </strong>
          </div>

          <button
            className="btn"
            onClick={pay}
            disabled={busy || !product}
            style={{ width: '100%', marginTop: 16 }}
          >
            {busy ? 'Processing\u2026' : 'Pay now'}
          </button>
        </div>

        <div className="stack">
          <div className="card">
            <div className="spread" style={{ marginBottom: 14 }}>
              <h3 style={{ margin: 0 }}>Result</h3>
              <span className="badge badge-neutral">{user.role} view</span>
            </div>
            {!result && (
              <p className="muted" style={{ marginBottom: 0 }}>
                Nothing yet. Press &ldquo;Pay now&rdquo;.
              </p>
            )}
            {result && (
              <>
                <div className="note" style={{ borderColor: statusColour }}>
                  {result.message}
                </div>
                <p className="muted" style={{ marginTop: 10, marginBottom: 0 }}>
                  Order <code>{result.order_id}</code> &middot;{' '}
                  <Link to="/orders">view in your orders</Link>
                </p>
                {!staff && (
                  <p className="muted" style={{ marginTop: 10, marginBottom: 0 }}>
                    No score, no reason codes. The backend omits them for a{' '}
                    <code>customer</code> role &mdash; telling an attacker which signal
                    fired is free reconnaissance.
                  </p>
                )}
              </>
            )}
          </div>

          {/* Only ever populated for staff: the backend does not include `risk`
              in the response for a customer role. */}
          {result?.risk && (
            <div className="card">
              <div className="spread" style={{ marginBottom: 14 }}>
                <h3 style={{ margin: 0 }}>Risk detail</h3>
                <span className="badge badge-neutral">staff only</span>
              </div>
              <div className="stack" style={{ gap: 20 }}>
                <ScoreDial
                  score={result.risk.risk_score}
                  decision={result.risk.decision}
                />
                <SubScoreBars sub={result.risk.sub_scores} />
                <div>
                  <div className="sub-head" style={{ marginBottom: 8 }}>
                    <span>Why</span>
                  </div>
                  <Reasons codes={result.risk.reason_codes} />
                </div>
                <div className="pill-row">
                  <span className="chip">{result.risk.transaction_id}</span>
                  {result.risk.override && (
                    <span className="chip">override: {result.risk.override}</span>
                  )}
                </div>
                <p className="muted" style={{ marginBottom: 0 }}>
                  {Math.round(result.risk.risk_score)} is a routing decision, not a
                  verdict. Ground truth only exists after an investigation or a
                  chargeback.
                </p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
