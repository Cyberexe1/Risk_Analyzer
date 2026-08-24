import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  ApiError,
  promoApi,
  rupees,
  shopApi,
  type MyRedemption,
  type Order,
  type ReturnRecord,
} from '../api'
import { ErrorNote, Stat } from '../components'
import { useAuth } from '../auth'

const STATUS_LABEL: Record<string, { label: string; cls: string; glyph: string }> = {
  confirmed: { label: 'Confirmed', cls: 'allow', glyph: '\u25CF' },
  verifying: { label: 'Verifying', cls: 'review', glyph: '\u25C6' },
  declined: { label: 'Declined', cls: 'block', glyph: '\u25B2' },
  declined_by_bank: { label: 'Bank declined', cls: 'review', glyph: '\u25C6' },
  credited: { label: 'Credited', cls: 'allow', glyph: '\u25CF' },
  under_review: { label: 'Under review', cls: 'review', glyph: '\u25C6' },
  denied: { label: 'Not available', cls: 'block', glyph: '\u25B2' },
}

function Pill({ status }: { status: string }) {
  const s = STATUS_LABEL[status] ?? { label: status, cls: 'neutral', glyph: '' }
  return (
    <span className={`badge badge-${s.cls}`}>
      {s.glyph && <span aria-hidden="true">{s.glyph}</span>}
      {s.label}
    </span>
  )
}

/**
 * Customer dashboard — the account overview.
 *
 * Everything here is the allow-listed customer projection: no risk score, no
 * sub-scores, no reason codes. Those fields are stripped server-side for a
 * `customer` role, so this page cannot leak them even by accident.
 */
export default function Dashboard() {
  const { user } = useAuth()
  const [orders, setOrders] = useState<Order[]>([])
  const [returns, setReturns] = useState<ReturnRecord[]>([])
  const [promos, setPromos] = useState<MyRedemption[]>([])
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    void (async () => {
      try {
        const [o, r, p] = await Promise.all([
          shopApi.orders(),
          shopApi.returns(),
          promoApi.mine(),
        ])
        setOrders(o.orders)
        setReturns(r.returns)
        setPromos(p.redemptions)
      } catch (e) {
        setError(e instanceof ApiError ? e.message : String(e))
      } finally {
        setLoading(false)
      }
    })()
  }, [])

  const confirmed = orders.filter((o) => o.status === 'confirmed')
  const spent = confirmed.reduce((a, o) => a + o.amount, 0)
  const credited = promos
    .filter((p) => p.status === 'credited')
    .reduce((a, p) => a + p.value, 0)
  const openReturns = returns.filter((r) => r.status === 'under_review').length
  const held = orders.filter((o) => o.status === 'verifying').length

  return (
    <div className="wrap section-sm">
      <div className="page-head spread">
        <div>
          <h1>Your account</h1>
          <p className="dim t-sm">{user?.email}</p>
        </div>
        <div className="row row-tight">
          <Link to="/checkout" className="btn btn-sm">
            Shop
          </Link>
          <Link to="/offers" className="btn btn-ghost btn-sm">
            Offers
          </Link>
        </div>
      </div>

      {error && (
        <div style={{ marginBottom: 'var(--sp-4)' }}>
          <ErrorNote error={error} />
        </div>
      )}

      <div className="grid grid-4" style={{ marginBottom: 'var(--sp-6)' }}>
        <Stat k="Orders" v={orders.length} n={`${confirmed.length} confirmed`} />
        <Stat k="Total spend" v={rupees(spent)} n="confirmed orders only" />
        <Stat k="Cashback earned" v={rupees(credited)} n={`${promos.length} claims`} />
        <Stat
          k="Needs attention"
          v={held + openReturns}
          n={`${held} verifying, ${openReturns} returns`}
        />
      </div>

      {loading && <div className="empty">Loading&hellip;</div>}

      {!loading && !orders.length && (
        <div className="card empty">
          <p style={{ marginBottom: 'var(--sp-3)' }}>No orders yet.</p>
          <Link to="/checkout" className="btn btn-sm">
            Start shopping
          </Link>
        </div>
      )}

      {!!orders.length && (
        <div className="split">
          <section>
            <div className="spread" style={{ marginBottom: 'var(--sp-3)' }}>
              <h2 className="t-lg" style={{ margin: 0 }}>
                Recent orders
              </h2>
              <Link to="/orders" className="t-sm">
                View all &rarr;
              </Link>
            </div>
            <div className="table-shell">
              <table>
                <caption className="sr-only">Your five most recent orders</caption>
                <thead>
                  <tr>
                    <th scope="col">Order</th>
                    <th scope="col">Paid with</th>
                    <th scope="col">Amount</th>
                    <th scope="col">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {orders.slice(0, 5).map((o) => (
                    <tr key={o.order_id}>
                      <td>
                        <div className="fw-medium">{o.product_name}</div>
                        <div className="muted t-2xs mono">
                          {new Date(o.created_at).toLocaleDateString()}
                        </div>
                      </td>
                      <td className="dim t-sm">
                        {o.instrument_display ?? o.payment_method.toUpperCase()}
                      </td>
                      <td className="num">{rupees(o.amount)}</td>
                      <td>
                        <Pill status={o.status} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>

          <aside className="stack">
            <div className="card">
              <h3 className="t-base">Cashback</h3>
              {!promos.length && (
                <p className="muted">
                  No claims yet. <Link to="/offers">See offers</Link>.
                </p>
              )}
              {promos.map((p) => (
                <div className="spread" key={p.redemption_id} style={{ marginBottom: 'var(--sp-2)' }}>
                  <span className="mono t-sm">{p.promo_code}</span>
                  <span className="row row-tight" style={{ gap: 8, flex: '0 0 auto' }}>
                    <span className="num t-sm">{rupees(p.value)}</span>
                    <Pill status={p.status} />
                  </span>
                </div>
              ))}
            </div>

            <div className="card">
              <h3 className="t-base">Returns</h3>
              {!returns.length && <p className="muted">No returns requested.</p>}
              {returns.map((r) => (
                <div key={r.return_id} style={{ marginBottom: 'var(--sp-3)' }}>
                  <div className="spread">
                    <span className="t-sm fw-medium">{r.product_name}</span>
                    <Pill status={r.status} />
                  </div>
                  <div className="muted t-xs">{r.reason}</div>
                </div>
              ))}
              {!!returns.length && (
                <p className="muted" style={{ marginTop: 'var(--sp-3)' }}>
                  Every return is reviewed by a person, not auto-approved.
                </p>
              )}
            </div>
          </aside>
        </div>
      )}
    </div>
  )
}
