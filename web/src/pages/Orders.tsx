import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  ApiError,
  rupees,
  shopApi,
  type Order,
  type ReturnRecord,
} from '../api'
import { ErrorNote } from '../components'
import { useAuth } from '../auth'

const REASONS = [
  'Item not received',
  'Damaged on arrival',
  'Wrong item sent',
  'Not as described',
  'No longer needed',
]

const STATUS_STYLE: Record<Order['status'], { label: string; glyph: string; colour: string }> = {
  confirmed: { label: 'Confirmed', glyph: '\u25CF', colour: 'var(--allow)' },
  verifying: { label: 'Verifying', glyph: '\u25C6', colour: 'var(--review)' },
  declined: { label: 'Declined', glyph: '\u25B2', colour: 'var(--block)' },
}

/**
 * Customer dashboard: order history and the return-request flow.
 *
 * Notice what is absent for a customer — no risk score, no sub-scores, no reason
 * codes. The backend's order projection is allow-list based, so those fields are
 * never sent to a `customer` role in the first place. Staff see them because the
 * same endpoint widens its response for `analyst`/`admin`.
 */
export default function Orders() {
  const { user } = useAuth()
  const [orders, setOrders] = useState<Order[]>([])
  const [returns, setReturns] = useState<ReturnRecord[]>([])
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [openFor, setOpenFor] = useState<string | null>(null)
  const [reason, setReason] = useState(REASONS[0])
  const [detail, setDetail] = useState('')
  const [busy, setBusy] = useState(false)
  const [flash, setFlash] = useState<string | null>(null)

  const load = useCallback(async () => {
    try {
      const [o, r] = await Promise.all([shopApi.orders(), shopApi.returns()])
      setOrders(o.orders)
      setReturns(r.returns)
      setError(null)
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void load()
  }, [load])

  async function submitReturn(orderId: string) {
    setBusy(true)
    try {
      const r = await shopApi.requestReturn(orderId, reason, detail)
      setFlash(r.message)
      setOpenFor(null)
      setDetail('')
      await load()
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }

  const spent = orders
    .filter((o) => o.status === 'confirmed')
    .reduce((a, o) => a + o.amount, 0)

  return (
    <div className="wrap section-sm">
      <div className="spread" style={{ marginBottom: 8 }}>
        <div>
          <h1 style={{ fontSize: '1.9rem', marginBottom: 4 }}>Your orders</h1>
          <p className="muted" style={{ margin: 0 }}>
            Signed in as {user?.email}
          </p>
        </div>
        <Link to="/checkout" className="btn btn-sm">
          Place an order
        </Link>
      </div>

      {error && (
        <div style={{ margin: '16px 0' }}>
          <ErrorNote error={error} />
        </div>
      )}
      {flash && (
        <div className="note" style={{ margin: '16px 0' }} role="status">
          {flash}
        </div>
      )}

      <div className="grid grid-3" style={{ margin: '20px 0' }}>
        <div className="stat">
          <div className="k">Orders</div>
          <div className="v">{orders.length}</div>
        </div>
        <div className="stat">
          <div className="k">Confirmed spend</div>
          <div className="v">{rupees(spent)}</div>
        </div>
        <div className="stat">
          <div className="k">Open returns</div>
          <div className="v">{returns.filter((r) => r.status === 'under_review').length}</div>
        </div>
      </div>

      {loading && <div className="empty">Loading&hellip;</div>}

      {!loading && !orders.length && (
        <div className="card empty">
          <p style={{ marginBottom: 12 }}>No orders yet.</p>
          <Link to="/checkout" className="btn btn-sm">
            Go to checkout
          </Link>
        </div>
      )}

      {!!orders.length && (
        <div className="stack">
          {orders.map((o) => {
            const s = STATUS_STYLE[o.status]
            return (
              <div className="card card-tight" key={o.order_id}>
                <div className="spread">
                  <div>
                    <div style={{ fontWeight: 600 }}>{o.product_name}</div>
                    <div className="muted mono" style={{ fontSize: 12 }}>
                      {o.order_id} &middot; {new Date(o.created_at).toLocaleString()} &middot;{' '}
                      {o.payment_method.toUpperCase()}
                    </div>
                  </div>
                  <div style={{ textAlign: 'right' }}>
                    <div className="mono" style={{ fontWeight: 700, fontSize: 16 }}>
                      {rupees(o.amount)}
                    </div>
                    <span
                      className="badge"
                      style={{
                        color: s.colour,
                        borderColor: s.colour,
                        background: 'transparent',
                        marginTop: 4,
                      }}
                    >
                      <span aria-hidden="true">{s.glyph}</span>
                      {s.label}
                    </span>
                  </div>
                </div>

                {/* Staff see the risk breakdown on their own orders; customers never do. */}
                {o.risk_score !== undefined && (
                  <div className="pill-row" style={{ marginTop: 12 }}>
                    <span className="chip">risk {Math.round(o.risk_score)}</span>
                    <span className="chip">{o.decision}</span>
                    {o.sub_scores && (
                      <span className="chip">
                        ml {Math.round(o.sub_scores.ml)} / rules{' '}
                        {Math.round(o.sub_scores.rules)} / net{' '}
                        {Math.round(o.sub_scores.network)}
                      </span>
                    )}
                  </div>
                )}

                <div style={{ marginTop: 12 }}>
                  {o.return_status ? (
                    <span className="muted">
                      Return {o.return_status.replace('_', ' ')}
                    </span>
                  ) : o.status === 'confirmed' ? (
                    openFor === o.order_id ? (
                      <div
                        className="stack"
                        style={{
                          gap: 10,
                          borderTop: '1px solid var(--line)',
                          paddingTop: 12,
                        }}
                      >
                        <div className="field" style={{ marginBottom: 0 }}>
                          <label htmlFor={`r-${o.order_id}`}>Reason</label>
                          <select
                            id={`r-${o.order_id}`}
                            value={reason}
                            onChange={(e) => setReason(e.target.value)}
                          >
                            {REASONS.map((r) => (
                              <option key={r} value={r}>
                                {r}
                              </option>
                            ))}
                          </select>
                        </div>
                        <div className="field" style={{ marginBottom: 0 }}>
                          <label htmlFor={`d-${o.order_id}`}>Anything else? (optional)</label>
                          <input
                            id={`d-${o.order_id}`}
                            value={detail}
                            maxLength={500}
                            onChange={(e) => setDetail(e.target.value)}
                            placeholder="A sentence or two helps us process it faster"
                          />
                        </div>
                        <div className="row">
                          <button
                            className="btn btn-sm"
                            disabled={busy}
                            onClick={() => void submitReturn(o.order_id)}
                          >
                            {busy ? 'Submitting\u2026' : 'Submit return'}
                          </button>
                          <button
                            className="btn btn-ghost btn-sm"
                            onClick={() => setOpenFor(null)}
                          >
                            Cancel
                          </button>
                        </div>
                      </div>
                    ) : (
                      <button
                        className="btn btn-ghost btn-sm"
                        onClick={() => setOpenFor(o.order_id)}
                      >
                        Request a return
                      </button>
                    )
                  ) : (
                    <span className="muted">
                      {o.status === 'verifying'
                        ? 'Payment verification in progress.'
                        : 'This payment did not go through.'}
                    </span>
                  )}
                </div>
              </div>
            )
          })}
        </div>
      )}

      {!!returns.length && (
        <>
          <h2 style={{ fontSize: '1.3rem', marginTop: 36 }}>Returns</h2>
          <div className="table-shell">
            <table>
              <caption className="sr-only">Your return requests</caption>
              <thead>
                <tr>
                  <th scope="col">Item</th>
                  <th scope="col">Reason</th>
                  <th scope="col">Amount</th>
                  <th scope="col">Status</th>
                </tr>
              </thead>
              <tbody>
                {returns.map((r) => (
                  <tr key={r.return_id}>
                    <td>{r.product_name}</td>
                    <td className="muted">{r.reason}</td>
                    <td className="mono">{rupees(r.amount)}</td>
                    <td>
                      <span className="badge badge-review">
                        {r.status.replace('_', ' ')}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="muted" style={{ marginTop: 12 }}>
            Every return goes to a human. Return abuse is only 0.455 recall at payment
            time, so auto-approving on the transaction score would be approving on
            evidence we know is weak.
          </p>
        </>
      )}
    </div>
  )
}
