import { useEffect, useMemo, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { ApiError, rupees, shopApi, type Catalogue } from '../api'
import { ErrorNote } from '../components'
import { useAuth } from '../auth'
import { useCart } from '../cart'
import PaymentSheet from './PaymentSheet'

/**
 * Checkout — review the cart, then pay.
 *
 * Prices are resolved from the catalogue at render time rather than read from the
 * cart, so a stale localStorage entry cannot show a price that no longer exists.
 * The total shown here is advisory: the backend recomputes it from its own
 * CATALOGUE when the order is placed, which is what stops a tampered cart from
 * setting its own amount.
 */
export default function Cart() {
  const { user, loading: authLoading } = useAuth()
  const { lines, count, add, remove, drop, clear } = useCart()
  const nav = useNavigate()

  const [cat, setCat] = useState<Catalogue | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [paying, setPaying] = useState(false)

  useEffect(() => {
    void shopApi
      .catalogue()
      .then(setCat)
      .catch((e) => setError(e instanceof ApiError ? e.message : String(e)))
  }, [])

  const rows = useMemo(() => {
    if (!cat) return []
    return Object.entries(lines).flatMap(([pid, qty]) => {
      const p = cat.products.find((x) => x.id === pid)
      // A product that has left the catalogue is dropped from the view rather
      // than rendered as a blank row.
      return p ? [{ ...p, qty }] : []
    })
  }, [lines, cat])

  const total = rows.reduce((a, r) => a + r.price * r.qty, 0)
  const items = useMemo(
    () => rows.map((r) => ({ product_id: r.id, qty: r.qty })),
    [rows],
  )

  if (authLoading) {
    return <div className="wrap section center muted">Checking your session&hellip;</div>
  }

  if (!count) {
    return (
      <div className="wrap-narrow section">
        <div className="card empty">
          <h1 className="t-lg">Your cart is empty</h1>
          <p style={{ marginBottom: 'var(--sp-4)' }}>
            Nothing added yet. The shop has twelve products to choose from.
          </p>
          <Link to="/checkout" className="btn btn-sm">
            Browse the shop
          </Link>
        </div>
      </div>
    )
  }

  return (
    <div className="wrap section-sm">
      <div className="page-head spread">
        <div>
          <h1>Checkout</h1>
          <p className="dim t-sm">
            {count} item{count === 1 ? '' : 's'} &middot; review, then pay.
          </p>
        </div>
        <Link to="/checkout" className="btn btn-ghost btn-sm">
          Keep shopping
        </Link>
      </div>

      {error && (
        <div style={{ marginBottom: 'var(--sp-4)' }}>
          <ErrorNote error={error} />
        </div>
      )}

      <div className="split">
        {/* ---------------- line items ---------------- */}
        <div className="table-shell">
          <table>
            <caption className="sr-only">Items in your cart</caption>
            <thead>
              <tr>
                <th scope="col">Item</th>
                <th scope="col">Quantity</th>
                <th scope="col" className="num">
                  Line total
                </th>
                <th scope="col">
                  <span className="sr-only">Remove</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id}>
                  <td>
                    <div className="fw-medium">{r.name}</div>
                    <div className="muted t-xs">
                      {rupees(r.price)} &middot; {r.category}
                    </div>
                  </td>
                  <td>
                    <div className="row row-tight" style={{ gap: 'var(--sp-2)' }}>
                      <button
                        className="btn btn-ghost btn-sm"
                        onClick={() => remove(r.id)}
                        aria-label={`Remove one ${r.name}`}
                      >
                        &minus;
                      </button>
                      <span
                        className="num center"
                        style={{ flex: '0 0 28px', lineHeight: '30px' }}
                      >
                        {r.qty}
                      </span>
                      <button
                        className="btn btn-ghost btn-sm"
                        onClick={() => add(r.id, r.stock)}
                        disabled={r.qty >= Math.min(r.stock, 10)}
                        aria-label={`Add one ${r.name}`}
                      >
                        +
                      </button>
                    </div>
                    {r.qty >= Math.min(r.stock, 10) && (
                      <div className="muted t-2xs" style={{ marginTop: 'var(--sp-1)' }}>
                        {r.stock <= 10 ? `only ${r.stock} in stock` : 'max 10 per order'}
                      </div>
                    )}
                  </td>
                  <td className="num">{rupees(r.price * r.qty)}</td>
                  <td>
                    <button
                      className="btn btn-ghost btn-sm"
                      onClick={() => drop(r.id)}
                      aria-label={`Remove ${r.name} from cart`}
                    >
                      &times;
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* ---------------- summary ---------------- */}
        <aside className="stack sticky-side">
          <div className="card">
            <h3 className="t-base">Order summary</h3>
            <div className="stack" style={{ gap: 'var(--sp-2)', marginTop: 'var(--sp-3)' }}>
              <div className="spread">
                <span className="muted">
                  Subtotal ({count} item{count === 1 ? '' : 's'})
                </span>
                <span className="num t-sm">{rupees(total)}</span>
              </div>
              <div className="spread">
                <span className="muted">Delivery</span>
                <span className="num t-sm">Free</span>
              </div>
            </div>
            <div
              className="spread"
              style={{
                borderTop: '1px solid var(--line)',
                paddingTop: 'var(--sp-3)',
                marginTop: 'var(--sp-3)',
              }}
            >
              <span className="fw-semi">Total</span>
              <strong className="num t-lg">{rupees(total)}</strong>
            </div>

            {user ? (
              <button
                className="btn btn-block"
                style={{ marginTop: 'var(--sp-4)' }}
                disabled={!cat || !rows.length}
                onClick={() => setPaying(true)}
              >
                Checkout
              </button>
            ) : (
              <>
                <div className="note" style={{ marginTop: 'var(--sp-4)' }}>
                  Sign in to pay. Orders are tied to an account, because the account is
                  what the risk engine builds a history against.
                </div>
                <div className="row row-tight" style={{ marginTop: 'var(--sp-3)' }}>
                  <button
                    className="btn btn-sm"
                    onClick={() => nav('/login', { state: { from: '/cart' } })}
                  >
                    Log in
                  </button>
                  <button className="btn btn-ghost btn-sm" onClick={() => nav('/signup')}>
                    Create account
                  </button>
                </div>
              </>
            )}

            <button
              className="btn btn-ghost btn-block btn-sm"
              style={{ marginTop: 'var(--sp-2)' }}
              onClick={clear}
            >
              Empty cart
            </button>
          </div>

          <div className="note">
            The amount is recalculated server-side from the catalogue when you pay, so
            what you are charged never depends on what this page sends.
          </div>
        </aside>
      </div>

      {paying && cat && (
        <PaymentSheet
          cat={cat}
          amount={total}
          body={{ items }}
          onClose={() => setPaying(false)}
          onSuccess={clear}
        />
      )}
    </div>
  )
}
