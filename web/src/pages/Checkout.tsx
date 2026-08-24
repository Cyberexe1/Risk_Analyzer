import { useEffect, useMemo, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { ApiError, rupees, shopApi, type Catalogue } from '../api'
import { ErrorNote } from '../components'
import { useAuth } from '../auth'
import { useCart } from '../cart'

/**
 * Shop — the catalogue.
 *
 * Adding to the cart is intentionally available to anonymous visitors: the cart
 * is local, holds nothing sensitive, and forcing a login before someone can see
 * what checkout looks like is friction with no security value. The gate is at
 * payment, where an account actually matters — the risk engine scores against an
 * account's history, so there is nothing to score without one.
 */
export default function Checkout() {
  const { user, loading: authLoading } = useAuth()
  const { lines, add, remove, count } = useCart()
  const nav = useNavigate()

  const [cat, setCat] = useState<Catalogue | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    void shopApi
      .catalogue()
      .then(setCat)
      .catch((e) => setError(e instanceof ApiError ? e.message : String(e)))
  }, [])

  const total = useMemo(() => {
    if (!cat) return 0
    return Object.entries(lines).reduce((sum, [pid, qty]) => {
      const p = cat.products.find((x) => x.id === pid)
      return sum + (p ? p.price * qty : 0)
    }, 0)
  }, [lines, cat])

  if (authLoading) {
    return <div className="wrap section center muted">Checking your session&hellip;</div>
  }

  const categories = [...new Set(cat?.products.map((p) => p.category) ?? [])]

  return (
    <div className="wrap section-sm">
      <div className="page-head spread">
        <div>
          <h1>Shop</h1>
          <p className="dim t-sm">
            Real orders: scored, authorised, persisted, and visible in{' '}
            <Link to="/orders">your orders</Link>.
          </p>
        </div>
        {count > 0 && (
          <div className="row row-tight">
            <span className="chip">
              {count} item{count === 1 ? '' : 's'} &middot; {rupees(total)}
            </span>
            <button className="btn btn-sm" onClick={() => nav('/cart')}>
              Go to cart
            </button>
          </div>
        )}
      </div>

      {error && (
        <div style={{ margin: 'var(--sp-4) 0' }}>
          <ErrorNote error={error} />
        </div>
      )}

      {!cat && !error && <div className="empty">Loading the catalogue&hellip;</div>}

      {categories.map((c) => (
        <section key={c} style={{ marginBottom: 'var(--sp-6)' }}>
          <h3 className="eyebrow">{c}</h3>
          <div className="grid grid-3" style={{ marginTop: 'var(--sp-3)' }}>
            {cat?.products
              .filter((p) => p.category === c)
              .map((p) => (
                <div className="card card-tight" key={p.id}>
                  <div className="fw-semi" style={{ minHeight: 44 }}>
                    {p.name}
                  </div>
                  <div className="num t-md" style={{ margin: 'var(--sp-2) 0' }}>
                    {rupees(p.price)}
                  </div>
                  <div className="muted t-xs" style={{ marginBottom: 'var(--sp-3)' }}>
                    {p.stock < 10 ? `Only ${p.stock} left` : `${p.stock} in stock`}
                  </div>

                  {lines[p.id] ? (
                    <div className="row row-tight" style={{ gap: 'var(--sp-2)' }}>
                      <button
                        className="btn btn-ghost btn-sm"
                        onClick={() => remove(p.id)}
                        aria-label={`Remove one ${p.name}`}
                      >
                        &minus;
                      </button>
                      <span
                        className="num center"
                        style={{ flex: '0 0 36px', lineHeight: '34px' }}
                        aria-live="polite"
                        aria-label={`${p.name} quantity ${lines[p.id]}`}
                      >
                        {lines[p.id]}
                      </span>
                      <button
                        className="btn btn-sm"
                        onClick={() => add(p.id, p.stock)}
                        disabled={lines[p.id] >= Math.min(p.stock, 10)}
                        aria-label={`Add one ${p.name}`}
                      >
                        +
                      </button>
                    </div>
                  ) : (
                    <button
                      className="btn btn-ghost btn-sm btn-block"
                      onClick={() => add(p.id, p.stock)}
                    >
                      Add to cart
                    </button>
                  )}
                </div>
              ))}
          </div>
        </section>
      ))}

      {count > 0 && (
        <div className="card spread" style={{ marginTop: 'var(--sp-6)' }}>
          <div>
            <div className="fw-semi">
              {count} item{count === 1 ? '' : 's'} in your cart
            </div>
            <div className="muted">
              {user ? 'Review and pay on the next step.' : 'Sign in at checkout to pay.'}
            </div>
          </div>
          <button className="btn" onClick={() => nav('/cart')} style={{ flex: '0 0 auto' }}>
            Checkout &middot; {rupees(total)}
          </button>
        </div>
      )}
    </div>
  )
}
