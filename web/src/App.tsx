import { NavLink, Navigate, Route, Routes, useLocation } from 'react-router-dom'
import type { ReactNode } from 'react'
import { useAuth } from './auth'
import { useCart } from './cart'
import Landing from './pages/Landing'
import Checkout from './pages/Checkout'
import Cart from './pages/Cart'
import Dashboard from './pages/Dashboard'
import Orders from './pages/Orders'
import Offers from './pages/Offers'
import Admin from './pages/Admin'
import Login from './pages/Login'
import Signup from './pages/Signup'

function UserMenu() {
  const { user, loading, logout } = useAuth()

  if (loading) {
    return <span className="muted">&hellip;</span>
  }

  if (!user) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        {/* Same endpoint, same form, same credential check as a customer login.
            The role comes from the account, not from which button was pressed —
            a separate admin auth path would double the attack surface and drift. */}
        <NavLink to="/login?staff=1" className="nav-link">
          Analyst console
        </NavLink>
        <NavLink to="/login" className="btn btn-ghost btn-sm">
          Log in
        </NavLink>
        <NavLink to="/signup" className="btn btn-sm">
          Get started
        </NavLink>
      </div>
    )
  }

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
      {/* The address is deliberately not rendered here. The header sits on every
          page, including ones a customer may screen-share or demo, and an email is
          the one identifier that is both personal and useless to them — they know
          which account they signed into. The role badge is what actually changes
          what they can do, so that is what earns the space. The full address is on
          the dashboard, one click away, where it is the subject of the page. */}
      <span className="badge badge-neutral">{user.role}</span>
      <button className="btn btn-ghost btn-sm" onClick={() => void logout()}>
        Log out
      </button>
    </div>
  )
}

/**
 * Cart button with a live count.
 *
 * The count is announced politely rather than assertively — a badge that
 * interrupts a screen reader mid-sentence on every "add to cart" is worse than
 * one that waits for a pause.
 */
function CartButton() {
  const { count } = useCart()
  return (
    <NavLink
      to="/cart"
      className="cart-btn"
      aria-label={
        count === 0 ? 'Cart, empty' : `Cart, ${count} item${count === 1 ? '' : 's'}`
      }
    >
      <span aria-hidden="true" className="cart-glyph">
        {'\u25A4'}
      </span>
      <span className="cart-label">Cart</span>
      {count > 0 && (
        <span className="cart-count" aria-hidden="true">
          {count}
        </span>
      )}
      <span className="sr-only" aria-live="polite">
        {count} item{count === 1 ? '' : 's'} in cart
      </span>
    </NavLink>
  )
}

function Nav() {
  const { user, logout } = useAuth()
  const isStaff = user?.role === 'analyst' || user?.role === 'admin'

  // STAFF HEADER: the brand and Log out, nothing else.
  //
  // An analyst reviewing a blocked payment has no use for Checkout, Orders,
  // Offers or a shopping cart, and the role badge only repeats what the page
  // they are already on says in its title. Every one of those was a thing to
  // read past on the way to the work.
  //
  // The brand points at the console rather than the marketing page, because with
  // the nav gone it is the only link left and sending it to a landing page would
  // strand a staff user with no route back.
  if (isStaff) {
    return (
      <header className="nav">
        <div className="wrap nav-inner">
          <NavLink to="/admin" className="brand">
            <span className="brand-mark" aria-hidden="true">
              {'\u25C6'}
            </span>
            FraudShield
          </NavLink>
          <nav className="nav-links" aria-label="Main">
            <button className="btn btn-ghost btn-sm" onClick={() => void logout()}>
              Log out
            </button>
          </nav>
        </div>
      </header>
    )
  }

  return (
    <header className="nav">
      <div className="wrap nav-inner">
        <NavLink to="/" className="brand">
          <span className="brand-mark" aria-hidden="true">
            {'\u25C6'}
          </span>
          FraudShield
        </NavLink>
        <nav className="nav-links" aria-label="Main">
          <NavLink to="/" end className="nav-link">
            Overview
          </NavLink>
          <NavLink to="/checkout" className="nav-link">
            Checkout
          </NavLink>
          {user && (
            <>
              <NavLink to="/dashboard" className="nav-link">
                Dashboard
              </NavLink>
              <NavLink to="/orders" className="nav-link">
                Orders
              </NavLink>
              <NavLink to="/offers" className="nav-link">
                Offers
              </NavLink>
            </>
          )}
          {/* No Console link here: staff never reach this branch, they get the
              minimal header above. The backend enforces the role on every admin
              request regardless — a nav link was never the control. */}
          <CartButton />
          <span
            aria-hidden="true"
            style={{ width: 1, height: 24, background: 'var(--line)', margin: '0 6px' }}
          />
          <UserMenu />
        </nav>
      </div>
    </header>
  )
}

/** Any signed-in user. A convenience gate â€” the backend still checks the token on
 *  every request, so this only avoids rendering a page that would 401. */
function RequireAuth({ children }: { children: ReactNode }) {
  const { user, loading } = useAuth()
  const loc = useLocation()
  if (loading) {
    return <div className="wrap section center muted">Checking your session&hellip;</div>
  }
  if (!user) {
    return <Navigate to="/login" replace state={{ from: loc.pathname }} />
  }
  return <>{children}</>
}

/** Gate for staff-only routes. Redirects rather than rendering an empty page, and
 *  remembers where the user was headed so login can return them there. */
function RequireStaff({ children }: { children: ReactNode }) {
  const { user, loading } = useAuth()
  const loc = useLocation()

  if (loading) {
    return <div className="wrap section center muted">Checking your session&hellip;</div>
  }
  if (!user) {
    return <Navigate to="/login" replace state={{ from: loc.pathname }} />
  }
  if (user.role !== 'analyst' && user.role !== 'admin') {
    return (
      <div className="wrap-narrow section">
        <div className="card">
          <h1 className="t-xl">Not your console</h1>
          <p>
            The analyst console needs an <code>analyst</code> or <code>admin</code> role.
            You are signed in as <code>{user.role}</code>.
          </p>
          <p style={{ marginBottom: 0 }}>
            Roles are granted by a direct write to the user store, never through the API.
            Promote an account with <code>python scripts/grant_role.py</code>.
          </p>
        </div>
      </div>
    )
  }
  return <>{children}</>
}

export default function App() {
  return (
    <div className="app-shell">
      <a href="#main" className="sr-only">
        Skip to content
      </a>
      <Nav />
      <main id="main" className="app-main">
        <Routes>
          <Route path="/" element={<Landing />} />
          <Route path="/checkout" element={<Checkout />} />
          {/* Public like the shop. The payment step inside gates on a session
              itself, so an anonymous visitor can still review a cart. */}
          <Route path="/cart" element={<Cart />} />
          <Route path="/login" element={<Login />} />
          <Route path="/signup" element={<Signup />} />
          <Route
            path="/dashboard"
            element={
              <RequireAuth>
                <Dashboard />
              </RequireAuth>
            }
          />
          <Route
            path="/orders"
            element={
              <RequireAuth>
                <Orders />
              </RequireAuth>
            }
          />
          <Route
            path="/offers"
            element={
              <RequireAuth>
                <Offers />
              </RequireAuth>
            }
          />
          <Route
            path="/admin"
            element={
              <RequireStaff>
                <Admin />
              </RequireStaff>
            }
          />
          <Route
            path="*"
            element={
              <div className="wrap section center">
                <h1>Not found</h1>
                <p>
                  Nothing at this address. <a href="/">Back to overview</a>.
                </p>
              </div>
            }
          />
        </Routes>
      </main>
      {/* Two-column editorial footer. No Privacy/Terms links: they would be dead
          ends on a defense-only demo, and a link that goes nowhere is worse than
          an absent one. The tagline carries the scope claim instead. */}
      <footer className="site-footer">
        <div className="wrap footer-inner">
          <div className="footer-col">
            <span className="footer-brand">FraudShield</span>
            <span className="footer-meta">
              Defense-only risk scoring &middot; synthetic data
            </span>
          </div>
          <div className="footer-col footer-col-end">
            <span className="footer-tagline">Routing decisions, not fraud verdicts.</span>
            <span className="footer-meta">
              Scores route attention. They are never a verdict of fraud.
            </span>
          </div>
        </div>
      </footer>
    </div>
  )
}
