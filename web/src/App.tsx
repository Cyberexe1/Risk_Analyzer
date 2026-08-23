import { NavLink, Navigate, Route, Routes, useLocation } from 'react-router-dom'
import type { ReactNode } from 'react'
import { useAuth } from './auth'
import Landing from './pages/Landing'
import Checkout from './pages/Checkout'
import Orders from './pages/Orders'
import Offers from './pages/Offers'
import Admin from './pages/Admin'
import Login from './pages/Login'
import Signup from './pages/Signup'

function UserMenu() {
  const { user, loading, logout } = useAuth()

  if (loading) {
    return <span className="muted" style={{ fontSize: 13 }}>&hellip;</span>
  }

  if (!user) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <NavLink to="/login" className="btn btn-ghost btn-sm">
          Log in
        </NavLink>
        <NavLink to="/signup" className="btn btn-sm">
          Sign up
        </NavLink>
      </div>
    )
  }

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
      <span
        className="chip"
        title={`${user.email} — role: ${user.role}`}
        style={{ maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis' }}
      >
        {user.email}
      </span>
      <span className="badge badge-neutral">{user.role}</span>
      <button className="btn btn-ghost btn-sm" onClick={() => void logout()}>
        Log out
      </button>
    </div>
  )
}

function Nav() {
  const { user } = useAuth()
  const isStaff = user?.role === 'analyst' || user?.role === 'admin'

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
              <NavLink to="/offers" className="nav-link">
                Offers
              </NavLink>
              <NavLink to="/orders" className="nav-link">
                My orders
              </NavLink>
            </>
          )}
          {/* Hidden for customers as a courtesy only. The backend enforces the
              role on every admin request — a nav link is not a control. */}
          {isStaff && (
            <NavLink to="/admin" className="nav-link">
              Console
            </NavLink>
          )}
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

/** Any signed-in user. A convenience gate — the backend still checks the token on
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
          <h1 style={{ fontSize: '1.5rem' }}>Not your console</h1>
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
    <>
      <a href="#main" className="sr-only">
        Skip to content
      </a>
      <Nav />
      <main id="main">
        <Routes>
          <Route path="/" element={<Landing />} />
          <Route path="/checkout" element={<Checkout />} />
          <Route path="/login" element={<Login />} />
          <Route path="/signup" element={<Signup />} />
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
      <footer
        style={{ borderTop: '1px solid var(--line-soft)', padding: '28px 0', marginTop: 40 }}
      >
        <div className="wrap spread">
          <span className="muted">
            FraudShield &middot; defense-only risk scoring &middot; synthetic data
          </span>
          <span className="muted">Routing decisions, not fraud verdicts.</span>
        </div>
      </footer>
    </>
  )
}
