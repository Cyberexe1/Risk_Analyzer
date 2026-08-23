import { NavLink, Route, Routes } from 'react-router-dom'
import Landing from './pages/Landing'
import Checkout from './pages/Checkout'
import Admin from './pages/Admin'

function Nav() {
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
          <NavLink to="/admin" className="nav-link">
            Console
          </NavLink>
        </nav>
      </div>
    </header>
  )
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
          <Route path="/admin" element={<Admin />} />
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
          <span className="muted">
            Routing decisions, not fraud verdicts.
          </span>
        </div>
      </footer>
    </>
  )
}
