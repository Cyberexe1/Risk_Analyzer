import { useState } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import { ApiError } from '../api'
import { useAuth } from '../auth'

export default function Login() {
  const { login } = useAuth()
  const nav = useNavigate()
  const loc = useLocation()
  const from = (loc.state as { from?: string } | null)?.from ?? '/checkout'

  const [email, setEmail] = useState('')
  const [pw, setPw] = useState('')
  const [show, setShow] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      await login(email, pw)
      nav(from, { replace: true })
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="wrap-narrow section-sm" style={{ maxWidth: 480 }}>
      <div className="card card-lift">
        <h1 style={{ fontSize: '1.6rem' }}>Log in</h1>
        <p>Welcome back.</p>

        {error && (
          <div className="note note-warn" role="alert" style={{ marginBottom: 16 }}>
            {error}
          </div>
        )}

        <form onSubmit={submit} noValidate>
          <div className="field">
            <label htmlFor="email">Email</label>
            <input
              id="email"
              type="email"
              autoComplete="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="you@example.com"
            />
          </div>

          <div className="field">
            <label htmlFor="pw">Password</label>
            <input
              id="pw"
              type={show ? 'text' : 'password'}
              autoComplete="current-password"
              required
              value={pw}
              onChange={(e) => setPw(e.target.value)}
            />
          </div>

          <label
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              fontWeight: 500,
              marginBottom: 18,
            }}
          >
            <input
              type="checkbox"
              checked={show}
              onChange={(e) => setShow(e.target.checked)}
              style={{ width: 16, height: 16, flex: '0 0 auto' }}
            />
            Show password
          </label>

          <button
            className="btn"
            type="submit"
            disabled={busy || !email || !pw}
            style={{ width: '100%' }}
          >
            {busy ? 'Logging in\u2026' : 'Log in'}
          </button>
        </form>

        <p className="muted" style={{ marginTop: 18, marginBottom: 0 }}>
          No account yet? <Link to="/signup">Sign up</Link>
        </p>
      </div>

      <div className="note" style={{ marginTop: 16 }}>
        Failed logins return the same message whether or not the email exists, and are
        rate limited to 5 attempts per email per 15 minutes. Both are deliberate:
        distinguishable errors turn a login form into an account-enumeration oracle.
      </div>
    </div>
  )
}
