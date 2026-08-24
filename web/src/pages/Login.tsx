import { useState } from 'react'
import { Link, useLocation, useNavigate, useSearchParams } from 'react-router-dom'
import { ApiError } from '../api'
import { useAuth } from '../auth'

/**
 * One login form for every role.
 *
 * `?staff=1` changes the copy and the post-login destination, nothing else — the
 * same endpoint, the same Argon2id verification, the same rate limits. A separate
 * admin auth path would double the surface to attack and inevitably drift out of
 * sync with this one.
 *
 * The role comes from the account record, not from which button was pressed. If a
 * customer signs in here they get a customer session, and the console will refuse
 * them server-side.
 */
export default function Login() {
  const { login } = useAuth()
  const nav = useNavigate()
  const loc = useLocation()
  const [params] = useSearchParams()
  const staffMode = params.get('staff') === '1'

  const fallback = staffMode ? '/admin' : '/dashboard'
  const from = (loc.state as { from?: string } | null)?.from ?? fallback

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
        {staffMode && (
          <span className="badge badge-neutral" style={{ marginBottom: 'var(--sp-3)' }}>
            Staff access
          </span>
        )}
        <h1 className="t-xl">{staffMode ? 'Analyst console' : 'Log in'}</h1>
        <p>
          {staffMode
            ? 'Sign in with an analyst or admin account.'
            : 'Welcome back.'}
        </p>

        {error && (
          <div className="note note-warn" role="alert" style={{ marginBottom: 'var(--sp-4)' }}>
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
              placeholder={staffMode ? 'admin@fraudshield.local' : 'you@example.com'}
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

          <label className="label-inline" style={{ marginBottom: 'var(--sp-4)' }}>
            <input
              type="checkbox"
              checked={show}
              onChange={(e) => setShow(e.target.checked)}
            />
            Show password
          </label>

          <button className="btn btn-block" type="submit" disabled={busy || !email || !pw}>
            {busy ? 'Signing in\u2026' : 'Sign in'}
          </button>
        </form>

        <p className="muted" style={{ marginTop: 'var(--sp-4)' }}>
          {staffMode ? (
            <>
              Not staff? <Link to="/login">Customer login</Link>
            </>
          ) : (
            <>
              No account yet? <Link to="/signup">Sign up</Link> &middot;{' '}
              <Link to="/login?staff=1">Admin login</Link>
            </>
          )}
        </p>
      </div>

      <div className="note" style={{ marginTop: 'var(--sp-4)' }}>
        {staffMode ? (
          <>
            <strong>Same credential check as any other account.</strong> This form only
            changes the wording and where you land. Roles are granted out-of-band
            (<code>scripts/grant_role.py</code>) &mdash; there is no API path to a
            privileged role, so signup can never escalate.
          </>
        ) : (
          <>
            Failed logins return the same message whether or not the email exists, and are
            rate limited to 5 attempts per email per 15 minutes. Both are deliberate:
            distinguishable errors turn a login form into an account-enumeration oracle.
          </>
        )}
      </div>
    </div>
  )
}
