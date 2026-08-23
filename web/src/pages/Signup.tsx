import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { ApiError } from '../api'
import { passwordProblem, passwordStrength, useAuth } from '../auth'

const BAR = ['var(--line)', 'var(--block)', 'var(--review)', 'var(--allow)']

export default function Signup() {
  const { register } = useAuth()
  const nav = useNavigate()
  const [email, setEmail] = useState('')
  const [pw, setPw] = useState('')
  const [pw2, setPw2] = useState('')
  const [show, setShow] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [touched, setTouched] = useState(false)

  const strength = passwordStrength(pw)
  const pwIssue = touched ? passwordProblem(pw) : null
  const mismatch = touched && pw2.length > 0 && pw !== pw2
  const canSubmit =
    email.includes('@') && !passwordProblem(pw) && pw === pw2 && !busy

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setTouched(true)
    if (!canSubmit) return
    setBusy(true)
    setError(null)
    try {
      await register(email, pw)
      nav('/checkout', { replace: true })
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="wrap-narrow section-sm" style={{ maxWidth: 480 }}>
      <div className="card card-lift">
        <h1 style={{ fontSize: '1.6rem' }}>Create your account</h1>
        <p>Free, and takes a few seconds.</p>

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
              autoComplete="new-password"
              required
              value={pw}
              onChange={(e) => setPw(e.target.value)}
              onBlur={() => setTouched(true)}
              aria-describedby="pw-help"
              aria-invalid={pwIssue ? true : undefined}
            />
            <div style={{ display: 'flex', gap: 4, marginTop: 8 }} aria-hidden="true">
              {[1, 2, 3].map((i) => (
                <span
                  key={i}
                  style={{
                    height: 4,
                    flex: 1,
                    borderRadius: 'var(--r-pill)',
                    background: strength.score >= i ? BAR[strength.score] : 'var(--line)',
                    transition: 'background .2s',
                  }}
                />
              ))}
            </div>
            <p
              id="pw-help"
              className="muted"
              style={{
                marginTop: 6,
                marginBottom: 0,
                color: pwIssue ? 'var(--block)' : undefined,
              }}
            >
              {pwIssue ?? (strength.label ? `${strength.label}.` : 'At least 10 characters.')}
            </p>
          </div>

          <div className="field">
            <label htmlFor="pw2">Confirm password</label>
            <input
              id="pw2"
              type={show ? 'text' : 'password'}
              autoComplete="new-password"
              required
              value={pw2}
              onChange={(e) => setPw2(e.target.value)}
              onBlur={() => setTouched(true)}
              aria-invalid={mismatch ? true : undefined}
              aria-describedby="pw2-help"
            />
            {mismatch && (
              <p id="pw2-help" style={{ color: 'var(--block)', fontSize: 13, margin: '6px 0 0' }}>
                Passwords do not match.
              </p>
            )}
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

          <button className="btn" type="submit" disabled={!canSubmit} style={{ width: '100%' }}>
            {busy ? 'Creating account\u2026' : 'Create account'}
          </button>
        </form>

        <p className="muted" style={{ marginTop: 18, marginBottom: 0 }}>
          Already have an account? <Link to="/login">Log in</Link>
        </p>
      </div>

      <div className="note" style={{ marginTop: 16 }}>
        Signup always creates a <strong>customer</strong> account. Analyst and admin
        roles can only be granted by a direct write to the user store &mdash; there is
        no API path to privilege escalation.
      </div>
    </div>
  )
}
