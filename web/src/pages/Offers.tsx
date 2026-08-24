import { useCallback, useEffect, useState } from 'react'
import {
  ApiError,
  promoApi,
  rupees,
  type MyRedemption,
  type Offer,
  type RedeemResult,
} from '../api'
import { ErrorNote, Reasons } from '../components'
import { useAuth } from '../auth'

function deviceFingerprint(): string {
  const k = 'fs_device'
  let v = localStorage.getItem(k)
  if (!v) {
    v = `dev_web_${Math.random().toString(36).slice(2, 10)}`
    localStorage.setItem(k, v)
  }
  return v
}

const STATUS: Record<string, { label: string; cls: string; glyph: string }> = {
  credited: { label: 'Credited', cls: 'allow', glyph: '\u25CF' },
  under_review: { label: 'Under review', cls: 'review', glyph: '\u25C6' },
  denied: { label: 'Not available', cls: 'block', glyph: '\u25B2' },
}

/**
 * Offer claiming â€” the promo abuse gate's customer-facing surface.
 *
 * Promo abuse is scored here, not at checkout: by the time a payment is scored
 * the cashback is already credited. And the evidence lives in relationships
 * between accounts, which a per-transaction model has nowhere to put.
 *
 * The "shared device" toggle exists so the gate is demonstrable. Claiming from a
 * device and payout destination that another account already used is what the
 * rules are looking for.
 */
export default function Offers() {
  const { user } = useAuth()
  const [offers, setOffers] = useState<Offer[]>([])
  const [mine, setMine] = useState<MyRedemption[]>([])
  const [result, setResult] = useState<RedeemResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState<string | null>(null)
  const [shared, setShared] = useState(false)

  const load = useCallback(async () => {
    try {
      const [o, m] = await Promise.all([promoApi.offers(), promoApi.mine()])
      setOffers(o.offers)
      setMine(m.redemptions)
      setError(null)
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e))
    }
  }, [])

  useEffect(() => {
    void load()
  }, [load])

  async function claim(code: string) {
    setBusy(code)
    setError(null)
    setResult(null)
    try {
      setResult(
        await promoApi.redeem({
          promo_code: code,
          device_fp: shared ? 'dev_demo_shared_promo' : deviceFingerprint(),
          // No ip_hash: the backend derives it from the connection. A client that
          // could choose its own would walk past every IP-based signal.
          payout_ref: shared ? 'upi_demo_shared' : `upi_${user?.user_id.slice(0, 10)}`,
        }),
      )
      await load()
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e))
    } finally {
      setBusy(null)
    }
  }

  const claimed = new Set(mine.map((m) => m.promo_code))
  const staff = user?.role === 'analyst' || user?.role === 'admin'

  return (
    <div className="wrap section-sm">
      <h1>Offers</h1>
      <p style={{ maxWidth: 620 }}>
        One claim per account. Claims are checked against the accounts, devices and
        payout destinations already linked to yours.
      </p>

      {error && (
        <div style={{ margin: '16px 0' }}>
          <ErrorNote error={error} />
        </div>
      )}

      <label
        className="card card-tight"
        style={{
          display: 'flex',
          gap: 10,
          alignItems: 'flex-start',
          fontWeight: 500,
          margin: '16px 0 24px',
          cursor: 'pointer',
        }}
      >
        <input
          type="checkbox"
          checked={shared}
          onChange={(e) => setShared(e.target.checked)}
          style={{ width: 16, height: 16, flex: '0 0 auto', marginTop: 3 }}
        />
        <span>
          Claim from a shared device and payout destination
          <span className="muted" style={{ display: 'block', fontWeight: 400 }}>
            Simulates one person cycling accounts through the same tablet and UPI id.
            The first claim goes through; the rest do not.
          </span>
        </span>
      </label>

      <div className="grid grid-2">
        {offers.map((o) => (
          <div className="card" key={o.code}>
            <div className="spread" style={{ marginBottom: 8 }}>
              <h3 style={{ margin: 0 }}>{o.name}</h3>
              <span className="num t-md">
                {rupees(o.value)}
              </span>
            </div>
            <p>{o.blurb}</p>
            <div className="pill-row" style={{ marginBottom: 14 }}>
              <span className="chip">{o.code}</span>
            </div>
            <button
              className="btn"
              style={{ width: '100%' }}
              disabled={busy !== null || claimed.has(o.code)}
              onClick={() => void claim(o.code)}
            >
              {claimed.has(o.code)
                ? 'Already claimed'
                : busy === o.code
                  ? 'Checking\u2026'
                  : 'Claim offer'}
            </button>
          </div>
        ))}
      </div>

      {result && (
        <div className="card" style={{ marginTop: 20 }}>
          <div className="spread" style={{ marginBottom: 12 }}>
            <h3 style={{ margin: 0 }}>Result</h3>
            <span className={`badge badge-${STATUS[result.status]?.cls ?? 'neutral'}`}>
              <span aria-hidden="true">{STATUS[result.status]?.glyph}</span>
              {STATUS[result.status]?.label ?? result.status}
            </span>
          </div>
          <div className="note">{result.message}</div>

          {/* Staff only. Telling a promo abuser which signal fired tells them
              exactly what to rotate next. */}
          {result.risk && (
            <div style={{ marginTop: 16 }}>
              <div className="sub-head" style={{ marginBottom: 8 }}>
                <span>Why (staff only)</span>
              </div>
              <Reasons codes={result.risk.reasons} />
              {result.risk.shared_ip_exempt && (
                <p className="muted" style={{ marginTop: 10, marginBottom: 0 }}>
                  Shared-IP exemption applied: this IP looks like office or carrier
                  infrastructure, so IP-only signals were suppressed.
                </p>
              )}
            </div>
          )}
          {!staff && (
            <p className="muted" style={{ marginTop: 12, marginBottom: 0 }}>
              No reason codes here. The backend omits them for a <code>customer</code>{' '}
              role.
            </p>
          )}
        </div>
      )}

      {!!mine.length && (
        <>
          <h2 className="t-lg" style={{ marginTop: 'var(--sp-10)' }}>Your claims</h2>
          <div className="table-shell">
            <table>
              <caption className="sr-only">Your promotion claims</caption>
              <thead>
                <tr>
                  <th scope="col">Offer</th>
                  <th scope="col">Value</th>
                  <th scope="col">Status</th>
                  <th scope="col">Claimed</th>
                </tr>
              </thead>
              <tbody>
                {mine.map((m) => (
                  <tr key={m.redemption_id}>
                    <td className="mono">{m.promo_code}</td>
                    <td className="mono">{rupees(m.value)}</td>
                    <td>
                      <span className={`badge badge-${STATUS[m.status]?.cls ?? 'neutral'}`}>
                        <span aria-hidden="true">{STATUS[m.status]?.glyph}</span>
                        {STATUS[m.status]?.label ?? m.status}
                      </span>
                    </td>
                    <td className="muted">{new Date(m.created_at).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      <p className="muted" style={{ marginTop: 24 }}>
        A refused cashback is not a refused sale &mdash; you can still order, and support
        can reverse it. That asymmetry is why this gate is allowed to be stricter than
        the checkout scorer.
      </p>
    </div>
  )
}
