import { Fragment, useCallback, useEffect, useState } from 'react'
import { api, ApiError, rupees, type SuspiciousIp } from '../api'
import { ErrorNote, Stat } from '../components'

/**
 * Flagged addresses, and the declines behind each one.
 *
 * The count is what trips the flag; these records are what make it reviewable. An
 * analyst asked "why is this address flagged?" needs the individual attempts, not
 * a number — so every row expands into the attempts that produced it.
 *
 * This signal is NOT part of the risk score. It is an operational flag, and
 * promoting it into the model would mean a retrain and a fresh evaluation, not a
 * code change. Nothing here re-decides a transaction.
 */
export default function SuspiciousIps() {
  const [items, setItems] = useState<SuspiciousIp[]>([])
  const [threshold, setThreshold] = useState(3)
  const [windowMin, setWindowMin] = useState(60)
  const [totalAttempts, setTotalAttempts] = useState<number | null>(null)
  const [open, setOpen] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  const load = useCallback(async () => {
    try {
      const [s, f] = await Promise.all([
        api.suspiciousIps(),
        api.failedAttempts().catch(() => null),
      ])
      setItems(s.items)
      setThreshold(s.threshold)
      setWindowMin(s.window_minutes)
      setTotalAttempts(f?.count ?? null)
      setError(null)
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void load()
    const t = setInterval(() => void load(), 5000)
    return () => clearInterval(t)
  }, [load])

  return (
    <div className="stack stack-lg">
      {error && <ErrorNote error={error} />}

      <div className="grid grid-4">
        <Stat k="Flagged addresses" v={items.length} n="currently marked" />
        <Stat
          k="Trigger"
          v={`${threshold} fails`}
          n={`within ${windowMin} minutes`}
        />
        <Stat
          k="Failed attempts"
          v={totalAttempts ?? '\u2014'}
          n="stored across all addresses"
        />
        <Stat
          k="Scoring impact"
          v="None"
          n="operational flag, not a feature"
        />
      </div>

      <div className="note">
        A single decline is not evidence: cards expire and balances run out. A{' '}
        <strong>burst</strong> from one address is different &mdash; that is the shape
        card testing leaves, where an attacker walks a list of stolen numbers until one
        authorises. Addresses carrying more than 25 accounts are exempt, because a
        carrier NAT or an office range pools unrelated customers&rsquo; declines through
        no fault of anyone behind it.
      </div>

      {loading && <div className="empty">Loading&hellip;</div>}

      {!loading && !items.length && (
        <div className="card empty">
          <p style={{ marginBottom: 0 }}>
            No addresses flagged. Fail {threshold} payments within {windowMin} minutes
            from the same network to populate this &mdash; the checkout&rsquo;s
            &ldquo;Fails checksum&rdquo; test card is the quickest way.
          </p>
        </div>
      )}

      {!!items.length && (
        <div className="table-shell">
          <table>
            <caption className="sr-only">
              Addresses flagged for repeated failed payments
            </caption>
            <thead>
              <tr>
                <th scope="col">Address</th>
                <th scope="col">Flagged</th>
                <th scope="col">Why</th>
                <th scope="col" className="num">
                  Fails
                </th>
                <th scope="col" className="num">
                  Accounts
                </th>
                <th scope="col">
                  <span className="sr-only">Evidence</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {items.map((it) => {
                const isOpen = open === it.ip_hash
                return (
                  <Fragment key={it.ip_hash}>
                    <tr>
                      <td>
                        <div className="mono t-2xs">{it.ip_hash}</div>
                        <span className="badge badge-block">
                          <span aria-hidden="true">{'\u25B2'}</span>suspicious
                        </span>
                        {it.source === 'persisted' && (
                          <div className="muted t-2xs" style={{ marginTop: 'var(--sp-1)' }}>
                            from records &mdash; counters lost on restart
                          </div>
                        )}
                      </td>
                      <td className="muted t-2xs">
                        {it.since ? new Date(it.since).toLocaleString() : '\u2014'}
                      </td>
                      <td className="t-sm">{it.reason}</td>
                      <td className="num">{it.failures_total}</td>
                      <td className="num">{it.accounts}</td>
                      <td>
                        <button
                          className="btn btn-ghost btn-sm"
                          aria-expanded={isOpen}
                          onClick={() => setOpen(isOpen ? null : it.ip_hash)}
                        >
                          {isOpen ? 'Hide' : `${it.attempt_count} attempts`}
                        </button>
                      </td>
                    </tr>

                    {isOpen && (
                      <tr>
                        <td colSpan={6} style={{ background: 'var(--bg-soft)' }}>
                          <div className="sub-head" style={{ marginBottom: 'var(--sp-3)' }}>
                            <span>The declines behind this flag</span>
                          </div>

                          {!!it.accounts_involved.length && (
                            <div className="pill-row" style={{ marginBottom: 'var(--sp-3)' }}>
                              <span className="muted">Accounts:</span>
                              {it.accounts_involved.map((e) => (
                                <span className="chip" key={e}>
                                  {e}
                                </span>
                              ))}
                            </div>
                          )}

                          <div className="stack" style={{ gap: 'var(--sp-2)' }}>
                            {it.attempts.map((a) => (
                              <div className="reason reason-high" key={a.attempt_id}>
                                <span className="mono t-2xs" style={{ flex: '0 0 132px' }}>
                                  {new Date(a.created_at).toLocaleTimeString()}
                                </span>
                                <span style={{ flex: 1 }}>
                                  {rupees(a.amount)} via {a.payment_method.toUpperCase()}
                                  {a.instrument_display ? ` (${a.instrument_display})` : ''}
                                  {' \u2014 '}
                                  {a.customer_status === 'declined'
                                    ? 'blocked'
                                    : 'declined by bank'}
                                </span>
                                <span className="src">risk {Math.round(a.risk_score)}</span>
                              </div>
                            ))}
                          </div>

                          {it.attempt_count > it.attempts.length && (
                            <p className="muted" style={{ marginTop: 'var(--sp-3)' }}>
                              Showing {it.attempts.length} of {it.attempt_count}.
                            </p>
                          )}
                        </td>
                      </tr>
                    )}
                  </Fragment>
                )
              })}
            </tbody>
          </table>
        </div>
      )}

      <p className="muted">
        Flags persist to the record store, but the trailing-window counters behind them
        live in process memory and reset on restart. A flag raised before a restart stays
        visible; the failure count that justified it does not keep accumulating.
      </p>
    </div>
  )
}
