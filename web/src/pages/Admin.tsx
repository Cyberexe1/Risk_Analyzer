import { useCallback, useEffect, useState } from 'react'
import { api, ApiError, band, rupees, type Health, type QueueItem } from '../api'
import { Badge, ErrorNote, Reasons, ScoreDial, Stat, SubScoreBars } from '../components'

/**
 * Analyst console: risk-sorted queue, evidence panel, and the decision actions
 * that write labels back.
 *
 * The label write is the only place ground truth is created. A risk score never
 * becomes a label on its own — that distinction is what keeps the system
 * accountable for routing attention rather than for declaring fraud.
 */
export default function Admin() {
  const [items, setItems] = useState<QueueItem[]>([])
  const [health, setHealth] = useState<Health | null>(null)
  const [selected, setSelected] = useState<QueueItem | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  const refresh = useCallback(async () => {
    try {
      const [q, h] = await Promise.all([api.queue(), api.health()])
      setItems(q.items)
      setHealth(h)
      setError(null)
      setSelected((prev) =>
        prev ? (q.items.find((i) => i.transaction_id === prev.transaction_id) ?? null) : null,
      )
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void refresh()
    const t = setInterval(() => void refresh(), 5000)
    return () => clearInterval(t)
  }, [refresh])

  async function decide(id: string, label: 'fraud' | 'legitimate') {
    try {
      await api.outcome(id, label)
      setSelected(null)
      await refresh()
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e))
    }
  }

  const blocked = items.filter((i) => i.decision === 'BLOCK').length
  const review = items.filter((i) => i.decision === 'MANUAL_REVIEW').length

  return (
    <div className="wrap section-sm">
      <div className="spread" style={{ marginBottom: 20 }}>
        <div>
          <h1 style={{ fontSize: '1.9rem', marginBottom: 4 }}>Analyst console</h1>
          <p className="muted" style={{ margin: 0 }}>
            Queue refreshes every 5 seconds.
          </p>
        </div>
        <button className="btn btn-ghost btn-sm" onClick={() => void refresh()}>
          Refresh now
        </button>
      </div>

      {error && (
        <div style={{ marginBottom: 16 }}>
          <ErrorNote error={error} />
        </div>
      )}

      <div className="grid grid-4" style={{ marginBottom: 20 }}>
        <Stat k="In queue" v={items.length} n="awaiting a decision" />
        <Stat k="Blocked" v={blocked} n="no human in the loop" />
        <Stat k="For review" v={review} n="held, not declined" />
        <Stat
          k="Thresholds"
          v={health?.thresholds ? `${health.thresholds.review} / ${health.thresholds.block}` : '\u2014'}
          n="review / block"
        />
      </div>

      {health && !health.model_loaded && (
        <div className="note note-warn" style={{ marginBottom: 16 }} role="alert">
          <strong>Model artifact missing.</strong> Running on rules and network only. Train
          with <code>python ml/train.py</code>.
        </div>
      )}

      <div className="grid" style={{ gridTemplateColumns: '1fr minmax(320px, 420px)' }}>
        {/* ---- queue ---- */}
        <div className="table-shell">
          <table>
            <caption className="sr-only">
              Transactions awaiting review, sorted by risk score descending
            </caption>
            <thead>
              <tr>
                <th scope="col">Risk</th>
                <th scope="col">Decision</th>
                <th scope="col">Transaction</th>
                <th scope="col">Amount</th>
              </tr>
            </thead>
            <tbody>
              {loading && (
                <tr>
                  <td colSpan={4} className="empty">
                    Loading&hellip;
                  </td>
                </tr>
              )}
              {!loading && !items.length && (
                <tr>
                  <td colSpan={4} className="empty">
                    Queue is empty. Run a few transactions from the{' '}
                    <a href="/checkout">checkout page</a>.
                  </td>
                </tr>
              )}
              {items.map((it) => {
                const b = band(it.decision)
                const isSel = selected?.transaction_id === it.transaction_id
                return (
                  <tr
                    key={it.transaction_id}
                    className="clickable"
                    aria-selected={isSel}
                    tabIndex={0}
                    onClick={() => setSelected(it)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault()
                        setSelected(it)
                      }
                    }}
                  >
                    <td>
                      <strong className="mono" style={{ color: b.colour, fontSize: 16 }}>
                        {Math.round(it.risk_score)}
                      </strong>
                    </td>
                    <td>
                      <Badge decision={it.decision} />
                    </td>
                    <td className="mono muted">{it.transaction_id}</td>
                    <td className="mono">{rupees(it.amount)}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>

        {/* ---- evidence ---- */}
        <div className="card" style={{ alignSelf: 'start', position: 'sticky', top: 82 }}>
          {!selected && (
            <div className="empty" style={{ padding: '32px 8px' }}>
              Select a transaction to see its evidence.
            </div>
          )}
          {selected && (
            <div className="stack" style={{ gap: 20 }}>
              <div>
                <div className="muted mono" style={{ marginBottom: 10 }}>
                  {selected.transaction_id}
                </div>
                <ScoreDial score={selected.risk_score} decision={selected.decision} />
              </div>

              <div className="spread">
                <span className="muted">Customer</span>
                <span className="mono">{selected.customer_id}</span>
              </div>
              <div className="spread" style={{ marginTop: -8 }}>
                <span className="muted">Amount</span>
                <span className="mono">{rupees(selected.amount)}</span>
              </div>

              <SubScoreBars sub={selected.sub_scores} />

              <div>
                <div className="sub-head" style={{ marginBottom: 8 }}>
                  <span>Why</span>
                </div>
                <Reasons codes={selected.reason_codes} />
              </div>

              {selected.override && (
                <div className="note">
                  Aggregation bypassed: <code>{selected.override}</code>
                </div>
              )}

              <div>
                <div className="sub-head" style={{ marginBottom: 8 }}>
                  <span>Record the outcome</span>
                </div>
                <p className="muted" style={{ fontSize: 13 }}>
                  This writes a label for retraining. The score was a routing decision, not
                  a verdict.
                </p>
                <div className="row">
                  <button
                    className="btn btn-sm"
                    style={{ background: 'var(--block)' }}
                    onClick={() => void decide(selected.transaction_id, 'fraud')}
                  >
                    Confirm fraud
                  </button>
                  <button
                    className="btn btn-sm"
                    style={{ background: 'var(--allow)', color: '#04140d' }}
                    onClick={() => void decide(selected.transaction_id, 'legitimate')}
                  >
                    Mark legitimate
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      <p className="muted" style={{ marginTop: 24 }}>
        Queue lives in the backend&rsquo;s process memory and is lost on restart. The
        DynamoDB adapter is not built.
      </p>
    </div>
  )
}
