import { useCallback, useEffect, useState } from 'react'
import {
  api,
  ApiError,
  band,
  promoApi,
  rupees,
  type AdminMetrics as Metrics,
  type Health,
  type PromoHold,
  type QueueItem,
} from '../api'
import { Badge, ErrorNote, Reasons, ScoreDial, Stat, SubScoreBars } from '../components'
import AdminMetricsPanel from './AdminMetrics'
import RingView from './RingView'
import Thresholds from './Thresholds'
import SuspiciousIps from './SuspiciousIps'
import { useAuth } from '../auth'

type Tab = 'queue' | 'rings' | 'ips' | 'promo' | 'metrics' | 'thresholds'
type Seed = { type: 'device' | 'ip' | 'account'; id: string }

/**
 * Analyst console.
 *
 * Three surfaces: the risk-sorted transaction queue with its evidence panel, the
 * promo-abuse holds, and live model performance read from the evaluation
 * artifacts.
 *
 * Recording an outcome is the only place ground truth is created. A risk score
 * never becomes a label on its own — which is what keeps the system accountable
 * for routing attention rather than for declaring fraud.
 */
export default function Admin() {
  const { user } = useAuth()
  const [tab, setTab] = useState<Tab>('queue')
  const [items, setItems] = useState<QueueItem[]>([])
  const [holds, setHolds] = useState<PromoHold[]>([])
  const [metrics, setMetrics] = useState<Metrics | null>(null)
  const [health, setHealth] = useState<Health | null>(null)
  const [flaggedIps, setFlaggedIps] = useState(0)
  const [selected, setSelected] = useState<QueueItem | null>(null)
  const [seed, setSeed] = useState<Seed | null>(null)
  const [lookupType, setLookupType] = useState<Seed['type']>('device')
  const [lookupId, setLookupId] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  function openRing(s: Seed) {
    setSeed(s)
    setTab('rings')
  }

  const refresh = useCallback(async () => {
    try {
      const [q, h, p, m, ips] = await Promise.all([
        api.queue(),
        api.health(),
        promoApi.holds().catch(() => ({ count: 0, items: [] as PromoHold[] })),
        api.metrics().catch(() => null),
        api.suspiciousIps().catch(() => null),
      ])
      setItems(q.items)
      setHealth(h)
      setHolds(p.items)
      setMetrics(m)
      setFlaggedIps(ips?.count ?? 0)
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

  async function overridePromo(rid: string) {
    try {
      await promoApi.override(rid)
      await refresh()
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e))
    }
  }

  const blocked = items.filter((i) => i.decision === 'BLOCK').length
  const review = items.filter((i) => i.decision === 'MANUAL_REVIEW').length

  return (
    <div className="wrap section-sm">
      <div className="page-head spread">
        <div>
          <h1>Analyst console</h1>
          <p className="dim t-sm">Queue refreshes every 5 seconds.</p>
        </div>
        <div className="row row-tight">
          <span className="chip">
            {health?.user_store?.startsWith('dynamodb') ? 'DynamoDB' : 'in-memory'}
          </span>
          <button className="btn btn-ghost btn-sm" onClick={() => void refresh()}>
            Refresh
          </button>
        </div>
      </div>

      {error && (
        <div style={{ marginBottom: 'var(--sp-4)' }}>
          <ErrorNote error={error} />
        </div>
      )}

      {health && !health.model_loaded && (
        <div className="note note-warn" style={{ marginBottom: 'var(--sp-4)' }} role="alert">
          <strong>Model artifact missing.</strong> Running on rules and network only. Train
          with <code>python ml/train.py</code>.
        </div>
      )}

      <div className="grid grid-4" style={{ marginBottom: 'var(--sp-5)' }}>
        <Stat k="In queue" v={items.length} n="awaiting a decision" />
        <Stat k="Blocked" v={blocked} n="no human in the loop" />
        <Stat k="For review" v={review} n="held, not declined" />
        <Stat k="Promo holds" v={holds.length} n="held or denied claims" />
      </div>

      <div className="tabs" role="tablist" aria-label="Console sections">
        {(
          [
            ['queue', `Transactions (${items.length})`],
            ['rings', 'Rings'],
            ['ips', flaggedIps ? `Suspicious IPs (${flaggedIps})` : 'Suspicious IPs'],
            ['promo', `Promo abuse (${holds.length})`],
            ['metrics', 'Model performance'],
            ['thresholds', 'Thresholds'],
          ] as [Tab, string][]
        ).map(([k, label]) => (
          <button
            key={k}
            className="tab"
            role="tab"
            aria-selected={tab === k}
            onClick={() => setTab(k)}
          >
            {label}
          </button>
        ))}
      </div>

      {/* ---------------- transaction queue ---------------- */}
      {tab === 'queue' && (
        <div className="split">
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
                      Queue is empty. Place a few orders from the{' '}
                      <a href="/checkout">shop</a>.
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
                        <span className="num t-md" style={{ color: b.colour }}>
                          {Math.round(it.risk_score)}
                        </span>
                      </td>
                      <td>
                        <Badge decision={it.decision} />
                      </td>
                      <td className="mono t-2xs faint">{it.transaction_id}</td>
                      <td className="num">{rupees(it.amount)}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>

          <aside className="card sticky-side">
            {!selected && (
              <div className="empty">Select a transaction to see its evidence.</div>
            )}
            {selected && (
              <div className="stack stack-lg">
                <div>
                  <div className="mono t-2xs faint" style={{ marginBottom: 'var(--sp-2)' }}>
                    {selected.transaction_id}
                  </div>
                  <ScoreDial score={selected.risk_score} decision={selected.decision} />
                </div>

                <div className="stack" style={{ gap: 'var(--sp-1)' }}>
                  <div className="spread">
                    <span className="muted">Customer</span>
                    <span className="mono t-sm">{selected.customer_id}</span>
                  </div>
                  <div className="spread">
                    <span className="muted">Amount</span>
                    <span className="num t-sm">{rupees(selected.amount)}</span>
                  </div>
                </div>

                <SubScoreBars sub={selected.sub_scores} />

                <div>
                  <div className="sub-head" style={{ marginBottom: 'var(--sp-2)' }}>
                    <span>Why</span>
                  </div>
                  <Reasons codes={selected.reason_codes} />
                </div>

                {selected.override && (
                  <div className="note">
                    Aggregation bypassed: <code>{selected.override}</code>
                  </div>
                )}

                {selected.ip_suspicious && (
                  <div className="note note-bad">
                    <strong>Origin address is flagged</strong> for repeated failed
                    payments. This did not affect the score above &mdash; it is a
                    separate operational signal. See the Suspicious IPs tab.
                  </div>
                )}

                {/* Pivot to the graph. The network sub-score says how connected
                    this is; the graph shows what it is connected to. */}
                {(selected.device_fp || selected.ip_hash) && (
                  <div>
                    <div className="sub-head" style={{ marginBottom: 'var(--sp-2)' }}>
                      <span>Investigate the cluster</span>
                    </div>
                    <div className="row">
                      {selected.device_fp && (
                        <button
                          className="btn btn-ghost btn-sm"
                          onClick={() =>
                            openRing({ type: 'device', id: selected.device_fp! })
                          }
                        >
                          Ring by device
                        </button>
                      )}
                      {selected.ip_hash && (
                        <button
                          className="btn btn-ghost btn-sm"
                          onClick={() => openRing({ type: 'ip', id: selected.ip_hash! })}
                        >
                          Ring by IP
                        </button>
                      )}
                      <button
                        className="btn btn-ghost btn-sm"
                        onClick={() =>
                          openRing({ type: 'account', id: selected.customer_id })
                        }
                      >
                        Ring by account
                      </button>
                    </div>
                  </div>
                )}

                <div>
                  <div className="sub-head" style={{ marginBottom: 'var(--sp-2)' }}>
                    <span>Record the outcome</span>
                  </div>
                  <p className="muted" style={{ marginBottom: 'var(--sp-3)' }}>
                    This writes a label for retraining. The score was a routing decision,
                    not a verdict.
                  </p>
                  <div className="row">
                    <button
                      className="btn btn-danger btn-sm"
                      onClick={() => void decide(selected.transaction_id, 'fraud')}
                    >
                      Confirm fraud
                    </button>
                    <button
                      className="btn btn-ok btn-sm"
                      onClick={() => void decide(selected.transaction_id, 'legitimate')}
                    >
                      Mark legitimate
                    </button>
                  </div>
                </div>
              </div>
            )}
          </aside>
        </div>
      )}

      {/* ---------------- rings ---------------- */}
      {tab === 'rings' && (
        <div className="stack stack-lg">
          <div className="card">
            <h3 className="t-base">Look up a cluster</h3>
            <p className="muted">
              Expand the accounts, devices and IPs connected to any entity. Pick a
              transaction in the queue to jump straight to its cluster.
            </p>
            <div className="row" style={{ marginTop: 'var(--sp-3)' }}>
              <div className="field" style={{ flex: '0 0 150px', marginBottom: 0 }}>
                <label htmlFor="ltype">Entity</label>
                <select
                  id="ltype"
                  value={lookupType}
                  onChange={(e) => setLookupType(e.target.value as Seed['type'])}
                >
                  <option value="device">Device</option>
                  <option value="ip">IP hash</option>
                  <option value="account">Account</option>
                </select>
              </div>
              <div className="field" style={{ marginBottom: 0 }}>
                <label htmlFor="lid">Identifier</label>
                <input
                  id="lid"
                  value={lookupId}
                  onChange={(e) => setLookupId(e.target.value)}
                  placeholder="dev_demo_shared, ip_..., or a customer id"
                />
              </div>
              <button
                className="btn"
                style={{ flex: '0 0 auto', alignSelf: 'flex-end' }}
                disabled={!lookupId.trim()}
                onClick={() => setSeed({ type: lookupType, id: lookupId.trim() })}
              >
                Expand
              </button>
            </div>
            {!!items.length && (
              <div className="pill-row" style={{ marginTop: 'var(--sp-4)' }}>
                <span className="muted">From the queue:</span>
                {[
                  ...new Set(items.map((i) => i.device_fp).filter(Boolean)),
                ]
                  .slice(0, 6)
                  .map((d) => (
                    <button
                      key={d}
                      className="chip"
                      style={{ cursor: 'pointer' }}
                      onClick={() => setSeed({ type: 'device', id: d as string })}
                    >
                      {d}
                    </button>
                  ))}
              </div>
            )}
          </div>

          {seed ? (
            <RingView seedType={seed.type} seedId={seed.id} onClose={() => setSeed(null)} />
          ) : (
            <div className="card empty">
              Nothing selected. Look up an entity above, or open a transaction in the
              queue and use &ldquo;Ring by device&rdquo;.
            </div>
          )}
        </div>
      )}

      {/* ---------------- suspicious IPs ---------------- */}
      {tab === 'ips' && <SuspiciousIps />}

      {/* ---------------- promo holds ---------------- */}
      {tab === 'promo' && (
        <>
          <div className="table-shell">
            <table>
              <caption className="sr-only">
                Promotion claims held or denied by the redemption gate
              </caption>
              <thead>
                <tr>
                  <th scope="col">Status</th>
                  <th scope="col">Account</th>
                  <th scope="col">Offer</th>
                  <th scope="col">Signals</th>
                  <th scope="col">Action</th>
                </tr>
              </thead>
              <tbody>
                {!holds.length && (
                  <tr>
                    <td colSpan={5} className="empty">
                      Nothing held. Claim an offer twice from the same device on the{' '}
                      <a href="/offers">offers page</a> to populate this.
                    </td>
                  </tr>
                )}
                {holds.map((h) => (
                  <tr key={h.redemption_id}>
                    <td>
                      <span
                        className={`badge badge-${h.decision === 'DENY' ? 'block' : 'review'}`}
                      >
                        <span aria-hidden="true">
                          {h.decision === 'DENY' ? '\u25B2' : '\u25C6'}
                        </span>
                        {h.decision === 'DENY' ? 'Denied' : 'Held'}
                      </span>
                    </td>
                    <td className="mono t-2xs">{h.email}</td>
                    <td>
                      <div className="mono t-sm">{h.promo_code}</div>
                      <div className="muted t-2xs">{rupees(h.value)}</div>
                    </td>
                    <td style={{ maxWidth: 360 }}>
                      <Reasons codes={h.reasons} />
                      {h.shared_ip_exempt && (
                        <p className="muted t-2xs" style={{ marginTop: 'var(--sp-2)' }}>
                          Shared-IP exemption applied
                        </p>
                      )}
                    </td>
                    <td>
                      <button
                        className="btn btn-ghost btn-sm"
                        onClick={() => void overridePromo(h.redemption_id)}
                      >
                        Grant anyway
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="muted" style={{ marginTop: 'var(--sp-3)' }}>
            Overrides are the <strong>only</strong> label source for this gate &mdash; it
            ships with no training data, so an analyst reversing a decision is how we learn
            the rules are wrong.
          </p>
        </>
      )}

      {/* ---------------- metrics ---------------- */}
      {tab === 'metrics' &&
        (metrics ? (
          <AdminMetricsPanel m={metrics} />
        ) : (
          <div className="empty">Loading metrics&hellip;</div>
        ))}

      {/* ---------------- threshold tuner ---------------- */}
      {tab === 'thresholds' && <Thresholds canEdit={user?.role === 'admin'} />}

      <p className="muted" style={{ marginTop: 'var(--sp-6)' }}>
        The review queue lives in the backend&rsquo;s process memory and is lost on
        restart. Users, orders and promo claims persist to DynamoDB; the transaction store
        does not yet.
      </p>
    </div>
  )
}
