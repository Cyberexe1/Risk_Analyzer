import { useEffect, useMemo, useRef, useState } from 'react'
import { api, ApiError, rupees, type RingGraph, type RingNode } from '../api'
import { ErrorNote } from '../components'

type Positioned = RingNode & { x: number; y: number; vx: number; vy: number }

const W = 660
const H = 460

const STYLE: Record<
  RingNode['type'],
  { r: number; fill: string; stroke: string; glyph: string; name: string }
> = {
  account: { r: 9, fill: 'var(--accent-soft)', stroke: 'var(--accent)', glyph: '\u25CF', name: 'Account' },
  device: { r: 12, fill: 'rgba(99,91,78,.16)', stroke: 'var(--violet)', glyph: '\u25A0', name: 'Device' },
  ip: { r: 11, fill: 'rgba(99,94,86,.16)', stroke: 'var(--cyan)', glyph: '\u25B2', name: 'IP' },
}

/**
 * Force-directed layout, hand-rolled.
 *
 * A dependency-free simulation: repulsion between all nodes, springs along edges,
 * mild centring. ~200 iterations settles a component of this size, and the cap of
 * 200 nodes from the backend keeps the O(n^2) repulsion cheap.
 *
 * Deliberately not a charting library. The graph is 60 lines of physics and
 * SVG; pulling in d3 for it would add ~90 KB to a bundle that is currently 232 KB.
 */
function layout(g: RingGraph): Positioned[] {
  const nodes: Positioned[] = g.nodes.map((n, i) => {
    const a = (i / Math.max(1, g.nodes.length)) * Math.PI * 2
    return {
      ...n,
      x: W / 2 + Math.cos(a) * 140 + (i % 3) * 7,
      y: H / 2 + Math.sin(a) * 110 + (i % 5) * 5,
      vx: 0,
      vy: 0,
    }
  })
  const byId = new Map(nodes.map((n) => [n.id, n]))

  for (let step = 0; step < 220; step++) {
    const cool = 1 - step / 260

    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const a = nodes[i]
        const b = nodes[j]
        let dx = b.x - a.x
        let dy = b.y - a.y
        let d2 = dx * dx + dy * dy
        if (d2 < 1) {
          dx = (Math.random() - 0.5) * 2
          dy = (Math.random() - 0.5) * 2
          d2 = 1
        }
        const f = 2600 / d2
        const d = Math.sqrt(d2)
        a.vx -= (dx / d) * f
        a.vy -= (dy / d) * f
        b.vx += (dx / d) * f
        b.vy += (dy / d) * f
      }
    }

    for (const e of g.edges) {
      const a = byId.get(e.source)
      const b = byId.get(e.target)
      if (!a || !b) continue
      const dx = b.x - a.x
      const dy = b.y - a.y
      const d = Math.max(1, Math.hypot(dx, dy))
      const f = (d - 84) * 0.035
      a.vx += (dx / d) * f
      a.vy += (dy / d) * f
      b.vx -= (dx / d) * f
      b.vy -= (dy / d) * f
    }

    for (const n of nodes) {
      n.vx += (W / 2 - n.x) * 0.004
      n.vy += (H / 2 - n.y) * 0.004
      n.x = Math.max(24, Math.min(W - 24, n.x + n.vx * cool * 0.35))
      n.y = Math.max(24, Math.min(H - 24, n.y + n.vy * cool * 0.35))
      n.vx *= 0.82
      n.vy *= 0.82
    }
  }
  return nodes
}

export default function RingView({
  seedType,
  seedId,
  onClose,
}: {
  seedType: 'device' | 'ip' | 'account'
  seedId: string
  onClose?: () => void
}) {
  const [g, setG] = useState<RingGraph | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [depth, setDepth] = useState(2)
  const [hover, setHover] = useState<Positioned | null>(null)
  const [showTable, setShowTable] = useState(false)
  const svgRef = useRef<SVGSVGElement>(null)

  useEffect(() => {
    setG(null)
    setError(null)
    void api
      .ring(seedType, seedId, depth)
      .then(setG)
      .catch((e) => setError(e instanceof ApiError ? e.message : String(e)))
  }, [seedType, seedId, depth])

  const nodes = useMemo(() => (g ? layout(g) : []), [g])
  const byId = useMemo(() => new Map(nodes.map((n) => [n.id, n])), [nodes])

  const suspicious = nodes.filter((n) => n.suspicious)

  return (
    <div className="card">
      <div className="spread" style={{ marginBottom: 'var(--sp-3)' }}>
        <div>
          <h3 className="t-base" style={{ margin: 0 }}>
            Shared-entity graph
          </h3>
          <p className="muted mono t-2xs" style={{ margin: 0 }}>
            {seedType}: {seedId}
          </p>
        </div>
        <div className="row row-tight">
          <label className="sr-only" htmlFor="depth">
            Expansion depth
          </label>
          <select
            id="depth"
            value={depth}
            onChange={(e) => setDepth(Number(e.target.value))}
            style={{ width: 'auto' }}
          >
            <option value={1}>Depth 1</option>
            <option value={2}>Depth 2</option>
            <option value={3}>Depth 3</option>
          </select>
          <button className="btn btn-ghost btn-sm" onClick={() => setShowTable((s) => !s)}>
            {showTable ? 'Show graph' : 'Show as table'}
          </button>
          {onClose && (
            <button className="btn btn-ghost btn-sm" onClick={onClose}>
              Close
            </button>
          )}
        </div>
      </div>

      {error && <ErrorNote error={error} />}
      {!g && !error && <div className="empty">Expanding component&hellip;</div>}

      {g && (
        <>
          <div className="pill-row" style={{ marginBottom: 'var(--sp-3)' }}>
            <span className="chip">{g.counts.accounts} accounts</span>
            <span className="chip">{g.counts.devices} devices</span>
            <span className="chip">{g.counts.ips} IPs</span>
            <span className="chip">{g.counts.edges} edges</span>
            {g.truncated && (
              <span className="badge badge-review">
                <span aria-hidden="true">{'\u25C6'}</span>truncated at 200
              </span>
            )}
          </div>

          {g.counts.accounts >= 3 && suspicious.length > 0 && (
            <div className="note note-warn" style={{ marginBottom: 'var(--sp-3)' }}>
              <strong>
                {g.counts.accounts} accounts share {suspicious.length}{' '}
                {suspicious.length === 1 ? 'entity' : 'entities'}.
              </strong>{' '}
              Each account may look ordinary alone. The structure is the evidence.
            </div>
          )}
          {/* Estimated exposure.
              The tooltip and the caption are not decoration: an unqualified rupee
              figure next to a "fraud ring" heading reads as money stolen, and
              nothing here supports that claim. `confirmed_fraud_amount` is the only
              field backed by ground truth, and it is null until a human labels
              something. */}
          {g.exposure && (
            <div className="card" style={{ marginBottom: 'var(--sp-3)' }}>
              <div className="spread">
                <h3 className="t-base" title={g.exposure.definition}>
                  Estimated exposure: {rupees(g.exposure.gross_exposure)}
                </h3>
                <span className="chip">
                  {g.exposure.complete ? 'retained history' : 'partial'}
                </span>
              </div>

              <div className="pill-row" style={{ marginTop: 'var(--sp-2)' }}>
                <span className="chip" title="Refused before authorisation. No money moved.">
                  blocked {rupees(g.exposure.blocked_amount)}
                </span>
                <span className="chip" title="Sent to a human for review.">
                  in review {rupees(g.exposure.review_amount)}
                </span>
                <span className="chip" title="Allowed through by the engine.">
                  allowed {rupees(g.exposure.allowed_amount)}
                </span>
                <span className="chip" title="Payments that actually settled successfully.">
                  settled {rupees(g.exposure.settled_amount)}
                </span>
                <span
                  className="chip"
                  title="Amount on transactions a human has labelled fraud. Null until someone rules on one."
                >
                  confirmed fraud{' '}
                  {g.exposure.confirmed_fraud_amount === null
                    ? 'not established'
                    : rupees(g.exposure.confirmed_fraud_amount)}
                </span>
              </div>

              <p className="muted t-xs" style={{ marginTop: 'var(--sp-3)' }}>
                {g.exposure.definition}
              </p>
              <p className="muted t-xs">
                Counted {g.exposure.transactions_counted} transaction
                {g.exposure.transactions_counted === 1 ? '' : 's'} across{' '}
                {g.exposure.accounts_with_transactions} of{' '}
                {g.exposure.accounts_in_component} accounts
                {g.exposure.transactions_skipped > 0 &&
                  `, skipping ${g.exposure.transactions_skipped} with unusable amounts`}
                . {g.exposure.window.note}
              </p>
              {!g.exposure.complete && (
                <div className="note note-warn" style={{ marginTop: 'var(--sp-2)' }}>
                  <strong>This figure is a floor, not a total.</strong> Some
                  transactions could not be counted, so the real associated amount is
                  higher than shown.
                </div>
              )}
            </div>
          )}

          {g.counts.accounts < 3 && (
            <div className="note" style={{ marginBottom: 'var(--sp-3)' }}>
              Fewer than 3 accounts in this component, so the network layer scores it 0.
              Not every shared device is a ring &mdash; family tablets and office networks
              look like this too.
            </div>
          )}

          {/* Table equivalent: the graph is not usable with a screen reader, so the
              same data is available in a linear form rather than only as an image. */}
          {showTable ? (
            <div className="table-shell">
              <table>
                <caption className="sr-only">
                  Accounts and the entities they share, as a table
                </caption>
                <thead>
                  <tr>
                    <th scope="col">Node</th>
                    <th scope="col">Type</th>
                    <th scope="col">Connected to</th>
                    <th scope="col">Detail</th>
                  </tr>
                </thead>
                <tbody>
                  {nodes.map((n) => {
                    const links = g.edges
                      .filter((e) => e.source === n.id || e.target === n.id)
                      .map((e) => (e.source === n.id ? e.target : e.source))
                    return (
                      <tr key={n.id}>
                        <td className="mono t-2xs">
                          {n.label}
                          {n.is_seed && <span className="badge badge-neutral">seed</span>}
                        </td>
                        <td>{STYLE[n.type].name}</td>
                        <td className="num">{links.length}</td>
                        <td className="muted t-2xs">
                          {n.type === 'account'
                            ? `${n.txn_count ?? 0} txns, ${n.fail_count ?? 0} failed`
                            : `${n.account_count ?? 0} accounts${
                                n.shared_infra ? ' (shared infra)' : ''
                              }`}
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          ) : (
            <div style={{ position: 'relative' }}>
              <svg
                ref={svgRef}
                viewBox={`0 0 ${W} ${H}`}
                width="100%"
                style={{
                  background: 'var(--bg-soft)',
                  border: '1px solid var(--line)',
                  borderRadius: 'var(--r-md)',
                  display: 'block',
                }}
                role="img"
                aria-label={`Shared-entity graph: ${g.counts.accounts} accounts connected through ${g.counts.devices} devices and ${g.counts.ips} IP addresses. Use "Show as table" for an accessible version.`}
              >
                {g.edges.map((e, i) => {
                  const a = byId.get(e.source)
                  const b = byId.get(e.target)
                  if (!a || !b) return null
                  return (
                    <line
                      key={i}
                      x1={a.x}
                      y1={a.y}
                      x2={b.x}
                      y2={b.y}
                      stroke={e.kind === 'device' ? 'var(--violet)' : 'var(--cyan)'}
                      strokeOpacity={0.32}
                      strokeWidth={1.4}
                    />
                  )
                })}
                {nodes.map((n) => {
                  const s = STYLE[n.type]
                  const r = n.is_seed ? s.r + 4 : s.r
                  return (
                    <g
                      key={n.id}
                      onMouseEnter={() => setHover(n)}
                      onMouseLeave={() => setHover(null)}
                      style={{ cursor: 'pointer' }}
                    >
                      {n.suspicious && (
                        <circle cx={n.x} cy={n.y} r={r + 6} fill="none"
                                stroke="var(--block)" strokeOpacity={0.5} strokeWidth={1.5} />
                      )}
                      <circle
                        cx={n.x}
                        cy={n.y}
                        r={r}
                        fill={s.fill}
                        stroke={n.is_seed ? 'var(--text)' : s.stroke}
                        strokeWidth={n.is_seed ? 2.5 : 1.6}
                      />
                    </g>
                  )
                })}
              </svg>

              {hover && (
                <div
                  className="card card-tight"
                  style={{
                    position: 'absolute',
                    left: 12,
                    bottom: 12,
                    maxWidth: 300,
                    pointerEvents: 'none',
                  }}
                >
                  <div className="mono t-2xs" style={{ wordBreak: 'break-all' }}>
                    {hover.label}
                  </div>
                  <div className="muted t-2xs">
                    {STYLE[hover.type].name}
                    {hover.type === 'account'
                      ? ` · ${hover.txn_count ?? 0} txns · ${hover.fail_count ?? 0} failed`
                      : ` · ${hover.account_count ?? 0} accounts`}
                    {hover.shared_infra && ' · shared infrastructure'}
                  </div>
                </div>
              )}

              <div className="pill-row" style={{ marginTop: 'var(--sp-3)' }}>
                {(['account', 'device', 'ip'] as const).map((k) => (
                  <span className="chip" key={k}>
                    <span aria-hidden="true" style={{ color: STYLE[k].stroke }}>
                      {STYLE[k].glyph}
                    </span>{' '}
                    {STYLE[k].name}
                  </span>
                ))}
                <span className="chip">
                  <span aria-hidden="true" style={{ color: 'var(--block)' }}>
                    {'\u25EF'}
                  </span>{' '}
                  over threshold
                </span>
              </div>
            </div>
          )}

          <p className="muted" style={{ marginTop: 'var(--sp-3)' }}>
            Same adjacency the network score walks, so the picture and the number cannot
            disagree. IPs above {26} accounts are treated as shared infrastructure and not
            followed &mdash; without that, a carrier range pulls in unrelated strangers.
          </p>
        </>
      )}
    </div>
  )
}
