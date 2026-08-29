import { useEffect, useMemo, useState } from 'react'
import { api, ApiError, rupees, type AuditEntry, type ThresholdInfo } from '../api'
import { ErrorNote, Stat } from '../components'

const W = 640
const H = 210

/** The wire value the backend emits for a threshold change. */
const THRESHOLD_UPDATE_ACTION = 'threshold_update'

/**
 * Threshold tuner.
 *
 * The review threshold is an operations parameter, not a model property. At a
 * 100:1 cost ratio between a missed fraud and a review, expected-cost
 * minimisation always wants to review more — so the binding constraint is analyst
 * headcount, and that belongs in a control surface rather than a config file.
 *
 * The curve is deliberately drawn rather than reduced to "the optimum is 5".
 * It is flat-bottomed across a wide band, and an operator who can see that will
 * make better calls than one handed a single number.
 */
export default function Thresholds({ canEdit }: { canEdit: boolean }) {
  const [info, setInfo] = useState<ThresholdInfo | null>(null)
  const [audit, setAudit] = useState<AuditEntry[]>([])
  const [review, setReview] = useState(5)
  const [block, setBlock] = useState(70)
  const [reason, setReason] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [flash, setFlash] = useState<string | null>(null)

  async function load() {
    try {
      const t = await api.thresholds()
      setInfo(t)
      setReview(t.current.review)
      setBlock(t.current.block)
      setError(null)
      if (canEdit) {
        // Filtered server-side now. The action name stays lower-case because that
        // spelling already exists in persisted audit partitions -- renaming it
        // would orphan every historical change.
        await api
          .audit({ action: THRESHOLD_UPDATE_ACTION, limit: 200 })
          .then((a) => setAudit(a.entries))
          .catch(() => setAudit([]))
      }
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e))
    }
  }

  useEffect(() => {
    void load()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  /** Cost as a function of the review threshold, holding block at its current value
   *  (or the nearest sampled one). */
  const curve = useMemo(() => {
    if (!info?.cost_curve.length) return []
    const blocks = [...new Set(info.cost_curve.map((p) => p.block))]
    const nearest = blocks.reduce((a, b) =>
      Math.abs(b - block) < Math.abs(a - block) ? b : a,
    )
    return info.cost_curve
      .filter((p) => p.block === nearest)
      .sort((a, b) => a.review - b.review)
  }, [info, block])

  const path = useMemo(() => {
    if (curve.length < 2) return ''
    const costs = curve.map((p) => p.cost)
    const lo = Math.min(...costs)
    const hi = Math.max(...costs)
    const xs = curve.map((p) => p.review)
    const xlo = Math.min(...xs)
    const xhi = Math.max(...xs)
    return curve
      .map((p, i) => {
        const x = 30 + ((p.review - xlo) / Math.max(1, xhi - xlo)) * (W - 50)
        const y = H - 28 - ((p.cost - lo) / Math.max(1, hi - lo)) * (H - 56)
        return `${i === 0 ? 'M' : 'L'}${x.toFixed(1)},${y.toFixed(1)}`
      })
      .join(' ')
  }, [curve])

  const best = curve.length
    ? curve.reduce((a, b) => (b.cost < a.cost ? b : a))
    : null
  const atCurrent = curve.find((p) => p.review === review)

  const liveNow = info?.live_projection.find(
    (p) => p.review === review && p.block === block,
  )

  async function save() {
    setBusy(true)
    setError(null)
    setFlash(null)
    try {
      const r = await api.setThresholds(review, block, reason)
      setFlash(
        `Applied: review \u2265 ${r.current.review}, block \u2265 ${r.current.block} ` +
          `(was ${r.previous.review} / ${r.previous.block}). New traffic only` +
          (r.persisted
            ? `, and saved as configuration v${r.version} \u2014 it survives a restart.`
            : '.'),
      )
      setReason('')
      await load()
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }

  const dirty = !!info && (review !== info.current.review || block !== info.current.block)
  const invalid = block <= review

  return (
    <div className="stack stack-lg">
      {error && <ErrorNote error={error} />}
      {flash && (
        <div className="note note-ok" role="status">
          {flash}
        </div>
      )}

      {info && (
        <>
          {/* Where the live values came from. `degraded` means a stored
              configuration was rejected, so the running thresholds are NOT the ones
              an admin last set -- exactly the log-versus-behaviour mismatch that
              persisting them was meant to remove, so it is stated loudly. */}
          {info.config?.degraded && (
            <div className="note note-warn" role="alert">
              <strong>Stored threshold configuration was rejected.</strong>{' '}
              {info.config.note} The service is running on environment defaults, so
              the values below are not the ones last saved.
            </div>
          )}
          {info.config && !info.config.degraded && (
            <div className="pill-row">
              <span className="chip">
                source: {info.config.source === 'persisted' ? 'saved configuration' : 'environment defaults'}
              </span>
              {info.config.source === 'persisted' && (
                <>
                  <span className="chip">v{info.config.version}</span>
                  <span className="chip">set by {info.config.updated_by}</span>
                  <span className="chip">survives restart</span>
                </>
              )}
              {info.config.source === 'env' && (
                <span className="chip">
                  defaults {info.config.env_defaults.review} /{' '}
                  {info.config.env_defaults.block}
                </span>
              )}
            </div>
          )}

          <div className="grid grid-4">
            <Stat k="Review at" v={`\u2265 ${info.current.review}`} n="live cut-off" />
            <Stat k="Block at" v={`\u2265 ${info.current.block}`} n="live cut-off" />
            <Stat
              k="Cost-optimal review"
              v={best ? `\u2265 ${best.review}` : '\u2014'}
              n={best ? rupees(best.cost) : 'no curve data'}
            />
            <Stat
              k="Queue at these settings"
              v={liveNow ? `${liveNow.would_review}` : '\u2014'}
              n={
                liveNow
                  ? `${liveNow.would_block} blocked, ${(liveNow.review_share * 100).toFixed(1)}% of ${info.live_sample_size}`
                  : 'not sampled'
              }
            />
          </div>

          <div className="card">
            <h3 className="t-base">Adjust</h3>
            <p className="muted">{info.cost_curve_note}</p>

            <div className="row" style={{ marginTop: 'var(--sp-4)' }}>
              <div className="field">
                <label htmlFor="rt">
                  Review threshold: <span className="num">{review}</span>
                </label>
                <input
                  id="rt"
                  type="range"
                  min={0}
                  max={99}
                  value={review}
                  onChange={(e) => setReview(Number(e.target.value))}
                  disabled={!canEdit}
                />
              </div>
              <div className="field">
                <label htmlFor="bt">
                  Block threshold: <span className="num">{block}</span>
                </label>
                <input
                  id="bt"
                  type="range"
                  min={1}
                  max={100}
                  value={block}
                  onChange={(e) => setBlock(Number(e.target.value))}
                  disabled={!canEdit}
                />
              </div>
            </div>

            {invalid && (
              <div className="note note-bad">Block must be above review.</div>
            )}

            {atCurrent && (
              <div className="grid grid-3" style={{ marginTop: 'var(--sp-3)' }}>
                <div className="stat">
                  <div className="k">Projected cost</div>
                  <div className="v">{rupees(atCurrent.cost)}</div>
                  <div className="n">
                    {best && atCurrent.cost > best.cost
                      ? `${rupees(atCurrent.cost - best.cost)} above optimum`
                      : 'at the optimum'}
                  </div>
                </div>
                <div className="stat">
                  <div className="k">Review volume</div>
                  <div className="v">{(atCurrent.review_volume * 100).toFixed(2)}%</div>
                  <div className="n">
                    {atCurrent.within_capacity ? 'within capacity' : 'EXCEEDS capacity'}
                  </div>
                </div>
                <div className="stat">
                  <div className="k">Legit blocked</div>
                  <div className="v">{atCurrent.legit_blocked}</div>
                  <div className="n">real customers refused</div>
                </div>
              </div>
            )}

            {canEdit ? (
              <div className="stack" style={{ marginTop: 'var(--sp-4)' }}>
                <div>
                  <label className="lbl" htmlFor="threshold-reason">
                    Reason (optional)
                  </label>
                  <input
                    id="threshold-reason"
                    type="text"
                    maxLength={280}
                    value={reason}
                    placeholder="e.g. two analysts on leave this week"
                    onChange={(e) => setReason(e.target.value)}
                  />
                  <p className="muted t-xs">
                    Recorded on the audit event. Never used to decide whether the
                    change is permitted &mdash; the ordering rule is enforced
                    regardless.
                  </p>
                </div>
              <div className="row row-tight">
                <button className="btn" disabled={busy || !dirty || invalid} onClick={save}>
                  {busy ? 'Applying\u2026' : 'Apply thresholds'}
                </button>
                {dirty && (
                  <button
                    className="btn btn-ghost"
                    onClick={() => {
                      setReview(info.current.review)
                      setBlock(info.current.block)
                    }}
                  >
                    Reset
                  </button>
                )}
              </div>
              </div>
            ) : (
              <div className="note" style={{ marginTop: 'var(--sp-4)' }}>
                Read-only. Moving a threshold changes every future decision and the
                merchant&rsquo;s whole false-positive exposure, so it needs the{' '}
                <code>admin</code> role &mdash; an <code>analyst</code> decides individual
                cases.
              </div>
            )}

            <div className="note note-warn" style={{ marginTop: 'var(--sp-3)' }}>
              {info.caveat}
            </div>
          </div>

          {curve.length > 1 && (
            <div className="card">
              <h3 className="t-base">Cost curve</h3>
              <p className="muted">
                Expected cost against the review threshold, at block &ge;{' '}
                {curve[0].block}. Note the flat bottom: being in the right region matters,
                the exact value does not.
              </p>
              <svg
                viewBox={`0 0 ${W} ${H}`}
                width="100%"
                style={{
                  background: 'var(--bg-soft)',
                  border: '1px solid var(--line)',
                  borderRadius: 'var(--r-md)',
                  marginTop: 'var(--sp-3)',
                }}
                role="img"
                aria-label={`Cost curve. Lowest cost is ${rupees(best?.cost ?? 0)} at a review threshold of ${best?.review}. The current setting of ${review} projects ${rupees(atCurrent?.cost ?? 0)}.`}
              >
                <path d={path} fill="none" stroke="var(--accent)" strokeWidth={2} />
                {curve.map((p) => {
                  const costs = curve.map((c) => c.cost)
                  const lo = Math.min(...costs)
                  const hi = Math.max(...costs)
                  const xs = curve.map((c) => c.review)
                  const xlo = Math.min(...xs)
                  const xhi = Math.max(...xs)
                  const x = 30 + ((p.review - xlo) / Math.max(1, xhi - xlo)) * (W - 50)
                  const y = H - 28 - ((p.cost - lo) / Math.max(1, hi - lo)) * (H - 56)
                  const isCur = p.review === review
                  const isBest = best && p.review === best.review
                  return (
                    <g key={p.review}>
                      <circle
                        cx={x}
                        cy={y}
                        r={isCur ? 5 : 3}
                        fill={
                          isCur
                            ? 'var(--text)'
                            : isBest
                              ? 'var(--allow)'
                              : p.within_capacity
                                ? 'var(--accent)'
                                : 'var(--block)'
                        }
                      />
                      {(isCur || isBest) && (
                        <text
                          x={x}
                          y={y - 11}
                          textAnchor="middle"
                          fill="var(--text-dim)"
                          fontSize="10"
                          fontFamily="var(--mono)"
                        >
                          {p.review}
                        </text>
                      )}
                    </g>
                  )
                })}
              </svg>
              <div className="pill-row" style={{ marginTop: 'var(--sp-3)' }}>
                <span className="chip">
                  <span aria-hidden="true" style={{ color: 'var(--text)' }}>
                    ●
                  </span>{' '}
                  current
                </span>
                <span className="chip">
                  <span aria-hidden="true" style={{ color: 'var(--allow)' }}>
                    ●
                  </span>{' '}
                  cost optimum
                </span>
                <span className="chip">
                  <span aria-hidden="true" style={{ color: 'var(--block)' }}>
                    ●
                  </span>{' '}
                  exceeds analyst capacity
                </span>
              </div>
            </div>
          )}

          {canEdit && (
            <div className="card">
              <h3 className="t-base">Change history</h3>
              {!audit.length && (
                <p className="muted">
                  No threshold changes recorded. A change that leaves no trace makes
                  every later &ldquo;why was this blocked?&rdquo; unanswerable, so each one
                  is written to an append-only audit item.
                </p>
              )}
              {!!audit.length && (
                <div className="table-shell" style={{ marginTop: 'var(--sp-3)' }}>
                  <table>
                    <caption className="sr-only">Threshold change audit log</caption>
                    <thead>
                      <tr>
                        <th scope="col">When</th>
                        <th scope="col">Who</th>
                        <th scope="col">From</th>
                        <th scope="col">To</th>
                        <th scope="col">Reason</th>
                      </tr>
                    </thead>
                    <tbody>
                      {audit.map((e, i) => (
                        <tr key={i}>
                          <td className="muted t-2xs">
                            {new Date(e.at).toLocaleString()}
                          </td>
                          <td className="mono t-2xs">{e.actor}</td>
                          <td className="num">
                            {String(e.before.review)} / {String(e.before.block)}
                          </td>
                          <td className="num">
                            {String(e.after.review)} / {String(e.after.block)}
                          </td>
                          <td className="muted t-2xs">
                            {(e.after.reason as string) || '\u2014'}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </>
      )}
    </div>
  )
}
