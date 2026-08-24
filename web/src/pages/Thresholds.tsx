import { useEffect, useMemo, useState } from 'react'
import { api, ApiError, rupees, type AuditEntry, type ThresholdInfo } from '../api'
import { ErrorNote, Stat } from '../components'

const W = 640
const H = 210

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
        await api
          .audit()
          .then((a) => setAudit(a.entries.filter((e) => e.action === 'threshold_update')))
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
      const r = await api.setThresholds(review, block)
      setFlash(
        `Applied: review \u2265 ${r.current.review}, block \u2265 ${r.current.block} ` +
          `(was ${r.previous.review} / ${r.previous.block}). New traffic only.`,
      )
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
              <div className="row row-tight" style={{ marginTop: 'var(--sp-4)' }}>
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
                            {e.before.review} / {e.before.block}
                          </td>
                          <td className="num">
                            {e.after.review} / {e.after.block}
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
