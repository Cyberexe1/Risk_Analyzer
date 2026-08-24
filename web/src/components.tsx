import type { ReactNode } from 'react'
import { band, type Decision, type ReasonCode, type SubScores } from './api'

export function Badge({ decision }: { decision: Decision }) {
  const b = band(decision)
  return (
    <span className={`badge badge-${b.cls}`}>
      <span aria-hidden="true" className="glyph">
        {b.glyph}
      </span>
      {b.label}
    </span>
  )
}

export function Stat({
  k,
  v,
  n,
}: {
  k: string
  v: ReactNode
  n?: string
}) {
  return (
    <div className="stat">
      <div className="k">{k}</div>
      <div className="v">{v}</div>
      {n && <div className="n">{n}</div>}
    </div>
  )
}

export function ScoreDial({
  score,
  decision,
}: {
  score: number
  decision: Decision
}) {
  const b = band(decision)
  return (
    <div className="stack" style={{ gap: 10 }}>
      <div className="spread">
        <div className="score-dial" style={{ color: b.colour }}>
          <span className="big">{Math.round(score)}</span>
          <span className="out-of">/ 100</span>
        </div>
        <Badge decision={decision} />
      </div>
      <div
        className="meter"
        role="meter"
        aria-valuenow={Math.round(score)}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-label={`Risk score ${Math.round(score)} of 100, decision ${b.label}`}
      >
        <span style={{ width: `${score}%`, background: b.colour }} />
      </div>
    </div>
  )
}

/** The three evidence sources, broken out. A single number hides which layer
 *  drove the decision, and that is the first thing an analyst needs. */
export function SubScoreBars({ sub }: { sub: SubScores }) {
  const rows: Array<[string, number, string]> = [
    ['ML model', sub.ml, 'var(--accent)'],
    ['Behavioural rules', sub.rules, 'var(--violet)'],
    ['Network / ring', sub.network, 'var(--cyan)'],
  ]
  return (
    <div className="stack">
      {rows.map(([label, value, colour]) => (
        <div className="sub" key={label}>
          <div className="sub-head">
            <span>{label}</span>
            <b>{Math.round(value)}</b>
          </div>
          <div
            className="meter"
            role="meter"
            aria-valuenow={Math.round(value)}
            aria-valuemin={0}
            aria-valuemax={100}
            aria-label={`${label} score ${Math.round(value)} of 100`}
          >
            <span style={{ width: `${value}%`, background: colour }} />
          </div>
        </div>
      ))}
    </div>
  )
}

export function Reasons({ codes }: { codes: ReasonCode[] }) {
  if (!codes.length) {
    return <p className="muted">No signals fired. Nothing stood out on this transaction.</p>
  }
  return (
    <div className="stack" style={{ gap: 8 }}>
      {codes.map((c, i) => (
        <div className={`reason reason-${c.severity}`} key={`${c.code}-${i}`}>
          <span
            className="glyph"
            aria-hidden="true"
            style={{
              color: c.severity === 'high' ? 'var(--block)' : 'var(--review)',
            }}
          >
            {c.severity === 'high' ? '\u25B2' : '\u25C6'}
          </span>
          <span>
            <span className="sr-only">
              {c.severity === 'high' ? 'High severity: ' : 'Medium severity: '}
            </span>
            {c.detail}
          </span>
          <span className="src">{c.source}</span>
        </div>
      ))}
    </div>
  )
}

export function ErrorNote({ error }: { error: string }) {
  return (
    <div className="note note-warn" role="alert">
      <strong>Backend unreachable.</strong> {error}
    </div>
  )
}
