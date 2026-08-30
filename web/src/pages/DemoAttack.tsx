import { useEffect, useState } from 'react'
import {
  api,
  ApiError,
  band,
  rupees,
  type DemoAttackResult,
  type DemoStatus,
} from '../api'
import { Badge } from '../components'

/**
 * The demo fraud-attack trigger.
 *
 * Generates eight suspicious payment attempts on one synthetic account, one
 * device and one address, sixty seconds apart, and puts every one of them through
 * the real scoring, persistence, audit and notification pipeline.
 *
 * WHAT THIS COMPONENT DOES NOT DO
 * ------------------------------
 * It never derives a risk score, a decision, or a signal. Every number below was
 * returned by the backend, which got it from `Scorer.score()`. A console that
 * recomputed any of it could disagree with the queue and the audit trail, and an
 * analyst who has seen those disagree once will not trust either again.
 *
 * WHY THE CONTROL CAN BE ABSENT
 * -----------------------------
 * Two server-side gates decide whether the endpoint will run: an explicit demo
 * flag, and the payment provider being the simulator. `/health` reports both, so
 * this renders an explanation rather than a button that could only fail. Hiding
 * the button is presentation; the server check is the control.
 */

/** The stages the single request runs through, in order.
 *
 *  These advance on a timer, exactly like the payment sheet's ticker, because the
 *  server answers one request rather than streaming per-stage events. So the list
 *  is honest about WHAT is being done and deliberately makes no claim about which
 *  step is executing at a given millisecond — which is why the panel also says so.
 */
const STAGES = [
  'Generating eight attempts\u2026',
  'Running the risk engine\u2026',
  'Checking network signals\u2026',
  'Persisting and auditing\u2026',
  'Triggering notification\u2026',
]

type Stage = 'idle' | 'confirm' | 'running' | 'done'

export default function DemoAttack({
  status,
  onGenerated,
}: {
  status?: DemoStatus | null
  onGenerated?: () => void | Promise<void>
}) {
  const [stage, setStage] = useState<Stage>('idle')
  const [step, setStep] = useState(0)
  const [result, setResult] = useState<DemoAttackResult | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (stage !== 'running') return
    const t = setInterval(
      () => setStep((s) => Math.min(s + 1, STAGES.length - 1)),
      450,
    )
    return () => clearInterval(t)
  }, [stage])

  async function run() {
    setStage('running')
    setStep(0)
    setError(null)
    setResult(null)
    try {
      const r = await api.demoFraudAttack()
      setResult(r)
      setStage('done')
      // Pull the queue immediately rather than waiting for the 5-second poll, so
      // the transactions are on screen by the time the operator looks.
      await onGenerated?.()
    } catch (e) {
      // A failure here has generated nothing, so the console goes back to idle
      // rather than showing a half-finished run. The message is the server's:
      // 403 for the flag, 409 for a real gateway.
      setError(e instanceof ApiError ? e.message : String(e))
      setStage('idle')
    }
  }

  // An older backend does not report demo readiness. Absent is treated as "not
  // available", never as "enabled".
  if (!status) return null

  if (!status.enabled) {
    return (
      <span
        className="chip"
        title={
          status.blocked_because.length
            ? `Unavailable: ${status.blocked_because.join('; ')}`
            : undefined
        }
      >
        demo trigger off
      </span>
    )
  }

  return (
    <>
      <button
        className="btn btn-danger btn-sm"
        onClick={() => setStage('confirm')}
        disabled={stage === 'running'}
      >
        {stage === 'running' ? 'Generating\u2026' : 'Trigger demo fraud attack'}
      </button>

      {error && (
        <span className="chip" role="alert">
          {error}
        </span>
      )}

      {(stage === 'confirm' || stage === 'running' || stage === 'done') && (
        <div
          className="pay-backdrop"
          role="presentation"
          onMouseDown={(e) => {
            // Never dismissable mid-flight: closing while the request is in the
            // air would leave the operator unsure whether eight transactions
            // were created.
            if (e.target === e.currentTarget && stage !== 'running') {
              setStage('idle')
            }
          }}
        >
          <div
            className="pay-sheet"
            role="dialog"
            aria-modal="true"
            aria-labelledby="demo-title"
            tabIndex={-1}
          >
            <div className="pay-head">
              <div>
                <div className="eyebrow">Demo mode</div>
                <h2 id="demo-title" className="t-lg" style={{ margin: 0 }}>
                  Synthetic fraud attack
                </h2>
              </div>
              {stage !== 'running' && (
                <button
                  className="btn btn-ghost btn-sm"
                  onClick={() => setStage('idle')}
                >
                  {stage === 'done' ? 'Close' : 'Cancel'}
                </button>
              )}
            </div>

            <div className="pay-body">
              {/* ---------------- confirmation ---------------- */}
              {stage === 'confirm' && (
                <div className="stack">
                  <p>
                    Generate {status.attempts} synthetic suspicious payment attempts?
                  </p>
                  <p className="muted t-sm">
                    One synthetic account, one device and one address, spread over{' '}
                    {Math.round(status.window_seconds / 60)} minutes of backdated
                    timestamps. This runs only in demo mode against the simulated
                    gateway and does not charge real money.
                  </p>
                  <p className="muted t-sm">
                    The attempts are scored by the real engine, so the decision is
                    whatever it decides. They land in the queue and the audit trail
                    marked <code>demo</code>, and they are not cleaned up
                    afterwards &mdash; the point is to investigate them.
                  </p>
                  {/* One affirmative action. Cancel lives in the dialog header,
                      where it already is for the payment sheet, rather than being
                      offered twice. */}
                  <div className="row row-tight">
                    <button className="btn btn-danger btn-sm" onClick={() => void run()}>
                      Generate {status.attempts} attempts
                    </button>
                  </div>
                </div>
              )}

              {/* ---------------- running ---------------- */}
              {stage === 'running' && (
                <div className="pay-processing" role="status" aria-live="polite">
                  <div className="spinner" aria-hidden="true" />
                  <div className="fw-semi">{STAGES[step]}</div>
                  <p className="muted t-sm">
                    One request runs the whole pipeline, so these stages are what
                    it does rather than a live trace of where it is.
                  </p>
                  <div className="pay-steps" aria-hidden="true">
                    {STAGES.map((s, i) => (
                      <span key={s} className={`pay-dot${i <= step ? ' on' : ''}`} />
                    ))}
                  </div>
                </div>
              )}

              {/* ---------------- result ---------------- */}
              {stage === 'done' && result && (
                <div className="stack stack-lg">
                  <div
                    className={`pay-status ${
                      result.final_transaction.decision === 'BLOCK'
                        ? 'pay-status-bad'
                        : result.final_transaction.decision === 'ALLOW'
                          ? 'pay-status-ok'
                          : 'pay-status-review'
                    }`}
                  >
                    <span className="pay-status-glyph" aria-hidden="true">
                      &#9632;
                    </span>
                    <div>
                      <div className="fw-semi">
                        {result.attempts_generated} attempts generated
                      </div>
                      <div className="t-sm">
                        Final risk score{' '}
                        <span
                          className="num"
                          style={{ color: band(result.final_transaction.decision).colour }}
                        >
                          {Math.round(result.final_transaction.risk_score)}
                        </span>{' '}
                        &middot; <Badge decision={result.final_transaction.decision} />
                      </div>
                    </div>
                  </div>

                  <div className="stack" style={{ gap: 'var(--sp-2)' }}>
                    <div className="spread t-sm">
                      <span className="muted">Decisions</span>
                      <span className="mono t-2xs">
                        {Object.entries(result.decisions)
                          .filter(([, n]) => n > 0)
                          .map(([k, n]) => `${k} ${n}`)
                          .join('  ')}
                      </span>
                    </div>
                    <div className="spread t-sm">
                      <span className="muted">Signals</span>
                      <span className="mono t-2xs">
                        {result.signals.length ? result.signals.join(', ') : 'none'}
                      </span>
                    </div>
                    <div className="spread t-sm">
                      <span className="muted">Velocity seen</span>
                      <span className="mono t-2xs">
                        {result.evidence.txn_count_10m ?? '\u2014'} attempts in 10 minutes
                      </span>
                    </div>
                    <div className="spread t-sm">
                      <span className="muted">Email</span>
                      <span className="mono t-2xs">
                        {summariseEmail(result)}
                      </span>
                    </div>
                    <div className="spread t-sm">
                      <span className="muted">Audit</span>
                      <span className="mono t-2xs">
                        {result.audit_created
                          ? `recorded (${result.audit_events} events)`
                          : 'not recorded'}
                      </span>
                    </div>
                    <div className="spread t-sm">
                      <span className="muted">Queue</span>
                      <span className="mono t-2xs">
                        {result.queued_for_review} of {result.attempts_generated} queued
                        &middot; {result.transactions_persisted} persisted
                      </span>
                    </div>
                    {result.ip_flagged && (
                      <div className="spread t-sm">
                        <span className="muted">Address</span>
                        <span className="mono t-2xs">
                          flagged for repeated declines
                        </span>
                      </div>
                    )}
                  </div>

                  <div className="table-shell">
                    <table>
                      <caption className="sr-only">
                        Each generated attempt, with the score the engine returned
                      </caption>
                      <thead>
                        <tr>
                          <th scope="col">#</th>
                          <th scope="col">Amount</th>
                          <th scope="col">10m</th>
                          <th scope="col">Risk</th>
                          <th scope="col">Decision</th>
                        </tr>
                      </thead>
                      <tbody>
                        {result.results.map((r) => (
                          <tr key={r.transaction_id}>
                            <td className="num">{r.attempt}</td>
                            <td className="num">{rupees(r.amount)}</td>
                            <td className="num">{r.txn_count_10m}</td>
                            <td>
                              <span
                                className="num"
                                style={{ color: band(r.decision).colour }}
                              >
                                {Math.round(r.risk_score)}
                              </span>
                            </td>
                            <td>
                              <Badge decision={r.decision} />
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>

                  <p className="muted t-2xs">
                    Customer <code>{result.customer_id}</code> on device{' '}
                    <code>{result.device_id}</code>. Thresholds in force: review{' '}
                    {result.thresholds.review}, block {result.thresholds.block}.{' '}
                    {result.note}
                  </p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </>
  )
}

/** What actually happened to the alert, in the notification system's own terms.
 *
 *  `skipped` is reported as "no recipients", not as a failure: an operator who
 *  configured nobody has not suffered a delivery failure, and calling it one would
 *  bury real failures in noise. Nothing here claims delivery — `sent` means the
 *  provider accepted the message. */
function summariseEmail(r: DemoAttackResult): string {
  const parts = Object.entries(r.notifications)
    .filter(([, n]) => n > 0)
    .map(([k, n]) => `${n} ${k}`)
  const provider = r.email_provider ?? 'unknown'
  if (!parts.length) return `${provider}: nothing alertable`
  if (!r.alerts_enabled) return `${provider}: ${parts.join(', ')} (no recipients)`
  return `${provider}: ${parts.join(', ')}`
}
