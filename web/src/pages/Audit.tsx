import { useCallback, useEffect, useState } from 'react'
import {
  api,
  ApiError,
  AUDIT_ACTIONS,
  auditActionLabel,
  auditKind,
  auditKindLabel,
  auditActorRole,
  auditGroundTruth,
  type ActionPolicy,
  type AuditEntry,
  type AuditLog,
  type NotificationLog,
} from '../api'
import { ErrorNote, Stat } from '../components'

/**
 * The audit trail, readable.
 *
 * WHY THIS TAB EXISTS
 * -------------------
 * Every event type was already recorded and already retrievable through
 * GET /v1/admin/audit, but only through the API — the console showed nothing but
 * threshold history. An audit trail nobody can read is a compliance artefact, not
 * an accountability one.
 *
 * THE DISTINCTION THIS VIEW MUST NEVER BLUR
 * -----------------------------------------
 *     AUTOMATED ACTION   actor system:scorer   the machine routed a payment
 *     HUMAN OUTCOME      actor an email        a person recorded ground truth
 *
 * A reader who confuses those two will believe the model confirmed fraud. It never
 * does. So the classification is derived from the ACTOR rather than the action
 * name, it is shown as text and a glyph rather than colour alone, and the counts
 * at the top are split by kind.
 *
 * Deliberately small: one filter, one table, one expandable detail. No charts, no
 * date pickers, no export. The backend already reads a single day's partition, and
 * pretending otherwise in the UI would misrepresent what is retrievable.
 */
/** Page size for the console. Well under the API's 200 cap: an analyst reads a
 *  screenful, and a smaller page keeps each request cheap on a busy partition. */
const PAGE = 50

/** Today in UTC, which is the partition key's timezone. Using the browser's local
 *  date would put an analyst in UTC+13 on the wrong partition after 11am. */
const TODAY = new Date().toISOString().slice(0, 10)

export default function Audit() {
  const [entries, setEntries] = useState<AuditEntry[]>([])
  const [filter, setFilter] = useState<string>('')
  const [policy, setPolicy] = useState<ActionPolicy | null>(null)
  const [notif, setNotif] = useState<NotificationLog | null>(null)
  const [log, setLog] = useState<AuditLog | null>(null)
  // `from` doubles as the single-date selector and the range start.
  const [from, setFrom] = useState(TODAY)
  const [to, setTo] = useState(TODAY)
  const [range, setRange] = useState(false)
  // The cursor trail. Keyset pagination has no page numbers to compute from.
  const [cursors, setCursors] = useState<string[]>([])
  const [open, setOpen] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  const load = useCallback(async () => {
    try {
      const a = await api.audit({
        action: filter || undefined,
        limit: PAGE,
        ...(range ? { startDate: from, endDate: to } : { date: from }),
      })
      setEntries(a.entries)
      setLog(a)
      setCursors([])
      // Alert delivery is fetched alongside, not in a separate tab: an analyst
      // asking "was I told about this?" is asking about the same events.
      // Tolerated separately, because a missing notification endpoint must not
      // blank out the audit trail.
      setNotif(await api.notifications(undefined, undefined, 200).catch(() => null))
      setError(null)
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e))
    } finally {
      setLoading(false)
    }
  }, [filter, range, from, to])

  useEffect(() => {
    void load()
  }, [load])

  /** Fetch the next page and push the current cursor so Back can return to it.
   *  Keyset pagination has no page numbers, so the trail of cursors IS the
   *  history — there is no arithmetic that can reconstruct a previous page. */
  const step = useCallback(
    async (cursor: string | null, push: string | null) => {
      setLoading(true)
      try {
        const a = await api.audit({
          action: filter || undefined,
          limit: PAGE,
          cursor: cursor ?? undefined,
          ...(range ? { startDate: from, endDate: to } : { date: from }),
        })
        setEntries(a.entries)
        setLog(a)
        setCursors((prev) =>
          push === null ? prev.slice(0, -1) : [...prev, push],
        )
        setOpen(null)
        setError(null)
      } catch (e) {
        setError(e instanceof ApiError ? e.message : String(e))
      } finally {
        setLoading(false)
      }
    },
    [filter, range, from, to],
  )

  // The policy is static per deployment, so it is fetched once rather than polled.
  // Analyst-readable, and it answers "what is the machine allowed to do?" right
  // next to the record of what it did.
  useEffect(() => {
    api
      .policy()
      .then(setPolicy)
      .catch(() => setPolicy(null))
  }, [])

  const counts = entries.reduce(
    (acc, e) => {
      acc[auditKind(e)] += 1
      return acc
    },
    { automated: 0, human: 0, communication: 0, system: 0 } as Record<
      string,
      number
    >,
  )

  return (
    <div className="stack stack-lg">
      {error && <ErrorNote error={error} />}

      {/* Completeness, before anything else on the page.
          An audit trail that cannot tell you it is incomplete is not an audit
          trail, so this is an alert rather than a footnote. */}
      {log && !log.complete && (
        <div className="note note-warn" role="alert">
          <strong>This audit view may be incomplete.</strong> {log.warning}
        </div>
      )}

      <div className="grid grid-4">
        <Stat
          k="Automated"
          v={counts.automated}
          n="routing decisions, no labels"
        />
        <Stat k="Human" v={counts.human} n="the only ground truth" />
        <Stat
          k="Communication"
          v={counts.communication}
          n="alerts; changed nothing"
        />
        <Stat k="System" v={counts.system} n="state transitions" />
      </div>

      <div className="pill-row">
        <span className="chip" title={log?.note}>
          {entries.length} shown{log?.has_more ? ', more available' : ''}
        </span>
        <span className="chip">
          {range ? `${from} \u2192 ${to}` : from} UTC
        </span>
        {!!log?.days_read?.length && log.days_read.length > 1 && (
          <span className="chip">{log.days_read.length} days read</span>
        )}
        <span
          className={`chip${log && !log.complete ? ' chip-human' : ''}`}
          title={log?.warning ?? 'durable read succeeded'}
        >
          source:{' '}
          {log?.source === 'persistent'
            ? 'persistent'
            : log?.source === 'empty'
              ? 'no events today'
              : 'memory fallback'}
        </span>
        {log?.day && <span className="chip">UTC day {log.day}</span>}
      </div>

      {/* Analyst alerting status. Small on purpose: mode, health and two counts.
          The delivery detail lives in the audit rows below, which is where the
          NOTIFICATION_SENT / NOTIFICATION_FAILED events already are. */}
      {notif && (
        <div className="card">
          <div className="spread">
            <h3 className="t-base">Analyst alerts</h3>
            <div className="row row-tight">
              <span className="chip" title={notif.email.note}>
                {notif.email.provider === 'smtp'
                  ? 'SMTP'
                  : 'console (rendered, not emailed)'}
                {notif.email.degraded ? ' \u2014 degraded' : ''}
              </span>
              <span className="chip">
                {notif.email.alerts_enabled
                  ? `${notif.email.recipient_count} recipient${
                      notif.email.recipient_count === 1 ? '' : 's'
                    }`
                  : 'no recipients configured'}
              </span>
            </div>
          </div>

          <div className="grid grid-4" style={{ marginTop: 'var(--sp-3)' }}>
            <Stat k="Alerts sent" v={notif.counts.sent} n="delivery attempted" />
            <Stat
              k="Alerts failed"
              v={notif.counts.failed}
              n={notif.counts.failed ? 'investigate below' : 'none'}
            />
            <Stat
              k="Not sent"
              v={notif.counts.skipped}
              n="no recipients configured"
            />
            <Stat
              k="Last alert"
              v={notif.items[0]?.status ?? '\u2014'}
              n={notif.items[0]?.event_type ?? 'nothing yet'}
            />
          </div>

          {notif.email.degraded && (
            <div className="note note-warn" style={{ marginTop: 'var(--sp-3)' }} role="alert">
              <strong>Email alerting is degraded.</strong> {notif.email.note}
            </div>
          )}
          {!notif.email.alerts_enabled && !notif.email.degraded && (
            <div className="note" style={{ marginTop: 'var(--sp-3)' }}>
              Alerts are being rendered but delivered to nobody. Set{' '}
              <code>FRAUDSHIELD_ALERT_RECIPIENTS</code> to staff addresses to
              receive them.
            </div>
          )}
          {!!notif.counts.failed && (
            <div className="note note-warn" style={{ marginTop: 'var(--sp-3)' }}>
              <strong>
                {notif.counts.failed} alert
                {notif.counts.failed === 1 ? '' : 's'} could not be delivered.
              </strong>{' '}
              The risk decisions themselves are unaffected &mdash; they were scored,
              queued and audited normally. Only the notification failed.
            </div>
          )}
          <p className="muted t-xs" style={{ marginTop: 'var(--sp-2)' }}>
            {notif.note} FraudShield never emails customers about risk decisions.
          </p>
        </div>
      )}

      <div className="note">
        <strong>Automated actions and human outcomes are different kinds of
        fact.</strong>{' '}
        A <code>RISK_DECISION</code> records that the engine routed a payment; it is
        never a finding of fraud. Ground truth exists only where the actor is a
        person &mdash; <code>OUTCOME_RECORDED</code> and{' '}
        <code>PROMO_OVERRIDE</code>. Neither rewrites the other: the machine
        decision and the human verdict are kept as independent facts.
      </div>

      {/* Date selection. Audit history is partitioned by UTC date, so this is a
          partition selector rather than a filter — which is why it sits apart
          from the event-type pills below. */}
      <div className="card">
        <div className="row row-tight" style={{ flexWrap: 'wrap' }}>
          <div>
            <label className="lbl" htmlFor="audit-from">
              {range ? 'From (UTC)' : 'Date (UTC)'}
            </label>
            <input
              id="audit-from"
              type="date"
              value={from}
              max={TODAY}
              onChange={(e) => setFrom(e.target.value || TODAY)}
            />
          </div>
          {range && (
            <div>
              <label className="lbl" htmlFor="audit-to">
                To (UTC)
              </label>
              <input
                id="audit-to"
                type="date"
                value={to}
                max={TODAY}
                onChange={(e) => setTo(e.target.value || TODAY)}
              />
            </div>
          )}
          <button
            type="button"
            className={`chip chip-btn${range ? ' chip-on' : ''}`}
            aria-pressed={range}
            onClick={() => {
              setRange(!range)
              if (!range) setTo(from)
            }}
          >
            date range
          </button>
          <button
            type="button"
            className="btn btn-ghost btn-sm"
            onClick={() => {
              setFrom(TODAY)
              setTo(TODAY)
              setRange(false)
            }}
          >
            Today
          </button>
          <button
            type="button"
            className="btn btn-ghost btn-sm"
            onClick={() => {
              const y = new Date(Date.now() - 86400000)
                .toISOString()
                .slice(0, 10)
              setFrom(y)
              setTo(y)
              setRange(false)
            }}
          >
            Yesterday
          </button>
        </div>
        <p className="muted t-xs" style={{ marginTop: 'var(--sp-2)' }}>
          Audit history is partitioned by UTC date. A range is read one day at a
          time, newest first, and is capped per request &mdash; it is never a table
          scan.
        </p>
      </div>

      <div className="pill-row" role="group" aria-label="Filter by event type">
        <button
          type="button"
          className={`chip chip-btn${filter === '' ? ' chip-on' : ''}`}
          aria-pressed={filter === ''}
          onClick={() => setFilter('')}
        >
          All events
        </button>
        {AUDIT_ACTIONS.map((a) => (
          <button
            key={a.action}
            type="button"
            className={`chip chip-btn${filter === a.action ? ' chip-on' : ''}`}
            aria-pressed={filter === a.action}
            onClick={() => setFilter(a.action)}
          >
            {a.label}
          </button>
        ))}
      </div>

      {loading && <p className="muted">Loading audit events&hellip;</p>}

      {!loading && !entries.length && (
        <div className="note">
          No audit events
          {filter ? ` of type ${auditActionLabel(filter)}` : ''}
          {range ? ` between ${from} and ${to}` : ` on ${from}`} (UTC).
          {log?.days_failed?.length
            ? ' Some dates could not be read \u2014 see the warning above.'
            : ' Every event is persisted; try another date.'}
        </div>
      )}

      {!!entries.length && (
        <div className="table-shell">
          <table>
            <caption className="sr-only">
              Audit events, newest first, with automated actions and human outcomes
              distinguished
            </caption>
            <thead>
              <tr>
                <th scope="col">Kind</th>
                <th scope="col">Time (UTC)</th>
                <th scope="col">Event</th>
                <th scope="col">Actor</th>
                <th scope="col">Role</th>
                <th scope="col">Target</th>
                <th scope="col">Outcome</th>
                <th scope="col">Ground truth</th>
                <th scope="col"></th>
              </tr>
            </thead>
            <tbody>
              {entries.map((e, i) => {
                const kind = auditKind(e)
                const k = auditKindLabel(kind)
                const gt = auditGroundTruth(e)
                const id = e.event_id ?? `${e.at}-${i}`
                const subject =
                  (e.before.transaction_id as string) ??
                  (e.before.redemption_id as string) ??
                  (e.before.payment_id as string) ??
                  (e.before.ip_hash as string) ??
                  '\u2014'
                const outcome =
                  (e.after.decision as string) ??
                  (e.after.human_outcome as string) ??
                  (e.after.label as string) ??
                  (typeof e.after.review === 'number'
                    ? `review \u2265 ${e.after.review}, block \u2265 ${e.after.block}`
                    : undefined) ??
                  (e.after.state as string) ??
                  '\u2014'
                return (
                  <tr key={id}>
                    <td>
                      <span className={`chip ${k.cls}`} title={k.label}>
                        <span aria-hidden="true">{k.glyph}</span> {k.label}
                      </span>
                    </td>
                    <td className="mono t-xs">{e.at.slice(11, 19)}</td>
                    <td>
                      {auditActionLabel(e.action)}
                      <span className="muted mono t-xs" style={{ display: 'block' }}>
                        {e.action}
                      </span>
                    </td>
                    {/* Actor is the load-bearing column: it is what makes the kind
                        verifiable rather than asserted. */}
                    <td className="mono t-xs">{e.actor}</td>
                    {/* Role at the time of the action, from the authenticated
                        token. An em dash for machine actors, which have none —
                        rather than a blank, which reads as missing data. */}
                    <td className="mono t-xs">
                      {auditActorRole(e) ?? '\u2014'}
                    </td>
                    <td className="mono t-xs">{String(subject).slice(0, 22)}</td>
                    <td>{String(outcome)}</td>
                    {/* Read from the event, never inferred from the category.
                        `n/a` where the event states neither: a threshold change is
                        an authorised human action that is deliberately not ground
                        truth, and "false" there would imply it was evaluated and
                        rejected. */}
                    <td>
                      {gt === true ? (
                        <span className="chip chip-human">yes</span>
                      ) : gt === false ? (
                        <span className="chip">no</span>
                      ) : (
                        <span className="muted t-xs">n/a</span>
                      )}
                    </td>
                    <td>
                      <button
                        type="button"
                        className="btn btn-ghost btn-sm"
                        aria-expanded={open === id}
                        onClick={() => setOpen(open === id ? null : id)}
                      >
                        {open === id ? 'Hide' : 'Detail'}
                      </button>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Pager. Next follows the opaque cursor; Back pops the trail, because
          keyset pagination has no page number to subtract from. */}
      {!!entries.length && (log?.has_more || cursors.length > 0) && (
        <div className="row row-tight">
          <button
            type="button"
            className="btn btn-ghost btn-sm"
            disabled={loading || cursors.length === 0}
            onClick={() =>
              void step(cursors[cursors.length - 2] ?? null, null)
            }
          >
            &larr; Newer
          </button>
          <button
            type="button"
            className="btn btn-ghost btn-sm"
            disabled={loading || !log?.has_more}
            onClick={() => void step(log?.next_cursor ?? null, log?.next_cursor ?? null)}
          >
            Older &rarr;
          </button>
          <span className="muted t-xs">
            page {cursors.length + 1}
            {log?.has_more ? '' : ' (last)'} &middot; {entries.length} shown
          </span>
        </div>
      )}

      {open &&
        (() => {
          const e = entries.find(
            (x, i) => (x.event_id ?? `${x.at}-${i}`) === open,
          )
          if (!e) return null
          const kind = auditKind(e)
          return (
            <div className="card">
              <div className="spread">
                <h3 className="t-base">{auditActionLabel(e.action)}</h3>
                <span className={`chip ${auditKindLabel(kind).cls}`}>
                  {auditKindLabel(kind).label}
                </span>
              </div>
              <p className="muted t-sm">
                {e.at} &middot; actor <code>{e.actor}</code>
                {e.actor_identity && (
                  <>
                    {' '}
                    &middot; role <code>{e.actor_identity.role}</code> &middot;
                    account <code>{e.actor_identity.user_id}</code>
                  </>
                )}
                {e.event_id && (
                  <>
                    {' '}
                    &middot; event <code>{e.event_id}</code>
                  </>
                )}
              </p>
              {/* before/after verbatim. Six event types share this partition and
                  rendering each with a bespoke layout would mean six places for the
                  audit view to drift from what was actually recorded. */}
              <div className="grid grid-2" style={{ marginTop: 'var(--sp-3)' }}>
                <div>
                  <h4 className="t-sm">Before</h4>
                  <pre className="code-block t-xs">
                    {JSON.stringify(e.before, null, 2)}
                  </pre>
                </div>
                <div>
                  <h4 className="t-sm">After</h4>
                  <pre className="code-block t-xs">
                    {JSON.stringify(e.after, null, 2)}
                  </pre>
                </div>
              </div>
            </div>
          )
        })()}

      {policy && (
        <div className="card">
          <div className="spread">
            <h3 className="t-base">What the automation may do</h3>
            <span className="chip">{policy.policy_version}</span>
          </div>
          <p className="muted t-sm" style={{ marginTop: 'var(--sp-2)' }}>
            {policy.note}
          </p>

          <div className="table-shell" style={{ marginTop: 'var(--sp-3)' }}>
            <table>
              <caption className="sr-only">
                Permitted automated action for each decision band
              </caption>
              <thead>
                <tr>
                  <th scope="col">Decision</th>
                  <th scope="col">Automated action</th>
                  <th scope="col">Because</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(policy.decisions).map(([band, spec]) => (
                  <tr key={band}>
                    <td className="mono t-xs">{band}</td>
                    <td className="mono t-xs">{spec.automated_action}</td>
                    <td className="muted t-xs">{spec.reason}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <h4 className="t-sm" style={{ marginTop: 'var(--sp-4)' }}>
            Never done automatically
          </h4>
          <ul className="muted t-sm">
            {policy.never_automated.map((n) => (
              <li key={n}>{n}</li>
            ))}
          </ul>
          <p className="muted t-xs">
            Ground truth source: {policy.ground_truth_source}
          </p>
        </div>
      )}
    </div>
  )
}
