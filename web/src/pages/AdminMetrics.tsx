import { rupees, type AdminMetrics } from '../api'
import { Stat } from '../components'

const pct = (n: number) => `${(n * 100).toFixed(1)}%`
const f3 = (n: number) => n.toFixed(3)

function Bar({ name, value, max, colour }: { name: string; value: number; max: number; colour: string }) {
  return (
    <div className="hbar">
      <span className="name">{name}</span>
      <span className="meter">
        <span style={{ width: `${Math.max(1, (value / max) * 100)}%`, background: colour }} />
      </span>
      <span className="val">{f3(value)}</span>
    </div>
  )
}

/**
 * Live model performance, read from ml/artifacts/*.json via the backend.
 *
 * Deliberately shows the unflattering figures alongside the good ones. A metrics
 * page that only reports cost reduction trains the operator to trust a system
 * they cannot audit.
 */
export default function AdminMetrics({ m }: { m: AdminMetrics }) {
  if (m.missing.length === 2 || (!m.transaction && !m.promo)) {
    return (
      <div className="note note-warn">
        <strong>No evaluation artifacts.</strong> Run <code>python ml/train.py</code>,{' '}
        <code>python ml/evaluate.py</code> and{' '}
        <code>python ml/evaluate_promo.py --tune</code>.
      </div>
    )
  }

  const t = m.transaction
  const p = m.promo

  return (
    <div className="stack stack-lg">
      {!!m.missing.length && (
        <div className="note note-warn">
          Missing artifact{m.missing.length > 1 ? 's' : ''}: {m.missing.join(', ')}
        </div>
      )}

      {t && (
        <section>
          <h2 className="t-lg">Transaction scorer</h2>
          <p className="muted">
            Held-out test split, {t.test_rows.toLocaleString()} transactions,{' '}
            {t.test_fraud} fraud ({pct(t.test_fraud_rate)}).
          </p>

          <div className="grid grid-4" style={{ marginBottom: 'var(--sp-4)' }}>
            <Stat k="PR-AUC" v={f3(t.ranking.pr_auc)} n="the honest ranking metric" />
            <Stat
              k="ROC-AUC"
              v={f3(t.ranking.roc_auc)}
              n="inflated by the negative class"
            />
            <Stat
              k="Net saving"
              v={rupees(t.cost.net_saving)}
              n={pct(t.cost.net_saving_pct)}
            />
            <Stat
              k="FP cost"
              v={rupees(t.cost.false_positive_cost)}
              n={`${t.cost.legit_blocked} customers blocked`}
            />
          </div>

          <div className="grid grid-2">
            <div className="card">
              <h3 className="t-base">Operating points</h3>
              <div className="table-shell" style={{ marginTop: 'var(--sp-3)' }}>
                <table>
                  <caption className="sr-only">Precision and recall at both gates</caption>
                  <thead>
                    <tr>
                      <th scope="col">Gate</th>
                      <th scope="col">Precision</th>
                      <th scope="col">Recall</th>
                      <th scope="col">Volume</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr>
                      <td>
                        Review <span className="muted">&ge; {t.thresholds.review}</span>
                      </td>
                      <td className="num">{f3(t.review_gate.precision)}</td>
                      <td className="num">{f3(t.review_gate.recall)}</td>
                      <td className="num">{pct(t.review_gate.volume_share)}</td>
                    </tr>
                    <tr>
                      <td>
                        Block <span className="muted">&ge; {t.thresholds.block}</span>
                      </td>
                      <td className="num">{f3(t.block_gate.precision)}</td>
                      <td className="num">{f3(t.block_gate.recall)}</td>
                      <td className="num">{pct(t.block_gate.volume_share)}</td>
                    </tr>
                  </tbody>
                </table>
              </div>
              {t.block_gate.precision >= 0.999 && (
                <div className="note note-warn" style={{ marginTop: 'var(--sp-3)' }}>
                  <strong>Block precision of {f3(t.block_gate.precision)} is a warning,
                  not a win.</strong> Zero false positives on {t.block_gate.tp} blocks
                  means the synthetic data&rsquo;s high-confidence fraud is too cleanly
                  separable. Real traffic will not behave this way.
                </div>
              )}
            </div>

            <div className="card">
              <h3 className="t-base">Confusion at the chosen point</h3>
              <div className="table-shell" style={{ marginTop: 'var(--sp-3)' }}>
                <table>
                  <caption className="sr-only">Confusion matrix</caption>
                  <thead>
                    <tr>
                      <th scope="col"></th>
                      <th scope="col">Block</th>
                      <th scope="col">Review</th>
                      <th scope="col">Allow</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr>
                      <th scope="row">Fraud</th>
                      <td className="num">{t.confusion.tp_block}</td>
                      <td className="num">{t.confusion.tp_review}</td>
                      <td className="num" style={{ color: 'var(--block)' }}>
                        {t.confusion.fn}
                      </td>
                    </tr>
                    <tr>
                      <th scope="row">Legitimate</th>
                      <td className="num" style={{ color: 'var(--block)' }}>
                        {t.confusion.fp_block}
                      </td>
                      <td className="num" style={{ color: 'var(--review)' }}>
                        {t.confusion.fp_review}
                      </td>
                      <td className="num">{t.confusion.tn.toLocaleString()}</td>
                    </tr>
                  </tbody>
                </table>
              </div>
              <p className="muted" style={{ marginTop: 'var(--sp-3)' }}>
                Blocking is{' '}
                {Math.round(
                  (t.cost.unit_costs.block_legit_cost ?? 0) /
                    (t.cost.unit_costs.review_cost ?? 1),
                )}
                &times; more expensive per error than reviewing, which is why most risk
                goes to a human.
              </p>
            </div>
          </div>

          <div className="grid grid-2" style={{ marginTop: 'var(--sp-4)' }}>
            <div className="card">
              <h3 className="t-base">Recall by fraud type</h3>
              <div className="stack" style={{ marginTop: 'var(--sp-3)' }}>
                {Object.entries(t.recall_by_archetype)
                  .sort((a, b) => b[1] - a[1])
                  .map(([k, v]) => (
                    <Bar
                      key={k}
                      name={k.replace(/_/g, ' ')}
                      value={v}
                      max={1}
                      colour={v < 0.5 ? 'var(--block)' : v < 0.8 ? 'var(--review)' : 'var(--allow)'}
                    />
                  ))}
              </div>
              {t.recall_by_archetype.first_party_abuse !== undefined &&
                t.recall_by_archetype.first_party_abuse < 0.05 && (
                  <div className="note note-warn" style={{ marginTop: 'var(--sp-3)' }}>
                    <strong>First-party abuse recall is
                    {' '}{f3(t.recall_by_archetype.first_party_abuse)}.</strong> Those are
                    genuinely normal transactions &mdash; a real customer buying a real
                    product then falsely disputing delivery leaves no payment-time signal.
                    Catching it needs delivery evidence, not better scoring.
                  </div>
                )}
            </div>

            <div className="card">
              <h3 className="t-base">Model vs. baselines</h3>
              <div className="stack" style={{ marginTop: 'var(--sp-3)' }}>
                {Object.entries(t.baselines)
                  .sort((a, b) => b[1].pr_auc - a[1].pr_auc)
                  .map(([k, v]) => (
                    <Bar
                      key={k}
                      name={k.replace(/_/g, ' ')}
                      value={v.pr_auc}
                      max={1}
                      colour={
                        k === 'fraudshield_ensemble'
                          ? 'var(--accent)'
                          : k === 'mvp_hand_picked_formula'
                            ? 'var(--review)'
                            : 'var(--surface-2)'
                      }
                    />
                  ))}
              </div>
              <p className="muted" style={{ marginTop: 'var(--sp-3)' }}>
                Learned weights roughly double the hand-picked formula. The ensemble ranks
                slightly <em>below</em> XGBoost alone &mdash; the rule layer earns its
                place on auditability and cold start, not accuracy.
              </p>
            </div>
          </div>

          <div className="card" style={{ marginTop: 'var(--sp-4)' }}>
            <h3 className="t-base">Review rate by slice</h3>
            <p className="muted">
              No protected attribute is a model input. These are behavioural slices,
              monitored for disparate impact.
            </p>
            <div className="table-shell" style={{ marginTop: 'var(--sp-3)' }}>
              <table>
                <caption className="sr-only">Review and block rate per slice</caption>
                <thead>
                  <tr>
                    <th scope="col">Slice</th>
                    <th scope="col">n</th>
                    <th scope="col">Review</th>
                    <th scope="col">Block</th>
                    <th scope="col">Ratio</th>
                  </tr>
                </thead>
                <tbody>
                  {Object.entries(t.fairness).map(([k, v]) => (
                    <tr key={k}>
                      <td>{k.replace(/_/g, ' ')}</td>
                      <td className="num">{v.n.toLocaleString()}</td>
                      <td className="num">{pct(v.review_rate)}</td>
                      <td className="num">{pct(v.block_rate)}</td>
                      <td
                        className="num"
                        style={{
                          color:
                            v.ratio_vs_overall > 3
                              ? 'var(--block)'
                              : v.ratio_vs_overall > 1.4
                                ? 'var(--review)'
                                : undefined,
                        }}
                      >
                        {v.ratio_vs_overall.toFixed(2)}&times;
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </section>
      )}

      {p && (
        <section>
          <h2 className="t-lg">Promotion abuse gate</h2>
          <p className="muted">
            Scored at redemption, not checkout. {p.rows.test} test redemptions,{' '}
            {pct(p.abuse_rate.test)} abusive.
          </p>
          <div className="grid grid-4" style={{ marginBottom: 'var(--sp-4)' }}>
            <Stat k="Precision" v={f3(p.gate.precision)} n="hold or deny" />
            <Stat k="Recall" v={f3(p.gate.recall)} n="abuse caught" />
            <Stat
              k="Wrongly denied"
              v={p.deny.fp}
              n={`of ${p.deny.n} denials`}
            />
            <Stat k="Net saving" v={rupees(p.cost.net_saving)} n="test split" />
          </div>
          <div className="card">
            <h3 className="t-base">Per-signal precision</h3>
            <div className="stack" style={{ marginTop: 'var(--sp-3)' }}>
              {Object.entries(p.per_rule)
                .filter(([, v]) => v.detections > 0 && v.precision !== null)
                .sort((a, b) => (b[1].precision ?? 0) - (a[1].precision ?? 0))
                .map(([k, v]) => (
                  <Bar
                    key={k}
                    name={`${k.replace(/_/g, ' ')} (${v.detections})`}
                    value={v.precision ?? 0}
                    max={1}
                    colour={v.action === 'DENY' ? 'var(--block)' : 'var(--review)'}
                  />
                ))}
            </div>
          </div>
        </section>
      )}

      {(t?.caveats || p?.caveats) && (
        <section>
          <h2 className="t-lg">Caveats</h2>
          <div className="stack">
            {[...(t?.caveats ?? []), ...(p?.caveats ?? [])].map((c, i) => (
              <div className="note" key={i}>
                {c}
              </div>
            ))}
          </div>
        </section>
      )}
    </div>
  )
}
