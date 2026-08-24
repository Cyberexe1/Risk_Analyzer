import { Link } from 'react-router-dom'

/**
 * Headline figures, mirrored from ml/artifacts/metrics.json.
 *
 * The landing page is public, so it cannot call the staff-only metrics endpoint.
 * These are kept in ONE object rather than scattered through the copy, so a
 * retrain means editing one block — and the admin console reads the live artifact
 * for anyone who needs the authoritative numbers.
 */
const M = {
  thresholds: { review: 5, block: 70 },
  prAuc: 0.788,
  review: { precision: 0.37, recall: 0.789, volume: 0.0489 },
  block: { precision: 1.0, recall: 0.553, volume: 0.0127 },
  cost: { saved: 939600, pct: 0.774, fp: 16065 },
  latencyMs: 25,
  ensembleVsXgb: { ensemble: 0.788, xgbOnly: 0.8 },
  promo: { precision: 0.962, wronglyDenied: 0, saved: 12150 },
}

const f3 = (n: number) => n.toFixed(3)
const pct = (n: number) => `${(n * 100).toFixed(1)}%`
const lakh = (n: number) => `\u20B9${(n / 100000).toFixed(2)} lakh`

/** Hero metric tile. label-caps key over a monospaced figure, centred, hairline
 *  bordered — the Stitch "Editorial Ledger" summary card. */
function Metric({ k, v }: { k: string; v: string }) {
  return (
    <div className="stat stat-centered">
      <div className="k">{k}</div>
      <div className="v">{v}</div>
    </div>
  )
}

/**
 * Landing page.
 *
 * Every metric here is the measured value from ml/artifacts/metrics.json. The
 * unflattering ones are on the page too, deliberately — a landing page that
 * only shows 77% cost reduction and hides 0.370 review precision is marketing,
 * not evidence.
 */
export default function Landing() {
  return (
    <>
      {/* ---------------- hero ---------------- */}
      <section className="wrap section">
        <div className="hero">
          <span className="badge badge-outline">Defense only</span>

          <h1 className="hero-title">
            Stop losing money to fraud without punishing real customers.
          </h1>

          <p className="hero-lead">
            FraudShield scores every ledger entry 0&ndash;100, explains exactly why, and
            routes it to allow, review or block. Deterministic graphs and a calibrated
            model, not black-box assumptions &mdash; and never a claim that
            &ldquo;this is fraud,&rdquo; only that this deserves attention, and here is the
            evidence.
          </p>

          <div className="row" style={{ marginTop: 'var(--sp-4)' }}>
            <Link to="/checkout" className="btn">
              Try a checkout
            </Link>
            <Link to="/admin" className="btn btn-ghost">
              Open analyst console
            </Link>
          </div>

          {/* Metrics row */}
          <div className="grid grid-4" style={{ marginTop: 'var(--sp-12)', width: '100%' }}>
            <Metric k="PR-AUC" v={f3(M.prAuc)} />
            <Metric k="Recall" v={f3(M.review.recall)} />
            <Metric k="Cost reduction" v={pct(M.cost.pct)} />
            <Metric k="Latency" v={`~${M.latencyMs}ms`} />
          </div>
          <p className="muted" style={{ marginTop: 'var(--sp-4)' }}>
            Held-out test split, cut by time. Recall is measured at the review gate;
            cost reduction is {lakh(M.cost.saved)} saved across 14,913 transactions;
            latency is p50 for a single transaction.
          </p>
        </div>
      </section>

      {/* ---------------- two problems ---------------- */}
      <section className="wrap section-sm">
        <h2 className="section-title">Two problems, not one</h2>

        <div className="grid grid-2">
          <div className="card">
            <div className="problem-head">
              <span className="glyph" aria-hidden="true" style={{ color: 'var(--block)' }}>
                {'\u25B2'}
              </span>
              <h3>The Leaks</h3>
            </div>
            <ul className="problem-list">
              <li>Stolen card utilisation</li>
              <li>Escalating chargeback fees</li>
              <li>Systematic bonus abuse</li>
            </ul>
            <p className="muted" style={{ marginTop: 'var(--sp-4)' }}>
              A stolen card takes a &#8377;20,000 product, the payment succeeds, and weeks
              later the real cardholder disputes it. You lose the goods, the shipping and
              a &#8377;750 fee. Or one person opens five accounts on one device and claims
              a &#8377;500 welcome bonus five times &mdash; each account looks fine alone.
            </p>
          </div>

          <div className="card">
            <div className="problem-head">
              <span className="glyph" aria-hidden="true" style={{ color: 'var(--review-ink)' }}>
                {'\u2298'}
              </span>
              <h3>The Blockade</h3>
            </div>
            <ul className="problem-list">
              <li>Real customers wrongly blocked</li>
              <li>High friction during checkout</li>
              <li>Lost lifetime value (LTV)</li>
            </ul>
            <p className="muted" style={{ marginTop: 'var(--sp-4)' }}>
              Flag 20% of traffic to catch everything and you destroy more value than the
              fraud did. Blocking a real customer costs roughly &#8377;1,438 in lost margin
              and churn. A human review costs &#8377;35.
            </p>
          </div>
        </div>

        <p className="pullquote">
          &ldquo;Blocking a legitimate customer is approximately 41&times; more expensive
          than manually reviewing a borderline transaction.&rdquo;
        </p>
        <p className="muted center" style={{ marginTop: 'var(--sp-4)' }}>
          That single ratio drives the whole design.
        </p>
      </section>

      {/* ---------------- how it scores ---------------- */}
      <section className="wrap section-sm">
        <h2 className="section-title">Three evidence sources, not one magic number</h2>
        <p className="hero-lead center" style={{ marginBottom: 'var(--sp-8)' }}>
          An earlier version added hand-picked points: +25 velocity, +20 device, +18
          amount. It demos well and collapses the moment someone asks why velocity is
          worth 25. So the weights are learned instead.
        </p>

        <div className="grid grid-3">
          <div className="card">
            <span className="badge badge-neutral">70% weight</span>
            <h3 style={{ marginTop: 'var(--sp-4)' }}>XGBoost</h3>
            <p style={{ marginBottom: 0 }}>
              22 engineered features, calibrated so a 0.30 really means 30%. Learns what
              each signal is worth from labelled data.
            </p>
          </div>
          <div className="card">
            <span className="badge badge-neutral">20% weight</span>
            <h3 style={{ marginTop: 'var(--sp-4)' }}>Deterministic rules</h3>
            <p style={{ marginBottom: 0 }}>
              Eight thresholds, capped and grouped so correlated rules cannot
              double-count. Auditable, and they work on day zero with no labels.
            </p>
          </div>
          <div className="card">
            <span className="badge badge-neutral">10% weight</span>
            <h3 style={{ marginTop: 'var(--sp-4)' }}>Entity graph</h3>
            <p style={{ marginBottom: 0 }}>
              Accounts sharing devices, IPs and payout destinations. One account looks
              fine; the ring does not.
            </p>
          </div>
        </div>
      </section>

      {/* ---------------- honest metrics ---------------- */}
      <section className="wrap section-sm">
        <h2 className="section-title">The numbers we would rather not show you</h2>
        <p className="hero-lead center" style={{ marginBottom: 'var(--sp-8)' }}>
          Measured on a held-out test split, cut by time so no future data leaks into the
          past. Reporting only the flattering half would be dishonest.
        </p>

        <div className="table-shell">
          <table>
            <caption className="sr-only">
              Measured performance at both decision gates
            </caption>
            <thead>
              <tr>
                <th scope="col">Gate</th>
                <th scope="col" className="num">
                  Precision
                </th>
                <th scope="col" className="num">
                  Recall
                </th>
                <th scope="col" className="num">
                  Volume
                </th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>
                  Manual review{' '}
                  <span className="muted">(&ge; {M.thresholds.review})</span>
                </td>
                <td className="num">{f3(M.review.precision)}</td>
                <td className="num">{f3(M.review.recall)}</td>
                <td className="num">{pct(M.review.volume)}</td>
              </tr>
              <tr>
                <td>
                  Block <span className="muted">(&ge; {M.thresholds.block})</span>
                </td>
                <td className="num">{f3(M.block.precision)}</td>
                <td className="num">{f3(M.block.recall)}</td>
                <td className="num">{pct(M.block.volume)}</td>
              </tr>
            </tbody>
          </table>
        </div>

        <div className="grid grid-2" style={{ marginTop: 'var(--sp-5)' }}>
          <div className="note note-warn">
            <strong>
              Block precision of {f3(M.block.precision)} is a warning, not a win.
            </strong>{' '}
            Zero false positives on 189 blocks means our synthetic data&rsquo;s
            high-confidence fraud is too cleanly separable. Real traffic will not behave
            this way.
          </div>
          <div className="note note-warn">
            <strong>The ensemble ranks worse than XGBoost alone</strong> &mdash;{' '}
            {f3(M.ensembleVsXgb.ensemble)} vs {f3(M.ensembleVsXgb.xgbOnly)} PR-AUC. The
            rule layer drags legitimate rows into review. It earns its place on
            auditability and cold start, not accuracy.
          </div>
          <div className="note note-warn">
            <strong>First-party abuse recall is 0.000.</strong> A real customer buying a
            real product then lying about delivery leaves no payment-time signal. That plus
            refund abuse is 70 of our 72 missed frauds.
          </div>
          <div className="note">
            <strong>The review threshold is set by analyst headcount</strong>, not model
            quality. At 100:1 cost asymmetry the optimiser always wants to review more, so
            it pins itself against whatever queue ceiling you give it.
          </div>
        </div>

        <p className="muted center" style={{ marginTop: 'var(--sp-5)' }}>
          All figures from synthetic data we generated ourselves. Production performance
          will be worse.
        </p>
      </section>

      {/* ---------------- scope ---------------- */}
      <section className="wrap section-sm">
        <div className="card card-lift">
          <h2 className="t-lg serif" style={{ marginBottom: 'var(--sp-4)' }}>
            Scope: defense only
          </h2>
          <p>
            FraudShield detects, explains and routes. It cannot generate fraudulent
            transactions, probe or enumerate payment credentials, evade third-party fraud
            controls, or profile users on protected attributes.
          </p>
          <p style={{ marginBottom: 0 }}>
            The synthetic data generator writes labelled rows into a local table. It has no
            network egress and no path to a payment processor.
          </p>
        </div>
      </section>
    </>
  )
}
