import { Link } from 'react-router-dom'
import { Stat } from '../components'

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
      <section style={{ position: 'relative', overflow: 'hidden' }}>
        <div className="hero-glow" aria-hidden="true" />
        <div className="wrap section" style={{ position: 'relative' }}>
          <span className="badge badge-neutral" style={{ marginBottom: 20 }}>
            Defense only
          </span>
          <h1 style={{ maxWidth: 780 }}>
            Stop losing money to fraud without punishing real customers.
          </h1>
          <p style={{ fontSize: 18, maxWidth: 640 }}>
            FraudShield scores every payment 0&ndash;100, explains exactly why, and routes it
            to allow, review or block. It never claims &ldquo;this is fraud&rdquo; &mdash; it
            claims &ldquo;this deserves attention, and here is the evidence.&rdquo;
          </p>
          <div className="row" style={{ maxWidth: 420, marginTop: 28 }}>
            <Link to="/checkout" className="btn" style={{ flex: '0 0 auto' }}>
              Try a checkout
            </Link>
            <Link to="/admin" className="btn btn-ghost" style={{ flex: '0 0 auto' }}>
              Open analyst console
            </Link>
          </div>

          <div className="grid grid-4" style={{ marginTop: 56 }}>
            <Stat k="PR-AUC" v="0.788" n="held-out test split" />
            <Stat k="Recall" v="0.789" n="at the review gate" />
            <Stat k="Cost reduction" v="77.4%" n="Rs 9.4L saved on 14,913 txns" />
            <Stat k="Latency" v="~25 ms" n="p50, single transaction" />
          </div>
        </div>
      </section>

      {/* ---------------- the problem ---------------- */}
      <section className="wrap section-sm">
        <h2>Two problems, not one</h2>
        <div className="grid grid-2" style={{ marginTop: 24 }}>
          <div className="card">
            <h3>Fraud gets through</h3>
            <p>
              A stolen card buys a &#8377;20,000 product. The payment succeeds, you ship,
              and weeks later the real cardholder disputes it. You lose the goods, the
              shipping, and a &#8377;750 chargeback fee.
            </p>
            <p style={{ marginBottom: 0 }}>
              Or one person opens five accounts on one device and claims a
              &#8377;500 welcome bonus five times. Each account looks fine alone.
            </p>
          </div>
          <div className="card">
            <h3>Or the detector overreacts</h3>
            <p>
              Flag 20% of traffic to catch everything and you destroy more value than the
              fraud did. Blocking a real customer costs roughly &#8377;1,438 in lost margin
              and churn. A human review costs &#8377;35.
            </p>
            <p style={{ marginBottom: 0 }}>
              <strong style={{ color: 'var(--text)' }}>
                Blocking is ~41&times; more expensive per mistake than reviewing.
              </strong>{' '}
              That single ratio drives the whole design.
            </p>
          </div>
        </div>
      </section>

      {/* ---------------- how it scores ---------------- */}
      <section className="wrap section-sm">
        <h2>Three evidence sources, not one magic number</h2>
        <p style={{ maxWidth: 680 }}>
          An earlier version added hand-picked points: +25 velocity, +20 device, +18
          amount. It demos well and collapses the moment someone asks why velocity is
          worth 25. So the weights are learned instead.
        </p>
        <div className="grid grid-3" style={{ marginTop: 24 }}>
          <div className="card">
            <div className="badge badge-neutral" style={{ marginBottom: 12 }}>
              70% weight
            </div>
            <h3>XGBoost</h3>
            <p style={{ marginBottom: 0 }}>
              22 engineered features, calibrated so a 0.30 really means 30%. Learns what
              each signal is worth from labelled data.
            </p>
          </div>
          <div className="card">
            <div className="badge badge-neutral" style={{ marginBottom: 12 }}>
              20% weight
            </div>
            <h3>Deterministic rules</h3>
            <p style={{ marginBottom: 0 }}>
              Eight thresholds, capped and grouped so correlated rules cannot
              double-count. Auditable, and they work on day zero with no labels.
            </p>
          </div>
          <div className="card">
            <div className="badge badge-neutral" style={{ marginBottom: 12 }}>
              10% weight
            </div>
            <h3>Entity graph</h3>
            <p style={{ marginBottom: 0 }}>
              Accounts sharing devices, IPs and payout destinations. One account looks
              fine; the ring does not.
            </p>
          </div>
        </div>
      </section>

      {/* ---------------- honest metrics ---------------- */}
      <section className="wrap section-sm">
        <h2>The numbers we would rather not show you</h2>
        <p style={{ maxWidth: 680 }}>
          Measured on a held-out test split, cut by time so no future data leaks into the
          past. Reporting only the flattering half would be dishonest.
        </p>

        <div className="table-shell" style={{ marginTop: 20 }}>
          <table>
            <caption className="sr-only">
              Measured performance at both decision gates
            </caption>
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
                  Manual review <span className="muted">(&ge; 5)</span>
                </td>
                <td className="mono">0.370</td>
                <td className="mono">0.789</td>
                <td className="mono">4.89%</td>
              </tr>
              <tr>
                <td>
                  Block <span className="muted">(&ge; 70)</span>
                </td>
                <td className="mono">1.000</td>
                <td className="mono">0.553</td>
                <td className="mono">1.27%</td>
              </tr>
            </tbody>
          </table>
        </div>

        <div className="grid grid-2" style={{ marginTop: 20 }}>
          <div className="note note-warn">
            <strong>Block precision of 1.000 is a warning, not a win.</strong> Zero false
            positives on 189 blocks means our synthetic data&rsquo;s high-confidence fraud
            is too cleanly separable. Real traffic will not behave this way.
          </div>
          <div className="note note-warn">
            <strong>The ensemble ranks worse than XGBoost alone</strong> &mdash; 0.788 vs
            0.800 PR-AUC. The rule layer drags legitimate rows into review. It earns its
            place on auditability and cold start, not accuracy.
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

        <p className="muted" style={{ marginTop: 20 }}>
          All figures from synthetic data we generated ourselves. Production performance
          will be worse.
        </p>
      </section>

      {/* ---------------- scope ---------------- */}
      <section className="wrap section-sm" style={{ paddingBottom: 80 }}>
        <div className="card card-lift">
          <h2 style={{ fontSize: '1.4rem' }}>Scope: defense only</h2>
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
