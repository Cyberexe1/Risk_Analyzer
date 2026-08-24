import { useEffect, useMemo, useRef, useState } from 'react'
import {
  ApiError,
  rupees,
  shopApi,
  type Catalogue,
  type CreateOrderBody,
  type OrderResult,
} from '../api'
import { Reasons, ScoreDial, SubScoreBars } from '../components'
import { useAuth } from '../auth'

/** Stand-in for a real device fingerprint. A production integration would use an
 *  opaque client-generated hash. Note this is inherently client-controlled, which
 *  is exactly why device signals must be corroborated by payout reuse or velocity
 *  rather than trusted alone. The IP, by contrast, is derived server-side. */
function deviceFingerprint(): string {
  const k = 'fs_device'
  let v = localStorage.getItem(k)
  if (!v) {
    v = `dev_web_${Math.random().toString(36).slice(2, 10)}`
    localStorage.setItem(k, v)
  }
  return v
}

/** Test cards. 4111… is the industry-standard Visa test number and passes Luhn;
 *  the last one fails it, so you can watch validation reject a typo before it
 *  ever reaches a gateway. */
const TEST_CARDS = [
  { label: 'Visa', number: '4111 1111 1111 1111', ok: true },
  { label: 'Mastercard', number: '5555 5555 5555 4444', ok: true },
  { label: 'Fails checksum', number: '4111 1111 1111 1112', ok: false },
]

const METHOD_GLYPH: Record<string, string> = {
  upi: '\u25C8',
  card: '\u25AC',
  netbanking: '\u25A4',
  wallet: '\u25CD',
  cod: '\u25CB',
}

/** Only the first digit is needed to name the network. */
function cardNetwork(num: string): string | null {
  const d = num.replace(/\D/g, '')
  if (!d) return null
  return (
    { '4': 'Visa', '5': 'Mastercard', '6': 'RuPay', '3': 'Amex' }[d[0]] ?? null
  )
}

/** Mirror of the backend's Luhn check, so a typo is caught before a round trip.
 *  The backend re-validates — this is UX, not enforcement. */
function luhnOk(num: string): boolean {
  const digits = [...num.replace(/\D/g, '')].map(Number)
  if (digits.length < 12) return false
  let sum = 0
  const parity = digits.length % 2
  digits.forEach((d, i) => {
    if (i % 2 === parity) {
      d *= 2
      if (d > 9) d -= 9
    }
    sum += d
  })
  return sum % 10 === 0
}

function formatCard(v: string): string {
  return v
    .replace(/\D/g, '')
    .slice(0, 19)
    .replace(/(.{4})/g, '$1 ')
    .trim()
}

type Stage = 'form' | 'otp' | 'processing' | 'done'

/** The staged progress text. Real gateways narrate, and a silent three-second
 *  wait during a payment reads as a hang. */
const STEPS = [
  'Contacting your bank\u2026',
  'Verifying the instrument\u2026',
  'Running risk checks\u2026',
  'Finalising\u2026',
]

export default function PaymentSheet({
  cat,
  amount,
  body,
  onClose,
  onSuccess,
}: {
  cat: Catalogue
  amount: number
  /** Items only. This component owns the instrument fields. */
  body: Pick<CreateOrderBody, 'items'>
  onClose: () => void
  onSuccess: () => void
}) {
  const { user } = useAuth()

  const [method, setMethod] = useState('upi')
  const [stage, setStage] = useState<Stage>('form')
  const [step, setStep] = useState(0)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<OrderResult | null>(null)

  const [cardNo, setCardNo] = useState('4111 1111 1111 1111')
  const [cardMonth, setCardMonth] = useState('12')
  const [cardYear, setCardYear] = useState('2029')
  const [cardCvv, setCardCvv] = useState('123')
  const [cardHolder, setCardHolder] = useState('')
  const [otp, setOtp] = useState('')
  const [vpa, setVpa] = useState(`${(user?.email ?? 'you').split('@')[0]}@okhdfcbank`)
  const [bank, setBank] = useState('HDFC')
  const [walletProvider, setWalletProvider] = useState('Paytm')
  const [walletPhone, setWalletPhone] = useState('9876543210')
  const [sharedDevice, setSharedDevice] = useState(false)

  const dialogRef = useRef<HTMLDivElement>(null)
  const needs = cat.payment_methods.find((m) => m.code === method)?.needs ?? null
  const network = cardNetwork(cardNo)
  const cardValid = needs !== 'card' || luhnOk(cardNo)

  // Escape closes, but never mid-flight: abandoning the dialog while the request
  // is in the air would leave the customer with no idea whether they were charged.
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape' && stage !== 'processing') onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose, stage])

  useEffect(() => {
    dialogRef.current?.focus()
  }, [])

  // Advance the narration while the request runs.
  useEffect(() => {
    if (stage !== 'processing') return
    const t = setInterval(() => setStep((s) => Math.min(s + 1, STEPS.length - 1)), 550)
    return () => clearInterval(t)
  }, [stage])

  const lineItems = useMemo(
    () =>
      body.items.map((l) => {
        const p = cat.products.find((x) => x.id === l.product_id)
        return { ...l, name: p?.name ?? l.product_id, price: p?.price ?? 0 }
      }),
    [body.items, cat.products],
  )

  async function submit() {
    setStage('processing')
    setStep(0)
    setError(null)

    const payload: CreateOrderBody = {
      items: body.items,
      payment_method: method,
      device_fp: sharedDevice ? 'dev_demo_shared' : deviceFingerprint(),
    }
    if (needs === 'card') {
      payload.card = {
        number: cardNo,
        expiry_month: Number(cardMonth),
        expiry_year: Number(cardYear),
        cvv: cardCvv,
        holder: cardHolder,
      }
    } else if (needs === 'vpa') {
      payload.upi = { vpa }
    } else if (needs === 'bank') {
      payload.netbanking = { bank_code: bank }
    } else if (needs === 'wallet') {
      payload.wallet = { provider: walletProvider, phone: walletPhone }
    }

    // Floor the visible wait so the narration is readable rather than a flicker.
    const started = Date.now()
    try {
      const r = await shopApi.createOrder(payload)
      const elapsed = Date.now() - started
      if (elapsed < 2200) await new Promise((res) => setTimeout(res, 2200 - elapsed))
      setResult(r)
      setStage('done')
      if (r.status === 'confirmed' || r.status === 'verifying') onSuccess()
    } catch (e) {
      const elapsed = Date.now() - started
      if (elapsed < 1200) await new Promise((res) => setTimeout(res, 1200 - elapsed))
      setError(e instanceof ApiError ? e.message : String(e))
      setStage('form')
    }
  }

  function proceed() {
    // Cards route through a simulated 3-D Secure step, which is where a real
    // issuer would challenge. Everything else authorises directly.
    if (needs === 'card') {
      setOtp('')
      setStage('otp')
    } else {
      void submit()
    }
  }

  const failed =
    result !== null && (result.status === 'declined' || result.status === 'declined_by_bank')

  return (
    <div
      className="pay-backdrop"
      role="presentation"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget && stage !== 'processing') onClose()
      }}
    >
      <div
        className="pay-sheet"
        role="dialog"
        aria-modal="true"
        aria-labelledby="pay-title"
        tabIndex={-1}
        ref={dialogRef}
      >
        {/* ---------------- header ---------------- */}
        <div className="pay-head">
          <div>
            <div className="eyebrow">Secure payment</div>
            <h2 id="pay-title" className="t-lg" style={{ margin: 0 }}>
              {rupees(amount)}
            </h2>
          </div>
          {stage !== 'processing' && (
            <button className="btn btn-ghost btn-sm" onClick={onClose}>
              {stage === 'done' ? 'Close' : 'Cancel'}
            </button>
          )}
        </div>

        <div className="pay-body">
          {error && (
            <div className="note note-bad" role="alert" style={{ marginBottom: 'var(--sp-4)' }}>
              {error}
            </div>
          )}

          {/* ---------------- form ---------------- */}
          {stage === 'form' && (
            <>
              <div className="pay-summary">
                {lineItems.map((l) => (
                  <div className="spread t-sm" key={l.product_id}>
                    <span>
                      {l.name} <span className="muted">&times;{l.qty}</span>
                    </span>
                    <span className="num">{rupees(l.price * l.qty)}</span>
                  </div>
                ))}
              </div>

              <div className="eyebrow" style={{ marginBottom: 'var(--sp-2)' }}>
                Choose a method
              </div>
              <div className="pay-methods" role="radiogroup" aria-label="Payment method">
                {cat.payment_methods.map((m) => (
                  <button
                    key={m.code}
                    type="button"
                    role="radio"
                    aria-checked={method === m.code}
                    className="pay-method"
                    onClick={() => setMethod(m.code)}
                  >
                    <span aria-hidden="true" className="pay-method-glyph">
                      {METHOD_GLYPH[m.code] ?? '\u25CB'}
                    </span>
                    <span>{m.label}</span>
                  </button>
                ))}
              </div>

              <div className="pay-fields">
                {needs === 'card' && (
                  <>
                    <div className="field">
                      <label htmlFor="cardno">Card number</label>
                      <div className="input-affix">
                        <input
                          id="cardno"
                          inputMode="numeric"
                          autoComplete="cc-number"
                          className="mono"
                          value={cardNo}
                          onChange={(e) => setCardNo(formatCard(e.target.value))}
                          aria-invalid={!cardValid || undefined}
                          aria-describedby="card-help"
                        />
                        {network && <span className="affix">{network}</span>}
                      </div>
                      <p
                        id="card-help"
                        className="t-xs"
                        style={{
                          margin: 'var(--sp-2) 0 0',
                          color: cardValid ? 'var(--text-faint)' : 'var(--block)',
                        }}
                      >
                        {cardValid
                          ? 'Checksum-validated, fingerprinted, then discarded. Never stored.'
                          : 'That number fails its checksum. Check for a typo.'}
                      </p>
                      <div className="pill-row" style={{ marginTop: 'var(--sp-2)' }}>
                        {TEST_CARDS.map((t) => (
                          <button
                            key={t.number}
                            type="button"
                            className="chip chip-btn"
                            onClick={() => setCardNo(t.number)}
                          >
                            {t.label}
                          </button>
                        ))}
                      </div>
                    </div>
                    <div className="row">
                      <div className="field">
                        <label htmlFor="mm">Month</label>
                        <input
                          id="mm"
                          inputMode="numeric"
                          autoComplete="cc-exp-month"
                          className="mono"
                          value={cardMonth}
                          onChange={(e) => setCardMonth(e.target.value.replace(/\D/g, '').slice(0, 2))}
                        />
                      </div>
                      <div className="field">
                        <label htmlFor="yy">Year</label>
                        <input
                          id="yy"
                          inputMode="numeric"
                          autoComplete="cc-exp-year"
                          className="mono"
                          value={cardYear}
                          onChange={(e) => setCardYear(e.target.value.replace(/\D/g, '').slice(0, 4))}
                        />
                      </div>
                      <div className="field">
                        <label htmlFor="cvv">CVV</label>
                        <input
                          id="cvv"
                          type="password"
                          inputMode="numeric"
                          autoComplete="cc-csc"
                          className="mono"
                          value={cardCvv}
                          onChange={(e) => setCardCvv(e.target.value.replace(/\D/g, '').slice(0, 4))}
                        />
                      </div>
                    </div>
                    <div className="field">
                      <label htmlFor="holder">Name on card (optional)</label>
                      <input
                        id="holder"
                        autoComplete="cc-name"
                        value={cardHolder}
                        onChange={(e) => setCardHolder(e.target.value)}
                      />
                    </div>
                  </>
                )}

                {needs === 'vpa' && (
                  <div className="field">
                    <label htmlFor="vpa">UPI ID</label>
                    <input
                      id="vpa"
                      className="mono"
                      value={vpa}
                      onChange={(e) => setVpa(e.target.value)}
                      placeholder="name@bank"
                    />
                    <div className="pill-row" style={{ marginTop: 'var(--sp-2)' }}>
                      {['@okhdfcbank', '@okicici', '@paytm', '@ybl'].map((h) => (
                        <button
                          key={h}
                          type="button"
                          className="chip chip-btn"
                          onClick={() => setVpa(`${vpa.split('@')[0]}${h}`)}
                        >
                          {h}
                        </button>
                      ))}
                    </div>
                  </div>
                )}

                {needs === 'bank' && (
                  <div className="field">
                    <label>Choose your bank</label>
                    <div className="bank-grid">
                      {cat.banks.map((b) => (
                        <button
                          key={b.code}
                          type="button"
                          className="bank-tile"
                          aria-pressed={bank === b.code}
                          onClick={() => setBank(b.code)}
                        >
                          {b.name}
                        </button>
                      ))}
                    </div>
                  </div>
                )}

                {needs === 'wallet' && (
                  <div className="row">
                    <div className="field">
                      <label htmlFor="wp">Wallet</label>
                      <select
                        id="wp"
                        value={walletProvider}
                        onChange={(e) => setWalletProvider(e.target.value)}
                      >
                        {cat.wallets.map((w) => (
                          <option key={w} value={w}>
                            {w}
                          </option>
                        ))}
                      </select>
                    </div>
                    <div className="field">
                      <label htmlFor="wph">Phone</label>
                      <input
                        id="wph"
                        inputMode="tel"
                        className="mono"
                        value={walletPhone}
                        onChange={(e) => setWalletPhone(e.target.value.replace(/\D/g, '').slice(0, 13))}
                      />
                    </div>
                  </div>
                )}

                {needs === null && (
                  <div className="note">Pay in cash when the order arrives.</div>
                )}
              </div>

              <label className="label-inline" style={{ margin: 'var(--sp-4) 0' }}>
                <input
                  type="checkbox"
                  checked={sharedDevice}
                  onChange={(e) => setSharedDevice(e.target.checked)}
                />
                <span>
                  Pay from a flagged shared device
                  <span className="muted" style={{ display: 'block', fontWeight: 400 }}>
                    Raises device-linkage signals. Your IP is derived server-side and
                    cannot be set from here.
                  </span>
                </span>
              </label>

              <button className="btn btn-block" disabled={!cardValid} onClick={proceed}>
                Pay {rupees(amount)}
              </button>
              <p className="pay-trust">
                <span aria-hidden="true">{'\u25C6'}</span> Simulated gateway. No money
                moves and no card data is stored.
              </p>
            </>
          )}

          {/* ---------------- 3-D Secure ---------------- */}
          {stage === 'otp' && (
            <div className="pay-otp">
              <div className="pay-bank-strip">
                <span className="fw-semi">{network ?? 'Card'} SecureCheck</span>
                <span className="chip">{cardNo.slice(-4).padStart(4, '\u2022')}</span>
              </div>
              <h3 style={{ marginTop: 'var(--sp-5)' }}>Verify it&rsquo;s you</h3>
              <p>
                We sent a 6-digit code to the mobile number registered with your card.
                Enter it to authorise {rupees(amount)}.
              </p>
              <div className="field">
                <label htmlFor="otp">One-time code</label>
                <input
                  id="otp"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  className="mono otp-input"
                  value={otp}
                  maxLength={6}
                  onChange={(e) => setOtp(e.target.value.replace(/\D/g, '').slice(0, 6))}
                  placeholder="000000"
                />
              </div>
              <button
                className="btn btn-block"
                disabled={otp.length !== 6}
                onClick={() => void submit()}
              >
                Authorise payment
              </button>
              <button
                className="btn btn-ghost btn-block"
                style={{ marginTop: 'var(--sp-2)' }}
                onClick={() => setStage('form')}
              >
                Back
              </button>
              <p className="pay-trust">
                Simulated challenge &mdash; any 6 digits work. A real issuer would
                verify the code, and this step is where it would happen.
              </p>
            </div>
          )}

          {/* ---------------- processing ---------------- */}
          {stage === 'processing' && (
            <div className="pay-processing" role="status" aria-live="polite">
              <div className="spinner" aria-hidden="true" />
              <div className="fw-semi">{STEPS[step]}</div>
              <p className="muted">
                Do not close this window. {rupees(amount)} via {method.toUpperCase()}.
              </p>
              <div className="pay-steps" aria-hidden="true">
                {STEPS.map((s, i) => (
                  <span key={s} className={`pay-dot${i <= step ? ' on' : ''}`} />
                ))}
              </div>
            </div>
          )}

          {/* ---------------- result ---------------- */}
          {stage === 'done' && result && (
            <div className="pay-result">
              <div
                className={`pay-status pay-status-${
                  result.status === 'confirmed'
                    ? 'ok'
                    : result.status === 'verifying'
                      ? 'review'
                      : 'bad'
                }`}
              >
                <span aria-hidden="true" className="pay-status-glyph">
                  {result.status === 'confirmed'
                    ? '\u2713'
                    : result.status === 'verifying'
                      ? '\u25C6'
                      : '\u2715'}
                </span>
                <div>
                  <div className="fw-semi">
                    {result.status === 'confirmed'
                      ? 'Payment successful'
                      : result.status === 'verifying'
                        ? 'Payment under verification'
                        : result.status === 'declined_by_bank'
                          ? 'Declined by your bank'
                          : 'Payment could not be processed'}
                  </div>
                  <div className="t-sm">{result.message}</div>
                </div>
              </div>

              <div className="pay-receipt">
                <div className="spread">
                  <span className="muted">Order</span>
                  <span className="mono t-sm">{result.order_id}</span>
                </div>
                <div className="spread">
                  <span className="muted">Amount</span>
                  <span className="num">{rupees(result.amount)}</span>
                </div>
                <div className="spread">
                  <span className="muted">Method</span>
                  <span className="t-sm">{result.instrument_display}</span>
                </div>
              </div>

              {failed && (
                <div className="note note-warn" style={{ marginTop: 'var(--sp-4)' }}>
                  This attempt was recorded. Repeated failures from the same network are
                  reviewed, so try a different method rather than retrying the same one.
                </div>
              )}

              {/* Staff-only evidence. A customer never sees a score or a reason code. */}
              {result.risk && (
                <div className="stack stack-lg" style={{ marginTop: 'var(--sp-5)' }}>
                  <div className="sub-head">
                    <span>Risk detail (staff only)</span>
                  </div>
                  <ScoreDial
                    score={result.risk.risk_score}
                    decision={result.risk.decision}
                  />
                  <SubScoreBars sub={result.risk.sub_scores} />
                  <Reasons codes={result.risk.reason_codes} />
                  <div className="pill-row">
                    <span className="chip">settled: {result.risk.settlement}</span>
                    <span className="chip">{result.risk.ip_hash}</span>
                    <span className="chip">
                      instrument on {result.risk.instrument_account_count} account
                      {result.risk.instrument_account_count === 1 ? '' : 's'}
                    </span>
                  </div>
                  {result.risk.ip_suspicious && (
                    <div className="note note-bad">
                      <strong>This address is now flagged.</strong>{' '}
                      {result.risk.ip_suspicious.reason}. It is visible under Suspicious
                      IPs in the console. The customer was not told &mdash; naming the
                      signal tells a card tester what to rotate.
                    </div>
                  )}
                </div>
              )}

              <div className="row" style={{ marginTop: 'var(--sp-5)' }}>
                {failed ? (
                  <button
                    className="btn"
                    onClick={() => {
                      setResult(null)
                      setStage('form')
                    }}
                  >
                    Try another method
                  </button>
                ) : null}
                <button className="btn btn-ghost" onClick={onClose}>
                  {failed ? 'Back to cart' : 'Done'}
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
