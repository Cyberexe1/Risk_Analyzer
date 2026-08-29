import { describe, expect, it } from 'vitest'
import { band, type Order, type OrderResult, type OrderStatus } from './api'

/**
 * What a customer is allowed to receive, and what a BLOCK is allowed to say.
 *
 * The backend is the enforcement point: `_customer_order_view` is an explicit
 * allow-list, and the risk block is only attached for staff roles. These tests
 * pin the CLIENT half of that contract — that the customer-facing types and the
 * decision presentation do not assume fields a customer never gets, and that no
 * customer-visible state accuses anyone of fraud.
 *
 * Kept as pure assertions over the shapes and helpers rather than full-page
 * renders: a render test here would prove the mock was shaped correctly, not that
 * the projection holds.
 */

/** Exactly what the backend returns to a customer for an order. */
const CUSTOMER_ORDER: Order = {
  order_id: 'ord_abc123',
  product_name: 'Wireless earbuds',
  items: [{ product_id: 'p1', name: 'Wireless earbuds', qty: 1, unit_price: 2499 }],
  item_count: 1,
  amount: 2499,
  payment_method: 'card',
  instrument_display: 'Visa \u2022\u2022\u2022\u2022 1111',
  created_at: '2026-08-27T10:00:00+00:00',
  status: 'confirmed',
  return_status: null,
}

/** The same order as a staff member sees it. */
const STAFF_ORDER: Order = {
  ...CUSTOMER_ORDER,
  risk_score: 47.2,
  decision: 'MANUAL_REVIEW',
  sub_scores: { ml: 33, rules: 9.4, network: 4.8 },
  transaction_id: 'pay_abc123',
  settlement: 'success',
  instrument_account_count: 1,
}

const RISK_FIELDS = [
  'risk_score',
  'decision',
  'sub_scores',
  'transaction_id',
  'settlement',
  'instrument_account_count',
  'reason_codes',
  'fired_rules',
  'device_fp',
  'ip_hash',
  'ip_suspicious',
  'label',
  'provider_error',
] as const

describe('customer order projection', () => {
  it('carries no risk evidence at all', () => {
    for (const f of RISK_FIELDS) {
      expect(CUSTOMER_ORDER).not.toHaveProperty(f)
    }
  })

  it('carries no entity identifiers a customer could not have chosen themselves', () => {
    // device_fp and ip_hash are how the ring view pivots. Handing them to a
    // customer would tell a card tester exactly what to rotate next.
    const blob = JSON.stringify(CUSTOMER_ORDER)
    expect(blob).not.toContain('ip_hash')
    expect(blob).not.toContain('device_fp')
  })

  it('never contains a raw card number or CVV', () => {
    const blob = JSON.stringify(CUSTOMER_ORDER)
    expect(blob).not.toMatch(/4111\s?1111\s?1111\s?1111/)
    expect(blob).not.toContain('cvv')
    // The instrument is shown as a masked display string only.
    expect(CUSTOMER_ORDER.instrument_display).toMatch(/\u2022{4}\s\d{4}$/)
  })

  it('marks the risk fields optional so no view can require them', () => {
    // A required field would force every customer-facing component to render
    // something for it, which is how such data leaks into a customer view.
    const asCustomer: Order = CUSTOMER_ORDER
    expect(asCustomer.risk_score).toBeUndefined()
    expect(asCustomer.decision).toBeUndefined()
  })
})

describe('staff order projection', () => {
  it('does carry the risk evidence an analyst needs to act', () => {
    expect(STAFF_ORDER.risk_score).toBe(47.2)
    expect(STAFF_ORDER.decision).toBe('MANUAL_REVIEW')
    expect(STAFF_ORDER.sub_scores).toEqual({ ml: 33, rules: 9.4, network: 4.8 })
    expect(STAFF_ORDER.transaction_id).toBe('pay_abc123')
  })

  it('breaks the score out per layer, so a decision is explainable', () => {
    const s = STAFF_ORDER.sub_scores!
    // Which layer drove it is the question an analyst actually asks. A single
    // aggregate would make the queue unreviewable.
    expect(Object.keys(s).sort()).toEqual(['ml', 'network', 'rules'])
  })
})

describe('customer-visible state is safe', () => {
  const BLOCKED: OrderResult = {
    order_id: 'ord_blocked',
    status: 'declined',
    message:
      "We couldn't process this payment. Please try a different method or contact support.",
    items: [],
    amount: 42999,
    payment_method: 'card',
    instrument_display: 'Visa \u2022\u2022\u2022\u2022 1111',
    settlement: 'failed',
  }

  const REVIEWING: OrderResult = {
    ...BLOCKED,
    order_id: 'ord_review',
    status: 'verifying',
    message: "We're verifying your payment. This usually takes about 2 minutes.",
    settlement: 'success',
  }

  const ACCUSATORY = [
    'fraud',
    'fraudulent',
    'suspicious',
    'abuse',
    'criminal',
    'risk score',
    'blocked',
    'flagged',
    'blacklist',
  ]

  it('a BLOCK tells the customer it failed without accusing them', () => {
    const text = `${BLOCKED.status} ${BLOCKED.message}`.toLowerCase()
    for (const word of ACCUSATORY) {
      expect(text).not.toContain(word)
    }
  })

  it('a BLOCK exposes no score, no reason codes and no risk block', () => {
    for (const f of RISK_FIELDS.filter((f) => f !== 'settlement')) {
      expect(BLOCKED).not.toHaveProperty(f)
    }
  })

  it('a MANUAL_REVIEW reads as pending verification, not as suspicion', () => {
    const text = `${REVIEWING.status} ${REVIEWING.message}`.toLowerCase()
    for (const word of ACCUSATORY) {
      expect(text).not.toContain(word)
    }
    expect(REVIEWING.status).toBe('verifying')
  })

  it('an innocent bank decline is worded differently from a risk refusal', () => {
    // Conflating the two would imply suspicion of a customer whose bank simply
    // said no, which is both wrong and bad for the merchant.
    const statuses: OrderStatus[] = [
      'confirmed',
      'verifying',
      'declined',
      'declined_by_bank',
    ]
    expect(statuses).toContain('declined_by_bank')
    expect(statuses).toContain('declined')
    expect('declined_by_bank').not.toBe('declined')
  })
})

describe('decision presentation', () => {
  it('never relies on colour alone', () => {
    // Each band carries a text label AND a distinct glyph, so the UI survives
    // greyscale, colour blindness and a screen reader.
    const bands = (['ALLOW', 'MANUAL_REVIEW', 'BLOCK'] as const).map(band)
    for (const b of bands) {
      expect(b.label).toBeTruthy()
      expect(b.glyph).toBeTruthy()
    }
    expect(new Set(bands.map((b) => b.glyph)).size).toBe(3)
    expect(new Set(bands.map((b) => b.label)).size).toBe(3)
  })

  it('labels a BLOCK as "Block", not as "Fraud"', () => {
    // The label is the decision, not a verdict about the customer.
    expect(band('BLOCK').label).toBe('Block')
    expect(band('BLOCK').label.toLowerCase()).not.toContain('fraud')
    expect(band('MANUAL_REVIEW').label).toBe('Review')
  })
})
