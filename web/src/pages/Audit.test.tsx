import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import {
  api,
  auditKind,
  type ActionPolicy,
  type AuditEntry,
  type AuditLog,
} from '../api'
import Audit from './Audit'

/**
 * The audit view's one job that matters.
 *
 * An AUTOMATED ACTION and a HUMAN OUTCOME are different kinds of fact. A reader who
 * confuses them concludes that the model confirmed fraud, which it never does. So
 * these tests assert the distinction is present, correct, and visible without
 * relying on colour.
 */

const RISK_DECISION: AuditEntry = {
  actor: 'system:scorer',
  action: 'RISK_DECISION',
  at: '2026-08-27T10:00:00+00:00',
  event_id: 'rde_aaa111',
  before: { transaction_id: 'pay_aaa', order_id: 'ord_aaa', amount: 42999 },
  after: {
    decision: 'BLOCK',
    risk_score: 91.4,
    is_ground_truth: false,
    automated_action: {
      action: 'REFUSE_BEFORE_AUTHORISATION',
      policy_version: 'action-policy-1',
      creates_fraud_label: false,
    },
  },
}

const OUTCOME: AuditEntry = {
  actor: 'analyst@example.com',
  action: 'OUTCOME_RECORDED',
  at: '2026-08-27T10:05:00+00:00',
  event_id: 'out_bbb222',
  before: { transaction_id: 'pay_aaa', previous_label: null },
  after: { label: 'fraud', ground_truth: true, original_decision: 'BLOCK' },
}

const PROMO: AuditEntry = {
  actor: 'admin@example.com',
  action: 'PROMO_OVERRIDE',
  at: '2026-08-27T10:07:00+00:00',
  event_id: 'pov_ccc333',
  before: { redemption_id: 'rdm_ccc', machine_decision: 'HOLD' },
  after: {
    human_outcome: 'OVERRIDDEN',
    is_ground_truth: true,
    machine_decision_unchanged: 'HOLD',
  },
}

const FALLBACK: AuditEntry = {
  actor: 'system',
  action: 'MODEL_FALLBACK_TRIGGERED',
  at: '2026-08-27T09:00:00+00:00',
  before: { artifacts_dir: '/srv/artifacts' },
  after: { state: 'degraded' },
}

const POLICY: ActionPolicy = {
  policy_version: 'action-policy-1',
  decisions: {
    ALLOW: {
      automated_action: 'PROCEED_TO_AUTHORISATION',
      reason: 'below review threshold',
      permitted: ['let the payment proceed'],
      reversible_by_human: true,
    },
    BLOCK: {
      automated_action: 'REFUSE_BEFORE_AUTHORISATION',
      reason: 'at or above block threshold',
      permitted: ['refuse the payment before it reaches the payment provider'],
      reversible_by_human: true,
    },
  },
  never_automated: ['confirm that a transaction was fraudulent', 'issue a refund'],
  thresholds: { review: 5, block: 70 },
  ground_truth_source: 'human only',
  note: 'A BLOCK is NOT a finding of fraud.',
}

function stubApi(
  entries: AuditEntry[] = [RISK_DECISION, OUTCOME, PROMO, FALLBACK],
  meta: Partial<AuditLog> = {},
) {
  vi.spyOn(api, 'audit').mockResolvedValue({
    count: entries.length,
    entries,
    source: 'persistent',
    complete: true,
    warning: null,
    has_more: false,
    next_cursor: null,
    limit: 50,
    days_requested: ['2026-08-28'],
    days_read: ['2026-08-28'],
    days_failed: [],
    filters: null,
    day: '2026-08-28',
    note: 'partitioned by UTC date',
    ...meta,
  } as AuditLog)
  vi.spyOn(api, 'policy').mockResolvedValue(POLICY)
}

// ---------------------------------------------------------------------------
// classification, at the unit level
// ---------------------------------------------------------------------------

describe('auditKind', () => {
  it('classifies an emailed actor as a human outcome', () => {
    expect(auditKind(OUTCOME)).toBe('human')
    expect(auditKind(PROMO)).toBe('human')
  })

  it('classifies system:scorer as an automated action, never human', () => {
    expect(auditKind(RISK_DECISION)).toBe('automated')
    expect(auditKind(RISK_DECISION)).not.toBe('human')
  })

  it('classifies an operational transition as a system event', () => {
    expect(auditKind(FALLBACK)).toBe('system')
  })

  it('classifies a webhook ingestion as a system event, never human', () => {
    // Re-categorised from `automated` to `system`: ingesting a provider event is
    // a state transition, not a decision taken against a transaction. What must
    // never change is that a machine actor cannot be classified human.
    const k = auditKind({
      actor: 'webhook',
      action: 'payment_event_ingested',
      at: '2026-08-27T10:00:00+00:00',
      before: {},
      after: {},
    })
    expect(k).toBe('system')
    expect(k).not.toBe('human')
  })

  it('classifies an alert as communication, distinct from a system event', () => {
    expect(
      auditKind({
        actor: 'system:notifier',
        action: 'NOTIFICATION_SENT',
        at: '2026-08-27T10:00:00+00:00',
        before: {},
        after: { is_ground_truth: false },
      }),
    ).toBe('communication')
  })

  it('defaults an unknown event to automated rather than human', () => {
    // Fail-safe direction: mislabelling a machine action as a human verdict would
    // invent ground truth that nobody created.
    expect(
      auditKind({
        actor: 'system:something-new',
        action: 'SOME_FUTURE_EVENT',
        at: '2026-08-27T10:00:00+00:00',
        before: {},
        after: {},
      }),
    ).toBe('automated')
  })
})

// ---------------------------------------------------------------------------
// the rendered view
// ---------------------------------------------------------------------------

describe('Audit view', () => {
  it('labels automated actions and human outcomes distinctly in text', async () => {
    stubApi()
    render(<Audit />)

    await waitFor(() => {
      expect(screen.getAllByText(/AUTOMATED/).length).toBeGreaterThan(0)
    })
    // Each kind spelled out as text. Not colour, not a coloured dot alone.
    expect(screen.getAllByText(/HUMAN/).length).toBe(2) // outcome + promo
    expect(screen.getAllByText(/SYSTEM/).length).toBe(1) // model fallback
  })

  it('shows the actor for every row, which is what makes the kind verifiable', async () => {
    stubApi()
    render(<Audit />)

    await waitFor(() => expect(screen.getByText('system:scorer')).toBeInTheDocument())
    expect(screen.getByText('analyst@example.com')).toBeInTheDocument()
    expect(screen.getByText('admin@example.com')).toBeInTheDocument()
  })

  it('states that a risk decision is not a fraud finding', async () => {
    stubApi()
    render(<Audit />)

    await waitFor(() =>
      expect(
        screen.getByText(/never a finding of fraud/i),
      ).toBeInTheDocument(),
    )
    expect(
      screen.getByText(/Ground truth exists only where the actor is a person/i),
    ).toBeInTheDocument()
  })

  it('counts all four kinds separately', async () => {
    stubApi()
    render(<Audit />)

    await waitFor(() => expect(screen.getByText('Human')).toBeInTheDocument())
    for (const label of ['Automated', 'Human', 'Communication', 'System']) {
      expect(screen.getByText(label)).toBeInTheDocument()
    }
    expect(screen.getByText('the only ground truth')).toBeInTheDocument()
  })

  it('warns when the audit view may be incomplete', async () => {
    stubApi(undefined, {
      source: 'memory_fallback',
      complete: false,
      warning: 'Audit persistence unavailable; results may be incomplete',
    })
    render(<Audit />)

    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent(/may be incomplete/i)
  })

  it('does not warn when the durable read succeeded', async () => {
    stubApi()
    render(<Audit />)
    await waitFor(() => expect(screen.getByText('Human')).toBeInTheDocument())
    expect(screen.queryByText(/may be incomplete/i)).not.toBeInTheDocument()
  })

  it('shows the role for a human event and none for a machine one', async () => {
    stubApi([
      { ...OUTCOME, actor_identity: { user_id: 'u1', email: OUTCOME.actor, role: 'analyst' } },
      RISK_DECISION,
    ])
    render(<Audit />)

    await waitFor(() => expect(screen.getByText('analyst')).toBeInTheDocument())
    // The machine row renders an em dash rather than a blank, so a reader can
    // tell "no role" from "data missing".
    expect(screen.getAllByText('\u2014').length).toBeGreaterThan(0)
  })

  it('shows ground truth read from the event, not inferred from the category', async () => {
    stubApi([OUTCOME, RISK_DECISION, FALLBACK])
    render(<Audit />)

    await waitFor(() => expect(screen.getByText('yes')).toBeInTheDocument())
    expect(screen.getByText('no')).toBeInTheDocument()
    // MODEL_FALLBACK_TRIGGERED states is_ground_truth: false in this fixture, so
    // only a genuinely silent event would render n/a.
  })

  it('filters by event type through the server, not in the browser', async () => {
    stubApi()
    const spy = vi.spyOn(api, 'audit')
    render(<Audit />)
    await waitFor(() => expect(spy).toHaveBeenCalled())

    await userEvent.click(screen.getByRole('button', { name: 'Promo override' }))
    await waitFor(() =>
      expect(spy).toHaveBeenCalledWith(
        expect.objectContaining({ action: 'PROMO_OVERRIDE' }),
      ),
    )
  })

  it('requests a specific UTC date, not just today', async () => {
    stubApi()
    const spy = vi.spyOn(api, 'audit')
    render(<Audit />)
    await waitFor(() => expect(spy).toHaveBeenCalled())

    await userEvent.click(screen.getByRole('button', { name: 'Yesterday' }))
    await waitFor(() =>
      expect(spy).toHaveBeenCalledWith(
        expect.objectContaining({ date: expect.stringMatching(/^\d{4}-\d{2}-\d{2}$/) }),
      ),
    )
  })

  it('requests a date range when range mode is enabled', async () => {
    stubApi()
    const spy = vi.spyOn(api, 'audit')
    render(<Audit />)
    await waitFor(() => expect(spy).toHaveBeenCalled())

    await userEvent.click(screen.getByRole('button', { name: 'date range' }))
    await waitFor(() =>
      expect(spy).toHaveBeenCalledWith(
        expect.objectContaining({
          startDate: expect.any(String),
          endDate: expect.any(String),
        }),
      ),
    )
  })

  it('follows the opaque cursor when paging older', async () => {
    stubApi(undefined, { has_more: true, next_cursor: 'opaque-token-1' })
    const spy = vi.spyOn(api, 'audit')
    render(<Audit />)
    await waitFor(() => expect(screen.getByText(/Older/)).toBeInTheDocument())

    await userEvent.click(screen.getByRole('button', { name: /Older/ }))
    await waitFor(() =>
      expect(spy).toHaveBeenCalledWith(
        expect.objectContaining({ cursor: 'opaque-token-1' }),
      ),
    )
  })

  it('offers no pager when a single page holds everything', async () => {
    stubApi(undefined, { has_more: false, next_cursor: null })
    render(<Audit />)
    await waitFor(() => expect(screen.getByText('Human')).toBeInTheDocument())
    expect(screen.queryByRole('button', { name: /Older/ })).not.toBeInTheDocument()
  })

  it('warns when part of a date range could not be read', async () => {
    stubApi(undefined, {
      source: 'partial',
      complete: false,
      warning: 'Audit persistence unavailable for 2026-08-27; this result is incomplete.',
      days_failed: ['2026-08-27'],
    })
    render(<Audit />)

    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent(/incomplete/i)
  })

  it('publishes what the automation is forbidden from doing', async () => {
    stubApi()
    render(<Audit />)

    await waitFor(() =>
      expect(screen.getByText('Never done automatically')).toBeInTheDocument(),
    )
    expect(
      screen.getByText('confirm that a transaction was fraudulent'),
    ).toBeInTheDocument()
    expect(screen.getByText('issue a refund')).toBeInTheDocument()
    expect(screen.getByText(/A BLOCK is NOT a finding of fraud/)).toBeInTheDocument()
  })

  it('shows the machine decision and the human verdict as separate fields', async () => {
    stubApi([PROMO])
    render(<Audit />)

    await waitFor(() => expect(screen.getByText('OVERRIDDEN')).toBeInTheDocument())
    await userEvent.click(screen.getByRole('button', { name: 'Detail' }))

    // The original HOLD survives in the record; it was not rewritten to ALLOW.
    const detail = await screen.findByText(/machine_decision_unchanged/)
    expect(detail.textContent).toContain('HOLD')
    expect(detail.textContent).not.toContain('ALLOW')
  })

  it('renders an empty trail honestly instead of implying nothing happened', async () => {
    stubApi([])
    render(<Audit />)

    await waitFor(() =>
      expect(screen.getByText(/No audit events/i)).toBeInTheDocument(),
    )
    // Names the date it looked at, and says the data is not lost — history is
    // partitioned by UTC date and another day may hold it.
    expect(
      screen.getByText(/No audit events.*on \d{4}-\d{2}-\d{2}.*\(UTC\)/),
    ).toBeInTheDocument()
    expect(screen.getByText(/Every event is persisted/i)).toBeInTheDocument()
  })
})
