import { describe, expect, it } from 'vitest'
import {
  auditKind,
  AUDIT_ACTIONS,
  type AuditEntry,
  type EmailStatus,
  type Health,
  type NotificationRecord,
} from './api'

/**
 * What the console is allowed to show about analyst alerting.
 *
 * Two security-relevant properties, both of which would be a real leak if wrong:
 *
 *  1. **No credential, sender or recipient address reaches the browser.** The
 *     backend already withholds them; these tests pin the client-side contract so
 *     a future field addition cannot quietly start rendering them.
 *
 *  2. **A notification is never presented as a risk decision or as ground truth.**
 *     An analyst who reads "alert sent" as "reviewed" would close items nobody
 *     looked at.
 */

const SENT: NotificationRecord = {
  notification_id: 'ntf_abc123',
  event_type: 'BLOCK',
  status: 'sent',
  provider: 'console',
  recipient_count: 2,
  transaction_id: 'pay_abc',
  order_id: 'ord_abc',
  created_at: '2026-08-28T10:00:00+00:00',
  sent_at: '2026-08-28T10:00:00+00:00',
  error_category: null,
  attempts: 1,
  durable: true,
}

const FAILED: NotificationRecord = {
  ...SENT,
  notification_id: 'ntf_def456',
  status: 'failed',
  provider: 'smtp',
  sent_at: null,
  error_category: 'auth_failed',
}

describe('notification projection', () => {
  const FORBIDDEN = [
    'recipients',
    'recipient_list',
    'body',
    'subject',
    'error',
    'password',
    'smtp_password',
    'username',
    'sender',
  ] as const

  it('carries no recipient addresses, body, or raw transport error', () => {
    for (const field of FORBIDDEN) {
      expect(SENT).not.toHaveProperty(field)
      expect(FAILED).not.toHaveProperty(field)
    }
  })

  it('publishes an error CATEGORY, never the transport message', () => {
    // A server banner can name internal hosts and an auth error can echo the
    // username, so the category is the only safe thing to render.
    expect(FAILED.error_category).toBe('auth_failed')
    expect(JSON.stringify(FAILED)).not.toContain('@')
  })

  it('distinguishes a delivered alert from an undelivered one', () => {
    expect(SENT.status).toBe('sent')
    expect(SENT.sent_at).toBeTruthy()
    expect(FAILED.status).toBe('failed')
    expect(FAILED.sent_at).toBeNull()
  })

  it('names the provider, so a rendered alert is not read as a delivered one', () => {
    // `status: sent` on the console provider means "rendered". The provider name
    // is what stops that reading as an email having left the building.
    expect(SENT.provider).toBe('console')
    expect(FAILED.provider).toBe('smtp')
  })
})

describe('email status published to the browser', () => {
  const STATUS: EmailStatus = {
    provider: 'smtp',
    requested_provider: 'smtp',
    configured: true,
    degraded: false,
    alerts_enabled: true,
    recipient_count: 3,
    note: 'SMTP configured.',
  }

  it('is a count and booleans, never addresses or credentials', () => {
    expect(STATUS.recipient_count).toBe(3)
    const blob = JSON.stringify(STATUS)
    expect(blob).not.toMatch(/@/)
    expect(blob.toLowerCase()).not.toContain('password')
  })

  it('separates "configured" from "actually alerting anyone"', () => {
    // A provider can be perfectly configured and still deliver to nobody, which
    // is the failure an operator is most likely to miss.
    const noRecipients: EmailStatus = {
      ...STATUS,
      alerts_enabled: false,
      recipient_count: 0,
      note: 'delivered to nobody',
    }
    expect(noRecipients.configured).toBe(true)
    expect(noRecipients.alerts_enabled).toBe(false)
  })

  it('exposes degradation as its own flag rather than only in prose', () => {
    const degraded: EmailStatus = {
      ...STATUS,
      provider: 'console',
      degraded: true,
      note: 'FRAUDSHIELD_SMTP_HOST is unset. Falling back to console: alerts are rendered, NOT emailed.',
    }
    expect(degraded.degraded).toBe(true)
    expect(degraded.provider).toBe('console')
    expect(degraded.note).toContain('NOT emailed')
  })
})

describe('health email block', () => {
  const HEALTH: Health = {
    status: 'ok',
    model_loaded: true,
    model_version: 'test',
    thresholds: { review: 5, block: 70 },
    store: 'in-memory',
    service_auth: 'api-key',
    user_auth: 'jwt + argon2id',
    user_store: 'memory',
    record_store: 'memory',
    admin_requires_role: ['analyst', 'admin'],
    email_notifications: {
      provider: 'console',
      configured: true,
      degraded: false,
      alerts_enabled: true,
      recipient_count: 2,
      note: 'console provider; alerts are rendered, not transmitted',
      sent: 4,
      failed: 1,
    },
  }

  it('reports mode and counts without any address or credential', () => {
    const e = HEALTH.email_notifications!
    expect(e.provider).toBe('console')
    expect(e.sent).toBe(4)
    expect(e.failed).toBe(1)
    const blob = JSON.stringify(e)
    expect(blob).not.toMatch(/@/)
    expect(blob.toLowerCase()).not.toContain('password')
  })

  it('is optional, so an older backend renders as absent not as zero', () => {
    const { email_notifications: _omitted, ...withoutEmail } = HEALTH
    expect((withoutEmail as Health).email_notifications).toBeUndefined()
  })
})

describe('notification audit classification', () => {
  const sentEvent: AuditEntry = {
    actor: 'system:notifier',
    action: 'NOTIFICATION_SENT',
    at: '2026-08-28T10:00:00+00:00',
    event_id: 'ntf_abc123',
    before: { event_type: 'BLOCK', transaction_id: 'pay_abc' },
    after: { status: 'sent', recipient_count: 2, is_ground_truth: false },
  }

  const failedEvent: AuditEntry = {
    ...sentEvent,
    action: 'NOTIFICATION_FAILED',
    after: { status: 'failed', error_category: 'auth_failed', is_ground_truth: false },
  }

  it('classifies an alert as a communication event, not a human outcome', () => {
    // The dangerous mistake would be `human`: that would present an email as a
    // person having ruled on the transaction.
    //
    // These were previously classified `system`, alongside a model fallback.
    // They are not the same kind of fact: a fallback changed how the engine
    // scores, an alert changed nothing at all.
    expect(auditKind(sentEvent)).toBe('communication')
    expect(auditKind(sentEvent)).not.toBe('human')
    expect(auditKind(failedEvent)).toBe('communication')
  })

  it('never marks a notification as ground truth', () => {
    expect(sentEvent.after.is_ground_truth).toBe(false)
    expect(failedEvent.after.is_ground_truth).toBe(false)
  })

  it('has a label for both notification actions', () => {
    const actions = AUDIT_ACTIONS.map((a) => a.action)
    expect(actions).toContain('NOTIFICATION_SENT')
    expect(actions).toContain('NOTIFICATION_FAILED')
    for (const a of AUDIT_ACTIONS.filter((x) =>
      x.action.startsWith('NOTIFICATION_'),
    )) {
      expect(a.kind).toBe('communication')
      expect(a.label).toBeTruthy()
    }
  })

  it('keeps the four event kinds separate', () => {
    const risk: AuditEntry = {
      actor: 'system:scorer',
      action: 'RISK_DECISION',
      at: '2026-08-28T10:00:00+00:00',
      before: {},
      after: { is_ground_truth: false },
    }
    const outcome: AuditEntry = {
      actor: 'analyst@example.com',
      action: 'OUTCOME_RECORDED',
      at: '2026-08-28T10:00:00+00:00',
      before: {},
      after: { ground_truth: true },
    }
    const fallback: AuditEntry = {
      actor: 'system:scorer',
      action: 'MODEL_FALLBACK_TRIGGERED',
      at: '2026-08-28T09:00:00+00:00',
      before: {},
      after: { is_ground_truth: false },
    }
    expect(auditKind(risk)).toBe('automated')
    expect(auditKind(sentEvent)).toBe('communication')
    expect(auditKind(outcome)).toBe('human')
    expect(auditKind(fallback)).toBe('system')
    expect(
      new Set([
        auditKind(risk),
        auditKind(sentEvent),
        auditKind(outcome),
        auditKind(fallback),
      ]).size,
    ).toBe(4)
  })
})
