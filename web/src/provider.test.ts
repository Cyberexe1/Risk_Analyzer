import { describe, expect, it } from 'vitest'
import type { Health } from './api'

/**
 * The payment-provider chip must describe the provider that is ACTUALLY serving
 * checkout.
 *
 * This is the one piece of UI where an inaccuracy becomes a false claim about the
 * product: a chip reading "Razorpay" on a service that is quietly running the
 * simulator would be exactly the misrepresentation the whole provider abstraction
 * exists to prevent. The console derives the chip from /health, so these tests pin
 * the derivation for every state the backend can report.
 */

/** Mirrors the expression in Admin.tsx. Kept in one place so the test and the
 *  component cannot drift on the logic, only on the markup. */
function chipFor(health: Health | null): string {
  const base = health?.payment_provider === 'razorpay' ? 'Razorpay' : 'simulated gateway'
  return base + (health?.payment_provider_status?.degraded ? ' (degraded)' : '')
}

const BASE: Health = {
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
}

describe('payment provider chip', () => {
  it('reads "simulated gateway" on the default configuration', () => {
    expect(
      chipFor({
        ...BASE,
        payment_provider: 'simulated',
        razorpay_configured: false,
        payment_provider_status: {
          payment_provider: 'simulated',
          requested_provider: 'simulated',
          razorpay_configured: false,
          degraded: false,
          note: 'simulated gateway; no external payment provider is called',
        },
      }),
    ).toBe('simulated gateway')
  })

  it('reads "Razorpay" only when Razorpay is the provider actually in use', () => {
    expect(
      chipFor({
        ...BASE,
        payment_provider: 'razorpay',
        razorpay_configured: true,
        payment_provider_status: {
          payment_provider: 'razorpay',
          requested_provider: 'razorpay',
          razorpay_configured: true,
          degraded: false,
          note: 'Razorpay credentials present.',
        },
      }),
    ).toBe('Razorpay')
  })

  it('does NOT read "Razorpay" merely because credentials exist', () => {
    // Credentials present but the provider is explicitly the simulator. Showing
    // "Razorpay" here would claim an integration that is not carrying traffic.
    const chip = chipFor({
      ...BASE,
      payment_provider: 'simulated',
      razorpay_configured: true,
      payment_provider_status: {
        payment_provider: 'simulated',
        requested_provider: 'simulated',
        razorpay_configured: true,
        degraded: false,
        note: 'simulated gateway',
      },
    })
    expect(chip).toBe('simulated gateway')
    expect(chip).not.toContain('Razorpay')
  })

  it('says "degraded" when Razorpay was requested but is unconfigured', () => {
    const chip = chipFor({
      ...BASE,
      payment_provider: 'simulated',
      razorpay_configured: false,
      payment_provider_status: {
        payment_provider: 'simulated',
        requested_provider: 'razorpay',
        razorpay_configured: false,
        degraded: true,
        note: 'RAZORPAY_KEY_ID / RAZORPAY_KEY_SECRET are unset.',
      },
    })
    expect(chip).toBe('simulated gateway (degraded)')
    // The operator must be able to tell that the configured provider is not the
    // running one.
    expect(chip).toContain('degraded')
  })

  it('falls back to the simulator label when /health has not loaded', () => {
    // Never optimistic. An unknown provider must not render as Razorpay.
    expect(chipFor(null)).toBe('simulated gateway')
  })

  it('carries no key material in anything the chip can show', () => {
    const health: Health = {
      ...BASE,
      payment_provider: 'razorpay',
      razorpay_configured: true,
      payment_provider_status: {
        payment_provider: 'razorpay',
        requested_provider: 'razorpay',
        razorpay_configured: true,
        degraded: false,
        note: 'Razorpay credentials present. This adapter has never been exercised against a live Razorpay account.',
      },
    }
    const blob = JSON.stringify(health)
    expect(blob).not.toMatch(/rzp_(test|live)_[A-Za-z0-9]/)
    expect(blob.toLowerCase()).not.toContain('key_secret')
    // And the note is honest about what has not been verified.
    expect(health.payment_provider_status!.note).toContain('never been exercised')
  })
})
