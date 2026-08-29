import { render, screen, waitFor } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { api, promoApi, type Health, type PublicUser } from '../api'
import * as auth from '../auth'
import Admin from './Admin'

/**
 * Who is offered the demo trigger in the console.
 *
 * The server enforces admin-only on `POST /v1/admin/demo/fraud-attack`; these
 * tests assert the console does not offer the control to anyone else and does not
 * offer it at all when the backend reports the demo gates are closed. Hiding a
 * button is presentation, not a security control — which is exactly why the
 * backend suite tests the 403 and the 409 as well.
 */

const HEALTH: Health = {
  status: 'ok',
  model_loaded: true,
  model_version: 'm-1',
  thresholds: { review: 5, block: 70 },
  store: 'memory',
  service_auth: 'open',
  user_auth: 'jwt',
  user_store: 'memory',
  record_store: 'memory',
  payment_provider: 'simulated',
  payment_provider_status: {
    payment_provider: 'simulated',
    requested_provider: 'simulated',
    razorpay_configured: false,
    degraded: false,
    note: 'simulated gateway',
  },
  demo: {
    enabled: true,
    demo_mode: true,
    provider_is_simulated: true,
    scenario: 'fraud_attack',
    attempts: 8,
    window_seconds: 420,
    blocked_because: [],
  },
  admin_requires_role: ['analyst', 'admin'],
}

function user(role: PublicUser['role']): PublicUser {
  return { user_id: 'u1', email: `${role}@example.com`, role }
}

function stub(role: PublicUser['role'], health: Health = HEALTH) {
  vi.spyOn(auth, 'useAuth').mockReturnValue({
    user: user(role),
    loading: false,
    login: vi.fn(),
    register: vi.fn(),
    logout: vi.fn(),
  })
  vi.spyOn(api, 'queue').mockResolvedValue({ count: 0, items: [] })
  vi.spyOn(api, 'health').mockResolvedValue(health)
  vi.spyOn(api, 'metrics').mockRejectedValue(new Error('not needed'))
  vi.spyOn(api, 'suspiciousIps').mockRejectedValue(new Error('not needed'))
  vi.spyOn(promoApi, 'holds').mockRejectedValue(new Error('not needed'))
}

const TRIGGER = /Trigger demo fraud attack/i

describe('demo trigger visibility in the console', () => {
  it('offers the control to an admin', async () => {
    stub('admin')
    render(<Admin />)
    await waitFor(() =>
      expect(screen.getByRole('button', { name: TRIGGER })).toBeInTheDocument(),
    )
  })

  it('offers no control to an analyst', async () => {
    stub('analyst')
    render(<Admin />)
    await waitFor(() => expect(screen.getByText(/Analyst console/i)).toBeInTheDocument())
    expect(screen.queryByRole('button', { name: TRIGGER })).not.toBeInTheDocument()
  })

  it('offers no control to a customer who reaches the page', async () => {
    stub('customer')
    render(<Admin />)
    await waitFor(() => expect(screen.getByText(/Analyst console/i)).toBeInTheDocument())
    expect(screen.queryByRole('button', { name: TRIGGER })).not.toBeInTheDocument()
  })

  it('offers no control to an admin when the server says demo mode is off', async () => {
    stub('admin', {
      ...HEALTH,
      demo: {
        ...HEALTH.demo!,
        enabled: false,
        demo_mode: false,
        blocked_because: ['FRAUDSHIELD_DEMO_MODE is not enabled'],
      },
    })
    render(<Admin />)
    await waitFor(() => expect(screen.getByText(/demo trigger off/i)).toBeInTheDocument())
    expect(screen.queryByRole('button', { name: TRIGGER })).not.toBeInTheDocument()
  })

  it('offers no control when an older backend reports no demo status', async () => {
    stub('admin', { ...HEALTH, demo: undefined })
    render(<Admin />)
    await waitFor(() => expect(screen.getByText(/Analyst console/i)).toBeInTheDocument())
    expect(screen.queryByRole('button', { name: TRIGGER })).not.toBeInTheDocument()
    expect(screen.queryByText(/demo trigger off/i)).not.toBeInTheDocument()
  })
})
