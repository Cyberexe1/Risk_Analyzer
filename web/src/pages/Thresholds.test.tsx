import { render, screen, waitFor } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { api, type ThresholdInfo } from '../api'
import Thresholds from './Thresholds'

/**
 * Who may move a threshold, and whether the UI tells the truth about where the
 * live values came from.
 *
 * Moving a threshold changes every future decision and the merchant's whole
 * false-positive exposure. The server enforces `admin` on the write; these tests
 * assert the console does not offer the control to anyone else, and — now that the
 * change is durable — that a rejected stored configuration is reported rather than
 * silently replaced by defaults.
 */

const INFO: ThresholdInfo = {
  current: { review: 5, block: 70 },
  config: {
    source: 'persisted',
    review: 5,
    block: 70,
    env_defaults: { review: 5, block: 70 },
    version: 3,
    updated_at: '2026-08-27T09:00:00+00:00',
    updated_by: 'admin@example.com',
    degraded: false,
    note: 'restored from the record store; survives restart',
  },
  source: 'persisted',
  cost_curve: [],
  cost_curve_note: 'validation split',
  live_projection: [],
  live_sample_size: 0,
  caveat: 'Applies to new traffic only.',
}

function stub(info: ThresholdInfo = INFO) {
  vi.spyOn(api, 'thresholds').mockResolvedValue(info)
  vi.spyOn(api, 'audit').mockResolvedValue({
    count: 0, entries: [], source: 'empty', complete: true, warning: null,
    has_more: false, next_cursor: null, limit: 200, days_requested: [],
    days_read: [], days_failed: [], filters: null,
    day: '2026-08-28', note: '',
  })
}

describe('threshold authorisation', () => {
  it('offers the control to an admin', async () => {
    stub()
    render(<Thresholds canEdit={true} />)

    await waitFor(() =>
      expect(
        screen.getByRole('button', { name: /Apply thresholds/i }),
      ).toBeInTheDocument(),
    )
  })

  it('offers no write control to an analyst, and says why', async () => {
    stub()
    render(<Thresholds canEdit={false} />)

    await waitFor(() => expect(screen.getByText(/Read-only/i)).toBeInTheDocument())
    expect(
      screen.queryByRole('button', { name: /Apply thresholds/i }),
    ).not.toBeInTheDocument()
    expect(screen.getByText(/needs the/i)).toBeInTheDocument()
  })

  it('disables the threshold inputs for an analyst', async () => {
    stub()
    render(<Thresholds canEdit={false} />)

    await waitFor(() => expect(screen.getByText(/Read-only/i)).toBeInTheDocument())
    for (const input of screen.getAllByRole('slider')) {
      expect(input).toBeDisabled()
    }
  })

  it('never fetches the audit trail for a non-admin', async () => {
    stub()
    const spy = vi.spyOn(api, 'audit')
    render(<Thresholds canEdit={false} />)

    await waitFor(() => expect(screen.getByText(/Read-only/i)).toBeInTheDocument())
    // GET /v1/admin/audit is admin-only; calling it as an analyst would only 403.
    expect(spy).not.toHaveBeenCalled()
  })
})

describe('threshold configuration provenance', () => {
  it('reports that a persisted configuration survives restart', async () => {
    stub()
    render(<Thresholds canEdit={true} />)

    await waitFor(() =>
      expect(screen.getByText(/saved configuration/i)).toBeInTheDocument(),
    )
    expect(screen.getByText('v3')).toBeInTheDocument()
    expect(screen.getByText(/set by admin@example.com/)).toBeInTheDocument()
    expect(screen.getByText('survives restart')).toBeInTheDocument()
  })

  it('reports env defaults as env defaults, not as a saved configuration', async () => {
    stub({
      ...INFO,
      source: 'env',
      config: {
        ...INFO.config!,
        source: 'env',
        version: null,
        updated_by: null,
        note: 'no persisted configuration',
      },
    })
    render(<Thresholds canEdit={true} />)

    await waitFor(() =>
      expect(screen.getByText(/environment defaults/i)).toBeInTheDocument(),
    )
    expect(screen.queryByText('survives restart')).not.toBeInTheDocument()
  })

  it('raises an alert when a stored configuration was rejected', async () => {
    // The running thresholds are NOT the ones an admin last set. Showing them
    // without saying so would recreate the log-versus-behaviour mismatch that
    // persisting thresholds was meant to remove.
    stub({
      ...INFO,
      source: 'env',
      config: {
        ...INFO.config!,
        source: 'env',
        degraded: true,
        note: 'persisted thresholds are invalid and were IGNORED',
      },
    })
    render(<Thresholds canEdit={true} />)

    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent(/rejected/i)
    expect(alert).toHaveTextContent(/not the ones last saved/i)
  })
})
