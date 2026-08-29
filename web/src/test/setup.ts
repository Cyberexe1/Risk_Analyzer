import '@testing-library/jest-dom/vitest'
import { cleanup } from '@testing-library/react'
import { afterEach, vi } from 'vitest'

// Unmount between tests. Without this, a component left mounted keeps its polling
// interval running and the next test sees stale DOM.
afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

// No test may reach the network. The whole point of several of these tests is what
// a given role receives, and a real fetch would make the assertion depend on a
// running backend rather than on the code under test.
Object.defineProperty(globalThis, 'fetch', {
  writable: true,
  value: vi.fn(() => {
    throw new Error(
      'unmocked fetch: a frontend test must stub the API, never call it',
    )
  }),
})
