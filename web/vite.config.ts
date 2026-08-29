import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    // Bound to loopback deliberately. The backend it talks to has a single
    // shared API key and no per-user auth, so neither should be reachable
    // from the network.
    host: '127.0.0.1',
  },
  test: {
    // jsdom rather than a real browser: these tests assert what a role can SEE,
    // which is a DOM question, not a rendering one.
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
    include: ['src/**/*.test.{ts,tsx}'],
    // No coverage gate. A percentage would reward testing whatever is easy to
    // reach; these tests are chosen for what they protect, not for their line
    // count.
    css: false,
  },
})
