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
})
