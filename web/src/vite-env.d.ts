/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_API_BASE?: string
  /**
   * Compiled into the bundle and readable in devtools. NOT a secret.
   * See the note in src/api.ts.
   */
  readonly VITE_API_KEY?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
