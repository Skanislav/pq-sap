import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// The UI imports js-client/src and python/vectors directly from the repo —
// allow Vite to serve files from one level above the project root.
//
// In-browser proving (key-exchange route): bb.js and noir_js ship WASM that
// Vite's dependency pre-bundler mangles, so they are excluded from it; the
// COOP/COEP headers enable SharedArrayBuffer, which bb.js needs for
// multi-threaded proving (it falls back to one thread without them).
const isolation = {
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Embedder-Policy': 'require-corp',
}

export default defineConfig({
  plugins: [react()],
  optimizeDeps: {
    exclude: ['@aztec/bb.js', '@noir-lang/noir_js', '@noir-lang/acvm_js', '@noir-lang/noirc_abi'],
  },
  // the prover worker pulls in bb.js, which code-splits: workers must be ES modules
  worker: { format: 'es' },
  server: {
    fs: { allow: ['..'] },
    headers: isolation,
  },
  preview: {
    headers: isolation,
  },
})
