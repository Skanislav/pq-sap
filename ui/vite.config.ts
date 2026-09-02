import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// The UI imports js-client/src and python/vectors directly from the repo —
// allow Vite to serve files from one level above the project root.
export default defineConfig({
  plugins: [react()],
  // Relative asset URLs so the same bundle works at the site root, under an
  // IPFS path gateway (https://gw/ipfs/<cid>/) and on a subdomain gateway.
  base: './',
  resolve: {
    // ../js-client/src imports viem from its own node_modules (same version);
    // resolve it from ui/node_modules so the bundle carries one copy. Do not
    // add @noble/* here: viem nests v1 noble libs, the app uses v2.
    dedupe: ['viem'],
  },
  server: {
    fs: { allow: ['..'] },
  },
})
