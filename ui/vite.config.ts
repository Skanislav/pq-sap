import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// The UI imports js-client/src and python/vectors directly from the repo —
// allow Vite to serve files from one level above the project root.
export default defineConfig({
  plugins: [react()],
  server: {
    fs: { allow: ['..'] },
  },
});
