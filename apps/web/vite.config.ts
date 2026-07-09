/// <reference types="vitest/config" />
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import pkg from './package.json';

// The UI build version, read from package.json at config time and inlined as the
// `__APP_VERSION__` global (see src/vite-env.d.ts). The version-check on boot compares it
// against the server's `/health` version to warn when the server binary is stale.
const appVersion: string = pkg.version;

function manualChunks(id: string): string | undefined {
  if (!id.includes('node_modules')) {
    return undefined;
  }

  if (/[\\/]node_modules[\\/](react|react-dom|scheduler)[\\/]/.test(id)) {
    return 'vendor-react';
  }
  if (/[\\/]node_modules[\\/]react-router/.test(id)) {
    return 'vendor-router';
  }
  if (/[\\/]node_modules[\\/]@tanstack[\\/]react-query[\\/]/.test(id)) {
    return 'vendor-query';
  }
  if (/[\\/]node_modules[\\/]@tauri-apps[\\/]/.test(id)) {
    return 'vendor-tauri';
  }
  return 'vendor';
}

// Vite 6 + @vitejs/plugin-react. Vitest config lives here (no separate file) so
// `vitest` and `vite build` share one plugin pipeline. Dev port stays the Vite
// default 5173 per the scaffold contract (Tauri devUrl points at it).
export default defineConfig({
  plugins: [react()],
  define: {
    __APP_VERSION__: JSON.stringify(appVersion),
  },
  server: {
    // Dev-only proxy: `npm run dev` (Vite :5173) forwards the API surface to the
    // Rust server on :8080 so the SPA's relative `/v1/...` and `/health` calls work
    // in development. Production is same-origin (server serves the built dist), so
    // no proxy is needed there.
    proxy: {
      '/v1': 'http://127.0.0.1:8080',
      '/health': 'http://127.0.0.1:8080',
    },
  },
  build: {
    rollupOptions: {
      output: {
        manualChunks,
      },
    },
  },
  test: {
    environment: 'jsdom',
    globals: false,
    css: false,
    include: ['src/**/*.{test,spec}.{ts,tsx}'],
  },
});
