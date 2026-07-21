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
  // pdf.js (visual seal designer, t67-e12) is heavy and reached only via a lazy dynamic import;
  // keep it in its own chunk so it stays an async load for signing, out of the eager vendor bundle.
  if (/[\\/]node_modules[\\/]pdfjs-dist[\\/]/.test(id)) {
    return 'vendor-pdfjs';
  }
  // ProseMirror + its markdown round-trip (the ata body editor, t74-e6) — same reasoning as
  // pdf.js above: heavy, reached only through a `React.lazy` import, needed by one surface.
  // `markdown-it` and `linkify-it`/`mdurl`/`uc.micro`/`entities` are `prosemirror-markdown`'s
  // parser runtime and ride the SAME chunk: split apart, first use would pull them out of
  // `vendor` anyway, and `prosemirror-model` must resolve to a single instance or schema
  // identity checks fail.
  if (
    /[\\/]node_modules[\\/](prosemirror-[^\\/]+|markdown-it|linkify-it|mdurl|uc\.micro|entities|orderedmap|w3c-keyname|rope-sequence)[\\/]/.test(
      id,
    )
  ) {
    return 'vendor-prosemirror';
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
    // Dev-only anti-clickjacking hardening so `npm run dev` (Vite :5173) matches the
    // production posture. Prod (Rust `security_headers`) and the Tauri shell already set
    // these on every served response; this covers the dev server too. Kept minimal —
    // only the frame-ancestors CSP directive, not the full prod CSP, to avoid breaking
    // Vite HMR / dev tooling.
    headers: {
      'X-Frame-Options': 'DENY',
      'Content-Security-Policy': "frame-ancestors 'none'",
    },
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
    /**
     * The suite runs west of UTC, deliberately.
     *
     * Chancela ships pt-BR and Brazil is UTC−3, but every runner we had sat at UTC+0/+1, where
     * an entire class of date defect is not weakly detected — it is **undetectable**. Two
     * mutation tests measured on 2026-07-21, each running identical, deliberately broken code
     * in both zones:
     *
     *   date parser (`YYYY-MM-DD` parsed as UTC midnight, then rendered locally)
     *     Europe/London (UTC+1)     → 20 passed   ← bug wholly invisible
     *     America/Sao_Paulo (UTC−3) →  1 failed   ← caught
     *
     *   `datetime-local` → instant conversion, broken the classic way
     *     Europe/London (January, GMT+0) → 33 passed   ← mutation wholly invisible
     *     America/Sao_Paulo (UTC−3)      →  1 failed   ← caught
     *
     * The real cost of the gap was every stored calendar date displaying a day early to
     * Brazilian users, through a fully green suite. Adopting this zone cost exactly one test
     * across 1655 — an assertion that hardcoded a UTC-only payload literal, since rewritten to
     * assert the actual contract and now stronger in every zone.
     *
     * It is set HERE, in config, rather than documented as a `TZ=… npx vitest` shell prefix,
     * because that prefix **silently no-ops in Git Bash on Windows** (`ENV=undefined`, zone
     * unchanged): a developer would run the documented command, see green, and conclude the
     * timezone path was verified — reintroducing the exact false-green this guard exists to
     * eliminate, one layer up. A config cannot be invoked wrongly; an instruction can.
     *
     * Do not "simplify" this back to UTC. UTC is the one zone in which these bugs cannot fail.
     */
    env: { TZ: 'America/Sao_Paulo' },
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json-summary'],
      reportsDirectory: './coverage',
      include: ['src/**/*.{ts,tsx}'],
      exclude: [
        'src/**/*.{test,spec}.{ts,tsx}',
        'src/test/**',
        'src/i18n/locales/**',
        'src/**/*.d.ts',
        'src/i18n/types.ts',
        'src/ui/toast/types.ts',
      ],
      // CI waiver ci.coverage.thresholds.non_web_unit: these thresholds apply
      // only to apps/web Vitest/V8 unit tests. Browser/desktop/Docker/live-provider
      // coverage thresholds remain explicit waiver debt outside the apps/web
      // Vitest/V8 unit-test lane.
      thresholds: {
        statements: 90,
        branches: 78,
        functions: 83,
        lines: 90,
      },
    },
  },
});
