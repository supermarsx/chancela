/// <reference types="vitest/config" />
import { execFileSync } from 'node:child_process';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import pkg from './package.json';

// The UI build version, read from package.json at config time and inlined as the
// `__APP_VERSION__` global (see src/vite-env.d.ts). The version-check on boot compares it
// against the server's `/health` version to warn when the server binary is stale.
const appVersion: string = pkg.version;

/**
 * BUILD PROVENANCE (t100) — which commit this bundle was built from, inlined as the
 * `__BUILD_COMMIT__` global (see src/vite-env.d.ts) and read by exactly ONE surface:
 * Settings → «Sobre». The web app cannot shell out to git at runtime, so it is resolved here.
 *
 * It sits BESIDE the release version and never in place of it. `__APP_VERSION__` remains the sole
 * CalVer value, `displayVersion()` keeps owning the user-facing `YY.N` form, and the version-skew
 * comparison in `src/api/versionCheck.ts` never reads these fields — they are provenance, not a
 * version (see VERSIONING.md).
 *
 * ─── IT MUST BUILD WHERE GIT IS ABSENT ─────────────────────────────────────────────────────────
 *
 * `.dockerignore` excludes `.git`, so the `web-build` stage of `docker/Dockerfile.server` and of
 * `Dockerfile.hardened` runs `npm run build --workspace apps/web` against a context with no
 * repository in it at all. `git` can also be missing from PATH, and a source tarball carries no
 * history either. Every one of those resolves to `null` here, and the Sobre screen then says in
 * words that the build carries no provenance. A build that failed for want of a codename would be
 * far worse than a build without one; a fabricated hash would be worse still.
 *
 * CI is not one of those cases: `actions/checkout` leaves a real `.git`, and even the depth-1
 * shallow clones the web job uses contain HEAD — the only commit this reads.
 *
 * ─── THE ENV OVERRIDE ──────────────────────────────────────────────────────────────────────────
 *
 * `CHANCELA_BUILD_COMMIT` / `CHANCELA_BUILD_COMMIT_DATE` let a build that HAS the facts but not the
 * repository supply them (the Docker case, whenever someone wires them as build args). Both must be
 * set or the pair is ignored: a half-supplied override degrades to "no provenance" rather than to a
 * plausible-looking half-truth.
 *
 * ─── COMMITTER DATE, NOT AUTHOR DATE, AND NEVER BUILD TIME ─────────────────────────────────────
 *
 * `%cI` is the *committer* date in strict ISO 8601 with an explicit offset. Committer date because
 * it is when the commit entered this history: a rebased or cherry-picked commit keeps its original
 * author date, which would stamp the build with work predating the branch it was actually built
 * from. Build time is deliberately not recorded — what is wanted is the commit's own date.
 *
 * ─── NO VALIDATION HERE ────────────────────────────────────────────────────────────────────────
 *
 * This reads two strings and does not judge them. Shape checking lives in
 * `src/features/settings/buildProvenance.ts`, which is covered by tests; anything malformed —
 * from git or from the env — is rejected there and renders as "not available" rather than reaching
 * the screen. Duplicating the patterns into this untested file would only let the two drift.
 */
type RawBuildCommit = { hash: string; committedAt: string } | null;

function buildCommitFromEnv(): RawBuildCommit {
  const hash = process.env.CHANCELA_BUILD_COMMIT;
  const committedAt = process.env.CHANCELA_BUILD_COMMIT_DATE;
  if (!hash || !committedAt) {
    return null;
  }
  return { hash: hash.trim(), committedAt: committedAt.trim() };
}

function buildCommitFromGit(): RawBuildCommit {
  try {
    const out = execFileSync('git', ['log', '-1', '--format=%H%n%cI'], {
      encoding: 'utf8',
      // stderr discarded: outside a repository git writes a fatal line that is not this build's
      // problem, and the empty result already carries the whole answer.
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 10_000,
    });
    const [hash, committedAt] = out.split('\n').map((line) => line.trim());
    if (!hash || !committedAt) {
      return null;
    }
    return { hash, committedAt };
  } catch {
    // No git binary, no repository, no commits yet, or a git that hung: all the same answer.
    return null;
  }
}

const buildCommit: RawBuildCommit = buildCommitFromEnv() ?? buildCommitFromGit();

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

// The production CSP is `script-src 'self'` — no inline scripts. That is enforced in three
// places: this `index.html` <meta>, the Rust server's `security_headers` (an HTTP header, the
// authoritative one for the self-hosted server), and the Tauri config. But `@vitejs/plugin-react`
// injects an inline React Fast Refresh preamble during `npm run dev`, which `script-src 'self'`
// blocks — so `vite dev` would fail to boot with the strict meta present. This plugin strips ONLY
// the CSP meta, and ONLY in dev (`apply: 'serve'`): the built `index.html` keeps it verbatim, and
// production's real protection (the header + Tauri) is untouched. It never relaxes the policy that
// ships — it removes a redundant meta from the dev server, where HMR needs its own inline script.
function stripCspMetaInDev() {
  return {
    name: 'chancela:strip-csp-meta-in-dev',
    apply: 'serve' as const,
    transformIndexHtml(html: string): string {
      return html.replace(/\s*<meta\s+http-equiv="Content-Security-Policy"[\s\S]*?\/>/i, '');
    },
  };
}

// Vite 6 + @vitejs/plugin-react. Vitest config lives here (no separate file) so
// `vitest` and `vite build` share one plugin pipeline. Dev port stays the Vite
// default 5173 per the scaffold contract (Tauri devUrl points at it).
export default defineConfig({
  plugins: [react(), stripCspMetaInDev()],
  define: {
    __APP_VERSION__: JSON.stringify(appVersion),
    // `JSON.stringify(null)` is the string "null", so an absent repository inlines a literal
    // `null` — the one value `describeBuildCommit()` reads as "this build has no provenance".
    __BUILD_COMMIT__: JSON.stringify(buildCommit),
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
    /**
     * Sized for an INSTRUMENTED run, not a bare one.
     *
     * This was vitest's unchosen 5000ms default, and it is not what CI runs against: the web job
     * gates on `test:coverage`, and V8 coverage instrumentation roughly triples the cost of the
     * heaviest React specs. Measured on 2026-07-30, the same specs that pass a plain `vitest run`
     * crossed the default under `--coverage` whenever the workers were also contending:
     * `AtaEditorStructured.test.tsx` at 5193/5456/6924ms, `EntitiesPage.enrichment` and
     * `noticeDismissGuards` likewise. Run in ISOLATION under coverage that same file passes all
     * 34 tests at about 1.4s each — so nothing was hanging; the budget was simply sized for the
     * uninstrumented case and CI never runs that.
     *
     * The failure mode this removes is the worst kind: a red CI run that reproduces only under
     * load, points at a different spec each time, and says "timeout" rather than naming a defect.
     * 20s still fails a genuinely hung test quickly — the cost is paid only by tests that fail —
     * while leaving ~3x headroom over the slowest instrumented observation.
     *
     * If a spec ever needs more than this, that is a signal about the spec, not about the budget.
     */
    testTimeout: 20_000,
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
