/**
 * PLATFORM LOG LIMITATIONS COPY (t97) — the pt-PT sentences under «Limitações» on the platform log
 * tail panel (Definições → Plataforma → Registos). `GET /v1/platform/logs` returns `limitations[]`
 * as raw English operator prose, and `SettingsPage.tsx`'s `PlatformLogTailPanel` rendered
 * `logs.data.limitations` verbatim inside a `<ul>`. Same defect class as `platformServiceFallback.ts`
 * (t92), a different endpoint.
 *
 * ─── THE FOUR SENTENCES, TWO OF WHICH ARE MUTUALLY EXCLUSIVE ──────────────────────────────────────
 *
 * `limitations(durable: bool)` in `crates/chancela-api/src/platform_logs.rs` returns:
 *  - durable:   "This is a data-dir-backed, bounded API-owned structured platform log tail."
 *  - durable:   a `format!` sentence interpolating `PLATFORM_LOG_RETENTION_LIMIT` — "Retention is
 *               deterministic: only the newest {N} API-owned platform log entries are kept."
 *  - !durable:  "This is an in-memory API-owned structured log ring; entries reset when the API
 *               process restarts."
 *  - always appended: "It is not historical stdout/stderr tailing and does not include MCP process
 *               logs unless a future supervisor forwards structured events into the API."
 *
 * ─── WHY THIS ONE IS NOT RESOLVED BY TEXT MATCH ────────────────────────────────────────────────────
 *
 * `platformServiceFallback.ts` resolves its `limitations[]` population by matching the server's
 * English text against a pinned tier, because that population carries no identifier on the wire at
 * all. That trick does not extend here: the retention sentence is built with `format!`, so its
 * rendered text varies with `PLATFORM_LOG_RETENTION_LIMIT` and there is no fixed English string to
 * match against. Matching text would either miss every real render (the number never equals a pinned
 * literal) or require re-deriving the number by parsing prose, which is fragile for no reason.
 *
 * The response already carries what is needed structurally: `retention.durable` — the very boolean
 * `limitations()` branches on — and `retention.retention_limit` — the very integer the `format!`
 * interpolates. This module keys on those two structured fields instead of the server's prose, the
 * same move `PlatformLogTailPanel` already makes a few lines below the limitations list for
 * `retention.basis.durable` / `retention.basis.memory`. `logs.data.limitations` itself is only
 * consulted, in DEV, as a length cross-check against what the two fields predict; a mismatch there is
 * a signal this module and the emitter have diverged, not a value ever rendered.
 *
 * The retention integer is agreement-inert (memory: `i18n-interpolated-nouns-break-agreement`): a
 * count, not a noun, the same class as `{seconds}` in `apiErrorFallback.ts`. Nothing else here is
 * ever interpolated into pt-PT prose.
 *
 * ─── THE GUARD ──────────────────────────────────────────────────────────────────────────────────
 *
 * `platformLogLimitationsFallback.test.ts` parses `limitations(durable: bool)` in `platform_logs.rs`
 * by brace matching (memory: `grep-the-symbol-not-the-line`), never by line number, and asserts, in
 * both directions: the two fixed branch literals plus the appended literal match
 * {@link platformLogLimitationsEnglish} exactly; and the retention template's fixed text — with
 * `{PLATFORM_LOG_RETENTION_LIMIT}` (Rust) and `{retentionLimit}` (here) both normalised to a common
 * placeholder — matches too. A one-word reword of any of the three fixed sentences, or of the
 * retention template's surrounding text, goes red; so does losing the interpolation slot itself.
 *
 * ─── CONVENTIONS ────────────────────────────────────────────────────────────────────────────────
 *
 * Code and identifiers stay English; only what an operator reads is Portuguese. pt-PT, never pt-BR,
 * no invented anglicisms (memory: `pt-pt-no-invented-anglicisms`). These sentences make precise
 * technical claims — bounded ring, entries reset on restart, not stdout/stderr tailing, no MCP
 * process logs — and the Portuguese preserves that precision rather than a friendlier approximation.
 *
 * Self-contained rather than folded into the shared catalog, for the same reason as its siblings
 * (`apiErrorFallback.ts`, `platformServiceFallback.ts`, ~20 others): `Catalog` is total over 14
 * locales, so one new key there is 14 edits across files several live lanes are serialised on. A
 * copy change here moves 2 places in 1 file.
 */
import { useMemo } from 'react';
import { useActiveLocale } from './useT';

/** Stable client-side codes for the four sentences `limitations()` can emit. None reaches the wire. */
export type PlatformLogLimitationCode =
  | 'basis.durable'
  | 'basis.memory'
  | 'retention.limit'
  | 'scope.notStdoutStderr';

export type PlatformLogLimitationsCopy = Record<PlatformLogLimitationCode, string>;

/** pt-PT source copy — the reviewed sentences. `retention.limit` carries the one placeholder this
 *  module ever interpolates. */
export const platformLogLimitationsPtPT: PlatformLogLimitationsCopy = {
  'basis.durable':
    'Isto é uma cauda de registo de plataforma estruturado, gerida pela API, guardada no diretório de dados e limitada em dimensão.',
  'basis.memory':
    'Isto é um anel de registo estruturado, gerido pela API, mantido em memória; as entradas perdem-se quando o processo da API reinicia.',
  'retention.limit':
    'A retenção é determinística: são guardadas apenas as {retentionLimit} entradas mais recentes do registo de plataforma gerido pela API.',
  'scope.notStdoutStderr':
    'Não é uma captura histórica de stdout/stderr e não inclui registos de processos MCP, a menos que um futuro supervisor venha a encaminhar eventos estruturados para a API.',
};

/**
 * English tier — served to the other 13 locales, and pinned to the Rust literals character for
 * character (verbatim for the three fixed sentences; the retention entry keeps `{retentionLimit}`
 * where Rust keeps `{PLATFORM_LOG_RETENTION_LIMIT}`). Do not paraphrase an entry here to read
 * better — change the Rust and mirror it, or the guard is comparing against a fiction.
 */
export const platformLogLimitationsEnglish: PlatformLogLimitationsCopy = {
  'basis.durable': 'This is a data-dir-backed, bounded API-owned structured platform log tail.',
  'basis.memory':
    'This is an in-memory API-owned structured log ring; entries reset when the API process restarts.',
  'retention.limit':
    'Retention is deterministic: only the newest {retentionLimit} API-owned platform log entries are kept.',
  'scope.notStdoutStderr':
    'It is not historical stdout/stderr tailing and does not include MCP process logs unless a future supervisor forwards structured events into the API.',
};

function warnDrift(detail: string): void {
  if (import.meta.env.DEV) {
    console.warn(
      `[platformLogLimitationsFallback] ${detail}; platform_logs.rs and this module may have diverged.`,
    );
  }
}

/** Substitute the one agreement-inert placeholder this module ever interpolates. */
function withRetentionLimit(template: string, retentionLimit: number): string {
  return template.replace('{retentionLimit}', String(retentionLimit));
}

/**
 * The active copy tier: pt-PT gets the reviewed sentences, every other locale gets the pinned
 * English — the same split `platformServiceFallback.ts` uses while off the shared catalog chain.
 */
export function usePlatformLogLimitationsCopy(): PlatformLogLimitationsCopy {
  const locale = useActiveLocale();
  return locale === 'pt-PT' ? platformLogLimitationsPtPT : platformLogLimitationsEnglish;
}

/**
 * Build the localized «Limitações» list for the platform log panel, keyed on the two structured
 * fields the server already puts on `retention` rather than parsed from `limitations[]`'s prose (see
 * module header for why). `serverLimitations` is only used, in DEV, as a length cross-check — never
 * rendered and never required to be non-empty for this to work.
 */
export function resolvePlatformLogLimitations(
  copy: PlatformLogLimitationsCopy,
  durable: boolean,
  retentionLimit: number,
  serverLimitations: readonly string[],
): string[] {
  const items = durable
    ? [copy['basis.durable'], withRetentionLimit(copy['retention.limit'], retentionLimit)]
    : [copy['basis.memory']];
  items.push(copy['scope.notStdoutStderr']);

  if (serverLimitations.length !== items.length) {
    warnDrift(
      `expected ${items.length} limitation sentence(s) for durable=${String(durable)}, server sent ${serverLimitations.length}`,
    );
  }
  return items;
}

/** `resolvePlatformLogLimitations` bound to the active locale. */
export function usePlatformLogLimitations(): (
  durable: boolean,
  retentionLimit: number,
  serverLimitations: readonly string[],
) => string[] {
  const copy = usePlatformLogLimitationsCopy();
  return useMemo(
    () => (durable: boolean, retentionLimit: number, serverLimitations: readonly string[]) =>
      resolvePlatformLogLimitations(copy, durable, retentionLimit, serverLimitations),
    [copy],
  );
}
