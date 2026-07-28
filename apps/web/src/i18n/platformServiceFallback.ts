/**
 * PLATFORM SERVICE-CONTROL COPY (t92) — the pt-PT sentences an operator reads on the Serviços,
 * API and MCP panels, where the server previously spoke English prose straight into the page.
 *
 * `GET /v1/platform/services` and `POST /v1/platform/services/{id}/actions/{action}` return three
 * populations of operator-readable English, and `PlatformOperationsSection.tsx` rendered all three
 * verbatim:
 *
 *  - `controllable_actions[].limitation` — why an action cannot be carried out (the strings the bug
 *    report shows under «Arrancar» / «Parar» / «Reiniciar»);
 *  - `result.message` / `last_action.message` / `platform.audit[].message` — what the backend
 *    actually did with a recorded action;
 *  - `limitations[]` — the standing caveats listed under «Limitações».
 *
 * ─── WHY THE EXISTING GATES DID NOT CATCH THIS ─────────────────────────────────────────────────
 *
 * Neither gate has a hole; both are structurally incapable of seeing these strings.
 * `noLiteralUiCopy.test.ts` walks the TypeScript AST of `../**\/*.tsx` looking for *string literals*
 * in JSX text and user-facing props — but `<p>{capability.limitation}</p>` is a JSX **expression**
 * holding a runtime value, so there is no literal in the tree to flag. `catalogLeakGate.test.ts`
 * only inspects the 13 shipped objects in `locales/`, and these sentences were never in a catalog.
 * A client-side literal gate cannot see server-authored prose. That is the whole class of defect
 * this module closes, and the reason the guard below reads Rust rather than TypeScript.
 *
 * ─── HOW A STRING IS IDENTIFIED ────────────────────────────────────────────────────────────────
 *
 * Unlike `apiErrorFallback.ts`, this endpoint puts **no `code` field on the wire**. Two of the three
 * populations do not need one: `(service_id, action)` is already on the wire and is a total, stable
 * key over both. That key is also the *right* one for the message population, which is persisted in
 * settings — an action recorded by an older build must still resolve to today's reviewed copy, and
 * keying on the stored prose would strand it.
 *
 * `limitations[]` genuinely has no identity on the wire, so it is resolved by matching the server's
 * English text against the {@link platformServiceEnglish} tier. That is only sound because the
 * English tier is **the Rust literal, verbatim**, and `platformServiceFallback.test.ts` parses
 * `crates/chancela-api/src/platform_ops.rs` and asserts exact string equality in both directions.
 * Edit the prose in Rust without editing it here and the guard goes red; it cannot rot quietly.
 *
 * Nothing was added to the Rust layer and no locale negotiation was added to the endpoint. Code and
 * identifiers stay English; only what an operator reads is Portuguese.
 *
 * ─── DEGRADATION ───────────────────────────────────────────────────────────────────────────────
 *
 * Every resolver takes the server's own text and returns it verbatim when nothing matches, marked
 * `known: false`. An unrecognised state renders the English sentence the server sent — never a
 * blank, never a key, never a silently dropped caveat (memory: `reject-never-silently-transform`).
 * A limitation the operator cannot read is a bug; a limitation that vanishes is an evidentiary one.
 *
 * ─── WHY A SELF-CONTAINED MODULE ───────────────────────────────────────────────────────────────
 *
 * `Catalog` is `Record<MessageKey, string>` over 14 locales, so one new key is 14 edits across
 * files several live lanes are serialised on. This follows the established escape valve —
 * `apiErrorFallback.ts`, `externalValidatorStatusFallback.ts`, `providerCredentialsFallback.ts`,
 * `noticeDismissFallback.ts`, `privacyLegalHoldFallback.ts` and ~20 siblings: a pt-PT source object
 * plus an English tier that `satisfies` the same key set, behind a locale-aware hook. A copy change
 * here moves 2 places in 1 file, not 28.
 *
 * pt-PT, never pt-BR, and no invented anglicisms (memory: `pt-pt-no-invented-anglicisms`). The
 * vocabulary matches the keys already in `locales/pt-PT.ts` for this panel — «estado desejado»,
 * «supervisor», «porta IA/MCP do inquilino», «arranque» / «paragem» / «reinício» — so the sentences
 * and the badges beside them speak the same language. Every entry is a complete standalone sentence
 * and none interpolates a noun (memory: `i18n-interpolated-nouns-break-agreement`).
 *
 * ─── PRECISION IS THE POINT ────────────────────────────────────────────────────────────────────
 *
 * These messages describe a real architectural constraint: this API process deliberately does not
 * manage OS processes, so it cannot start a second copy of itself, cannot terminate itself, and
 * cannot relaunch itself. The Portuguese states the same limitation, not a friendlier approximation
 * of it. «Reinício requer um supervisor externo» would lose that the process *records a desire* and
 * something outside it must act; each sentence below keeps both halves.
 */
import { useMemo } from 'react';
import type { PlatformControllableServiceId, PlatformServiceAction } from '../api/types';
import { useActiveLocale } from './useT';

/**
 * The `(service_id, action)` key shared by the capability and message populations. Total over the
 * two controllable services and the three actions `parse_action` accepts: six pairs, no gaps.
 */
export type PlatformServiceActionKey = `${PlatformControllableServiceId}.${PlatformServiceAction}`;

/**
 * Message keys: the six real pairs plus `fallback` for `outcome_message`'s `_` arm. That arm is
 * unreachable while `validate_controllable_service_id` and `parse_action` both hold, but it is a
 * sentence the emitter can return, so it is translated rather than left to leak English if either
 * validator is ever widened.
 */
export type PlatformControlMessageKey = PlatformServiceActionKey | 'fallback';

/** Stable client-side codes for the standing caveats, which carry no identity on the wire. */
export type PlatformServiceLimitationCode =
  | 'api.self_observation'
  | 'api.control_requires_supervisor'
  | 'mcp.external_launch'
  | 'mcp.secrets_not_exposed'
  | 'mcp.ai_gate_disabled';

export interface PlatformServiceCopy {
  /** Why an action cannot be performed, keyed by `(service_id, action)`. */
  capabilityLimitation: Record<PlatformServiceActionKey, string>;
  /** What the backend did with a recorded action, keyed by `(service_id, action)`. */
  controlMessage: Record<PlatformControlMessageKey, string>;
  /** The standing caveats listed under «Limitações». */
  serviceLimitation: Record<PlatformServiceLimitationCode, string>;
}

/**
 * pt-PT source copy — the reviewed sentences. Each says what the constraint *is*, and where the
 * server only recorded an intention, says that too.
 */
export const platformServicePtPT = {
  capabilityLimitation: {
    'api.start':
      'O processo da API que está a responder não consegue iniciar outra cópia de si próprio.',
    'api.stop': 'O processo da API não se consegue parar a si próprio através deste pedido.',
    'api.restart': 'Reiniciar exige um supervisor externo ou o relançamento do processo.',
    'mcp_stdio.start':
      'O servidor MCP em stdio é lançado a partir do exterior; a API apenas consegue registar o estado desejado.',
    'mcp_stdio.stop':
      'O servidor MCP em stdio é lançado a partir do exterior; a API apenas consegue registar o estado desejado.',
    'mcp_stdio.restart':
      'O servidor MCP em stdio é lançado a partir do exterior; a API apenas consegue registar o estado desejado.',
  },
  controlMessage: {
    'api.start':
      'O estado desejado de arranque da API foi registado, mas este processo já está em execução e não se consegue iniciar a si próprio.',
    'api.stop':
      'O estado desejado de paragem da API foi registado, mas este processo não se consegue terminar a si próprio com segurança através da API.',
    'api.restart':
      'O estado desejado de reinício da API foi registado. O processo não reinicia sozinho: um supervisor externo tem de o reiniciar.',
    'mcp_stdio.start':
      'O estado desejado de arranque do MCP foi registado. Relance o cliente ou o supervisor externo do MCP.',
    'mcp_stdio.stop':
      'O estado desejado de paragem do MCP foi registado. Pare ou relance o cliente ou o supervisor externo do MCP.',
    'mcp_stdio.restart':
      'O estado desejado de reinício do MCP foi registado. Relance o cliente ou o supervisor externo do MCP.',
    fallback: 'O estado desejado de controlo do serviço de plataforma foi registado.',
  },
  serviceLimitation: {
    'api.self_observation':
      'A API só consegue observar este processo como em execução porque é este o processo que está a responder ao pedido.',
    'api.control_requires_supervisor':
      'Arrancar, parar e reiniciar exigem um supervisor externo ou o relançamento do processo.',
    'mcp.external_launch':
      'O servidor MCP em stdio é lançado por um cliente ou supervisor externo; a API não consegue observar nem criar esse processo.',
    'mcp.secrets_not_exposed':
      'Esta superfície de estado não expõe nenhuma chave API do MCP nem qualquer outro segredo.',
    'mcp.ai_gate_disabled':
      'A porta IA/MCP do inquilino, settings.ai.enabled, está desativada; quem lança o processo tem de espelhar essa definição antes de o MCP poder servir.',
  },
} as const satisfies PlatformServiceCopy;

/**
 * English tier, served to the other 13 locales — and **the Rust literal, character for character**.
 *
 * This is not merely the fallback: it is the pinned copy of what `platform_ops.rs` emits, which is
 * what lets `limitations[]` be resolved by text match and what gives the divergence guard something
 * exact to compare. Do not paraphrase an entry here to read better; change the Rust and mirror it,
 * or the guard is comparing against a fiction.
 */
export const platformServiceEnglish = {
  capabilityLimitation: {
    'api.start': 'The current API process cannot start another copy of itself.',
    'api.stop': 'The current API process cannot stop itself through this request.',
    'api.restart': 'Restart requires an external supervisor or process relaunch.',
    'mcp_stdio.start':
      'The stdio MCP server is launched externally; the API can only record desired state.',
    'mcp_stdio.stop':
      'The stdio MCP server is launched externally; the API can only record desired state.',
    'mcp_stdio.restart':
      'The stdio MCP server is launched externally; the API can only record desired state.',
  },
  controlMessage: {
    'api.start':
      'API start desired state was recorded, but this already-running process cannot start itself.',
    'api.stop':
      'API stop desired state was recorded, but this process cannot terminate itself safely through the API.',
    'api.restart':
      'API restart desired state was recorded; an external supervisor must restart the process.',
    'mcp_stdio.start':
      'MCP start desired state was recorded; relaunch the external MCP client or supervisor.',
    'mcp_stdio.stop':
      'MCP stop desired state was recorded; stop or relaunch the external MCP client or supervisor.',
    'mcp_stdio.restart':
      'MCP restart desired state was recorded; relaunch the external MCP client or supervisor.',
    fallback: 'Platform service control desired state was recorded.',
  },
  serviceLimitation: {
    'api.self_observation':
      'The API can observe this process as running only because it is serving this request.',
    'api.control_requires_supervisor':
      'Start, stop, and restart require an external supervisor or process relaunch.',
    'mcp.external_launch':
      'The stdio MCP server is launched by an external client or supervisor; the API cannot observe or spawn that process.',
    'mcp.secrets_not_exposed':
      'No MCP API key or other secret is exposed through this status surface.',
    'mcp.ai_gate_disabled':
      'Tenant AI/MCP gate settings.ai.enabled is false; a launcher must mirror it before MCP can serve.',
  },
} as const satisfies PlatformServiceCopy;

/**
 * Which service each standing caveat belongs to. Asserted against the `limitations_for` match arms,
 * so a caveat attributed to the wrong service is a red guard rather than a plausible-looking line
 * on the wrong panel.
 */
export const SERVICE_LIMITATION_OWNER = {
  'api.self_observation': 'api',
  'api.control_requires_supervisor': 'api',
  'mcp.external_launch': 'mcp_stdio',
  'mcp.secrets_not_exposed': 'mcp_stdio',
  'mcp.ai_gate_disabled': 'mcp_stdio',
} as const satisfies Record<PlatformServiceLimitationCode, PlatformControllableServiceId>;

/**
 * The stable, deliberately UNTRANSLATED triplet an operator quotes in a support thread:
 * `api/start · unsupported`.
 *
 * Before this module the English prose itself was the quotable artifact — a maintainer could search
 * the Rust source for the sentence on screen. Translating it removes that, so the identifiers the
 * sentence was derived from are surfaced in its place. All three parts are wire tokens, never copy,
 * and stay English in every locale (memory: `english-codebase-pt-ui`); it renders inside a `<code>`
 * element, which is also what keeps it out of the literal-copy gate's scan.
 *
 * This is the same split `externalValidatorStatusFallback.ts` uses — human sentence plus the raw
 * token retained beside it — reached from the opposite direction: there the identifier was already
 * on screen and needed prose, here the prose was on screen and needed the identifier.
 */
export function platformDiagnosticCode(serviceId: string, action: string, outcome: string): string {
  return `${serviceId}/${action} · ${outcome}`;
}

/** How a server string resolved. `text` is never empty. */
export interface PlatformCopyResolution {
  /** The sentence to render. */
  text: string;
  /**
   * `false` when no entry matched and `text` is the server's own English, rendered verbatim rather
   * than dropped. In DEV this also logs, because it means this module has drifted from the emitter.
   */
  known: boolean;
}

/** English prose → limitation code, built from the pinned English tier. */
const LIMITATION_BY_ENGLISH: ReadonlyMap<string, PlatformServiceLimitationCode> = new Map(
  (
    Object.entries(platformServiceEnglish.serviceLimitation) as [
      PlatformServiceLimitationCode,
      string,
    ][]
  ).map(([code, english]) => [english, code] as const),
);

function warnDrift(what: string, detail: string): void {
  if (import.meta.env.DEV) {
    console.warn(
      `[platformServiceFallback] no copy for ${what} (${detail}); the server's English was ` +
        'rendered verbatim. platform_ops.rs and this module have diverged.',
    );
  }
}

/**
 * The active copy tier: pt-PT gets the reviewed sentences, every other locale gets the pinned
 * English — the same split the sibling fallback modules use while off the shared catalog chain.
 */
export function usePlatformServiceCopy(): PlatformServiceCopy {
  const locale = useActiveLocale();
  return locale === 'pt-PT' ? platformServicePtPT : platformServiceEnglish;
}

/** The `(service_id, action)` key, or `null` when the pair is not one this module covers. */
function actionKey(serviceId: string, action: string): PlatformServiceActionKey | null {
  const key = `${serviceId}.${action}`;
  return key in platformServiceEnglish.capabilityLimitation
    ? (key as PlatformServiceActionKey)
    : null;
}

/**
 * Resolve `controllable_actions[].limitation`. `serverText` is what the endpoint sent and is the
 * rendered result if the pair is unknown.
 */
export function resolveCapabilityLimitation(
  copy: PlatformServiceCopy,
  serviceId: string,
  action: string,
  serverText: string,
): PlatformCopyResolution {
  const key = actionKey(serviceId, action);
  if (key === null) {
    warnDrift('an action capability', `${serviceId}/${action}`);
    return { text: serverText, known: false };
  }
  return { text: copy.capabilityLimitation[key], known: true };
}

/**
 * Resolve a control `message` — the live `result.message`, the persisted `last_action.message`, and
 * each `platform.audit[].message`.
 *
 * The audit population is typed `PlatformServiceId`, which includes `app`; only `api` and
 * `mcp_stdio` are controllable, so an `app` row falls through to the server's own text rather than
 * being forced into a key that does not describe it.
 */
export function resolveControlMessage(
  copy: PlatformServiceCopy,
  serviceId: string,
  action: string,
  serverText: string,
): PlatformCopyResolution {
  const key = actionKey(serviceId, action);
  if (key === null) {
    warnDrift('a control message', `${serviceId}/${action}`);
    return { text: serverText, known: false };
  }
  return { text: copy.controlMessage[key], known: true };
}

/**
 * Resolve one entry of `limitations[]` by matching the server's English against the pinned tier.
 * The only population without an identifier on the wire; see the module header for why that is
 * sound and what keeps it so.
 */
export function resolveServiceLimitation(
  copy: PlatformServiceCopy,
  serverText: string,
): PlatformCopyResolution {
  const code = LIMITATION_BY_ENGLISH.get(serverText.trim());
  if (code === undefined) {
    warnDrift('a service limitation', serverText);
    return { text: serverText, known: false };
  }
  return { text: copy.serviceLimitation[code], known: true };
}

/** The three resolvers bound to the active locale, for components that need more than one. */
export function usePlatformServiceText(): {
  capabilityLimitation: (
    serviceId: string,
    action: string,
    serverText: string,
  ) => PlatformCopyResolution;
  controlMessage: (serviceId: string, action: string, serverText: string) => PlatformCopyResolution;
  serviceLimitation: (serverText: string) => PlatformCopyResolution;
} {
  const copy = usePlatformServiceCopy();
  return useMemo(
    () => ({
      capabilityLimitation: (serviceId, action, serverText) =>
        resolveCapabilityLimitation(copy, serviceId, action, serverText),
      controlMessage: (serviceId, action, serverText) =>
        resolveControlMessage(copy, serviceId, action, serverText),
      serviceLimitation: (serverText) => resolveServiceLimitation(copy, serverText),
    }),
    [copy],
  );
}
