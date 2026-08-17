/**
 * Client-side code → catalog-key map for **ASiC signature inspection findings**.
 *
 * # The problem this closes
 *
 * `POST /v1/signature/asic/inspect` returns findings as `{severity, code, message}`, where the
 * `message` is an English sentence written in `crates/chancela-api/src/asic_signature_validation.rs`.
 * The inspector panel rendered it verbatim, so a Portuguese operator read the server's English
 * directly beneath the panel's own pt-PT copy. No CI gate could catch it: `noLiteralUiCopy` and
 * `catalogLeakGate` inspect the web app and are blind by construction to a sentence that arrives
 * over the wire.
 *
 * # The shape
 *
 * The same one {@link ./providerProbeDiagnostics} uses, for the same reason: **the wire stays
 * English and stable, and the client maps a stable identifier to a catalog key.** The server still
 * sends `message`, so the English is still on the wire and still in any operator's saved report.
 *
 * Nothing here is positional — every code is an explicit identifier, so a reordering on the backend
 * cannot desynchronise this file. Two completeness guards, in the order they fire:
 *
 * 1. every mapped value is a real `MessageKey` literal, so `tsc` rejects a typo or a missing key;
 * 2. `asicInspectionDiagnostics.test.ts` reads `ASIC_INSPECTION_FINDING_CODES` out of the Rust
 *    source and proves every code the server can emit is mapped here.
 *
 * # Why two codes are framed rather than replaced
 *
 * `asic_invalid_local_technical` and `asic_validation_not_performed` do not carry a fixed sentence.
 * Their `message` is `technical_failure_summary()` — the concatenated failure reasons the ASiC
 * validator itself produced, member paths and all. Those are not ours to paraphrase: inventing a
 * tidier diagnosis for why a container failed would be reporting something the validator did not
 * say. So the reason text passes through **verbatim** as a parameter, and the translated sentence
 * around it names whose words they are. This is the same decision
 * `providerProbeDiagnostics` records for `tsl_selection_invalid` and its siblings.
 *
 * # What is NOT translated here
 *
 * The `code` itself. The panel renders it as a `<code>` badge and it is what an operator quotes in
 * a support thread or greps a stored report for — the same rule the DPIA `no_claims` flags and the
 * `CHANCELA_*` variable names already follow.
 *
 * Also untranslated, and deliberately out of scope for this file: the profile **blocker** findings
 * that `append_blocker_findings` appends. Those carry `AsicDiagnosticBlockerId::as_str()` from
 * `chancela-signing` — a separate 25-identifier vocabulary with its own English messages. They fall
 * through {@link resolveAsicFinding}'s unknown-code path and render as marked English rather than
 * silently passing for localized copy.
 */
import type { AsicInspectionFinding } from '../api/types';
import type { MessageKey, TParams } from './types';

/** The catalog-key prefix every finding sentence lives under. */
const PREFIX = 'asicInspector.finding.';

/**
 * Every finding code the inspector can emit, mapped to its translated sentence.
 *
 * Ordered as `ASIC_INSPECTION_FINDING_CODES` in `asic_signature_validation.rs`, so the two read
 * side by side. Adding a code there without adding it here fails `asicInspectionDiagnostics.test.ts`.
 */
export const ASIC_FINDING_KEYS: Record<string, MessageKey> = {
  technical_scope_only: `${PREFIX}technical_scope_only`,
  asic_valid_local_technical: `${PREFIX}asic_valid_local_technical`,
  asic_invalid_local_technical: `${PREFIX}asic_invalid_local_technical`,
  asic_validation_not_performed: `${PREFIX}asic_validation_not_performed`,
  xades_not_supported: `${PREFIX}xades_not_supported`,
};

/**
 * Codes whose server `message` is the validator's own reason text rather than a fixed sentence.
 *
 * For these, and only these, the catalog string is a frame carrying a `{reasons}` placeholder and
 * the raw message is substituted into it untouched.
 */
export const VERBATIM_REASON_CODES: ReadonlySet<string> = new Set([
  'asic_invalid_local_technical',
  'asic_validation_not_performed',
]);

/** The catalog key for a finding code, or `undefined` for a code this build does not know. */
export function asicFindingKey(code: string | undefined): MessageKey | undefined {
  return code ? ASIC_FINDING_KEYS[code] : undefined;
}

/** What to render for one finding, and whether it is the operator's language. */
export interface ResolvedAsicFinding {
  /** The sentence to show. */
  text: string;
  /**
   * `true` when `text` is the server's raw English because the code was unknown. The caller MUST
   * surface this — a fallback that looks identical to a translation would pass English off as
   * localized copy, and would make the next backend-added code invisible instead of loud.
   */
  untranslated: boolean;
}

/**
 * Resolve one finding into the operator's language.
 *
 * Never blank, never a crash, and never a silent lie: an unknown code yields the server's own
 * English with `untranslated: true`, so the UI can mark it as such (and tag it `lang="en"`, which
 * is also what makes a screen reader pronounce it correctly).
 *
 * A framed code with an empty `message` falls back to the raw message path rather than rendering a
 * frame around nothing — "reasons reported by the validator:" followed by silence reads as a
 * missing UI, and would hide that the server sent us nothing to show.
 */
export function resolveAsicFinding(
  finding: Pick<AsicInspectionFinding, 'code' | 'message'>,
  t: (key: MessageKey, params?: TParams) => string,
): ResolvedAsicFinding {
  const key = asicFindingKey(finding.code);
  if (!key) return { text: finding.message, untranslated: true };
  if (VERBATIM_REASON_CODES.has(finding.code)) {
    const reasons = finding.message?.trim();
    if (!reasons) return { text: finding.message, untranslated: true };
    return { text: t(key, { reasons }), untranslated: false };
  }
  return { text: t(key), untranslated: false };
}
