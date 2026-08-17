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
 * Also untranslated, but no longer *unaccounted*: the profile **blocker** findings that
 * `append_blocker_findings` appends, carrying `AsicDiagnosticBlockerId::as_str()` from
 * `chancela-signing`. Those 25 identifiers are enumerated in {@link BLOCKER_PENDING_TRANSLATION}
 * and render as marked English through {@link resolveAsicFinding}'s unknown-code path. Listing
 * them is what lets the guard demand `mapped ∪ pending == what Rust emits`, so a 26th blocker
 * fails loudly instead of quietly joining the untranslated pile.
 */
import type { AsicInspectionFinding } from '../api/types';
import type { MessageKey, TParams } from './types';
import { type ResolvedServerFinding, resolveServerFinding } from './serverFindingText';

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

/**
 * The 25 `AsicDiagnosticBlockerId` identifiers, knowingly untranslated for now.
 *
 * `append_blocker_findings` pushes these into the same `findings` array as the codes above, each
 * carrying `chancela-signing`'s own English message, so they arrive through the identical render
 * path. They are enumerated here rather than left implicit for the reason the PDF vocabulary has a
 * `PENDING_TRANSLATION` set: the guard can then require
 * `mapped ∪ pending == what Rust emits`, so a **new** blocker still fails loudly while the
 * deliberately-untranslated set stays visible and countable.
 *
 * `xades_not_supported` is deliberately **absent**: it is already in {@link ASIC_FINDING_KEYS},
 * because the API emits a dedicated finding for it *and* it exists as a blocker id. Same code,
 * same meaning, one translation.
 */
export const BLOCKER_PENDING_TRANSLATION: ReadonlySet<string> = new Set([
  'duplicate_member',
  'encrypted_member',
  'member_uncompressed_size_exceeded',
  'total_uncompressed_size_exceeded',
  'unsupported_meta_inf_member',
  'asic_s_requires_single_payload',
  'asic_s_manifest_unsupported',
  'asic_s_missing_cades_signature',
  'asic_s_unsupported_cades_signature_path',
  'asic_e_requires_payload',
  'asic_e_missing_manifest',
  'asic_e_unsupported_manifest_path',
  'asic_e_multiple_manifests',
  'asic_e_missing_cades_signature',
  'asic_e_multiple_cades_signatures',
  'empty_signature_member',
  'empty_manifest_member',
  'asic_e_manifest_parse_failed',
  'asic_e_manifest_references_missing_signature',
  'asic_e_manifest_duplicate_signature_reference',
  'asic_e_unreferenced_signature',
  'asic_e_manifest_references_missing_payload',
  'asic_e_manifest_unreferenced_payload',
  'asic_e_manifest_digest_mismatch',
]);

/** The catalog key for a finding code, or `undefined` for a code this build does not know. */
export function asicFindingKey(code: string | undefined): MessageKey | undefined {
  return code ? ASIC_FINDING_KEYS[code] : undefined;
}

/**
 * What to render for one finding.
 *
 * # Why three arms and not `{ text, untranslated }`
 *
 * A boolean cannot mark a *substring*, and the framed case is exactly a substring problem: a
 * Portuguese sentence with an English clause inside it. The first version of this file returned
 * `{ text: t(key, { reasons }), untranslated: false }` for those, which is honest about the frame
 * and silently wrong about the clause — the English lost its `lang="en"`, so a screen reader read
 * English technical prose with Portuguese phonetics and nothing flagged it visually.
 *
 * That is **worse than the raw-English status quo** in one specific way: raw English is visibly
 * foreign, whereas a frame launders it into a sentence that presents as fully translated.
 *
 * It was invisible in review because the template — `'…pelo validador: {reasons}'` — reads as
 * entirely Portuguese. Only rendering it with a real value shows the English. For anything
 * user-visible, the template is not the artefact.
 */
export type ResolvedAsicFinding = ResolvedServerFinding;

/**
 * Resolve one finding into the operator's language.
 *
 * Never blank, never a crash, and never a silent lie: an unknown code yields the server's own
 * English as `kind: 'untranslated'`, so the UI marks it (and tags it `lang="en"`, which is also
 * what makes a screen reader pronounce it correctly).
 *
 * A framed code with an empty `message` degrades to the untranslated arm rather than rendering a
 * frame around nothing — "Motivos comunicados pelo validador:" followed by silence reads as a
 * broken UI and would hide that the server sent us nothing to show.
 */
export function resolveAsicFinding(
  finding: Pick<AsicInspectionFinding, 'code' | 'message'>,
  t: (key: MessageKey, params?: TParams) => string,
): ResolvedAsicFinding {
  return resolveServerFinding(finding, t, {
    keys: ASIC_FINDING_KEYS,
    // For this vocabulary the whole `message` IS the validator's reason text, so the verbatim
    // payload is the message itself. `PdfSignatureValidationFinding` differs — there only a
    // `params.error` tail is verbatim — which is why the resolver takes a callback.
    verbatimOf: (f) => (VERBATIM_REASON_CODES.has(f.code) ? f.message : undefined),
  });
}
