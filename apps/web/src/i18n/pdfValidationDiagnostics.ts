/**
 * Client-side code → catalog-key map for **PDF/PAdES validation findings**.
 *
 * # Mechanism first, translations second — deliberately
 *
 * {@link PDF_FINDING_KEYS} is **empty on purpose**. The Rust emitter now has a closed code list,
 * the wire carries `params`, the guard test reads that list, and the panel marks unknown codes as
 * English. What is missing is only the catalog copy, which lands as its own reviewable commit.
 *
 * Until then every code takes the `untranslated` path, so behaviour is identical to what shipped
 * before **except** that the English is now honestly labelled as English instead of passing for
 * localized copy — strictly better than the status quo, and it exercises the fallback in
 * production rather than only in a test.
 *
 * {@link PENDING_TRANSLATION} is what keeps that honest: the guard requires
 * `mapped ∪ pending == what Rust emits`, so a **new** code still fails loudly and the deliberately
 * untranslated set stays enumerated rather than silent.
 *
 * # Where the verbatim text lives, and why it differs from ASiC
 *
 * `asicInspectionDiagnostics` frames the **whole** `message`, because for that vocabulary the
 * message is entirely the validator's own reason text. Here the message is
 * `"<our summary>: <PadesError>"` — the summary is ours and translatable, only the tail is not —
 * so `chancela-api` hands the tail over separately as `params.error` and the frame carries an
 * `{error}` placeholder.
 *
 * That difference is the whole reason {@link resolveServerFinding} takes a `verbatimOf` callback
 * rather than assuming a fixed field. It is also the answer to "does the shape generalise?": it
 * does, but only once the verbatim payload stopped being hard-coded as `message`.
 */
import type { PdfSignatureValidationFinding } from '../api/types';
import type { MessageKey, TParams } from './types';
import { type ResolvedServerFinding, resolveServerFinding } from './serverFindingText';

/** The catalog-key prefix every finding sentence will live under. */
export const PDF_FINDING_PREFIX = 'pdfValidator.finding.';

/**
 * Codes mapped to translated copy. Empty until the pt-PT lands as its own reviewed commit.
 *
 * Ordered as `PDF_VALIDATION_FINDING_CODES` in `pdf_signature_validation.rs` when populated, so
 * the two read side by side.
 */
export const PDF_FINDING_KEYS: Record<string, MessageKey> = {};

/**
 * Codes knowingly left untranslated, so the completeness guard can tell "not yet translated" from
 * "nobody noticed". Every entry here renders as marked English.
 *
 * Removing a code from this set without adding it to {@link PDF_FINDING_KEYS} fails the guard.
 */
export const PENDING_TRANSLATION: ReadonlySet<string> = new Set([
  'technical_scope_only',
  'not_pdf',
  'pdf_missing_eof',
  'pdf_missing_startxref',
  'unsigned_pdf',
  'pades_cades_cryptographic_validation_succeeded',
  'rendered_document_not_covered',
  'embedded_dss_revocation_evidence',
  'document_timestamp_evidence',
  'invalid_byte_range',
  'invalid_embedded_signature',
  'signature_markers_without_parseable_signature',
  'pdf_signature_parse_indeterminate',
  'pdf_signature_validation_indeterminate',
]);

/**
 * Codes whose sentence ends in the PAdES layer's own failure text.
 *
 * These are the `classify_pades_error` arms. Their catalog frame must carry an `{error}`
 * placeholder; the value arrives in `params.error` and reaches the operator verbatim.
 */
export const VERBATIM_ERROR_CODES: ReadonlySet<string> = new Set([
  'invalid_byte_range',
  'invalid_embedded_signature',
  'signature_markers_without_parseable_signature',
  'pdf_signature_parse_indeterminate',
  'pdf_signature_validation_indeterminate',
]);

/** What to render for one PDF validation finding. */
export type ResolvedPdfFinding = ResolvedServerFinding;

/**
 * Resolve one finding into the operator's language.
 *
 * With {@link PDF_FINDING_KEYS} empty this always returns `kind: 'untranslated'`, which the panel
 * must render with `lang="en"` and the "Em inglês" badge.
 */
export function resolvePdfFinding(
  finding: Pick<PdfSignatureValidationFinding, 'code' | 'message' | 'params'>,
  t: (key: MessageKey, params?: TParams) => string,
): ResolvedPdfFinding {
  return resolveServerFinding(finding, t, {
    keys: PDF_FINDING_KEYS,
    placeholder: 'error',
    verbatimOf: (f) => (VERBATIM_ERROR_CODES.has(f.code) ? (f.params?.error ?? '') : undefined),
  });
}
