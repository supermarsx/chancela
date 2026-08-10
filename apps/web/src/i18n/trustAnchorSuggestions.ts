/**
 * Client-side code → catalog-key map for **trust-anchor suggestions** (t118).
 *
 * # The problem this closes
 *
 * `GET /v1/trust/anchor-suggestions` reports, per configured Trusted List source, whether the
 * authenticated EU LOTL vouches for it — and if not, why not. Every one of those outcomes is a
 * sentence an operator reads on the settings screen, and a sentence written in `chancela-api` is
 * invisible to `noLiteralUiCopy` and `catalogLeakGate`: both inspect the web app, and are blind by
 * construction to prose that arrives over the wire.
 *
 * So the endpoint sends a stable `code` and nothing else, and this file turns it into copy. Same
 * shape as `providerProbeDiagnostics.ts`, deliberately — a second mechanism for the same problem
 * would be a second thing to keep in step.
 *
 * # Why there is no English fallback text here
 *
 * The probe map falls back to the server's own English sentence for a code this build does not
 * know. This endpoint sends no sentence, so there is nothing to fall back TO — and inventing one
 * client-side would be guessing at a diagnosis. An unknown code therefore yields `undefined`, and
 * the caller renders the raw identifier marked as untranslated. That is ugly on purpose: it is the
 * visible failure that makes the next backend-added code get a translation.
 *
 * # What is NOT translated, and must never be
 *
 * The `detail` field beside a failure code. It is the underlying library's or transport's own error
 * string — a TLS message, a size-bound refusal, an XML-DSig verification failure. Paraphrasing it
 * would be inventing a diagnosis, so it reaches every locale verbatim, inside a translated sentence
 * that says whose words they are.
 */
import type { MessageKey } from './types';

/** The catalog-key prefix every outcome sentence lives under. */
const PREFIX = 'settings.signing.anchorSuggest.code.';

/**
 * The one outcome the UI has to branch on rather than merely render: it is the state in which the
 * bootstrap question can be asked at all. Exported as a constant so the component compares against
 * the same spelling this map is keyed by — a bare literal in the component would drift silently.
 */
export const LOTL_ANCHOR_NOT_CONFIGURED = 'lotl_anchor_not_configured';

/**
 * Every outcome code the server can emit, mapped to its sentence.
 *
 * Ordered as `ALL_TRUST_ANCHOR_SUGGESTION_CODES` in
 * `crates/chancela-api/src/trust_anchor_suggestion_codes.rs`, so the two read side by side.
 * `trustAnchorSuggestions.test.ts` reads that file and proves this map covers it exactly.
 */
export const TRUST_ANCHOR_SUGGESTION_KEYS: Record<string, MessageKey> = {
  lotl_authenticated: `${PREFIX}lotl_authenticated`,
  [LOTL_ANCHOR_NOT_CONFIGURED]: `${PREFIX}lotl_anchor_not_configured`,
  lotl_anchor_config_invalid: `${PREFIX}lotl_anchor_config_invalid`,
  lotl_fetch_failed: `${PREFIX}lotl_fetch_failed`,
  lotl_not_authenticated: `${PREFIX}lotl_not_authenticated`,
  lotl_no_pointers: `${PREFIX}lotl_no_pointers`,
  lotl_bootstrap_self_asserted: `${PREFIX}lotl_bootstrap_self_asserted`,
  lotl_bootstrap_fetch_failed: `${PREFIX}lotl_bootstrap_fetch_failed`,
  lotl_bootstrap_signer_cert_absent: `${PREFIX}lotl_bootstrap_signer_cert_absent`,
  lotl_bootstrap_not_applicable: `${PREFIX}lotl_bootstrap_not_applicable`,
  source_anchors_from_lotl: `${PREFIX}source_anchors_from_lotl`,
  source_is_lotl: `${PREFIX}source_is_lotl`,
  source_not_in_lotl: `${PREFIX}source_not_in_lotl`,
  source_pointer_without_signer_cert: `${PREFIX}source_pointer_without_signer_cert`,
  source_fetch_failed: `${PREFIX}source_fetch_failed`,
  source_signer_cert_absent: `${PREFIX}source_signer_cert_absent`,
  source_location_unsupported: `${PREFIX}source_location_unsupported`,
};

/** The catalog key for `code`, or `undefined` when this build does not know it. */
export function trustAnchorSuggestionKey(code: string | null | undefined): MessageKey | undefined {
  return code ? TRUST_ANCHOR_SUGGESTION_KEYS[code] : undefined;
}
