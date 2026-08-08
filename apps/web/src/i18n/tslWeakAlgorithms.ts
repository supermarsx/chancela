/**
 * Client-side code → catalog-key map for the **Trusted List weak-algorithm diagnostics**, and the
 * label map for the three algorithms an operator may enable.
 *
 * # Why a map rather than server prose
 *
 * The backend deliberately emits no sentence here. `chancela_tsl::WeakAlgorithmUse` carries a
 * stable `code`, the exact algorithm URI, and a structured position — nothing translatable — for
 * the reason `providerProbeDiagnostics.ts` documents at length: `noLiteralUiCopy` and
 * `catalogLeakGate` inspect the web app and are blind by construction to a sentence that arrives
 * over the wire, so a server-authored English string would reach a Portuguese operator with no gate
 * able to see it. The wording lives here, in all fourteen catalogs.
 *
 * Two completeness guards, in the order they fire:
 *
 * 1. every mapped value is a real `MessageKey` literal, so `tsc` rejects a typo or a missing key;
 * 2. `tslWeakAlgorithms.test.ts` reads `crates/chancela-tsl/src/xmldsig.rs` and proves both closed
 *    sets — the two `CODE_*` constants and `KNOWN_LEGACY_ALGORITHMS` — are exactly what is mapped
 *    here, so a backend-added code or algorithm fails loudly instead of rendering a blank.
 *
 * # What is NOT translated, and must never be
 *
 * The algorithm **URI**. It is a machine identifier — the exact string the operator's settings
 * document holds and the exact string a 422 names — so it reaches every locale verbatim, the same
 * rule the probe's `detail_params` and the DPIA `no_claims` flags already follow. The translated
 * label ("SHA-1 digest") sits beside it, never instead of it.
 *
 * The URI is also never interpolated into an inflected sentence: it is rendered as its own token
 * next to the sentence. Dropping a noun into a clause whose article or adjective has to agree with
 * it is the failure mode `i18n-interpolated-nouns-break-agreement` exists to prevent, and a URI
 * has no gender in any of the fourteen languages.
 */
import { TSL_LEGACY_ALGORITHMS, TSL_WEAK_ALGORITHM_CODES } from '../api/types';
import type { TslLegacyAlgorithm, TslWeakAlgorithmCode, WeakAlgorithmUse } from '../api/types';
import type { MessageKey } from './types';

/** The catalog-key prefix for the three algorithm labels on the settings screen. */
const ALGORITHM_PREFIX = 'settings.signing.tslLegacy.algorithm.';

/**
 * Every enable-able broken algorithm, mapped to its human label.
 *
 * Keyed by the exact wire URI, so there is no second identifier to keep in step — the key IS the
 * value that goes over the wire. Ordered as `KNOWN_LEGACY_ALGORITHMS` in `xmldsig.rs`, which is
 * also the order the checkboxes render in.
 */
export const TSL_LEGACY_ALGORITHM_LABEL_KEYS: Record<TslLegacyAlgorithm, MessageKey> = {
  'http://www.w3.org/2000/09/xmldsig#sha1': `${ALGORITHM_PREFIX}sha1`,
  'http://www.w3.org/2000/09/xmldsig#rsa-sha1': `${ALGORITHM_PREFIX}rsaSha1`,
  'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1': `${ALGORITHM_PREFIX}ecdsaSha1`,
};

/**
 * Every weak-algorithm code the server can emit, mapped to the sentence naming what was relied
 * upon. The two codes say different things — a reference's digest versus the signature over
 * `<ds:SignedInfo>` itself — and collapsing them into one sentence would lose the distinction the
 * backend went to the trouble of reporting.
 */
export const TSL_WEAK_ALGORITHM_SENTENCE_KEYS: Record<TslWeakAlgorithmCode, MessageKey> = {
  tsl_weak_digest_permitted: 'trust.weakAlgorithms.digest',
  tsl_weak_signature_method_permitted: 'trust.weakAlgorithms.signatureMethod',
};

/** Whether this URI is one the settings control may offer. Narrows for the checkbox list. */
export function isKnownLegacyAlgorithm(uri: string): uri is TslLegacyAlgorithm {
  return (TSL_LEGACY_ALGORITHMS as readonly string[]).includes(uri);
}

/** Whether this is a weak-algorithm code this build knows how to word. */
export function isKnownWeakAlgorithmCode(code: string): code is TslWeakAlgorithmCode {
  return (TSL_WEAK_ALGORITHM_CODES as readonly string[]).includes(code);
}

/**
 * The catalog key for one use's sentence, or `undefined` for a code this build does not know.
 *
 * `undefined` is a real outcome and not a defect to paper over: a server newer than this bundle can
 * emit a code that did not exist when these translations were written. The caller renders
 * `trust.weakAlgorithms.unknown` in its place — which still says a broken algorithm was relied
 * upon, because that much is certain from the code's mere presence, and only declines to say which
 * kind. Falling back to *silence* would turn a newer backend into a missing warning.
 */
export function weakAlgorithmSentenceKey(code: string): MessageKey | undefined {
  return isKnownWeakAlgorithmCode(code) ? TSL_WEAK_ALGORITHM_SENTENCE_KEYS[code] : undefined;
}

/**
 * The label key for one algorithm URI, or `undefined` when the URI is not one of the three.
 *
 * Unknown is reachable only through a hand-edited settings document — the server refuses any other
 * URI at save — and the caller shows the raw URI rather than dropping it. Dropping is the failure
 * `reject-never-silently-transform` names: a settings screen that quietly stops displaying a value
 * the deployment is actually running on.
 */
export function legacyAlgorithmLabelKey(uri: string): MessageKey | undefined {
  return isKnownLegacyAlgorithm(uri) ? TSL_LEGACY_ALGORITHM_LABEL_KEYS[uri] : undefined;
}

/**
 * Split a settings document's `tsl_legacy_algorithms` into the URIs the checkbox list owns and the
 * ones it does not recognise.
 *
 * The second bucket is what stops this control from silently rewriting the operator's settings: an
 * unrecognised entry is preserved through a save rather than dropped by a control that could not
 * draw it, and the screen says so.
 */
export function partitionLegacyAlgorithms(uris: readonly string[]): {
  known: TslLegacyAlgorithm[];
  unknown: string[];
} {
  const known: TslLegacyAlgorithm[] = [];
  const unknown: string[] = [];
  for (const uri of uris) {
    if (isKnownLegacyAlgorithm(uri)) known.push(uri);
    else unknown.push(uri);
  }
  return { known, unknown };
}

/**
 * Is this verdict's weak-algorithm list non-empty?
 *
 * A one-line helper only because the field is optional on the wire (`skip_serializing_if`), and
 * every call site would otherwise repeat the `?? []`. Absent and empty mean the same thing —
 * validated under strong algorithms alone — and that equivalence should be written once.
 */
export function hasWeakAlgorithms(uses: readonly WeakAlgorithmUse[] | undefined): boolean {
  return (uses?.length ?? 0) > 0;
}
