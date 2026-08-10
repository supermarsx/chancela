/**
 * Client-side code → catalog-key map for **connector probe failures**.
 *
 * # The problem this closes
 *
 * `48e3590e` added a stable `error_code` to `ConnectorError` *specifically* so a client could
 * translate the failure — and then nothing consumed it. `ConnectorOperations.tsx` rendered the
 * server's English `error` sentence verbatim, so a pt-PT operator whose build lacks a transport
 * read `this build was compiled without the s3 transport…` in English, under a fully translated
 * heading. No CI gate could have caught it: `noLiteralUiCopy` and `catalogLeakGate` inspect the web
 * app and are blind by construction to a sentence that arrives over the wire.
 *
 * `codes.rs` also *claimed* the guard that would have caught it — "a client-side guard can prove
 * every code maps to a catalog key". {@link connectorErrorCodes.test.ts} is that guard; before it
 * existed the sentence was aspirational.
 *
 * # The shape, and why it is this shape
 *
 * Exactly the one {@link providerProbeDiagnostics} uses, for the same reason: **the wire stays
 * English and stable, and the client maps a stable identifier to a catalog key.** The server sends
 * `error_code` alongside — never instead of — `error`, so the English sentence is still on the wire
 * and still in the audit log for a client that does not know the code.
 *
 * Two completeness guards, in the order they fire:
 *
 * 1. every mapped value is a real `MessageKey` literal, so `tsc` rejects a typo or a key the
 *    catalog is missing;
 * 2. `connectorErrorCodes.test.ts` reads `crates/chancela-connectors/src/codes.rs` and proves every
 *    code the Rust side can emit is mapped here, and that nothing here is stale — so a
 *    backend-added code fails loudly rather than silently rendering English again.
 *
 * Nothing here is positional: every code is an explicit identifier, so reordering
 * `ALL_GATED_TRANSPORTS` cannot desynchronise this file.
 *
 * # One sentence per transport, and no interpolation
 *
 * `codes.rs` declares one code per transport rather than one code with a `{transport}` parameter,
 * and this file inherits that on purpose. A bare `S3` dropped into an inflected sentence cannot
 * agree with the article or preposition around it in most of the fourteen locales; four sentences
 * that read correctly beat one that reads correctly in English only.
 *
 * # What stays verbatim
 *
 * The cargo feature name (`s3`, `sftp`, `smb`, `ftps`) and the crate name are machine identifiers —
 * what an operator types into a build command — so they reach every locale untranslated, quoted in
 * that locale's own quotation marks. The same rule the probe diagnostics' `detail_params` and the
 * `CHANCELA_*` variable names already follow.
 *
 * # What this does NOT cover
 *
 * `ConnectorStatusView.detail`, the sentence a *successful* probe returns, is also server-written
 * English and has no code vocabulary at all. Giving it one is a backend change, not a mapping, so
 * it is deliberately out of scope here rather than half-covered.
 */
import type { ConnectorProbeErrorCode } from '../api/types';
import type { MessageKey } from './types';

/** The catalog-key prefix every connector failure sentence lives under. */
const PREFIX = 'operations.connectors.probe.errorCode.';

/**
 * Every error code a connector probe can emit, mapped to its translated sentence.
 *
 * Ordered as `ALL_GATED_TRANSPORTS` in `codes.rs`, so the two read side by side. Adding a code to
 * that file without adding it here fails `connectorErrorCodes.test.ts`.
 */
export const CONNECTOR_ERROR_KEYS: Record<string, MessageKey> = {
  transport_not_compiled_s3: `${PREFIX}transport_not_compiled_s3`,
  transport_not_compiled_sftp: `${PREFIX}transport_not_compiled_sftp`,
  transport_not_compiled_smb: `${PREFIX}transport_not_compiled_smb`,
  transport_not_compiled_ftps: `${PREFIX}transport_not_compiled_ftps`,
};

/**
 * The catalog key for a connector error code, or `undefined` for a code this build does not know.
 *
 * `undefined` is a real outcome, not a defect to be papered over: a server newer than this bundle
 * can emit a code that did not exist when these translations were written, and most connector
 * failures still carry no code at all. See {@link resolveConnectorError} for what the caller does.
 */
export function connectorErrorKey(code: string | null | undefined): MessageKey | undefined {
  return code ? CONNECTOR_ERROR_KEYS[code] : undefined;
}

/** What to render for a failed probe, and whether it is the operator's language. */
export interface ResolvedConnectorError {
  /** The sentence to show. */
  text: string;
  /**
   * `true` when `text` is the server's raw English because the code was unknown or absent. The
   * caller MUST surface this — a fallback that looks identical to a translation would pass English
   * off as localized copy, and would make the next backend-added code invisible instead of loud.
   */
  untranslated: boolean;
}

/**
 * Resolve a probe's failure into the operator's language.
 *
 * `null` when the probe reported no failure — the caller has a status to render instead, and an
 * empty error note would be worse than none. Otherwise never blank, never a crash, and never a
 * silent lie: an unknown or absent `error_code` yields the server's own English with
 * `untranslated: true`, so the UI can mark it as such (and tag it `lang="en"`, which is also what
 * makes a screen reader pronounce it correctly).
 */
export function resolveConnectorError(
  probe: { error: string | null; error_code: ConnectorProbeErrorCode | null },
  t: (key: MessageKey) => string,
): ResolvedConnectorError | null {
  if (!probe.error) return null;
  const key = connectorErrorKey(probe.error_code);
  if (!key) return { text: probe.error, untranslated: true };
  return { text: t(key), untranslated: false };
}
