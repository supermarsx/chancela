/**
 * Client-side code → catalog-key map for the **unverified transport** marker.
 *
 * # Why a map rather than server prose
 *
 * The same reason as `tslCacheFallback.ts` and `tslWeakAlgorithms.ts`: the backend emits a stable
 * `code` plus the source id and URL, and nothing translatable. `noLiteralUiCopy` and
 * `catalogLeakGate` inspect the web app and are blind by construction to a sentence that arrives
 * over the wire, so a server-authored English string would reach a Portuguese operator with no gate
 * able to see it. The wording lives here, in all fourteen catalogs.
 *
 * # The distinction the wording must preserve, and it is the hard one
 *
 * This marker means **the transport was not authenticated**. It does *not* mean the list is
 * untrustworthy, and copy that implies otherwise would be false. A Trusted List's authenticity comes
 * from its own XML-DSig signature checked against the operator's configured trust anchors; that
 * check is mandatory, cannot be switched off anywhere in this product, and is unaffected by the
 * transport. A forged list still fails it. The badge therefore sits beside a `Valid` signature
 * verdict routinely, and both are true at once.
 *
 * What an attacker on the network path actually gains is worth naming precisely, because vagueness
 * here is what makes a warning ignorable: they can serve a **genuine but older** list — which
 * authenticates perfectly, being genuine, and on which a trust service the scheme operator has since
 * withdrawn still reads as granted — and they can **block** the fetch. Those two, and not "the list
 * may be fake".
 *
 * False alarms train people to ignore true ones, which is why the tone here is `info` rather than
 * `warn` and why the copy leads with the remedy: supplying the missing intermediate certificate
 * usually removes the need for this setting entirely, at no cost.
 */
import { TSL_UNVERIFIED_TRANSPORT_CODES } from '../api/types';
import type { TslUnverifiedTransportCode } from '../api/types';
import type { MessageKey } from './types';

/** Every unverified-transport code the server can emit, mapped to its explanatory sentence. */
export const TSL_UNVERIFIED_TRANSPORT_SENTENCE_KEYS: Record<
  TslUnverifiedTransportCode,
  MessageKey
> = {
  tsl_transport_not_verified: 'trust.unverifiedTransport.body',
};

/** Whether this is an unverified-transport code this build knows how to word. */
export function isKnownUnverifiedTransportCode(code: string): code is TslUnverifiedTransportCode {
  return (TSL_UNVERIFIED_TRANSPORT_CODES as readonly string[]).includes(code);
}

/**
 * The catalog key for the marker's sentence, or `undefined` for a code this build does not know.
 *
 * `undefined` is a real outcome rather than a defect: a server newer than this bundle can emit a
 * code that did not exist when these translations were written. The caller renders
 * `trust.unverifiedTransport.unknown` in its place, which still says the transport was not
 * authenticated — that much is certain from the marker's mere presence. Falling back to silence
 * would turn a newer backend into a missing disclosure.
 */
export function unverifiedTransportSentenceKey(code: string): MessageKey | undefined {
  return isKnownUnverifiedTransportCode(code)
    ? TSL_UNVERIFIED_TRANSPORT_SENTENCE_KEYS[code]
    : undefined;
}
