/**
 * The **unverified transport** marker: this Trusted List is fetched from a server whose TLS
 * certificate this installation does not check, because an operator set `tls_skip_verification` on
 * its configured source.
 *
 * # Why it is here and not only on the settings page
 *
 * A settings page is read once, by whoever made the change, possibly months before anyone looks at
 * a trust verdict. The fact that a result was obtained over an unauthenticated transport is a
 * property *of that result*, so it belongs next to it — the same argument that put the cache
 * fallback and weak-algorithm markers on these surfaces. It renders for as long as the setting is
 * on, on every screen that reports a Trusted List verdict.
 *
 * # The tone, which is a deliberate decision and not an oversight
 *
 * `info`, not `warn`, and the copy does not say the list may be forged — because it may not be. A
 * Trusted List's authenticity rests on its own XML-DSig signature verified against the operator's
 * configured trust anchors. That check is mandatory, has no off switch anywhere in this product, and
 * is untouched by the transport. A substituted list still fails it and qualified signing still
 * refuses. This badge therefore appears beside a `Valid` signature verdict as the normal case, and
 * both statements are true simultaneously.
 *
 * Telling an operator their list is untrustworthy when it demonstrably authenticated would be false,
 * and false warnings are how true ones get ignored. What the copy says instead is the truth: the
 * transport is not authenticated, so somebody on the network path can serve a **genuine but older**
 * list (replay — on which a since-withdrawn service still reads as granted) or **block** the fetch,
 * and supplying the missing intermediate certificate usually removes the need for the setting at no
 * cost at all.
 */
import { unverifiedTransportSentenceKey } from '../../i18n/tslUnverifiedTransport';
import type { TFunction } from '../../i18n';
import type { TslUnverifiedTransportView } from '../../api/types';
import type { TrustConcern } from './trustConcerns';

/**
 * The concern, or `null` when the transport is authenticated.
 *
 * Absent entirely — not a green "verified" entry — in the ordinary case, so its mere presence is
 * the signal. `severity: 'info'` for the reason argued at the top of this file: the list's own
 * signature still authenticated it, and a warning tone here would contradict the `Valid` badge it
 * routinely sits beside. The body leads with the remedy and names the two residual risks rather
 * than gesturing at them.
 */
export function unverifiedTransportConcern(
  t: TFunction,
  transport?: TslUnverifiedTransportView | null,
): TrustConcern | null {
  if (!transport) return null;
  const sentence = unverifiedTransportSentenceKey(transport.code);
  return {
    slug: 'unverified-transport',
    severity: 'info',
    label: t('trust.unverifiedTransport.label'),
    badge: t('trust.unverifiedTransport.badge'),
    heading: t('trust.unverifiedTransport.title'),
    body: (
      <>
        <p>{t(sentence ?? 'trust.unverifiedTransport.unknown')}</p>
        {/* Stated explicitly, because it is the belief this entry most needs to prevent forming:
            an operator who reads "not verified" next to a Valid badge will otherwise conclude that
            the Valid badge cannot be relied upon either. */}
        <p>{t('trust.unverifiedTransport.stillAuthenticated')}</p>
        <p>{t('trust.unverifiedTransport.residualRisk')}</p>
        <p>{t('trust.unverifiedTransport.remedy')}</p>
        {/* The source id and URL verbatim, in every locale. They are the settings-document values
            an operator searches for and the host whose certificate goes unchecked; translating or
            abbreviating either would remove the only thing they are for. */}
        <p className="mono trust-opaque" data-unverified-transport={transport.code}>
          {transport.source_id}
        </p>
        <p className="mono trust-opaque">{transport.url}</p>
      </>
    ),
  };
}
