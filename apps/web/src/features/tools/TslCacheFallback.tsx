/**
 * The AT-USE-TIME marker for a Trusted List verdict that came out of the **durable cache** instead
 * of off the network.
 *
 * ## Why this exists at all
 *
 * The Trusted List is fetched over the network, and when that fetch fails the installation falls
 * back to the last copy it stored. That fallback is the point — a transient egress or DNS fault
 * used to make qualified signing outright impossible — but it is not free of consequence, and the
 * consequence has to be visible where the verdict is read.
 *
 * A Trusted List is the mechanism by which a withdrawn or revoked trust service *stops* being
 * trusted. Serving one past its own `NextUpdate` therefore means a service the scheme operator has
 * since withdrawn can still read as granted. "Signature valid" and "signature valid against a list
 * that expired nine days ago" are different facts, and a screen that renders them identically is
 * the failure this component removes.
 *
 * It is deliberately additive to the existing signature badge, exactly like
 * {@link ./TslWeakAlgorithms}: the verdict is still whatever the backend said, and this states what
 * it rested on.
 *
 * ## Two tones, because there are two situations
 *
 * Inside the list's own `NextUpdate` a cached copy is ordinary — the scheme operator's document
 * says the list is valid until then, and ETSI TS 119 612 lists are *designed* to be cached until
 * it. That case gets a neutral, informational treatment: it says the network is unreachable, which
 * an operator wants to know, without implying the trust decision is doubtful.
 *
 * Past `NextUpdate` the tone is `warn`, because that is the case where the verdict may no longer
 * reflect the scheme. Not `error`: nothing failed, the list validated, and the fallback is bounded
 * — a copy more than the configured maximum past its expiry is refused rather than served, so a
 * marker on screen always means the copy was still inside that bound.
 *
 * ## One of three concerns, sharing one treatment
 *
 * This used to own both of its own pieces — a labelled status-line cell and a banner directly
 * under it. It now contributes a {@link TrustConcern} instead, and `trustConcerns.tsx` renders the
 * icon in the status line and the entry in the single banner below the lists. Nothing was dropped
 * in the move: the label and badge that were the cell's whole content became the entry's header,
 * and the title and body are the entry's heading and prose.
 *
 * It returns **nothing at all** when the field is absent, which is how the wire spells "the list
 * came live". That is what makes this a signal rather than decoration.
 */
import { DateTime } from '../../ui';
import { cacheFallbackBadgeKey, cacheFallbackSentenceKey } from '../../i18n/tslCacheFallback';
import type { TFunction } from '../../i18n';
import type { TslCacheFallbackView } from '../../api/types';
import type { TrustConcern } from './trustConcerns';

/**
 * The concern, or `null` when the verdict came off the network.
 *
 * The severity follows the backend's `stale` flag and not the code, so a code this build does not
 * recognise still lands on the cautious side whenever the server said the copy was past its
 * validity — the case where a since-withdrawn trust service can still read as granted.
 */
export function cacheFallbackConcern(
  t: TFunction,
  fallback?: TslCacheFallbackView | null,
): TrustConcern | null {
  if (!fallback) return null;
  const sentence = cacheFallbackSentenceKey(fallback.code);
  const badge = cacheFallbackBadgeKey(fallback.code);
  return {
    slug: 'cache-fallback',
    severity: fallback.stale ? 'warn' : 'info',
    label: t('trust.cacheFallback.label'),
    badge: t(badge ?? 'trust.cacheFallback.badge.stale'),
    heading: t(fallback.stale ? 'trust.cacheFallback.title.stale' : 'trust.cacheFallback.title'),
    body: (
      <>
        <p>{t(sentence ?? 'trust.cacheFallback.unknown')}</p>
        <dl className="trust-cache-fallback" data-cache-fallback={fallback.code}>
          <div>
            <dt>{t('trust.cacheFallback.fetchedAt')}</dt>
            {/* Every one of these three is a record of something having happened: evidentiary. */}
            <dd>
              <DateTime className="mono" value={fallback.fetched_at} evidentiary />
            </dd>
          </div>
          <div>
            <dt>{t('trust.cacheFallback.expiresAt')}</dt>
            <dd>
              <DateTime className="mono" value={fallback.expires_at} evidentiary />
            </dd>
          </div>
          <div>
            <dt>{t('trust.cacheFallback.servedAt')}</dt>
            <dd>
              <DateTime className="mono" value={fallback.served_at} evidentiary />
            </dd>
          </div>
        </dl>
        <p>{t('trust.cacheFallback.reason')}</p>
        {/* The transport failure verbatim, in every locale. It is a technical diagnostic whose
            whole value is that "connection timed out" and "certificate verify failed" send an
            operator to different places; translating or summarising it would remove the only
            thing it is for. */}
        <p className="mono trust-opaque">{fallback.fetch_error}</p>
      </>
    ),
  };
}
