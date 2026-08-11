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
 * ## Two pieces, two distances
 *
 * {@link TslCacheFallbackStatuslineItem} is a labelled cell in the status line an operator scans;
 * it answers "is there anything to look at here". {@link TslCacheFallbackNotice} is the banner
 * below it that answers "what exactly", naming when the cached list was fetched, when it expired,
 * when the cache was consulted, and why the fetch failed.
 *
 * The status-line piece renders its own labelled cell rather than a bare badge: two badges dropped
 * side by side in one cell are separated only by a CSS `gap`, which inserts no character, so a
 * screen reader and find-in-page both read them fused into one word.
 *
 * Both render **nothing at all** when the field is absent, which is how the wire spells "the list
 * came live". That is what makes this a signal rather than decoration.
 */
import { Badge, DateTime, InlineWarning } from '../../ui';
import { useT } from '../../i18n';
import { cacheFallbackBadgeKey, cacheFallbackSentenceKey } from '../../i18n/tslCacheFallback';
import type { TslCacheFallbackView } from '../../api/types';

/**
 * A compact marker for a `.trust-statusline`: this verdict was decided from a cached list.
 *
 * Renders nothing when it was not — including when the field is absent.
 */
export function TslCacheFallbackStatuslineItem({
  fallback,
}: {
  fallback?: TslCacheFallbackView | null;
}) {
  const t = useT();
  if (!fallback) return null;
  const badge = cacheFallbackBadgeKey(fallback.code);
  return (
    <div className="trust-statusline__item" data-cache-fallback={fallback.code}>
      <span className="trust-statusline__label">{t('trust.cacheFallback.label')}</span>
      <Badge tone={fallback.stale ? 'warn' : 'neutral'}>
        {t(badge ?? 'trust.cacheFallback.badge.stale')}
      </Badge>
    </div>
  );
}

/**
 * The full banner: which cached list answered, how old it is, and what the network said.
 *
 * No `notice` key, so there is no dismiss control: this is a property of the verdict on screen, not
 * an announcement, and it must come back the next time the same thing happens.
 */
export function TslCacheFallbackNotice({ fallback }: { fallback?: TslCacheFallbackView | null }) {
  const t = useT();
  if (!fallback) return null;
  const sentence = cacheFallbackSentenceKey(fallback.code);
  return (
    <InlineWarning
      tone={fallback.stale ? 'warn' : 'info'}
      title={t(fallback.stale ? 'trust.cacheFallback.title.stale' : 'trust.cacheFallback.title')}
    >
      <p>{t(sentence ?? 'trust.cacheFallback.unknown')}</p>
      <dl className="trust-cache-fallback">
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
      {/* The transport failure verbatim, in every locale. It is a technical diagnostic whose whole
          value is that "connection timed out" and "certificate verify failed" send an operator to
          different places; translating or summarising it would remove the only thing it is for. */}
      <p className="mono trust-opaque">{fallback.fetch_error}</p>
    </InlineWarning>
  );
}
