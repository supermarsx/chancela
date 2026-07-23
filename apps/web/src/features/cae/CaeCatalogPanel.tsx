/**
 * The active CAE catalog's state + "Atualizar catálogo" refresh, relocated from the
 * standalone /cae page onto the Ferramentas surface (t22-web item 3):
 *
 *  - the metadata (origin Embedded/Cache, generation stamp, per-revision node totals);
 *  - a refresh button (`POST /v1/cae/refresh`) reporting its outcomes distinctly —
 *    updated, already-current (no-op), a **422 "not configured"** that points the
 *    operator at Configurações (Documentos → Catálogo CAE), and an upstream 502.
 *
 * The 422 replaces the former env-var-only 500 copy: the update URL is now settings-
 * configurable (contract F1b), so "not configured" is a client-actionable state routed
 * to Configurações, with the server's friendly message rendered verbatim.
 */
import { Link } from 'react-router-dom';
import { useCaeCatalog, useRefreshCae } from '../../api/hooks';
import { ApiError } from '../../api/client';
import { useT } from '../../i18n';
import {
  Badge,
  Button,
  Card,
  DateTime,
  ErrorNote,
  Icon,
  SkeletonDeflist,
  useToast,
} from '../../ui';
import type { CaeLevelCounts } from '../../api/types';

/** Total nodes across all five levels of a revision. */
function totalNodes(c: CaeLevelCounts): number {
  return c.seccao + c.divisao + c.grupo + c.classe + c.subclasse;
}

/** A short summary of a refresh outcome, tone-tagged for the badge. */
function RefreshOutcome({ refresh }: { refresh: ReturnType<typeof useRefreshCae> }) {
  const t = useT();
  if (refresh.error) {
    const status = refresh.error instanceof ApiError ? refresh.error.status : 0;
    // 422 = the update URL is not configured (contract F1b) → route to Configurações.
    // 502 = the configured source failed. Anything else surfaces its message plainly.
    if (status === 422) {
      return (
        <div className="cae-refresh-note" role="status">
          <Badge tone="error">{t('cae.refresh.notConfigured.badge')}</Badge>
          <p className="muted">
            {t('cae.refresh.notConfigured.hintBefore')}{' '}
            <Link to="/settings">{t('cae.refresh.notConfigured.link')}</Link>.
          </p>
          <ErrorNote error={refresh.error} />
        </div>
      );
    }
    const heading =
      status === 502 ? t('cae.refresh.sourceUnavailable.badge') : t('cae.refresh.failed.badge');
    const hint = status === 502 ? t('cae.refresh.sourceUnavailable.hint') : null;
    return (
      <div className="cae-refresh-note" role="status">
        <Badge tone="error">{heading}</Badge>
        {hint ? <p className="muted">{hint}</p> : null}
        <ErrorNote error={refresh.error} />
      </div>
    );
  }
  if (refresh.data) {
    return (
      <div className="cae-refresh-note" role="status">
        {refresh.data.updated ? (
          <>
            <Badge tone="ok">{t('cae.refresh.updated.badge')}</Badge>
            <p className="muted">{refresh.data.note}</p>
          </>
        ) : (
          <>
            <Badge tone="neutral">{t('cae.refresh.upToDate.badge')}</Badge>
            <p className="muted">{t('cae.refresh.upToDate.hint')}</p>
          </>
        )}
      </div>
    );
  }
  return null;
}

export function CaeCatalogPanel() {
  const t = useT();
  const toast = useToast();
  const catalog = useCaeCatalog();
  const refresh = useRefreshCae();

  // R7: the inline RefreshOutcome note (role=status, with the 422/502 distinctions) stays;
  // the toast is additive and keeps the updated-vs-no-op distinction.
  function onRefresh() {
    refresh.mutate(undefined, {
      onSuccess: (result) =>
        toast.success(result.updated ? t('toast.cae.refreshed') : t('toast.cae.upToDate')),
      onError: (e) => toast.error(e),
    });
  }

  return (
    <Card
      title={t('cae.catalog.title')}
      actions={
        <Button
          type="button"
          variant="secondary"
          icon={<Icon.Refresh />}
          disabled={refresh.isPending}
          onClick={onRefresh}
        >
          {refresh.isPending ? t('cae.refresh.button.pending') : t('cae.refresh.button')}
        </Button>
      }
    >
      {catalog.isLoading ? (
        <SkeletonDeflist rows={4} />
      ) : catalog.error ? (
        <ErrorNote error={catalog.error} />
      ) : catalog.data ? (
        <div className="stack--tight">
          <dl className="deflist">
            <div>
              <dt>{t('cae.catalog.origin.label')}</dt>
              <dd>
                <Badge tone={catalog.data.origin === 'Cache' ? 'accent' : 'neutral'}>
                  {catalog.data.origin === 'Cache'
                    ? t('cae.catalog.origin.cache')
                    : t('cae.catalog.origin.embedded')}
                </Badge>
              </dd>
            </div>
            <div>
              <dt>{t('cae.catalog.generatedAt.label')}</dt>
              {/* The catalog's generation stamp is provenance for the codes below it —
                  evidentiary, with the exact instant kept in the `datetime` attribute. */}
              <dd>
                <DateTime value={catalog.data.generated_at} evidentiary className="mono" />
              </dd>
            </div>
            <div>
              <dt>{t('cae.catalog.rev4Total.label')}</dt>
              <dd className="mono">{totalNodes(catalog.data.counts.rev4)}</dd>
            </div>
            <div>
              <dt>{t('cae.catalog.rev3Total.label')}</dt>
              <dd className="mono">{totalNodes(catalog.data.counts.rev3)}</dd>
            </div>
          </dl>
          {catalog.data.source_note ? (
            <p className="muted cae-source-note">{catalog.data.source_note}</p>
          ) : null}
          <RefreshOutcome refresh={refresh} />
        </div>
      ) : null}
    </Card>
  );
}
