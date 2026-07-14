/**
 * Arquivo — the append-only ledger with its verify status. The chain-valid badge
 * comes from `GET /v1/ledger/verify`; the table lazily pages
 * `GET /v1/ledger/events/page` newest-first. The filter block narrows both the feed
 * and archive exports on the server.
 */
import { useDeferredValue, useMemo, useState } from 'react';
import {
  useDownloadLedgerArchiveDocument,
  useLedgerPages,
  useLedgerIntegrity,
  useLedgerVerify,
} from '../../api/hooks';
import type {
  LedgerArchiveDocumentFormat,
  LedgerArchiveDocumentParams,
  LedgerQueryParams,
} from '../../api/types';
import { useT, type TFunction } from '../../i18n';
import { saveBlobAs, saveBlobResultMessage, type SaveBlobResult } from '../../desktop/saveFile';
import {
  Badge,
  Button,
  Card,
  EmptyState,
  ErrorNote,
  Field,
  IconButton,
  Icon,
  Input,
  PageHeader,
  Select,
  SkeletonTable,
  useToast,
} from '../../ui';
import { LedgerTable } from './LedgerTable';

const DEFAULT_PAGE_LIMIT = 100;

interface LedgerFilters {
  search: string;
  chain: string;
  scope: string;
  kind: string;
  actor: string;
  from: string;
  to: string;
  limit: number;
}

const INITIAL_FILTERS: LedgerFilters = {
  search: '',
  chain: '',
  scope: '',
  kind: '',
  actor: '',
  from: '',
  to: '',
  limit: DEFAULT_PAGE_LIMIT,
};

function trimParam(value: string): string | undefined {
  const trimmed = value.trim();
  return trimmed ? trimmed : undefined;
}

function filteredParams(filters: LedgerFilters): LedgerQueryParams {
  return {
    order: 'desc',
    limit: filters.limit,
    ...(trimParam(filters.search) ? { q: trimParam(filters.search) } : {}),
    ...(filters.chain ? { chain: filters.chain } : {}),
    ...(trimParam(filters.scope) ? { scope: trimParam(filters.scope) } : {}),
    ...(trimParam(filters.kind) ? { kind: trimParam(filters.kind) } : {}),
    ...(trimParam(filters.actor) ? { actor: trimParam(filters.actor) } : {}),
    ...(filters.from ? { from: filters.from } : {}),
    ...(filters.to ? { to: filters.to } : {}),
  };
}

function shortId(id: string | undefined): string {
  return id ? id.slice(0, 8) : '';
}

function chainLabel(chain: string, t: TFunction): string {
  if (chain === 'application') return t('ledger.chain.application');
  const [kind, id] = chain.split(':', 2);
  if (kind === 'book') return t('ledger.chain.book', { id: shortId(id) });
  if (kind === 'company') return t('ledger.chain.company', { id: shortId(id) });
  return chain;
}

function slug(value: string): string {
  return (
    value
      .normalize('NFD')
      .replace(/[\u0300-\u036f]/g, '')
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '') || 'global'
  );
}

function archiveFilename(params: LedgerArchiveDocumentParams): string {
  const chain = params.chain ? slug(params.chain) : 'global';
  const scope = params.scope ? `-${slug(params.scope)}` : '';
  const format = params.format ?? 'pdfa';
  const extension = format === 'pdfa' ? 'pdf' : format;
  return `arquivo-${chain}${scope}.${extension}`;
}

function exportContentType(format: LedgerArchiveDocumentFormat): string {
  switch (format) {
    case 'json':
      return 'application/json';
    case 'txt':
      return 'text/plain;charset=utf-8';
    case 'csv':
      return 'text/csv;charset=utf-8';
    case 'html':
      return 'text/html;charset=utf-8';
    case 'pdfa':
    default:
      return 'application/pdf';
  }
}

function countActiveFilters(filters: LedgerFilters): number {
  let count = 0;
  if (filters.chain !== '') count += 1;
  if (filters.search.trim() !== '') count += 1;
  if (filters.scope.trim() !== '') count += 1;
  if (filters.kind.trim() !== '') count += 1;
  if (filters.actor.trim() !== '') count += 1;
  if (filters.from !== '') count += 1;
  if (filters.to !== '') count += 1;
  if (filters.limit !== DEFAULT_PAGE_LIMIT) count += 1;
  return count;
}

function isActiveFilterDefault(filters: LedgerFilters): boolean {
  return (
    filters.chain === INITIAL_FILTERS.chain &&
    filters.search === INITIAL_FILTERS.search &&
    filters.scope === INITIAL_FILTERS.scope &&
    filters.kind === INITIAL_FILTERS.kind &&
    filters.actor === INITIAL_FILTERS.actor &&
    filters.from === INITIAL_FILTERS.from &&
    filters.to === INITIAL_FILTERS.to &&
    filters.limit === INITIAL_FILTERS.limit
  );
}

export function LedgerPage() {
  const t = useT();
  const toast = useToast();
  const [filters, setFilters] = useState<LedgerFilters>(INITIAL_FILTERS);
  const deferredSearch = useDeferredValue(filters.search);
  const [archiveFormat, setArchiveFormat] = useState<LedgerArchiveDocumentFormat>('pdfa');
  const verify = useLedgerVerify();
  const integrity = useLedgerIntegrity();
  const downloadArchive = useDownloadLedgerArchiveDocument();
  const ledgerParams = useMemo(
    () => filteredParams({ ...filters, search: deferredSearch }),
    [deferredSearch, filters],
  );
  const eventsQuery = useLedgerPages(ledgerParams);
  const pages = eventsQuery.data?.pages ?? [];
  const events = pages.flatMap((page) => page.events);
  const activeFilterCount = countActiveFilters(filters);
  const activeFilters = activeFilterCount > 0;
  const chainOptions = useMemo(() => {
    const options = [{ value: '', label: t('ledger.chain.global') }];
    const seen = new Set(['global']);
    for (const status of integrity.data?.chains ?? []) {
      if (seen.has(status.chain)) continue;
      seen.add(status.chain);
      options.push({ value: status.chain, label: chainLabel(status.chain, t) });
    }
    if (filters.chain && !seen.has(filters.chain)) {
      options.push({ value: filters.chain, label: chainLabel(filters.chain, t) });
    }
    return options;
  }, [filters.chain, integrity.data?.chains, t]);
  const limitOptions = useMemo(
    () => [
      { value: '25', label: '25' },
      { value: '50', label: '50' },
      { value: '100', label: '100' },
      { value: '250', label: '250' },
    ],
    [],
  );
  const archiveFormatOptions = useMemo(
    () => [
      { value: 'pdfa', label: t('ledger.archive.format.pdfa') },
      { value: 'txt', label: t('ledger.archive.format.txt') },
      { value: 'json', label: t('ledger.archive.format.json') },
      { value: 'csv', label: t('ledger.archive.format.csv') },
      { value: 'html', label: t('ledger.archive.format.html') },
    ],
    [t],
  );

  function showSaveResult(result: SaveBlobResult) {
    if (result.kind === 'cancelled') {
      toast.info(saveBlobResultMessage(result));
      return;
    }
    toast.success(saveBlobResultMessage(result));
  }

  function updateFilter(patch: Partial<LedgerFilters>) {
    setFilters((current) => ({ ...current, ...patch }));
  }

  function onDownloadArchive() {
    const params = { ...filteredParams(filters), format: archiveFormat };
    downloadArchive.mutate(params, {
      onSuccess: async (blob) => {
        try {
          showSaveResult(
            await saveBlobAs({
              blob,
              filename: archiveFilename(params),
              contentType: exportContentType(archiveFormat),
              preferBrowserSavePicker: true,
            }),
          );
        } catch (e) {
          toast.error(e);
        }
      },
      onError: (e) => toast.error(e),
    });
  }

  const resultStatus = eventsQuery.hasNextPage
    ? t('ledger.status.loadedMore', { shown: events.length })
    : t('ledger.status.loaded', { shown: events.length });

  return (
    <div className="stack">
      <PageHeader title={t('ledger.page.title')} />

      <div className="row-wrap">
        <div className="chain-status">
          <span className="card__label">{t('ledger.integrity.label')}</span>{' '}
          {verify.isLoading ? (
            <Badge tone="neutral">{t('ledger.verify.checking')}</Badge>
          ) : verify.data?.valid ? (
            <Badge tone="ok">{t('ledger.chain.verified', { count: verify.data.length })}</Badge>
          ) : (
            <Badge tone="error">{t('ledger.chain.compromised')}</Badge>
          )}
        </div>
      </div>

      <Card
        title={t('ledger.events.title')}
        actions={
          <div className="ledger-export-controls">
            <Field
              label={t('ledger.archive.format.label')}
              htmlFor="ledger-export-format"
              help={t('ledger.archive.format.help')}
            >
              <Select
                id="ledger-export-format"
                options={archiveFormatOptions}
                value={archiveFormat}
                onChange={(e) => setArchiveFormat(e.target.value as LedgerArchiveDocumentFormat)}
              />
            </Field>
            <Button
              type="button"
              variant="primary"
              icon={<Icon.Archive />}
              disabled={downloadArchive.isPending}
              onClick={onDownloadArchive}
            >
              {downloadArchive.isPending
                ? t('ledger.archive.downloading')
                : t('ledger.archive.export')}
            </Button>
          </div>
        }
      >
        <div className="stack">
          <div
            className="stack--tight ledger-filters"
            role="search"
            aria-label={t('ledger.filters.aria')}
          >
            <div className="ledger-filterbar filter">
              <div className="ledger-filterbar__primary">
                <Field label={t('books.filters.search.label')} htmlFor="ledger-search">
                  <Input
                    id="ledger-search"
                    type="search"
                    placeholder={t('ledger.search.placeholder')}
                    value={filters.search}
                    onChange={(e) => updateFilter({ search: e.target.value })}
                  />
                </Field>
                <Field label={t('ledger.chain.label')} htmlFor="ledger-chain">
                  <Select
                    id="ledger-chain"
                    options={chainOptions}
                    value={filters.chain}
                    onChange={(e) => updateFilter({ chain: e.target.value })}
                  />
                </Field>
                <Field label={t('ledger.scope.label')} htmlFor="ledger-scope">
                  <Input
                    id="ledger-scope"
                    type="search"
                    placeholder={t('ledger.scope.placeholder')}
                    value={filters.scope}
                    onChange={(e) => updateFilter({ scope: e.target.value })}
                  />
                </Field>
                <IconButton
                  className="ledger-filterbar__clear"
                  icon={<Icon.FilterClear />}
                  label={t('ledger.filters.clear.aria')}
                  disabled={!activeFilters}
                  onClick={() => {
                    if (!isActiveFilterDefault(filters)) setFilters(INITIAL_FILTERS);
                  }}
                />
              </div>
            </div>

            <details className="ledger-advanced-filters filter-advanced">
              <summary>{t('ledger.filters.advanced')}</summary>
              <div className="ledger-advanced-filters__body filter filter-advanced__body">
                <Field label={t('ledger.kind.label')} htmlFor="ledger-kind">
                  <Input
                    id="ledger-kind"
                    placeholder={t('ledger.kind.placeholder')}
                    value={filters.kind}
                    onChange={(e) => updateFilter({ kind: e.target.value })}
                  />
                </Field>
                <Field label={t('ledger.actor.label')} htmlFor="ledger-actor">
                  <Input
                    id="ledger-actor"
                    placeholder={t('ledger.actor.placeholder')}
                    value={filters.actor}
                    onChange={(e) => updateFilter({ actor: e.target.value })}
                  />
                </Field>
                <Field label={t('ledger.from.label')} htmlFor="ledger-from">
                  <Input
                    id="ledger-from"
                    type="date"
                    value={filters.from}
                    onChange={(e) => updateFilter({ from: e.target.value })}
                  />
                </Field>
                <Field label={t('ledger.to.label')} htmlFor="ledger-to">
                  <Input
                    id="ledger-to"
                    type="date"
                    value={filters.to}
                    onChange={(e) => updateFilter({ to: e.target.value })}
                  />
                </Field>
                <Field label={t('ledger.limit.label')} htmlFor="ledger-limit">
                  <Select
                    id="ledger-limit"
                    value={String(filters.limit)}
                    options={limitOptions}
                    onChange={(e) => updateFilter({ limit: Number(e.target.value) })}
                  />
                </Field>
              </div>
            </details>
          </div>

          {!eventsQuery.isLoading && !eventsQuery.error ? (
            <div className="ledger-resultbar">
              <Badge tone="accent">{t('ledger.order.newestFirst')}</Badge>
              <Badge>{t('ledger.filters.activeCount', { count: activeFilterCount })}</Badge>
              <span aria-label={resultStatus}>
                <Badge>{resultStatus}</Badge>
              </span>
            </div>
          ) : null}

          {eventsQuery.isLoading ? (
            <SkeletonTable cols={7} />
          ) : eventsQuery.error ? (
            <ErrorNote error={eventsQuery.error} />
          ) : events.length === 0 && activeFilters ? (
            <EmptyState title={t('ledger.filteredEmpty.title')}>
              {t('ledger.filteredEmpty.body')}
            </EmptyState>
          ) : (
            <>
              <LedgerTable events={events} showChains />
              {eventsQuery.hasNextPage ? (
                <div className="ledger-load-more">
                  <Button
                    type="button"
                    icon={<Icon.ArrowDown />}
                    disabled={eventsQuery.isFetchingNextPage}
                    onClick={() => void eventsQuery.fetchNextPage()}
                  >
                    {eventsQuery.isFetchingNextPage
                      ? t('ledger.loadMore.loading')
                      : t('ledger.loadMore')}
                  </Button>
                </div>
              ) : null}
            </>
          )}
        </div>
      </Card>
    </div>
  );
}
