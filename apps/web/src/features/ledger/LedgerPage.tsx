/**
 * Arquivo — the append-only ledger, split into two deep-linkable sub-tabs through the shared
 * `<SubNav>` primitive and the path-segment convention `SettingsPage`/`BookDetailPage` already
 * use — `/archive/export` (Registo is the default and owns the bare `/archive`):
 *
 *  - **Registo** — the ledger itself: the chain-valid badge from `GET /v1/ledger/verify`, the
 *    filter block, and the table lazily paging `GET /v1/ledger/events/page` newest-first.
 *  - **Exportação** — every export this surface offers, with the options each one genuinely
 *    accepts. The ledger-document export still reads the Registo filters (they narrow it on the
 *    server), so the filter state lives here on the page and both tabs share it.
 */
import { useDeferredValue, useMemo, useState } from 'react';
import {
  useBooks,
  useDownloadBookArchivePackage,
  useDownloadLedgerArchiveDocument,
  useEntities,
  useExportBook,
  useLedgerPages,
  useLedgerIntegrity,
  useLedgerVerify,
} from '../../api/hooks';
import type {
  BookKind,
  BookView,
  LedgerArchiveDocumentFormat,
  LedgerArchiveDocumentParams,
  LedgerArchiveDocumentScope,
  LedgerQueryParams,
} from '../../api/types';
import { BOOK_KINDS } from '../../api/types';
import { bookKindLabels } from '../../api/labels';
import { abbreviateId } from './scopeLabel';
import { useT, type TFunction } from '../../i18n';
import { saveBlobAs, saveBlobResultMessage, type SaveBlobResult } from '../../desktop/saveFile';
import {
  GateButton,
  PermissionDeniedNote,
  scopeBook,
  usePermissions,
} from '../session/permissions';
import {
  Badge,
  Button,
  Card,
  EmptyState,
  ErrorNote,
  Field,
  IconButton,
  Icon,
  InlineWarning,
  Input,
  PageHeader,
  Select,
  SkeletonList,
  SkeletonTable,
  SkeletonRegion,
  SubNav,
  Table,
  Toggle,
  useToast,
} from '../../ui';
import { useSectionNav } from '../../app/navPath';
import { LedgerTable } from './LedgerTable';

const DEFAULT_PAGE_LIMIT = 100;

/** The two Arquivo sub-tabs. `registo` is the default and owns the bare `/archive`. */
const LEDGER_SECTIONS = ['register', 'export'] as const;
type LedgerSection = (typeof LEDGER_SECTIONS)[number];

function isLedgerSection(value: string | undefined): value is LedgerSection {
  return value !== undefined && (LEDGER_SECTIONS as readonly string[]).includes(value);
}

/** An unknown segment falls back to Registo rather than blanking the panel. */
const parseLedgerSection = (raw: string | undefined): LedgerSection =>
  isLedgerSection(raw) ? raw : 'register';

/**
 * The two per-book ZIP profiles, spelled out because picking the wrong one is a real operator
 * error: the preservation package is a read-only archival/evidence deposit that the importer does
 * NOT accept, the bundle is the portability format that it does.
 */
const PRESERVATION_PACKAGE_PROFILE = 'chancela-internal-preservation-package/v1';
const BOOK_BUNDLE_PROFILE = 'chancela-book-bundle/v1';

function preservationPackageFilename(bookId: string): string {
  return `chancela-preservation-book-${bookId}.zip`;
}

function bookBundleFilename(bookId: string): string {
  return `book-${bookId}.zip`;
}

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
  const exportScope = params.export_scope === 'all_filtered' ? '-all-filtered' : '';
  const format = params.format ?? 'pdfa';
  const extension = format === 'pdfa' ? 'pdf' : format;
  return `arquivo-${chain}${scope}${exportScope}.${extension}`;
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

function showSaveResultVia(toast: ReturnType<typeof useToast>, result: SaveBlobResult) {
  if (result.kind === 'cancelled') {
    toast.info(saveBlobResultMessage(result));
    return;
  }
  toast.success(saveBlobResultMessage(result));
}

/**
 * The per-book ZIP exports. Both are gated `book.export@Book`; when the principal holds it at no
 * scope at all the book list is never even requested (so no 403 is provoked) and an honest
 * permission note replaces the controls, matching the pattern the other gated panels use.
 */
function BookExportsCard() {
  const t = useT();
  const { canAny } = usePermissions();

  return (
    <Card title={t('ledger.export.book.title')}>
      <div className="stack">
        <p className="field__hint">{t('ledger.export.book.body')}</p>
        {/* The controls live in a child so the book list is only queried once the principal may
            actually export something — an unauthorised visit fires no request at all. */}
        {canAny('book.export') ? <BookExportControls /> : <PermissionDeniedNote />}
      </div>
    </Card>
  );
}

/**
 * A cascade level's effective value. A stale or blank choice collapses to the sole option when
 * the level has exactly one (so a single-entity instance needs no click), else stays empty so the
 * placeholder shows. Mirrors the derived-value pattern the prior single-select used, without an
 * effect.
 */
function resolveChoice(current: string, options: readonly { value: string }[]): string {
  if (options.some((o) => o.value === current)) return current;
  return options.length === 1 ? options[0].value : '';
}

function BookExportControls() {
  const t = useT();
  const toast = useToast();
  const books = useBooks();
  const entities = useEntities();
  // The three cascade choices. Each `onChange` clears the levels below it; `resolveChoice` then
  // re-derives what is actually in effect (auto-selecting a sole option, dropping a stale one).
  const [entityId, setEntityId] = useState('');
  const [kind, setKind] = useState('');
  const [bookId, setBookId] = useState('');
  const [legalHold, setLegalHold] = useState(false);
  const [legalHoldReason, setLegalHoldReason] = useState('');
  const [reasonTouched, setReasonTouched] = useState(false);

  const bookList = useMemo(() => books.data ?? [], [books.data]);
  const entityList = useMemo(() => entities.data ?? [], [entities.data]);

  // Entity id → name for the dropdown labels. A book whose entity the viewer cannot read (or that
  // is still loading) falls back to an abbreviated id rather than vanishing.
  const entityNameById = useMemo(() => {
    const map = new Map<string, string>();
    for (const entity of entityList) map.set(entity.id, entity.name);
    return map;
  }, [entityList]);

  // Step 1 — only entities that actually own a readable book appear; a guided cascade never offers
  // an entity with nothing behind it.
  const entityOptions = useMemo(() => {
    const withBooks = new Set(bookList.map((book: BookView) => book.entity_id));
    return [...withBooks]
      .map((id) => ({ value: id, label: entityNameById.get(id) ?? abbreviateId(id) }))
      .sort((a, b) => a.label.localeCompare(b.label, 'pt'));
  }, [bookList, entityNameById]);
  const effectiveEntityId = resolveChoice(entityId, entityOptions);

  // Step 2 — the book types present under the chosen entity, in the canonical `BOOK_KINDS` order.
  const kindOptions = useMemo(() => {
    if (!effectiveEntityId) return [];
    const present = new Set(
      bookList
        .filter((book: BookView) => book.entity_id === effectiveEntityId)
        .map((book: BookView) => book.kind),
    );
    return BOOK_KINDS.filter((k) => present.has(k)).map((k) => ({
      value: k,
      label: bookKindLabels[k],
    }));
  }, [bookList, effectiveEntityId]);
  const effectiveKind = resolveChoice(kind, kindOptions) as BookKind | '';

  // Step 3 — the specific books of that entity and type; a book with no recorded purpose falls
  // back to an abbreviated id (never blank).
  const bookOptions = useMemo(() => {
    if (!effectiveEntityId || !effectiveKind) return [];
    return bookList
      .filter(
        (book: BookView) => book.entity_id === effectiveEntityId && book.kind === effectiveKind,
      )
      .map((book: BookView) => ({
        value: book.id,
        label: book.purpose?.trim() || abbreviateId(book.id),
      }));
  }, [bookList, effectiveEntityId, effectiveKind]);
  const selectedBookId = resolveChoice(bookId, bookOptions);

  const placeholder = {
    value: '',
    label: t('ledger.export.book.selectPlaceholder'),
    disabled: true,
  };

  const preservation = useDownloadBookArchivePackage(selectedBookId);
  const bundle = useExportBook();

  const trimmedReason = legalHoldReason.trim();
  // Mirrors the server rule: `legal_hold=true` without a non-blank reason is a 422, so the button
  // is held back rather than sending a request that is known to fail.
  const reasonMissing = legalHold && trimmedReason === '';

  function onDownloadPreservationPackage() {
    if (!selectedBookId || reasonMissing) {
      setReasonTouched(true);
      return;
    }
    preservation.mutate(legalHold ? { legal_hold: true, legal_hold_reason: trimmedReason } : {}, {
      onSuccess: async (blob) => {
        try {
          showSaveResultVia(
            toast,
            await saveBlobAs({
              blob,
              filename: preservationPackageFilename(selectedBookId),
              contentType: 'application/zip',
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

  function onDownloadBundle() {
    if (!selectedBookId) return;
    bundle.mutate(selectedBookId, {
      onSuccess: async ({ blob }) => {
        try {
          showSaveResultVia(
            toast,
            await saveBlobAs({
              blob,
              filename: bookBundleFilename(selectedBookId),
              contentType: 'application/zip',
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

  if (books.isLoading || entities.isLoading) {
    return (
      <SkeletonRegion>
        <SkeletonList items={2} />
      </SkeletonRegion>
    );
  }
  if (books.error) return <ErrorNote error={books.error} />;
  if (entityOptions.length === 0) {
    return (
      <EmptyState title={t('ledger.export.book.empty')}>
        {t('ledger.export.book.emptyBody')}
      </EmptyState>
    );
  }

  return (
    <div className="stack">
      {/* Step 1 → 2 → 3: pick the entity, then the book type it holds, then the specific book.
          Each step below is disabled until the one above it resolves, so the choice is guided. */}
      <Field label={t('books.entity')} htmlFor="ledger-export-entity">
        <Select
          id="ledger-export-entity"
          options={[placeholder, ...entityOptions]}
          value={effectiveEntityId}
          onChange={(e) => {
            setEntityId(e.target.value);
            setKind('');
            setBookId('');
          }}
        />
      </Field>

      <Field label={t('books.bookKind')} htmlFor="ledger-export-kind">
        <Select
          id="ledger-export-kind"
          options={[placeholder, ...kindOptions]}
          value={effectiveKind}
          disabled={!effectiveEntityId}
          onChange={(e) => {
            setKind(e.target.value);
            setBookId('');
          }}
        />
      </Field>

      <Field
        label={t('ledger.export.book.label')}
        htmlFor="ledger-export-book"
        help={t('ledger.export.book.help')}
      >
        <Select
          id="ledger-export-book"
          options={[placeholder, ...bookOptions]}
          value={selectedBookId}
          disabled={!effectiveKind}
          onChange={(e) => setBookId(e.target.value)}
        />
      </Field>

      {/* The two packages side by side as a readable comparison, so their purpose and what each
          one costs (a registered export, a legal-hold flag) is legible at a glance. */}
      <Table
        className="book-export-table"
        caption={t('ledger.export.book.title')}
        head={
          <tr>
            <th scope="col">{t('ledger.export.table.package')}</th>
            <th scope="col">{t('ledger.export.table.purpose')}</th>
            <th scope="col" />
          </tr>
        }
      >
        <tr>
          <th scope="row">{t('ledger.export.preservation.title')}</th>
          <td>
            <p className="field__hint">
              {t('ledger.export.preservation.body')} <code>{PRESERVATION_PACKAGE_PROFILE}</code>
            </p>
            <p className="field__hint">{t('ledger.export.preservation.contents')}</p>
          </td>
          <td>
            <div className="stack--tight">
              <Toggle
                id="ledger-export-legal-hold"
                checked={legalHold}
                onChange={(next) => {
                  setLegalHold(next);
                  if (!next) setReasonTouched(false);
                }}
                label={t('ledger.export.legalHold.label')}
              />
              <p className="field__hint">{t('ledger.export.legalHold.help')}</p>
              {legalHold ? (
                <Field
                  label={t('ledger.export.legalHold.reason.label')}
                  htmlFor="ledger-export-legal-hold-reason"
                  error={
                    reasonTouched && reasonMissing
                      ? t('ledger.export.legalHold.reason.required')
                      : undefined
                  }
                >
                  <Input
                    id="ledger-export-legal-hold-reason"
                    value={legalHoldReason}
                    placeholder={t('ledger.export.legalHold.reason.placeholder')}
                    onChange={(e) => setLegalHoldReason(e.target.value)}
                    onBlur={() => setReasonTouched(true)}
                  />
                </Field>
              ) : null}
              <GateButton
                perm="book.export"
                scope={scopeBook(selectedBookId)}
                type="button"
                variant="primary"
                icon={<Icon.Archive />}
                disabled={!selectedBookId || preservation.isPending}
                onClick={onDownloadPreservationPackage}
              >
                {preservation.isPending
                  ? t('books.preservationPackage.downloading')
                  : t('books.preservationPackage.download')}
              </GateButton>
            </div>
          </td>
        </tr>

        <tr>
          <th scope="row">{t('ledger.export.bundle.title')}</th>
          <td>
            <p className="field__hint">
              {t('ledger.export.bundle.body')} <code>{BOOK_BUNDLE_PROFILE}</code>
            </p>
            <InlineWarning tone="info" title={t('ledger.export.bundle.retainedTitle')}>
              {t('ledger.export.bundle.retained')}
            </InlineWarning>
          </td>
          <td>
            <div className="stack--tight">
              <GateButton
                perm="book.export"
                scope={scopeBook(selectedBookId)}
                type="button"
                variant="secondary"
                icon={<Icon.Tray />}
                disabled={!selectedBookId || bundle.isPending}
                onClick={onDownloadBundle}
              >
                {bundle.isPending
                  ? t('ledger.export.bundle.downloading')
                  : t('ledger.export.bundle.download')}
              </GateButton>
            </div>
          </td>
        </tr>
      </Table>
    </div>
  );
}

export function LedgerPage() {
  const t = useT();
  const toast = useToast();
  // `/archive/export`; Registo is the default, so it stays at the bare `/archive`.
  const { section, select: selectSection } = useSectionNav<LedgerSection>({
    base: '/archive',
    parse: parseLedgerSection,
    fallback: 'register',
    replace: true,
  });
  const [filters, setFilters] = useState<LedgerFilters>(INITIAL_FILTERS);
  const deferredSearch = useDeferredValue(filters.search);
  const [archiveFormat, setArchiveFormat] = useState<LedgerArchiveDocumentFormat>('pdfa');
  const [archiveScope, setArchiveScope] = useState<LedgerArchiveDocumentScope>('current_page');
  const verify = useLedgerVerify();
  const integrity = useLedgerIntegrity();
  const downloadArchive = useDownloadLedgerArchiveDocument();
  const ledgerParams = useMemo(
    () => filteredParams({ ...filters, search: deferredSearch }),
    [deferredSearch, filters],
  );
  const eventsQuery = useLedgerPages(ledgerParams);
  const pages = eventsQuery.data?.pages ?? [];
  // A page whose envelope carries no `events` array contributes no rows rather than a hole:
  // `flatMap` would otherwise splice an `undefined` into the list and crash the table.
  const events = pages.flatMap((page) => page.events ?? []);
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
  const archiveScopeOptions = useMemo(
    () => [
      { value: 'current_page', label: t('ledger.archive.scope.currentPage') },
      { value: 'all_filtered', label: t('ledger.archive.scope.allFiltered') },
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
    const baseParams = filteredParams(filters);
    const params: LedgerArchiveDocumentParams =
      archiveScope === 'all_filtered'
        ? {
            ...baseParams,
            limit: undefined,
            format: archiveFormat,
            export_scope: 'all_filtered',
          }
        : { ...baseParams, format: archiveFormat };
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
  /*
   * `aria-rowcount`, header row included. The page endpoint reports `has_more`/`next_cursor` but
   * never a total, so while older events remain the honest value is `-1` — the ARIA constant for
   * "the total is not known" — rather than the loaded count, which would tell a screen-reader user
   * the archive ends where the fetching happens to have stopped. Once `has_more` is false the
   * table IS the whole filtered set and the real total can be stated.
   */
  const ledgerRowCount = eventsQuery.hasNextPage ? -1 : events.length + 1;

  return (
    <div className="stack">
      <PageHeader title={t('ledger.page.title')}>
        <SubNav
          items={[
            { id: 'register', label: t('ledger.subnav.registo'), icon: <Icon.Layers /> },
            { id: 'export', label: t('ledger.subnav.exportacao'), icon: <Icon.Archive /> },
          ]}
          active={section}
          onSelect={selectSection}
          ariaLabel={t('ledger.subnav.aria')}
        />
      </PageHeader>

      {/* The chain-valid headline stays page-level: it is the trust statement for the whole
          Arquivo surface, not a property of either sub-tab. */}
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

      {/* One sub-tab at a time; the panel replays the route-enter fade on each switch.
          `wide-page` rides on the PANEL, not the page: Registo's seven-column chain table
          wants the room, while Exportação is two cards that read better at the prose
          measure. `section` is derived from the path on every render, so a deep link into
          either tab gets the right width on first paint. */}
      <div
        className={section === 'register' ? 'route-transition wide-page' : 'route-transition'}
        key={section}
      >
        {section === 'export' ? (
          <div className="stack">
            <Card title={t('ledger.export.document.title')}>
              <div className="stack">
                <p className="field__hint">{t('ledger.export.document.body')}</p>
                <div className="ledger-export-controls">
                  <Field
                    label={t('ledger.archive.scope.label')}
                    htmlFor="ledger-export-scope"
                    help={t('ledger.archive.scope.help')}
                  >
                    <Select
                      id="ledger-export-scope"
                      options={archiveScopeOptions}
                      value={archiveScope}
                      onChange={(e) =>
                        setArchiveScope(e.target.value as LedgerArchiveDocumentScope)
                      }
                    />
                  </Field>
                  <Field
                    label={t('ledger.archive.format.label')}
                    htmlFor="ledger-export-format"
                    help={t('ledger.archive.format.help')}
                  >
                    <Select
                      id="ledger-export-format"
                      options={archiveFormatOptions}
                      value={archiveFormat}
                      onChange={(e) =>
                        setArchiveFormat(e.target.value as LedgerArchiveDocumentFormat)
                      }
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
                {/* The filters that shape this export live in Registo, so their current state is
                    echoed here with a way back to change them. */}
                <div className="ledger-resultbar">
                  <Badge>{t('ledger.filters.activeCount', { count: activeFilterCount })}</Badge>
                  <Button
                    type="button"
                    variant="ghost"
                    icon={<Icon.Search />}
                    onClick={() => selectSection('register')}
                  >
                    {t('ledger.export.document.editFilters')}
                  </Button>
                </div>
              </div>
            </Card>

            <BookExportsCard />
          </div>
        ) : (
          <Card title={t('ledger.events.title')}>
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
                  <summary>
                    <span className="ledger-advanced-filters__summary">
                      <span>{t('ledger.filters.advanced')}</span>
                      {activeFilterCount > 0 ? (
                        <span
                          className="ledger-advanced-filters__count"
                          aria-label={t('ledger.filters.activeCount', { count: activeFilterCount })}
                        >
                          <Badge tone="accent">{activeFilterCount}</Badge>
                        </span>
                      ) : null}
                    </span>
                  </summary>
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
                  {/* A live region, not just a label: loading older events changes this count
                      without moving focus, so without `role="status"` the only feedback a
                      screen-reader user gets from "Carregar eventos mais antigos" is silence. */}
                  <span role="status" aria-label={resultStatus}>
                    <Badge>{resultStatus}</Badge>
                  </span>
                </div>
              ) : null}

              {eventsQuery.isLoading ? (
                <SkeletonRegion>
                  <SkeletonTable cols={7} />
                </SkeletonRegion>
              ) : eventsQuery.error ? (
                <ErrorNote error={eventsQuery.error} />
              ) : events.length === 0 && activeFilters ? (
                <EmptyState title={t('ledger.filteredEmpty.title')}>
                  {t('ledger.filteredEmpty.body')}
                </EmptyState>
              ) : (
                <>
                  <LedgerTable events={events} showChains compact rowCount={ledgerRowCount} />
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
        )}
      </div>
    </div>
  );
}
