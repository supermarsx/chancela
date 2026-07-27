/**
 * A book's atas (minutes) as a search + filter + neatly-formatted table, brought to parity with the
 * Livros list (`BooksPage` / `BooksTable`).
 *
 * The list used to be a bare `<Table>` with no search, no ordering and none of the books table's
 * outlining: the rows arrived numbered-ascending-then-drafts straight from the API, so the newest ata
 * and the draft you were working on sat at the very bottom. This mirrors the books filter bar (search
 * box + two selects + clear + a result count) and the books table styling (fixed layout, truncating
 * columns, a badge for state, an icon "open" action), and orders the rows most-recent-first: drafts
 * (the active work) first, then sealed atas by descending number.
 *
 * The empty-book case (no atas at all) stays with the caller — this renders once there is at least
 * one ata to show, and owns only the "your search/filters matched nothing" case.
 */
import { useDeferredValue, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { useDownloadBookTermoAberturaDocument } from '../../api/hooks';
import { actStateLabels, meetingChannelLabels } from '../../api/labels';
import {
  ACT_STATES,
  MEETING_CHANNELS,
  type ActState,
  type ActView,
  type MeetingChannel,
  type TermoState,
} from '../../api/types';
import { saveBlobAs } from '../../desktop/saveFile';
import { formatDate } from '../../format';
import { useT, type MessageKey } from '../../i18n';
import { useAtasFilterT } from '../../i18n/atasFilterFallback';
import { useTableColumnsT } from '../../i18n/tableColumnsFallback';
import {
  Badge,
  DateOnly,
  EmptyState,
  Field,
  Icon,
  IconButton,
  Input,
  Select,
  Table,
  Tooltip,
  Truncate,
  useToast,
} from '../../ui';
import { ColumnPicker } from '../tableColumns/ColumnPicker';
import { resolveColumnOrigin } from '../tableColumns/columnOrigin';
import {
  ACTS_TABLE,
  dataColumns,
  renderedColumns,
  tableColumnsSpec,
  type ActsTableColumn,
} from '../tableColumns/tableColumnRegistry';
import { useTableColumns } from '../tableColumns/useTableColumns';
import { useTermoT } from './termoStrings';

type ActStateFilter = 'all' | ActState | TermoState;
type ActChannelFilter = 'all' | MeetingChannel;

/** The toggleable act columns, derived from the registry's roles, and the label each answers to. */
const ACTS_HIDEABLE_COLUMNS = dataColumns(ACTS_TABLE);

const ACTS_COLUMN_LABEL_KEYS: Record<(typeof ACTS_HIDEABLE_COLUMNS)[number], MessageKey> = {
  Title: 'books.th.actTitle',
  Channel: 'books.th.channel',
  State: 'books.th.actState',
};

/** All four storable columns show by default; `Actions` is a control, shown unconditionally. */
const ACTS_COLUMN_SPEC = tableColumnsSpec(ACTS_TABLE);

export interface OpeningTermRecord {
  bookId: string;
  title: string;
  state: TermoState;
  instrumentDate: string | null;
  legacy: boolean;
  documentAvailable: boolean;
  /** Required slots with a stored PAdES document, not provisional `slot.signed` markers. */
  availableSignatures: number;
  requiredSignatures: number;
}

function stateTone(state: ActState | TermoState): 'accent' | 'neutral' {
  return state === 'Sealed' || state === 'Archived' ? 'accent' : 'neutral';
}

function normalizeSearch(value: string): string {
  return value
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase();
}

function dateRank(value: string | null): number {
  if (!value) return 0;
  const time = new Date(value).getTime();
  return Number.isNaN(time) ? 0 : time;
}

function actSearchText(act: ActView): string {
  return normalizeSearch(
    [
      act.ata_number != null ? String(act.ata_number) : '',
      act.title,
      meetingChannelLabels[act.channel],
      actStateLabels[act.state],
    ].join(' '),
  );
}

/**
 * Most-recent-first order. Drafts (no ata number yet — the work in progress) come first, then the
 * numbered atas by descending number so the latest sealed record is near the top rather than buried
 * under every historical ata. Drafts among themselves fall back to meeting date, then title, then id
 * so the order is stable (the API returns unnumbered acts in an arbitrary map order).
 */
function compareActs(a: ActView, b: ActView): number {
  const aNumbered = a.ata_number != null;
  const bNumbered = b.ata_number != null;
  if (aNumbered !== bNumbered) return aNumbered ? 1 : -1;
  if (aNumbered && bNumbered) return (b.ata_number ?? 0) - (a.ata_number ?? 0);
  const dateDelta = dateRank(b.meeting_date) - dateRank(a.meeting_date);
  if (dateDelta !== 0) return dateDelta;
  return a.title.localeCompare(b.title, 'pt') || a.id.localeCompare(b.id);
}

export function BookActsList({ acts, opening }: { acts: ActView[]; opening: OpeningTermRecord }) {
  const t = useT();
  const at = useAtasFilterT();
  const tt = useTermoT();
  const ct = useTableColumnsT();
  const toast = useToast();
  const downloadOpening = useDownloadBookTermoAberturaDocument(opening.bookId);
  const [search, setSearch] = useState('');
  const deferredSearch = useDeferredValue(search);
  const [stateFilter, setStateFilter] = useState<ActStateFilter>('all');
  const [channelFilter, setChannelFilter] = useState<ActChannelFilter>('all');
  const columns = useTableColumns(ACTS_COLUMN_SPEC);
  const visibleColumns = renderedColumns(ACTS_TABLE, columns.visible);
  const shows = (column: ActsTableColumn) => visibleColumns.includes(column);

  const ordered = useMemo(() => [...acts].sort(compareActs), [acts]);

  const channels = useMemo(() => {
    const present = new Set(acts.map((act) => act.channel));
    return MEETING_CHANNELS.filter((channel) => present.has(channel));
  }, [acts]);

  const visibleActs = useMemo(() => {
    const query = normalizeSearch(deferredSearch.trim());
    return ordered.filter((act) => {
      if (stateFilter !== 'all' && act.state !== stateFilter) return false;
      if (channelFilter !== 'all' && act.channel !== channelFilter) return false;
      return query === '' || actSearchText(act).includes(query);
    });
  }, [channelFilter, deferredSearch, ordered, stateFilter]);

  const normalizedQuery = normalizeSearch(deferredSearch.trim());
  const openingVisible =
    (stateFilter === 'all' || opening.state === stateFilter) &&
    channelFilter === 'all' &&
    (normalizedQuery === '' ||
      normalizeSearch(
        [
          opening.title,
          opening.instrumentDate ?? '',
          formatDate(opening.instrumentDate),
          tt(`books.termo.state.${opening.state}`),
          opening.legacy ? 'legado legacy' : '',
        ].join(' '),
      ).includes(normalizedQuery));
  const totalRecords = acts.length + 1;
  const visibleRecordCount = visibleActs.length + (openingVisible ? 1 : 0);
  // Draft/signing work is active and stays at the top. Once sealed (including legacy records), the
  // opening instrument is the book's genesis record and follows the newest-first ata chronology.
  const openingFirst = opening.state === 'Draft' || opening.state === 'Signing';

  const hasFilters = search.trim() !== '' || stateFilter !== 'all' || channelFilter !== 'all';

  function clearFilters() {
    setSearch('');
    setStateFilter('all');
    setChannelFilter('all');
  }

  const openLabel = t('common.open');
  const stateFilterOptions = [
    { value: 'all', label: t('books.filters.state.all') },
    ...ACT_STATES.map((state) => ({ value: state, label: actStateLabels[state] })),
  ];
  const channelFilterOptions = [
    { value: 'all', label: at('acts.filters.channel.all') },
    ...channels.map((channel) => ({ value: channel, label: meetingChannelLabels[channel] })),
  ];

  function saveOpeningDocument() {
    downloadOpening.mutate(undefined, {
      onSuccess: async (blob) => {
        try {
          await saveBlobAs({
            blob,
            filename: `termo-de-abertura-${opening.bookId}-base-sem-assinaturas.pdf`,
            contentType: 'application/pdf',
          });
          toast.success(t('toast.document.downloaded'));
        } catch (error) {
          toast.error(error);
        }
      },
      onError: (error) => toast.error(error),
    });
  }

  const openingRow = openingVisible ? (
    <tr key={`termo-abertura-${opening.bookId}`} data-record-type="TermoAbertura">
      <td className="acts-table__cell--truncate" data-act-column="Number">
        <Truncate text="—" mono />
      </td>
      {shows('Title') ? (
        <td className="acts-table__cell--truncate" data-act-column="Title">
          <div className="stack--tight">
            <Truncate text={opening.title} />
            <span className="field__hint">
              <DateOnly value={opening.instrumentDate} />
              {' · '}
              {opening.legacy
                ? tt('books.termo.atas.legacyRecord')
                : `${opening.availableSignatures}/${opening.requiredSignatures} ${tt(
                    'books.termo.atas.padesAvailable',
                  )}`}
            </span>
          </div>
        </td>
      ) : null}
      {shows('Channel') ? (
        <td className="acts-table__cell--truncate" data-act-column="Channel">
          <Truncate text="—" />
        </td>
      ) : null}
      {shows('State') ? (
        <td data-act-column="State">
          <span className="acts-table__state">
            <Badge tone={stateTone(opening.state)}>{tt(`books.termo.state.${opening.state}`)}</Badge>
          </span>
        </td>
      ) : null}
      <td className="acts-table__cell--actions" data-act-column="Actions">
        <span className="acts-table__actions">
          {opening.documentAvailable ? (
            <Tooltip label={tt('books.termo.document.downloadUnsignedBase')} placement="left">
              <button
                className="btn btn--ghost btn--icon btn--iconOnly"
                type="button"
                aria-label={tt('books.termo.document.downloadUnsignedBase')}
                disabled={downloadOpening.isPending}
                onClick={saveOpeningDocument}
              >
                <span className="btn__icon" aria-hidden="true">
                  <Icon.Tray />
                </span>
              </button>
            </Tooltip>
          ) : null}
          <Tooltip label={openLabel} placement="left">
            <Link
              className="btn btn--ghost btn--icon btn--iconOnly acts-table__open"
              to={`/books/${opening.bookId}/opening`}
              aria-label={`${openLabel}: ${opening.title}`}
            >
              <span className="btn__icon" aria-hidden="true">
                <Icon.ArrowRight />
              </span>
            </Link>
          </Tooltip>
        </span>
      </td>
    </tr>
  ) : null;

  return (
    <div className="stack">
      <div className="stack--tight acts-filters" role="search" aria-label={at('acts.filters.aria')}>
        <div className="acts-filterbar filter">
          <div className="acts-filterbar__primary">
            <Field label={t('books.filters.search.label')} htmlFor="acts-search">
              <Input
                id="acts-search"
                type="search"
                value={search}
                placeholder={at('acts.filters.search.placeholder')}
                onChange={(e) => setSearch(e.target.value)}
              />
            </Field>
            <Field label={t('books.filters.state.label')} htmlFor="acts-state-filter">
              <Select
                id="acts-state-filter"
                value={stateFilter}
                onChange={(e) => setStateFilter(e.target.value as ActStateFilter)}
                options={stateFilterOptions}
              />
            </Field>
            <Field label={t('books.th.channel')} htmlFor="acts-channel-filter">
              <Select
                id="acts-channel-filter"
                value={channelFilter}
                onChange={(e) => setChannelFilter(e.target.value as ActChannelFilter)}
                options={channelFilterOptions}
              />
            </Field>
            <span
              className="acts-filterbar__count"
              aria-label={at('acts.filters.count.aria', {
                shown: visibleRecordCount,
                total: totalRecords,
              })}
            >
              <Badge>
                {t('books.filters.count', {
                  shown: visibleRecordCount,
                  total: totalRecords,
                })}
              </Badge>
            </span>
            <IconButton
              className="acts-filterbar__clear"
              icon={<Icon.FilterClear />}
              label={at('acts.filters.clear.aria')}
              disabled={!hasFilters}
              onClick={clearFilters}
            />
          </div>
        </div>
      </div>

      <ColumnPicker
        columns={ACTS_HIDEABLE_COLUMNS}
        label={ct('tableColumns.summary')}
        isVisible={columns.isVisible}
        onToggle={columns.toggle}
        columnLabel={(column) => t(ACTS_COLUMN_LABEL_KEYS[column])}
        origin={resolveColumnOrigin(ACTS_TABLE, {
          overridden: columns.overridden,
          fallback: ACTS_COLUMN_SPEC.fallback,
        })}
      />

      {visibleRecordCount === 0 ? (
        <EmptyState title={t('books.filters.empty.title')}>
          <p>{at('acts.filters.empty.body')}</p>
        </EmptyState>
      ) : (
        <div className="acts-table">
          <Table
            head={
              <tr>
                <th data-act-column="Number">{t('books.th.number')}</th>
                {shows('Title') ? <th data-act-column="Title">{t('books.th.actTitle')}</th> : null}
                {shows('Channel') ? (
                  <th data-act-column="Channel">{t('books.th.channel')}</th>
                ) : null}
                {shows('State') ? <th data-act-column="State">{t('books.th.actState')}</th> : null}
                <th data-act-column="Actions" />
              </tr>
            }
          >
            {openingFirst ? openingRow : null}
            {visibleActs.map((act) => (
              <tr key={act.id}>
                <td className="acts-table__cell--truncate" data-act-column="Number">
                  <Truncate text={act.ata_number != null ? String(act.ata_number) : '—'} mono />
                </td>
                {shows('Title') ? (
                  <td className="acts-table__cell--truncate" data-act-column="Title">
                    <Truncate text={act.title} />
                  </td>
                ) : null}
                {shows('Channel') ? (
                  <td className="acts-table__cell--truncate" data-act-column="Channel">
                    <Truncate text={meetingChannelLabels[act.channel]} />
                  </td>
                ) : null}
                {shows('State') ? (
                  <td data-act-column="State">
                    <span className="acts-table__state">
                      <Badge tone={stateTone(act.state)}>{actStateLabels[act.state]}</Badge>
                    </span>
                  </td>
                ) : null}
                <td className="acts-table__cell--actions" data-act-column="Actions">
                  <span className="acts-table__actions">
                    <Tooltip label={openLabel} placement="left">
                      <Link
                        className="btn btn--ghost btn--icon btn--iconOnly acts-table__open"
                        to={`/acts/${act.id}`}
                        aria-label={openLabel}
                      >
                        <span className="btn__icon" aria-hidden="true">
                          <Icon.ArrowRight />
                        </span>
                      </Link>
                    </Tooltip>
                  </span>
                </td>
              </tr>
            ))}
            {openingFirst ? null : openingRow}
          </Table>
        </div>
      )}
    </div>
  );
}
