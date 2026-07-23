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
import { actStateLabels, meetingChannelLabels } from '../../api/labels';
import {
  ACT_STATES,
  MEETING_CHANNELS,
  type ActState,
  type ActView,
  type MeetingChannel,
} from '../../api/types';
import { useT } from '../../i18n';
import { useAtasFilterT } from '../../i18n/atasFilterFallback';
import {
  Badge,
  EmptyState,
  Field,
  Icon,
  IconButton,
  Input,
  Select,
  Table,
  Tooltip,
  Truncate,
} from '../../ui';

type ActStateFilter = 'all' | ActState;
type ActChannelFilter = 'all' | MeetingChannel;

function stateTone(state: ActState): 'accent' | 'neutral' {
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

export function BookActsList({ acts }: { acts: ActView[] }) {
  const t = useT();
  const at = useAtasFilterT();
  const [search, setSearch] = useState('');
  const deferredSearch = useDeferredValue(search);
  const [stateFilter, setStateFilter] = useState<ActStateFilter>('all');
  const [channelFilter, setChannelFilter] = useState<ActChannelFilter>('all');

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
                shown: visibleActs.length,
                total: acts.length,
              })}
            >
              <Badge>
                {t('books.filters.count', { shown: visibleActs.length, total: acts.length })}
              </Badge>
            </span>
            <IconButton
              className="acts-filterbar__clear"
              icon={<Icon.Close />}
              label={at('acts.filters.clear.aria')}
              disabled={!hasFilters}
              onClick={clearFilters}
            />
          </div>
        </div>
      </div>

      {visibleActs.length === 0 ? (
        <EmptyState title={t('books.filters.empty.title')}>
          <p>{at('acts.filters.empty.body')}</p>
        </EmptyState>
      ) : (
        <div className="acts-table">
          <Table
            head={
              <tr>
                <th data-act-column="Number">{t('books.th.number')}</th>
                <th data-act-column="Title">{t('books.th.actTitle')}</th>
                <th data-act-column="Channel">{t('books.th.channel')}</th>
                <th data-act-column="State">{t('books.th.actState')}</th>
                <th data-act-column="Actions" />
              </tr>
            }
          >
            {visibleActs.map((act) => (
              <tr key={act.id}>
                <td className="acts-table__cell--truncate" data-act-column="Number">
                  <Truncate text={act.ata_number != null ? String(act.ata_number) : '—'} mono />
                </td>
                <td className="acts-table__cell--truncate" data-act-column="Title">
                  <Truncate text={act.title} />
                </td>
                <td className="acts-table__cell--truncate" data-act-column="Channel">
                  <Truncate text={meetingChannelLabels[act.channel]} />
                </td>
                <td data-act-column="State">
                  <span className="acts-table__state">
                    <Badge tone={stateTone(act.state)}>{actStateLabels[act.state]}</Badge>
                  </span>
                </td>
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
          </Table>
        </div>
      )}
    </div>
  );
}
