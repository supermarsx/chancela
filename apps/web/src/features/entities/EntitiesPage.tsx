/**
 * Entidades — the full-width list of registered entities. Creating an entity (by hand or
 * from a certidão permanente) lives behind neat buttons in the panel header, each opening
 * its own dedicated route (`/entidades/nova`, `/entidades/importar`) — so the list is no
 * longer squeezed by an always-visible aside form (t13 items 1–2).
 */
import { useDeferredValue, useMemo, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useBooks, useEntities } from '../../api/hooks';
import {
  bookKindLabels,
  bookStateLabels,
  closingReasonLabels,
  entityFamilyLabels,
  entityKindLabels,
} from '../../api/labels';
import {
  BOOK_KINDS,
  type BookKind,
  type BookState,
  type BookView,
  type Entity,
  type EntityBookStateCounts,
  type EntityFamily,
  type EntityKind,
  type EntityRegistrySummary,
  type LedgerEventView,
} from '../../api/types';
import { useLocale, useT } from '../../i18n';
import {
  Badge,
  Button,
  Card,
  EmptyState,
  ErrorNote,
  Field,
  Icon,
  IconButton,
  Input,
  PageHeader,
  Select,
  SkeletonTable,
  Table,
} from '../../ui';
import { GateButtonLink } from '../session/permissions';
import { NipcBadge } from './NipcBadge';

type BookFilter = 'all' | 'open' | 'created' | 'closed' | 'no-open' | 'none';
type BookKindFilter = 'all' | BookKind;
type LastBookFilter = 'all' | BookState | 'none';
type ActivityFilter = 'all' | 'registry' | 'entity' | 'book' | 'act' | 'document' | 'none';
type ValidationFilter = 'all' | 'validated' | 'unvalidated';
type RegistryImportFilter = 'all' | 'imported' | 'not-imported';
type RegistryFreshnessFilter = 'all' | 'fresh' | 'expired' | 'no-expiry';

interface EnrichedEntityRow {
  entity: Entity;
  books: BookView[];
  lastBook: BookView | null;
  bookStateCounts: Record<BookState, number>;
  activity: LedgerEventView | null;
  registry: EntityRegistrySummary | null;
  hasActivitySummary: boolean;
  searchText: string;
}

const SUMMARY_STACK_STYLE = {
  display: 'inline-flex',
  flexDirection: 'column',
  alignItems: 'flex-start',
  gap: '0.35rem',
} as const;

const BOOK_FILTER_OPTIONS: { value: BookFilter; label: string }[] = [
  { value: 'all', label: 'Todos os livros' },
  { value: 'open', label: 'Com livro aberto' },
  { value: 'created', label: 'Em preparação' },
  { value: 'closed', label: 'Com livro encerrado' },
  { value: 'no-open', label: 'Sem livro aberto' },
  { value: 'none', label: 'Sem livros' },
];

const BOOK_KIND_FILTER_OPTIONS: { value: BookKindFilter; label: string }[] = [
  { value: 'all', label: 'Todos os tipos' },
  ...BOOK_KINDS.map((value) => ({ value, label: bookKindLabels[value] })),
];

const LAST_BOOK_FILTER_OPTIONS: { value: LastBookFilter; label: string }[] = [
  { value: 'all', label: 'Qualquer estado' },
  { value: 'Open', label: bookStateLabels.Open },
  { value: 'Created', label: bookStateLabels.Created },
  { value: 'Closed', label: bookStateLabels.Closed },
  { value: 'none', label: 'Sem último livro' },
];

const ACTIVITY_FILTER_OPTIONS: { value: ActivityFilter; label: string }[] = [
  { value: 'all', label: 'Toda a atividade' },
  { value: 'registry', label: 'Registo importado' },
  { value: 'entity', label: 'Alteração da entidade' },
  { value: 'book', label: 'Livros' },
  { value: 'act', label: 'Atas e convocatórias' },
  { value: 'document', label: 'Documentos e assinaturas' },
  { value: 'none', label: 'Sem atividade' },
];

const VALIDATION_FILTER_OPTIONS: { value: ValidationFilter; label: string }[] = [
  { value: 'all', label: 'Todos os NIPC' },
  { value: 'validated', label: 'NIPC validado' },
  { value: 'unvalidated', label: 'NIPC por validar' },
];

const REGISTRY_IMPORT_FILTER_OPTIONS: { value: RegistryImportFilter; label: string }[] = [
  { value: 'all', label: 'Todo o registo' },
  { value: 'imported', label: 'Importado' },
  { value: 'not-imported', label: 'Não importado' },
];

const REGISTRY_FRESHNESS_FILTER_OPTIONS: { value: RegistryFreshnessFilter; label: string }[] = [
  { value: 'all', label: 'Qualquer validade' },
  { value: 'fresh', label: 'Dentro da validade' },
  { value: 'expired', label: 'Expirado' },
  { value: 'no-expiry', label: 'Sem validade' },
];

function normalizeSearch(value: string): string {
  return value
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase();
}

function displayFiscalYearEnd(value: string | null | undefined): string {
  return value ? value : '12-31 (por omissão)';
}

function bookStateTone(state: BookView['state']): 'neutral' | 'accent' | 'ok' {
  if (state === 'Open') return 'ok';
  if (state === 'Closed') return 'neutral';
  return 'accent';
}

function dateRank(value: string | null): number {
  if (!value) return 0;
  const time = new Date(value).getTime();
  return Number.isNaN(time) ? 0 : time;
}

function selectLastBook(books: BookView[]): BookView | null {
  if (books.length === 0) return null;
  return [...books].sort((a, b) => {
    const date =
      Math.max(dateRank(b.opening_date), dateRank(b.closing_date)) -
      Math.max(dateRank(a.opening_date), dateRank(a.closing_date));
    if (date !== 0) return date;
    const ataRank = b.last_ata_number - a.last_ata_number;
    if (ataRank !== 0) return ataRank;
    const stateRank =
      Number(b.state === 'Open') - Number(a.state === 'Open') ||
      Number(b.state === 'Created') - Number(a.state === 'Created');
    if (stateRank !== 0) return stateRank;
    return b.id.localeCompare(a.id);
  })[0];
}

function activityTone(kind: string): 'neutral' | 'accent' | 'ok' {
  if (kind === 'registry.imported') return 'ok';
  if (kind === 'act.sealed' || kind === 'document.signed') return 'ok';
  if (kind === 'entity.statute_updated' || kind === 'act.advanced') return 'accent';
  return 'neutral';
}

function activityLabel(kind: string): string {
  if (kind === 'registry.imported') return 'Registo importado';
  if (kind === 'entity.statute_updated') return 'Entidade atualizada';
  if (kind === 'entity.created') return 'Entidade criada';
  if (kind === 'book.opened') return 'Livro aberto';
  if (kind === 'book.closed') return 'Livro encerrado';
  if (kind === 'book.start_over') return 'Livro recomeçado';
  if (kind === 'act.drafted') return 'Ata rascunhada';
  if (kind === 'act.advanced') return 'Ata avançada';
  if (kind === 'act.sealed') return 'Ata selada';
  if (kind === 'act.archived') return 'Ata arquivada';
  if (kind === 'convening.dispatched') return 'Convocatória expedida';
  if (kind === 'document.generated') return 'Documento gerado';
  if (kind === 'document.signed') return 'Documento assinado';
  return kind;
}

function activityCategory(kind: string): Exclude<ActivityFilter, 'all' | 'none'> | 'other' {
  if (kind === 'registry.imported') return 'registry';
  if (kind.startsWith('entity.')) return 'entity';
  if (kind.startsWith('book.')) return 'book';
  if (kind.startsWith('act.') || kind.startsWith('convening.')) return 'act';
  if (kind.startsWith('document.') || kind.startsWith('signature.')) return 'document';
  return 'other';
}

function formatActivityTimestamp(value: string, locale: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat(locale, { dateStyle: 'short', timeStyle: 'short' }).format(date);
}

function formatDateValue(value: string | null | undefined, fallback = '—'): string {
  return value ?? fallback;
}

function caeLabel(cae: EntityRegistrySummary['cae'][number]): string {
  const suffix = cae.role === 'Principal' ? ' principal' : ' secundário';
  return `${cae.code}${suffix}`;
}

function registryFreshnessTone(
  registry: EntityRegistrySummary | null,
): 'neutral' | 'accent' | 'ok' | 'warn' {
  if (!registry) return 'neutral';
  if (registry.expired === true) return 'warn';
  if (registry.expired === false) return 'ok';
  return 'accent';
}

function registryFreshnessLabel(registry: EntityRegistrySummary | null): string {
  if (!registry) return 'Não importado';
  if (registry.expired === true) return 'Expirado';
  if (registry.expired === false) return 'Dentro da validade';
  return 'Validade desconhecida';
}

function indexBooksByEntity(books: BookView[] | undefined): Map<string, BookView[]> {
  const byEntity = new Map<string, BookView[]>();
  for (const book of books ?? []) {
    const entityBooks = byEntity.get(book.entity_id) ?? [];
    entityBooks.push(book);
    byEntity.set(book.entity_id, entityBooks);
  }
  return byEntity;
}

function bookDateSummary(book: BookView): string {
  const opened = book.opening_date ? `Aberto em ${book.opening_date}` : 'Sem data de abertura';
  if (!book.closing_date) return opened;
  return `${opened} · Encerrado em ${book.closing_date}`;
}

function emptyBookStateCounts(): Record<BookState, number> {
  return { Created: 0, Open: 0, Closed: 0 };
}

function bookStateCountsFromSummary(counts: EntityBookStateCounts): Record<BookState, number> {
  return { Created: counts.created, Open: counts.open, Closed: counts.closed };
}

function bookStateCounts(books: BookView[]): Record<BookState, number> {
  return books.reduce<Record<BookState, number>>(
    (counts, book) => ({ ...counts, [book.state]: counts[book.state] + 1 }),
    emptyBookStateCounts(),
  );
}

function totalBooksFromCounts(counts: Record<BookState, number>): number {
  return counts.Created + counts.Open + counts.Closed;
}

function bookStateSummary(counts: Record<BookState, number>): string {
  const totalCount = totalBooksFromCounts(counts);
  if (totalCount === 0) return '0 livros';
  const parts = (['Open', 'Created', 'Closed'] as const)
    .filter((state) => counts[state] > 0)
    .map((state) => `${bookStateLabels[state]}: ${counts[state]}`);
  const total = `${totalCount} ${totalCount === 1 ? 'livro' : 'livros'}`;
  return parts.length > 0 ? `${total} · ${parts.join(' · ')}` : total;
}

function entityProfile(entity: Entity): Entity['profile'] | undefined {
  return (entity as { profile?: Entity['profile'] }).profile;
}

function entityRulePack(entity: Entity): string {
  return entityProfile(entity)?.rule_pack_id ?? 'por determinar';
}

function entityTemplateFamily(entity: Entity): string {
  return entityProfile(entity)?.template_family ?? '';
}

function entityAllowedChannels(entity: Entity): string[] {
  return entityProfile(entity)?.allowed_channels ?? [];
}

function buildSearchText(
  entity: Entity,
  books: BookView[],
  lastBook: BookView | null,
  stateCounts: Record<BookState, number>,
  activity: LedgerEventView | null,
  registry: EntityRegistrySummary | null,
  locale: string,
): string {
  const searchableBooks =
    lastBook && !books.some((book) => book.id === lastBook.id) ? [lastBook, ...books] : books;
  return normalizeSearch(
    [
      locale,
      entity.name,
      entity.nipc,
      entity.seat,
      entityKindLabels[entity.kind],
      entityFamilyLabels[entity.family],
      displayFiscalYearEnd(entity.fiscal_year_end),
      entityRulePack(entity),
      entityTemplateFamily(entity),
      entity.nipc_validated ? 'NIPC validado' : 'NIPC por validar',
      ...entityAllowedChannels(entity),
      ...searchableBooks.flatMap((book) => [
        book.id,
        bookKindLabels[book.kind],
        bookStateLabels[book.state],
        book.purpose ?? '',
        book.opening_date ?? '',
        book.closing_date ?? '',
        book.closing_reason ? closingReasonLabels[book.closing_reason] : '',
        String(book.last_ata_number || ''),
      ]),
      bookStateSummary(stateCounts),
      activity ? activityLabel(activity.kind) : '',
      activity?.kind ?? '',
      activity?.actor ?? '',
      activity?.scope ?? '',
      registry ? 'registo importado' : 'registo não importado',
      registry?.matricula ?? '',
      registry?.data_constituicao ?? '',
      registry?.capital ?? '',
      registry?.retrieved_at ?? '',
      registry?.valid_until ?? '',
      registry ? registryFreshnessLabel(registry) : '',
      ...(registry?.cae.flatMap((cae) => [cae.code, cae.role, cae.designation ?? '']) ?? []),
      registry?.last_registry_change?.label ?? '',
      registry?.last_registry_change?.date ?? '',
      registry?.last_registry_change?.reference ?? '',
    ].join(' '),
  );
}

function entityMatchesBookFilter(counts: Record<BookState, number>, filter: BookFilter): boolean {
  if (filter === 'all') return true;
  if (filter === 'none') return totalBooksFromCounts(counts) === 0;
  const hasOpen = counts.Open > 0;
  if (filter === 'open') return hasOpen;
  if (filter === 'created') return counts.Created > 0;
  if (filter === 'closed') return counts.Closed > 0;
  return !hasOpen;
}

function entityMatchesBookKindFilter(books: BookView[], filter: BookKindFilter): boolean {
  if (filter === 'all') return true;
  return books.some((book) => book.kind === filter);
}

function entityMatchesLastBookFilter(lastBook: BookView | null, filter: LastBookFilter): boolean {
  if (filter === 'all') return true;
  if (filter === 'none') return lastBook === null;
  return lastBook?.state === filter;
}

function entityMatchesActivityFilter(
  activity: LedgerEventView | null,
  filter: ActivityFilter,
): boolean {
  if (filter === 'all') return true;
  if (filter === 'none') return activity === null;
  if (!activity) return false;
  return activityCategory(activity.kind) === filter;
}

function entityMatchesActivityKindFilter(
  activity: LedgerEventView | null,
  filter: string,
): boolean {
  if (filter === 'all') return true;
  if (filter === 'none') return activity === null;
  return activity?.kind === filter;
}

function entityMatchesValidationFilter(entity: Entity, filter: ValidationFilter): boolean {
  if (filter === 'all') return true;
  return filter === 'validated' ? entity.nipc_validated : !entity.nipc_validated;
}

function entityMatchesRegistryImportFilter(
  registry: EntityRegistrySummary | null,
  filter: RegistryImportFilter,
): boolean {
  if (filter === 'all') return true;
  return filter === 'imported' ? !!registry : !registry;
}

function entityMatchesRegistryFreshnessFilter(
  registry: EntityRegistrySummary | null,
  filter: RegistryFreshnessFilter,
): boolean {
  if (filter === 'all') return true;
  if (!registry) return filter === 'no-expiry';
  if (filter === 'fresh') return registry.expired === false;
  if (filter === 'expired') return registry.expired === true;
  return registry.valid_until === null || registry.expired === null;
}

function familyFilterOptions(entities: Entity[] | undefined): { value: string; label: string }[] {
  const seen = new Set<EntityFamily>();
  for (const entity of entities ?? []) seen.add(entity.family);
  return [
    { value: 'all', label: 'Todas as famílias' },
    ...Array.from(seen).map((value) => ({ value, label: entityFamilyLabels[value] })),
  ];
}

function kindFilterOptions(entities: Entity[] | undefined): { value: string; label: string }[] {
  const seen = new Set<EntityKind>();
  for (const entity of entities ?? []) seen.add(entity.kind);
  return [
    { value: 'all', label: 'Todas as formas' },
    ...Array.from(seen).map((value) => ({ value, label: entityKindLabels[value] })),
  ];
}

function activityKindFilterOptions(rows: EnrichedEntityRow[]): { value: string; label: string }[] {
  const kinds = new Set<string>();
  for (const row of rows) {
    if (row.activity) kinds.add(row.activity.kind);
  }
  return [
    { value: 'all', label: 'Qualquer alteração' },
    ...Array.from(kinds)
      .sort((a, b) => activityLabel(a).localeCompare(activityLabel(b)))
      .map((kind) => ({ value: kind, label: activityLabel(kind) })),
    { value: 'none', label: 'Sem alteração' },
  ];
}

function EntityContext({ entity }: { entity: Entity }) {
  return (
    <span style={SUMMARY_STACK_STYLE}>
      <span>{entityKindLabels[entity.kind]}</span>
      <span className="row-wrap">
        <Badge>{entityFamilyLabels[entity.family]}</Badge>
      </span>
      <span className="muted">Regras {entityRulePack(entity)}</span>
    </span>
  );
}

function BookSummary({
  book,
  stateCounts,
  loading,
  error,
}: {
  book: BookView | null;
  stateCounts: Record<BookState, number>;
  loading: boolean;
  error: unknown;
}) {
  if (loading) return <span className="muted">A carregar livros…</span>;
  if (error) return <span className="muted">Livros indisponíveis</span>;
  if (!book) return <span className="muted">Sem livros</span>;
  return (
    <span style={SUMMARY_STACK_STYLE}>
      <span className="row-wrap">
        <Link to={`/livros/${book.id}`}>{bookKindLabels[book.kind]}</Link>
        <Badge tone={bookStateTone(book.state)}>{bookStateLabels[book.state]}</Badge>
      </span>
      <span className="muted">
        {book.purpose ?? 'Sem finalidade'} · Última ata{' '}
        {book.last_ata_number > 0 ? book.last_ata_number : '—'}
      </span>
      <span className="muted">{bookDateSummary(book)}</span>
      {book.closing_reason ? (
        <span className="muted">Motivo {closingReasonLabels[book.closing_reason]}</span>
      ) : null}
      <span className="muted">{bookStateSummary(stateCounts)}</span>
    </span>
  );
}

function ActivitySummary({
  activity,
  locale,
}: {
  activity: LedgerEventView | null;
  locale: string;
}) {
  if (!activity) {
    return (
      <span style={SUMMARY_STACK_STYLE}>
        <span className="muted">Sem atividade no arquivo</span>
        <Link to="/arquivo">Ver arquivo</Link>
      </span>
    );
  }
  return (
    <span style={SUMMARY_STACK_STYLE}>
      <span className="row-wrap">
        <Badge tone={activityTone(activity.kind)}>{activityLabel(activity.kind)}</Badge>
      </span>
      <span className="muted">
        <time dateTime={activity.timestamp}>
          {formatActivityTimestamp(activity.timestamp, locale)}
        </time>{' '}
        · {activity.actor}
      </span>
    </span>
  );
}

function RegistryFreshnessSummary({ registry }: { registry: EntityRegistrySummary | null }) {
  if (!registry) {
    return (
      <span style={SUMMARY_STACK_STYLE}>
        <Badge tone="neutral">Não importado</Badge>
        <span className="muted">Sem certidão</span>
      </span>
    );
  }
  return (
    <span style={SUMMARY_STACK_STYLE}>
      <Badge tone={registryFreshnessTone(registry)}>{registryFreshnessLabel(registry)}</Badge>
      <span className="muted">Obtido {formatDateValue(registry.retrieved_at)}</span>
      <span className="muted">Válido até {formatDateValue(registry.valid_until)}</span>
    </span>
  );
}

function CaeSummary({ registry }: { registry: EntityRegistrySummary | null }) {
  if (!registry || registry.cae.length === 0) return <span className="muted">—</span>;
  const [first, ...rest] = registry.cae;
  return (
    <span style={SUMMARY_STACK_STYLE}>
      <span className="mono">{caeLabel(first)}</span>
      {first.designation ? <span className="muted">{first.designation}</span> : null}
      {rest.length > 0 ? <span className="muted">+{rest.length} CAE</span> : null}
    </span>
  );
}

function LastRegistryChange({ registry }: { registry: EntityRegistrySummary | null }) {
  const change = registry?.last_registry_change;
  if (!change) return <span className="muted">—</span>;
  return (
    <span style={SUMMARY_STACK_STYLE}>
      <span>{change.label}</span>
      <span className="muted">
        {formatDateValue(change.date)}
        {change.reference ? ` · ${change.reference}` : ''}
      </span>
    </span>
  );
}

export function EntitiesPage() {
  const t = useT();
  const locale = useLocale();
  const navigate = useNavigate();
  const { data, isLoading, error } = useEntities();
  const books = useBooks();
  const [search, setSearch] = useState('');
  const deferredSearch = useDeferredValue(search);
  const [family, setFamily] = useState<'all' | EntityFamily>('all');
  const [kind, setKind] = useState<'all' | EntityKind>('all');
  const [validationFilter, setValidationFilter] = useState<ValidationFilter>('all');
  const [bookFilter, setBookFilter] = useState<BookFilter>('all');
  const [bookKindFilter, setBookKindFilter] = useState<BookKindFilter>('all');
  const [lastBookFilter, setLastBookFilter] = useState<LastBookFilter>('all');
  const [activityFilter, setActivityFilter] = useState<ActivityFilter>('all');
  const [activityKindFilter, setActivityKindFilter] = useState('all');
  const [registryImportFilter, setRegistryImportFilter] = useState<RegistryImportFilter>('all');
  const [registryFreshnessFilter, setRegistryFreshnessFilter] =
    useState<RegistryFreshnessFilter>('all');

  const enrichedRows = useMemo<EnrichedEntityRow[]>(() => {
    const entities = data ?? [];
    const booksByEntity = indexBooksByEntity(books.data);

    return entities.map((entity) => {
      const entityBooks = booksByEntity.get(entity.id) ?? [];
      const summary = entity.activity_summary;
      const lastBook = summary?.last_book ?? selectLastBook(entityBooks);
      const stateCounts = summary
        ? bookStateCountsFromSummary(summary.book_state_counts)
        : bookStateCounts(entityBooks);
      const activity = summary?.last_change ?? null;
      const registry = entity.registry_summary ?? null;
      return {
        entity,
        books: entityBooks,
        lastBook,
        bookStateCounts: stateCounts,
        activity,
        registry,
        hasActivitySummary: !!summary,
        searchText: buildSearchText(
          entity,
          entityBooks,
          lastBook,
          stateCounts,
          activity,
          registry,
          locale,
        ),
      };
    });
  }, [books.data, data, locale]);

  const query = normalizeSearch(deferredSearch.trim());
  const rows = useMemo(() => {
    return enrichedRows.filter(
      ({
        entity,
        books: entityBooks,
        lastBook,
        bookStateCounts,
        activity,
        registry,
        searchText,
      }) => {
        if (family !== 'all' && entity.family !== family) return false;
        if (kind !== 'all' && entity.kind !== kind) return false;
        if (!entityMatchesValidationFilter(entity, validationFilter)) return false;
        if (!entityMatchesRegistryImportFilter(registry, registryImportFilter)) return false;
        if (!entityMatchesRegistryFreshnessFilter(registry, registryFreshnessFilter)) return false;
        if (!entityMatchesBookFilter(bookStateCounts, bookFilter)) return false;
        if (!entityMatchesBookKindFilter(entityBooks, bookKindFilter)) return false;
        if (!entityMatchesLastBookFilter(lastBook, lastBookFilter)) return false;
        if (!entityMatchesActivityFilter(activity, activityFilter)) return false;
        if (!entityMatchesActivityKindFilter(activity, activityKindFilter)) return false;
        return query === '' || searchText.includes(query);
      },
    );
  }, [
    activityFilter,
    activityKindFilter,
    bookFilter,
    bookKindFilter,
    enrichedRows,
    family,
    kind,
    lastBookFilter,
    query,
    registryFreshnessFilter,
    registryImportFilter,
    validationFilter,
  ]);

  const familyOptions = familyFilterOptions(data);
  const kindOptions = kindFilterOptions(data);
  const activityKindOptions = activityKindFilterOptions(enrichedRows);

  const hasFilters =
    search.trim() !== '' ||
    family !== 'all' ||
    kind !== 'all' ||
    validationFilter !== 'all' ||
    registryImportFilter !== 'all' ||
    registryFreshnessFilter !== 'all' ||
    bookFilter !== 'all' ||
    bookKindFilter !== 'all' ||
    lastBookFilter !== 'all' ||
    activityFilter !== 'all' ||
    activityKindFilter !== 'all';

  function clearFilters() {
    setSearch('');
    setFamily('all');
    setKind('all');
    setValidationFilter('all');
    setRegistryImportFilter('all');
    setRegistryFreshnessFilter('all');
    setBookFilter('all');
    setBookKindFilter('all');
    setLastBookFilter('all');
    setActivityFilter('all');
    setActivityKindFilter('all');
  }

  return (
    <div className="stack">
      <PageHeader
        title={t('entities.title')}
        actions={
          <>
            <GateButtonLink perm="entity.create" to="/entidades/importar" icon={<Icon.Tray />}>
              {t('entities.importButton')}
            </GateButtonLink>
            <GateButtonLink
              perm="entity.create"
              to="/entidades/nova"
              variant="primary"
              icon={<Icon.Plus />}
            >
              {t('entities.newButton')}
            </GateButtonLink>
          </>
        }
      />

      <Card
        title={t('entities.registeredCard')}
        actions={
          data && data.length > 0 ? (
            <span aria-label={`A mostrar ${rows.length} de ${data.length} entidades`}>
              <Badge>
                {rows.length} de {data.length}
              </Badge>
            </span>
          ) : null
        }
      >
        {isLoading ? (
          <SkeletonTable cols={12} />
        ) : error ? (
          <ErrorNote error={error} />
        ) : !data || data.length === 0 ? (
          <EmptyState title={t('entities.empty.title')}>
            <p>
              {t('entities.emptyBody.before')}
              <strong>{t('entities.newButton')}</strong>
              {t('entities.emptyBody.after')}
            </p>
          </EmptyState>
        ) : (
          <div className="stack">
            <div
              className="row-wrap filter"
              role="search"
              aria-label="Pesquisar e filtrar entidades"
              style={{ alignItems: 'flex-end' }}
            >
              <Field label="Pesquisar" htmlFor="entities-search">
                <Input
                  id="entities-search"
                  type="search"
                  value={search}
                  placeholder="Nome, NIPC, sede, forma, livro ou atividade"
                  onChange={(e) => setSearch(e.target.value)}
                />
              </Field>
              <Field label="Família" htmlFor="entities-family-filter">
                <Select
                  id="entities-family-filter"
                  value={family}
                  onChange={(e) => setFamily(e.target.value as 'all' | EntityFamily)}
                  options={familyOptions}
                />
              </Field>
              <Field label="Forma" htmlFor="entities-kind-filter">
                <Select
                  id="entities-kind-filter"
                  value={kind}
                  onChange={(e) => setKind(e.target.value as 'all' | EntityKind)}
                  options={kindOptions}
                />
              </Field>
              <Field label="NIPC" htmlFor="entities-nipc-filter">
                <Select
                  id="entities-nipc-filter"
                  value={validationFilter}
                  onChange={(e) => setValidationFilter(e.target.value as ValidationFilter)}
                  options={VALIDATION_FILTER_OPTIONS}
                />
              </Field>
              <Field label="Registo" htmlFor="entities-registry-import-filter">
                <Select
                  id="entities-registry-import-filter"
                  value={registryImportFilter}
                  onChange={(e) => setRegistryImportFilter(e.target.value as RegistryImportFilter)}
                  options={REGISTRY_IMPORT_FILTER_OPTIONS}
                />
              </Field>
              <Field label="Validade" htmlFor="entities-registry-freshness-filter">
                <Select
                  id="entities-registry-freshness-filter"
                  value={registryFreshnessFilter}
                  onChange={(e) =>
                    setRegistryFreshnessFilter(e.target.value as RegistryFreshnessFilter)
                  }
                  options={REGISTRY_FRESHNESS_FILTER_OPTIONS}
                />
              </Field>
              <Field label="Livros" htmlFor="entities-book-filter">
                <Select
                  id="entities-book-filter"
                  value={bookFilter}
                  onChange={(e) => setBookFilter(e.target.value as BookFilter)}
                  options={BOOK_FILTER_OPTIONS}
                />
              </Field>
              <Field label="Tipo de livro" htmlFor="entities-book-kind-filter">
                <Select
                  id="entities-book-kind-filter"
                  value={bookKindFilter}
                  onChange={(e) => setBookKindFilter(e.target.value as BookKindFilter)}
                  options={BOOK_KIND_FILTER_OPTIONS}
                />
              </Field>
              <Field label="Último livro" htmlFor="entities-last-book-filter">
                <Select
                  id="entities-last-book-filter"
                  value={lastBookFilter}
                  onChange={(e) => setLastBookFilter(e.target.value as LastBookFilter)}
                  options={LAST_BOOK_FILTER_OPTIONS}
                />
              </Field>
              <Field label="Atividade" htmlFor="entities-activity-filter">
                <Select
                  id="entities-activity-filter"
                  value={activityFilter}
                  onChange={(e) => setActivityFilter(e.target.value as ActivityFilter)}
                  options={ACTIVITY_FILTER_OPTIONS}
                />
              </Field>
              <Field label="Última alteração" htmlFor="entities-activity-kind-filter">
                <Select
                  id="entities-activity-kind-filter"
                  value={activityKindFilter}
                  onChange={(e) => setActivityKindFilter(e.target.value)}
                  options={activityKindOptions}
                />
              </Field>
              <Button
                type="button"
                variant="ghost"
                icon={<Icon.Close />}
                disabled={!hasFilters}
                aria-label="Limpar filtros de entidades"
                onClick={clearFilters}
              >
                Limpar
              </Button>
            </div>

            {rows.length === 0 ? (
              <EmptyState title="Sem resultados">
                <p>Altere a pesquisa ou os filtros para voltar a ver entidades.</p>
              </EmptyState>
            ) : (
              <Table
                head={
                  <tr>
                    <th>{t('entities.th.name')}</th>
                    <th>{t('entities.th.nipc')}</th>
                    <th>{t('entities.th.seat')}</th>
                    <th>{t('entities.th.form')}</th>
                    <th>Matrícula</th>
                    <th>Constituição</th>
                    <th>Capital</th>
                    <th>CAE</th>
                    <th>Registo</th>
                    <th>Últ. registo</th>
                    <th>Fecho fiscal</th>
                    <th>Último livro</th>
                    <th>Última alteração / atividade</th>
                    <th>
                      <span className="sr-only">Ações</span>
                    </th>
                  </tr>
                }
              >
                {rows.map(
                  ({
                    entity: ent,
                    lastBook,
                    bookStateCounts: stateCounts,
                    activity,
                    registry,
                    hasActivitySummary,
                  }) => (
                    <tr key={ent.id}>
                      <td>{ent.name}</td>
                      <td>
                        <span className="nipc-cell">
                          <code className="mono">{ent.nipc}</code>
                          {!ent.nipc_validated ? <NipcBadge /> : null}
                        </span>
                      </td>
                      <td>{ent.seat}</td>
                      <td>
                        <EntityContext entity={ent} />
                      </td>
                      <td>
                        {registry?.matricula ? (
                          <code className="mono">{registry.matricula}</code>
                        ) : (
                          <span className="muted">—</span>
                        )}
                      </td>
                      <td>{formatDateValue(registry?.data_constituicao)}</td>
                      <td>{registry?.capital ?? <span className="muted">—</span>}</td>
                      <td>
                        <CaeSummary registry={registry} />
                      </td>
                      <td>
                        <RegistryFreshnessSummary registry={registry} />
                      </td>
                      <td>
                        <LastRegistryChange registry={registry} />
                      </td>
                      <td>
                        <code className="mono">{displayFiscalYearEnd(ent.fiscal_year_end)}</code>
                      </td>
                      <td>
                        <BookSummary
                          book={lastBook}
                          stateCounts={stateCounts}
                          loading={!hasActivitySummary && books.isLoading}
                          error={hasActivitySummary ? null : books.error}
                        />
                      </td>
                      <td>
                        <ActivitySummary activity={activity} locale={locale} />
                      </td>
                      <td className="users-actions">
                        <IconButton
                          icon={<Icon.ArrowRight />}
                          label={t('common.open')}
                          onClick={() => navigate(`/entidades/${ent.id}`)}
                        />
                      </td>
                    </tr>
                  ),
                )}
              </Table>
            )}
          </div>
        )}
      </Card>
    </div>
  );
}
