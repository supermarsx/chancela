/**
 * Entidades — the full-width list of registered entities. Creating an entity (by hand or
 * from a certidão permanente) lives behind neat buttons in the panel header, each opening
 * its own dedicated route (`/entidades/nova`, `/entidades/importar`) — so the list is no
 * longer squeezed by an always-visible aside form (t13 items 1–2).
 */
import { useDeferredValue, useMemo, useState, type ReactNode } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useBooks, useEntities, useSettings } from '../../api/hooks';
import {
  bookKindLabels,
  bookStateLabels,
  closingReasonLabels,
  entityFamilyLabels,
  entityKindLabels,
} from '../../api/labels';
import {
  BOOK_KINDS,
  DEFAULT_SETTINGS,
  type BookKind,
  type BookState,
  type BookView,
  type Entity,
  type EntityBookStateCounts,
  type EntityFamily,
  type EntityKind,
  type EntityRegistrySummary,
  type LedgerEventView,
  type RegisteredEntityColumn,
} from '../../api/types';
import { useLocale, useT, type MessageKey, type TFunction } from '../../i18n';
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
  Truncate,
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

const BOOK_FILTER_OPTIONS: { value: BookFilter; labelKey: MessageKey }[] = [
  { value: 'all', labelKey: 'entities.filters.books.all' },
  { value: 'open', labelKey: 'entities.filters.books.open' },
  { value: 'created', labelKey: 'entities.filters.books.created' },
  { value: 'closed', labelKey: 'entities.filters.books.closed' },
  { value: 'no-open', labelKey: 'entities.filters.books.noOpen' },
  { value: 'none', labelKey: 'entities.filters.books.none' },
];

const BOOK_KIND_FILTER_OPTIONS: { value: BookKindFilter; labelKey?: MessageKey; label?: string }[] =
  [
    { value: 'all', labelKey: 'entities.filters.bookKind.all' },
    ...BOOK_KINDS.map((value) => ({ value, label: bookKindLabels[value] })),
  ];

const LAST_BOOK_FILTER_OPTIONS: { value: LastBookFilter; labelKey?: MessageKey; label?: string }[] =
  [
    { value: 'all', labelKey: 'entities.filters.lastBook.all' },
    { value: 'Open', label: bookStateLabels.Open },
    { value: 'Created', label: bookStateLabels.Created },
    { value: 'Closed', label: bookStateLabels.Closed },
    { value: 'none', labelKey: 'entities.filters.lastBook.none' },
  ];

const ACTIVITY_FILTER_OPTIONS: { value: ActivityFilter; labelKey: MessageKey }[] = [
  { value: 'all', labelKey: 'entities.filters.activity.all' },
  { value: 'registry', labelKey: 'entities.filters.activity.registry' },
  { value: 'entity', labelKey: 'entities.filters.activity.entity' },
  { value: 'book', labelKey: 'entities.filters.activity.book' },
  { value: 'act', labelKey: 'entities.filters.activity.act' },
  { value: 'document', labelKey: 'entities.filters.activity.document' },
  { value: 'none', labelKey: 'entities.filters.activity.none' },
];

const VALIDATION_FILTER_OPTIONS: { value: ValidationFilter; labelKey: MessageKey }[] = [
  { value: 'all', labelKey: 'entities.filters.nipc.all' },
  { value: 'validated', labelKey: 'entities.filters.nipc.validated' },
  { value: 'unvalidated', labelKey: 'entities.filters.nipc.unvalidated' },
];

const REGISTRY_IMPORT_FILTER_OPTIONS: { value: RegistryImportFilter; labelKey: MessageKey }[] = [
  { value: 'all', labelKey: 'entities.filters.registry.all' },
  { value: 'imported', labelKey: 'entities.filters.registry.imported' },
  { value: 'not-imported', labelKey: 'entities.filters.registry.notImported' },
];

const REGISTRY_FRESHNESS_FILTER_OPTIONS: {
  value: RegistryFreshnessFilter;
  labelKey: MessageKey;
}[] = [
  { value: 'all', labelKey: 'entities.filters.freshness.all' },
  { value: 'fresh', labelKey: 'entities.filters.freshness.fresh' },
  { value: 'expired', labelKey: 'entities.filters.freshness.expired' },
  { value: 'no-expiry', labelKey: 'entities.filters.freshness.noExpiry' },
];

const ENTITY_COLUMN_LABEL_KEYS: Record<RegisteredEntityColumn, MessageKey> = {
  Name: 'entities.columns.name',
  Nipc: 'entities.columns.nipc',
  Seat: 'entities.columns.seat',
  Type: 'entities.columns.type',
  Matricula: 'entities.columns.matricula',
  Constitution: 'entities.columns.constitution',
  Capital: 'entities.columns.capital',
  Cae: 'entities.columns.cae',
  Registry: 'entities.columns.registry',
  LastRegistryChange: 'entities.columns.lastRegistryChange',
  FiscalYearEnd: 'entities.columns.fiscalYearEnd',
  LastBook: 'entities.columns.lastBook',
  LastActivity: 'entities.columns.lastActivity',
  Actions: 'entities.columns.actions',
};

const COMPACT_ENTITY_KIND_LABELS: Partial<Record<EntityKind, string>> = {
  SociedadeEmNomeColetivo: 'S.N.C.',
  SociedadePorQuotas: 'Lda.',
  SociedadeUnipessoalPorQuotas: 'Unip. Lda.',
  SociedadeAnonima: 'S.A.',
  SociedadeEmComanditaSimples: 'S.C.S.',
  SociedadeEmComanditaPorAcoes: 'S.C.A.',
};

function normalizeSearch(value: string): string {
  return value
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase();
}

function displayFiscalYearEnd(value: string | null | undefined, t: TFunction): string {
  return value ? value : t('entities.fiscalYearEnd.default');
}

function cx(...classes: Array<string | false | null | undefined>): string {
  return classes.filter((item): item is string => !!item).join(' ');
}

function joinCellParts(parts: Array<string | null | undefined | false>): string {
  return parts
    .filter((part): part is string => typeof part === 'string' && part !== '')
    .join(' · ');
}

function CellLine({
  title,
  className,
  children,
}: {
  title: string;
  className?: string;
  children: ReactNode;
}) {
  return (
    <span className={cx('entity-cell-line', className)} title={title}>
      {children}
    </span>
  );
}

function EntityTableCell({
  column,
  actions = false,
  children,
}: {
  column: RegisteredEntityColumn;
  actions?: boolean;
  children: ReactNode;
}) {
  return (
    <td
      className={cx(
        'entities-table__cell',
        actions ? 'entities-table__cell--actions' : 'entities-table__cell--truncate',
      )}
      data-entity-column={column}
    >
      {children}
    </td>
  );
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

function formatActivityDate(value: string, locale: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat(locale, { dateStyle: 'short' }).format(date);
}

function formatDateValue(value: string | null | undefined, fallback = '—'): string {
  return value ?? fallback;
}

function caeLabel(cae: EntityRegistrySummary['cae'][number]): string {
  const suffix = cae.role === 'Principal' ? ' principal' : ' secundário';
  return `${cae.code}${suffix}`;
}

function caeDetails(cae: EntityRegistrySummary['cae'][number]): string {
  const parts = [caeLabel(cae)];
  if (cae.designation) parts.push(cae.designation);
  if (cae.level || cae.revision) parts.push([cae.level, cae.revision].filter(Boolean).join(' · '));
  return parts.join(' — ');
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
  t: TFunction,
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
      displayFiscalYearEnd(entity.fiscal_year_end, t),
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

function optionLabels<T extends string>(
  options: { value: T; labelKey?: MessageKey; label?: string }[],
  t: TFunction,
): { value: T; label: string }[] {
  return options.map((option) => ({
    value: option.value,
    label: option.labelKey ? t(option.labelKey) : (option.label ?? ''),
  }));
}

function familyFilterOptions(
  entities: Entity[] | undefined,
  t: TFunction,
): { value: string; label: string }[] {
  const seen = new Set<EntityFamily>();
  for (const entity of entities ?? []) seen.add(entity.family);
  return [
    { value: 'all', label: t('entities.filters.family.all') },
    ...Array.from(seen).map((value) => ({ value, label: entityFamilyLabels[value] })),
  ];
}

function kindFilterOptions(
  entities: Entity[] | undefined,
  t: TFunction,
): { value: string; label: string }[] {
  const seen = new Set<EntityKind>();
  for (const entity of entities ?? []) seen.add(entity.kind);
  return [
    { value: 'all', label: t('entities.filters.kind.all') },
    ...Array.from(seen).map((value) => ({ value, label: entityKindLabels[value] })),
  ];
}

function activityKindFilterOptions(
  rows: EnrichedEntityRow[],
  t: TFunction,
): { value: string; label: string }[] {
  const kinds = new Set<string>();
  for (const row of rows) {
    if (row.activity) kinds.add(row.activity.kind);
  }
  return [
    { value: 'all', label: t('entities.filters.activityKind.all') },
    ...Array.from(kinds)
      .sort((a, b) => activityLabel(a).localeCompare(activityLabel(b)))
      .map((kind) => ({ value: kind, label: activityLabel(kind) })),
    { value: 'none', label: t('entities.filters.activityKind.none') },
  ];
}

function compactEntityKindLabel(kind: EntityKind): string {
  return COMPACT_ENTITY_KIND_LABELS[kind] ?? entityKindLabels[kind];
}

function EntityContext({ entity }: { entity: Entity }) {
  const details = joinCellParts([
    entityKindLabels[entity.kind],
    entityFamilyLabels[entity.family],
    `Regras ${entityRulePack(entity)}`,
    entityTemplateFamily(entity),
  ]);
  return (
    <CellLine title={details} className="entity-cell-line--compact entity-cell-line--type">
      <span className="entity-cell-line__primary">{compactEntityKindLabel(entity.kind)}</span>
    </CellLine>
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
  if (loading) return <Truncate text="A carregar livros…" className="muted" />;
  if (error) return <Truncate text="Livros indisponíveis" className="muted" />;
  if (!book) return <Truncate text="Sem livros" className="muted" />;
  const bookMeta = joinCellParts([
    book.purpose ?? 'Sem finalidade',
    `Última ata ${book.last_ata_number > 0 ? book.last_ata_number : '—'}`,
    bookDateSummary(book),
  ]);
  const closingReason = book.closing_reason
    ? `Motivo ${closingReasonLabels[book.closing_reason]}`
    : null;
  const states = bookStateSummary(stateCounts);
  const title = joinCellParts([
    bookKindLabels[book.kind],
    bookStateLabels[book.state],
    bookMeta,
    closingReason,
    states,
  ]);
  return (
    <CellLine title={title}>
      <Link className="entity-cell-line__link" to={`/livros/${book.id}`}>
        {bookKindLabels[book.kind]}
      </Link>
      <Badge tone={bookStateTone(book.state)}>{bookStateLabels[book.state]}</Badge>
      <span className="entity-cell-line__text muted">{bookMeta}</span>
      {closingReason ? <span className="entity-cell-line__text muted">{closingReason}</span> : null}
      <span className="entity-cell-line__text muted">{states}</span>
    </CellLine>
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
      <CellLine title="Sem atividade no arquivo">
        <span className="entity-cell-line__text muted">Sem atividade</span>
      </CellLine>
    );
  }
  const timestamp = formatActivityTimestamp(activity.timestamp, locale);
  const activityDate = formatActivityDate(activity.timestamp, locale);
  const title = joinCellParts([activityLabel(activity.kind), timestamp, activity.actor]);
  return (
    <CellLine title={title} className="entity-cell-line--compact entity-cell-line--activity">
      <Badge tone={activityTone(activity.kind)}>{activityLabel(activity.kind)}</Badge>
      <span className="entity-cell-line__text muted">
        <time dateTime={activity.timestamp}>{activityDate}</time>
      </span>
    </CellLine>
  );
}

function RegistryFreshnessSummary({ registry }: { registry: EntityRegistrySummary | null }) {
  if (!registry) {
    return (
      <CellLine title="Não importado · Sem certidão">
        <Badge tone="neutral">Não importado</Badge>
        <span className="entity-cell-line__text muted">Sem certidão</span>
      </CellLine>
    );
  }
  const meta = joinCellParts([
    `Obtido ${formatDateValue(registry.retrieved_at)}`,
    `Válido até ${formatDateValue(registry.valid_until)}`,
  ]);
  const title = joinCellParts([registryFreshnessLabel(registry), meta]);
  return (
    <CellLine title={title}>
      <Badge tone={registryFreshnessTone(registry)}>{registryFreshnessLabel(registry)}</Badge>
      <span className="entity-cell-line__text muted">{meta}</span>
    </CellLine>
  );
}

function CaeSummary({ registry }: { registry: EntityRegistrySummary | null }) {
  if (!registry || registry.cae.length === 0) return <Truncate text="—" className="muted" />;
  const first = registry.cae.find((cae) => cae.role === 'Principal') ?? registry.cae[0];
  const fullDetails = registry.cae.map(caeDetails).join('\n');
  return (
    <CellLine title={fullDetails}>
      <span className="mono">{caeLabel(first)}</span>
      {first.designation ? (
        <span className="entity-cell-line__text muted">{first.designation}</span>
      ) : null}
    </CellLine>
  );
}

function LastRegistryChange({ registry }: { registry: EntityRegistrySummary | null }) {
  const change = registry?.last_registry_change;
  if (!change) return <Truncate text="—" className="muted" />;
  const meta = joinCellParts([formatDateValue(change.date), change.reference]);
  const title = joinCellParts([change.label, meta]);
  return (
    <CellLine title={title}>
      <span className="entity-cell-line__primary">{change.label}</span>
      <span className="entity-cell-line__text muted">{meta}</span>
    </CellLine>
  );
}

function normalizeVisibleColumns(
  columns: readonly RegisteredEntityColumn[],
): RegisteredEntityColumn[] {
  const seen = new Set<RegisteredEntityColumn>();
  const next = columns.filter((column) => {
    if (seen.has(column)) return false;
    seen.add(column);
    return true;
  });
  if (!seen.has('Actions')) next.push('Actions');
  return next.length > 0 ? next : [...DEFAULT_SETTINGS.ui.registered_entity_columns];
}

function EntityColumnCell({
  column,
  entity,
  registry,
  lastBook,
  stateCounts,
  activity,
  locale,
  loadingBooks,
  booksError,
  onOpen,
  openLabel,
  t,
}: {
  column: RegisteredEntityColumn;
  entity: Entity;
  registry: EntityRegistrySummary | null;
  lastBook: BookView | null;
  stateCounts: Record<BookState, number>;
  activity: LedgerEventView | null;
  locale: string;
  loadingBooks: boolean;
  booksError: unknown;
  onOpen: () => void;
  openLabel: string;
  t: TFunction;
}) {
  switch (column) {
    case 'Name':
      return (
        <EntityTableCell column={column}>
          <Truncate text={entity.name} />
        </EntityTableCell>
      );
    case 'Nipc':
      return (
        <EntityTableCell column={column}>
          <CellLine
            className="entity-cell-line--nipc"
            title={joinCellParts([
              entity.nipc,
              entity.nipc_validated ? 'NIPC validado' : 'NIPC não validado',
            ])}
          >
            <code className="mono">{entity.nipc}</code>
            {!entity.nipc_validated ? <NipcBadge /> : null}
          </CellLine>
        </EntityTableCell>
      );
    case 'Seat':
      return (
        <EntityTableCell column={column}>
          <Truncate text={entity.seat} />
        </EntityTableCell>
      );
    case 'Type':
      return (
        <EntityTableCell column={column}>
          <EntityContext entity={entity} />
        </EntityTableCell>
      );
    case 'Matricula':
      return (
        <EntityTableCell column={column}>
          {registry?.matricula ? (
            <Truncate text={registry.matricula} mono />
          ) : (
            <Truncate text="—" className="muted" />
          )}
        </EntityTableCell>
      );
    case 'Constitution':
      return (
        <EntityTableCell column={column}>
          <Truncate text={formatDateValue(registry?.data_constituicao)} />
        </EntityTableCell>
      );
    case 'Capital':
      return (
        <EntityTableCell column={column}>
          <Truncate text={registry?.capital ?? '—'} className={registry?.capital ? '' : 'muted'} />
        </EntityTableCell>
      );
    case 'Cae':
      return (
        <EntityTableCell column={column}>
          <CaeSummary registry={registry} />
        </EntityTableCell>
      );
    case 'Registry':
      return (
        <EntityTableCell column={column}>
          <RegistryFreshnessSummary registry={registry} />
        </EntityTableCell>
      );
    case 'LastRegistryChange':
      return (
        <EntityTableCell column={column}>
          <LastRegistryChange registry={registry} />
        </EntityTableCell>
      );
    case 'FiscalYearEnd':
      return (
        <EntityTableCell column={column}>
          <Truncate text={displayFiscalYearEnd(entity.fiscal_year_end, t)} mono />
        </EntityTableCell>
      );
    case 'LastBook':
      return (
        <EntityTableCell column={column}>
          <BookSummary
            book={lastBook}
            stateCounts={stateCounts}
            loading={loadingBooks}
            error={booksError}
          />
        </EntityTableCell>
      );
    case 'LastActivity':
      return (
        <EntityTableCell column={column}>
          <ActivitySummary activity={activity} locale={locale} />
        </EntityTableCell>
      );
    case 'Actions':
      return (
        <EntityTableCell column={column} actions>
          <span className="users-actions entities-table__actions">
            <IconButton icon={<Icon.ArrowRight />} label={openLabel} onClick={onOpen} />
          </span>
        </EntityTableCell>
      );
  }
}

export function EntitiesPage() {
  const t = useT();
  const locale = useLocale();
  const navigate = useNavigate();
  const { data, isLoading, error } = useEntities();
  const settings = useSettings();
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
          t,
        ),
      };
    });
  }, [books.data, data, locale, t]);

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

  const familyOptions = familyFilterOptions(data, t);
  const kindOptions = kindFilterOptions(data, t);
  const activityKindOptions = activityKindFilterOptions(enrichedRows, t);
  const validationFilterOptions = optionLabels(VALIDATION_FILTER_OPTIONS, t);
  const registryImportFilterOptions = optionLabels(REGISTRY_IMPORT_FILTER_OPTIONS, t);
  const registryFreshnessFilterOptions = optionLabels(REGISTRY_FRESHNESS_FILTER_OPTIONS, t);
  const bookFilterOptions = optionLabels(BOOK_FILTER_OPTIONS, t);
  const bookKindFilterOptions = optionLabels(BOOK_KIND_FILTER_OPTIONS, t);
  const lastBookFilterOptions = optionLabels(LAST_BOOK_FILTER_OPTIONS, t);
  const activityFilterOptions = optionLabels(ACTIVITY_FILTER_OPTIONS, t);
  const visibleColumns = normalizeVisibleColumns(
    settings.data?.ui?.registered_entity_columns ?? DEFAULT_SETTINGS.ui.registered_entity_columns,
  );

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
        lede={t('entities.lede')}
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
            <span
              aria-label={t('entities.filters.count.aria', {
                shown: rows.length,
                total: data.length,
              })}
            >
              <Badge>
                {t('entities.filters.count', { shown: rows.length, total: data.length })}
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
              className="stack--tight entities-filters"
              role="search"
              aria-label={t('entities.filters.aria')}
            >
              <div className="entities-filterbar filter">
                <div className="entities-filterbar__primary">
                  <Field label={t('entities.filters.search.label')} htmlFor="entities-search">
                    <Input
                      id="entities-search"
                      type="search"
                      value={search}
                      placeholder={t('entities.filters.search.placeholder')}
                      onChange={(e) => setSearch(e.target.value)}
                    />
                  </Field>
                  <Field
                    label={t('entities.filters.family.label')}
                    htmlFor="entities-family-filter"
                  >
                    <Select
                      id="entities-family-filter"
                      value={family}
                      onChange={(e) => setFamily(e.target.value as 'all' | EntityFamily)}
                      options={familyOptions}
                    />
                  </Field>
                  <Field label={t('entities.filters.kind.label')} htmlFor="entities-kind-filter">
                    <Select
                      id="entities-kind-filter"
                      value={kind}
                      onChange={(e) => setKind(e.target.value as 'all' | EntityKind)}
                      options={kindOptions}
                    />
                  </Field>
                  <Button
                    type="button"
                    variant="ghost"
                    icon={<Icon.Close />}
                    disabled={!hasFilters}
                    aria-label={t('entities.filters.clear.aria')}
                    onClick={clearFilters}
                  >
                    {t('entities.filters.clear')}
                  </Button>
                </div>
              </div>
              <details className="entities-advanced-filters">
                <summary>{t('entities.filters.advanced')}</summary>
                <div className="entities-advanced-filters__body filter">
                  <Field label={t('entities.filters.nipc.label')} htmlFor="entities-nipc-filter">
                    <Select
                      id="entities-nipc-filter"
                      value={validationFilter}
                      onChange={(e) => setValidationFilter(e.target.value as ValidationFilter)}
                      options={validationFilterOptions}
                    />
                  </Field>
                  <Field
                    label={t('entities.filters.registry.label')}
                    htmlFor="entities-registry-import-filter"
                  >
                    <Select
                      id="entities-registry-import-filter"
                      value={registryImportFilter}
                      onChange={(e) =>
                        setRegistryImportFilter(e.target.value as RegistryImportFilter)
                      }
                      options={registryImportFilterOptions}
                    />
                  </Field>
                  <Field
                    label={t('entities.filters.freshness.label')}
                    htmlFor="entities-registry-freshness-filter"
                  >
                    <Select
                      id="entities-registry-freshness-filter"
                      value={registryFreshnessFilter}
                      onChange={(e) =>
                        setRegistryFreshnessFilter(e.target.value as RegistryFreshnessFilter)
                      }
                      options={registryFreshnessFilterOptions}
                    />
                  </Field>
                  <Field label={t('entities.filters.books.label')} htmlFor="entities-book-filter">
                    <Select
                      id="entities-book-filter"
                      value={bookFilter}
                      onChange={(e) => setBookFilter(e.target.value as BookFilter)}
                      options={bookFilterOptions}
                    />
                  </Field>
                  <Field
                    label={t('entities.filters.bookKind.label')}
                    htmlFor="entities-book-kind-filter"
                  >
                    <Select
                      id="entities-book-kind-filter"
                      value={bookKindFilter}
                      onChange={(e) => setBookKindFilter(e.target.value as BookKindFilter)}
                      options={bookKindFilterOptions}
                    />
                  </Field>
                  <Field
                    label={t('entities.filters.lastBook.label')}
                    htmlFor="entities-last-book-filter"
                  >
                    <Select
                      id="entities-last-book-filter"
                      value={lastBookFilter}
                      onChange={(e) => setLastBookFilter(e.target.value as LastBookFilter)}
                      options={lastBookFilterOptions}
                    />
                  </Field>
                  <Field
                    label={t('entities.filters.activity.label')}
                    htmlFor="entities-activity-filter"
                  >
                    <Select
                      id="entities-activity-filter"
                      value={activityFilter}
                      onChange={(e) => setActivityFilter(e.target.value as ActivityFilter)}
                      options={activityFilterOptions}
                    />
                  </Field>
                  <Field
                    label={t('entities.filters.activityKind.label')}
                    htmlFor="entities-activity-kind-filter"
                  >
                    <Select
                      id="entities-activity-kind-filter"
                      value={activityKindFilter}
                      onChange={(e) => setActivityKindFilter(e.target.value)}
                      options={activityKindOptions}
                    />
                  </Field>
                </div>
              </details>
            </div>

            {rows.length === 0 ? (
              <EmptyState title={t('entities.filters.empty.title')}>
                <p>{t('entities.filters.empty.body')}</p>
              </EmptyState>
            ) : (
              <div className="entities-table">
                <Table
                  head={
                    <tr>
                      {visibleColumns.map((column) => {
                        const label = t(ENTITY_COLUMN_LABEL_KEYS[column]);
                        return (
                          <th key={column} data-entity-column={column} title={label}>
                            {label}
                          </th>
                        );
                      })}
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
                        {visibleColumns.map((column) => (
                          <EntityColumnCell
                            key={column}
                            column={column}
                            entity={ent}
                            registry={registry}
                            lastBook={lastBook}
                            stateCounts={stateCounts}
                            activity={activity}
                            locale={locale}
                            loadingBooks={!hasActivitySummary && books.isLoading}
                            booksError={hasActivitySummary ? null : books.error}
                            onOpen={() => navigate(`/entidades/${ent.id}`)}
                            openLabel={t('common.open')}
                            t={t}
                          />
                        ))}
                      </tr>
                    ),
                  )}
                </Table>
              </div>
            )}
          </div>
        )}
      </Card>
    </div>
  );
}
