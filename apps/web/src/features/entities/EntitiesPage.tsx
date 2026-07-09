/**
 * Entidades — the full-width list of registered entities. Creating an entity (by hand or
 * from a certidão permanente) lives behind neat buttons in the panel header, each opening
 * its own dedicated route (`/entidades/nova`, `/entidades/importar`) — so the list is no
 * longer squeezed by an always-visible aside form (t13 items 1–2).
 */
import { useDeferredValue, useMemo, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useBooks, useEntities, useLedger } from '../../api/hooks';
import {
  bookKindLabels,
  bookStateLabels,
  entityFamilyLabels,
  entityKindLabels,
} from '../../api/labels';
import type { BookView, Entity, EntityFamily, EntityKind, LedgerEventView } from '../../api/types';
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
type ActivityFilter = 'all' | 'registry' | 'entity' | 'book' | 'act' | 'document' | 'none';
type ValidationFilter = 'all' | 'validated' | 'unvalidated';

interface EnrichedEntityRow {
  entity: Entity;
  books: BookView[];
  currentBook: BookView | null;
  activity: LedgerEventView | null;
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

const ACTIVITY_FILTER_OPTIONS: { value: ActivityFilter; label: string }[] = [
  { value: 'all', label: 'Toda a atividade' },
  { value: 'registry', label: 'Registo importado' },
  { value: 'entity', label: 'Alteração da entidade' },
  { value: 'book', label: 'Livros' },
  { value: 'act', label: 'Atas e convocatórias' },
  { value: 'document', label: 'Documentos e assinaturas' },
  { value: 'none', label: 'Sem atividade recente' },
];

const VALIDATION_FILTER_OPTIONS: { value: ValidationFilter; label: string }[] = [
  { value: 'all', label: 'Todos os NIPC' },
  { value: 'validated', label: 'NIPC validado' },
  { value: 'unvalidated', label: 'NIPC por validar' },
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

function compareLedgerEventRecency(a: LedgerEventView, b: LedgerEventView): number {
  const timestampRank = dateRank(a.timestamp) - dateRank(b.timestamp);
  if (timestampRank !== 0) return timestampRank;
  return a.seq - b.seq;
}

function selectCurrentOrLatestBook(books: BookView[]): BookView | null {
  if (books.length === 0) return null;
  return [...books].sort((a, b) => {
    const stateRank = Number(b.state === 'Open') - Number(a.state === 'Open');
    if (stateRank !== 0) return stateRank;
    const date =
      Math.max(dateRank(b.opening_date), dateRank(b.closing_date)) -
      Math.max(dateRank(a.opening_date), dateRank(a.closing_date));
    if (date !== 0) return date;
    return b.last_ata_number - a.last_ata_number;
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

function segmentValues(value: string, prefix: 'entity:' | 'company:' | 'book:'): string[] {
  return value
    .split('/')
    .filter((segment) => segment.startsWith(prefix))
    .map((segment) => segment.slice(prefix.length))
    .filter(Boolean);
}

function collectActivityEntityIds(
  event: LedgerEventView,
  entityIds: Set<string>,
  bookEntityIds: Map<string, string>,
): Set<string> {
  const ids = new Set<string>();
  if (entityIds.has(event.scope)) ids.add(event.scope);

  for (const source of [event.scope, ...event.chains]) {
    for (const entityId of segmentValues(source, 'entity:')) {
      if (entityIds.has(entityId)) ids.add(entityId);
    }
    for (const entityId of segmentValues(source, 'company:')) {
      if (entityIds.has(entityId)) ids.add(entityId);
    }
    for (const bookId of segmentValues(source, 'book:')) {
      const entityId = bookEntityIds.get(bookId);
      if (entityId) ids.add(entityId);
    }
  }

  return ids;
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

function indexLatestActivityByEntity(
  events: LedgerEventView[] | undefined,
  entities: Entity[],
  bookEntityIds: Map<string, string>,
): Map<string, LedgerEventView> {
  const entityIds = new Set(entities.map((entity) => entity.id));
  const latest = new Map<string, LedgerEventView>();

  for (const event of events ?? []) {
    for (const entityId of collectActivityEntityIds(event, entityIds, bookEntityIds)) {
      const previous = latest.get(entityId);
      if (!previous || compareLedgerEventRecency(event, previous) > 0) {
        latest.set(entityId, event);
      }
    }
  }

  return latest;
}

function bookDateSummary(book: BookView): string {
  const opened = book.opening_date ? `Aberto em ${book.opening_date}` : 'Sem data de abertura';
  if (!book.closing_date) return opened;
  return `${opened} · Encerrado em ${book.closing_date}`;
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
  activity: LedgerEventView | null,
  locale: string,
): string {
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
      ...books.flatMap((book) => [
        book.id,
        bookKindLabels[book.kind],
        bookStateLabels[book.state],
        book.purpose ?? '',
        book.opening_date ?? '',
        book.closing_date ?? '',
        String(book.last_ata_number || ''),
      ]),
      activity ? activityLabel(activity.kind) : '',
      activity?.kind ?? '',
      activity?.actor ?? '',
      activity?.scope ?? '',
    ].join(' '),
  );
}

function entityMatchesBookFilter(books: BookView[], filter: BookFilter): boolean {
  if (filter === 'all') return true;
  if (filter === 'none') return books.length === 0;
  const hasOpen = books.some((book) => book.state === 'Open');
  if (filter === 'open') return hasOpen;
  if (filter === 'created') return books.some((book) => book.state === 'Created');
  if (filter === 'closed') return books.some((book) => book.state === 'Closed');
  return !hasOpen;
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

function entityMatchesValidationFilter(entity: Entity, filter: ValidationFilter): boolean {
  if (filter === 'all') return true;
  return filter === 'validated' ? entity.nipc_validated : !entity.nipc_validated;
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
  loading,
  error,
}: {
  book: BookView | null;
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
    </span>
  );
}

function ActivitySummary({
  activity,
  loading,
  error,
  locale,
  entityId,
}: {
  activity: LedgerEventView | null;
  loading: boolean;
  error: unknown;
  locale: string;
  entityId: string;
}) {
  if (loading) return <span className="muted">A consultar arquivo…</span>;
  if (error) {
    return (
      <span style={SUMMARY_STACK_STYLE}>
        <span className="muted">Arquivo indisponível</span>
        <Link to={`/entidades/${entityId}`}>Ver detalhe</Link>
      </span>
    );
  }
  if (!activity) {
    return (
      <span style={SUMMARY_STACK_STYLE}>
        <span className="muted">Sem atividade no arquivo recente</span>
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

export function EntitiesPage() {
  const t = useT();
  const locale = useLocale();
  const navigate = useNavigate();
  const { data, isLoading, error } = useEntities();
  const books = useBooks();
  const ledger = useLedger({ limit: 500 });
  const [search, setSearch] = useState('');
  const deferredSearch = useDeferredValue(search);
  const [family, setFamily] = useState<'all' | EntityFamily>('all');
  const [kind, setKind] = useState<'all' | EntityKind>('all');
  const [validationFilter, setValidationFilter] = useState<ValidationFilter>('all');
  const [bookFilter, setBookFilter] = useState<BookFilter>('all');
  const [activityFilter, setActivityFilter] = useState<ActivityFilter>('all');

  const enrichedRows = useMemo<EnrichedEntityRow[]>(() => {
    const entities = data ?? [];
    const booksByEntity = indexBooksByEntity(books.data);
    const bookEntityIds = new Map((books.data ?? []).map((book) => [book.id, book.entity_id]));
    const activityByEntity = indexLatestActivityByEntity(ledger.data, entities, bookEntityIds);

    return entities.map((entity) => {
      const entityBooks = booksByEntity.get(entity.id) ?? [];
      const activity = activityByEntity.get(entity.id) ?? null;
      return {
        entity,
        books: entityBooks,
        currentBook: selectCurrentOrLatestBook(entityBooks),
        activity,
        searchText: buildSearchText(entity, entityBooks, activity, locale),
      };
    });
  }, [books.data, data, ledger.data, locale]);

  const query = normalizeSearch(deferredSearch.trim());
  const rows = useMemo(() => {
    return enrichedRows.filter(({ entity, books: entityBooks, activity, searchText }) => {
      if (family !== 'all' && entity.family !== family) return false;
      if (kind !== 'all' && entity.kind !== kind) return false;
      if (!entityMatchesValidationFilter(entity, validationFilter)) return false;
      if (!entityMatchesBookFilter(entityBooks, bookFilter)) return false;
      if (!entityMatchesActivityFilter(activity, activityFilter)) return false;
      return query === '' || searchText.includes(query);
    });
  }, [activityFilter, bookFilter, enrichedRows, family, kind, query, validationFilter]);

  const familyOptions = familyFilterOptions(data);
  const kindOptions = kindFilterOptions(data);

  const hasFilters =
    search.trim() !== '' ||
    family !== 'all' ||
    kind !== 'all' ||
    validationFilter !== 'all' ||
    bookFilter !== 'all' ||
    activityFilter !== 'all';

  function clearFilters() {
    setSearch('');
    setFamily('all');
    setKind('all');
    setValidationFilter('all');
    setBookFilter('all');
    setActivityFilter('all');
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
          <SkeletonTable cols={8} />
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
              <Field label="Livros" htmlFor="entities-book-filter">
                <Select
                  id="entities-book-filter"
                  value={bookFilter}
                  onChange={(e) => setBookFilter(e.target.value as BookFilter)}
                  options={BOOK_FILTER_OPTIONS}
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
                    <th>Fecho fiscal</th>
                    <th>Livro atual / último</th>
                    <th>Última alteração / atividade</th>
                    <th>
                      <span className="sr-only">Ações</span>
                    </th>
                  </tr>
                }
              >
                {rows.map(({ entity: ent, currentBook, activity }) => (
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
                      <code className="mono">{displayFiscalYearEnd(ent.fiscal_year_end)}</code>
                    </td>
                    <td>
                      <BookSummary
                        book={currentBook}
                        loading={books.isLoading}
                        error={books.error}
                      />
                    </td>
                    <td>
                      <ActivitySummary
                        activity={activity}
                        loading={ledger.isLoading}
                        error={ledger.error}
                        locale={locale}
                        entityId={ent.id}
                      />
                    </td>
                    <td className="users-actions">
                      <IconButton
                        icon={<Icon.ArrowRight />}
                        label={t('common.open')}
                        onClick={() => navigate(`/entidades/${ent.id}`)}
                      />
                    </td>
                  </tr>
                ))}
              </Table>
            )}
          </div>
        )}
      </Card>
    </div>
  );
}
