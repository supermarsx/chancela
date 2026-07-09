import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react';
import {
  DEFAULT_SETTINGS,
  REGISTERED_ENTITY_COLUMNS,
  type BookView,
  type Entity,
  type EntityRegistrySummary,
  type LedgerEventView,
} from '../../api/types';
import { renderWithProviders } from '../../test/utils';
import { EntitiesPage } from './EntitiesPage';

type EntityActivitySummary = NonNullable<Entity['activity_summary']>;

const PROFILE: Entity['profile'] = {
  family: 'CommercialCompany',
  rule_pack_id: 'csc-art63/v2',
  allowed_channels: ['Physical', 'Hybrid', 'Telematic', 'WrittenResolution'],
  signature_policy: 'QualifiedPreferred',
  template_family: 'csc-commercial',
  calendar_presets: [],
};

const ENTITY_A: Entity = {
  id: 'ent-a',
  name: 'Encosto Estratégico, Lda.',
  nipc: '503004642',
  nipc_validated: true,
  seat: 'Lisboa',
  family: 'CommercialCompany',
  kind: 'SociedadePorQuotas',
  fiscal_year_end: '06-30',
  profile: PROFILE,
  statute: null,
};

const ENTITY_B: Entity = {
  id: 'ent-b',
  name: 'Condomínio Azul',
  nipc: '900000001',
  nipc_validated: true,
  seat: 'Porto',
  family: 'Condominium',
  kind: 'Condominio',
  fiscal_year_end: null,
  profile: { ...PROFILE, family: 'Condominium', template_family: 'condo' },
  statute: null,
};

const REGISTRY_SUMMARY_A: EntityRegistrySummary = {
  imported: true,
  matricula: '99999/20200101',
  data_constituicao: '2020-01-01',
  capital: '5.000,00 EUR',
  cae: [
    {
      code: '68110',
      role: 'Principal',
      designation: 'Compra e venda de bens imobiliários.',
      level: 'Subclasse',
      revision: 'Rev4',
    },
    {
      code: '99999',
      role: 'Secundario',
      designation: null,
      level: null,
      revision: null,
    },
  ],
  retrieved_at: '2026-07-07T10:15:30Z',
  valid_until: '2027-07-05',
  expired: false,
  last_registry_change: {
    label: 'CONSTITUIÇÃO DE SOCIEDADE',
    date: '2020-01-01',
    reference: '1/20200101',
  },
};

const EXPIRED_REGISTRY_SUMMARY_B: EntityRegistrySummary = {
  imported: true,
  matricula: '11111/20190101',
  data_constituicao: '2019-01-01',
  capital: '1.000,00 EUR',
  cae: [
    {
      code: '70220',
      role: 'Principal',
      designation: 'Outras atividades de consultoria para os negócios e a gestão.',
      level: 'Subclasse',
      revision: 'Rev4',
    },
  ],
  retrieved_at: '2026-01-10T12:00:00Z',
  valid_until: '2026-01-01',
  expired: true,
  last_registry_change: {
    label: 'ALTERAÇÕES AO CONTRATO DE SOCIEDADE',
    date: '2025-12-15',
    reference: '2/20251215',
  },
};

const OPEN_BOOK: BookView = {
  id: 'book-open',
  entity_id: ENTITY_A.id,
  kind: 'AssembleiaGeral',
  state: 'Open',
  purpose: 'Assembleia anual 2026',
  numbering_scheme: 'Sequential',
  opening_date: '2026-01-10',
  closing_date: null,
  closing_reason: null,
  last_ata_number: 4,
  predecessor: null,
  required_signatories_abertura: [],
  required_signatories_encerramento: null,
};

const CLOSED_BOOK: BookView = {
  id: 'book-closed',
  entity_id: ENTITY_A.id,
  kind: 'ConselhoFiscal',
  state: 'Closed',
  purpose: 'Fiscalização 2026',
  numbering_scheme: 'Sequential',
  opening_date: '2026-02-01',
  closing_date: '2026-06-30',
  closing_reason: 'BookFull',
  last_ata_number: 8,
  predecessor: OPEN_BOOK.id,
  required_signatories_abertura: [],
  required_signatories_encerramento: ['Presidente'],
};

function ledgerEvent(entity: Entity, kind: LedgerEventView['kind'], seq: number): LedgerEventView {
  return {
    id: `event-${entity.id}-${seq}`,
    seq,
    actor: 'amelia.marques',
    justification: null,
    timestamp: `2026-07-0${seq}T10:15:30Z`,
    scope: entity.id,
    kind,
    payload_digest: '0'.repeat(64),
    prev_hash: '0'.repeat(64),
    hash: String(seq).repeat(64).slice(0, 64),
    chains: ['global', `company:${entity.id}`],
    attestation: null,
  };
}

function bookLedgerEvent(
  book: BookView,
  kind: LedgerEventView['kind'],
  seq: number,
): LedgerEventView {
  return {
    id: `event-${book.id}-${seq}`,
    seq,
    actor: 'bruno.costa',
    justification: null,
    timestamp: `2026-07-0${seq}T10:15:30Z`,
    scope: `book:${book.id}`,
    kind,
    payload_digest: '0'.repeat(64),
    prev_hash: '0'.repeat(64),
    hash: String(seq).repeat(64).slice(0, 64),
    chains: ['global', `book:${book.id}`],
    attestation: null,
  };
}

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function dateRank(value: string | null): number {
  if (!value) return 0;
  const time = new Date(value).getTime();
  return Number.isNaN(time) ? 0 : time;
}

function latestBookForEntity(entity: Entity, books: BookView[]): BookView | null {
  const entityBooks = books.filter((book) => book.entity_id === entity.id);
  if (entityBooks.length === 0) return null;
  return [...entityBooks].sort((a, b) => {
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

function bookStateCountsForEntity(
  entity: Entity,
  books: BookView[],
): EntityActivitySummary['book_state_counts'] {
  const counts = { created: 0, open: 0, closed: 0 };
  for (const book of books.filter((item) => item.entity_id === entity.id)) {
    if (book.state === 'Created') counts.created += 1;
    if (book.state === 'Open') counts.open += 1;
    if (book.state === 'Closed') counts.closed += 1;
  }
  return counts;
}

function eventTouchesEntity(entity: Entity, books: BookView[], event: LedgerEventView): boolean {
  if (event.scope === entity.id) return true;
  if (event.scope.includes(`entity:${entity.id}`)) return true;
  if (event.scope.includes(`company:${entity.id}`)) return true;
  if (event.chains.includes(`company:${entity.id}`)) return true;
  return books
    .filter((book) => book.entity_id === entity.id)
    .some(
      (book) => event.scope.includes(`book:${book.id}`) || event.chains.includes(`book:${book.id}`),
    );
}

function latestActivityForEntity(
  entity: Entity,
  books: BookView[],
  ledger: LedgerEventView[],
): LedgerEventView | null {
  return (
    ledger
      .filter((event) => eventTouchesEntity(entity, books, event))
      .sort((a, b) => dateRank(b.timestamp) - dateRank(a.timestamp) || b.seq - a.seq)[0] ?? null
  );
}

function withActivitySummary(entity: Entity, books: BookView[], ledger: LedgerEventView[]): Entity {
  return {
    ...entity,
    activity_summary: {
      last_book: latestBookForEntity(entity, books),
      book_state_counts: bookStateCountsForEntity(entity, books),
      last_change: latestActivityForEntity(entity, books, ledger),
    },
  };
}

function stubEntitiesPageFetch({
  entities = [ENTITY_A, ENTITY_B],
  books = [OPEN_BOOK],
  ledger = [ledgerEvent(ENTITY_A, 'registry.imported', 2)],
  booksStatus = 200,
  summaries = true,
  settingsColumns = REGISTERED_ENTITY_COLUMNS,
}: {
  entities?: Entity[];
  books?: BookView[];
  ledger?: LedgerEventView[];
  booksStatus?: number;
  summaries?: boolean;
  settingsColumns?: readonly string[];
} = {}) {
  const entityRows = summaries
    ? entities.map((entity) =>
        entity.activity_summary ? entity : withActivitySummary(entity, books, ledger),
      )
    : entities;
  const fn = ((input: RequestInfo | URL) => {
    const url = typeof input === 'string' ? input : input.toString();
    if (url.includes('/v1/settings')) {
      return Promise.resolve(
        jsonResponse({
          ...DEFAULT_SETTINGS,
          ui: { registered_entity_columns: settingsColumns },
        }),
      );
    }
    if (url.includes('/v1/entities')) return Promise.resolve(jsonResponse(entityRows));
    if (url.includes('/v1/books')) return Promise.resolve(jsonResponse(books, booksStatus));
    if (url.includes('/v1/ledger/events')) {
      return Promise.reject(new Error('EntitiesPage must use entity activity_summary'));
    }
    return Promise.reject(new Error(`no stub for ${url}`));
  }) as typeof fetch;
  vi.stubGlobal('fetch', fn);
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('EntitiesPage enrichment and filtering', () => {
  it('surfaces fiscal year, current book and registry/change activity from entity summaries', async () => {
    stubEntitiesPageFetch({
      entities: [{ ...ENTITY_A, registry_summary: REGISTRY_SUMMARY_A }, ENTITY_B],
    });
    renderWithProviders(<EntitiesPage />, ['/entidades']);

    expect(await screen.findByText(ENTITY_A.name)).toBeTruthy();
    await waitFor(() => expect(screen.getAllByText('Registo importado').length).toBeGreaterThan(0));

    expect(screen.getByRole('columnheader', { name: 'Fecho fiscal' })).toBeTruthy();
    expect(screen.getByRole('columnheader', { name: 'Matrícula' })).toBeTruthy();
    expect(screen.getByRole('columnheader', { name: 'Constituição' })).toBeTruthy();
    expect(screen.getByRole('columnheader', { name: 'Capital' })).toBeTruthy();
    expect(screen.getByRole('columnheader', { name: 'CAE' })).toBeTruthy();
    expect(screen.getByRole('columnheader', { name: 'Registo' })).toBeTruthy();
    expect(screen.getByRole('columnheader', { name: 'Últ. registo' })).toBeTruthy();
    expect(screen.getByRole('columnheader', { name: 'Último livro' })).toBeTruthy();
    expect(screen.getByRole('columnheader', { name: 'Última atividade' })).toBeTruthy();
    expect(screen.getByText('99999/20200101')).toBeTruthy();
    expect(screen.getByText('2020-01-01')).toBeTruthy();
    expect(screen.getByText('5.000,00 EUR')).toBeTruthy();
    expect(screen.getByText('68110 principal')).toBeTruthy();
    expect(screen.getByText('Compra e venda de bens imobiliários.')).toBeTruthy();
    expect(screen.queryByText('+1 CAE')).toBeNull();
    expect(screen.getAllByText('Dentro da validade').length).toBeGreaterThan(1);
    expect(screen.getByText(/Válido até 2027-07-05/)).toBeTruthy();
    expect(screen.getByText('CONSTITUIÇÃO DE SOCIEDADE')).toBeTruthy();
    expect(screen.getByText('06-30')).toBeTruthy();
    expect(screen.getByText('12-31 (por omissão)')).toBeTruthy();

    const entityRow = screen.getByText(ENTITY_A.name).closest('tr') as HTMLElement;
    const cells = within(entityRow).getAllByRole('cell');
    const typeLine = cells[3].querySelector('.entity-cell-line');
    expect(typeLine?.textContent).toBe('Lda.');
    expect(typeLine?.className).toContain('entity-cell-line--compact');
    expect(typeLine?.textContent).not.toContain('Sociedade por Quotas');
    expect(typeLine?.getAttribute('title')).toContain('Sociedade por Quotas');
    expect(typeLine?.getAttribute('title')).toContain('Regras csc-art63/v2');

    const bookLink = screen.getByRole('link', { name: 'Assembleia Geral' });
    expect(bookLink.getAttribute('href')).toBe('/livros/book-open');
    expect(screen.getAllByText('Aberto').length).toBeGreaterThan(0);
    expect(screen.getByText(/Assembleia anual 2026/)).toBeTruthy();
    expect(screen.getByText(/Última ata\s+4/)).toBeTruthy();
    expect(screen.getByText(/Aberto em 2026-01-10/)).toBeTruthy();
    expect(screen.getByText('1 livro · Aberto: 1')).toBeTruthy();

    const activityLine = cells[12].querySelector('.entity-cell-line');
    expect(activityLine?.className).toContain('entity-cell-line--compact');
    expect(activityLine?.textContent).not.toContain('amelia.marques');
    expect(activityLine?.getAttribute('title')).toContain('amelia.marques');
    expect(screen.getAllByText('Sem livros').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Sem atividade').length).toBeGreaterThan(0);
    expect(screen.queryByRole('link', { name: 'Ver arquivo' })).toBeNull();
  });

  it('filters by folded search text, legal form, NIPC validation, registry state, book state and activity type', async () => {
    stubEntitiesPageFetch({
      entities: [
        { ...ENTITY_A, registry_summary: REGISTRY_SUMMARY_A },
        { ...ENTITY_B, nipc_validated: false },
      ],
      ledger: [
        ledgerEvent(ENTITY_A, 'registry.imported', 2),
        ledgerEvent(ENTITY_B, 'entity.created', 3),
      ],
    });
    renderWithProviders(<EntitiesPage />, ['/entidades']);

    expect(await screen.findByText(ENTITY_A.name)).toBeTruthy();
    await waitFor(() => expect(screen.getAllByText('Entidade criada').length).toBeGreaterThan(0));

    fireEvent.change(screen.getByLabelText('Pesquisar'), { target: { value: 'condominio' } });
    await waitFor(() => expect(screen.queryByText(ENTITY_A.name)).toBeNull());
    expect(screen.getByText(ENTITY_B.name)).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: /limpar/i }));
    await waitFor(() => expect(screen.getByText(ENTITY_A.name)).toBeTruthy());

    fireEvent.change(screen.getByLabelText('Forma'), { target: { value: 'Condominio' } });
    expect(screen.queryByText(ENTITY_A.name)).toBeNull();
    expect(screen.getByText(ENTITY_B.name)).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: /limpar/i }));
    await waitFor(() => expect(screen.getByText(ENTITY_A.name)).toBeTruthy());
    fireEvent.change(screen.getByLabelText('NIPC'), { target: { value: 'unvalidated' } });
    expect(screen.queryByText(ENTITY_A.name)).toBeNull();
    expect(screen.getByText(ENTITY_B.name)).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: /limpar/i }));
    await waitFor(() => expect(screen.getByText(ENTITY_A.name)).toBeTruthy());
    fireEvent.change(screen.getByLabelText('Registo'), { target: { value: 'imported' } });
    expect(screen.getByText(ENTITY_A.name)).toBeTruthy();
    expect(screen.queryByText(ENTITY_B.name)).toBeNull();

    fireEvent.click(screen.getByRole('button', { name: /limpar/i }));
    await waitFor(() => expect(screen.getByText(ENTITY_A.name)).toBeTruthy());
    fireEvent.change(screen.getByLabelText('Registo'), { target: { value: 'not-imported' } });
    expect(screen.queryByText(ENTITY_A.name)).toBeNull();
    expect(screen.getByText(ENTITY_B.name)).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: /limpar/i }));
    await waitFor(() => expect(screen.getByText(ENTITY_A.name)).toBeTruthy());
    fireEvent.click(screen.getByText('Filtros avançados'));
    fireEvent.change(screen.getByLabelText('Livros'), { target: { value: 'open' } });
    expect(screen.getByText(ENTITY_A.name)).toBeTruthy();
    expect(screen.queryByText(ENTITY_B.name)).toBeNull();

    fireEvent.change(screen.getByLabelText('Livros'), { target: { value: 'all' } });
    fireEvent.change(screen.getByLabelText('Atividade'), { target: { value: 'entity' } });
    expect(screen.queryByText(ENTITY_A.name)).toBeNull();
    expect(screen.getByText(ENTITY_B.name)).toBeTruthy();
  });

  it('filters registry freshness and searches registry-specific fields', async () => {
    stubEntitiesPageFetch({
      entities: [
        { ...ENTITY_A, registry_summary: REGISTRY_SUMMARY_A },
        { ...ENTITY_B, registry_summary: EXPIRED_REGISTRY_SUMMARY_B },
      ],
      ledger: [
        ledgerEvent(ENTITY_A, 'registry.imported', 2),
        ledgerEvent(ENTITY_B, 'registry.imported', 3),
      ],
    });
    renderWithProviders(<EntitiesPage />, ['/entidades']);

    expect(await screen.findByText(ENTITY_A.name)).toBeTruthy();
    await waitFor(() => expect(screen.getAllByText('Expirado').length).toBeGreaterThan(1));

    fireEvent.click(screen.getByText('Filtros avançados'));
    fireEvent.change(screen.getByLabelText('Validade'), { target: { value: 'expired' } });
    expect(screen.queryByText(ENTITY_A.name)).toBeNull();
    expect(screen.getByText(ENTITY_B.name)).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: /limpar/i }));
    await waitFor(() => expect(screen.getByText(ENTITY_A.name)).toBeTruthy());
    fireEvent.change(screen.getByLabelText('Pesquisar'), { target: { value: '70220' } });
    expect(screen.queryByText(ENTITY_A.name)).toBeNull();
    expect(screen.getByText(ENTITY_B.name)).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: /limpar/i }));
    await waitFor(() => expect(screen.getByText(ENTITY_A.name)).toBeTruthy());
    fireEvent.change(screen.getByLabelText('Pesquisar'), { target: { value: '99999/20200101' } });
    expect(screen.getByText(ENTITY_A.name)).toBeTruthy();
    expect(screen.queryByText(ENTITY_B.name)).toBeNull();
  });

  it('filters by book kind, last-book state and exact last-change type while exposing state totals', async () => {
    stubEntitiesPageFetch({
      books: [OPEN_BOOK, CLOSED_BOOK],
      ledger: [
        ledgerEvent(ENTITY_B, 'entity.created', 3),
        bookLedgerEvent(CLOSED_BOOK, 'book.closed', 4),
      ],
    });
    renderWithProviders(<EntitiesPage />, ['/entidades']);

    expect(await screen.findByText(ENTITY_A.name)).toBeTruthy();
    await waitFor(() => expect(screen.getAllByText('Livro encerrado').length).toBeGreaterThan(0));

    const latestBook = screen.getByRole('link', { name: 'Conselho Fiscal' });
    expect(latestBook.getAttribute('href')).toBe('/livros/book-closed');
    expect(screen.getByText(/Fiscalização 2026/)).toBeTruthy();
    expect(screen.getByText('2 livros · Aberto: 1 · Encerrado: 1')).toBeTruthy();
    expect(screen.getByText('Motivo Livro completo')).toBeTruthy();

    fireEvent.click(screen.getByText('Filtros avançados'));
    fireEvent.change(screen.getByLabelText('Tipo de livro'), {
      target: { value: 'ConselhoFiscal' },
    });
    expect(screen.getByText(ENTITY_A.name)).toBeTruthy();
    expect(screen.queryByText(ENTITY_B.name)).toBeNull();

    fireEvent.click(screen.getByRole('button', { name: /limpar/i }));
    await waitFor(() => expect(screen.getByText(ENTITY_B.name)).toBeTruthy());
    fireEvent.change(screen.getByLabelText('Último livro'), { target: { value: 'Closed' } });
    expect(screen.getByText(ENTITY_A.name)).toBeTruthy();
    expect(screen.queryByText(ENTITY_B.name)).toBeNull();

    fireEvent.click(screen.getByRole('button', { name: /limpar/i }));
    await waitFor(() => expect(screen.getByText(ENTITY_B.name)).toBeTruthy());
    fireEvent.change(screen.getByLabelText('Última alteração'), {
      target: { value: 'book.closed' },
    });
    expect(screen.getByText(ENTITY_A.name)).toBeTruthy();
    expect(screen.queryByText(ENTITY_B.name)).toBeNull();
  });

  it('keeps the entity list usable when optional books or activity summaries are unavailable', async () => {
    stubEntitiesPageFetch({ booksStatus: 403, summaries: false });
    renderWithProviders(<EntitiesPage />, ['/entidades']);

    expect(await screen.findByText(ENTITY_A.name)).toBeTruthy();
    await waitFor(() =>
      expect(screen.getAllByText('Livros indisponíveis').length).toBeGreaterThan(0),
    );
    expect(screen.getAllByText('Sem atividade').length).toBeGreaterThan(0);

    const rows = screen.getAllByRole('row');
    const entityRow = rows.find((row) => within(row).queryByText(ENTITY_A.name));
    expect(entityRow).toBeTruthy();
    expect(within(entityRow as HTMLElement).getByRole('button', { name: 'Abrir' })).toBeTruthy();
  });
});
