import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react';
import type { BookView, Entity, LedgerEventView } from '../../api/types';
import { renderWithProviders } from '../../test/utils';
import { EntitiesPage } from './EntitiesPage';

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

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function stubEntitiesPageFetch({
  entities = [ENTITY_A, ENTITY_B],
  books = [OPEN_BOOK],
  ledger = [ledgerEvent(ENTITY_A, 'registry.imported', 2)],
  booksStatus = 200,
  ledgerStatus = 200,
}: {
  entities?: Entity[];
  books?: BookView[];
  ledger?: LedgerEventView[];
  booksStatus?: number;
  ledgerStatus?: number;
} = {}) {
  const fn = ((input: RequestInfo | URL) => {
    const url = typeof input === 'string' ? input : input.toString();
    if (url.includes('/v1/entities')) return Promise.resolve(jsonResponse(entities));
    if (url.includes('/v1/books')) return Promise.resolve(jsonResponse(books, booksStatus));
    if (url.includes('/v1/ledger/events')) {
      return Promise.resolve(
        jsonResponse(ledgerStatus === 200 ? ledger : { error: 'denied' }, ledgerStatus),
      );
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
  it('surfaces fiscal year, current book and recent registry/change activity from existing API data', async () => {
    stubEntitiesPageFetch();
    renderWithProviders(<EntitiesPage />, ['/entidades']);

    expect(await screen.findByText(ENTITY_A.name)).toBeTruthy();
    await waitFor(() => expect(screen.getAllByText('Registo importado').length).toBeGreaterThan(0));

    expect(screen.getByRole('columnheader', { name: 'Fecho fiscal' })).toBeTruthy();
    expect(screen.getByRole('columnheader', { name: 'Livro atual / último' })).toBeTruthy();
    expect(screen.getByRole('columnheader', { name: 'Última alteração / atividade' })).toBeTruthy();
    expect(screen.getByText('06-30')).toBeTruthy();
    expect(screen.getByText('12-31 (por omissão)')).toBeTruthy();
    expect(screen.getAllByText('Sociedade por Quotas').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Regras csc-art63/v2').length).toBeGreaterThan(0);

    const bookLink = screen.getByRole('link', { name: 'Assembleia Geral' });
    expect(bookLink.getAttribute('href')).toBe('/livros/book-open');
    expect(screen.getByText('Aberto')).toBeTruthy();
    expect(screen.getByText(/Assembleia anual 2026/)).toBeTruthy();
    expect(screen.getByText(/Última ata\s+4/)).toBeTruthy();
    expect(screen.getByText(/Aberto em 2026-01-10/)).toBeTruthy();

    expect(screen.getByText('amelia.marques', { exact: false })).toBeTruthy();
    expect(screen.getAllByText('Sem livros').length).toBeGreaterThan(0);
    expect(screen.getByText('Sem atividade no arquivo recente')).toBeTruthy();
    expect(screen.getByRole('link', { name: 'Ver arquivo' }).getAttribute('href')).toBe('/arquivo');
  });

  it('filters by folded search text, legal form, NIPC validation, book state and activity type', async () => {
    stubEntitiesPageFetch({
      entities: [ENTITY_A, { ...ENTITY_B, nipc_validated: false }],
      ledger: [
        ledgerEvent(ENTITY_A, 'registry.imported', 2),
        ledgerEvent(ENTITY_B, 'entity.created', 3),
      ],
    });
    renderWithProviders(<EntitiesPage />, ['/entidades']);

    expect(await screen.findByText(ENTITY_A.name)).toBeTruthy();
    await waitFor(() => expect(screen.getByText('Entidade criada')).toBeTruthy());

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
    fireEvent.change(screen.getByLabelText('Livros'), { target: { value: 'open' } });
    expect(screen.getByText(ENTITY_A.name)).toBeTruthy();
    expect(screen.queryByText(ENTITY_B.name)).toBeNull();

    fireEvent.change(screen.getByLabelText('Livros'), { target: { value: 'all' } });
    fireEvent.change(screen.getByLabelText('Atividade'), { target: { value: 'entity' } });
    expect(screen.queryByText(ENTITY_A.name)).toBeNull();
    expect(screen.getByText(ENTITY_B.name)).toBeTruthy();
  });

  it('keeps the entity list usable when optional books or ledger enrichment is unavailable', async () => {
    stubEntitiesPageFetch({ booksStatus: 403, ledgerStatus: 403 });
    renderWithProviders(<EntitiesPage />, ['/entidades']);

    expect(await screen.findByText(ENTITY_A.name)).toBeTruthy();
    await waitFor(() =>
      expect(screen.getAllByText('Livros indisponíveis').length).toBeGreaterThan(0),
    );
    expect(screen.getAllByText('Arquivo indisponível').length).toBeGreaterThan(0);

    const rows = screen.getAllByRole('row');
    const entityRow = rows.find((row) => within(row).queryByText(ENTITY_A.name));
    expect(entityRow).toBeTruthy();
    expect(
      within(entityRow as HTMLElement).getByRole('link', { name: 'Ver detalhe' }),
    ).toBeTruthy();
  });
});
