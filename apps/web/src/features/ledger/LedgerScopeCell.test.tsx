import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, screen, waitFor } from '@testing-library/react';
import { fetchTable, getByRevealedText, renderWithProviders } from '../../test/utils';
import type { LedgerEventView } from '../../api/types';
import { LedgerTable } from './LedgerTable';

const ENTITY = '0a20de34-e096-4121-9d55-e5f76214be3c';
const BOOK = '7c1f9a02-1111-4222-8333-444455556666';

const entity = {
  id: ENTITY,
  tenant_id: 't1',
  group_id: null,
  name: 'Encosto Estratégico Lda',
  nipc: '500000000',
  nipc_validated: true,
  seat: 'Lisboa',
  family: 'Comercial',
  kind: 'Lda',
  profile: {},
  statute: null,
};

const book = {
  id: BOOK,
  entity_id: ENTITY,
  kind: 'AssembleiaGeral',
  state: 'Open',
  purpose: null,
  numbering_scheme: null,
  opening_date: null,
  closing_date: null,
  closing_reason: null,
  last_ata_number: 0,
  predecessor: null,
  required_signatories_abertura: null,
  required_signatories_encerramento: null,
};

function event(scope: string, chains: string[] = ['global']): LedgerEventView {
  return {
    id: `event-${scope}`,
    seq: 1,
    actor: 'amelia.marques',
    justification: null,
    timestamp: '2026-07-07T10:20:30Z',
    scope,
    kind: 'entity.statute_updated',
    payload_digest: 'aa'.repeat(32),
    prev_hash: '00'.repeat(32),
    hash: '11'.repeat(32),
    chains,
    attestation: null,
  };
}

function stubLists() {
  vi.stubGlobal(
    'fetch',
    fetchTable([
      { match: '/v1/entities', body: [entity] },
      { match: '/v1/books', body: [book] },
    ]),
  );
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('the Arquivo scope column', () => {
  it('names the bare id the user saw, and says what kind of thing it is', async () => {
    stubLists();
    renderWithProviders(<LedgerTable events={[event(ENTITY)]} />);

    // Was: `0a20de34-e096-4121-9d55-e5f76214be3c`, alone, meaning nothing.
    await waitFor(() => expect(screen.getByText(/Encosto Estratégico Lda/)).toBeTruthy());
    expect(screen.getByText('Entidade — Encosto Estratégico Lda')).toBeTruthy();
  });

  it('keeps the exact identifier reachable for an auditor', async () => {
    stubLists();
    renderWithProviders(<LedgerTable events={[event(`entity:${ENTITY}/book:${BOOK}`)]} />);

    // The Arquivo is evidentiary: the value the `?scope=` filter and every export use must
    // still be obtainable, and through a focusable tooltip rather than hover alone.
    await waitFor(() => expect(getByRevealedText(`entity:${ENTITY}/book:${BOOK}`)).toBeTruthy());
  });

  it('falls back to a labelled id rather than blanking an unresolvable scope', async () => {
    stubLists();
    const missing = 'deadbeef-0000-4000-8000-000000000000';
    renderWithProviders(<LedgerTable events={[event(`book:${missing}`)]} />);

    // Deleted, or outside this viewer's authority: never blank, never `undefined`, never a
    // naked UUID — the type still names what was scoped.
    await waitFor(() => expect(screen.getByText('Livro — deadbeef…')).toBeTruthy());
    expect(getByRevealedText(`book:${missing}`)).toBeTruthy();
  });

  it('names a book by its kind when no purpose was recorded, and shows its entity as context', async () => {
    stubLists();
    renderWithProviders(<LedgerTable events={[event(`entity:${ENTITY}/book:${BOOK}`)]} />);

    await waitFor(() => expect(screen.getByText('Livro — Assembleia Geral')).toBeTruthy());
    expect(screen.getByText(/Entidade — Encosto Estratégico Lda/)).toBeTruthy();
  });

  it('labels a keyword scope without inventing an identifier for it', async () => {
    stubLists();
    renderWithProviders(<LedgerTable events={[event('settings')]} />);

    await waitFor(() => expect(screen.getByText('Definições')).toBeTruthy());
  });

  it('reads a keyword-only path as both of its segments', async () => {
    stubLists();
    // `lib.rs` appends `backup/archive` — path-shaped, but with no `prefix:` anywhere in it.
    // Showing only the deepest segment would have silently turned it into "Arquivo".
    renderWithProviders(<LedgerTable events={[event('backup/archive')]} />);

    await waitFor(() => expect(screen.getByText('Arquivo')).toBeTruthy());
    expect(screen.getByText(/Cópias de segurança/)).toBeTruthy();
  });

  it('keeps an unmapped keyword token visible instead of swallowing it', async () => {
    stubLists();
    // The API grows scope types faster than the catalog follows them. An unknown token must
    // degrade to a weaker word, never to a lost fact.
    renderWithProviders(<LedgerTable events={[event('some-future-scope')]} />);

    await waitFor(() => expect(screen.getByText('Âmbito — some-future-scope')).toBeTruthy());
  });

  it('labels the scopes hidden behind a const rather than an inline literal', async () => {
    stubLists();
    // `smtp_settings.rs` and `chancela-ledger` reach the wire through `const AUDIT_SCOPE` /
    // `RECOVERY_SCOPE`, so a literal-only sweep of the crates misses them entirely.
    renderWithProviders(<LedgerTable events={[event('email'), event('recovery')]} />);

    await waitFor(() => expect(screen.getByText('E-mail')).toBeTruthy());
    expect(screen.getByText('Recuperação da cadeia')).toBeTruthy();
  });
});

describe('the Arquivo chains column', () => {
  it('names each chain membership by its resolved entity/book instead of a raw id', async () => {
    stubLists();
    // The chains vocabulary says `company:` where a scope says `entity:` — it must still resolve
    // to the entity's name, and the book to its (kind) name, both `·`-separated like Âmbito.
    renderWithProviders(
      <LedgerTable
        events={[event('act:1', ['global', `company:${ENTITY}`, `book:${BOOK}`])]}
        showChains
      />,
    );

    await waitFor(() => expect(screen.getByText('Entidade Encosto Estratégico Lda')).toBeTruthy());
    expect(screen.getByText('Livro Assembleia Geral')).toBeTruthy();
    // `global` is the primary spine, distinct from the `application` audit chain — both are named.
    expect(screen.getByText('Registo global')).toBeTruthy();
  });

  it('names the application-audit chain distinctly from the global spine', async () => {
    stubLists();
    renderWithProviders(
      <LedgerTable events={[event('settings', ['application', 'global'])]} showChains />,
    );

    await waitFor(() => expect(screen.getByText('Aplicação')).toBeTruthy());
    expect(screen.getByText('Registo global')).toBeTruthy();
  });

  it('keeps the exact chain id reachable and labels an unresolvable membership rather than blanking', async () => {
    stubLists();
    const missing = 'deadbeef-0000-4000-8000-000000000000';
    renderWithProviders(
      <LedgerTable events={[event('act:1', [`company:${missing}`])]} showChains />,
    );

    // Deleted, or outside this viewer's authority: an abbreviated id under the type, never blank,
    // never a bare `company:{uuid}` — and the exact chain id stays one focus away for an auditor.
    await waitFor(() => expect(screen.getByText('Entidade deadbeef…')).toBeTruthy());
    expect(getByRevealedText(`company:${missing}`)).toBeTruthy();
  });
});
