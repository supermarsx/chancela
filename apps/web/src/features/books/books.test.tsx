import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen } from '@testing-library/react';
import { Route, Routes } from 'react-router-dom';
import { renderWithProviders, fetchTable } from '../../test/utils';
import { BooksPage } from './BooksPage';
import { NewBookPage } from './NewBookPage';
import { OpenBookForm } from './OpenBookForm';
import { DEFAULT_SETTINGS, type Entity } from '../../api/types';

const ENTITY: Entity = {
  id: 'ent-1',
  name: 'Encosto Estratégico, Lda.',
  nipc: '503004642',
  nipc_validated: true,
  seat: 'Lisboa',
  family: 'CommercialCompany',
  kind: 'SociedadePorQuotas',
  profile: {
    family: 'CommercialCompany',
    rule_pack_id: 'csc-art63/v2',
    allowed_channels: ['Physical', 'Hybrid', 'Telematic', 'WrittenResolution'],
    signature_policy: 'QualifiedPreferred',
    template_family: 'csc-commercial',
    calendar_presets: [],
  },
  statute: null,
};

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('BooksPage', () => {
  it('offers a neat button to the open-book route instead of an inline form', async () => {
    vi.stubGlobal('fetch', fetchTable([{ match: '/v1/books', body: [] }]));
    renderWithProviders(<BooksPage />, ['/livros']);

    const abrir = await screen.findByRole('link', { name: /abrir livro/i });
    expect(abrir.getAttribute('href')).toBe('/livros/novo');
    // No inline open-book form on the list page.
    expect(screen.queryByLabelText('Tipo de livro')).toBeNull();
  });
});

describe('NewBookPage', () => {
  function renderAt(path: string) {
    return renderWithProviders(
      <Routes>
        <Route path="/livros/novo" element={<NewBookPage />} />
      </Routes>,
      [path],
    );
  }

  it('fixes the book to the entity from the ?entidade query param (no picker)', async () => {
    vi.stubGlobal(
      'fetch',
      fetchTable([
        { match: '/v1/settings', body: DEFAULT_SETTINGS },
        { match: '/v1/entities', body: [ENTITY] },
      ]),
    );
    renderAt('/livros/novo?entidade=ent-1');

    // The open-book form renders with no entity picker; the entity is fixed.
    expect(await screen.findByLabelText('Tipo de livro')).toBeTruthy();
    expect(screen.queryByLabelText('Entidade')).toBeNull();
    expect(screen.getByRole('button', { name: /abrir livro/i })).toBeTruthy();
    // The manual audit-actor input is gone: attribution is the signed-in user
    // (topbar picker) via X-Chancela-Session, so the form sends no body actor (t22-web).
    expect(screen.queryByLabelText(/ator/i)).toBeNull();
  });

  it('shows an empty state when there are no entities to open a book against', async () => {
    vi.stubGlobal('fetch', fetchTable([{ match: '/v1/entities', body: [] }]));
    renderAt('/livros/novo');

    expect(await screen.findByText('Sem entidades')).toBeTruthy();
  });
});

describe('OpenBookForm — book-open guidance (t60)', () => {
  it('shows the autonomy info panel and per-field help on kind and numbering', async () => {
    vi.stubGlobal('fetch', fetchTable([{ match: '/v1/settings', body: DEFAULT_SETTINGS }]));

    renderWithProviders(
      <Routes>
        <Route path="/entidades/ent-1" element={<OpenBookForm entityId="ent-1" />} />
      </Routes>,
      ['/entidades/ent-1'],
    );

    // The concise autonomy-oriented info panel sits at the top of the form.
    expect(await screen.findByText('Como escolher')).toBeTruthy();
    // A FieldHelp glyph accompanies the book-kind and numbering-scheme fields (≥2 "Ajuda").
    expect(screen.getAllByRole('button', { name: 'Ajuda' }).length).toBeGreaterThanOrEqual(2);
  });
});

describe('OpenBookForm — toast on success', () => {
  it('fires a success toast after opening a book (survives navigate-away)', async () => {
    const book = { id: 'book-9', entity_id: 'ent-1' };
    vi.stubGlobal(
      'fetch',
      fetchTable([
        { match: '/v1/settings', body: DEFAULT_SETTINGS },
        { match: '/v1/books', status: 201, body: book },
      ]),
    );

    renderWithProviders(
      <Routes>
        <Route path="/entidades/ent-1" element={<OpenBookForm entityId="ent-1" />} />
        <Route path="/livros/:id" element={<div>DETALHE DO LIVRO</div>} />
      </Routes>,
      ['/entidades/ent-1'],
    );

    fireEvent.change(await screen.findByLabelText('Finalidade'), {
      target: { value: 'Atas AG' },
    });
    fireEvent.change(screen.getByLabelText('Data de abertura'), {
      target: { value: '2026-01-01' },
    });
    fireEvent.click(screen.getByRole('button', { name: /abrir livro/i }));

    expect(await screen.findByText('DETALHE DO LIVRO')).toBeTruthy();
    // R6: the toast fired in onSuccess renders even though we navigated to the book.
    expect(await screen.findByText('Livro aberto.')).toBeTruthy();
  });
});
