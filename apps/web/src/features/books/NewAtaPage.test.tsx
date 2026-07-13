import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen } from '@testing-library/react';
import { Route, Routes } from 'react-router-dom';
import { renderWithProviders } from '../../test/utils';
import { NewAtaPage } from './NewAtaPage';
import type { ActView } from '../../api/types';

const NEW_ACT = {
  id: 'act-9',
  book_id: 'book-1',
  title: 'Assembleia Geral Ordinária',
  channel: 'Physical',
  state: 'Draft',
} as unknown as ActView;

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function renderPage() {
  return renderWithProviders(
    <Routes>
      <Route path="/livros/:id/nova-ata" element={<NewAtaPage />} />
      <Route path="/atas/:id" element={<div>EDITOR DE ATA</div>} />
    </Routes>,
    ['/livros/book-1/nova-ata'],
  );
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('NewAtaPage', () => {
  it('renders the header, breadcrumbs bound to the book id, and the draft form', () => {
    vi.stubGlobal('fetch', (() => new Promise<Response>(() => {})) as typeof fetch);
    renderPage();

    // Title appears both as the page heading and the card title.
    expect(screen.getAllByText('Nova ata').length).toBeGreaterThanOrEqual(1);

    const booksCrumb = screen.getByRole('link', { name: 'Livros' });
    expect(booksCrumb.getAttribute('href')).toBe('/livros');
    const bookCrumb = screen.getByRole('link', { name: 'Livro' });
    expect(bookCrumb.getAttribute('href')).toBe('/livros/book-1');

    // The embedded DraftAtaForm renders its title field.
    expect(screen.getByLabelText('Título da ata')).toBeTruthy();
  });

  it('drafts an ata through the embedded form and navigates to the new act', async () => {
    vi.stubGlobal('fetch', (() => Promise.resolve(jsonResponse(NEW_ACT, 201))) as typeof fetch);
    renderPage();

    fireEvent.change(screen.getByLabelText('Título da ata'), {
      target: { value: 'Assembleia Geral Ordinária' },
    });
    fireEvent.click(screen.getByRole('button', { name: /nova ata/i }));

    expect(await screen.findByText('EDITOR DE ATA')).toBeTruthy();
    expect(await screen.findByText('Ata criada.')).toBeTruthy();
  });
});
