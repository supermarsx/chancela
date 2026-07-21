import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen } from '@testing-library/react';
import { Route, Routes } from 'react-router-dom';
import { renderWithProviders } from '../../test/utils';
import { CloseBookPage } from './CloseBookPage';
import type { BookView } from '../../api/types';

const CLOSED_BOOK: BookView = {
  id: 'book-1',
  entity_id: 'ent-1',
  kind: 'AssembleiaGeral',
  state: 'Closed',
  purpose: 'Atas da Assembleia',
  numbering_scheme: 'Sequential',
  opening_date: '2026-01-01',
  closing_date: '2026-07-13',
  closing_reason: 'BookFull',
  last_ata_number: 3,
  predecessor: null,
  required_signatories_abertura: null,
  required_signatories_encerramento: null,
};

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function renderPage() {
  return renderWithProviders(
    <Routes>
      <Route path="/books/:id/close" element={<CloseBookPage />} />
      <Route path="/books/:id" element={<div>DETALHE DO LIVRO</div>} />
    </Routes>,
    ['/books/book-1/close'],
  );
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('CloseBookPage', () => {
  it('renders the header, breadcrumbs bound to the book id, and the close form', () => {
    vi.stubGlobal('fetch', (() => new Promise<Response>(() => {})) as typeof fetch);
    renderPage();

    // "Encerrar livro" is both the page heading and the submit button label.
    expect(screen.getAllByText('Encerrar livro').length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText('Termo de encerramento')).toBeTruthy();

    const booksCrumb = screen.getByRole('link', { name: 'Livros' });
    expect(booksCrumb.getAttribute('href')).toBe('/books');
    const bookCrumb = screen.getByRole('link', { name: 'Livro' });
    expect(bookCrumb.getAttribute('href')).toBe('/books/book-1');

    // The embedded CloseBookForm renders its fields.
    expect(screen.getByLabelText('Data de encerramento')).toBeTruthy();
  });

  it('closes the book through the embedded form and returns to the book detail', async () => {
    vi.stubGlobal('fetch', (() => Promise.resolve(jsonResponse(CLOSED_BOOK))) as typeof fetch);
    renderPage();

    fireEvent.change(screen.getByLabelText('Data de encerramento'), {
      target: { value: '2026-07-13' },
    });
    fireEvent.click(screen.getByRole('button', { name: /encerrar livro/i }));

    // onClosed navigates back to the book detail route.
    expect(await screen.findByText('DETALHE DO LIVRO')).toBeTruthy();
    expect(await screen.findByText('Livro encerrado.')).toBeTruthy();
  });
});
