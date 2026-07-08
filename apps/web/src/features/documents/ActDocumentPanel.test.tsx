/**
 * ActDocumentPanel tests (t48-e6): the download action only appears once the act is sealed
 * AND a document exists (the DOC-03 bundle resolves), and the live preview degrades to an
 * honest "sem modelo disponível" state when the family has no template (the endpoint 422s)
 * rather than surfacing an error.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react';
import { ActDocumentPanel } from './ActDocumentPanel';
import { renderWithProviders } from '../../test/utils';
import type { ActView, DocumentBundle } from '../../api/types';

const baseAct: ActView = {
  id: 'act-1',
  book_id: 'book-1',
  title: 'Assembleia Geral Anual',
  channel: 'Physical',
  meeting_date: '2026-06-30',
  meeting_time: null,
  place: 'Lisboa',
  mesa: { presidente: 'Amélia Marques', secretarios: [] },
  agenda: [],
  attendance_reference: null,
  members_present: null,
  members_represented: null,
  referenced_documents: [],
  deliberations: '',
  deliberation_items: [],
  telematic_evidence: null,
  attachments: [],
  signatories: [],
  state: 'Draft',
  ata_number: null,
  payload_digest: null,
  seal_event_seq: null,
  retifies: null,
};

const bundle: DocumentBundle = {
  act_id: 'act-1',
  document: {
    id: 'doc-1',
    template_id: 'csc-ata-ag/v1',
    pdf_digest: 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2',
    profile: 'application/pdf; profile=PDF/A-2u',
    created_at: '2026-06-30T10:00:00Z',
  },
  pdf: { media_type: 'application/pdf', byte_length: 12345, download: '/v1/acts/act-1/document' },
  attachments_manifest: [],
  validation_report: null,
};

function json(body: unknown, status = 200) {
  return Promise.resolve(
    new Response(JSON.stringify(body), {
      status,
      headers: { 'Content-Type': 'application/json' },
    }),
  );
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('ActDocumentPanel — download only post-seal', () => {
  it('hides the download while the act is a draft', async () => {
    vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
      const url = input.toString();
      if (url.includes('/templates')) {
        return json([
          { id: 'csc-ata-ag/v1', family: 'CommercialCompany', stage: 'Ata', locale: 'pt-PT' },
        ]);
      }
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderWithProviders(<ActDocumentPanel act={baseAct} family="CommercialCompany" />);

    // The template picker surfaces which model applies…
    expect(await screen.findByText('csc-ata-ag/v1')).toBeTruthy();
    // …but no download button while unsealed.
    expect(screen.queryByRole('button', { name: 'Descarregar PDF' })).toBeNull();
  });

  it('shows the download + digest once sealed and a document exists', async () => {
    vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
      const url = input.toString();
      if (url.includes('/document/bundle')) return json(bundle);
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    const sealed: ActView = { ...baseAct, state: 'Sealed', ata_number: 1 };
    renderWithProviders(
      <ActDocumentPanel
        act={sealed}
        entityName="Encosto Estratégico Lda"
        family="CommercialCompany"
      />,
    );

    expect(await screen.findByRole('button', { name: 'Descarregar PDF' })).toBeTruthy();
    expect(screen.getByText('Impressão do PDF:')).toBeTruthy();
  });

  it('shows an honest "not generated" note when a sealed act has no document', async () => {
    vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
      const url = input.toString();
      if (url.includes('/document/bundle')) return json({ error: 'sem documento' }, 404);
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    const sealed: ActView = { ...baseAct, state: 'Sealed', ata_number: 1 };
    renderWithProviders(<ActDocumentPanel act={sealed} family="Condominium" />);

    expect(await screen.findByText('Documento não gerado')).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Descarregar PDF' })).toBeNull();
  });
});

describe('ActDocumentPanel — honest no-template preview', () => {
  it('renders "sem modelo disponível" when the preview endpoint 422s', async () => {
    vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
      const url = input.toString();
      if (url.includes('/document/preview')) return json({ error: 'sem modelo' }, 422);
      if (url.includes('/templates')) return json([]);
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderWithProviders(<ActDocumentPanel act={baseAct} family="Condominium" />);

    fireEvent.click(await screen.findByRole('button', { name: 'Pré-visualizar documento' }));

    await waitFor(() => expect(screen.getByText('Sem modelo disponível')).toBeTruthy());
  });
});
