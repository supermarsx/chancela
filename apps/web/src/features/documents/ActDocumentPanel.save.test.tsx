import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react';
import { renderWithProviders } from '../../test/utils';
import type { ActView, DocumentBundle } from '../../api/types';

const saveFileMock = vi.hoisted(() => ({
  saveBlobAs: vi.fn(),
  saveBlobResultMessage: vi.fn((result: { filename: string }) => `Guardado: ${result.filename}`),
}));

vi.mock('../../desktop/saveFile', () => saveFileMock);

import { ActDocumentPanel } from './ActDocumentPanel';

const sealedAct: ActView = {
  id: 'act-1',
  book_id: 'book-1',
  title: 'Assembleia Geral Anual',
  channel: 'Physical',
  meeting_date: '2026-06-30',
  meeting_time: null,
  place: 'Lisboa',
  mesa: { presidente: 'Amelia Marques', secretarios: [] },
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
  state: 'Sealed',
  ata_number: 7,
  payload_digest: null,
  seal_event_seq: null,
  seal_metadata: null,
  retifies: null,
};

const bundle = {
  act_id: 'act-1',
  document: {
    id: 'doc-1',
    template_id: 'csc-ata-ag/v1',
    pdf_digest: 'a1'.repeat(32),
    profile: 'application/pdf; profile=PDF/A-2u',
    created_at: '2026-06-30T10:00:00Z',
  },
} as DocumentBundle;

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function blobText(blob: Blob): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result));
    reader.onerror = () => reject(reader.error);
    reader.readAsText(blob);
  });
}

function stubDocumentFetch(extra: (url: string) => Response | null): {
  calls: string[];
  fn: typeof fetch;
} {
  const calls: string[] = [];
  const fn = ((input: RequestInfo | URL) => {
    const url = input.toString();
    calls.push(url);
    const custom = extra(url);
    if (custom) return Promise.resolve(custom);
    if (url.includes('/v1/acts/act-1/document/bundle'))
      return Promise.resolve(jsonResponse(bundle));
    if (url.includes('/v1/documents/imported')) return Promise.resolve(jsonResponse([]));
    return Promise.reject(new Error(`no stub for ${url}`));
  }) as typeof fetch;
  return { calls, fn };
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  saveFileMock.saveBlobAs.mockReset();
  saveFileMock.saveBlobResultMessage.mockClear();
});

describe('ActDocumentPanel export save prompts', () => {
  it('routes the sealed act PDF through the save prompt helper', async () => {
    saveFileMock.saveBlobAs.mockResolvedValue({
      kind: 'browser-save',
      filename: 'encosto-estrategico-lda-ata-7.pdf',
      contentType: 'application/pdf',
      bytes: 13,
    });
    const { calls, fn } = stubDocumentFetch((url) => {
      if (url.endsWith('/v1/acts/act-1/document')) {
        return new Response('%PDF-1.7\n%%EOF', {
          status: 200,
          headers: { 'Content-Type': 'application/pdf' },
        });
      }
      return null;
    });
    vi.stubGlobal('fetch', fn);

    renderWithProviders(
      <ActDocumentPanel
        act={sealedAct}
        entityName="Encosto Estratégico Lda"
        family="CommercialCompany"
      />,
    );

    fireEvent.click(await screen.findByRole('button', { name: 'Descarregar PDF' }));

    await waitFor(() => expect(saveFileMock.saveBlobAs).toHaveBeenCalledTimes(1));
    const saved = saveFileMock.saveBlobAs.mock.calls[0][0] as {
      blob: Blob;
      filename: string;
      contentType: string;
      preferBrowserSavePicker: boolean;
    };
    expect(saved.filename).toBe('encosto-estrategico-lda-ata-7.pdf');
    expect(saved.contentType).toBe('application/pdf');
    expect(saved.preferBrowserSavePicker).toBe(true);
    expect(saved.blob).toBeInstanceOf(Blob);
    expect(saved.blob.type).toBe('application/pdf');
    expect(await blobText(saved.blob)).toBe('%PDF-1.7\n%%EOF');
    expect(calls).toContain('/v1/acts/act-1/document');
  });

  it('routes a working-copy export through the save prompt helper with response metadata', async () => {
    saveFileMock.saveBlobAs.mockResolvedValue({
      kind: 'browser-save',
      filename: 'encosto-estrategico-lda-ata-7-working-copy.md',
      contentType: 'text/markdown;charset=utf-8',
      bytes: 12,
    });
    const { calls, fn } = stubDocumentFetch((url) => {
      if (url.endsWith('/v1/acts/act-1/document/working-copy')) {
        return new Response('# Ata\n\nTexto', {
          status: 200,
          headers: { 'Content-Type': 'text/markdown;charset=utf-8' },
        });
      }
      return null;
    });
    vi.stubGlobal('fetch', fn);

    renderWithProviders(
      <ActDocumentPanel
        act={sealedAct}
        entityName="Encosto Estratégico Lda"
        family="CommercialCompany"
      />,
    );

    fireEvent.click(await screen.findByRole('button', { name: 'Descarregar Markdown' }));

    await waitFor(() => expect(saveFileMock.saveBlobAs).toHaveBeenCalledTimes(1));
    const saved = saveFileMock.saveBlobAs.mock.calls[0][0] as {
      blob: Blob;
      filename: string;
      contentType: string;
      preferBrowserSavePicker: boolean;
    };
    expect(saved.filename).toBe('encosto-estrategico-lda-ata-7-working-copy.md');
    expect(saved.contentType).toBe('text/markdown;charset=utf-8');
    expect(saved.preferBrowserSavePicker).toBe(true);
    expect(saved.blob.type).toBe('text/markdown;charset=utf-8');
    expect(await blobText(saved.blob)).toBe('# Ata\n\nTexto');
    expect(calls).toContain('/v1/acts/act-1/document/working-copy');
  });
});
