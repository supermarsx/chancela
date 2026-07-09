/**
 * ActDocumentPanel tests (t48-e6): the download action only appears once the act is sealed
 * AND a document exists (the DOC-03 bundle resolves), and the live preview degrades to an
 * honest "sem modelo disponível" state when the family has no template (the endpoint 422s)
 * rather than surfacing an error.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { ActDocumentPanel } from './ActDocumentPanel';
import { renderWithProviders } from '../../test/utils';
import type { ActView, DocumentBundle, ImportedDocumentView } from '../../api/types';

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

const importedDocument: ImportedDocumentView = {
  id: 'import-1',
  act_id: 'act-1',
  filename: 'supporting-evidence.pdf',
  size_bytes: 52,
  sha256: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
  declared_content_type: 'application/pdf',
  detected_content_type: 'application/pdf',
  imported_at: '2026-07-09T10:15:30Z',
  imported_by: 'amelia.marques',
  non_canonical: true,
  legal_notice:
    'Imported document preserved as non-canonical evidence only; it does not replace the generated PDF/A or signed PDF, and no legal validity, PDF/A conformance, or signature validity is claimed.',
  bytes_download: '/v1/documents/imported/import-1/bytes',
};

function json(body: unknown, status = 200) {
  return Promise.resolve(
    new Response(JSON.stringify(body), {
      status,
      headers: { 'Content-Type': 'application/json' },
    }),
  );
}

function blobText(blob: Blob): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result));
    reader.onerror = () => reject(reader.error);
    reader.readAsText(blob);
  });
}

function emptyImports(url: string) {
  if (url.includes('/v1/documents/imported')) return json([]);
  return null;
}

function isImportCreate(url: string) {
  return url.endsWith('/v1/documents/import');
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
      const imports = emptyImports(url);
      if (imports) return imports;
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderWithProviders(<ActDocumentPanel act={baseAct} family="CommercialCompany" />);

    // The template picker surfaces which model applies…
    expect(await screen.findByText('csc-ata-ag/v1')).toBeTruthy();
    // …but no download button while unsealed.
    expect(screen.queryByRole('button', { name: 'Descarregar PDF' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Descarregar Markdown' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Descarregar DOCX' })).toBeNull();
  });

  it('shows the PDF, Markdown, and DOCX downloads + digest once sealed and a document exists', async () => {
    vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
      const url = input.toString();
      if (url.includes('/document/bundle')) return json(bundle);
      const imports = emptyImports(url);
      if (imports) return imports;
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
    expect(screen.getByRole('button', { name: 'Descarregar Markdown' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Descarregar DOCX' })).toBeTruthy();
    expect(
      screen.getByText(
        'Markdown e DOCX são cópias de trabalho não probatórias para revisão; o PDF/A preservado é o documento oficial.',
      ),
    ).toBeTruthy();
    expect(screen.getByText('Impressão do PDF:')).toBeTruthy();
  });

  it('surfaces PDF/A metadata and unresolved legal source/threshold caveats without fake links', async () => {
    vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
      const url = input.toString();
      if (url.includes('/document/bundle')) return json(bundle);
      const imports = emptyImports(url);
      if (imports) return imports;
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    const sealed: ActView = { ...baseAct, state: 'Sealed', ata_number: 1 };
    renderWithProviders(<ActDocumentPanel act={sealed} family="CommercialCompany" />);

    const metadata = await screen.findByRole('group', {
      name: 'Metadados e proveniência do documento',
    });
    expect(within(metadata).getByText('Metadados do PDF/A')).toBeTruthy();
    expect(within(metadata).getByText('csc-ata-ag/v1')).toBeTruthy();
    expect(within(metadata).getByText('application/pdf; profile=PDF/A-2u')).toBeTruthy();
    expect(
      within(metadata).getByText(
        'Não fornecida pelo bundle do documento; nenhuma ligação foi criada.',
      ),
    ).toBeTruthy();
    expect(within(metadata).getByText('Não fornecido pelo bundle do documento.')).toBeTruthy();
    expect(within(metadata).queryByRole('link')).toBeNull();
  });

  it('renders missing template id and profile honestly instead of blank metadata', async () => {
    const incompleteBundle: DocumentBundle = {
      ...bundle,
      document: {
        id: 'doc-1',
        pdf_digest: bundle.document.pdf_digest,
        created_at: bundle.document.created_at,
      } as DocumentBundle['document'],
    };
    vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
      const url = input.toString();
      if (url.includes('/document/bundle')) return json(incompleteBundle);
      const imports = emptyImports(url);
      if (imports) return imports;
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    const sealed: ActView = { ...baseAct, state: 'Sealed', ata_number: 1 };
    renderWithProviders(<ActDocumentPanel act={sealed} family="CommercialCompany" />);

    const metadata = await screen.findByRole('group', {
      name: 'Metadados e proveniência do documento',
    });
    expect(within(metadata).getAllByText('Não indicado no bundle')).toHaveLength(2);
    expect(within(metadata).getByText('doc-1')).toBeTruthy();
  });

  it('keeps a long template id visible as metadata and does not turn it into a source link', async () => {
    const longTemplateId =
      'csc-ata-ag/sociedade-por-quotas/assembleia-geral-ordinaria-com-convocatoria-especial/v2026.07.09';
    vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
      const url = input.toString();
      if (url.includes('/document/bundle')) {
        return json({
          ...bundle,
          document: { ...bundle.document, template_id: longTemplateId },
        });
      }
      const imports = emptyImports(url);
      if (imports) return imports;
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    const sealed: ActView = { ...baseAct, state: 'Sealed', ata_number: 1 };
    renderWithProviders(<ActDocumentPanel act={sealed} family="CommercialCompany" />);

    const metadata = await screen.findByRole('group', {
      name: 'Metadados e proveniência do documento',
    });
    expect(within(metadata).getByText(longTemplateId)).toBeTruthy();
    expect(within(metadata).getByTitle(longTemplateId)).toBeTruthy();
    expect(within(metadata).queryByRole('link', { name: longTemplateId })).toBeNull();
    expect(
      screen.getByText(
        'Markdown e DOCX são cópias de trabalho não probatórias para revisão; o PDF/A preservado é o documento oficial.',
      ),
    ).toBeTruthy();
  });

  it('downloads the Markdown working copy as a text/markdown .md file without replacing the PDF action', async () => {
    const calls: string[] = [];
    vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
      const url = input.toString();
      calls.push(url);
      if (url.includes('/document/bundle')) return json(bundle);
      if (url.includes('/document/working-copy')) {
        return Promise.resolve(
          new Response('# Ata\n\nCópia de trabalho', {
            status: 200,
            headers: { 'Content-Type': 'text/markdown; charset=utf-8' },
          }),
        );
      }
      const imports = emptyImports(url);
      if (imports) return imports;
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    const createUrl = vi.fn((object: Blob | MediaSource) => {
      void object;
      return 'blob:working-copy';
    });
    const revokeUrl = vi.fn();
    vi.stubGlobal('URL', { ...URL, createObjectURL: createUrl, revokeObjectURL: revokeUrl });
    const clickedDownloads: string[] = [];
    const clickSpy = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (
      this: HTMLAnchorElement,
    ) {
      clickedDownloads.push(this.download);
    });

    const sealed: ActView = { ...baseAct, state: 'Sealed', ata_number: 1 };
    renderWithProviders(
      <ActDocumentPanel
        act={sealed}
        entityName="Encosto Estratégico Lda"
        family="CommercialCompany"
      />,
    );

    expect(await screen.findByRole('button', { name: 'Descarregar PDF' })).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Descarregar Markdown' }));

    await waitFor(() =>
      expect(calls.some((url) => url.includes('/v1/acts/act-1/document/working-copy'))).toBe(true),
    );
    await waitFor(() => expect(createUrl).toHaveBeenCalled());
    const blob = createUrl.mock.calls[0]?.[0];
    expect(blob).toBeInstanceOf(Blob);
    const markdownBlob = blob as Blob;
    expect(markdownBlob.type).toBe('text/markdown;charset=utf-8');
    expect(await blobText(markdownBlob)).toBe('# Ata\n\nCópia de trabalho');
    expect(clickedDownloads).toEqual(['encosto-estrategico-lda-ata-1-working-copy.md']);
    expect(revokeUrl).toHaveBeenCalledWith('blob:working-copy');
    expect(clickSpy).toHaveBeenCalled();
    expect(screen.getByRole('button', { name: 'Descarregar PDF' })).toBeTruthy();
  });

  it('downloads the DOCX office working copy as a non-evidentiary .docx file', async () => {
    const calls: string[] = [];
    vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
      const url = input.toString();
      calls.push(url);
      if (url.includes('/document/bundle')) return json(bundle);
      if (url.includes('/document/office')) {
        return Promise.resolve(
          new Response(new Blob(['PK\u0003\u0004docx']), {
            status: 200,
            headers: {
              'Content-Type':
                'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            },
          }),
        );
      }
      const imports = emptyImports(url);
      if (imports) return imports;
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    const createUrl = vi.fn((object: Blob | MediaSource) => {
      void object;
      return 'blob:office';
    });
    const revokeUrl = vi.fn();
    vi.stubGlobal('URL', { ...URL, createObjectURL: createUrl, revokeObjectURL: revokeUrl });
    const clickedDownloads: string[] = [];
    const clickSpy = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (
      this: HTMLAnchorElement,
    ) {
      clickedDownloads.push(this.download);
    });

    const sealed: ActView = { ...baseAct, state: 'Sealed', ata_number: 1 };
    renderWithProviders(
      <ActDocumentPanel
        act={sealed}
        entityName="Encosto Estratégico Lda"
        family="CommercialCompany"
      />,
    );

    expect(await screen.findByRole('button', { name: 'Descarregar DOCX' })).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Descarregar DOCX' }));

    await waitFor(() =>
      expect(calls.some((url) => url.includes('/v1/acts/act-1/document/office'))).toBe(true),
    );
    await waitFor(() => expect(createUrl).toHaveBeenCalled());
    const blob = createUrl.mock.calls[0]?.[0];
    expect(blob).toBeInstanceOf(Blob);
    expect((blob as Blob).type).toBe(
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    );
    expect(clickedDownloads).toEqual(['encosto-estrategico-lda-ata-1-office-working-copy.docx']);
    expect(revokeUrl).toHaveBeenCalledWith('blob:office');
    expect(clickSpy).toHaveBeenCalled();
  });

  it('shows an honest "not generated" note when a sealed act has no document', async () => {
    vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
      const url = input.toString();
      if (url.includes('/document/bundle')) return json({ error: 'sem documento' }, 404);
      const imports = emptyImports(url);
      if (imports) return imports;
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    const sealed: ActView = { ...baseAct, state: 'Sealed', ata_number: 1 };
    renderWithProviders(<ActDocumentPanel act={sealed} family="Condominium" />);

    expect(await screen.findByText('Documento não gerado')).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Descarregar PDF' })).toBeNull();
  });
});

describe('ActDocumentPanel — imported evidence documents', () => {
  it('shows an evidence-only import affordance and an empty state without validity claims', async () => {
    vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
      const url = input.toString();
      const imports = emptyImports(url);
      if (imports) return imports;
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderWithProviders(<ActDocumentPanel act={baseAct} />);

    expect(await screen.findByText('Nenhum documento importado')).toBeTruthy();
    expect(screen.getByLabelText('Importar evidência')).toBeTruthy();
    expect(screen.getByText('Evidência não canónica')).toBeTruthy();
    expect(
      screen.getByText(
        'Documentos importados ficam guardados como evidência ou referência não canónica. Não substituem o PDF/A preservado nem qualquer PDF assinado; a importação não declara validade legal, conformidade PDF/A ou validade de assinatura.',
      ),
    ).toBeTruthy();
    expect(screen.queryByText('Assinatura válida')).toBeNull();
    expect(screen.queryByText('PDF/A válido')).toBeNull();
  });

  it('lists imported documents and reads metadata with missing filenames and long values intact', async () => {
    const longId =
      'import-long-id-0000000000000000000000000000000000000000000000000000000000000000';
    const longFilename =
      'assembleia-geral-extraordinaria-anexos-de-suporte-com-nome-muito-longo-2026-07-09.pdf';
    const missingName: ImportedDocumentView = {
      ...importedDocument,
      id: longId,
      filename: null,
      declared_content_type: null,
      detected_content_type: 'application/octet-stream',
      sha256: 'a'.repeat(64),
      bytes_download: `/v1/documents/imported/${longId}/bytes`,
    };
    const longNamed: ImportedDocumentView = {
      ...importedDocument,
      id: 'import-2',
      filename: longFilename,
      sha256: 'b'.repeat(64),
      bytes_download: '/v1/documents/imported/import-2/bytes',
    };
    const calls: string[] = [];

    vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
      const url = input.toString();
      calls.push(url);
      if (url.includes(`/v1/documents/imported/${encodeURIComponent(longId)}/bytes`)) {
        return Promise.resolve(
          new Response(new Blob(['import bytes'], { type: 'application/octet-stream' }), {
            status: 200,
          }),
        );
      }
      if (url.includes(`/v1/documents/imported/${encodeURIComponent(longId)}`)) {
        return json(missingName);
      }
      if (url.includes('/v1/documents/imported')) return json([missingName, longNamed]);
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    const createUrl = vi.fn((object: Blob | MediaSource) => {
      void object;
      return 'blob:imported';
    });
    const revokeUrl = vi.fn();
    vi.stubGlobal('URL', { ...URL, createObjectURL: createUrl, revokeObjectURL: revokeUrl });
    const clickedDownloads: string[] = [];
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (
      this: HTMLAnchorElement,
    ) {
      clickedDownloads.push(this.download);
    });

    renderWithProviders(<ActDocumentPanel act={baseAct} />);

    const list = await screen.findByRole('list', { name: 'Documentos importados' });
    expect(within(list).getByText('Documento importado sem nome')).toBeTruthy();
    expect(within(list).getByText(longFilename)).toBeTruthy();
    expect(within(list).getByTitle(longFilename)).toBeTruthy();

    const firstItem = within(list).getAllByRole('listitem')[0];
    fireEvent.click(within(firstItem).getByRole('button', { name: 'Ver metadados' }));

    const metadata = await screen.findByRole('group', {
      name: 'Metadados do documento importado',
    });
    expect(within(metadata).getByText('Nome não fornecido pelo importador')).toBeTruthy();
    expect(within(metadata).getByTitle(longId)).toBeTruthy();
    expect(within(metadata).getByText('Não declarado')).toBeTruthy();
    expect(within(metadata).getByText('application/octet-stream')).toBeTruthy();
    expect(within(metadata).getByText('Não canónico')).toBeTruthy();
    expect(calls.some((url) => url.includes(`/v1/documents/imported/${longId}`))).toBe(true);

    fireEvent.click(within(firstItem).getByRole('button', { name: 'Descarregar importado' }));

    await waitFor(() =>
      expect(calls.some((url) => url.includes(`/v1/documents/imported/${longId}/bytes`))).toBe(
        true,
      ),
    );
    expect(clickedDownloads).toEqual([`documento-importado-${longId}.bin`]);
    expect(revokeUrl).toHaveBeenCalledWith('blob:imported');
    expect(screen.queryByText('Assinatura válida')).toBeNull();
  });

  it('imports an uploaded file for the current act after server-side validation', async () => {
    const bodies: unknown[] = [];
    let stored = false;

    vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = input.toString();
      if (isImportCreate(url)) {
        bodies.push(JSON.parse(String(init?.body)));
        stored = true;
        return json(importedDocument);
      }
      if (url.includes('/v1/documents/imported/import-1')) return json(importedDocument);
      if (url.includes('/v1/documents/imported')) return json(stored ? [importedDocument] : []);
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderWithProviders(<ActDocumentPanel act={baseAct} />);
    expect(await screen.findByText('Nenhum documento importado')).toBeTruthy();

    const input = screen.getByLabelText('Importar evidência') as HTMLInputElement;
    const file = new File(['evidence'], 'evidence.pdf', { type: 'application/pdf' });
    fireEvent.change(input, { target: { files: [file] } });

    await waitFor(() => expect(bodies).toHaveLength(1));
    expect(bodies[0]).toEqual({
      content_base64: 'ZXZpZGVuY2U=',
      content_type: 'application/pdf',
      filename: 'evidence.pdf',
      act_id: 'act-1',
    });
    expect(await screen.findAllByText('supporting-evidence.pdf')).toHaveLength(2);
    expect(
      await screen.findByRole('group', { name: 'Metadados do documento importado' }),
    ).toBeTruthy();
  });

  it('surfaces invalid imported content from the API and does not add a fake success state', async () => {
    const bodies: unknown[] = [];

    vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = input.toString();
      if (isImportCreate(url)) {
        bodies.push(JSON.parse(String(init?.body)));
        return json({ error: 'Conteúdo inválido: tipo não suportado' }, 422);
      }
      const imports = emptyImports(url);
      if (imports) return imports;
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderWithProviders(<ActDocumentPanel act={baseAct} />);
    expect(await screen.findByText('Nenhum documento importado')).toBeTruthy();

    const input = screen.getByLabelText('Importar evidência') as HTMLInputElement;
    const file = new File(['bad'], 'bad.bin', { type: 'application/octet-stream' });
    fireEvent.change(input, { target: { files: [file] } });

    await waitFor(() => expect(bodies).toHaveLength(1));
    expect(await screen.findAllByText('Conteúdo inválido: tipo não suportado')).toHaveLength(2);
    expect(screen.queryByRole('group', { name: 'Metadados do documento importado' })).toBeNull();
    expect(screen.queryByText('Assinatura válida')).toBeNull();
  });
});

describe('ActDocumentPanel — honest no-template preview', () => {
  it('renders "sem modelo disponível" when the preview endpoint 422s', async () => {
    vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
      const url = input.toString();
      if (url.includes('/document/preview')) return json({ error: 'sem modelo' }, 422);
      if (url.includes('/templates')) return json([]);
      const imports = emptyImports(url);
      if (imports) return imports;
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderWithProviders(<ActDocumentPanel act={baseAct} family="Condominium" />);

    fireEvent.click(await screen.findByRole('button', { name: 'Pré-visualizar documento' }));

    await waitFor(() => expect(screen.getByText('Sem modelo disponível')).toBeTruthy());
  });
});
