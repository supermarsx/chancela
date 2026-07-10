import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react';
import { renderWithProviders } from '../../test/utils';
import type {
  CaeCatalogView,
  CaeEntryView,
  CaeNode,
  LawCorpusView,
  PdfSignatureValidationResponse,
} from '../../api/types';

const saveFileMock = vi.hoisted(() => ({
  saveBlobAs: vi.fn(),
  saveBlobResultMessage: vi.fn(
    (result: { filename: string }) =>
      `Transferência iniciada pelo navegador: ${result.filename}. A pasta é definida pelo browser.`,
  ),
}));

vi.mock('../../desktop/saveFile', () => saveFileMock);

import { FerramentasPage } from './FerramentasPage';
import { CaeExplorer } from '../cae/CaeExplorer';

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

const CATALOG: CaeCatalogView = {
  origin: 'Embedded',
  schema_version: 1,
  generated_at: '2026-07-07T00:00:00Z',
  source_note: 'Tabela oficial DL 9/2025.',
  digest: 'a'.repeat(64),
  counts: {
    rev3: { seccao: 21, divisao: 88, grupo: 272, classe: 616, subclasse: 850 },
    rev4: { seccao: 22, divisao: 87, grupo: 287, classe: 651, subclasse: 915 },
  },
};

// A subclasse and a divisão with full ancestor chains, for the lookup endpoint.
const SUBCLASSE: CaeEntryView = {
  code: '68110',
  designation: 'Compra e venda de bens imobiliários.',
  level: 'Subclasse',
  revision: 'Rev4',
  hierarchy: [
    { code: 'L', designation: 'Atividades imobiliárias', level: 'Seccao', revision: 'Rev4' },
    { code: '68', designation: 'Atividades imobiliárias', level: 'Divisao', revision: 'Rev4' },
    { code: '681', designation: 'Compra e venda de imóveis', level: 'Grupo', revision: 'Rev4' },
    { code: '6811', designation: 'Compra e venda de imóveis', level: 'Classe', revision: 'Rev4' },
    {
      code: '68110',
      designation: 'Compra e venda de bens imobiliários.',
      level: 'Subclasse',
      revision: 'Rev4',
    },
  ],
};

const DIVISAO: CaeEntryView = {
  code: '68',
  designation: 'Atividades imobiliárias',
  level: 'Divisao',
  revision: 'Rev4',
  hierarchy: [
    { code: 'L', designation: 'Atividades imobiliárias', level: 'Seccao', revision: 'Rev4' },
    { code: '68', designation: 'Atividades imobiliárias', level: 'Divisao', revision: 'Rev4' },
  ],
};

const LOOKUPS: Record<string, CaeEntryView> = { '68110': SUBCLASSE, '68': DIVISAO };

// The search endpoint (also used for children-by-prefix). Keyed by the search term.
const SEARCHES: Record<string, CaeNode[]> = {
  imobili: [
    {
      code: '68110',
      designation: 'Compra e venda de bens imobiliários.',
      level: 'Subclasse',
      revision: 'Rev4',
    },
  ],
  // Children pool for divisão "68": two grupos (kept) + noise the filter must drop
  // (a deeper classe by length; an unrelated code that only matched by designation).
  '68': [
    { code: '681', designation: 'Compra e venda de imóveis', level: 'Grupo', revision: 'Rev4' },
    { code: '682', designation: 'Arrendamento de imóveis', level: 'Grupo', revision: 'Rev4' },
    { code: '6811', designation: 'Compra e venda de imóveis', level: 'Classe', revision: 'Rev4' },
    { code: '55', designation: 'Referência a imóvel 68', level: 'Divisao', revision: 'Rev4' },
  ],
};

/**
 * A branching fetch stub for the Ferramentas surface. Order matters: refresh (POST) →
 * single-code lookup (`/v1/cae/<code>`) → search (`?search=`) → catalog metadata.
 */
function ferramentasFetch(
  refresh: () => Response = () => jsonResponse({ updated: false }),
): typeof fetch {
  return ((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const method = init?.method ?? 'GET';
    if (url.includes('/v1/cae/refresh') && method === 'POST') return Promise.resolve(refresh());
    const lookup = url.match(/\/v1\/cae\/([^?]+)/);
    if (lookup) {
      const code = decodeURIComponent(lookup[1]);
      const entry = LOOKUPS[code];
      return Promise.resolve(entry ? jsonResponse(entry) : jsonResponse({ error: 'unknown' }, 404));
    }
    const search = new URL(url, 'http://x').searchParams.get('search');
    if (search !== null) {
      return Promise.resolve(jsonResponse(SEARCHES[search] ?? []));
    }
    if (url.includes('/v1/cae')) return Promise.resolve(jsonResponse(CATALOG));
    return Promise.reject(new Error(`no stub for ${url}`));
  }) as typeof fetch;
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  saveFileMock.saveBlobAs.mockReset();
  saveFileMock.saveBlobResultMessage.mockClear();
});

const PDF_VALIDATION_RESPONSE: PdfSignatureValidationResponse = {
  report_kind: 'pdf_signature_validation',
  scope: 'local_technical_pdf_pades_evidence',
  legal_notice:
    'Local technical PDF/PAdES evidence validation only. No AMA integration, live trusted-list validation, live revocation validation, qualified-status decision, or legal-validity conclusion is performed or claimed.',
  status: 'valid',
  filename: 'signed.pdf',
  sha256: '1'.repeat(64),
  size_bytes: 14,
  declared_sha256: '1'.repeat(64),
  declared_size_bytes: 14,
  structure: {
    is_pdf: true,
    header_offset: 0,
    version: '1.7',
    has_eof_marker: true,
    has_startxref: true,
  },
  signature: {
    status: 'valid',
    validation_performed: true,
    validation_error: null,
    signed_pdf_signal: true,
    signature_marker_count: 1,
    byte_range_marker_count: 1,
    has_contents_marker: true,
    pades_profile: 'PAdES-B-T',
    byte_range: {
      byte_range: [0, 10, 20, 30],
      covered_len: 40,
      total_len: 42,
      signed_revision_len: 42,
      excluded_len: 2,
      covers_whole_file_except_contents: true,
      covers_signed_revision_except_contents: true,
      has_later_incremental_updates: false,
      digest_sha256: '2'.repeat(64),
    },
    cades: {
      status: 'valid',
      attrs_ok: true,
      signing_certificate_v2_present: true,
      signer_cert_sha256: '3'.repeat(64),
      signer_cert_subject: 'CN=Signer',
      signing_time: '2026-07-10T10:00:00Z',
    },
    timestamp: { signature_timestamp_present: true, status_scope: 'technical_evidence_only' },
    dss: {
      present: true,
      vri_count: 1,
      vri_tu_count: 1,
      vri_has_tu: true,
      certificate_count: 2,
      ocsp_count: 1,
      crl_count: 0,
      revocation_evidence_present: true,
      certificate_sha256: ['4'.repeat(64)],
      ocsp_sha256: ['5'.repeat(64)],
      crl_sha256: [],
      status_scope: 'technical_evidence_only',
    },
    doc_timestamp: {
      present: true,
      count: 1,
      token_count: 1,
      token_sha256: ['6'.repeat(64)],
      all_imprints_valid: true,
      validations: [
        {
          index: 0,
          object_id: '12 0 R',
          byte_range: [0, 10, 20, 30],
          document_digest_sha256: '7'.repeat(64),
          token_imprint_sha256: '7'.repeat(64),
          token_hash_algorithm: 'sha256',
          status: 'valid',
          failure_reason: null,
        },
      ],
      status_scope: 'technical_evidence_only',
    },
  },
  trust: {
    status: 'not_performed',
    performed: false,
    live_trusted_list_validation_performed: false,
    ama_integration_performed: false,
    message: 'trust validation not performed',
  },
  revocation: {
    status: 'not_performed',
    live_fetch_performed: false,
    freshness_validation_performed: false,
    embedded_evidence_inspected: true,
    embedded_revocation_evidence_present: true,
    message: 'revocation freshness not performed',
  },
  qualification: {
    status: 'not_performed',
    qualified_status_claimed: false,
    legal_validity_claimed: false,
    legal_effect_assessed: false,
    message: 'qualification not assessed',
  },
  findings: [
    {
      severity: 'info',
      code: 'pades_valid_local_technical',
      message: 'PAdES/CAdES cryptographic validation succeeded locally',
    },
  ],
};

function pdfValidatorFetch(response: Response): typeof fetch {
  return ((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const method = init?.method ?? 'GET';
    if (url.includes('/v1/signature/pdf/validate') && method === 'POST') {
      return Promise.resolve(response);
    }
    return Promise.reject(new Error(`no stub for ${url}`));
  }) as typeof fetch;
}

describe('Ferramentas — PDF signature validator', () => {
  it('keeps validation disabled until a PDF is selected', async () => {
    vi.stubGlobal('fetch', pdfValidatorFetch(jsonResponse(PDF_VALIDATION_RESPONSE)));
    renderWithProviders(<FerramentasPage />, ['/ferramentas?tool=pdf']);

    expect(
      (await screen.findByRole('button', { name: /validar pdf/i })).hasAttribute('disabled'),
    ).toBe(true);
  });

  it('uploads a PDF as base64 with declared SHA-256 and size', async () => {
    const fetchMock = vi.fn(pdfValidatorFetch(jsonResponse(PDF_VALIDATION_RESPONSE)));
    vi.stubGlobal('fetch', fetchMock);
    renderWithProviders(<FerramentasPage />, ['/ferramentas?tool=pdf']);

    const file = new File(['%PDF-1.7\n%%EOF'], 'signed.pdf', { type: 'application/pdf' });
    fireEvent.change(await screen.findByLabelText('PDF assinado'), { target: { files: [file] } });
    fireEvent.click(screen.getByRole('button', { name: /validar pdf/i }));

    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const body = JSON.parse(String(init.body)) as {
      content_base64: string;
      filename: string;
      declared_sha256: string | null;
      declared_size_bytes: number;
    };
    expect(url).toBe('/v1/signature/pdf/validate');
    expect(init.method).toBe('POST');
    expect(body.content_base64).toBe('JVBERi0xLjcKJSVFT0Y=');
    expect(body.filename).toBe('signed.pdf');
    expect(body.declared_size_bytes).toBe(14);
    expect(body.declared_sha256).toMatch(/^[a-f0-9]{64}$/);
  });

  it('renders a valid response with structure, PAdES, DSS and trust sections', async () => {
    vi.stubGlobal('fetch', pdfValidatorFetch(jsonResponse(PDF_VALIDATION_RESPONSE)));
    renderWithProviders(<FerramentasPage />, ['/ferramentas?tool=pdf']);

    const file = new File(['%PDF-1.7\n%%EOF'], 'signed.pdf', { type: 'application/pdf' });
    fireEvent.change(await screen.findByLabelText('PDF assinado'), { target: { files: [file] } });
    fireEvent.click(screen.getByRole('button', { name: /validar pdf/i }));

    expect(await screen.findByText('Tecnicamente válido')).toBeTruthy();
    expect(screen.getByText('PAdES-B-T')).toBeTruthy();
    expect(screen.getByText('DSS, VRI e revogação embebida')).toBeTruthy();
    expect(screen.getByText('Confiança, revogação e qualificação')).toBeTruthy();
    expect(screen.getByText('pades_valid_local_technical')).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Copiar JSON' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Guardar JSON' })).toBeTruthy();
  });

  it('copies the technical JSON report after validation returns a report body', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText },
      configurable: true,
    });
    vi.stubGlobal('fetch', pdfValidatorFetch(jsonResponse(PDF_VALIDATION_RESPONSE)));
    renderWithProviders(<FerramentasPage />, ['/ferramentas?tool=pdf']);

    const file = new File(['%PDF-1.7\n%%EOF'], 'signed.pdf', { type: 'application/pdf' });
    fireEvent.change(await screen.findByLabelText('PDF assinado'), { target: { files: [file] } });
    fireEvent.click(screen.getByRole('button', { name: /validar pdf/i }));

    fireEvent.click(await screen.findByRole('button', { name: 'Copiar JSON' }));

    await waitFor(() => expect(writeText).toHaveBeenCalledTimes(1));
    const copied = String(writeText.mock.calls[0][0]);
    expect(copied).toContain('\n  "report_kind": "pdf_signature_validation"');
    expect(copied).toContain('technical PDF/PAdES evidence validation only');
    expect(JSON.parse(copied)).toEqual(PDF_VALIDATION_RESPONSE);
  });

  it('saves the technical JSON report as a browser-save/download Blob', async () => {
    saveFileMock.saveBlobAs.mockResolvedValue({
      kind: 'browser-download',
      filename: 'signed-validation-report.json',
      contentType: 'application/json;charset=utf-8',
      bytes: 1,
    });
    vi.stubGlobal('fetch', pdfValidatorFetch(jsonResponse(PDF_VALIDATION_RESPONSE)));
    renderWithProviders(<FerramentasPage />, ['/ferramentas?tool=pdf']);

    const file = new File(['%PDF-1.7\n%%EOF'], 'signed.pdf', { type: 'application/pdf' });
    fireEvent.change(await screen.findByLabelText('PDF assinado'), { target: { files: [file] } });
    fireEvent.click(screen.getByRole('button', { name: /validar pdf/i }));
    fireEvent.click(await screen.findByRole('button', { name: 'Guardar JSON' }));

    await waitFor(() => expect(saveFileMock.saveBlobAs).toHaveBeenCalledTimes(1));
    const saved = saveFileMock.saveBlobAs.mock.calls[0][0] as {
      blob: Blob;
      filename: string;
      contentType: string;
      filters: { name: string; extensions: string[] }[];
      preferBrowserSavePicker: boolean;
    };
    expect(saved.filename).toBe('signed-validation-report.json');
    expect(saved.contentType).toBe('application/json;charset=utf-8');
    expect(saved.filters).toEqual([{ name: 'JSON', extensions: ['json'] }]);
    expect(saved.preferBrowserSavePicker).toBe(true);
    expect(saved.blob.type).toBe('application/json;charset=utf-8');
    expect(JSON.parse(await blobText(saved.blob))).toEqual(PDF_VALIDATION_RESPONSE);
  });

  it('renders invalid findings from the backend report', async () => {
    vi.stubGlobal(
      'fetch',
      pdfValidatorFetch(
        jsonResponse({
          ...PDF_VALIDATION_RESPONSE,
          status: 'invalid',
          signature: {
            ...PDF_VALIDATION_RESPONSE.signature,
            status: 'invalid',
            validation_error: 'invalid byte range',
          },
          findings: [
            {
              severity: 'error',
              code: 'invalid_byte_range',
              message: 'signature ByteRange is malformed or outside the file',
            },
          ],
        } satisfies PdfSignatureValidationResponse),
      ),
    );
    renderWithProviders(<FerramentasPage />, ['/ferramentas?tool=pdf']);

    const file = new File(['%PDF-1.7\n%%EOF'], 'bad.pdf', { type: 'application/pdf' });
    fireEvent.change(await screen.findByLabelText('PDF assinado'), { target: { files: [file] } });
    fireEvent.click(screen.getByRole('button', { name: /validar pdf/i }));

    expect(await screen.findByText('Inválido')).toBeTruthy();
    expect(screen.getByText('invalid_byte_range')).toBeTruthy();
    expect(screen.getByText('invalid byte range')).toBeTruthy();
  });

  it('shows digest/size mismatch backend refusals as fail-closed', async () => {
    vi.stubGlobal(
      'fetch',
      pdfValidatorFetch(
        jsonResponse(
          { error: 'declared PDF SHA-256 digest does not match the received bytes' },
          422,
        ),
      ),
    );
    renderWithProviders(<FerramentasPage />, ['/ferramentas?tool=pdf']);

    const file = new File(['%PDF-1.7\n%%EOF'], 'mismatch.pdf', { type: 'application/pdf' });
    fireEvent.change(await screen.findByLabelText('PDF assinado'), { target: { files: [file] } });
    fireEvent.click(screen.getByRole('button', { name: /validar pdf/i }));

    expect(await screen.findByText('Validação recusada')).toBeTruthy();
    expect(screen.getByText(/recusa segura/i)).toBeTruthy();
    expect(screen.getByText(/SHA-256 digest does not match/i)).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Copiar JSON' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Guardar JSON' })).toBeNull();
  });
});

describe('Ferramentas — CAE catalog panel', () => {
  it('shows catalog metadata (origin + per-revision totals)', async () => {
    vi.stubGlobal('fetch', ferramentasFetch());
    renderWithProviders(<FerramentasPage />, ['/ferramentas']);

    expect(await screen.findByText('Incorporado')).toBeTruthy();
    // Rev.4 total = sum of the five level counts.
    expect(screen.getByText('1962')).toBeTruthy();
  });

  it('reports a successful refresh distinctly', async () => {
    vi.stubGlobal(
      'fetch',
      ferramentasFetch(() =>
        jsonResponse({
          updated: true,
          metadata: { ...CATALOG, origin: 'Cache' },
          note: 'cache atualizada para a versão gerada em 2026-08-01.',
        }),
      ),
    );
    renderWithProviders(<FerramentasPage />, ['/ferramentas']);

    fireEvent.click(await screen.findByRole('button', { name: /atualizar catálogo/i }));
    expect(await screen.findByText('Catálogo atualizado')).toBeTruthy();
  });

  it('routes a 422 "not configured" to Configurações (contract F1b)', async () => {
    vi.stubGlobal(
      'fetch',
      ferramentasFetch(() =>
        jsonResponse(
          {
            error:
              'URL de atualização do catálogo não configurado — defina-o em Configurações (Documentos → Catálogo CAE) ou na variável de ambiente CHANCELA_CAE_URL.',
          },
          422,
        ),
      ),
    );
    renderWithProviders(<FerramentasPage />, ['/ferramentas']);

    fireEvent.click(await screen.findByRole('button', { name: /atualizar catálogo/i }));
    expect(await screen.findByText('Configuração em falta')).toBeTruthy();
    // The copy links to Configurações, not the env var.
    const link = screen.getByRole('link', { name: /Configurações/i });
    expect(link.getAttribute('href')).toBe('/configuracoes');
    // The server's friendly message is rendered verbatim — inline note + error toast (R7).
    expect(screen.getAllByText(/não configurado/).length).toBeGreaterThanOrEqual(1);
  });

  it('reports a 502 upstream failure distinctly from the 422 config state', async () => {
    vi.stubGlobal(
      'fetch',
      ferramentasFetch(() => jsonResponse({ error: 'cae source failed: connection refused' }, 502)),
    );
    renderWithProviders(<FerramentasPage />, ['/ferramentas']);

    fireEvent.click(await screen.findByRole('button', { name: /atualizar catálogo/i }));
    expect(await screen.findByText('Fonte do catálogo indisponível')).toBeTruthy();
    expect(screen.queryByText('Configuração em falta')).toBeNull();
  });
});

describe('Ferramentas — sub-tab animation + indicator', () => {
  // A minimal but valid corpus so the Legislação corpus reader (the default sub-view) mounts
  // cleanly; the PDF-archive `/v1/law` probe answers with an empty manifest.
  const EMPTY_CORPUS: LawCorpusView = {
    schema_version: 1,
    generated_at: '2026-07-08T00:00:00Z',
    source_note: 'Corpus de teste.',
    digest: 'a'.repeat(64),
    origin: 'Embedded',
    counts: { diplomas: 0, articles: 0, verified: 0, pending: 0 },
    diplomas: [],
  };

  // A stub that also answers the Legislação surface's corpus + `/v1/law` probes cleanly.
  function toolsFetch(): typeof fetch {
    const base = ferramentasFetch();
    return ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.includes('/v1/law/corpus')) return Promise.resolve(jsonResponse(EMPTY_CORPUS));
      if (url.includes('/v1/law')) return Promise.resolve(jsonResponse([]));
      return base(input, init);
    }) as typeof fetch;
  }

  it('re-keys the content on tool switch but not on an unrelated (?q) param change', async () => {
    vi.stubGlobal('fetch', toolsFetch());
    const { container } = renderWithProviders(<FerramentasPage />, ['/ferramentas']);
    const animKey = () => container.querySelector('[data-anim-key]')?.getAttribute('data-anim-key');

    // Default surface is CAE; its indicator + active pill track the CAE sub-tab.
    expect(await screen.findByText('Incorporado')).toBeTruthy();
    expect(animKey()).toBe('cae');
    expect(container.querySelector('.ferramentas-subnav__indicator')).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Catálogo CAE' }).getAttribute('aria-pressed')).toBe(
      'true',
    );

    // Switching tool re-keys the content region (so it replays the enter animation).
    fireEvent.click(screen.getByRole('button', { name: 'Legislação' }));
    expect(animKey()).toBe('legislacao');
    expect(screen.getByRole('button', { name: 'Legislação' }).getAttribute('aria-pressed')).toBe(
      'true',
    );

    // Legislação's own ?q search changes the URL but NOT the section → no re-key/replay. The
    // default Legislação sub-view is now the full-text corpus reader.
    fireEvent.change(screen.getByLabelText('Pesquisar em toda a legislação'), {
      target: { value: 'condominio' },
    });
    expect(animKey()).toBe('legislacao');
  });
});

describe('Ferramentas — CAE explorer', () => {
  it('searches, and selecting a hit resolves its detail with a hierarchy breadcrumb', async () => {
    vi.stubGlobal('fetch', ferramentasFetch());
    renderWithProviders(<CaeExplorer />, ['/ferramentas']);

    fireEvent.change(screen.getByLabelText('Procurar no catálogo CAE'), {
      target: { value: 'imobili' },
    });
    // The search hit appears; click it to open the detail pane.
    const hit = await screen.findByText('Compra e venda de bens imobiliários.');
    fireEvent.click(hit);

    // The detail resolves: designation + a terminal-level note + the breadcrumb roots at
    // the secção. The breadcrumb renders each ancestor's code as a clickable crumb.
    expect(await screen.findByText(/Nível terminal/)).toBeTruthy();
    expect(screen.getByRole('button', { name: 'L' })).toBeTruthy();
    expect(screen.getByRole('button', { name: '681' })).toBeTruthy();
  });

  it('drills DOWN a numeric node to its exact prefix children, dropping non-children', async () => {
    vi.stubGlobal('fetch', ferramentasFetch());
    // Deep-link straight to the divisão so its subníveis load.
    renderWithProviders(<CaeExplorer />, ['/ferramentas?code=68&rev=Rev4']);

    // Direct grupos are listed…
    expect(await screen.findByRole('button', { name: /681/ })).toBeTruthy();
    expect(screen.getByRole('button', { name: /682/ })).toBeTruthy();
    // …while a deeper classe (wrong length) and a designation-only match (wrong prefix)
    // are filtered out.
    expect(screen.queryByRole('button', { name: /6811/ })).toBeNull();
    expect(screen.queryByRole('button', { name: /^55/ })).toBeNull();
  });

  it('switches revision (Rev.3 / Rev.4) via the segmented control', async () => {
    vi.stubGlobal('fetch', ferramentasFetch());
    renderWithProviders(<CaeExplorer />, ['/ferramentas']);

    const rev3 = await screen.findByRole('button', { name: 'Rev.3' });
    const rev4 = screen.getByRole('button', { name: 'Rev.4' });
    // Rev.4 is the default active revision.
    expect(rev4.getAttribute('aria-pressed')).toBe('true');
    expect(rev3.getAttribute('aria-pressed')).toBe('false');

    fireEvent.click(rev3);
    expect(rev3.getAttribute('aria-pressed')).toBe('true');
    expect(rev4.getAttribute('aria-pressed')).toBe('false');
  });
});
