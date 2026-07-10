import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { renderWithProviders } from '../../test/utils';
import { LegislacaoPage } from './LegislacaoPage';
import { CorpusReader } from './CorpusReader';
import { FerramentasPage } from '../ferramentas/FerramentasPage';
import {
  DIPLOMAS,
  LEGISLACAO_TEMAS,
  REVIEWED_ON,
  diplomasByTema,
  searchDiplomas,
} from './diplomas';
import type {
  LawEntryView,
  LawCitationReport,
  LawCorpusView,
  LawDiplomaDetailView,
  LawSearchView,
} from '../../api/types';

// The law shelf links out through openExternal; mock it so a click is observable and
// nothing tries to reach the OS / a real tab under jsdom.
vi.mock('../../desktop/openExternal', () => ({ openExternal: vi.fn() }));
import { openExternal } from '../../desktop/openExternal';

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

/** Build a full frozen §law-v1 `LawEntryView` from a partial (fills the required fields). */
function lawEntry(p: Partial<LawEntryView> & { id: string }): LawEntryView {
  return {
    title: 'Diploma',
    ref: 'Ref',
    articles: [],
    why: 'Porquê',
    official_url: 'https://diariodarepublica.pt/x',
    pdf_url: null,
    last_amended: null,
    reviewed_on: REVIEWED_ON,
    stored: false,
    stored_digest: null,
    stored_bytes: null,
    retrieved_at: null,
    ...p,
  };
}

/**
 * A fetch stub for the law-archive endpoints. `manifest: 'missing'` simulates an old
 * server (404 → the UI falls back to links-only); an array is the `/v1/law` manifest
 * (a bare `[LawEntryView]`, per frozen §law-v1). POST `/v1/law/{id}/fetch` returns
 * `fetchResult`.
 */
function lawFetch(opts: {
  manifest?: LawEntryView[] | 'missing';
  fetchResult?: LawEntryView;
}): typeof fetch {
  return vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const method = init?.method ?? 'GET';
    if (url.includes('/v1/law/') && url.endsWith('/fetch') && method === 'POST') {
      return Promise.resolve(json(opts.fetchResult ?? lawEntry({ id: 'x', stored: true })));
    }
    if (url === '/v1/law' || url.startsWith('/v1/law?')) {
      if (opts.manifest === 'missing') return Promise.resolve(json({ error: 'not found' }, 404));
      return Promise.resolve(json(opts.manifest ?? []));
    }
    return Promise.reject(new Error(`no stub for ${url}`));
  }) as unknown as typeof fetch;
}

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
  vi.unstubAllGlobals();
});

describe('Legislação — data module', () => {
  it('every diploma has the required fields and a themed, unique id', () => {
    const temaIds = new Set(LEGISLACAO_TEMAS.map((t) => t.id));
    const seen = new Set<string>();
    for (const d of DIPLOMAS) {
      expect(d.id).toBeTruthy();
      expect(seen.has(d.id)).toBe(false);
      seen.add(d.id);

      expect(d.title.trim().length).toBeGreaterThan(0);
      expect(d.ref.trim().length).toBeGreaterThan(0);
      expect(d.why.trim().length).toBeGreaterThan(0);
      expect(d.extract.trim().length).toBeGreaterThan(0);
      expect(temaIds.has(d.tema)).toBe(true);

      // Official link is present and stable (DRE or EUR-Lex, https).
      expect(d.officialUrl).toMatch(/^https:\/\/(diariodarepublica\.pt|eur-lex\.europa\.eu)\//);
      // reviewed_on present on every entry.
      expect(d.reviewedOn).toBe(REVIEWED_ON);
    }
  });

  it('marks extracts as quote or resumo, and PDFs are official (DR files. or EUR-Lex)', () => {
    const pdfPattern =
      /^https:\/\/(files\.(dre\.pt|diariodarepublica\.pt)\/.+\.pdf|eur-lex\.europa\.eu\/legal-content\/PT\/TXT\/PDF\/\?uri=CELEX:\w+)$/;
    for (const d of DIPLOMAS) {
      expect(['quote', 'resumo']).toContain(d.extractKind);
      if (d.pdfUrl !== null) expect(d.pdfUrl).toMatch(pdfPattern);
    }
    // The verbatim quotes are the two canonical EU provisions (eIDAS art. 25 + RGPD art. 5).
    const quotes = DIPLOMAS.filter((d) => d.extractKind === 'quote').map((d) => d.id);
    expect(quotes).toEqual(['eidas-art-25', 'rgpd-art-5']);
    // Both CAE diplomas carry a stored-source PDF; the consolidated codes (CSC articles,
    // Código Civil) are HTML-only, so they are null.
    const byId = new Map(DIPLOMAS.map((d) => [d.id, d]));
    expect(byId.get('dl-9-2025')?.pdfUrl).toBeTruthy();
    expect(byId.get('dl-381-2007')?.pdfUrl).toBeTruthy();
    expect(byId.get('csc-63')?.pdfUrl).toBeNull();
    expect(byId.get('codigo-civil-pessoas-coletivas')?.pdfUrl).toBeNull();
    // The archive covers a meaningful share of the shelf (more than just the CAE pair).
    expect(DIPLOMAS.filter((d) => d.pdfUrl !== null).length).toBeGreaterThan(6);
  });

  it('populates every declared theme and carries the expanded curation', () => {
    // No theme is an empty shelf.
    for (const tema of LEGISLACAO_TEMAS) {
      expect(diplomasByTema(tema.id).length).toBeGreaterThan(0);
    }
    // The t34 additions are present, grouped into their themes.
    const ids = new Set(DIPLOMAS.map((d) => d.id));
    for (const id of [
      'csc-56-58',
      'csc-246',
      'csc-270a',
      'codigo-comercial-escrituracao',
      'cc-propriedade-horizontal',
      'eidas2-2024-1183',
      'lei-58-2019',
      'cc-associacoes',
      'crcom-403-86',
      'dl-129-98-rnpc',
      'lei-89-2017-rcbe',
    ]) {
      expect(ids.has(id), id).toBe(true);
    }
    // The new "Registo e identificação" theme is populated.
    expect(diplomasByTema('registo-identificacao').length).toBeGreaterThanOrEqual(3);
  });

  it('searchDiplomas folds accents and case across title/ref/why/extract', () => {
    // Accent- and case-insensitive: "CONDOMINIO" matches "condomínio".
    expect(searchDiplomas('CONDOMINIO').some((d) => d.id === 'dl-268-94')).toBe(true);
    // Matches on the reference field too.
    expect(searchDiplomas('270.º-A').some((d) => d.id === 'csc-270a')).toBe(true);
    // Matches on the why/extract text.
    expect(searchDiplomas('beneficiário efetivo').some((d) => d.id === 'lei-89-2017-rcbe')).toBe(
      true,
    );
    // A blank query returns the whole shelf; a nonsense query returns nothing.
    expect(searchDiplomas('   ').length).toBe(DIPLOMAS.length);
    expect(searchDiplomas('zzzznaoexiste')).toEqual([]);
  });
});

describe('Legislação — page', () => {
  it('renders every theme group and the informative caveat', () => {
    vi.stubGlobal('fetch', lawFetch({ manifest: 'missing' }));
    renderWithProviders(<LegislacaoPage />, ['/?leg=prateleira']);
    for (const t of LEGISLACAO_TEMAS) {
      expect(screen.getByRole('heading', { name: t.label })).toBeTruthy();
    }
    expect(screen.getByText(/faz fé a publicação oficial no Diário da República/)).toBeTruthy();
  });

  it('shows a diploma card with its amendment + last-reviewed badges', () => {
    vi.stubGlobal('fetch', lawFetch({ manifest: 'missing' }));
    renderWithProviders(<LegislacaoPage />, ['/?leg=prateleira']);
    // DL 268/94 records an amendment (Lei 8/2022) and the review date.
    const card = screen.getByText('Atas das assembleias de condóminos').closest('article');
    expect(card).not.toBeNull();
    const scope = within(card as HTMLElement);
    expect(scope.getByText(/Alterado por Lei n\.º 8\/2022/)).toBeTruthy();
    expect(scope.getByText(`Revisto em ${REVIEWED_ON}`)).toBeTruthy();
  });

  it('routes the official-source link through openExternal on a plain click', () => {
    vi.stubGlobal('fetch', lawFetch({ manifest: 'missing' }));
    renderWithProviders(<LegislacaoPage />, ['/?leg=prateleira']);
    const card = screen.getByText('Atas das assembleias de condóminos').closest('article');
    const link = within(card as HTMLElement).getByRole('link', { name: 'Publicação oficial' });
    // The anchor keeps its real href for modified/middle clicks…
    expect(link.getAttribute('href')).toContain('diariodarepublica.pt');
    // …but a plain left-click is handed to openExternal instead of navigating the WebView.
    fireEvent.click(link, { button: 0 });
    expect(openExternal).toHaveBeenCalledWith(
      expect.stringContaining(
        'diariodarepublica.pt/dr/legislacao-consolidada/decreto-lei/1994-144575382',
      ),
    );
  });
});

describe('Legislação — mini law archive (frozen §law-v1 t27 seam)', () => {
  // dl-9-2025 is an id that matches BOTH our shelf and the server manifest AND is archivable
  // (pinned pdf_url), so it exercises the real Guardar/stored path.
  const CAE4 = 'Classificação Portuguesa das Atividades Económicas, Rev.4 (CAE-Rev.4)'; // dl-9-2025
  const EIDAS = 'Execução do eIDAS na ordem jurídica interna'; // dl-12-2021 (server: pdf_url null)

  it('falls back to links-only when the server has no law store (404)', async () => {
    vi.stubGlobal('fetch', lawFetch({ manifest: 'missing' }));
    renderWithProviders(<LegislacaoPage />, ['/?leg=prateleira']);
    const scope = within(screen.getByText(CAE4).closest('article') as HTMLElement);
    // The official PDF link is shown, but no "Guardar PDF" action (feature absent).
    expect(scope.getByRole('link', { name: 'PDF oficial' })).toBeTruthy();
    await waitFor(() => expect(scope.queryByRole('button', { name: /Guardar PDF/ })).toBeNull());
  });

  it('stays links-only when the server holds the diploma but it is not archivable (pdf_url null)', async () => {
    // The server manifest for dl-12-2021 has a null pdf_url (cannot pin the DR files. URL) —
    // even though our shelf has a curated pdfUrl, no Guardar action is offered.
    vi.stubGlobal('fetch', lawFetch({ manifest: [lawEntry({ id: 'dl-12-2021', pdf_url: null })] }));
    renderWithProviders(<LegislacaoPage />, ['/?leg=prateleira']);
    const scope = within(screen.getByText(EIDAS).closest('article') as HTMLElement);
    expect(scope.getByRole('link', { name: 'PDF oficial' })).toBeTruthy();
    await waitFor(() => expect(scope.queryByRole('button', { name: /Guardar PDF/ })).toBeNull());
  });

  it('offers "Guardar PDF" when available + archivable + not stored, and posts the fetch', async () => {
    const fetchMock = lawFetch({
      manifest: [lawEntry({ id: 'dl-9-2025', pdf_url: 'https://files.x/y.pdf', stored: false })],
    });
    vi.stubGlobal('fetch', fetchMock);
    renderWithProviders(<LegislacaoPage />, ['/?leg=prateleira']);

    const card = screen.getByText(CAE4).closest('article') as HTMLElement;
    const button = await within(card).findByRole('button', { name: 'Guardar PDF' });
    fireEvent.click(button);

    await waitFor(() =>
      expect(
        (fetchMock as unknown as ReturnType<typeof vi.fn>).mock.calls.some(
          ([input, init]) =>
            String(input).endsWith('/v1/law/dl-9-2025/fetch') &&
            (init as RequestInit | undefined)?.method === 'POST',
        ),
      ).toBe(true),
    );
    // A success toast confirms the local store (t44 retrofit-b).
    expect(await screen.findByText('PDF guardado localmente.')).toBeTruthy();
  });

  it('shows the stored badge + a local "Abrir PDF" link when stored', async () => {
    vi.stubGlobal(
      'fetch',
      lawFetch({
        manifest: [
          lawEntry({
            id: 'dl-9-2025',
            pdf_url: 'https://files.x/y.pdf',
            stored: true,
            stored_digest: 'a'.repeat(64),
            stored_bytes: 123456,
            retrieved_at: '2026-07-07T10:00:00Z',
          }),
        ],
      }),
    );
    renderWithProviders(<LegislacaoPage />, ['/?leg=prateleira']);

    const scope = within(screen.getByText(CAE4).closest('article') as HTMLElement);
    // The stored badge appears (digest + date), and "Abrir PDF" targets the local endpoint.
    expect(await scope.findByText(/Guardado/)).toBeTruthy();
    const open = scope.getByRole('link', { name: 'Abrir PDF' });
    expect(open.getAttribute('href')).toBe('/v1/law/dl-9-2025/pdf');
    // No "Guardar PDF" once it is stored.
    expect(scope.queryByRole('button', { name: /Guardar PDF/ })).toBeNull();
  });
});

describe('Legislação — search', () => {
  const FUNDACOES = 'Lei-Quadro das Fundações'; // a diploma that must NOT match "condominio"

  it('filters the cards live (accent- and case-folded) and shows a match count', async () => {
    vi.stubGlobal('fetch', lawFetch({ manifest: 'missing' }));
    renderWithProviders(<LegislacaoPage />, ['/?leg=prateleira']);
    const box = screen.getByLabelText('Procurar na legislação');
    // A query typed without accents still matches accented content. Wait for the debounced
    // filter to drop the non-matching diplomas from the shelf.
    fireEvent.change(box, { target: { value: 'condominio' } });
    await waitFor(() => expect(screen.queryByText(FUNDACOES)).toBeNull());
    // The matching condominio diploma remains.
    expect(screen.getByText('Atas das assembleias de condóminos')).toBeTruthy();
    // The match count is shown (N de TOTAL diplomas).
    expect(await screen.findByText(/de \d+ diplomas/)).toBeTruthy();
  });

  it('shows an empty state when nothing matches', async () => {
    vi.stubGlobal('fetch', lawFetch({ manifest: 'missing' }));
    renderWithProviders(<LegislacaoPage />, ['/?leg=prateleira']);
    fireEvent.change(screen.getByLabelText('Procurar na legislação'), {
      target: { value: 'zzzznaoexiste' },
    });
    expect(await screen.findByText('Nenhum diploma corresponde a «zzzznaoexiste».')).toBeTruthy();
  });

  it('clears the search with the clear affordance', async () => {
    vi.stubGlobal('fetch', lawFetch({ manifest: 'missing' }));
    renderWithProviders(<LegislacaoPage />, ['/?leg=prateleira']);
    const box = screen.getByLabelText('Procurar na legislação');
    fireEvent.change(box, { target: { value: 'condominio' } });
    await waitFor(() => expect(screen.queryByText(FUNDACOES)).toBeNull());
    fireEvent.click(await screen.findByRole('button', { name: 'Limpar' }));
    // The whole shelf returns.
    await waitFor(() => expect(screen.getByText(FUNDACOES)).toBeTruthy());
  });

  it('is deep-linkable via ?q= — seeds the field and pre-filters the shelf', async () => {
    vi.stubGlobal('fetch', lawFetch({ manifest: 'missing' }));
    renderWithProviders(<LegislacaoPage />, [
      '/ferramentas?tool=legislacao&leg=prateleira&q=eIDAS',
    ]);
    const box = screen.getByLabelText('Procurar na legislação') as HTMLInputElement;
    expect(box.value).toBe('eIDAS');
    // Pre-filtered to eIDAS diplomas; unrelated themes are hidden.
    await waitFor(() =>
      expect(
        screen.getByText('Efeitos legais das assinaturas eletrónicas qualificadas'),
      ).toBeTruthy(),
    );
    expect(screen.queryByText(FUNDACOES)).toBeNull();
  });
});

describe('Ferramentas — Legislação sub-navigation', () => {
  it('defaults to CAE, opens the Legislação corpus reader, then the curated shelf', () => {
    // Stub fetch so the mounted CAE panels + law manifest resolve quietly. The corpus reader's
    // /v1/law/corpus probe simply errors under this stub — its search box still renders.
    vi.stubGlobal('fetch', lawFetch({ manifest: 'missing' }));
    renderWithProviders(<FerramentasPage />, ['/ferramentas']);

    // Default: the CAE explorer search is present (keeps the /cae smoke flow intact).
    expect(screen.getByLabelText('Procurar no catálogo CAE')).toBeTruthy();

    // Legislação opens the full-text corpus reader (its default sub-view), not the CAE search.
    fireEvent.click(screen.getByRole('button', { name: 'Legislação' }));
    expect(screen.getByLabelText('Pesquisar em toda a legislação')).toBeTruthy();
    expect(screen.queryByLabelText('Procurar no catálogo CAE')).toBeNull();

    // The curated shelf is one sub-tab away — a known theme heading then appears.
    fireEvent.click(screen.getByRole('button', { name: 'Prateleira curada' }));
    expect(screen.getByRole('heading', { name: 'Assinaturas e confiança' })).toBeTruthy();
  });
});

describe('Legislação — corpus reader (full text, t55-E3)', () => {
  // Two diplomas: a fully-verified EU regulation and an all-pending code, so the reader must
  // badge Verified vs Pending distinctly and never present the pending body as authoritative.
  const CORPUS: LawCorpusView = {
    schema_version: 1,
    generated_at: '2026-07-08T00:00:00Z',
    source_note: 'Corpus de teste.',
    digest: 'a'.repeat(64),
    origin: 'Embedded',
    counts: { diplomas: 2, articles: 3, verified: 1, pending: 2 },
    diplomas: [
      {
        id: 'eidas-910-2014',
        kind: 'RegulamentoUe',
        number: '910/2014',
        title: 'Regulamento eIDAS',
        ref: 'Regulamento (UE) n.º 910/2014, de 23 de julho',
        official_url: 'https://eur-lex.europa.eu/eli/reg/2014/910/oj',
        eli: 'https://eur-lex.europa.eu/eli/reg/2014/910/oj',
        article_count: 1,
        verified_count: 1,
        pending_count: 0,
      },
      {
        id: 'csc',
        kind: 'Codigo',
        number: '262/86',
        title: 'Código das Sociedades Comerciais',
        ref: 'Decreto-Lei n.º 262/86, de 2 de setembro',
        official_url: 'https://diariodarepublica.pt/x',
        article_count: 2,
        verified_count: 0,
        pending_count: 2,
      },
    ],
  };

  const EIDAS_DETAIL: LawDiplomaDetailView = {
    ...CORPUS.diplomas[0],
    articles: [
      {
        diploma_id: 'eidas-910-2014',
        number: '25',
        label: 'Artigo 25.º',
        heading: 'Efeitos legais das assinaturas eletrónicas',
        body: 'A assinatura eletrónica qualificada tem um efeito legal equivalente ao de uma assinatura manuscrita.',
        verification: 'Verified',
        verified: true,
        source: {
          diploma: 'Regulamento (UE) n.º 910/2014, de 23 de julho',
          article: 'Artigo 25.º',
          dr_reference: 'JO L 257 de 28.8.2014, p. 73',
          dr_date: '2014-08-28',
          url: 'https://eur-lex.europa.eu/legal-content/PT/TXT/HTML/?uri=CELEX:32014R0910',
          source_digest: 'b'.repeat(64),
          retrieved_at: '2026-07-08T00:00:00Z',
          complete: true,
        },
      },
    ],
  };

  const CSC_DETAIL: LawDiplomaDetailView = {
    ...CORPUS.diplomas[1],
    articles: [
      {
        diploma_id: 'csc',
        number: '63',
        label: 'Artigo 63.º',
        heading: 'Ata',
        body: '[NÃO VERIFICADO / fonte pendente]',
        verification: 'Pending',
        verified: false,
        source: {
          diploma: 'Decreto-Lei n.º 262/86, de 2 de setembro',
          article: 'Artigo 63.º',
          complete: false,
        },
      },
      {
        diploma_id: 'csc',
        number: '255',
        label: 'Artigo 255.º',
        heading: 'Remuneração dos gerentes',
        body: '[NÃO VERIFICADO / fonte pendente]',
        verification: 'Pending',
        verified: false,
        source: {
          diploma: 'Decreto-Lei n.º 262/86, de 2 de setembro',
          article: 'Artigo 255.º',
          complete: false,
        },
      },
    ],
  };

  const SEARCH: LawSearchView = {
    query: 'assinatura',
    count: 2,
    results: [
      {
        diploma_id: 'eidas-910-2014',
        diploma_title: 'Regulamento eIDAS',
        number: '25',
        label: 'Artigo 25.º',
        heading: 'Efeitos legais das assinaturas eletrónicas',
        snippet: '…a assinatura eletrónica qualificada tem um efeito legal equivalente…',
        verification: 'Verified',
        verified: true,
      },
      {
        diploma_id: 'csc',
        diploma_title: 'Código das Sociedades Comerciais',
        number: '255',
        label: 'Artigo 255.º',
        heading: 'Remuneração dos gerentes',
        snippet: 'Remuneração dos gerentes',
        verification: 'Pending',
        verified: false,
      },
    ],
  };

  const EIDAS_CITATION: LawCitationReport = {
    legal_notice:
      'Referências informativas para apoio à redação/conformidade; não substituem a publicação oficial nem revisão jurídica.',
    count: 1,
    citations: [
      {
        source_id: 'eidas-910-2014',
        source_label: 'Regulamento eIDAS',
        article: '25',
        article_label: 'Artigo 25.º',
        citation: 'Regulamento (UE) n.º 910/2014, de 23 de julho, Artigo 25.º',
        verification: 'Verified',
        source_url: 'https://eur-lex.europa.eu/legal-content/PT/TXT/HTML/?uri=CELEX:32014R0910',
        source_complete: true,
        dr_reference: 'JO L 257 de 28.8.2014, p. 73',
      },
    ],
  };

  const CSC_CITATION: LawCitationReport = {
    legal_notice:
      'Referências informativas para apoio à redação/conformidade; não substituem a publicação oficial nem revisão jurídica.',
    count: 1,
    citations: [
      {
        source_id: 'csc',
        source_label: 'Código das Sociedades Comerciais',
        article: '63',
        article_label: 'Artigo 63.º',
        citation: 'Decreto-Lei n.º 262/86, de 2 de setembro, Artigo 63.º',
        verification: 'Pending',
        source_url: null,
        source_complete: false,
      },
    ],
  };

  /** A fetch stub for the corpus endpoints (search / diploma detail / corpus list), in order. */
  function corpusFetch(): typeof fetch {
    return vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.includes('/v1/law/citations/resolve') && init?.method === 'POST') {
        const body = JSON.parse(String(init.body ?? '{}')) as {
          references?: { diploma_id: string; article: string }[];
        };
        const first = body.references?.[0];
        return Promise.resolve(json(first?.diploma_id === 'csc' ? CSC_CITATION : EIDAS_CITATION));
      }
      if (url.includes('/v1/law/corpus/search')) return Promise.resolve(json(SEARCH));
      if (url.includes('/v1/law/corpus/eidas-910-2014')) return Promise.resolve(json(EIDAS_DETAIL));
      if (url.includes('/v1/law/corpus/csc')) return Promise.resolve(json(CSC_DETAIL));
      if (url.includes('/v1/law/corpus')) return Promise.resolve(json(CORPUS));
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as unknown as typeof fetch;
  }

  it('browses diplomas with counts and Verified vs Pending authenticity badges', async () => {
    vi.stubGlobal('fetch', corpusFetch());
    renderWithProviders(<CorpusReader />);

    // The origem/autenticidade caveat discloses the corpus provenance/integrity.
    expect(await screen.findByText('Origem e autenticidade')).toBeTruthy();
    expect(screen.getByText(/gerado em 2026-07-08/)).toBeTruthy();

    // Both diplomas are listed; the fully-verified one badges Verified, the pending one Pending —
    // and the two badges carry visually-distinct tone classes.
    const eidas = screen.getByText('Regulamento eIDAS').closest('button') as HTMLElement;
    const csc = screen
      .getByText('Código das Sociedades Comerciais')
      .closest('button') as HTMLElement;
    expect(within(eidas).getByText('Verificado').className).toContain('badge--ok');
    expect(within(csc).getByText('Por verificar').className).toContain('badge--warn');
    expect(csc.className).toContain('leg-corpus__diploma');
    expect(csc.getAttribute('aria-label')).toBe('Abrir Código das Sociedades Comerciais');
  });

  it('opens a diploma and never presents a Pending article body as law', async () => {
    vi.stubGlobal('fetch', corpusFetch());
    renderWithProviders(<CorpusReader />);

    fireEvent.click(
      await screen.findByRole('button', { name: 'Abrir Código das Sociedades Comerciais' }),
    );

    // The pending article renders the loud unverified marker inside an explicit warning — never
    // an un-sourced body dressed up as statute.
    expect((await screen.findAllByText('Texto por verificar')).length).toBeGreaterThan(0);
    expect(screen.getAllByText('[NÃO VERIFICADO / fonte pendente]').length).toBeGreaterThan(0);
    expect(screen.getByRole('button', { name: 'Abrir Artigo 63.º — Ata' }).className).toContain(
      'leg-corpus__article-title',
    );
  });

  it('shows an article view with its full verbatim text and citation (deep-linked)', async () => {
    vi.stubGlobal('fetch', corpusFetch());
    renderWithProviders(<CorpusReader />, ['/?diploma=eidas-910-2014&artigo=25']);

    // The full verbatim body + the citation (source + official publication link) are shown.
    expect(
      await screen.findByText(/efeito legal equivalente ao de uma assinatura manuscrita/),
    ).toBeTruthy();
    expect(screen.getByText('Fonte')).toBeTruthy();
    const official = screen.getByRole('link', {
      name: 'https://eur-lex.europa.eu/legal-content/PT/TXT/HTML/?uri=CELEX:32014R0910',
    });
    expect(official).toBeTruthy();
  });

  it('full-text search ranks hits with the snippet + badge, and a hit opens the article', async () => {
    vi.stubGlobal('fetch', corpusFetch());
    renderWithProviders(<CorpusReader />);

    fireEvent.change(await screen.findByLabelText('Pesquisar em toda a legislação'), {
      target: { value: 'assinatura' },
    });

    // Ranked hits appear with the matched context snippet and the count.
    expect(await screen.findByText(/efeito legal equivalente/)).toBeTruthy();
    expect(screen.getByText('2 resultados')).toBeTruthy();
    // A Verified and a Pending hit are both badged.
    expect(screen.getAllByText('Verificado').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Por verificar').length).toBeGreaterThan(0);

    // Clicking the verified hit opens that article's full text.
    const hit = screen.getByRole('button', {
      name: 'Abrir Artigo 25.º — Efeitos legais das assinaturas eletrónicas',
    });
    expect(hit.className).toContain('leg-corpus__hit');
    fireEvent.click(hit);
    expect(
      await screen.findByText(/efeito legal equivalente ao de uma assinatura manuscrita/),
    ).toBeTruthy();
  });

  it('pins a verified article citation and copies a draft-ready citation block', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
    vi.stubGlobal('fetch', corpusFetch());
    renderWithProviders(<CorpusReader />, ['/?diploma=eidas-910-2014&artigo=25']);

    fireEvent.click(await screen.findByRole('button', { name: 'Fixar citação' }));
    expect(
      await screen.findByText('Regulamento (UE) n.º 910/2014, de 23 de julho, Artigo 25.º'),
    ).toBeTruthy();
    expect(screen.getAllByText('Verificado').length).toBeGreaterThan(0);

    fireEvent.click(screen.getByRole('button', { name: 'Copiar para minuta' }));
    await waitFor(() => expect(writeText).toHaveBeenCalled());
    const copied = String(writeText.mock.calls[0][0]);
    expect(copied).toContain('não substituem a publicação oficial');
    expect(copied).toContain('[Verificado]');
    expect(copied).toContain('https://eur-lex.europa.eu/legal-content/PT/TXT/HTML/');
  });

  it('pins a pending DRE article without presenting it as verified', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
    vi.stubGlobal('fetch', corpusFetch());
    renderWithProviders(<CorpusReader />, ['/?diploma=csc&artigo=63']);

    fireEvent.click(await screen.findByRole('button', { name: 'Fixar citação' }));
    expect(
      await screen.findByText('Decreto-Lei n.º 262/86, de 2 de setembro, Artigo 63.º'),
    ).toBeTruthy();
    expect(screen.getAllByText('Por verificar').length).toBeGreaterThan(0);
    expect(screen.getByText('Fonte pendente; não usar como verificada.')).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: 'Copiar para minuta' }));
    await waitFor(() => expect(writeText).toHaveBeenCalled());
    const copied = String(writeText.mock.calls[0][0]);
    expect(copied).toContain('[Por verificar - fonte pendente]');
    expect(copied).not.toContain('[Verificado]');
  });
});
