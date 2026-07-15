import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { TemplatesCatalogPage } from './TemplatesCatalogPage';
import { fetchTable, renderWithProviders } from '../../test/utils';
import type { TemplateSummary } from '../../api/types';

interface RecordedRequest {
  url: string;
  method: string;
  body?: BodyInit | null;
}

const USER_TEMPLATE: TemplateSummary = {
  id: 'user-encosto-ata/v1',
  family: 'CommercialCompany',
  stage: 'Ata',
  channels: ['Physical'],
  signature_policy: 'QualifiedPreferred',
  rule_pack_id: 'csc-art63/v2',
  law_references: [],
  locale: 'pt-PT',
  editable: true,
  source: 'user',
};

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(status === 204 ? null : JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

/**
 * A method-aware fetch stub over the template endpoints. `handle` may answer a specific
 * (url, method) pair; any GET on the collection falls back to `catalog`.
 */
function templatesFetch(
  catalog: TemplateSummary[],
  handle?: (url: string, method: string) => Response | null,
) {
  const calls: RecordedRequest[] = [];
  const fn = ((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const method = (init?.method ?? 'GET').toUpperCase();
    calls.push({ url, method, body: init?.body });
    const custom = handle?.(url, method);
    if (custom) return Promise.resolve(custom);
    if (url.includes('/v1/templates') && method === 'GET') {
      return Promise.resolve(jsonResponse(catalog));
    }
    return Promise.reject(new Error(`no stub for ${method} ${url}`));
  }) as typeof fetch;
  return { fn, calls };
}

function jsonFile(content: string, name = 'modelo.json'): File {
  const file = new File([content], name, { type: 'application/json' });
  // jsdom's File does not implement async body readers; the dialog reads via `file.text()`.
  Object.defineProperty(file, 'text', { value: () => Promise.resolve(content) });
  return file;
}

const CATALOG: TemplateSummary[] = [
  {
    id: 'csc-ata-ag/v1',
    family: 'CommercialCompany',
    stage: 'Ata',
    channels: ['Physical', 'Hybrid', 'Telematic', 'WrittenResolution'],
    signature_policy: 'QualifiedPreferred',
    rule_pack_id: 'csc-art63/v2',
    law_references: [],
    locale: 'pt-PT',
    editable: false,
    source: 'builtin',
  },
  {
    id: 'csc-certidao-ata/v1',
    family: 'CommercialCompany',
    stage: 'Certidao',
    channels: [],
    signature_policy: 'QualifiedPreferred',
    rule_pack_id: 'csc-art63/v2',
    law_references: [],
    locale: 'pt-PT',
    editable: false,
    source: 'builtin',
  },
  {
    id: 'assoc-convocatoria-ga/v1',
    family: 'Association',
    stage: 'Convocatoria',
    channels: [],
    signature_policy: 'ManualAttested',
    rule_pack_id: 'assoc-cc/v1',
    law_references: [
      {
        source_id: 'cc',
        source_label: 'Código Civil',
        article: '175',
        citation: 'CC arts. 173.º e 175.º',
        source: 'ThresholdRegistry',
        verification: 'Pending',
        threshold_id: 'assoc.convocatoria_maioria',
      },
    ],
    locale: 'pt-PT',
    editable: false,
    source: 'builtin',
  },
  {
    id: 'condominio-lista-presencas/v1',
    family: 'Condominium',
    stage: 'Reuniao',
    channels: ['Physical', 'Hybrid', 'Telematic'],
    signature_policy: 'QualifiedOrHandwritten',
    rule_pack_id: 'condominio-dl268/v1',
    law_references: [],
    locale: 'pt-PT',
    editable: false,
    source: 'builtin',
  },
];

const EDGE_CATALOG: TemplateSummary[] = [
  {
    id: 'assoc-convocatoria-ga/pt',
    family: 'Association',
    stage: 'Convocatoria',
    channels: ['Physical'],
    signature_policy: 'ManualAttested',
    rule_pack_id: 'assoc-cc/v1',
    law_references: [],
    locale: 'pt-PT',
    editable: false,
    source: 'builtin',
  },
  {
    id: 'assoc-convocatoria-ga/en',
    family: 'Association',
    stage: 'Convocatoria',
    channels: ['Telematic'],
    signature_policy: 'ManualAttested',
    rule_pack_id: 'assoc-cc/v1',
    law_references: [],
    locale: 'en-US',
    editable: false,
    source: 'builtin',
  },
  {
    id: 'fundacao-reuniao/v1',
    family: 'Foundation',
    stage: 'Reuniao',
    channels: ['Hybrid'],
    signature_policy: 'ManualAttested',
    rule_pack_id: 'fundacao-cc/v1',
    law_references: [],
    locale: 'pt-PT',
    editable: false,
    source: 'builtin',
  },
];

async function themeCss(): Promise<string> {
  const nodeFs = 'node:fs';
  const { readFileSync } = (await import(nodeFs)) as {
    readFileSync(path: string, encoding: 'utf8'): string;
  };
  return readFileSync('src/theme.css', 'utf8');
}

function expectCssRule(css: string, selector: RegExp, declarations: string[]) {
  const match = css.match(selector);
  expect(match?.[1]).toBeTruthy();
  const body = match?.[1] ?? '';
  for (const declaration of declarations) {
    expect(body).toContain(declaration);
  }
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('TemplatesCatalogPage', () => {
  it('browses the existing template catalog and points generation back to acts', async () => {
    vi.stubGlobal('fetch', fetchTable([{ match: '/v1/templates', body: CATALOG }]));

    const { container } = renderWithProviders(<TemplatesCatalogPage />, ['/minutas']);

    const filters = screen.getByRole('search', { name: 'Pesquisar e filtrar' });
    expect(filters.classList.contains('templates-filters')).toBe(true);
    const primary = filters.querySelector('.templates-filterbar__primary') as HTMLElement;
    expect(primary).toBeTruthy();
    expect(primary.querySelectorAll('.field')).toHaveLength(3);
    expect(within(primary).getByLabelText('Pesquisa')).toBeTruthy();
    expect(within(primary).getByLabelText('Família da entidade')).toBeTruthy();
    expect(within(primary).getByLabelText('Fase da minuta')).toBeTruthy();
    const advanced = container.querySelector(
      'details.templates-advanced-filters.filter-advanced',
    ) as HTMLDetailsElement;
    expect(advanced).toBeTruthy();
    expect(advanced.open).toBe(false);
    const advancedBody = advanced.querySelector(
      '.templates-advanced-filters__body.filter-advanced__body',
    );
    expect(advancedBody).toBeTruthy();
    expect(advancedBody?.querySelectorAll('.field')).toHaveLength(4);
    const clearFilters = within(filters).getByRole('button', {
      name: 'Limpar pesquisa e filtros',
    }) as HTMLButtonElement;
    expect(clearFilters.disabled).toBe(true);
    expect(clearFilters.className).toContain('btn--iconOnly');
    expect(clearFilters.textContent?.trim()).toBe('');
    expect(
      document.getElementById(clearFilters.getAttribute('aria-describedby') ?? '')?.textContent,
    ).toBe('Limpar pesquisa e filtros');

    fireEvent.click(within(advanced).getByText('Filtros avançados'));
    expect(advanced.open).toBe(true);
    expect(within(advanced).getByLabelText('Idioma do modelo')).toBeTruthy();
    expect(within(advanced).getByLabelText('Canal do modelo')).toBeTruthy();
    expect(within(advanced).getByLabelText('Política de assinatura')).toBeTruthy();
    expect(within(advanced).getByLabelText('Pacote de regras')).toBeTruthy();

    const ataId = await screen.findByText('csc-ata-ag/v1');
    const ataCard = ataId.closest('article');
    expect(ataCard).toBeTruthy();
    expect(
      within(ataCard as HTMLElement).getByText('Assinatura qualificada preferencial'),
    ).toBeTruthy();
    expect(within(ataCard as HTMLElement).getByText('csc-art63/v2')).toBeTruthy();
    expect(within(ataCard as HTMLElement).getByText('Deliberação por escrito')).toBeTruthy();
    expect(screen.getByText('4 de 4 modelos')).toBeTruthy();
    expect(screen.getAllByRole('link', { name: 'Escolher ata' })[0].getAttribute('href')).toBe(
      '/livros',
    );
    expect(screen.queryByRole('button', { name: /gerar/i })).toBeNull();

    fireEvent.change(screen.getByLabelText('Pesquisa'), {
      target: { value: ' CERTIDÃO ' },
    });
    expect(clearFilters.disabled).toBe(false);
    expect(await screen.findByText('csc-certidao-ata/v1')).toBeTruthy();
    expect(screen.queryByText('csc-ata-ag/v1')).toBeNull();
    expect(screen.getByText('1 de 4 modelos')).toBeTruthy();
    expect(screen.getByText('Sem canal específico')).toBeTruthy();

    fireEvent.click(clearFilters);
    expect(await screen.findByText('csc-ata-ag/v1')).toBeTruthy();
    expect(clearFilters.disabled).toBe(true);

    fireEvent.change(screen.getByLabelText('Canal do modelo'), {
      target: { value: 'Telematic' },
    });
    expect(screen.getByText('2 de 4 modelos')).toBeTruthy();
    expect(screen.getByText('csc-ata-ag/v1')).toBeTruthy();
    expect(screen.getByText('condominio-lista-presencas/v1')).toBeTruthy();

    fireEvent.change(screen.getByLabelText('Política de assinatura'), {
      target: { value: 'QualifiedOrHandwritten' },
    });
    expect(screen.getByText('1 de 4 modelos')).toBeTruthy();
    const condoCard = screen.getByText('condominio-lista-presencas/v1').closest('article');
    expect(condoCard).toBeTruthy();
    expect(within(condoCard as HTMLElement).getByText('Qualificada ou manuscrita')).toBeTruthy();

    fireEvent.click(clearFilters);
    expect(await screen.findByText('csc-ata-ag/v1')).toBeTruthy();

    fireEvent.change(screen.getByLabelText('Família da entidade'), {
      target: { value: 'Association' },
    });
    const associationCard = await screen.findByText('assoc-convocatoria-ga/v1');
    expect(associationCard).toBeTruthy();
    expect(screen.queryByText('condominio-lista-presencas/v1')).toBeNull();

    fireEvent.change(screen.getByLabelText('Fase da minuta'), {
      target: { value: 'Convocatoria' },
    });
    const catalog = screen.getByRole('region', { name: 'Catálogo de minutas' });
    expect(within(catalog).getByText('assoc-convocatoria-ga/v1')).toBeTruthy();
    expect(within(catalog).getByText('Convocatória')).toBeTruthy();
  });

  it('combines folded search, locale filters, empty state and clear without stale results', async () => {
    vi.stubGlobal('fetch', fetchTable([{ match: '/v1/templates', body: EDGE_CATALOG }]));

    const { container } = renderWithProviders(<TemplatesCatalogPage />, ['/minutas']);
    const advanced = container.querySelector(
      'details.templates-advanced-filters',
    ) as HTMLDetailsElement;

    expect(await screen.findByText('assoc-convocatoria-ga/pt')).toBeTruthy();
    expect(advanced.open).toBe(false);
    fireEvent.click(within(advanced).getByText('Filtros avançados'));
    expect(advanced.open).toBe(true);

    fireEvent.change(screen.getByLabelText('Pesquisa'), {
      target: { value: 'CONVOCATÓRIA' },
    });
    expect(screen.getByText('2 de 3 modelos')).toBeTruthy();
    expect(screen.getByText('assoc-convocatoria-ga/pt')).toBeTruthy();
    expect(screen.getByText('assoc-convocatoria-ga/en')).toBeTruthy();
    expect(screen.queryByText('fundacao-reuniao/v1')).toBeNull();

    fireEvent.change(screen.getByLabelText('Pacote de regras'), {
      target: { value: 'assoc-cc/v1' },
    });
    expect(screen.getByText('2 de 3 modelos')).toBeTruthy();
    expect(screen.queryByText('fundacao-reuniao/v1')).toBeNull();

    fireEvent.change(screen.getByLabelText('Idioma do modelo'), { target: { value: 'en-US' } });
    expect(screen.getByText('1 de 3 modelos')).toBeTruthy();
    expect(screen.getByText('assoc-convocatoria-ga/en')).toBeTruthy();
    expect(screen.queryByText('assoc-convocatoria-ga/pt')).toBeNull();

    fireEvent.change(screen.getByLabelText('Pesquisa'), {
      target: { value: 'sem resultado' },
    });
    expect(await screen.findByText('Sem modelos encontrados')).toBeTruthy();
    expect(screen.getByText('0 de 3 modelos')).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: 'Limpar pesquisa e filtros' }));
    expect(await screen.findByText('fundacao-reuniao/v1')).toBeTruthy();
    expect(screen.getByText('3 de 3 modelos')).toBeTruthy();
  });

  it('keeps templates filters compact, collapsible, and overflow-safe in CSS', async () => {
    const css = await themeCss();

    expectCssRule(css, /\.templates-filters\s*\{([^}]*)\}/, [
      'min-width: 0;',
      'max-width: 100%;',
      'overflow-x: clip;',
    ]);
    expectCssRule(css, /\.templates-filterbar\s*\{([^}]*)\}/, [
      'max-width: 100%;',
      'overflow-x: clip;',
    ]);
    expectCssRule(css, /\.templates-controls__primary\s*\{([^}]*)\}/, [
      'display: flex;',
      'flex-wrap: wrap;',
      'max-width: 100%;',
    ]);
    expectCssRule(css, /\.templates-controls__search\s*\{([^}]*)\}/, [
      'min-width: min(100%, 16rem);',
      'max-width: 100%;',
    ]);
    expectCssRule(css, /\.templates-controls__primary > \.field\s*\{([^}]*)\}/, [
      'min-width: min(100%, 11rem);',
      'max-width: 100%;',
    ]);
    expectCssRule(css, /\.templates-controls__advanced\s*\{([^}]*)\}/, [
      'max-width: 100%;',
      'overflow-x: clip;',
    ]);
    expectCssRule(css, /\.templates-controls__filters\s*\{([^}]*)\}/, [
      'display: grid;',
      'grid-template-columns: repeat(auto-fit, minmax(min(100%, 12rem), 1fr));',
      'min-width: 0;',
      'max-width: 100%;',
    ]);
    expectCssRule(css, /\.templates-controls__actions \.btn\s*\{([^}]*)\}/, [
      'max-width: 100%;',
      'overflow: hidden;',
      'white-space: nowrap;',
    ]);
  });

  it('renders pending law references and searches by citation or article text', async () => {
    vi.stubGlobal('fetch', fetchTable([{ match: '/v1/templates', body: CATALOG }]));

    renderWithProviders(<TemplatesCatalogPage />, ['/minutas']);

    const associationId = await screen.findByText('assoc-convocatoria-ga/v1');
    const associationCard = associationId.closest('article');
    expect(associationCard).toBeTruthy();
    expect(within(associationCard as HTMLElement).getByText('Fonte legal')).toBeTruthy();
    expect(within(associationCard as HTMLElement).getByText('Por verificar')).toBeTruthy();
    expect(within(associationCard as HTMLElement).getByText('CC arts. 173.º e 175.º')).toBeTruthy();
    expect(
      within(associationCard as HTMLElement).getByText('Fonte: Código Civil · art. 175'),
    ).toBeTruthy();
    expect(
      within(associationCard as HTMLElement).getByText('Fonte pendente; não usar como verificada.'),
    ).toBeTruthy();

    fireEvent.change(screen.getByLabelText('Pesquisa'), {
      target: { value: '175' },
    });
    expect(screen.getByText('1 de 4 modelos')).toBeTruthy();
    expect(screen.getByText('assoc-convocatoria-ga/v1')).toBeTruthy();
    expect(screen.queryByText('csc-ata-ag/v1')).toBeNull();

    fireEvent.change(screen.getByLabelText('Pesquisa'), {
      target: { value: 'CC ARTS. 173' },
    });
    expect(screen.getByText('1 de 4 modelos')).toBeTruthy();
    expect(screen.getByText('assoc-convocatoria-ga/v1')).toBeTruthy();
  });

  it('shows management actions on user templates and keeps built-ins read-only', async () => {
    const { fn } = templatesFetch([CATALOG[0], USER_TEMPLATE]);
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<TemplatesCatalogPage />, ['/minutas']);

    expect(screen.getByRole('button', { name: 'Novo modelo' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Importar' })).toBeTruthy();

    const userCard = (await screen.findByText('user-encosto-ata/v1')).closest(
      'article',
    ) as HTMLElement;
    expect(within(userCard).getByText('Criado pelo utilizador')).toBeTruthy();
    expect(within(userCard).getByRole('button', { name: 'Editar' })).toBeTruthy();
    expect(within(userCard).getByRole('button', { name: 'Exportar' })).toBeTruthy();
    expect(within(userCard).getByRole('button', { name: 'Eliminar' })).toBeTruthy();

    const builtinCard = screen.getByText('csc-ata-ag/v1').closest('article') as HTMLElement;
    expect(within(builtinCard).getByText('Incluído (só leitura)')).toBeTruthy();
    expect(within(builtinCard).queryByRole('button', { name: 'Editar' })).toBeNull();
    expect(within(builtinCard).queryByRole('button', { name: 'Eliminar' })).toBeNull();
  });

  it('creates a user template through the editor form', async () => {
    const { fn, calls } = templatesFetch([CATALOG[0]], (url, method) =>
      url.endsWith('/v1/templates') && method === 'POST' ? jsonResponse(USER_TEMPLATE, 201) : null,
    );
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<TemplatesCatalogPage />, ['/minutas']);

    fireEvent.click(screen.getByRole('button', { name: 'Novo modelo' }));
    const dialog = await screen.findByRole('dialog', { name: 'Novo modelo' });

    fireEvent.change(within(dialog).getByLabelText('Identificador'), {
      target: { value: 'user-encosto-ata/v1' },
    });
    fireEvent.change(within(dialog).getByLabelText('Pacote de regras'), {
      target: { value: 'csc-art63/v2' },
    });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Guardar' }));

    await waitFor(() =>
      expect(
        calls.some((c) => c.method === 'POST' && c.url.endsWith('/v1/templates')),
      ).toBe(true),
    );
    const post = calls.find((c) => c.method === 'POST' && c.url.endsWith('/v1/templates'));
    expect(String(post?.body)).toContain('user-encosto-ata/v1');
    await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Novo modelo' })).toBeNull());
  });

  it('blocks an invalid import in the dry-run preflight', async () => {
    const { fn, calls } = templatesFetch([CATALOG[0]], (url, method) =>
      url.includes('/v1/templates/import') && method === 'POST'
        ? jsonResponse({ ok: false, error: { code: 'no_blocks', message: 'sem blocos' } })
        : null,
    );
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<TemplatesCatalogPage />, ['/minutas']);

    fireEvent.click(screen.getByRole('button', { name: 'Importar' }));
    const dialog = await screen.findByRole('dialog', { name: 'Importar modelo' });

    const fileInput = dialog.querySelector('input[type="file"]') as HTMLInputElement;
    fireEvent.change(fileInput, { target: { files: [jsonFile('{"id":"user-x/v1"}')] } });

    expect(
      await within(dialog).findByText('O modelo tem de conter pelo menos um bloco.'),
    ).toBeTruthy();
    const confirm = within(dialog).getByRole('button', {
      name: 'Confirmar importação',
    }) as HTMLButtonElement;
    expect(confirm.disabled).toBe(true);
    expect(
      calls.some((c) => c.method === 'POST' && c.url.includes('dry_run=true')),
    ).toBe(true);
  });

  it('deletes a user template through the confirm dialog', async () => {
    const { fn, calls } = templatesFetch([CATALOG[0], USER_TEMPLATE], (url, method) =>
      url.includes('/v1/templates/') && method === 'DELETE' ? jsonResponse(null, 204) : null,
    );
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<TemplatesCatalogPage />, ['/minutas']);

    const userCard = (await screen.findByText('user-encosto-ata/v1')).closest(
      'article',
    ) as HTMLElement;
    fireEvent.click(within(userCard).getByRole('button', { name: 'Eliminar' }));

    const dialog = await screen.findByRole('dialog');
    expect(
      within(dialog).getByText('Eliminar o modelo «user-encosto-ata/v1»? Esta ação não pode ser anulada.'),
    ).toBeTruthy();
    fireEvent.click(within(dialog).getByRole('button', { name: 'Eliminar' }));

    await waitFor(() =>
      expect(calls.some((c) => c.method === 'DELETE' && c.url.includes('/v1/templates/'))).toBe(
        true,
      ),
    );
  });
});
