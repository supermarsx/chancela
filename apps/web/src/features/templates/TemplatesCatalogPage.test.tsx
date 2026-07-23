import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { TemplatesCatalogPage } from './TemplatesCatalogPage';
import { useLocation } from 'react-router-dom';
import { fetchTable, renderWithProviders } from '../../test/utils';
import type { TemplateSummary } from '../../api/types';

/** Reports the router's current path, so a navigation can be asserted under the memory router. */
function LocationPathname() {
  return <>{useLocation().pathname}</>;
}

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

/** The catalog table's body rows, in render order. */
function catalogRows(): HTMLTableRowElement[] {
  return Array.from(document.querySelectorAll<HTMLTableRowElement>('.templates-table tbody tr'));
}

/** The leading label of each row: the document name, or the id when the catalog names none. */
function rowNames(): string[] {
  return catalogRows().map(
    (row) =>
      row.querySelector('.templates-table__name')?.textContent ??
      row.querySelector('.templates-table__id')?.textContent ??
      '',
  );
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  // The column set is persisted per device; a test that toggles it must not leak into the next.
  window.localStorage.clear();
});

/** Open the column-visibility disclosure and return it. */
function openColumns(): HTMLDetailsElement {
  const columns = document.querySelector('details.templates-columns') as HTMLDetailsElement;
  fireEvent.click(columns.querySelector('summary') as HTMLElement);
  return columns;
}

/**
 * A stateful preferences-aware fetch over a `fetchTable` base (t37): the per-user column store
 * `GET|PUT /v1/me/preferences` is answered in-memory so a column toggle round-trips and a remount
 * reads the persisted choice back, exactly as the server does. Every other URL delegates to the
 * base table. The column set now lives in the account, not `localStorage`.
 */
function fetchWithPreferences(
  entries: { match: string; status?: number; body: unknown }[],
): typeof fetch {
  const base = fetchTable(entries);
  let stored: unknown = { table_columns: {} };
  return ((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    if (url.includes('/v1/me/preferences')) {
      if ((init?.method ?? 'GET').toUpperCase() === 'PUT') {
        stored = JSON.parse(String(init?.body ?? '{}'));
      }
      return Promise.resolve(
        new Response(JSON.stringify(stored), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      );
    }
    return base(input, init);
  }) as typeof fetch;
}

describe('TemplatesCatalogPage', () => {
  it('leads each row with the document name and keeps the versioned id searchable', async () => {
    vi.stubGlobal(
      'fetch',
      fetchTable([{ match: '/v1/templates', body: [...CATALOG, USER_TEMPLATE] }]),
    );

    renderWithProviders(<TemplatesCatalogPage />, ['/templates']);

    expect(await screen.findByText('Ata de assembleia geral')).toBeTruthy();
    expect(screen.getByText('Certidão de ata')).toBeTruthy();
    // The `/vN` is provenance, so it is demoted to a secondary line rather than dropped.
    expect(screen.getByText('csc-ata-ag/v1')).toBeTruthy();
    // A user-authored template the catalog cannot name keeps the id as its only label.
    const userRow = screen.getByText('user-encosto-ata/v1').closest('tr') as HTMLElement;
    expect(userRow.querySelector('.templates-table__name')).toBeNull();

    // Searching by the readable name now finds the row.
    fireEvent.change(screen.getByLabelText('Pesquisa'), {
      target: { value: 'certidão' },
    });
    await waitFor(() => expect(catalogRows()).toHaveLength(1));
    expect(screen.getByText('Certidão de ata')).toBeTruthy();
  });

  it('renders the catalog as a named, sortable table over the operator column set', async () => {
    vi.stubGlobal(
      'fetch',
      fetchWithPreferences([{ match: '/v1/templates', body: [...CATALOG, USER_TEMPLATE] }]),
    );

    renderWithProviders(<TemplatesCatalogPage />, ['/templates']);

    const table = await screen.findByRole('table', { name: 'Catálogo de minutas' });
    const headers = within(table).getAllByRole('columnheader');
    // Eight by default: "Fonte legal" is hidden until the operator asks for it.
    expect(headers.map((header) => header.getAttribute('scope'))).toEqual(Array(8).fill('col'));
    expect(headers.map((header) => header.textContent?.trim())).toEqual([
      'Modelo',
      'Família',
      'Fase',
      'Canais',
      'Assinatura',
      'Pacote de regras',
      'Origem',
      'Ações',
    ]);
    expect(catalogRows()).toHaveLength(5);

    // Every row carries the full metadata the cards used to spread over a <dl>.
    const ataRow = screen.getByText('csc-ata-ag/v1').closest('tr') as HTMLElement;
    expect(within(ataRow).getByText('Ata de assembleia geral')).toBeTruthy();
    expect(within(ataRow).getByText('Sociedade comercial')).toBeTruthy();
    expect(within(ataRow).getByText('Assinatura qualificada preferencial')).toBeTruthy();
    expect(within(ataRow).getByText('csc-art63/v2')).toBeTruthy();
    expect(within(ataRow).getByText('Deliberação por escrito')).toBeTruthy();
    expect(within(ataRow).getByText('Incluído (só leitura)')).toBeTruthy();
    expect(within(ataRow).getByText('pt-PT')).toBeTruthy();

    // Sorting: unsorted by default, then ascending, then descending on a second click.
    const nameHeader = headers[0];
    expect(nameHeader.getAttribute('aria-sort')).toBe('none');
    fireEvent.click(within(nameHeader).getByRole('button', { name: 'Modelo' }));
    expect(nameHeader.getAttribute('aria-sort')).toBe('ascending');
    expect(rowNames()[0]).toBe('Ata de assembleia geral');
    fireEvent.click(within(nameHeader).getByRole('button', { name: 'Modelo' }));
    expect(nameHeader.getAttribute('aria-sort')).toBe('descending');
    expect(rowNames()[0]).toBe('user-encosto-ata/v1');

    // Sorting another column releases the first one.
    const familyHeader = headers[1];
    fireEvent.click(within(familyHeader).getByRole('button', { name: 'Família' }));
    expect(nameHeader.getAttribute('aria-sort')).toBe('none');
    expect(familyHeader.getAttribute('aria-sort')).toBe('ascending');
    expect(rowNames()[0]).toBe('Convocatória — Assembleia Geral');

    // Hiding the sorted column releases the sort rather than leaving the rows ordered by
    // something the reader can no longer see.
    const columns = openColumns();
    fireEvent.click(within(columns).getByLabelText('Família'));
    // The toggle now persists to the account, so the header drops after the write settles.
    await waitFor(() => {
      const headersNow = within(
        screen.getByRole('table', { name: 'Catálogo de minutas' }),
      ).getAllByRole('columnheader');
      expect(headersNow.map((header) => header.textContent?.trim())).not.toContain('Família');
    });
    const afterHide = within(
      screen.getByRole('table', { name: 'Catálogo de minutas' }),
    ).getAllByRole('columnheader');
    expect(afterHide[0].getAttribute('aria-sort')).toBe('none');
  });

  it('hides the legal source by default, restores it on demand, and remembers the choice', async () => {
    // One shared preferences store across both mounts, so the second render reads back the choice
    // the first persisted — the account-scoped replacement for the old per-device localStorage.
    vi.stubGlobal('fetch', fetchWithPreferences([{ match: '/v1/templates', body: CATALOG }]));

    const first = renderWithProviders(<TemplatesCatalogPage />, ['/templates']);
    await screen.findByText('csc-ata-ag/v1');
    expect(screen.queryByRole('columnheader', { name: 'Fonte legal' })).toBeNull();
    // Hidden from the table, never deleted: the value has a home on the template's own page.
    expect(screen.queryByText('CC arts. 173.º e 175.º')).toBeNull();

    const columns = openColumns();
    const toggle = within(columns).getByLabelText('Fonte legal') as HTMLInputElement;
    expect(toggle.checked).toBe(false);
    fireEvent.click(toggle);

    expect(await screen.findByRole('columnheader', { name: 'Fonte legal' })).toBeTruthy();
    expect(await screen.findByText('CC arts. 173.º e 175.º')).toBeTruthy();

    // The choice is saved to the account, so a fresh mount reads it back rather than resetting.
    first.unmount();
    renderWithProviders(<TemplatesCatalogPage />, ['/templates']);
    expect(await screen.findByRole('columnheader', { name: 'Fonte legal' })).toBeTruthy();
  });

  it('shows the table skeleton while the catalog loads', async () => {
    vi.stubGlobal('fetch', (() => new Promise<Response>(() => {})) as typeof fetch);

    const { container } = renderWithProviders(<TemplatesCatalogPage />, ['/templates']);

    const loading = await screen.findByRole('status');
    expect(loading.getAttribute('aria-busy')).toBe('true');
    expect(within(loading).getByText('A carregar…')).toBeTruthy();
    expect(container.querySelector('.skeleton-table')).toBeTruthy();
    expect(screen.queryByRole('table')).toBeNull();
  });

  it('browses the existing template catalog and points generation back to acts', async () => {
    vi.stubGlobal('fetch', fetchTable([{ match: '/v1/templates', body: CATALOG }]));

    const { container } = renderWithProviders(<TemplatesCatalogPage />, ['/templates']);

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
    const ataRow = ataId.closest('tr');
    expect(ataRow).toBeTruthy();
    expect(
      within(ataRow as HTMLElement).getByText('Assinatura qualificada preferencial'),
    ).toBeTruthy();
    expect(within(ataRow as HTMLElement).getByText('csc-art63/v2')).toBeTruthy();
    expect(within(ataRow as HTMLElement).getByText('Deliberação por escrito')).toBeTruthy();
    expect(screen.getByText('4 de 4 modelos')).toBeTruthy();
    expect(screen.getAllByRole('link', { name: 'Escolher ata' })[0].getAttribute('href')).toBe(
      '/books',
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
    const condoRow = screen.getByText('condominio-lista-presencas/v1').closest('tr');
    expect(condoRow).toBeTruthy();
    expect(within(condoRow as HTMLElement).getByText('Qualificada ou manuscrita')).toBeTruthy();

    fireEvent.click(clearFilters);
    expect(await screen.findByText('csc-ata-ag/v1')).toBeTruthy();

    fireEvent.change(screen.getByLabelText('Família da entidade'), {
      target: { value: 'Association' },
    });
    const associationRow = await screen.findByText('assoc-convocatoria-ga/v1');
    expect(associationRow).toBeTruthy();
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

    const { container } = renderWithProviders(<TemplatesCatalogPage />, ['/templates']);
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

    fireEvent.change(within(advanced).getByLabelText('Pacote de regras'), {
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

  it('opts the catalog out of the shell prose measure so nine columns get the room', async () => {
    vi.stubGlobal('fetch', fetchTable([{ match: '/v1/templates', body: CATALOG }]));

    renderWithProviders(<TemplatesCatalogPage />, ['/templates']);
    await screen.findByText('csc-ata-ag/v1');
    // The page root carries the opt-in; the width itself is a CSS concern jsdom cannot lay out.
    expect(document.querySelector('.wide-page')).toBeTruthy();

    const css = await themeCss();
    // The shell measure still applies by default — the opt-out is a separate rule, not a
    // relaxation of `.app` that every prose page would inherit.
    // t18 named the two shell measures + the gutter as custom props on `.app`, so the measure
    // and wide cap are asserted through those vars (the 1080px/92rem literals live on the decls).
    expectCssRule(css, /\.app\s*\{([^}]*)\}/, [
      '--app-measure: 1080px;',
      'max-width: var(--app-measure);',
      '--app-measure-wide: 92rem;',
    ]);
    expectCssRule(css, /\.app:has\(\.wide-page\)\s*\{([^}]*)\}/, [
      'max-width: var(--app-measure-wide);',
    ]);
    // The gutters are the shell's own padding, so widening must not have dropped it.
    expectCssRule(css, /\.app\s*\{([^}]*)\}/, [
      '--app-gutter: clamp(1.25rem, 4vw, 3rem);',
      'padding: var(--app-gutter);',
    ]);
  });

  it('renders pending law references and searches by citation or article text', async () => {
    vi.stubGlobal('fetch', fetchWithPreferences([{ match: '/v1/templates', body: CATALOG }]));

    renderWithProviders(<TemplatesCatalogPage />, ['/templates']);

    await screen.findByText('assoc-convocatoria-ga/v1');
    // The column is off by default, so this test asks for it before reading its cells; the toggle
    // now persists to the account, so it waits for the header to appear before reading them.
    fireEvent.click(within(openColumns()).getByLabelText('Fonte legal'));
    await screen.findByRole('columnheader', { name: 'Fonte legal' });

    const associationId = screen.getByText('assoc-convocatoria-ga/v1');
    const associationRow = associationId.closest('tr');
    expect(associationRow).toBeTruthy();
    // The "Fonte legal" label is now the column header the cell answers to.
    expect(screen.getByRole('columnheader', { name: 'Fonte legal' })).toBeTruthy();
    expect(within(associationRow as HTMLElement).getByText('Por verificar')).toBeTruthy();
    expect(within(associationRow as HTMLElement).getByText('CC arts. 173.º e 175.º')).toBeTruthy();
    expect(
      within(associationRow as HTMLElement).getByText('Fonte: Código Civil · art. 175'),
    ).toBeTruthy();
    expect(
      within(associationRow as HTMLElement).getByText('Fonte pendente; não usar como verificada.'),
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

    renderWithProviders(<TemplatesCatalogPage />, ['/templates']);

    expect(screen.getByRole('button', { name: 'Novo modelo' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Importar' })).toBeTruthy();

    const userRow = (await screen.findByText('user-encosto-ata/v1')).closest('tr') as HTMLElement;
    expect(within(userRow).getByText('Criado pelo utilizador')).toBeTruthy();
    expect(within(userRow).getByRole('button', { name: 'Editar' })).toBeTruthy();
    expect(within(userRow).getByRole('button', { name: 'Exportar' })).toBeTruthy();
    expect(within(userRow).getByRole('button', { name: 'Eliminar' })).toBeTruthy();

    const builtinRow = screen.getByText('csc-ata-ag/v1').closest('tr') as HTMLElement;
    expect(within(builtinRow).getByText('Incluído (só leitura)')).toBeTruthy();
    // A built-in is still never DELETED or exported from the row, but it is no longer a dead
    // end: "Editar" and "Duplicar" both lead to a fork (see the fork test below).
    expect(within(builtinRow).getByRole('button', { name: 'Editar' })).toBeTruthy();
    expect(within(builtinRow).getByRole('button', { name: 'Duplicar' })).toBeTruthy();
    expect(within(builtinRow).queryByRole('button', { name: 'Eliminar' })).toBeNull();
  });

  // --- Editing a built-in forks it, and says what the fork cannot do (t79) --------------
  //
  // Built-in specs are frozen because a sealed document records the digest of the spec it was
  // generated from. The UI must therefore never offer an in-place edit of one — and, because a
  // `user-…` template is offered by the pickers but refused at the seal, it must say so BEFORE
  // the operator invests any work in the copy.

  const BUILTIN_SPEC = JSON.stringify({
    id: 'csc-ata-ag/v1',
    family: 'CommercialCompany',
    stage: 'Ata',
    channels: ['Physical'],
    signature_policy: 'QualifiedPreferred',
    rule_pack_id: 'csc-art63/v2',
    locale: 'pt-PT',
    blocks: [{ kind: 'Paragraph', template: 'Ata de {{ entity.name }}.' }],
  });

  function specFetch(catalog: TemplateSummary[]) {
    return templatesFetch(catalog, (url, method) =>
      url.includes('/export') && method === 'GET'
        ? new Response(BUILTIN_SPEC, {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          })
        : null,
    );
  }

  it('turns "editar" on a built-in into a fork, and states the limit before any work is done', async () => {
    const { fn, calls } = specFetch([CATALOG[0]]);
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<TemplatesCatalogPage />, ['/templates']);

    const builtinRow = (await screen.findByText('csc-ata-ag/v1')).closest('tr') as HTMLElement;
    fireEvent.click(within(builtinRow).getByRole('button', { name: 'Editar' }));

    // Not the edit dialog: a duplicate dialog, pre-filled with a free `user-…/v1` id.
    const dialog = await screen.findByRole('dialog', { name: 'Duplicar modelo' });
    expect(screen.queryByRole('dialog', { name: 'Editar modelo' })).toBeNull();
    expect((within(dialog).getByLabelText('Identificador') as HTMLInputElement).value).toBe(
      'user-csc-ata-ag/v1',
    );
    expect(within(dialog).getByText('Modelo de origem: csc-ata-ag/v1')).toBeTruthy();
    expect(within(dialog).getByText('Os modelos incluídos não se editam')).toBeTruthy();
    // The honest part: the copy cannot yet seal, and it says so here rather than at the seal.
    expect(within(dialog).getByText('Uma cópia ainda não produz documentos')).toBeTruthy();
    expect(
      within(dialog).getByText(/a geração e o selo de uma ata só reconhecem os modelos incluídos/),
    ).toBeTruthy();

    // Nothing was written to the built-in: the only request was the read of its spec.
    expect(calls.some((c) => c.method === 'PUT')).toBe(false);
    expect(calls.some((c) => c.method === 'POST')).toBe(false);
  });

  it('saves a fork as a new user template rather than replacing its source', async () => {
    const { fn, calls } = templatesFetch([CATALOG[0]], (url, method) => {
      if (url.includes('/export') && method === 'GET') {
        return new Response(BUILTIN_SPEC, {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      return url.endsWith('/v1/templates') && method === 'POST'
        ? jsonResponse(USER_TEMPLATE, 201)
        : null;
    });
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<TemplatesCatalogPage />, ['/templates']);

    const builtinRow = (await screen.findByText('csc-ata-ag/v1')).closest('tr') as HTMLElement;
    fireEvent.click(within(builtinRow).getByRole('button', { name: 'Duplicar' }));
    const dialog = await screen.findByRole('dialog', { name: 'Duplicar modelo' });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Guardar' }));

    await waitFor(() =>
      expect(calls.some((c) => c.method === 'POST' && c.url.endsWith('/v1/templates'))).toBe(true),
    );
    const post = calls.find((c) => c.method === 'POST' && c.url.endsWith('/v1/templates'));
    // A CREATE under the new id, carrying the source's body — never a PUT over the built-in.
    expect(String(post?.body)).toContain('user-csc-ata-ag/v1');
    expect(String(post?.body)).toContain('Ata de {{ entity.name }}.');
    expect(calls.some((c) => c.method === 'PUT')).toBe(false);
  });

  // The export endpoint emits the `chancela.template-bundle` envelope (t43), where the spec lives
  // under `.spec`. The fork path used to cast the envelope straight to `TemplateSpec`, leaving
  // `rule_pack_id`/`blocks` undefined — which crashed the fork editor on `spec.rule_pack_id.trim()`
  // (`can't access property "trim", p.rule_pack_id is undefined`). The bare-spec fork tests above
  // never caught it because they mock the legacy shape; this one mocks the real envelope.
  const BUILTIN_BUNDLE = JSON.stringify({
    format: 'chancela.template-bundle',
    format_version: 1,
    spec: JSON.parse(BUILTIN_SPEC),
    body_markdown: '',
  });

  it('forks from the real template-bundle envelope without crashing on an undefined rule pack', async () => {
    const { fn, calls } = templatesFetch([CATALOG[0]], (url, method) => {
      if (url.includes('/export') && method === 'GET') {
        return new Response(BUILTIN_BUNDLE, {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      return url.endsWith('/v1/templates') && method === 'POST'
        ? jsonResponse(USER_TEMPLATE, 201)
        : null;
    });
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<TemplatesCatalogPage />, ['/templates']);

    const builtinRow = (await screen.findByText('csc-ata-ag/v1')).closest('tr') as HTMLElement;
    fireEvent.click(within(builtinRow).getByRole('button', { name: 'Duplicar' }));

    // Before the fix the modal threw while rendering (canSubmit's `.trim()`); it now opens.
    const dialog = await screen.findByRole('dialog', { name: 'Duplicar modelo' });
    // The spec was unwrapped from `.spec`: the rule pack carried through rather than being undefined.
    expect((within(dialog).getByLabelText('Pacote de regras') as HTMLInputElement).value).toBe(
      'csc-art63/v2',
    );

    fireEvent.click(within(dialog).getByRole('button', { name: 'Guardar' }));
    await waitFor(() =>
      expect(calls.some((c) => c.method === 'POST' && c.url.endsWith('/v1/templates'))).toBe(true),
    );
    const post = calls.find((c) => c.method === 'POST' && c.url.endsWith('/v1/templates'));
    // The saved fork carries the source's rule pack and body — proof the envelope was unwrapped.
    expect(String(post?.body)).toContain('"rule_pack_id":"csc-art63/v2"');
    expect(String(post?.body)).toContain('Ata de {{ entity.name }}.');
  });

  // Behaviour CHANGED in t109: a user template is still edited in place (never forked), but the
  // editing surface is now its own full-width page rather than the dialog — its body is canonical
  // BlockSpec JSON and needs the room. The invariant under test is unchanged and is the one that
  // matters: editing a `user-…` template does NOT open the fork dialog and does NOT copy it.
  it('sends a user template to its own edit page, with no fork dialog', async () => {
    const { fn, calls } = templatesFetch([USER_TEMPLATE], (url, method) =>
      url.includes('/export') && method === 'GET'
        ? new Response(JSON.stringify({ ...JSON.parse(BUILTIN_SPEC), id: USER_TEMPLATE.id }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          })
        : null,
    );
    vi.stubGlobal('fetch', fn);

    renderWithProviders(
      <>
        <TemplatesCatalogPage />
        <span data-testid="location">{<LocationPathname />}</span>
      </>,
      ['/templates'],
    );

    const userRow = (await screen.findByText('user-encosto-ata/v1')).closest('tr') as HTMLElement;
    fireEvent.click(within(userRow).getByRole('button', { name: 'Editar' }));

    // The id carries a slash, so the path percent-encodes it or the route cannot match.
    await waitFor(() =>
      expect(screen.getByTestId('location').textContent).toBe(
        '/templates/user-encosto-ata%2Fv1/edit',
      ),
    );
    expect(screen.queryByRole('dialog')).toBeNull();
    // Nothing was created or written on the way to the editor.
    expect(calls.some((c) => c.method === 'POST' || c.method === 'PUT')).toBe(false);
  });

  it('opens a template on its own page from the catalog row', async () => {
    vi.stubGlobal('fetch', fetchTable([{ match: '/v1/templates', body: CATALOG }]));

    renderWithProviders(<TemplatesCatalogPage />, ['/templates']);

    const row = (await screen.findByText('csc-ata-ag/v1')).closest('tr') as HTMLElement;
    // The id carries a slash, so the link percent-encodes it or the route cannot match.
    expect(within(row).getByRole('link', { name: 'Abrir modelo' }).getAttribute('href')).toBe(
      '/templates/csc-ata-ag%2Fv1',
    );
  });

  it('creates a user template through the editor form', async () => {
    const { fn, calls } = templatesFetch([CATALOG[0]], (url, method) =>
      url.endsWith('/v1/templates') && method === 'POST' ? jsonResponse(USER_TEMPLATE, 201) : null,
    );
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<TemplatesCatalogPage />, ['/templates']);

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
      expect(calls.some((c) => c.method === 'POST' && c.url.endsWith('/v1/templates'))).toBe(true),
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

    renderWithProviders(<TemplatesCatalogPage />, ['/templates']);

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
    expect(calls.some((c) => c.method === 'POST' && c.url.includes('dry_run=true'))).toBe(true);
  });

  // --- Import: verify, then confirm (tg4) ---------------------------------------
  //
  // The dialog's promise is that nothing is written until the operator confirms, and that what
  // is then written is the file's bytes unchanged — so a template exported from one install
  // round-trips into another exactly. Both halves are invisible in the UI and only a request
  // body can prove them.

  const VALID_JSON = '{\n  "id": "user-encosto-ata/v1",\n  "blocks": [{"kind":"Paragraph"}]\n}';

  /** Open the import dialog over a stub, and return it. */
  async function openImport(handle?: (url: string, method: string) => Response | null) {
    const { fn, calls } = templatesFetch([CATALOG[0]], handle);
    vi.stubGlobal('fetch', fn);
    renderWithProviders(<TemplatesCatalogPage />, ['/templates']);
    fireEvent.click(screen.getByRole('button', { name: 'Importar' }));
    const dialog = await screen.findByRole('dialog', { name: 'Importar modelo' });
    return {
      dialog,
      calls,
      fileInput: dialog.querySelector('input[type="file"]') as HTMLInputElement,
    };
  }

  const importCalls = (calls: RecordedRequest[]) =>
    calls.filter((c) => c.method === 'POST' && c.url.includes('/v1/templates/import'));

  it('commits exactly the bytes it verified, and only after an explicit confirmation', async () => {
    const { dialog, calls, fileInput } = await openImport((url, method) =>
      url.includes('/v1/templates/import') && method === 'POST'
        ? url.includes('dry_run=true')
          ? jsonResponse({ ok: true })
          : jsonResponse(USER_TEMPLATE, 201)
        : null,
    );

    fireEvent.change(fileInput, { target: { files: [jsonFile(VALID_JSON)] } });

    expect(
      await within(dialog).findAllByText('Ficheiro válido. Pode confirmar a importação.'),
    ).not.toHaveLength(0);
    // The filename is echoed so an operator can see which file the verdict is about.
    expect(within(dialog).getByText('modelo.json')).toBeTruthy();
    // The preflight ran and persisted nothing.
    expect(importCalls(calls)).toHaveLength(1);
    expect(importCalls(calls)[0].url).toContain('dry_run=true');

    const confirm = within(dialog).getByRole('button', { name: 'Confirmar importação' });
    expect((confirm as HTMLButtonElement).disabled).toBe(false);
    fireEvent.click(confirm);

    await waitFor(() => expect(importCalls(calls)).toHaveLength(2));
    const commit = importCalls(calls)[1];
    expect(commit.url).not.toContain('dry_run');
    // Byte-for-byte, including the whitespace: the commit must not re-serialise the JSON, or a
    // re-exported template would stop round-tripping and its digest would change.
    expect(commit.body).toBe(VALID_JSON);
    expect(commit.body).toBe(importCalls(calls)[0].body);

    expect(await screen.findByText('Modelo «user-encosto-ata/v1» importado.')).toBeTruthy();
    await waitFor(() =>
      expect(screen.queryByRole('dialog', { name: 'Importar modelo' })).toBeNull(),
    );
  });

  it('maps a preflight rejected at the HTTP level to its reason, not to a raw status line', async () => {
    // The dry run can fail as a 4xx rather than as a 200 verdict (an oversized body never reaches
    // the validator). Both must reach the operator as the same actionable sentence.
    const { dialog, calls, fileInput } = await openImport((url, method) =>
      url.includes('/v1/templates/import') && method === 'POST'
        ? jsonResponse({ error: 'demasiado grande', code: 'too_large' }, 413)
        : null,
    );

    fireEvent.change(fileInput, { target: { files: [jsonFile(VALID_JSON)] } });

    expect(
      await within(dialog).findByText('O ficheiro do modelo excede o limite permitido.'),
    ).toBeTruthy();
    expect(within(dialog).queryByText(/413/)).toBeNull();
    expect(
      (within(dialog).getByRole('button', { name: 'Confirmar importação' }) as HTMLButtonElement)
        .disabled,
    ).toBe(true);
    expect(importCalls(calls)).toHaveLength(1);
  });

  it('refuses the import when the preflight cannot be reached at all', async () => {
    // A transport-level failure with no error code must still leave the operator refused rather
    // than silently confirmable.
    //
    // NOTE (finding, not a fix): the dialog defaults a code-less failure to `malformed`, which is
    // in the known-code set, so `mappedTemplateError` translates it and the server's own sentence
    // never reaches the screen — a 503 reads as "o modelo está malformado". That is a source
    // change and is reported in `.orchestration/logs/tg4-coverage.md` rather than made here; this
    // test therefore asserts only the refusal, which is correct either way.
    const { dialog, calls, fileInput } = await openImport((url, method) =>
      url.includes('/v1/templates/import') && method === 'POST'
        ? jsonResponse({ error: 'o catálogo está em manutenção' }, 503)
        : null,
    );

    fireEvent.change(fileInput, { target: { files: [jsonFile(VALID_JSON)] } });

    expect(
      await within(dialog).findAllByText('Ficheiro inválido. Corrija os erros antes de importar.'),
    ).not.toHaveLength(0);
    expect(
      (within(dialog).getByRole('button', { name: 'Confirmar importação' }) as HTMLButtonElement)
        .disabled,
    ).toBe(true);
    expect(importCalls(calls)).toHaveLength(1);
  });

  it('keeps the dialog open with the reason when the commit itself fails', async () => {
    // Closing here would look exactly like a successful import while nothing was written.
    let committed = false;
    const { dialog, calls, fileInput } = await openImport((url, method) => {
      if (!url.includes('/v1/templates/import') || method !== 'POST') return null;
      if (url.includes('dry_run=true')) return jsonResponse({ ok: true });
      committed = true;
      return jsonResponse({ error: 'já existe', code: 'conflict' }, 409);
    });

    fireEvent.change(fileInput, { target: { files: [jsonFile(VALID_JSON)] } });
    fireEvent.click(await within(dialog).findByRole('button', { name: 'Confirmar importação' }));

    expect(
      await within(dialog).findByText('Já existe um modelo com este identificador.'),
    ).toBeTruthy();
    expect(committed).toBe(true);
    expect(screen.getByRole('dialog', { name: 'Importar modelo' })).toBeTruthy();
    // And the failed verdict disarms Confirm, so a second click cannot retry blindly.
    expect(
      (within(dialog).getByRole('button', { name: 'Confirmar importação' }) as HTMLButtonElement)
        .disabled,
    ).toBe(true);
    expect(importCalls(calls)).toHaveLength(2);
  });

  it('replaces the previous verdict when a corrected file is picked again', async () => {
    // An operator who fixes the file on disk and re-picks it must see the new answer, not the
    // stale refusal — otherwise a valid template looks permanently rejected.
    let attempt = 0;
    const { dialog, calls, fileInput } = await openImport((url, method) => {
      if (!url.includes('/v1/templates/import') || method !== 'POST') return null;
      attempt += 1;
      return attempt === 1
        ? jsonResponse({ ok: false, error: { code: 'no_blocks', message: 'sem blocos' } })
        : jsonResponse({ ok: true });
    });

    fireEvent.change(fileInput, { target: { files: [jsonFile(VALID_JSON)] } });
    expect(
      await within(dialog).findByText('O modelo tem de conter pelo menos um bloco.'),
    ).toBeTruthy();

    fireEvent.change(fileInput, { target: { files: [jsonFile(VALID_JSON)] } });
    expect(
      await within(dialog).findAllByText('Ficheiro válido. Pode confirmar a importação.'),
    ).not.toHaveLength(0);
    expect(within(dialog).queryByText('O modelo tem de conter pelo menos um bloco.')).toBeNull();
    expect(importCalls(calls)).toHaveLength(2);
  });

  it('closes on Cancelar and on the backdrop, but not on a click inside the dialog', async () => {
    const { dialog, calls } = await openImport();

    fireEvent.click(dialog);
    expect(screen.getByRole('dialog', { name: 'Importar modelo' })).toBeTruthy();

    fireEvent.click(document.querySelector('.modal-backdrop') as HTMLElement);
    await waitFor(() =>
      expect(screen.queryByRole('dialog', { name: 'Importar modelo' })).toBeNull(),
    );

    fireEvent.click(screen.getByRole('button', { name: 'Importar' }));
    const reopened = await screen.findByRole('dialog', { name: 'Importar modelo' });
    fireEvent.click(within(reopened).getByRole('button', { name: 'Cancelar' }));
    await waitFor(() =>
      expect(screen.queryByRole('dialog', { name: 'Importar modelo' })).toBeNull(),
    );
    // Opening and closing the dialog writes nothing at all.
    expect(importCalls(calls)).toHaveLength(0);
  });

  it('deletes a user template through the confirm dialog', async () => {
    const { fn, calls } = templatesFetch([CATALOG[0], USER_TEMPLATE], (url, method) =>
      url.includes('/v1/templates/') && method === 'DELETE' ? jsonResponse(null, 204) : null,
    );
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<TemplatesCatalogPage />, ['/templates']);

    const userRow = (await screen.findByText('user-encosto-ata/v1')).closest('tr') as HTMLElement;
    fireEvent.click(within(userRow).getByRole('button', { name: 'Eliminar' }));

    const dialog = await screen.findByRole('dialog');
    expect(
      within(dialog).getByText(
        'Eliminar o modelo «user-encosto-ata/v1»? Esta ação não pode ser anulada.',
      ),
    ).toBeTruthy();
    fireEvent.click(within(dialog).getByRole('button', { name: 'Eliminar' }));

    await waitFor(() =>
      expect(calls.some((c) => c.method === 'DELETE' && c.url.includes('/v1/templates/'))).toBe(
        true,
      ),
    );
  });
});
