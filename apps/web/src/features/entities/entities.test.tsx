import { afterEach, describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { Route, Routes } from 'react-router-dom';
import { renderWithProviders, fetchTable } from '../../test/utils';
import { EntitiesPage } from './EntitiesPage';
import { NewEntityPage } from './NewEntityPage';
import { EntityDetailPage } from './EntityDetailPage';
import { entityFieldHelp } from './fieldHelp';
import { DEFAULT_SETTINGS, type Entity, type LedgerEventView } from '../../api/types';

const ENTITY: Entity = {
  id: 'new-ent-1',
  name: 'Encosto Estratégico, Lda.',
  nipc: '503004642',
  nipc_validated: true,
  seat: 'Lisboa',
  family: 'CommercialCompany',
  kind: 'SociedadePorQuotas',
  fiscal_year_end: null,
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

function themeCss(): string {
  return readFileSync('src/theme.css', 'utf8');
}

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function entityDetailFetch(initial: Entity) {
  let current = initial;
  const calls: { url: string; method: string; body: unknown }[] = [];
  const fn = ((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const method = init?.method ?? 'GET';
    const body = init?.body ? JSON.parse(init.body as string) : null;
    calls.push({ url, method, body });

    if (url.includes(`/v1/entities/${current.id}/chronology`)) {
      return Promise.resolve(jsonResponse({ error: 'not found' }, 404));
    }
    if (url.includes(`/v1/entities/${current.id}/registry`)) {
      return Promise.resolve(jsonResponse({ error: 'not found' }, 404));
    }
    if (url.includes('/v1/books')) {
      return Promise.resolve(jsonResponse([]));
    }
    if (url.includes(`/v1/entities/${current.id}`) && method === 'PATCH') {
      const patch = body as { fiscal_year_end?: string | null };
      current = {
        ...current,
        fiscal_year_end: Object.prototype.hasOwnProperty.call(patch, 'fiscal_year_end')
          ? patch.fiscal_year_end
          : current.fiscal_year_end,
      };
      return Promise.resolve(jsonResponse(current));
    }
    if (url.includes(`/v1/entities/${current.id}`) && method === 'GET') {
      return Promise.resolve(jsonResponse(current));
    }
    return Promise.reject(new Error(`no stub for ${method} ${url}`));
  }) as typeof fetch;
  return { fn, calls };
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('EntitiesPage', () => {
  it('offers neat buttons to the create/import routes instead of an inline form', async () => {
    vi.stubGlobal(
      'fetch',
      fetchTable([
        { match: '/v1/settings', body: DEFAULT_SETTINGS },
        { match: '/v1/entities', body: [] },
      ]),
    );
    renderWithProviders(<EntitiesPage />, ['/entidades']);

    await screen.findByText('Ainda não há entidades');

    const nova = screen.getByRole('link', { name: /nova entidade/i });
    expect(nova.getAttribute('href')).toBe('/entidades/nova');
    const importar = screen.getByRole('link', { name: /importar do registo/i });
    expect(importar.getAttribute('href')).toBe('/entidades/importar');

    // No inline create form on the list page anymore.
    expect(screen.queryByLabelText('Denominação')).toBeNull();
    expect(screen.queryByRole('button', { name: /criar entidade/i })).toBeNull();
  });

  it('flags an unvalidated NIPC with a warning badge in the list', async () => {
    const unvalidated: Entity = { ...ENTITY, nipc: 'GB-12345', nipc_validated: false };
    vi.stubGlobal(
      'fetch',
      fetchTable([
        { match: '/v1/settings', body: DEFAULT_SETTINGS },
        { match: '/v1/entities', body: [unvalidated] },
      ]),
    );
    renderWithProviders(<EntitiesPage />, ['/entidades']);

    expect(await screen.findByText('GB-12345')).toBeTruthy();
    expect(screen.getByText('não validado')).toBeTruthy();
  });

  it('defaults the registered entities table to the compact configured columns', async () => {
    vi.stubGlobal(
      'fetch',
      fetchTable([
        { match: '/v1/settings', body: DEFAULT_SETTINGS },
        { match: '/v1/entities', body: [ENTITY] },
      ]),
    );
    renderWithProviders(<EntitiesPage />, ['/entidades']);

    expect(await screen.findByText(ENTITY.name)).toBeTruthy();
    expect(screen.getByRole('columnheader', { name: 'Denominação' })).toBeTruthy();
    expect(screen.getByRole('columnheader', { name: 'NIPC' })).toBeTruthy();
    expect(screen.getByRole('columnheader', { name: 'Tipo' })).toBeTruthy();
    expect(screen.getByRole('columnheader', { name: 'Última atividade' })).toBeTruthy();
    expect(screen.getByRole('columnheader', { name: 'Actions' })).toBeTruthy();
    expect(screen.queryByRole('columnheader', { name: 'Sede' })).toBeNull();
    expect(screen.queryByRole('columnheader', { name: 'CAE' })).toBeNull();
  });

  it('keeps common filters visible and collapses extra filters into the advanced panel', async () => {
    vi.stubGlobal(
      'fetch',
      fetchTable([
        { match: '/v1/settings', body: DEFAULT_SETTINGS },
        { match: '/v1/entities', body: [ENTITY] },
      ]),
    );
    renderWithProviders(<EntitiesPage />, ['/entidades']);

    expect(await screen.findByText(ENTITY.name)).toBeTruthy();
    const filters = screen.getByRole('search', { name: 'Pesquisar e filtrar entidades' });
    expect(filters.className).toContain('entities-filters');
    const primary = filters.querySelector('.entities-filterbar__primary') as HTMLElement;
    expect(primary).toBeTruthy();
    expect(primary.querySelectorAll('.field')).toHaveLength(3);
    expect(within(primary).getByLabelText('Pesquisar')).toBeTruthy();
    expect(within(primary).getByLabelText('Família')).toBeTruthy();
    expect(within(primary).getByLabelText('Forma')).toBeTruthy();
    expect(within(primary).getByRole('button', { name: /limpar/i })).toBeTruthy();
    expect(within(primary).queryByLabelText('NIPC')).toBeNull();
    expect(within(primary).queryByLabelText('Registo')).toBeNull();

    const advanced = filters.querySelector(
      'details.entities-advanced-filters',
    ) as HTMLDetailsElement;
    expect(advanced).toBeTruthy();
    expect(advanced.open).toBe(false);
    const advancedBody = advanced.querySelector('.entities-advanced-filters__body.filter');
    expect(advancedBody).toBeTruthy();
    expect(advancedBody?.querySelectorAll('.field')).toHaveLength(8);
    expect(within(advanced).getByLabelText('NIPC')).toBeTruthy();
    expect(within(advanced).getByLabelText('Registo')).toBeTruthy();

    fireEvent.click(within(advanced).getByText('Filtros avançados'));
    expect(advanced.open).toBe(true);
    expect(within(advanced).getByLabelText('Livros')).toBeTruthy();
    expect(within(advanced).getByLabelText('Última alteração')).toBeTruthy();
  });

  it('pins entity table and filter CSS to single-line no-overflow rules', () => {
    const css = themeCss();
    const filterRule = css.match(/\.entities-filters\s*{(?<body>[^}]*)}/s)?.groups?.body ?? '';
    const filterbarRule = css.match(/\.entities-filterbar\s*{(?<body>[^}]*)}/s)?.groups?.body ?? '';
    const filterButtonRule =
      css.match(/\.entities-filterbar__primary \.btn\s*{(?<body>[^}]*)}/s)?.groups?.body ?? '';
    const tableWrapRule =
      css.match(/\.entities-table \.table-wrap\s*{(?<body>[^}]*)}/s)?.groups?.body ?? '';
    const tableCellRule =
      css.match(/\.entities-table \.table th,\s*\.entities-table \.table td\s*{(?<body>[^}]*)}/s)
        ?.groups?.body ?? '';
    const truncateRule =
      css.match(/\.entities-table__cell--truncate > \.truncate\s*{(?<body>[^}]*)}/s)?.groups
        ?.body ?? '';
    const cellLineRule =
      css.match(/(?:^|\n)\.entity-cell-line\s*{(?<body>[^}]*)}/s)?.groups?.body ?? '';

    expect(filterRule).toContain('min-width: 0;');
    expect(filterRule).toContain('max-width: 100%;');
    expect(filterRule).toContain('overflow-x: clip;');
    expect(filterbarRule).toContain('overflow-x: clip;');
    expect(filterButtonRule).toContain('max-width: 100%;');
    expect(filterButtonRule).toContain('overflow: hidden;');
    expect(tableWrapRule).toContain('overflow-x: hidden;');
    expect(tableCellRule).toContain('white-space: nowrap;');
    expect(truncateRule).toContain('white-space: nowrap;');
    expect(truncateRule).not.toContain('-webkit-line-clamp');
    expect(cellLineRule).toContain('flex-wrap: nowrap;');
    expect(cellLineRule).toContain('white-space: nowrap;');
  });

  it('renders the default entity table columns as single-line truncating cells', async () => {
    const activity: LedgerEventView = {
      id: 'event-long-entity',
      seq: 1,
      actor: 'amelia.marques.com.identificador.operacional.extenso',
      justification: null,
      timestamp: '2026-07-02T10:15:30Z',
      scope: ENTITY.id,
      kind: 'entity.created',
      payload_digest: '0'.repeat(64),
      prev_hash: '0'.repeat(64),
      hash: '1'.repeat(64),
      chains: ['global', `company:${ENTITY.id}`],
      attestation: null,
    };
    const longEntity: Entity = {
      ...ENTITY,
      name: 'Encosto Estratégico Sociedade de Investimento Imobiliário e Participações Internacionais, Lda.',
      activity_summary: {
        last_book: null,
        book_state_counts: { created: 0, open: 0, closed: 0 },
        last_change: activity,
      },
    };
    vi.stubGlobal(
      'fetch',
      fetchTable([
        { match: '/v1/settings', body: DEFAULT_SETTINGS },
        { match: '/v1/entities', body: [longEntity] },
      ]),
    );
    renderWithProviders(<EntitiesPage />, ['/entidades']);

    const name = await screen.findByText(longEntity.name);
    expect(name.className).toContain('truncate');
    expect(name.getAttribute('title')).toBe(longEntity.name);

    const row = name.closest('tr') as HTMLElement;
    const cells = within(row).getAllByRole('cell');
    expect(cells).toHaveLength(5);
    for (const cell of cells.slice(0, 4)) {
      expect(cell.className).toContain('entities-table__cell--truncate');
      const singleLine = cell.querySelector('.truncate, .entity-cell-line');
      expect(singleLine).toBeTruthy();
      expect(singleLine?.getAttribute('title')).toBeTruthy();
    }
    expect(cells[4].className).toContain('entities-table__cell--actions');
    expect(cells[4].className).not.toContain('entities-table__cell--truncate');
    expect(within(cells[4]).getByRole('button', { name: 'Abrir' })).toBeTruthy();

    const typeLine = cells[2].querySelector('.entity-cell-line');
    expect(typeLine?.textContent).toBe('Lda.');
    expect(typeLine?.className).toContain('entity-cell-line--compact');
    expect(typeLine?.textContent).not.toContain('Sociedade por Quotas');
    expect(typeLine?.textContent).not.toContain('Regras');
    expect(typeLine?.getAttribute('title')).toContain('Sociedade por Quotas');
    expect(typeLine?.getAttribute('title')).toContain('Regras csc-art63/v2');

    const activityLine = cells[3].querySelector('.entity-cell-line');
    expect(activityLine?.className).toContain('entity-cell-line--compact');
    expect(activityLine?.textContent).not.toContain(activity.actor);
    expect(activityLine?.textContent).not.toContain('10:15');
    expect(activityLine?.getAttribute('title')).toContain('Entidade criada');
    expect(activityLine?.getAttribute('title')).toContain(activity.actor);
  });

  it('opens an entity via an icon button carrying an accessible "Abrir" tooltip label', async () => {
    vi.stubGlobal(
      'fetch',
      fetchTable([
        { match: '/v1/settings', body: DEFAULT_SETTINGS },
        { match: '/v1/entities', body: [ENTITY] },
      ]),
    );
    renderWithProviders(
      <Routes>
        <Route path="/entidades" element={<EntitiesPage />} />
        <Route path="/entidades/:id" element={<div>DETALHE DA ENTIDADE</div>} />
      </Routes>,
      ['/entidades'],
    );

    // The open control is an icon-only button named by its tooltip (no visible link text).
    const open = await screen.findByRole('button', { name: 'Abrir' });
    expect(screen.queryByRole('link', { name: 'Abrir' })).toBeNull();
    fireEvent.click(open);
    expect(await screen.findByText('DETALHE DA ENTIDADE')).toBeTruthy();
  });
});

describe('NewEntityPage', () => {
  it('adds inline help to core entity identity fields', () => {
    vi.stubGlobal('fetch', fetchTable([]));
    renderWithProviders(<NewEntityPage />, ['/entidades/nova']);

    expect(screen.getAllByRole('button', { name: 'Ajuda' }).length).toBeGreaterThanOrEqual(4);
    expect(document.body.textContent).toContain(entityFieldHelp.nipc);
    expect(document.body.textContent).toContain(entityFieldHelp.seat);
    expect(document.body.textContent).toContain(entityFieldHelp.legalForm);
    expect(document.body.textContent).toContain(entityFieldHelp.fiscalYearEnd);
  });

  it('creates an entity and navigates to its detail page', async () => {
    const calls: { url: string; body: unknown }[] = [];
    const fn = ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      const body = init?.body ? JSON.parse(init.body as string) : null;
      calls.push({ url, body });
      return Promise.resolve(
        new Response(JSON.stringify(ENTITY), {
          status: 201,
          headers: { 'Content-Type': 'application/json' },
        }),
      );
    }) as typeof fetch;
    vi.stubGlobal('fetch', fn);

    renderWithProviders(
      <Routes>
        <Route path="/entidades/nova" element={<NewEntityPage />} />
        <Route path="/entidades/:id" element={<div>DETALHE DA ENTIDADE</div>} />
      </Routes>,
      ['/entidades/nova'],
    );

    fireEvent.change(screen.getByLabelText('Denominação'), {
      target: { value: 'Encosto Estratégico, Lda.' },
    });
    fireEvent.change(screen.getByLabelText('NIPC'), { target: { value: '503004642' } });
    fireEvent.change(screen.getByLabelText('Sede'), { target: { value: 'Lisboa' } });
    fireEvent.click(screen.getByRole('button', { name: /criar entidade/i }));

    expect(await screen.findByText('DETALHE DA ENTIDADE')).toBeTruthy();
    // The success toast fires even though the handler navigated away (t44 retrofit-a, R6).
    expect(await screen.findByText('Entidade criada.')).toBeTruthy();

    const post = calls.find((c) => c.url.includes('/v1/entities'));
    expect((post?.body as { nipc?: string })?.nipc).toBe('503004642');
    // Strict by default: the override flag is false when the tickbox is untouched.
    expect((post?.body as { allow_invalid_nipc?: boolean })?.allow_invalid_nipc).toBe(false);
    // Empty means the backend applies its calendar-year default (12-31).
    expect((post?.body as { fiscal_year_end?: string | null })?.fiscal_year_end).toBeNull();
  });

  it('creates an entity with a custom fiscal-year end', async () => {
    const calls: { url: string; body: unknown }[] = [];
    const fn = ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      const body = init?.body ? JSON.parse(init.body as string) : null;
      calls.push({ url, body });
      return Promise.resolve(
        new Response(JSON.stringify({ ...ENTITY, fiscal_year_end: '06-30' }), {
          status: 201,
          headers: { 'Content-Type': 'application/json' },
        }),
      );
    }) as typeof fetch;
    vi.stubGlobal('fetch', fn);

    renderWithProviders(
      <Routes>
        <Route path="/entidades/nova" element={<NewEntityPage />} />
        <Route path="/entidades/:id" element={<div>DETALHE DA ENTIDADE</div>} />
      </Routes>,
      ['/entidades/nova'],
    );

    fireEvent.change(screen.getByLabelText('Denominação'), {
      target: { value: 'Encosto Estratégico, Lda.' },
    });
    fireEvent.change(screen.getByLabelText('NIPC'), { target: { value: '503004642' } });
    fireEvent.change(screen.getByLabelText('Sede'), { target: { value: 'Lisboa' } });
    fireEvent.change(screen.getByLabelText('Fecho do exercício (MM-DD)'), {
      target: { value: '06-30' },
    });
    fireEvent.click(screen.getByRole('button', { name: /criar entidade/i }));

    expect(await screen.findByText('DETALHE DA ENTIDADE')).toBeTruthy();
    const post = calls.find((c) => c.url.includes('/v1/entities'));
    expect((post?.body as { fiscal_year_end?: string | null })?.fiscal_year_end).toBe('06-30');
  });

  it('blocks an invalid fiscal-year end before creating', async () => {
    const calls: { url: string; body: unknown }[] = [];
    const fn = ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      const body = init?.body ? JSON.parse(init.body as string) : null;
      calls.push({ url, body });
      return Promise.resolve(jsonResponse(ENTITY, 201));
    }) as typeof fetch;
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<NewEntityPage />, ['/entidades/nova']);

    fireEvent.change(screen.getByLabelText('Denominação'), {
      target: { value: 'Encosto Estratégico, Lda.' },
    });
    fireEvent.change(screen.getByLabelText('NIPC'), { target: { value: '503004642' } });
    fireEvent.change(screen.getByLabelText('Sede'), { target: { value: 'Lisboa' } });
    fireEvent.change(screen.getByLabelText('Fecho do exercício (MM-DD)'), {
      target: { value: '13-40' },
    });
    fireEvent.click(screen.getByRole('button', { name: /criar entidade/i }));

    expect(await screen.findByText('Use uma data válida no formato MM-DD.')).toBeTruthy();
    expect(calls).toHaveLength(0);
  });

  it('sends allow_invalid_nipc when the override tickbox is checked', async () => {
    const calls: { url: string; body: unknown }[] = [];
    const fn = ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      const body = init?.body ? JSON.parse(init.body as string) : null;
      calls.push({ url, body });
      return Promise.resolve(
        new Response(JSON.stringify({ ...ENTITY, nipc: 'GB-12345', nipc_validated: false }), {
          status: 201,
          headers: { 'Content-Type': 'application/json' },
        }),
      );
    }) as typeof fetch;
    vi.stubGlobal('fetch', fn);

    renderWithProviders(
      <Routes>
        <Route path="/entidades/nova" element={<NewEntityPage />} />
        <Route path="/entidades/:id" element={<div>DETALHE DA ENTIDADE</div>} />
      </Routes>,
      ['/entidades/nova'],
    );

    fireEvent.change(screen.getByLabelText('Denominação'), {
      target: { value: 'Foreign Holdings Ltd.' },
    });
    fireEvent.change(screen.getByLabelText('NIPC'), { target: { value: 'GB-12345' } });
    fireEvent.change(screen.getByLabelText('Sede'), { target: { value: 'Londres' } });
    // The override tickbox is a labelled switch.
    fireEvent.click(screen.getByRole('switch', { name: /NIPC sem validação/i }));
    fireEvent.click(screen.getByRole('button', { name: /criar entidade/i }));

    expect(await screen.findByText('DETALHE DA ENTIDADE')).toBeTruthy();
    const post = calls.find((c) => c.url.includes('/v1/entities'));
    expect((post?.body as { allow_invalid_nipc?: boolean })?.allow_invalid_nipc).toBe(true);
  });
});

describe('EntityDetailPage', () => {
  it('adds inline help to read-only identity and fiscal-year detail fields', async () => {
    const { fn } = entityDetailFetch({ ...ENTITY, fiscal_year_end: null });
    vi.stubGlobal('fetch', fn);

    renderWithProviders(
      <Routes>
        <Route path="/entidades/:id" element={<EntityDetailPage />} />
      </Routes>,
      ['/entidades/new-ent-1'],
    );

    expect((await screen.findAllByText('12-31 (por omissão)')).length).toBeGreaterThan(0);
    expect(screen.getAllByRole('button', { name: 'Ajuda' }).length).toBeGreaterThanOrEqual(5);
    expect(document.body.textContent).toContain(entityFieldHelp.nipc);
    expect(document.body.textContent).toContain(entityFieldHelp.seat);
    expect(document.body.textContent).toContain(entityFieldHelp.legalForm);
    expect(document.body.textContent).toContain(entityFieldHelp.fiscalYearEnd);
  });

  it('displays the default fiscal-year end and persists a custom date', async () => {
    const { fn, calls } = entityDetailFetch({ ...ENTITY, fiscal_year_end: null });
    vi.stubGlobal('fetch', fn);

    renderWithProviders(
      <Routes>
        <Route path="/entidades/:id" element={<EntityDetailPage />} />
      </Routes>,
      ['/entidades/new-ent-1'],
    );

    expect((await screen.findAllByText('12-31 (por omissão)')).length).toBeGreaterThan(0);
    const input = screen.getByLabelText('Fecho do exercício (MM-DD)') as HTMLInputElement;
    expect(input.value).toBe('');

    fireEvent.change(input, { target: { value: '06-30' } });
    fireEvent.click(screen.getByRole('button', { name: /guardar fecho/i }));

    await waitFor(() => {
      expect(calls.some((c) => c.method === 'PATCH')).toBe(true);
    });
    const patch = calls.find((c) => c.method === 'PATCH');
    expect((patch?.body as { fiscal_year_end?: string | null })?.fiscal_year_end).toBe('06-30');
    expect(await screen.findByText('Exercício fiscal atualizado.')).toBeTruthy();
    expect(screen.getAllByText('06-30').length).toBeGreaterThan(0);
  });

  it('blocks an invalid fiscal-year end before patching the entity', async () => {
    const { fn, calls } = entityDetailFetch({ ...ENTITY, fiscal_year_end: '03-31' });
    vi.stubGlobal('fetch', fn);

    renderWithProviders(
      <Routes>
        <Route path="/entidades/:id" element={<EntityDetailPage />} />
      </Routes>,
      ['/entidades/new-ent-1'],
    );

    const input = (await screen.findByLabelText('Fecho do exercício (MM-DD)')) as HTMLInputElement;
    expect(input.value).toBe('03-31');

    fireEvent.change(input, { target: { value: '02-30' } });
    fireEvent.click(screen.getByRole('button', { name: /guardar fecho/i }));

    expect(await screen.findByText('Use uma data válida no formato MM-DD.')).toBeTruthy();
    expect(calls.some((c) => c.method === 'PATCH')).toBe(false);
  });

  it('surfaces the backend entity chronology and Mermaid graph source', async () => {
    const { fn, calls } = entityDetailFetch(ENTITY);
    const urls: string[] = [];
    vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      urls.push(url);
      if (url.includes(`/v1/entities/${ENTITY.id}/chronology`)) {
        return Promise.resolve(
          jsonResponse({
            events: [
              {
                date: '2020-01-01',
                kind: 'Constitution',
                description: 'Constituição de sociedade',
                source_inscription: '1',
                actors: ['Maria Silva'],
              },
            ],
            mermaid: {
              shareholders: 'graph TD\n  Maria[Maria Silva] --> Quota[Quota EUR 5000]',
              organs: 'timeline\n  2020 : Gerência',
              relationships: 'graph LR\n  Entidade --> Registo',
            },
          }),
        );
      }
      return fn(input, init);
    }) as typeof fetch);

    renderWithProviders(
      <Routes>
        <Route path="/entidades/:id" element={<EntityDetailPage />} />
      </Routes>,
      ['/entidades/new-ent-1'],
    );

    expect(await screen.findByText('Cronologia e grafo')).toBeTruthy();
    expect(await screen.findByText('Constituição de sociedade')).toBeTruthy();
    expect(screen.getByText('Maria Silva')).toBeTruthy();
    expect(screen.getByText('Insc. 1')).toBeTruthy();
    expect(
      (screen.getByLabelText('Código Mermaid: Sócios e quotas') as HTMLTextAreaElement).value,
    ).toContain('Maria[Maria Silva] --> Quota[Quota EUR 5000]');
    expect(
      (screen.getByLabelText('Código Mermaid: Órgãos sociais') as HTMLTextAreaElement).value,
    ).toContain('timeline');
    expect(urls.some((url) => url.includes(`/v1/entities/${ENTITY.id}/chronology`))).toBe(true);
    expect(calls.some((c) => c.url.includes('/chronology'))).toBe(false);
  });
});
