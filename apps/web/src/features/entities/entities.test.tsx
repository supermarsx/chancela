import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes, useLocation, useNavigationType } from 'react-router-dom';
import { makeClient, renderWithProviders, fetchTable } from '../../test/utils';
import { ToastProvider } from '../../ui/toast';
import { ALLOW_ALL_PERMISSIONS, StaticPermissionsProvider } from '../session/permissions';
import { EntitiesPage } from './EntitiesPage';
import { NewEntityPage } from './NewEntityPage';
import { EntityDetailPage } from './EntityDetailPage';
import { entityFieldHelp } from './fieldHelp';
import {
  DEFAULT_SETTINGS,
  type Entity,
  type LedgerEventView,
  type RegistryExtractView,
} from '../../api/types';

/**
 * The text a cell reveals BEYOND what it displays — the themed tooltip bubble it points at
 * via `aria-describedby`. Replaces the old `getAttribute('title')` probes: t31 moved these
 * reveals off the unstyleable native tooltip onto the shared `Tooltip` primitive.
 */
function describedText(el: Element | null | undefined): string | null {
  const id = el?.getAttribute('aria-describedby');
  return id ? (document.getElementById(id)?.textContent ?? null) : null;
}

const ENTITY: Entity = {
  id: 'new-ent-1',
  tenant_id: 'tenant-1',
  group_id: null,
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
    attendee_qualities: ['Member'],
  },
  statute: null,
};

async function themeCss(): Promise<string> {
  const nodeFs = 'node:fs';
  const { readFileSync } = (await import(nodeFs)) as {
    readFileSync(path: string, encoding: 'utf8'): string;
  };
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
    renderWithProviders(<EntitiesPage />, ['/entities']);

    await screen.findByText('Ainda não há entidades');

    const nova = screen.getByRole('link', { name: /nova entidade/i });
    expect(nova.getAttribute('href')).toBe('/entities/new');
    const importar = screen.getByRole('link', { name: /importar do registo/i });
    expect(importar.getAttribute('href')).toBe('/entities/import');

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
    renderWithProviders(<EntitiesPage />, ['/entities']);

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
    renderWithProviders(<EntitiesPage />, ['/entities']);

    expect(await screen.findByText(ENTITY.name)).toBeTruthy();
    expect(screen.getByRole('columnheader', { name: 'Denominação' })).toBeTruthy();
    expect(screen.getByRole('columnheader', { name: 'NIPC' })).toBeTruthy();
    expect(screen.getByRole('columnheader', { name: 'Tipo' })).toBeTruthy();
    expect(screen.getByRole('columnheader', { name: 'Última atividade' })).toBeTruthy();
    expect(screen.getByRole('columnheader', { name: 'Ações' })).toBeTruthy();
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
    renderWithProviders(<EntitiesPage />, ['/entities']);

    expect(await screen.findByText(ENTITY.name)).toBeTruthy();
    const filters = screen.getByRole('search', { name: 'Pesquisar e filtrar entidades' });
    expect(filters.className).toContain('entities-filters');
    const primary = filters.querySelector('.entities-filterbar__primary') as HTMLElement;
    expect(primary).toBeTruthy();
    expect(primary.querySelectorAll('.field')).toHaveLength(3);
    expect(within(primary).getByLabelText('Pesquisar')).toBeTruthy();
    expect(within(primary).getByLabelText('Família')).toBeTruthy();
    expect(within(primary).getByLabelText('Forma')).toBeTruthy();
    const clearFilters = within(primary).getByRole('button', {
      name: 'Limpar filtros de entidades',
    }) as HTMLButtonElement;
    expect(clearFilters.className).toContain('btn--iconOnly');
    expect(clearFilters.textContent?.trim()).toBe('');
    expect(
      document.getElementById(clearFilters.getAttribute('aria-describedby') ?? '')?.textContent,
    ).toBe('Limpar filtros de entidades');
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

  it('sizes each entity column to what it holds, leaving only the name elastic', async () => {
    const css = await themeCss();

    // Every fixed-shape column declares its own width. Without these the `table-layout:
    // fixed` above splits the table EQUALLY (CSS 2.1 §17.5.2.1), which is what made a
    // 9-digit NIPC as wide as a company name while the name itself clipped.
    const sized = [
      ['Nipc', '--ec-nipc'],
      ['Seat', '--ec-seat'],
      ['Type', '--ec-type'],
      ['Matricula', '--ec-matricula'],
      ['Constitution', '--ec-constitution'],
      ['Capital', '--ec-capital'],
      ['Cae', '--ec-cae'],
      ['Registry', '--ec-registry'],
      ['LastRegistryChange', '--ec-last-registry-change'],
      ['FiscalYearEnd', '--ec-fiscal-year-end'],
      ['LastBook', '--ec-last-book'],
      ['LastActivity', '--ec-last-activity'],
      ['Actions', '--ec-actions'],
    ] as const;
    for (const [column, token] of sized) {
      const rule =
        css.match(
          new RegExp(`\\.table th\\[data-entity-column='${column}'\\]\\s*{(?<body>[^}]*)}`, 's'),
        )?.groups?.body ?? '';
      expect(rule, column).toContain(`width: var(${token});`);
      // Relative units only — a pixel width would not track the user's text size.
      expect(css, token).toMatch(new RegExp(`${token}:\\s*[\\d.]+rem;`));
    }

    // `Name` must stay `auto`: it is the single column that absorbs the leftover width.
    expect(css).not.toMatch(/\.table th\[data-entity-column='Name'\]\s*{[^}]*width:/s);

    // The floor is composed from the same tokens for whichever columns are visible, so a
    // wide set scrolls at its natural size instead of collapsing.
    const tableRule = css.match(/\.entities-table \.table\s*{(?<body>[^}]*)}/s)?.groups?.body ?? '';
    expect(tableRule).toContain('table-layout: fixed;');
    expect(tableRule).toContain('min-width: var(--entities-table-floor, 0);');

    // A NIPC is never half-shown: the flag wraps beneath it rather than clipping either.
    const nipcRule = css.match(/\.entity-cell-line--nipc\s*{(?<body>[^}]*)}/s)?.groups?.body ?? '';
    expect(nipcRule).toContain('flex-wrap: wrap;');
    // …and the fixed-width date in Última atividade outlives its unbounded event label.
    const activityDateRule =
      css.match(/\.entity-cell-line--activity \.entity-cell-line__text\s*{(?<body>[^}]*)}/s)?.groups
        ?.body ?? '';
    expect(activityDateRule).toContain('flex: 0 0 auto;');
  });

  it('keeps Última atividade and Ações wide enough for what they actually hold', async () => {
    const css = await themeCss();

    // Measured in headless Chromium against this stylesheet, at 1920/1440/1280 and with
    // every locale's labels — see .orchestration/logs/t98-entitycolwidths.md. These two
    // numbers are the answer to a measurement, not a preference, so pin them:
    //
    //  --ec-last-activity  the cell is a dd/mm/aaaa date (79px, `flex: 0 0 auto`) + a
    //    7px gap + 19px of cell padding + the event badge. 13rem left the badge 103px,
    //    which fitted 2 of the 134 pt-PT event labels; 17rem leaves it 167px and fits 43.
    //    It cannot go higher: 17rem already puts the default five-column floor at 888px
    //    against the 900px the card offers at a 1024 viewport.
    //
    //  --ec-actions  one 31px icon button always fitted; the COLUMN HEADING did not.
    //    da-DK "Handlinger" needs 101px, fi-FI "Toiminnot" 92, de-DE "Aktionen" 84, and
    //    pt-PT "Ações" 60 — all clipped at 3.6rem/58px. 6.5rem clears the widest.
    expect(css).toContain('--ec-last-activity: 17rem;');
    expect(css).toContain('--ec-actions: 6.5rem;');

    // The two widened columns must not become elastic — `Name` stays the sole slack
    // absorber, which is the whole reason the layout is predictable (see the test above).
    expect(css).toMatch(
      /\.table th\[data-entity-column='LastActivity'\]\s*{[^}]*width: var\(--ec-last-activity\);/s,
    );
    expect(css).toMatch(
      /\.table th\[data-entity-column='Actions'\]\s*{[^}]*width: var\(--ec-actions\);/s,
    );

    // The composed floor still sums the same tokens, so widening a column raises the
    // floor rather than silently letting the table crush below it.
    expect(css).toContain('min-width: var(--entities-table-floor, 0);');
    // …and a set too wide for the card scrolls inside its own box, never the page.
    const wrapRule = css.match(/\.entities-table \.table-wrap\s*{(?<body>[^}]*)}/s)?.groups?.body;
    expect(wrapRule).toContain('overflow-x: auto;');
  });

  it('composes the table width floor from the visible columns', async () => {
    vi.stubGlobal(
      'fetch',
      fetchTable([
        { match: '/v1/settings', body: DEFAULT_SETTINGS },
        { match: '/v1/entities', body: [ENTITY] },
      ]),
    );
    renderWithProviders(<EntitiesPage />, ['/entities']);
    const table = await screen.findByRole('table');
    const box = table.closest('.entities-table') as HTMLElement;
    // The default column set (Name, Nipc, Type, LastActivity, Actions) — the floor names
    // exactly those tokens, so the table never shrinks below the sum of its own columns.
    expect(box.style.getPropertyValue('--entities-table-floor')).toBe(
      'calc(var(--ec-name) + var(--ec-nipc) + var(--ec-type) + var(--ec-last-activity) + var(--ec-actions))',
    );
  });

  it('opts the entity list out of the shell prose measure so the columns get the room', async () => {
    vi.stubGlobal(
      'fetch',
      fetchTable([
        { match: '/v1/settings', body: DEFAULT_SETTINGS },
        { match: '/v1/entities', body: [ENTITY] },
      ]),
    );
    renderWithProviders(<EntitiesPage />, ['/entities']);
    await screen.findByRole('table');
    // The page root carries the opt-in; the width itself is a CSS concern jsdom cannot lay out.
    expect(document.querySelector('.wide-page')).toBeTruthy();

    const css = await themeCss();
    // The shell measure still applies by default — the opt-out is a separate rule, not a
    // relaxation of `.app` that every prose page would inherit.
    const appRule = css.match(/\.app\s*{(?<body>[^}]*)}/s)?.groups?.body ?? '';
    // t18 named the two shell measures + the gutter as custom props on `.app`; the measure,
    // gutter and wide cap are asserted through those vars (the literals live on the decls).
    expect(appRule).toContain('--app-measure: 1080px;');
    expect(appRule).toContain('max-width: var(--app-measure);');
    // The gutters are the shell's own padding, so widening must not have dropped it.
    expect(appRule).toContain('--app-gutter: clamp(1.25rem, 4vw, 3rem);');
    expect(appRule).toContain('padding: var(--app-gutter);');
    const wideRule = css.match(/\.app:has\(\.wide-page\)\s*{(?<body>[^}]*)}/s)?.groups?.body ?? '';
    expect(appRule).toContain('--app-measure-wide: 92rem;');
    expect(wideRule).toContain('max-width: var(--app-measure-wide);');

    // The wider measure must reach the table as slack for `Name`, not as a new floor: the
    // composed floor stays the sum of the visible columns so a wide set still scrolls.
    const tableRule = css.match(/\.entities-table \.table\s*{(?<body>[^}]*)}/s)?.groups?.body ?? '';
    expect(tableRule).toContain('min-width: var(--entities-table-floor, 0);');
    expect(css).not.toMatch(/\.table th\[data-entity-column='Name'\]\s*{[^}]*width:/s);
  });

  it('pins entity table and filter CSS to single-line no-overflow rules', async () => {
    const css = await themeCss();
    const filterRule = css.match(/\.entities-filters\s*{(?<body>[^}]*)}/s)?.groups?.body ?? '';
    const filterbarRule = css.match(/\.entities-filterbar\s*{(?<body>[^}]*)}/s)?.groups?.body ?? '';
    const primaryRule =
      css.match(/\.entities-filterbar__primary\s*{(?<body>[^}]*)}/s)?.groups?.body ?? '';
    const primaryFieldRule =
      css.match(/\.entities-filterbar__primary \.field\s*{(?<body>[^}]*)}/s)?.groups?.body ?? '';
    const advancedRule =
      css.match(/\.entities-advanced-filters\s*{(?<body>[^}]*)}/s)?.groups?.body ?? '';
    const advancedBodyRule =
      css.match(/\.entities-advanced-filters__body\s*{(?<body>[^}]*)}/s)?.groups?.body ?? '';
    const mobilePrimaryRule =
      css.match(
        /@media\s*\(max-width:\s*720px\)\s*{\s*\.entities-filterbar__primary\s*{(?<body>[^}]*)}/s,
      )?.groups?.body ?? '';
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
    expect(primaryRule).toContain('flex-wrap: nowrap;');
    expect(primaryFieldRule).toContain('min-width: 0;');
    expect(mobilePrimaryRule).toContain('flex-wrap: wrap;');
    expect(advancedRule).toContain('overflow-x: clip;');
    expect(advancedBodyRule).toContain(
      'grid-template-columns: repeat(auto-fit, minmax(min(100%, 12rem), 1fr));',
    );
    expect(advancedBodyRule).toContain('min-width: 0;');
    expect(filterButtonRule).toContain('max-width: 100%;');
    expect(filterButtonRule).toContain('overflow: hidden;');
    // The wrap SCROLLS rather than clips (t72): a column set wider than the card used to
    // be crushed to equal stubs and then hidden, which lost content outright. It is the
    // `.entities-table` box outside it that stays clipped to the card.
    expect(tableWrapRule).toContain('overflow-x: auto;');
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
    renderWithProviders(<EntitiesPage />, ['/entities']);

    const name = await screen.findByText(longEntity.name);
    expect(name.className).toContain('truncate');
    // t31: the name is clipped by CSS, not abbreviated, so it stays complete in the DOM (the
    // themed tooltip de-truncates it visually in place of the old unstyleable `title`).
    expect(name.textContent).toBe(longEntity.name);

    const row = name.closest('tr') as HTMLElement;
    const cells = within(row).getAllByRole('cell');
    expect(cells).toHaveLength(5);
    for (const cell of cells.slice(0, 4)) {
      expect(cell.className).toContain('entities-table__cell--truncate');
      const singleLine = cell.querySelector('.truncate, .entity-cell-line');
      expect(singleLine).toBeTruthy();
      // Each line conveys its value either on screen or through the themed tooltip.
      expect(singleLine?.textContent || describedText(singleLine)).toBeTruthy();
    }
    expect(cells[4].className).toContain('entities-table__cell--actions');
    expect(cells[4].className).not.toContain('entities-table__cell--truncate');
    expect(within(cells[4]).getByRole('button', { name: 'Abrir' })).toBeTruthy();

    const typeLine = cells[2].querySelector('.entity-cell-line');
    expect(typeLine?.textContent).toBe('Lda.');
    expect(typeLine?.className).toContain('entity-cell-line--compact');
    expect(typeLine?.textContent).not.toContain('Sociedade por Quotas');
    expect(typeLine?.textContent).not.toContain('Regras');
    expect(describedText(typeLine)).toContain('Sociedade por Quotas');
    expect(describedText(typeLine)).toContain('Regras csc-art63/v2');

    const activityLine = cells[3].querySelector('.entity-cell-line');
    expect(activityLine?.className).toContain('entity-cell-line--compact');
    expect(activityLine?.textContent).not.toContain(activity.actor);
    expect(activityLine?.textContent).not.toContain('10:15');
    expect(describedText(activityLine)).toContain('Entidade criada');
    expect(describedText(activityLine)).toContain(activity.actor);
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
        <Route path="/entities" element={<EntitiesPage />} />
        <Route path="/entities/:id" element={<div>DETALHE DA ENTIDADE</div>} />
      </Routes>,
      ['/entities'],
    );

    // The open control is an icon-only button named by its tooltip (no visible link text).
    const open = await screen.findByRole('button', { name: 'Abrir' });
    expect(screen.queryByRole('link', { name: 'Abrir' })).toBeNull();
    fireEvent.click(open);
    expect(await screen.findByText('DETALHE DA ENTIDADE')).toBeTruthy();
  });

  it('makes the entity name a client-side link straight to its detail page', async () => {
    vi.stubGlobal(
      'fetch',
      fetchTable([
        { match: '/v1/settings', body: DEFAULT_SETTINGS },
        { match: '/v1/entities', body: [ENTITY] },
      ]),
    );
    renderWithProviders(
      <Routes>
        <Route path="/entities" element={<EntitiesPage />} />
        <Route path="/entities/:id" element={<div>DETALHE DA ENTIDADE</div>} />
      </Routes>,
      ['/entities'],
    );

    // The name is a real router link, not plain truncated text, and points at the detail route.
    const nameLink = await screen.findByRole('link', { name: ENTITY.name });
    expect(nameLink.getAttribute('href')).toBe(`/entities/${ENTITY.id}`);
    expect(nameLink.className).toContain('truncate');

    // Clicking it navigates in-app (SPA) to the detail page — the Actions "Abrir" button remains too.
    expect(screen.getByRole('button', { name: 'Abrir' })).toBeTruthy();
    fireEvent.click(nameLink);
    expect(await screen.findByText('DETALHE DA ENTIDADE')).toBeTruthy();
  });
});

describe('NewEntityPage', () => {
  it('adds inline help to core entity identity fields', () => {
    vi.stubGlobal('fetch', fetchTable([]));
    renderWithProviders(<NewEntityPage />, ['/entities/new']);

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
        <Route path="/entities/new" element={<NewEntityPage />} />
        <Route path="/entities/:id" element={<div>DETALHE DA ENTIDADE</div>} />
      </Routes>,
      ['/entities/new'],
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
        <Route path="/entities/new" element={<NewEntityPage />} />
        <Route path="/entities/:id" element={<div>DETALHE DA ENTIDADE</div>} />
      </Routes>,
      ['/entities/new'],
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

    renderWithProviders(<NewEntityPage />, ['/entities/new']);

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
        <Route path="/entities/new" element={<NewEntityPage />} />
        <Route path="/entities/:id" element={<div>DETALHE DA ENTIDADE</div>} />
      </Routes>,
      ['/entities/new'],
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
        <Route path="/entities/:id/:sec?" element={<EntityDetailPage />} />
      </Routes>,
      ['/entities/new-ent-1/identification'],
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
        <Route path="/entities/:id/:sec?" element={<EntityDetailPage />} />
      </Routes>,
      ['/entities/new-ent-1/fiscal'],
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
        <Route path="/entities/:id/:sec?" element={<EntityDetailPage />} />
      </Routes>,
      ['/entities/new-ent-1/fiscal'],
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
              {
                date: null,
                kind: 'RegistryNote',
                description: 'Averbamento sem data normalizada',
                source_inscription: '2',
                actors: [],
              },
            ],
            mermaid: {
              shareholders:
                'graph LR\n  Entidade[Encosto Estratégico]\n  Maria[Maria Silva]\n  Entidade -->|"Quota EUR 5000"| Maria',
              organs: 'timeline\n  2020 : Gerência',
              relationships: 'graph LR\n  Entidade[Encosto Estratégico] --> Registo[Certidão]',
            },
            graph: {
              shareholders: {
                nodes: [
                  {
                    id: 'entity',
                    label: 'Encosto Estratégico',
                    kind: 'entity',
                    category: null,
                    source_inscription: null,
                    source_date: null,
                  },
                  {
                    id: 'actor-maria',
                    label: 'Maria Silva',
                    kind: 'actor',
                    category: 'shareholder',
                    source_inscription: '1',
                    source_date: '2020-01-01',
                  },
                ],
                edges: [
                  {
                    id: 'quota-1',
                    from: 'entity',
                    to: 'actor-maria',
                    label: 'Quota EUR 5000',
                    kind: 'quota',
                    source_inscription: '1',
                    source_date: '2020-01-01',
                  },
                ],
                warnings: [],
              },
              organs: {
                nodes: [
                  {
                    id: 'entity',
                    label: 'Encosto Estratégico',
                    kind: 'entity',
                    category: null,
                    source_inscription: null,
                    source_date: null,
                  },
                ],
                edges: [],
                warnings: [],
              },
              relationships: {
                nodes: [
                  {
                    id: 'entity',
                    label: 'Encosto Estratégico',
                    kind: 'entity',
                    category: null,
                    source_inscription: null,
                    source_date: null,
                  },
                ],
                edges: [],
                warnings: ['No structured relationship evidence in the imported extract.'],
              },
            },
            analytics: {
              total_events: 2,
              dated_events: 1,
              undated_events: 1,
              event_kinds: [
                { kind: 'Constitution', count: 1 },
                { kind: 'RegistryNote', count: 1 },
              ],
              source_inscription_count: 2,
              source_inscriptions: ['1', '2'],
              graph: {
                shareholders: { nodes: 2, edges: 1, warnings: 0 },
                organs: { nodes: 1, edges: 0, warnings: 0 },
                relationships: { nodes: 1, edges: 0, warnings: 1 },
              },
            },
            sealed_act_projection: {
              events: [
                {
                  date: '2026-03-01',
                  kind: 'SealedAct',
                  description: 'Sealed ata n.º 1: Deliberação original',
                  act_id: 'act-original',
                  book_id: 'book-1',
                  ata_number: 1,
                  act_state: 'Sealed',
                  source: {
                    kind: 'sealed_act',
                    act_id: 'act-original',
                    book_id: 'book-1',
                    ata_number: 1,
                    payload_digest: 'a'.repeat(64),
                    seal_event_seq: 21,
                  },
                },
                {
                  date: '2026-03-02',
                  kind: 'Correction',
                  description: 'Ata n.º 2 rectifies act act-original',
                  act_id: 'act-correction',
                  book_id: 'book-1',
                  ata_number: 2,
                  act_state: 'Sealed',
                  source: {
                    kind: 'sealed_act',
                    act_id: 'act-correction',
                    book_id: 'book-1',
                    ata_number: 2,
                    payload_digest: 'b'.repeat(64),
                    seal_event_seq: 22,
                  },
                },
              ],
              graph: {
                nodes: [
                  {
                    id: 'act:act-original',
                    label: 'Ata n.º 1',
                    kind: 'sealed_act',
                    source: {
                      kind: 'sealed_act',
                      act_id: 'act-original',
                      book_id: 'book-1',
                      ata_number: 1,
                      payload_digest: 'a'.repeat(64),
                      seal_event_seq: 21,
                    },
                  },
                  {
                    id: 'act:act-correction',
                    label: 'Ata n.º 2',
                    kind: 'sealed_act',
                    source: {
                      kind: 'sealed_act',
                      act_id: 'act-correction',
                      book_id: 'book-1',
                      ata_number: 2,
                      payload_digest: 'b'.repeat(64),
                      seal_event_seq: 22,
                    },
                  },
                ],
                edges: [
                  {
                    id: 'correction:act-correction:act-original',
                    from: 'act:act-correction',
                    to: 'act:act-original',
                    label: 'retifies',
                    kind: 'correction',
                    source: {
                      kind: 'sealed_act',
                      act_id: 'act-correction',
                      book_id: 'book-1',
                      ata_number: 2,
                      payload_digest: 'b'.repeat(64),
                      seal_event_seq: 22,
                    },
                  },
                ],
              },
              provenance: [
                {
                  kind: 'sealed_act',
                  act_id: 'act-original',
                  book_id: 'book-1',
                  ata_number: 1,
                  payload_digest: 'a'.repeat(64),
                  seal_event_seq: 21,
                },
                {
                  kind: 'sealed_act',
                  act_id: 'act-correction',
                  book_id: 'book-1',
                  ata_number: 2,
                  payload_digest: 'b'.repeat(64),
                  seal_event_seq: 22,
                },
              ],
              legal_validity_claimed: false,
              authority_certified_claimed: false,
            },
          }),
        );
      }
      return fn(input, init);
    }) as typeof fetch);

    const { container } = renderWithProviders(
      <Routes>
        <Route path="/entities/:id/:sec?" element={<EntityDetailPage />} />
      </Routes>,
      ['/entities/new-ent-1/chronology'],
    );

    // Twice: the sub-nav pill and the card it heads.
    expect((await screen.findAllByText('Cronologia e grafo')).length).toBe(2);
    expect((await screen.findAllByText('Constituição de sociedade')).length).toBeGreaterThan(1);
    expect(screen.getAllByText('Maria Silva').length).toBeGreaterThan(1);
    expect(screen.getAllByText('Insc. 1').length).toBeGreaterThan(1);
    const railItems = container.querySelectorAll('.chronology-rail__item');
    expect(railItems).toHaveLength(2);
    expect(railItems[0]?.textContent).toContain('1');
    expect(railItems[0]?.textContent).toContain('Constitution');
    expect(railItems[1]?.textContent).toContain('Averbamento sem data normalizada');
    expect(railItems[1]?.textContent).toContain('—');
    expect(railItems[1]?.textContent).toContain('Insc. 2');
    const pathRows = [...container.querySelectorAll('.chronology-paths li')].map(
      (row) => row.textContent ?? '',
    );
    expect(pathRows).toContain('Encosto Estratégico->Maria Silva (Quota EUR 5000)');
    expect(pathRows).toContain('2020->Gerência');
    expect(pathRows).toContain('Encosto Estratégico->Certidão');
    const analytics = screen.getByLabelText('Resumo analítico local');
    expect(analytics.textContent).toContain('Eventos');
    expect(analytics.textContent).toContain('Com data');
    expect(analytics.textContent).toContain('Sem data');
    expect(analytics.textContent).toContain('Inscrições fonte');
    expect(analytics.textContent).toContain('Constitution: 1');
    expect(analytics.textContent).toContain('RegistryNote: 1');
    expect(analytics.textContent).toContain('Insc. 1, Insc. 2');
    expect(analytics.textContent).toContain('Sócios e quotas: 2 nós / 1 ligações / 0 avisos');
    expect(analytics.textContent).toContain('Relações: 1 nós / 0 ligações / 1 avisos');
    expect(analytics.textContent).toContain('não certificam prioridade');
    expect(analytics.textContent).toContain('validade jurídica');
    expect(analytics.textContent).toContain('aprovação de autoridade');
    const sealedProjection = screen.getByLabelText('Cronologia local de atos selados');
    expect(sealedProjection.textContent).toContain('Eventos locais');
    expect(sealedProjection.textContent).toContain('Fontes seladas');
    expect(sealedProjection.textContent).toContain('SealedAct');
    expect(sealedProjection.textContent).toContain('Correction');
    expect(sealedProjection.textContent).toContain('ata 2 · seq 22');
    expect(sealedProjection.textContent).toContain('correction');
    expect(sealedProjection.textContent).toContain('Não reclama validade jurídica');
    expect(
      (screen.getByLabelText('Código Mermaid: Sócios e quotas') as HTMLTextAreaElement).value,
    ).toContain('Entidade -->|"Quota EUR 5000"| Maria');
    expect(
      (screen.getByLabelText('Código Mermaid: Órgãos sociais') as HTMLTextAreaElement).value,
    ).toContain('timeline');
    expect(urls.some((url) => url.includes(`/v1/entities/${ENTITY.id}/chronology`))).toBe(true);
    expect(calls.some((c) => c.url.includes('/chronology'))).toBe(false);
  });
});

/**
 * The entity detail sub-tabs (t62): the seventh surface on the shared `<SubNav>` + path-segment
 * convention. These pin the deep-link contract, the fact that every pre-existing action
 * still has a home, and that the sparse sections tell the truth instead of inventing content.
 */
describe('EntityDetailPage — sub-tabs', () => {
  const SUBNAV = 'Secções da entidade';
  const TAB_LABELS = [
    'Livros',
    'Identificação',
    'Exercício fiscal',
    'Registo comercial',
    'Inscrições e averbamentos',
    'Cronologia e grafo',
  ];

  /**
   * Renders the router's live query string and the last navigation type, so both halves of
   * the deep-link contract are assertable: the URL carries the tab, and reaching it PUSHED
   * a history entry (MemoryRouter keeps its own history, so `window.history.back()` cannot
   * be used to probe it).
   */
  // The sub-tab is a path segment now, so the probe reports the pathname.
  function SearchProbe() {
    return (
      <>
        <span data-testid="search-probe">{useLocation().pathname}</span>
        <span data-testid="navtype-probe">{useNavigationType()}</span>
      </>
    );
  }

  /**
   * The active tab panel. Queries are scoped to it because `EntityPrintDocument` renders the
   * same firma, NIPC, sede and "Dados do registo" heading into a portaled print-only sheet.
   */
  function panel() {
    const el = document.querySelector('.route-transition');
    if (!el) throw new Error('no tab panel rendered');
    return within(el as HTMLElement);
  }

  const EXTRACT: RegistryExtractView = {
    matricula: '503004642',
    nipc: '503004642',
    firma: 'Encosto Estratégico, Lda.',
    forma_juridica: 'Sociedade por quotas',
    legal_form: 'SociedadePorQuotas',
    sede: 'Rua das Amoreiras 1, Lisboa',
    cae: [],
    objeto: 'Consultoria de gestão',
    capital: 'EUR 5.000,00',
    data_constituicao: '2019-04-02',
    orgaos: [
      {
        name: 'Amélia Marques',
        role: 'Gerente',
        appointment_date: '2019-04-02',
        cessation_date: null,
        source_event: '1',
      },
    ],
    inscricoes: [
      {
        number: 'AP. 1/20190402',
        kind_hint: 'Constituição',
        apresentacao: 'Ap. 1/20190402',
        date: '2019-04-02',
        text: 'Constituição de sociedade por quotas.',
        detail: null,
      },
    ],
    anotacoes: [],
    provenance: {
      access_code_masked: '1234-****-9012',
      retrieved_at: '2026-07-01T10:00:00Z',
      source_url: 'https://eportugal.gov.pt/certidao',
      raw_digest: 'c'.repeat(64),
      conservatoria: 'Conservatória do Registo Comercial de Lisboa',
      oficial: 'Ana Costa',
      subscribed_on: '2026-06-30',
      valid_until: '2026-12-30',
      expired: false,
    },
  };

  /** The page's stub, optionally serving a real certidão instead of the 404 empty state. */
  function detailFetch(extract?: RegistryExtractView) {
    const base = entityDetailFetch(ENTITY);
    if (!extract) return base;
    const fn = ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.includes(`/v1/entities/${ENTITY.id}/registry`)) {
        return Promise.resolve(jsonResponse(extract));
      }
      return base.fn(input, init);
    }) as typeof fetch;
    return { fn, calls: base.calls };
  }

  function renderAtEntity(entry = '/entities/new-ent-1') {
    return renderWithProviders(
      <Routes>
        <Route path="/entities/:id/:sec?" element={<EntityDetailPage />} />
      </Routes>,
      [entry],
    );
  }

  it('reuses the shared SubNav pill with the six sections in the requested order', async () => {
    vi.stubGlobal('fetch', detailFetch().fn);
    renderAtEntity();

    const subnav = await screen.findByRole('group', { name: SUBNAV });
    expect(
      within(subnav)
        .getAllByRole('button')
        .map((b) => b.textContent),
    ).toEqual(TAB_LABELS);
  });

  it('lands on Livros with no section segment, and marks only that tab pressed', async () => {
    vi.stubGlobal('fetch', detailFetch().fn);
    renderAtEntity();

    const subnav = await screen.findByRole('group', { name: SUBNAV });
    expect(
      within(subnav).getByRole('button', { name: 'Livros' }).getAttribute('aria-pressed'),
    ).toBe('true');
    for (const label of TAB_LABELS.slice(1)) {
      expect(within(subnav).getByRole('button', { name: label }).getAttribute('aria-pressed')).toBe(
        'false',
      );
    }
    // The "Abrir livro" action survived the reorganisation.
    expect(screen.getByRole('link', { name: /abrir livro/i })).toBeTruthy();
  });

  it('reflects the chosen tab in the URL as a path segment and PUSHES it so Back returns to it', async () => {
    vi.stubGlobal('fetch', detailFetch().fn);
    // MemoryRouter keeps history in memory, so a sibling probe reports the live search.
    render(
      <QueryClientProvider client={makeClient()}>
        <ToastProvider>
          <StaticPermissionsProvider value={ALLOW_ALL_PERMISSIONS}>
            <MemoryRouter initialEntries={['/entities/new-ent-1']}>
              <SearchProbe />
              <Routes>
                <Route path="/entities/:id/:sec?" element={<EntityDetailPage />} />
              </Routes>
            </MemoryRouter>
          </StaticPermissionsProvider>
        </ToastProvider>
      </QueryClientProvider>,
    );

    const subnav = await screen.findByRole('group', { name: SUBNAV });
    expect(screen.getByTestId('search-probe').textContent).toBe('/entities/new-ent-1');

    fireEvent.click(within(subnav).getByRole('button', { name: 'Exercício fiscal' }));
    await waitFor(() =>
      expect(screen.getByTestId('search-probe').textContent).toBe('/entities/new-ent-1/fiscal'),
    );

    // Each tab is a PUSH, so browser Back returns to the previous tab rather than leaving the
    // entity — the trap t34 had to undo in the legislação reader, where `replace: true`
    // destroyed the history entry.
    expect(screen.getByTestId('navtype-probe').textContent).toBe('PUSH');
    expect(panel().getByLabelText('Fecho do exercício (MM-DD)')).toBeTruthy();

    fireEvent.click(within(subnav).getByRole('button', { name: 'Registo comercial' }));
    await waitFor(() =>
      expect(screen.getByTestId('search-probe').textContent).toBe('/entities/new-ent-1/registry'),
    );
    expect(screen.getByTestId('navtype-probe').textContent).toBe('PUSH');

    // Back to the default section drops the segment rather than writing `.../books`.
    fireEvent.click(within(subnav).getByRole('button', { name: 'Livros' }));
    await waitFor(() =>
      expect(screen.getByTestId('search-probe').textContent).toBe('/entities/new-ent-1'),
    );
  });

  it('deep-links straight into Identificação, which also carries the statute overlay', async () => {
    vi.stubGlobal('fetch', detailFetch().fn);
    renderAtEntity('/entities/new-ent-1/identification');

    expect(await screen.findByRole('group', { name: SUBNAV })).toBeTruthy();
    expect(panel().getByText('503004642')).toBeTruthy();
    expect(panel().getByText('Lisboa')).toBeTruthy();
    // Estatutos has no tab of its own; it belongs to "what this entity is".
    expect(panel().getByText('Estatutos')).toBeTruthy();
    expect(panel().queryByLabelText('Fecho do exercício (MM-DD)')).toBeNull();
  });

  it('deep-links straight into Registo comercial with the import action and the registry payload', async () => {
    vi.stubGlobal('fetch', detailFetch(EXTRACT).fn);
    renderAtEntity('/entities/new-ent-1/registry');

    await waitFor(() => expect(panel().getByText('Dados do registo')).toBeTruthy());
    expect(panel().getByText('Conservatória do Registo Comercial de Lisboa')).toBeTruthy();
    expect(panel().getByText('Órgãos sociais')).toBeTruthy();
    // The certidão import action survived the reorganisation.
    expect(panel().getByRole('link', { name: /importar do registo/i })).toBeTruthy();
    // The event feed is the NEXT tab, not this one.
    expect(panel().queryByText('Inscrições, averbamentos e anotações')).toBeNull();
  });

  it('deep-links straight into Inscrições e averbamentos, keeping anotações beside them', async () => {
    vi.stubGlobal('fetch', detailFetch(EXTRACT).fn);
    renderAtEntity('/entities/new-ent-1/filings');

    await waitFor(() =>
      expect(panel().getByText('Inscrições, averbamentos e anotações')).toBeTruthy(),
    );
    expect(panel().getByText('Constituição de sociedade por quotas.')).toBeTruthy();
    // Anotações is a named section, so an empty one says so rather than vanishing.
    expect(panel().getByText('Anotações')).toBeTruthy();
    expect(panel().getByText('A certidão não continha anotações.')).toBeTruthy();
    expect(panel().queryByText('Dados do registo')).toBeNull();
  });

  it('renders an honest empty state on both registry tabs when nothing was imported', async () => {
    vi.stubGlobal('fetch', detailFetch().fn);
    const { unmount } = renderAtEntity('/entities/new-ent-1/registry');
    expect(await screen.findByText('Sem dados do registo')).toBeTruthy();
    unmount();

    renderAtEntity('/entities/new-ent-1/filings');
    expect(await screen.findByText('Sem dados do registo')).toBeTruthy();
  });

  it('lets the Cronologia tab look as sparse as the parser actually left it', async () => {
    vi.stubGlobal('fetch', detailFetch().fn);
    renderAtEntity('/entities/new-ent-1/chronology');

    // The certidão parser extracts almost nothing today, so a 404 chronology is the honest
    // answer. No invented timeline, no placeholder graph.
    expect(await screen.findByText('Sem cronologia')).toBeTruthy();
    expect(document.querySelector('.chronology-rail__item')).toBeNull();
  });

  it('widens the Livros panel only, on a tab switch as well as a deep link', async () => {
    vi.stubGlobal('fetch', detailFetch().fn);
    renderAtEntity();

    // Arquivo's pattern: `wide-page` rides on the PANEL, so the measure follows the mounted
    // sub-tab. Livros is a six-column table; the other five are prose-shaped.
    const panel = () => document.querySelector('.route-transition');
    await screen.findByRole('link', { name: /abrir livro/i });
    expect(panel()?.classList.contains('wide-page')).toBe(true);

    const tab = async (label: string) =>
      within(await screen.findByRole('group', { name: SUBNAV })).getByRole('button', {
        name: label,
      });

    fireEvent.click(await tab('Identificação'));
    await waitFor(() => expect(panel()?.classList.contains('wide-page')).toBe(false));

    fireEvent.click(await tab('Cronologia e grafo'));
    await waitFor(() => expect(panel()?.classList.contains('wide-page')).toBe(false));

    fireEvent.click(await tab('Livros'));
    await waitFor(() => expect(panel()?.classList.contains('wide-page')).toBe(true));
  });

  it('gets the panel width right on a deep link, not only after a tab switch', async () => {
    vi.stubGlobal('fetch', detailFetch().fn);
    const { unmount } = renderAtEntity('/entities/new-ent-1/identification');
    // The loading skeleton also renders an "Identificação" card, so wait on the sub-nav —
    // it only exists once the entity has resolved and the real panel is mounted.
    await screen.findByRole('group', { name: SUBNAV });
    expect(document.querySelector('.route-transition')?.classList.contains('wide-page')).toBe(
      false,
    );
    unmount();

    vi.stubGlobal('fetch', detailFetch().fn);
    renderAtEntity('/entities/new-ent-1/books');
    await screen.findByRole('link', { name: /abrir livro/i });
    expect(document.querySelector('.route-transition')?.classList.contains('wide-page')).toBe(true);
  });

  it('falls back to Livros for an unknown sec value rather than rendering nothing', async () => {
    vi.stubGlobal('fetch', detailFetch().fn);
    renderAtEntity('/entities/new-ent-1/inventado');

    const subnav = await screen.findByRole('group', { name: SUBNAV });
    expect(
      within(subnav).getByRole('button', { name: 'Livros' }).getAttribute('aria-pressed'),
    ).toBe('true');
    expect(screen.getByRole('link', { name: /abrir livro/i })).toBeTruthy();
  });

  it('withholds the book list with a permission note instead of firing a request that would 403', async () => {
    // `GET /v1/books` is gated `book.read@Global`; a principal with only `entity.read` on this
    // entity must see why the list is missing, not a 403 in the console.
    const { fn, calls } = detailFetch();
    vi.stubGlobal('fetch', fn);
    render(
      <QueryClientProvider client={makeClient()}>
        <ToastProvider>
          <StaticPermissionsProvider
            value={{
              can: (perm: string) => perm !== 'book.read',
              canAny: (perm: string) => perm !== 'book.read',
              grants: [],
              ready: true,
            }}
          >
            <MemoryRouter initialEntries={['/entities/new-ent-1']}>
              <Routes>
                <Route path="/entities/:id/:sec?" element={<EntityDetailPage />} />
              </Routes>
            </MemoryRouter>
          </StaticPermissionsProvider>
        </ToastProvider>
      </QueryClientProvider>,
    );

    expect(await screen.findByText('Sem permissão')).toBeTruthy();
    await waitFor(() => expect(calls.some((c) => c.url.includes('/v1/entities/'))).toBe(true));
    expect(calls.some((c) => c.url.includes('/v1/books'))).toBe(false);
  });

  it('keeps the print abstract mounted from any tab', async () => {
    vi.stubGlobal('fetch', detailFetch().fn);
    renderAtEntity('/entities/new-ent-1/chronology');

    expect(await screen.findByRole('button', { name: /imprimir/i })).toBeTruthy();
    await waitFor(() => expect(document.querySelector('.print-doc')).toBeTruthy());
  });
});
