import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react';
import { Route, Routes } from 'react-router-dom';
import { renderWithProviders, fetchTable } from '../../test/utils';
import { EntitiesPage } from './EntitiesPage';
import { NewEntityPage } from './NewEntityPage';
import { EntityDetailPage } from './EntityDetailPage';
import { entityFieldHelp } from './fieldHelp';
import { DEFAULT_SETTINGS, type Entity } from '../../api/types';

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
});
