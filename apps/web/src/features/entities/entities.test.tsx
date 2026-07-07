import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen } from '@testing-library/react';
import { Route, Routes } from 'react-router-dom';
import { renderWithProviders, fetchTable } from '../../test/utils';
import { EntitiesPage } from './EntitiesPage';
import { NewEntityPage } from './NewEntityPage';
import type { Entity } from '../../api/types';

const ENTITY: Entity = {
  id: 'new-ent-1',
  name: 'Encosto Estratégico, Lda.',
  nipc: '503004642',
  nipc_validated: true,
  seat: 'Lisboa',
  family: 'CommercialCompany',
  kind: 'SociedadePorQuotas',
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

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('EntitiesPage', () => {
  it('offers neat buttons to the create/import routes instead of an inline form', async () => {
    vi.stubGlobal('fetch', fetchTable([{ match: '/v1/entities', body: [] }]));
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
    vi.stubGlobal('fetch', fetchTable([{ match: '/v1/entities', body: [unvalidated] }]));
    renderWithProviders(<EntitiesPage />, ['/entidades']);

    expect(await screen.findByText('GB-12345')).toBeTruthy();
    expect(screen.getByText('não validado')).toBeTruthy();
  });
});

describe('NewEntityPage', () => {
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

    const post = calls.find((c) => c.url.includes('/v1/entities'));
    expect((post?.body as { nipc?: string })?.nipc).toBe('503004642');
    // Strict by default: the override flag is false when the tickbox is untouched.
    expect((post?.body as { allow_invalid_nipc?: boolean })?.allow_invalid_nipc).toBe(false);
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
