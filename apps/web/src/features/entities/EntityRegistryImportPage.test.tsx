/**
 * Unit tests for EntityRegistryImportPage (enrich-an-entity route). The page is a thin
 * wrapper that fetches the entity for its crumb/title and mounts RegistryImportPanel, so
 * these tests drive the wrapper AND the panel's mutating submit through the shared
 * conventions: submit gated on the código + pending label in flight (§5), inline error
 * + toast on failure (§2/§7) and the success report + toast.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react';
import { Route, Routes } from 'react-router-dom';
import { renderWithProviders } from '../../test/utils';
import { EntityRegistryImportPage } from './EntityRegistryImportPage';
import type { Entity, RegistryExtractView, RegistryImportReport } from '../../api/types';

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
  },
  statute: null,
};

const EXTRACT: RegistryExtractView = {
  matricula: '12345',
  nipc: '503004642',
  firma: 'Encosto Estratégico, Lda.',
  forma_juridica: 'Sociedade por Quotas',
  legal_form: 'SociedadePorQuotas',
  sede: 'Lisboa',
  cae: [],
  objeto: null,
  capital: null,
  data_constituicao: null,
  orgaos: [],
  inscricoes: [],
  anotacoes: [],
  provenance: {
    access_code_masked: '1234-****-9012',
    retrieved_at: '2026-07-13T09:00:00Z',
    source_url: 'https://registo.example.pt/certidao',
    raw_digest: 'a'.repeat(64),
    conservatoria: null,
    oficial: null,
    subscribed_on: null,
    valid_until: null,
    expired: null,
  },
};

function makeReport(overrides: Partial<RegistryImportReport> = {}): RegistryImportReport {
  return {
    entity: ENTITY,
    extract: EXTRACT,
    applied: ['sede'],
    conflicts: [],
    warnings: [],
    ...overrides,
  };
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

interface Recorded {
  url: string;
  method: string;
  body: unknown;
}

/**
 * Stub GET /v1/entities/:id (crumb + panel refetch after import) and route the import
 * POST through `handleImport`, recording every call so the body can be asserted.
 */
function installFetch(handleImport: () => Response | Promise<Response>): Recorded[] {
  const calls: Recorded[] = [];
  const fn = ((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const method = init?.method ?? 'GET';
    const body = init?.body ? JSON.parse(init.body as string) : null;
    calls.push({ url, method, body });
    if (url.includes('/v1/entities/new-ent-1/registry/import') && method === 'POST') {
      return Promise.resolve(handleImport());
    }
    if (url.includes('/v1/entities/new-ent-1')) {
      return Promise.resolve(jsonResponse(ENTITY));
    }
    return Promise.reject(new Error(`no stub for ${method} ${url}`));
  }) as typeof fetch;
  vi.stubGlobal('fetch', fn);
  return calls;
}

function renderPage() {
  return renderWithProviders(
    <Routes>
      <Route path="/entidades/:id/importar" element={<EntityRegistryImportPage />} />
    </Routes>,
    ['/entidades/new-ent-1/importar'],
  );
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('EntityRegistryImportPage', () => {
  it('renders the crumb with the fetched entity name, the title and the import panel', async () => {
    installFetch(() => jsonResponse(makeReport()));
    renderPage();

    expect(await screen.findByText('Importar do registo comercial')).toBeTruthy();
    // The entity name arrives from the useEntity query and lands in the breadcrumb link.
    const nameLink = await screen.findByRole('link', { name: 'Encosto Estratégico, Lda.' });
    expect(nameLink.getAttribute('href')).toBe('/entidades/new-ent-1');
    expect(screen.getByRole('link', { name: 'Voltar à entidade' }).getAttribute('href')).toBe(
      '/entidades/new-ent-1',
    );
    // The panel's código field is present and the submit starts disabled (no code yet).
    expect(screen.getByLabelText('Código da certidão permanente')).toBeTruthy();
    expect(
      (screen.getByRole('button', { name: 'Consultar e importar' }) as HTMLButtonElement).disabled,
    ).toBe(true);
  });

  it('enables submit once a código is typed, imports and surfaces the applied report + toast', async () => {
    const calls = installFetch(() => jsonResponse(makeReport({ applied: ['sede'] })));
    renderPage();

    const code = await screen.findByLabelText('Código da certidão permanente');
    const submit = screen.getByRole('button', {
      name: 'Consultar e importar',
    }) as HTMLButtonElement;
    expect(submit.disabled).toBe(true);

    fireEvent.change(code, { target: { value: '1234-5678-9012' } });
    expect(submit.disabled).toBe(false);

    fireEvent.click(submit);

    // Applied fields produce the success toast (R7) and the report summary is rendered.
    expect(await screen.findByText('Entidade atualizada a partir da certidão.')).toBeTruthy();
    expect(screen.getByText('Resumo da importação')).toBeTruthy();

    const post = calls.find((c) => c.url.includes('/registry/import'));
    expect(post?.method).toBe('POST');
    expect((post?.body as { code?: string })?.code).toBe('1234-5678-9012');
    expect((post?.body as { overwrite?: boolean })?.overwrite).toBe(false);
    // The secret is cleared from the visible field once resolved.
    expect((code as HTMLInputElement).value).toBe('');
  });

  it('surfaces a 422 registry failure inline and via toast, and flags action needed', async () => {
    installFetch(() =>
      jsonResponse({ error: 'código de acesso inválido ou certidão incompleta' }, 422),
    );
    renderPage();

    fireEvent.change(await screen.findByLabelText('Código da certidão permanente'), {
      target: { value: '0000-0000-0000' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Consultar e importar' }));

    // Inline RegistryErrorNote (query error state) + toast (onError) both carry the server
    // message (the R7 spine); they commit in separate ticks, so wait for both.
    await waitFor(() =>
      expect(screen.getAllByText('código de acesso inválido ou certidão incompleta')).toHaveLength(
        2,
      ),
    );
    expect(screen.getByText('Ação necessária')).toBeTruthy();
  });
});
