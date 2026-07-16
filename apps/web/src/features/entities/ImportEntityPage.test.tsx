/**
 * Unit tests for ImportEntityPage (create-an-entity-from-the-registry route). The page is
 * a thin wrapper around ImportFromRegistryForm, whose mutating submit is exercised here
 * per the shared conventions: submit gated on the código, pending label in flight (§5),
 * inline error + toast on failure (§2/§7) and success (toast + navigate to the new entity).
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react';
import { Route, Routes } from 'react-router-dom';
import { renderWithProviders } from '../../test/utils';
import { ImportEntityPage } from './ImportEntityPage';
import type { Entity, RegistryImportReport } from '../../api/types';

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

const REPORT: RegistryImportReport = {
  entity: ENTITY,
  extract: {
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
  },
  applied: ['name', 'nipc', 'sede'],
  conflicts: [],
  warnings: [],
};

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

function installFetch(handleImport: () => Response | Promise<Response>): Recorded[] {
  const calls: Recorded[] = [];
  const fn = ((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const method = init?.method ?? 'GET';
    const body = init?.body ? JSON.parse(init.body as string) : null;
    calls.push({ url, method, body });
    if (url.includes('/v1/entities/import-from-registry') && method === 'POST') {
      return Promise.resolve(handleImport());
    }
    return Promise.reject(new Error(`no stub for ${method} ${url}`));
  }) as typeof fetch;
  vi.stubGlobal('fetch', fn);
  return calls;
}

function renderPage() {
  return renderWithProviders(
    <Routes>
      <Route path="/entidades/importar" element={<ImportEntityPage />} />
      <Route path="/entidades/:id" element={<div>DETALHE DA ENTIDADE</div>} />
    </Routes>,
    ['/entidades/importar'],
  );
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('ImportEntityPage', () => {
  it('renders the crumb, page title and the import card with a gated submit', () => {
    installFetch(() => jsonResponse(REPORT, 201));
    renderPage();

    expect(screen.getByRole('heading', { name: 'Importar do registo comercial' })).toBeTruthy();
    // Crumb chain: Entidades · Importar do registo.
    expect(screen.getByRole('link', { name: 'Entidades' }).getAttribute('href')).toBe('/entidades');
    expect(screen.getByLabelText('Código da certidão permanente')).toBeTruthy();
    expect(
      (screen.getByRole('button', { name: 'Importar do registo' }) as HTMLButtonElement).disabled,
    ).toBe(true);
  });

  it('imports on a valid código, toasts and navigates to the new entity', async () => {
    const calls = installFetch(() => jsonResponse(REPORT, 201));
    renderPage();

    const code = screen.getByLabelText('Código da certidão permanente');
    fireEvent.change(code, { target: { value: '1234-5678-9012' } });
    fireEvent.change(screen.getByLabelText('E-mail (opcional)'), {
      target: { value: 'amelia.marques@example.pt' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Importar do registo' }));

    // Navigates to the freshly created entity and the success toast survives the navigate.
    expect(await screen.findByText('DETALHE DA ENTIDADE')).toBeTruthy();
    expect(await screen.findByText('Entidade importada do registo.')).toBeTruthy();

    const post = calls.find((c) => c.url.includes('/import-from-registry'));
    expect(post?.method).toBe('POST');
    expect((post?.body as { code?: string })?.code).toBe('1234-5678-9012');
    expect((post?.body as { email?: string })?.email).toBe('amelia.marques@example.pt');
  });

  it('shows the pending label and disables submit while the import is in flight (§5)', async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => {
      release = r;
    });
    installFetch(() => gate.then(() => jsonResponse(REPORT, 201)));
    renderPage();

    fireEvent.change(screen.getByLabelText('Código da certidão permanente'), {
      target: { value: '1234-5678-9012' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Importar do registo' }));

    const pending = (await screen.findByRole('button', {
      name: 'A consultar o registo…',
    })) as HTMLButtonElement;
    expect(pending.disabled).toBe(true);
    // The "A consultar" status card is shown while the certidão is being fetched.
    expect(screen.getByRole('status')).toBeTruthy();

    release();
    await waitFor(() => expect(screen.getByText('DETALHE DA ENTIDADE')).toBeTruthy());
  });

  it('surfaces a 502 upstream failure inline and via toast without navigating', async () => {
    installFetch(() => jsonResponse({ error: 'o registo comercial não respondeu' }, 502));
    renderPage();

    fireEvent.change(screen.getByLabelText('Código da certidão permanente'), {
      target: { value: '1234-5678-9012' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Importar do registo' }));

    // Inline RegistryErrorNote (query error state) + toast (onError) commit in separate
    // ticks, so wait until both carry the server message.
    await waitFor(() =>
      expect(screen.getAllByText('o registo comercial não respondeu')).toHaveLength(2),
    );
    // The form stays put — no navigation to a detail page on error.
    expect(screen.queryByText('DETALHE DA ENTIDADE')).toBeNull();
    expect(screen.getByText('Ação necessária')).toBeTruthy();
  });
});
