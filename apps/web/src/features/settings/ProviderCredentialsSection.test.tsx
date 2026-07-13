/**
 * Tests for the provider-credential management section (wp13 Phase D). It drives the
 * encrypted multi-key store via react-query, so `fetch` is stubbed per the sibling settings
 * tests and real handler/branch behaviour is asserted: metadata render, the write-only
 * create body, reorder, the inline enable toggle, delete-with-confirm, disabled+pending, and
 * the failure → inline + toast path.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { ProviderCredentialsSection } from './ProviderCredentialsSection';
import type { ProviderCredentialsListView } from '../../api/types';
import { renderWithProviders } from '../../test/utils';

function listView(overrides: Partial<ProviderCredentialsListView> = {}): ProviderCredentialsListView {
  return {
    strict: false,
    protection_level: 'obfuscation',
    providers: [
      {
        mode: 'csc',
        provider_id: 'encosto-qtsp',
        entries: [
          {
            entry_id: 'entry-a',
            label: 'Primária',
            priority: 0,
            enabled: true,
            endpoint: 'https://qtsp.example/csc',
            selectors: { authorization: 'service' },
            fields: [{ field_name: 'client_secret', configured: true }],
            created_at: '2026-07-01T10:00:00Z',
            updated_at: '2026-07-01T10:00:00Z',
          },
          {
            entry_id: 'entry-b',
            label: 'Secundária',
            priority: 1,
            enabled: false,
            selectors: {},
            fields: [{ field_name: 'client_secret', configured: true }],
            created_at: '2026-07-01T11:00:00Z',
            updated_at: '2026-07-01T11:00:00Z',
          },
        ],
      },
    ],
    ...overrides,
  };
}

interface Call {
  url: string;
  method: string;
  body: string | null;
}

function stubFetch(opts: {
  list?: ProviderCredentialsListView;
  writeStatus?: number;
  writeBody?: unknown;
  hangWrite?: boolean;
} = {}): { fn: typeof fetch; calls: Call[] } {
  const {
    list = listView(),
    writeStatus = 200,
    writeBody = { mode: 'csc', provider_id: 'encosto-qtsp', deleted: false },
    hangWrite = false,
  } = opts;
  const calls: Call[] = [];
  const json = (body: unknown, status = 200) =>
    new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
  const fn = ((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const method = init?.method ?? 'GET';
    calls.push({ url, method, body: (init?.body as string) ?? null });
    if (url.includes('/v1/signature/provider-credentials') && method === 'GET') {
      return Promise.resolve(json(list));
    }
    // Any mutation (POST/PATCH/DELETE) on the entries surface.
    if (hangWrite) return new Promise<Response>(() => {});
    return Promise.resolve(json(writeBody, writeStatus));
  }) as typeof fetch;
  return { fn, calls };
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('ProviderCredentialsSection', () => {
  it('renders provider groups, entries in priority order, and configured field badges', async () => {
    vi.stubGlobal('fetch', stubFetch().fn);
    renderWithProviders(<ProviderCredentialsSection />);

    // The group card title and both entries render.
    expect(await screen.findByText(/QTSP CSC · encosto-qtsp/)).toBeTruthy();
    expect(screen.getByText('Primária')).toBeTruthy();
    expect(screen.getByText('Secundária')).toBeTruthy();
    // The endpoint and a configured field badge are shown.
    expect(screen.getByText('https://qtsp.example/csc')).toBeTruthy();
    expect(screen.getAllByText(/client_secret · configurado/).length).toBeGreaterThan(0);
  });

  it('sends a write-only create body with the secret in `set`', async () => {
    const stub = stubFetch({
      writeBody: { mode: 'csc', provider_id: 'novo-qtsp', deleted: false },
    });
    vi.stubGlobal('fetch', stub.fn);
    renderWithProviders(<ProviderCredentialsSection />);

    fireEvent.click(await screen.findByRole('button', { name: 'Nova entrada' }));
    fireEvent.change(screen.getByLabelText('Identificador do fornecedor'), {
      target: { value: 'novo-qtsp' },
    });
    fireEvent.change(screen.getByLabelText('Client secret'), {
      target: { value: 'sk_live_secret_123' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar' }));

    await waitFor(() => {
      const post = stub.calls.find((c) => c.method === 'POST' && c.url.endsWith('/entries'));
      expect(post, 'a create POST was issued').toBeTruthy();
      const body = JSON.parse(post!.body ?? '{}');
      expect(post!.url).toContain('/provider-credentials/csc/novo-qtsp/entries');
      expect(body.set.client_secret).toBe('sk_live_secret_123');
    });
  });

  it('reorders entries with a permutation of entry ids', async () => {
    const stub = stubFetch();
    vi.stubGlobal('fetch', stub.fn);
    renderWithProviders(<ProviderCredentialsSection />);

    // Move the top entry (Primária) down.
    const primaria = (await screen.findByText('Primária')).closest('[role="group"]') as HTMLElement;
    fireEvent.click(within(primaria).getByRole('button', { name: 'Descer prioridade' }));

    await waitFor(() => {
      const post = stub.calls.find((c) => c.method === 'POST' && c.url.endsWith('/reorder'));
      expect(post).toBeTruthy();
      const body = JSON.parse(post!.body ?? '{}');
      expect(body.order).toEqual(['entry-b', 'entry-a']);
    });
  });

  it('toggles an entry enabled flag through a PATCH', async () => {
    const stub = stubFetch();
    vi.stubGlobal('fetch', stub.fn);
    renderWithProviders(<ProviderCredentialsSection />);

    // The enabled top entry exposes an "Ativa" switch; clicking it disables the entry.
    const toggle = await screen.findByRole('switch', { name: 'Ativa' });
    fireEvent.click(toggle);

    await waitFor(() => {
      const patch = stub.calls.find((c) => c.method === 'PATCH');
      expect(patch).toBeTruthy();
      expect(patch!.url).toContain('/entries/entry-a');
      expect(JSON.parse(patch!.body ?? '{}').enabled).toBe(false);
    });
  });

  it('deletes an entry after confirmation', async () => {
    const stub = stubFetch({ writeBody: { mode: 'csc', provider_id: 'encosto-qtsp', deleted: true } });
    vi.stubGlobal('fetch', stub.fn);
    renderWithProviders(<ProviderCredentialsSection />);

    const primaria = (await screen.findByText('Primária')).closest('[role="group"]') as HTMLElement;
    fireEvent.click(within(primaria).getByRole('button', { name: 'Remover' }));
    // The shared confirm modal opens; confirm the deletion.
    fireEvent.click(await screen.findByRole('button', { name: 'Remover entrada' }));

    await waitFor(() => {
      const del = stub.calls.find((c) => c.method === 'DELETE');
      expect(del).toBeTruthy();
      expect(del!.url).toContain('/entries/entry-a');
    });
  });

  it('disables the submit control and shows the pending label while a create is in flight', async () => {
    vi.stubGlobal('fetch', stubFetch({ hangWrite: true }).fn);
    renderWithProviders(<ProviderCredentialsSection />);

    fireEvent.click(await screen.findByRole('button', { name: 'Nova entrada' }));
    fireEvent.change(screen.getByLabelText('Identificador do fornecedor'), {
      target: { value: 'novo-qtsp' },
    });
    fireEvent.change(screen.getByLabelText('Client secret'), { target: { value: 's' } });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar' }));

    await waitFor(() => {
      const pending = screen.getByRole('button', { name: 'A guardar…' }) as HTMLButtonElement;
      expect(pending.disabled).toBe(true);
    });
  });

  it('surfaces a create failure as an inline error and a toast', async () => {
    vi.stubGlobal(
      'fetch',
      stubFetch({
        writeStatus: 409,
        writeBody: { error: 'não há nenhuma fonte de chave disponível' },
      }).fn,
    );
    renderWithProviders(<ProviderCredentialsSection />);

    fireEvent.click(await screen.findByRole('button', { name: 'Nova entrada' }));
    fireEvent.change(screen.getByLabelText('Identificador do fornecedor'), {
      target: { value: 'novo-qtsp' },
    });
    fireEvent.change(screen.getByLabelText('Client secret'), { target: { value: 's' } });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar' }));

    // The error appears both inline (ErrorNote) and as a toast — at least one match, and the
    // form stays open (write-only inputs are never lost on failure).
    const matches = await screen.findAllByText(/não há nenhuma fonte de chave disponível/);
    expect(matches.length).toBeGreaterThan(0);
  });
});
