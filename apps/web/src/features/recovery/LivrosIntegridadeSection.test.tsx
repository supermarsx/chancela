import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { renderWithProviders } from '../../test/utils';

const saveFileMock = vi.hoisted(() => ({
  saveBlobAs: vi.fn(),
  saveBlobResultMessage: vi.fn((result: { filename: string }) => `Guardado: ${result.filename}`),
}));

vi.mock('../../desktop/saveFile', () => saveFileMock);

import { LivrosIntegridadeSection } from './LivrosIntegridadeSection';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function blobText(blob: Blob): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result));
    reader.onerror = () => reject(reader.error);
    reader.readAsText(blob);
  });
}

const HEALTHY_REPORT = {
  healthy: true,
  degraded: false,
  global: {
    chain: 'global',
    genesis_kind: null,
    length: 5,
    head: 'aa'.repeat(32),
    verified: true,
    first_break: null,
  },
  chains: [],
  reanchored_segments: [],
};

const BROKEN_REPORT = {
  healthy: false,
  degraded: true,
  global: {
    chain: 'global',
    genesis_kind: null,
    length: 5,
    head: 'aa'.repeat(32),
    verified: false,
    first_break: {
      chain: 'global',
      kind: 'HashMismatch',
      global_seq: 3,
      chain_seq: 3,
      event_id: 'bb'.repeat(16),
      expected_hash: 'cc'.repeat(32),
      actual_hash: 'dd'.repeat(32),
      message: 'hash mismatch at seq 3',
    },
  },
  chains: [],
  reanchored_segments: [],
};

const BOOK = {
  id: 'book-1',
  entity_id: 'ent-1',
  kind: 'AssembleiaGeral',
  state: 'Open',
  purpose: 'Atas da Assembleia',
  numbering_scheme: 'Sequential',
  opening_date: '2026-01-01',
  closing_date: null,
  closing_reason: null,
  last_ata_number: 0,
  predecessor: null,
  required_signatories_abertura: null,
  required_signatories_encerramento: null,
};

interface Recorded {
  url: string;
  method: string;
  body?: BodyInit | null;
}

/** A fetch stub over the section's read endpoints; `report` chooses healthy vs broken. */
function sectionFetch(
  report: unknown,
  extra?: (url: string, method: string, init?: RequestInit) => Response | null,
) {
  const calls: Recorded[] = [];
  const fn = ((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const method = init?.method ?? 'GET';
    calls.push({ url, method, body: init?.body });
    const custom = extra?.(url, method, init);
    if (custom) return Promise.resolve(custom);
    if (url.includes('/v1/ledger/integrity')) return Promise.resolve(jsonResponse(report));
    if (url.includes('/v1/books')) return Promise.resolve(jsonResponse([BOOK]));
    if (url.includes('/v1/entities')) return Promise.resolve(jsonResponse([]));
    return Promise.reject(new Error(`no stub for ${url}`));
  }) as typeof fetch;
  return { fn, calls };
}

async function openRestoreModal() {
  fireEvent.click(await screen.findByRole('button', { name: 'Restaurar de cópia de segurança' }));
  await screen.findByRole('dialog', { name: 'Restaurar de cópia de segurança' });
}

function restoreEndpointCalls(calls: Recorded[]) {
  return calls.filter((c) => c.url === '/v1/ledger/recovery/restore' && c.method === 'POST');
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  saveFileMock.saveBlobAs.mockReset();
  saveFileMock.saveBlobResultMessage.mockClear();
});

describe('LivrosIntegridadeSection', () => {
  it('renders the per-chain integrity report with the exact break location when broken', async () => {
    const { fn } = sectionFetch(BROKEN_REPORT);
    vi.stubGlobal('fetch', fn);
    renderWithProviders(<LivrosIntegridadeSection />);

    // A broken chain also puts the instance in read-only (degraded) mode.
    expect(await screen.findByText('Modo só-leitura ativo')).toBeTruthy();
    // The exact break detail is surfaced (kind + message).
    expect(await screen.findByText('Local exato da quebra')).toBeTruthy();
    expect(screen.getByText('HashMismatch')).toBeTruthy();
    expect(screen.getByText('hash mismatch at seq 3')).toBeTruthy();

    // Re-anchor is enabled only because the chain is broken.
    const reanchor = screen.getByRole('button', { name: /Re-ancorar cadeia/ });
    expect((reanchor as HTMLButtonElement).disabled).toBe(false);
  });

  it('disables re-anchor when all chains are intact', async () => {
    const { fn } = sectionFetch(HEALTHY_REPORT);
    vi.stubGlobal('fetch', fn);
    renderWithProviders(<LivrosIntegridadeSection />);

    expect(await screen.findByText('Todas as cadeias íntegras')).toBeTruthy();
    const reanchor = screen.getByRole('button', { name: /Re-ancorar cadeia/ });
    expect((reanchor as HTMLButtonElement).disabled).toBe(true);
  });

  it('exports a book bundle through the save prompt helper', async () => {
    saveFileMock.saveBlobAs.mockResolvedValue({
      kind: 'browser-save',
      filename: 'book-book-1.zip',
      contentType: 'application/zip',
      bytes: 8,
    });

    const { fn } = sectionFetch(HEALTHY_REPORT, (url, method) => {
      if (url.includes('/v1/books/book-1/export') && method === 'POST') {
        return new Response('zipbytes', {
          status: 200,
          headers: { 'Content-Type': 'application/zip' },
        });
      }
      return null;
    });
    vi.stubGlobal('fetch', fn);
    renderWithProviders(<LivrosIntegridadeSection />);

    fireEvent.click(await screen.findByRole('button', { name: /Exportar/ }));
    await waitFor(() => expect(saveFileMock.saveBlobAs).toHaveBeenCalledTimes(1));
    const saved = saveFileMock.saveBlobAs.mock.calls[0][0] as {
      blob: Blob;
      filename: string;
      contentType: string;
      preferBrowserSavePicker: boolean;
    };
    expect(saved.filename).toBe('book-book-1.zip');
    expect(saved.contentType).toBe('application/zip');
    expect(saved.preferBrowserSavePicker).toBe(true);
    expect(saved.blob).toBeInstanceOf(Blob);
    expect(saved.blob.type).toBe('application/zip');
    expect(await blobText(saved.blob)).toBe('zipbytes');
    expect(saveFileMock.saveBlobResultMessage).toHaveBeenCalledWith({
      kind: 'browser-save',
      filename: 'book-book-1.zip',
      contentType: 'application/zip',
      bytes: 8,
    });
  });

  it('imports a bundle and shows the honest Quarantined verdict', async () => {
    const outcome = {
      import_id: 'imp-1',
      entity_id: 'ent-1',
      book_id: 'book-9',
      verdict: {
        status: 'Quarantined',
        break: { chain: 'book:book-9', kind: 'HashMismatch', message: 'forged' },
      },
      source_instance_id: 'other',
      bundle_digest: 'ee'.repeat(32),
      collided: false,
    };
    const { fn } = sectionFetch(HEALTHY_REPORT, (url, method) => {
      if (url.includes('/v1/books/import') && method === 'POST') return jsonResponse(outcome);
      return null;
    });
    vi.stubGlobal('fetch', fn);
    renderWithProviders(<LivrosIntegridadeSection />);

    // The file input carries the accessible "Choose bundle…" label of its wrapping button.
    const fileInput = document.querySelector('input[type=file]') as HTMLInputElement;
    const file = new File(['zip'], 'bundle.zip', { type: 'application/zip' });
    // jsdom's File does not implement arrayBuffer(); provide it so the import can read bytes.
    Object.defineProperty(file, 'arrayBuffer', {
      value: () => Promise.resolve(new ArrayBuffer(3)),
    });
    fireEvent.change(fileInput, { target: { files: [file] } });

    expect(await screen.findByText('Em quarentena')).toBeTruthy();
    expect(
      screen.getByText(
        'O pacote não passou na verificação. Foi isolado em quarentena, apenas de leitura, e nunca associado às cadeias ativas.',
      ),
    ).toBeTruthy();
  });

  it('clicking restore preflight preserves exact passphrase and calls only preflight, not restore', async () => {
    const secretMaterial = 'restore-key-not-for-dom';
    const secretKey = `  ${secretMaterial}  `;
    const preflight = {
      ok: true,
      ready: true,
      encrypted: true,
      archive: 'backup-ready.zip',
      manifest: {
        path: 'backup-ready.zip',
        schema: 1,
        version: 7,
        app_version: 'internal-build-not-rendered',
        store_schema_version: 7,
        ledger_length: 12,
        ledger_verified: true,
        member_count: 3,
        sidecar_member_count: 2,
        db_member_present: true,
        total_member_bytes: 4096,
      },
      ledger_verified: true,
      findings: [],
      errors: [],
      next_step: 'restore',
    };
    const { fn, calls } = sectionFetch(HEALTHY_REPORT, (url, method) => {
      if (url === '/v1/ledger/recovery/restore/preflight' && method === 'POST') {
        return jsonResponse(preflight);
      }
      if (url === '/v1/ledger/recovery/restore' && method === 'POST') {
        return jsonResponse({ error: 'restore should not be called' }, 500);
      }
      return null;
    });
    vi.stubGlobal('fetch', fn);
    renderWithProviders(<LivrosIntegridadeSection />);

    await openRestoreModal();
    fireEvent.change(screen.getByLabelText('Cópia de segurança (nome ou caminho)'), {
      target: { value: 'backup-ready.zip' },
    });
    fireEvent.change(screen.getByLabelText('Chave do backup (opcional)'), {
      target: { value: secretKey },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Verificar backup' }));

    await screen.findByText('Backup pronto para restauro');
    const preflightCalls = calls.filter(
      (c) => c.url === '/v1/ledger/recovery/restore/preflight' && c.method === 'POST',
    );
    expect(preflightCalls).toHaveLength(1);
    expect(JSON.parse(preflightCalls[0].body as string)).toEqual({
      archive: 'backup-ready.zip',
      passphrase: secretKey,
    });
    await waitFor(() =>
      expect((screen.getByLabelText('Chave do backup (opcional)') as HTMLInputElement).value).toBe(
        '',
      ),
    );
    expect(document.body.textContent).not.toContain(secretMaterial);
    expect(restoreEndpointCalls(calls)).toHaveLength(0);
  });

  it('renders restore preflight ledger/member/schema evidence without secrets or hashes', async () => {
    const hiddenHash = 'ff'.repeat(32);
    const hiddenSecret = 'server-secret-not-for-dom';
    const preflight = {
      ok: true,
      ready: true,
      encrypted: true,
      archive: 'backup-ready.zip',
      manifest: {
        path: 'backup-ready.zip',
        schema: 9,
        version: 9,
        app_version: 'internal-build-not-rendered',
        store_schema_version: 9,
        ledger_length: 42,
        ledger_verified: true,
        member_count: 4,
        sidecar_member_count: 3,
        db_member_present: true,
        total_member_bytes: 8192,
      },
      ledger_verified: true,
      secret_token: hiddenSecret,
      findings: [`safe evidence ${hiddenHash}`],
      errors: [],
      next_step: 'restore',
    };
    const { fn } = sectionFetch(HEALTHY_REPORT, (url, method) => {
      if (url === '/v1/ledger/recovery/restore/preflight' && method === 'POST') {
        return jsonResponse(preflight);
      }
      return null;
    });
    vi.stubGlobal('fetch', fn);
    renderWithProviders(<LivrosIntegridadeSection />);

    await openRestoreModal();
    fireEvent.change(screen.getByLabelText('Cópia de segurança (nome ou caminho)'), {
      target: { value: 'backup-ready.zip' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Verificar backup' }));

    const dialog = await screen.findByRole('dialog', { name: 'Restaurar de cópia de segurança' });
    expect(await within(dialog).findByText('Backup pronto para restauro')).toBeTruthy();
    expect(within(dialog).getByText('Eventos no livro-razão')).toBeTruthy();
    expect(within(dialog).getByText('42')).toBeTruthy();
    expect(within(dialog).getByText('Membros no arquivo')).toBeTruthy();
    expect(within(dialog).getByText('4')).toBeTruthy();
    expect(within(dialog).getByText('Membros sidecar')).toBeTruthy();
    expect(within(dialog).getByText('3')).toBeTruthy();
    expect(within(dialog).getByText('Membro da base de dados presente')).toBeTruthy();
    expect(within(dialog).getByText('Total de bytes dos membros')).toBeTruthy();
    expect(within(dialog).getByText('8192')).toBeTruthy();
    expect(within(dialog).getByText('Esquema do backup')).toBeTruthy();
    expect(within(dialog).getAllByText('9')).toHaveLength(2);
    expect(dialog.textContent).not.toContain(hiddenHash);
    expect(dialog.textContent).not.toContain(hiddenSecret);
    expect(dialog.textContent).not.toContain('secret-member.sqlite');
    expect(dialog.textContent).not.toContain('internal-build-not-rendered');
  });

  it('renders failed restore preflight safe findings without executing restore', async () => {
    const hiddenHash = 'ab'.repeat(32);
    const preflight = {
      ok: true,
      ready: false,
      encrypted: false,
      archive: 'backup-blocked.zip',
      manifest: {
        path: 'backup-blocked.zip',
        schema: 1,
        version: 5,
        app_version: 'internal-build-not-rendered',
        store_schema_version: 9,
        ledger_length: 0,
        ledger_verified: false,
        member_count: 1,
        sidecar_member_count: 0,
        db_member_present: false,
        total_member_bytes: 128,
      },
      ledger_verified: false,
      findings: ['schema_incompatible'],
      errors: [`Backup schema is older than the current store ${hiddenHash}`],
      next_step: 'choose another backup',
    };
    const { fn, calls } = sectionFetch(HEALTHY_REPORT, (url, method) => {
      if (url === '/v1/ledger/recovery/restore/preflight' && method === 'POST') {
        return jsonResponse(preflight);
      }
      return null;
    });
    vi.stubGlobal('fetch', fn);
    renderWithProviders(<LivrosIntegridadeSection />);

    await openRestoreModal();
    fireEvent.change(screen.getByLabelText('Cópia de segurança (nome ou caminho)'), {
      target: { value: 'backup-blocked.zip' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Verificar backup' }));

    const dialog = await screen.findByRole('dialog', { name: 'Restaurar de cópia de segurança' });
    expect(await within(dialog).findByText('Backup bloqueado')).toBeTruthy();
    expect(within(dialog).getByText('schema_incompatible')).toBeTruthy();
    expect(within(dialog).getByText(/Backup schema is older/)).toBeTruthy();
    expect(within(dialog).getByText('choose another backup')).toBeTruthy();
    expect(dialog.textContent).not.toContain(hiddenHash);
    expect(restoreEndpointCalls(calls)).toHaveLength(0);
  });

  it('renders failed restore preflight safely when manifest is null', async () => {
    const preflight = {
      ok: false,
      ready: false,
      encrypted: true,
      archive: 'backup-without-manifest.zip',
      manifest: null,
      ledger_verified: false,
      findings: ['archive_readable'],
      errors: ['manifest_missing'],
      next_step: 'choose another backup',
    };
    const { fn, calls } = sectionFetch(HEALTHY_REPORT, (url, method) => {
      if (url === '/v1/ledger/recovery/restore/preflight' && method === 'POST') {
        return jsonResponse(preflight);
      }
      return null;
    });
    vi.stubGlobal('fetch', fn);
    renderWithProviders(<LivrosIntegridadeSection />);

    await openRestoreModal();
    fireEvent.change(screen.getByLabelText('Cópia de segurança (nome ou caminho)'), {
      target: { value: 'backup-without-manifest.zip' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Verificar backup' }));

    const dialog = await screen.findByRole('dialog', { name: 'Restaurar de cópia de segurança' });
    expect(await within(dialog).findByText('Backup bloqueado')).toBeTruthy();
    expect(within(dialog).getByText('error')).toBeTruthy();
    expect(within(dialog).getByText('archive_readable')).toBeTruthy();
    expect(within(dialog).getByText('manifest_missing')).toBeTruthy();
    expect(within(dialog).getByText('choose another backup')).toBeTruthy();
    expect(within(dialog).queryByText('Eventos no livro-razão')).toBeNull();
    expect(restoreEndpointCalls(calls)).toHaveLength(0);
  });

  it('keeps destructive restore separate from restore preflight', async () => {
    const restoreOutcome = {
      restored_from: 'backup-ready.zip',
      ledger_length: 12,
      ledger_head: 'ee'.repeat(32),
      chain_verified: true,
      integrity: HEALTHY_REPORT,
    };
    const { fn, calls } = sectionFetch(HEALTHY_REPORT, (url, method) => {
      if (url === '/v1/ledger/recovery/restore' && method === 'POST') {
        return jsonResponse(restoreOutcome);
      }
      if (url === '/v1/ledger/recovery/restore/preflight' && method === 'POST') {
        return jsonResponse({ error: 'preflight should not be called' }, 500);
      }
      return null;
    });
    vi.stubGlobal('fetch', fn);
    renderWithProviders(<LivrosIntegridadeSection />);

    await openRestoreModal();
    fireEvent.change(screen.getByLabelText('Cópia de segurança (nome ou caminho)'), {
      target: { value: 'backup-ready.zip' },
    });
    const dialog = screen.getByRole('dialog', { name: 'Restaurar de cópia de segurança' });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Restaurar' }));

    await waitFor(() => expect(restoreEndpointCalls(calls)).toHaveLength(1));
    expect(JSON.parse(restoreEndpointCalls(calls)[0].body as string)).toEqual({
      archive: 'backup-ready.zip',
    });
    expect(
      calls.filter((c) => c.url === '/v1/ledger/recovery/restore/preflight' && c.method === 'POST'),
    ).toHaveLength(0);
  });
});
