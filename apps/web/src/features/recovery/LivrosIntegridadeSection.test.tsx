import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react';
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
  extra?: (url: string, method: string, init?: RequestInit) => Promise<Response> | Response | null,
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

/**
 * Open the last-resort re-anchor modal. The card button only enables once the integrity
 * query resolves broken (`disabled={!broken}`), so wait for that before clicking.
 */
async function openReanchorModal() {
  const trigger = (await screen.findByRole('button', {
    name: 'Re-ancorar cadeia',
  })) as HTMLButtonElement;
  await waitFor(() => expect(trigger.disabled).toBe(false));
  fireEvent.click(trigger);
  await screen.findByRole('dialog', { name: 'Re-ancorar cadeia' });
}

function restoreEndpointCalls(calls: Recorded[]) {
  return calls.filter((c) => c.url === '/v1/ledger/recovery/restore' && c.method === 'POST');
}

function importPreflightCalls(calls: Recorded[]) {
  return calls.filter((c) => c.url.startsWith('/v1/books/import/preflight') && c.method === 'POST');
}

function importEndpointCalls(calls: Recorded[]) {
  return calls.filter((c) => c.url.startsWith('/v1/books/import?') && c.method === 'POST');
}

function makeZipFile(name = 'bundle.zip') {
  const file = new File(['zip'], name, { type: 'application/zip' });
  Object.defineProperty(file, 'arrayBuffer', {
    value: () => Promise.resolve(new ArrayBuffer(3)),
  });
  return file;
}

function makeImportPreflight(overrides: Record<string, unknown> = {}) {
  return {
    ok: true,
    ready: true,
    would_import: true,
    would_record_ledger_event: false,
    would_store_import_record: false,
    policy: 'refuse',
    entity_id: 'ent-1',
    book_id: 'book-9',
    verdict: { status: 'Verified' },
    source_instance_id: 'other',
    bundle_digest: 'ee'.repeat(32),
    collided: false,
    manifest_file_count: 4,
    manifest_total_bytes: 1200,
    zip_member_count: 5,
    event_count: 2,
    book_chain_verified: true,
    book_chain_length: 2,
    signature_present: false,
    errors: [],
    findings: ['Preflight did not append ledger.imported or store an imported_books record.'],
    next_step: 'review and confirm',
    ...overrides,
  };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
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

  it('preflights a selected bundle before confirm import and shows the honest final verdict', async () => {
    const preflight = makeImportPreflight();
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
    const { fn, calls } = sectionFetch(HEALTHY_REPORT, (url, method) => {
      if (url.includes('/v1/books/import/preflight') && method === 'POST') {
        return jsonResponse(preflight);
      }
      if (url.includes('/v1/books/import') && method === 'POST') return jsonResponse(outcome);
      return null;
    });
    vi.stubGlobal('fetch', fn);
    renderWithProviders(<LivrosIntegridadeSection />);

    const fileInput = document.querySelector('input[type=file]') as HTMLInputElement;
    fireEvent.change(fileInput, { target: { files: [makeZipFile()] } });

    expect(importPreflightCalls(calls)).toHaveLength(0);
    expect(importEndpointCalls(calls)).toHaveLength(0);
    const confirm = screen.getByRole('button', { name: 'Confirmar importação' });
    expect((confirm as HTMLButtonElement).disabled).toBe(true);

    fireEvent.click(screen.getByRole('button', { name: 'Pré-validar pacote' }));

    await screen.findByText('Pacote pronto para importação');
    expect(importPreflightCalls(calls)).toHaveLength(1);
    expect(importEndpointCalls(calls)).toHaveLength(0);
    expect((confirm as HTMLButtonElement).disabled).toBe(false);

    fireEvent.click(confirm);

    expect(await screen.findByText('Em quarentena')).toBeTruthy();
    expect(
      screen.getByText(
        'O pacote não passou na verificação. Foi isolado em quarentena, apenas de leitura, e nunca associado às cadeias ativas.',
      ),
    ).toBeTruthy();
    expect(importEndpointCalls(calls)).toHaveLength(1);
  });

  it('clears a stale book import preflight when a different file is selected', async () => {
    const preflight = makeImportPreflight({ findings: [] });
    const { fn } = sectionFetch(HEALTHY_REPORT, (url, method) => {
      if (url.includes('/v1/books/import/preflight') && method === 'POST') {
        return jsonResponse(preflight);
      }
      return null;
    });
    vi.stubGlobal('fetch', fn);
    renderWithProviders(<LivrosIntegridadeSection />);

    const fileInput = document.querySelector('input[type=file]') as HTMLInputElement;
    fireEvent.change(fileInput, { target: { files: [makeZipFile('first.zip')] } });
    fireEvent.click(screen.getByRole('button', { name: 'Pré-validar pacote' }));
    await screen.findByText('Pacote pronto para importação');
    expect(
      (screen.getByRole('button', { name: 'Confirmar importação' }) as HTMLButtonElement).disabled,
    ).toBe(false);

    fireEvent.change(fileInput, { target: { files: [makeZipFile('second.zip')] } });

    expect(screen.queryByText('Pacote pronto para importação')).toBeNull();
    expect(
      (screen.getByRole('button', { name: 'Confirmar importação' }) as HTMLButtonElement).disabled,
    ).toBe(true);
    expect(screen.getByText('Pacote selecionado: second.zip')).toBeTruthy();
  });

  it('keeps confirm disabled when book import preflight fails', async () => {
    const preflight = makeImportPreflight({
      ok: false,
      ready: false,
      would_import: false,
      verdict: {
        status: 'Quarantined',
        break: { chain: 'book:book-9', kind: 'HashMismatch', message: 'forged' },
      },
      event_count: null,
      book_chain_verified: false,
      errors: ['bundle would be quarantined by import verification: forged'],
      next_step: 'choose another bundle',
    });
    const { fn, calls } = sectionFetch(HEALTHY_REPORT, (url, method) => {
      if (url.includes('/v1/books/import/preflight') && method === 'POST') {
        return jsonResponse(preflight);
      }
      if (url.includes('/v1/books/import') && method === 'POST') {
        return jsonResponse({ error: 'import should not be called' }, 500);
      }
      return null;
    });
    vi.stubGlobal('fetch', fn);
    renderWithProviders(<LivrosIntegridadeSection />);

    const fileInput = document.querySelector('input[type=file]') as HTMLInputElement;
    fireEvent.change(fileInput, { target: { files: [makeZipFile()] } });
    fireEvent.click(screen.getByRole('button', { name: 'Pré-validar pacote' }));

    await screen.findByText('Pacote bloqueado');
    expect(
      screen.getByText('bundle would be quarantined by import verification: forged'),
    ).toBeTruthy();
    const confirm = screen.getByRole('button', {
      name: 'Confirmar importação',
    }) as HTMLButtonElement;
    expect(confirm.disabled).toBe(true);
    fireEvent.click(confirm);
    expect(importEndpointCalls(calls)).toHaveLength(0);
  });

  it('ignores a deferred import preflight when the policy changes before it resolves', async () => {
    const firstPreflight = deferred<Response>();
    const secondPreflight = deferred<Response>();
    const outcome = {
      import_id: 'imp-1',
      entity_id: 'ent-1',
      book_id: 'book-9',
      verdict: { status: 'Verified' },
      source_instance_id: 'other',
      bundle_digest: 'ee'.repeat(32),
      collided: false,
    };
    let preflightCount = 0;
    const { fn, calls } = sectionFetch(HEALTHY_REPORT, (url, method) => {
      if (url.includes('/v1/books/import/preflight') && method === 'POST') {
        preflightCount += 1;
        return preflightCount === 1 ? firstPreflight.promise : secondPreflight.promise;
      }
      if (url.includes('/v1/books/import') && method === 'POST') return jsonResponse(outcome);
      return null;
    });
    vi.stubGlobal('fetch', fn);
    renderWithProviders(<LivrosIntegridadeSection />);

    fireEvent.change(document.querySelector('input[type=file]') as HTMLInputElement, {
      target: { files: [makeZipFile('policy-a.zip')] },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Pré-validar pacote' }));
    await waitFor(() => expect(importPreflightCalls(calls)).toHaveLength(1));

    fireEvent.change(document.querySelector('#import-policy') as HTMLSelectElement, {
      target: { value: 'quarantine_copy' },
    });
    await act(async () => {
      firstPreflight.resolve(jsonResponse(makeImportPreflight({ policy: 'refuse' })));
      await firstPreflight.promise;
    });

    expect(screen.queryByText('Pacote pronto para importação')).toBeNull();
    const confirm = screen.getByRole('button', { name: 'Confirmar importação' });
    expect((confirm as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(confirm);
    expect(importEndpointCalls(calls)).toHaveLength(0);

    fireEvent.click(screen.getByRole('button', { name: 'Pré-validar pacote' }));
    await waitFor(() => expect(importPreflightCalls(calls)).toHaveLength(2));
    await act(async () => {
      secondPreflight.resolve(jsonResponse(makeImportPreflight({ policy: 'quarantine_copy' })));
      await secondPreflight.promise;
    });

    expect(await screen.findByText('Pacote pronto para importação')).toBeTruthy();
    expect((confirm as HTMLButtonElement).disabled).toBe(false);
    fireEvent.click(confirm);
    await waitFor(() => expect(importEndpointCalls(calls)).toHaveLength(1));
  });

  it('ignores a deferred import preflight when a different file is selected before it resolves', async () => {
    const firstPreflight = deferred<Response>();
    const secondPreflight = deferred<Response>();
    const outcome = {
      import_id: 'imp-1',
      entity_id: 'ent-1',
      book_id: 'book-9',
      verdict: { status: 'Verified' },
      source_instance_id: 'other',
      bundle_digest: 'ee'.repeat(32),
      collided: false,
    };
    let preflightCount = 0;
    const { fn, calls } = sectionFetch(HEALTHY_REPORT, (url, method) => {
      if (url.includes('/v1/books/import/preflight') && method === 'POST') {
        preflightCount += 1;
        return preflightCount === 1 ? firstPreflight.promise : secondPreflight.promise;
      }
      if (url.includes('/v1/books/import') && method === 'POST') return jsonResponse(outcome);
      return null;
    });
    vi.stubGlobal('fetch', fn);
    renderWithProviders(<LivrosIntegridadeSection />);

    const fileInput = document.querySelector('input[type=file]') as HTMLInputElement;
    fireEvent.change(fileInput, { target: { files: [makeZipFile('file-a.zip')] } });
    fireEvent.click(screen.getByRole('button', { name: 'Pré-validar pacote' }));
    await waitFor(() => expect(importPreflightCalls(calls)).toHaveLength(1));

    fireEvent.change(fileInput, { target: { files: [makeZipFile('file-b.zip')] } });
    await act(async () => {
      firstPreflight.resolve(jsonResponse(makeImportPreflight()));
      await firstPreflight.promise;
    });

    expect(screen.queryByText('Pacote pronto para importação')).toBeNull();
    const confirm = screen.getByRole('button', { name: 'Confirmar importação' });
    expect((confirm as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(confirm);
    expect(importEndpointCalls(calls)).toHaveLength(0);

    fireEvent.click(screen.getByRole('button', { name: 'Pré-validar pacote' }));
    await waitFor(() => expect(importPreflightCalls(calls)).toHaveLength(2));
    await act(async () => {
      secondPreflight.resolve(jsonResponse(makeImportPreflight()));
      await secondPreflight.promise;
    });

    expect(await screen.findByText('Pacote pronto para importação')).toBeTruthy();
    expect((confirm as HTMLButtonElement).disabled).toBe(false);
    fireEvent.click(confirm);
    await waitFor(() => expect(importEndpointCalls(calls)).toHaveLength(1));
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
    // Verdict-first: a plain-language result leads, with the technical evidence tucked
    // behind a collapsible summary.
    expect(
      within(dialog).getByText('Esta cópia de segurança é válida e pode ser restaurada.'),
    ).toBeTruthy();
    expect(within(dialog).getByText('Evidência técnica')).toBeTruthy();
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

  it('surfaces re-anchored segments with the honest permanent-disclosure note', async () => {
    const report = {
      ...HEALTHY_REPORT,
      reanchored_segments: [
        {
          pre_reanchor_digest: 'aa'.repeat(32),
          actor: 'amelia.marques',
          reason: 'corrupção de disco',
        },
      ],
    };
    const { fn } = sectionFetch(report);
    vi.stubGlobal('fetch', fn);
    renderWithProviders(<LivrosIntegridadeSection />);

    expect(await screen.findByText('Segmentos re-ancorados')).toBeTruthy();
    // The permanent-disclosure copy is shown verbatim, per-segment.
    expect(
      screen.getByText(/A evidência original de inviolabilidade do segmento foi perdida/),
    ).toBeTruthy();
    expect(screen.getByText('Por amelia.marques · corrupção de disco')).toBeTruthy();
  });

  it('re-anchors a broken chain only after a required reason + step-up re-auth', async () => {
    const { fn, calls } = sectionFetch(BROKEN_REPORT, (url, method) => {
      if (url === '/v1/ledger/recovery/reanchor' && method === 'POST') {
        return jsonResponse({ reanchored: true, pre_reanchor_digest: 'aa'.repeat(32) });
      }
      return null;
    });
    vi.stubGlobal('fetch', fn);
    renderWithProviders(<LivrosIntegridadeSection />);

    // Open the last-resort re-anchor modal (enabled because the chain is broken).
    await openReanchorModal();

    // The confirm is gated on BOTH a non-empty reason and the step-up proof.
    const confirm = screen.getByRole('button', { name: 'Re-ancorar' }) as HTMLButtonElement;
    expect(confirm.disabled).toBe(true);

    fireEvent.change(screen.getByLabelText('Motivo (obrigatório)'), {
      target: { value: 'quebra confirmada na origem' },
    });
    // Reason alone is not enough — the re-auth password is still required.
    expect(confirm.disabled).toBe(true);

    fireEvent.change(screen.getByLabelText('Palavra-passe'), { target: { value: 'operator-pw' } });
    expect(confirm.disabled).toBe(false);

    fireEvent.click(confirm);

    // On success the modal toasts the honest completion notice and the POST carried the
    // trimmed reason + the gathered re-auth proof.
    expect(await screen.findByText('Cadeia re-ancorada.')).toBeTruthy();
    const reanchorCalls = calls.filter(
      (c) => c.url === '/v1/ledger/recovery/reanchor' && c.method === 'POST',
    );
    expect(reanchorCalls).toHaveLength(1);
    expect(JSON.parse(reanchorCalls[0].body as string)).toEqual({
      reason: 'quebra confirmada na origem',
      reauth: { password: 'operator-pw' },
    });
  });

  it('holds the re-anchor confirm in a disabled pending state while the mutation is in flight', async () => {
    const pending = deferred<Response>();
    const { fn } = sectionFetch(BROKEN_REPORT, (url, method) => {
      if (url === '/v1/ledger/recovery/reanchor' && method === 'POST') return pending.promise;
      return null;
    });
    vi.stubGlobal('fetch', fn);
    renderWithProviders(<LivrosIntegridadeSection />);

    await openReanchorModal();
    fireEvent.change(screen.getByLabelText('Motivo (obrigatório)'), {
      target: { value: 'quebra confirmada' },
    });
    fireEvent.change(screen.getByLabelText('Palavra-passe'), { target: { value: 'operator-pw' } });
    fireEvent.click(screen.getByRole('button', { name: 'Re-ancorar' }));

    // While the mutation never settles the confirm swaps to its pending label and is disabled.
    const pendingBtn = (await screen.findByRole('button', {
      name: 'A re-ancorar…',
    })) as HTMLButtonElement;
    expect(pendingBtn.disabled).toBe(true);

    await act(async () => {
      pending.resolve(jsonResponse({ reanchored: true, pre_reanchor_digest: 'aa'.repeat(32) }));
      await pending.promise;
    });
    expect(await screen.findByText('Cadeia re-ancorada.')).toBeTruthy();
  });

  it('re-anchor failure surfaces an inline error and a toast without leaving the modal', async () => {
    const { fn, calls } = sectionFetch(BROKEN_REPORT, (url, method) => {
      if (url === '/v1/ledger/recovery/reanchor' && method === 'POST') {
        return jsonResponse({ error: 'a cadeia já verifica; re-ancoragem recusada' }, 409);
      }
      return null;
    });
    vi.stubGlobal('fetch', fn);
    renderWithProviders(<LivrosIntegridadeSection />);

    await openReanchorModal();
    fireEvent.change(screen.getByLabelText('Motivo (obrigatório)'), {
      target: { value: 'tentativa inválida' },
    });
    fireEvent.change(screen.getByLabelText('Palavra-passe'), { target: { value: 'operator-pw' } });
    fireEvent.click(screen.getByRole('button', { name: 'Re-ancorar' }));

    // The server message renders BOTH inline (in the still-open modal) and as a toast.
    expect(await screen.findAllByText('a cadeia já verifica; re-ancoragem recusada')).toHaveLength(
      2,
    );
    expect(screen.getByRole('dialog', { name: 'Re-ancorar cadeia' })).toBeTruthy();
    expect(
      calls.filter((c) => c.url === '/v1/ledger/recovery/reanchor' && c.method === 'POST'),
    ).toHaveLength(1);
  });

  it('toasts a book export failure and never invokes the save prompt', async () => {
    const { fn } = sectionFetch(HEALTHY_REPORT, (url, method) => {
      if (url.includes('/v1/books/book-1/export') && method === 'POST') {
        return jsonResponse({ error: 'exportação indisponível sem persistência' }, 422);
      }
      return null;
    });
    vi.stubGlobal('fetch', fn);
    renderWithProviders(<LivrosIntegridadeSection />);

    fireEvent.click(await screen.findByRole('button', { name: /Exportar/ }));

    expect(await screen.findByText('exportação indisponível sem persistência')).toBeTruthy();
    expect(saveFileMock.saveBlobAs).not.toHaveBeenCalled();
  });

  it('toasts a confirmed import failure after a ready preflight', async () => {
    const preflight = makeImportPreflight();
    const { fn, calls } = sectionFetch(HEALTHY_REPORT, (url, method) => {
      if (url.includes('/v1/books/import/preflight') && method === 'POST') {
        return jsonResponse(preflight);
      }
      if (url.includes('/v1/books/import') && method === 'POST') {
        return jsonResponse({ error: 'importação rejeitada pelo servidor' }, 422);
      }
      return null;
    });
    vi.stubGlobal('fetch', fn);
    renderWithProviders(<LivrosIntegridadeSection />);

    fireEvent.change(document.querySelector('input[type=file]') as HTMLInputElement, {
      target: { files: [makeZipFile()] },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Pré-validar pacote' }));
    await screen.findByText('Pacote pronto para importação');

    fireEvent.click(screen.getByRole('button', { name: 'Confirmar importação' }));

    expect(await screen.findByText('importação rejeitada pelo servidor')).toBeTruthy();
    expect(importEndpointCalls(calls)).toHaveLength(1);
  });
});
