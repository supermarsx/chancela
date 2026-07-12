import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { GestaoDadosSection } from './GestaoDadosSection';
import { renderWithProviders } from '../../test/utils';
import type { DataStatusResponse } from '../../api/types';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

interface Recorded {
  url: string;
  method: string;
  body: string | null;
}

const durableStatus: DataStatusResponse = {
  generated_at: '2026-07-10T10:20:30Z',
  persistence: {
    mode: 'durable',
    data_dir_configured: true,
    durable_store_open: true,
    database_encryption_configured: true,
    store_schema_version: 7,
    ledger_length: 42,
    ledger_verified: true,
    degraded: false,
  },
  data_dir: {
    path: 'F:\\ChancelaData',
    exists: true,
    is_directory: true,
  },
  permissions: {
    read_dir: { ok: true, checked: true, message: 'directory can be read' },
    create_file: { ok: true, checked: true, message: 'probe file can be created' },
    write_file: { ok: true, checked: true, message: 'probe file can be written' },
    delete_probe_file: { ok: true, checked: true, message: 'probe file can be deleted' },
    sqlite_store_open: { ok: true, checked: true, message: 'durable SQLite store is open' },
  },
  usage: {
    total_bytes: 4096,
    filesystem: [
      {
        id: 'database',
        label: 'Database',
        bytes: 2048,
        basis: 'sqlite_file',
        exact: true,
        file_count: 2,
        directory_count: 0,
        relative_roots: ['chancela.db', 'chancela.db-wal'],
      },
      {
        id: 'settings',
        label: 'Settings',
        bytes: 1024,
        basis: 'filesystem',
        exact: true,
        file_count: 1,
        directory_count: 0,
        relative_roots: ['settings.json'],
      },
      {
        id: 'crash',
        label: 'Crash reports',
        bytes: 512,
        basis: 'filesystem',
        exact: true,
        file_count: 1,
        directory_count: 1,
        relative_roots: ['crash-reports'],
      },
      {
        id: 'exports',
        label: 'Exports',
        bytes: 512,
        basis: 'filesystem',
        exact: true,
        file_count: 2,
        directory_count: 1,
        relative_roots: ['exports'],
      },
    ],
    sqlite_logical: [
      {
        id: 'ledger',
        label: 'Ledger payloads',
        bytes: 1024,
        basis: 'sqlite_logical_payload',
        exact: false,
        file_count: 0,
        directory_count: 0,
        row_count: 3,
        relative_roots: ['ledger_events'],
      },
      {
        id: 'sqlite_table_ledger_events',
        kind: 'sqlite_logical_table',
        label: 'SQLite table ledger_events',
        bytes: 768,
        basis: 'sqlite_logical_payload',
        exact: false,
        file_count: 0,
        directory_count: 0,
        row_count: 3,
        relative_roots: ['ledger_events'],
      },
      {
        id: 'sqlite_table_entity_enrichment_cache_with_a_very_long_table_name',
        kind: 'sqlite_logical_table',
        label: 'SQLite table entity_enrichment_cache_with_a_very_long_table_name',
        bytes: 256,
        basis: 'sqlite_logical_payload',
        exact: false,
        file_count: 0,
        directory_count: 0,
        row_count: 12,
        relative_roots: ['entity_enrichment_cache_with_a_very_long_table_name'],
      },
    ],
    scan_errors: ['failed to read exports: access denied'],
  },
};

const inMemoryStatus: DataStatusResponse = {
  generated_at: '2026-07-10T11:20:30Z',
  persistence: {
    mode: 'in_memory',
    data_dir_configured: false,
    durable_store_open: false,
    database_encryption_configured: false,
    store_schema_version: null,
    ledger_length: 0,
    ledger_verified: null,
    degraded: false,
  },
  data_dir: {
    path: null,
    exists: null,
    is_directory: null,
  },
  permissions: {
    read_dir: { ok: false, checked: false, message: 'no data directory configured' },
    create_file: { ok: false, checked: false, message: 'no data directory configured' },
    write_file: { ok: false, checked: false, message: 'no data directory configured' },
    delete_probe_file: { ok: false, checked: false, message: 'no data directory configured' },
    sqlite_store_open: {
      ok: false,
      checked: true,
      message: 'durable SQLite store is not open because no data directory is configured',
    },
  },
  usage: {
    total_bytes: 0,
    filesystem: [],
    sqlite_logical: [],
    scan_errors: [],
  },
};

const permissionStatus: DataStatusResponse = {
  ...durableStatus,
  permissions: {
    read_dir: { ok: true, checked: true, message: 'directory can be read' },
    create_file: { ok: false, checked: true, message: 'probe file cannot be created: denied' },
    write_file: {
      ok: false,
      checked: false,
      message: 'write probe skipped because the probe file could not be created',
    },
    delete_probe_file: {
      ok: false,
      checked: false,
      message: 'delete probe skipped because the probe file could not be created',
    },
    sqlite_store_open: { ok: false, checked: true, message: 'durable SQLite store is not open' },
  },
};

function installFetch(
  statuses: DataStatusResponse[] = [durableStatus],
  extra?: (url: string, init: RequestInit | undefined) => Response | Promise<Response> | null,
): Recorded[] {
  const calls: Recorded[] = [];
  let statusIndex = 0;
  const fn = ((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const method = init?.method ?? 'GET';
    calls.push({ url, method, body: (init?.body as string) ?? null });
    if (url.includes('/v1/data/status')) {
      const body = statuses[Math.min(statusIndex, statuses.length - 1)];
      statusIndex += 1;
      return Promise.resolve(jsonResponse(body));
    }
    const response = extra?.(url, init);
    if (response) return Promise.resolve(response);
    return Promise.reject(new Error(`no stub for ${url}`));
  }) as typeof fetch;
  vi.stubGlobal('fetch', fn);
  return calls;
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('GestaoDadosSection', () => {
  it('offers backup creation plus the five distinct data-management operations', async () => {
    installFetch();
    renderWithProviders(<GestaoDadosSection />);
    for (const name of [
      'Criar backup',
      'Repor interface',
      'Recomeçar',
      'Limpar dados',
      'Reposição de fábrica',
      'Reposição total',
    ]) {
      expect((await screen.findAllByRole('button', { name })).length).toBeGreaterThan(0);
    }
    expect(await screen.findByText('Estado do armazenamento')).toBeTruthy();
  });

  it('renders durable storage, folder affordances, ledger state and usage breakdown', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
    installFetch();
    renderWithProviders(<GestaoDadosSection />);

    expect(await screen.findByText('Durável')).toBeTruthy();
    expect(screen.getByText('F:\\ChancelaData')).toBeTruthy();
    expect(screen.getByText('Durável aberto')).toBeTruthy();
    expect(screen.getByText('7')).toBeTruthy();
    expect(screen.getByText('42')).toBeTruthy();
    expect(screen.getByText('Database')).toBeTruthy();
    expect(screen.getByText('Ledger payloads')).toBeTruthy();
    expect(screen.getByText('Relatórios de falha')).toBeTruthy();
    expect(screen.getByText('Exportações retidas')).toBeTruthy();
    expect(screen.getByText(/Total:/).textContent).toContain('4 KB');
    const maintenanceSection = screen
      .getByRole('heading', { name: 'Manutenção' })
      .closest('section')!;
    const cleanupRows = within(maintenanceSection).getAllByRole('listitem');
    expect(cleanupRows).toHaveLength(2);
    const crashCleanup = within(maintenanceSection).getByText('Relatórios de falha').closest('li')!;
    expect(crashCleanup.querySelector('.data-status-cleanup__main')?.textContent).toContain(
      'Remove diagnósticos locais de falhas antigas',
    );
    expect(crashCleanup.querySelector('.data-status-cleanup__metric')?.textContent).toContain(
      '512 B',
    );
    expect(within(crashCleanup).getByRole('button', { name: 'Limpar falhas' })).toBeTruthy();
    const usageSection = screen.getByRole('heading', { name: 'Utilização' }).closest('section')!;
    const databaseRow = within(usageSection).getByText('Database').closest('li')!;
    expect(within(databaseRow).getByText('ficheiro SQLite')).toBeTruthy();
    expect(within(databaseRow).getByText('medição exata')).toBeTruthy();
    expect(within(databaseRow).getByText('Ficheiros: 2')).toBeTruthy();
    expect(within(databaseRow).getByText('Pastas: 0')).toBeTruthy();
    expect(within(databaseRow).getByText('Raízes: chancela.db, chancela.db-wal')).toBeTruthy();
    const ledgerRow = within(usageSection).getByText('Ledger payloads').closest('li')!;
    expect(within(ledgerRow).getByText('Linhas: 3')).toBeTruthy();
    const sqliteGroup = within(usageSection)
      .getByRole('heading', { name: 'SQLite lógico' })
      .closest('.data-status-usage-group')!;
    const tablePayloads = sqliteGroup.querySelector('.data-status-sqlite-table-list')!;
    expect(tablePayloads).toBeTruthy();
    const tableRows = tablePayloads.querySelectorAll('.data-status-sqlite-table-row');
    expect(tableRows).toHaveLength(2);
    expect(within(tablePayloads as HTMLElement).getByText('ledger_events')).toBeTruthy();
    expect(
      within(tablePayloads as HTMLElement).getByText(
        'entity_enrichment_cache_with_a_very_long_table_name',
      ),
    ).toBeTruthy();
    expect(within(tablePayloads as HTMLElement).getByText('Linhas: 12')).toBeTruthy();
    expect(within(tablePayloads as HTMLElement).getByText('768 B')).toBeTruthy();
    expect(tablePayloads.textContent).not.toContain('SQLite table ledger_events');
    expect(screen.getByText('failed to read exports: access denied')).toBeTruthy();

    const open = screen.getByRole('button', { name: 'Abrir pasta' }) as HTMLButtonElement;
    expect(open.disabled).toBe(true);
    expect(screen.getByText(/Abrir caminhos locais não está disponível no navegador/)).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: 'Copiar caminho' }));
    await waitFor(() => expect(writeText).toHaveBeenCalledWith('F:\\ChancelaData'));
  });

  it('renders the in-memory empty state without a data folder', async () => {
    installFetch([inMemoryStatus]);
    renderWithProviders(<GestaoDadosSection />);

    expect((await screen.findAllByText('Em memória')).length).toBeGreaterThanOrEqual(2);
    expect(screen.getByText('Sem pasta de dados configurada')).toBeTruthy();
    expect(screen.getByText('Configurada: Não · existe: — · pasta: —')).toBeTruthy();
    expect(screen.getAllByText('Sem dados reportados.').length).toBe(2);
    expect(screen.getAllByText('Não verificado').length).toBeGreaterThanOrEqual(4);
  });

  it('shows ok, warning and unchecked permission probes with backend messages', async () => {
    installFetch([permissionStatus]);
    renderWithProviders(<GestaoDadosSection />);

    expect(await screen.findByText('Ler pasta')).toBeTruthy();
    const permissionsSection = screen
      .getByRole('heading', { name: 'Permissões' })
      .closest('section')!;
    const permissionItems = within(permissionsSection).getAllByRole('listitem');
    expect(permissionItems).toHaveLength(5);
    expect(permissionItems.map((item) => item.textContent)).toEqual([
      expect.stringContaining('Ler pasta'),
      expect.stringContaining('Criar ficheiro'),
      expect.stringContaining('Escrever ficheiro'),
      expect.stringContaining('Apagar ficheiro de teste'),
      expect.stringContaining('SQLite aberto'),
    ]);
    expect(screen.getByText('directory can be read')).toBeTruthy();
    expect(screen.getByText('probe file cannot be created: denied')).toBeTruthy();
    expect(
      screen.getByText('write probe skipped because the probe file could not be created'),
    ).toBeTruthy();
    expect(screen.getAllByText('OK').length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText('Aviso').length).toBeGreaterThanOrEqual(2);
    expect(screen.getAllByText('Não verificado').length).toBeGreaterThanOrEqual(2);
  });

  it('refreshes data status manually', async () => {
    const refreshed: DataStatusResponse = {
      ...durableStatus,
      generated_at: '2026-07-10T12:00:00Z',
      data_dir: { ...durableStatus.data_dir, path: 'F:\\Data2' },
      persistence: { ...durableStatus.persistence, ledger_length: 43 },
    };
    const calls = installFetch([durableStatus, refreshed]);
    renderWithProviders(<GestaoDadosSection />);

    expect(await screen.findByText('F:\\ChancelaData')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Atualizar estado' }));

    expect(await screen.findByText('F:\\Data2')).toBeTruthy();
    expect(calls.filter((c) => c.url.includes('/v1/data/status'))).toHaveLength(2);
  });

  it('runs a secret-clearing data key rotation preflight and renders only returned evidence', async () => {
    const currentSecret = 'current-secret-not-for-dom';
    const replacementSecret = 'replacement-secret-not-for-dom';
    const calls = installFetch([durableStatus], (url) => {
      if (url.includes('/v1/data/key-rotation/preflight')) {
        return jsonResponse({
          ready: false,
          status: 'plaintext_store_not_rotatable',
          next_action:
            'plaintext SQLite cannot be rekeyed in place; use the export/restore migration plan',
          evidence: {
            database_format: 'plaintext_sqlite',
            current_key_config: 'configured',
            requested_key_config: 'configured',
            sqlcipher_available: false,
            database_file: 'F:\\ChancelaData\\chancela.db',
          },
        });
      }
      return null;
    });
    renderWithProviders(<GestaoDadosSection />);
    const current = (await screen.findByLabelText('Chave atual')) as HTMLInputElement;
    const replacement = screen.getByLabelText('Chave de substituição') as HTMLInputElement;
    fireEvent.change(current, { target: { value: currentSecret } });
    fireEvent.change(replacement, { target: { value: replacementSecret } });
    fireEvent.click(screen.getByRole('button', { name: 'Verificar rotação' }));

    await waitFor(() =>
      expect(calls.some((c) => c.url.includes('/v1/data/key-rotation/preflight'))).toBe(true),
    );
    const preflight = calls.find((c) => c.url.includes('/v1/data/key-rotation/preflight'))!;
    expect(preflight.method).toBe('POST');
    expect(JSON.parse(preflight.body as string)).toEqual({
      current_key: currentSecret,
      new_key: replacementSecret,
    });

    expect(await screen.findAllByText('plaintext_store_not_rotatable')).toHaveLength(2);
    expect(screen.getByText('plaintext_sqlite')).toBeTruthy();
    expect(screen.getAllByText('configured').length).toBeGreaterThanOrEqual(2);
    expect(screen.getByText('F:\\ChancelaData\\chancela.db')).toBeTruthy();
    expect(screen.getByText(/export\/restore migration plan/)).toBeTruthy();
    expect(current.value).toBe('');
    expect(replacement.value).toBe('');
    expect(document.body.textContent).not.toContain(currentSecret);
    expect(document.body.textContent).not.toContain(replacementSecret);
  });

  it('executes a guarded data key rekey only after a ready preflight and clears secrets', async () => {
    const currentSecret = 'current-secret-ready-only';
    const preflightReplacement = 'replacement-secret-ready-only';
    const executionSecret = 'execution-secret-not-for-dom';
    const calls = installFetch([durableStatus], (url) => {
      if (url.includes('/v1/data/key-rotation/preflight')) {
        return jsonResponse({
          ready: true,
          status: 'ready',
          next_action:
            'open the existing non-plaintext store with the current key and issue SQLCipher rekey with the replacement key',
          evidence: {
            database_format: 'non_plaintext_or_encrypted',
            current_key_config: 'configured',
            requested_key_config: 'configured',
            sqlcipher_available: true,
            database_file: 'F:\\ChancelaData\\chancela.db',
          },
        });
      }
      if (url === '/v1/data/key-rotation') {
        return jsonResponse({
          status: 'rekey_applied',
          rekey_executed: true,
          ledger_integrity_verified: true,
          ledger_length: 42,
          evidence: {
            operation: 'sqlcipher_rekey',
            requested_key_config: 'configured',
            sqlcipher_available: true,
            checkpointed_before_rekey: true,
            checkpointed_after_rekey: true,
            post_rekey_integrity_checked: true,
          },
        });
      }
      return null;
    });

    renderWithProviders(<GestaoDadosSection />);
    const current = (await screen.findByLabelText('Chave atual')) as HTMLInputElement;
    const replacement = screen.getByLabelText('Chave de substituição') as HTMLInputElement;
    fireEvent.change(current, { target: { value: currentSecret } });
    fireEvent.change(replacement, { target: { value: preflightReplacement } });
    fireEvent.click(screen.getByRole('button', { name: 'Verificar rotação' }));

    expect(await screen.findByLabelText('Nova chave SQLCipher')).toBeTruthy();
    expect(current.value).toBe('');
    expect(replacement.value).toBe('');

    const execution = screen.getByLabelText('Nova chave SQLCipher') as HTMLInputElement;
    fireEvent.change(execution, { target: { value: executionSecret } });
    fireEvent.click(screen.getByRole('button', { name: 'Executar rekey SQLCipher' }));

    await waitFor(() =>
      expect(calls.some((c) => c.url === '/v1/data/key-rotation' && c.method === 'POST')).toBe(
        true,
      ),
    );
    const executeCall = calls.find((c) => c.url === '/v1/data/key-rotation')!;
    expect(JSON.parse(executeCall.body as string)).toEqual({ new_key: executionSecret });

    expect(await screen.findByText('Resultado da execução SQLCipher')).toBeTruthy();
    expect(screen.getByText('rekey_applied')).toBeTruthy();
    expect(screen.getByText('sqlcipher_rekey')).toBeTruthy();
    expect(execution.value).toBe('');
    expect(document.body.textContent).not.toContain(currentSecret);
    expect(document.body.textContent).not.toContain(preflightReplacement);
    expect(document.body.textContent).not.toContain(executionSecret);
  });

  it('clears key rotation secrets after a failed preflight request', async () => {
    const currentSecret = 'current-secret-after-error';
    const replacementSecret = 'replacement-secret-after-error';
    installFetch([durableStatus], (url) => {
      if (url.includes('/v1/data/key-rotation/preflight')) {
        return jsonResponse({ error: 'preflight blocked without secret echo' }, 422);
      }
      return null;
    });
    renderWithProviders(<GestaoDadosSection />);
    const current = (await screen.findByLabelText('Chave atual')) as HTMLInputElement;
    const replacement = screen.getByLabelText('Chave de substituição') as HTMLInputElement;
    fireEvent.change(current, { target: { value: currentSecret } });
    fireEvent.change(replacement, { target: { value: replacementSecret } });
    fireEvent.click(screen.getByRole('button', { name: 'Verificar rotação' }));

    expect(await screen.findAllByText('preflight blocked without secret echo')).toHaveLength(2);
    expect(current.value).toBe('');
    expect(replacement.value).toBe('');
    expect(document.body.textContent).not.toContain(currentSecret);
    expect(document.body.textContent).not.toContain(replacementSecret);
  });

  it('cleans crash reports from the storage maintenance panel and refreshes status', async () => {
    const cleanedStatus: DataStatusResponse = {
      ...durableStatus,
      usage: {
        ...durableStatus.usage,
        filesystem: durableStatus.usage.filesystem.filter((concern) => concern.id !== 'crash'),
      },
    };
    const calls = installFetch([durableStatus, cleanedStatus], (url) => {
      if (url.includes('/v1/data/cleanup')) {
        return jsonResponse({
          target: 'crash',
          data_dir: 'F:\\ChancelaData',
          dry_run: false,
          deleted_bytes: 512,
          deleted_files: 1,
          deleted_directories: 1,
          would_delete_bytes: 0,
          would_delete_files: 0,
          would_delete_directories: 0,
          skipped: [],
        });
      }
      return null;
    });
    renderWithProviders(<GestaoDadosSection />);
    await screen.findByText('F:\\ChancelaData');
    const maintenanceSection = screen
      .getByRole('heading', { name: 'Manutenção' })
      .closest('section')!;
    const cleanupRows = within(maintenanceSection).getAllByRole('listitem');
    expect(cleanupRows).toHaveLength(2);
    expect(cleanupRows[0].textContent).toContain('Relatórios de falha');
    expect(cleanupRows[1].textContent).toContain('Exportações retidas');

    fireEvent.click(screen.getByRole('button', { name: 'Limpar falhas' }));
    const confirmBtns = screen.getAllByRole('button', { name: 'Limpar falhas' });
    fireEvent.click(confirmBtns[confirmBtns.length - 1]);

    await waitFor(() => expect(calls.some((c) => c.url.includes('/v1/data/cleanup'))).toBe(true));
    const cleanupCall = calls.find((c) => c.url.includes('/v1/data/cleanup'))!;
    expect(cleanupCall.method).toBe('POST');
    expect(JSON.parse(cleanupCall.body as string)).toEqual({ target: 'crash' });
    expect(await screen.findByText(/Apagados 1 ficheiros e 1 pastas/)).toBeTruthy();
    await waitFor(() =>
      expect(calls.filter((c) => c.url.includes('/v1/data/status'))).toHaveLength(2),
    );
  });

  it('previews retained export cleanup before explicit confirmed execution', async () => {
    const cleanedStatus: DataStatusResponse = {
      ...durableStatus,
      usage: {
        ...durableStatus.usage,
        filesystem: durableStatus.usage.filesystem.map((concern) =>
          concern.id === 'exports'
            ? { ...concern, bytes: 0, file_count: 0, directory_count: 0 }
            : concern,
        ),
      },
    };
    const calls = installFetch([durableStatus, durableStatus, cleanedStatus], (url, init) => {
      if (url.includes('/v1/data/cleanup')) {
        const body = JSON.parse((init?.body as string) ?? '{}');
        if (body.dry_run === false) {
          return jsonResponse({
            target: 'exports',
            data_dir: 'F:\\ChancelaData',
            dry_run: false,
            deleted_bytes: 512,
            deleted_files: 2,
            deleted_directories: 1,
            would_delete_bytes: 0,
            would_delete_files: 0,
            would_delete_directories: 0,
            skipped: [],
          });
        }
        return jsonResponse({
          target: 'exports',
          data_dir: 'F:\\ChancelaData',
          dry_run: true,
          preview_token: 'export-preview-token-1',
          deleted_bytes: 0,
          deleted_files: 0,
          deleted_directories: 0,
          would_delete_bytes: 512,
          would_delete_files: 2,
          would_delete_directories: 1,
          skipped: [],
        });
      }
      return null;
    });
    renderWithProviders(<GestaoDadosSection />);
    await screen.findByText('F:\\ChancelaData');
    const maintenanceSection = screen
      .getByRole('heading', { name: 'Manutenção' })
      .closest('section')!;
    const exportsRow = within(maintenanceSection).getByText('Exportações retidas').closest('li')!;
    expect(exportsRow.querySelector('.data-status-cleanup__main')?.textContent).toContain(
      'Pré-visualiza ficheiros de exportação locais retidos com pelo menos 30 dias',
    );
    expect(exportsRow.querySelector('.data-status-cleanup__main')?.textContent).toContain(
      'Nenhum ficheiro é removido nesta ação',
    );
    expect(exportsRow.querySelector('.data-status-cleanup__metric')?.textContent).toContain(
      '2 ficheiros',
    );
    const executeBeforePreview = within(exportsRow).getByRole('button', {
      name: 'Executar limpeza destrutiva',
    }) as HTMLButtonElement;
    expect(executeBeforePreview.disabled).toBe(true);
    expect(screen.getByTitle(/Executa a limpeza destrutiva/)).toBeTruthy();

    fireEvent.click(within(exportsRow).getByRole('button', { name: 'Pré-visualizar limpeza' }));

    await waitFor(() => expect(calls.some((c) => c.url.includes('/v1/data/cleanup'))).toBe(true));
    const previewCall = calls.find((c) => c.url.includes('/v1/data/cleanup'))!;
    expect(previewCall.method).toBe('POST');
    expect(JSON.parse(previewCall.body as string)).toEqual({
      target: 'exports',
      dry_run: true,
      minimum_age_days: 30,
      keep_latest: 5,
    });
    expect(
      await screen.findByText('Pré-visualização da limpeza de exportações retidas'),
    ).toBeTruthy();
    expect(
      screen.getByText(/2 ficheiros e 1 pastas seriam removidos numa limpeza confirmada/),
    ).toBeTruthy();
    expect(screen.getByText(/Nenhum ficheiro foi removido/)).toBeTruthy();
    expect(exportsRow.querySelector('.data-status-cleanup__main')?.textContent).toContain(
      'Não é apagamento legal',
    );
    await waitFor(() =>
      expect(calls.filter((c) => c.url.includes('/v1/data/status'))).toHaveLength(2),
    );
    expect(screen.getByText('Relatórios de falha')).toBeTruthy();

    const executeAfterPreview = within(exportsRow).getByRole('button', {
      name: 'Executar limpeza destrutiva',
    }) as HTMLButtonElement;
    expect(executeAfterPreview.disabled).toBe(false);
    fireEvent.click(executeAfterPreview);
    const confirmBtns = screen.getAllByRole('button', { name: 'Executar limpeza destrutiva' });
    fireEvent.click(confirmBtns[confirmBtns.length - 1]);

    await waitFor(() =>
      expect(calls.filter((c) => c.url.includes('/v1/data/cleanup'))).toHaveLength(2),
    );
    const executeCall = calls.filter((c) => c.url.includes('/v1/data/cleanup'))[1];
    expect(executeCall.method).toBe('POST');
    expect(JSON.parse(executeCall.body as string)).toEqual({
      target: 'exports',
      dry_run: false,
      minimum_age_days: 30,
      keep_latest: 5,
      preview_token: 'export-preview-token-1',
    });
    expect(await screen.findByText('Limpeza de exportações retidas concluída')).toBeTruthy();
    const result = screen.getByText(/2 ficheiros e 1 pastas de exportações locais retidas/);
    expect(result.textContent).toContain('foram removidos');
    expect(result.textContent).not.toMatch(/apagamento legal|RGPD|descarte|eliminação de arquivo/i);
    await waitFor(() =>
      expect(calls.filter((c) => c.url.includes('/v1/data/status'))).toHaveLength(3),
    );
  });

  it('clears retained export cleanup preview token when confirmation is cancelled', async () => {
    const calls = installFetch([durableStatus, durableStatus], (url) => {
      if (url.includes('/v1/data/cleanup')) {
        return jsonResponse({
          target: 'exports',
          data_dir: 'F:\\ChancelaData',
          dry_run: true,
          preview_token: 'export-preview-token-cancel',
          deleted_bytes: 0,
          deleted_files: 0,
          deleted_directories: 0,
          would_delete_bytes: 512,
          would_delete_files: 2,
          would_delete_directories: 1,
          skipped: [],
        });
      }
      return null;
    });
    renderWithProviders(<GestaoDadosSection />);
    await screen.findByText('F:\\ChancelaData');
    const maintenanceSection = screen
      .getByRole('heading', { name: 'Manutenção' })
      .closest('section')!;
    const exportsRow = within(maintenanceSection).getByText('Exportações retidas').closest('li')!;

    fireEvent.click(within(exportsRow).getByRole('button', { name: 'Pré-visualizar limpeza' }));
    await waitFor(() =>
      expect(calls.filter((c) => c.url.includes('/v1/data/cleanup'))).toHaveLength(1),
    );

    const execute = within(exportsRow).getByRole('button', {
      name: 'Executar limpeza destrutiva',
    }) as HTMLButtonElement;
    expect(execute.disabled).toBe(false);
    fireEvent.click(execute);
    fireEvent.click(screen.getByRole('button', { name: 'Cancelar' }));

    expect(execute.disabled).toBe(true);
    expect(calls.filter((c) => c.url.includes('/v1/data/cleanup'))).toHaveLength(1);
  });

  it('clears retained export cleanup preview token when confirmation is rejected', async () => {
    const calls = installFetch([durableStatus, durableStatus], (url, init) => {
      if (url.includes('/v1/data/cleanup')) {
        const body = JSON.parse((init?.body as string) ?? '{}');
        if (body.dry_run === false) {
          return jsonResponse(
            { error: 'export cleanup preview_token is invalid or expired; run preview again' },
            422,
          );
        }
        return jsonResponse({
          target: 'exports',
          data_dir: 'F:\\ChancelaData',
          dry_run: true,
          preview_token: 'export-preview-token-rejected',
          deleted_bytes: 0,
          deleted_files: 0,
          deleted_directories: 0,
          would_delete_bytes: 512,
          would_delete_files: 2,
          would_delete_directories: 1,
          skipped: [],
        });
      }
      return null;
    });
    renderWithProviders(<GestaoDadosSection />);
    await screen.findByText('F:\\ChancelaData');
    const maintenanceSection = screen
      .getByRole('heading', { name: 'Manutenção' })
      .closest('section')!;
    const exportsRow = within(maintenanceSection).getByText('Exportações retidas').closest('li')!;

    fireEvent.click(within(exportsRow).getByRole('button', { name: 'Pré-visualizar limpeza' }));
    await waitFor(() =>
      expect(calls.filter((c) => c.url.includes('/v1/data/cleanup'))).toHaveLength(1),
    );

    const execute = within(exportsRow).getByRole('button', {
      name: 'Executar limpeza destrutiva',
    }) as HTMLButtonElement;
    expect(execute.disabled).toBe(false);
    fireEvent.click(execute);
    const confirmBtns = screen.getAllByRole('button', { name: 'Executar limpeza destrutiva' });
    fireEvent.click(confirmBtns[confirmBtns.length - 1]);

    expect(
      await screen.findAllByText(
        'export cleanup preview_token is invalid or expired; run preview again',
      ),
    ).toHaveLength(2);
    expect(calls.filter((c) => c.url.includes('/v1/data/cleanup'))).toHaveLength(2);
    expect(execute.disabled).toBe(true);
    const retryBtns = screen.getAllByRole('button', { name: 'Executar limpeza destrutiva' });
    expect((retryBtns[retryBtns.length - 1] as HTMLButtonElement).disabled).toBe(true);
  });

  it('keeps retained export cleanup confirmation disabled when preview has no server token', async () => {
    const calls = installFetch([durableStatus, durableStatus], (url) => {
      if (url.includes('/v1/data/cleanup')) {
        return jsonResponse({
          target: 'exports',
          data_dir: 'F:\\ChancelaData',
          dry_run: true,
          deleted_bytes: 0,
          deleted_files: 0,
          deleted_directories: 0,
          would_delete_bytes: 512,
          would_delete_files: 2,
          would_delete_directories: 1,
          skipped: [],
        });
      }
      return null;
    });
    renderWithProviders(<GestaoDadosSection />);
    await screen.findByText('F:\\ChancelaData');
    const maintenanceSection = screen
      .getByRole('heading', { name: 'Manutenção' })
      .closest('section')!;
    const exportsRow = within(maintenanceSection).getByText('Exportações retidas').closest('li')!;

    fireEvent.click(within(exportsRow).getByRole('button', { name: 'Pré-visualizar limpeza' }));
    await waitFor(() =>
      expect(calls.filter((c) => c.url.includes('/v1/data/cleanup'))).toHaveLength(1),
    );

    const execute = within(exportsRow).getByRole('button', {
      name: 'Executar limpeza destrutiva',
    }) as HTMLButtonElement;
    expect(execute.disabled).toBe(true);
    expect(screen.getByText(/Nenhum ficheiro foi removido/)).toBeTruthy();
  });

  it('viewing and refreshing the data tab do not PUT settings or call platform logs', async () => {
    const calls = installFetch([durableStatus, durableStatus]);
    renderWithProviders(<GestaoDadosSection />);

    expect(await screen.findByText('F:\\ChancelaData')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Atualizar estado' }));
    await waitFor(() =>
      expect(calls.filter((c) => c.url.includes('/v1/data/status'))).toHaveLength(2),
    );

    expect(calls.every((c) => c.url.includes('/v1/data/status') && c.method === 'GET')).toBe(true);
    expect(calls.some((c) => c.url.includes('/v1/settings') && c.method === 'PUT')).toBe(false);
    expect(calls.some((c) => c.url.includes('/v1/platform/logs'))).toBe(false);
  });

  it('creates a hot backup from the storage panel and renders the non-secret manifest', async () => {
    const backupPath = 'F:\\ChancelaData\\backups\\chancela-backup-20260710.zip';
    const secretLikeField = 'server-secret-not-for-dom';
    const calls = installFetch([durableStatus, durableStatus], (url) => {
      if (url === '/v1/backup') {
        return jsonResponse({
          path: backupPath,
          bytes: 4096,
          created_at: '2026-07-10T10:30:00Z',
          app_version: '0.1.0-test',
          store_schema_version: 7,
          ledger_length: 42,
          ledger_head: 'a'.repeat(64),
          ledger_verified: true,
          secret_token: secretLikeField,
          files: [
            { name: 'backup-member-secret-name.sqlite', sha256: 'b'.repeat(64), bytes: 3072 },
            { name: 'backup-settings-secret-name.json', sha256: 'c'.repeat(64), bytes: 1024 },
          ],
        });
      }
      return null;
    });
    renderWithProviders(<GestaoDadosSection />);

    fireEvent.click(await screen.findByRole('button', { name: 'Criar backup' }));

    await waitFor(() => expect(calls.some((c) => c.url === '/v1/backup')).toBe(true));
    const backup = calls.find((c) => c.url === '/v1/backup')!;
    expect(backup.method).toBe('POST');
    expect(backup.body).toBeNull();
    expect(await screen.findByText('Backup criado')).toBeTruthy();
    expect(screen.getByText(backupPath)).toBeTruthy();
    expect(screen.getAllByText('4 KB').length).toBeGreaterThan(0);
    expect(screen.getByText('2 / 4 KB')).toBeTruthy();
    expect(document.body.textContent).not.toContain(secretLikeField);
    expect(document.body.textContent).not.toContain('0.1.0-test');
    expect(document.body.textContent).not.toContain('backup-member-secret-name.sqlite');
    expect(document.body.textContent).not.toContain('b'.repeat(64));
    await waitFor(() =>
      expect(calls.filter((c) => c.url.includes('/v1/data/status'))).toHaveLength(2),
    );
  });

  it('surfaces backup creation failures without rendering arbitrary response fields', async () => {
    const secretLikeField = 'backend-secret-not-for-dom';
    const calls = installFetch([durableStatus], (url) => {
      if (url === '/v1/backup') {
        return jsonResponse(
          {
            error: 'backups require on-disk persistence',
            secret_token: secretLikeField,
          },
          422,
        );
      }
      return null;
    });
    renderWithProviders(<GestaoDadosSection />);

    fireEvent.click(await screen.findByRole('button', { name: 'Criar backup' }));

    await waitFor(() => expect(calls.some((c) => c.url === '/v1/backup')).toBe(true));
    expect(await screen.findAllByText('backups require on-disk persistence')).toHaveLength(2);
    expect(document.body.textContent).not.toContain(secretLikeField);
  });

  it('posts a preflight-only recovery drill receipt with exact passphrase, clears the key and renders bounded evidence', async () => {
    const archive = 'F:\\ChancelaData\\backups\\chancela-backup-drill.cbackup';
    const passphraseMaterial = 'drill-passphrase-not-for-dom';
    const passphrase = `  ${passphraseMaterial}  `;
    const hiddenSecret = 'server-secret-not-for-dom';
    const hiddenHash = 'f'.repeat(64);
    const calls = installFetch([durableStatus], (url, init) => {
      if (url === '/v1/backup/recovery-drills') {
        const body = JSON.parse((init?.body as string) ?? '{}');
        expect(body).toEqual({
          archive,
          passphrase,
          operator_notes: 'Quarterly drill only',
          custody_location: 'Safe A / shelf 3',
        });
        return jsonResponse(
          {
            id: 'drill-1',
            created_at: '2026-07-10T10:40:00Z',
            archive,
            preflight_ok: true,
            preflight_ready: true,
            encrypted: true,
            ledger_verified: true,
            manifest: {
              schema: 'chancela-backup-manifest/v1',
              version: 1,
              app_version: 'internal-build-not-rendered',
              store_schema_version: 7,
              ledger_length: 42,
              ledger_verified: true,
              member_count: 3,
              sidecar_member_count: 2,
              db_member_present: true,
              total_member_bytes: 4096,
              member_name: 'secret-member-name.json',
              sha256: hiddenHash,
            },
            operator_notes: 'Quarterly drill only',
            custody_location: 'Safe A / shelf 3',
            restore_executed: false,
            live_db_swapped: false,
            sidecars_staged: false,
            ledger_restored_appended: false,
            data_deleted: false,
            offsite_custody_proven: false,
            legal_archive_certified: false,
            secret_token: hiddenSecret,
          },
          201,
        );
      }
      if (url === '/v1/ledger/recovery/restore') {
        return jsonResponse({ error: 'restore should not be called' }, 500);
      }
      return null;
    });
    renderWithProviders(<GestaoDadosSection />);

    fireEvent.change(await screen.findByLabelText('Arquivo do backup para ensaio'), {
      target: { value: archive },
    });
    const key = screen.getByLabelText('Chave do backup (opcional)') as HTMLInputElement;
    fireEvent.change(key, { target: { value: passphrase } });
    fireEvent.change(screen.getByLabelText('Local de custódia'), {
      target: { value: 'Safe A / shelf 3' },
    });
    fireEvent.change(screen.getByLabelText('Notas do operador'), {
      target: { value: 'Quarterly drill only' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Registar ensaio sem restauro' }));

    await waitFor(() =>
      expect(calls.some((c) => c.url === '/v1/backup/recovery-drills')).toBe(true),
    );
    const drill = calls.find((c) => c.url === '/v1/backup/recovery-drills')!;
    expect(drill.method).toBe('POST');
    expect(calls.some((c) => c.url === '/v1/ledger/recovery/restore')).toBe(false);
    expect(calls.some((c) => c.url === '/v1/ledger/recovery/restore/preflight')).toBe(false);

    expect(await screen.findByText('Recibo de ensaio registado')).toBeTruthy();
    expect(screen.getByText(archive)).toBeTruthy();
    expect(screen.getByText('chancela-backup-manifest/v1')).toBeTruthy();
    expect(screen.getByText('Membros no arquivo')).toBeTruthy();
    expect(screen.getByText('Membros sidecar')).toBeTruthy();
    expect(screen.getByText('Custódia off-site comprovada')).toBeTruthy();
    expect(screen.getByText('Certificação legal de arquivo')).toBeTruthy();
    expect(screen.getByText('Custódia off-site comprovada').closest('div')?.textContent).toContain(
      'Não',
    );
    expect(screen.getByText('Certificação legal de arquivo').closest('div')?.textContent).toContain(
      'Não',
    );
    expect(key.value).toBe('');
    expect(document.body.textContent).not.toContain(passphraseMaterial);
    expect(document.body.textContent).not.toContain(hiddenSecret);
    expect(document.body.textContent).not.toContain(hiddenHash);
    expect(document.body.textContent).not.toContain('internal-build-not-rendered');
    expect(document.body.textContent).not.toContain('secret-member-name.json');
  });

  it('disables backup creation when the instance is not using durable storage', async () => {
    installFetch([inMemoryStatus]);
    renderWithProviders(<GestaoDadosSection />);

    expect(await screen.findByText('Sem pasta de dados configurada')).toBeTruthy();
    const backupButton = screen.getByRole('button', { name: 'Criar backup' }) as HTMLButtonElement;
    expect(backupButton.disabled).toBe(true);
    expect(screen.getAllByText('Requer armazenamento durável em disco.').length).toBeGreaterThan(0);
  });

  it('gates the domain wipe on the exact phrase + step-up re-auth, then calls /v1/data/reset', async () => {
    const calls = installFetch([durableStatus, durableStatus], (url) => {
      if (url.includes('/v1/data/reset')) {
        return jsonResponse({
          scope: 'BackendDomain',
          export_archive: 'exports/x.zip',
          cleared: ['entities'],
        });
      }
      return null;
    });
    renderWithProviders(<GestaoDadosSection />);
    await screen.findByText('Estado do armazenamento');

    fireEvent.click(screen.getByRole('button', { name: 'Limpar dados' }));

    // The confirm button inside the modal shares the label; it is the last match.
    const confirmBtns = screen.getAllByRole('button', { name: 'Limpar dados' });
    const confirm = confirmBtns[confirmBtns.length - 1] as HTMLButtonElement;
    expect(confirm.disabled).toBe(true);

    fireEvent.change(screen.getByLabelText('Escreva LIMPAR DADOS para confirmar'), {
      target: { value: 'LIMPAR DADOS' },
    });
    // Phrase alone is not enough — step-up re-auth is required.
    expect(confirm.disabled).toBe(true);

    fireEvent.change(screen.getByLabelText('Palavra-passe'), { target: { value: 'operator-pw' } });
    expect(confirm.disabled).toBe(false);

    fireEvent.click(confirm);
    await waitFor(() => expect(calls.some((c) => c.url.includes('/v1/data/reset'))).toBe(true));

    const reset = calls.find((c) => c.url.includes('/v1/data/reset'))!;
    const sent = JSON.parse(reset.body as string);
    expect(sent.scope).toBe('backend_domain');
    expect(sent.confirm_phrase).toBe('LIMPAR DADOS');
    expect(sent.export_first).toBe(true);
    expect(sent.reauth).toEqual({ password: 'operator-pw' });

    // The cleared summary is surfaced honestly.
    expect(await screen.findByText('entities')).toBeTruthy();
    expect(calls.some((c) => c.url.includes('/v1/data/status'))).toBe(true);
  });

  it('performs the frontend reset without reset/start-over/settings/platform-log calls', async () => {
    const calls = installFetch();
    // Guard window.location.reload (not implemented in jsdom).
    const reloadSpy = vi.fn();
    Object.defineProperty(window, 'location', {
      value: { ...window.location, reload: reloadSpy },
      writable: true,
    });
    renderWithProviders(<GestaoDadosSection />);
    await screen.findByText('Estado do armazenamento');

    fireEvent.click(screen.getByRole('button', { name: 'Repor interface' }));
    // The client-only modal has no phrase / re-auth, so confirm is immediately available.
    const confirmBtns = screen.getAllByRole('button', { name: 'Repor interface' });
    fireEvent.click(confirmBtns[confirmBtns.length - 1]);

    await waitFor(() => expect(reloadSpy).toHaveBeenCalled());
    expect(calls.some((c) => c.url.includes('/v1/data/reset'))).toBe(false);
    expect(calls.some((c) => c.url.includes('/v1/data/start-over'))).toBe(false);
    expect(calls.some((c) => c.url.includes('/v1/settings') && c.method === 'PUT')).toBe(false);
    expect(calls.some((c) => c.url.includes('/v1/platform/logs'))).toBe(false);
  });
});
