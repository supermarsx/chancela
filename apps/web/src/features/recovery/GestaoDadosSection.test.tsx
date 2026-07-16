import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { renderWithProviders } from '../../test/utils';
import {
  DEFAULT_SETTINGS,
  type DataStatusResponse,
  type SyncHandoffPreflightReport,
} from '../../api/types';

const saveFileMock = vi.hoisted(() => ({
  saveBlobAs: vi.fn(),
  saveBlobResultMessage: vi.fn((result: { filename: string }) => `Guardado: ${result.filename}`),
}));

vi.mock('../../desktop/saveFile', () => saveFileMock);

import { GestaoDadosSection } from './GestaoDadosSection';

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

interface Recorded {
  url: string;
  method: string;
  body: string | null;
}

const readyDatabaseEncryption = {
  configured: true,
  sqlcipher_available: true,
  sqlcipher_backed: true,
  key_source: 'operator_env',
  hardware_derived_fallback: {
    available: false,
    selected: false,
    fail_closed_if_requested: true,
    status: 'unavailable',
    message:
      'No hardware-bound database key derivation provider is wired; requests for it fail closed instead of using a static fallback key.',
  },
  database_format: 'non_plaintext_or_encrypted',
  key_ops_plan: 'open_encrypted_store',
  plaintext_migration_pending: false,
  plaintext_migration_blocked: false,
  key_ops: {
    sqlcipher_available: true,
    key_config: 'configured',
    database_file: 'F:\\ChancelaData\\chancela.db',
    database_format: 'non_plaintext_or_encrypted',
    plan: 'open_encrypted_store',
    migration_plan: {
      required: false,
      status: 'not_required',
      summary:
        'no plaintext-to-encrypted export/restore migration is required for this key-ops status',
      steps: [],
      evidence: {
        plan: 'open_encrypted_store',
        database_format: 'non_plaintext_or_encrypted',
        key_config: 'configured',
        sqlcipher_available: true,
        database_file: 'F:\\ChancelaData\\chancela.db',
      },
    },
  },
} satisfies DataStatusResponse['persistence']['database_encryption'];

const absentDatabaseEncryption = {
  configured: false,
  sqlcipher_available: false,
  sqlcipher_backed: false,
  key_source: 'none',
  hardware_derived_fallback: {
    available: false,
    selected: false,
    fail_closed_if_requested: true,
    status: 'unavailable',
    message:
      'No hardware-bound database key derivation provider is wired; requests for it fail closed instead of using a static fallback key.',
  },
  database_format: null,
  key_ops_plan: null,
  plaintext_migration_pending: false,
  plaintext_migration_blocked: false,
  key_ops: null,
} satisfies DataStatusResponse['persistence']['database_encryption'];

const durableStatus: DataStatusResponse = {
  generated_at: '2026-07-10T10:20:30Z',
  persistence: {
    mode: 'durable',
    data_dir_configured: true,
    durable_store_open: true,
    active_backend_family: 'sqlite',
    sidecar_storage_mode: 'file',
    database_encryption_configured: true,
    database_encryption: readyDatabaseEncryption,
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
    durable_store_open: { ok: true, checked: true, message: 'durable store is open' },
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
        id: 'platform_logs',
        label: 'Platform logs',
        bytes: 256,
        basis: 'filesystem',
        exact: true,
        file_count: 1,
        directory_count: 0,
        relative_roots: ['platform-logs.json'],
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
    logical_payload: [
      {
        id: 'ledger',
        label: 'Ledger payloads',
        bytes: 1024,
        basis: 'logical_payload',
        exact: false,
        file_count: 0,
        directory_count: 0,
        row_count: 3,
        relative_roots: ['ledger_events'],
      },
      {
        id: 'sqlite_table_ledger_events',
        kind: 'sqlite_logical_table',
        label: 'Database table ledger_events',
        bytes: 768,
        basis: 'logical_payload',
        exact: false,
        file_count: 0,
        directory_count: 0,
        row_count: 3,
        payload_stats: {
          table_name: 'ledger_events',
          estimated_payload_bytes: 768,
          row_count: 3,
          average_bytes_per_row: 256,
          estimate_method: 'local_loaded_payload_estimate',
          estimate_basis: 'logical_payload',
        },
        relative_roots: ['ledger_events'],
      },
      {
        id: 'sqlite_table_entity_enrichment_cache_with_a_very_long_table_name',
        kind: 'sqlite_logical_table',
        label: 'Database table entity_enrichment_cache_with_a_very_long_table_name',
        bytes: 256,
        basis: 'logical_payload',
        exact: false,
        file_count: 0,
        directory_count: 0,
        row_count: 12,
        payload_stats: {
          table_name: 'entity_enrichment_cache_with_a_very_long_table_name',
          estimated_payload_bytes: 256,
          row_count: 12,
          average_bytes_per_row: 21,
          estimate_method: 'local_loaded_payload_estimate',
          estimate_basis: 'logical_payload',
        },
        relative_roots: ['entity_enrichment_cache_with_a_very_long_table_name'],
      },
    ],
    sidecars: [],
    largest_payload_table: {
      table_name: 'ledger_events',
      estimated_payload_bytes: 768,
      row_count: 3,
      average_bytes_per_row: 256,
      estimate_method: 'local_loaded_payload_estimate',
      estimate_basis: 'logical_payload',
    },
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
        payload_stats: {
          table_name: 'ledger_events',
          estimated_payload_bytes: 768,
          row_count: 3,
          average_bytes_per_row: 256,
          estimate_method: 'local_loaded_payload_estimate',
          estimate_basis: 'sqlite_logical_payload',
        },
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
        payload_stats: {
          table_name: 'entity_enrichment_cache_with_a_very_long_table_name',
          estimated_payload_bytes: 256,
          row_count: 12,
          average_bytes_per_row: 21,
          estimate_method: 'local_loaded_payload_estimate',
          estimate_basis: 'sqlite_logical_payload',
        },
        relative_roots: ['entity_enrichment_cache_with_a_very_long_table_name'],
      },
    ],
    sqlite_largest_payload_table: {
      table_name: 'ledger_events',
      estimated_payload_bytes: 768,
      row_count: 3,
      average_bytes_per_row: 256,
      estimate_method: 'local_loaded_payload_estimate',
      estimate_basis: 'sqlite_logical_payload',
    },
    scan_errors: ['failed to read exports: access denied'],
  },
  key_rotation: {
    latest_receipt: null,
    history: [],
    history_count: 0,
    history_limit: 10,
  },
};

const inMemoryStatus: DataStatusResponse = {
  generated_at: '2026-07-10T11:20:30Z',
  persistence: {
    mode: 'in_memory',
    data_dir_configured: false,
    durable_store_open: false,
    active_backend_family: null,
    sidecar_storage_mode: 'in_memory',
    database_encryption_configured: false,
    database_encryption: absentDatabaseEncryption,
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
    durable_store_open: {
      ok: false,
      checked: true,
      message: 'durable store is not open because no data directory is configured',
    },
    sqlite_store_open: {
      ok: false,
      checked: true,
      message: 'durable SQLite store is not open because no data directory is configured',
    },
  },
  usage: {
    total_bytes: 0,
    filesystem: [],
    logical_payload: [],
    sidecars: [],
    sqlite_logical: [],
    scan_errors: [],
  },
  key_rotation: {
    latest_receipt: null,
    history: [],
    history_count: 0,
    history_limit: 10,
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
    durable_store_open: { ok: false, checked: true, message: 'durable store is not open' },
    sqlite_store_open: { ok: false, checked: true, message: 'durable SQLite store is not open' },
  },
};

const defaultRecoveryDrillList = {
  receipts: [],
  durable: true,
  max_receipts: 50,
  freshness: {
    generated_at: '2026-07-13T10:00:00Z',
    policy: DEFAULT_SETTINGS.data_management.backup_recovery,
    status: 'no_receipt',
    latest_receipt_id: null,
    latest_receipt_at: null,
    latest_receipt_age_days: null,
    latest_receipt_preflight_ready: null,
    latest_receipt_isolated_restore_verified: null,
    restore_performed: false,
    db_swap_performed: false,
    offsite_custody_verified: false,
    rpo_rto_certified: false,
    production_backup_policy_certified: false,
  },
};

const defaultSyncHandoffPreflight: SyncHandoffPreflightReport = {
  report_kind: 'sync_handoff_preflight',
  endpoint: '/v1/sync/handoff-preflight',
  generated_at: '2026-07-14T12:00:00Z',
  readiness: {
    status: 'missing_local_evidence',
    local_handoff_review_ready: false,
    production_sync_ready: false,
    external_connector_ready: false,
    active_sync_performed: false,
  },
  data_status: {
    data_dir_configured: true,
    durable_store_open: true,
    ledger_length: 42,
    ledger_healthy: true,
    ledger_degraded: false,
    global_chain_verified: true,
    global_chain_first_break: null,
    boot_chain_status_ok: true,
  },
  backup: {
    backup_route: '/v1/backup',
    recovery_drill_route: '/v1/backup/recovery-drills',
    durable_receipts: true,
    backup_directory: {
      relative_path: 'backups',
      scanned: true,
      present: true,
      untrusted_candidate_file_count: 1,
      total_candidate_bytes: 1024,
      latest_candidate_file: {
        file_name: 'chancela-backup-test.zip',
        bytes: 1024,
        modified_at: '2026-07-14T12:00:00Z',
      },
      validation_performed: false,
      validated_manifest_evidence_present: false,
      scan_error: null,
    },
    recovery_drill_receipt_count: 1,
    verified_recovery_drill_evidence: false,
    latest_recovery_drill: {
      id: 'drill-unverified',
      created_at: '2026-07-14T12:05:00Z',
      archive_label: 'chancela-backup-test.zip',
      preflight_ok: true,
      preflight_ready: true,
      encrypted: false,
      ledger_verified: false,
      manifest_evidence_present: true,
      manifest_ledger_verified: false,
      manifest_ledger_length: 42,
      manifest_member_count: 0,
      manifest_db_member_present: false,
      manifest_sidecar_member_count: 0,
      manifest_total_member_bytes: 0,
      isolated_restore_verified: false,
      isolated_restore_status: 'failed',
      isolated_snapshot_ledger_verified: false,
      isolated_snapshot_cleanup_verified: false,
      verified_manifest_and_isolated_snapshot: false,
      restore_executed: false,
      live_db_swapped: false,
      sidecars_staged: false,
      ledger_restored_appended: false,
      data_deleted: false,
      offsite_custody_proven: false,
      legal_archive_certified: false,
    },
  },
  book_bundles: {
    export_route: '/v1/books/{id}/export',
    import_preflight_route: '/v1/books/import/preflight',
    import_confirmation_route: '/v1/books/import',
    import_preflight_read_only: true,
    max_import_bundle_bytes: 67108864,
    collision_policies: ['refuse', 'quarantine_copy'],
    durable_store_required: true,
    durable_store_available: true,
    retained_export_relative_path: 'exports',
    book_count: 1,
    open_book_count: 0,
    closed_book_count: 1,
  },
  archive_dglab: {
    archive_package_route: '/v1/books/{id}/archive/package',
    local_dglab_manifest_route: '/v1/books/{id}/archive/local-dglab-interchange-manifest',
    local_dglab_manifest_read_only: true,
    local_dglab_manifest_route_available: true,
    book_count: 1,
    closed_book_count: 1,
    sealed_or_archived_act_count: 1,
    preserved_document_count: 1,
    signed_document_count: 0,
    external_validator_report_metadata_count: 0,
    dglab_certification_claimed: false,
    archive_certification_claimed: false,
  },
  no_claims: {
    active_sync_implemented: false,
    connector_protocol_implemented: true,
    background_job_configured: false,
    upload_or_download_performed: false,
    import_performed: false,
    records_mutated: false,
    production_sync_readiness_claimed: false,
    external_connector_compatibility_claimed: false,
    legal_validity_claimed: false,
    dglab_certification_claimed: false,
    archive_certification_claimed: false,
    signing_notarization_attestation_claimed: false,
    deployment_readiness_claimed: false,
  },
  blockers: [],
  missing_evidence: [
    'no validated whole-instance backup manifest or verified recovery-drill evidence is available',
  ],
  operator_actions: [
    'use explicit existing confirmation endpoints for any later export/import/recovery action; this report itself is read-only',
  ],
};

function installFetch(
  statuses: DataStatusResponse[] = [durableStatus],
  extra?: (url: string, init: RequestInit | undefined) => Response | Promise<Response> | null,
  settings: unknown = DEFAULT_SETTINGS,
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
    if (url.includes('/v1/settings')) {
      return Promise.resolve(jsonResponse(settings));
    }
    if (url === '/v1/backup/recovery-drills' && method === 'GET') {
      return Promise.resolve(jsonResponse(defaultRecoveryDrillList));
    }
    if (url === '/v1/sync/handoff-preflight' && method === 'GET') {
      return Promise.resolve(jsonResponse(defaultSyncHandoffPreflight));
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
  saveFileMock.saveBlobAs.mockReset();
  saveFileMock.saveBlobResultMessage.mockClear();
});

// The Gestão de dados surface splits into three sub-sub-tabs reached through the shared
// SubNav. "Armazenamento" (storage usage/permissions/maintenance) is the default; the
// backup/recovery surface and the key-rotation + reset surface live behind their tabs.
const TAB_BACKUP = 'Cópias e recuperação';
const TAB_KEYS = 'Chaves e reposição';

async function selectTab(name: string) {
  fireEvent.click(await screen.findByRole('button', { name }));
}

describe('GestaoDadosSection', () => {
  it('offers backup creation plus the five distinct data-management operations across sub-sub-tabs', async () => {
    installFetch();
    renderWithProviders(<GestaoDadosSection />);
    // Storage sub-sub-tab is the default landing surface.
    expect(await screen.findByText('Estado do armazenamento')).toBeTruthy();
    // Backup + recovery sub-sub-tab hosts the hot backup action.
    await selectTab(TAB_BACKUP);
    expect((await screen.findAllByRole('button', { name: 'Criar backup' })).length).toBeGreaterThan(
      0,
    );
    // Keys + reset sub-sub-tab hosts the five distinct reset/recomeço operations.
    await selectTab(TAB_KEYS);
    for (const name of [
      'Repor interface',
      'Recomeçar',
      'Limpar dados',
      'Reposição de fábrica',
      'Reposição total',
    ]) {
      expect((await screen.findAllByRole('button', { name })).length).toBeGreaterThan(0);
    }
  });

  it('renders local backup recovery policy freshness without claiming restore or RPO/RTO certification', async () => {
    installFetch();
    renderWithProviders(<GestaoDadosSection />);
    await selectTab(TAB_BACKUP);

    expect(await screen.findByText('Política local de recuperação')).toBeTruthy();
    expect(screen.getByText('Estado do ensaio')).toBeTruthy();
    expect(screen.getAllByText('Sem recibo local').length).toBeGreaterThan(0);
    expect(screen.getByText('RPO alvo declarado')).toBeTruthy();
    expect(screen.getByText('RTO alvo declarado')).toBeTruthy();
    expect(document.body.textContent).toContain('sem restauro executado');
    expect(document.body.textContent).toContain('sem certificação de RPO/RTO');
    expect(document.body.textContent).toContain(
      'sem certificação de política de backup de produção',
    );
  });

  it('renders sync handoff preflight as local-only evidence with missing verified backup proof', async () => {
    installFetch();
    renderWithProviders(<GestaoDadosSection />);
    await selectTab(TAB_BACKUP);

    expect((await screen.findAllByText('Pré-validação local de handoff')).length).toBeGreaterThan(
      0,
    );
    // Verdict-first: a plain-language result leads; the dense evidence is disclosed on demand.
    expect(screen.getByText('Evidência local insuficiente para rever o handoff')).toBeTruthy();
    expect(
      screen.getByText(
        'Falta evidência local verificada para rever o handoff — reúna o que falta antes de prosseguir.',
      ),
    ).toBeTruthy();
    expect(
      screen.getByText(
        'Isto é apenas uma pré-validação local (simulação): não executa a sincronização, o handoff nem qualquer alteração de dados.',
      ),
    ).toBeTruthy();
    expect(screen.getAllByText('Evidência técnica').length).toBeGreaterThan(0);
    expect(screen.getByText('missing_local_evidence')).toBeTruthy();
    expect(screen.getByText('Candidatos não validados')).toBeTruthy();
    expect(screen.getByText('chancela-backup-test.zip (1 KB)')).toBeTruthy();
    expect(screen.getByText('Evidência verificada')).toBeTruthy();
    expect(screen.getByText(/Protocolo de conector externo implementado/)).toBeTruthy();
    expect(screen.getAllByText('missing').length).toBeGreaterThanOrEqual(1);
    expect(document.body.textContent).toContain(
      'no validated whole-instance backup manifest or verified recovery-drill evidence is available',
    );
    expect(document.body.textContent).toContain(
      'use explicit existing confirmation endpoints for any later export/import/recovery action',
    );
  });

  it('saves the loaded sync handoff preflight report as JSON without extra requests', async () => {
    saveFileMock.saveBlobAs.mockResolvedValue({
      kind: 'browser-save',
      filename: 'chancela-sync-handoff-preflight.json',
      contentType: 'application/json;charset=utf-8',
      bytes: 2048,
    });

    const calls = installFetch();
    renderWithProviders(<GestaoDadosSection />);
    await selectTab(TAB_BACKUP);

    expect(
      await screen.findByText('Evidência local insuficiente para rever o handoff'),
    ).toBeTruthy();
    const callsBeforeSave = calls.length;
    fireEvent.click(await screen.findByRole('button', { name: 'Guardar JSON' }));

    await waitFor(() => expect(saveFileMock.saveBlobAs).toHaveBeenCalledTimes(1));
    expect(calls).toHaveLength(callsBeforeSave);

    const saved = saveFileMock.saveBlobAs.mock.calls[0][0] as {
      blob: Blob;
      filename: string;
      contentType: string;
      filters: { name: string; extensions: string[] }[];
      preferBrowserSavePicker: boolean;
    };
    expect(saved.filename).toBe('chancela-sync-handoff-preflight.json');
    expect(saved.contentType).toBe('application/json;charset=utf-8');
    expect(saved.filters).toEqual([{ name: 'JSON', extensions: ['json'] }]);
    expect(saved.preferBrowserSavePicker).toBe(true);
    expect(saved.blob).toBeInstanceOf(Blob);
    expect(saved.blob.type).toBe('application/json;charset=utf-8');

    const text = await blobText(saved.blob);
    expect(text).toBe(`${JSON.stringify(defaultSyncHandoffPreflight, null, 2)}\n`);
    expect(JSON.parse(text)).toEqual(defaultSyncHandoffPreflight);
    expect(saveFileMock.saveBlobResultMessage).toHaveBeenCalledWith({
      kind: 'browser-save',
      filename: 'chancela-sync-handoff-preflight.json',
      contentType: 'application/json;charset=utf-8',
      bytes: 2048,
    });
    expect(calls.filter((call) => call.method !== 'GET')).toHaveLength(0);
  });

  it('renders durable storage, folder affordances, ledger state and usage breakdown', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
    installFetch();
    renderWithProviders(<GestaoDadosSection />);

    expect(await screen.findByText('Durável')).toBeTruthy();
    expect(screen.getByText('F:\\ChancelaData')).toBeTruthy();
    expect(screen.getByText('Durável aberto')).toBeTruthy();
    expect(screen.getByText('sqlite')).toBeTruthy();
    expect(screen.getByText('file')).toBeTruthy();
    expect(screen.getByText('7')).toBeTruthy();
    expect(screen.getByText('42')).toBeTruthy();
    expect(screen.getByText('Database')).toBeTruthy();
    expect(screen.getByText('Ledger payloads')).toBeTruthy();
    expect(screen.getByText('Relatórios de falha')).toBeTruthy();
    expect(screen.getByText('Registos de plataforma')).toBeTruthy();
    expect(screen.getByText('Exportações retidas')).toBeTruthy();
    expect(screen.getByText(/Total:/).textContent).toContain('4 KB');
    const maintenanceSection = screen
      .getByRole('heading', { name: 'Manutenção' })
      .closest('section')!;
    const cleanupRows = within(maintenanceSection).getAllByRole('listitem');
    expect(cleanupRows).toHaveLength(3);
    const crashCleanup = within(maintenanceSection).getByText('Relatórios de falha').closest('li')!;
    expect(crashCleanup.querySelector('.data-status-cleanup__main')?.textContent).toContain(
      'Remove diagnósticos locais de falhas antigas',
    );
    expect(crashCleanup.querySelector('.data-status-cleanup__metric')?.textContent).toContain(
      '512 B',
    );
    expect(within(crashCleanup).getByRole('button', { name: 'Limpar falhas' })).toBeTruthy();
    const platformLogsCleanup = within(maintenanceSection)
      .getByText('Registos de plataforma')
      .closest('li')!;
    expect(platformLogsCleanup.querySelector('.data-status-cleanup__main')?.textContent).toContain(
      'Remove apenas o ficheiro local platform-logs.json',
    );
    expect(
      platformLogsCleanup.querySelector('.data-status-cleanup__metric')?.textContent,
    ).toContain('256 B');
    expect(
      within(platformLogsCleanup).getByRole('button', { name: 'Limpar registos' }),
    ).toBeTruthy();
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
      .getByRole('heading', { name: 'Payload lógico durável' })
      .closest('.data-status-usage-group')!;
    const tablePayloads = sqliteGroup.querySelector('.data-status-sqlite-table-list')!;
    expect(tablePayloads).toBeTruthy();
    const tableRows = tablePayloads.querySelectorAll('.data-status-sqlite-table-row');
    expect(tableRows).toHaveLength(2);
    expect(
      within(sqliteGroup as HTMLElement).getByText(/não provam eliminação, retenção, custódia/),
    ).toBeTruthy();
    expect(
      within(sqliteGroup as HTMLElement).getByText(/Maior tabela local estimada: ledger_events/),
    ).toBeTruthy();
    expect(within(tablePayloads as HTMLElement).getByText('ledger_events')).toBeTruthy();
    expect(
      within(tablePayloads as HTMLElement).getByText(
        'entity_enrichment_cache_with_a_very_long_table_name',
      ),
    ).toBeTruthy();
    expect(within(tablePayloads as HTMLElement).getByText('Linhas: 12')).toBeTruthy();
    expect(within(tablePayloads as HTMLElement).getByText('768 B')).toBeTruthy();
    expect(within(tablePayloads as HTMLElement).getByText('Média: 256 B/linha')).toBeTruthy();
    expect(
      within(tablePayloads as HTMLElement).getAllByText(
        'Método: estimativa local da carga carregada',
      ).length,
    ).toBe(2);
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
      expect.stringContaining('Loja durável'),
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

  it('renders secret-free key rotation receipt history as local evidence only', async () => {
    const receiptStatus: DataStatusResponse = {
      ...durableStatus,
      key_rotation: {
        latest_receipt: {
          schema_version: 1,
          receipt_id: '0f4d87a0-7019-4f83-a770-b548f42a022d',
          rotated_at: '2026-07-10T09:15:00Z',
          actor_user_id: '6d5e4f00-0000-4000-8000-000000000005',
          mode: 'guarded_sqlcipher_rekey',
          status: 'rekey_applied',
          backend_family: 'sqlite',
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
          no_claims: {
            current_key_persisted: false,
            replacement_key_persisted: false,
            key_fingerprint_persisted: false,
            database_path_persisted: false,
            sqlcipher_at_rest_certified: false,
            plaintext_migration_performed: false,
            legal_disposal_or_erasure_certified: false,
          },
        },
        history: [],
        history_count: 1,
        history_limit: 10,
      },
    };
    receiptStatus.key_rotation.history = [receiptStatus.key_rotation.latest_receipt!];

    installFetch([receiptStatus]);
    renderWithProviders(<GestaoDadosSection />);
    await selectTab(TAB_KEYS);

    expect(await screen.findByText('Recibos locais de rotação')).toBeTruthy();
    expect(screen.getByText(/Evidência operacional local/)).toBeTruthy();
    expect(screen.getByText(/não certificam cifragem em repouso/)).toBeTruthy();
    expect(screen.getByText('guarded_sqlcipher_rekey')).toBeTruthy();
    expect(screen.getAllByText('rekey_applied').length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText('sqlcipher_rekey')).toBeTruthy();
    expect(screen.getByText('6d5e4f00-0000-4000-8000-000000000005')).toBeTruthy();
    expect(document.body.textContent).not.toContain('current-secret');
    expect(document.body.textContent).not.toContain('replacement-secret');
    expect(document.body.textContent).not.toContain('chancela.db');
  });

  it('renders SQLCipher and key-custody readiness gaps without key material or completion claims', async () => {
    const gapStatus: DataStatusResponse = {
      ...durableStatus,
      persistence: {
        ...durableStatus.persistence,
        database_encryption_configured: false,
        database_encryption: {
          configured: false,
          sqlcipher_available: false,
          sqlcipher_backed: false,
          key_source: 'none',
          hardware_derived_fallback: {
            available: false,
            selected: true,
            fail_closed_if_requested: true,
            status: 'unavailable',
            message:
              'No hardware-bound database key derivation provider is wired; requests for it fail closed instead of using a static fallback key.',
          },
          database_format: 'plaintext_sqlite',
          key_ops_plan: 'refuse_plaintext_to_encrypted_migration',
          plaintext_migration_pending: true,
          plaintext_migration_blocked: true,
          key_ops: {
            sqlcipher_available: false,
            key_config: 'configured',
            database_file: 'F:\\ChancelaData\\chancela.db',
            database_format: 'plaintext_sqlite',
            plan: 'refuse_plaintext_to_encrypted_migration',
            migration_plan: {
              required: true,
              status: 'refuse_direct_plaintext_to_encrypted_migration',
              summary:
                'direct keyed open is refused; use backup/export-restore into a fresh SQLCipher-enabled store',
              steps: [
                {
                  order: 1,
                  title: 'backup_export_plaintext',
                  detail:
                    'start the existing plaintext instance without a database key and create a verified backup/export before changing encryption settings',
                  source_destructive: false,
                },
              ],
              evidence: {
                plan: 'refuse_plaintext_to_encrypted_migration',
                database_format: 'plaintext_sqlite',
                key_config: 'configured',
                sqlcipher_available: false,
                database_file: 'F:\\ChancelaData\\chancela.db',
              },
            },
          },
        },
      },
    };

    installFetch([gapStatus]);
    renderWithProviders(<GestaoDadosSection />);
    await selectTab(TAB_KEYS);

    expect(
      (await screen.findAllByText('Prontidão SQLCipher e custódia da chave')).length,
    ).toBeGreaterThanOrEqual(1);
    expect(screen.getByText('Build sem SQLCipher')).toBeTruthy();
    expect(screen.getByText('Fonte de chave ausente')).toBeTruthy();
    expect(screen.getByText('Migração de plaintext pendente')).toBeTruthy();
    expect(screen.getByText('Migração direta plaintext bloqueada')).toBeTruthy();
    expect(screen.getByText('Fallback derivado de hardware indisponível')).toBeTruthy();
    expect(
      screen.getByText('Fallback derivado de hardware falha fechado quando solicitado'),
    ).toBeTruthy();
    expect(screen.getByText('plaintext_sqlite')).toBeTruthy();
    expect(screen.getAllByText('refuse_plaintext_to_encrypted_migration').length).toBeGreaterThan(
      0,
    );
    expect(screen.getByText('refuse_direct_plaintext_to_encrypted_migration')).toBeTruthy();
    expect(screen.getByText('backup_export_plaintext')).toBeTruthy();
    expect(document.body.textContent).toContain('Não certificam cifragem em repouso');
    expect(document.body.textContent).not.toContain('operator-key-secret');
    expect(document.body.textContent).not.toContain('key_fingerprint');
    expect(document.body.textContent).not.toContain('produção cifrada certificada');
    expect(document.body.textContent).not.toContain('migração plaintext concluída: Sim');
    expect(document.body.textContent).not.toContain('custódia de produção concluída');
    expect(document.body.textContent).not.toContain('chancela.db');
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
    await selectTab(TAB_KEYS);
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
    await selectTab(TAB_KEYS);
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
    await selectTab(TAB_KEYS);
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
    expect(cleanupRows).toHaveLength(3);
    expect(cleanupRows[0].textContent).toContain('Relatórios de falha');
    expect(cleanupRows[1].textContent).toContain('Registos de plataforma');
    expect(cleanupRows[2].textContent).toContain('Exportações retidas');

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

  it('cleans platform logs from the storage maintenance panel and refreshes status', async () => {
    const cleanedStatus: DataStatusResponse = {
      ...durableStatus,
      usage: {
        ...durableStatus.usage,
        filesystem: durableStatus.usage.filesystem.filter(
          (concern) => concern.id !== 'platform_logs',
        ),
      },
    };
    const calls = installFetch([durableStatus, cleanedStatus], (url) => {
      if (url.includes('/v1/data/cleanup')) {
        return jsonResponse({
          target: 'platform_logs',
          data_dir: 'F:\\ChancelaData',
          dry_run: false,
          deleted_bytes: 256,
          deleted_files: 1,
          deleted_directories: 0,
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

    fireEvent.click(screen.getByRole('button', { name: 'Limpar registos' }));
    const confirmBtns = screen.getAllByRole('button', { name: 'Limpar registos' });
    fireEvent.click(confirmBtns[confirmBtns.length - 1]);

    await waitFor(() => expect(calls.some((c) => c.url.includes('/v1/data/cleanup'))).toBe(true));
    const cleanupCall = calls.find((c) => c.url.includes('/v1/data/cleanup'))!;
    expect(cleanupCall.method).toBe('POST');
    expect(JSON.parse(cleanupCall.body as string)).toEqual({ target: 'platform_logs' });
    expect(await screen.findByText(/Apagados 1 ficheiros e 0 pastas/)).toBeTruthy();
    await waitFor(() =>
      expect(calls.filter((c) => c.url.includes('/v1/data/status'))).toHaveLength(2),
    );
  });

  it('previews retained export cleanup before explicit confirmed execution', async () => {
    const settings = {
      ...DEFAULT_SETTINGS,
      data_management: {
        retained_export_cleanup: {
          minimum_age_days: 45,
          keep_latest: 9,
        },
      },
    };
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
    const calls = installFetch(
      [durableStatus, durableStatus, cleanedStatus],
      (url, init) => {
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
      },
      settings,
    );
    renderWithProviders(<GestaoDadosSection />);
    await screen.findByText('F:\\ChancelaData');
    const maintenanceSection = screen
      .getByRole('heading', { name: 'Manutenção' })
      .closest('section')!;
    const exportsRow = within(maintenanceSection).getByText('Exportações retidas').closest('li')!;
    expect(exportsRow.querySelector('.data-status-cleanup__main')?.textContent).toContain(
      'Pré-visualiza ficheiros de exportação locais retidos com pelo menos 45 dias',
    );
    expect(exportsRow.querySelector('.data-status-cleanup__main')?.textContent).toContain(
      'preservando os 9 mais recentes',
    );
    expect(exportsRow.querySelector('.data-status-cleanup__main')?.textContent).toContain(
      'Nenhum ficheiro é removido nesta ação',
    );
    expect(exportsRow.querySelector('.data-status-cleanup__metric')?.textContent).toContain(
      '2 ficheiros',
    );
    const crashRow = within(maintenanceSection).getByText('Relatórios de falha').closest('li')!;
    const crashCleanupButton = within(crashRow).getByRole('button', { name: 'Limpar falhas' });
    const platformLogsRow = within(maintenanceSection)
      .getByText('Registos de plataforma')
      .closest('li')!;
    const platformLogsCleanupButton = within(platformLogsRow).getByRole('button', {
      name: 'Limpar registos',
    });
    const previewButton = within(exportsRow).getByRole('button', {
      name: 'Pré-visualizar limpeza',
    });
    const executeBeforePreview = within(exportsRow).getByRole('button', {
      name: 'Executar limpeza de ficheiros',
    }) as HTMLButtonElement;
    expect(previewButton.classList.contains('btn--danger')).toBe(false);
    expect(crashCleanupButton.classList.contains('btn--danger')).toBe(false);
    expect(platformLogsCleanupButton.classList.contains('btn--danger')).toBe(false);
    expect(executeBeforePreview.classList.contains('btn--danger')).toBe(false);
    expect(executeBeforePreview.querySelector('.btn__icon svg')?.innerHTML).toBe(
      crashCleanupButton.querySelector('.btn__icon svg')?.innerHTML,
    );
    expect(executeBeforePreview.querySelector('.btn__icon svg')?.innerHTML).toContain(
      'M15.5 4a4.5',
    );
    expect(executeBeforePreview.disabled).toBe(true);
    expect(screen.getByTitle(/Executa a limpeza apenas dos ficheiros locais retidos/)).toBeTruthy();

    fireEvent.click(previewButton);

    await waitFor(() => expect(calls.some((c) => c.url.includes('/v1/data/cleanup'))).toBe(true));
    const previewCall = calls.find((c) => c.url.includes('/v1/data/cleanup'))!;
    expect(previewCall.method).toBe('POST');
    expect(JSON.parse(previewCall.body as string)).toEqual({
      target: 'exports',
      dry_run: true,
      minimum_age_days: 45,
      keep_latest: 9,
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
      name: 'Executar limpeza de ficheiros',
    }) as HTMLButtonElement;
    expect(executeAfterPreview.disabled).toBe(false);
    fireEvent.click(executeAfterPreview);
    const confirmBtns = screen.getAllByRole('button', { name: 'Executar limpeza de ficheiros' });
    fireEvent.click(confirmBtns[confirmBtns.length - 1]);

    await waitFor(() =>
      expect(calls.filter((c) => c.url.includes('/v1/data/cleanup'))).toHaveLength(2),
    );
    const executeCall = calls.filter((c) => c.url.includes('/v1/data/cleanup'))[1];
    expect(executeCall.method).toBe('POST');
    expect(JSON.parse(executeCall.body as string)).toEqual({
      target: 'exports',
      dry_run: false,
      minimum_age_days: 45,
      keep_latest: 9,
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
      name: 'Executar limpeza de ficheiros',
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
      name: 'Executar limpeza de ficheiros',
    }) as HTMLButtonElement;
    expect(execute.disabled).toBe(false);
    fireEvent.click(execute);
    const confirmBtns = screen.getAllByRole('button', { name: 'Executar limpeza de ficheiros' });
    fireEvent.click(confirmBtns[confirmBtns.length - 1]);

    expect(
      await screen.findAllByText(
        'export cleanup preview_token is invalid or expired; run preview again',
      ),
    ).toHaveLength(2);
    expect(calls.filter((c) => c.url.includes('/v1/data/cleanup'))).toHaveLength(2);
    expect(execute.disabled).toBe(true);
    const retryBtns = screen.getAllByRole('button', { name: 'Executar limpeza de ficheiros' });
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
      name: 'Executar limpeza de ficheiros',
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

    expect(
      calls.every(
        (c) =>
          c.method === 'GET' &&
          (c.url.includes('/v1/data/status') ||
            c.url.includes('/v1/settings') ||
            c.url.includes('/v1/backup/recovery-drills') ||
            c.url.includes('/v1/sync/handoff-preflight')),
      ),
    ).toBe(true);
    expect(calls.some((c) => c.url.includes('/v1/settings') && c.method === 'GET')).toBe(true);
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
    await selectTab(TAB_BACKUP);

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
    await selectTab(TAB_BACKUP);

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
    const hiddenMember = 'secret-member-name.json';
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
              member_name: hiddenMember,
              sha256: hiddenHash,
            },
            isolated_restore_verified: true,
            isolated_restore_verification: {
              status: 'verified',
              db_snapshot_materialized: true,
              db_snapshot_opened: true,
              state_loaded: true,
              ledger_verified: true,
              cleanup_verified: true,
              entity_count: 4,
              book_count: 2,
              act_count: 12,
              sidecar_root_count: 2,
              sidecar_materialized_file_count: 2,
              sidecar_materialized_bytes: 4096,
              sqlcipher_encryption_verified: null,
              findings: [
                'isolated database snapshot was materialized, opened, and loaded',
                `hash ${hiddenHash} and member ${hiddenMember} stayed bounded`,
              ],
              errors: [`raw archive ${archive} and token ${hiddenSecret} stayed bounded`],
              next_step:
                'record as preflight-only isolated snapshot evidence; authorize recovery execution separately',
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
      if (url === '/v1/ledger/recovery/restore/preflight') {
        return jsonResponse({ error: 'restore preflight should not be called' }, 500);
      }
      if (url === '/v1/data/reset') {
        return jsonResponse({ error: 'destructive reset should not be called' }, 500);
      }
      return null;
    });
    renderWithProviders(<GestaoDadosSection />);
    await selectTab(TAB_BACKUP);

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
    const drill = calls.find((c) => c.url === '/v1/backup/recovery-drills' && c.method === 'POST')!;
    expect(drill.method).toBe('POST');
    expect(calls.some((c) => c.url === '/v1/ledger/recovery/restore')).toBe(false);
    for (const forbiddenUrl of ['/v1/ledger/recovery/restore/preflight', '/v1/data/reset']) {
      expect(calls.some((c) => c.url === forbiddenUrl)).toBe(false);
    }

    expect(await screen.findByText('Recibo de ensaio registado')).toBeTruthy();
    // Verdict-first: a plain-language result leads; the dense evidence is disclosed on demand.
    expect(screen.getByText('Cópia de segurança verificada e restaurável')).toBeTruthy();
    expect(
      screen.getByText(
        'A pré-validação e o restauro isolado tiveram sucesso, sem qualquer restauro ao vivo.',
      ),
    ).toBeTruthy();
    // Both verdict surfaces (recovery drill + sync-handoff preflight) share the toggle label.
    expect(screen.getAllByText('Evidência técnica').length).toBeGreaterThan(0);
    expect(screen.queryByText(archive)).toBeNull();
    expect(screen.getByText('chancela-backup-drill.cbackup')).toBeTruthy();
    expect(screen.getByText('chancela-backup-manifest/v1')).toBeTruthy();
    expect(screen.getByText('Membros no arquivo')).toBeTruthy();
    expect(screen.getByText('Membros sidecar')).toBeTruthy();
    const isolated = screen.getByText('Verificação isolada').closest('div')!;
    expect(within(isolated).getByText('verified')).toBeTruthy();
    expect(
      within(isolated).getByText('Snapshot materializado').closest('div')?.textContent,
    ).toContain('Sim');
    expect(within(isolated).getByText('Snapshot aberto').closest('div')?.textContent).toContain(
      'Sim',
    );
    expect(within(isolated).getByText('Estado carregado').closest('div')?.textContent).toContain(
      'Sim',
    );
    expect(within(isolated).getByText('Ledger verificado').closest('div')?.textContent).toContain(
      'Sim',
    );
    expect(within(isolated).getByText('Limpeza verificada').closest('div')?.textContent).toContain(
      'Sim',
    );
    expect(within(isolated).getByText('Entidades').closest('div')?.textContent).toContain('4');
    expect(within(isolated).getByText('Livros').closest('div')?.textContent).toContain('2');
    expect(within(isolated).getByText('Atos').closest('div')?.textContent).toContain('12');
    expect(within(isolated).getByText('Raízes sidecar').closest('div')?.textContent).toContain('2');
    expect(
      within(isolated).getByText('Ficheiros sidecar materializados').closest('div')?.textContent,
    ).toContain('2');
    expect(
      within(isolated).getByText('Bytes sidecar materializados').closest('div')?.textContent,
    ).toContain('4 KB');
    expect(
      within(isolated).getByText('isolated database snapshot was materialized, opened, and loaded'),
    ).toBeTruthy();
    expect(
      within(isolated).getByText(/record as preflight-only isolated snapshot evidence/),
    ).toBeTruthy();
    expect(within(isolated).getByText(/hash redigido/)).toBeTruthy();
    expect(within(isolated).getByText(/caminho redigido/)).toBeTruthy();
    expect(within(isolated).getAllByText(/segredo redigido/).length).toBeGreaterThan(0);
    for (const limit of [
      'Sem restauro ao vivo',
      'Sem troca ao vivo da base de dados',
      'Sem preparação ao vivo de sidecars',
      'Sem evento ledger.restored',
      'Sem apagamento de dados',
      'Sem certificação de custódia off-site',
      'Sem certificação legal ou de arquivo',
    ]) {
      expect(screen.getByText(limit).closest('div')?.textContent).toContain('Confirmado');
    }
    for (const overclaim of [
      'Restauro executado',
      'Base de dados trocada',
      'Sidecars preparados',
      'ledger.restored acrescentado',
      'Dados apagados',
      'Custódia off-site comprovada',
      'Certificação legal de arquivo',
    ]) {
      expect(document.body.textContent).not.toContain(overclaim);
    }
    expect(key.value).toBe('');
    expect(document.body.textContent).not.toContain(archive);
    expect(document.body.textContent).not.toContain(passphraseMaterial);
    expect(document.body.textContent).not.toContain(hiddenSecret);
    expect(document.body.textContent).not.toContain(hiddenHash);
    expect(document.body.textContent).not.toContain('internal-build-not-rendered');
    expect(document.body.textContent).not.toContain(hiddenMember);
  });

  it('disables backup creation when the instance is not using durable storage', async () => {
    installFetch([inMemoryStatus]);
    renderWithProviders(<GestaoDadosSection />);

    expect(await screen.findByText('Sem pasta de dados configurada')).toBeTruthy();
    await selectTab(TAB_BACKUP);
    const backupButton = (await screen.findByRole('button', {
      name: 'Criar backup',
    })) as HTMLButtonElement;
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
    await selectTab(TAB_KEYS);

    fireEvent.click(await screen.findByRole('button', { name: 'Limpar dados' }));

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
    await selectTab(TAB_KEYS);

    fireEvent.click(await screen.findByRole('button', { name: 'Repor interface' }));
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
