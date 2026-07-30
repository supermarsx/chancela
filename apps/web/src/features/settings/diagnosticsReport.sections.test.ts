/**
 * The diagnostics report's ANSWERED sections.
 *
 * `diagnosticsReport.test.ts` proves the report is honest when a source did not answer, and that
 * env secrets never leak. This file feeds every remaining section real, populated payloads —
 * because that is the state in which a leak is possible at all. An absent source cannot disclose
 * anything; a fully populated `DataStatusResponse` carries a filesystem path naming the operator's
 * account, an `IntegrityReportView` carries a composed break narration, and a `SearchStatusResponse`
 * carries the worker's error text. Each is asserted to arrive as presence or as a count, never as
 * itself.
 *
 * All assertions go through the machine tokens (`<unset>`, `<unknown>`, `configured`, `true`) which
 * are identical in every locale — this file is the export's wire format, not its copy.
 */
import { describe, expect, it } from 'vitest';
import {
  buildDiagnosticsReport,
  renderDiagnosticsText,
  type DiagnosticsInput,
  type DiagnosticsSource,
} from './diagnosticsReport';
import type {
  DataStatusResponse,
  IntegrityReportView,
  SearchStatusResponse,
  TslSummaryView,
  ZkStorageStatus,
} from '../../api/types';

const AT = new Date('2026-07-29T13:04:05.000Z');

const ok = <T>(data: T): DiagnosticsSource<T> => ({ state: { kind: 'ok' }, data });
const absent = <T>(): DiagnosticsSource<T> => ({
  state: { kind: 'not_checked', reason: 'no_response' },
  data: undefined,
});

function input(overrides: Partial<DiagnosticsInput> = {}): DiagnosticsInput {
  return {
    generatedAt: AT,
    locale: 'pt-PT',
    timeZone: 'Europe/Lisbon',
    uiVersion: '26.1.0',
    build: null,
    desktop: false,
    host: 'chancela.example:8443',
    health: absent(),
    services: absent(),
    env: absent(),
    storage: absent(),
    zk: absent(),
    ledger: absent(),
    search: absent(),
    trust: absent(),
    email: absent(),
    deliveries: absent(),
    credentials: absent(),
    settingsSchemaVersion: absent(),
    ...overrides,
  };
}

const row = (id: string, token: string): string => `${id.padEnd(46)} = ${token}`;

function textFor(overrides: Partial<DiagnosticsInput> = {}): string {
  return renderDiagnosticsText(buildDiagnosticsReport(input(overrides)));
}

// --- Storage -------------------------------------------------------------------

/** The account name a real data directory carries, and which must never leave the building. */
const DATA_DIR_PATH = 'C:\\Users\\amelia.marques\\AppData\\Roaming\\Chancela';

function storageStatus(overrides: Partial<DataStatusResponse> = {}): DataStatusResponse {
  return {
    generated_at: '2026-07-29T12:59:00Z',
    persistence: {
      mode: 'durable',
      data_dir_configured: true,
      durable_store_open: true,
      active_backend_family: 'sqlite',
      sidecar_storage_mode: 'file',
      database_encryption_configured: true,
      database_encryption: {
        configured: true,
        sqlcipher_available: true,
        sqlcipher_backed: true,
        key_source: 'dpapi',
        hardware_derived_fallback: {
          available: false,
          selected: false,
          fail_closed_if_requested: false,
          status: 'unavailable',
          message: 'no platform key store',
        },
        database_format: 'sqlcipher',
        key_ops_plan: 'rekey',
        plaintext_migration_pending: false,
        plaintext_migration_blocked: false,
        key_ops: null,
        key_ops_error: `could not open ${DATA_DIR_PATH}\\chancela.db`,
      },
      store_schema_version: 7,
      ledger_length: 42,
      ledger_verified: true,
      degraded: false,
    },
    data_dir: { path: DATA_DIR_PATH, exists: true, is_directory: true },
    permissions: {
      read_dir: { ok: true, checked: true, message: `read ${DATA_DIR_PATH}` },
      create_file: { ok: false, checked: true, message: `cannot create in ${DATA_DIR_PATH}` },
      // Never performed. `ok: true` here is meaningless and must not render as a pass.
      write_file: { ok: true, checked: false, message: 'not attempted' },
      delete_probe_file: { ok: true, checked: true, message: 'ok' },
      durable_store_open: { ok: true, checked: true, message: 'ok' },
      sqlite_store_open: { ok: true, checked: true, message: 'ok' },
    },
    usage: {
      total_bytes: 4096,
      filesystem: [],
      logical_payload: [],
      sidecars: [],
      sqlite_logical: [],
      scan_errors: [`permission denied: ${DATA_DIR_PATH}\\exports`, 'permission denied: /var/tmp'],
    },
    key_rotation: { latest_receipt: null, history: [], history_count: 3, history_limit: 20 },
    ...overrides,
  };
}

describe('diagnostics report — storage', () => {
  it('reports the data directory as presence, never as the path it carries', () => {
    const out = textFor({ storage: ok(storageStatus()) });

    expect(out).toContain(row('storage.data_dir.exists', 'true'));
    expect(out).toContain(row('storage.data_dir.is_directory', 'true'));
    // The path names the operator's account. It has no row, and it must not arrive through any
    // other field either.
    expect(out).not.toContain('amelia.marques');
    expect(out).not.toContain(DATA_DIR_PATH);
  });

  it('renders an UNCHECKED permission probe as unknown, never as the pass it claims', () => {
    const out = textFor({ storage: ok(storageStatus()) });

    expect(out).toContain(row('storage.permissions.read_dir', 'true'));
    expect(out).toContain(row('storage.permissions.create_file', 'false'));
    // `checked: false` with `ok: true` is the exact payload that would turn a probe nobody ran
    // into a green row.
    expect(out).toContain(row('storage.permissions.write_file', '<unknown>'));
  });

  it('counts scan errors instead of carrying the paths they name', () => {
    const out = textFor({ storage: ok(storageStatus()) });

    expect(out).toContain(row('storage.usage.scan_error_count', '2'));
    expect(out).not.toContain('permission denied');
  });

  it('reduces the key-ops error to presence', () => {
    const out = textFor({ storage: ok(storageStatus()) });
    expect(out).toContain(row('storage.encryption.key_ops_error', 'true'));
    expect(out).not.toContain('could not open');
  });

  it('leaves the key-rotation receipt rows unset when there has been no rotation', () => {
    const out = textFor({ storage: ok(storageStatus()) });

    expect(out).toContain(row('storage.key_rotation.history_count', '3'));
    expect(out).toContain(row('storage.key_rotation.latest_status', '<unset>'));
    expect(out).toContain(row('storage.key_rotation.latest_rotated_at', '<unset>'));
    expect(out).toContain(row('storage.key_rotation.read_error', 'false'));
  });

  it('carries a rotation receipt as its status and instant, never as its actor', () => {
    const status = storageStatus();
    const out = textFor({
      storage: ok({
        ...status,
        key_rotation: {
          ...status.key_rotation,
          history_count: 4,
          read_error: 'receipt directory unreadable',
          latest_receipt: {
            schema_version: 1,
            receipt_id: 'rot-1',
            rotated_at: '2026-06-01T09:00:00Z',
            actor_user_id: 'user-amelia-marques',
            mode: 'rekey',
            status: 'completed',
            backend_family: 'sqlite',
            rekey_executed: true,
            ledger_integrity_verified: true,
            ledger_length: 42,
            evidence: {
              operation: 'rekey',
              requested_key_config: 'dpapi',
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
        },
      }),
    });

    expect(out).toContain(row('storage.key_rotation.latest_status', 'completed'));
    expect(out).toContain(row('storage.key_rotation.latest_rotated_at', '2026-06-01T09:00:00Z'));
    expect(out).toContain(row('storage.key_rotation.read_error', 'true'));
    expect(out).not.toContain('user-amelia-marques');
    expect(out).not.toContain('receipt directory unreadable');
  });

  it('keeps a nulled store schema version and ledger verification distinct from a read failure', () => {
    const status = storageStatus();
    const out = textFor({
      storage: ok({
        ...status,
        persistence: {
          ...status.persistence,
          active_backend_family: null,
          store_schema_version: null,
          ledger_verified: null,
        },
      }),
    });

    // "read, and unset" — not `<unknown>`, which claims the field was never read at all.
    expect(out).toContain(row('storage.persistence.store_schema_version', '<unset>'));
    expect(out).toContain(row('storage.persistence.backend_family', '<unset>'));
    // `ledger_verified: null` means NOT VERIFIED, which is not `false` and not a pass.
    expect(out).toContain(row('storage.persistence.ledger_verified', '<unknown>'));
  });
});

// --- Zero-knowledge interlock --------------------------------------------------

describe('diagnostics report — zero-knowledge object root', () => {
  const ZK: ZkStorageStatus = {
    ready: false,
    reason: 'shared object root is not reachable from this node',
    requires_shared_root: true,
    declared_root: 's3://chancela-objects/amelia-marques-tenant',
    source: 'environment',
  };

  it('reports the declared root as configured, never as the URL it is', () => {
    const out = textFor({ zk: ok(ZK) });

    expect(out).toContain(row('storage.zk.ready', 'false'));
    expect(out).toContain(row('storage.zk.requires_shared_root', 'true'));
    expect(out).toContain(row('storage.zk.source', 'environment'));
    expect(out).toContain(row('storage.zk.root_declared', 'configured'));
    expect(out).toContain(row('storage.zk.reason', 'true'));
    expect(out).not.toContain('s3://chancela-objects');
    expect(out).not.toContain('not reachable');
  });

  it('says not-configured for an undeclared root, and has no reason to report', () => {
    const out = textFor({ zk: ok({ ...ZK, declared_root: null, reason: null }) });

    expect(out).toContain(row('storage.zk.root_declared', 'not-configured'));
    expect(out).toContain(row('storage.zk.reason', 'false'));
  });
});

// --- Ledger ---------------------------------------------------------------------

describe('diagnostics report — ledger', () => {
  const BREAK_MESSAGE = 'hash mismatch in ata «Reunião de 3 de março» of Encosto Estratégico Lda';

  function integrity(overrides: Partial<IntegrityReportView> = {}): IntegrityReportView {
    return {
      healthy: false,
      degraded: true,
      global: {
        chain: 'global',
        genesis_kind: 'system.genesis',
        length: 120,
        head: 'abc',
        verified: true,
        first_break: null,
      },
      chains: [
        {
          chain: 'book:9f2c',
          genesis_kind: 'book.opened',
          length: 10,
          head: 'def',
          verified: true,
          first_break: null,
        },
        {
          chain: 'book:7a1d',
          genesis_kind: 'book.opened',
          length: 8,
          head: null,
          verified: false,
          first_break: {
            chain: 'book:7a1d',
            kind: 'HashMismatch',
            global_seq: 88,
            chain_seq: 4,
            event_id: 'evt-4',
            expected_hash: 'aaa',
            actual_hash: 'bbb',
            message: BREAK_MESSAGE,
          },
        },
      ],
      reanchored_segments: [],
      ...overrides,
    };
  }

  it('locates the first break from a broken CHAIN when the global chain has none', () => {
    const out = textFor({ ledger: ok(integrity()) });

    expect(out).toContain(row('ledger.healthy', 'false'));
    expect(out).toContain(row('ledger.degraded', 'true'));
    expect(out).toContain(row('ledger.chain_count', '2'));
    expect(out).toContain(row('ledger.unverified_chain_count', '1'));
    // The break's LOCATION: a canonical chain id and a variant name, both machine tokens.
    expect(out).toContain(row('ledger.first_break.chain', 'book:7a1d'));
    expect(out).toContain(row('ledger.first_break.kind', 'HashMismatch'));
    expect(out).toContain(row('ledger.first_break.global_seq', '88'));
  });

  it('never carries the break narration, which names the act and the entity', () => {
    const out = textFor({ ledger: ok(integrity()) });

    expect(out).not.toContain(BREAK_MESSAGE);
    expect(out).not.toContain('Encosto Estratégico');
    expect(out).not.toContain('Reunião de 3');
  });

  it('prefers the global chain break over a chain one, and reports a healthy ledger without any', () => {
    const healthy = integrity({
      healthy: true,
      degraded: false,
      chains: [
        {
          chain: 'book:9f2c',
          genesis_kind: 'book.opened',
          length: 10,
          head: 'def',
          verified: true,
          first_break: null,
        },
      ],
      reanchored_segments: [
        {
          actor: 'amelia.marques',
          at: '2026-05-01T00:00:00Z',
          reason: 'restored from backup',
          affected: [],
          original_global_head: 'old-head',
          new_global_head: 'new-head',
          pre_reanchor_digest: 'digest',
        },
      ],
    });
    const out = textFor({ ledger: ok(healthy) });

    expect(out).toContain(row('ledger.unverified_chain_count', '0'));
    expect(out).toContain(row('ledger.first_break.chain', '<unset>'));
    expect(out).toContain(row('ledger.first_break.global_seq', '<unset>'));
    // A re-anchor is COUNTED; its actor and its reason are not part of a diagnostics dump.
    expect(out).toContain(row('ledger.reanchored_segment_count', '1'));
    expect(out).not.toContain('restored from backup');
  });

  it('keeps a genesis-less global chain as unset rather than inventing a kind', () => {
    const report = integrity();
    const out = textFor({
      ledger: ok({ ...report, global: { ...report.global, genesis_kind: null } }),
    });
    expect(out).toContain(row('ledger.global.genesis_kind', '<unset>'));
  });
});

// --- Search ---------------------------------------------------------------------

describe('diagnostics report — search', () => {
  const FULL: SearchStatusResponse = {
    execution_mode: 'embedded',
    enabled: true,
    partial: false,
    stale: false,
    phase: 'idle',
    details_redacted: false,
    generation: 12,
    document_count: 900,
    truncated_document_count: 3,
    content_truncated: true,
    content_budget_exhausted: false,
    queue_depth: 0,
    queue_capacity: 1024,
    dropped_commands: 0,
    last_event_seq: 4120,
    last_started_at: '2026-07-29T11:00:00Z',
    last_completed_at: '2026-07-29T11:00:09Z',
    projection_writer: true,
    projector_phase: 'idle',
    projector_heartbeat_at: '2026-07-29T12:58:00Z',
    projector_heartbeat_fresh: true,
    last_error: 'failed to index ata «Reunião de 3 de março»',
    error_at: '2026-07-29T10:00:00Z',
  };

  it('reports the worker diagnostics but reduces its error prose to presence', () => {
    const out = textFor({ search: ok(FULL) });

    expect(out).toContain(row('search.enabled', 'true'));
    expect(out).toContain(row('search.execution_mode', 'embedded'));
    expect(out).toContain(row('search.phase', 'idle'));
    expect(out).toContain(row('search.details_redacted', 'false'));
    expect(out).toContain(row('search.generation', '12'));
    expect(out).toContain(row('search.document_count', '900'));
    expect(out).toContain(row('search.projector_heartbeat_fresh', 'true'));
    expect(out).toContain(row('search.last_error', 'true'));
    expect(out).toContain(row('search.error_at', '2026-07-29T10:00:00Z'));
    // The indexed document's title is exactly the kind of content that must not ride along.
    expect(out).not.toContain('Reunião de 3');
  });

  it('renders a permission-redacted status as unset rows, distinct from an unread source', () => {
    const redacted: SearchStatusResponse = {
      execution_mode: 'query-only',
      enabled: true,
      partial: false,
      stale: true,
      phase: 'idle',
      details_redacted: true,
    };
    const out = textFor({ search: ok(redacted) });

    // `details_redacted` is what tells the operator the blanks are a permission boundary.
    expect(out).toContain(row('search.details_redacted', 'true'));
    expect(out).toContain(row('search.generation', '<unset>'));
    expect(out).toContain(row('search.queue_depth', '<unset>'));
    expect(out).toContain(row('search.projection_writer', '<unknown>'));
    expect(out).toContain(row('search.last_error', 'false'));
    // The section itself still answered — the source is `ok`, not a failure.
    expect(out).toContain('[search] source=ok');
  });
});

// --- Trust list -----------------------------------------------------------------

describe('diagnostics report — trust list', () => {
  const SUMMARY: TslSummaryView = {
    source: { kind: 'Cache', path: null, note: '' },
    last_refresh: null,
    scheme_operator_name: 'Gabinete Nacional de Segurança',
    scheme_name: 'PT TSL',
    scheme_territory: 'PT',
    sequence_number: 88,
    issue_date_time: '2026-07-01T00:00:00Z',
    next_update: '2026-08-01T00:00:00Z',
    stale: false,
    validation: { checked_at: '2026-07-29T12:00:00Z', signature: 'Valid', error: null },
    providers: 14,
    services: 60,
    ca_qc_services: 9,
    qualified_esignature_services: 12,
    trusted_esignature_services: 20,
  };

  it('counts the trust list and leaves the never-refreshed rows unset', () => {
    const out = textFor({ trust: ok(SUMMARY) });

    expect(out).toContain(row('trust.scheme_territory', 'PT'));
    expect(out).toContain(row('trust.sequence_number', '88'));
    expect(out).toContain(row('trust.stale', 'false'));
    expect(out).toContain(row('trust.validation.signature', 'Valid'));
    expect(out).toContain(row('trust.validation.error', 'false'));
    expect(out).toContain(row('trust.services', '60'));
    expect(out).toContain(row('trust.last_refresh.attempted_at', '<unset>'));
    expect(out).toContain(row('trust.last_refresh.outcome', '<unset>'));
    expect(out).toContain(row('trust.last_refresh.error', '<unset>'));
  });

  it('reports a failed refresh by outcome and source kind, not by its error text', () => {
    const out = textFor({
      trust: ok({
        ...SUMMARY,
        stale: true,
        sequence_number: null,
        issue_date_time: null,
        next_update: null,
        validation: {
          checked_at: '2026-07-29T12:00:00Z',
          signature: 'Invalid',
          error: 'signer certificate not in the scheme',
        },
        last_refresh: {
          attempted_at: '2026-07-29T11:30:00Z',
          source_kind: 'Url',
          source_url: 'https://tsl.internal/amelia-marques/PT.xml',
          source_path: null,
          target_path: 'C:\\Users\\amelia.marques\\tsl.xml',
          outcome: 'Failed',
          validation: {
            checked_at: '2026-07-29T11:30:00Z',
            signature: 'Invalid',
            error: 'signer certificate not in the scheme',
          },
          providers: null,
          services: null,
          ca_qc_services: null,
          qualified_esignature_services: null,
          trusted_esignature_services: null,
          error: 'connection refused by tsl.internal',
        },
      }),
    });

    expect(out).toContain(row('trust.last_refresh.outcome', 'Failed'));
    expect(out).toContain(row('trust.last_refresh.source_kind', 'Url'));
    expect(out).toContain(row('trust.last_refresh.error', 'true'));
    expect(out).toContain(row('trust.validation.error', 'true'));
    expect(out).toContain(row('trust.sequence_number', '<unset>'));
    // Neither the URL nor the local target path is a diagnostic fact worth disclosing.
    expect(out).not.toContain('tsl.internal');
    expect(out).not.toContain('amelia.marques');
    expect(out).not.toContain('signer certificate');
  });
});
