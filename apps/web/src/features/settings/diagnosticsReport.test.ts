/**
 * Tests for the diagnostics report model.
 *
 * The centrepiece is `never exports a secret`. It is not a nicety: the report is copied to a
 * clipboard, printed and written to a file that gets attached to a support ticket, so a single
 * echoed credential is an unrecoverable disclosure. The fixture deliberately feeds Tier B rows that
 * DO carry values — a server that regressed, or a hand-corrupted override file that reached the
 * client — and asserts none of those values appears anywhere in the rendered text. If someone ever
 * "simplifies" `envVarRows` into passing `effective_value` through unconditionally, this fails.
 *
 * The rest pins the other two rules the model exists to enforce: no personal datum from the
 * delivery log or the credential store reaches the export, and a source that did not answer
 * produces explicit unknowns rather than a green row.
 */
import { describe, expect, it } from 'vitest';
import {
  buildDiagnosticsReport,
  diagnosticsFilename,
  isoWithOffset,
  renderDiagnosticsText,
  safeFilenamePart,
  type DiagnosticsInput,
  type DiagnosticsSource,
} from './diagnosticsReport';
import type {
  EmailDeliveryView,
  ProviderCredentialsListView,
  ServerEnvResponse,
  ServerEnvVarView,
} from '../../api/types';

const AT = new Date('2026-07-29T13:04:05.000Z');

/** A source that answered. */
const ok = <T>(data: T): DiagnosticsSource<T> => ({ state: { kind: 'ok' }, data });
/** A source nothing was heard from. */
const absent = <T>(): DiagnosticsSource<T> => ({
  state: { kind: 'not_checked', reason: 'no_response' },
  data: undefined,
});
const refused = <T>(): DiagnosticsSource<T> => ({ state: { kind: 'forbidden' }, data: undefined });

function envVar(overrides: Partial<ServerEnvVarView> = {}): ServerEnvVarView {
  return {
    name: 'CHANCELA_LOG',
    group: 'logging',
    tier: 'A',
    editable: true,
    secret: false,
    boundary: false,
    narrow_only: false,
    acknowledgement_required: false,
    excluded_typed_slice: null,
    external_reader: null,
    source: 'env',
    configured: true,
    effective_value: 'info',
    override_value: null,
    default_value: 'info',
    restart_pending: false,
    validator: { kind: 'free_text', allowed: null },
    ...overrides,
  };
}

/**
 * The hostile fixture: every secret family the panel must never echo, each carrying a value the
 * real server would have masked. A DIFFERENT, unmistakable value per row, so a leak names itself.
 */
const SECRET_VALUES = {
  CHANCELA_DB_KEY: 'sqlcipher-passphrase-LEAK1',
  DATABASE_URL: 'postgres://chancela:LEAK2@db.internal/chancela',
  REDIS_URL: 'redis://:LEAK3@cache.internal:6379',
  CHANCELA_CREDENTIAL_KEY: 'credential-root-LEAK4',
  CHANCELA_SEARCH_DATABASE_URL: 'postgres://projector:LEAK5@db.internal/search',
  CHANCELA_MCP_API_KEY: 'mcp-LEAK6',
  CHANCELA_CSC_ACME_CLIENT_SECRET: 'csc-LEAK7',
  CHANCELA_CONNECTOR_SECRET_SFTP: 'connector-LEAK8',
  CHANCELA_CMD_APPLICATION_ID: 'cmd-LEAK9',
  CHANCELA_SCAP_KEYSTORE_PASSWORD: 'scap-LEAK10',
} as const;

function leakyEnvResponse(): ServerEnvResponse {
  const secrets = Object.entries(SECRET_VALUES).map(([name, value]) =>
    envVar({
      name,
      tier: 'B',
      secret: true,
      editable: false,
      group: 'credentials',
      configured: true,
      // A compliant server sends `null` for all three. These are populated on purpose.
      effective_value: value,
      override_value: value,
      default_value: value,
    }),
  );
  return {
    vars: [envVar(), ...secrets],
    restart_pending: false,
    overrides_path: '/var/lib/chancela/env-overrides.json',
    generated_at: '2026-07-29T12:00:00Z',
  };
}

function delivery(overrides: Partial<EmailDeliveryView> = {}): EmailDeliveryView {
  return {
    id: 'd1',
    template_id: 'user.welcome',
    recipient: 'amelia.marques@encosto-estrategico.example',
    user_id: 'user-9f2c',
    status: 'failed',
    attempt: 1,
    failure_stage: 'auth',
    failure_kind: 'rejected',
    failure_code: 535,
    failure_detail: 'authentication failed for amelia.marques',
    created_at: '2026-07-29T10:00:00Z',
    actor: 'amelia.marques',
    resendable: true,
    ...overrides,
  };
}

function credentials(): ProviderCredentialsListView {
  return {
    strict: true,
    protection_level: 'confidential',
    can_store: true,
    providers: [
      {
        mode: 'csc',
        provider_id: 'acme-qtsp',
        entries: [
          {
            entry_id: 'e1',
            // Operator-typed free text that routinely names a person.
            label: 'cartão da Amélia Marques',
            priority: 1,
            enabled: true,
            endpoint: 'https://csc.example/api',
            selectors: { credentialID: 'amelia.marques' },
            fields: [
              { field_name: 'client_secret', configured: true },
              { field_name: 'client_id', configured: false },
            ],
            created_at: '2026-01-01T00:00:00Z',
            updated_at: '2026-01-01T00:00:00Z',
          },
        ],
      },
    ],
  };
}

/** Every source absent unless a test supplies one. */
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

/** The exact line the renderer emits for one field, so assertions never hand-count padding. */
const row = (id: string, token: string): string => `${id.padEnd(46)} = ${token}`;

function textFor(overrides: Partial<DiagnosticsInput> = {}): string {
  return renderDiagnosticsText(buildDiagnosticsReport(input(overrides)));
}

describe('diagnostics report — secrets', () => {
  it('never exports a secret value, even when the payload carries one', () => {
    const text = textFor({ env: ok(leakyEnvResponse()) });

    for (const [name, value] of Object.entries(SECRET_VALUES)) {
      // The variable's NAME is a machine identifier and must be quotable; its VALUE must not
      // appear anywhere in the export, in any form.
      expect(text, `${name} name missing`).toContain(name);
      expect(text, `${name} value leaked`).not.toContain(value);
    }
    // The distinctive fragments each fixture value was built around, independently of the whole.
    for (const marker of Object.values(SECRET_VALUES).flatMap((v) => v.match(/LEAK\d+/g) ?? [])) {
      expect(text, `${marker} leaked`).not.toContain(marker);
    }
  });

  it('reports a secret only as configured or not configured', () => {
    const text = textFor({ env: ok(leakyEnvResponse()) });
    expect(text).toContain(row('env.var.CHANCELA_DB_KEY.configured', 'configured'));
    // The three value-bearing rows exist for non-secret vars and for no secret var.
    expect(text).toContain('env.var.CHANCELA_LOG.value');
    expect(text).not.toContain('env.var.CHANCELA_DB_KEY.value');
    expect(text).not.toContain('env.var.CHANCELA_DB_KEY.override');
    expect(text).not.toContain('env.var.CHANCELA_DB_KEY.default');
  });

  it('counts secrets without naming their contents', () => {
    const text = textFor({ env: ok(leakyEnvResponse()) });
    expect(text).toContain('env.secret_count');
    expect(text).toContain('env.secret_configured_count');
  });
});

describe('diagnostics report — personal data', () => {
  it('aggregates the delivery log to counts and never carries a recipient', () => {
    const text = textFor({
      deliveries: ok([
        delivery(),
        delivery({ id: 'd2', status: 'sent', failure_stage: undefined, failure_kind: undefined }),
        delivery({ id: 'd3', attempt: 2, failure_stage: 'tls', failure_kind: 'tls' }),
      ]),
    });

    expect(text).toContain('email.deliveries.count');
    expect(text).toContain('email.deliveries.failure_stage.auth');
    expect(text).toContain('email.deliveries.failure_kind.rejected');
    expect(text).not.toContain('amelia.marques');
    expect(text).not.toContain('@encosto-estrategico.example');
    expect(text).not.toContain('user-9f2c');
    // The relay's own words name the account it rejected.
    expect(text).not.toContain('authentication failed');
  });

  it('reduces credential entries to counts and drops their operator-typed labels', () => {
    const text = textFor({ credentials: ok(credentials()) });

    expect(text).toContain('credentials.csc.acme-qtsp.entry_count');
    expect(text).toContain('credentials.csc.acme-qtsp.configured_field_count');
    expect(text).not.toContain('Amélia');
    expect(text).not.toContain('cartão da');
    expect(text).not.toContain('csc.example');
  });
});

describe('diagnostics report — honest unknowns', () => {
  it('renders a source that did not answer as unknown, never as a pass', () => {
    const report = buildDiagnosticsReport(input());
    const health = report.sections.find((section) => section.id === 'health');

    expect(health?.source).toEqual({ kind: 'not_checked', reason: 'no_response' });
    expect(health?.rows.map((row) => row.value.kind)).toEqual([
      'unknown',
      'unknown',
      'unknown',
      'unknown',
      'unknown',
    ]);
  });

  it('marks a refused source as forbidden in the export', () => {
    const text = textFor({ ledger: refused() });
    expect(text).toContain('[ledger] source=forbidden');
    expect(text).toContain(row('ledger.healthy', '<unknown>'));
  });

  it('never emits an "ok" token for a source it did not read', () => {
    const report = buildDiagnosticsReport(input());
    // Only the two client-side sections (the header and the not-covered list) may be `ok` when
    // nothing answered. Everything else must carry its own honest state.
    const okSections = report.sections
      .filter((section) => section.source.kind === 'ok')
      .map((section) => section.id);
    expect(okSections).toEqual(['report', 'not_covered']);
  });

  it('lists what it deliberately does not cover with a machine reason', () => {
    const text = textFor();
    expect(text).toContain(row('not_covered.cluster_runtime', 'no_client_endpoint'));
    expect(text).toContain(row('not_covered.accounts', 'personal_data'));
    expect(text).toContain(row('not_covered.secret_values', 'never_exported'));
  });
});

describe('diagnostics report — provenance and format', () => {
  it('heads the export with the facts a support ticket needs', () => {
    const text = textFor({
      build: {
        hash: '744f82f2c1d4b6a8e0f13579bd2468ace0135791',
        shortHash: '744f82f2c1d4',
        committedAt: '2026-07-20T09:11:00+01:00',
        codename: 'Riólito',
      },
      settingsSchemaVersion: ok(7),
    });

    expect(text.startsWith('CHANCELA DIAGNOSTICS REPORT\n')).toBe(true);
    expect(text).toContain(row('report.locale', 'pt-PT'));
    expect(text).toContain(row('report.ui_version', '26.1.0'));
    expect(text).toContain(row('report.time_zone', 'Europe/Lisbon'));
    expect(text).toContain(row('report.build.provenance', 'available'));
    expect(text).toContain(row('report.build.commit', '744f82f2c1d4b6a8e0f13579bd2468ace0135791'));
    expect(text).toContain(row('report.settings.schema_version', '7'));
  });

  it('says so when the build carries no provenance', () => {
    const text = textFor();
    expect(text).toContain(row('report.build.provenance', 'absent'));
    expect(text).toContain(row('report.build.commit', '<unset>'));
  });

  it('keeps the key column at a constant width so two dumps diff cleanly', () => {
    const short = textFor();
    const long = textFor({ env: ok(leakyEnvResponse()) });
    const columnOf = (text: string, id: string) =>
      text
        .split('\n')
        .find((row) => row.startsWith(id))
        ?.indexOf('=');

    expect(columnOf(short, 'report.locale')).toBe(columnOf(long, 'report.locale'));
  });

  it('renders an ISO 8601 instant with an explicit offset', () => {
    expect(isoWithOffset(AT)).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2}$/);
  });

  it('is deterministic — the same input renders the same bytes', () => {
    const first = textFor({ env: ok(leakyEnvResponse()) });
    const second = textFor({ env: ok(leakyEnvResponse()) });
    expect(first).toBe(second);
  });
});

describe('diagnostics report — filename', () => {
  it('carries the instance and a filesystem-safe UTC stamp', () => {
    expect(diagnosticsFilename('chancela.example:8443', AT)).toBe(
      'chancela-diagnostics-chancela.example-8443-20260729T130405Z.txt',
    );
  });

  it('strips anything a filesystem would refuse', () => {
    expect(safeFilenamePart('../../etc/passwd')).toBe('etc-passwd');
    expect(safeFilenamePart('a<b>c:d"e|f?g*h')).toBe('a-b-c-d-e-f-g-h');
    expect(safeFilenamePart('')).toBe('instance');
    expect(safeFilenamePart('...')).toBe('instance');
  });
});
