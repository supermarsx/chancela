/**
 * DEFAULT_SETTINGS invariants (t57-S4).
 *
 * The optimistic client default must mirror the backend/contract default byte-for-byte so the UI
 * matches before the first GET resolves. In particular the TSA endpoint is plain `http` — RFC 3161
 * timestamping uses http, and the contract fixture (`contracts/settings.json`) is http — so the web
 * default must NOT "upgrade" it to https (that mismatch was the t57 Slice-1 bug this pins closed).
 */
import { describe, it, expect } from 'vitest';
import { DEFAULT_SETTINGS } from './types';

describe('DEFAULT_SETTINGS.signing', () => {
  it('keeps the TSA URL on plain http (RFC 3161; matches the backend/contract default)', () => {
    expect(DEFAULT_SETTINGS.signing.tsa_url).toBe('http://ts.cartaodecidadao.pt/tsa/server');
    expect(DEFAULT_SETTINGS.signing.tsa_url?.startsWith('https://')).toBe(false);
  });

  it('defaults the preferred family to the recommended Chave Móvel Digital', () => {
    expect(DEFAULT_SETTINGS.signing.preferred_family).toBe('ChaveMovelDigital');
  });

  it('carries the serde-defaulted CMD config (preprod, no ApplicationId, cert not configured)', () => {
    expect(DEFAULT_SETTINGS.signing.cmd).toEqual({
      env: 'preprod',
      application_id: null,
      ama_cert_configured: false,
    });
  });

  it('mirrors the default configured TSL and TSA trust sources', () => {
    expect(DEFAULT_SETTINGS.signing.tsl_sources.map((source) => source.id)).toEqual([
      'pt-gns',
      'eu-lotl',
    ]);
    expect(DEFAULT_SETTINGS.signing.tsl_sources[0]).toMatchObject({
      enabled: true,
      url: 'https://www.gns.gov.pt/media/TSLPT.xml',
      country: 'PT',
      scheme: 'eidas',
      timeout_seconds: 30,
      max_bytes: 26214400,
      refresh: { enabled: false, cadence: { kind: 'daily', hour_utc: 3 } },
    });
    expect(DEFAULT_SETTINGS.signing.tsa_providers).toEqual([
      {
        id: 'pt-cc',
        name: 'Portugal Cartao de Cidadao TSA',
        enabled: true,
        url: 'http://ts.cartaodecidadao.pt/tsa/server',
        path: null,
        default: true,
        policy: null,
        digest: 'sha256',
        timeout_seconds: 30,
        max_bytes: 1048576,
      },
    ]);
  });

  it('surfaces non-secret provider-mode metadata by default', () => {
    expect(DEFAULT_SETTINGS.signing.providers.map((p) => p.mode)).toEqual([
      'CMD',
      'CC',
      'CSC_QTSP',
      'LOCAL_PKCS12',
    ]);
    expect(DEFAULT_SETTINGS.signing.providers.find((p) => p.id === 'soft_pkcs12')).toMatchObject({
      configured: false,
      production_blocked: true,
      local_only: true,
    });
  });
});

describe('DEFAULT_SETTINGS.ui', () => {
  it('defaults registered entities to the compact operational column set', () => {
    expect(DEFAULT_SETTINGS.ui.registered_entity_columns).toEqual([
      'Name',
      'Nipc',
      'Type',
      'LastActivity',
      'Actions',
    ]);
  });
});

describe('DEFAULT_SETTINGS.platform', () => {
  it('mirrors backend platform logging and desired-state defaults', () => {
    expect(DEFAULT_SETTINGS.platform.logging).toEqual({
      global: 'info',
      app: 'info',
      api: 'info',
      mcp: 'info',
      service_overrides: {},
    });
    expect(DEFAULT_SETTINGS.platform.api_server).toEqual({
      enabled: true,
      desired_state: 'running',
      last_action: null,
    });
    expect(DEFAULT_SETTINGS.platform.mcp_stdio_server).toEqual({
      enabled: false,
      desired_state: 'stopped',
      last_action: null,
    });
    expect(DEFAULT_SETTINGS.platform.audit).toEqual([]);
  });
});

describe('DEFAULT_SETTINGS.workflow', () => {
  it('defaults local dashboard reminders to the existing generated output policy', () => {
    expect(DEFAULT_SETTINGS.workflow.reminders).toEqual({
      enabled: true,
      dashboard_limit: 5,
      due_soon_days: 45,
      attendance_lookahead_days: 45,
      sources: {
        profile_calendar: true,
        act_follow_ups: true,
        attendance_hygiene: true,
        privacy_control_reviews: true,
      },
    });
  });
});
