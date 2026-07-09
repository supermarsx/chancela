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
