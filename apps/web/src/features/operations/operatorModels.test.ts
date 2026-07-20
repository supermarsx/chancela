import { describe, expect, it } from 'vitest';
import type { Entity } from '../../api/types';
import {
  CONNECTOR_KINDS,
  EMPTY_CUSTODY_FORM,
  commaSeparatedIds,
  connectorConfigTemplate,
  connectorSecretReference,
  custodyPolicyFromForm,
  parseConnectorConfig,
  tenantIdsFromEntities,
} from './operatorModels';

describe('operator contract models', () => {
  it('derives stable unique tenant choices only from authoritative entity DTOs', () => {
    const entities = [
      { id: 'e1', tenant_id: 'tenant-b' },
      { id: 'e2', tenant_id: 'tenant-a' },
      { id: 'e3', tenant_id: 'tenant-b' },
    ] as Entity[];
    expect(tenantIdsFromEntities(entities)).toEqual(['tenant-a', 'tenant-b']);
  });

  it('normalizes duplicate comma-separated immutable ids deterministically', () => {
    expect(commaSeparatedIds(' tpl-b, tpl-a, tpl-b ,, ')).toEqual(['tpl-a', 'tpl-b']);
  });

  it('ships a secret-reference-only valid template for every API connector kind', () => {
    for (const kind of CONNECTOR_KINDS) {
      const template = connectorConfigTemplate(kind);
      expect(parseConnectorConfig(JSON.stringify(template), kind)).toEqual(template);
      const serialized = JSON.stringify(template);
      expect(serialized).not.toMatch(/"(?:password|token|access_key|secret_key)":/i);
    }
  });

  it('rejects malformed, kind-swapped, raw-secret, and unconfined-reference configuration', () => {
    expect(() => parseConnectorConfig('{', 'web_dav')).toThrow('valid JSON');
    expect(() =>
      parseConnectorConfig(JSON.stringify(connectorConfigTemplate('s3')), 'web_dav'),
    ).toThrow('kind must remain');
    expect(() =>
      parseConnectorConfig(
        JSON.stringify({ kind: 'web_dav', id: 'x', password: 'actual-secret' }),
        'web_dav',
      ),
    ).toThrow('secret material');
    expect(() =>
      parseConnectorConfig(
        JSON.stringify({ kind: 'web_dav', id: 'x', token_ref: 'TOKEN' }),
        'web_dav',
      ),
    ).toThrow('CHANCELA_CONNECTOR_SECRET');
  });

  it('rejects configuration that is valid JSON but not a connector object', () => {
    expect(() => parseConnectorConfig('"web_dav"', 'web_dav')).toThrow('must be a JSON object');
    expect(() => parseConnectorConfig('[]', 'web_dav')).toThrow('must be a JSON object');
    expect(() => parseConnectorConfig('null', 'web_dav')).toThrow('must be a JSON object');
    expect(() => parseConnectorConfig(JSON.stringify({ kind: 'web_dav' }), 'web_dav')).toThrow(
      'non-empty placeholder id',
    );
    expect(() =>
      parseConnectorConfig(JSON.stringify({ kind: 'web_dav', id: '   ' }), 'web_dav'),
    ).toThrow('non-empty placeholder id');
  });

  it('inspects nested and repeated structures for smuggled credentials', () => {
    expect(() =>
      parseConnectorConfig(
        JSON.stringify({ kind: 'web_dav', id: 'x', auth: { mode: 'basic', token: 'raw' } }),
        'web_dav',
      ),
    ).toThrow('config.auth.token looks like secret material');
    expect(() =>
      parseConnectorConfig(
        JSON.stringify({ kind: 'web_dav', id: 'x', hosts: [{ password_ref: 'nope' }] }),
        'web_dav',
      ),
    ).toThrow('config.hosts[0].password_ref must be a CHANCELA_CONNECTOR_SECRET_*');
  });

  it('accepts an explicitly absent optional secret reference', () => {
    const config = { kind: 'web_dav', id: 'x', session_token_ref: null };
    expect(parseConnectorConfig(JSON.stringify(config), 'web_dav')).toEqual(config);
  });

  it('admits only confined connector secret references', () => {
    expect(connectorSecretReference('CHANCELA_CONNECTOR_SECRET_S3_ACCESS_KEY')).toBe(
      'CHANCELA_CONNECTOR_SECRET_S3_ACCESS_KEY',
    );
    expect(() => connectorSecretReference('AWS_ACCESS_KEY')).toThrow(
      'Invalid connector secret reference',
    );
  });

  it('builds public custody metadata without recovery shares and enforces threshold invariants', () => {
    expect(custodyPolicyFromForm(EMPTY_CUSTODY_FORM)).toEqual({
      bring_your_own_key: true,
      webauthn_prf_unsealing: false,
      split_key_recovery: null,
    });
    expect(
      custodyPolicyFromForm({
        ...EMPTY_CUSTODY_FORM,
        splitRecovery: true,
        custodianLabels: 'Legal, Security, Continuity',
      }),
    ).toEqual({
      bring_your_own_key: true,
      webauthn_prf_unsealing: false,
      split_key_recovery: {
        threshold: 2,
        share_count: 3,
        custodian_labels: ['Continuity', 'Legal', 'Security'],
      },
    });
    expect(() =>
      custodyPolicyFromForm({
        ...EMPTY_CUSTODY_FORM,
        byok: false,
        splitRecovery: false,
      }),
    ).toThrow('at least one');
    expect(() =>
      custodyPolicyFromForm({
        ...EMPTY_CUSTODY_FORM,
        splitRecovery: true,
        threshold: '3',
        shareCount: '2',
        custodianLabels: 'A, B',
      }),
    ).toThrow('one public label');
    expect(() =>
      custodyPolicyFromForm({
        ...EMPTY_CUSTODY_FORM,
        splitRecovery: true,
        threshold: '2.5',
        custodianLabels: 'A, B, C',
      }),
    ).toThrow('whole numbers');
  });
});
