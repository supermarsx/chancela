import { describe, expect, it } from 'vitest';
import type { Entity } from '../../api/types';
import {
  CONNECTOR_KINDS,
  EMPTY_CUSTODY_FORM,
  commaSeparatedIds,
  connectorConfigTemplate,
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
  });
});
