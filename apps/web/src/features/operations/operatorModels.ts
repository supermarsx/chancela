import type {
  ConnectorKind,
  ConnectorSecretReference,
  ConnectorTargetConfig,
  Entity,
  KeyCustodyPolicy,
} from '../../api/types';

export const CONNECTOR_KINDS: readonly ConnectorKind[] = [
  'web_dav',
  'microsoft_graph',
  'google_drive',
  'sftp',
  'ftps',
  'smb',
  's3',
];

const SECRET_REFERENCE = /^CHANCELA_CONNECTOR_SECRET_[A-Z0-9_]+$/;
const RAW_SECRET_KEY = /^(password|token|access_key|secret_key|session_token)$/i;

export function tenantIdsFromEntities(entities: Entity[]): string[] {
  return [...new Set(entities.map((entity) => entity.tenant_id).filter(Boolean))].sort();
}

export function commaSeparatedIds(value: string): string[] {
  return [
    ...new Set(
      value
        .split(',')
        .map((item) => item.trim())
        .filter(Boolean),
    ),
  ].sort();
}

export function connectorConfigTemplate(kind: ConnectorKind): ConnectorTargetConfig {
  const common = { id: 'pending-target', timeout_seconds: 60 } as const;
  switch (kind) {
    case 'web_dav':
      return {
        kind,
        ...common,
        base_url: 'https://storage.example.invalid/dav',
        auth: {
          mode: 'basic',
          username: 'operator',
          password_ref: 'CHANCELA_CONNECTOR_SECRET_WEBDAV_PASSWORD',
        },
        allow_insecure_http: false,
      };
    case 'microsoft_graph':
      return {
        kind,
        ...common,
        drive_id: 'drive-id',
        parent_item_id: 'root',
        token_ref: 'CHANCELA_CONNECTOR_SECRET_GRAPH_TOKEN',
        api_base_url: 'https://graph.microsoft.com/v1.0',
        allow_insecure_http: false,
      };
    case 'google_drive':
      return {
        kind,
        ...common,
        parent_folder_id: 'folder-id',
        token_ref: 'CHANCELA_CONNECTOR_SECRET_GOOGLE_TOKEN',
        api_base_url: 'https://www.googleapis.com',
        allow_insecure_http: false,
      };
    case 'sftp':
      return {
        kind,
        ...common,
        host: 'sftp.example.invalid',
        port: 22,
        username: 'operator',
        password_ref: 'CHANCELA_CONNECTOR_SECRET_SFTP_PASSWORD',
        host_key_sha256: 'SHA256:replace-with-pinned-ed25519-or-ecdsa-fingerprint',
        root: '/chancela',
      };
    case 'ftps':
      return {
        kind,
        ...common,
        host: 'ftps.example.invalid',
        port: 21,
        username: 'operator',
        password_ref: 'CHANCELA_CONNECTOR_SECRET_FTPS_PASSWORD',
        root: '/chancela',
      };
    case 'smb':
      return {
        kind,
        ...common,
        host: 'files.example.invalid',
        port: 445,
        share: 'records',
        username: 'operator',
        domain: '',
        password_ref: 'CHANCELA_CONNECTOR_SECRET_SMB_PASSWORD',
        root: 'chancela',
        allow_unencrypted: false,
      };
    case 's3':
      return {
        kind,
        ...common,
        bucket: 'chancela-backups',
        prefix: '',
        region: 'eu-west-1',
        endpoint_url: null,
        force_path_style: false,
        access_key_ref: 'CHANCELA_CONNECTOR_SECRET_S3_ACCESS_KEY',
        secret_key_ref: 'CHANCELA_CONNECTOR_SECRET_S3_SECRET_KEY',
        session_token_ref: null,
        allow_insecure_http: false,
      };
  }
}

function inspectCredentialBoundary(value: unknown, path = 'config'): void {
  if (Array.isArray(value)) {
    value.forEach((item, index) => inspectCredentialBoundary(item, `${path}[${index}]`));
    return;
  }
  if (!value || typeof value !== 'object') return;
  for (const [key, item] of Object.entries(value)) {
    const field = `${path}.${key}`;
    if (RAW_SECRET_KEY.test(key)) {
      throw new Error(`${field} looks like secret material; submit a *_ref field instead`);
    }
    if (key.endsWith('_ref')) {
      if (item === null) continue;
      if (typeof item !== 'string' || !SECRET_REFERENCE.test(item)) {
        throw new Error(
          `${field} must be a CHANCELA_CONNECTOR_SECRET_* environment or confined-file reference`,
        );
      }
      continue;
    }
    inspectCredentialBoundary(item, field);
  }
}

/** Parse the advanced connector editor without allowing raw credential fields through. */
export function parseConnectorConfig(
  raw: string,
  expectedKind: ConnectorKind,
): ConnectorTargetConfig {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error('Connector configuration must be valid JSON');
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('Connector configuration must be a JSON object');
  }
  const candidate = parsed as { kind?: unknown; id?: unknown };
  if (candidate.kind !== expectedKind) {
    throw new Error(`Connector configuration kind must remain ${expectedKind}`);
  }
  if (typeof candidate.id !== 'string' || !candidate.id.trim()) {
    throw new Error('Connector configuration needs a non-empty placeholder id');
  }
  inspectCredentialBoundary(candidate);
  return candidate as ConnectorTargetConfig;
}

export interface CustodyFormState {
  byok: boolean;
  webauthn: boolean;
  splitRecovery: boolean;
  threshold: string;
  shareCount: string;
  custodianLabels: string;
}

export const EMPTY_CUSTODY_FORM: CustodyFormState = {
  byok: true,
  webauthn: false,
  splitRecovery: false,
  threshold: '2',
  shareCount: '3',
  custodianLabels: '',
};

export function custodyPolicyFromForm(form: CustodyFormState): KeyCustodyPolicy {
  const labels = commaSeparatedIds(form.custodianLabels);
  const threshold = Number(form.threshold);
  const shareCount = Number(form.shareCount);
  if (form.splitRecovery) {
    if (!Number.isInteger(threshold) || !Number.isInteger(shareCount)) {
      throw new Error('Recovery threshold and share count must be whole numbers');
    }
    if (threshold < 2 || shareCount < threshold || labels.length !== shareCount) {
      throw new Error('Recovery needs at least two shares and one public label per custodian');
    }
  }
  if (!form.byok && !form.webauthn && !form.splitRecovery) {
    throw new Error('A zero-knowledge policy needs at least one client custody method');
  }
  return {
    bring_your_own_key: form.byok,
    webauthn_prf_unsealing: form.webauthn,
    split_key_recovery: form.splitRecovery
      ? { threshold, share_count: shareCount, custodian_labels: labels }
      : null,
  };
}

export function connectorSecretReference(value: string): ConnectorSecretReference {
  if (!SECRET_REFERENCE.test(value)) throw new Error('Invalid connector secret reference');
  return value as ConnectorSecretReference;
}
