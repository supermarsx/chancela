import type { CredentialMode } from '../../api/types';

const MODES: readonly CredentialMode[] = ['cmd', 'csc', 'scap', 'pkcs12'];

export function isCredentialMode(value: string | null | undefined): value is CredentialMode {
  return value !== null && value !== undefined && (MODES as readonly string[]).includes(value);
}

export function providerCredentialCreatePath(mode?: CredentialMode, providerId?: string): string {
  const params = new URLSearchParams();
  if (mode) params.set('mode', mode);
  if (providerId !== undefined) params.set('provider', providerId);
  const query = params.toString();
  return `/admin/signing/providers/new${query ? `?${query}` : ''}`;
}

export function providerCredentialEditPath(
  mode: CredentialMode,
  providerId: string,
  entryId: string,
): string {
  return `/admin/signing/providers/${encodeURIComponent(mode)}/${encodeURIComponent(
    providerId || '_',
  )}/${encodeURIComponent(entryId)}/edit`;
}

export function decodeProviderSegment(value: string): string {
  return value === '_' ? '' : value;
}
