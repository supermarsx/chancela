import {
  getMobileShellConfig,
  type ChancelaMobileShellConfig,
  type MobileShellWindow,
} from '../shell/mobileShell';

export const API_BASE_URL_ENV = 'VITE_CHANCELA_API_BASE_URL';

export interface ChancelaRuntimeConfig {
  apiBaseUrl?: unknown;
  api_base_url?: unknown;
}

export interface ApiBaseUrlWindow extends MobileShellWindow {
  __CHANCELA_CONFIG__?: ChancelaRuntimeConfig;
}

export interface ApiUrlResolutionOptions {
  env?: Partial<Record<typeof API_BASE_URL_ENV, string | undefined>>;
  win?: ApiBaseUrlWindow;
}

function currentWindow(): ApiBaseUrlWindow | undefined {
  return typeof window === 'undefined' ? undefined : (window as unknown as ApiBaseUrlWindow);
}

function stringValue(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function configBaseUrl(config: ChancelaRuntimeConfig | ChancelaMobileShellConfig | undefined): string {
  return stringValue(config?.apiBaseUrl) || stringValue(config?.api_base_url);
}

export function normalizeApiBaseUrl(value: string): string {
  return value.trim().replace(/\/+$/, '');
}

export function resolveApiBaseUrl(options: ApiUrlResolutionOptions = {}): string {
  const win = options.win ?? currentWindow();
  const runtimeConfig = configBaseUrl(win?.__CHANCELA_CONFIG__);
  const mobileConfig = configBaseUrl(getMobileShellConfig(win));
  const envConfig = stringValue(
    options.env?.[API_BASE_URL_ENV] ?? import.meta.env.VITE_CHANCELA_API_BASE_URL,
  );

  return normalizeApiBaseUrl(runtimeConfig || mobileConfig || envConfig);
}

export function resolveApiUrl(path: string, options: ApiUrlResolutionOptions = {}): string {
  const baseUrl = resolveApiBaseUrl(options);
  if (!baseUrl) return path;
  if (/^[a-z][a-z0-9+.-]*:/i.test(path)) return path;
  return `${baseUrl}/${path.replace(/^\/+/, '')}`;
}
