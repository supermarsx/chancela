import { describe, expect, it } from 'vitest';
import { API_BASE_URL_ENV, resolveApiBaseUrl, resolveApiUrl } from './baseUrl';

describe('api base URL resolution', () => {
  it('keeps browser and Tauri defaults relative', () => {
    const options = { env: {}, win: {} };

    expect(resolveApiBaseUrl(options)).toBe('');
    expect(resolveApiUrl('/v1/entities', options)).toBe('/v1/entities');
    expect(resolveApiUrl('/health', options)).toBe('/health');
  });

  it('uses an explicit environment API base URL override', () => {
    const options = {
      env: { [API_BASE_URL_ENV]: 'https://api.example.test/chancela///' },
      win: {},
    };

    expect(resolveApiBaseUrl(options)).toBe('https://api.example.test/chancela');
    expect(resolveApiUrl('/v1/entities?limit=10', options)).toBe(
      'https://api.example.test/chancela/v1/entities?limit=10',
    );
  });

  it('lets runtime config override build-time config', () => {
    const options = {
      env: { [API_BASE_URL_ENV]: 'https://build.example.test' },
      win: {
        __CHANCELA_CONFIG__: { apiBaseUrl: 'https://runtime.example.test/api/' },
      },
    };

    expect(resolveApiUrl('/health', options)).toBe('https://runtime.example.test/api/health');
  });

  it('uses a mobile shell injected API base URL', () => {
    const options = {
      env: {},
      win: {
        __CHANCELA_MOBILE_SHELL__: { apiBaseUrl: 'http://10.0.2.2:8080/' },
      },
    };

    expect(resolveApiBaseUrl(options)).toBe('http://10.0.2.2:8080');
    expect(resolveApiUrl('/v1/session', options)).toBe('http://10.0.2.2:8080/v1/session');
  });

  it('does not rewrite already absolute URLs', () => {
    const options = {
      env: { [API_BASE_URL_ENV]: 'https://api.example.test' },
      win: {},
    };

    expect(resolveApiUrl('https://cdn.example.test/document.pdf', options)).toBe(
      'https://cdn.example.test/document.pdf',
    );
  });
});
