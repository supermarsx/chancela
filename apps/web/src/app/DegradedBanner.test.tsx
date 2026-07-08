import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, screen, waitFor } from '@testing-library/react';
import { DegradedBanner } from './DegradedBanner';
import { renderWithProviders } from '../test/utils';

function healthFetch(body: unknown): typeof fetch {
  return (() =>
    Promise.resolve(
      new Response(JSON.stringify(body), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )) as typeof fetch;
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('DegradedBanner', () => {
  it('shows a loud read-only banner when the server reports a degraded/broken chain', async () => {
    vi.stubGlobal('fetch', healthFetch({ status: 'ok', integrity: 'broken', degraded: true }));
    renderWithProviders(<DegradedBanner />);

    const banner = await screen.findByRole('alert');
    expect(banner.textContent).toContain('Sistema em modo só-leitura');
    // It links to the repair surface.
    expect(screen.getByRole('link', { name: 'Abrir Livros & Integridade' })).toBeTruthy();
  });

  it('renders nothing when the server reports a healthy chain', async () => {
    vi.stubGlobal('fetch', healthFetch({ status: 'ok', integrity: 'ok', degraded: false }));
    const { container } = renderWithProviders(<DegradedBanner />);
    // Give the health query a tick to resolve, then assert the banner never appears.
    await waitFor(() => expect(container.querySelector('.degraded-banner')).toBeNull());
  });
});
