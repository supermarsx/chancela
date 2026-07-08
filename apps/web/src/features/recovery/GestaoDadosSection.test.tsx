import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react';
import { GestaoDadosSection } from './GestaoDadosSection';
import { renderWithProviders } from '../../test/utils';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

interface Recorded {
  url: string;
  method: string;
  body: string | null;
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('GestaoDadosSection', () => {
  it('offers the five distinct data-management operations', async () => {
    vi.stubGlobal('fetch', vi.fn());
    renderWithProviders(<GestaoDadosSection />);
    for (const name of [
      'Repor interface',
      'Recomeçar',
      'Limpar dados',
      'Reposição de fábrica',
      'Reposição total',
    ]) {
      expect(screen.getAllByRole('button', { name }).length).toBeGreaterThan(0);
    }
  });

  it('gates the domain wipe on the exact phrase + step-up re-auth, then calls /v1/data/reset', async () => {
    const calls: Recorded[] = [];
    const fn = ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      const method = init?.method ?? 'GET';
      calls.push({ url, method, body: (init?.body as string) ?? null });
      if (url.includes('/v1/data/reset')) {
        return Promise.resolve(
          jsonResponse({
            scope: 'BackendDomain',
            export_archive: 'exports/x.zip',
            cleared: ['entities'],
          }),
        );
      }
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch;
    vi.stubGlobal('fetch', fn);
    renderWithProviders(<GestaoDadosSection />);

    fireEvent.click(screen.getByRole('button', { name: 'Limpar dados' }));

    // The confirm button inside the modal shares the label; it is the last match.
    const confirmBtns = screen.getAllByRole('button', { name: 'Limpar dados' });
    const confirm = confirmBtns[confirmBtns.length - 1] as HTMLButtonElement;
    expect(confirm.disabled).toBe(true);

    fireEvent.change(screen.getByLabelText('Escreva LIMPAR DADOS para confirmar'), {
      target: { value: 'LIMPAR DADOS' },
    });
    // Phrase alone is not enough — step-up re-auth is required.
    expect(confirm.disabled).toBe(true);

    fireEvent.change(screen.getByLabelText('Palavra-passe'), { target: { value: 'operator-pw' } });
    expect(confirm.disabled).toBe(false);

    fireEvent.click(confirm);
    await waitFor(() => expect(calls.some((c) => c.url.includes('/v1/data/reset'))).toBe(true));

    const reset = calls.find((c) => c.url.includes('/v1/data/reset'))!;
    const sent = JSON.parse(reset.body as string);
    expect(sent.scope).toBe('backend_domain');
    expect(sent.confirm_phrase).toBe('LIMPAR DADOS');
    expect(sent.export_first).toBe(true);
    expect(sent.reauth).toEqual({ password: 'operator-pw' });

    // The cleared summary is surfaced honestly.
    expect(await screen.findByText('entities')).toBeTruthy();
  });

  it('performs the frontend reset with no server call', async () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal('fetch', fetchSpy);
    // Guard window.location.reload (not implemented in jsdom).
    const reloadSpy = vi.fn();
    Object.defineProperty(window, 'location', {
      value: { ...window.location, reload: reloadSpy },
      writable: true,
    });
    renderWithProviders(<GestaoDadosSection />);

    fireEvent.click(screen.getByRole('button', { name: 'Repor interface' }));
    // The client-only modal has no phrase / re-auth, so confirm is immediately available.
    const confirmBtns = screen.getAllByRole('button', { name: 'Repor interface' });
    fireEvent.click(confirmBtns[confirmBtns.length - 1]);

    await waitFor(() => expect(reloadSpy).toHaveBeenCalled());
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});
