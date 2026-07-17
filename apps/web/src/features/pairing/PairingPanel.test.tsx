/**
 * Behavioural tests for the companion pairing panel (wp27-e5): mint → QR/deep-link render,
 * TTL countdown, auto re-mint on expiry, enrollment reflection via the device poll, revoke,
 * and the mint error path. Tests run in the pt-PT source locale (like the sibling settings
 * tests) and drive the real hooks against a stubbed `fetch`.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, fireEvent, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { render } from '@testing-library/react';
import { PairingPanel } from './PairingPanel';
import { ToastProvider } from '../../ui/toast';
import { ALLOW_ALL_PERMISSIONS, StaticPermissionsProvider } from '../session/permissions';
import { renderWithProviders } from '../../test/utils';

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

const ACTIVE_DEVICE = {
  device_id: '9b1f6c00-0000-4000-8000-0000000000a1',
  label: 'Telemóvel da Amélia',
  created_at: '2026-07-16T10:15:30Z',
  revoked: false,
  revoked_at: null,
};

const REVOKED_DEVICE = {
  device_id: '9b1f6c00-0000-4000-8000-0000000000a2',
  label: 'Tablet de reserva',
  created_at: '2026-07-15T09:00:00Z',
  revoked: true,
  revoked_at: '2026-07-16T11:20:00Z',
};

const MINTED = {
  code: '9b1f6c0000004000800000000000a1de',
  expires_at: '2026-07-16T10:20:30Z',
  expires_in_secs: 300,
  label: 'Telemóvel da Amélia',
};

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.useRealTimers();
});

describe('PairingPanel', () => {
  it('lists enrolled devices with active and revoked status', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() => Promise.resolve(json({ devices: [ACTIVE_DEVICE, REVOKED_DEVICE] }))),
    );
    renderWithProviders(<PairingPanel />);

    expect(await screen.findByText('Telemóvel da Amélia')).toBeTruthy();
    expect(screen.getByText('Tablet de reserva')).toBeTruthy();
    expect(screen.getByText('Ativo')).toBeTruthy();
    expect(screen.getByText('Revogado')).toBeTruthy();
  });

  it('renders a scannable QR, deep-link and countdown after minting a code', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = input.toString();
        if (url.includes('/v1/pairing/codes')) return Promise.resolve(json(MINTED));
        return Promise.resolve(json({ devices: [] }));
      }),
    );
    renderWithProviders(<PairingPanel />);

    fireEvent.click(await screen.findByText('Gerar código de emparelhamento'));

    // The hand-rolled QR renders as an accessible <svg role="img">.
    expect(await screen.findByRole('img', { name: 'Código QR de emparelhamento' })).toBeTruthy();
    // The copyable deep-link carries the code, and the TTL countdown is shown.
    expect(screen.getByText(/companion_pair=9b1f6c0000004000800000000000a1de/)).toBeTruthy();
    expect(screen.getByText('Expira em 5:00')).toBeTruthy();
    expect(screen.getByText('Copiar ligação')).toBeTruthy();
  });

  it('auto re-mints a fresh code when the outstanding one expires', async () => {
    let mintCalls = 0;
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = input.toString();
        if (url.includes('/v1/pairing/codes')) {
          mintCalls += 1;
          // First code is already expired (ttl 0) → the panel must mint a fresh one.
          return Promise.resolve(
            json(mintCalls === 1 ? { ...MINTED, expires_in_secs: 0 } : MINTED),
          );
        }
        return Promise.resolve(json({ devices: [] }));
      }),
    );
    renderWithProviders(<PairingPanel />);

    fireEvent.click(await screen.findByText('Gerar código de emparelhamento'));

    // The re-mint lands a live code with a positive countdown.
    expect(await screen.findByText('Expira em 5:00')).toBeTruthy();
    await waitFor(() => expect(mintCalls).toBe(2));
  });

  it('reflects enrollment when the phone exchanges the code', async () => {
    const state = { devices: [] as unknown[] };
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = input.toString();
        if (url.includes('/v1/pairing/codes')) return Promise.resolve(json(MINTED));
        return Promise.resolve(json({ devices: state.devices }));
      }),
    );

    const client = new QueryClient({
      defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
    });
    render(
      <QueryClientProvider client={client}>
        <ToastProvider>
          <StaticPermissionsProvider value={ALLOW_ALL_PERMISSIONS}>
            <MemoryRouter>
              <PairingPanel />
            </MemoryRouter>
          </StaticPermissionsProvider>
        </ToastProvider>
      </QueryClientProvider>,
    );

    fireEvent.click(await screen.findByText('Gerar código de emparelhamento'));
    expect(await screen.findByRole('img', { name: 'Código QR de emparelhamento' })).toBeTruthy();

    // The phone exchanges the code: a new device appears on the next poll.
    state.devices = [ACTIVE_DEVICE];
    await act(async () => {
      await client.refetchQueries({ queryKey: ['pairing', 'devices'] });
    });

    expect(await screen.findByText('Telemóvel emparelhado')).toBeTruthy();
    expect(
      screen.getByText('Telemóvel da Amélia foi adicionado aos seus dispositivos.'),
    ).toBeTruthy();
  });

  it('revokes an enrolled device', async () => {
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = input.toString();
      if (url.includes('/v1/pairing/devices/') && init?.method === 'DELETE') {
        return Promise.resolve(new Response(null, { status: 204 }));
      }
      return Promise.resolve(json({ devices: [ACTIVE_DEVICE] }));
    });
    vi.stubGlobal('fetch', fetchMock);
    renderWithProviders(<PairingPanel />);

    fireEvent.click(await screen.findByText('Revogar'));
    fireEvent.click(await screen.findByText('Confirmar revogação'));

    await waitFor(() =>
      expect(
        fetchMock.mock.calls.some(
          ([input, init]) =>
            input.toString().includes(`/v1/pairing/devices/${ACTIVE_DEVICE.device_id}`) &&
            (init as RequestInit | undefined)?.method === 'DELETE',
        ),
      ).toBe(true),
    );
  });

  it('surfaces an error when minting fails', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = input.toString();
        if (url.includes('/v1/pairing/codes')) {
          return Promise.resolve(json({ error: 'Falha ao gerar código' }, 500));
        }
        return Promise.resolve(json({ devices: [] }));
      }),
    );
    renderWithProviders(<PairingPanel />);

    fireEvent.click(await screen.findByText('Gerar código de emparelhamento'));

    // The failure is surfaced (inline error and/or toast) and no QR is shown; the operator
    // can retry from the connect card that returns.
    await waitFor(() =>
      expect(screen.getAllByText('Falha ao gerar código').length).toBeGreaterThan(0),
    );
    expect(screen.queryByRole('img', { name: 'Código QR de emparelhamento' })).toBeNull();
    expect(screen.getByText('Gerar código de emparelhamento')).toBeTruthy();
  });
});
