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

const openExternalMock = vi.hoisted(() =>
  vi.fn<(url: string) => Promise<void>>(() => Promise.resolve()),
);
vi.mock('../../desktop/openExternal', () => ({
  openExternal: (url: string) => openExternalMock(url),
}));

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
  openExternalMock.mockReset();
  openExternalMock.mockResolvedValue(undefined);
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

  it('opens user-mediated email and WhatsApp drafts containing only the existing pairing link', async () => {
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = input.toString();
      if (url.includes('/v1/pairing/codes')) return Promise.resolve(json(MINTED));
      return Promise.resolve(json({ devices: [] }));
    });
    vi.stubGlobal('fetch', fetchMock);
    renderWithProviders(<PairingPanel />);

    fireEvent.click(await screen.findByText('Gerar código de emparelhamento'));

    const emailButton = await screen.findByRole('button', { name: 'Enviar por email' });
    expect(
      screen.getByText(
        /Nada é enviado até escolher o destinatário e confirmar o envio.*Copiar ligação/,
      ),
    ).toBeTruthy();

    fireEvent.click(emailButton);
    await waitFor(() => expect(openExternalMock).toHaveBeenCalledTimes(1));
    const emailUrl = new URL(openExternalMock.mock.calls[0][0] as string);
    expect(emailUrl.protocol).toBe('mailto:');
    expect(emailUrl.searchParams.get('subject')).toBe(
      'Convite para emparelhar um telemóvel com o Chancela',
    );
    expect(emailUrl.searchParams.get('body')).toContain(
      '/?companion_pair=9b1f6c0000004000800000000000a1de',
    );

    fireEvent.click(screen.getByRole('button', { name: 'Enviar por WhatsApp' }));
    await waitFor(() => expect(openExternalMock).toHaveBeenCalledTimes(2));
    const whatsappUrl = new URL(openExternalMock.mock.calls[1][0] as string);
    expect(whatsappUrl.origin).toBe('https://wa.me');
    expect(whatsappUrl.searchParams.get('text')).toContain(
      '/?companion_pair=9b1f6c0000004000800000000000a1de',
    );

    // Both actions only hand a draft to another app; no notification/send endpoint is called.
    expect(
      fetchMock.mock.calls.filter(([input]) => input.toString().includes('/v1/pairing/codes')),
    ).toHaveLength(1);
  });

  it('honours disabled admin share channels and keeps the copy-link fallback available', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        if (input.toString().includes('/v1/pairing/codes')) return Promise.resolve(json(MINTED));
        return Promise.resolve(json({ devices: [] }));
      }),
    );
    renderWithProviders(<PairingPanel shareEmailEnabled={false} shareWhatsappEnabled={false} />);

    fireEvent.click(await screen.findByText('Gerar código de emparelhamento'));

    expect(
      await screen.findByText(/partilha de convites foi desativada pelo administrador/i),
    ).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Enviar por email' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Enviar por WhatsApp' })).toBeNull();
    expect(screen.getByRole('button', { name: 'Copiar ligação' })).toBeTruthy();
  });

  it('handles a rejected share hand-off with copy-link fallback guidance', async () => {
    openExternalMock.mockRejectedValueOnce(new Error('No protocol handler'));
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        if (input.toString().includes('/v1/pairing/codes')) return Promise.resolve(json(MINTED));
        return Promise.resolve(json({ devices: [] }));
      }),
    );
    renderWithProviders(<PairingPanel />);

    fireEvent.click(await screen.findByText('Gerar código de emparelhamento'));
    fireEvent.click(await screen.findByRole('button', { name: 'Enviar por email' }));

    expect(
      await screen.findByText(
        'Não foi possível abrir a aplicação de partilha. Copie a ligação de emparelhamento e envie-a manualmente.',
      ),
    ).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Copiar ligação' })).toBeTruthy();
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
