/**
 * Behavioural tests for the companion pairing panel (wp27-e5): mint → QR/deep-link render,
 * TTL countdown, enrollment reflection via the device poll, revoke, and the mint error path.
 * Tests run in the pt-PT source locale (like the sibling settings tests) and drive the real
 * hooks against a stubbed `fetch`.
 *
 * Minting is floored at `confirm_with_reauth` (t70), so every mint here goes through the
 * guarded-action dialog. Two of these tests are the guard rather than the happy path: that
 * NOTHING is minted while the dialog is merely open, and that the proof the dialog gathered
 * actually reaches the request body. Asserting only that a dialog renders would pass against a
 * panel that minted behind it.
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
  confirmed_by: 'password',
};

const REVOKED_DEVICE = {
  device_id: '9b1f6c00-0000-4000-8000-0000000000a2',
  label: 'Tablet de reserva',
  created_at: '2026-07-15T09:00:00Z',
  revoked: true,
  revoked_at: '2026-07-16T11:20:00Z',
  confirmed_by: 'totp_code',
};

const MINTED = {
  code: '9b1f6c0000004000800000000000a1de',
  expires_at: '2026-07-16T10:20:30Z',
  expires_in_secs: 300,
  label: 'Telemóvel da Amélia',
  accepted_confirmation_methods: ['password', 'totp_code'],
};

/** The server's resolved policy for the mint. `confirm_with_reauth` is the registry's floor. */
const POLICY = {
  actions: [
    {
      action: 'device.pairing',
      floor: 'confirm_with_reauth',
      effective: 'confirm_with_reauth',
      consequence: 'consequential',
      wired: true,
    },
  ],
};

const OPERATOR_PASSWORD = 'Cavalo-Certo9!';

/**
 * A `fetch` stub that answers the confirmation policy as well as the pairing endpoints. The
 * policy MUST be answered: without it the dialog falls back to a plain confirm and stops
 * asking for a proof, so a test that omitted it would quietly stop covering the step-up.
 */
function pairingFetch(handler: (url: string, init?: RequestInit) => Response | null) {
  return vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = input.toString();
    if (url.includes('/v1/confirmation-policy')) return Promise.resolve(json(POLICY));
    const answer = handler(url, init);
    if (answer) return Promise.resolve(answer);
    return Promise.resolve(json({ devices: [] }));
  });
}

/** Open the mint dialog, supply the step-up proof, and confirm. */
async function mintWithConfirmation() {
  fireEvent.click(await screen.findByText('Gerar código de emparelhamento'));
  const confirm = await screen.findByRole('button', { name: 'Gerar código' });
  fireEvent.change(screen.getByLabelText('Palavra-passe'), {
    target: { value: OPERATOR_PASSWORD },
  });
  fireEvent.click(confirm);
}

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
      pairingFetch((url) => (url.includes('/v1/pairing/codes') ? json(MINTED) : null)),
    );
    renderWithProviders(<PairingPanel />);

    await mintWithConfirmation();

    // The hand-rolled QR renders as an accessible <svg role="img">.
    expect(await screen.findByRole('img', { name: 'Código QR de emparelhamento' })).toBeTruthy();
    // The copyable deep-link carries the code, and the TTL countdown is shown.
    expect(screen.getByText(/[/]pair[?]code=9b1f6c0000004000800000000000a1de/)).toBeTruthy();
    expect(screen.getByText('Expira em 5:00')).toBeTruthy();
    expect(screen.getByText('Copiar ligação')).toBeTruthy();
  });

  it('opens user-mediated email and WhatsApp drafts containing only the existing pairing link', async () => {
    const fetchMock = pairingFetch((url) =>
      url.includes('/v1/pairing/codes') ? json(MINTED) : null,
    );
    vi.stubGlobal('fetch', fetchMock);
    renderWithProviders(<PairingPanel />);

    await mintWithConfirmation();

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
      '/pair?code=9b1f6c0000004000800000000000a1de',
    );

    fireEvent.click(screen.getByRole('button', { name: 'Enviar por WhatsApp' }));
    await waitFor(() => expect(openExternalMock).toHaveBeenCalledTimes(2));
    const whatsappUrl = new URL(openExternalMock.mock.calls[1][0] as string);
    expect(whatsappUrl.origin).toBe('https://wa.me');
    expect(whatsappUrl.searchParams.get('text')).toContain(
      '/pair?code=9b1f6c0000004000800000000000a1de',
    );

    // Both actions only hand a draft to another app; no notification/send endpoint is called.
    expect(
      fetchMock.mock.calls.filter(([input]) => input.toString().includes('/v1/pairing/codes')),
    ).toHaveLength(1);
  });

  it('honours disabled admin share channels and keeps the copy-link fallback available', async () => {
    vi.stubGlobal(
      'fetch',
      pairingFetch((url) => (url.includes('/v1/pairing/codes') ? json(MINTED) : null)),
    );
    renderWithProviders(<PairingPanel shareEmailEnabled={false} shareWhatsappEnabled={false} />);

    await mintWithConfirmation();

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
      pairingFetch((url) => (url.includes('/v1/pairing/codes') ? json(MINTED) : null)),
    );
    renderWithProviders(<PairingPanel />);

    await mintWithConfirmation();
    fireEvent.click(await screen.findByRole('button', { name: 'Enviar por email' }));

    expect(
      await screen.findByText(
        'Não foi possível abrir a aplicação de partilha. Copie a ligação de emparelhamento e envie-a manualmente.',
      ),
    ).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Copiar ligação' })).toBeTruthy();
  });

  it('never re-mints on its own when a code expires, and asks to confirm again', async () => {
    // The panel used to re-mint automatically. That is a zero-click mint loop in front of an
    // action the registry floors precisely because "an unattended signed-in browser must not be
    // one click from it", so it is gone. The assertion is the ABSENCE of a second mint.
    let mintCalls = 0;
    vi.stubGlobal(
      'fetch',
      pairingFetch((url) => {
        if (!url.includes('/v1/pairing/codes')) return null;
        mintCalls += 1;
        return json({ ...MINTED, expires_in_secs: 0 });
      }),
    );
    renderWithProviders(<PairingPanel />);

    await mintWithConfirmation();

    // The expired code offers a deliberate way forward instead of silently replacing itself.
    expect(await screen.findByText('Código expirado')).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Gerar novo código' })).toBeTruthy();
    await waitFor(() => expect(mintCalls).toBe(1));
    // Give any stray re-mint effect a chance to fire before concluding there is none.
    await new Promise((resolve) => setTimeout(resolve, 60));
    expect(mintCalls).toBe(1);
  });

  it('mints nothing until the confirmation is completed', async () => {
    const fetchMock = pairingFetch((url) =>
      url.includes('/v1/pairing/codes') ? json(MINTED) : null,
    );
    vi.stubGlobal('fetch', fetchMock);
    renderWithProviders(<PairingPanel />);

    fireEvent.click(await screen.findByText('Gerar código de emparelhamento'));
    // The dialog is up. Nothing has been minted — this is the guard, not the dialog's presence.
    await screen.findByRole('button', { name: 'Gerar código' });
    const mintCalls = () =>
      fetchMock.mock.calls.filter(([input]) => input.toString().includes('/v1/pairing/codes'));
    expect(mintCalls()).toHaveLength(0);
    expect(screen.queryByRole('img', { name: 'Código QR de emparelhamento' })).toBeNull();

    fireEvent.change(screen.getByLabelText('Palavra-passe'), {
      target: { value: OPERATOR_PASSWORD },
    });
    // Still nothing: typing a proof is not confirming it.
    expect(mintCalls()).toHaveLength(0);

    fireEvent.click(screen.getByRole('button', { name: 'Gerar código' }));
    await waitFor(() => expect(mintCalls()).toHaveLength(1));
  });

  it('sends the gathered step-up proof in the mint request', async () => {
    const fetchMock = pairingFetch((url) =>
      url.includes('/v1/pairing/codes') ? json(MINTED) : null,
    );
    vi.stubGlobal('fetch', fetchMock);
    renderWithProviders(<PairingPanel />);

    await mintWithConfirmation();

    await waitFor(() =>
      expect(screen.getByRole('img', { name: 'Código QR de emparelhamento' })).toBeTruthy(),
    );
    const mint = fetchMock.mock.calls.find(([input]) =>
      input.toString().includes('/v1/pairing/codes'),
    );
    expect(mint).toBeTruthy();
    const body = JSON.parse(String((mint![1] as RequestInit).body));
    // The dialog gathers the proof; the panel is what must transmit it.
    expect(body.confirmation).toEqual({ reauth: { password: OPERATOR_PASSWORD } });
  });

  it('reflects enrollment when the phone exchanges the code', async () => {
    const state = { devices: [] as unknown[] };
    vi.stubGlobal(
      'fetch',
      pairingFetch((url) =>
        url.includes('/v1/pairing/codes') ? json(MINTED) : json({ devices: state.devices }),
      ),
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

    await mintWithConfirmation();
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
    const fetchMock = pairingFetch((url, init) =>
      url.includes('/v1/pairing/devices/') && init?.method === 'DELETE'
        ? new Response(null, { status: 204 })
        : json({ devices: [ACTIVE_DEVICE] }),
    );
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
      pairingFetch((url) =>
        url.includes('/v1/pairing/codes') ? json({ error: 'Falha ao gerar código' }, 500) : null,
      ),
    );
    renderWithProviders(<PairingPanel />);

    await mintWithConfirmation();

    // The failure is surfaced (inline error and/or toast) and no QR is shown; the operator
    // can retry from the connect card that returns.
    await waitFor(() =>
      expect(screen.getAllByText('Falha ao gerar código').length).toBeGreaterThan(0),
    );
    expect(screen.queryByRole('img', { name: 'Código QR de emparelhamento' })).toBeNull();
    expect(screen.getByText('Gerar código de emparelhamento')).toBeTruthy();
  });
});
