/**
 * Behavioural tests for the companion (phone-side) pairing page (t70).
 *
 * The load-bearing ones are the guards, not the happy path: that the page sends exactly the proof
 * the operator chose and nothing else, that it will not submit an empty proof at all, and that a
 * server refusal leaves the page unpaired rather than showing success. A test that only checked
 * "the form renders" would pass against a page that paired on load.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { CompanionPairPage, parseOfferedMethods } from './CompanionPairPage';
import { ToastProvider } from '../../ui/toast';

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

const EXCHANGED = {
  token: 'companion-token',
  device_id: '9b1f6c00-0000-4000-8000-0000000000a1',
  label: 'Telemóvel da Amélia',
  user: { username: 'amelia.marques' },
  confirmed_by: 'totp_code',
};

function renderAt(search: string) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <ToastProvider>
        <MemoryRouter initialEntries={[`/pair${search}`]}>
          <CompanionPairPage />
        </MemoryRouter>
      </ToastProvider>
    </QueryClientProvider>,
  );
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('parseOfferedMethods', () => {
  it('offers exactly what the link names, dropping anything it cannot collect', () => {
    expect(parseOfferedMethods('password,totp_code')).toEqual(['password', 'totp_code']);
    expect(parseOfferedMethods('totp_code')).toEqual(['totp_code']);
    // An unknown entry would draw a field with nowhere to send it.
    expect(parseOfferedMethods('totp_code,teleport')).toEqual(['totp_code']);
  });

  it('offers everything when the link says nothing usable', () => {
    // Being shown one field too many is a smaller failure than being shown none of the one you
    // hold — and this parameter is presentational, so generosity here costs no security.
    const all = ['password', 'totp_code', 'emailed_code'];
    expect(parseOfferedMethods(null)).toEqual(all);
    expect(parseOfferedMethods('')).toEqual(all);
    expect(parseOfferedMethods('teleport')).toEqual(all);
  });
});

describe('CompanionPairPage', () => {
  it('sends only the chosen proof, and pairs on success', async () => {
    // Typed with the real `fetch` argument list so the assertion below can read the request body
    // rather than casting an untyped tuple.
    const fetchMock = vi.fn((_input: RequestInfo | URL, _init?: RequestInit) =>
      Promise.resolve(json(EXCHANGED)),
    );
    vi.stubGlobal('fetch', fetchMock);
    renderAt('?code=9b1f6c0000004000800000000000a1de&methods=totp_code');

    fireEvent.change(await screen.findByLabelText('Código do autenticador'), {
      target: { value: '123456' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Confirmar e emparelhar' }));

    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));
    const body = JSON.parse(String(fetchMock.mock.calls[0][1]?.body));
    expect(body.code).toBe('9b1f6c0000004000800000000000a1de');
    // Exactly one proof. A blank `password: ''` riding along would be a credential-shaped empty
    // value in a slot the server then has to reason about.
    expect(body.confirmation).toEqual({ totp_code: '123456' });

    expect(await screen.findByText('Dispositivo emparelhado')).toBeTruthy();
  });

  it('does not exchange anything until a proof is entered', async () => {
    const fetchMock = vi.fn(() => Promise.resolve(json(EXCHANGED)));
    vi.stubGlobal('fetch', fetchMock);
    renderAt('?code=9b1f6c0000004000800000000000a1de&methods=password');

    const submit = await screen.findByRole('button', { name: 'Confirmar e emparelhar' });
    expect((submit as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(submit);
    // Whitespace is not a proof either.
    fireEvent.change(screen.getByLabelText('Palavra-passe'), { target: { value: '   ' } });
    expect((submit as HTMLButtonElement).disabled).toBe(true);

    expect(fetchMock).not.toHaveBeenCalled();
    expect(screen.queryByText('Dispositivo emparelhado')).toBeNull();
  });

  it('stays unpaired when the server refuses the proof', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(json({ error: 'o emparelhamento do dispositivo não foi confirmado' }, 403)),
      ),
    );
    renderAt('?code=9b1f6c0000004000800000000000a1de&methods=password');

    fireEvent.change(await screen.findByLabelText('Palavra-passe'), {
      target: { value: 'Cavalo-Errado9!' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Confirmar e emparelhar' }));

    // The refusal is surfaced and the success panel never appears — "did not pair", not
    // "showed a message".
    await waitFor(() => expect(screen.queryByText('Dispositivo emparelhado')).toBeNull());
    expect(screen.getByRole('button', { name: 'Confirmar e emparelhar' })).toBeTruthy();
  });

  it('changing method clears the proof rather than carrying it into another slot', async () => {
    const fetchMock = vi.fn(() => Promise.resolve(json(EXCHANGED)));
    vi.stubGlobal('fetch', fetchMock);
    renderAt('?code=9b1f6c0000004000800000000000a1de&methods=password,totp_code');

    fireEvent.change(await screen.findByLabelText('Palavra-passe'), {
      target: { value: 'Cavalo-Certo9!' },
    });
    fireEvent.change(screen.getByLabelText('Forma de confirmação'), {
      target: { value: 'totp_code' },
    });
    // The password must not still be sitting there, about to be submitted as a TOTP code.
    expect((screen.getByLabelText('Código do autenticador') as HTMLInputElement).value).toBe('');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('refuses to proceed without a pairing code in the link', async () => {
    const fetchMock = vi.fn(() => Promise.resolve(json(EXCHANGED)));
    vi.stubGlobal('fetch', fetchMock);
    renderAt('');

    expect(await screen.findByText('Falta o código de emparelhamento')).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Confirmar e emparelhar' })).toBeNull();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('takes the pairing code out of the address bar once it has been read', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() => Promise.resolve(json(EXCHANGED))),
    );
    renderAt('?code=9b1f6c0000004000800000000000a1de&methods=password');

    // A live credential must not linger in a phone's history or whatever sync it has on.
    await waitFor(() =>
      expect(window.location.search).not.toContain('9b1f6c0000004000800000000000a1de'),
    );
    // …and the page still works: it kept the code in state, so the form is usable.
    expect(await screen.findByLabelText('Palavra-passe')).toBeTruthy();
  });
});
