/**
 * Tests for the email (SMTP) settings section (t23).
 *
 * The two behaviours worth locking down are the ones a regression would quietly break:
 *
 * 1. **The password is write-only.** It must go out in the request body, be wiped from the field
 *    on success, and never come back — the status view has no field that could carry it.
 * 2. **The test send reports the relay's real answer.** A rejection arrives as a `200` describing a
 *    failure, and the UI must render the actual SMTP code and server text, not a generic message.
 *
 * Plus the encryption guardrail: choosing "no encryption" must surface the warning and the
 * acknowledgement toggle, and re-enabling encryption must retire the acknowledgement.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react';
import { EmailSection } from './EmailSection';
import { DEFAULT_SETTINGS } from '../../api/types';
import type { EmailSettings, EmailStatusView, EmailTestResult } from '../../api/types';
import { renderWithProviders } from '../../test/utils';

interface Call {
  url: string;
  method: string;
  body: string | null;
}

function statusView(overrides: Partial<EmailStatusView> = {}): EmailStatusView {
  return {
    password_configured: false,
    deliverable: false,
    encrypted: true,
    warnings: [],
    ...overrides,
  };
}

function stubFetch(
  opts: { status?: EmailStatusView; test?: EmailTestResult; writeStatus?: number } = {},
): { fn: typeof fetch; calls: Call[] } {
  const { status = statusView(), test, writeStatus = 200 } = opts;
  const calls: Call[] = [];
  const json = (body: unknown, code = 200) =>
    new Response(JSON.stringify(body), { status: code, headers: { 'Content-Type': 'application/json' } });
  const fn = ((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const method = init?.method ?? 'GET';
    calls.push({ url, method, body: (init?.body as string) ?? null });
    if (url.includes('/v1/settings/email/test')) {
      return Promise.resolve(json(test ?? { ok: true, tls: true, authenticated: true }));
    }
    if (url.includes('/v1/settings/email/password')) {
      // The server echoes the new status; a PUT means a password now exists.
      return Promise.resolve(
        json({ ...status, password_configured: method === 'PUT' }, writeStatus),
      );
    }
    return Promise.resolve(json(status));
  }) as typeof fetch;
  return { fn, calls };
}

function email(overrides: Partial<EmailSettings> = {}): EmailSettings {
  return { ...DEFAULT_SETTINGS.email, ...overrides };
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('EmailSection', () => {
  it('edits the non-secret settings through the working copy rather than its own endpoint', async () => {
    const stub = stubFetch();
    vi.stubGlobal('fetch', stub.fn);
    const onChange = vi.fn();
    renderWithProviders(<EmailSection email={email()} onChange={onChange} />);

    fireEvent.change(await screen.findByLabelText('Servidor'), {
      target: { value: 'smtp.encosto-estrategico.pt' },
    });
    expect(onChange).toHaveBeenCalledWith('host', 'smtp.encosto-estrategico.pt');
    // The host is part of the settings document, so the section must NOT issue its own write.
    expect(stub.calls.some((c) => c.method !== 'GET')).toBe(false);
  });

  it('sends the password write-only and wipes the field afterwards', async () => {
    const stub = stubFetch();
    vi.stubGlobal('fetch', stub.fn);
    renderWithProviders(<EmailSection email={email()} onChange={vi.fn()} />);

    const field = (await screen.findByLabelText('Palavra-passe')) as HTMLInputElement;
    // A secret input is a password input and is never pre-filled.
    expect(field.type).toBe('password');
    expect(field.value).toBe('');

    fireEvent.change(field, { target: { value: 'correct-horse-battery-staple' } });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar palavra-passe' }));

    await waitFor(() => {
      const put = stub.calls.find((c) => c.method === 'PUT');
      expect(put, 'a password PUT was issued').toBeTruthy();
      expect(put!.url).toContain('/v1/settings/email/password');
      expect(JSON.parse(put!.body ?? '{}').password).toBe('correct-horse-battery-staple');
    });
    // Cleared on success, so the plaintext does not linger in the DOM.
    await waitFor(() => expect(field.value).toBe(''));
  });

  it('reports whether a password is stored without ever showing one', async () => {
    vi.stubGlobal('fetch', stubFetch({ status: statusView({ password_configured: true }) }).fn);
    renderWithProviders(<EmailSection email={email()} onChange={vi.fn()} />);

    expect(await screen.findByText('Definida')).toBeTruthy();
    expect(screen.queryByText('Por definir')).toBeNull();
  });

  it('shows the relay’s real SMTP code and text when the test send is rejected', async () => {
    vi.stubGlobal(
      'fetch',
      stubFetch({
        test: {
          ok: false,
          tls: false,
          authenticated: false,
          failure: {
            stage: 'auth',
            kind: 'rejected',
            code: 535,
            enhanced_code: '5.7.8',
            detail: 'Error: authentication failed',
            tls: true,
          },
        },
      }).fn,
    );
    renderWithProviders(<EmailSection email={email()} onChange={vi.fn()} />);

    fireEvent.change(await screen.findByLabelText('Destinatário'), {
      target: { value: 'amelia.marques@encosto-estrategico.pt' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Enviar teste' }));

    // The stage, the real code, and the server's own words — not a generic failure message.
    expect(await screen.findByText('O envio falhou')).toBeTruthy();
    expect(screen.getByText('Autenticação')).toBeTruthy();
    expect(screen.getByText('535 5.7.8')).toBeTruthy();
    expect(screen.getByText('Error: authentication failed')).toBeTruthy();
  });

  it('distinguishes an unreachable relay from a rejected one', async () => {
    vi.stubGlobal(
      'fetch',
      stubFetch({
        test: {
          ok: false,
          tls: false,
          authenticated: false,
          failure: {
            stage: 'connect',
            kind: 'unreachable',
            detail: '127.0.0.1:2525: No connection could be made',
            tls: false,
          },
        },
      }).fn,
    );
    renderWithProviders(<EmailSection email={email()} onChange={vi.fn()} />);

    fireEvent.change(await screen.findByLabelText('Destinatário'), {
      target: { value: 'amelia.marques@encosto-estrategico.pt' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Enviar teste' }));

    expect(await screen.findByText('Ligação ao servidor')).toBeTruthy();
    expect(screen.getByText('127.0.0.1:2525: No connection could be made')).toBeTruthy();
    // The remedy points at the port/firewall, not at credentials.
    expect(screen.getByText(/firewall/)).toBeTruthy();
  });

  it('confirms a successful send without overclaiming delivery', async () => {
    vi.stubGlobal(
      'fetch',
      stubFetch({
        test: { ok: true, tls: true, authenticated: true, accepted_detail: '2.0.0 Ok: queued as 4F2' },
      }).fn,
    );
    renderWithProviders(<EmailSection email={email()} onChange={vi.fn()} />);

    fireEvent.change(await screen.findByLabelText('Destinatário'), {
      target: { value: 'amelia.marques@encosto-estrategico.pt' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Enviar teste' }));

    expect(await screen.findByText('Mensagem aceite pelo servidor')).toBeTruthy();
    expect(screen.getByText('2.0.0 Ok: queued as 4F2')).toBeTruthy();
    // Accepting is not delivering, and the copy says so.
    expect(screen.getByText(/não confirma a entrega/i)).toBeTruthy();
  });

  it('warns loudly and demands an acknowledgement before sending without encryption', async () => {
    vi.stubGlobal('fetch', stubFetch().fn);
    const onChange = vi.fn();
    renderWithProviders(
      <EmailSection email={email({ encryption: 'none' })} onChange={onChange} />,
    );

    expect(await screen.findByText('Ligação sem encriptação')).toBeTruthy();
    expect(screen.getByLabelText('Confirmo que quero enviar sem encriptação')).toBeTruthy();
  });

  it('retires the cleartext acknowledgement when encryption is turned back on', async () => {
    vi.stubGlobal('fetch', stubFetch().fn);
    const onChange = vi.fn();
    renderWithProviders(
      <EmailSection
        email={email({ encryption: 'none', allow_insecure: true })}
        onChange={onChange}
      />,
    );

    fireEvent.change(await screen.findByLabelText('Encriptação'), {
      target: { value: 'starttls' },
    });
    expect(onChange).toHaveBeenCalledWith('encryption', 'starttls');
    expect(onChange).toHaveBeenCalledWith('allow_insecure', false);
  });

  it('surfaces the server’s configuration warnings verbatim', async () => {
    vi.stubGlobal(
      'fetch',
      stubFetch({
        status: statusView({
          warnings: ['A username is configured but no password is stored, so authentication will fail.'],
        }),
      }).fn,
    );
    renderWithProviders(<EmailSection email={email()} onChange={vi.fn()} />);

    expect(
      await screen.findByText(
        'A username is configured but no password is stored, so authentication will fail.',
      ),
    ).toBeTruthy();
  });
});
