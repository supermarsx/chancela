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
import { cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { EmailSection } from './EmailSection';
import { DEFAULT_SETTINGS } from '../../api/types';
import type {
  EmailSettings,
  EmailStatusView,
  EmailTestResult,
  SmtpTrace,
} from '../../api/types';
import { renderWithProviders } from '../../test/utils';

interface Call {
  url: string;
  method: string;
  body: string | null;
}

/**
 * A test-send result as a *test* writes one: everything except t70's `trace`.
 *
 * `EmailTestResult.trace` is required, so without this every fixture below would have to spell out
 * a full protocol trace — host, port, encryption, capabilities, steps, transcript — none of which
 * any of these tests are about. `stubFetch` supplies a default. Keeping the shape in ONE place
 * also means t70's next iteration on `SmtpTrace` is a one-line change here rather than seven.
 *
 * `trace` stays overridable for whichever test eventually does care about it.
 */
type TestResultFixture = Omit<EmailTestResult, 'trace'> & { trace?: SmtpTrace };

/** A minimal, internally consistent trace: one session that connected and got as far as EHLO. */
function smtpTrace(overrides: Partial<SmtpTrace> = {}): SmtpTrace {
  return {
    host: 'smtp.encosto-estrategico.pt',
    port: 587,
    encryption: 'starttls',
    helo_name: 'chancela.encosto-estrategico.pt',
    tls_established: true,
    advertised_capabilities: ['STARTTLS', 'AUTH PLAIN LOGIN'],
    steps: [{ stage: 'connect', outcome: 'ok', started_ms: 0, duration_ms: 4 }],
    transcript: [{ direction: 'server', text: '220 smtp ready', at_ms: 4 }],
    total_ms: 12,
    ...overrides,
  };
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
  opts: { status?: EmailStatusView; test?: TestResultFixture; writeStatus?: number } = {},
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
      const result: EmailTestResult = {
        ...(test ?? { ok: true, tls: true, authenticated: true }),
        trace: test?.trace ?? smtpTrace(),
      };
      return Promise.resolve(json(result));
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

    // Scoped to the summary warning (t70): the stage label and the relay's text now also appear in
    // the technical-detail timeline below, so an unscoped query matches twice. What this test is
    // about is the *summary* naming the connect stage, which is unchanged.
    //
    // Located by its own title rather than by `role="note"`: this section renders several notes
    // (an `ErrorNote`, the cleartext warning, the server's configuration warnings), so "the first
    // note on the page" would silently start asserting against a different warning the day one of
    // those appears in this scenario. (t69's hardening, restored after the working-tree loss.)
    const warning = (await screen.findByText('O envio falhou')).closest('.inline-warning');
    expect(warning, 'the failure warning is rendered').toBeTruthy();
    const summary = within(warning as HTMLElement);
    expect(summary.getByText('Ligação ao servidor')).toBeTruthy();
    expect(summary.getByText('127.0.0.1:2525: No connection could be made')).toBeTruthy();
    // The remedy points at the port/firewall, not at credentials.
    expect(summary.getByText(/firewall/)).toBeTruthy();
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

  it('routes every sender-identity field into the working copy under its own key', async () => {
    // These four fields decide who the recipient sees the mail as from, and which name the relay
    // is greeted with. They ride the settings document's debounced autosave, so the only thing
    // that can go wrong here is a field writing under the wrong key — which would silently
    // overwrite a different setting and look like the edit simply did not take.
    const stub = stubFetch();
    vi.stubGlobal('fetch', stub.fn);
    const onChange = vi.fn();
    renderWithProviders(<EmailSection email={email()} onChange={onChange} />);

    const edits: [string, string, string][] = [
      ['Utilizador', 'username', 'ata@encosto-estrategico.pt'],
      ['Endereço de remetente', 'from_address', 'nao-responder@encosto-estrategico.pt'],
      ['Nome de remetente', 'from_name', 'Encosto Estratégico Lda'],
      ['Nome EHLO', 'helo_name', 'chancela.encosto-estrategico.pt'],
    ];
    for (const [label, key, value] of edits) {
      fireEvent.change(await screen.findByLabelText(label), { target: { value } });
      expect(onChange, `${label} writes to ${key}`).toHaveBeenCalledWith(key, value);
    }

    expect(onChange).toHaveBeenCalledTimes(edits.length);
    // Still the settings document, not a private endpoint of this section.
    expect(stub.calls.some((c) => c.method !== 'GET')).toBe(false);
  });

  it('keeps the port a number so a typed digit does not become a string in the document', async () => {
    const stub = stubFetch();
    vi.stubGlobal('fetch', stub.fn);
    const onChange = vi.fn();
    renderWithProviders(<EmailSection email={email()} onChange={onChange} />);

    fireEvent.change(await screen.findByLabelText('Porta'), { target: { value: '2525' } });

    // A string here would be written into the settings document and rejected by the API on the
    // next autosave, long after the operator stopped looking at this field.
    expect(onChange).toHaveBeenCalledWith('port', 2525);
    expect(typeof onChange.mock.calls[0][1]).toBe('number');
  });

  it('makes sending in the clear an explicit, separate act — never a side effect of the mode', async () => {
    // Choosing "no encryption" surfaces the warning, but the acknowledgement is its own control:
    // credentials would travel in the clear, and that must be something an operator did on
    // purpose rather than something that happened when they changed a dropdown.
    const stub = stubFetch();
    vi.stubGlobal('fetch', stub.fn);
    const onChange = vi.fn();
    renderWithProviders(
      <EmailSection email={email({ encryption: 'none', allow_insecure: false })} onChange={onChange} />,
    );

    const confirm = await screen.findByLabelText('Confirmo que quero enviar sem encriptação');
    expect((confirm as HTMLInputElement).checked).toBe(false);
    expect(onChange).not.toHaveBeenCalled();

    fireEvent.click(confirm);
    expect(onChange).toHaveBeenCalledWith('allow_insecure', true);
    expect(onChange).toHaveBeenCalledTimes(1);
  });

  it('offers no cleartext acknowledgement at all while encryption is on', async () => {
    // The flag is only meaningful without encryption; showing it otherwise would invite an
    // operator to pre-authorise something they have not chosen.
    vi.stubGlobal('fetch', stubFetch().fn);
    renderWithProviders(<EmailSection email={email({ encryption: 'starttls' })} onChange={vi.fn()} />);

    expect(await screen.findByLabelText('Servidor')).toBeTruthy();
    expect(screen.queryByLabelText('Confirmo que quero enviar sem encriptação')).toBeNull();
    expect(screen.queryByText('Ligação sem encriptação')).toBeNull();
  });

  it('never renders the stored password back, in any state', async () => {
    // The API has no field that could return it, and the component must not invent one: the
    // status view says only whether one exists. This is the property the whole write-only design
    // exists to hold, so it is asserted over the DOM rather than over one input's value.
    vi.stubGlobal(
      'fetch',
      stubFetch({
        status: statusView({ password_configured: true, deliverable: true }),
      }).fn,
    );
    renderWithProviders(
      <EmailSection
        email={email({ username: 'ata@encosto-estrategico.pt', encryption: 'starttls' })}
        onChange={vi.fn()}
      />,
    );

    const field = (await screen.findByLabelText('Palavra-passe')) as HTMLInputElement;
    expect(field.value).toBe('');
    expect(field.type).toBe('password');
    // Nothing anywhere in the section — value, placeholder, title, aria — carries a secret.
    for (const input of Array.from(document.querySelectorAll('input'))) {
      expect(input.value).not.toBe('correct-horse-battery-staple');
    }
    expect(document.body.textContent).not.toMatch(/correct-horse/);
  });

  it('clears a stored password and wipes any draft alongside it', async () => {
    const stub = stubFetch({ status: statusView({ password_configured: true }) });
    vi.stubGlobal('fetch', stub.fn);
    renderWithProviders(<EmailSection email={email()} onChange={vi.fn()} />);

    const field = (await screen.findByLabelText('Palavra-passe')) as HTMLInputElement;
    fireEvent.change(field, { target: { value: 'about-to-be-abandoned' } });
    fireEvent.click(screen.getByRole('button', { name: 'Remover palavra-passe' }));

    await waitFor(() => {
      const del = stub.calls.find((c) => c.method === 'DELETE');
      expect(del, 'a password DELETE was issued').toBeTruthy();
      expect(del!.url).toContain('/v1/settings/email/password');
    });
    // A draft left in the field after a clear would be sent by the next Guardar click.
    await waitFor(() => expect(field.value).toBe(''));
    expect(await screen.findByText('Palavra-passe do servidor removida')).toBeTruthy();
  });

  it('will not submit an empty password, so a stray click cannot store one', async () => {
    const stub = stubFetch();
    vi.stubGlobal('fetch', stub.fn);
    renderWithProviders(<EmailSection email={email()} onChange={vi.fn()} />);

    const save = await screen.findByRole('button', { name: 'Guardar palavra-passe' });
    fireEvent.click(save);

    expect((save as HTMLButtonElement).disabled || save.getAttribute('aria-disabled') === 'true').toBe(
      true,
    );
    expect(stub.calls.some((c) => c.method === 'PUT')).toBe(false);
  });

  it('reports a rejected password write instead of claiming it was stored', async () => {
    vi.stubGlobal('fetch', stubFetch({ writeStatus: 403 }).fn);
    renderWithProviders(<EmailSection email={email()} onChange={vi.fn()} />);

    const field = (await screen.findByLabelText('Palavra-passe')) as HTMLInputElement;
    fireEvent.change(field, { target: { value: 'rejected-secret' } });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar palavra-passe' }));

    // The badge must not flip to "Definida" on a failed write.
    expect(await screen.findByText('Por definir')).toBeTruthy();
    expect(screen.queryByText('Definida')).toBeNull();
  });

  it('reports a failed send that carries no failure detail rather than rendering nothing', async () => {
    // `ok: false` with no `failure` object is a shape the relay path can produce; falling through
    // to an empty card would read as "the test send did nothing", which is the wrong conclusion.
    vi.stubGlobal(
      'fetch',
      stubFetch({ test: { ok: false, tls: false, authenticated: false } }).fn,
    );
    renderWithProviders(<EmailSection email={email()} onChange={vi.fn()} />);

    fireEvent.change(await screen.findByLabelText('Destinatário'), {
      target: { value: 'amelia.marques@encosto-estrategico.pt' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Enviar teste' }));

    expect(await screen.findByText('O envio falhou')).toBeTruthy();
    expect(screen.queryByText('Mensagem aceite pelo servidor')).toBeNull();
  });

  it('names the stage and the remedy for each kind of relay failure', async () => {
    // The whole point of this card is that `535 authentication failed` and a TLS refusal need
    // different fixes. A stage or remedy that collapses to the same words for both is the
    // regression that turns this back into "sending failed".
    type Failure = NonNullable<EmailTestResult['failure']>;
    const cases: [Failure['stage'], Failure['kind'], string, RegExp][] = [
      ['tls', 'tls', 'Handshake TLS', /certificado do servidor não foi aceite/i],
      ['ehlo', 'protocol', 'Apresentação (EHLO)', /porta serve SMTP/i],
      ['mail_from', 'configuration', 'Remetente (MAIL FROM)', /Reveja o utilizador/i],
      ['rcpt_to', 'rejected', 'Destinatário (RCPT TO)', /recusou o pedido/i],
      ['data', 'timeout', 'Envio da mensagem', /demorou demasiado a responder/i],
    ];

    for (const [stage, kind, stageLabel, remedy] of cases) {
      vi.stubGlobal(
        'fetch',
        stubFetch({
          test: {
            ok: false,
            tls: false,
            authenticated: false,
            failure: { stage, kind, detail: `recusado em ${stage}`, tls: false },
          },
        }).fn,
      );
      renderWithProviders(<EmailSection email={email()} onChange={vi.fn()} />);
      fireEvent.change(await screen.findByLabelText('Destinatário'), {
        target: { value: 'amelia.marques@encosto-estrategico.pt' },
      });
      fireEvent.click(screen.getByRole('button', { name: 'Enviar teste' }));

      expect(await screen.findByText(stageLabel), `stage ${stage}`).toBeTruthy();
      expect(screen.getByText(`recusado em ${stage}`)).toBeTruthy();
      expect(screen.getByText(remedy), `remedy for ${kind}`).toBeTruthy();
      cleanup();
    }
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
