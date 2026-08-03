/**
 * The saved CMD mobile number on the signing panel — the opt-in, its step-up wall, and the three
 * states the server can report.
 *
 * These assert the *behaviour that protects the number*, not its copy: that nothing is stored
 * unless the box is ticked, that both directions of the toggle go through a credential, that a
 * prefill never overwrites something the operator typed, and that "saved but undecryptable" is
 * shown as its own state rather than as an empty field. Where a string is unavoidable it is a
 * label used to *find* a control, never an assertion about a translation — the wording of these
 * sentences is the catalogs' business and is free to change without failing this file.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react';
import { SigningPanel } from './SigningPanel';
import { renderWithProviders } from '../../test/utils';
import type { ActView, SavedCmdPhoneView, SignatureStatusView } from '../../api/types';

/** A clearly-synthetic number. No real number belongs in a fixture. */
const FAKE_PHONE = '+351 900 000 000';
const OTHER_FAKE_PHONE = '+351 900 000 001';

const signingAct: ActView = {
  id: 'act-1',
  book_id: 'book-1',
  title: 'Assembleia Geral Anual',
  channel: 'Physical',
  meeting_date: '2026-06-30',
  meeting_time: null,
  place: 'Lisboa',
  mesa: { presidente: 'Amélia Marques', secretarios: [] },
  agenda: [],
  attendance_reference: null,
  members_present: null,
  members_represented: null,
  referenced_documents: [],
  deliberations: '',
  deliberation_items: [],
  telematic_evidence: null,
  attachments: [],
  signatories: [],
  state: 'Signing',
  ata_number: 1,
  payload_digest: null,
  seal_event_seq: null,
  seal_metadata: null,
  retifies: null,
};

const unsignedStatus = {
  status: 'unsigned',
  finalization: 'em_assinatura',
  require_qualified_for_seal: false,
  evidence: {
    current_level: 'Unsigned',
    timestamp_evidence_present: false,
    dss_revocation_evidence_present: false,
    dss_revocation_evidence_status: 'unsupported',
    dss: {
      present: false,
      vri_count: 0,
      certificate_count: 0,
      ocsp_count: 0,
      crl_count: 0,
      certificate_sha256: [],
      ocsp_sha256: [],
      crl_sha256: [],
      revocation_evidence_present: false,
      inspection_status: 'not_applicable',
    },
    doc_timestamp: { present: false, count: 0, token_sha256: [], inspection_status: 'not_-' },
    long_term_status: ['not_configured', 'lt_not_implemented', 'lta_not_implemented'],
  },
} as unknown as SignatureStatusView;

function json(body: unknown, status = 200): Promise<Response> {
  return Promise.resolve(
    new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } }),
  );
}

function saved(overrides: Partial<SavedCmdPhoneView> = {}): SavedCmdPhoneView {
  return {
    saved: true,
    saved_at: '2026-07-01T09:00:00Z',
    phone: FAKE_PHONE,
    readable: true,
    ...overrides,
  };
}

const NONE_SAVED: SavedCmdPhoneView = {
  saved: false,
  saved_at: null,
  phone: null,
  readable: false,
};

/** Requests the panel makes that these tests do not care about. */
function background(url: string, method: string): Promise<Response> | null {
  if (url.endsWith('/signature') && method === 'GET') return json(unsignedStatus);
  if (url.endsWith('/document/bundle') && method === 'GET') return json({});
  if (url.includes('/signature/external-invites') && method === 'GET') return json([]);
  if (url.includes('/external-signing/envelopes') && method === 'GET') return json([]);
  if (url.includes('/v1/me/preferences') && method === 'GET') return json({ table_columns: {} });
  return null;
}

/**
 * Stub `fetch` with a saved-number state, recording every `PUT /v1/me/cmd-phone` body. The recorder
 * is what most of these tests actually assert on: "was anything stored, and exactly what".
 */
function stubFetch(state: SavedCmdPhoneView, putStatus = 200) {
  const puts: unknown[] = [];
  let current = state;
  vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
    const url = input.toString();
    const method = init?.method ?? 'GET';
    if (url.includes('/v1/me/cmd-phone')) {
      if (method === 'GET') return json(current);
      const body = JSON.parse(String(init?.body ?? '{}'));
      puts.push(body);
      if (putStatus !== 200) return json({ error: 'refused', code: 'step_up' }, putStatus);
      current =
        body.phone === null
          ? NONE_SAVED
          : saved({ phone: body.phone, saved_at: '2026-07-02T09:00:00Z' });
      return json(current);
    }
    if (url.includes('/signature/cmd/initiate')) {
      return json({
        session_id: 'sess-1',
        masked_phone: '+351 9••••000',
        status: 'otp_pending',
        expires_at: '2026-07-06T10:05:00Z',
        family: 'ChaveMovelDigital',
        evidentiary_level: 'Qualified',
      });
    }
    return background(url, method) ?? Promise.reject(new Error(`no stub for ${method} ${url}`));
  }) as typeof fetch);
  return puts;
}

/** Walk into the CMD phone-entry step and return the phone field. */
async function openCmdStep(): Promise<HTMLInputElement> {
  renderWithProviders(<SigningPanel act={signingAct} />);
  fireEvent.click(await screen.findByRole('button', { name: 'Assinar com Chave Móvel Digital' }));
  return (await screen.findByLabelText('Número de telemóvel')) as HTMLInputElement;
}

const rememberBox = () =>
  screen.getByLabelText('Guardar este número na minha conta') as HTMLInputElement;

/** Fill the step-up dialog's password arm and confirm. */
function confirmWithPassword(action: string) {
  fireEvent.change(screen.getByLabelText('Palavra-passe'), { target: { value: 's3cret-pass' } });
  fireEvent.click(screen.getByRole('button', { name: action }));
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('the saved CMD mobile number', () => {
  it('stores nothing until the box is ticked, and never as a side effect of signing', async () => {
    const puts = stubFetch(NONE_SAVED);
    const phone = await openCmdStep();

    // Nothing saved ⇒ the box starts unticked. This is the opt-in, stated as a fact about the
    // initial render rather than as a promise in a comment.
    expect(rememberBox().checked).toBe(false);

    fireEvent.change(phone, { target: { value: FAKE_PHONE } });
    fireEvent.change(screen.getByLabelText('PIN de assinatura da CMD'), {
      target: { value: '1234' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Enviar código por SMS' }));

    // The signature proceeded to the OTP step…
    await screen.findByLabelText('Código SMS (OTP)');
    // …and stored nothing. Typing a number and signing with it is not consent to keep it.
    expect(puts).toEqual([]);
  });

  it('ticking the box demands a credential before anything is stored', async () => {
    const puts = stubFetch(NONE_SAVED);
    const phone = await openCmdStep();
    fireEvent.change(phone, { target: { value: FAKE_PHONE } });

    fireEvent.click(rememberBox());

    // The tick alone stored nothing — a dialog opened instead.
    expect(puts).toEqual([]);
    await screen.findByRole('dialog');

    confirmWithPassword('Guardar número');
    await waitFor(() => expect(puts).toHaveLength(1));
    expect(puts[0]).toMatchObject({
      phone: FAKE_PHONE,
      reauth: { password: 's3cret-pass' },
    });
    // The server's answer, not the click, is what ticks the box.
    await waitFor(() => expect(rememberBox().checked).toBe(true));
  });

  it('leaves the box untouched when the step-up proof is refused', async () => {
    const puts = stubFetch(NONE_SAVED, 403);
    const phone = await openCmdStep();
    fireEvent.change(phone, { target: { value: FAKE_PHONE } });
    fireEvent.click(rememberBox());
    await screen.findByRole('dialog');

    confirmWithPassword('Guardar número');

    await waitFor(() => expect(puts).toHaveLength(1));
    // The refusal is not silently swallowed into a ticked box: nothing is stored, so nothing shows
    // as stored. An optimistic toggle here would tell the operator their number is kept when it is
    // not — the one lie this control must never tell.
    expect(rememberBox().checked).toBe(false);
  });

  it('prefills a saved number and clears it back through the same wall', async () => {
    const puts = stubFetch(saved());
    const phone = await openCmdStep();

    await waitFor(() => expect(phone.value).toBe(FAKE_PHONE));
    expect(rememberBox().checked).toBe(true);

    fireEvent.click(rememberBox());
    await screen.findByRole('dialog');
    confirmWithPassword('Remover número');

    await waitFor(() => expect(puts).toHaveLength(1));
    // `phone: null` is the clear — the whole row, and with it every wrap of it, goes.
    expect(puts[0]).toMatchObject({ phone: null, reauth: { password: 's3cret-pass' } });
    await waitFor(() => expect(rememberBox().checked).toBe(false));
  });

  it('never overwrites a number the operator has started typing', async () => {
    // The saved number resolves only after the field has been touched — the ordering that makes an
    // unconditional prefill replace someone's input with a different phone number.
    let releaseSaved: (value: Promise<Response>) => void = () => {};
    const pending = new Promise<Promise<Response>>((resolve) => {
      releaseSaved = resolve;
    });
    vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = input.toString();
      const method = init?.method ?? 'GET';
      if (url.includes('/v1/me/cmd-phone') && method === 'GET') return pending.then((r) => r);
      return background(url, method) ?? Promise.reject(new Error(`no stub for ${method} ${url}`));
    }) as typeof fetch);

    const phone = await openCmdStep();
    fireEvent.change(phone, { target: { value: OTHER_FAKE_PHONE } });
    releaseSaved(json(saved()));

    // Give the resolved query a chance to land, then assert the typed value survived it.
    await waitFor(() => expect(rememberBox().checked).toBe(true));
    expect(phone.value).toBe(OTHER_FAKE_PHONE);
  });

  it('says so when a number is stored but this session cannot decrypt it', async () => {
    stubFetch(saved({ phone: null, readable: false }));
    const phone = await openCmdStep();

    // The box reflects the truth — a number IS stored — so it cannot be left unticked…
    await waitFor(() => expect(rememberBox().checked).toBe(true));
    // …and the field stays empty, which without the warning below would read as "we lost it".
    expect(phone.value).toBe('');
    expect(screen.getByText('Número guardado indisponível nesta sessão')).toBeTruthy();
  });

  it('does not read the saved number until the CMD step is actually open', async () => {
    const reads: string[] = [];
    vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = input.toString();
      const method = init?.method ?? 'GET';
      if (url.includes('/v1/me/cmd-phone')) {
        reads.push(url);
        return json(saved());
      }
      return background(url, method) ?? Promise.reject(new Error(`no stub for ${method} ${url}`));
    }) as typeof fetch);

    renderWithProviders(<SigningPanel act={signingAct} />);
    await screen.findByRole('button', { name: 'Assinar com Chave Móvel Digital' });
    // Decrypting personal data is a side effect, so it waits for a reason to happen.
    expect(reads).toEqual([]);

    fireEvent.click(screen.getByRole('button', { name: 'Assinar com Chave Móvel Digital' }));
    await waitFor(() => expect(reads.length).toBeGreaterThan(0));
  });
});
