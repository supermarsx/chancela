/**
 * RemoteBatchSigningPanel tests (s5-web-branches). The panel had no dedicated suite, so these
 * pin the behaviours that carry the load: the transient credential is scoped to the provider it
 * was typed for and is dropped after every attempt, changing the act or the seal invalidates any
 * result already on screen, a stale in-flight batch can never paint over a newer act, and every
 * optional field of a per-act result falls back rather than rendering `undefined`.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react';
import { RemoteBatchSigningPanel } from './RemoteBatchSigningPanel';
import { renderWithProviders, Wrapper } from '../../test/utils';
import { scopeBook } from '../session/permissions';
import type {
  ActView,
  RemoteBatchInitiateResponse,
  SealAppearanceBody,
  SignatureProviderView,
} from '../../api/types';

const BATCH_PATH = '/v1/signature/remote/';

const sealedAct: ActView = {
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

function provider(overrides: Partial<SignatureProviderView> = {}): SignatureProviderView {
  return {
    id: 'cmd',
    family: 'ChaveMovelDigital',
    label: 'Chave Móvel Digital',
    evidentiary_level: 'qualified',
    configured: true,
    ...overrides,
  };
}

const configuredProviders: SignatureProviderView[] = [
  provider(),
  provider({ id: 'multicert', label: 'Multicert', family: 'QualifiedCertificate' }),
];

function json(body: unknown, status = 200): Promise<Response> {
  return Promise.resolve(
    new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } }),
  );
}

function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  const promise = new Promise<T>((res) => {
    resolve = res;
  });
  return { promise, resolve };
}

function successResponse(
  overrides: Partial<RemoteBatchInitiateResponse> = {},
): RemoteBatchInitiateResponse {
  return {
    provider_id: 'cmd',
    family: 'ChaveMovelDigital',
    evidentiary_level: 'qualified',
    auth_mode: 'per_document_activation',
    requested: 2,
    pending: 1,
    failed: 1,
    initiate_events: 2,
    results: [
      {
        act_id: 'act-1',
        status: 'pending',
        session_id: 'sess-1',
        provider_id: 'cmd',
        family: 'ChaveMovelDigital',
        pending_status: 'activation_pending',
        activation_hint: 'Confirme na app Autenticação.gov',
        expires_at: '2026-07-19T12:00:00Z',
      },
      {
        act_id: 'act-2',
        status: 'error',
        error: 'referência de utilizador desconhecida',
      },
    ],
    ...overrides,
  };
}

function renderPanel(
  props: {
    act?: ActView;
    providers?: SignatureProviderView[];
    seal?: SealAppearanceBody | null;
  } = {},
) {
  const act = props.act ?? sealedAct;
  return renderWithProviders(
    <RemoteBatchSigningPanel
      currentAct={act}
      bookScope={scopeBook(act.book_id)}
      providers={props.providers ?? configuredProviders}
      seal={props.seal}
    />,
  );
}

function addAct(actId: string) {
  fireEvent.change(screen.getByLabelText('ID do ato'), { target: { value: actId } });
  fireEvent.click(screen.getByRole('button', { name: 'Adicionar' }));
}

function fillUserRef(value: string) {
  fireEvent.change(screen.getByLabelText('Referência do utilizador para sessões remotas'), {
    target: { value },
  });
}

function submit() {
  fireEvent.click(screen.getByRole('button', { name: 'Iniciar sessões remotas' }));
}

/** Stub `fetch` for the batch-initiate endpoint, recording every request body it receives. */
function stubBatch(respond: (body: Record<string, unknown>) => Promise<Response>) {
  const bodies: Record<string, unknown>[] = [];
  vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
    const url = input.toString();
    if (url.includes(BATCH_PATH)) {
      const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
      bodies.push(body);
      return respond(body);
    }
    return Promise.reject(new Error(`no stub for ${url}`));
  }) as typeof fetch);
  return bodies;
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  window.localStorage.clear();
  window.sessionStorage.clear();
});

describe('RemoteBatchSigningPanel — selection and provider gating', () => {
  it('offers only configured providers and blocks submission when none is configured', () => {
    renderPanel({ providers: [provider({ configured: false })] });

    const select = screen.getByLabelText('Prestador remoto') as HTMLSelectElement;
    expect(select.disabled).toBe(true);
    expect(select.value).toBe('');
    expect(screen.getByText('Sem prestadores remotos configurados')).toBeTruthy();
    expect(screen.queryByText('Chave Móvel Digital')).toBeNull();
    expect(
      (screen.getByRole('button', { name: 'Iniciar sessões remotas' }) as HTMLButtonElement)
        .disabled,
    ).toBe(true);
  });

  it('requires two acts and a user reference before the batch can be initiated', () => {
    renderPanel();

    expect(screen.getByText('1 selecionados de 200')).toBeTruthy();
    expect(
      screen.getByText(
        'Selecione pelo menos dois atos, um prestador e a referência do utilizador.',
      ),
    ).toBeTruthy();
    expect(
      (screen.getByRole('button', { name: 'Iniciar sessões remotas' }) as HTMLButtonElement)
        .disabled,
    ).toBe(true);

    addAct('act-2');
    expect(screen.getByText('2 selecionados de 200')).toBeTruthy();
    // Two acts alone are not enough — the user reference is still blank.
    expect(
      (screen.getByRole('button', { name: 'Iniciar sessões remotas' }) as HTMLButtonElement)
        .disabled,
    ).toBe(true);

    fillUserRef('  ');
    expect(
      (screen.getByRole('button', { name: 'Iniciar sessões remotas' }) as HTMLButtonElement)
        .disabled,
    ).toBe(true);

    fillUserRef('+351911111111');
    expect(
      (screen.getByRole('button', { name: 'Iniciar sessões remotas' }) as HTMLButtonElement)
        .disabled,
    ).toBe(false);
    expect(
      screen.queryByText(
        'Selecione pelo menos dois atos, um prestador e a referência do utilizador.',
      ),
    ).toBeNull();
  });

  it('ignores a duplicate or blank manual ID and drops a removed act from the selection', () => {
    renderPanel();

    addAct('act-2');
    addAct('act-2');
    addAct('act-1'); // already present as the current act
    expect(screen.getAllByText('act-2').length).toBe(1);
    expect(screen.getByText('2 selecionados de 200')).toBeTruthy();

    // A manual row is removable; the current act's row is not.
    expect(screen.getAllByRole('button', { name: 'Remover ato' }).length).toBe(1);
    fireEvent.click(screen.getByRole('button', { name: 'Remover ato' }));
    expect(screen.queryByText('act-2')).toBeNull();
    expect(screen.getByText('1 selecionados de 200')).toBeTruthy();

    // Deselecting the remaining act empties the selection without removing the row.
    fireEvent.click(screen.getByLabelText('Selecionar ato act-1'));
    expect((screen.getByLabelText('Selecionar ato act-1') as HTMLInputElement).checked).toBe(false);
    expect(screen.getByText('0 selecionados de 200')).toBeTruthy();
  });

  it('renders the provider manifest capabilities and hides it for a provider without one', () => {
    const withManifest = provider({
      id: 'cmd',
      manifest: {
        readiness: {
          configured: true,
          environment: 'preprod',
          sandbox: true,
          production_blocked: false,
          missing_local_config: [],
          authorization_mode: 'oauth',
        },
        capabilities: {
          remote_single_initiate_confirm: true,
          remote_batch_repeated_per_document_initiate: true,
          provider_native_batch_claimed: false,
          single_otp_pin_sad_batch_claimed: false,
        },
        boundaries: {
          live_provider_checked: false,
          provider_approval_claimed: false,
          legal_validity_claimed: false,
          qualified_status_determined_at_listing: false,
          trust_list_validation_performed_at_listing: false,
        },
        evidence_basis: ['local_manifest'],
      },
    });
    renderPanel({ providers: [withManifest, provider({ id: 'multicert', label: 'Multicert' })] });

    // Repeated per-document initiate is claimed; native batch and single-OTP batch are not.
    expect(screen.getByText('Sem lote nativo do prestador')).toBeTruthy();
    expect(
      screen.getByText(/Inícios repetidos por documento=Sim.*lote nativo do prestador=Não/),
    ).toBeTruthy();
    expect(screen.getByText(/PIN\/OTP\/SAD único para todo o lote=Não/)).toBeTruthy();

    // Switching to the manifest-less provider removes the notice entirely.
    fireEvent.change(screen.getByLabelText('Prestador remoto'), {
      target: { value: 'multicert' },
    });
    expect(screen.queryByText('Sem lote nativo do prestador')).toBeNull();
  });
});

describe('RemoteBatchSigningPanel — request shape and the transient credential', () => {
  it('trims the request, omits blank optionals and forwards the seal', async () => {
    const seal: SealAppearanceBody = { page: 2, x: 100, y: 200, w: 180, h: 60 };
    const bodies = stubBatch(() => json(successResponse()));

    renderPanel({ seal });
    addAct('act-2');
    fillUserRef('  +351911111111  ');
    fireEvent.change(screen.getByLabelText('Credencial para sessões remotas'), {
      target: { value: '4321' },
    });
    fireEvent.change(screen.getByLabelText('Qualidade/capacidade declarada'), {
      target: { value: '  Presidente da Mesa  ' },
    });
    fireEvent.change(screen.getByLabelText('Ator'), { target: { value: '   ' } });
    submit();

    await waitFor(() =>
      expect(bodies).toEqual([
        {
          act_ids: ['act-1', 'act-2'],
          user_ref: '+351911111111',
          credential: '4321',
          capacity: 'Presidente da Mesa',
          seal,
        },
      ]),
    );
    // Blank `actor` is omitted rather than sent as an empty string.
    expect(Object.keys(bodies[0])).not.toContain('actor');
    // The credential is dropped from the form the moment the attempt settles.
    expect(
      (screen.getByLabelText('Credencial para sessões remotas') as HTMLInputElement).value,
    ).toBe('');
  });

  // Note: the panel also guards the send with a `credentialProviderRef === providerId` check, but
  // that arm is unreachable — the only `setProviderId` call also clears the credential, so the two
  // can never disagree with a non-empty credential. What is observable, and what this pins, is the
  // clearing itself.
  it('clears the credential when the provider changes, so it never reaches the new provider', async () => {
    const bodies = stubBatch(() => json(successResponse()));

    renderPanel();
    addAct('act-2');
    fillUserRef('+351911111111');
    fireEvent.change(screen.getByLabelText('Credencial para sessões remotas'), {
      target: { value: 'cmd-secret' },
    });
    fireEvent.change(screen.getByLabelText('Prestador remoto'), {
      target: { value: 'multicert' },
    });

    // Switching provider must clear the visible credential, not just ignore it.
    expect(
      (screen.getByLabelText('Credencial para sessões remotas') as HTMLInputElement).value,
    ).toBe('');
    submit();

    await waitFor(() => expect(bodies.length).toBe(1));
    expect(bodies[0]).toEqual({ act_ids: ['act-1', 'act-2'], user_ref: '+351911111111' });
    expect(bodies[0].credential).toBeUndefined();
  });

  it('clears the credential and surfaces the server refusal when the batch fails', async () => {
    const bodies = stubBatch(() => json({ error: 'credencial rejeitada' }, 422));

    renderPanel();
    addAct('act-2');
    fillUserRef('+351911111111');
    fireEvent.change(screen.getByLabelText('Credencial para sessões remotas'), {
      target: { value: 'wrong' },
    });
    submit();

    expect((await screen.findAllByText('credencial rejeitada')).length).toBeGreaterThan(0);
    expect(bodies).toEqual([
      { act_ids: ['act-1', 'act-2'], user_ref: '+351911111111', credential: 'wrong' },
    ]);
    expect(
      (screen.getByLabelText('Credencial para sessões remotas') as HTMLInputElement).value,
    ).toBe('');
    // No result table is painted for a failed batch.
    expect(screen.queryByText('Modo de ativação')).toBeNull();
  });

  it('does not write the credential to storage and forgets it across a remount', () => {
    const storageSet = vi.spyOn(Storage.prototype, 'setItem');
    const { unmount } = renderPanel();
    fireEvent.change(screen.getByLabelText('Credencial para sessões remotas'), {
      target: { value: 'super-secret' },
    });
    expect(
      (screen.getByLabelText('Credencial para sessões remotas') as HTMLInputElement).value,
    ).toBe('super-secret');

    fireEvent.click(screen.getByRole('button', { name: 'Limpar sessões' }));
    expect(
      (screen.getByLabelText('Credencial para sessões remotas') as HTMLInputElement).value,
    ).toBe('');

    fireEvent.change(screen.getByLabelText('Credencial para sessões remotas'), {
      target: { value: 'super-secret-again' },
    });
    unmount();
    expect(storageSet).not.toHaveBeenCalled();
    expect(window.localStorage.length).toBe(0);
    expect(window.sessionStorage.length).toBe(0);

    renderPanel();
    expect(
      (screen.getByLabelText('Credencial para sessões remotas') as HTMLInputElement).value,
    ).toBe('');
  });
});

describe('RemoteBatchSigningPanel — per-act results', () => {
  it('renders pending and error rows and falls back for every absent optional field', async () => {
    stubBatch(() =>
      json(
        successResponse({
          results: [
            successResponse().results[0],
            // A pending row the server could not attribute to a session or provider.
            { act_id: 'act-2', status: 'pending' },
            // An error row with no message at all.
            { act_id: 'act-3', status: 'error' },
          ],
        }),
      ),
    );

    renderPanel();
    addAct('act-2');
    fillUserRef('+351911111111');
    submit();

    expect(await screen.findByText('Ativação por documento')).toBeTruthy();
    expect(screen.getByText('sess-1')).toBeTruthy();
    expect(screen.getByText('Confirme na app Autenticação.gov')).toBeTruthy();
    expect(screen.getByText('2026-07-19T12:00:00Z')).toBeTruthy();
    expect(screen.getByText('ChaveMovelDigital')).toBeTruthy();
    expect(screen.getAllByText('Pendente').length).toBe(2);
    // One «Erro» for the status badge and one for the message-less row's activation cell, which
    // falls back to the generic error label rather than rendering blank.
    expect(screen.getAllByText('Erro').length).toBe(2);
    // session / provider / activation / expiry all fall back to an em dash.
    expect(screen.getAllByText('—').length).toBeGreaterThanOrEqual(5);
    expect(screen.queryByText('undefined')).toBeNull();

    // The counters come straight from the response.
    expect(screen.getByText('Inícios enviados')).toBeTruthy();
    expect(screen.getByText('A resposta não mostra credenciais, códigos ou ativações.')).toBeTruthy();
  });

  it('discards a result already on screen when the seal changes', async () => {
    stubBatch(() => json(successResponse()));
    const seal: SealAppearanceBody = { page: 1, x: 10, y: 10, w: 100, h: 40 };

    const { rerender } = renderPanel({ seal });
    addAct('act-2');
    fillUserRef('+351911111111');
    submit();
    expect(await screen.findByText('sess-1')).toBeTruthy();

    rerender(
      <Wrapper>
        <RemoteBatchSigningPanel
          currentAct={sealedAct}
          bookScope={scopeBook(sealedAct.book_id)}
          providers={configuredProviders}
          seal={{ ...seal, page: 3 }}
        />
      </Wrapper>,
    );

    // The sessions were opened against the previous seal; the stale result must not linger.
    await waitFor(() => expect(screen.queryByText('sess-1')).toBeNull());
    expect(screen.queryByText('Modo de ativação')).toBeNull();
    // The selection itself survives — only the request artifacts are dropped.
    expect(screen.getByText('2 selecionados de 200')).toBeTruthy();
  });

  it('resets the whole panel when the current act changes', async () => {
    stubBatch(() => json(successResponse()));
    const nextAct: ActView = { ...sealedAct, id: 'act-next', ata_number: 2 };

    const { rerender } = renderPanel();
    addAct('act-2');
    fillUserRef('+351911111111');
    fireEvent.change(screen.getByLabelText('Qualidade/capacidade declarada'), {
      target: { value: 'Presidente da Mesa' },
    });
    fireEvent.change(screen.getByLabelText('Ator'), { target: { value: 'operador-1' } });
    submit();
    expect(await screen.findByText('sess-1')).toBeTruthy();

    rerender(
      <Wrapper>
        <RemoteBatchSigningPanel
          currentAct={nextAct}
          bookScope={scopeBook(nextAct.book_id)}
          providers={configuredProviders}
        />
      </Wrapper>,
    );

    expect(screen.queryByText('sess-1')).toBeNull();
    expect(screen.queryByText('Modo de ativação')).toBeNull();
    expect(screen.queryByText('act-2')).toBeNull();
    expect((screen.getByLabelText('Selecionar ato act-next') as HTMLInputElement).checked).toBe(
      true,
    );
    expect(screen.getByText('1 selecionados de 200')).toBeTruthy();
    expect(
      (screen.getByLabelText('Referência do utilizador para sessões remotas') as HTMLInputElement)
        .value,
    ).toBe('');
    expect(
      (screen.getByLabelText('Qualidade/capacidade declarada') as HTMLInputElement).value,
    ).toBe('');
    expect((screen.getByLabelText('Ator') as HTMLInputElement).value).toBe('');
  });

  it('never paints a stale batch result over a newer act', async () => {
    const pending = deferred<Response>();
    const bodies = stubBatch(() => pending.promise);
    const nextAct: ActView = { ...sealedAct, id: 'act-next', ata_number: 2 };

    const { rerender } = renderPanel();
    addAct('act-2');
    fillUserRef('+351911111111');
    submit();
    await waitFor(() => expect(bodies.length).toBe(1));

    rerender(
      <Wrapper>
        <RemoteBatchSigningPanel
          currentAct={nextAct}
          bookScope={scopeBook(nextAct.book_id)}
          providers={configuredProviders}
        />
      </Wrapper>,
    );
    expect((screen.getByLabelText('Selecionar ato act-next') as HTMLInputElement).checked).toBe(
      true,
    );

    pending.resolve(
      new Response(JSON.stringify(successResponse()), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    );
    await pending.promise;
    await Promise.resolve();
    await Promise.resolve();

    await waitFor(() => {
      expect(screen.queryByText('sess-1')).toBeNull();
      expect(screen.queryByText('Modo de ativação')).toBeNull();
      expect(screen.queryByText('Sessões remotas iniciadas.')).toBeNull();
    });
  });
});
