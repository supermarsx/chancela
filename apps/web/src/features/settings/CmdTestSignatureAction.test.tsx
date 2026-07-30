/**
 * The CMD PRODUCTION test-signature flow (t51-e3/t69/t82), rebuilt as one stepped dialog (t94).
 *
 * What these tests are guarding is not "a dialog rendered". They pin:
 *
 *  - the EXACT request bodies of both phases, including the nested `confirmation` proof the
 *    server's own test suite pins byte-for-byte;
 *  - that NO request is issued until that phase's confirmation is complete — asserted per phase,
 *    because `ConfirmationAction::CmdTestSignature` is floored at `ConfirmWithReauthAndPhrase`
 *    and `initiate` and `confirm` each demand their own proof;
 *  - that folding the two phases into one dialog did NOT fold the two confirmations into one:
 *    the proof typed for phase 1 must not survive into phase 2;
 *  - that failures stay individually recognisable — a server refusal keeps its own diagnostic
 *    text, and an expired session is presented as a phase that aged out rather than as a
 *    generic error;
 *  - that the honest legal-effect negatives and the self-validation verdict are rendered rather
 *    than omitted, a negative verdict as prominently as a positive one.
 *
 * Interacts with the shared confirmation gate's fields the same way every other gated-action test
 * in this codebase does (`getByLabelText('Palavra-passe')` / `getByLabelText('Escreva … para
 * confirmar')` — see `DataManagementSection.test.tsx`), since those labels are shared app-wide
 * copy this suite does not own. Everything this suite DOES own is read from its own fallback
 * catalog (`providerCredentialsFallback.ts`), never guessed as a substring.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { Route, Routes } from 'react-router-dom';
import { ProviderCredentialsSection } from './ProviderCredentialsSection';
import type {
  CmdTestSignatureConfirmResult,
  CmdTestSignatureInitiateResult,
  ProviderCredentialsListView,
} from '../../api/types';
import { renderWithProviders } from '../../test/utils';
import { providerCredentialsPtPT as copy } from '../../i18n/providerCredentialsFallback';

const CONFIRM_PHRASE = 'ASSINAR TESTE';
const PHRASE_LABEL = `Escreva ${CONFIRM_PHRASE} para confirmar`;
const PASSWORD_LABEL = 'Palavra-passe';

const cmdList: ProviderCredentialsListView = {
  strict: false,
  protection_level: 'confidential',
  can_store: true,
  providers: [
    {
      mode: 'cmd',
      provider_id: '',
      entries: [
        {
          entry_id: 'cmd-entry-1',
          label: 'CMD principal',
          priority: 0,
          enabled: true,
          selectors: { env: 'prod' },
          fields: [{ field_name: 'application_id', configured: true }],
          created_at: '2026-07-01T10:00:00Z',
          updated_at: '2026-07-01T10:00:00Z',
        },
      ],
    },
  ],
};

const cscList: ProviderCredentialsListView = {
  strict: false,
  protection_level: 'confidential',
  can_store: true,
  providers: [
    {
      mode: 'csc',
      provider_id: 'qtsp',
      entries: [
        {
          entry_id: 'entry-a',
          label: 'Primária',
          priority: 0,
          enabled: true,
          selectors: {},
          fields: [],
          created_at: '2026-07-01T10:00:00Z',
          updated_at: '2026-07-01T10:00:00Z',
        },
      ],
    },
  ],
};

const initiateResult: CmdTestSignatureInitiateResult = {
  session_id: 'sess-1',
  status: 'otp_pending',
  masked_phone: '+351 9*****678',
  credential_source: 'stored_entry',
  entry_id: 'cmd-entry-1',
  entry_label: 'CMD principal',
  environment: 'prod',
  expires_at: '2026-07-28T10:05:00Z',
  provider_contacted: true,
  signer_authorization_requested: true,
  document_signed: false,
};

const confirmResult: CmdTestSignatureConfirmResult = {
  test_id: 'test-1',
  status: 'signed',
  provider_contacted: true,
  document_signed: true,
  legal_effect: 'none',
  counts_toward_book_opening: false,
  counts_toward_act_signature: false,
  signed_pdf_digest: 'ab12cd34',
  signed_pdf_bytes: 1024,
  signing_time: '2026-07-28T10:00:00Z',
  signed_at: '2026-07-28T10:00:05Z',
  masked_phone: '+351 9*****678',
  credential_source: 'stored_entry',
  entry_id: 'cmd-entry-1',
  entry_label: 'CMD principal',
  environment: 'prod',
  trusted_list_status: 'Ok',
  timestamped: true,
  retained: true,
  self_validation: {
    signature_verifies: true,
    covers_rendered_document: true,
    coverage: 'whole_document',
    signature_timestamp_present: true,
  },
};

interface Call {
  url: string;
  method: string;
  body: string | null;
}

function stubFetch(
  view: ProviderCredentialsListView,
  options: {
    initiateStatus?: number;
    initiateBody?: unknown;
    confirmStatus?: number;
    confirmBody?: unknown;
  } = {},
) {
  const {
    initiateStatus = 200,
    initiateBody = initiateResult,
    confirmStatus = 200,
    confirmBody = confirmResult,
  } = options;
  const calls: Call[] = [];
  const fn = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const method = init?.method ?? 'GET';
    calls.push({ url, method, body: (init?.body as string) ?? null });
    if (method === 'GET') {
      return Promise.resolve(
        new Response(JSON.stringify(view), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      );
    }
    if (url.endsWith('/signature/cmd/test-signature/initiate')) {
      return Promise.resolve(
        new Response(JSON.stringify(initiateBody), {
          status: initiateStatus,
          headers: { 'Content-Type': 'application/json' },
        }),
      );
    }
    if (url.endsWith('/signature/cmd/test-signature/confirm')) {
      return Promise.resolve(
        new Response(JSON.stringify(confirmBody), {
          status: confirmStatus,
          headers: { 'Content-Type': 'application/json' },
        }),
      );
    }
    return Promise.resolve(
      new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } }),
    );
  }) as unknown as typeof fetch;
  return { fn, calls };
}

function renderSection() {
  return renderWithProviders(
    <Routes>
      <Route path="/admin/signing/providers" element={<ProviderCredentialsSection />} />
    </Routes>,
    ['/admin/signing/providers'],
  );
}

const initiateCalls = (calls: Call[]) =>
  calls.filter((c) => c.url.endsWith('/signature/cmd/test-signature/initiate'));
const confirmCalls = (calls: Call[]) =>
  calls.filter((c) => c.url.endsWith('/signature/cmd/test-signature/confirm'));

/** Open the flow from the credentials table row. */
async function openFlow() {
  fireEvent.click(
    await screen.findByRole('button', { name: copy['providerCredentials.cmdTest.button'] }),
  );
  return screen.findByRole('dialog');
}

/** Fill a phase's confirmation proof — the phrase and the step-up — inside the open dialog. */
function fillConfirmationProof(dialog: HTMLElement) {
  fireEvent.change(within(dialog).getByLabelText(PHRASE_LABEL), {
    target: { value: CONFIRM_PHRASE },
  });
  fireEvent.change(within(dialog).getByLabelText(PASSWORD_LABEL), {
    target: { value: 'operator-pw' },
  });
}

/**
 * Drive both phases to a completed result. The request shapes and the per-phase gating are pinned
 * by the first two cases in this file; cases that are about what the RESULT renders go through
 * here so they assert on the panel rather than re-deriving the flow.
 */
async function runTestSignatureToResult() {
  const dialog = await openFlow();
  fireEvent.change(within(dialog).getByLabelText(copy['providerCredentials.cmdTest.phoneLabel']), {
    target: { value: '+351 912345678' },
  });
  fireEvent.change(within(dialog).getByLabelText(copy['providerCredentials.cmdTest.pinLabel']), {
    target: { value: '271828' },
  });
  fillConfirmationProof(dialog);
  fireEvent.click(
    within(dialog).getByRole('button', {
      name: copy['providerCredentials.cmdTest.initiateConfirm'],
    }),
  );

  await screen.findByTestId('cmd-test-step-authorisation');
  fireEvent.change(within(dialog).getByLabelText(copy['providerCredentials.cmdTest.otpLabel']), {
    target: { value: '314159' },
  });
  fillConfirmationProof(dialog);
  fireEvent.click(
    within(dialog).getByRole('button', {
      name: copy['providerCredentials.cmdTest.confirmConfirm'],
    }),
  );
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('CmdTestSignatureAction', () => {
  it('walks both phases inside one dialog with the exact request shapes, and steps through the flow', async () => {
    const stub = stubFetch(cmdList);
    vi.stubGlobal('fetch', stub.fn);
    renderSection();

    const dialog = await openFlow();
    // Step 1 of 4. The rail is the app's shared STATUS stepper, not a set of controls — so the
    // progress is read off its per-step state rather than off any styling.
    const rail = () =>
      within(screen.getByRole('dialog')).getByRole('list', {
        name: copy['providerCredentials.cmdTest.stepperLabel'],
      });
    const railStates = () =>
      Array.from(rail().querySelectorAll('li')).map((li) => li.getAttribute('data-state'));
    expect(railStates()).toEqual(['current', 'upcoming', 'upcoming', 'upcoming']);
    expect(within(dialog).getByTestId('cmd-test-step-credentials')).toBeTruthy();

    fireEvent.change(
      within(dialog).getByLabelText(copy['providerCredentials.cmdTest.phoneLabel']),
      {
        target: { value: '+351 912345678' },
      },
    );
    fireEvent.change(within(dialog).getByLabelText(copy['providerCredentials.cmdTest.pinLabel']), {
      target: { value: '271828' },
    });
    fillConfirmationProof(dialog);
    fireEvent.click(
      within(dialog).getByRole('button', {
        name: copy['providerCredentials.cmdTest.initiateConfirm'],
      }),
    );

    await waitFor(() => expect(initiateCalls(stub.calls).length).toBe(1));
    expect(JSON.parse(initiateCalls(stub.calls)[0].body ?? '{}')).toEqual({
      phone: '+351 912345678',
      pin: '271828',
      entry_id: 'cmd-entry-1',
      confirmation: { reauth: { password: 'operator-pw' }, confirm_phrase: CONFIRM_PHRASE },
    });

    // The dialog does NOT close between phases — it advances a step, and the waiting state says
    // the product is waiting on the person.
    const stillOpen = screen.getByRole('dialog');
    expect(await within(stillOpen).findByTestId('cmd-test-step-authorisation')).toBeTruthy();
    expect(
      within(stillOpen).getByText(copy['providerCredentials.cmdTest.waitingTitle']),
    ).toBeTruthy();
    expect(
      within(stillOpen).getByText(copy['providerCredentials.cmdTest.waitingNote']),
    ).toBeTruthy();
    // The rail advanced: the credentials step is done, the wait is where the run is.
    expect(railStates()).toEqual(['done', 'current', 'upcoming', 'upcoming']);

    fireEvent.change(
      within(stillOpen).getByLabelText(copy['providerCredentials.cmdTest.otpLabel']),
      { target: { value: '314159' } },
    );
    fillConfirmationProof(stillOpen);
    fireEvent.click(
      within(stillOpen).getByRole('button', {
        name: copy['providerCredentials.cmdTest.confirmConfirm'],
      }),
    );

    await waitFor(() => expect(confirmCalls(stub.calls).length).toBe(1));
    expect(JSON.parse(confirmCalls(stub.calls)[0].body ?? '{}')).toEqual({
      session_id: 'sess-1',
      otp: '314159',
      confirmation: { reauth: { password: 'operator-pw' }, confirm_phrase: CONFIRM_PHRASE },
    });

    // The result lands on the last step, inside the same dialog, with the honest negatives
    // rendered rather than omitted — an explicit `false` is a claim; absence is ambiguity.
    const result = await screen.findByTestId('cmd-test-signature-result');
    expect(railStates()).toEqual(['done', 'done', 'done', 'current']);
    expect(within(result).getByText(copy['providerCredentials.cmdTest.resultSigned'])).toBeTruthy();
    expect(
      within(result).getByText(copy['providerCredentials.cmdTest.legalEffectNone']),
    ).toBeTruthy();
    expect(
      within(result).getByText(copy['providerCredentials.cmdTest.countsBookOpening'])
        .nextElementSibling?.textContent,
    ).toBe(copy['providerCredentials.probe.no']);
    expect(
      within(result).getByText(copy['providerCredentials.cmdTest.countsActSignature'])
        .nextElementSibling?.textContent,
    ).toBe(copy['providerCredentials.probe.no']);
    expect(within(result).getByText(copy['providerCredentials.cmdTest.disclaimer'])).toBeTruthy();
    expect(within(result).getByText('ab12cd34')).toBeTruthy();
    // And the application's own verdict on the bytes it produced.
    expect(within(result).getByTestId('cmd-test-self-validation')).toBeTruthy();
  });

  /**
   * The constraint that a "single modal with steps" would otherwise quietly break. The server
   * FLOORS this action at `ConfirmWithReauthAndPhrase` and re-checks the proof on `confirm`
   * independently of `initiate`, so one dialog must still collect two proofs — and must issue
   * NEITHER request before the proof for that phase is complete.
   */
  it('issues no request until each phase has its own complete confirmation, and does not carry phase 1 into phase 2', async () => {
    const stub = stubFetch(cmdList);
    vi.stubGlobal('fetch', stub.fn);
    renderSection();

    const dialog = await openFlow();
    const send = () =>
      within(screen.getByRole('dialog')).getByRole('button', {
        name: copy['providerCredentials.cmdTest.initiateConfirm'],
      }) as HTMLButtonElement;

    expect(send().disabled).toBe(true);
    fireEvent.click(send());
    expect(initiateCalls(stub.calls).length).toBe(0);

    fireEvent.change(
      within(dialog).getByLabelText(copy['providerCredentials.cmdTest.phoneLabel']),
      {
        target: { value: '+351 912345678' },
      },
    );
    fireEvent.change(within(dialog).getByLabelText(copy['providerCredentials.cmdTest.pinLabel']), {
      target: { value: '271828' },
    });
    // Phone + PIN alone are not enough — the phrase and the step-up are still required.
    expect(send().disabled).toBe(true);
    fireEvent.click(send());
    expect(initiateCalls(stub.calls).length).toBe(0);

    fireEvent.change(within(dialog).getByLabelText(PHRASE_LABEL), {
      target: { value: CONFIRM_PHRASE },
    });
    expect(send().disabled).toBe(true); // the phrase alone still isn't enough
    fireEvent.click(send());
    expect(initiateCalls(stub.calls).length).toBe(0);

    fireEvent.change(within(dialog).getByLabelText(PASSWORD_LABEL), {
      target: { value: 'operator-pw' },
    });
    expect(send().disabled).toBe(false);
    fireEvent.click(send());
    await waitFor(() => expect(initiateCalls(stub.calls).length).toBe(1));

    // --- Phase 2. The proof gathered for phase 1 must NOT survive the phase boundary: the
    // server does not accept it, and a UI that kept it would imply one confirmation covered
    // two requests.
    const phase2 = screen.getByRole('dialog');
    await within(phase2).findByTestId('cmd-test-step-authorisation');
    expect((within(phase2).getByLabelText(PHRASE_LABEL) as HTMLInputElement).value).toBe('');
    expect((within(phase2).getByLabelText(PASSWORD_LABEL) as HTMLInputElement).value).toBe('');

    const confirmBtn = () =>
      within(screen.getByRole('dialog')).getByRole('button', {
        name: copy['providerCredentials.cmdTest.confirmConfirm'],
      }) as HTMLButtonElement;

    fireEvent.change(within(phase2).getByLabelText(copy['providerCredentials.cmdTest.otpLabel']), {
      target: { value: '314159' },
    });
    // The OTP alone does not sign: the second confirmation is a separate gate.
    expect(confirmBtn().disabled).toBe(true);
    fireEvent.click(confirmBtn());
    expect(confirmCalls(stub.calls).length).toBe(0);

    fireEvent.change(within(phase2).getByLabelText(PHRASE_LABEL), {
      target: { value: CONFIRM_PHRASE },
    });
    expect(confirmBtn().disabled).toBe(true);
    fireEvent.click(confirmBtn());
    expect(confirmCalls(stub.calls).length).toBe(0);

    fireEvent.change(within(phase2).getByLabelText(PASSWORD_LABEL), {
      target: { value: 'operator-pw' },
    });
    expect(confirmBtn().disabled).toBe(false);
    fireEvent.click(confirmBtn());
    await waitFor(() => expect(confirmCalls(stub.calls).length).toBe(1));
  });

  it('surfaces the server refusal reason inline and never signs on an initiate failure', async () => {
    const stub = stubFetch(cmdList, {
      initiateStatus: 409,
      initiateBody: {
        error:
          'a Chave Móvel Digital está configurada para pré-produção; a assinatura de teste só corre em produção',
      },
    });
    vi.stubGlobal('fetch', stub.fn);
    renderSection();

    const dialog = await openFlow();
    fireEvent.change(
      within(dialog).getByLabelText(copy['providerCredentials.cmdTest.phoneLabel']),
      {
        target: { value: '+351 912345678' },
      },
    );
    fireEvent.change(within(dialog).getByLabelText(copy['providerCredentials.cmdTest.pinLabel']), {
      target: { value: '271828' },
    });
    fillConfirmationProof(dialog);
    fireEvent.click(
      within(dialog).getByRole('button', {
        name: copy['providerCredentials.cmdTest.initiateConfirm'],
      }),
    );

    // The server's own diagnostic message — naming pré-produção specifically, not a generic
    // failure — surfaces (inline in the dialog, and as a toast), and the flow stays on the step
    // it failed on. No session was ever created, so the waiting step is not reachable.
    expect((await screen.findAllByText(/pré-produção/)).length).toBeGreaterThan(0);
    expect(screen.getByTestId('cmd-test-step-credentials')).toBeTruthy();
    expect(screen.queryByTestId('cmd-test-step-authorisation')).toBeNull();
    expect(confirmCalls(stub.calls).length).toBe(0);
  });

  /**
   * A 410 is the single-use session ageing out, not a failure of the integration. The flow must
   * drop the session so it falls back to a fresh initiate rather than re-offering a confirm that
   * can only 410 again — and must say THAT, rather than presenting it as one more error.
   */
  it('presents an expired session as a phase that aged out and falls back to a fresh initiate', async () => {
    const stub = stubFetch(cmdList, {
      confirmStatus: 410,
      confirmBody: { error: 'a sessão de assinatura de teste expirou' },
    });
    vi.stubGlobal('fetch', stub.fn);
    renderSection();
    await runTestSignatureToResult();

    await waitFor(() => expect(confirmCalls(stub.calls).length).toBe(1));

    // Back on step 1, with the expiry named as itself.
    const dialog = await screen.findByRole('dialog');
    expect(await within(dialog).findByTestId('cmd-test-step-credentials')).toBeTruthy();
    expect(within(dialog).getByText(copy['providerCredentials.cmdTest.expiredTitle'])).toBeTruthy();
    expect(within(dialog).getByText(copy['providerCredentials.cmdTest.expiredBody'])).toBeTruthy();

    // The confirm affordance is gone: a second confirm could only 410 again.
    expect(
      within(dialog).queryByRole('button', {
        name: copy['providerCredentials.cmdTest.confirmConfirm'],
      }),
    ).toBeNull();
    expect(
      within(dialog).getByRole('button', {
        name: copy['providerCredentials.cmdTest.initiateConfirm'],
      }),
    ).toBeTruthy();
    // And nothing was signed.
    expect(screen.queryByTestId('cmd-test-signature-result')).toBeNull();
  });

  /**
   * NEGATIVE SPACE — this asserts an absence, so it passes under many mutations of the flow's
   * own logic and must not be counted as coverage of it. It guards one thing only: that the
   * production control never appears on a credential that is not CMD.
   */
  it('does not offer the production test-signature control on a non-CMD credential', async () => {
    vi.stubGlobal('fetch', stubFetch(cscList).fn);
    renderSection();

    expect(await screen.findByText('Primária')).toBeTruthy();
    expect(
      screen.queryByRole('button', { name: copy['providerCredentials.cmdTest.button'] }),
    ).toBeNull();
  });

  /**
   * The self-validation verdict (t82). The end of the chain is not "AMA answered" but "the product
   * can verify what AMA produced", so the verdict is rendered — and a NEGATIVE one has to be as
   * visible as a positive one. The signature is real and retained in both cases; a panel that
   * quietly dropped a failure would make the test worth less than not running it.
   */
  it('renders a failed self-validation verdict as an explicit negative, with the reason', async () => {
    const stub = stubFetch(cmdList, {
      confirmBody: {
        ...confirmResult,
        self_validation: {
          signature_verifies: false,
          covers_rendered_document: false,
          coverage: 'malformed',
          signature_timestamp_present: false,
          error: 'the /ByteRange gap is not exactly the /Contents value',
        },
      },
    });
    vi.stubGlobal('fetch', stub.fn);
    renderSection();
    await runTestSignatureToResult();

    const panel = await screen.findByTestId('cmd-test-self-validation');
    // Every flag renders as a value. The negatives are present, not omitted.
    expect(
      within(panel).getByText(copy['providerCredentials.cmdTest.selfValidationVerifies'])
        .nextElementSibling?.textContent,
    ).toBe(copy['providerCredentials.probe.no']);
    expect(
      within(panel).getByText(copy['providerCredentials.cmdTest.selfValidationCovers'])
        .nextElementSibling?.textContent,
    ).toBe(copy['providerCredentials.probe.no']);
    expect(
      within(panel).getByText(copy['providerCredentials.cmdTest.selfValidationCoverage'])
        .nextElementSibling?.textContent,
    ).toBe(copy['providerCredentials.cmdTest.coverage.malformed']);
    // The server's own explanation reaches the operator verbatim.
    expect(
      within(panel).getByText('the /ByteRange gap is not exactly the /Contents value'),
    ).toBeTruthy();
    // And the panel says the signature nonetheless exists and is downloadable, rather than
    // implying the test failed to produce one.
    expect(
      within(panel).getByText(copy['providerCredentials.cmdTest.selfValidationBad']),
    ).toBeTruthy();
    expect(
      screen.getByRole('button', { name: copy['providerCredentials.cmdTest.download'] }),
    ).toBeTruthy();
  });

  /**
   * The unverified verdict must survive the dialog being closed: the row is where an operator
   * comes back to it, and a test the application could not verify does not get to look like a
   * clean pass from there either.
   */
  it('summarises an unverified completed test on the row rather than as a plain success', async () => {
    const stub = stubFetch(cmdList, {
      confirmBody: {
        ...confirmResult,
        self_validation: {
          signature_verifies: false,
          covers_rendered_document: false,
          coverage: 'altered_after_signing',
          signature_timestamp_present: false,
        },
      },
    });
    vi.stubGlobal('fetch', stub.fn);
    renderSection();
    await runTestSignatureToResult();

    await screen.findByTestId('cmd-test-signature-result');
    fireEvent.click(
      screen.getByRole('button', { name: copy['providerCredentials.cmdTest.close'] }),
    );

    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(screen.getByText(copy['providerCredentials.cmdTest.rowDoneUnverified'])).toBeTruthy();
    expect(screen.queryByText(copy['providerCredentials.cmdTest.rowDone'])).toBeNull();
    // The result is not lost with the dialog — it is one click away again.
    expect(
      screen.getByRole('button', { name: copy['providerCredentials.cmdTest.viewResult'] }),
    ).toBeTruthy();
  });

  /**
   * A coverage token this build does not know must not be rendered as one of the verdicts it is
   * not, and must not leak the raw token. `PdfSignatureCoverage` is `#[non_exhaustive]`, so a
   * newer server can legitimately send one.
   */
  it('reports an unknown coverage token as unrecognised rather than guessing or leaking it', async () => {
    const stub = stubFetch(cmdList, {
      confirmBody: {
        ...confirmResult,
        self_validation: {
          ...confirmResult.self_validation,
          coverage: 'some_future_verdict',
        },
      },
    });
    vi.stubGlobal('fetch', stub.fn);
    renderSection();
    await runTestSignatureToResult();

    const panel = await screen.findByTestId('cmd-test-self-validation');
    expect(
      within(panel).getByText(copy['providerCredentials.cmdTest.selfValidationCoverage'])
        .nextElementSibling?.textContent,
    ).toBe(copy['providerCredentials.cmdTest.coverage.unrecognised']);
    expect(within(panel).queryByText('some_future_verdict')).toBeNull();
  });

  /**
   * **t113.** Which environment the run will use, stated before the operator commits.
   *
   * The run is production-only and the server refuses anything else. An operator who is about to
   * type a phrase and a password should be told the credential is preprod BEFORE they do, not
   * after — and the notice is read straight off the entry's own `env` selector, which is the value
   * the server now treats as authoritative.
   */
  it.each([
    ['prod', 'providerCredentials.cmdTest.envEntryProd', 'field__hint'],
    ['preprod', 'providerCredentials.cmdTest.envEntryPreprod', 'field__error'],
  ] as const)('names the %s environment on the credentials step', async (env, key, className) => {
    const view: ProviderCredentialsListView = {
      ...cmdList,
      providers: [
        {
          ...cmdList.providers[0],
          entries: [{ ...cmdList.providers[0].entries[0], selectors: { env } }],
        },
      ],
    };
    vi.stubGlobal('fetch', stubFetch(view).fn);
    renderSection();

    const dialog = await openFlow();
    const notice = within(dialog).getByTestId('cmd-test-environment-notice');
    expect(notice.textContent).toBe(copy[key]);
    // A preprod credential is a refusal the operator is walking into, and reads as one.
    expect(notice.className).toBe(className);
  });

  it('says an entry with no selector inherits the deployment default', async () => {
    const view: ProviderCredentialsListView = {
      ...cmdList,
      providers: [
        {
          ...cmdList.providers[0],
          entries: [{ ...cmdList.providers[0].entries[0], selectors: {} }],
        },
      ],
    };
    vi.stubGlobal('fetch', stubFetch(view).fn);
    renderSection();

    const dialog = await openFlow();
    // It does NOT claim which environment that default is — the client does not resolve it, and
    // guessing would be the same overclaim this whole change is removing.
    expect(within(dialog).getByTestId('cmd-test-environment-notice').textContent).toBe(
      copy['providerCredentials.cmdTest.envEntryInherited'],
    );
  });
});
